package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	"github.com/nutmegdevelopment/nutcracker/secrets"
	"github.com/pborman/uuid"
	"golang.org/x/crypto/curve25519"
)

func Health(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)
	api.message("OK", 200)
	return
}

// Initialise should be run on first use of a new vault.
func Initialise(w http.ResponseWriter, r *http.Request) {

	api := newAPI(w, r)

	// Check for an existing master secret
	master := new(secrets.Secret)
	master.Name = "master"

	err := database.GetRootSecret(master)
	switch err {

	case gorm.RecordNotFound:
		break

	case nil:
		api.error("Vault already initialised", 409)
		return

	default:
		api.error("Database error", 500)
		return

	}

	key, err := secrets.Initialise()
	if err != nil {
		api.error("Error intialising master secret", 500)
		return
	}

	err = database.AddSecret(key)
	if err != nil {
		api.error("Database error", 500)
		return
	}

	log.Info("Vault initialised")

	api.reply(secrets.Key{
		Name: key.Name,
		Key:  key.Key.Display()},
		201)
}

func Unseal(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() || !api.admin {
		api.error("Unauthorized", 401)
		return
	}

	master := new(secrets.Secret)
	master.Name = "master"

	err := database.GetRootSecret(master)
	switch err {

	case gorm.RecordNotFound:
		api.error("Vault not initialised", 404)
		return

	case nil:
		break

	default:
		log.Error(err)
		api.error("Database error", 500)
		return

	}

	err = secrets.Unseal(master, api.key)
	if err != nil {
		api.error("Incorrect key for vault", 403)
		return
	}

	log.Info("Vault unsealed")

	api.message("OK", 200)
	return

}

func Seal(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	secrets.Seal()

	log.Info("Vault sealed")

	api.message("OK", 200)
	return
}

func Message(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() || !api.admin {
		api.error("Unauthorized", 401)
		return
	}

	request, err := api.read()
	if err != nil {
		api.error("Bad request", 400)
		return
	}

	if len(request.Message) == 0 {
		api.error("Missing elements in request", 400)
		return
	}
	if len(request.Name) == 0 {
		api.error("Missing elements in request", 400)
		return
	}

	s, err := secrets.New(request.Name, []byte(request.Message))
	if err != nil {
		api.error(err.Error(), 500)
		return
	}

	err = database.AddSecret(s)
	switch {

	case err == nil:
		log.Info("New secret added: ", s.Name)
		api.message("OK", 201)

	case err.Error() == "Secret already exists":
		api.error("Secret already exists", 409)

	default:
		log.Error(err)
		api.error("Database error", 500)

	}

	return
}

func Key(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() || !api.admin {
		api.error("Unauthorized", 401)
		return
	}

	request, err := api.read()
	if err != nil {
		api.error("Bad request", 400)
		return
	}

	key := new(secrets.Key)

	err = key.New(uuid.New())
	if err != nil {
		log.Error(err)
		api.error("Server error", 500)
		return
	}

	if request.Admin {
		key.ReadOnly = false
	} else {
		key.ReadOnly = true
	}

	err = database.AddKey(key)
	if err != nil {
		log.Error(err)
		api.error("Database error", 500)
		return
	}

	log.Info("New key added: ", key.Name)

	api.reply(secrets.Key{
		Name:     key.Name,
		Key:      key.Display(),
		ReadOnly: key.ReadOnly,
	},
		201)
}

func Share(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() || !api.admin {
		api.error("Unauthorized", 401)
		return
	}

	request, err := api.read()
	if err != nil {
		api.error("Bad request", 400)
		return
	}

	if len(request.KeyID) == 0 {
		api.error("Missing elements in request", 400)
		return
	}
	if len(request.Name) == 0 {
		api.error("Missing elements in request", 400)
		return
	}

	key := new(secrets.Key)
	key.Name = request.KeyID
	key.Key = request.Key

	err = database.GetKey(key)
	if err != nil {
		log.Error(err)
		api.error("Database error", 500)
		return
	}

	secret := new(secrets.Secret)
	secret.Name = request.Name

	err = database.GetRootSecret(secret)
	switch err {

	case gorm.RecordNotFound:
		api.error("Secret does not exist", 404)
		return

	case nil:
		break

	default:
		log.Error(err)
		api.error("Database error", 500)
		return

	}

	shared, err := secret.Share(key)
	if err != nil {
		log.Error(err)
		api.error(err.Error(), 500)
		return
	}

	err = database.AddSecret(shared)
	if err != nil {
		log.Error(err)
		api.error("Database error", 500)
		return
	}

	log.Info("Secret: ", shared.Name, " shared with: ", key.Name)

	api.message("OK", 201)
	return
}

func View(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() {
		api.error("Unauthorized", 401)
		return
	}

	request, err := api.read()
	if err != nil {
		api.error("Bad request", 400)
		return
	}

	root := new(secrets.Secret)
	shared := new(secrets.Secret)
	root.Name = request.Name
	shared.Name = request.Name

	key := new(secrets.Key)
	key.Name = api.keyID

	err = database.GetSharedSecret(shared, key)
	switch err {

	case gorm.RecordNotFound:
		api.error("Secret does not exist", 404)
		return

	case nil:
		break

	default:
		log.Error(err)
		api.error("Database error", 500)
		return

	}

	err = database.GetRootSecret(root)
	switch err {

	case gorm.RecordNotFound:
		api.error("Secret does not exist", 404)
		return

	case nil:
		break

	default:
		log.Error(err)
		api.error("Database error", 500)
		return
	}

	message, err := root.Decrypt(shared, api.key)
	if err != nil {
		api.error("Cannot decrypt secret", 400)
		return
	}
	defer secrets.Zero(message)

	log.Info("Secret: ", shared.Name, " viewed by: ", key.Name)

	api.rawMessage(message, 200)
}

func Update(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() || !api.admin {
		api.error("Unauthorized", 401)
		return
	}

	request, err := api.read()
	if err != nil {
		api.error("Bad request", 400)
		return
	}

	if len(request.Message) == 0 {
		api.error("Missing elements in request", 400)
		return
	}
	if len(request.Name) == 0 {
		api.error("Missing elements in request", 400)
		return
	}

	secret := new(secrets.Secret)
	secret.Name = request.Name

	err = database.GetRootSecret(secret)
	switch err {

	case gorm.RecordNotFound:
		api.error("Secret does not exist", 404)
		return

	case nil:
		break

	default:
		log.Error(err)
		api.error("Database error", 500)
		return

	}

	err = secret.Update([]byte(request.Message))
	if err != nil {
		api.error("Server error", 500)
		return
	}

	err = database.UpdateSecret(secret)
	if err != nil {
		log.Error(err)
		api.error("Database error", 500)
	} else {
		log.Info("Secret updated: ", secret.Name)
		api.message("OK", 201)
	}
	return
}

type Request struct {
	Name    string
	Key     []byte
	KeyID   string
	Message string
	Admin   bool
}

type api struct {
	req   *http.Request
	resp  http.ResponseWriter
	keyID string
	key   []byte
	admin bool
}

func newAPI(w http.ResponseWriter, r *http.Request) *api {
	return &api{
		resp: w,
		req:  r,
	}
}

func (a *api) read() (req Request, err error) {
	if a.req.Method == "GET" {
		urlParams := mux.Vars(a.req)
		req.Name = urlParams["messageName"]
	} else {
		defer a.req.Body.Close()
		dec := json.NewDecoder(a.req.Body)
		err = dec.Decode(&req)
	}
	return
}

func (a *api) reply(v interface{}, code int) {
	data, _ := json.MarshalIndent(&v, "", "  ")
	a.resp.WriteHeader(code)
	a.resp.Write(data)
}

func (a *api) error(message string, code int) {
	r := map[string]string{"error": message}
	data, _ := json.MarshalIndent(&r, "", "  ")
	a.resp.WriteHeader(code)
	a.resp.Write(data)
}

func (a *api) message(message string, code int) {
	r := map[string]string{"response": message}
	data, _ := json.MarshalIndent(&r, "", "  ")
	a.resp.WriteHeader(code)
	a.resp.Write(data)
}

func (a *api) rawMessage(message []byte, code int) {
	a.resp.WriteHeader(code)
	a.resp.Write(message)
}

func (a *api) auth() bool {
	var err error

	var secretID string
	var secretKey string

	if a.req.Method == "GET" {
		secretID = a.req.FormValue("secretid")
		secretKeySlice, err := base64.StdEncoding.DecodeString(a.req.FormValue("secretkey"))
		if err != nil {
			return false
		}
		secretKey = string(secretKeySlice)
	} else {
		secretID = a.req.Header.Get("X-Secret-ID")
		secretKey = a.req.Header.Get("X-Secret-Key")
	}

	k := new(secrets.Key)
	k.Name = secretID
	a.keyID = k.Name
	a.key, err = base64.StdEncoding.DecodeString(
		secretKey)
	if err != nil {
		return false
	}

	priv := new([32]byte)
	pub := new([32]byte)

	copy(priv[:], a.key)
	defer secrets.Zero(priv[:])

	err = database.GetKey(k)
	if err != nil {
		return false
	}

	if !k.ReadOnly {
		a.admin = true
	}

	curve25519.ScalarBaseMult(pub, priv)
	if subtle.ConstantTimeCompare(pub[:], k.Public) == 1 {
		return true
	}
	return false
}
