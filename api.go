package main

import (
	"code.google.com/p/go-uuid/uuid"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"github.com/jinzhu/gorm"
	"github.com/nutmegdevelopment/nutcracker/secrets"
	"golang.org/x/crypto/curve25519"
	"net/http"
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

	api.reply(secrets.Key{
		Name: key.Name,
		Key:  key.Key.Display()},
		201)
}

func Unseal(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() {
		api.error("Unauthorized", 401)
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
		api.error("Database error", 500)
		return

	}

	err = secrets.Unseal(master, api.key)
	if err != nil {
		api.error("Incorrect key for vault", 403)
		return
	}

	api.message("OK", 200)
	return

}

func Seal(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	secrets.Seal()

	api.message("OK", 200)
	return
}

func Message(w http.ResponseWriter, r *http.Request) {
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
		api.error("Server error", 500)
		return
	}

	err = database.AddSecret(s)
	if err != nil {
		api.error("Database error", 500)
		return
	}

	api.message("OK", 201)
	return
}

func Key(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() {
		api.error("Unauthorized", 401)
		return
	}

	key := new(secrets.Key)

	err := key.New(uuid.New())
	if err != nil {
		api.error("Server error", 500)
		return
	}

	err = database.AddKey(key)
	if err != nil {
		api.error("Database error", 500)
		return
	}

	api.reply(secrets.Key{
		Name: key.Name,
		Key:  key.Display()},
		201)
}

func Share(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() {
		api.error("Unauthorized", 401)
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
		api.error("Database error", 500)
		return
	}

	secret := new(secrets.Secret)
	secret.Name = request.Name

	err = database.GetRootSecret(secret)
	if err != nil {
		api.error("Database error", 500)
		return
	}

	shared, err := secret.Share(key)
	if err != nil {
		api.error("Server error", 500)
		return
	}

	err = database.AddSecret(shared)
	if err != nil {
		api.error("Database error", 500)
		return
	}

	api.message("OK", 201)
	return
}

func View(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	api.auth()

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
		api.error("Database error", 500)
		return
	}

	message, err := root.Decrypt(shared, api.key)
	if err != nil {
		api.error("Cannot decrypt secret", 400)
		return
	}
	defer secrets.Zero(message)
	api.message(string(message), 200)
}

type Request struct {
	Name    string
	Key     []byte
	KeyID   string
	Message string
}

type api struct {
	req   *http.Request
	resp  http.ResponseWriter
	keyID string
	key   []byte
}

func newAPI(w http.ResponseWriter, r *http.Request) *api {
	return &api{
		resp: w,
		req:  r,
	}
}

func (a *api) read() (req Request, err error) {
	defer a.req.Body.Close()
	dec := json.NewDecoder(a.req.Body)
	err = dec.Decode(&req)
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

func (a *api) auth() bool {
	var err error

	k := new(secrets.Key)
	k.Name = a.req.Header.Get("X-Secret-ID")
	a.keyID = k.Name

	a.key, err = base64.StdEncoding.DecodeString(
		a.req.Header.Get("X-Secret-Key"))
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

	curve25519.ScalarBaseMult(pub, priv)
	if subtle.ConstantTimeCompare(pub[:], k.Public) == 1 {
		return true
	}
	return false
}
