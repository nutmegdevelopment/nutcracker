package main // import "github.com/nutmegdevelopment/nutcracker"

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	"github.com/nutmegdevelopment/nutcracker/secrets"
	"github.com/pborman/uuid"
	"golang.org/x/crypto/curve25519"
)

const pageSize int = 10

var secretIDRegex *regexp.Regexp
var secretKeyRegex *regexp.Regexp

func init() {
	// Compile credential checking regex patterns.
	secretIDRegex = regexp.MustCompile(`^([0-9a-zA-Z_.\-])+$`)
	secretKeyRegex = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)
}

// Health returns 200 if the service is running and can connect to the DB.
func Health(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)
	err := database.Ping()
	if err == nil {
		api.message("OK", 200)
	} else {
		api.error("Cannot connect to the DB", 500)
	}
	return
}

// Initialise should be run on first use of a new vault.
func Initialise(w http.ResponseWriter, r *http.Request) {

	api := newAPI(w, r)

	// Check for an existing master secret
	master := new(secrets.Secret)
	master.Name = secrets.MasterKeyName

	err := database.GetRootSecret(master)
	switch err {

	case gorm.ErrRecordNotFound:
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

// Unseal opens the vault for writing
func Unseal(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() || !api.admin {
		api.error("Unauthorized", 401)
		return
	}

	master := new(secrets.Secret)
	master.Name = secrets.MasterKeyName

	err := database.GetRootSecret(master)
	switch err {

	case gorm.ErrRecordNotFound:
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

// Auth returns the auth details for the current user
func Auth(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() {
		api.error("Unauthorized", 401)
		return
	}

	api.reply(map[string]interface{}{
		"Admin": api.admin,
	}, 200)
	return
}

// Seal locks the vault into read-only mode
func Seal(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	secrets.Seal()

	log.Info("Vault sealed")

	api.message("OK", 200)
	return
}

// Message adds a new secret message to the vault
func Message(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() || !api.admin {
		api.error("Unauthorized", 401)
		return
	}

	request, err := api.read()
	if err != nil {
		log.Debug(err)
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
		log.Debug(err)
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

// Key adds a new secret key to the vault
func Key(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() || !api.admin {
		api.error("Unauthorized", 401)
		return
	}

	request, err := api.read()
	if err != nil {
		log.Debug(err)
		api.error("Bad request", 400)
		return
	}

	if request.Name == "" {
		request.Name = uuid.New()
	}

	if !secretIDRegex.MatchString(request.Name) {
		api.error("Invalid key ID", 400)
	}

	key := new(secrets.Key)

	err = key.New(request.Name)
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

// Share grants a key access to a message
func Share(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() || !api.admin {
		api.error("Unauthorized", 401)
		return
	}

	request, err := api.read()
	if err != nil {
		log.Debug(err)
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

	case gorm.ErrRecordNotFound:
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

// View downloads a decrypted message
func View(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() {
		api.error("Unauthorized", 401)
		return
	}

	request, err := api.read()
	if err != nil {
		log.Debug(err)
		api.error("Bad request", 400)
		return
	}

	if name, ok := api.params["messageName"]; ok {
		request.Name = name
	}

	root := new(secrets.Secret)
	shared := new(secrets.Secret)
	root.Name = request.Name
	shared.Name = request.Name

	key := new(secrets.Key)
	key.Name = api.keyID

	err = database.GetSharedSecret(shared, key)
	switch err {

	case gorm.ErrRecordNotFound:
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

	case gorm.ErrRecordNotFound:
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
		log.Debug(err)
		api.error("Cannot decrypt secret", 500)
		return
	}
	defer secrets.Zero(message)

	log.Info("Secret: ", shared.Name, " viewed by: ", key.Name)
	viewCount++

	api.rawMessage(message, 200)
}

// List lists all secrets or keys
func List(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() {
		api.error("Unauthorized", 401)
		return
	}

	_, err := api.read()
	if err != nil {
		log.Debug(err)
		api.error("Bad request", 400)
		return
	}

	switch api.params["type"] {

	case "secret", "secrets":
		if _, ok := api.params["target"]; ok {
			listKeys(api)
		} else {
			listSecrets(api)
		}

	case "key", "keys":
		if _, ok := api.params["target"]; ok {
			listSecrets(api)
		} else {
			listKeys(api)
		}

	default:
		api.error("Invalid type to list", 500)

	}

}

func listSecrets(api *api) {

	var search *string
	if _, ok := api.params["target"]; ok {
		search = new(string)
		*search = api.params["target"]
	}

	iter := database.ListSecrets(search)

	for {

		res, err := iter(pageSize)
		if err != nil {
			log.Error(err)
			api.error("Database error", 500)
			return
		}

		if len(res) == 0 {
			return
		}

		data, err := json.MarshalIndent(&res, "", "  ")
		if err != nil {
			log.Error(err)
			api.error("JSON error", 500)
			return
		}

		api.resp.Write(data)

		res = res[:0]

	}

}

func listKeys(api *api) {

	var search *string
	if _, ok := api.params["target"]; ok {
		search = new(string)
		*search = api.params["target"]
	}

	iter := database.ListKeys(search)

	for {

		res, err := iter(pageSize)
		if err != nil {
			log.Error(err)
			api.error("Database error", 500)
			return
		}

		if len(res) == 0 {
			return
		}

		data, err := json.MarshalIndent(&res, "", "  ")
		if err != nil {
			log.Error(err)
			api.error("JSON error", 500)
			return
		}

		api.resp.Write(data)

		res = res[:0]

	}

}

// Update changes the contents of a message but does not affect
// which keys it is shared with
func Update(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() || !api.admin {
		api.error("Unauthorized", 401)
		return
	}

	request, err := api.read()
	if err != nil {
		log.Debug(err)
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

	case gorm.ErrRecordNotFound:
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

// Delete removes a secret or key
func Delete(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)

	if !api.auth() || !api.admin {
		api.error("Unauthorized", 401)
		return
	}

	_, err := api.read()
	if err != nil {
		log.Debug(err)
		api.error("Bad request", 400)
		return
	}

	var ok bool
	switch api.params["type"] {

	case "secret", "secrets":
		s := new(secrets.Secret)
		s.Name, ok = api.params["target"]
		if !ok {
			log.Debug(err)
			api.error("Invalid secret", 400)
		}

		err = database.DeleteSecret(s)
		if err != nil {
			log.Error(err)
			api.error("Database error", 500)
		}

	case "key", "keys":
		k := new(secrets.Key)
		k.Name, ok = api.params["target"]
		if !ok {
			log.Debug(err)
			api.error("Invalid key", 400)
		}

		err = database.DeleteKey(k)
		if err != nil {
			log.Error(err)
			api.error("Database error", 500)
		}

	default:
		api.error("Invalid type to delete", 500)

	}

	api.message("OK", 200)
}

// Metrics returns basic server metrics
func Metrics(w http.ResponseWriter, r *http.Request) {
	api := newAPI(w, r)
	metrics, err := database.Metrics()
	if err != nil {
		log.Error(err)
		api.error("Database error", 500)
	}
	metrics["views"] = viewCount

	if secrets.IsSealed() {
		metrics["sealed"] = true
	} else {
		metrics["sealed"] = false
	}

	api.reply(metrics, 200)
}

type request struct {
	Name    string
	Key     []byte
	KeyID   string
	Message string
	Admin   bool
}

type api struct {
	req    *http.Request
	resp   http.ResponseWriter
	keyID  string
	key    []byte
	admin  bool
	params map[string]string
}

func newAPI(w http.ResponseWriter, r *http.Request) *api {
	return &api{
		resp: w,
		req:  r,
	}
}

func (a *api) read() (req request, err error) {
	a.params = mux.Vars(a.req)

	if a.req.Method != "POST" && a.req.Method != "PUT" {
		a.req.Body.Close()
		return
	}

	defer a.req.Body.Close()
	dec := json.NewDecoder(a.req.Body)
	err = dec.Decode(&req)
	if err != nil {
		return
	}
	err = a.req.Body.Close()
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

	k := new(secrets.Key)

	var secretKey string

	// Grab the credentials, look in the header first and fall back to the query string.
	if k.Name = a.req.Header.Get("X-Secret-ID"); k.Name == "" {
		k.Name = a.req.FormValue("secretid")
	}
	if secretKey = a.req.Header.Get("X-Secret-Key"); secretKey == "" {
		secretKey = a.req.FormValue("secretkey")
	}

	// If the master key has been used then just check the key, else check both.
	if k.Name == secrets.MasterKeyName {
		if secretKeyRegex.MatchString(secretKey) != true {
			log.Error("Invalid auth credential format.")
			return false
		}
	} else if secretIDRegex.MatchString(k.Name) != true || secretKeyRegex.MatchString(secretKey) != true {
		log.Error("Invalid auth credential format.")
		return false
	}

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
