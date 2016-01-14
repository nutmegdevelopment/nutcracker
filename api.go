package main

import (
	"code.google.com/p/go-uuid/uuid"
	"encoding/json"
	"github.com/nutmegdevelopment/nutcracker/secrets"
	"net/http"
)

func Health(w http.ResponseWriter, r *http.Request) {
	resp := newApiResponse(w)
	resp.message("OK", 200)
	return
}

// Initialise should be run on first use of a new vault.
func Initialise(w http.ResponseWriter, r *http.Request) {

	resp := newApiResponse(w)

	// Check for an existing master secret
	res, err := database.GetSecrets(&secrets.Secret{Name: "master"})
	if err != nil {
		resp.error("Database error", 500)
		return
	}
	if len(res) > 0 {
		resp.error("Vault already initialised", 409)
		return
	}

	key, err := secrets.Initialise()
	if err != nil {
		resp.error("Error intialising master secret", 500)
		return
	}
	err = database.AddSecret(key)
	if err != nil {
		resp.error("Database error", 500)
		return
	}

	resp.reply(secrets.Key{
		Name: key.Name,
		Key:  key.Key.Display()},
		201)
}

func Unseal(w http.ResponseWriter, r *http.Request) {
	req := newApiRequest(r)
	resp := newApiResponse(w)

	request, err := req.read()
	if err != nil {
		println(err.Error())
		resp.error("Bad request", 400)
		return
	}

	if request.Key == nil {
		resp.error("Missing elements in request", 400)
		return
	}

	defer secrets.Zero(request.Key)

	res, err := database.GetSecrets(&secrets.Secret{Name: "master"})
	if err != nil {
		resp.error("Database error", 500)
		return
	}
	if len(res) == 0 {
		resp.error("Vault not initialised", 400)
		return
	}

	err = secrets.Unseal(&res[0], request.Key)
	if err != nil {
		resp.error("Incorrect key for vault", 403)
		return
	}

	resp.message("OK", 200)
	return

}

func Message(w http.ResponseWriter, r *http.Request) {
	req := newApiRequest(r)
	resp := newApiResponse(w)

	request, err := req.read()
	if err != nil {
		println(err.Error())
		resp.error("Bad request", 400)
		return
	}

	if len(request.Message) == 0 {
		resp.error("Missing elements in request", 400)
		return
	}
	if len(request.Name) == 0 {
		resp.error("Missing elements in request", 400)
		return
	}

	s, err := secrets.New(request.Name, []byte(request.Message))
	if err != nil {
		resp.error("Server error", 500)
		return
	}

	err = database.AddSecret(s)
	if err != nil {
		resp.error("Database error", 500)
		return
	}

	resp.message("OK", 201)
	return
}

func Key(w http.ResponseWriter, r *http.Request) {
	resp := newApiResponse(w)

	key := new(secrets.Key)

	err := key.New(uuid.New())
	if err != nil {
		resp.error("Server error", 500)
		return
	}

	err = database.AddKey(key)
	if err != nil {
		resp.error("Database error", 500)
		return
	}

	resp.reply(secrets.Key{
		Name: key.Name,
		Key:  key.Display()},
		201)
}

type Request struct {
	Name    string
	Key     []byte
	KeyID   string
	Message string
}

type apiRequest struct {
	*http.Request
}

func newApiRequest(r *http.Request) *apiRequest {
	return &apiRequest{r}
}

func (a *apiRequest) read() (req Request, err error) {
	defer a.Body.Close()
	dec := json.NewDecoder(a.Body)
	err = dec.Decode(&req)
	return
}

type apiResponse struct {
	http.ResponseWriter
}

func newApiResponse(w http.ResponseWriter) apiResponse {
	return apiResponse{w}
}

func (a apiResponse) reply(v interface{}, code int) {
	data, _ := json.MarshalIndent(&v, "", "  ")
	a.WriteHeader(code)
	a.Write(data)
}

func (a apiResponse) error(message string, code int) {
	r := map[string]string{"error": message}
	data, _ := json.MarshalIndent(&r, "", "  ")
	a.WriteHeader(code)
	a.Write(data)
}

func (a apiResponse) message(message string, code int) {
	r := map[string]string{"response": message}
	data, _ := json.MarshalIndent(&r, "", "  ")
	a.WriteHeader(code)
	a.Write(data)
}
