package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	log "github.com/Sirupsen/logrus"
	"github.com/jinzhu/gorm"
	"github.com/nutmegdevelopment/nutcracker/db/mocks"
	"github.com/nutmegdevelopment/nutcracker/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/curve25519"
	"net/http"
	"net/http/httptest"
	"testing"
)

func init() {
	var buf []byte
	log.SetOutput(bytes.NewBuffer(buf))
}

func TestHealth(t *testing.T) {
	w := httptest.NewRecorder()
	Health(w, nil)
	res := getResp(w.Body.Bytes())
	assert.Contains(t, res, "response", "Result should contain response")
	assert.Equal(t, "OK", res["response"])
}

func TestAuth(t *testing.T) {

	a := new(api)
	a.req = new(http.Request)
	a.req.Header = make(http.Header)
	a.req.Header.Set("X-Secret-ID", "testkey")
	a.req.Header.Set("X-Secret-Key", base64.StdEncoding.EncodeToString(authKey[:]))

	testDb := new(mocks.DB)

	authSetup(testDb, nil, nil)

	database = testDb

	assert.True(t, a.auth(), "Auth should succeed")

	a = new(api)
	a.req = new(http.Request)
	a.req.Header = make(http.Header)
	a.req.Header.Set("X-Secret-ID", "testkey")
	a.req.Header.Set("X-Secret-Key", base64.StdEncoding.EncodeToString([]byte("fail")))

	testDb = new(mocks.DB)

	authSetup(testDb, nil, nil)

	database = testDb
	assert.False(t, a.auth(), "Auth should fail")
}

func TestInititalise(t *testing.T) {

	testDb := new(mocks.DB)

	testDb.On("GetRootSecret", &secrets.Secret{Name: "master"}).Return(gorm.RecordNotFound)
	testDb.On("AddSecret", mock.AnythingOfType("*secrets.Secret")).Return(nil)

	database = testDb

	w := httptest.NewRecorder()
	Initialise(w, nil)

	res := getResp(w.Body.Bytes())

	assert.Contains(t, res, "Id", "Result should contain Id")
	assert.Contains(t, res, "Key", "Result should contain Key")

	assert.Equal(t, "master", res["Id"], "Result name should be master")

	testDb = new(mocks.DB)

	testDb.On("GetRootSecret", &secrets.Secret{Name: "master"}).Return(nil)

	database = testDb

	w = httptest.NewRecorder()
	Initialise(w, nil)

	res = getResp(w.Body.Bytes())
	assert.Equal(t, "Vault already initialised", res["error"], "Should return error")
}

func TestUnseal(t *testing.T) {

	master, err := secrets.Initialise()
	assert.Nil(t, err, "Should not return error")

	testDb := new(mocks.DB)

	r := new(http.Request)

	authSetup(testDb, r, master.Key.Display())

	testDb.On("GetRootSecret", &secrets.Secret{Name: "master"}).Run(func(args mock.Arguments) {
		args.Get(0).(*secrets.Secret).Name = "master"
		args.Get(0).(*secrets.Secret).Nonce = master.Nonce
		args.Get(0).(*secrets.Secret).Message = master.Message
	}).Return(nil)

	database = testDb

	w := httptest.NewRecorder()

	assert.Nil(t, err, "Should not return error")

	Unseal(w, r)

	res := getResp(w.Body.Bytes())
	assert.Contains(t, res, "response", "Result should contain response")
	assert.Equal(t, "OK", res["response"], "Should unseal vault")
}

func TestMessage(t *testing.T) {
	w := httptest.NewRecorder()

	req := Request{Name: "test", Message: "message"}
	data, err := json.Marshal(req)
	assert.Nil(t, err, "Should not return error")

	r, err := http.NewRequest("POST", "/secrets/message", bytes.NewReader(data))
	assert.Nil(t, err, "Should not return error")

	testDb := new(mocks.DB)

	authSetup(testDb, r, nil)

	testDb.Mock.On("AddSecret", mock.AnythingOfType("*secrets.Secret")).Return(nil)
	database = testDb

	Message(w, r)

	res := getResp(w.Body.Bytes())
	assert.Contains(t, res, "response", "Result should contain response")
	assert.Equal(t, "OK", res["response"])
}

func TestKey(t *testing.T) {
	w := httptest.NewRecorder()

	req := Request{Admin: false}
	data, err := json.Marshal(req)
	assert.Nil(t, err, "Should not return error")

	r, err := http.NewRequest("POST", "/secrets/key", bytes.NewReader(data))
	assert.Nil(t, err, "Should not return error")

	testDb := new(mocks.DB)

	authSetup(testDb, r, nil)

	testDb.Mock.On("AddKey", mock.AnythingOfType("*secrets.Key")).Return(nil)
	database = testDb

	Key(w, r)
	res := getResp(w.Body.Bytes())
	assert.Contains(t, res, "Id", "Result should contain id")
	assert.Contains(t, res, "Key", "Result should contain key")
}

func TestShare(t *testing.T) {
	w := httptest.NewRecorder()

	secret, err := secrets.New("testsecret", []byte("testmessage"))
	assert.Nil(t, err, "Should not return error")

	pub := new([32]byte)
	curve25519.ScalarBaseMult(pub, &authKey)

	req := Request{Name: "testsecret", KeyID: "1-2-3-4"}
	data, err := json.Marshal(req)
	assert.Nil(t, err, "Should not return error")

	r, err := http.NewRequest("POST", "/secrets/share", bytes.NewReader(data))
	assert.Nil(t, err, "Should not return error")

	testDb := new(mocks.DB)

	authSetup(testDb, r, nil)

	testDb.Mock.On("GetKey", mock.AnythingOfType("*secrets.Key")).Run(func(args mock.Arguments) {
		args.Get(0).(*secrets.Key).Name = "1-2-3-4"
		args.Get(0).(*secrets.Key).Public = pub[:]
	}).Return(nil)

	testDb.On("GetRootSecret", &secrets.Secret{Name: "testsecret"}).Run(func(args mock.Arguments) {
		args.Get(0).(*secrets.Secret).Name = secret.Name
		args.Get(0).(*secrets.Secret).Nonce = secret.Nonce
		args.Get(0).(*secrets.Secret).Message = secret.Message
		args.Get(0).(*secrets.Secret).Key = secret.Key
	}).Return(nil)

	testDb.On("AddSecret", mock.AnythingOfType("*secrets.Secret")).Return(nil)

	database = testDb

	Share(w, r)

	res := getResp(w.Body.Bytes())
	assert.Contains(t, res, "response", "Result should contain response")
	assert.Equal(t, "OK", res["response"])
}

func TestView(t *testing.T) {
	w := httptest.NewRecorder()

	root, err := secrets.New("testsecret", []byte("testmessage"))
	assert.Nil(t, err, "Should not return error")

	key := new(secrets.Key)
	err = key.New("testkey")
	priv := key.Display()
	assert.Nil(t, err, "Should not return error")

	shared, err := root.Share(key)
	assert.Nil(t, err, "Should not return error")

	req := Request{Name: "testsecret"}
	data, err := json.Marshal(req)
	assert.Nil(t, err, "Should not return error")

	r, err := http.NewRequest("POST", "/secrets/view", bytes.NewReader(data))
	assert.Nil(t, err, "Should not return error")

	testDb := new(mocks.DB)

	authSetup(testDb, r, priv)

	testDb.On(
		"GetSharedSecret",
		&secrets.Secret{Name: "testsecret"},
		&secrets.Key{Name: "testkey"}).Run(
		func(args mock.Arguments) {
			args.Get(0).(*secrets.Secret).Name = shared.Name
			args.Get(0).(*secrets.Secret).Nonce = shared.Nonce
			args.Get(0).(*secrets.Secret).Message = shared.Message
			args.Get(0).(*secrets.Secret).Pubkey = shared.Pubkey
			args.Get(0).(*secrets.Secret).Key = shared.Key
		}).Return(nil)

	testDb.On("GetRootSecret", mock.AnythingOfType("*secrets.Secret")).Run(func(args mock.Arguments) {
		args.Get(0).(*secrets.Secret).Name = root.Name
		args.Get(0).(*secrets.Secret).Nonce = root.Nonce
		args.Get(0).(*secrets.Secret).Message = root.Message
		args.Get(0).(*secrets.Secret).Pubkey = root.Pubkey
		args.Get(0).(*secrets.Secret).Key = root.Key
	}).Return(nil)

	database = testDb

	View(w, r)
	assert.Equal(t, "testmessage", string(w.Body.Bytes()))

}

func TestUpdate(t *testing.T) {
	w := httptest.NewRecorder()

	secret, err := secrets.New("testsecret", []byte("testmessage"))
	assert.Nil(t, err, "Should not return error")

	req := Request{Name: "testsecret", Message: "newmessage"}
	data, err := json.Marshal(req)
	assert.Nil(t, err, "Should not return error")

	r, err := http.NewRequest("POST", "/secrets/message", bytes.NewReader(data))
	assert.Nil(t, err, "Should not return error")

	testDb := new(mocks.DB)

	authSetup(testDb, r, nil)

	testDb.On("GetRootSecret", &secrets.Secret{Name: "testsecret"}).Run(func(args mock.Arguments) {
		args.Get(0).(*secrets.Secret).Name = secret.Name
		args.Get(0).(*secrets.Secret).Nonce = secret.Nonce
		args.Get(0).(*secrets.Secret).Message = secret.Message
		args.Get(0).(*secrets.Secret).Key = secret.Key
	}).Return(nil)

	testDb.Mock.On("UpdateSecret", mock.AnythingOfType("*secrets.Secret")).Return(nil)
	database = testDb

	Update(w, r)

	res := getResp(w.Body.Bytes())
	assert.Contains(t, res, "response", "Result should contain response")
	assert.Equal(t, "OK", res["response"])
}

func TestSeal(t *testing.T) {
	w := httptest.NewRecorder()
	Seal(w, nil)
	res := getResp(w.Body.Bytes())
	assert.Contains(t, res, "response", "Result should contain response")
	assert.Equal(t, "OK", res["response"])
}

func getResp(data []byte) map[string]string {
	var res map[string]string
	json.Unmarshal(data, &res)
	return res
}

var authKey = [32]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

func authSetup(testDb *mocks.DB, req *http.Request, key []byte) {

	priv := new([32]byte)
	if key == nil {
		priv = &authKey
	} else {
		copy(priv[:], key)
	}

	if req != nil {
		req.Header = make(http.Header)
		req.Header.Set("X-Secret-ID", "testkey")
		req.Header.Set("X-Secret-Key", base64.StdEncoding.EncodeToString(priv[:]))
	}

	pub := new([32]byte)
	curve25519.ScalarBaseMult(pub, priv)

	testDb.On("GetKey", &secrets.Key{Name: "testkey"}).Run(func(args mock.Arguments) {
		args.Get(0).(*secrets.Key).Name = "testkey"
		args.Get(0).(*secrets.Key).Public = pub[:]
	}).Return(nil)
}
