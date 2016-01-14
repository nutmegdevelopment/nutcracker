package main

import (
	"bytes"
	"encoding/json"
	"github.com/nutmegdevelopment/nutcracker/db/mocks"
	"github.com/nutmegdevelopment/nutcracker/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealth(t *testing.T) {
	w := httptest.NewRecorder()
	Health(w, nil)
	res := getResp(w.Body.Bytes())
	assert.Contains(t, res, "response", "Result should contain response")
	assert.Equal(t, "OK", res["response"])
}

func TestInititalise(t *testing.T) {

	testDb := new(mocks.DB)

	testDb.On("GetSecrets", &secrets.Secret{Name: "master"}).Return(nil, nil)
	testDb.On("AddSecret", mock.AnythingOfType("*secrets.Secret")).Return(nil)

	database = testDb

	w := httptest.NewRecorder()
	Initialise(w, nil)

	res := getResp(w.Body.Bytes())

	assert.Contains(t, res, "Id", "Result should contain Id")
	assert.Contains(t, res, "Key", "Result should contain Key")

	assert.Equal(t, "master", res["Id"], "Result name should be master")

	testDb = new(mocks.DB)

	dbRes := make([]secrets.Secret, 1)
	dbRes[0] = secrets.Secret{Name: "master"}

	testDb.On("GetSecrets", &secrets.Secret{Name: "master"}).Return(dbRes, nil)

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

	dbRes := make([]secrets.Secret, 1)
	dbRes[0] = secrets.Secret{
		Name:    "master",
		Message: master.Message,
		Nonce:   master.Nonce}

	testDb.On("GetSecrets", &secrets.Secret{Name: "master"}).Return(dbRes, nil)

	database = testDb

	req := make(map[string][]byte)
	req["key"] = master.Key.Display()

	data, err := json.Marshal(req)
	assert.Nil(t, err, "Should not return error")

	w := httptest.NewRecorder()
	r, err := http.NewRequest("POST", "/unseal", bytes.NewReader(data))
	assert.Nil(t, err, "Should not return error")

	Unseal(w, r)

	res := getResp(w.Body.Bytes())
	assert.Contains(t, res, "response", "Result should contain response")
	assert.Equal(t, "OK", res["response"], "Should unseal vault")
}

func TestMessage(t *testing.T) {
	w := httptest.NewRecorder()

	testDb := new(mocks.DB)
	testDb.Mock.On("AddSecret", mock.AnythingOfType("*secrets.Secret")).Return(nil)
	database = testDb

	req := Request{Name: "test", Message: "message"}
	data, err := json.Marshal(req)
	assert.Nil(t, err, "Should not return error")

	r, err := http.NewRequest("POST", "/secrets/message", bytes.NewReader(data))
	assert.Nil(t, err, "Should not return error")

	Message(w, r)

	res := getResp(w.Body.Bytes())
	assert.Contains(t, res, "response", "Result should contain response")
	assert.Equal(t, "OK", res["response"])
}

func TestKey(t *testing.T) {
	w := httptest.NewRecorder()

	testDb := new(mocks.DB)
	testDb.Mock.On("AddKey", mock.AnythingOfType("*secrets.Key")).Return(nil)
	database = testDb

	Key(w, nil)
	res := getResp(w.Body.Bytes())
	assert.Contains(t, res, "Id", "Result should contain id")
	assert.Contains(t, res, "Key", "Result should contain key")
}

func getResp(data []byte) map[string]string {
	var res map[string]string
	json.Unmarshal(data, &res)
	return res
}
