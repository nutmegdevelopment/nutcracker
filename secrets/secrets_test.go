package secrets

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestZero(t *testing.T) {
	slice := []byte("123456")
	array := [32]byte{1, 2, 3, 4, 5, 6}

	Zero(slice)
	Zero(array[:])

	assert.True(t, isNull(array[:]), "Array should be zeroed")
	assert.True(t, isNull(slice), "Slice should be zeroed")
}

func TestEncrypt(t *testing.T) {

	s, err := New("test", []byte("message"))
	assert.Equal(t, errors.New("Please unseal first"), err,
		"Should raise an error")

	_, err = s.Share(&Key{})
	assert.Equal(t, errors.New("Please unseal first"), err,
		"Should raise an error")

	masterSecret, err := Initialise()
	assert.Nil(t, err)

	origMaster := master
	masterKey := masterSecret.Key.Display()

	Seal()
	assert.True(t, isNull(master[:]), "Master key should be sealed")

	err = Unseal(masterSecret, masterKey)
	assert.Nil(t, err)

	assert.False(t, isNull(master[:]), "Master key should be unsealed")

	assert.Equal(t, origMaster, master, "Master key should match")

	s, err = New("test", []byte("message"))
	assert.Nil(t, err)

	assert.True(t, isNull(s.Key.raw[:]), "Private key should be zeroed")

	dest := new(Key)
	err = dest.New("testid")
	assert.Nil(t, err)

	privKey := *dest.raw

	shared, err := s.Share(dest)
	assert.Nil(t, err)

	message, err := s.Decrypt(shared, dest.Display())
	assert.Nil(t, err)

	assert.Equal(t, []byte("message"), message,
		"Decrypted message should match")

	s.Update([]byte("new message"))

	message, err = s.Decrypt(shared, privKey[:])
	assert.Nil(t, err)

	assert.Equal(t, []byte("new message"), message,
		"new decrypted message should match")

}
