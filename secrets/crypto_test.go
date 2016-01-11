package secrets

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/nacl/box"
	"testing"
)

func isZero(in []byte) bool {
	for i := range in {
		if in[i] != 0 {
			return false
		}
	}
	return true
}

func TestZero(t *testing.T) {
	slice := []byte("123456")
	array := [32]byte{1, 2, 3, 4, 5, 6}

	Zero(slice)
	Zero(array[:])

	assert.True(t, isZero(array[:]), "Array should be zeroed")
	assert.True(t, isZero(slice), "Slice should be zeroed")
}

func TestEncrypt(t *testing.T) {

	srcPub, srcPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("test message")

	s, decKey, err := New("test")
	if err != nil {
		t.Fatal(err)
	}

	err = s.Encrypt(srcPub, srcPriv, message)
	if err != nil {
		t.Fatal(err)
	}

	assert.True(t, isZero(message), "Message should be zeroed")
	assert.True(t, isZero(srcPriv[:]), "Private key should be zeroed")
	assert.False(t, isZero(s.Box), "Box should contain data")
	assert.False(t, isZero(s.Nonce[:]), "Nonce should contain data")

	out, err := s.Decrypt(decKey)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, []byte("test message"), out, "Decrypted message should match")

}
