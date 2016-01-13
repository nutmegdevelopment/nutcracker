package secrets

import (
	"code.google.com/p/go.crypto/nacl/box"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
	"io"
)

var master *[32]byte

func init() {
	master = new([32]byte)
}

// Create a new master secret.
func Initialise() (masterKey Secret, err error) {

	// We can't use masterKey.New() here
	masterKey.Name = "master"
	masterKey.Nonce = new([24]byte)
	_, err = io.ReadFull(rand.Reader, masterKey.Nonce[:])
	if err != nil {
		return
	}
	masterKey.Root = true

	// Create a new master key
	_, err = io.ReadFull(rand.Reader, master[:])
	if err != nil {
		return
	}

	// Create an encryption key
	err = masterKey.Key.New("master")
	if err != nil {
		return
	}

	// Encrypt the master key
	masterKey.Message = secretbox.Seal(
		nil,
		master[:],
		masterKey.Nonce,
		masterKey.Key.raw)

	return
}

func Unseal(masterKey Secret, key []byte) (err error) {
	defer Zero(key)

	priv, err := decode(key)
	if err != nil {
		return
	}
	defer Zero(priv[:])

	_, ok := secretbox.Open(master[:],
		masterKey.Message,
		masterKey.Nonce,
		priv)

	if !ok {
		err = errors.New("Unable to decrypt secret")
		return
	}
	return
}

type Secret struct {
	Name    string
	Message []byte
	Nonce   *[24]byte // 24 byte length mandated by NaCL.
	Key     Key
	Pubkey  *[32]byte // Used for sharing secrets
	KeyID   string    // To find sharing secrets matching a key.
	Root    bool      // Identifies root secrets
}

// New creates a new secret container with a unique key.
// Requires the master key to be unsealed.
func New(name string, message []byte) (s *Secret, err error) {

	if isNull(master[:]) {
		err = errors.New("Please unseal first")
		return
	}

	defer Zero(message)

	if name == "master" {
		err = errors.New("Cannot create a new master key")
		return
	}

	s = new(Secret)

	// Generate a unique encryption key
	err = s.Key.New("")
	if err != nil {
		return
	}

	s.Name = name
	s.Root = true

	return s, s.encrypt(message)
}

func (s *Secret) Update(message []byte) (err error) {
	if isNull(master[:]) {
		err = errors.New("Please unseal first")
		return
	}

	defer Zero(message)

	// Decrypt the unique encryption key
	s.Key.Decrypt()

	return s.encrypt(message)
}

func (s *Secret) encrypt(message []byte) (err error) {
	// We generate nonces randomly - chance of collision is negligable
	s.Nonce = new([24]byte)
	_, err = io.ReadFull(rand.Reader, s.Nonce[:])
	if err != nil {
		return
	}

	// Encrypt the message and unique key
	s.Message = secretbox.Seal(
		nil,
		message,
		s.Nonce,
		s.Key.raw)

	s.Key.Encrypt()

	return
}

// Share creates a shared key, which the given key can use to decrypt
// the secret.
// This shared key is encrypted with
// Requires the master key to be unsealed.
func (s *Secret) Share(key *Key) (shared *Secret, err error) {
	if isNull(master[:]) {
		err = errors.New("Please unseal first")
		return
	}
	shared = new(Secret)

	// Set mapping values
	shared.Name = s.Name
	shared.KeyID = key.Id

	err = s.Key.Decrypt()
	if err != nil {
		return
	}
	defer s.Key.Zero()

	shared.Nonce = new([24]byte)
	_, err = io.ReadFull(rand.Reader, shared.Nonce[:])
	if err != nil {
		return
	}

	// Generate a public key from the master
	shared.Pubkey = new([32]byte)
	curve25519.ScalarBaseMult(shared.Pubkey, master)

	shared.Message = box.Seal(
		nil,
		s.Key.raw[:],
		shared.Nonce,
		key.Public,
		master)

	return
}

// Decrypt decrypts a secret given a shared key and a
// base64-encoded secret key provided by the user.
// This does not require the master key to be unsealed.
func (s *Secret) Decrypt(shared *Secret, key []byte) (message []byte, err error) {
	defer Zero(key)

	priv, err := decode(key)
	if err != nil {
		return
	}
	defer Zero(priv[:])

	// Decrypt the shared key
	sharedKey := new([32]byte)
	buf, ok := box.Open(
		nil,
		shared.Message,
		shared.Nonce,
		shared.Pubkey,
		priv)

	if !ok {
		err = errors.New("Unable to decrypt key")
		return
	}

	copy(sharedKey[:], buf)
	Zero(buf)

	defer Zero(sharedKey[:])

	// Decrypt the secret itself
	message, ok = secretbox.Open(
		nil,
		s.Message,
		s.Nonce,
		sharedKey)

	if !ok {
		err = errors.New("Unable to decrypt secret")
		return
	}

	return

}

type Key struct {
	Id     string
	Key    []byte
	Nonce  *[24]byte // 24 byte length mandated by NaCL.
	Public *[32]byte
	raw    *[32]byte
}

// Creates a new key
func (k *Key) New(id string) (err error) {
	k.Id = id
	k.Nonce = new([24]byte)
	_, err = io.ReadFull(rand.Reader, k.Nonce[:])
	if err != nil {
		return
	}
	k.Public, k.raw, err = box.GenerateKey(rand.Reader)
	return
}

// Encrypts the key with the master key.
// Requires the master key to be unsealed.
func (k *Key) Encrypt() {
	defer Zero(k.raw[:])
	k.Key = secretbox.Seal(
		nil,
		k.raw[:],
		k.Nonce,
		master)
}

// Decrypts the key with the master key.
// Requires the master key to be unsealed.
func (k *Key) Decrypt() (err error) {
	k.raw = new([32]byte)

	buf, ok := secretbox.Open(
		nil,
		k.Key,
		k.Nonce,
		master)
	if !ok {
		err = errors.New("Unable to decrypt secret")
		return
	}

	copy(k.raw[:], buf)
	Zero(buf)
	return
}

// Show returns a base64-encoded representation of the key for
// end users.
func (k *Key) Display() []byte {
	return encode(k.raw[:])
}

// Zero erases the private portion of a key in memory
func (k *Key) Zero() {
	Zero(k.raw[:])
}

// Zero wipes a byte slice in memory
func Zero(in []byte) {
	for i := range in {
		in[i] ^= in[i]
	}
}

func encode(in []byte) (out []byte) {
	encLen := base64.RawURLEncoding.EncodedLen(len(in))

	out = make([]byte, encLen, encLen)
	base64.RawURLEncoding.Encode(out, in)
	return
}

func decode(in []byte) (out *[32]byte, err error) {
	out = new([32]byte)

	// We can't use out directly as base64 has an irritating
	// habit of appending null bytes.
	buf := make([]byte, base64.RawURLEncoding.DecodedLen(len(in)))

	_, err = base64.RawURLEncoding.Decode(buf, in)
	if err != nil {
		return
	}

	copy(out[:], buf[0:32])
	Zero(buf)
	return
}

func isNull(in []byte) bool {
	for i := range in {
		if in[i] != 0 {
			return false
		}
	}
	return true
}
