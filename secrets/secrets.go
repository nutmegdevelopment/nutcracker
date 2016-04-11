package secrets

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/pborman/uuid"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

var master *[32]byte

const MasterKeyName = "master"

func init() {
	master = new([32]byte)
}

// Create a new master secret.
func Initialise() (masterKey *Secret, err error) {

	masterKey = new(Secret)

	// We can't use masterKey.New() here
	masterKey.Name = MasterKeyName
	masterKey.Root = true

	if masterKey.newNonce() != nil {
		return
	}

	// Create a new master key
	_, err = io.ReadFull(rand.Reader, master[:])
	if err != nil {
		return
	}

	// Create an encryption key
	err = masterKey.Key.New(MasterKeyName)
	if err != nil {
		return
	}

	// Encrypt the master key
	masterKey.Message = secretbox.Seal(
		nil,
		master[:],
		masterKey.nonce(),
		masterKey.Key.raw)

	return
}

func Unseal(masterKey *Secret, key []byte) (err error) {
	defer Zero(key)

	priv := new([32]byte)
	scopy(priv[:], key)
	defer Zero(priv[:])

	buf, ok := secretbox.Open(
		nil,
		masterKey.Message,
		masterKey.nonce(),
		priv)
	defer Zero(buf)
	if !ok {
		err = errors.New("Unable to decrypt secret")
		return
	}
	scopy(master[:], buf)
	return
}

func Seal() {
	Zero(master[:])
}

func IsSealed() bool {
    if isNull(master[:]) {
		return true
	}
    return false
}

type Secret struct {
	ID      uint   `gorm:"primary_key" json:"-"`
	Name    string `sql:"not null"`
	Message []byte `json:",omitempty"`
	Nonce   []byte `json:"-"`
	Key     Key    `json:",omitempty"`
	Pubkey  []byte `json:"-"`
	KeyID   uint   `json:"-"`
	Root    bool   `json:"-"`
}

func (s *Secret) nonce() *[24]byte {
	nonce := new([24]byte)
	scopy(nonce[:], s.Nonce)
	return nonce
}

func (s *Secret) pubkey() *[32]byte {
	pubkey := new([32]byte)
	scopy(pubkey[:], s.Pubkey)
	return pubkey
}

func (s *Secret) newNonce() error {
	s.Nonce = make([]byte, 24, 24)
	// We generate nonces randomly - chance of collision is negligable
	_, err := io.ReadFull(rand.Reader, s.Nonce)
	return err
}

// New creates a new secret container with a unique key.
// Requires the master key to be unsealed.
func New(name string, message []byte) (s *Secret, err error) {

	if IsSealed() {
		err = errors.New("Please unseal first")
		return
	}

	defer Zero(message)

	if name == MasterKeyName {
		err = errors.New("Cannot create a new master key")
		return
	}

	s = new(Secret)

	// Generate a unique encryption key
	err = s.Key.New(uuid.New())
	if err != nil {
		return
	}

	s.Name = name
	s.Root = true

	return s, s.encrypt(message)
}

func (s *Secret) Update(message []byte) (err error) {
	if IsSealed() {
		err = errors.New("Please unseal first")
		return
	}

	defer Zero(message)

	// Decrypt the unique encryption key
	s.Key.Decrypt()

	return s.encrypt(message)
}

func (s *Secret) encrypt(message []byte) (err error) {
	if s.newNonce() != nil {
		return
	}

	// Encrypt the message and unique key
	s.Message = secretbox.Seal(
		nil,
		message,
		s.nonce(),
		s.Key.raw)

	s.Key.Encrypt()

	return
}

// Share creates a shared key, which the given key can use to decrypt
// the secret.
// Requires the master key to be unsealed.
func (s *Secret) Share(key *Key) (shared *Secret, err error) {
	if IsSealed() {
		err = errors.New("Please unseal first")
		return
	}
	shared = new(Secret)
	shared.Name = s.Name

	shared.Key = *key

	err = s.Key.Decrypt()
	if err != nil {
		return
	}
	defer s.Key.Zero()

	if shared.newNonce() != nil {
		return
	}

	// Generate a public key from the master
	pub := new([32]byte)
	curve25519.ScalarBaseMult(pub, master)

	shared.Pubkey = pub[:]

	shared.Message = box.Seal(
		nil,
		s.Key.raw[:],
		shared.nonce(),
		key.pubkey(),
		master)

	return
}

// Decrypt decrypts a secret given a shared key and a
// secret key provided by the user.
// This does not require the master key to be unsealed.
func (s *Secret) Decrypt(shared *Secret, key []byte) (message []byte, err error) {
	defer Zero(key)

	priv := new([32]byte)
	scopy(priv[:], key)
	defer Zero(priv[:])

	// Decrypt the shared key
	sharedKey := new([32]byte)
	buf, ok := box.Open(
		nil,
		shared.Message,
		shared.nonce(),
		shared.pubkey(),
		priv)

	if !ok {
		err = errors.New("Unable to decrypt key")
		return
	}

	scopy(sharedKey[:], buf)
	Zero(buf)

	defer Zero(sharedKey[:])

	// Decrypt the secret itself
	message, ok = secretbox.Open(
		nil,
		s.Message,
		s.nonce(),
		sharedKey)

	if !ok {
		err = errors.New("Unable to decrypt secret")
		return
	}

	return

}

type Key struct {
	ID       uint   `gorm:"primary_key" json:"-"`
	Name     string `sql:"not null;unique" json:"Id,omitempty"`
	Key      []byte `json:",omitempty"`
	Nonce    []byte `json:"-"`
	Public   []byte `json:"-"`
	ReadOnly bool
	raw      *[32]byte
}

func (k *Key) nonce() *[24]byte {
	nonce := new([24]byte)
	scopy(nonce[:], k.Nonce)
	return nonce
}

func (k *Key) pubkey() *[32]byte {
	pubkey := new([32]byte)
	scopy(pubkey[:], k.Public)
	return pubkey
}

func (k *Key) newNonce() error {
	k.Nonce = make([]byte, 24, 24)
	// We generate nonces randomly - chance of collision is negligable
	_, err := io.ReadFull(rand.Reader, k.Nonce)
	return err
}

// Creates a new key
func (k *Key) New(name string) (err error) {
	k.Name = name
	if k.newNonce() != nil {
		return
	}
	pub := new([32]byte)
	pub, k.raw, err = box.GenerateKey(rand.Reader)
	k.Public = pub[:]
	return
}

// Encrypts the key with the master key.
// Requires the master key to be unsealed.
func (k *Key) Encrypt() {
	defer Zero(k.raw[:])
	k.Key = secretbox.Seal(
		nil,
		k.raw[:],
		k.nonce(),
		master)
}

// Decrypts the key with the master key.
// Requires the master key to be unsealed.
func (k *Key) Decrypt() (err error) {
	k.raw = new([32]byte)

	buf, ok := secretbox.Open(
		nil,
		k.Key,
		k.nonce(),
		master)
	if !ok {
		err = errors.New("Unable to decrypt key")
		return
	}

	scopy(k.raw[:], buf)
	Zero(buf)
	return
}

// Display prints the unexported raw key
func (k *Key) Display() []byte {
	return k.raw[:]
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

func isNull(in []byte) bool {
	for i := range in {
		if in[i] != 0 {
			return false
		}
	}
	return true
}

func scopy(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		if i == len(dst) {
			return
		}
		dst[i] = src[i]
	}
}
