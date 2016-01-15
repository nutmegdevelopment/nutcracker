package db

import (
	"github.com/nutmegdevelopment/nutcracker/secrets"
)

type DB interface {
	Connect() error
	AddSecret(*secrets.Secret) error
	AddKey(*secrets.Key) error
	GetKey(*secrets.Key) error
	GetRootSecret(*secrets.Secret) error
	GetSharedSecret(*secrets.Secret, *secrets.Key) error
	UpdateSecret(*secrets.Secret) error
}
