package db

import (
	"github.com/nutmegdevelopment/nutcracker/secrets"
)

type DB interface {
	Connect() error
	AddSecret(*secrets.Secret) error
	AddKey(*secrets.Key) error
	GetKey(*secrets.Key) error
	GetSecrets(*secrets.Secret) ([]secrets.Secret, error)
	UpdateSecret(*secrets.Secret) error
}
