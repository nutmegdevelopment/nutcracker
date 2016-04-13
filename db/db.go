package db

import (
	"github.com/nutmegdevelopment/nutcracker/secrets"
)

// DB is a generic database interface. 
type DB interface {
	Connect() error
	AddSecret(*secrets.Secret) error
	AddKey(*secrets.Key) error
	GetKey(*secrets.Key) error
	GetRootSecret(*secrets.Secret) error
	GetSharedSecret(*secrets.Secret, *secrets.Key) error
    ListSecrets(*string) (func(int) ([]secrets.Secret, error))
    ListKeys(*string) (func(int) ([]secrets.Key, error))
	UpdateSecret(*secrets.Secret) error
    Ping() error
    Metrics() (map[string]interface{}, error)
}
