package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestX509(t *testing.T) {

	tlsCert, err := GenCert()
	assert.Nil(t, err, "Should not return error")

	assert.NotEmpty(t, tlsCert.Certificate, "Certificate data not empty")
}
