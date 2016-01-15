package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"
)

var ciphers = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}

func newCert(key *ecdsa.PrivateKey) (cert *x509.Certificate, err error) {
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "nutcracker",
		},
		NotBefore:          time.Now().Add(-5 * time.Minute).UTC(),
		NotAfter:           time.Now().AddDate(1, 0, 0).UTC(),
		KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return
	}
	return x509.ParseCertificate(derBytes)
}

func newKey() (key *ecdsa.PrivateKey, err error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenCert creates a self-signed TLS cert.
func GenCert() (tlsCert tls.Certificate, err error) {
	key, err := newKey()
	if err != nil {
		return
	}

	cert, err := newCert(key)
	if err != nil {
		return
	}

	certBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if certBytes == nil {
		err = errors.New("Unable to encode cert")
		return
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return
	}

	keyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: der,
	})
	if keyBytes == nil {
		err = errors.New("Unable to encode key")
		return
	}

	return tls.X509KeyPair(certBytes, keyBytes)
}

// Loads a cert from disk, given paths to the cert and key.
func LoadCert(cert, key string) (tlsCert tls.Certificate, err error) {
	return tls.LoadX509KeyPair(cert, key)
}

// Creates a TLs socket
func Socket(address string, cert tls.Certificate) (socket net.Listener, err error) {
	cfg := &tls.Config{
		Rand:                     nil, // Use crypto/rand
		CipherSuites:             ciphers,
		SessionTicketsDisabled:   false,
		ClientAuth:               tls.NoClientCert,
		PreferServerCipherSuites: true,
	}

	cfg.Certificates = make([]tls.Certificate, 1)
	cfg.Certificates[0] = cert

	return tls.Listen("tcp", address, cfg)
}
