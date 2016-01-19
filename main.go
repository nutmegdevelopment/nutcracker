package main

import (
	"crypto/tls"
	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/nutmegdevelopment/nutcracker/db"
	"github.com/nutmegdevelopment/nutcracker/postgres"
	"net/http"
	"os"
)

var database db.DB

func init() {
	database = new(postgres.DB)
}

func main() {
	err := database.Connect()
	if err != nil {
		log.Fatal(err)
	}

	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = "0.0.0.0:8443"
	}

	keyFile := os.Getenv("SSL_KEY")
	certFile := os.Getenv("SSL_CERT")

	var cert tls.Certificate

	if keyFile == "" && certFile == "" {
		cert, err = GenCert()
	} else {
		cert, err = LoadCert(certFile, keyFile)
	}
	if err != nil {
		log.Fatal(err)
	}

	sock, err := Socket(addr, cert)
	if err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/health", Health).Methods("GET")
	r.HandleFunc("/initialise", Initialise).Methods("GET")
	r.HandleFunc("/seal", Seal).Methods("GET")
	r.HandleFunc("/unseal", Unseal).Methods("GET")
	r.HandleFunc("/secrets/message", Message).Methods("POST")
	r.HandleFunc("/secrets/key", Key).Methods("POST")
	r.HandleFunc("/secrets/share", Share).Methods("POST")
	r.HandleFunc("/secrets/view", View).Methods("POST")
	r.HandleFunc("/secrets/update", Update).Methods("POST")

	server := new(http.Server)
	server.Addr = addr
	server.Handler = r
	log.Error(server.Serve(sock))
}
