package main // import "github.com/nutmegdevelopment/nutcracker"

import (
	"crypto/tls"
	"flag"
	"net/http"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/nutmegdevelopment/nutcracker/db"
	"github.com/nutmegdevelopment/nutcracker/postgres"
	"io/ioutil"
	stdLog "log"
)

var (
	database  db.DB
	viewCount int64
	certID    string
	certKey   string
	certName  string
)

func init() {
	flag.StringVar(&certID, "id", "", "ID to decrypt TLS cert")
	flag.StringVar(&certKey, "key", "", "Key to decrypt TLS cert")
	flag.StringVar(&certName, "cert", "", "Name of TLS cert.  Will use a selfsigned cert if empty")
	flag.Parse()

	database = new(postgres.DB)
}

func addRoutes(r *mux.Router) {
	r.HandleFunc("/health", Health).Methods("GET")
	r.HandleFunc("/auth", Auth).Methods("GET")
	r.HandleFunc("/metrics", Metrics).Methods("GET")
	r.HandleFunc("/initialise", Initialise).Methods("GET")
	r.HandleFunc("/seal", Seal).Methods("GET")
	r.HandleFunc("/unseal", Unseal).Methods("GET")
	r.HandleFunc("/secrets/message", Message).Methods("POST")
	r.HandleFunc("/secrets/key", Key).Methods("POST")
	r.HandleFunc("/secrets/share", Share).Methods("POST")
	r.HandleFunc("/secrets/view", View).Methods("POST")
	r.HandleFunc("/secrets/view/{messageName}", View).Queries("secretid", "", "secretkey", "").Methods("GET")
	r.HandleFunc("/secrets/list/{type}", List).Methods("GET")
	r.HandleFunc("/secrets/list/{type}/{target}", List).Methods("GET")
	r.HandleFunc("/secrets/update", Update).Methods("POST")
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

	if os.Getenv("DEBUG") == "true" {
		log.SetLevel(log.DebugLevel)
	}

	var cert tls.Certificate

	if certName == "" {
		log.Info("Generating self-signed certificate")
		cert, err = GenCert()
	} else {
		log.Info("Using certificate from vault")
		cert, err = GetNutcrackerCert()
	}
	if err != nil {
		log.Fatal(err)
	}

	sock, err := Socket(addr, cert)
	if err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()
	addRoutes(r)

	server := new(http.Server)
	server.ErrorLog = new(stdLog.Logger)
	server.ErrorLog.SetOutput(ioutil.Discard)
	server.Addr = addr
	server.Handler = r
	log.Infof("HTTPS server listening on: %s", addr)
	server.Serve(sock)
}
