package main

import (
	"crypto"
	"crypto/ed25519"
	"log"
	"net/http"

	"github.com/beardkoda/httpsig-go/httpsig/keys"
	hsmw "github.com/beardkoda/httpsig-go/httpsig/middleware"
	"github.com/beardkoda/httpsig-go/httpsig/verifier"
)

func main() {
	pub, _, _ := ed25519.GenerateKey(nil)

	v := verifier.New(keys.NewStaticKeyStore(map[string]crypto.PublicKey{
		"example-key": pub,
	}))

	protected := hsmw.VerifyMiddleware(v, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("verified"))
	}))

	mux := http.NewServeMux()
	mux.Handle("/webhook", protected)

	log.Println("listening on :3000")
	log.Fatal(http.ListenAndServe(":3000", mux))
}
