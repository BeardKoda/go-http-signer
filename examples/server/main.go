package main

import (
	"crypto"
	"log"
	"net/http"

	"github.com/beardkoda/httpsig-go/examples/internal/demokey"
	"github.com/beardkoda/httpsig-go/httpsig/keys"
	hsmw "github.com/beardkoda/httpsig-go/httpsig/middleware"
	"github.com/beardkoda/httpsig-go/httpsig/verifier"
)

func main() {
	v := verifier.New(keys.NewStaticKeyStore(map[string]crypto.PublicKey{
		demokey.KeyID: demokey.Public(),
	}))
	v.ReplayCache = verifier.NewInMemoryReplayCache()

	protected := hsmw.VerifyMiddleware(v, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("verified"))
	}))

	mux := http.NewServeMux()
	mux.Handle("/webhook", protected)

	log.Println("listening on :3000")
	log.Fatal(http.ListenAndServe(":3000", mux))
}
