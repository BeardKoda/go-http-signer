package main

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"net/http"

	"github.com/beardkoda/httpsig-go/httpsig/keys"
	"github.com/beardkoda/httpsig-go/httpsig/verifier"
)

func main() {
	pub, _, _ := ed25519.GenerateKey(nil)
	v := verifier.New(keys.NewStaticKeyStore(map[string]crypto.PublicKey{
		"example-key": pub,
	}))

	http.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		ok, err := v.Verify(r)
		if err != nil || !ok {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		fmt.Fprintln(w, "webhook accepted")
	})

	_ = http.ListenAndServe(":8080", nil)
}
