// Verifies webhooks without middleware. Point the client example at
// http://localhost:8080/webhook to exercise it.
package main

import (
	"crypto"
	"fmt"
	"log"
	"net/http"

	"github.com/beardkoda/httpsig-go/examples/internal/demokey"
	"github.com/beardkoda/httpsig-go/httpsig/keys"
	"github.com/beardkoda/httpsig-go/httpsig/verifier"
)

func main() {
	v := verifier.New(keys.NewStaticKeyStore(map[string]crypto.PublicKey{
		demokey.KeyID: demokey.Public(),
	}))
	v.ReplayCache = verifier.NewInMemoryReplayCache()

	http.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		ok, err := v.Verify(r)
		if err != nil || !ok {
			log.Printf("rejected webhook: %v", err)
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		fmt.Fprintln(w, "webhook accepted")
	})

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
