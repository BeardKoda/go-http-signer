// Sends a signed POST to the server example (go run ./examples/server).
package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/beardkoda/httpsig-go/examples/internal/demokey"
	"github.com/beardkoda/httpsig-go/httpsig/signer"
)

func main() {
	req, err := http.NewRequest(http.MethodPost, "http://localhost:3000/webhook", bytes.NewBufferString(`{"hello":"world"}`))
	if err != nil {
		log.Fatal(err)
	}

	s := signer.Signer{
		KeyID:      demokey.KeyID,
		Algorithm:  "ed25519",
		PrivateKey: demokey.Private(),
		Components: []string{"@method", "@path", "@authority", "content-digest"},
	}
	if err := s.Sign(req); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Signature-Input:", req.Header.Get("Signature-Input"))
	fmt.Println("Signature:", req.Header.Get("Signature"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("server replied %d: %s\n", resp.StatusCode, body)
}
