package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net/http"

	"github.com/beardkoda/httpsig-go/httpsig/signer"
)

func main() {
	_, priv, _ := ed25519.GenerateKey(nil)
	req, _ := http.NewRequest(http.MethodPost, "http://localhost:3000/webhook", bytes.NewBufferString(`{"hello":"world"}`))

	s := signer.Signer{
		KeyID:      "example-key",
		Algorithm:  "ed25519",
		PrivateKey: priv,
		Components: []string{"@method", "@path", "@authority", "content-digest"},
	}
	_ = s.Sign(req)

	fmt.Println("Signature-Input:", req.Header.Get("Signature-Input"))
	fmt.Println("Signature:", req.Header.Get("Signature"))
}
