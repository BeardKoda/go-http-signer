package tests

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"net/http"
	"testing"

	"github.com/beardkoda/httpsig-go/httpsig/keys"
	"github.com/beardkoda/httpsig-go/httpsig/signer"
	"github.com/beardkoda/httpsig-go/httpsig/verifier"
)

func BenchmarkSigning(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_ = pub

	s := signer.Signer{
		KeyID:      "k1",
		Algorithm:  "ed25519",
		PrivateKey: priv,
		Components: []string{"@method", "@path", "@authority", "content-digest"},
	}
	body := []byte(`{"benchmark":true}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/bench", bytes.NewReader(body))
		if err := s.Sign(req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerification(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	s := signer.Signer{
		KeyID:      "k1",
		Algorithm:  "ed25519",
		PrivateKey: priv,
		Components: []string{"@method", "@path", "@authority", "content-digest"},
	}
	v := verifier.New(keys.NewStaticKeyStore(map[string]crypto.PublicKey{"k1": pub}))

	body := []byte(`{"benchmark":true}`)
	req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/bench", bytes.NewReader(body))
	if err := s.Sign(req); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := v.Verify(req)
		if err != nil || !ok {
			b.Fatalf("verify failed: ok=%v err=%v", ok, err)
		}
	}
}
