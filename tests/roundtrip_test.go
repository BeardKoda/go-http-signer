package tests

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"

	"github.com/beardkoda/httpsig-go/httpsig/keys"
	"github.com/beardkoda/httpsig-go/httpsig/signer"
	"github.com/beardkoda/httpsig-go/httpsig/verifier"
)

func TestSigningVerificationRoundTrip(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/webhook", bytes.NewBufferString(`{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}

	s := signer.Signer{
		KeyID:      "k1",
		Algorithm:  "ed25519",
		PrivateKey: priv,
		Components: []string{"@method", "@path", "@authority", "content-digest"},
		Now: func() time.Time {
			return time.Unix(1_700_000_000, 0)
		},
	}
	if err := s.Sign(req); err != nil {
		t.Fatal(err)
	}

	v := verifier.New(keys.NewStaticKeyStore(map[string]crypto.PublicKey{"k1": pub}))
	ok, err := v.Verify(req)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected signature to be valid")
	}
}

func TestInvalidSignatureRejected(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	if err != nil {
		t.Fatal(err)
	}

	s := signer.Signer{
		KeyID:      "k1",
		Algorithm:  "ed25519",
		PrivateKey: priv,
		Components: []string{"@method", "@path", "@authority"},
	}
	if err := s.Sign(req); err != nil {
		t.Fatal(err)
	}
	req.Header.Set("signature", "sig1=:ZmFrZQ==:")

	v := verifier.New(keys.NewStaticKeyStore(map[string]crypto.PublicKey{"k1": pub}))
	ok, err := v.Verify(req)
	if err == nil || ok {
		t.Fatal("expected invalid signature error")
	}
}

func TestReplayAttackRejected(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1", nil)
	if err != nil {
		t.Fatal(err)
	}

	s := signer.Signer{
		KeyID:      "k1",
		Algorithm:  "ed25519",
		PrivateKey: priv,
		Components: []string{"@method", "@path", "@authority"},
	}
	if err := s.Sign(req); err != nil {
		t.Fatal(err)
	}

	v := verifier.New(keys.NewStaticKeyStore(map[string]crypto.PublicKey{"k1": pub}))
	v.ReplayCache = verifier.NewInMemoryReplayCache()

	ok, err := v.Verify(req)
	if err != nil || !ok {
		t.Fatalf("first verify failed: ok=%v err=%v", ok, err)
	}
	ok, err = v.Verify(req)
	if err == nil || ok {
		t.Fatal("expected replay to be rejected")
	}
}
