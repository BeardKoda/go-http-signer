package keys

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestJWKSUnknownKeyDoesNotRefetchWithinInterval(t *testing.T) {
	t.Parallel()

	pub, _, _ := ed25519.GenerateKey(nil)
	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		fmt.Fprintf(w, `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":%q}]}`,
			base64.RawURLEncoding.EncodeToString(pub))
	}))
	defer srv.Close()

	s := NewJWKSKeyStore(srv.URL, time.Minute)
	s.MinRefreshInterval = time.Hour

	if _, err := s.GetKey("k1"); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		if _, err := s.GetKey(fmt.Sprintf("unknown-%d", i)); !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("expected ErrKeyNotFound, got %v", err)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("expected 1 fetch, got %d", got)
	}
}

func TestJWKSServesStaleKeysWhenRefreshFails(t *testing.T) {
	t.Parallel()

	pub, _, _ := ed25519.GenerateKey(nil)
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintf(w, `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":%q}]}`,
			base64.RawURLEncoding.EncodeToString(pub))
	}))
	defer srv.Close()

	s := NewJWKSKeyStore(srv.URL, time.Nanosecond)
	s.MinRefreshInterval = time.Nanosecond
	if _, err := s.GetKey("k1"); err != nil {
		t.Fatal(err)
	}

	fail.Store(true)
	time.Sleep(time.Millisecond)
	if _, err := s.GetKey("k1"); err != nil {
		t.Fatalf("expected stale key during outage, got %v", err)
	}
}

func TestParseJWKRejectsOversizedExponent(t *testing.T) {
	t.Parallel()

	_, err := parseJWK(jwk{
		KTY: "RSA",
		N:   base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}),
		E:   base64.RawURLEncoding.EncodeToString(make([]byte, 9)),
	})
	if err == nil {
		t.Fatal("expected error for oversized exponent")
	}
}
