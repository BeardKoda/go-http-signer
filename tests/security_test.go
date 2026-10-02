package tests

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beardkoda/httpsig-go/httpsig"
	"github.com/beardkoda/httpsig-go/httpsig/keys"
	"github.com/beardkoda/httpsig-go/httpsig/signer"
	"github.com/beardkoda/httpsig-go/httpsig/verifier"
)

var signedAt = time.Unix(1_700_000_000, 0)

type fixture struct {
	signer   signer.Signer
	verifier *verifier.Verifier
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	v := verifier.New(keys.NewStaticKeyStore(map[string]crypto.PublicKey{"k1": pub}))
	v.Now = func() time.Time { return signedAt.Add(10 * time.Second) }
	return fixture{
		signer: signer.Signer{
			KeyID:      "k1",
			Algorithm:  "ed25519",
			PrivateKey: priv,
			Components: []string{"@method", "@path", "@authority"},
			Now:        func() time.Time { return signedAt },
		},
		verifier: v,
	}
}

func (f fixture) signedRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/payments", r)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.signer.Sign(req); err != nil {
		t.Fatal(err)
	}
	return req
}

func expectRejected(t *testing.T, v *verifier.Verifier, req *http.Request, wantErr string) {
	t.Helper()
	ok, err := v.Verify(req)
	if ok || err == nil {
		t.Fatalf("expected rejection containing %q, got ok=%v err=%v", wantErr, ok, err)
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("expected error containing %q, got %v", wantErr, err)
	}
}

func TestSignatureParamsAreCovered(t *testing.T) {
	t.Parallel()

	cases := map[string]func(string) string{
		"created stripped": func(in string) string {
			return strings.Replace(in, ";created=1700000000", "", 1)
		},
		"created moved forward": func(in string) string {
			return strings.Replace(in, "created=1700000000", "created=1700000005", 1)
		},
		"keyid swapped": func(in string) string {
			return strings.Replace(in, `keyid="k1"`, `keyid="k2"`, 1)
		},
		"component dropped": func(in string) string {
			return strings.Replace(in, ` "@authority"`, "", 1)
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			f.verifier.KeyStore = keys.NewStaticKeyStore(map[string]crypto.PublicKey{
				"k1": f.signer.PrivateKey.(ed25519.PrivateKey).Public(),
				"k2": f.signer.PrivateKey.(ed25519.PrivateKey).Public(),
			})
			// Missing created is allowed here so the test proves the
			// signature itself, not the policy, catches the change.
			f.verifier.AllowMissingCreated = true

			req := f.signedRequest(t, "")
			req.Header.Set("Signature-Input", tamper(req.Header.Get("Signature-Input")))
			expectRejected(t, f.verifier, req, "signature verification failed")
		})
	}
}

func TestMissingCreatedRejectedByDefault(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	req := f.signedRequest(t, "")
	req.Header.Set("Signature-Input", strings.Replace(req.Header.Get("Signature-Input"), ";created=1700000000", "", 1))
	expectRejected(t, f.verifier, req, "no created parameter")
}

func TestOldSignatureRejected(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.verifier.Now = func() time.Time { return signedAt.Add(verifier.DefaultMaxAge + time.Minute) }
	expectRejected(t, f.verifier, f.signedRequest(t, ""), "too old")
}

func TestExpiresHonoured(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.signer.Expiry = 5 * time.Second
	f.verifier.AllowedClockSkew = 0
	expectRejected(t, f.verifier, f.signedRequest(t, ""), "expired")
}

func TestBodyDigestEnforced(t *testing.T) {
	t.Parallel()

	t.Run("signer covers digest even if not requested", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		req := f.signedRequest(t, `{"amount":100}`)
		if !strings.Contains(req.Header.Get("Signature-Input"), `"content-digest"`) {
			t.Fatalf("content-digest not covered: %s", req.Header.Get("Signature-Input"))
		}
		if ok, err := f.verifier.Verify(req); !ok || err != nil {
			t.Fatalf("verify failed: ok=%v err=%v", ok, err)
		}
		body, _ := io.ReadAll(req.Body)
		if string(body) != `{"amount":100}` {
			t.Fatalf("body not restored after verify: %q", body)
		}
	})

	t.Run("body swapped and digest header removed", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		req := f.signedRequest(t, `{"amount":100}`)
		req.Body = io.NopCloser(bytes.NewBufferString(`{"amount":999999}`))
		req.Header.Del("content-digest")
		expectRejected(t, f.verifier, req, "no content-digest header")
	})

	t.Run("body swapped with matching digest", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		req := f.signedRequest(t, `{"amount":100}`)
		forged := `{"amount":999999}`
		req.Body = io.NopCloser(strings.NewReader(forged))
		req.Header.Set("content-digest", httpsig.ComputeContentDigest([]byte(forged)))
		expectRejected(t, f.verifier, req, "signature verification failed")
	})

	t.Run("digest present but not signed", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		// Sign without a body, then attach one with a valid digest.
		req := f.signedRequest(t, "")
		req.Body = io.NopCloser(strings.NewReader(`{"amount":1}`))
		req.Header.Set("content-digest", httpsig.ComputeContentDigest([]byte(`{"amount":1}`)))
		expectRejected(t, f.verifier, req, "not covered by the signature")
	})
}

func TestConcurrentReplayAcceptedOnce(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.verifier.ReplayCache = verifier.NewInMemoryReplayCache()
	req := f.signedRequest(t, "")

	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := req.Clone(req.Context())
			if ok, _ := f.verifier.Verify(r); ok {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := accepted.Load(); got != 1 {
		t.Fatalf("expected exactly one acceptance, got %d", got)
	}
}
