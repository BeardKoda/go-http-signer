package verifier

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	root "github.com/beardkoda/httpsig-go/httpsig"
	"github.com/beardkoda/httpsig-go/httpsig/algorithms"
	"github.com/beardkoda/httpsig-go/httpsig/canonical"
	"github.com/beardkoda/httpsig-go/httpsig/keys"
)

type KeyStore interface {
	GetKey(keyID string) (crypto.PublicKey, error)
}

// DefaultMaxAge is how long after its created time a signature is accepted
// when Verifier.MaxAge is zero.
const DefaultMaxAge = 5 * time.Minute

type Verifier struct {
	KeyStore         KeyStore
	AllowedClockSkew time.Duration
	// MaxAge bounds how old a signature may be, measured from its created
	// parameter. Zero means DefaultMaxAge.
	MaxAge time.Duration
	// AllowMissingCreated accepts signatures without a created parameter.
	// Such signatures have no age limit, so only enable this together with
	// an expires-based policy you control.
	AllowMissingCreated bool
	ReplayCache         ReplayCache
	// DisableBodyDigest skips the content-digest check. When it is false,
	// any request with a body must carry a matching content-digest header
	// that is listed among the signed components.
	DisableBodyDigest bool
	Now               func() time.Time
}

func New(keyStore keys.KeyStore) *Verifier {
	return &Verifier{
		KeyStore:         keyStore,
		AllowedClockSkew: 30 * time.Second,
		MaxAge:           DefaultMaxAge,
	}
}

func (v *Verifier) Verify(req *http.Request) (bool, error) {
	if req == nil {
		return false, fmt.Errorf("request is required")
	}
	if v.KeyStore == nil {
		return false, fmt.Errorf("keystore is required")
	}

	inputHeader := req.Header.Get("Signature-Input")
	signatureHeader := req.Header.Get("Signature")
	if strings.TrimSpace(inputHeader) == "" || strings.TrimSpace(signatureHeader) == "" {
		return false, fmt.Errorf("missing signature headers")
	}

	input, err := parseSignatureInput(inputHeader)
	if err != nil {
		return false, err
	}
	sig, err := parseSignature(signatureHeader, input.Label)
	if err != nil {
		return false, err
	}

	nowFn := v.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn()
	if err := v.checkTimestamps(input, now); err != nil {
		return false, err
	}

	if err := v.verifyBodyDigest(req, input.Components); err != nil {
		return false, err
	}

	base, err := canonical.BuildSignatureBase(req, input.Components, input.Params)
	if err != nil {
		return false, err
	}

	pub, err := v.KeyStore.GetKey(input.KeyID)
	if err != nil {
		return false, err
	}
	algo, err := algorithms.GetAlgorithm(input.Algorithm)
	if err != nil {
		return false, err
	}
	if err := algo.Verify([]byte(base), sig, pub); err != nil {
		return false, err
	}

	if v.ReplayCache != nil {
		// The signature bytes cover every parameter, so they identify the
		// signed message uniquely.
		if v.ReplayCache.SeenOrStore(string(sig), v.replayTTL(input, now)) {
			return false, fmt.Errorf("replay detected")
		}
	}

	return true, nil
}

func (v *Verifier) maxAge() time.Duration {
	if v.MaxAge > 0 {
		return v.MaxAge
	}
	return DefaultMaxAge
}

func (v *Verifier) checkTimestamps(input signatureInput, now time.Time) error {
	skew := v.AllowedClockSkew
	if input.Created == 0 {
		if !v.AllowMissingCreated {
			return fmt.Errorf("signature has no created parameter")
		}
	} else {
		created := time.Unix(input.Created, 0)
		if created.After(now.Add(skew)) {
			return fmt.Errorf("signature created time is in the future")
		}
		if now.After(created.Add(v.maxAge() + skew)) {
			return fmt.Errorf("signature too old")
		}
	}
	if input.Expires != 0 {
		expires := time.Unix(input.Expires, 0)
		if now.After(expires.Add(skew)) {
			return fmt.Errorf("signature expired")
		}
	}
	return nil
}

// replayTTL keeps a signature in the replay cache for as long as
// checkTimestamps would still accept it.
func (v *Verifier) replayTTL(input signatureInput, now time.Time) time.Duration {
	var until time.Time
	if input.Created != 0 {
		until = time.Unix(input.Created, 0).Add(v.maxAge())
	}
	if input.Expires != 0 {
		if exp := time.Unix(input.Expires, 0); until.IsZero() || exp.Before(until) {
			until = exp
		}
	}
	if until.IsZero() {
		// No created and no expires: the signature never ages out, so the
		// best the cache can do is remember it for a long time.
		return 24 * time.Hour
	}
	return until.Add(v.AllowedClockSkew).Sub(now) + time.Second
}

func (v *Verifier) verifyBodyDigest(req *http.Request, components []string) error {
	if v.DisableBodyDigest {
		return nil
	}
	if req.Body == nil {
		return nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	got := strings.TrimSpace(req.Header.Get("content-digest"))
	if len(body) == 0 && got == "" {
		return nil
	}
	if got == "" {
		return fmt.Errorf("request has a body but no content-digest header")
	}
	if !slices.Contains(components, "content-digest") {
		return fmt.Errorf("content-digest is not covered by the signature")
	}
	want := root.ComputeContentDigest(body)
	if got != want {
		return fmt.Errorf("content-digest mismatch")
	}
	return nil
}
