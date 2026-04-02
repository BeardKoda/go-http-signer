package verifier

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"net/http"
	"strconv"
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

type Verifier struct {
	KeyStore          KeyStore
	AllowedClockSkew  time.Duration
	ReplayCache       ReplayCache
	DefaultReplayTTL  time.Duration
	DisableBodyDigest bool
	Now               func() time.Time
}

func New(keyStore keys.KeyStore) *Verifier {
	return &Verifier{
		KeyStore:         keyStore,
		AllowedClockSkew: 30 * time.Second,
		DefaultReplayTTL: 5 * time.Minute,
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
	if err := checkTimestamps(input, now, v.AllowedClockSkew); err != nil {
		return false, err
	}

	if err := v.verifyBodyDigest(req); err != nil {
		return false, err
	}

	base, err := canonical.BuildSignatureBase(req, input.Components)
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
		replayID := signatureReplayID(signatureHeader, input.Created)
		if v.ReplayCache.Seen(replayID) {
			return false, fmt.Errorf("replay detected")
		}
		v.ReplayCache.Store(replayID, v.replayTTL(input, now))
	}

	return true, nil
}

func checkTimestamps(input signatureInput, now time.Time, allowedSkew time.Duration) error {
	if input.Created != 0 {
		created := time.Unix(input.Created, 0)
		if created.After(now.Add(allowedSkew)) {
			return fmt.Errorf("signature created time is in the future")
		}
	}
	if input.Expires != 0 {
		expires := time.Unix(input.Expires, 0)
		if now.After(expires.Add(allowedSkew)) {
			return fmt.Errorf("signature expired")
		}
	}
	return nil
}

func signatureReplayID(signatureHeader string, created int64) string {
	return signatureHeader + "|" + strconv.FormatInt(created, 10)
}

func (v *Verifier) replayTTL(input signatureInput, now time.Time) time.Duration {
	if input.Expires > 0 {
		d := time.Until(time.Unix(input.Expires, 0))
		if d > 0 {
			return d
		}
	}
	if v.DefaultReplayTTL > 0 {
		return v.DefaultReplayTTL
	}
	return 5 * time.Minute
}

func (v *Verifier) verifyBodyDigest(req *http.Request) error {
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
	if got == "" {
		return nil
	}
	want := root.ComputeContentDigest(body)
	if got != want {
		return fmt.Errorf("content-digest mismatch")
	}
	return nil
}
