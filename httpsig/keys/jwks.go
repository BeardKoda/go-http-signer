package keys

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// maxJWKSBytes caps the size of a JWKS response body.
const maxJWKSBytes = 1 << 20

type JWKSKeyStore struct {
	URL    string
	TTL    time.Duration
	Client *http.Client
	// MinRefreshInterval is the minimum time between fetches. It stops
	// requests carrying unknown key IDs from hammering the JWKS endpoint.
	// Zero means 30 seconds.
	MinRefreshInterval time.Duration

	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey
	expiresAt time.Time

	refreshMu   sync.Mutex
	lastAttempt time.Time
	lastErr     error
}

func NewJWKSKeyStore(url string, ttl time.Duration) *JWKSKeyStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &JWKSKeyStore{
		URL:  url,
		TTL:  ttl,
		keys: map[string]crypto.PublicKey{},
	}
}

func (s *JWKSKeyStore) GetKey(keyID string) (crypto.PublicKey, error) {
	// Fast path: cached key exists and cache is still valid.
	if key, ok, expired := s.cached(keyID); ok && !expired {
		return key, nil
	}

	// One refresh at a time; callers that waited re-check the cache first.
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	key, ok, expired := s.cached(keyID)
	if ok && !expired {
		return key, nil
	}

	minInterval := s.MinRefreshInterval
	if minInterval <= 0 {
		minInterval = 30 * time.Second
	}
	if time.Since(s.lastAttempt) >= minInterval {
		s.lastAttempt = time.Now()
		s.lastErr = s.refresh(context.Background())
		key, ok, _ = s.cached(keyID)
	}

	// On a failed refresh, keep serving the last good key set.
	if ok {
		return key, nil
	}
	if s.lastErr != nil {
		return nil, s.lastErr
	}
	return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
}

func (s *JWKSKeyStore) cached(keyID string) (key crypto.PublicKey, ok, expired bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok = s.keys[keyID]
	return key, ok, time.Now().After(s.expiresAt)
}

func (s *JWKSKeyStore) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return fmt.Errorf("build jwks request: %w", err)
	}

	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("fetch jwks: status %d", resp.StatusCode)
	}

	var set jwksSet
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&set); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}

	parsed := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		pub, err := parseJWK(k)
		if err != nil {
			continue
		}
		parsed[k.KID] = pub
	}

	s.mu.Lock()
	s.keys = parsed
	s.expiresAt = time.Now().Add(s.TTL)
	s.mu.Unlock()
	return nil
}

type jwksSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	KTY string `json:"kty"`
	KID string `json:"kid"`
	ALG string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	CRV string `json:"crv"`
	X   string `json:"x"`
}

func parseJWK(k jwk) (crypto.PublicKey, error) {
	switch strings.ToUpper(k.KTY) {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("decode rsa n: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("decode rsa e: %w", err)
		}
		if len(eBytes) == 0 || len(eBytes) > 4 {
			return nil, errors.New("invalid rsa exponent")
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		if e == 0 {
			return nil, errors.New("invalid rsa exponent")
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: e,
		}, nil
	case "OKP":
		if !strings.EqualFold(k.CRV, "Ed25519") {
			return nil, fmt.Errorf("unsupported okp curve %q", k.CRV)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("decode okp x: %w", err)
		}
		if len(xBytes) != ed25519.PublicKeySize {
			return nil, errors.New("invalid ed25519 public key size")
		}
		return ed25519.PublicKey(xBytes), nil
	default:
		return nil, fmt.Errorf("unsupported kty %q", k.KTY)
	}
}
