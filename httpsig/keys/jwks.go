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
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

type JWKSKeyStore struct {
	URL    string
	TTL    time.Duration
	Client *http.Client

	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey
	expiresAt time.Time
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
	s.mu.RLock()
	key, ok := s.keys[keyID]
	expired := time.Now().After(s.expiresAt)
	s.mu.RUnlock()
	if ok && !expired {
		return key, nil
	}

	if err := s.refresh(context.Background()); err != nil {
		return nil, err
	}

	s.mu.RLock()
	key, ok = s.keys[keyID]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}
	return key, nil
}

func (s *JWKSKeyStore) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return fmt.Errorf("build jwks request: %w", err)
	}

	client := s.Client
	if client == nil {
		client = http.DefaultClient
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
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
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
