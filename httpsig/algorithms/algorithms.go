package algorithms

import (
	"crypto"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Algorithm signs and verifies HTTP signature base bytes.
type Algorithm interface {
	Sign(data []byte, privateKey crypto.PrivateKey) ([]byte, error)
	Verify(data []byte, sig []byte, publicKey crypto.PublicKey) error
	Name() string
}

var (
	registryMu sync.RWMutex
	registry   = map[string]Algorithm{}
)

func RegisterAlgorithm(name string, algo Algorithm) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" || algo == nil {
		return
	}

	registryMu.Lock()
	registry[n] = algo
	registryMu.Unlock()
}

func GetAlgorithm(name string) (Algorithm, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		n = "ed25519"
	}

	registryMu.RLock()
	algo, ok := registry[n]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("algorithm %q not registered", n)
	}
	return algo, nil
}

func init() {
	RegisterAlgorithm("ed25519", Ed25519Algorithm{})
	RegisterAlgorithm("rsa-pss-sha512", RSAPSSSHA512Algorithm{})
	RegisterAlgorithm("rsa-pss", RSAPSSSHA512Algorithm{})
}

var ErrInvalidKeyType = errors.New("invalid key type")
