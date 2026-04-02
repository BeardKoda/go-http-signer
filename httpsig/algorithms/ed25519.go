package algorithms

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
)

type Ed25519Algorithm struct{}

func (a Ed25519Algorithm) Name() string { return "ed25519" }

func (a Ed25519Algorithm) Sign(data []byte, privateKey crypto.PrivateKey) ([]byte, error) {
	key, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: expected ed25519 private key", ErrInvalidKeyType)
	}
	return ed25519.Sign(key, data), nil
}

func (a Ed25519Algorithm) Verify(data []byte, sig []byte, publicKey crypto.PublicKey) error {
	key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("%w: expected ed25519 public key", ErrInvalidKeyType)
	}
	if !ed25519.Verify(key, data, sig) {
		return fmt.Errorf("signature verification failed for %s", a.Name())
	}
	return nil
}
