package algorithms

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
)

type RSAPSSSHA512Algorithm struct{}

func (a RSAPSSSHA512Algorithm) Name() string { return "rsa-pss-sha512" }

func (a RSAPSSSHA512Algorithm) Sign(data []byte, privateKey crypto.PrivateKey) ([]byte, error) {
	key, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: expected rsa private key", ErrInvalidKeyType)
	}
	sum := sha512.Sum512(data)
	return rsa.SignPSS(rand.Reader, key, crypto.SHA512, sum[:], nil)
}

func (a RSAPSSSHA512Algorithm) Verify(data []byte, sig []byte, publicKey crypto.PublicKey) error {
	key, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: expected rsa public key", ErrInvalidKeyType)
	}
	sum := sha512.Sum512(data)
	if err := rsa.VerifyPSS(key, crypto.SHA512, sum[:], sig, nil); err != nil {
		return fmt.Errorf("signature verification failed for %s: %w", a.Name(), err)
	}
	return nil
}
