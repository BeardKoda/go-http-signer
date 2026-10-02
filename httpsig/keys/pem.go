package keys

import (
	"crypto"

	"github.com/beardkoda/httpsig-go/httpsig/internal"
)

// ParsePrivateKeyPEM parses a PKCS#8 (RSA or Ed25519) or PKCS#1 (RSA)
// private key.
func ParsePrivateKeyPEM(data []byte) (crypto.PrivateKey, error) {
	return internal.ParsePrivateKeyPEM(data)
}

// ParsePublicKeyPEM parses a PKIX public key or an X.509 certificate.
func ParsePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	return internal.ParsePublicKeyPEM(data)
}
