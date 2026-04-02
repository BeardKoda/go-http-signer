package internal

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func ParsePrivateKeyPEM(data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM private key")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch k := key.(type) {
		case *rsa.PrivateKey, ed25519.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported private key type %T", k)
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("failed parsing private key")
}

func ParsePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM public key")
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		switch p := pub.(type) {
		case *rsa.PublicKey, ed25519.PublicKey:
			return p, nil
		default:
			return nil, fmt.Errorf("unsupported public key type %T", p)
		}
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		return cert.PublicKey, nil
	}
	return nil, fmt.Errorf("failed parsing public key")
}
