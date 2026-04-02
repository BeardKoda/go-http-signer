package keys

import (
	"crypto"
	"errors"
)

type KeyStore interface {
	GetKey(keyID string) (crypto.PublicKey, error)
}

var ErrKeyNotFound = errors.New("key not found")
