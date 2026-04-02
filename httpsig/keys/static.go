package keys

import (
	"crypto"
	"fmt"
	"sync"
)

type StaticKeyStore struct {
	mu   sync.RWMutex
	keys map[string]crypto.PublicKey
}

func NewStaticKeyStore(keys map[string]crypto.PublicKey) *StaticKeyStore {
	cp := make(map[string]crypto.PublicKey, len(keys))
	for k, v := range keys {
		cp[k] = v
	}
	return &StaticKeyStore{keys: cp}
}

func (s *StaticKeyStore) GetKey(keyID string) (crypto.PublicKey, error) {
	s.mu.RLock()
	key, ok := s.keys[keyID]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}
	return key, nil
}

func (s *StaticKeyStore) SetKey(keyID string, key crypto.PublicKey) {
	s.mu.Lock()
	if s.keys == nil {
		s.keys = map[string]crypto.PublicKey{}
	}
	s.keys[keyID] = key
	s.mu.Unlock()
}
