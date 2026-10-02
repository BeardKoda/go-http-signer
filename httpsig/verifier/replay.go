package verifier

import (
	"sync"
	"time"
)

// ReplayCache remembers signatures that have already been accepted.
type ReplayCache interface {
	// SeenOrStore reports whether id was already stored and unexpired. If it
	// was not, it stores id for ttl. The check and the store must be atomic,
	// otherwise two concurrent copies of one request can both be accepted.
	SeenOrStore(id string, ttl time.Duration) bool
}

type InMemoryReplayCache struct {
	mu    sync.Mutex
	items map[string]time.Time
	Now   func() time.Time
}

func NewInMemoryReplayCache() *InMemoryReplayCache {
	return &InMemoryReplayCache{items: map[string]time.Time{}}
}

func (c *InMemoryReplayCache) SeenOrStore(id string, ttl time.Duration) bool {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.items == nil {
		c.items = map[string]time.Time{}
	}
	c.gcLocked(now)
	if exp, ok := c.items[id]; ok && now.Before(exp) {
		return true
	}
	c.items[id] = now.Add(ttl)
	return false
}

func (c *InMemoryReplayCache) gcLocked(now time.Time) {
	for k, exp := range c.items {
		if now.After(exp) {
			delete(c.items, k)
		}
	}
}
