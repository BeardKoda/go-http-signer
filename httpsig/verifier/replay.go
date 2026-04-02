package verifier

import (
	"sync"
	"time"
)

type ReplayCache interface {
	Seen(id string) bool
	Store(id string, ttl time.Duration)
}

type InMemoryReplayCache struct {
	mu    sync.Mutex
	items map[string]time.Time
}

func NewInMemoryReplayCache() *InMemoryReplayCache {
	return &InMemoryReplayCache{items: map[string]time.Time{}}
}

func (c *InMemoryReplayCache) Seen(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gcLocked()
	exp, ok := c.items[id]
	return ok && time.Now().Before(exp)
}

func (c *InMemoryReplayCache) Store(id string, ttl time.Duration) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	c.mu.Lock()
	c.gcLocked()
	c.items[id] = time.Now().Add(ttl)
	c.mu.Unlock()
}

func (c *InMemoryReplayCache) gcLocked() {
	now := time.Now()
	for k, exp := range c.items {
		if now.After(exp) {
			delete(c.items, k)
		}
	}
}
