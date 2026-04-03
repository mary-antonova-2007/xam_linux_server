package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string]*entry
}

type entry struct {
	count    int
	deadline time.Time
}

func New(limit int, window time.Duration) *Limiter {
	return &Limiter{
		limit:   limit,
		window:  window,
		entries: make(map[string]*entry),
	}
}

func (l *Limiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	item, ok := l.entries[key]
	if !ok || now.After(item.deadline) {
		l.entries[key] = &entry{
			count:    1,
			deadline: now.Add(l.window),
		}
		return true
	}

	if item.count >= l.limit {
		return false
	}

	item.count++
	return true
}
