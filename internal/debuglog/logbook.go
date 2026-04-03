package debuglog

import (
	"log/slog"
	"sync"
	"time"
)

type Entry struct {
	Timestamp time.Time      `json:"timestamp"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields,omitempty"`
}

type LogBook struct {
	mu      sync.RWMutex
	entries []Entry
	next    int
	full    bool
}

func New(capacity int) *LogBook {
	if capacity <= 0 {
		capacity = 200
	}
	return &LogBook{entries: make([]Entry, capacity)}
}

func (b *LogBook) Add(level slog.Level, message string, fields map[string]any) {
	if b == nil || len(b.entries) == 0 {
		return
	}
	entry := Entry{
		Timestamp: time.Now().UTC(),
		Level:     level.String(),
		Message:   message,
		Fields:    cloneFields(fields),
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.entries[b.next] = entry
	b.next = (b.next + 1) % len(b.entries)
	if b.next == 0 {
		b.full = true
	}
}

func (b *LogBook) List(limit int) []Entry {
	if b == nil {
		return nil
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	total := b.next
	if b.full {
		total = len(b.entries)
	}
	if total == 0 {
		return []Entry{}
	}
	if limit <= 0 || limit > total {
		limit = total
	}

	result := make([]Entry, 0, limit)
	start := total - limit
	for i := start; i < total; i++ {
		idx := i
		if b.full {
			idx = (b.next + i) % len(b.entries)
		}
		result = append(result, copyEntry(b.entries[idx]))
	}
	return result
}

func copyEntry(entry Entry) Entry {
	return Entry{
		Timestamp: entry.Timestamp,
		Level:     entry.Level,
		Message:   entry.Message,
		Fields:    cloneFields(entry.Fields),
	}
}

func cloneFields(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]any, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}
