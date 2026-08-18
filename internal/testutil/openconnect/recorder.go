package openconnect

import (
	"strings"
	"sync"
)

const redactedValue = "[REDACTED]"

// Record is one sanitized test protocol event.
type Record struct {
	Kind    string
	Message string
}

// Recorder stores deterministic protocol events without retaining configured secrets.
type Recorder struct {
	access    sync.Mutex
	secrets   []string
	records   []Record
	counts    map[string]uint64
	countOnly bool
}

// NewRecorder creates an empty recorder. Empty secrets are ignored.
func NewRecorder(secrets ...string) *Recorder {
	filtered := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if secret != "" {
			filtered = append(filtered, secret)
		}
	}
	return &Recorder{secrets: filtered}
}

// NewCountingRecorder records only event counts. It avoids retaining one
// message per data packet in long-running benchmarks.
func NewCountingRecorder() *Recorder {
	return &Recorder{counts: make(map[string]uint64), countOnly: true}
}

// Add sanitizes and appends an event.
func (r *Recorder) Add(kind string, message string) {
	if r == nil {
		return
	}
	if r.countOnly {
		r.access.Lock()
		r.counts[kind]++
		r.access.Unlock()
		return
	}
	for _, secret := range r.secrets {
		message = strings.ReplaceAll(message, secret, redactedValue)
	}
	r.access.Lock()
	r.records = append(r.records, Record{Kind: kind, Message: message})
	r.access.Unlock()
}

// Count returns the number of recorded events with kind.
func (r *Recorder) Count(kind string) uint64 {
	if r == nil {
		return 0
	}
	r.access.Lock()
	defer r.access.Unlock()
	if r.counts != nil {
		return r.counts[kind]
	}
	var count uint64
	for _, record := range r.records {
		if record.Kind == kind {
			count++
		}
	}
	return count
}

// Records returns a caller-owned snapshot.
func (r *Recorder) Records() []Record {
	if r == nil {
		return nil
	}
	r.access.Lock()
	defer r.access.Unlock()
	return append([]Record(nil), r.records...)
}
