package anyconnect

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
	access  sync.Mutex
	secrets []string
	records []Record
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

// Add sanitizes and appends an event.
func (r *Recorder) Add(kind string, message string) {
	if r == nil {
		return
	}
	for _, secret := range r.secrets {
		message = strings.ReplaceAll(message, secret, redactedValue)
	}
	r.access.Lock()
	r.records = append(r.records, Record{Kind: kind, Message: message})
	r.access.Unlock()
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
