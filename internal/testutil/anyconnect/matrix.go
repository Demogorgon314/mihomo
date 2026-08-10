package anyconnect

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Capability identifies one independently verifiable protocol behavior.
type Capability string

const (
	CapabilityCookieCSTP Capability = "cookie-cstp"
	CapabilityPacketIPv4 Capability = "packet-ipv4"
	CapabilityModernDTLS Capability = "modern-dtls"
	CapabilityFallback   Capability = "cstp-fallback"
	CapabilityTLSVerify  Capability = "tls-verification"
	CapabilityFraming    Capability = "cstp-framing-rejection"
	CapabilityAuth       Capability = "xmlpost-authentication"
)

// Driver identifies the client layer exercised by evidence.
type Driver string

const (
	DriverProbe    Driver = "probe"
	DriverCore     Driver = "sing-openconnect"
	DriverOutbound Driver = "mihomo-outbound"
)

// Evidence is one capability result from one driver and environment.
type Evidence struct {
	Capability Capability `json:"capability"`
	Scenario   string     `json:"scenario"`
	Driver     Driver     `json:"driver"`
	Gateway    string     `json:"gateway"`
	Transport  string     `json:"transport"`
	Address    string     `json:"address_family"`
	Passed     bool       `json:"passed"`
}

// CapabilityMatrix stores a deterministic, duplicate-free evidence set.
type CapabilityMatrix struct {
	access  sync.Mutex
	entries map[string]Evidence
}

// NewCapabilityMatrix creates an empty matrix.
func NewCapabilityMatrix() *CapabilityMatrix {
	return &CapabilityMatrix{entries: make(map[string]Evidence)}
}

// Record validates and replaces evidence with the same capability, driver, and environment.
func (m *CapabilityMatrix) Record(evidence Evidence) error {
	if m == nil {
		return errors.New("capability matrix is nil")
	}
	if evidence.Capability == "" || strings.TrimSpace(evidence.Scenario) == "" || evidence.Driver == "" ||
		strings.TrimSpace(evidence.Gateway) == "" || strings.TrimSpace(evidence.Transport) == "" ||
		strings.TrimSpace(evidence.Address) == "" {
		return errors.New("capability, scenario, driver, gateway, transport, and address family are required")
	}
	key := evidenceKey(evidence)
	m.access.Lock()
	m.entries[key] = evidence
	m.access.Unlock()
	return nil
}

// Snapshot returns evidence sorted by capability, driver, then environment.
func (m *CapabilityMatrix) Snapshot() []Evidence {
	if m == nil {
		return nil
	}
	m.access.Lock()
	entries := make([]Evidence, 0, len(m.entries))
	for _, evidence := range m.entries {
		entries = append(entries, evidence)
	}
	m.access.Unlock()
	sort.Slice(entries, func(i int, j int) bool {
		return evidenceKey(entries[i]) < evidenceKey(entries[j])
	})
	return entries
}

// WriteJSON writes a deterministic capability artifact for CI and review.
func (m *CapabilityMatrix) WriteJSON(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("capability matrix output path is required")
	}
	content, err := json.MarshalIndent(m.Snapshot(), "", "  ")
	if err != nil {
		return fmt.Errorf("marshal capability matrix: %w", err)
	}
	content = append(content, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create capability matrix directory: %w", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return fmt.Errorf("write capability matrix: %w", err)
	}
	return nil
}

func evidenceKey(evidence Evidence) string {
	return strings.Join([]string{
		string(evidence.Capability), evidence.Scenario, string(evidence.Driver),
		evidence.Gateway, evidence.Transport, evidence.Address,
	}, "\x00")
}
