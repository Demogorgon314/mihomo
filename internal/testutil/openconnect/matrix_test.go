package openconnect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

var phase0CapabilityMatrix = NewCapabilityMatrix()

func TestMain(main *testing.M) {
	code := main.Run()
	if path := os.Getenv("MIHOMO_ANYCONNECT_MATRIX"); path != "" {
		if err := phase0CapabilityMatrix.WriteJSON(path); err != nil {
			_, _ = os.Stderr.WriteString("write AnyConnect capability matrix: " + err.Error() + "\n")
			if code == 0 {
				code = 1
			}
		}
	}
	os.Exit(code)
}

func TestCapabilityMatrixRecordsDeterministicEvidence(t *testing.T) {
	matrix := NewCapabilityMatrix()
	evidence := []Evidence{
		{Capability: CapabilityPacketIPv4, Scenario: "packet", Driver: DriverProbe, Gateway: "fake", Transport: "cstp", Address: "ipv4", Passed: true},
		{Capability: CapabilityCookieCSTP, Scenario: "cookie", Driver: DriverProbe, Gateway: "fake", Transport: "cstp", Address: "ipv4", Passed: false},
		{Capability: CapabilityCookieCSTP, Scenario: "cookie", Driver: DriverCore, Gateway: "ocserv", Transport: "cstp", Address: "ipv4", Passed: true},
	}
	var waitGroup sync.WaitGroup
	for _, entry := range evidence {
		entry := entry
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			if err := matrix.Record(entry); err != nil {
				t.Errorf("record evidence: %v", err)
			}
		}()
	}
	waitGroup.Wait()
	updated := evidence[1]
	updated.Passed = true
	if err := matrix.Record(updated); err != nil {
		t.Fatal(err)
	}
	entries := matrix.Snapshot()
	if len(entries) != 3 {
		t.Fatalf("unexpected evidence count: %d", len(entries))
	}
	if entries[0].Capability != CapabilityCookieCSTP || entries[0].Driver != DriverProbe {
		t.Fatalf("evidence is not sorted: %#v", entries)
	}
	if !entries[0].Passed {
		t.Fatalf("duplicate evidence was not replaced: %#v", entries[0])
	}
	entries[0].Gateway = "changed"
	if matrix.Snapshot()[0].Gateway == "changed" {
		t.Fatal("snapshot mutation changed matrix")
	}
}

func TestCapabilityMatrixRejectsInvalidEvidence(t *testing.T) {
	var nilMatrix *CapabilityMatrix
	if err := nilMatrix.Record(Evidence{}); err == nil {
		t.Fatal("expected nil matrix error")
	}
	matrix := NewCapabilityMatrix()
	for _, evidence := range []Evidence{
		{},
		{Capability: CapabilityCookieCSTP, Driver: DriverProbe},
		{Capability: CapabilityCookieCSTP, Gateway: "fake"},
		{Driver: DriverProbe, Gateway: "fake"},
	} {
		if err := matrix.Record(evidence); err == nil {
			t.Fatalf("expected invalid evidence error: %#v", evidence)
		}
	}
	if snapshot := nilMatrix.Snapshot(); snapshot != nil {
		t.Fatalf("nil matrix returned evidence: %#v", snapshot)
	}
}

func TestCapabilityMatrixWritesJSONArtifact(t *testing.T) {
	matrix := NewCapabilityMatrix()
	evidence := Evidence{Capability: CapabilityModernDTLS, Scenario: "modern-dtls", Driver: DriverCore, Gateway: "fake", Transport: "dtls", Address: "ipv4", Passed: true}
	if err := matrix.Record(evidence); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nested", "matrix.json")
	if err := matrix.WriteJSON(path); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entries []Evidence
	if err := json.Unmarshal(content, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0] != evidence {
		t.Fatalf("unexpected matrix artifact: %#v", entries)
	}
	if err := matrix.WriteJSON(""); err == nil {
		t.Fatal("expected empty output path error")
	}
}
