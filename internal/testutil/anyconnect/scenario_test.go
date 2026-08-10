package anyconnect

import (
	"net/netip"
	"strings"
	"testing"
)

func TestBasicCSTPScenario(t *testing.T) {
	scenario := BasicCSTPScenario()
	if err := scenario.Validate(); err != nil {
		t.Fatal(err)
	}
	if scenario.Configuration.MTU != defaultTunnelMTU {
		t.Fatalf("unexpected MTU: %d", scenario.Configuration.MTU)
	}
}

func TestScenarioValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Scenario)
		message string
	}{
		{name: "name", mutate: func(s *Scenario) { s.Name = "" }, message: "name"},
		{name: "cookie", mutate: func(s *Scenario) { s.Cookie = "" }, message: "cookie"},
		{name: "cookie newline", mutate: func(s *Scenario) { s.Cookie = "value\r\ninjected" }, message: "header character"},
		{name: "address missing", mutate: func(s *Scenario) { s.Configuration.Addresses = nil }, message: "tunnel address"},
		{name: "address unspecified", mutate: func(s *Scenario) { s.Configuration.Addresses = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} }, message: "invalid tunnel address"},
		{name: "DNS unspecified", mutate: func(s *Scenario) { s.Configuration.DNS = []netip.Addr{netip.IPv4Unspecified()} }, message: "invalid DNS"},
		{name: "MTU", mutate: func(s *Scenario) { s.Configuration.MTU = 0 }, message: "MTU"},
		{name: "status low", mutate: func(s *Scenario) { s.CSTP.RejectStatus = 399 }, message: "status"},
		{name: "status high", mutate: func(s *Scenario) { s.CSTP.RejectStatus = 600 }, message: "status"},
		{name: "chunk size", mutate: func(s *Scenario) { s.CSTP.ResponseChunkSize = -1 }, message: "chunk"},
		{name: "legacy DTLS fault", mutate: func(s *Scenario) { s.LegacyDTLS = true; s.LegacyDTLSFault = "typo" }, message: "legacy DTLS fault"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scenario := BasicCSTPScenario()
			test.mutate(&scenario)
			err := scenario.Validate()
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("expected error containing %q, got %v", test.message, err)
			}
		})
	}
}
