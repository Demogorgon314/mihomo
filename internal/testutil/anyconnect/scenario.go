package anyconnect

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const (
	defaultTunnelMTU = 1400
	maximumCSTPMTU   = 65535
)

// NetworkConfiguration is the network state advertised by a fake gateway.
type NetworkConfiguration struct {
	Addresses      []netip.Prefix
	Routes         []netip.Prefix
	ExcludedRoutes []netip.Prefix
	DNS            []netip.Addr
	SearchDomains  []string
	SplitDNS       []string
	Banner         string
	TunnelAllDNS   bool
	MTU            uint16
}

// CSTPFaults controls one deliberate protocol failure in a scenario.
type CSTPFaults struct {
	RejectStatus           int
	ResponseChunkSize      int
	MalformedDataHeader    bool
	CompressedPackets      [][]byte
	ReconnectConfiguration *NetworkConfiguration
	RekeyInterval          time.Duration
	ResponseDelay          time.Duration
}

// AuthenticationScenario controls the deterministic XMLPOST authentication
// exchange offered by the fake gateway. CookieUses limits successful CSTP
// CONNECT requests for one issued cookie; zero means unlimited.
type AuthenticationScenario struct {
	Enabled                    bool
	Username                   string
	Password                   string
	AuthGroup                  string
	Challenge                  string
	ChallengeResponse          string
	ChallengeResponses         []string
	Browser                    bool
	HostScan                   bool
	ClientCertificateAuthority []byte
	CookieUses                 int
}

// Scenario describes one deterministic fake AnyConnect gateway behavior.
type Scenario struct {
	Name           string
	Cookie         string
	Configuration  NetworkConfiguration
	Authentication AuthenticationScenario
	ModernDTLS     bool
	InjectedDTLS   bool
	DTLSMTU        uint16
	DTLSAppID      []byte
	Compression    string
	CSTP           CSTPFaults
}

// BasicCSTPScenario returns the smallest valid IPv4 CSTP scenario.
func BasicCSTPScenario() Scenario {
	return Scenario{
		Name:   "basic-cstp",
		Cookie: "phase0-test-cookie",
		Configuration: NetworkConfiguration{
			Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")},
			DNS:       []netip.Addr{netip.MustParseAddr("192.0.2.53")},
			MTU:       defaultTunnelMTU,
		},
	}
}

// Validate rejects scenarios that cannot produce an unambiguous tunnel.
func (s Scenario) Validate() error {
	var validationErrors []error
	if strings.TrimSpace(s.Name) == "" {
		validationErrors = append(validationErrors, errors.New("scenario name is required"))
	}
	if s.Cookie == "" {
		validationErrors = append(validationErrors, errors.New("scenario cookie is required"))
	} else if strings.ContainsAny(s.Cookie, "\r\n") {
		validationErrors = append(validationErrors, errors.New("scenario cookie contains an invalid header character"))
	}
	if len(s.Configuration.Addresses) == 0 {
		validationErrors = append(validationErrors, errors.New("at least one tunnel address is required"))
	}
	for _, prefix := range s.Configuration.Addresses {
		if !prefix.IsValid() || prefix.Addr().IsUnspecified() {
			validationErrors = append(validationErrors, fmt.Errorf("invalid tunnel address: %s", prefix))
		}
	}
	for _, address := range s.Configuration.DNS {
		if !address.IsValid() || address.IsUnspecified() {
			validationErrors = append(validationErrors, fmt.Errorf("invalid DNS address: %s", address))
		}
	}
	for _, prefix := range append(append([]netip.Prefix(nil), s.Configuration.Routes...), s.Configuration.ExcludedRoutes...) {
		if !prefix.IsValid() {
			validationErrors = append(validationErrors, fmt.Errorf("invalid tunnel route: %s", prefix))
		}
	}
	for _, value := range append(append([]string(nil), s.Configuration.SearchDomains...), s.Configuration.SplitDNS...) {
		if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\x00\r\n") {
			validationErrors = append(validationErrors, errors.New("tunnel DNS domain is invalid"))
		}
	}
	if strings.ContainsAny(s.Configuration.Banner, "\x00\r\n") {
		validationErrors = append(validationErrors, errors.New("tunnel banner contains an invalid header character"))
	}
	if s.Configuration.MTU == 0 || uint32(s.Configuration.MTU) > maximumCSTPMTU {
		validationErrors = append(validationErrors, fmt.Errorf("tunnel MTU must be between 1 and %d", maximumCSTPMTU))
	}
	if s.CSTP.RejectStatus != 0 && (s.CSTP.RejectStatus < 400 || s.CSTP.RejectStatus > 599) {
		validationErrors = append(validationErrors, errors.New("CSTP rejection status must be between 400 and 599"))
	}
	if s.CSTP.ResponseChunkSize < 0 {
		validationErrors = append(validationErrors, errors.New("CSTP response chunk size cannot be negative"))
	}
	if s.CSTP.ResponseDelay < 0 {
		validationErrors = append(validationErrors, errors.New("CSTP response delay cannot be negative"))
	}
	if s.CSTP.RekeyInterval < 0 || s.CSTP.RekeyInterval%time.Second != 0 {
		validationErrors = append(validationErrors, errors.New("CSTP rekey interval must be a non-negative whole number of seconds"))
	}
	if s.Compression != "" && s.Compression != "lzs" && s.Compression != "oc-lz4" {
		validationErrors = append(validationErrors, errors.New("compression must be lzs or oc-lz4"))
	}
	if s.DTLSMTU != 0 && (!s.ModernDTLS || s.DTLSMTU < 576 || s.DTLSMTU > s.Configuration.MTU) {
		validationErrors = append(validationErrors, errors.New("DTLS MTU requires modern DTLS and must be between 576 and the CSTP MTU"))
	}
	if len(s.DTLSAppID) > 0 && (!s.ModernDTLS || len(s.DTLSAppID) > 32) {
		validationErrors = append(validationErrors, errors.New("DTLS App ID requires modern DTLS and cannot exceed 32 bytes"))
	}
	if s.InjectedDTLS && (!s.ModernDTLS || len(s.DTLSAppID) > 0) {
		validationErrors = append(validationErrors, errors.New("injected DTLS requires modern DTLS without an App ID"))
	}
	if len(s.CSTP.CompressedPackets) > 0 && s.Compression == "" {
		validationErrors = append(validationErrors, errors.New("compressed packets require negotiated compression"))
	}
	if configuration := s.CSTP.ReconnectConfiguration; configuration != nil {
		if len(configuration.Addresses) == 0 {
			validationErrors = append(validationErrors, errors.New("reconnect configuration requires a tunnel address"))
		}
		for _, prefix := range configuration.Addresses {
			if !prefix.IsValid() || prefix.Addr().IsUnspecified() {
				validationErrors = append(validationErrors, fmt.Errorf("invalid reconnect tunnel address: %s", prefix))
			}
		}
		if configuration.MTU == 0 || uint32(configuration.MTU) > maximumCSTPMTU {
			validationErrors = append(validationErrors, fmt.Errorf("reconnect tunnel MTU must be between 1 and %d", maximumCSTPMTU))
		}
	}
	if s.Authentication.Enabled {
		if s.Authentication.Username == "" || s.Authentication.Password == "" {
			validationErrors = append(validationErrors, errors.New("authentication username and password are required"))
		}
		hasChallengeResponse := s.Authentication.ChallengeResponse != "" || len(s.Authentication.ChallengeResponses) > 0
		if (s.Authentication.Challenge != "") != hasChallengeResponse {
			validationErrors = append(validationErrors, errors.New("authentication challenge and response must be configured together"))
		}
		if s.Authentication.Browser && (s.Authentication.Challenge != "" || s.Authentication.HostScan) {
			validationErrors = append(validationErrors, errors.New("browser authentication cannot be combined with challenge or host scan"))
		}
		if s.Authentication.HostScan && s.Authentication.Challenge != "" {
			validationErrors = append(validationErrors, errors.New("host scan cannot be combined with challenge"))
		}
		if s.Authentication.CookieUses < 0 {
			validationErrors = append(validationErrors, errors.New("authentication cookie uses cannot be negative"))
		}
	}
	return errors.Join(validationErrors...)
}
