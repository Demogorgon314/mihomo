package anyconnect

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	defaultTunnelMTU = 1400
	maximumCSTPMTU   = 65535
)

// NetworkConfiguration is the network state advertised by a fake gateway.
type NetworkConfiguration struct {
	Addresses []netip.Prefix
	DNS       []netip.Addr
	MTU       uint16
}

// CSTPFaults controls one deliberate protocol failure in a scenario.
type CSTPFaults struct {
	RejectStatus        int
	ResponseChunkSize   int
	MalformedDataHeader bool
}

// AuthenticationScenario controls the deterministic XMLPOST authentication
// exchange offered by the fake gateway. CookieUses limits successful CSTP
// CONNECT requests for one issued cookie; zero means unlimited.
type AuthenticationScenario struct {
	Enabled           bool
	Username          string
	Password          string
	Challenge         string
	ChallengeResponse string
	CookieUses        int
}

// Scenario describes one deterministic fake AnyConnect gateway behavior.
type Scenario struct {
	Name           string
	Cookie         string
	Configuration  NetworkConfiguration
	Authentication AuthenticationScenario
	ModernDTLS     bool
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
	if s.Configuration.MTU == 0 || uint32(s.Configuration.MTU) > maximumCSTPMTU {
		validationErrors = append(validationErrors, fmt.Errorf("tunnel MTU must be between 1 and %d", maximumCSTPMTU))
	}
	if s.CSTP.RejectStatus != 0 && (s.CSTP.RejectStatus < 400 || s.CSTP.RejectStatus > 599) {
		validationErrors = append(validationErrors, errors.New("CSTP rejection status must be between 400 and 599"))
	}
	if s.CSTP.ResponseChunkSize < 0 {
		validationErrors = append(validationErrors, errors.New("CSTP response chunk size cannot be negative"))
	}
	if s.Authentication.Enabled {
		if s.Authentication.Username == "" || s.Authentication.Password == "" {
			validationErrors = append(validationErrors, errors.New("authentication username and password are required"))
		}
		if (s.Authentication.Challenge == "") != (s.Authentication.ChallengeResponse == "") {
			validationErrors = append(validationErrors, errors.New("authentication challenge and response must be configured together"))
		}
		if s.Authentication.CookieUses < 0 {
			validationErrors = append(validationErrors, errors.New("authentication cookie uses cannot be negative"))
		}
	}
	return errors.Join(validationErrors...)
}
