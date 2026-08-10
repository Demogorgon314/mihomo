package anyconnect

import (
	"net/url"
	"strings"
)

// Config contains the protocol settings supported by the first CSTP-only
// integration slice. Authentication methods other than a pre-issued cookie are
// intentionally left to later phases.
type Config struct {
	Server               string
	Cookie               string
	ServerName           string
	CertificateAuthority []byte
	PeerFingerprint      string
	MTU                  uint32
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Server) == "" {
		return invalidConfig("server is required")
	}
	serverURL, err := url.Parse(c.Server)
	if err != nil || serverURL.Scheme != "https" || serverURL.Hostname() == "" || serverURL.User != nil || serverURL.RawQuery != "" || serverURL.Fragment != "" {
		return invalidConfig("server must be a valid HTTPS URL")
	}
	if c.Cookie == "" {
		return invalidConfig("cookie is required")
	}
	if strings.ContainsAny(c.Cookie, "\x00\r\n") {
		return invalidConfig("cookie contains an invalid character")
	}
	if len(c.CertificateAuthority) > 0 && c.PeerFingerprint != "" {
		return invalidConfig("certificate authority and peer fingerprint cannot both be configured")
	}
	if strings.ContainsAny(c.ServerName, "\x00\r\n") {
		return invalidConfig("server name contains an invalid character")
	}
	return nil
}
