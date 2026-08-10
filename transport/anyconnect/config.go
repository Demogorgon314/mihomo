package anyconnect

import (
	"context"
	"net/url"
	"strings"
)

const (
	TokenModeTOTP = "totp"
	TokenModeHOTP = "hotp"
)

// TokenConfig configures a software OATH token. UpdateCounter persists the
// next HOTP counter after a successful generation.
type TokenConfig struct {
	Mode          string
	Secret        string
	Counter       uint64
	UpdateCounter func(ctx context.Context, counter uint64) error
}

type FormEntry struct {
	FormID        string `proxy:"form-id,omitempty"`
	SubmissionKey string `proxy:"submission-key,omitempty"`
	Name          string `proxy:"name,omitempty"`
	Value         string `proxy:"value,omitempty"`
}

// Config contains the protocol, authentication, and TLS settings owned by the
// mihomo façade. All byte slices and form entries are copied before use.
type Config struct {
	Server               string
	Cookie               string
	Username             string
	Password             string
	AuthGroup            string
	FormEntries          []FormEntry
	Token                *TokenConfig
	ServerName           string
	CertificateAuthority []byte
	ClientCertificate    []byte
	ClientKey            []byte
	ClientKeyPassword    string
	PeerFingerprint      string
	SkipCertVerify       bool
	MTU                  uint32
}

// ValidateConfig validates configuration without opening a network connection.
func ValidateConfig(config Config, authProvider AuthProvider) error {
	return config.validate(authProvider != nil)
}

func (c Config) validate(hasAuthProvider bool) error {
	if strings.TrimSpace(c.Server) == "" {
		return invalidConfig("server is required")
	}
	serverURL, err := url.Parse(c.Server)
	if err != nil || serverURL.Scheme != "https" || serverURL.Hostname() == "" || serverURL.User != nil || serverURL.RawQuery != "" || serverURL.Fragment != "" {
		return invalidConfig("server must be a valid HTTPS URL")
	}
	if c.Cookie == "" && c.Username == "" && len(c.ClientCertificate) == 0 && !hasAuthProvider {
		return invalidConfig("cookie, username, client certificate, or authentication provider is required")
	}
	if strings.ContainsAny(c.Cookie, "\x00\r\n") {
		return invalidConfig("cookie contains an invalid character")
	}
	trustModes := 0
	for _, configured := range []bool{len(c.CertificateAuthority) > 0, c.PeerFingerprint != "", c.SkipCertVerify} {
		if configured {
			trustModes++
		}
	}
	if trustModes > 1 {
		return invalidConfig("certificate authority, peer fingerprint, and skip certificate verify are mutually exclusive")
	}
	if strings.ContainsAny(c.ServerName, "\x00\r\n") {
		return invalidConfig("server name contains an invalid character")
	}
	if (len(c.ClientCertificate) == 0) != (len(c.ClientKey) == 0) {
		return invalidConfig("client certificate and key must be configured together")
	}
	if c.ClientKeyPassword != "" && len(c.ClientKey) == 0 {
		return invalidConfig("client key password requires a client key")
	}
	if c.Token != nil {
		if c.Token.Mode != TokenModeTOTP && c.Token.Mode != TokenModeHOTP {
			return invalidConfig("token mode must be totp or hotp")
		}
		if c.Token.Secret == "" {
			return invalidConfig("token secret is required")
		}
		if c.Token.Mode == TokenModeHOTP && c.Token.UpdateCounter == nil {
			return invalidConfig("HOTP token requires a counter update callback")
		}
	}
	for _, entry := range c.FormEntries {
		if entry.SubmissionKey == "" && (entry.FormID == "" || entry.Name == "") {
			return invalidConfig("form entry requires a submission key or a form ID and field name")
		}
		for _, identifier := range []string{entry.FormID, entry.SubmissionKey, entry.Name} {
			if strings.ContainsAny(identifier, "\x00\r\n") {
				return invalidConfig("form entry identifier contains an invalid character")
			}
		}
	}
	return nil
}
