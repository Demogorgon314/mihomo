package openconnect

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/sagernet/sing/common/logger"
)

const (
	ProtocolAnyConnect = "anyconnect"
	ProtocolF5         = "f5"
	TokenModeTOTP      = "totp"
	TokenModeHOTP      = "hotp"
	TokenModeRSA       = "rsa"
	TokenModeOIDC      = "oidc"

	CompressionOff            = "off"
	CompressionStateless      = "stateless"
	CompressionAll            = "all"
	DTLSModeOff               = "off"
	DTLSModeAuto              = "auto"
	DTLSModeRequire           = "require"
	DTLSKeyExchangeAuto       = "auto"
	DTLSKeyExchangeResumption = "resumption"
	MaximumQueueLength        = 4096
)

// TokenConfig configures a software OATH token. UpdateCounter persists the
// next HOTP counter after a successful generation.
type TokenConfig struct {
	Mode          string
	Secret        string
	PIN           string
	Password      string
	DeviceID      string
	Counter       uint64
	UpdateCounter func(ctx context.Context, counter uint64) error
}

type FormEntry struct {
	FormID        string `proxy:"form-id,omitempty"`
	SubmissionKey string `proxy:"submission-key,omitempty"`
	Name          string `proxy:"name,omitempty"`
	Value         string `proxy:"value,omitempty"`
	Promote       bool   `proxy:"promote,omitempty"`
}

type MobileConfig struct {
	PlatformVersion string `proxy:"platform-version,omitempty"`
	DeviceType      string `proxy:"device-type,omitempty"`
	DeviceUniqueID  string `proxy:"device-unique-id,omitempty"`
}

// Config contains the protocol, authentication, and TLS settings owned by the
// mihomo façade. All byte slices and form entries are copied before use.
type Config struct {
	Server                           string
	Protocol                         string
	Cookie                           string
	Username                         string
	Password                         string
	AuthGroup                        string
	ReportedOS                       string
	UserAgent                        string
	Version                          string
	LocalHostname                    string
	Mobile                           *MobileConfig
	FormEntries                      []FormEntry
	Token                            *TokenConfig
	ServerName                       string
	CertificateAuthority             []byte
	ClientCertificate                []byte
	ClientKey                        []byte
	ClientKeyPassword                string
	MCACertificate                   []byte
	MCAKey                           []byte
	MCAKeyPassword                   string
	CertificateExpiryWarning         time.Duration
	CertificateExpiryWarningDisabled bool
	PeerFingerprint                  string
	PeerFingerprints                 []string
	SystemTrustDisabled              bool
	SkipCertVerify                   bool
	HTTPKeepAliveDisabled            bool
	XMLPostDisabled                  bool
	ExternalAuthDisabled             bool
	PasswordAuthenticationDisabled   bool
	PFS                              bool
	AllowInsecureCrypto              bool
	MTU                              uint32
	BaseMTU                          uint32
	IPv6Disabled                     bool
	Compression                      string
	DTLSMode                         string
	DTLSKeyExchange                  string
	LegacyDTLSDisabled               bool
	DTLSLocalPort                    uint16
	DPDInterval                      time.Duration
	ReconnectTimeout                 time.Duration
	QueueLength                      uint32
	Logger                           logger.ContextLogger
	OnNetworkConfig                  func(event NetworkConfigEvent) error
}

// ValidateConfig validates configuration without opening a network connection.
func ValidateConfig(config Config, authProvider AuthProvider) error {
	return config.validate(authProvider != nil)
}

func normalizeProtocol(protocol string) string {
	if protocol == "" {
		return ProtocolAnyConnect
	}
	return protocol
}

func (c Config) validate(hasAuthProvider bool) error {
	if strings.TrimSpace(c.Server) == "" {
		return invalidConfig("server is required")
	}
	serverURL, err := url.Parse(c.Server)
	if err != nil || serverURL.Scheme != "https" || serverURL.Hostname() == "" || serverURL.User != nil || serverURL.RawQuery != "" || serverURL.Fragment != "" {
		return invalidConfig("server must be a valid HTTPS URL")
	}
	switch c.Protocol {
	case "", ProtocolAnyConnect, ProtocolF5:
	default:
		return invalidConfig("protocol must be anyconnect or f5")
	}
	if c.Cookie == "" && c.Username == "" && len(c.ClientCertificate) == 0 && !hasAuthProvider {
		return invalidConfig("cookie, username, client certificate, or authentication provider is required")
	}
	if strings.ContainsAny(c.Cookie, "\x00\r\n") {
		return invalidConfig("cookie contains an invalid character")
	}
	trustModes := 0
	for _, configured := range []bool{len(c.CertificateAuthority) > 0, c.PeerFingerprint != "" || len(c.PeerFingerprints) > 0, c.SkipCertVerify} {
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
	switch c.ReportedOS {
	case "", "linux", "linux-64", "win", "mac-intel", "android", "apple-ios":
	default:
		return invalidConfig("reported OS must be linux, linux-64, win, mac-intel, android, or apple-ios")
	}
	for name, value := range map[string]string{
		"user agent":     c.UserAgent,
		"version":        c.Version,
		"local hostname": c.LocalHostname,
	} {
		if strings.ContainsAny(value, "\x00\r\n") {
			return invalidConfig(name + " contains an invalid character")
		}
	}
	if c.Mobile != nil {
		for name, value := range map[string]string{
			"mobile platform version": c.Mobile.PlatformVersion,
			"mobile device type":      c.Mobile.DeviceType,
			"mobile device unique ID": c.Mobile.DeviceUniqueID,
		} {
			if value == "" {
				return invalidConfig(name + " is required")
			}
			if strings.ContainsAny(value, "\x00\r\n") {
				return invalidConfig(name + " contains an invalid character")
			}
		}
	}
	for _, fingerprint := range c.PeerFingerprints {
		if strings.TrimSpace(fingerprint) == "" {
			return invalidConfig("peer fingerprint list contains an empty value")
		}
	}
	if (len(c.ClientCertificate) == 0) != (len(c.ClientKey) == 0) {
		return invalidConfig("client certificate and key must be configured together")
	}
	if c.ClientKeyPassword != "" && len(c.ClientKey) == 0 {
		return invalidConfig("client key password requires a client key")
	}
	if (len(c.MCACertificate) == 0) != (len(c.MCAKey) == 0) {
		return invalidConfig("MCA certificate and key must be configured together")
	}
	if c.MCAKeyPassword != "" && len(c.MCAKey) == 0 {
		return invalidConfig("MCA key password requires an MCA key")
	}
	if c.CertificateExpiryWarning < 0 {
		return invalidConfig("certificate expiry warning must be non-negative")
	}
	if c.CertificateExpiryWarningDisabled && c.CertificateExpiryWarning != 0 {
		return invalidConfig("certificate expiry warning cannot be configured and disabled together")
	}
	if c.Token != nil {
		switch c.Token.Mode {
		case TokenModeTOTP, TokenModeHOTP, TokenModeRSA, TokenModeOIDC:
		default:
			return invalidConfig("token mode must be totp, hotp, rsa, or oidc")
		}
		if c.Token.Secret == "" {
			return invalidConfig("token secret is required")
		}
		if c.Token.Mode == TokenModeHOTP && c.Token.UpdateCounter == nil {
			return invalidConfig("HOTP token requires a counter update callback")
		}
	}
	if c.MTU != 0 && (c.MTU < 576 || c.MTU > 65535) {
		return invalidConfig("MTU must be between 576 and 65535")
	}
	if !c.IPv6Disabled && c.MTU != 0 && c.MTU < 1280 {
		return invalidConfig("IPv6 MTU must be at least 1280")
	}
	if c.BaseMTU != 0 && (c.BaseMTU < 576 || c.BaseMTU > 65535) {
		return invalidConfig("base MTU must be between 576 and 65535")
	}
	if c.DPDInterval < 0 {
		return invalidConfig("DPD interval must be non-negative")
	}
	if c.ReconnectTimeout < 0 {
		return invalidConfig("reconnect timeout must be non-negative")
	}
	if c.QueueLength > MaximumQueueLength {
		return invalidConfig("packet queue length must not exceed 4096")
	}
	switch c.Compression {
	case "", CompressionOff, CompressionStateless, CompressionAll:
	default:
		return invalidConfig("compression must be off, stateless, or all")
	}
	switch c.DTLSMode {
	case "", DTLSModeOff, DTLSModeAuto, DTLSModeRequire:
	default:
		return invalidConfig("DTLS mode must be off, auto, or require")
	}
	switch c.DTLSKeyExchange {
	case "", DTLSKeyExchangeAuto, DTLSKeyExchangeResumption:
	default:
		return invalidConfig("DTLS key exchange must be auto or resumption")
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
		if entry.Promote && entry.Value != "" {
			return invalidConfig("promoted form entry cannot also provide a value")
		}
	}
	return nil
}
