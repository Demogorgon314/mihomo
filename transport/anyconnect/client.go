package anyconnect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/netip"
	"strings"

	openconnect "github.com/sagernet/sing-openconnect"
)

// NetworkConfig is a caller-owned snapshot of the negotiated tunnel settings.
type NetworkConfig struct {
	Addresses      []netip.Prefix
	Routes         []netip.Prefix
	ExcludedRoutes []netip.Prefix
	DNS            []netip.Addr
	MTU            uint32
}

// Client isolates the outbound package from sing-openconnect types.
type Client struct {
	core *openconnect.Client
}

// NewClient creates a CSTP-only, cookie-authenticated protocol client.
func NewClient(ctx context.Context, config Config, dialer Dialer) (*Client, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, invalidConfig("context is required")
	}
	underlay, err := newSingDialer(dialer)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: config.ServerName,
	}
	if len(config.CertificateAuthority) > 0 {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(config.CertificateAuthority) {
			return nil, invalidConfig("certificate authority is not valid PEM")
		}
		tlsConfig.RootCAs = roots
	} else if config.PeerFingerprint == "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, invalidConfig("load system certificate authorities")
		}
		tlsConfig.RootCAs = roots
	}
	tlsOptions := openconnect.ClientTLSOptions{Config: tlsConfig}
	if config.PeerFingerprint != "" {
		tlsOptions.PeerFingerprints = []string{config.PeerFingerprint}
	}
	core, err := openconnect.NewClient(openconnect.ClientOptions{
		Context:             ctx,
		Server:              config.Server,
		Cookie:              normalizeCookie(config.Cookie),
		NoUDP:               true,
		CompressionDisabled: true,
		IPv6Disabled:        true,
		MTU:                 config.MTU,
		TLSConfig:           tlsOptions,
		Dialer:              underlay,
	})
	if err != nil {
		return nil, err
	}
	return &Client{core: core}, nil
}

func normalizeCookie(cookie string) string {
	if strings.HasPrefix(strings.TrimSpace(cookie), "webvpn=") {
		return cookie
	}
	return "webvpn=" + cookie
}

func (c *Client) Start() error {
	return c.core.Start()
}

func (c *Client) WaitReady(ctx context.Context) (NetworkConfig, error) {
	configuration, err := c.core.WaitReady(ctx)
	if err != nil {
		return NetworkConfig{}, err
	}
	return networkConfigFromCore(configuration), nil
}

func (c *Client) ReadPacket(ctx context.Context) ([]byte, error) {
	return c.core.ReadDataPacket(ctx)
}

func (c *Client) WritePacket(packet []byte) error {
	return c.core.WriteDataPacket(packet)
}

func (c *Client) ActiveTransport() string {
	return c.core.ActiveTransport()
}

func (c *Client) Close() error {
	return c.core.Close()
}

func networkConfigFromCore(configuration openconnect.TunnelConfiguration) NetworkConfig {
	result := NetworkConfig{
		Addresses: append([]netip.Prefix(nil), configuration.Addresses...),
		DNS:       append([]netip.Addr(nil), configuration.DNS...),
		MTU:       configuration.MTU,
	}
	result.Routes = make([]netip.Prefix, 0, len(configuration.Routes))
	for _, route := range configuration.Routes {
		result.Routes = append(result.Routes, route.Prefix)
	}
	result.ExcludedRoutes = make([]netip.Prefix, 0, len(configuration.ExcludedRoutes))
	for _, route := range configuration.ExcludedRoutes {
		result.ExcludedRoutes = append(result.ExcludedRoutes, route.Prefix)
	}
	return result
}
