package anyconnect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/netip"
	"strings"
	"sync"
	"time"

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
	core         *openconnect.Client
	authProvider AuthProvider
	authCtx      context.Context
	authCancel   context.CancelFunc
	authDone     chan struct{}
	events       chan Event
	secretAccess sync.Mutex
	secrets      []string
	errorAccess  sync.Mutex
	authError    error
	closeOnce    sync.Once
	closeErr     error
}

// NewClient creates a CSTP-only AnyConnect protocol client.
func NewClient(ctx context.Context, config Config, dialer Dialer, authProvider AuthProvider) (*Client, error) {
	if err := ValidateConfig(config, authProvider); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, invalidConfig("context is required")
	}
	if err := validateClientCertificate(config.ClientCertificate); err != nil {
		return nil, err
	}
	underlay, err := newSingDialer(dialer)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         config.ServerName,
		InsecureSkipVerify: config.SkipCertVerify, //nolint:gosec // Explicit user opt-in.
	}
	if len(config.CertificateAuthority) > 0 {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(config.CertificateAuthority) {
			return nil, invalidConfig("certificate authority is not valid PEM")
		}
		tlsConfig.RootCAs = roots
	} else if config.PeerFingerprint == "" && !config.SkipCertVerify {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, invalidConfig("load system certificate authorities")
		}
		tlsConfig.RootCAs = roots
	}
	tlsOptions := openconnect.ClientTLSOptions{
		Config:              tlsConfig,
		Certificate:         openconnect.Material{Content: append([]byte(nil), config.ClientCertificate...)},
		Key:                 openconnect.Material{Content: append([]byte(nil), config.ClientKey...)},
		KeyPassword:         config.ClientKeyPassword,
		SystemTrustDisabled: config.SkipCertVerify,
	}
	if config.PeerFingerprint != "" {
		tlsOptions.PeerFingerprints = []string{config.PeerFingerprint}
	}
	formEntries := make([]openconnect.FormEntry, 0, len(config.FormEntries))
	for _, entry := range config.FormEntries {
		formEntries = append(formEntries, openconnect.FormEntry{
			FormID:        entry.FormID,
			SubmissionKey: entry.SubmissionKey,
			Name:          entry.Name,
			Value:         entry.Value,
		})
	}
	var tokenOptions *openconnect.TokenOptions
	if config.Token != nil {
		tokenOptions = &openconnect.TokenOptions{
			Mode:          config.Token.Mode,
			Secret:        config.Token.Secret,
			Counter:       config.Token.Counter,
			UpdateCounter: config.Token.UpdateCounter,
		}
	}
	authCtx, authCancel := context.WithCancel(ctx)
	client := &Client{
		authProvider: authProvider,
		authCtx:      authCtx,
		authCancel:   authCancel,
		authDone:     make(chan struct{}),
		events:       make(chan Event, 16),
		secrets:      configSecrets(config),
	}
	core, err := openconnect.NewClient(openconnect.ClientOptions{
		Context:             ctx,
		Server:              config.Server,
		Cookie:              normalizeCookie(config.Cookie),
		Username:            config.Username,
		Password:            config.Password,
		AuthGroup:           config.AuthGroup,
		Token:               tokenOptions,
		NoUDP:               true,
		CompressionDisabled: true,
		IPv6Disabled:        true,
		MTU:                 config.MTU,
		TLSConfig:           tlsOptions,
		FormEntries:         formEntries,
		Dialer:              underlay,
		OnAuthenticationRejected: func(context.Context) {
			client.rejectAuthentication()
		},
		OnHostScanRequested: func(context.Context) error {
			client.publishEvent(Event{Type: EventHostScanRequested})
			return ErrHostScanPolicy
		},
	})
	if err != nil {
		authCancel()
		return nil, classifyClientError(err, client.secretsSnapshot())
	}
	client.core = core
	go client.runAuthBridge()
	return client, nil
}

func validateClientCertificate(content []byte) error {
	if len(content) == 0 {
		return nil
	}
	block, _ := pem.Decode(content)
	if block == nil || block.Type != "CERTIFICATE" {
		return newTerminalError(ErrTLSRejected, "anyconnect client certificate is not valid PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return newTerminalError(ErrTLSRejected, "anyconnect client certificate is invalid")
	}
	now := time.Now()
	if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return newTerminalError(ErrTLSRejected, "anyconnect client certificate is not currently valid")
	}
	return nil
}

func normalizeCookie(cookie string) string {
	if cookie == "" {
		return ""
	}
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
		if authErr := c.authenticationError(); authErr != nil {
			return NetworkConfig{}, authErr
		}
		return NetworkConfig{}, classifyClientError(err, c.secretsSnapshot())
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
	c.closeOnce.Do(func() {
		c.authCancel()
		c.closeErr = c.core.Close()
		<-c.authDone
		close(c.events)
	})
	return c.closeErr
}

// Events reports authentication and policy events without response secrets.
func (c *Client) Events() <-chan Event { return c.events }

func (c *Client) runAuthBridge() {
	defer close(c.authDone)
	for {
		challenge := c.core.PendingAuthChallenge()
		if challenge != nil {
			if !c.handleAuthChallenge(*challenge) {
				return
			}
			continue
		}
		updated := c.core.AuthChallengeUpdated()
		select {
		case <-c.authCtx.Done():
			return
		case <-updated:
		}
	}
}

func (c *Client) handleAuthChallenge(challenge openconnect.AuthChallenge) bool {
	mapped := sanitizeAuthChallenge(authChallengeFromCore(challenge), c.secretsSnapshot())
	eventType := EventAuthChallenge
	if mapped.Browser != nil {
		eventType = EventBrowserRequested
	}
	eventChallenge := sanitizeEventAuthChallenge(mapped, c.secretsSnapshot())
	c.publishEvent(Event{Type: eventType, Challenge: &eventChallenge})
	if c.authProvider == nil {
		c.failAuthentication(newTerminalError(ErrAuthRequired, ErrAuthRequired.Error()))
		return false
	}
	response, err := c.authProvider.Respond(c.authCtx, mapped)
	if err != nil {
		message := ErrAuthProvider.Error()
		if c.authCtx.Err() != nil {
			message += ": " + c.authCtx.Err().Error()
		}
		c.failAuthentication(newTerminalError(ErrAuthProvider, message))
		return false
	}
	c.registerAuthResponseSecrets(response)
	coreResponse := authResponseToCore(response)
	mergeCoreFormValues(challenge, mapped, &coreResponse)
	if err := c.core.CompleteAuthChallenge(challenge.ID, coreResponse); err != nil {
		c.failAuthentication(newTerminalError(ErrAuthProvider, ErrAuthProvider.Error()+": invalid response"))
		return false
	}
	return true
}

func mergeCoreFormValues(challenge openconnect.AuthChallenge, providerChallenge AuthChallenge, response *openconnect.AuthResponse) {
	if challenge.Form == nil || providerChallenge.Form == nil || response.Form == nil {
		return
	}
	if response.Form.Values == nil {
		response.Form.Values = make(map[string]string, len(challenge.Form.Fields))
	}
	for index, field := range challenge.Form.Fields {
		value, exists := response.Form.Values[field.SubmissionKey]
		if !exists || index < len(providerChallenge.Form.Fields) && field.Value != providerChallenge.Form.Fields[index].Value && value == providerChallenge.Form.Fields[index].Value {
			response.Form.Values[field.SubmissionKey] = field.Value
		}
	}
}

func (c *Client) failAuthentication(err error) {
	if c.setAuthenticationError(err) {
		_ = c.core.Close()
	}
}

func (c *Client) rejectAuthentication() {
	if c.setAuthenticationError(newTerminalError(ErrAuthRejected, ErrAuthRejected.Error())) {
		go func() { _ = c.core.Close() }()
	}
}

func (c *Client) setAuthenticationError(err error) bool {
	c.errorAccess.Lock()
	defer c.errorAccess.Unlock()
	if c.authError == nil {
		c.authError = err
		return true
	}
	return false
}

func (c *Client) authenticationError() error {
	c.errorAccess.Lock()
	defer c.errorAccess.Unlock()
	return c.authError
}

func (c *Client) publishEvent(event Event) {
	select {
	case c.events <- event:
	default:
	}
}

func configSecrets(config Config) []string {
	secrets := []string{config.Cookie, config.Password, config.ClientKeyPassword, string(config.ClientKey)}
	if config.Token != nil {
		secrets = append(secrets, config.Token.Secret)
	}
	for _, entry := range config.FormEntries {
		secrets = append(secrets, entry.Value)
	}
	return secrets
}

func (c *Client) secretsSnapshot() []string {
	c.secretAccess.Lock()
	defer c.secretAccess.Unlock()
	return append([]string(nil), c.secrets...)
}

func (c *Client) registerAuthResponseSecrets(response AuthResponse) {
	c.secretAccess.Lock()
	defer c.secretAccess.Unlock()
	for _, value := range response.FormValues {
		if value != "" {
			c.secrets = append(c.secrets, value)
		}
	}
	if response.Browser == nil {
		return
	}
	if response.Browser.FinalURL != "" {
		c.secrets = append(c.secrets, response.Browser.FinalURL)
	}
	for _, cookie := range response.Browser.Cookies {
		if cookie.Value != "" {
			c.secrets = append(c.secrets, cookie.Value)
		}
	}
	for _, values := range response.Browser.Header {
		for _, value := range values {
			if value != "" {
				c.secrets = append(c.secrets, value)
			}
		}
	}
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
