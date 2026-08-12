package openconnect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
)

const (
	modernDTLSCipherSuites      = "PSK-NEGOTIATE:OC2-DTLS1_2-CHACHA20-POLY1305:OC-DTLS1_2-AES256-GCM:OC-DTLS1_2-AES128-GCM"
	resumptionDTLSCipherSuites  = "OC-DTLS1_2-AES256-GCM:OC-DTLS1_2-AES128-GCM"
	legacyDTLSCipherSuiteSuffix = ":DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:AES256-SHA:AES128-SHA"
	modernDTLS12CipherSuites    = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256"
	maximumIncomingPacketBatch  = 64
)

// NetworkConfig is a caller-owned snapshot of the negotiated tunnel settings.
type NetworkConfig struct {
	RemoteAddress            netip.Addr
	Addresses                []netip.Prefix
	Routes                   []netip.Prefix
	ExcludedRoutes           []netip.Prefix
	DNS                      []netip.Addr
	NBNS                     []netip.Addr
	SearchDomains            []string
	SplitDNS                 []string
	SplitDNSRules            []NetworkSplitDNSRule
	ProxyAutoConfigURL       string
	Banner                   string
	TunnelAllDNS             bool
	ClientBypassProtocol     bool
	IdleTimeout              time.Duration
	AuthenticationExpiration time.Time
	ActiveTransport          string
	MTU                      uint32
}

type NetworkSplitDNSRule struct {
	Domains []string
	Servers []netip.Addr
}

type NetworkConfigEventReason string

const (
	NetworkConfigInitial         NetworkConfigEventReason = "initial"
	NetworkConfigReestablishment NetworkConfigEventReason = "reestablishment"
	NetworkConfigRekey           NetworkConfigEventReason = "rekey"
	NetworkConfigPathMTU         NetworkConfigEventReason = "path-mtu"
)

type NetworkConfigEvent struct {
	Reason   NetworkConfigEventReason
	Revision uint64
	Config   NetworkConfig
}

// Client isolates the outbound package from sing-openconnect types.
type Client struct {
	core                 *openconnect.Client
	authProvider         AuthProvider
	authCtx              context.Context
	authCancel           context.CancelFunc
	authDone             chan struct{}
	events               chan Event
	eventAccess          sync.Mutex
	eventsClosed         bool
	secretAccess         sync.Mutex
	secrets              []string
	errorAccess          sync.Mutex
	authError            error
	networkAccess        sync.Mutex
	networkConfig        NetworkConfig
	networkRevision      uint64
	networkApplied       bool
	networkHandler       func(NetworkConfigEvent) error
	networkUpdated       chan struct{}
	networkError         error
	dtlsMode             string
	transportAccess      sync.Mutex
	dtlsReady            bool
	transportError       error
	transportMonitorOnce sync.Once
	transportMonitorDone chan struct{}
	closeOnce            sync.Once
	closeErr             error
}

// NewClient creates an OpenConnect client for the configured VPN protocol.
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
		authProvider:         authProvider,
		authCtx:              authCtx,
		authCancel:           authCancel,
		authDone:             make(chan struct{}),
		events:               make(chan Event, 16),
		secrets:              configSecrets(config),
		networkHandler:       config.OnNetworkConfig,
		networkUpdated:       make(chan struct{}),
		dtlsMode:             normalizeDTLSMode(config.DTLSMode),
		transportMonitorDone: make(chan struct{}),
	}
	compressionDisabled := config.Compression == CompressionOff
	compressionMode := openconnect.CompressionModeStateless
	if config.Compression == CompressionAll {
		compressionMode = openconnect.CompressionModeAll
	}
	dtlsCipherSuites := modernDTLSCipherSuites
	if config.DTLSKeyExchange == DTLSKeyExchangeResumption {
		dtlsCipherSuites = resumptionDTLSCipherSuites
	} else if !config.LegacyDTLSDisabled {
		dtlsCipherSuites += legacyDTLSCipherSuiteSuffix
	}
	core, err := openconnect.NewClient(openconnect.ClientOptions{
		Context:             ctx,
		Server:              config.Server,
		Flavor:              normalizeProtocol(config.Protocol),
		Cookie:              normalizeCookie(config.Cookie),
		Username:            config.Username,
		Password:            config.Password,
		AuthGroup:           config.AuthGroup,
		Token:               tokenOptions,
		NoUDP:               normalizeDTLSMode(config.DTLSMode) == DTLSModeOff,
		DTLSRequired:        normalizeDTLSMode(config.DTLSMode) == DTLSModeRequire,
		LegacyDTLSDisabled:  config.LegacyDTLSDisabled,
		DTLSCipherSuites:    dtlsCipherSuites,
		DTLS12CipherSuites:  modernDTLS12CipherSuites,
		CompressionDisabled: compressionDisabled,
		CompressionMode:     compressionMode,
		IPv6Disabled:        config.IPv6Disabled,
		MTU:                 config.MTU,
		BaseMTU:             config.BaseMTU,
		QueueLength:         config.QueueLength,
		DPDInterval:         config.DPDInterval,
		ReconnectTimeout:    config.ReconnectTimeout,
		TLSConfig:           tlsOptions,
		FormEntries:         formEntries,
		Dialer:              underlay,
		Logger:              config.Logger,
		OnAuthenticationRejected: func(context.Context) {
			client.rejectAuthentication()
		},
		OnHostScanRequested: func(context.Context) error {
			client.publishEvent(Event{Type: EventHostScanRequested})
			return ErrHostScanPolicy
		},
		OnTunnelConfiguration: client.handleNetworkConfigEvent,
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
		return newTerminalError(ErrTLSRejected, "openconnect client certificate is not valid PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return newTerminalError(ErrTLSRejected, "openconnect client certificate is invalid")
	}
	now := time.Now()
	if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return newTerminalError(ErrTLSRejected, "openconnect client certificate is not currently valid")
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

func normalizeDTLSMode(mode string) string {
	if mode == "" {
		return DTLSModeAuto
	}
	return mode
}

func (c *Client) Start() error {
	if err := c.core.Start(); err != nil {
		return err
	}
	c.transportMonitorOnce.Do(func() {
		go c.runActiveTransportMonitor()
	})
	return nil
}

func (c *Client) WaitReady(ctx context.Context) (NetworkConfig, error) {
	if err := c.transportFailure(); err != nil {
		return NetworkConfig{}, err
	}
	configuration, err := c.core.WaitReady(ctx)
	if err != nil {
		if transportErr := c.transportFailure(); transportErr != nil {
			return NetworkConfig{}, transportErr
		}
		if c.dtlsMode == DTLSModeRequire && c.core.ActiveTransport() == openconnect.TransportCSTP {
			return NetworkConfig{}, fmt.Errorf("%w: %v", ErrDTLSRequired, err)
		}
		if authErr := c.authenticationError(); authErr != nil {
			return NetworkConfig{}, authErr
		}
		return NetworkConfig{}, classifyClientError(err, c.secretsSnapshot())
	}
	result := networkConfigFromCore(configuration)
	result.ActiveTransport = c.core.ActiveTransport()
	if err := c.waitNetworkConfig(ctx, result); err != nil {
		return NetworkConfig{}, err
	}
	if err := c.ensureDTLSTransport(ctx); err != nil {
		return NetworkConfig{}, err
	}
	result.ActiveTransport = c.core.ActiveTransport()
	return cloneNetworkConfig(result), nil
}

// WaitDataPlaneReady waits until the current network configuration is applied
// locally and returns the revision that is safe for packet I/O.
func (c *Client) WaitDataPlaneReady(ctx context.Context) (uint64, error) {
	if err := c.transportFailure(); err != nil {
		return 0, err
	}
	revision, err := c.core.WaitReadyRevision(ctx)
	if err != nil {
		if transportErr := c.transportFailure(); transportErr != nil {
			return 0, transportErr
		}
		if c.dtlsMode == DTLSModeRequire && c.core.ActiveTransport() == openconnect.TransportCSTP {
			return 0, fmt.Errorf("%w: %v", ErrDTLSRequired, err)
		}
		if authErr := c.authenticationError(); authErr != nil {
			return 0, authErr
		}
		return 0, classifyClientError(err, c.secretsSnapshot())
	}
	if err := c.waitNetworkRevision(ctx, revision); err != nil {
		return 0, err
	}
	if err := c.ensureDTLSTransport(ctx); err != nil {
		return 0, err
	}
	return revision, nil
}

func (c *Client) ReadPacket(ctx context.Context) ([]byte, error) {
	packet, _, err := c.ReadPacketWithRevision(ctx)
	return packet, err
}

// ReadPacketWithRevision returns a packet and the applied network revision that
// received it.
func (c *Client) ReadPacketWithRevision(ctx context.Context) ([]byte, uint64, error) {
	for {
		packet, packetRevision, err := c.core.ReadDataPacketWithRevision(ctx)
		if err != nil {
			if transportErr := c.transportFailure(); transportErr != nil {
				return nil, 0, transportErr
			}
			return nil, 0, err
		}
		readyRevision, err := c.WaitDataPlaneReady(ctx)
		if err != nil {
			return nil, 0, err
		}
		if readyRevision != packetRevision {
			continue
		}
		return packet, packetRevision, nil
	}
}

// ReadPacketsWithRevision returns currently available packets from the active
// data-plane revision. The caller must invoke release after it has finished
// using every returned packet.
func (c *Client) ReadPacketsWithRevision(ctx context.Context) ([][]byte, uint64, func(), error) {
	for {
		packetBuffers, packetRevision, err := c.core.ReadDataPacketsWithRevision(ctx, maximumIncomingPacketBatch)
		if err != nil {
			if transportErr := c.transportFailure(); transportErr != nil {
				return nil, 0, nil, transportErr
			}
			return nil, 0, nil, err
		}
		readyRevision, err := c.WaitDataPlaneReady(ctx)
		if err != nil {
			for _, packetBuffer := range packetBuffers {
				packetBuffer.Release()
			}
			return nil, 0, nil, err
		}
		if readyRevision != packetRevision {
			for _, packetBuffer := range packetBuffers {
				packetBuffer.Release()
			}
			continue
		}
		packets := make([][]byte, len(packetBuffers))
		for index, packetBuffer := range packetBuffers {
			packets[index] = packetBuffer.Bytes()
		}
		var releaseOnce sync.Once
		return packets, packetRevision, func() {
			releaseOnce.Do(func() {
				for _, packetBuffer := range packetBuffers {
					packetBuffer.Release()
				}
			})
		}, nil
	}
}

func (c *Client) WritePacket(packet []byte) error {
	if err := c.ensureDTLSTransport(c.authCtx); err != nil {
		return err
	}
	return c.core.WriteDataPacket(packet)
}

// WritePacketAtRevision writes a packet only while revision still identifies
// the active data plane.
func (c *Client) WritePacketAtRevision(packet []byte, revision uint64) error {
	return c.WritePacketsAtRevision([][]byte{packet}, revision)
}

// WritePacketsAtRevision writes packets only while revision still identifies
// the active data plane.
func (c *Client) WritePacketsAtRevision(packets [][]byte, revision uint64) error {
	if err := c.ensureDTLSTransport(c.authCtx); err != nil {
		return err
	}
	return c.core.WriteDataPacketsAtRevision(packets, revision)
}

func (c *Client) ActiveTransport() string {
	return c.core.ActiveTransport()
}

func (c *Client) runActiveTransportMonitor() {
	defer close(c.transportMonitorDone)
	lastTransport := ""
	for {
		updated := c.core.ActiveTransportUpdated()
		transport := c.core.ActiveTransport()
		c.observeActiveTransport(transport)
		if transport != "" && transport != lastTransport {
			c.publishEvent(Event{Type: EventActiveTransport, ActiveTransport: transport})
		}
		lastTransport = transport
		select {
		case <-c.authCtx.Done():
			return
		case <-updated:
		}
	}
}

func (c *Client) ensureDTLSTransport(ctx context.Context) error {
	if c.dtlsMode != DTLSModeRequire {
		return nil
	}
	for {
		updated := c.core.ActiveTransportUpdated()
		transport := c.core.ActiveTransport()
		if err := c.observeActiveTransport(transport); err != nil {
			return err
		}
		if transport == openconnect.TransportDTLS {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %v", ErrDTLSRequired, ctx.Err())
		case <-updated:
		}
	}
}

func (c *Client) observeActiveTransport(transport string) error {
	c.transportAccess.Lock()
	if transport == openconnect.TransportDTLS {
		c.dtlsReady = true
	}
	failed := c.dtlsMode == DTLSModeRequire && c.dtlsReady && transport == openconnect.TransportCSTP && c.transportError == nil
	if failed {
		c.transportError = ErrDTLSRequired
	}
	err := c.transportError
	c.transportAccess.Unlock()
	if failed {
		go func() { _ = c.core.Close() }()
	}
	return err
}

func (c *Client) transportFailure() error {
	c.transportAccess.Lock()
	defer c.transportAccess.Unlock()
	return c.transportError
}

func (c *Client) handleNetworkConfigEvent(event openconnect.TunnelConfigurationEvent) error {
	configuration := networkConfigFromCore(event.Configuration)
	configuration.ActiveTransport = c.core.ActiveTransport()
	mapped := NetworkConfigEvent{Reason: NetworkConfigEventReason(event.Reason), Revision: event.Revision, Config: configuration}
	eventConfiguration := sanitizeNetworkConfigForEvent(configuration, c.secretsSnapshot())
	c.publishEvent(Event{Type: EventNetworkConfig, NetworkConfig: &eventConfiguration, NetworkReason: mapped.Reason})
	return c.applyNetworkConfig(mapped)
}

func (c *Client) applyNetworkConfig(event NetworkConfigEvent) error {
	c.networkAccess.Lock()
	defer c.networkAccess.Unlock()
	if c.networkHandler != nil {
		if err := c.networkHandler(NetworkConfigEvent{Reason: event.Reason, Revision: event.Revision, Config: cloneNetworkConfig(event.Config)}); err != nil {
			c.networkError = err
			c.signalNetworkUpdatedLocked()
			return err
		}
	}
	c.networkConfig = cloneNetworkConfig(event.Config)
	c.networkRevision = event.Revision
	c.networkApplied = true
	c.signalNetworkUpdatedLocked()
	return nil
}

func (c *Client) waitNetworkRevision(ctx context.Context, revision uint64) error {
	for {
		c.networkAccess.Lock()
		if c.networkError != nil {
			err := c.networkError
			c.networkAccess.Unlock()
			return err
		}
		if c.networkApplied && c.networkRevision >= revision {
			c.networkAccess.Unlock()
			return nil
		}
		updated := c.networkUpdated
		c.networkAccess.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-updated:
		}
	}
}

func (c *Client) waitNetworkConfig(ctx context.Context, configuration NetworkConfig) error {
	for {
		c.networkAccess.Lock()
		if c.networkError != nil {
			err := c.networkError
			c.networkAccess.Unlock()
			return err
		}
		if c.networkApplied && sameNetworkConfig(c.networkConfig, configuration) {
			c.networkAccess.Unlock()
			return nil
		}
		updated := c.networkUpdated
		c.networkAccess.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-updated:
		}
	}
}

func (c *Client) signalNetworkUpdatedLocked() {
	close(c.networkUpdated)
	c.networkUpdated = make(chan struct{})
}

func sameNetworkConfig(left NetworkConfig, right NetworkConfig) bool {
	if left.RemoteAddress != right.RemoteAddress || left.MTU != right.MTU ||
		left.ProxyAutoConfigURL != right.ProxyAutoConfigURL || left.Banner != right.Banner ||
		left.TunnelAllDNS != right.TunnelAllDNS || left.ClientBypassProtocol != right.ClientBypassProtocol ||
		left.IdleTimeout != right.IdleTimeout || !left.AuthenticationExpiration.Equal(right.AuthenticationExpiration) ||
		!slices.Equal(left.Addresses, right.Addresses) || !slices.Equal(left.Routes, right.Routes) ||
		!slices.Equal(left.ExcludedRoutes, right.ExcludedRoutes) || !slices.Equal(left.DNS, right.DNS) ||
		!slices.Equal(left.NBNS, right.NBNS) || !slices.Equal(left.SearchDomains, right.SearchDomains) ||
		!slices.Equal(left.SplitDNS, right.SplitDNS) || len(left.SplitDNSRules) != len(right.SplitDNSRules) {
		return false
	}
	for index := range left.SplitDNSRules {
		if !slices.Equal(left.SplitDNSRules[index].Domains, right.SplitDNSRules[index].Domains) ||
			!slices.Equal(left.SplitDNSRules[index].Servers, right.SplitDNSRules[index].Servers) {
			return false
		}
	}
	return true
}

func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.authCancel()
		c.closeErr = c.core.Close()
		<-c.authDone
		c.transportMonitorOnce.Do(func() { close(c.transportMonitorDone) })
		<-c.transportMonitorDone
		c.networkAccess.Lock()
		c.networkError = openconnect.ErrClientClosed
		c.signalNetworkUpdatedLocked()
		c.networkAccess.Unlock()
		c.eventAccess.Lock()
		c.eventsClosed = true
		close(c.events)
		c.eventAccess.Unlock()
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
	c.eventAccess.Lock()
	defer c.eventAccess.Unlock()
	if c.eventsClosed {
		return
	}
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
		RemoteAddress:            configuration.RemoteAddress,
		Addresses:                append([]netip.Prefix(nil), configuration.Addresses...),
		DNS:                      append([]netip.Addr(nil), configuration.DNS...),
		NBNS:                     append([]netip.Addr(nil), configuration.NBNS...),
		SearchDomains:            append([]string(nil), configuration.SearchDomains...),
		SplitDNS:                 append([]string(nil), configuration.SplitDNS...),
		ProxyAutoConfigURL:       configuration.ProxyAutoConfigURL,
		Banner:                   configuration.Banner,
		TunnelAllDNS:             configuration.TunnelAllDNS,
		ClientBypassProtocol:     configuration.ClientBypassProtocol,
		IdleTimeout:              configuration.IdleTimeout,
		AuthenticationExpiration: configuration.AuthenticationExpiration,
		MTU:                      configuration.MTU,
	}
	result.Routes = make([]netip.Prefix, 0, len(configuration.Routes))
	for _, route := range configuration.Routes {
		result.Routes = append(result.Routes, route.Prefix)
	}
	result.ExcludedRoutes = make([]netip.Prefix, 0, len(configuration.ExcludedRoutes))
	for _, route := range configuration.ExcludedRoutes {
		result.ExcludedRoutes = append(result.ExcludedRoutes, route.Prefix)
	}
	result.SplitDNSRules = make([]NetworkSplitDNSRule, len(configuration.SplitDNSRules))
	for index, rule := range configuration.SplitDNSRules {
		result.SplitDNSRules[index] = NetworkSplitDNSRule{
			Domains: append([]string(nil), rule.Domains...),
			Servers: append([]netip.Addr(nil), rule.Servers...),
		}
	}
	return result
}

func cloneNetworkConfig(configuration NetworkConfig) NetworkConfig {
	configuration.Addresses = append([]netip.Prefix(nil), configuration.Addresses...)
	configuration.Routes = append([]netip.Prefix(nil), configuration.Routes...)
	configuration.ExcludedRoutes = append([]netip.Prefix(nil), configuration.ExcludedRoutes...)
	configuration.DNS = append([]netip.Addr(nil), configuration.DNS...)
	configuration.NBNS = append([]netip.Addr(nil), configuration.NBNS...)
	configuration.SearchDomains = append([]string(nil), configuration.SearchDomains...)
	configuration.SplitDNS = append([]string(nil), configuration.SplitDNS...)
	configuration.SplitDNSRules = append([]NetworkSplitDNSRule(nil), configuration.SplitDNSRules...)
	for index := range configuration.SplitDNSRules {
		configuration.SplitDNSRules[index].Domains = append([]string(nil), configuration.SplitDNSRules[index].Domains...)
		configuration.SplitDNSRules[index].Servers = append([]netip.Addr(nil), configuration.SplitDNSRules[index].Servers...)
	}
	return configuration
}

func sanitizeNetworkConfigForEvent(configuration NetworkConfig, secrets []string) NetworkConfig {
	configuration = cloneNetworkConfig(configuration)
	configuration.ProxyAutoConfigURL = redactErrorMessage(configuration.ProxyAutoConfigURL, secrets)
	configuration.Banner = redactErrorMessage(configuration.Banner, secrets)
	redactStrings(configuration.SearchDomains, secrets)
	redactStrings(configuration.SplitDNS, secrets)
	for index := range configuration.SplitDNSRules {
		redactStrings(configuration.SplitDNSRules[index].Domains, secrets)
	}
	return configuration
}
