package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"
	oc "github.com/metacubex/mihomo/transport/openconnect"

	M "github.com/metacubex/sing/common/metadata"
)

const (
	defaultOpenConnectPort         = 443
	openConnectRetryInitialBackoff = 250 * time.Millisecond
	openConnectRetryMaximumBackoff = 30 * time.Second
)

type OpenConnect struct {
	*Base
	option OpenConnectOption
	config oc.Config
	dns    []dns.NameServer

	runCtx    context.Context
	runCancel context.CancelFunc

	access     sync.Mutex
	starting   chan struct{}
	session    *openConnectSession
	startupErr error
	retryAt    time.Time
	retryDelay time.Duration
	closed     bool
	closeOnce  sync.Once
	closeDone  chan struct{}
	closeErr   error
}

type OpenConnectOption struct {
	BasicOption
	Name                           string           `proxy:"name"`
	Protocol                       string           `proxy:"protocol,omitempty"`
	Server                         string           `proxy:"server"`
	Port                           int              `proxy:"port,omitempty"`
	Cookie                         string           `proxy:"cookie,omitempty"`
	Username                       string           `proxy:"username,omitempty"`
	Password                       string           `proxy:"password,omitempty"`
	AuthGroup                      string           `proxy:"authgroup,omitempty"`
	ReportedOS                     string           `proxy:"reported-os,omitempty"`
	UserAgent                      string           `proxy:"user-agent,omitempty"`
	Version                        string           `proxy:"version,omitempty"`
	LocalHostname                  string           `proxy:"local-hostname,omitempty"`
	Mobile                         *oc.MobileConfig `proxy:"mobile,omitempty"`
	FormEntries                    []oc.FormEntry   `proxy:"form-entries,omitempty"`
	CA                             string           `proxy:"ca,omitempty"`
	Cert                           string           `proxy:"cert,omitempty"`
	Key                            string           `proxy:"key,omitempty"`
	KeyPassword                    string           `proxy:"key-password,omitempty"`
	MCACertificate                 string           `proxy:"mca-certificate,omitempty"`
	MCAKey                         string           `proxy:"mca-key,omitempty"`
	MCAKeyPassword                 string           `proxy:"mca-key-password,omitempty"`
	CertExpireWarning              *int             `proxy:"cert-expire-warning,omitempty"`
	ServerName                     string           `proxy:"server-name,omitempty"`
	PeerFingerprint                string           `proxy:"peer-fingerprint,omitempty"`
	PeerFingerprints               []string         `proxy:"peer-fingerprints,omitempty"`
	SystemTrustDisabled            bool             `proxy:"system-trust-disabled,omitempty"`
	SkipCertVerify                 bool             `proxy:"skip-cert-verify,omitempty"`
	HTTPKeepAliveDisabled          bool             `proxy:"http-keepalive-disabled,omitempty"`
	XMLPostDisabled                bool             `proxy:"xml-post-disabled,omitempty"`
	ExternalAuthDisabled           bool             `proxy:"external-auth-disabled,omitempty"`
	PasswordAuthenticationDisabled bool             `proxy:"password-authentication-disabled,omitempty"`
	PFS                            bool             `proxy:"pfs,omitempty"`
	AllowInsecureCrypto            bool             `proxy:"allow-insecure-crypto,omitempty"`
	TokenMode                      string           `proxy:"token-mode,omitempty"`
	TokenSecret                    string           `proxy:"token-secret,omitempty"`
	TokenPIN                       string           `proxy:"token-pin,omitempty"`
	TokenPassword                  string           `proxy:"token-password,omitempty"`
	TokenDeviceID                  string           `proxy:"token-device-id,omitempty"`
	TokenCounter                   uint64           `proxy:"token-counter,omitempty"`
	HandshakeTimeout               int              `proxy:"handshake-timeout,omitempty"`
	MTU                            int              `proxy:"mtu,omitempty"`
	BaseMTU                        int              `proxy:"base-mtu,omitempty"`
	IPv6Disabled                   bool             `proxy:"ipv6-disabled,omitempty"`
	Compression                    string           `proxy:"compression,omitempty"`
	QueueLength                    uint32           `proxy:"queue-length,omitempty"`
	DPDInterval                    int              `proxy:"dpd-interval,omitempty"`
	ReconnectTimeout               int              `proxy:"reconnect-timeout,omitempty"`
	RemoteDnsResolve               bool             `proxy:"remote-dns-resolve,omitempty"`
	Dns                            []string         `proxy:"dns,omitempty"`
	DTLSMode                       string           `proxy:"dtls-mode,omitempty"`
	DTLSKeyExchange                string           `proxy:"dtls-key-exchange,omitempty"`
	LegacyDTLS                     *bool            `proxy:"legacy-dtls,omitempty"`
	DTLSLocalPort                  int              `proxy:"dtls-local-port,omitempty"`

	AuthProvider       oc.AuthProvider                     `proxy:"-"`
	TokenCounterUpdate func(context.Context, uint64) error `proxy:"-"`
}

func NewOpenConnect(option OpenConnectOption) (*OpenConnect, error) {
	if strings.TrimSpace(option.Name) == "" {
		return nil, errors.New("openconnect name is required")
	}
	if err := validateOpenConnectServer(option.Server); err != nil {
		return nil, err
	}
	if option.Port == 0 {
		option.Port = defaultOpenConnectPort
	}
	if option.Port < 1 || option.Port > 65535 {
		return nil, errors.New("openconnect port must be between 1 and 65535")
	}
	if strings.ContainsAny(option.Cookie, "\x00\r\n") {
		return nil, errors.New("openconnect cookie contains an invalid character")
	}
	if option.HandshakeTimeout < 0 {
		return nil, errors.New("openconnect handshake timeout must be non-negative")
	}
	if option.MTU != 0 && (option.MTU < 576 || option.MTU > 65535) {
		return nil, errors.New("openconnect MTU must be between 576 and 65535")
	}
	if !option.IPv6Disabled && option.MTU != 0 && option.MTU < 1280 {
		return nil, errors.New("openconnect IPv6 MTU must be at least 1280")
	}
	if option.BaseMTU != 0 && (option.BaseMTU < 576 || option.BaseMTU > 65535) {
		return nil, errors.New("openconnect base MTU must be between 576 and 65535")
	}
	if option.DPDInterval < 0 {
		return nil, errors.New("openconnect DPD interval must be non-negative")
	}
	if option.ReconnectTimeout < 0 {
		return nil, errors.New("openconnect reconnect timeout must be non-negative")
	}
	if option.DTLSLocalPort < 0 || option.DTLSLocalPort > 65535 {
		return nil, errors.New("openconnect DTLS local port must be between 0 and 65535")
	}
	var certificateExpiryWarning time.Duration
	certificateExpiryWarningDisabled := false
	if option.CertExpireWarning != nil {
		if *option.CertExpireWarning < 0 {
			return nil, errors.New("openconnect certificate expiry warning must be non-negative")
		}
		maximumDays := int64((time.Duration(1<<63 - 1)) / (24 * time.Hour))
		if int64(*option.CertExpireWarning) > maximumDays {
			return nil, errors.New("openconnect certificate expiry warning is too large")
		}
		if *option.CertExpireWarning == 0 {
			certificateExpiryWarningDisabled = true
		} else {
			certificateExpiryWarning = time.Duration(*option.CertExpireWarning) * 24 * time.Hour
		}
	}
	if option.QueueLength > oc.MaximumQueueLength {
		return nil, fmt.Errorf("openconnect packet queue length must not exceed %d", oc.MaximumQueueLength)
	}
	if len(option.Dns) > 0 && !option.RemoteDnsResolve {
		return nil, errors.New("openconnect DNS override requires remote-dns-resolve")
	}
	if option.DTLSMode != "" && option.DTLSMode != oc.DTLSModeOff && option.DTLSMode != oc.DTLSModeAuto && option.DTLSMode != oc.DTLSModeRequire {
		return nil, fmt.Errorf("unsupported openconnect DTLS mode %q; expected off, auto, or require", option.DTLSMode)
	}
	legacyDTLSDisabled := option.LegacyDTLS != nil && !*option.LegacyDTLS
	address := net.JoinHostPort(option.Server, fmt.Sprint(option.Port))
	config := oc.Config{
		Server:                           "https://" + address,
		Protocol:                         option.Protocol,
		Cookie:                           option.Cookie,
		Username:                         option.Username,
		Password:                         option.Password,
		AuthGroup:                        option.AuthGroup,
		ReportedOS:                       option.ReportedOS,
		UserAgent:                        option.UserAgent,
		Version:                          option.Version,
		LocalHostname:                    option.LocalHostname,
		Mobile:                           option.Mobile,
		FormEntries:                      option.FormEntries,
		ServerName:                       option.ServerName,
		CertificateAuthority:             []byte(option.CA),
		ClientCertificate:                []byte(option.Cert),
		ClientKey:                        []byte(option.Key),
		ClientKeyPassword:                option.KeyPassword,
		MCACertificate:                   []byte(option.MCACertificate),
		MCAKey:                           []byte(option.MCAKey),
		MCAKeyPassword:                   option.MCAKeyPassword,
		CertificateExpiryWarning:         certificateExpiryWarning,
		CertificateExpiryWarningDisabled: certificateExpiryWarningDisabled,
		PeerFingerprint:                  option.PeerFingerprint,
		PeerFingerprints:                 option.PeerFingerprints,
		SystemTrustDisabled:              option.SystemTrustDisabled,
		SkipCertVerify:                   option.SkipCertVerify,
		HTTPKeepAliveDisabled:            option.HTTPKeepAliveDisabled,
		XMLPostDisabled:                  option.XMLPostDisabled,
		ExternalAuthDisabled:             option.ExternalAuthDisabled,
		PasswordAuthenticationDisabled:   option.PasswordAuthenticationDisabled,
		PFS:                              option.PFS,
		AllowInsecureCrypto:              option.AllowInsecureCrypto,
		MTU:                              uint32(option.MTU),
		BaseMTU:                          uint32(option.BaseMTU),
		IPv6Disabled:                     option.IPv6Disabled,
		Compression:                      option.Compression,
		QueueLength:                      option.QueueLength,
		DPDInterval:                      time.Duration(option.DPDInterval) * time.Second,
		ReconnectTimeout:                 time.Duration(option.ReconnectTimeout) * time.Second,
		DTLSMode:                         option.DTLSMode,
		DTLSKeyExchange:                  option.DTLSKeyExchange,
		LegacyDTLSDisabled:               legacyDTLSDisabled,
		DTLSLocalPort:                    uint16(option.DTLSLocalPort),
		Logger:                           log.SingLogger,
	}
	if option.TokenMode != "" || option.TokenSecret != "" || option.TokenPIN != "" || option.TokenPassword != "" || option.TokenDeviceID != "" || option.TokenCounter != 0 || option.TokenCounterUpdate != nil {
		config.Token = &oc.TokenConfig{
			Mode:          option.TokenMode,
			Secret:        option.TokenSecret,
			PIN:           option.TokenPIN,
			Password:      option.TokenPassword,
			DeviceID:      option.TokenDeviceID,
			Counter:       option.TokenCounter,
			UpdateCounter: option.TokenCounterUpdate,
		}
	}
	if err := oc.ValidateConfig(config, option.AuthProvider); err != nil {
		return nil, err
	}
	runCtx, runCancel := context.WithCancel(context.Background())
	outbound := &OpenConnect{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         address,
			Type:         C.OpenConnect,
			ProviderName: option.ProviderName,
			UDP:          true,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:    option,
		runCtx:    runCtx,
		runCancel: runCancel,
		closeDone: make(chan struct{}),
		config:    config,
	}
	if option.RemoteDnsResolve && len(option.Dns) > 0 {
		parsedDNS, err := parseOpenConnectNameServers(option.Dns)
		if err != nil {
			runCancel()
			return nil, err
		}
		outbound.dns = parsedDNS
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}

func parseOpenConnectNameServers(servers []string) ([]dns.NameServer, error) {
	result := make([]dns.NameServer, 0, len(servers))
	for _, server := range servers {
		address, err := netip.ParseAddr(server)
		if err != nil {
			return nil, fmt.Errorf("openconnect DNS override must be an IP address: %q", server)
		}
		result = append(result, dns.NameServer{Addr: net.JoinHostPort(address.String(), "53")})
	}
	return result, nil
}

func validateOpenConnectServer(server string) error {
	if strings.TrimSpace(server) == "" {
		return errors.New("openconnect server is required")
	}
	if address, err := netip.ParseAddr(server); err == nil && address.IsValid() {
		return nil
	}
	parsed, err := url.Parse("https://" + server)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.EscapedPath() != "" {
		return errors.New("openconnect server must be a hostname or IP address")
	}
	if parsed.Port() != "" {
		return errors.New("openconnect server must not include a port")
	}
	return nil
}

func (o *OpenConnect) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	session, err := o.run(ctx)
	if err != nil {
		return nil, err
	}
	device, remoteResolver, err := session.currentDevice()
	if err != nil {
		return nil, err
	}
	var connection net.Conn
	if !metadata.Resolved() || remoteResolver != nil {
		if remoteResolver == nil {
			remoteResolver = resolver.DefaultResolver
		}
		options := o.DialOptions()
		options = append(options, dialer.WithResolver(remoteResolver), dialer.WithNetDialer(wgNetDialer{tunDevice: device}))
		connection, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	} else {
		connection, err = device.DialContext(ctx, "tcp", M.SocksaddrFrom(metadata.DstIP, metadata.DstPort).Unwrap())
	}
	if err != nil {
		return nil, err
	}
	if connection == nil {
		return nil, errors.New("openconnect connection is nil")
	}
	return NewConn(connection, o), nil
}

func (o *OpenConnect) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	session, err := o.run(ctx)
	if err != nil {
		return nil, err
	}
	device, remoteResolver, err := session.currentDevice()
	if err != nil {
		return nil, err
	}
	if err := o.resolveUDP(ctx, metadata, remoteResolver); err != nil {
		return nil, err
	}
	packetConn, err := device.ListenPacket(ctx, M.SocksaddrFrom(metadata.DstIP, metadata.DstPort).Unwrap())
	if err != nil {
		return nil, err
	}
	if packetConn == nil {
		return nil, errors.New("openconnect packet connection is nil")
	}
	return NewPacketConn(packetConn, o), nil
}

func (o *OpenConnect) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	session, err := o.run(ctx)
	if err != nil {
		return err
	}
	_, remoteResolver, err := session.currentDevice()
	if err != nil {
		return err
	}
	return o.resolveUDP(ctx, metadata, remoteResolver)
}

func (o *OpenConnect) resolveUDP(ctx context.Context, metadata *C.Metadata, remoteResolver resolver.Resolver) error {
	if (!metadata.Resolved() || remoteResolver != nil) && metadata.Host != "" {
		if remoteResolver == nil {
			remoteResolver = resolver.DefaultResolver
		}
		ip, err := resolveIPWithResolver(ctx, metadata.Host, o.prefer, remoteResolver)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

func (o *OpenConnect) resolverForConfig(configuration oc.NetworkConfig) (resolver.Resolver, error) {
	if !o.option.RemoteDnsResolve {
		return nil, nil
	}
	nameservers := append([]dns.NameServer(nil), o.dns...)
	if len(nameservers) == 0 {
		for _, address := range configuration.DNS {
			nameservers = append(nameservers, dns.NameServer{Addr: net.JoinHostPort(address.String(), "53")})
		}
	}
	if len(nameservers) == 0 {
		return nil, errors.New("OpenConnect server did not provide a DNS server")
	}
	for index := range nameservers {
		nameservers[index].ProxyAdapter = o
	}
	return dns.NewResolver(dns.Config{Main: nameservers, IPv6: networkConfigHasIPv6(configuration)}).Resolver, nil
}

func networkConfigHasIPv6(configuration oc.NetworkConfig) bool {
	for _, prefix := range configuration.Addresses {
		if prefix.Addr().Is6() {
			return true
		}
	}
	return false
}

func (o *OpenConnect) ProxyInfo() C.ProxyInfo {
	info := o.Base.ProxyInfo()
	info.DialerProxy = o.option.DialerProxy
	return info
}

func (o *OpenConnect) IsL3Protocol(*C.Metadata) bool {
	return true
}

func (o *OpenConnect) Close() error {
	o.closeOnce.Do(func() {
		o.access.Lock()
		o.closed = true
		o.runCancel()
		starting := o.starting
		session := o.session
		o.access.Unlock()
		if starting != nil {
			<-starting
			o.access.Lock()
			session = o.session
			o.access.Unlock()
		}
		if session != nil {
			o.closeErr = session.close()
		}
		close(o.closeDone)
	})
	<-o.closeDone
	return o.closeErr
}

func (o *OpenConnect) run(ctx context.Context) (*openConnectSession, error) {
	for {
		o.access.Lock()
		if o.closed {
			o.access.Unlock()
			return nil, net.ErrClosed
		}
		if o.startupErr != nil {
			err := o.startupErr
			if retryableOpenConnectError(err) && !time.Now().Before(o.retryAt) {
				o.startupErr = nil
				o.retryAt = time.Time{}
			} else {
				o.access.Unlock()
				return nil, err
			}
		}
		if o.session != nil {
			session := o.session
			select {
			case <-session.done:
				err := session.err()
				o.session = nil
				o.recordFailureLocked(err)
				o.access.Unlock()
				return nil, err
			default:
				o.access.Unlock()
				return session, nil
			}
		}
		starting := o.starting
		if starting == nil {
			starting = make(chan struct{})
			o.starting = starting
			go o.start(starting)
		}
		o.access.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-starting:
		}
	}
}

func (o *OpenConnect) start(starting chan struct{}) {
	var timeout time.Duration
	if o.option.HandshakeTimeout > 0 {
		timeout = time.Duration(o.option.HandshakeTimeout) * time.Second
	}
	handshakeCtx, cancel := openConnectHandshakeContext(o.runCtx, timeout)
	defer cancel()
	session, err := newAnyConnectSession(o.runCtx, handshakeCtx, o.config, o.dialer, o.option.AuthProvider, o.resolverForConfig, o.name)
	o.access.Lock()
	if err == nil && !o.closed {
		o.session = session
		o.startupErr = nil
		o.retryAt = time.Time{}
		o.retryDelay = 0
	} else {
		if session != nil {
			_ = session.close()
		}
		if err == nil {
			err = net.ErrClosed
		}
		o.recordFailureLocked(err)
	}
	o.starting = nil
	close(starting)
	o.access.Unlock()
}

func (o *OpenConnect) recordFailureLocked(err error) {
	o.startupErr = err
	if !retryableOpenConnectError(err) {
		o.retryAt = time.Time{}
		return
	}
	if o.retryDelay == 0 {
		o.retryDelay = openConnectRetryInitialBackoff
	} else {
		o.retryDelay = min(o.retryDelay*2, openConnectRetryMaximumBackoff)
	}
	o.retryAt = time.Now().Add(o.retryDelay)
}

func retryableOpenConnectError(err error) bool {
	if err == nil || oc.IsTerminal(err) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, oc.ErrReconnectTimeout) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError)
}

func openConnectHandshakeContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout == 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}
