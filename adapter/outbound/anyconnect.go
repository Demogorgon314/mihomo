package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"
	ac "github.com/metacubex/mihomo/transport/anyconnect"

	M "github.com/metacubex/sing/common/metadata"
)

const defaultAnyConnectHandshakeTimeout = 30 * time.Second

type AnyConnect struct {
	*Base
	option AnyConnectOption
	config ac.Config
	dns    []dns.NameServer

	runCtx    context.Context
	runCancel context.CancelFunc

	access     sync.Mutex
	starting   chan struct{}
	session    *anyConnectSession
	startupErr error
	closed     bool
	closeOnce  sync.Once
	closeDone  chan struct{}
	closeErr   error
}

type AnyConnectOption struct {
	BasicOption
	Name             string         `proxy:"name"`
	Server           string         `proxy:"server"`
	Port             int            `proxy:"port"`
	Cookie           string         `proxy:"cookie,omitempty"`
	Username         string         `proxy:"username,omitempty"`
	Password         string         `proxy:"password,omitempty"`
	AuthGroup        string         `proxy:"authgroup,omitempty"`
	FormEntries      []ac.FormEntry `proxy:"form-entries,omitempty"`
	CA               string         `proxy:"ca,omitempty"`
	Cert             string         `proxy:"cert,omitempty"`
	Key              string         `proxy:"key,omitempty"`
	KeyPassword      string         `proxy:"key-password,omitempty"`
	ServerName       string         `proxy:"server-name,omitempty"`
	PeerFingerprint  string         `proxy:"peer-fingerprint,omitempty"`
	SkipCertVerify   bool           `proxy:"skip-cert-verify,omitempty"`
	TokenMode        string         `proxy:"token-mode,omitempty"`
	TokenSecret      string         `proxy:"token-secret,omitempty"`
	TokenCounter     uint64         `proxy:"token-counter,omitempty"`
	HandshakeTimeout int            `proxy:"handshake-timeout,omitempty"`
	MTU              int            `proxy:"mtu,omitempty"`
	BaseMTU          int            `proxy:"base-mtu,omitempty"`
	IPv6             bool           `proxy:"ipv6,omitempty"`
	Compression      string         `proxy:"compression,omitempty"`
	QueueLength      uint32         `proxy:"queue-length,omitempty"`
	DPDInterval      int            `proxy:"dpd-interval,omitempty"`
	ReconnectTimeout int            `proxy:"reconnect-timeout,omitempty"`
	RemoteDnsResolve bool           `proxy:"remote-dns-resolve,omitempty"`
	Dns              []string       `proxy:"dns,omitempty"`
	DTLSMode         string         `proxy:"dtls-mode,omitempty"`
	DTLSKeyExchange  string         `proxy:"dtls-key-exchange,omitempty"`
	LegacyDTLS       bool           `proxy:"legacy-dtls,omitempty"`

	AuthProvider       ac.AuthProvider                     `proxy:"-"`
	TokenCounterUpdate func(context.Context, uint64) error `proxy:"-"`
}

func NewAnyConnect(option AnyConnectOption) (*AnyConnect, error) {
	if strings.TrimSpace(option.Name) == "" {
		return nil, errors.New("anyconnect name is required")
	}
	if err := validateAnyConnectServer(option.Server); err != nil {
		return nil, err
	}
	if option.Port < 1 || option.Port > 65535 {
		return nil, errors.New("anyconnect port must be between 1 and 65535")
	}
	if strings.ContainsAny(option.Cookie, "\x00\r\n") {
		return nil, errors.New("anyconnect cookie contains an invalid character")
	}
	if option.HandshakeTimeout < 0 {
		return nil, errors.New("anyconnect handshake timeout must be non-negative")
	}
	if option.MTU != 0 && (option.MTU < 576 || option.MTU > 65535) {
		return nil, errors.New("anyconnect MTU must be between 576 and 65535")
	}
	if option.IPv6 && option.MTU != 0 && option.MTU < 1280 {
		return nil, errors.New("anyconnect IPv6 MTU must be at least 1280")
	}
	if option.BaseMTU != 0 && (option.BaseMTU < 576 || option.BaseMTU > 65535) {
		return nil, errors.New("anyconnect base MTU must be between 576 and 65535")
	}
	if option.DPDInterval < 0 {
		return nil, errors.New("anyconnect DPD interval must be non-negative")
	}
	if option.ReconnectTimeout < 0 {
		return nil, errors.New("anyconnect reconnect timeout must be non-negative")
	}
	if option.QueueLength > ac.MaximumQueueLength {
		return nil, fmt.Errorf("anyconnect packet queue length must not exceed %d", ac.MaximumQueueLength)
	}
	if len(option.Dns) > 0 && !option.RemoteDnsResolve {
		return nil, errors.New("anyconnect DNS override requires remote-dns-resolve")
	}
	if option.DTLSMode != "" && option.DTLSMode != ac.DTLSModeOff && option.DTLSMode != ac.DTLSModeAuto && option.DTLSMode != ac.DTLSModeRequire {
		return nil, fmt.Errorf("unsupported anyconnect DTLS mode %q; expected off, auto, or require", option.DTLSMode)
	}
	if option.LegacyDTLS && option.DTLSMode == ac.DTLSModeOff {
		return nil, errors.New("anyconnect legacy DTLS requires DTLS mode auto or require")
	}
	address := net.JoinHostPort(option.Server, fmt.Sprint(option.Port))
	config := ac.Config{
		Server:               "https://" + address,
		Cookie:               option.Cookie,
		Username:             option.Username,
		Password:             option.Password,
		AuthGroup:            option.AuthGroup,
		FormEntries:          option.FormEntries,
		ServerName:           option.ServerName,
		CertificateAuthority: []byte(option.CA),
		ClientCertificate:    []byte(option.Cert),
		ClientKey:            []byte(option.Key),
		ClientKeyPassword:    option.KeyPassword,
		PeerFingerprint:      option.PeerFingerprint,
		SkipCertVerify:       option.SkipCertVerify,
		MTU:                  uint32(option.MTU),
		BaseMTU:              uint32(option.BaseMTU),
		IPv6:                 option.IPv6,
		Compression:          option.Compression,
		QueueLength:          option.QueueLength,
		DPDInterval:          time.Duration(option.DPDInterval) * time.Second,
		ReconnectTimeout:     time.Duration(option.ReconnectTimeout) * time.Second,
		DTLSMode:             option.DTLSMode,
		DTLSKeyExchange:      option.DTLSKeyExchange,
		LegacyDTLS:           option.LegacyDTLS,
	}
	if option.TokenMode != "" || option.TokenSecret != "" || option.TokenCounter != 0 || option.TokenCounterUpdate != nil {
		config.Token = &ac.TokenConfig{
			Mode:          option.TokenMode,
			Secret:        option.TokenSecret,
			Counter:       option.TokenCounter,
			UpdateCounter: option.TokenCounterUpdate,
		}
	}
	if err := ac.ValidateConfig(config, option.AuthProvider); err != nil {
		return nil, err
	}
	if option.LegacyDTLS {
		log.Warnln("[AnyConnect](%s) legacy DTLS 0.9 enables deprecated MD5/SHA-1 handshake and AES-CBC record protection", option.Name)
	}
	runCtx, runCancel := context.WithCancel(context.Background())
	outbound := &AnyConnect{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         address,
			Type:         C.AnyConnect,
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
		parsedDNS, err := parseAnyConnectNameServers(option.Dns)
		if err != nil {
			runCancel()
			return nil, err
		}
		outbound.dns = parsedDNS
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}

func parseAnyConnectNameServers(servers []string) ([]dns.NameServer, error) {
	result := make([]dns.NameServer, 0, len(servers))
	for _, server := range servers {
		address, err := netip.ParseAddr(server)
		if err != nil {
			return nil, fmt.Errorf("anyconnect DNS override must be an IP address: %q", server)
		}
		result = append(result, dns.NameServer{Addr: net.JoinHostPort(address.String(), "53")})
	}
	return result, nil
}

func validateAnyConnectServer(server string) error {
	if strings.TrimSpace(server) == "" {
		return errors.New("anyconnect server is required")
	}
	if address, err := netip.ParseAddr(server); err == nil && address.IsValid() {
		return nil
	}
	parsed, err := url.Parse("https://" + server)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.EscapedPath() != "" {
		return errors.New("anyconnect server must be a hostname or IP address")
	}
	if parsed.Port() != "" {
		return errors.New("anyconnect server must not include a port")
	}
	return nil
}

func (o *AnyConnect) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
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
		return nil, errors.New("anyconnect connection is nil")
	}
	return NewConn(connection, o), nil
}

func (o *AnyConnect) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
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
		return nil, errors.New("anyconnect packet connection is nil")
	}
	return NewPacketConn(packetConn, o), nil
}

func (o *AnyConnect) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
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

func (o *AnyConnect) resolveUDP(ctx context.Context, metadata *C.Metadata, remoteResolver resolver.Resolver) error {
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

func (o *AnyConnect) resolverForConfig(configuration ac.NetworkConfig) (resolver.Resolver, error) {
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
		return nil, errors.New("AnyConnect server did not provide a DNS server")
	}
	for index := range nameservers {
		nameservers[index].ProxyAdapter = o
	}
	return dns.NewResolver(dns.Config{Main: nameservers, IPv6: networkConfigHasIPv6(configuration)}).Resolver, nil
}

func networkConfigHasIPv6(configuration ac.NetworkConfig) bool {
	for _, prefix := range configuration.Addresses {
		if prefix.Addr().Is6() {
			return true
		}
	}
	return false
}

func (o *AnyConnect) ProxyInfo() C.ProxyInfo {
	info := o.Base.ProxyInfo()
	info.DialerProxy = o.option.DialerProxy
	return info
}

func (o *AnyConnect) IsL3Protocol(*C.Metadata) bool {
	return true
}

func (o *AnyConnect) Close() error {
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

func (o *AnyConnect) run(ctx context.Context) (*anyConnectSession, error) {
	for {
		o.access.Lock()
		if o.closed {
			o.access.Unlock()
			return nil, net.ErrClosed
		}
		if o.startupErr != nil {
			err := o.startupErr
			o.access.Unlock()
			return nil, err
		}
		if o.session != nil {
			session := o.session
			o.access.Unlock()
			select {
			case <-session.done:
				return nil, session.err()
			default:
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

func (o *AnyConnect) start(starting chan struct{}) {
	timeout := defaultAnyConnectHandshakeTimeout
	if o.option.HandshakeTimeout > 0 {
		timeout = time.Duration(o.option.HandshakeTimeout) * time.Second
	}
	handshakeCtx, cancel := context.WithTimeout(o.runCtx, timeout)
	defer cancel()
	session, err := newAnyConnectSession(o.runCtx, handshakeCtx, o.config, o.dialer, o.option.AuthProvider, o.resolverForConfig, o.name)
	o.access.Lock()
	if err == nil && !o.closed {
		o.session = session
	} else {
		if session != nil {
			_ = session.close()
		}
		if err == nil {
			err = net.ErrClosed
		}
		o.startupErr = err
	}
	o.starting = nil
	close(starting)
	o.access.Unlock()
}
