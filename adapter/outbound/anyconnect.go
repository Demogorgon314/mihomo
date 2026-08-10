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

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	ac "github.com/metacubex/mihomo/transport/anyconnect"

	M "github.com/metacubex/sing/common/metadata"
)

const defaultAnyConnectHandshakeTimeout = 30 * time.Second

type AnyConnect struct {
	*Base
	option AnyConnectOption
	config ac.Config

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
	DTLSMode         string         `proxy:"dtls-mode,omitempty"`

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
	if option.DTLSMode != "" && option.DTLSMode != "off" {
		return nil, fmt.Errorf("unsupported anyconnect DTLS mode %q; only off is available", option.DTLSMode)
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
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
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
	if !metadata.Resolved() {
		ip, resolveErr := resolveIPWithResolver(ctx, metadata.Host, o.prefer, resolver.DefaultResolver)
		if resolveErr != nil {
			return nil, fmt.Errorf("can't resolve ip: %w", resolveErr)
		}
		metadata.DstIP = ip
	}
	connection, err := session.device.DialContext(ctx, "tcp", M.SocksaddrFrom(metadata.DstIP, metadata.DstPort).Unwrap())
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
	if err := o.resolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	packetConn, err := session.device.ListenPacket(ctx, M.SocksaddrFrom(metadata.DstIP, metadata.DstPort).Unwrap())
	if err != nil {
		return nil, err
	}
	if packetConn == nil {
		return nil, errors.New("anyconnect packet connection is nil")
	}
	return NewPacketConn(packetConn, o), nil
}

func (o *AnyConnect) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if _, err := o.run(ctx); err != nil {
		return err
	}
	return o.resolveUDP(ctx, metadata)
}

func (o *AnyConnect) resolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if !metadata.Resolved() && metadata.Host != "" {
		ip, err := resolveIPWithResolver(ctx, metadata.Host, o.prefer, resolver.DefaultResolver)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
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
	session, err := newAnyConnectSession(o.runCtx, handshakeCtx, o.config, o.dialer, o.option.AuthProvider, o.name)
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
