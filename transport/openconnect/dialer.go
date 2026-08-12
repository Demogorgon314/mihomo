package openconnect

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"

	M "github.com/sagernet/sing/common/metadata"
)

// Dialer is the mihomo underlay contract required by the protocol client.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	ListenPacket(ctx context.Context, network, address string, remote netip.AddrPort) (net.PacketConn, error)
}

type singDialer struct {
	dialer    Dialer
	localPort uint16
}

func newSingDialer(dialer Dialer, localPort uint16) (*singDialer, error) {
	if dialer == nil {
		return nil, invalidConfig("underlay dialer is required")
	}
	return &singDialer{dialer: dialer, localPort: localPort}, nil
}

func (d *singDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, destination.String())
}

func (d *singDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.Addr.IsValid() {
		return nil, errors.New("openconnect UDP destination must be resolved")
	}
	network := "udp"
	localAddress := ""
	if destination.IsIPv4() {
		network = "udp4"
		localAddress = net.IPv4zero.String()
	} else if destination.IsIPv6() {
		network = "udp6"
		localAddress = net.IPv6unspecified.String()
	}
	return d.dialer.ListenPacket(ctx, network, net.JoinHostPort(localAddress, strconv.Itoa(int(d.localPort))), destination.AddrPort())
}
