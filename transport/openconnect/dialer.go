package openconnect

import (
	"context"
	"errors"
	"net"
	"net/netip"

	M "github.com/sagernet/sing/common/metadata"
)

// Dialer is the mihomo underlay contract required by the protocol client.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	ListenPacket(ctx context.Context, network, address string, remote netip.AddrPort) (net.PacketConn, error)
}

type singDialer struct {
	dialer Dialer
}

func newSingDialer(dialer Dialer) (*singDialer, error) {
	if dialer == nil {
		return nil, invalidConfig("underlay dialer is required")
	}
	return &singDialer{dialer: dialer}, nil
}

func (d *singDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, destination.String())
}

func (d *singDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.Addr.IsValid() {
		return nil, errors.New("openconnect UDP destination must be resolved")
	}
	return d.dialer.ListenPacket(ctx, "udp", destination.String(), destination.AddrPort())
}
