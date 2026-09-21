package outbound

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// openConnectStack owns tunnel sockets and exchanges complete IP packets with
// the VPN transport. Closing it must unblock packet I/O and all of its sockets.
type openConnectStack interface {
	N.Dialer
	Start() error
	Close() error
	Read(buffers [][]byte, sizes []int, offset int) (int, error)
	Write(buffers [][]byte, offset int) (int, error)
}

func newOpenConnectStack(backend string, addresses []netip.Prefix, mtu uint32) (openConnectStack, error) {
	if backend == "" {
		backend = ipStackGVisor
	}
	stack, err := newIPStack(IPStackOption{Mode: backend}, addresses, mtu)
	if err != nil {
		return nil, err
	}
	// Preserve gVisor's native Dialer and optional WriteGRO fast path.
	if device, ok := stack.(openConnectStack); ok {
		return device, nil
	}
	device := &openConnectMIPSStack{ipStack: stack}
	// Match the existing gVisor backend's source selection when the gateway
	// assigns multiple addresses in one family: bind the last such address.
	for _, prefix := range addresses {
		if prefix.Addr().Is4() {
			device.ipv4 = prefix.Addr()
		} else {
			device.ipv6 = prefix.Addr()
		}
	}
	return device, nil
}

type openConnectMIPSStack struct {
	ipStack
	ipv4 netip.Addr
	ipv6 netip.Addr
}

func (s *openConnectMIPSStack) source(destination M.Socksaddr) (netip.AddrPort, error) {
	address := s.ipv6
	if destination.IsIPv4() {
		address = s.ipv4
	}
	if !destination.Addr.IsValid() || !address.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("OpenConnect tunnel has no address for destination %s", destination)
	}
	return netip.AddrPortFrom(address, 0), nil
}

func (s *openConnectMIPSStack) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	source, err := s.source(destination)
	if err != nil {
		return nil, err
	}
	remote := netip.AddrPortFrom(destination.Addr, destination.Port)
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return s.DialTCP(ctx, network, source, remote)
	case N.NetworkUDP:
		return s.DialUDP(ctx, network, source, remote)
	default:
		return nil, fmt.Errorf("unsupported OpenConnect network %q", network)
	}
}

func (s *openConnectMIPSStack) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	source, err := s.source(destination)
	if err != nil {
		return nil, err
	}
	return s.ListenUDP(ctx, "udp", source)
}
