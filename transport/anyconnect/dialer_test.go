package anyconnect

import (
	"context"
	"net"
	"net/netip"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

type stubDialer struct {
	network string
	address string
	remote  netip.AddrPort
}

func (d *stubDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	left, right := net.Pipe()
	_ = right.Close()
	return left, nil
}

func (d *stubDialer) ListenPacket(_ context.Context, network string, address string, remote netip.AddrPort) (net.PacketConn, error) {
	d.network = network
	d.address = address
	d.remote = remote
	return net.ListenPacket("udp4", "127.0.0.1:0")
}

func TestSingDialerConvertsResolvedUDPDestination(t *testing.T) {
	wrapped := new(stubDialer)
	dialer, err := newSingDialer(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	destination := M.SocksaddrFrom(netip.MustParseAddr("192.0.2.10"), 443)
	packetConn, err := dialer.ListenPacket(context.Background(), destination)
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	if wrapped.network != "udp" || wrapped.address != "192.0.2.10:443" || wrapped.remote != netip.MustParseAddrPort("192.0.2.10:443") {
		t.Fatalf("unexpected converted destination: network=%q address=%q remote=%s", wrapped.network, wrapped.address, wrapped.remote)
	}
}

func TestSingDialerRejectsUnresolvedUDPDestination(t *testing.T) {
	dialer, err := newSingDialer(new(stubDialer))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dialer.ListenPacket(context.Background(), M.ParseSocksaddr("vpn.example:443")); err == nil {
		t.Fatal("expected unresolved UDP destination error")
	}
}

func TestNormalizeCookie(t *testing.T) {
	if result := normalizeCookie("opaque=padding"); result != "webvpn=opaque=padding" {
		t.Fatalf("unexpected normalized cookie: %q", result)
	}
	if result := normalizeCookie("webvpn=already-named"); result != "webvpn=already-named" {
		t.Fatalf("named cookie changed: %q", result)
	}
}
