//go:build with_gvisor

package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	testopenconnect "github.com/metacubex/mihomo/internal/testutil/openconnect"
	oc "github.com/metacubex/mihomo/transport/openconnect"
)

func TestF5OutboundTCPAndUDPPPPOverTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	scenario := testopenconnect.BasicF5Scenario()
	peer, err := testopenconnect.NewIPv4TCPUDPEchoPeer(ctx, scenario.PeerAddress, testAnyConnectTCPPort, testAnyConnectUDPPort)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := peer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	}()
	gateway, err := testopenconnect.StartF5Gateway(ctx, scenario, peer)
	if err != nil {
		t.Fatal(err)
	}
	dialer := new(openConnectRecordingDialer)
	outbound, err := NewOpenConnect(OpenConnectOption{
		BasicOption:  BasicOption{DialerForAPI: dialer},
		Name:         "fake-f5",
		Protocol:     oc.ProtocolF5,
		Server:       "127.0.0.1",
		Port:         gateway.Port(),
		Cookie:       scenario.CookieHeader(),
		CA:           string(gateway.CAPEM()),
		ServerName:   gateway.ServerName(),
		IPv6Disabled: true,
		DTLSMode:     oc.DTLSModeOff,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := outbound.Close(); err != nil {
			t.Error(err)
		}
		if err := gateway.Close(); err != nil {
			t.Error(err)
		}
	}()

	connection, err := outbound.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: scenario.PeerAddress, DstPort: testAnyConnectTCPPort})
	if err != nil {
		t.Fatal(err)
	}
	tcpPayload := []byte("F5 PPP TLS TCP echo")
	if _, err := connection.Write(tcpPayload); err != nil {
		t.Fatal(err)
	}
	tcpReply := make([]byte, len(tcpPayload))
	if _, err := io.ReadFull(connection, tcpReply); err != nil {
		t.Fatal(err)
	}
	if string(tcpReply) != string(tcpPayload) {
		t.Fatalf("unexpected F5 TCP echo: %q", tcpReply)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	packetConnection, err := outbound.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: scenario.PeerAddress, DstPort: testAnyConnectUDPPort})
	if err != nil {
		t.Fatal(err)
	}
	destination := &net.UDPAddr{IP: scenario.PeerAddress.AsSlice(), Port: testAnyConnectUDPPort}
	exchangeAnyConnectUDP(t, ctx, packetConnection, destination, "F5 PPP TLS UDP echo")
	if err := packetConnection.Close(); err != nil {
		t.Fatal(err)
	}

	tcpCalls, udpCalls := dialer.counts()
	if tcpCalls < 2 || udpCalls != 0 {
		t.Fatalf("unexpected F5 underlay calls: tcp=%d udp=%d", tcpCalls, udpCalls)
	}
	if gateway.TunnelConnections() != 1 {
		t.Fatalf("unexpected F5 tunnel count: %d", gateway.TunnelConnections())
	}
}

func TestF5OutboundCertificateDTLSAndTLSFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	scenario := testopenconnect.BasicF5Scenario()
	scenario.DTLS = true
	peer, err := testopenconnect.NewIPv4TCPUDPEchoPeer(ctx, scenario.PeerAddress, testAnyConnectTCPPort, testAnyConnectUDPPort)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	gateway, err := testopenconnect.StartF5Gateway(ctx, scenario, peer)
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := NewOpenConnect(OpenConnectOption{
		BasicOption:  BasicOption{DialerForAPI: new(openConnectRecordingDialer)},
		Name:         "fake-f5-dtls",
		Protocol:     oc.ProtocolF5,
		Server:       "127.0.0.1",
		Port:         gateway.Port(),
		Cookie:       scenario.CookieHeader(),
		CA:           string(gateway.CAPEM()),
		ServerName:   gateway.ServerName(),
		IPv6Disabled: true,
		DTLSMode:     oc.DTLSModeAuto,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := outbound.Close(); err != nil {
			t.Error(err)
		}
		if err := gateway.Close(); err != nil {
			t.Error(err)
		}
	}()
	session, err := outbound.run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	waitAnyConnectTransport(t, ctx, session, "dtls")
	packetConnection, err := outbound.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: scenario.PeerAddress, DstPort: testAnyConnectUDPPort})
	if err != nil {
		t.Fatal(err)
	}
	destination := &net.UDPAddr{IP: scenario.PeerAddress.AsSlice(), Port: testAnyConnectUDPPort}
	exchangeAnyConnectUDP(t, ctx, packetConnection, destination, "F5 certificate DTLS")
	if gateway.DropDTLSConnections() != 1 {
		t.Fatal("fake F5 gateway did not own one DTLS tunnel")
	}
	waitAnyConnectTransport(t, ctx, session, "tls")
	_ = packetConnection.Close()
	packetConnection, err = outbound.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: scenario.PeerAddress, DstPort: testAnyConnectUDPPort})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = packetConnection.Close() }()
	exchangeAnyConnectUDP(t, ctx, packetConnection, destination, "F5 TLS fallback")
	if gateway.DTLSConnections() != 1 || gateway.TunnelConnections() != 1 {
		t.Fatalf("unexpected F5 transport counts: dtls=%d tls=%d", gateway.DTLSConnections(), gateway.TunnelConnections())
	}
}
