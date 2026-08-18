package openconnect

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	testopenconnect "github.com/metacubex/mihomo/internal/testutil/openconnect"
)

func TestClientF5CookiePPPOverTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	scenario := testopenconnect.BasicF5Scenario()
	peer, err := testopenconnect.NewIPv4ICMPEchoPeer(scenario.PeerAddress)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := testopenconnect.StartF5Gateway(ctx, scenario, peer)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ctx, Config{
		Server:               "https://" + gateway.Address(),
		Protocol:             ProtocolF5,
		Cookie:               scenario.CookieHeader(),
		ServerName:           gateway.ServerName(),
		CertificateAuthority: gateway.CAPEM(),
		IPv6Disabled:         true,
		DTLSMode:             DTLSModeOff,
	}, new(recordingDialer), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
		if err := gateway.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	configuration, err := client.WaitReady(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(configuration.Addresses) != 1 || configuration.Addresses[0].Addr() != scenario.ClientAddress {
		t.Fatalf("unexpected F5 network configuration: %#v", configuration)
	}
	if client.ActiveTransport() != "tls" {
		t.Fatalf("unexpected F5 active transport: %q", client.ActiveTransport())
	}
	request, err := testopenconnect.BuildIPv4ICMPEchoRequest(scenario.ClientAddress, scenario.PeerAddress, 1, 1, []byte("f5-facade"))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WritePacket(request); err != nil {
		t.Fatal(err)
	}
	reply, err := client.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if source := netip.AddrFrom4([4]byte{reply[12], reply[13], reply[14], reply[15]}); source != scenario.PeerAddress || string(reply[28:]) != "f5-facade" {
		t.Fatalf("unexpected F5 packet reply: %x", reply)
	}
	if gateway.TunnelConnections() != 1 {
		t.Fatalf("unexpected F5 tunnel count: %d", gateway.TunnelConnections())
	}
}

func TestClientF5DTLSRequiredRejectsTLSFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	scenario := testopenconnect.BasicF5Scenario()
	peer, err := testopenconnect.NewIPv4ICMPEchoPeer(scenario.PeerAddress)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := testopenconnect.StartF5Gateway(ctx, scenario, peer)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	client, err := NewClient(ctx, Config{
		Server:               "https://" + gateway.Address(),
		Protocol:             ProtocolF5,
		Cookie:               scenario.CookieHeader(),
		ServerName:           gateway.ServerName(),
		CertificateAuthority: gateway.CAPEM(),
		IPv6Disabled:         true,
		DTLSMode:             DTLSModeRequire,
	}, new(recordingDialer), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WaitReady(ctx); !errors.Is(err, ErrDTLSRequired) {
		t.Fatalf("F5 required DTLS accepted TLS fallback: %v", err)
	}
}

func TestClientF5CertificateDTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	scenario := testopenconnect.BasicF5Scenario()
	scenario.DTLS = true
	peer, err := testopenconnect.NewIPv4ICMPEchoPeer(scenario.PeerAddress)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := testopenconnect.StartF5Gateway(ctx, scenario, peer)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ctx, Config{
		Server:               "https://" + gateway.Address(),
		Protocol:             ProtocolF5,
		Cookie:               scenario.CookieHeader(),
		ServerName:           gateway.ServerName(),
		CertificateAuthority: gateway.CAPEM(),
		IPv6Disabled:         true,
		DTLSMode:             DTLSModeRequire,
	}, new(recordingDialer), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
		if err := gateway.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if client.ActiveTransport() != "dtls" || gateway.DTLSConnections() != 1 {
		t.Fatalf("F5 did not establish certificate DTLS: transport=%q connections=%d", client.ActiveTransport(), gateway.DTLSConnections())
	}
	request, err := testopenconnect.BuildIPv4ICMPEchoRequest(scenario.ClientAddress, scenario.PeerAddress, 2, 1, []byte("f5-dtls"))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WritePacket(request); err != nil {
		t.Fatal(err)
	}
	reply, err := client.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(reply[28:]) != "f5-dtls" {
		t.Fatalf("unexpected F5 DTLS reply: %x", reply)
	}
	if gateway.DropDTLSConnections() != 1 {
		t.Fatal("fake F5 gateway did not own one DTLS tunnel")
	}
	for !errors.Is(client.transportFailure(), ErrDTLSRequired) {
		select {
		case <-ctx.Done():
			t.Fatalf("F5 required DTLS did not fail closed after TLS fallback: %v", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
}

func TestClientF5UsernamePassword(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	scenario := testopenconnect.BasicF5Scenario()
	peer, err := testopenconnect.NewIPv4ICMPEchoPeer(scenario.PeerAddress)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := testopenconnect.StartF5Gateway(ctx, scenario, peer)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ctx, Config{
		Server:               "https://" + gateway.Address(),
		Protocol:             ProtocolF5,
		Username:             scenario.Username,
		Password:             scenario.Password,
		ServerName:           gateway.ServerName(),
		CertificateAuthority: gateway.CAPEM(),
		IPv6Disabled:         true,
		DTLSMode:             DTLSModeOff,
	}, new(recordingDialer), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
		if err := gateway.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if gateway.AuthenticationRequests() != 1 || gateway.TunnelConnections() != 1 {
		t.Fatalf("unexpected F5 authentication/tunnel counts: auth=%d tunnel=%d", gateway.AuthenticationRequests(), gateway.TunnelConnections())
	}
}
