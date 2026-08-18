package openconnect

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	singopenconnect "github.com/sagernet/sing-openconnect"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestSingOpenConnectCSTPDriver(t *testing.T) {
	scenario := BasicAnyConnectScenario()
	scenario.CSTP.ResponseChunkSize = 1
	serverAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := NewIPv4ICMPEchoPeer(serverAddress)
	if err != nil {
		t.Fatal(err)
	}
	recorder := NewRecorder(scenario.Cookie)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gateway, err := StartAnyConnectGateway(ctx, scenario, peer, recorder)
	if err != nil {
		t.Fatal(err)
	}
	configurationEvents := make(chan singopenconnect.TunnelConfigurationEvent, 1)
	client, err := newCoreTestClient(ctx, gateway, scenario.Cookie, configurationEvents, gateway.RootCAs(), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	configuration, err := client.WaitReady(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.MTU != uint32(scenario.Configuration.MTU) || len(configuration.Addresses) != 1 || configuration.Addresses[0] != scenario.Configuration.Addresses[0] {
		t.Fatalf("unexpected core configuration: %#v", configuration)
	}
	if !client.Ready() || client.ActiveTransport() != singopenconnect.TransportCSTP {
		t.Fatalf("core is not ready on CSTP: ready=%v transport=%q", client.Ready(), client.ActiveTransport())
	}
	request, err := BuildIPv4ICMPEchoRequest(scenario.Configuration.Addresses[0].Addr(), serverAddress, 13, 21, []byte("sing-openconnect-core"))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteDataPacket(request); err != nil {
		t.Fatal(err)
	}
	reply, err := client.ReadDataPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) < 28 || reply[20] != 0 || !bytes.Equal(reply[28:], []byte("sing-openconnect-core")) {
		t.Fatalf("unexpected core packet reply: %x", reply)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second core close failed: %v", err)
	}
	if err := gateway.Close(); err != nil {
		t.Fatal(err)
	}
	for _, capability := range []Capability{CapabilityCookieCSTP, CapabilityPacketIPv4} {
		if err := phase0CapabilityMatrix.Record(Evidence{
			Capability: capability,
			Scenario:   scenario.Name,
			Driver:     DriverCore,
			Gateway:    "fake",
			Transport:  singopenconnect.TransportCSTP,
			Address:    "ipv4",
			Passed:     true,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSingOpenConnectAuthenticationDriver(t *testing.T) {
	scenario := BasicAnyConnectScenario()
	scenario.Authentication = AnyConnectAuthenticationScenario{
		Enabled:           true,
		Username:          "core-user",
		Password:          "core-password",
		Challenge:         "Core second factor",
		ChallengeResponse: "123456",
	}
	serverAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := NewIPv4ICMPEchoPeer(serverAddress)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gateway, err := StartAnyConnectGateway(ctx, scenario, peer, NewRecorder(scenario.Cookie, scenario.Authentication.Password, scenario.Authentication.ChallengeResponse))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	_, port, err := net.SplitHostPort(gateway.Address())
	if err != nil {
		t.Fatal(err)
	}
	client, err := singopenconnect.NewClient(singopenconnect.ClientOptions{
		Context:      ctx,
		Server:       "https://" + gateway.ServerName() + ":" + port,
		Username:     scenario.Authentication.Username,
		Password:     scenario.Authentication.Password,
		NoUDP:        true,
		IPv6Disabled: true,
		FormEntries: []singopenconnect.FormEntry{{
			FormID: "challenge",
			Name:   "answer",
			Value:  scenario.Authentication.ChallengeResponse,
		}},
		TLSConfig: singopenconnect.ClientTLSOptions{Config: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: gateway.ServerName(),
			RootCAs:    gateway.RootCAs(),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	request, err := BuildIPv4ICMPEchoRequest(scenario.Configuration.Addresses[0].Addr(), serverAddress, 17, 19, []byte("authenticated-core"))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteDataPacket(request); err != nil {
		t.Fatal(err)
	}
	reply, err := client.ReadDataPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) < 28 || reply[20] != 0 || string(reply[28:]) != "authenticated-core" {
		t.Fatalf("unexpected authenticated core reply: %x", reply)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := phase0CapabilityMatrix.Record(Evidence{
		Capability: CapabilityAuth,
		Scenario:   "username-password-challenge",
		Driver:     DriverCore,
		Gateway:    "fake",
		Transport:  singopenconnect.TransportCSTP,
		Address:    "ipv4",
		Passed:     true,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSingOpenConnectTerminalTLSError(t *testing.T) {
	scenario := BasicAnyConnectScenario()
	gateway, _, ctx := startProbeTestGateway(t, scenario)
	client, err := newCoreTestClient(ctx, gateway, scenario.Cookie, make(chan singopenconnect.TunnelConfigurationEvent, 1), x509.NewCertPool(), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	_, err = client.WaitReady(ctx)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected terminal certificate error, got %v", err)
	}
	if client.Ready() {
		t.Fatal("client became ready after terminal TLS error")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

type failingCoreUDPDialer struct {
	attempts atomic.Uint64
}

func (d *failingCoreUDPDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network == N.NetworkUDP {
		d.attempts.Add(1)
		return nil, &net.DNSError{Err: "injected UDP failure", Name: destination.String(), IsTemporary: true}
	}
	return N.SystemDialer.DialContext(ctx, network, destination)
}

func (d *failingCoreUDPDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

func TestSingOpenConnectDTLSFailureFallsBackToCSTP(t *testing.T) {
	scenario := BasicAnyConnectScenario()
	scenario.ModernDTLS = true
	gateway, _, ctx := startProbeTestGateway(t, scenario)
	events := make(chan singopenconnect.TunnelConfigurationEvent, 1)
	dialer := new(failingCoreUDPDialer)
	client, err := newCoreTestClient(ctx, gateway, scenario.Cookie, events, gateway.RootCAs(), false, dialer)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	for dialer.attempts.Load() == 0 && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if dialer.attempts.Load() == 0 {
		t.Fatal("core did not attempt the advertised DTLS transport")
	}
	if !client.Ready() || client.ActiveTransport() != singopenconnect.TransportCSTP {
		t.Fatalf("core did not fall back to CSTP: ready=%v transport=%q", client.Ready(), client.ActiveTransport())
	}
	serverAddress := netip.MustParseAddr("192.0.2.1")
	request, err := BuildIPv4ICMPEchoRequest(scenario.Configuration.Addresses[0].Addr(), serverAddress, 31, 37, []byte("dtls-fallback"))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteDataPacket(request); err != nil {
		t.Fatal(err)
	}
	reply, err := client.ReadDataPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) < 28 || reply[20] != 0 || string(reply[28:]) != "dtls-fallback" {
		t.Fatalf("unexpected fallback reply: %x", reply)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := phase0CapabilityMatrix.Record(Evidence{
		Capability: CapabilityFallback,
		Scenario:   "dtls-dial-failure",
		Driver:     DriverCore,
		Gateway:    "fake",
		Transport:  singopenconnect.TransportCSTP,
		Address:    "ipv4",
		Passed:     true,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSingOpenConnectModernDTLSDriver(t *testing.T) {
	scenario := BasicAnyConnectScenario()
	scenario.ModernDTLS = true
	serverAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := NewIPv4ICMPEchoPeer(serverAddress)
	if err != nil {
		t.Fatal(err)
	}
	recorder := NewRecorder(scenario.Cookie)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gateway, err := StartAnyConnectGateway(ctx, scenario, peer, recorder)
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan singopenconnect.TunnelConfigurationEvent, 1)
	client, err := newCoreTestClient(ctx, gateway, scenario.Cookie, events, gateway.RootCAs(), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	for client.ActiveTransport() != singopenconnect.TransportDTLS && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if !client.Ready() || client.ActiveTransport() != singopenconnect.TransportDTLS {
		t.Fatalf("core is not ready on modern DTLS: ready=%v transport=%q", client.Ready(), client.ActiveTransport())
	}
	request, err := BuildIPv4ICMPEchoRequest(scenario.Configuration.Addresses[0].Addr(), serverAddress, 41, 43, []byte("modern-dtls"))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteDataPacket(request); err != nil {
		t.Fatal(err)
	}
	reply, err := client.ReadDataPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) < 28 || reply[20] != 0 || string(reply[28:]) != "modern-dtls" {
		t.Fatalf("unexpected DTLS reply: %x", reply)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gateway.Close(); err != nil {
		t.Fatal(err)
	}
	records := recorder.Records()
	if recorder.Count("dtls-data") == 0 {
		t.Fatalf("fake gateway did not record DTLS data: %#v", records)
	}
	for _, capability := range []Capability{CapabilityModernDTLS, CapabilityPacketIPv4} {
		if err := phase0CapabilityMatrix.Record(Evidence{
			Capability: capability,
			Scenario:   "modern-dtls",
			Driver:     DriverCore,
			Gateway:    "fake",
			Transport:  singopenconnect.TransportDTLS,
			Address:    "ipv4",
			Passed:     true,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSingOpenConnectStatelessCompressionDriver(t *testing.T) {
	for _, algorithm := range []string{"lzs", "oc-lz4"} {
		t.Run(algorithm, func(t *testing.T) {
			scenario := BasicAnyConnectScenario()
			scenario.Compression = algorithm
			peerAddress := netip.MustParseAddr("192.0.2.1")
			peer, err := NewIPv4ICMPEchoPeer(peerAddress)
			if err != nil {
				t.Fatal(err)
			}
			recorder := NewRecorder(scenario.Cookie)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			gateway, err := StartAnyConnectGateway(ctx, scenario, peer, recorder)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = gateway.Close() }()
			_, port, err := net.SplitHostPort(gateway.Address())
			if err != nil {
				t.Fatal(err)
			}
			client, err := singopenconnect.NewClient(singopenconnect.ClientOptions{
				Context:             ctx,
				Server:              "https://" + gateway.ServerName() + ":" + port,
				Cookie:              scenario.Cookie,
				NoUDP:               true,
				IPv6Disabled:        true,
				CompressionMode:     singopenconnect.CompressionModeStateless,
				CompressionDisabled: false,
				TLSConfig: singopenconnect.ClientTLSOptions{Config: &tls.Config{
					MinVersion: tls.VersionTLS12,
					ServerName: gateway.ServerName(),
					RootCAs:    gateway.RootCAs(),
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			if err := client.Start(); err != nil {
				t.Fatal(err)
			}
			if _, err := client.WaitReady(ctx); err != nil {
				t.Fatal(err)
			}
			request, err := BuildIPv4ICMPEchoRequest(scenario.Configuration.Addresses[0].Addr(), peerAddress, 31, 1, bytes.Repeat([]byte("compressible-"), 64))
			if err != nil {
				t.Fatal(err)
			}
			if err := client.WriteDataPacket(request); err != nil {
				t.Fatal(err)
			}
			for {
				compressed := false
				for _, record := range recorder.Records() {
					if record.Kind == "cstp-compressed" {
						compressed = true
						break
					}
				}
				if compressed {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
			}
			if err := phase0CapabilityMatrix.Record(Evidence{
				Capability: CapabilityCompression,
				Scenario:   scenario.Name + "-" + algorithm,
				Driver:     DriverCore,
				Gateway:    "fake",
				Transport:  singopenconnect.TransportCSTP,
				Address:    "ipv4",
				Passed:     true,
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func newCoreTestClient(
	ctx context.Context,
	gateway *AnyConnectGateway,
	cookie string,
	configurationEvents chan<- singopenconnect.TunnelConfigurationEvent,
	roots *x509.CertPool,
	noUDP bool,
	dialer N.Dialer,
) (*singopenconnect.Client, error) {
	_, port, err := net.SplitHostPort(gateway.Address())
	if err != nil {
		return nil, err
	}
	return singopenconnect.NewClient(singopenconnect.ClientOptions{
		Context:      ctx,
		Server:       "https://" + gateway.ServerName() + ":" + port,
		Cookie:       cookie,
		NoUDP:        noUDP,
		IPv6Disabled: true,
		Dialer:       dialer,
		TLSConfig: singopenconnect.ClientTLSOptions{Config: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: gateway.ServerName(),
			RootCAs:    roots,
		}},
		OnTunnelConfiguration: func(event singopenconnect.TunnelConfigurationEvent) error {
			select {
			case configurationEvents <- event:
			default:
			}
			return nil
		},
	})
}
