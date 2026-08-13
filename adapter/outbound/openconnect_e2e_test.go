//go:build with_gvisor

package outbound

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	testanyconnect "github.com/metacubex/mihomo/internal/testutil/anyconnect"
	oc "github.com/metacubex/mihomo/transport/openconnect"
)

const (
	testAnyConnectTCPPort = 18080
	testAnyConnectUDPPort = 15353
)

type openConnectRecordingDialer struct {
	access       sync.Mutex
	tcpCalls     int
	udpCalls     int
	destinations []string
	dialStarted  chan struct{}
	dialOnce     sync.Once
}

type openConnectBlockingReconnectDialer struct {
	access           sync.Mutex
	attempts         int
	reconnectStarted chan struct{}
}

type openConnectSwitchingDialer struct {
	access           sync.Mutex
	attempts         int
	alternateAddress string
}

func (d *openConnectSwitchingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.access.Lock()
	d.attempts++
	if d.attempts > 1 {
		address = d.alternateAddress
	}
	d.access.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (*openConnectSwitchingDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, errors.New("unexpected UDP underlay")
}

func (d *openConnectSwitchingDialer) count() int {
	d.access.Lock()
	defer d.access.Unlock()
	return d.attempts
}

func (d *openConnectBlockingReconnectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.access.Lock()
	d.attempts++
	attempt := d.attempts
	d.access.Unlock()
	if attempt == 2 {
		close(d.reconnectStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (d *openConnectBlockingReconnectDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, errors.New("unexpected UDP underlay")
}

func (d *openConnectBlockingReconnectDialer) count() int {
	d.access.Lock()
	defer d.access.Unlock()
	return d.attempts
}

type openConnectAuthProviderFunc func(context.Context, oc.AuthChallenge) (oc.AuthResponse, error)

func (f openConnectAuthProviderFunc) Respond(ctx context.Context, challenge oc.AuthChallenge) (oc.AuthResponse, error) {
	return f(ctx, challenge)
}

func (d *openConnectRecordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network == "tcp" && d.dialStarted != nil {
		d.dialOnce.Do(func() { close(d.dialStarted) })
	}
	d.access.Lock()
	if network == "tcp" {
		d.tcpCalls++
	}
	d.destinations = append(d.destinations, address)
	d.access.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (d *openConnectRecordingDialer) ListenPacket(ctx context.Context, network, address string, remote netip.AddrPort) (net.PacketConn, error) {
	d.access.Lock()
	d.udpCalls++
	d.destinations = append(d.destinations, address)
	d.access.Unlock()
	return (&net.ListenConfig{}).ListenPacket(ctx, network, "")
}

func (d *openConnectRecordingDialer) counts() (int, int) {
	d.access.Lock()
	defer d.access.Unlock()
	return d.tcpCalls, d.udpCalls
}

func TestAnyConnectOutboundTCPAndUDPEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	scenario := testanyconnect.BasicCSTPScenario()
	peerAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := testanyconnect.NewIPv4TCPUDPEchoPeer(ctx, peerAddress, testAnyConnectTCPPort, testAnyConnectUDPPort)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := peer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	}()
	recorder := testanyconnect.NewRecorder(scenario.Cookie)
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, recorder)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := gateway.Close(); err != nil {
			t.Error(err)
		}
	}()
	dialer := new(openConnectRecordingDialer)
	outbound := newFakeAnyConnectOutbound(t, gateway, scenario, dialer, 0)
	defer func() {
		if err := outbound.Close(); err != nil {
			t.Error(err)
		}
	}()
	if outbound.Type() != C.OpenConnect || !outbound.SupportUDP() || !outbound.IsL3Protocol(nil) {
		t.Fatalf("unexpected outbound capabilities: type=%s udp=%v l3=%v", outbound.Type(), outbound.SupportUDP(), outbound.IsL3Protocol(nil))
	}
	if err := outbound.ResolveUDP(ctx, &C.Metadata{NetWork: C.UDP, DstIP: peerAddress, DstPort: testAnyConnectUDPPort}); err != nil {
		t.Fatalf("resolve already-addressed UDP target: %v", err)
	}

	tcpMetadata := &C.Metadata{NetWork: C.TCP, DstIP: peerAddress, DstPort: testAnyConnectTCPPort}
	connection, err := outbound.DialContext(ctx, tcpMetadata)
	if err != nil {
		t.Fatal(err)
	}
	request := []byte("anyconnect TCP echo")
	if _, err := connection.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(request))
	if _, err := io.ReadFull(connection, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != string(request) {
		t.Fatalf("unexpected TCP echo: %q", reply)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	udpMetadata := &C.Metadata{NetWork: C.UDP, DstIP: peerAddress, DstPort: testAnyConnectUDPPort}
	packetConn, err := outbound.ListenPacketContext(ctx, udpMetadata)
	if err != nil {
		t.Fatal(err)
	}
	udpRequest := []byte("anyconnect UDP echo")
	destination := &net.UDPAddr{IP: peerAddress.AsSlice(), Port: testAnyConnectUDPPort}
	if _, err := packetConn.WriteTo(udpRequest, destination); err != nil {
		t.Fatal(err)
	}
	udpReply := make([]byte, 128)
	count, _, err := packetConn.ReadFrom(udpReply)
	if err != nil {
		t.Fatal(err)
	}
	if string(udpReply[:count]) != string(udpRequest) {
		t.Fatalf("unexpected UDP echo: %q", udpReply[:count])
	}
	if err := packetConn.Close(); err != nil {
		t.Fatal(err)
	}

	tcpCalls, udpCalls := dialer.counts()
	if tcpCalls != 1 || udpCalls != 0 {
		t.Fatalf("unexpected gateway underlay calls: tcp=%d udp=%d", tcpCalls, udpCalls)
	}
	if waitAnyConnectRecordCount(t, ctx, recorder, "cstp-connect", 1) != 1 {
		t.Fatalf("expected one CSTP session, records=%v", recorder.Records())
	}
	writeAnyConnectOutboundEvidence(t, scenario.Name)
}

func TestAnyConnectOutboundIPv6TCPAndUDPEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	scenario := testanyconnect.BasicCSTPScenario()
	scenario.Configuration.Addresses = []netip.Prefix{netip.MustParsePrefix("2001:db8::2/64")}
	scenario.Configuration.DNS = []netip.Addr{netip.MustParseAddr("2001:db8::53")}
	peerAddress := netip.MustParseAddr("2001:db8::1")
	peer, err := testanyconnect.NewIPv6TCPUDPEchoPeer(ctx, peerAddress, testAnyConnectTCPPort, testAnyConnectUDPPort)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	outbound := newFakeAnyConnectOutboundWithOption(t, gateway, scenario, new(openConnectRecordingDialer), 0, func(option *OpenConnectOption) {
		option.MTU = 1280
	})
	defer func() { _ = outbound.Close() }()
	packetConn, err := outbound.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: peerAddress, DstPort: testAnyConnectUDPPort})
	if err != nil {
		t.Fatal(err)
	}
	udpDestination := &net.UDPAddr{IP: peerAddress.AsSlice(), Port: testAnyConnectUDPPort}
	exchangeAnyConnectUDP(t, ctx, packetConn, udpDestination, "anyconnect IPv6 UDP before TCP")

	connection, err := outbound.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: peerAddress, DstPort: testAnyConnectTCPPort})
	if err != nil {
		t.Fatal(err)
	}
	request := []byte("anyconnect IPv6 TCP echo")
	if _, err := connection.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(request))
	if _, err := io.ReadFull(connection, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != string(request) {
		t.Fatalf("unexpected IPv6 TCP echo: %q", reply)
	}
	_ = packetConn.Close()
	_ = connection.Close()
	writeAnyConnectEvidenceForAddress(t, "ipv6", scenario.Name+"-tcp-udp-echo", []testanyconnect.Capability{testanyconnect.CapabilityPacketIPv6}, "ipv6")
}

func TestAnyConnectModernDTLSOutbound(t *testing.T) {
	t.Run("auto fallback", func(t *testing.T) {
		ctx, outbound, session, gateway, recorder, peerAddress := startModernDTLSOutbound(t, "")
		waitAnyConnectTransport(t, ctx, session, "dtls")
		connection, err := outbound.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: peerAddress, DstPort: testAnyConnectTCPPort})
		if err != nil {
			t.Fatal(err)
		}
		request := []byte("modern DTLS TCP echo")
		if _, err := connection.Write(request); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(request))
		if _, err := io.ReadFull(connection, reply); err != nil {
			t.Fatal(err)
		}
		_ = connection.Close()
		packetConn, err := outbound.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: peerAddress, DstPort: testAnyConnectUDPPort})
		if err != nil {
			t.Fatal(err)
		}
		defer packetConn.Close()
		destination := &net.UDPAddr{IP: peerAddress.AsSlice(), Port: testAnyConnectUDPPort}
		exchangeAnyConnectUDP(t, ctx, packetConn, destination, "modern DTLS UDP echo")
		waitAnyConnectRecordCount(t, ctx, recorder, "dtls-data", 1)
		beforeFallback := recorder.Count("cstp-data")
		gateway.SetDTLSBlackhole(true)
		waitAnyConnectTransport(t, ctx, session, "cstp")
		exchangeAnyConnectUDP(t, ctx, packetConn, destination, "CSTP fallback UDP echo")
		waitAnyConnectRecordCount(t, ctx, recorder, "cstp-data", beforeFallback+1)
		writeAnyConnectEvidenceForTransport(t, "modern-dtls", "modern-dtls-auto", []testanyconnect.Capability{testanyconnect.CapabilityModernDTLS}, "dtls")
		writeAnyConnectEvidenceForTransport(t, "modern-dtls-fallback", "modern-dtls-auto-fallback", []testanyconnect.Capability{testanyconnect.CapabilityFallback}, "cstp")
	})

	t.Run("require fail closed", func(t *testing.T) {
		ctx, outbound, session, gateway, recorder, peerAddress := startModernDTLSOutbound(t, oc.DTLSModeRequire)
		waitAnyConnectTransport(t, ctx, session, "dtls")
		packetConn, err := outbound.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: peerAddress, DstPort: testAnyConnectUDPPort})
		if err != nil {
			t.Fatal(err)
		}
		defer packetConn.Close()
		destination := &net.UDPAddr{IP: peerAddress.AsSlice(), Port: testAnyConnectUDPPort}
		exchangeAnyConnectUDP(t, ctx, packetConn, destination, "required DTLS UDP echo")
		request, err := testanyconnect.BuildIPv4ICMPEchoRequest(netip.MustParseAddr("192.0.2.2"), peerAddress, 62, 1, []byte("require-fail-closed"))
		if err != nil {
			t.Fatal(err)
		}
		writerStarted := make(chan struct{})
		writerDone := make(chan struct{})
		go func() {
			defer close(writerDone)
			started := false
			for {
				if err := session.client.WritePacket(request); err != nil {
					return
				}
				if !started {
					close(writerStarted)
					started = true
				}
				time.Sleep(time.Millisecond)
			}
		}()
		<-writerStarted
		beforeFallback := countRecords(recorder.Records(), "cstp-data")
		if gateway.DropDTLSConnections() != 1 {
			t.Fatal("fake gateway did not have one active DTLS connection")
		}
		select {
		case <-session.done:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		<-writerDone
		if afterFallback := countRecords(recorder.Records(), "cstp-data"); afterFallback != beforeFallback {
			t.Fatalf("require mode transmitted data over CSTP: before=%d after=%d", beforeFallback, afterFallback)
		}
		if _, err := outbound.run(ctx); !errors.Is(err, oc.ErrDTLSRequired) {
			t.Fatalf("require failure was not latched by the outbound: %v", err)
		}
	})
}

func TestAnyConnectLegacyDTLSOutbound(t *testing.T) {
	ctx, outbound, session, gateway, recorder, peerAddress := startLegacyDTLSOutbound(t, oc.DTLSModeAuto)
	waitAnyConnectTransport(t, ctx, session, "dtls")
	connection, err := outbound.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: peerAddress, DstPort: testAnyConnectTCPPort})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("legacy DTLS TCP echo")
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, reply); err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	packetConn, err := outbound.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: peerAddress, DstPort: testAnyConnectUDPPort})
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	destination := &net.UDPAddr{IP: peerAddress.AsSlice(), Port: testAnyConnectUDPPort}
	exchangeAnyConnectUDP(t, ctx, packetConn, destination, "legacy DTLS UDP echo")
	waitAnyConnectRecordCount(t, ctx, recorder, "legacy-dtls-data", 1)
	beforeFallback := recorder.Count("cstp-data")
	gateway.SetDTLSBlackhole(true)
	waitAnyConnectTransport(t, ctx, session, "cstp")
	exchangeAnyConnectUDP(t, ctx, packetConn, destination, "legacy CSTP fallback UDP echo")
	waitAnyConnectRecordCount(t, ctx, recorder, "cstp-data", beforeFallback+1)
	gateway.SetDTLSBlackhole(false)
	waitAnyConnectTransport(t, ctx, session, "dtls")
	exchangeAnyConnectUDP(t, ctx, packetConn, destination, "legacy DTLS restored UDP echo")
	writeAnyConnectEvidenceForTransport(t, "legacy-dtls", "legacy-dtls-default", []testanyconnect.Capability{testanyconnect.CapabilityLegacyDTLS}, "dtls")
	writeAnyConnectEvidenceForTransport(t, "legacy-dtls-fallback", "legacy-dtls-auto-fallback", []testanyconnect.Capability{testanyconnect.CapabilityFallback}, "cstp")
}

func TestAnyConnectLegacyDTLSRekey(t *testing.T) {
	ctx, outbound, session, _, recorder, peerAddress := startLegacyDTLSRekeyOutbound(t, oc.DTLSModeAuto)
	waitAnyConnectTransport(t, ctx, session, "dtls")
	packetConn, err := outbound.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: peerAddress, DstPort: testAnyConnectUDPPort})
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	destination := &net.UDPAddr{IP: peerAddress.AsSlice(), Port: testAnyConnectUDPPort}
	exchangeAnyConnectUDP(t, ctx, packetConn, destination, "legacy DTLS before rekey")
	handshakes := countRecords(recorder.Records(), "legacy-dtls-handshake")
	for countRecords(recorder.Records(), "cstp-connect") < 2 || countRecords(recorder.Records(), "legacy-dtls-handshake") <= handshakes {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	waitAnyConnectTransport(t, ctx, session, "dtls")
	exchangeAnyConnectUDP(t, ctx, packetConn, destination, "legacy DTLS rekey UDP echo")
	writeAnyConnectEvidenceForTransport(t, "legacy-dtls-rekey", "legacy-dtls-rekey", []testanyconnect.Capability{testanyconnect.CapabilityRekey}, "dtls")
}

func startModernDTLSOutbound(t testing.TB, mode string) (context.Context, *OpenConnect, *openConnectSession, *testanyconnect.Gateway, *testanyconnect.Recorder, netip.Addr) {
	return startDTLSOutbound(t, mode, false, 0)
}

func startLegacyDTLSOutbound(t testing.TB, mode string) (context.Context, *OpenConnect, *openConnectSession, *testanyconnect.Gateway, *testanyconnect.Recorder, netip.Addr) {
	return startDTLSOutbound(t, mode, true, 0)
}

func startLegacyDTLSRekeyOutbound(t testing.TB, mode string) (context.Context, *OpenConnect, *openConnectSession, *testanyconnect.Gateway, *testanyconnect.Recorder, netip.Addr) {
	return startDTLSOutbound(t, mode, true, 5*time.Second)
}

func startDTLSOutbound(t testing.TB, mode string, legacy bool, rekeyInterval time.Duration) (context.Context, *OpenConnect, *openConnectSession, *testanyconnect.Gateway, *testanyconnect.Recorder, netip.Addr) {
	t.Helper()
	timeout := 30 * time.Second
	if legacy {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	scenario := testanyconnect.BasicCSTPScenario()
	if legacy {
		scenario.LegacyDTLS = true
	} else {
		scenario.ModernDTLS = true
	}
	scenario.CSTP.RekeyInterval = rekeyInterval
	peerAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := testanyconnect.NewIPv4TCPUDPEchoPeer(ctx, peerAddress, testAnyConnectTCPPort, testAnyConnectUDPPort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	recorder := testanyconnect.NewRecorder(scenario.Cookie)
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, recorder)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Close() })
	outbound := newFakeAnyConnectOutboundWithOption(t, gateway, scenario, new(openConnectRecordingDialer), 0, func(option *OpenConnectOption) {
		option.DTLSMode = mode
		option.DPDInterval = 2
	})
	t.Cleanup(func() { _ = outbound.Close() })
	session, err := outbound.run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, outbound, session, gateway, recorder, peerAddress
}

func waitAnyConnectTransport(t testing.TB, ctx context.Context, session *openConnectSession, transport string) {
	t.Helper()
	for session.client.ActiveTransport() != transport {
		select {
		case <-ctx.Done():
			t.Fatalf("wait for %s transport: %v", transport, ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
}

func TestAnyConnectRemoteDNSUsesTunnelAndOverridePrecedence(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		serverDNS   netip.Addr
		overrideDNS []string
	}{
		{name: "server DNS", serverDNS: netip.MustParseAddr("192.0.2.1")},
		{name: "override DNS", serverDNS: netip.MustParseAddr("192.0.2.99"), overrideDNS: []string{"192.0.2.1"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			scenario := testanyconnect.BasicCSTPScenario()
			scenario.Configuration.DNS = []netip.Addr{testCase.serverDNS}
			peerAddress := netip.MustParseAddr("192.0.2.1")
			peer, err := testanyconnect.NewIPv4TCPUDPEchoPeerWithDNS(ctx, peerAddress, testAnyConnectTCPPort, testAnyConnectUDPPort, 53, map[string]netip.Addr{
				"service.internal": peerAddress,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = gateway.Close() }()
			dialer := new(openConnectRecordingDialer)
			outbound := newFakeAnyConnectOutboundWithOption(t, gateway, scenario, dialer, 0, func(option *OpenConnectOption) {
				option.RemoteDnsResolve = true
				option.Dns = testCase.overrideDNS
			})
			defer func() { _ = outbound.Close() }()
			connection, err := outbound.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "service.internal", DstPort: testAnyConnectTCPPort})
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("resolved through tunnel")
			if _, err := connection.Write(payload); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(payload))
			if _, err := io.ReadFull(connection, reply); err != nil {
				t.Fatal(err)
			}
			_ = connection.Close()
			if string(reply) != string(payload) || peer.DNSQueries() == 0 {
				t.Fatalf("remote DNS did not resolve through the tunnel: reply=%q queries=%d", reply, peer.DNSQueries())
			}
			tcpCalls, udpCalls := dialer.counts()
			if tcpCalls != 1 || udpCalls != 0 {
				t.Fatalf("remote DNS recursed into the gateway underlay: tcp=%d udp=%d", tcpCalls, udpCalls)
			}
		})
	}
	writeAnyConnectEvidence(t, "dns", "server-and-override-private-dns", []testanyconnect.Capability{testanyconnect.CapabilityPrivateDNS})
}

func TestAnyConnectRekeyAndEOFKeepGenerationAndUDPFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	scenario := testanyconnect.BasicCSTPScenario()
	scenario.CSTP.RekeyInterval = 2 * time.Second
	peerAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := testanyconnect.NewIPv4TCPUDPEchoPeer(ctx, peerAddress, testAnyConnectTCPPort, testAnyConnectUDPPort)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	recorder := testanyconnect.NewRecorder(scenario.Cookie)
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, recorder)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	dialer := new(openConnectRecordingDialer)
	outbound := newFakeAnyConnectOutboundWithOption(t, gateway, scenario, dialer, 0, func(option *OpenConnectOption) {
		option.ReconnectTimeout = 5
	})
	defer func() { _ = outbound.Close() }()
	session, err := outbound.run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	firstDevice, _, err := session.currentDevice()
	if err != nil {
		t.Fatal(err)
	}
	connection, err := outbound.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: peerAddress, DstPort: testAnyConnectUDPPort})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	destination := &net.UDPAddr{IP: peerAddress.AsSlice(), Port: testAnyConnectUDPPort}
	exchange := func(payload string) {
		exchangeAnyConnectUDP(t, ctx, connection, destination, payload)
	}
	exchange("before reconnect")
	for countRecords(recorder.Records(), "cstp-connect") < 2 {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if closed := gateway.DropCSTPConnections(); closed != 1 {
		t.Fatalf("expected one active CSTP connection, closed %d", closed)
	}
	for countRecords(recorder.Records(), "cstp-connect") < 3 {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if _, err := session.client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	secondSession, err := outbound.run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secondDevice, _, err := secondSession.currentDevice()
	if err != nil {
		t.Fatal(err)
	}
	if secondSession != session || secondDevice != firstDevice {
		t.Fatal("same network identity replaced the session or stack generation during reconnect")
	}
	exchange("after reconnect")
	writeAnyConnectEvidence(t, "reconnect", scenario.Name+"-rekey-eof", []testanyconnect.Capability{
		testanyconnect.CapabilityRekey,
		testanyconnect.CapabilityReconnect,
	})
}

func TestAnyConnectDPDBlackholeKeepsGenerationAndUDPFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	scenario := testanyconnect.BasicCSTPScenario()
	scenario.CSTP.BlackholeDPD = true
	peerAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := testanyconnect.NewIPv4TCPUDPEchoPeer(ctx, peerAddress, testAnyConnectTCPPort, testAnyConnectUDPPort)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	recorder := testanyconnect.NewRecorder(scenario.Cookie)
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, recorder)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	outbound := newFakeAnyConnectOutboundWithOption(t, gateway, scenario, new(openConnectRecordingDialer), 0, func(option *OpenConnectOption) {
		option.ReconnectTimeout = 5
		option.DPDInterval = 1
	})
	defer func() { _ = outbound.Close() }()
	session, err := outbound.run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	device, _, err := session.currentDevice()
	if err != nil {
		t.Fatal(err)
	}
	connection, err := outbound.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: peerAddress, DstPort: testAnyConnectUDPPort})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	destination := &net.UDPAddr{IP: peerAddress.AsSlice(), Port: testAnyConnectUDPPort}
	exchangeAnyConnectUDP(t, ctx, connection, destination, "before DPD blackhole")
	for countRecords(recorder.Records(), "cstp-connect") < 2 {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if blackholed := countRecords(recorder.Records(), "cstp-dpd-blackhole"); blackholed < 2 {
		t.Fatalf("sustained DPD blackhole did not consume repeated probes: %d", blackholed)
	}
	if _, err := session.client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	currentDevice, _, err := session.currentDevice()
	if err != nil {
		t.Fatal(err)
	}
	if currentDevice != device {
		t.Fatal("DPD recovery replaced an unchanged stack generation")
	}
	exchangeAnyConnectUDP(t, ctx, connection, destination, "after DPD blackhole recovery")
	for countRecords(recorder.Records(), "cstp-dpd") == 0 {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	writeAnyConnectEvidence(t, "dpd-blackhole", scenario.Name+"-dpd-blackhole", []testanyconnect.Capability{
		testanyconnect.CapabilityDPD,
		testanyconnect.CapabilityReconnect,
	})
}

func TestAnyConnectReconnectReplacesChangedMTUGeneration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	scenario := testanyconnect.BasicCSTPScenario()
	scenario.Configuration.Routes = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	scenario.Configuration.ExcludedRoutes = []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15")}
	reconfigured := scenario.Configuration
	reconfigured.MTU = 1280
	scenario.CSTP.ReconnectConfiguration = &reconfigured
	peerAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := testanyconnect.NewIPv4TCPUDPEchoPeer(ctx, peerAddress, testAnyConnectTCPPort, testAnyConnectUDPPort)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	recorder := testanyconnect.NewRecorder(scenario.Cookie)
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, recorder)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	outbound := newFakeAnyConnectOutboundWithOption(t, gateway, scenario, new(openConnectRecordingDialer), 0, func(option *OpenConnectOption) {
		option.ReconnectTimeout = 5
	})
	defer func() { _ = outbound.Close() }()
	session, err := outbound.run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	firstDevice, _, err := session.currentDevice()
	if err != nil {
		t.Fatal(err)
	}
	oldFlow, err := outbound.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: peerAddress, DstPort: testAnyConnectUDPPort})
	if err != nil {
		t.Fatal(err)
	}
	destination := &net.UDPAddr{IP: peerAddress.AsSlice(), Port: testAnyConnectUDPPort}
	exchangeAnyConnectUDP(t, ctx, oldFlow, destination, "before identity change")
	if closed := gateway.DropCSTPConnections(); closed != 1 {
		t.Fatalf("expected one active CSTP connection, closed %d", closed)
	}
	for countRecords(recorder.Records(), "cstp-connect") < 2 {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	configuration, err := session.client.WaitReady(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secondDevice, _, err := session.currentDevice()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.Addresses[0] != reconfigured.Addresses[0] || configuration.MTU != uint32(reconfigured.MTU) || secondDevice == firstDevice {
		t.Fatalf("changed network identity did not replace the stack: addresses=%#v mtu=%d", configuration.Addresses, configuration.MTU)
	}
	if !slices.Equal(configuration.Routes, reconfigured.Routes) || !slices.Equal(configuration.ExcludedRoutes, reconfigured.ExcludedRoutes) {
		t.Fatalf("negotiated routes changed across reconfiguration: routes=%v excluded=%v", configuration.Routes, configuration.ExcludedRoutes)
	}
	if _, err := oldFlow.WriteTo([]byte("stale flow"), destination); err == nil {
		t.Fatal("flow from the replaced generation remained usable")
	}
	_ = oldFlow.Close()
	newFlow, err := outbound.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: peerAddress, DstPort: testAnyConnectUDPPort})
	if err != nil {
		t.Fatal(err)
	}
	defer newFlow.Close()
	exchangeAnyConnectUDP(t, ctx, newFlow, destination, "after identity change")
	writeAnyConnectEvidence(t, "network-change", scenario.Name+"-mtu-routes", []testanyconnect.Capability{
		testanyconnect.CapabilityNetworkMTU,
		testanyconnect.CapabilityRoutes,
	})
}

func TestAnyConnectReconnectsAfterUnderlaySwitch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	scenario := testanyconnect.BasicCSTPScenario()
	peerAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := testanyconnect.NewIPv4TCPUDPEchoPeer(ctx, peerAddress, testAnyConnectTCPPort, testAnyConnectUDPPort)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	primaryRecorder := testanyconnect.NewRecorder(scenario.Cookie)
	primary, err := testanyconnect.StartGateway(ctx, scenario, peer, primaryRecorder)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = primary.Close() }()
	secondaryRecorder := testanyconnect.NewRecorder(scenario.Cookie)
	secondary, err := testanyconnect.StartGateway(ctx, scenario, peer, secondaryRecorder)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = secondary.Close() }()
	dialer := &openConnectSwitchingDialer{alternateAddress: secondary.Address()}
	outbound := newFakeAnyConnectOutboundWithOption(t, primary, scenario, dialer, 0, func(option *OpenConnectOption) {
		option.ReconnectTimeout = 5
	})
	defer func() { _ = outbound.Close() }()
	session, err := outbound.run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	device, _, err := session.currentDevice()
	if err != nil {
		t.Fatal(err)
	}
	connection, err := outbound.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: peerAddress, DstPort: testAnyConnectUDPPort})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	destination := &net.UDPAddr{IP: peerAddress.AsSlice(), Port: testAnyConnectUDPPort}
	exchangeAnyConnectUDP(t, ctx, connection, destination, "before underlay switch")
	if closed := primary.DropCSTPConnections(); closed != 1 {
		t.Fatalf("expected one primary CSTP connection, closed %d", closed)
	}
	for countRecords(secondaryRecorder.Records(), "cstp-connect") < 1 {
		select {
		case <-ctx.Done():
			t.Fatalf("tunnel did not reconnect through switched underlay: %v", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if _, err := session.client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	currentDevice, _, err := session.currentDevice()
	if err != nil {
		t.Fatal(err)
	}
	if currentDevice != device {
		t.Fatal("same network identity replaced the stack after underlay switch")
	}
	exchangeAnyConnectUDP(t, ctx, connection, destination, "after underlay switch")
	if attempts := dialer.count(); attempts != 2 {
		t.Fatalf("underlay switch caused unexpected dial attempts: %d", attempts)
	}
	if countRecords(primaryRecorder.Records(), "cstp-connect") != 1 {
		t.Fatalf("primary gateway was dialed after underlay switch: %v", primaryRecorder.Records())
	}
	writeAnyConnectEvidence(t, "underlay-switch", scenario.Name+"-underlay-switch", []testanyconnect.Capability{
		testanyconnect.CapabilityReconnect,
		testanyconnect.CapabilityUnderlay,
	})
}

func TestOpenConnectReconnectTimeoutIsBoundedAndOutboundRecovers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	scenario := testanyconnect.BasicCSTPScenario()
	peer, err := testanyconnect.NewIPv4ICMPEchoPeer(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	recorder := testanyconnect.NewRecorder(scenario.Cookie)
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, recorder)
	if err != nil {
		t.Fatal(err)
	}
	dialer := new(openConnectRecordingDialer)
	outbound := newFakeAnyConnectOutboundWithOption(t, gateway, scenario, dialer, 0, func(option *OpenConnectOption) {
		option.ReconnectTimeout = 1
	})
	defer func() { _ = outbound.Close() }()
	session, err := outbound.run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if !errors.Is(session.err(), oc.ErrReconnectTimeout) {
		t.Fatalf("unexpected terminal reconnect error: %v", session.err())
	}
	attempts, _ := dialer.counts()
	if attempts < 2 || attempts > 3 {
		t.Fatalf("reconnect attempts were not bounded: %d", attempts)
	}
	if _, deadErr := outbound.run(ctx); !errors.Is(deadErr, oc.ErrReconnectTimeout) {
		t.Fatalf("outbound did not observe the exhausted session: %v", deadErr)
	}
	outbound.access.Lock()
	if outbound.session != nil || outbound.retryDelay != openConnectRetryInitialBackoff || outbound.retryAt.IsZero() {
		failedSession := outbound.session
		retryDelay := outbound.retryDelay
		retryAt := outbound.retryAt
		outbound.access.Unlock()
		t.Fatalf("dead session did not arm outbound retry: session=%v delay=%s at=%v", failedSession, retryDelay, retryAt)
	}
	outbound.access.Unlock()

	healthyPeer, err := testanyconnect.NewIPv4ICMPEchoPeer(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	healthyRecorder := testanyconnect.NewRecorder(scenario.Cookie)
	healthyGateway, err := testanyconnect.StartGateway(ctx, scenario, healthyPeer, healthyRecorder)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = healthyGateway.Close() }()
	outbound.access.Lock()
	outbound.retryAt = time.Now()
	outbound.config.Server = "https://" + healthyGateway.Address()
	outbound.access.Unlock()
	recovered, err := outbound.run(ctx)
	if err != nil {
		t.Fatalf("outbound did not recover after reconnect exhaustion: %v", err)
	}
	if recovered == nil || waitAnyConnectRecordCount(t, ctx, healthyRecorder, "cstp-connect", 1) != 1 {
		t.Fatalf("outbound recovery did not establish exactly one tunnel: %v", healthyRecorder.Records())
	}
}

func TestAnyConnectCloseStopsActiveReconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	scenario := testanyconnect.BasicCSTPScenario()
	peer, err := testanyconnect.NewIPv4ICMPEchoPeer(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	dialer := &openConnectBlockingReconnectDialer{reconnectStarted: make(chan struct{})}
	outbound := newFakeAnyConnectOutboundWithOption(t, gateway, scenario, dialer, 0, func(option *OpenConnectOption) {
		option.ReconnectTimeout = 5
	})
	if _, err := outbound.run(ctx); err != nil {
		t.Fatal(err)
	}
	if closed := gateway.DropCSTPConnections(); closed != 1 {
		t.Fatalf("expected one active CSTP connection, closed %d", closed)
	}
	select {
	case <-dialer.reconnectStarted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := outbound.Close(); err != nil {
		t.Fatal(err)
	}
	if attempts := dialer.count(); attempts != 2 {
		t.Fatalf("supervisor dialed after close: %d attempts", attempts)
	}
	if _, err := outbound.run(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("run after close returned %v", err)
	}
}

func TestAnyConnectCSTPSoak(t *testing.T) {
	runAnyConnectSoak(t, "")
}

func TestAnyConnectModernDTLSSoak(t *testing.T) {
	runAnyConnectSoak(t, "modern")
}

func TestAnyConnectLegacyDTLSSoak(t *testing.T) {
	runAnyConnectSoak(t, "legacy")
}

func TestAnyConnectReleaseStress(t *testing.T) {
	if os.Getenv("MIHOMO_ANYCONNECT_STRESS") != "1" {
		t.Skip("set MIHOMO_ANYCONNECT_STRESS=1 to run the AnyConnect release stress test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	scenario := testanyconnect.BasicCSTPScenario()
	peerAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := testanyconnect.NewIPv4TCPUDPEchoPeer(ctx, peerAddress, testAnyConnectTCPPort, testAnyConnectUDPPort)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	recorder := testanyconnect.NewRecorder(scenario.Cookie)
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, recorder)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()

	t.Run("concurrent UDP flows", func(t *testing.T) {
		outbound := newFakeAnyConnectOutboundWithOption(t, gateway, scenario, new(openConnectRecordingDialer), 0, func(option *OpenConnectOption) {
			option.QueueLength = 4096
		})
		defer func() { _ = outbound.Close() }()
		if _, err := outbound.run(ctx); err != nil {
			t.Fatal(err)
		}
		baselineGoroutines := runtime.NumGoroutine()
		baselineFDs := countAnyConnectFileDescriptors()
		for _, count := range []int{1, 100, 1000} {
			t.Run(strconv.Itoa(count), func(t *testing.T) {
				errorsFound := make(chan error, count)
				var wait sync.WaitGroup
				wait.Add(count)
				for index := range count {
					go func() {
						defer wait.Done()
						connection, err := outbound.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: peerAddress, DstPort: testAnyConnectUDPPort})
						if err != nil {
							errorsFound <- err
							return
						}
						defer connection.Close()
						payload := []byte("flow-" + strconv.Itoa(index))
						destination := &net.UDPAddr{IP: peerAddress.AsSlice(), Port: testAnyConnectUDPPort}
						_ = connection.SetDeadline(time.Now().Add(time.Minute))
						if _, err := connection.WriteTo(payload, destination); err != nil {
							errorsFound <- err
							return
						}
						reply := make([]byte, len(payload))
						read, _, err := connection.ReadFrom(reply)
						if err != nil {
							errorsFound <- err
							return
						}
						if read != len(payload) || !bytes.Equal(reply, payload) {
							errorsFound <- fmt.Errorf("unexpected UDP flow %d reply: %q", index, reply[:read])
						}
					}()
				}
				wait.Wait()
				close(errorsFound)
				for err := range errorsFound {
					t.Fatal(err)
				}
			})
		}
		waitForAnyConnectResourceCeiling(t, "concurrent flow stress", baselineGoroutines, baselineFDs, 8, 2)
	})

	t.Run("startup close cycles", func(t *testing.T) {
		baseline := countRecords(recorder.Records(), "cstp-connect")
		baselineGoroutines := runtime.NumGoroutine()
		baselineFDs := countAnyConnectFileDescriptors()
		for range 20 {
			outbound := newFakeAnyConnectOutbound(t, gateway, scenario, new(openConnectRecordingDialer), 0)
			if _, err := outbound.run(ctx); err != nil {
				t.Fatal(err)
			}
			if err := outbound.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if connections := countRecords(recorder.Records(), "cstp-connect") - baseline; connections != 20 {
			t.Fatalf("startup/close cycles created %d CSTP sessions", connections)
		}
		waitForAnyConnectResourceCeiling(t, "startup/close stress", baselineGoroutines, baselineFDs, 4, 2)
	})
}

func runAnyConnectSoak(t *testing.T, dtlsTransport string) {
	t.Helper()
	if dtlsTransport != "" && dtlsTransport != "modern" && dtlsTransport != "legacy" {
		t.Fatalf("unsupported AnyConnect soak transport %q", dtlsTransport)
	}
	if os.Getenv("MIHOMO_ANYCONNECT_SOAK") != "1" {
		t.Skip("set MIHOMO_ANYCONNECT_SOAK=1 to run the accelerated AnyConnect soak")
	}
	const soakDuration = 5 * time.Minute
	baselineGoroutines := runtime.NumGoroutine()
	baselineFDs := countAnyConnectFileDescriptors()
	ctx, cancel := context.WithTimeout(context.Background(), soakDuration+30*time.Second)
	defer cancel()
	scenario := testanyconnect.BasicCSTPScenario()
	scenario.ModernDTLS = dtlsTransport == "modern"
	scenario.LegacyDTLS = dtlsTransport == "legacy"
	peerAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := testanyconnect.NewIPv4TCPUDPEchoPeer(ctx, peerAddress, testAnyConnectTCPPort, testAnyConnectUDPPort)
	if err != nil {
		t.Fatal(err)
	}
	recorder := testanyconnect.NewRecorder(scenario.Cookie)
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, recorder)
	if err != nil {
		_ = peer.Close()
		t.Fatal(err)
	}
	dialer := new(openConnectRecordingDialer)
	outbound := newFakeAnyConnectOutboundWithOption(t, gateway, scenario, dialer, 0, func(option *OpenConnectOption) {
		option.ReconnectTimeout = 5
		option.DPDInterval = 30
		option.QueueLength = 64
		if dtlsTransport != "" {
			option.DTLSMode = oc.DTLSModeAuto
			option.DPDInterval = 2
		}
	})
	t.Cleanup(func() {
		_ = outbound.Close()
		_ = gateway.Close()
		_ = peer.Close()
	})
	session, err := outbound.run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if dtlsTransport != "" {
		waitAnyConnectTransport(t, ctx, session, "dtls")
	}
	udpConnection, err := outbound.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: peerAddress, DstPort: testAnyConnectUDPPort})
	if err != nil {
		t.Fatal(err)
	}
	destination := &net.UDPAddr{IP: peerAddress.AsSlice(), Port: testAnyConnectUDPPort}
	activeGoroutines := runtime.NumGoroutine()
	activeFDs := countAnyConnectFileDescriptors()
	start := time.Now()
	nextReconnect := start.Add(10 * time.Second)
	nextResourceCheck := start.Add(10 * time.Second)
	reconnects := 0
	sequence := 0
	trafficTicker := time.NewTicker(time.Second)
	defer trafficTicker.Stop()
	for time.Since(start) < soakDuration {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-trafficTicker.C:
		}
		sequence++
		payload := "soak-" + strconv.Itoa(sequence)
		exchangeAnyConnectUDP(t, ctx, udpConnection, destination, payload)
		tcpConnection, err := outbound.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: peerAddress, DstPort: testAnyConnectTCPPort})
		if err != nil {
			t.Fatal(err)
		}
		_ = tcpConnection.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := tcpConnection.Write([]byte(payload)); err != nil {
			_ = tcpConnection.Close()
			t.Fatal(err)
		}
		tcpReply := make([]byte, len(payload))
		if _, err := io.ReadFull(tcpConnection, tcpReply); err != nil {
			_ = tcpConnection.Close()
			t.Fatal(err)
		}
		_ = tcpConnection.Close()
		if string(tcpReply) != payload {
			t.Fatalf("unexpected soak TCP reply: %q", tcpReply)
		}

		now := time.Now()
		if !now.Before(nextReconnect) {
			if dtlsTransport == "legacy" {
				legacyHandshakes := countRecords(recorder.Records(), "legacy-dtls-handshake")
				gateway.SetDTLSBlackhole(true)
				waitAnyConnectTransport(t, ctx, session, "cstp")
				gateway.SetDTLSBlackhole(false)
				for countRecords(recorder.Records(), "legacy-dtls-handshake") <= legacyHandshakes {
					select {
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-time.After(10 * time.Millisecond):
					}
				}
				waitAnyConnectTransport(t, ctx, session, "dtls")
			} else if dtlsTransport == "modern" {
				if closed := gateway.DropDTLSConnections(); closed != 1 {
					t.Fatalf("soak expected one active modern DTLS connection, closed %d", closed)
				}
				waitAnyConnectTransport(t, ctx, session, "cstp")
				waitAnyConnectTransport(t, ctx, session, "dtls")
			} else {
				before, _ := dialer.counts()
				if closed := gateway.DropCSTPConnections(); closed != 1 {
					t.Fatalf("soak expected one active CSTP connection, closed %d", closed)
				}
				for {
					connections, _ := dialer.counts()
					if connections == before+1 {
						break
					}
					if connections > before+1 {
						t.Fatalf("one CSTP failure caused %d reconnect attempts", connections-before)
					}
					select {
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-time.After(10 * time.Millisecond):
					}
				}
				if _, err := session.client.WaitReady(ctx); err != nil {
					t.Fatal(err)
				}
			}
			reconnects++
			nextReconnect = time.Now().Add(10 * time.Second)
		}
		if !now.Before(nextResourceCheck) {
			if current := runtime.NumGoroutine(); current > activeGoroutines+8 {
				t.Fatalf("AnyConnect soak goroutines grew from %d to %d", activeGoroutines, current)
			}
			if current := countAnyConnectFileDescriptors(); activeFDs >= 0 && current > activeFDs+4 {
				t.Fatalf("AnyConnect soak file descriptors grew from %d to %d", activeFDs, current)
			}
			nextResourceCheck = nextResourceCheck.Add(10 * time.Second)
		}
	}
	connections, _ := dialer.counts()
	expectedConnections := reconnects + 1
	if dtlsTransport != "" {
		expectedConnections = 1
	}
	if connections != expectedConnections {
		t.Fatalf("CSTP reconnects were not bounded: connections=%d forced=%d", connections, reconnects)
	}
	_ = udpConnection.Close()
	if err := outbound.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gateway.Close(); err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	waitForAnyConnectResourceCeiling(t, "AnyConnect soak", baselineGoroutines, baselineFDs, 4, 2)
}

func waitForAnyConnectResourceCeiling(t *testing.T, name string, baselineGoroutines int, baselineFDs int, goroutineAllowance int, fdAllowance int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		runtime.GC()
		goroutines := runtime.NumGoroutine()
		fds := countAnyConnectFileDescriptors()
		if goroutines <= baselineGoroutines+goroutineAllowance && (baselineFDs < 0 || fds <= baselineFDs+fdAllowance) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s leaked resources: goroutines %d -> %d, file descriptors %d -> %d", name, baselineGoroutines, goroutines, baselineFDs, fds)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func exchangeAnyConnectUDP(t *testing.T, ctx context.Context, connection net.PacketConn, destination net.Addr, payload string) {
	t.Helper()
	write := func() {
		if _, err := connection.WriteTo([]byte(payload), destination); err != nil {
			t.Fatal(err)
		}
	}
	write()
	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		if err := connection.SetReadDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}
	readResult := make(chan error, 1)
	go func() {
		reply := make([]byte, 128)
		for {
			count, _, err := connection.ReadFrom(reply)
			if err != nil {
				readResult <- err
				return
			}
			if string(reply[:count]) == payload {
				readResult <- nil
				return
			}
		}
	}()
	retry := time.NewTicker(500 * time.Millisecond)
	defer retry.Stop()
	for {
		select {
		case err := <-readResult:
			if err != nil {
				t.Fatal(err)
			}
			return
		case <-retry.C:
			write()
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func countAnyConnectFileDescriptors() int {
	for _, directory := range []string{"/proc/self/fd", "/dev/fd"} {
		entries, err := os.ReadDir(directory)
		if err == nil {
			return len(entries)
		}
	}
	return -1
}

func TestAnyConnectConcurrentStartupAndCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	scenario := testanyconnect.BasicCSTPScenario()
	scenario.CSTP.ResponseDelay = 150 * time.Millisecond
	peer, err := testanyconnect.NewIPv4ICMPEchoPeer(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	recorder := testanyconnect.NewRecorder(scenario.Cookie)
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, recorder)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	dialer := &openConnectRecordingDialer{dialStarted: make(chan struct{})}
	outbound := newFakeAnyConnectOutbound(t, gateway, scenario, dialer, 0)
	defer func() { _ = outbound.Close() }()

	canceledContext, cancelCaller := context.WithCancel(ctx)
	canceledResult := make(chan error, 1)
	go func() {
		_, runErr := outbound.run(canceledContext)
		canceledResult <- runErr
	}()
	select {
	case <-dialer.dialStarted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancelCaller()
	if err := <-canceledResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled caller returned %v", err)
	}

	const callers = 100
	results := make(chan *openConnectSession, callers)
	errorsCh := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			session, runErr := outbound.run(ctx)
			if runErr != nil {
				errorsCh <- runErr
				return
			}
			results <- session
		}()
	}
	wait.Wait()
	close(results)
	close(errorsCh)
	for runErr := range errorsCh {
		t.Error(runErr)
	}
	var first *openConnectSession
	for session := range results {
		if first == nil {
			first = session
		} else if session != first {
			t.Fatal("concurrent callers received different sessions")
		}
	}
	if first == nil {
		t.Fatal("no caller received a session")
	}
	configuration := first.configurationSnapshot()
	if len(configuration.Routes) == 0 || configuration.Routes[0] != netip.MustParsePrefix("0.0.0.0/0") {
		t.Fatalf("negotiated routes were not retained: %#v", configuration.Routes)
	}
	if waitAnyConnectRecordCount(t, ctx, recorder, "cstp-connect", 1) != 1 {
		t.Fatalf("expected one shared CSTP session, records=%v", recorder.Records())
	}
}

func TestAnyConnectCloseDuringStartup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	scenario := testanyconnect.BasicCSTPScenario()
	scenario.CSTP.ResponseDelay = time.Second
	peer, err := testanyconnect.NewIPv4ICMPEchoPeer(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	dialer := &openConnectRecordingDialer{dialStarted: make(chan struct{})}
	outbound := newFakeAnyConnectOutbound(t, gateway, scenario, dialer, 0)
	runResult := make(chan error, 1)
	go func() {
		_, runErr := outbound.run(ctx)
		runResult <- runErr
	}()
	select {
	case <-dialer.dialStarted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	closeResults := make(chan error, 2)
	go func() { closeResults <- outbound.Close() }()
	go func() { closeResults <- outbound.Close() }()
	if err := <-runResult; !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("startup returned %v after close", err)
	}
	for range 2 {
		if err := <-closeResults; err != nil {
			t.Fatalf("concurrent close failed: %v", err)
		}
	}
}

func TestAnyConnectSessionStopsOnTunnelReadFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	scenario := testanyconnect.BasicCSTPScenario()
	scenario.CSTP.MalformedDataHeader = true
	peerAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := testanyconnect.NewIPv4ICMPEchoPeer(peerAddress)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	outbound := newFakeAnyConnectOutbound(t, gateway, scenario, new(openConnectRecordingDialer), 0)
	defer func() { _ = outbound.Close() }()
	session, err := outbound.run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request, err := testanyconnect.BuildIPv4ICMPEchoRequest(scenario.Configuration.Addresses[0].Addr(), peerAddress, 1, 1, []byte("malformed-response"))
	if err != nil {
		t.Fatal(err)
	}
	if err := session.client.WritePacket(request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.done:
	case <-ctx.Done():
		t.Fatalf("session did not stop after malformed tunnel data: %v", ctx.Err())
	}
	terminalErr := session.err()
	if terminalErr == nil || errors.Is(terminalErr, net.ErrClosed) {
		t.Fatalf("unexpected terminal tunnel error: %v", terminalErr)
	}
	if _, err := outbound.run(ctx); err != terminalErr {
		t.Fatalf("terminal tunnel error was not retained: got=%v want=%v", err, terminalErr)
	}
}

func TestAnyConnectAuthenticatedStartupAndTerminalFailureLatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	scenario := testanyconnect.BasicCSTPScenario()
	scenario.Authentication = testanyconnect.AuthenticationScenario{
		Enabled:           true,
		Username:          "phase2-user",
		Password:          "phase2-password",
		Challenge:         "Phase 2 challenge",
		ChallengeResponse: "phase2-answer",
		CookieUses:        1,
	}
	peerAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := testanyconnect.NewIPv4TCPUDPEchoPeer(ctx, peerAddress, testAnyConnectTCPPort, testAnyConnectUDPPort)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	recorder := testanyconnect.NewRecorder(scenario.Cookie, scenario.Authentication.Password, scenario.Authentication.ChallengeResponse)
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, recorder)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	provider := openConnectAuthProviderFunc(func(_ context.Context, challenge oc.AuthChallenge) (oc.AuthResponse, error) {
		if challenge.Form == nil || len(challenge.Form.Fields) != 1 {
			return oc.AuthResponse{}, errors.New("unexpected AnyConnect challenge")
		}
		field := challenge.Form.Fields[0]
		return oc.AuthResponse{FormValues: map[string]string{field.SubmissionKey: scenario.Authentication.ChallengeResponse}}, nil
	})
	authenticated := newFakeAnyConnectOutboundWithOption(t, gateway, scenario, new(openConnectRecordingDialer), 0, func(option *OpenConnectOption) {
		option.Cookie = ""
		option.Username = scenario.Authentication.Username
		option.Password = scenario.Authentication.Password
		option.AuthProvider = provider
	})
	authenticatedSession, err := authenticated.run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if closed := gateway.DropCSTPConnections(); closed != 1 {
		t.Fatalf("expected one authenticated CSTP connection, closed %d", closed)
	}
	for countRecords(recorder.Records(), "auth-complete") < 2 || countRecords(recorder.Records(), "cstp-connect") < 2 {
		select {
		case <-ctx.Done():
			t.Fatalf("cookie expiry did not trigger reauthentication: %v", recorder.Records())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if readySession, err := authenticated.run(ctx); err != nil {
		t.Fatal(err)
	} else if readySession != authenticatedSession {
		t.Fatal("cookie reauthentication replaced the shared outbound session")
	}
	packetConnection, err := authenticated.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: peerAddress, DstPort: testAnyConnectUDPPort})
	if err != nil {
		t.Fatal(err)
	}
	exchangeAnyConnectUDP(t, ctx, packetConnection, &net.UDPAddr{IP: peerAddress.AsSlice(), Port: testAnyConnectUDPPort}, "after cookie reauthentication")
	_ = packetConnection.Close()
	if err := authenticated.Close(); err != nil {
		t.Fatal(err)
	}

	rejectedScenario := scenario
	rejectedScenario.Name = "missing-auth-provider"
	rejectedRecorder := testanyconnect.NewRecorder(rejectedScenario.Cookie, rejectedScenario.Authentication.Password, rejectedScenario.Authentication.ChallengeResponse)
	rejectedGateway, err := testanyconnect.StartGateway(ctx, rejectedScenario, peer, rejectedRecorder)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rejectedGateway.Close() }()
	wrongCredentialProvider := openConnectAuthProviderFunc(func(_ context.Context, challenge oc.AuthChallenge) (oc.AuthResponse, error) {
		values := make(map[string]string)
		if challenge.Form == nil {
			return oc.AuthResponse{}, errors.New("unexpected browser challenge")
		}
		for _, field := range challenge.Form.Fields {
			switch field.Name {
			case "username":
				values[field.SubmissionKey] = rejectedScenario.Authentication.Username
			case "password":
				values[field.SubmissionKey] = "wrong-password"
			default:
				values[field.SubmissionKey] = field.Value
			}
		}
		return oc.AuthResponse{FormValues: values}, nil
	})
	rejected := newFakeAnyConnectOutboundWithOption(t, rejectedGateway, rejectedScenario, new(openConnectRecordingDialer), 0, func(option *OpenConnectOption) {
		option.Cookie = ""
		option.AuthProvider = wrongCredentialProvider
	})
	defer func() { _ = rejected.Close() }()
	_, firstErr := rejected.run(ctx)
	if !errors.Is(firstErr, oc.ErrAuthRejected) || !oc.IsTerminal(firstErr) {
		t.Fatalf("expected terminal auth-rejected error, got %v", firstErr)
	}
	if rejectedCount := countRecords(rejectedRecorder.Records(), "auth-reject"); rejectedCount != 1 {
		t.Fatalf("credential rejection was retried: %d attempts", rejectedCount)
	}
	recordCount := len(rejectedRecorder.Records())
	_, secondErr := rejected.run(ctx)
	if secondErr != firstErr {
		t.Fatalf("terminal authentication error was not latched: first=%v second=%v", firstErr, secondErr)
	}
	if len(rejectedRecorder.Records()) != recordCount {
		t.Fatalf("latched auth failure caused another login: before=%d after=%d", recordCount, len(rejectedRecorder.Records()))
	}
	writeAnyConnectEvidence(t, "auth-outbound", scenario.Name+"-provider-reauthentication-and-rejection", []testanyconnect.Capability{
		testanyconnect.CapabilityAuth,
		testanyconnect.CapabilityReauth,
	})
}

func TestOpenConnectHandshakeTimeoutRetriesAfterBackoff(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	scenario := testanyconnect.BasicCSTPScenario()
	scenario.CSTP.ResponseDelay = 2 * time.Second
	peer, err := testanyconnect.NewIPv4ICMPEchoPeer(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	recorder := testanyconnect.NewRecorder(scenario.Cookie)
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, recorder)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	outbound := newFakeAnyConnectOutbound(t, gateway, scenario, new(openConnectRecordingDialer), 1)
	defer func() { _ = outbound.Close() }()

	_, firstErr := outbound.run(ctx)
	if !errors.Is(firstErr, context.DeadlineExceeded) {
		t.Fatalf("expected handshake timeout, got %v", firstErr)
	}
	_, secondErr := outbound.run(ctx)
	if secondErr != firstErr {
		t.Fatalf("startup retry ignored its backoff: first=%v second=%v", firstErr, secondErr)
	}
	if err := gateway.Close(); err != nil {
		t.Fatal(err)
	}
	healthyScenario := testanyconnect.BasicCSTPScenario()
	healthyPeer, err := testanyconnect.NewIPv4ICMPEchoPeer(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	healthyRecorder := testanyconnect.NewRecorder(healthyScenario.Cookie)
	healthyGateway, err := testanyconnect.StartGateway(ctx, healthyScenario, healthyPeer, healthyRecorder)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = healthyGateway.Close() }()
	outbound.access.Lock()
	if outbound.retryDelay != openConnectRetryInitialBackoff || outbound.retryAt.IsZero() {
		outbound.access.Unlock()
		t.Fatalf("startup timeout did not arm bounded retry: delay=%s at=%v", outbound.retryDelay, outbound.retryAt)
	}
	outbound.retryAt = time.Now()
	outbound.option.HandshakeTimeout = 0
	outbound.config.Server = "https://" + healthyGateway.Address()
	outbound.access.Unlock()
	session, retryErr := outbound.run(ctx)
	if retryErr != nil {
		t.Fatalf("startup did not recover after transient timeout: %v", retryErr)
	}
	if session == nil || waitAnyConnectRecordCount(t, ctx, healthyRecorder, "cstp-connect", 1) != 1 {
		t.Fatalf("startup retry did not establish exactly one tunnel: %v", healthyRecorder.Records())
	}
	if !retryableOpenConnectError(context.DeadlineExceeded) || !retryableOpenConnectError(oc.ErrReconnectTimeout) {
		t.Fatal("timeout and reconnect exhaustion must remain retryable")
	}
}

func TestOpenConnectHandshakeContext(t *testing.T) {
	withoutTimeout, cancelWithoutTimeout := openConnectHandshakeContext(context.Background(), 0)
	defer cancelWithoutTimeout()
	if _, hasDeadline := withoutTimeout.Deadline(); hasDeadline {
		t.Fatal("zero handshake timeout created an overall deadline")
	}

	withTimeout, cancelWithTimeout := openConnectHandshakeContext(context.Background(), time.Second)
	defer cancelWithTimeout()
	deadline, hasDeadline := withTimeout.Deadline()
	if !hasDeadline || time.Until(deadline) <= 0 || time.Until(deadline) > time.Second {
		t.Fatalf("positive handshake timeout created an invalid deadline: deadline=%v present=%v", deadline, hasDeadline)
	}
}

func newFakeAnyConnectOutbound(t testing.TB, gateway *testanyconnect.Gateway, scenario testanyconnect.Scenario, dialer C.Dialer, handshakeTimeout int) *OpenConnect {
	return newFakeAnyConnectOutboundWithOption(t, gateway, scenario, dialer, handshakeTimeout, nil)
}

func newFakeAnyConnectOutboundWithOption(t testing.TB, gateway *testanyconnect.Gateway, scenario testanyconnect.Scenario, dialer C.Dialer, handshakeTimeout int, mutate func(*OpenConnectOption)) *OpenConnect {
	t.Helper()
	_, portText, err := net.SplitHostPort(gateway.Address())
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}
	option := OpenConnectOption{
		BasicOption:      BasicOption{DialerForAPI: dialer},
		Name:             "fake-anyconnect",
		Protocol:         oc.ProtocolAnyConnect,
		Server:           gateway.ServerName(),
		Port:             port,
		Cookie:           scenario.Cookie,
		CA:               string(testanyconnect.RootCAPEM()),
		ServerName:       gateway.ServerName(),
		HandshakeTimeout: handshakeTimeout,
		DTLSMode:         "off",
	}
	if mutate != nil {
		mutate(&option)
	}
	outbound, err := NewOpenConnect(option)
	if err != nil {
		t.Fatal(err)
	}
	return outbound
}

func countRecords(records []testanyconnect.Record, kind string) int {
	count := 0
	for _, record := range records {
		if record.Kind == kind {
			count++
		}
	}
	return count
}

func waitAnyConnectRecordCount(t *testing.T, ctx context.Context, recorder *testanyconnect.Recorder, kind string, minimum uint64) uint64 {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		count := recorder.Count(kind)
		if count >= minimum {
			return count
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for %q record: %v", kind, ctx.Err())
		case <-timer.C:
			t.Fatalf("waiting for %q record: got %d, want at least %d; records=%v", kind, count, minimum, recorder.Records())
		case <-ticker.C:
		}
	}
}

func writeAnyConnectOutboundEvidence(t *testing.T, scenario string) {
	writeAnyConnectEvidence(t, "outbound", scenario+"-tcp-udp-echo", []testanyconnect.Capability{
		testanyconnect.CapabilityCookieCSTP,
		testanyconnect.CapabilityPacketIPv4,
	})
}

func writeAnyConnectEvidence(t *testing.T, suffix string, scenario string, capabilities []testanyconnect.Capability) {
	writeAnyConnectEvidenceForTransport(t, suffix, scenario, capabilities, "cstp")
}

func writeAnyConnectEvidenceForAddress(t *testing.T, suffix string, scenario string, capabilities []testanyconnect.Capability, address string) {
	writeAnyConnectEvidenceForTransportAndAddress(t, suffix, scenario, capabilities, "cstp", address)
}

func writeAnyConnectEvidenceForTransport(t *testing.T, suffix string, scenario string, capabilities []testanyconnect.Capability, transport string) {
	writeAnyConnectEvidenceForTransportAndAddress(t, suffix, scenario, capabilities, transport, "ipv4")
}

func writeAnyConnectEvidenceForTransportAndAddress(t *testing.T, suffix string, scenario string, capabilities []testanyconnect.Capability, transport string, address string) {
	t.Helper()
	path := os.Getenv("MIHOMO_ANYCONNECT_MATRIX")
	if path == "" {
		return
	}
	extension := filepath.Ext(path)
	path = strings.TrimSuffix(path, extension) + "-" + suffix + extension
	matrix := testanyconnect.NewCapabilityMatrix()
	for _, capability := range capabilities {
		if err := matrix.Record(testanyconnect.Evidence{
			Capability: capability,
			Scenario:   scenario,
			Driver:     testanyconnect.DriverOutbound,
			Gateway:    "fake",
			Transport:  transport,
			Address:    address,
			Passed:     true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := matrix.WriteJSON(path); err != nil {
		t.Fatal(err)
	}
}
