//go:build with_gvisor

package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	testanyconnect "github.com/metacubex/mihomo/internal/testutil/anyconnect"
)

const (
	testAnyConnectTCPPort = 18080
	testAnyConnectUDPPort = 15353
)

type anyConnectRecordingDialer struct {
	access       sync.Mutex
	tcpCalls     int
	udpCalls     int
	destinations []string
	dialStarted  chan struct{}
	dialOnce     sync.Once
}

func (d *anyConnectRecordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
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

func (d *anyConnectRecordingDialer) ListenPacket(ctx context.Context, network, address string, remote netip.AddrPort) (net.PacketConn, error) {
	d.access.Lock()
	d.udpCalls++
	d.destinations = append(d.destinations, address)
	d.access.Unlock()
	return (&net.ListenConfig{}).ListenPacket(ctx, network, "")
}

func (d *anyConnectRecordingDialer) counts() (int, int) {
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
	dialer := new(anyConnectRecordingDialer)
	outbound := newFakeAnyConnectOutbound(t, gateway, scenario, dialer, 0)
	defer func() {
		if err := outbound.Close(); err != nil {
			t.Error(err)
		}
	}()
	if outbound.Type() != C.AnyConnect || !outbound.SupportUDP() || !outbound.IsL3Protocol(nil) {
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
	if countRecords(recorder.Records(), "cstp-connect") != 1 {
		t.Fatalf("expected one CSTP session, records=%v", recorder.Records())
	}
	writeAnyConnectOutboundEvidence(t, scenario.Name)
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
	dialer := &anyConnectRecordingDialer{dialStarted: make(chan struct{})}
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
	results := make(chan *anyConnectSession, callers)
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
	var first *anyConnectSession
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
	if len(first.configuration.Routes) == 0 || first.configuration.Routes[0] != netip.MustParsePrefix("0.0.0.0/0") {
		t.Fatalf("negotiated routes were not retained: %#v", first.configuration.Routes)
	}
	if countRecords(recorder.Records(), "cstp-connect") != 1 {
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
	dialer := &anyConnectRecordingDialer{dialStarted: make(chan struct{})}
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
	outbound := newFakeAnyConnectOutbound(t, gateway, scenario, new(anyConnectRecordingDialer), 0)
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

func TestAnyConnectHandshakeTimeoutIsLatched(t *testing.T) {
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
	outbound := newFakeAnyConnectOutbound(t, gateway, scenario, new(anyConnectRecordingDialer), 1)
	defer func() { _ = outbound.Close() }()

	started := time.Now()
	_, firstErr := outbound.run(ctx)
	if !errors.Is(firstErr, context.DeadlineExceeded) {
		t.Fatalf("expected handshake timeout, got %v", firstErr)
	}
	if elapsed := time.Since(started); elapsed < 900*time.Millisecond || elapsed > 1500*time.Millisecond {
		t.Fatalf("handshake timeout took %s", elapsed)
	}
	_, secondErr := outbound.run(ctx)
	if secondErr != firstErr {
		t.Fatalf("startup failure was not latched: first=%v second=%v", firstErr, secondErr)
	}
	if countRecords(recorder.Records(), "cstp-connect") != 0 {
		t.Fatalf("timed out session unexpectedly became ready: %v", recorder.Records())
	}
}

func newFakeAnyConnectOutbound(t *testing.T, gateway *testanyconnect.Gateway, scenario testanyconnect.Scenario, dialer C.Dialer, handshakeTimeout int) *AnyConnect {
	t.Helper()
	_, portText, err := net.SplitHostPort(gateway.Address())
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := NewAnyConnect(AnyConnectOption{
		BasicOption:      BasicOption{DialerForAPI: dialer},
		Name:             "fake-anyconnect",
		Server:           gateway.ServerName(),
		Port:             port,
		Cookie:           scenario.Cookie,
		CA:               string(testanyconnect.RootCAPEM()),
		ServerName:       gateway.ServerName(),
		HandshakeTimeout: handshakeTimeout,
		DTLSMode:         "off",
	})
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

func writeAnyConnectOutboundEvidence(t *testing.T, scenario string) {
	t.Helper()
	path := os.Getenv("MIHOMO_ANYCONNECT_MATRIX")
	if path == "" {
		return
	}
	extension := filepath.Ext(path)
	path = strings.TrimSuffix(path, extension) + "-outbound" + extension
	matrix := testanyconnect.NewCapabilityMatrix()
	for _, capability := range []testanyconnect.Capability{testanyconnect.CapabilityCookieCSTP, testanyconnect.CapabilityPacketIPv4} {
		if err := matrix.Record(testanyconnect.Evidence{
			Capability: capability,
			Scenario:   scenario + "-tcp-udp-echo",
			Driver:     testanyconnect.DriverOutbound,
			Gateway:    "fake",
			Transport:  "cstp",
			Address:    "ipv4",
			Passed:     true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := matrix.WriteJSON(path); err != nil {
		t.Fatal(err)
	}
}
