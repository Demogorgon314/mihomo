package anyconnect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestFakeGatewayCSTPProbe(t *testing.T) {
	scenario := BasicCSTPScenario()
	scenario.CSTP.ResponseChunkSize = 1
	serverAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := NewIPv4ICMPEchoPeer(serverAddress)
	if err != nil {
		t.Fatal(err)
	}
	recorder := NewRecorder(scenario.Cookie)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gateway, err := StartGateway(ctx, scenario, peer, recorder)
	if err != nil {
		t.Fatal(err)
	}
	request, err := BuildIPv4ICMPEchoRequest(scenario.Configuration.Addresses[0].Addr(), serverAddress, 3, 5, []byte("phase0-gateway"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := RunCSTPProbe(ctx, ProbeOptions{
		Address:    gateway.Address(),
		ServerName: gateway.ServerName(),
		RootCAs:    gateway.RootCAs(),
		Cookie:     scenario.Cookie,
		Packet:     request,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Configuration.MTU != scenario.Configuration.MTU || len(result.Configuration.Addresses) != 1 || result.Configuration.Addresses[0] != scenario.Configuration.Addresses[0] {
		t.Fatalf("unexpected negotiated configuration: %#v", result.Configuration)
	}
	if result.Packet[20] != 0 || !bytes.Equal(result.Packet[28:], []byte("phase0-gateway")) {
		t.Fatalf("unexpected tunneled reply: %x", result.Packet)
	}
	if err := gateway.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gateway.Close(); err != nil {
		t.Fatalf("second close failed: %v", err)
	}
	records := recorder.Records()
	if len(records) != 2 || records[0].Kind != "cstp-connect" || records[1].Kind != "cstp-data" {
		t.Fatalf("unexpected gateway records: %#v", records)
	}
	for _, record := range records {
		if strings.Contains(record.Message, scenario.Cookie) {
			t.Fatalf("cookie leaked into record: %#v", record)
		}
	}
	for _, capability := range []Capability{CapabilityCookieCSTP, CapabilityPacketIPv4} {
		if err := phase0CapabilityMatrix.Record(Evidence{
			Capability: capability,
			Scenario:   scenario.Name,
			Driver:     DriverProbe,
			Gateway:    "fake",
			Transport:  "cstp",
			Address:    "ipv4",
			Passed:     true,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFakeGatewayModernDTLSProbe(t *testing.T) {
	scenario := BasicCSTPScenario()
	scenario.ModernDTLS = true
	gateway, request, ctx := startProbeTestGateway(t, scenario)
	result, err := RunDTLSProbe(ctx, DTLSProbeOptions{ProbeOptions: ProbeOptions{
		Address:    gateway.Address(),
		ServerName: gateway.ServerName(),
		RootCAs:    gateway.RootCAs(),
		Cookie:     scenario.Cookie,
		Packet:     request,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Packet) < 28 || result.Packet[20] != 0 || string(result.Packet[28:]) != "probe" {
		t.Fatalf("unexpected DTLS probe reply: %x", result.Packet)
	}
	if err := phase0CapabilityMatrix.Record(Evidence{
		Capability: CapabilityModernDTLS,
		Scenario:   "modern-dtls",
		Driver:     DriverProbe,
		Gateway:    "fake",
		Transport:  "dtls",
		Address:    "ipv4",
		Passed:     true,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFakeGatewayModernDTLSRejectsWrongExporterPSK(t *testing.T) {
	scenario := BasicCSTPScenario()
	scenario.ModernDTLS = true
	gateway, request, ctx := startProbeTestGateway(t, scenario)
	probeContext, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	_, err := RunDTLSProbe(probeContext, DTLSProbeOptions{
		ProbeOptions: ProbeOptions{
			Address:    gateway.Address(),
			ServerName: gateway.ServerName(),
			RootCAs:    gateway.RootCAs(),
			Cookie:     scenario.Cookie,
			Packet:     request,
		},
		PSKOverride: make([]byte, 32),
	})
	if err == nil || !strings.Contains(err.Error(), "handshake probe DTLS") {
		t.Fatalf("expected DTLS authentication failure, got %v", err)
	}
}

func TestFakeGatewayRejectsWrongCookie(t *testing.T) {
	scenario := BasicCSTPScenario()
	gateway, request, ctx := startProbeTestGateway(t, scenario)
	_, err := RunCSTPProbe(ctx, ProbeOptions{
		Address:    gateway.Address(),
		ServerName: gateway.ServerName(),
		RootCAs:    gateway.RootCAs(),
		Cookie:     "wrong-cookie",
		Packet:     request,
	})
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("expected HTTP 401, got %v", err)
	}
}

func TestFakeGatewayConfiguredRejection(t *testing.T) {
	scenario := BasicCSTPScenario()
	scenario.CSTP.RejectStatus = 503
	gateway, request, ctx := startProbeTestGateway(t, scenario)
	_, err := RunCSTPProbe(ctx, ProbeOptions{
		Address:    gateway.Address(),
		ServerName: gateway.ServerName(),
		RootCAs:    gateway.RootCAs(),
		Cookie:     scenario.Cookie,
		Packet:     request,
	})
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("expected HTTP 503, got %v", err)
	}
}

func TestFakeGatewayMalformedFrameIsDetected(t *testing.T) {
	scenario := BasicCSTPScenario()
	scenario.CSTP.MalformedDataHeader = true
	gateway, request, ctx := startProbeTestGateway(t, scenario)
	_, err := RunCSTPProbe(ctx, ProbeOptions{
		Address:    gateway.Address(),
		ServerName: gateway.ServerName(),
		RootCAs:    gateway.RootCAs(),
		Cookie:     scenario.Cookie,
		Packet:     request,
	})
	if err == nil || !strings.Contains(err.Error(), "magic") {
		t.Fatalf("expected malformed magic error, got %v", err)
	}
	if err := phase0CapabilityMatrix.Record(Evidence{
		Capability: CapabilityFraming,
		Scenario:   "malformed-data-header",
		Driver:     DriverProbe,
		Gateway:    "fake",
		Transport:  "cstp",
		Address:    "ipv4",
		Passed:     true,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFakeGatewayProbeDetectsCorruptPacket(t *testing.T) {
	scenario := BasicCSTPScenario()
	gateway, request, ctx := startProbeTestGateway(t, scenario)
	request[10] ^= 0xff // Break the IPv4 header checksum after construction.
	_, err := RunCSTPProbe(ctx, ProbeOptions{
		Address:    gateway.Address(),
		ServerName: gateway.ServerName(),
		RootCAs:    gateway.RootCAs(),
		Cookie:     scenario.Cookie,
		Packet:     request,
	})
	if err == nil || !strings.Contains(err.Error(), "read tunneled probe reply") {
		t.Fatalf("expected corrupt packet to terminate the probe, got %v", err)
	}
	if err := gateway.Close(); err == nil || !strings.Contains(err.Error(), "invalid IPv4 header checksum") {
		t.Fatalf("expected gateway checksum rejection, got %v", err)
	}
	if err := phase0CapabilityMatrix.Record(Evidence{
		Capability: CapabilityPacketIPv4,
		Scenario:   "corrupt-ipv4-checksum",
		Driver:     DriverProbe,
		Gateway:    "fake",
		Transport:  "cstp",
		Address:    "ipv4",
		Passed:     true,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFakeGatewayTLSIsVerified(t *testing.T) {
	scenario := BasicCSTPScenario()
	gateway, request, ctx := startProbeTestGateway(t, scenario)
	_, err := RunCSTPProbe(ctx, ProbeOptions{
		Address:    gateway.Address(),
		ServerName: gateway.ServerName(),
		RootCAs:    x509.NewCertPool(),
		Cookie:     scenario.Cookie,
		Packet:     request,
	})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected certificate verification error, got %v", err)
	}
	if err := phase0CapabilityMatrix.Record(Evidence{
		Capability: CapabilityTLSVerify,
		Scenario:   "untrusted-ca",
		Driver:     DriverProbe,
		Gateway:    "fake",
		Transport:  "cstp",
		Address:    "ipv4",
		Passed:     true,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRunCSTPProbeValidatesOptions(t *testing.T) {
	if _, err := RunCSTPProbe(nil, ProbeOptions{}); err == nil || !strings.Contains(err.Error(), "context") {
		t.Fatalf("expected context error, got %v", err)
	}
	if _, err := RunCSTPProbe(context.Background(), ProbeOptions{}); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected option error, got %v", err)
	}
	if _, err := RunCSTPProbe(context.Background(), ProbeOptions{Address: "unused", ServerName: "unused", RootCAs: x509.NewCertPool(), Cookie: "value\r\ninjected", Packet: []byte{1}}); err == nil || !strings.Contains(err.Error(), "header character") {
		t.Fatalf("expected cookie header error, got %v", err)
	}
}

func TestFakeGatewayCloseInterruptsActiveConnection(t *testing.T) {
	scenario := BasicCSTPScenario()
	serverAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := NewIPv4ICMPEchoPeer(serverAddress)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := StartGateway(context.Background(), scenario, peer, nil)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := tls.Dial("tcp", gateway.Address(), &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: gateway.ServerName(),
		RootCAs:    gateway.RootCAs(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\nHost: localhost\r\nCookie: webvpn=" + scenario.Cookie + "\r\n\r\n"
	if _, err := connection.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		if line == "\r\n" {
			break
		}
	}
	closed := make(chan error, 1)
	go func() { closed <- gateway.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway close did not interrupt the active CSTP connection")
	}
	_ = connection.Close()
}

func TestStartGatewayValidatesArguments(t *testing.T) {
	scenario := BasicCSTPScenario()
	peer, err := NewIPv4ICMPEchoPeer(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := StartGateway(nil, scenario, peer, nil); err == nil {
		t.Fatal("expected nil context error")
	}
	if _, err := StartGateway(context.Background(), Scenario{}, peer, nil); err == nil {
		t.Fatal("expected invalid scenario error")
	}
	if _, err := StartGateway(context.Background(), scenario, nil, nil); err == nil {
		t.Fatal("expected nil peer error")
	}
}

func startProbeTestGateway(t *testing.T, scenario Scenario) (*Gateway, []byte, context.Context) {
	t.Helper()
	serverAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := NewIPv4ICMPEchoPeer(serverAddress)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	gateway, err := StartGateway(ctx, scenario, peer, NewRecorder(scenario.Cookie))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Close() })
	request, err := BuildIPv4ICMPEchoRequest(scenario.Configuration.Addresses[0].Addr(), serverAddress, 1, 1, []byte("probe"))
	if err != nil {
		t.Fatal(err)
	}
	return gateway, request, ctx
}
