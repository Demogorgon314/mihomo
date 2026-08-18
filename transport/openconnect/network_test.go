package openconnect

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	testopenconnect "github.com/metacubex/mihomo/internal/testutil/openconnect"
	"github.com/pierrec/lz4/v4"
)

type burstPacketPeer struct {
	peer  *testopenconnect.IPv4ICMPEchoPeer
	count int
}

func (p *burstPacketPeer) HandlePacket(packet []byte) ([]byte, error) {
	return p.peer.HandlePacket(packet)
}

func (p *burstPacketPeer) HandlePackets(packet []byte) ([][]byte, error) {
	reply, err := p.peer.HandlePacket(packet)
	if err != nil {
		return nil, err
	}
	replies := make([][]byte, p.count)
	for index := range replies {
		replies[index] = reply
	}
	return replies, nil
}

func TestClientPublishesCallerOwnedNetworkConfiguration(t *testing.T) {
	scenario := testopenconnect.BasicAnyConnectScenario()
	scenario.Configuration.Addresses = append(scenario.Configuration.Addresses, netip.MustParsePrefix("2001:db8::2/64"))
	scenario.Configuration.Routes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8:1::/64")}
	scenario.Configuration.ExcludedRoutes = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	scenario.Configuration.DNS = []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("2001:db8::53")}
	scenario.Configuration.SearchDomains = []string{"corp.example"}
	scenario.Configuration.SplitDNS = []string{"internal.example"}
	scenario.Configuration.Banner = scenario.Cookie
	scenario.Configuration.TunnelAllDNS = true
	events := make(chan NetworkConfigEvent, 4)
	client, gateway, cancel := newTLSScenarioClient(t, scenario, Config{
		Cookie: scenario.Cookie,
		OnNetworkConfig: func(event NetworkConfigEvent) error {
			events <- event
			return nil
		},
	})
	defer cancel()
	defer func() { _ = gateway.Close() }()
	defer func() { _ = client.Close() }()
	ctx, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWait()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	configuration, err := client.WaitReady(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var event NetworkConfigEvent
	select {
	case event = <-events:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if event.Reason != NetworkConfigInitial || configuration.ActiveTransport != "cstp" || event.Config.Banner != scenario.Configuration.Banner || !event.Config.TunnelAllDNS {
		t.Fatalf("unexpected network event: %#v", event)
	}
	revision, err := client.WaitDataPlaneReady(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if event.Revision == 0 || revision != event.Revision {
		t.Fatalf("data plane revision was not synchronized with the applied network event: ready=%d event=%d", revision, event.Revision)
	}
	var publicEvent Event
	for publicEvent.Type != EventNetworkConfig {
		select {
		case publicEvent = <-client.Events():
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if publicEvent.Type != EventNetworkConfig || publicEvent.NetworkConfig == nil || publicEvent.NetworkConfig.Banner == scenario.Cookie || publicEvent.NetworkConfig.Banner != "[redacted]" {
		t.Fatalf("public network event exposed a configured secret: %#v", publicEvent)
	}
	if len(configuration.Addresses) != 2 || len(configuration.Routes) != 2 || len(configuration.ExcludedRoutes) != 1 || len(configuration.DNS) != 2 || len(configuration.SearchDomains) != 1 || len(configuration.SplitDNS) != 1 {
		t.Fatalf("incomplete network configuration: %#v", configuration)
	}
	event.Config.Addresses[0] = netip.MustParsePrefix("203.0.113.2/24")
	event.Config.DNS[0] = netip.MustParseAddr("203.0.113.53")
	event.Config.SearchDomains[0] = "mutated.example"
	again, err := client.WaitReady(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.Addresses[0] != scenario.Configuration.Addresses[0] || again.DNS[0] != scenario.Configuration.DNS[0] || again.SearchDomains[0] != scenario.Configuration.SearchDomains[0] {
		t.Fatalf("network event aliased core state: %#v", again)
	}
	select {
	case duplicate := <-events:
		t.Fatalf("unchanged ready state emitted a duplicate configuration callback: %#v", duplicate)
	default:
	}
}

func TestClientDefaultStatelessCompressionIgnoresInvalidBoundedFrames(t *testing.T) {
	largePacket := make([]byte, 64*1024)
	compressed := make([]byte, lz4.CompressBlockBound(len(largePacket)))
	compressor := new(lz4.Compressor)
	compressedSize, err := compressor.CompressBlock(largePacket, compressed)
	if err != nil || compressedSize == 0 {
		t.Fatalf("create oversized compressed fixture: size=%d err=%v", compressedSize, err)
	}
	scenario := testopenconnect.BasicAnyConnectScenario()
	scenario.Compression = "oc-lz4"
	scenario.CSTP.CompressedPackets = [][]byte{{0xff, 0x00}, compressed[:compressedSize]}
	peerAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := testopenconnect.NewIPv4ICMPEchoPeer(peerAddress)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gateway, err := testopenconnect.StartAnyConnectGateway(ctx, scenario, peer, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	_, port, err := net.SplitHostPort(gateway.Address())
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ctx, Config{
		Server:               "https://" + gateway.ServerName() + ":" + port,
		Cookie:               scenario.Cookie,
		ServerName:           gateway.ServerName(),
		CertificateAuthority: testopenconnect.AnyConnectRootCAPEM(),
	}, new(recordingDialer), nil)
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
	request, err := testopenconnect.BuildIPv4ICMPEchoRequest(scenario.Configuration.Addresses[0].Addr(), peerAddress, 1, 1, nil)
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
	if len(reply) != len(request) || reply[20] != 0 {
		t.Fatalf("valid packet after invalid compressed frames was lost: %x", reply)
	}
}

func TestClientIPv6Packet(t *testing.T) {
	scenario := testopenconnect.BasicAnyConnectScenario()
	scenario.Configuration.Addresses = []netip.Prefix{netip.MustParsePrefix("2001:db8::2/64")}
	scenario.Configuration.DNS = []netip.Addr{netip.MustParseAddr("2001:db8::53")}
	peerAddress := netip.MustParseAddr("2001:db8::1")
	peer, err := testopenconnect.NewIPv6ICMPEchoPeer(peerAddress)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gateway, err := testopenconnect.StartAnyConnectGateway(ctx, scenario, peer, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	_, port, err := net.SplitHostPort(gateway.Address())
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ctx, Config{
		Server:               "https://" + gateway.ServerName() + ":" + port,
		Cookie:               scenario.Cookie,
		ServerName:           gateway.ServerName(),
		CertificateAuthority: testopenconnect.AnyConnectRootCAPEM(),
	}, new(recordingDialer), nil)
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
	request, err := testopenconnect.BuildIPv6ICMPEchoRequest(scenario.Configuration.Addresses[0].Addr(), peerAddress, 1, 1, []byte("ipv6"))
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
	if len(reply) != len(request) || reply[40] != 129 || string(reply[48:]) != "ipv6" {
		t.Fatalf("unexpected IPv6 echo reply: %x", reply)
	}
}

func TestClientCloseUnblocksBoundedPacketQueue(t *testing.T) {
	basePeer, err := testopenconnect.NewIPv4ICMPEchoPeer(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	peer := &burstPacketPeer{peer: basePeer, count: 2048}
	scenario := testopenconnect.BasicAnyConnectScenario()
	recorder := testopenconnect.NewRecorder(scenario.Cookie)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	gateway, err := testopenconnect.StartAnyConnectGateway(ctx, scenario, peer, recorder)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	_, port, err := net.SplitHostPort(gateway.Address())
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ctx, Config{
		Server:               "https://" + gateway.ServerName() + ":" + port,
		Cookie:               scenario.Cookie,
		ServerName:           gateway.ServerName(),
		CertificateAuthority: testopenconnect.AnyConnectRootCAPEM(),
		QueueLength:          1,
	}, new(recordingDialer), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	request, err := testopenconnect.BuildIPv4ICMPEchoRequest(scenario.Configuration.Addresses[0].Addr(), netip.MustParseAddr("192.0.2.1"), 1, 1, make([]byte, 1200))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WritePacket(request); err != nil {
		t.Fatal(err)
	}
	for {
		replies := 0
		for _, record := range recorder.Records() {
			if record.Kind == "cstp-data" {
				replies++
			}
		}
		if replies >= 2 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client close blocked behind a full packet queue")
	}
}
