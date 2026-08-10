//go:build with_gvisor

package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	ac "github.com/metacubex/mihomo/transport/anyconnect"

	M "github.com/metacubex/sing/common/metadata"
)

type generationTestClient struct{}

func (generationTestClient) WaitReady(context.Context) (ac.NetworkConfig, error) {
	return ac.NetworkConfig{}, nil
}

func (generationTestClient) ReadPacket(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (generationTestClient) WritePacket([]byte) error { return nil }
func (generationTestClient) ActiveTransport() string  { return "cstp" }
func (generationTestClient) Close() error             { return nil }

type packetSequenceTestClient struct {
	packets chan []byte
	err     error
}

func (c *packetSequenceTestClient) WaitReady(context.Context) (ac.NetworkConfig, error) {
	return ac.NetworkConfig{}, nil
}

func (c *packetSequenceTestClient) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case packet := <-c.packets:
		if packet == nil {
			return nil, c.err
		}
		return packet, nil
	}
}

func (*packetSequenceTestClient) WritePacket([]byte) error { return nil }
func (*packetSequenceTestClient) ActiveTransport() string  { return "dtls" }
func (*packetSequenceTestClient) Close() error             { return nil }

func TestAnyConnectNetworkGenerationReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	session := &anyConnectSession{
		client:          generationTestClient{},
		ctx:             sessionCtx,
		cancel:          sessionCancel,
		name:            "generation-test",
		resolverFactory: func(ac.NetworkConfig) (resolver.Resolver, error) { return nil, nil },
		initialDone:     make(chan struct{}),
		done:            make(chan struct{}),
	}
	session.wait.Add(1)
	go session.runTunnelToStack()
	go func() {
		session.wait.Wait()
		close(session.done)
	}()
	t.Cleanup(func() { _ = session.close() })

	initial := ac.NetworkConfig{Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24"), netip.MustParsePrefix("198.51.100.2/24")}, DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")}, MTU: 1400}
	if err := session.applyNetworkConfig(ac.NetworkConfigEvent{Reason: ac.NetworkConfigInitial, Config: initial}); err != nil {
		t.Fatal(err)
	}
	first, _, err := session.currentDevice()
	if err != nil {
		t.Fatal(err)
	}
	flow, err := first.ListenPacket(ctx, M.SocksaddrFrom(netip.MustParseAddr("192.0.2.1"), 53).Unwrap())
	if err != nil {
		t.Fatal(err)
	}

	metadataOnly := initial
	metadataOnly.Addresses = []netip.Prefix{initial.Addresses[1], initial.Addresses[0]}
	metadataOnly.DNS = []netip.Addr{netip.MustParseAddr("192.0.2.54")}
	if err := session.applyNetworkConfig(ac.NetworkConfigEvent{Reason: ac.NetworkConfigReestablishment, Config: metadataOnly}); err != nil {
		t.Fatal(err)
	}
	unchanged, _, err := session.currentDevice()
	if err != nil {
		t.Fatal(err)
	}
	if unchanged != first {
		t.Fatal("metadata-only update replaced the stack generation")
	}

	replaced := metadataOnly
	replaced.Addresses = []netip.Prefix{netip.MustParsePrefix("198.51.100.2/24")}
	if err := session.applyNetworkConfig(ac.NetworkConfigEvent{Reason: ac.NetworkConfigRekey, Config: replaced}); err != nil {
		t.Fatal(err)
	}
	second, _, err := session.currentDevice()
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("address change did not replace the stack generation")
	}
	if _, err := flow.WriteTo([]byte("old-flow"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53}); err == nil {
		t.Fatal("flow from the replaced stack generation remained usable")
	}
	_ = flow.Close()
}

func TestAnyConnectIgnoresUnconfiguredAddressFamily(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	readErr := errors.New("packet sequence complete")
	client := &packetSequenceTestClient{packets: make(chan []byte, 2), err: readErr}
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	session := &anyConnectSession{
		client:          client,
		ctx:             sessionCtx,
		cancel:          sessionCancel,
		name:            "address-family-test",
		resolverFactory: func(ac.NetworkConfig) (resolver.Resolver, error) { return nil, nil },
		initialDone:     make(chan struct{}),
		done:            make(chan struct{}),
	}
	session.wait.Add(1)
	go session.runTunnelToStack()
	go func() {
		session.wait.Wait()
		close(session.done)
	}()
	t.Cleanup(func() { _ = session.close() })

	configuration := ac.NetworkConfig{Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")}, MTU: 1400}
	if err := session.applyNetworkConfig(ac.NetworkConfigEvent{Reason: ac.NetworkConfigInitial, Config: configuration}); err != nil {
		t.Fatal(err)
	}
	unexpectedIPv6 := make([]byte, 40)
	unexpectedIPv6[0] = 0x60
	client.packets <- unexpectedIPv6
	client.packets <- nil

	select {
	case <-session.done:
	case <-ctx.Done():
		t.Fatalf("session did not finish packet sequence: %v", ctx.Err())
	}
	if err := session.err(); !errors.Is(err, readErr) {
		t.Fatalf("unconfigured address family stopped the tunnel: %v", err)
	}
}

func TestAnyConnectNetworkConfigRejectsInvalidMTUAndAddress(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		config ac.NetworkConfig
	}{
		{name: "missing address", config: ac.NetworkConfig{MTU: 1400}},
		{name: "IPv4 MTU below minimum", config: ac.NetworkConfig{Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")}, MTU: 575}},
		{name: "IPv6 MTU below minimum", config: ac.NetworkConfig{Addresses: []netip.Prefix{netip.MustParsePrefix("2001:db8::2/64")}, MTU: 1279}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := validateAnyConnectNetworkConfig(testCase.config)
			if err == nil || errors.Is(err, net.ErrClosed) {
				t.Fatalf("expected a network configuration error, got %v", err)
			}
		})
	}
	v4 := ac.NetworkConfig{Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")}, MTU: 1400}
	validIPv4 := make([]byte, 20)
	validIPv4[0] = 0x45
	validIPv6 := make([]byte, 40)
	validIPv6[0] = 0x60
	oversizedIPv4 := make([]byte, 1401)
	oversizedIPv4[0] = 0x45
	if packetMatchesGeneration(nil, v4) || packetMatchesGeneration([]byte{0x45}, v4) || packetMatchesGeneration(validIPv6, v4) || packetMatchesGeneration(oversizedIPv4, v4) || !packetMatchesGeneration(validIPv4, v4) {
		t.Fatal("packet boundary validation accepted an invalid packet or rejected IPv4")
	}
	v6 := ac.NetworkConfig{Addresses: []netip.Prefix{netip.MustParsePrefix("2001:db8::2/64")}, MTU: 1400}
	if !packetMatchesGeneration(validIPv6, v6) || packetMatchesGeneration(validIPv4, v6) {
		t.Fatal("packet address-family validation rejected IPv6 or accepted IPv4")
	}
}

func FuzzAnyConnectPacketBoundary(f *testing.F) {
	validIPv4 := make([]byte, 20)
	validIPv4[0] = 0x45
	validIPv6 := make([]byte, 40)
	validIPv6[0] = 0x60
	f.Add(validIPv4, uint16(1400), false)
	f.Add(validIPv6, uint16(1400), true)
	f.Add([]byte{0x45}, uint16(576), false)
	f.Fuzz(func(t *testing.T, packet []byte, mtuValue uint16, ipv6 bool) {
		mtu := uint32(mtuValue)
		address := netip.MustParsePrefix("192.0.2.2/24")
		minimumMTU := uint32(576)
		expectedVersion := byte(4)
		minimumPacketSize := 20
		if ipv6 {
			address = netip.MustParsePrefix("2001:db8::2/64")
			minimumMTU = 1280
			expectedVersion = 6
			minimumPacketSize = 40
		}
		if mtu < minimumMTU {
			mtu = minimumMTU
		}
		configuration := ac.NetworkConfig{Addresses: []netip.Prefix{address}, MTU: mtu}
		got := packetMatchesGeneration(packet, configuration)
		want := len(packet) >= minimumPacketSize && uint32(len(packet)) <= mtu && packet[0]>>4 == expectedVersion
		if got != want {
			t.Fatalf("packet boundary mismatch: got %v, want %v (length=%d mtu=%d IPv6=%v)", got, want, len(packet), mtu, ipv6)
		}
	})
}
