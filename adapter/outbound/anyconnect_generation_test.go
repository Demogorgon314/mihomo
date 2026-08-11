//go:build with_gvisor

package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	ac "github.com/metacubex/mihomo/transport/anyconnect"

	wireguard "github.com/metacubex/sing-wireguard"
	M "github.com/metacubex/sing/common/metadata"
)

type generationTestClient struct{}

func (generationTestClient) WaitReady(context.Context) (ac.NetworkConfig, error) {
	return ac.NetworkConfig{}, nil
}

func (generationTestClient) WaitDataPlaneReady(context.Context) (uint64, error) { return 0, nil }

func (generationTestClient) ReadPacketWithRevision(ctx context.Context) ([]byte, uint64, error) {
	<-ctx.Done()
	return nil, 0, ctx.Err()
}

func (generationTestClient) WritePacketAtRevision([]byte, uint64) error { return nil }
func (generationTestClient) WritePacketsAtRevision([][]byte, uint64) error {
	return nil
}
func (generationTestClient) WritePacket([]byte) error { return nil }
func (generationTestClient) ActiveTransport() string  { return "cstp" }
func (generationTestClient) Close() error             { return nil }

type packetSequenceTestClient struct {
	packets  chan []byte
	err      error
	revision atomic.Uint64
}

func (c *packetSequenceTestClient) WaitReady(context.Context) (ac.NetworkConfig, error) {
	return ac.NetworkConfig{}, nil
}

func (*packetSequenceTestClient) WaitDataPlaneReady(context.Context) (uint64, error) {
	return 0, nil
}

func (c *packetSequenceTestClient) ReadPacketWithRevision(ctx context.Context) ([]byte, uint64, error) {
	select {
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	case packet := <-c.packets:
		if packet == nil {
			return nil, 0, c.err
		}
		return packet, c.revision.Load(), nil
	}
}

type blockingGenerationTestDevice struct {
	wireguard.Device
	writeStarted chan struct{}
	releaseWrite chan struct{}
	closed       chan struct{}
	closedFlag   atomic.Bool
	closeOnce    sync.Once
}

type outboundBatchTestDevice struct {
	wireguard.Device
	packets   chan []byte
	closeOnce sync.Once
}

func (d *outboundBatchTestDevice) Read(buffers [][]byte, sizes []int, _ int) (int, error) {
	packet, loaded := <-d.packets
	if !loaded {
		return 0, os.ErrClosed
	}
	sizes[0] = copy(buffers[0], packet)
	return 1, nil
}

func (d *outboundBatchTestDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.packets)
	})
	return nil
}

type outboundBatchTestClient struct {
	batches chan []byte
}

func (*outboundBatchTestClient) WaitReady(context.Context) (ac.NetworkConfig, error) {
	return ac.NetworkConfig{}, nil
}

func (*outboundBatchTestClient) WaitDataPlaneReady(context.Context) (uint64, error) {
	return 1, nil
}

func (*outboundBatchTestClient) ReadPacketWithRevision(ctx context.Context) ([]byte, uint64, error) {
	<-ctx.Done()
	return nil, 0, ctx.Err()
}

func (*outboundBatchTestClient) WritePacket([]byte) error { return nil }
func (*outboundBatchTestClient) WritePacketAtRevision([]byte, uint64) error {
	return nil
}

func (c *outboundBatchTestClient) WritePacketsAtRevision(packets [][]byte, _ uint64) error {
	values := make([]byte, len(packets))
	for index, packet := range packets {
		values[index] = packet[0]
	}
	c.batches <- values
	return nil
}

func (*outboundBatchTestClient) ActiveTransport() string { return "dtls" }
func (*outboundBatchTestClient) Close() error            { return nil }

func TestAnyConnectStackPacketsBatchWithoutTimer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	device := &outboundBatchTestDevice{packets: make(chan []byte, 3)}
	client := &outboundBatchTestClient{batches: make(chan []byte, 1)}
	generation := &anyConnectGeneration{
		device:          device,
		revision:        1,
		outboundPackets: make(chan []byte, anyConnectOutboundPacketBatchSize),
	}
	generation.packetPool.New = func() any {
		return make([]byte, 1400)
	}
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	session := &anyConnectSession{
		client:      client,
		ctx:         sessionCtx,
		cancel:      sessionCancel,
		generation:  generation,
		name:        "batch-test",
		initialDone: make(chan struct{}),
	}
	session.wait.Add(2)
	go session.readStackPackets(generation)

	device.packets <- []byte{1}
	device.packets <- []byte{2}
	device.packets <- []byte{3}
	for len(generation.outboundPackets) < 3 {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		default:
			runtime.Gosched()
		}
	}
	go session.writeStackPackets(generation)
	select {
	case values := <-client.batches:
		if !slices.Equal(values, []byte{1, 2, 3}) {
			t.Fatalf("unexpected batch: %v", values)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	session.access.Lock()
	session.generation = nil
	session.access.Unlock()
	if err := generation.close(); err != nil {
		t.Fatal(err)
	}
	sessionCancel()
	session.wait.Wait()
}

func (d *blockingGenerationTestDevice) Write([][]byte, int) (int, error) {
	d.writeStarted <- struct{}{}
	select {
	case <-d.releaseWrite:
		if d.closedFlag.Load() {
			return 0, net.ErrClosed
		}
		return 1, nil
	case <-d.closed:
		return 0, net.ErrClosed
	}
}

func (d *blockingGenerationTestDevice) Close() error {
	d.closeOnce.Do(func() {
		d.closedFlag.Store(true)
		close(d.closed)
	})
	return nil
}

func TestAnyConnectGenerationReplacementClosesBlockedWriter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := &packetSequenceTestClient{packets: make(chan []byte, 1), err: net.ErrClosed}
	client.revision.Store(1)
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	session := &anyConnectSession{
		client:          client,
		ctx:             sessionCtx,
		cancel:          sessionCancel,
		name:            "blocked-generation-test",
		resolverFactory: func(ac.NetworkConfig) (resolver.Resolver, error) { return nil, nil },
		initialDone:     make(chan struct{}),
		done:            make(chan struct{}),
	}
	configuration := ac.NetworkConfig{Addresses: []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")}, MTU: 1400}
	device := &blockingGenerationTestDevice{
		writeStarted: make(chan struct{}, 1),
		releaseWrite: make(chan struct{}, 1),
		closed:       make(chan struct{}),
	}
	session.generation = &anyConnectGeneration{device: device, revision: 1, configuration: configuration}
	session.configuration = configuration
	session.signalInitial(nil)
	session.wait.Add(1)
	go session.runTunnelToStack()
	go func() {
		session.wait.Wait()
		close(session.done)
	}()
	t.Cleanup(func() { _ = session.close() })

	packet := make([]byte, 20)
	packet[0] = 0x45
	client.packets <- packet
	select {
	case <-device.writeStarted:
	case <-ctx.Done():
		t.Fatalf("stack writer did not block in the fake device: %v", ctx.Err())
	}

	metadataUpdate := configuration
	metadataUpdate.DNS = []netip.Addr{netip.MustParseAddr("192.0.2.53")}
	metadataUpdated := make(chan error, 1)
	go func() {
		metadataUpdated <- session.applyNetworkConfig(ac.NetworkConfigEvent{Reason: ac.NetworkConfigReestablishment, Revision: 2, Config: metadataUpdate})
	}()
	updateDeadline := time.NewTimer(time.Second)
	defer updateDeadline.Stop()
	for session.generation.dataPlaneAccess.TryRLock() {
		session.generation.dataPlaneAccess.RUnlock()
		select {
		case <-updateDeadline.C:
			t.Fatal("metadata revision update did not queue behind the active device write")
		default:
			runtime.Gosched()
		}
	}
	select {
	case err := <-metadataUpdated:
		t.Fatalf("metadata revision update crossed the blocked device write: %v", err)
	default:
	}
	device.releaseWrite <- struct{}{}
	select {
	case err := <-metadataUpdated:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatalf("metadata revision update did not complete after the device write: %v", ctx.Err())
	}
	session.access.RLock()
	metadataRevision := session.generation.revision
	session.access.RUnlock()
	if metadataRevision != 2 {
		t.Fatalf("metadata-only update did not publish revision 2: %d", metadataRevision)
	}

	client.revision.Store(2)
	client.packets <- packet
	select {
	case <-device.writeStarted:
	case <-ctx.Done():
		t.Fatalf("second stack writer did not block in the fake device: %v", ctx.Err())
	}
	replacement := ac.NetworkConfig{Addresses: []netip.Prefix{netip.MustParsePrefix("198.51.100.2/24")}, MTU: 1400}
	replaced := make(chan error, 1)
	go func() {
		replaced <- session.applyNetworkConfig(ac.NetworkConfigEvent{Reason: ac.NetworkConfigRekey, Revision: 3, Config: replacement})
	}()
	select {
	case err := <-replaced:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatalf("configuration replacement did not close the blocked generation: %v", ctx.Err())
	}
}

func (*packetSequenceTestClient) WritePacketAtRevision([]byte, uint64) error { return nil }
func (*packetSequenceTestClient) WritePacketsAtRevision([][]byte, uint64) error {
	return nil
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
	if err := session.applyNetworkConfig(ac.NetworkConfigEvent{Reason: ac.NetworkConfigInitial, Revision: 1, Config: initial}); err != nil {
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
	if err := session.applyNetworkConfig(ac.NetworkConfigEvent{Reason: ac.NetworkConfigReestablishment, Revision: 2, Config: metadataOnly}); err != nil {
		t.Fatal(err)
	}
	unchanged, _, err := session.currentDevice()
	if err != nil {
		t.Fatal(err)
	}
	if unchanged != first {
		t.Fatal("metadata-only update replaced the stack generation")
	}
	session.access.RLock()
	unchangedRevision := session.generation.revision
	session.access.RUnlock()
	if unchangedRevision != 2 {
		t.Fatalf("metadata-only update did not advance stack revision: %d", unchangedRevision)
	}

	replaced := metadataOnly
	replaced.Addresses = []netip.Prefix{netip.MustParsePrefix("198.51.100.2/24")}
	if err := session.applyNetworkConfig(ac.NetworkConfigEvent{Reason: ac.NetworkConfigRekey, Revision: 3, Config: replaced}); err != nil {
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
