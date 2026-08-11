package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	ac "github.com/metacubex/mihomo/transport/anyconnect"

	wireguard "github.com/metacubex/sing-wireguard"
)

const anyConnectOutboundPacketBatchSize = 64

type anyConnectGeneration struct {
	device          wireguard.Device
	resolver        resolver.Resolver
	revision        uint64
	configuration   ac.NetworkConfig
	outboundPackets chan []byte
	packetPool      sync.Pool
	dataPlaneAccess sync.RWMutex
	closed          atomic.Bool
}

func (g *anyConnectGeneration) writePacket(packet []byte, expectedRevision uint64) (bool, error) {
	g.dataPlaneAccess.RLock()
	defer g.dataPlaneAccess.RUnlock()
	if g.closed.Load() || g.revision != expectedRevision {
		return false, nil
	}
	_, err := g.device.Write([][]byte{packet}, 0)
	return true, err
}

func (g *anyConnectGeneration) close() error {
	var err error
	if g.closed.CompareAndSwap(false, true) {
		err = g.device.Close()
	}
	// Close the device before waiting so a blocked Write can return and release
	// the read side of the data-plane gate.
	g.dataPlaneAccess.Lock()
	g.dataPlaneAccess.Unlock()
	return err
}

type anyConnectSession struct {
	client acClient
	ctx    context.Context
	cancel context.CancelFunc
	name   string

	resolverFactory func(configuration ac.NetworkConfig) (resolver.Resolver, error)

	access        sync.RWMutex
	generation    *anyConnectGeneration
	configuration ac.NetworkConfig
	stopped       bool

	initialOnce sync.Once
	initialDone chan struct{}
	initialErr  error

	stopOnce sync.Once
	wait     sync.WaitGroup
	done     chan struct{}
	errLock  sync.Mutex
	stopErr  error
}

type acClient interface {
	WaitReady(ctx context.Context) (ac.NetworkConfig, error)
	WaitDataPlaneReady(ctx context.Context) (uint64, error)
	ReadPacketWithRevision(ctx context.Context) ([]byte, uint64, error)
	WritePacket(packet []byte) error
	WritePacketAtRevision(packet []byte, revision uint64) error
	WritePacketsAtRevision(packets [][]byte, revision uint64) error
	ActiveTransport() string
	Close() error
}

func newAnyConnectSession(
	runCtx context.Context,
	handshakeCtx context.Context,
	config ac.Config,
	dialer C.Dialer,
	authProvider ac.AuthProvider,
	resolverFactory func(configuration ac.NetworkConfig) (resolver.Resolver, error),
	name string,
) (*anyConnectSession, error) {
	sessionCtx, cancel := context.WithCancel(runCtx)
	session := &anyConnectSession{
		ctx:             sessionCtx,
		cancel:          cancel,
		name:            name,
		resolverFactory: resolverFactory,
		initialDone:     make(chan struct{}),
		done:            make(chan struct{}),
	}
	config.OnNetworkConfig = session.applyNetworkConfig
	client, err := ac.NewClient(runCtx, config, dialer, authProvider)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create AnyConnect client: %w", err)
	}
	session.client = client
	session.wait.Add(1)
	go session.runTunnelToStack()
	go func() {
		session.wait.Wait()
		close(session.done)
	}()
	if err := client.Start(); err != nil {
		_ = session.close()
		return nil, fmt.Errorf("start AnyConnect client: %w", err)
	}
	if _, err := client.WaitReady(handshakeCtx); err != nil {
		_ = session.close()
		return nil, fmt.Errorf("connect AnyConnect server: %w", err)
	}
	select {
	case <-handshakeCtx.Done():
		_ = session.close()
		return nil, handshakeCtx.Err()
	case <-session.initialDone:
	}
	if session.initialErr != nil {
		_ = session.close()
		return nil, session.initialErr
	}
	configuration := session.configurationSnapshot()
	log.Debugln("[AnyConnect](%s) tunnel ready: addresses=%v mtu=%d transport=%s", name, configuration.Addresses, configuration.MTU, configuration.ActiveTransport)
	return session, nil
}

func (s *anyConnectSession) applyNetworkConfig(event ac.NetworkConfigEvent) error {
	configuration, err := validateAnyConnectNetworkConfig(event.Config)
	if err != nil {
		s.signalInitial(err)
		return err
	}
	remoteResolver, err := s.resolverFactory(configuration)
	if err != nil {
		s.signalInitial(err)
		return err
	}

	s.access.RLock()
	current := s.generation
	var currentConfiguration ac.NetworkConfig
	if current != nil {
		currentConfiguration = current.configuration
	}
	stopped := s.stopped || s.ctx.Err() != nil
	s.access.RUnlock()
	if stopped {
		return net.ErrClosed
	}
	if current != nil && sameAnyConnectNetworkIdentity(currentConfiguration, configuration) {
		current.dataPlaneAccess.Lock()
		s.access.Lock()
		if s.generation == current && !s.stopped && !current.closed.Load() {
			current.revision = event.Revision
			current.configuration = configuration
			current.resolver = remoteResolver
			s.configuration = configuration
		}
		s.access.Unlock()
		current.dataPlaneAccess.Unlock()
		s.signalInitial(nil)
		return nil
	}

	device, err := wireguard.NewStackDevice(configuration.Addresses, configuration.MTU)
	if err != nil {
		err = fmt.Errorf("create AnyConnect stack device: %w", err)
		s.signalInitial(err)
		return err
	}
	if err := device.Start(); err != nil {
		_ = device.Close()
		err = fmt.Errorf("start AnyConnect stack device: %w", err)
		s.signalInitial(err)
		return err
	}
	generation := &anyConnectGeneration{
		device:          device,
		resolver:        remoteResolver,
		revision:        event.Revision,
		configuration:   configuration,
		outboundPackets: make(chan []byte, anyConnectOutboundPacketBatchSize),
	}
	packetSize := int(configuration.MTU)
	generation.packetPool.New = func() any {
		return make([]byte, packetSize)
	}

	s.access.Lock()
	if s.stopped || s.ctx.Err() != nil {
		s.access.Unlock()
		_ = device.Close()
		return net.ErrClosed
	}
	previous := s.generation
	s.generation = generation
	s.configuration = configuration
	s.wait.Add(2)
	s.access.Unlock()
	go s.readStackPackets(generation)
	go s.writeStackPackets(generation)
	if previous != nil {
		_ = previous.close()
	}
	s.signalInitial(nil)
	log.Debugln("[AnyConnect](%s) applied %s network configuration: addresses=%v mtu=%d", s.name, event.Reason, configuration.Addresses, configuration.MTU)
	return nil
}

func validateAnyConnectNetworkConfig(configuration ac.NetworkConfig) (ac.NetworkConfig, error) {
	if len(configuration.Addresses) == 0 {
		return ac.NetworkConfig{}, errors.New("AnyConnect server did not assign a tunnel address")
	}
	if configuration.MTU == 0 {
		configuration.MTU = 1400
	}
	minimumMTU := uint32(576)
	for _, prefix := range configuration.Addresses {
		if !prefix.IsValid() || prefix.Addr().IsUnspecified() {
			return ac.NetworkConfig{}, fmt.Errorf("AnyConnect server assigned an invalid tunnel address: %s", prefix)
		}
		if prefix.Addr().Is6() {
			minimumMTU = 1280
		}
	}
	if configuration.MTU < minimumMTU || configuration.MTU > 65535 {
		return ac.NetworkConfig{}, fmt.Errorf("AnyConnect server assigned MTU %d outside %d..65535", configuration.MTU, minimumMTU)
	}
	return configuration, nil
}

func sameAnyConnectNetworkIdentity(left ac.NetworkConfig, right ac.NetworkConfig) bool {
	if left.MTU != right.MTU || len(left.Addresses) != len(right.Addresses) {
		return false
	}
	leftAddresses := append([]netip.Prefix(nil), left.Addresses...)
	rightAddresses := append([]netip.Prefix(nil), right.Addresses...)
	comparePrefix := func(left netip.Prefix, right netip.Prefix) int {
		if comparison := left.Addr().Compare(right.Addr()); comparison != 0 {
			return comparison
		}
		return left.Bits() - right.Bits()
	}
	slices.SortFunc(leftAddresses, comparePrefix)
	slices.SortFunc(rightAddresses, comparePrefix)
	return slices.Equal(leftAddresses, rightAddresses)
}

func (s *anyConnectSession) signalInitial(err error) {
	s.initialOnce.Do(func() {
		s.initialErr = err
		close(s.initialDone)
	})
}

func (s *anyConnectSession) currentDevice() (wireguard.Device, resolver.Resolver, error) {
	s.access.RLock()
	defer s.access.RUnlock()
	if s.stopped || s.generation == nil {
		return nil, nil, net.ErrClosed
	}
	return s.generation.device, s.generation.resolver, nil
}

func (s *anyConnectSession) configurationSnapshot() ac.NetworkConfig {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.configuration
}

func (s *anyConnectSession) readStackPackets(generation *anyConnectGeneration) {
	defer s.wait.Done()
	defer close(generation.outboundPackets)
	var packet []byte
	defer func() {
		if packet != nil {
			generation.packetPool.Put(packet)
		}
	}()
	buffers := make([][]byte, 1)
	sizes := []int{0}
	for s.ctx.Err() == nil {
		packet = generation.packetPool.Get().([]byte)
		buffers[0] = packet
		sizes[0] = 0
		_, err := generation.device.Read(buffers, sizes, 0)
		if err != nil {
			if !s.isCurrent(generation) {
				return
			}
			if s.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
				log.Warnln("[AnyConnect](%s) stack read failed: %v", s.name, err)
			}
			s.stop(err)
			return
		}
		if sizes[0] == 0 {
			generation.packetPool.Put(packet)
			packet = nil
			continue
		}
		packet = packet[:sizes[0]]
		select {
		case generation.outboundPackets <- packet:
			packet = nil
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *anyConnectSession) writeStackPackets(generation *anyConnectGeneration) {
	defer s.wait.Done()
	defer func() {
		for packet := range generation.outboundPackets {
			packet = packet[:cap(packet)]
			generation.packetPool.Put(packet)
		}
	}()
	for {
		packet, loaded := <-generation.outboundPackets
		if !loaded {
			return
		}
		packets := [][]byte{packet}
		for len(packets) < cap(generation.outboundPackets) {
			select {
			case packet, loaded = <-generation.outboundPackets:
				if loaded {
					packets = append(packets, packet)
					continue
				}
			default:
			}
			break
		}
		current, err := s.writePackets(generation, packets)
		for _, packet = range packets {
			packet = packet[:cap(packet)]
			generation.packetPool.Put(packet)
		}
		if !current {
			return
		}
		if err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				log.Warnln("[AnyConnect](%s) tunnel write failed: %v", s.name, err)
			}
			s.stop(err)
			return
		}
	}
}

func (s *anyConnectSession) writePackets(generation *anyConnectGeneration, packets [][]byte) (bool, error) {
	for {
		revision, err := s.client.WaitDataPlaneReady(s.ctx)
		if err != nil {
			return true, err
		}
		s.access.RLock()
		if s.generation != generation || s.stopped {
			s.access.RUnlock()
			return false, nil
		}
		if generation.revision != revision {
			s.access.RUnlock()
			continue
		}
		s.access.RUnlock()
		err = s.client.WritePacketsAtRevision(packets, revision)
		if !errors.Is(err, ac.ErrDataChannelNotReady) {
			return true, err
		}
	}
}

func (s *anyConnectSession) runTunnelToStack() {
	defer s.wait.Done()
	select {
	case <-s.ctx.Done():
		return
	case <-s.initialDone:
		if s.initialErr != nil {
			return
		}
	}
	for s.ctx.Err() == nil {
		packet, revision, err := s.client.ReadPacketWithRevision(s.ctx)
		if err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				log.Warnln("[AnyConnect](%s) tunnel read failed: %v", s.name, err)
			}
			s.stop(err)
			return
		}
		s.access.RLock()
		generation := s.generation
		if generation == nil {
			s.access.RUnlock()
			s.stop(net.ErrClosed)
			return
		}
		if generation.revision != revision {
			s.access.RUnlock()
			continue
		}
		configuration := generation.configuration
		s.access.RUnlock()
		if !validAnyConnectPacket(packet, configuration.MTU) {
			s.stop(errors.New("AnyConnect server sent an invalid network packet"))
			return
		}
		if !packetMatchesGeneration(packet, configuration) {
			continue
		}
		started, err := generation.writePacket(packet, revision)
		if !started {
			continue
		}
		if err != nil {
			s.access.RLock()
			current := s.generation == generation && generation.revision == revision
			s.access.RUnlock()
			if !current {
				continue
			}
			if s.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
				log.Warnln("[AnyConnect](%s) stack write failed: %v", s.name, err)
			}
			s.stop(err)
			return
		}
	}
}

func packetMatchesGeneration(packet []byte, configuration ac.NetworkConfig) bool {
	if !validAnyConnectPacket(packet, configuration.MTU) {
		return false
	}
	version := packet[0] >> 4
	for _, prefix := range configuration.Addresses {
		if version == 4 && prefix.Addr().Is4() || version == 6 && prefix.Addr().Is6() {
			return true
		}
	}
	return false
}

func validAnyConnectPacket(packet []byte, mtu uint32) bool {
	if len(packet) == 0 || uint32(len(packet)) > mtu {
		return false
	}
	switch packet[0] >> 4 {
	case 4:
		return len(packet) >= 20
	case 6:
		return len(packet) >= 40
	default:
		return false
	}
}

func (s *anyConnectSession) isCurrent(generation *anyConnectGeneration) bool {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.generation == generation
}

func (s *anyConnectSession) stop(err error) {
	s.stopOnce.Do(func() {
		if err == nil {
			err = net.ErrClosed
		}
		s.errLock.Lock()
		s.stopErr = err
		s.errLock.Unlock()
		s.cancel()
		_ = s.client.Close()
		s.access.Lock()
		s.stopped = true
		generation := s.generation
		s.generation = nil
		s.access.Unlock()
		if generation != nil {
			_ = generation.close()
		}
		s.signalInitial(err)
	})
}

func (s *anyConnectSession) err() error {
	s.errLock.Lock()
	defer s.errLock.Unlock()
	if s.stopErr == nil {
		return net.ErrClosed
	}
	return s.stopErr
}

func (s *anyConnectSession) close() error {
	s.stop(net.ErrClosed)
	<-s.done
	return nil
}
