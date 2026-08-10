//go:build with_gvisor

package anyconnect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/icmp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
)

const echoPeerNIC tcpip.NICID = 1

// IPv4TCPUDPEchoPeer terminates TCP and UDP flows in an independent gVisor
// stack and exposes its link as raw packets to the fake gateway.
type IPv4TCPUDPEchoPeer struct {
	stack    *stack.Stack
	endpoint *channel.Endpoint
	tcp      net.Listener
	udp      net.PacketConn
	cancel   context.CancelFunc
	wait     sync.WaitGroup
	access   sync.Mutex
}

func NewIPv4TCPUDPEchoPeer(parent context.Context, address netip.Addr, tcpPort uint16, udpPort uint16) (*IPv4TCPUDPEchoPeer, error) {
	if parent == nil {
		return nil, errors.New("echo peer context is required")
	}
	if !address.Is4() || address.IsUnspecified() {
		return nil, fmt.Errorf("echo peer requires a concrete IPv4 address: %s", address)
	}
	ipStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})
	endpoint := channel.New(256, 65535, "")
	if err := ipStack.CreateNIC(echoPeerNIC, endpoint); err != nil {
		ipStack.Close()
		return nil, fmt.Errorf("create echo peer NIC: %s", err)
	}
	stackAddress := tcpip.AddrFrom4(address.As4())
	if err := ipStack.AddProtocolAddress(echoPeerNIC, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   stackAddress,
			PrefixLen: 32,
		},
	}, stack.AddressProperties{}); err != nil {
		endpoint.Close()
		ipStack.Close()
		return nil, fmt.Errorf("add echo peer address: %s", err)
	}
	ipStack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: echoPeerNIC})
	tcpListener, err := gonet.ListenTCP(ipStack, tcpip.FullAddress{NIC: echoPeerNIC, Addr: stackAddress, Port: tcpPort}, ipv4.ProtocolNumber)
	if err != nil {
		endpoint.Close()
		ipStack.Close()
		return nil, fmt.Errorf("listen on echo peer TCP port: %w", err)
	}
	udpConnection, err := gonet.DialUDP(ipStack, &tcpip.FullAddress{NIC: echoPeerNIC, Addr: stackAddress, Port: udpPort}, nil, ipv4.ProtocolNumber)
	if err != nil {
		_ = tcpListener.Close()
		endpoint.Close()
		ipStack.Close()
		return nil, fmt.Errorf("listen on echo peer UDP port: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	peer := &IPv4TCPUDPEchoPeer{
		stack:    ipStack,
		endpoint: endpoint,
		tcp:      tcpListener,
		udp:      udpConnection,
		cancel:   cancel,
	}
	peer.wait.Add(2)
	go peer.serveTCP(ctx)
	go peer.serveUDP(ctx)
	return peer, nil
}

func (p *IPv4TCPUDPEchoPeer) serveTCP(ctx context.Context) {
	defer p.wait.Done()
	for ctx.Err() == nil {
		connection, err := p.tcp.Accept()
		if err != nil {
			return
		}
		p.wait.Add(1)
		go func() {
			defer p.wait.Done()
			defer connection.Close()
			_, _ = io.Copy(connection, connection)
		}()
	}
}

func (p *IPv4TCPUDPEchoPeer) serveUDP(ctx context.Context) {
	defer p.wait.Done()
	buffer := make([]byte, 65535)
	for ctx.Err() == nil {
		count, source, err := p.udp.ReadFrom(buffer)
		if err != nil {
			return
		}
		if _, err := p.udp.WriteTo(buffer[:count], source); err != nil {
			return
		}
	}
}

func (p *IPv4TCPUDPEchoPeer) HandlePacket(packet []byte) ([]byte, error) {
	replies, err := p.HandlePackets(packet)
	if err != nil || len(replies) == 0 {
		return nil, err
	}
	return replies[0], nil
}

func (p *IPv4TCPUDPEchoPeer) HandlePackets(packet []byte) ([][]byte, error) {
	if p == nil || p.endpoint == nil {
		return nil, errors.New("TCP/UDP echo peer is closed")
	}
	if len(packet) < header.IPv4MinimumSize || header.IPVersion(packet) != header.IPv4Version {
		return nil, errors.New("echo peer received a non-IPv4 packet")
	}
	p.access.Lock()
	defer p.access.Unlock()
	packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	p.endpoint.InjectInbound(ipv4.ProtocolNumber, packetBuffer)
	packetBuffer.DecRef()
	readContext, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	first := p.endpoint.ReadContext(readContext)
	if first == nil {
		return nil, nil
	}
	replies := [][]byte{packetBytes(first)}
	first.DecRef()
	quiet := time.NewTimer(2 * time.Millisecond)
	defer quiet.Stop()
	for {
		select {
		case <-quiet.C:
			return replies, nil
		default:
		}
		next := p.endpoint.Read()
		if next == nil {
			time.Sleep(100 * time.Microsecond)
			continue
		}
		replies = append(replies, packetBytes(next))
		next.DecRef()
	}
}

func packetBytes(packet *stack.PacketBuffer) []byte {
	var result []byte
	for _, content := range packet.AsSlices() {
		result = append(result, content...)
	}
	return result
}

func (p *IPv4TCPUDPEchoPeer) Close() error {
	if p == nil {
		return nil
	}
	p.cancel()
	tcpErr := p.tcp.Close()
	udpErr := p.udp.Close()
	p.endpoint.Close()
	p.stack.Close()
	for _, endpoint := range p.stack.CleanupEndpoints() {
		endpoint.Abort()
	}
	p.stack.Wait()
	p.wait.Wait()
	return errors.Join(tcpErr, udpErr)
}
