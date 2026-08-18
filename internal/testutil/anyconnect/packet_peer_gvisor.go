//go:build with_gvisor

package anyconnect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/icmp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	D "github.com/miekg/dns"
)

const echoPeerNIC tcpip.NICID = 1

const (
	echoPeerResponseTimeout = 2 * time.Second
	echoPeerQuietTimeout    = 2 * time.Millisecond
)

// TCPUDPEchoPeer terminates TCP and UDP flows in an independent gVisor
// stack and exposes its link as raw packets to the fake gateway.
type TCPUDPEchoPeer struct {
	stack    *stack.Stack
	endpoint *channel.Endpoint
	tcp      net.Listener
	udp      net.PacketConn
	dns      net.PacketConn
	dnsNames map[string]netip.Addr
	dnsCount atomic.Int64
	cancel   context.CancelFunc
	wait     sync.WaitGroup
	access   sync.Mutex
	protocol tcpip.NetworkProtocolNumber
	version  int
}

func NewIPv4TCPUDPEchoPeer(parent context.Context, address netip.Addr, tcpPort uint16, udpPort uint16) (*TCPUDPEchoPeer, error) {
	if !address.Is4() {
		return nil, fmt.Errorf("IPv4 echo peer requires an IPv4 address: %s", address)
	}
	return newTCPUDPEchoPeer(parent, address, tcpPort, udpPort, 0, nil)
}

// NewIPv6TCPUDPEchoPeer terminates TCP and UDP flows at an IPv6 address.
func NewIPv6TCPUDPEchoPeer(parent context.Context, address netip.Addr, tcpPort uint16, udpPort uint16) (*TCPUDPEchoPeer, error) {
	if !address.Is6() {
		return nil, fmt.Errorf("IPv6 echo peer requires an IPv6 address: %s", address)
	}
	return newTCPUDPEchoPeer(parent, address, tcpPort, udpPort, 0, nil)
}

// NewIPv4TCPUDPEchoPeerWithDNS also serves deterministic A/AAAA responses on dnsPort.
func NewIPv4TCPUDPEchoPeerWithDNS(parent context.Context, address netip.Addr, tcpPort uint16, udpPort uint16, dnsPort uint16, names map[string]netip.Addr) (*TCPUDPEchoPeer, error) {
	if !address.Is4() {
		return nil, fmt.Errorf("IPv4 DNS echo peer requires an IPv4 address: %s", address)
	}
	if dnsPort == 0 || len(names) == 0 {
		return nil, errors.New("DNS echo peer requires a port and at least one name")
	}
	return newTCPUDPEchoPeer(parent, address, tcpPort, udpPort, dnsPort, names)
}

func newTCPUDPEchoPeer(parent context.Context, address netip.Addr, tcpPort uint16, udpPort uint16, dnsPort uint16, names map[string]netip.Addr) (*TCPUDPEchoPeer, error) {
	if parent == nil {
		return nil, errors.New("echo peer context is required")
	}
	if !address.IsValid() || address.IsUnspecified() {
		return nil, fmt.Errorf("echo peer requires a concrete IP address: %s", address)
	}
	networkProtocols := []stack.NetworkProtocolFactory{ipv4.NewProtocol}
	transportProtocols := []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4}
	protocol := ipv4.ProtocolNumber
	version := header.IPv4Version
	var stackAddress tcpip.Address
	emptySubnet := header.IPv4EmptySubnet
	prefixLength := 32
	if address.Is6() {
		networkProtocols = []stack.NetworkProtocolFactory{ipv6.NewProtocol}
		transportProtocols = []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6}
		protocol = ipv6.ProtocolNumber
		version = header.IPv6Version
		stackAddress = tcpip.AddrFrom16(address.As16())
		emptySubnet = header.IPv6EmptySubnet
		prefixLength = 128
	} else {
		stackAddress = tcpip.AddrFrom4(address.As4())
	}
	ipStack := stack.New(stack.Options{
		NetworkProtocols:   networkProtocols,
		TransportProtocols: transportProtocols,
	})
	endpoint := channel.New(256, 65535, "")
	if err := ipStack.CreateNIC(echoPeerNIC, endpoint); err != nil {
		ipStack.Close()
		return nil, fmt.Errorf("create echo peer NIC: %s", err)
	}
	if err := ipStack.AddProtocolAddress(echoPeerNIC, tcpip.ProtocolAddress{
		Protocol: protocol,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   stackAddress,
			PrefixLen: prefixLength,
		},
	}, stack.AddressProperties{}); err != nil {
		endpoint.Close()
		ipStack.Close()
		return nil, fmt.Errorf("add echo peer address: %s", err)
	}
	ipStack.AddRoute(tcpip.Route{Destination: emptySubnet, NIC: echoPeerNIC})
	tcpListener, err := gonet.ListenTCP(ipStack, tcpip.FullAddress{NIC: echoPeerNIC, Addr: stackAddress, Port: tcpPort}, protocol)
	if err != nil {
		endpoint.Close()
		ipStack.Close()
		return nil, fmt.Errorf("listen on echo peer TCP port: %w", err)
	}
	udpConnection, err := gonet.DialUDP(ipStack, &tcpip.FullAddress{NIC: echoPeerNIC, Addr: stackAddress, Port: udpPort}, nil, protocol)
	if err != nil {
		_ = tcpListener.Close()
		endpoint.Close()
		ipStack.Close()
		return nil, fmt.Errorf("listen on echo peer UDP port: %w", err)
	}
	var dnsConnection net.PacketConn
	if dnsPort != 0 {
		dnsConnection, err = gonet.DialUDP(ipStack, &tcpip.FullAddress{NIC: echoPeerNIC, Addr: stackAddress, Port: dnsPort}, nil, protocol)
		if err != nil {
			_ = udpConnection.Close()
			_ = tcpListener.Close()
			endpoint.Close()
			ipStack.Close()
			return nil, fmt.Errorf("listen on echo peer DNS port: %w", err)
		}
	}
	ctx, cancel := context.WithCancel(parent)
	peer := &TCPUDPEchoPeer{
		stack:    ipStack,
		endpoint: endpoint,
		tcp:      tcpListener,
		udp:      udpConnection,
		dns:      dnsConnection,
		dnsNames: make(map[string]netip.Addr, len(names)),
		cancel:   cancel,
		protocol: protocol,
		version:  version,
	}
	for name, value := range names {
		peer.dnsNames[strings.ToLower(D.Fqdn(name))] = value
	}
	peer.wait.Add(2)
	go peer.serveTCP(ctx)
	go peer.serveUDP(ctx)
	if peer.dns != nil {
		peer.wait.Add(1)
		go peer.serveDNS(ctx)
	}
	return peer, nil
}

func (p *TCPUDPEchoPeer) serveTCP(ctx context.Context) {
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

func (p *TCPUDPEchoPeer) serveUDP(ctx context.Context) {
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

func (p *TCPUDPEchoPeer) serveDNS(ctx context.Context) {
	defer p.wait.Done()
	buffer := make([]byte, 4096)
	for ctx.Err() == nil {
		count, source, err := p.dns.ReadFrom(buffer)
		if err != nil {
			return
		}
		request := new(D.Msg)
		if err := request.Unpack(buffer[:count]); err != nil {
			continue
		}
		response := new(D.Msg)
		response.SetReply(request)
		for _, question := range request.Question {
			address, loaded := p.dnsNames[strings.ToLower(D.Fqdn(question.Name))]
			if !loaded {
				continue
			}
			switch {
			case question.Qtype == D.TypeA && address.Is4():
				response.Answer = append(response.Answer, &D.A{Hdr: D.RR_Header{Name: question.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IP(address.AsSlice())})
			case question.Qtype == D.TypeAAAA && address.Is6():
				response.Answer = append(response.Answer, &D.AAAA{Hdr: D.RR_Header{Name: question.Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: 60}, AAAA: net.IP(address.AsSlice())})
			}
		}
		payload, err := response.Pack()
		if err != nil {
			continue
		}
		p.dnsCount.Add(1)
		if _, err := p.dns.WriteTo(payload, source); err != nil {
			return
		}
	}
}

func (p *TCPUDPEchoPeer) DNSQueries() int64 {
	if p == nil {
		return 0
	}
	return p.dnsCount.Load()
}

func (p *TCPUDPEchoPeer) HandlePacket(packet []byte) ([]byte, error) {
	replies, err := p.handlePackets(packet, false)
	if err != nil || len(replies) == 0 {
		return nil, err
	}
	return replies[0], nil
}

func (p *TCPUDPEchoPeer) HandlePackets(packet []byte) ([][]byte, error) {
	return p.handlePackets(packet, true)
}

func (p *TCPUDPEchoPeer) handlePackets(packet []byte, collectAdditional bool) ([][]byte, error) {
	if p == nil || p.endpoint == nil {
		return nil, errors.New("TCP/UDP echo peer is closed")
	}
	minimumSize := header.IPv4MinimumSize
	if p.version == header.IPv6Version {
		minimumSize = header.IPv6MinimumSize
	}
	if len(packet) < minimumSize || header.IPVersion(packet) != p.version {
		return nil, errors.New("echo peer received a packet from the wrong address family")
	}
	p.access.Lock()
	defer p.access.Unlock()
	packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	p.endpoint.InjectInbound(p.protocol, packetBuffer)
	packetBuffer.DecRef()
	readContext, cancel := context.WithTimeout(context.Background(), echoPeerWaitTimeout(packet, p.version))
	defer cancel()
	first := p.endpoint.ReadContext(readContext)
	if first == nil {
		return nil, nil
	}
	replies := [][]byte{packetBytes(first)}
	first.DecRef()
	wantTCPPayload := echoPeerTCPPayloadLength(packet, p.version) > 0
	if !collectAdditional || !wantTCPPayload || echoPeerTCPPayloadLength(replies[0], p.version) > 0 {
		return replies, nil
	}
	additionalContext, cancelAdditional := context.WithTimeout(context.Background(), echoPeerResponseTimeout)
	defer cancelAdditional()
	for {
		next := p.endpoint.ReadContext(additionalContext)
		if next == nil {
			return nil, errors.New("TCP echo peer did not produce a data response")
		}
		reply := packetBytes(next)
		next.DecRef()
		replies = append(replies, reply)
		if echoPeerTCPPayloadLength(reply, p.version) > 0 {
			return replies, nil
		}
	}
}

func echoPeerWaitTimeout(packet []byte, version int) time.Duration {
	payloadLength, tcp := echoPeerTCPPayload(packet, version)
	if !tcp {
		return echoPeerResponseTimeout
	}
	if payloadLength > 0 {
		return echoPeerResponseTimeout
	}
	transport, _ := echoPeerTransport(packet, version)
	tcpHeader := header.TCP(transport)
	if tcpHeader.Flags().Intersects(header.TCPFlagSyn | header.TCPFlagFin) {
		return echoPeerResponseTimeout
	}
	return echoPeerQuietTimeout
}

func echoPeerTCPPayloadLength(packet []byte, version int) int {
	payloadLength, _ := echoPeerTCPPayload(packet, version)
	return payloadLength
}

func echoPeerTCPPayload(packet []byte, version int) (int, bool) {
	transport, protocol := echoPeerTransport(packet, version)
	if protocol != header.TCPProtocolNumber || len(transport) < header.TCPMinimumSize {
		return 0, false
	}
	headerLength := int(header.TCP(transport).DataOffset())
	if headerLength < header.TCPMinimumSize || headerLength > len(transport) {
		return 0, false
	}
	return len(transport) - headerLength, true
}

func echoPeerTransport(packet []byte, version int) ([]byte, tcpip.TransportProtocolNumber) {
	var transport []byte
	var protocol tcpip.TransportProtocolNumber
	switch version {
	case header.IPv4Version:
		ipv4Header := header.IPv4(packet)
		if !ipv4Header.IsValid(len(packet)) {
			return nil, 0
		}
		protocol = ipv4Header.TransportProtocol()
		transport = ipv4Header.Payload()
	case header.IPv6Version:
		ipv6Header := header.IPv6(packet)
		if !ipv6Header.IsValid(len(packet)) {
			return nil, 0
		}
		var parsed bool
		protocol, parsed = ipv6Header.TryParseTransportProtocol()
		if !parsed || ipv6Header.NextHeader() != uint8(protocol) {
			return nil, 0
		}
		transport = packet[header.IPv6MinimumSize:]
	default:
		return nil, 0
	}
	return transport, protocol
}

func packetBytes(packet *stack.PacketBuffer) []byte {
	var result []byte
	for _, content := range packet.AsSlices() {
		result = append(result, content...)
	}
	return result
}

func (p *TCPUDPEchoPeer) Close() error {
	if p == nil {
		return nil
	}
	p.cancel()
	tcpErr := p.tcp.Close()
	udpErr := p.udp.Close()
	var dnsErr error
	if p.dns != nil {
		dnsErr = p.dns.Close()
	}
	p.endpoint.Close()
	p.stack.Close()
	for _, endpoint := range p.stack.CleanupEndpoints() {
		endpoint.Abort()
	}
	p.stack.Wait()
	p.wait.Wait()
	return errors.Join(tcpErr, udpErr, dnsErr)
}
