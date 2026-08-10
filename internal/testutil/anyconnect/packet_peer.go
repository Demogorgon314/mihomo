package anyconnect

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const ipv4ICMPProtocol = 1

const ipv6ICMPProtocol = 58

// PacketPeer handles raw tunnel packets without relying on the client implementation.
type PacketPeer interface {
	HandlePacket(packet []byte) ([]byte, error)
}

type packetBatchPeer interface {
	HandlePackets(packet []byte) ([][]byte, error)
}

func handlePeerPackets(peer PacketPeer, packet []byte) ([][]byte, error) {
	if batchPeer, ok := peer.(packetBatchPeer); ok {
		return batchPeer.HandlePackets(packet)
	}
	reply, err := peer.HandlePacket(packet)
	if err != nil || len(reply) == 0 {
		return nil, err
	}
	return [][]byte{reply}, nil
}

// IPv4ICMPEchoPeer replies to valid ICMP echo requests addressed to it.
type IPv4ICMPEchoPeer struct {
	address netip.Addr
}

// IPv6ICMPEchoPeer replies to valid ICMPv6 echo requests addressed to it.
type IPv6ICMPEchoPeer struct {
	address netip.Addr
}

// NewIPv6ICMPEchoPeer creates a raw IPv6 packet peer.
func NewIPv6ICMPEchoPeer(address netip.Addr) (*IPv6ICMPEchoPeer, error) {
	if !address.Is6() || address.IsUnspecified() {
		return nil, fmt.Errorf("ICMPv6 echo peer requires a concrete IPv6 address: %s", address)
	}
	return &IPv6ICMPEchoPeer{address: address}, nil
}

// HandlePacket validates one IPv6 ICMP echo request and returns a caller-owned reply.
func (p *IPv6ICMPEchoPeer) HandlePacket(packet []byte) ([]byte, error) {
	if p == nil {
		return nil, errors.New("ICMPv6 echo peer is nil")
	}
	if len(packet) < 48 || packet[0]>>4 != 6 || packet[6] != ipv6ICMPProtocol {
		return nil, errors.New("packet is not a complete IPv6 ICMP echo request")
	}
	payloadLength := int(binary.BigEndian.Uint16(packet[4:6]))
	if payloadLength != len(packet)-40 {
		return nil, fmt.Errorf("IPv6 payload length mismatch: %d != %d", payloadLength, len(packet)-40)
	}
	destination, ok := netip.AddrFromSlice(packet[24:40])
	if !ok || destination != p.address {
		return nil, fmt.Errorf("packet addressed to %s instead of %s", destination, p.address)
	}
	message := packet[40:]
	if message[0] != 128 || message[1] != 0 || icmpv6Checksum(packet[8:24], packet[24:40], message) != 0 {
		return nil, errors.New("invalid ICMPv6 echo request")
	}
	reply := append([]byte(nil), packet...)
	copy(reply[8:24], packet[24:40])
	copy(reply[24:40], packet[8:24])
	reply[7] = 64
	reply[40] = 129
	reply[42], reply[43] = 0, 0
	binary.BigEndian.PutUint16(reply[42:44], icmpv6Checksum(reply[8:24], reply[24:40], reply[40:]))
	return reply, nil
}

// NewIPv4ICMPEchoPeer creates a raw IPv4 packet peer.
func NewIPv4ICMPEchoPeer(address netip.Addr) (*IPv4ICMPEchoPeer, error) {
	if !address.Is4() || address.IsUnspecified() {
		return nil, fmt.Errorf("ICMP echo peer requires a concrete IPv4 address: %s", address)
	}
	return &IPv4ICMPEchoPeer{address: address}, nil
}

// HandlePacket validates one IPv4 ICMP echo request and returns a caller-owned reply.
func (p *IPv4ICMPEchoPeer) HandlePacket(packet []byte) ([]byte, error) {
	if p == nil {
		return nil, errors.New("ICMP echo peer is nil")
	}
	if len(packet) < 28 || packet[0]>>4 != 4 {
		return nil, errors.New("packet is not a complete IPv4 ICMP echo request")
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || headerLength+8 > len(packet) {
		return nil, errors.New("invalid IPv4 header length")
	}
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLength != len(packet) {
		return nil, fmt.Errorf("IPv4 total length mismatch: %d != %d", totalLength, len(packet))
	}
	if packet[9] != ipv4ICMPProtocol {
		return nil, fmt.Errorf("unexpected IPv4 protocol: %d", packet[9])
	}
	if internetChecksum(packet[:headerLength]) != 0 {
		return nil, errors.New("invalid IPv4 header checksum")
	}
	destinationBytes := [4]byte{packet[16], packet[17], packet[18], packet[19]}
	if destination := netip.AddrFrom4(destinationBytes); destination != p.address {
		return nil, fmt.Errorf("packet addressed to %s instead of %s", destination, p.address)
	}
	icmpMessage := packet[headerLength:]
	if icmpMessage[0] != 8 || icmpMessage[1] != 0 {
		return nil, fmt.Errorf("unexpected ICMP type/code: %d/%d", icmpMessage[0], icmpMessage[1])
	}
	if internetChecksum(icmpMessage) != 0 {
		return nil, errors.New("invalid ICMP checksum")
	}
	reply := append([]byte(nil), packet...)
	copy(reply[12:16], packet[16:20])
	copy(reply[16:20], packet[12:16])
	reply[8] = 64
	reply[10], reply[11] = 0, 0
	binary.BigEndian.PutUint16(reply[10:12], internetChecksum(reply[:headerLength]))
	reply[headerLength] = 0
	reply[headerLength+2], reply[headerLength+3] = 0, 0
	binary.BigEndian.PutUint16(reply[headerLength+2:headerLength+4], internetChecksum(reply[headerLength:]))
	return reply, nil
}

// BuildIPv4ICMPEchoRequest builds a checksummed raw IPv4 packet for driver tests.
func BuildIPv4ICMPEchoRequest(source netip.Addr, destination netip.Addr, identifier uint16, sequence uint16, payload []byte) ([]byte, error) {
	if !source.Is4() || source.IsUnspecified() || !destination.Is4() || destination.IsUnspecified() {
		return nil, errors.New("ICMP echo request requires concrete IPv4 source and destination addresses")
	}
	if len(payload) > cstpMaximumPayloadSize-28 {
		return nil, errors.New("ICMP echo request payload is too large")
	}
	icmpMessage := make([]byte, 8+len(payload))
	icmpMessage[0] = 8
	binary.BigEndian.PutUint16(icmpMessage[4:6], identifier)
	binary.BigEndian.PutUint16(icmpMessage[6:8], sequence)
	copy(icmpMessage[8:], payload)
	binary.BigEndian.PutUint16(icmpMessage[2:4], internetChecksum(icmpMessage))
	packet := make([]byte, 20+len(icmpMessage))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], identifier)
	packet[8] = 64
	packet[9] = ipv4ICMPProtocol
	sourceBytes := source.As4()
	destinationBytes := destination.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:20]))
	copy(packet[20:], icmpMessage)
	return packet, nil
}

// BuildIPv6ICMPEchoRequest builds a checksummed raw IPv6 packet for driver tests.
func BuildIPv6ICMPEchoRequest(source netip.Addr, destination netip.Addr, identifier uint16, sequence uint16, payload []byte) ([]byte, error) {
	if !source.Is6() || source.IsUnspecified() || !destination.Is6() || destination.IsUnspecified() {
		return nil, errors.New("ICMPv6 echo request requires concrete IPv6 source and destination addresses")
	}
	if len(payload) > cstpMaximumPayloadSize-48 {
		return nil, errors.New("ICMPv6 echo request payload is too large")
	}
	message := make([]byte, 8+len(payload))
	message[0] = 128
	binary.BigEndian.PutUint16(message[4:6], identifier)
	binary.BigEndian.PutUint16(message[6:8], sequence)
	copy(message[8:], payload)
	packet := make([]byte, 40+len(message))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(message)))
	packet[6] = ipv6ICMPProtocol
	packet[7] = 64
	sourceBytes := source.As16()
	destinationBytes := destination.As16()
	copy(packet[8:24], sourceBytes[:])
	copy(packet[24:40], destinationBytes[:])
	binary.BigEndian.PutUint16(message[2:4], icmpv6Checksum(packet[8:24], packet[24:40], message))
	copy(packet[40:], message)
	return packet, nil
}

func icmpv6Checksum(source []byte, destination []byte, message []byte) uint16 {
	pseudoHeader := make([]byte, 40+len(message))
	copy(pseudoHeader[0:16], source)
	copy(pseudoHeader[16:32], destination)
	binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(len(message)))
	pseudoHeader[39] = ipv6ICMPProtocol
	copy(pseudoHeader[40:], message)
	return internetChecksum(pseudoHeader)
}

func internetChecksum(content []byte) uint16 {
	var sum uint32
	for len(content) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(content[:2]))
		content = content[2:]
	}
	if len(content) == 1 {
		sum += uint32(content[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
