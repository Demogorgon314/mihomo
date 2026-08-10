package anyconnect

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

func TestIPv4ICMPEchoPeer(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.2")
	serverAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := NewIPv4ICMPEchoPeer(serverAddress)
	if err != nil {
		t.Fatal(err)
	}
	request, err := BuildIPv4ICMPEchoRequest(clientAddress, serverAddress, 7, 11, []byte("phase0"))
	if err != nil {
		t.Fatal(err)
	}
	requestCopy := append([]byte(nil), request...)
	reply, err := peer.HandlePacket(request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(request, requestCopy) {
		t.Fatal("peer mutated caller packet")
	}
	if reply[20] != 0 || !bytes.Equal(reply[12:16], request[16:20]) || !bytes.Equal(reply[16:20], request[12:16]) {
		t.Fatalf("invalid ICMP echo reply: %x", reply)
	}
	if internetChecksum(reply[:20]) != 0 || internetChecksum(reply[20:]) != 0 {
		t.Fatal("reply checksum is invalid")
	}
}

func TestIPv4ICMPEchoPeerRejectsInvalidPackets(t *testing.T) {
	serverAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := NewIPv4ICMPEchoPeer(serverAddress)
	if err != nil {
		t.Fatal(err)
	}
	request, err := BuildIPv4ICMPEchoRequest(netip.MustParseAddr("192.0.2.2"), serverAddress, 1, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		mutate  func([]byte) []byte
		message string
	}{
		{name: "short", mutate: func(packet []byte) []byte { return packet[:12] }, message: "complete"},
		{name: "protocol", mutate: func(packet []byte) []byte { packet[9] = 17; return packet }, message: "protocol"},
		{name: "destination", mutate: func(packet []byte) []byte {
			packet[19] = 99
			packet[10], packet[11] = 0, 0
			putChecksum(packet[10:12], packet[:20])
			return packet
		}, message: "addressed"},
		{name: "ICMP type", mutate: func(packet []byte) []byte {
			packet[20] = 3
			packet[22], packet[23] = 0, 0
			putChecksum(packet[22:24], packet[20:])
			return packet
		}, message: "type/code"},
		{name: "checksum", mutate: func(packet []byte) []byte { packet[len(packet)-1] ^= 1; return packet }, message: "checksum"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet := test.mutate(append([]byte(nil), request...))
			_, err := peer.HandlePacket(packet)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("expected error containing %q, got %v", test.message, err)
			}
		})
	}
}

func TestNewIPv4ICMPEchoPeerRejectsInvalidAddress(t *testing.T) {
	for _, address := range []netip.Addr{netip.Addr{}, netip.IPv4Unspecified(), netip.IPv6Unspecified()} {
		if _, err := NewIPv4ICMPEchoPeer(address); err == nil {
			t.Fatalf("expected invalid address error for %s", address)
		}
	}
}

func putChecksum(destination []byte, content []byte) {
	checksum := internetChecksum(content)
	destination[0] = byte(checksum >> 8)
	destination[1] = byte(checksum)
}
