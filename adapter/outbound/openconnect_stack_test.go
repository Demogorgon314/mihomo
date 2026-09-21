package outbound

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mipstack"
	M "github.com/metacubex/sing/common/metadata"
)

// Run without with_gvisor as well: mips must not depend on the gVisor backend.
func TestOpenConnectMIPSStackSockets(t *testing.T) {
	for _, testCase := range []struct {
		name, first, source, peer string
		mtu                       uint32
	}{
		{"IPv4-minimum-MTU", "192.0.2.2/24", "192.0.2.3/24", "192.0.2.1/24", 576},
		{"IPv6", "2001:db8::2/64", "2001:db8::3/64", "2001:db8::1/64", 1280},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			source := netip.MustParsePrefix(testCase.source)
			device, err := newOpenConnectStack("mips", []netip.Prefix{netip.MustParsePrefix(testCase.first), source}, testCase.mtu)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = device.Close() })
			peerPrefix := netip.MustParsePrefix(testCase.peer)
			peer, err := mipstack.New(mipstack.Config{LocalAddresses: []netip.Prefix{peerPrefix}, MTU: testCase.mtu})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = peer.Close() })
			if err := device.Start(); err != nil {
				t.Fatal(err)
			}
			if err := peer.Start(); err != nil {
				t.Fatal(err)
			}
			var pumps sync.WaitGroup
			pump := func(read func([][]byte, []int, int) (int, error), write func([][]byte, int) (int, error)) {
				defer pumps.Done()
				buffer := make([]byte, testCase.mtu)
				sizes := make([]int, 1)
				for {
					if _, err := read([][]byte{buffer}, sizes, 0); err != nil {
						return
					}
					if _, err := write([][]byte{buffer[:sizes[0]]}, 0); err != nil {
						return
					}
				}
			}
			pumps.Add(2)
			go pump(device.Read, peer.Write)
			go pump(peer.Read, device.Write)
			t.Cleanup(func() {
				_ = device.Close()
				_ = peer.Close()
				pumps.Wait()
			})
			deadline, _ := ctx.Deadline()
			remote := netip.AddrPortFrom(peerPrefix.Addr(), 12345)
			destination := M.SocksaddrFrom(remote.Addr(), remote.Port())
			listener, err := peer.ListenTCP(ctx, "tcp", remote)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			connection, err := device.DialContext(ctx, "tcp", destination)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			accepted, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer accepted.Close()
			_ = connection.SetDeadline(deadline)
			_ = accepted.SetDeadline(deadline)
			if got := accepted.RemoteAddr().(*net.TCPAddr).AddrPort().Addr(); got != source.Addr() {
				t.Fatalf("TCP source = %s, want %s", got, source.Addr())
			}
			payload := []byte("OpenConnect mips socket exchange")
			if _, err := connection.Write(payload); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(payload))
			if _, err := io.ReadFull(accepted, reply); err != nil || string(reply) != string(payload) {
				t.Fatalf("TCP payload %q: %v", reply, err)
			}
			udpPeer, err := peer.ListenUDP(ctx, "udp", remote)
			if err != nil {
				t.Fatal(err)
			}
			defer udpPeer.Close()
			udp, err := device.ListenPacket(ctx, destination)
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			_ = udp.SetDeadline(deadline)
			_ = udpPeer.SetDeadline(deadline)
			if _, err := udp.WriteTo(payload, net.UDPAddrFromAddrPort(remote)); err != nil {
				t.Fatal(err)
			}
			n, address, err := udpPeer.ReadFrom(reply)
			if err != nil || string(reply[:n]) != string(payload) {
				t.Fatalf("UDP payload %q: %v", reply[:n], err)
			}
			if got := address.(*net.UDPAddr).AddrPort().Addr(); got != source.Addr() {
				t.Fatalf("UDP source = %s, want %s", got, source.Addr())
			}
			if _, err := udpPeer.WriteTo(payload, address); err != nil {
				t.Fatal(err)
			}
			n, _, err = udp.ReadFrom(reply)
			if err != nil || string(reply[:n]) != string(payload) {
				t.Fatalf("UDP reply %q: %v", reply[:n], err)
			}
			if err := device.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := udp.WriteTo(payload, net.UDPAddrFromAddrPort(remote)); err == nil {
				t.Fatal("closed stack allowed a UDP write")
			}
			if _, err := connection.Read(reply); err == nil {
				t.Fatal("closed stack allowed a TCP read")
			}
		})
	}
}
