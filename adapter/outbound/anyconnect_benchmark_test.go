//go:build with_gvisor

package outbound

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	testanyconnect "github.com/metacubex/mihomo/internal/testutil/anyconnect"
	ac "github.com/metacubex/mihomo/transport/anyconnect"
)

const anyConnectE2EBenchmarkMagic = 0x41434e42

// BenchmarkAnyConnectDataPlaneE2E is the final performance and correctness
// gate. It uses the local fake gateway, real Pion DTLS, sing-openconnect, and
// mihomo's packet stack. Replies may be reordered, but none may be lost,
// duplicated, corrupted, delivered over CSTP, or cross a data-plane revision.
func BenchmarkAnyConnectDataPlaneE2E(b *testing.B) {
	for _, payloadSize := range []int{128, 512, 1200, 1372} {
		b.Run(fmt.Sprintf("%dB", payloadSize), func(b *testing.B) {
			ctx, outbound, session, recorder, peerAddress := startAnyConnectE2EBenchmark(b)
			waitAnyConnectTransport(b, ctx, session, "dtls")
			revision, err := session.client.WaitDataPlaneReady(ctx)
			if err != nil {
				b.Fatal(err)
			}
			if revision == 0 {
				b.Fatal("AnyConnect benchmark started without a data-plane revision")
			}

			connection, err := outbound.ListenPacketContext(ctx, &C.Metadata{
				NetWork: C.UDP,
				DstIP:   peerAddress,
				DstPort: testAnyConnectUDPPort,
			})
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = connection.Close() })
			if deadline, loaded := ctx.Deadline(); loaded {
				if err = connection.SetDeadline(deadline); err != nil {
					b.Fatal(err)
				}
			}
			destination := &net.UDPAddr{IP: peerAddress.AsSlice(), Port: testAnyConnectUDPPort}
			const maximumWindow = 32
			windowSize := min(maximumWindow, max(1, b.N))
			writeBuffers := make([][]byte, windowSize)
			for index := range writeBuffers {
				writeBuffers[index] = newAnyConnectE2EBenchmarkPacket(payloadSize)
			}
			readBuffer := make([]byte, payloadSize+64)
			seen := make([]bool, windowSize)
			baselineDTLS := recorder.Count("dtls-data")
			baselineCSTP := recorder.Count("cstp-data")

			b.ReportAllocs()
			b.SetBytes(int64(payloadSize))
			b.ResetTimer()
			for base := 0; base < b.N; base += windowSize {
				count := min(windowSize, b.N-base)
				clear(seen[:count])
				for offset := 0; offset < count; offset++ {
					packet := writeBuffers[offset]
					setAnyConnectE2EBenchmarkSequence(packet, uint64(base+offset))
					written, writeErr := connection.WriteTo(packet, destination)
					if writeErr != nil {
						b.Fatalf("write packet %d: %v", base+offset, writeErr)
					}
					if written != len(packet) {
						b.Fatalf("short packet write %d: got %d, want %d", base+offset, written, len(packet))
					}
				}
				for range count {
					read, source, readErr := connection.ReadFrom(readBuffer)
					if readErr != nil {
						b.Fatalf("read packet window starting at %d: %v", base, readErr)
					}
					if source.String() != destination.String() {
						b.Fatalf("unexpected echo source: got %s, want %s", source, destination)
					}
					sequence, validateErr := validateAnyConnectE2EBenchmarkPacket(readBuffer[:read])
					if validateErr != nil {
						b.Fatal(validateErr)
					}
					if sequence < uint64(base) || sequence >= uint64(base+count) {
						b.Fatalf("packet %d crossed benchmark window [%d,%d)", sequence, base, base+count)
					}
					offset := int(sequence) - base
					if seen[offset] {
						b.Fatalf("duplicate packet %d", sequence)
					}
					seen[offset] = true
				}
			}
			b.StopTimer()

			if currentRevision, readyErr := session.client.WaitDataPlaneReady(ctx); readyErr != nil || currentRevision != revision {
				b.Fatalf("data-plane revision changed: got %d, want %d, err=%v", currentRevision, revision, readyErr)
			}
			if transport := session.client.ActiveTransport(); transport != "dtls" {
				b.Fatalf("benchmark left DTLS transport: %q", transport)
			}
			if actual := recorder.Count("dtls-data") - baselineDTLS; actual != uint64(b.N) {
				b.Fatalf("gateway DTLS packet count mismatch: got %d, want %d", actual, b.N)
			}
			if actual := recorder.Count("cstp-data"); actual != baselineCSTP {
				b.Fatalf("benchmark leaked data over CSTP: before=%d after=%d", baselineCSTP, actual)
			}
		})
	}
}

type anyConnectSingleReplyPeer struct {
	peer *testanyconnect.IPv4TCPUDPEchoPeer
}

func (p anyConnectSingleReplyPeer) HandlePacket(packet []byte) ([]byte, error) {
	return p.peer.HandlePacket(packet)
}

func startAnyConnectE2EBenchmark(b *testing.B) (context.Context, *AnyConnect, *anyConnectSession, *testanyconnect.Recorder, netip.Addr) {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	b.Cleanup(cancel)
	scenario := testanyconnect.BasicCSTPScenario()
	scenario.ModernDTLS = true
	peerAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := testanyconnect.NewIPv4TCPUDPEchoPeer(ctx, peerAddress, testAnyConnectTCPPort, testAnyConnectUDPPort)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = peer.Close() })
	recorder := testanyconnect.NewCountingRecorder()
	gateway, err := testanyconnect.StartGateway(ctx, scenario, anyConnectSingleReplyPeer{peer: peer}, recorder)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = gateway.Close() })
	outbound := newFakeAnyConnectOutboundWithOption(b, gateway, scenario, new(anyConnectRecordingDialer), 0, func(option *AnyConnectOption) {
		option.DTLSMode = ac.DTLSModeRequire
		option.DPDInterval = 2
	})
	b.Cleanup(func() { _ = outbound.Close() })
	session, err := outbound.run(ctx)
	if err != nil {
		b.Fatal(err)
	}
	return ctx, outbound, session, recorder, peerAddress
}

func newAnyConnectE2EBenchmarkPacket(size int) []byte {
	if size < 24 {
		panic("AnyConnect benchmark packet must be at least 24 bytes")
	}
	packet := make([]byte, size)
	binary.BigEndian.PutUint32(packet[0:4], anyConnectE2EBenchmarkMagic)
	binary.BigEndian.PutUint32(packet[4:8], uint32(size))
	for index := 24; index < len(packet); index++ {
		packet[index] = byte(index*31 + 17)
	}
	return packet
}

func setAnyConnectE2EBenchmarkSequence(packet []byte, sequence uint64) {
	binary.BigEndian.PutUint64(packet[8:16], sequence)
	binary.BigEndian.PutUint64(packet[16:24], ^sequence)
}

func validateAnyConnectE2EBenchmarkPacket(packet []byte) (uint64, error) {
	if len(packet) < 24 || binary.BigEndian.Uint32(packet[0:4]) != anyConnectE2EBenchmarkMagic {
		return 0, fmt.Errorf("invalid E2E benchmark packet header")
	}
	if int(binary.BigEndian.Uint32(packet[4:8])) != len(packet) {
		return 0, fmt.Errorf("E2E benchmark packet length mismatch: header=%d actual=%d", binary.BigEndian.Uint32(packet[4:8]), len(packet))
	}
	sequence := binary.BigEndian.Uint64(packet[8:16])
	if binary.BigEndian.Uint64(packet[16:24]) != ^sequence {
		return 0, fmt.Errorf("E2E benchmark sequence canary changed at packet %d", sequence)
	}
	for index := 24; index < len(packet); index++ {
		if packet[index] != byte(index*31+17) {
			return 0, fmt.Errorf("E2E benchmark payload changed at packet %d offset %d", sequence, index)
		}
	}
	return sequence, nil
}
