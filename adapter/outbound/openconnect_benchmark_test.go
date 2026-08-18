//go:build with_gvisor

package outbound

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	testopenconnect "github.com/metacubex/mihomo/internal/testutil/openconnect"
	oc "github.com/metacubex/mihomo/transport/openconnect"
)

const openConnectE2EBenchmarkMagic = 0x41434e42

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
			actual := waitAnyConnectBenchmarkRecordCount(ctx, recorder, "dtls-data", baselineDTLS+uint64(b.N)) - baselineDTLS
			if actual != uint64(b.N) {
				b.Fatalf("gateway DTLS packet count mismatch: got %d, want %d", actual, b.N)
			}
			if actual := recorder.Count("cstp-data"); actual != baselineCSTP {
				b.Fatalf("benchmark leaked data over CSTP: before=%d after=%d", baselineCSTP, actual)
			}
		})
	}
}

// BenchmarkAnyConnectTCPDownloadE2E isolates the high-throughput receive path
// and the pure TCP acknowledgement traffic sent back through DTLS.
func BenchmarkAnyConnectTCPDownloadE2E(b *testing.B) {
	const (
		segmentSize      = 1024
		segmentsPerBlock = 32
		blockSize        = segmentSize * segmentsPerBlock
	)
	block := make([]byte, blockSize)
	for index := range block {
		block[index] = byte(index*31 + 17)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	b.Cleanup(cancel)
	peerAddress := netip.MustParseAddr("192.0.2.1")
	peer := newAnyConnectTCPDownloadPeer(peerAddress, testAnyConnectTCPPort, segmentSize, segmentsPerBlock, block)
	outbound, session, recorder := startAnyConnectE2EBenchmarkTunnel(b, ctx, peer)
	waitAnyConnectTransport(b, ctx, session, "dtls")
	revision, err := session.client.WaitDataPlaneReady(ctx)
	if err != nil {
		b.Fatal(err)
	}
	connection, err := outbound.DialContext(ctx, &C.Metadata{
		NetWork: C.TCP,
		DstIP:   peerAddress,
		DstPort: testAnyConnectTCPPort,
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
	received := make([]byte, blockSize)
	baselineDTLS := recorder.Count("dtls-data")
	baselineCSTP := recorder.Count("cstp-data")

	b.ReportAllocs()
	b.SetBytes(blockSize)
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err = io.ReadFull(connection, received); err != nil {
			b.Fatalf("read block %d: %v", index, err)
		}
		if !bytes.Equal(received, block) {
			b.Fatalf("download block %d was corrupted", index)
		}
	}
	b.StopTimer()

	if currentRevision, readyErr := session.client.WaitDataPlaneReady(ctx); readyErr != nil || currentRevision != revision {
		b.Fatalf("data-plane revision changed: got %d, want %d, err=%v", currentRevision, revision, readyErr)
	}
	if transport := session.client.ActiveTransport(); transport != "dtls" {
		b.Fatalf("benchmark left DTLS transport: %q", transport)
	}
	if actual := recorder.Count("dtls-data"); actual <= baselineDTLS {
		b.Fatalf("gateway received no DTLS acknowledgements: before=%d after=%d", baselineDTLS, actual)
	}
	if actual := recorder.Count("cstp-data"); actual != baselineCSTP {
		b.Fatalf("benchmark leaked data over CSTP: before=%d after=%d", baselineCSTP, actual)
	}
}

type openConnectTCPDownloadPeer struct {
	access           sync.Mutex
	address          netip.Addr
	port             uint16
	segmentSize      int
	segmentsPerBlock int
	block            []byte
	clientAddress    [4]byte
	clientPort       uint16
	clientNext       uint32
	serverInitial    uint32
	serverNext       uint32
	established      bool
}

func newAnyConnectTCPDownloadPeer(address netip.Addr, port uint16, segmentSize int, segmentsPerBlock int, block []byte) *openConnectTCPDownloadPeer {
	return &openConnectTCPDownloadPeer{
		address:          address,
		port:             port,
		segmentSize:      segmentSize,
		segmentsPerBlock: segmentsPerBlock,
		block:            append([]byte(nil), block...),
		serverInitial:    0x10203040,
	}
}

func (p *openConnectTCPDownloadPeer) HandlePacket(packet []byte) ([]byte, error) {
	replies, err := p.HandlePackets(packet)
	if err != nil || len(replies) == 0 {
		return nil, err
	}
	return replies[0], nil
}

func (p *openConnectTCPDownloadPeer) HandlePackets(packet []byte) ([][]byte, error) {
	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 {
		return nil, fmt.Errorf("download peer received a non-TCP IPv4 packet")
	}
	ipHeaderLength := int(packet[0]&0x0f) * 4
	if ipHeaderLength < 20 || ipHeaderLength+20 > len(packet) || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		return nil, fmt.Errorf("download peer received an invalid IPv4 packet")
	}
	destination := [4]byte{packet[16], packet[17], packet[18], packet[19]}
	if netip.AddrFrom4(destination) != p.address {
		return nil, fmt.Errorf("download peer received a packet for %s", netip.AddrFrom4(destination))
	}
	tcpPacket := packet[ipHeaderLength:]
	tcpHeaderLength := int(tcpPacket[12]>>4) * 4
	if tcpHeaderLength < 20 || tcpHeaderLength > len(tcpPacket) || binary.BigEndian.Uint16(tcpPacket[2:4]) != p.port {
		return nil, fmt.Errorf("download peer received an invalid TCP packet")
	}
	flags := tcpPacket[13]
	clientSequence := binary.BigEndian.Uint32(tcpPacket[4:8])
	clientAcknowledgement := binary.BigEndian.Uint32(tcpPacket[8:12])
	clientPort := binary.BigEndian.Uint16(tcpPacket[0:2])
	clientAddress := [4]byte{packet[12], packet[13], packet[14], packet[15]}
	clientPayloadLength := len(tcpPacket) - tcpHeaderLength

	p.access.Lock()
	defer p.access.Unlock()
	if flags&0x02 != 0 {
		p.clientAddress = clientAddress
		p.clientPort = clientPort
		p.clientNext = clientSequence + 1
		p.serverNext = p.serverInitial + 1
		p.established = true
		return [][]byte{p.buildPacket(p.serverInitial, p.clientNext, 0x12, nil)}, nil
	}
	if !p.established || clientAddress != p.clientAddress || clientPort != p.clientPort {
		return nil, fmt.Errorf("download peer received a packet for an unknown TCP flow")
	}
	if clientPayloadLength > 0 {
		p.clientNext = clientSequence + uint32(clientPayloadLength)
	}
	if flags&(0x01|0x04) != 0 {
		if flags&0x01 != 0 {
			p.clientNext++
			return [][]byte{p.buildPacket(p.serverNext, p.clientNext, 0x10, nil)}, nil
		}
		return nil, nil
	}
	if flags&0x10 == 0 || clientAcknowledgement < p.serverNext {
		return nil, nil
	}
	if clientAcknowledgement != p.serverNext {
		return nil, fmt.Errorf("download peer received ACK %d beyond sequence %d", clientAcknowledgement, p.serverNext)
	}
	replies := make([][]byte, p.segmentsPerBlock)
	sequence := p.serverNext
	for index := range replies {
		start := index * p.segmentSize
		end := start + p.segmentSize
		replies[index] = p.buildPacket(sequence, p.clientNext, 0x18, p.block[start:end])
		sequence += uint32(p.segmentSize)
	}
	p.serverNext = sequence
	return replies, nil
}

func (p *openConnectTCPDownloadPeer) buildPacket(sequence uint32, acknowledgement uint32, flags byte, payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 6
	serverAddress := p.address.As4()
	copy(packet[12:16], serverAddress[:])
	copy(packet[16:20], p.clientAddress[:])
	binary.BigEndian.PutUint16(packet[10:12], openConnectBenchmarkChecksum(packet[:20]))
	tcpPacket := packet[20:]
	binary.BigEndian.PutUint16(tcpPacket[0:2], p.port)
	binary.BigEndian.PutUint16(tcpPacket[2:4], p.clientPort)
	binary.BigEndian.PutUint32(tcpPacket[4:8], sequence)
	binary.BigEndian.PutUint32(tcpPacket[8:12], acknowledgement)
	tcpPacket[12] = 0x50
	tcpPacket[13] = flags
	binary.BigEndian.PutUint16(tcpPacket[14:16], 65535)
	copy(tcpPacket[20:], payload)
	binary.BigEndian.PutUint16(tcpPacket[16:18], openConnectBenchmarkTCPChecksum(packet[12:16], packet[16:20], tcpPacket))
	return packet
}

func openConnectBenchmarkTCPChecksum(source []byte, destination []byte, tcpPacket []byte) uint16 {
	pseudoHeader := make([]byte, 12+len(tcpPacket))
	copy(pseudoHeader[0:4], source)
	copy(pseudoHeader[4:8], destination)
	pseudoHeader[9] = 6
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(tcpPacket)))
	copy(pseudoHeader[12:], tcpPacket)
	return openConnectBenchmarkChecksum(pseudoHeader)
}

func openConnectBenchmarkChecksum(content []byte) uint16 {
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

func waitAnyConnectBenchmarkRecordCount(ctx context.Context, recorder *testopenconnect.Recorder, kind string, expected uint64) uint64 {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		actual := recorder.Count(kind)
		if actual >= expected {
			return actual
		}
		select {
		case <-ctx.Done():
			return actual
		case <-timer.C:
			return actual
		default:
			runtime.Gosched()
		}
	}
}

type openConnectSingleReplyPeer struct {
	peer *testopenconnect.TCPUDPEchoPeer
}

func (p openConnectSingleReplyPeer) HandlePacket(packet []byte) ([]byte, error) {
	return p.peer.HandlePacket(packet)
}

func startAnyConnectE2EBenchmark(b *testing.B) (context.Context, *OpenConnect, *openConnectSession, *testopenconnect.Recorder, netip.Addr) {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	b.Cleanup(cancel)
	peerAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := testopenconnect.NewIPv4TCPUDPEchoPeer(ctx, peerAddress, testAnyConnectTCPPort, testAnyConnectUDPPort)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = peer.Close() })
	outbound, session, recorder := startAnyConnectE2EBenchmarkTunnel(b, ctx, openConnectSingleReplyPeer{peer: peer})
	return ctx, outbound, session, recorder, peerAddress
}

func startAnyConnectE2EBenchmarkTunnel(b *testing.B, ctx context.Context, peer testopenconnect.PacketPeer) (*OpenConnect, *openConnectSession, *testopenconnect.Recorder) {
	b.Helper()
	scenario := testopenconnect.BasicAnyConnectScenario()
	scenario.ModernDTLS = true
	recorder := testopenconnect.NewCountingRecorder()
	gateway, err := testopenconnect.StartAnyConnectGateway(ctx, scenario, peer, recorder)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = gateway.Close() })
	outbound := newFakeAnyConnectOutboundWithOption(b, gateway, scenario, new(openConnectRecordingDialer), 0, func(option *OpenConnectOption) {
		option.DTLSMode = oc.DTLSModeRequire
		option.DPDInterval = 30
	})
	b.Cleanup(func() { _ = outbound.Close() })
	session, err := outbound.run(ctx)
	if err != nil {
		b.Fatal(err)
	}
	return outbound, session, recorder
}

func newAnyConnectE2EBenchmarkPacket(size int) []byte {
	if size < 24 {
		panic("AnyConnect benchmark packet must be at least 24 bytes")
	}
	packet := make([]byte, size)
	binary.BigEndian.PutUint32(packet[0:4], openConnectE2EBenchmarkMagic)
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
	if len(packet) < 24 || binary.BigEndian.Uint32(packet[0:4]) != openConnectE2EBenchmarkMagic {
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
