//go:build anyconnect_ocserv

package openconnect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"

	singopenconnect "github.com/sagernet/sing-openconnect"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	ocservImage          = "mihomo-anyconnect-ocserv:1.3.0-2"
	ocservUsername       = "test"
	ocservPassword       = "test"
	ocservBenchmarkMagic = 0x4f43424d
)

func TestOCServFixture(t *testing.T) {
	if os.Getenv("MIHOMO_ANYCONNECT_OCSERV") != "1" {
		t.Fatal("anyconnect_ocserv tag requires MIHOMO_ANYCONNECT_OCSERV=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	fixture := startOCServFixture(t, ctx)
	testOCServCoreDriver(t, ctx, fixture.tcpAddress, fixture.udpAddress, fixture.roots)
	testOCServOutboundDriver(t, ctx, fixture.containerID, fixture.tcpAddress, fixture.udpAddress, fixture.roots, fixture.certificatePEM)
	for _, capability := range []Capability{CapabilityModernDTLS, CapabilityPacketIPv4} {
		if err := capabilityMatrix.Record(Evidence{
			Capability: capability,
			Scenario:   "username-password-modern-dtls",
			Driver:     DriverCore,
			Gateway:    "ocserv-1.3.0-2",
			Transport:  singopenconnect.TransportDTLS,
			Address:    "ipv4",
			Passed:     true,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkOCServAnyConnectDataPlaneE2E(b *testing.B) {
	if os.Getenv("MIHOMO_ANYCONNECT_OCSERV") != "1" {
		b.Fatal("anyconnect_ocserv tag requires MIHOMO_ANYCONNECT_OCSERV=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	fixture := startOCServFixtureWithOptions(b, ctx, ocservFixtureOptions{
		compression: false,
		dtlsPSK:     false,
		// ocserv groups Cisco's DTLS 1.2 injected-resumption protocol under
		// this server-side compatibility switch. The client still rejects DTLS 0.9.
		dtlsLegacy: true,
	})
	cookie, err := RunAnyConnectAuthProbe(ctx, AnyConnectAuthProbeOptions{
		Address:    fixture.tcpAddress,
		ServerName: fakeGatewayServerName,
		RootCAs:    fixture.roots,
		Username:   ocservUsername,
		Password:   ocservPassword,
	})
	if err != nil {
		b.Fatal(err)
	}
	_, port, err := net.SplitHostPort(fixture.tcpAddress)
	if err != nil {
		b.Fatal(err)
	}
	proxy, err := adapter.ParseProxy(map[string]any{
		"name":              "ocserv-anyconnect-benchmark",
		"type":              "openconnect",
		"server":            fakeGatewayServerName,
		"port":              port,
		"cookie":            cookie,
		"ca":                string(fixture.certificatePEM),
		"server-name":       fakeGatewayServerName,
		"dtls-mode":         "auto",
		"dtls-key-exchange": "resumption",
		"compression":       "off",
		"ipv6-disabled":     true,
	}, adapter.WithDialerForAPI(&ocservOutboundDialer{tcpAddress: fixture.tcpAddress, udpAddress: fixture.udpAddress}))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = proxy.Close() })
	target := netip.MustParseAddr("192.168.77.1")
	for _, payloadSize := range []int{128, 512, 1200, 1372, 16 * 1024, 64 * 1024} {
		b.Run(fmt.Sprintf("%dB", payloadSize), func(b *testing.B) {
			connection, dialErr := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: target, DstPort: 18080})
			if dialErr != nil {
				b.Fatal(dialErr)
			}
			defer connection.Close()
			waitForOCServBenchmarkDTLS(b, ctx, fixture.containerID)
			if deadline, loaded := ctx.Deadline(); loaded {
				if err = connection.SetDeadline(deadline); err != nil {
					b.Fatal(err)
				}
			}
			packet := newOCServBenchmarkPacket(payloadSize)
			readDone := make(chan error, 1)
			go func() {
				reply := make([]byte, payloadSize)
				for expected := 0; expected < b.N; expected++ {
					if _, readErr := io.ReadFull(connection, reply); readErr != nil {
						readDone <- fmt.Errorf("read packet %d: %w", expected, readErr)
						return
					}
					sequence, validateErr := validateOCServBenchmarkPacket(reply)
					if validateErr != nil {
						readDone <- validateErr
						return
					}
					if sequence != uint64(expected) {
						readDone <- fmt.Errorf("out-of-order packet: got %d, want %d", sequence, expected)
						return
					}
				}
				readDone <- nil
			}()
			b.ReportAllocs()
			b.SetBytes(int64(payloadSize))
			b.ResetTimer()
			for sequence := 0; sequence < b.N; sequence++ {
				setOCServBenchmarkSequence(packet, uint64(sequence))
				if writeErr := writeOCServBenchmarkPacket(connection, packet); writeErr != nil {
					b.StopTimer()
					_ = connection.Close()
					<-readDone
					b.Fatalf("write packet %d: %v", sequence, writeErr)
				}
			}
			readErr := <-readDone
			b.StopTimer()
			if readErr != nil {
				b.Fatal(readErr)
			}
		})
	}
}

func waitForOCServBenchmarkDTLS(t testing.TB, ctx context.Context, containerID string) {
	t.Helper()
	waitContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var latest string
	for {
		output, err := dockerOutput(waitContext, "logs", containerID)
		if err == nil {
			latest = output
			aes256GCM := strings.Contains(output, "DTLS ciphersuite: OC-DTLS1_2-AES256-GCM") ||
				strings.Contains(output, "DTLS ciphersuite: ECDHE-RSA-AES256-GCM-SHA384")
			if aes256GCM &&
				strings.Contains(output, "Main DTLS session 1 active") {
				return
			}
		} else {
			latest = err.Error()
		}
		select {
		case <-waitContext.Done():
			t.Fatalf("ocserv did not activate the production AES-256-GCM DTLS data plane:\n%s", latest)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func newOCServBenchmarkPacket(size int) []byte {
	packet := make([]byte, size)
	binary.BigEndian.PutUint32(packet[0:4], ocservBenchmarkMagic)
	binary.BigEndian.PutUint32(packet[4:8], uint32(size))
	for index := 24; index < size; index++ {
		packet[index] = byte(index*31 + 17)
	}
	return packet
}

func setOCServBenchmarkSequence(packet []byte, sequence uint64) {
	binary.BigEndian.PutUint64(packet[8:16], sequence)
	binary.BigEndian.PutUint64(packet[16:24], ^sequence)
}

func validateOCServBenchmarkPacket(packet []byte) (uint64, error) {
	if len(packet) < 24 || binary.BigEndian.Uint32(packet[0:4]) != ocservBenchmarkMagic {
		return 0, errors.New("invalid ocserv benchmark packet header")
	}
	if int(binary.BigEndian.Uint32(packet[4:8])) != len(packet) {
		return 0, fmt.Errorf("ocserv benchmark packet length mismatch: header=%d actual=%d", binary.BigEndian.Uint32(packet[4:8]), len(packet))
	}
	sequence := binary.BigEndian.Uint64(packet[8:16])
	if binary.BigEndian.Uint64(packet[16:24]) != ^sequence {
		return 0, fmt.Errorf("ocserv benchmark sequence canary changed at packet %d", sequence)
	}
	for index := 24; index < len(packet); index++ {
		if packet[index] != byte(index*31+17) {
			return 0, fmt.Errorf("ocserv benchmark payload changed at packet %d offset %d", sequence, index)
		}
	}
	return sequence, nil
}

func writeOCServBenchmarkPacket(connection net.Conn, packet []byte) error {
	for len(packet) > 0 {
		written, err := connection.Write(packet)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		packet = packet[written:]
	}
	return nil
}

type ocservFixture struct {
	containerID    string
	tcpAddress     string
	udpAddress     string
	roots          *x509.CertPool
	certificatePEM []byte
}

type ocservFixtureOptions struct {
	compression bool
	dtlsPSK     bool
	dtlsLegacy  bool
}

func startOCServFixture(t testing.TB, ctx context.Context) ocservFixture {
	return startOCServFixtureWithOptions(t, ctx, ocservFixtureOptions{
		compression: true,
		dtlsPSK:     true,
	})
}

func startOCServFixtureWithOptions(t testing.TB, ctx context.Context, options ocservFixtureOptions) ocservFixture {
	t.Helper()
	fixtureDirectory := t.TempDir()
	roots, certificatePEM := writeOCServFixture(t, fixtureDirectory, options)
	runDocker(t, ctx, "build", "--pull=false", "--tag", ocservImage, filepath.Join("testdata", "ocserv"))
	containerID := strings.TrimSpace(runDocker(t, ctx,
		"run", "--detach", "--rm",
		"--cap-add", "NET_ADMIN",
		"--device", "/dev/net/tun",
		"--mount", "type=bind,src="+fixtureDirectory+",dst=/fixture,readonly",
		"--publish", "127.0.0.1::443/tcp",
		"--publish", "127.0.0.1::443/udp",
		ocservImage,
	))
	if containerID == "" {
		t.Fatal("docker run returned an empty ocserv container ID")
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupContext, "docker", "rm", "--force", containerID).Run()
	})
	tcpAddress := waitForOCServAddress(t, ctx, containerID, "443/tcp", true)
	udpAddress := waitForOCServAddress(t, ctx, containerID, "443/udp", false)
	dialer := tls.Dialer{Config: &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: fakeGatewayServerName,
		RootCAs:    roots,
	}}
	var connection net.Conn
	var err error
	readyContext, readyCancel := context.WithTimeout(ctx, 15*time.Second)
	defer readyCancel()
	for {
		connection, err = dialer.DialContext(readyContext, "tcp", tcpAddress)
		if err == nil {
			break
		}
		select {
		case <-readyContext.Done():
			logs := runDocker(t, ctx, "logs", containerID)
			t.Fatalf("verify ocserv TLS listener: %v\n%s", err, logs)
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	return ocservFixture{
		containerID:    containerID,
		tcpAddress:     tcpAddress,
		udpAddress:     udpAddress,
		roots:          roots,
		certificatePEM: certificatePEM,
	}
}

func writeOCServFixture(t testing.TB, directory string, options ocservFixtureOptions) (*x509.CertPool, []byte) {
	t.Helper()
	certificatePEM, keyPEM, roots := newOCServCertificate(t)
	configuration := `auth = "plain[passwd=/fixture/ocpasswd]"

tcp-port = 443
udp-port = 443
run-as-user = nobody
run-as-group = nogroup
socket-file = /run/ocserv-socket
server-cert = /fixture/server-cert.pem
server-key = /fixture/server-key.pem
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT"
isolate-workers = false
max-clients = 4
max-same-clients = 2
rate-limit-ms = 0
auth-timeout = 30
cookie-timeout = 300
keepalive = 60
dpd = 30
try-mtu-discovery = false
device = vpns
ipv4-network = 192.168.77.0
ipv4-netmask = 255.255.255.0
route = 192.168.77.0/255.255.255.0
ping-leases = false
mtu = 1400
cisco-client-compat = false
dtls-psk = true
dtls-legacy = false
match-tls-dtls-ciphers = false
compression = true
compression-algo-priority = lzs:1000
no-compress-limit = 64
`
	if !options.compression {
		configuration = strings.Replace(configuration, "compression = true", "compression = false", 1)
	}
	configuration = strings.Replace(configuration, "dtls-psk = true", fmt.Sprintf("dtls-psk = %t", options.dtlsPSK), 1)
	configuration = strings.Replace(configuration, "dtls-legacy = false", fmt.Sprintf("dtls-legacy = %t", options.dtlsLegacy), 1)
	files := map[string][]byte{
		"ocserv.conf":     []byte(configuration),
		"ocpasswd":        []byte("test:users:$5$i6SNmLDCgBNjyJ7q$SZ4bVJb7I/DLgXo3txHBVohRFBjOtdbxGQZp.DOnrA.\n"),
		"server-cert.pem": certificatePEM,
		"server-key.pem":  keyPEM,
	}
	for name, content := range files {
		mode := os.FileMode(0o600)
		if name == "ocserv.conf" {
			mode = 0o644
		}
		if err := os.WriteFile(filepath.Join(directory, name), content, mode); err != nil {
			t.Fatalf("write ocserv fixture %s: %v", name, err)
		}
	}
	return roots, append([]byte(nil), certificatePEM...)
}

func newOCServCertificate(t testing.TB) ([]byte, []byte, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mihomo ocserv test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: fakeGatewayServerName},
		DNSNames:     []string{fakeGatewayServerName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCertificate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	certificatePEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...,
	)
	return certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), roots
}

func waitForOCServAddress(t testing.TB, ctx context.Context, containerID string, port string, waitForTCP bool) string {
	t.Helper()
	for {
		output, err := dockerOutput(ctx, "port", containerID, port)
		if err == nil {
			address := strings.TrimSpace(output)
			if _, _, splitErr := net.SplitHostPort(address); splitErr == nil {
				if !waitForTCP {
					return address
				}
				connection, dialErr := net.DialTimeout("tcp", address, 250*time.Millisecond)
				if dialErr == nil {
					_ = connection.Close()
					return address
				}
			}
		}
		select {
		case <-ctx.Done():
			logs, _ := dockerOutput(context.Background(), "logs", containerID)
			t.Fatalf("wait for ocserv listener: %v\n%s", ctx.Err(), logs)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type ocservDTLSDialer struct {
	udpDestination M.Socksaddr
}

type ocservOutboundDialer struct {
	tcpAddress string
	udpAddress string
}

func (d *ocservOutboundDialer) DialContext(ctx context.Context, network string, _ string) (net.Conn, error) {
	address := d.tcpAddress
	if network == N.NetworkUDP {
		address = d.udpAddress
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (d *ocservOutboundDialer) ListenPacket(ctx context.Context, network string, address string, _ netip.AddrPort) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, network, address)
}

func (d *ocservDTLSDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network == N.NetworkUDP {
		destination = d.udpDestination
	}
	return N.SystemDialer.DialContext(ctx, network, destination)
}

func (d *ocservDTLSDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

func testOCServCoreDriver(t *testing.T, ctx context.Context, tcpAddress string, udpAddress string, roots *x509.CertPool) {
	t.Helper()
	_, tcpPort, err := net.SplitHostPort(tcpAddress)
	if err != nil {
		t.Fatal(err)
	}
	configurationEvents := make(chan singopenconnect.TunnelConfigurationEvent, 1)
	client, err := singopenconnect.NewClient(singopenconnect.ClientOptions{
		Context:  ctx,
		Server:   "https://" + fakeGatewayServerName + ":" + tcpPort,
		Username: ocservUsername,
		Password: ocservPassword,
		Dialer:   &ocservDTLSDialer{udpDestination: M.ParseSocksaddr(udpAddress)},
		TLSConfig: singopenconnect.ClientTLSOptions{Config: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: fakeGatewayServerName,
			RootCAs:    roots,
		}},
		OnTunnelConfiguration: func(event singopenconnect.TunnelConfigurationEvent) error {
			select {
			case configurationEvents <- event:
			default:
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	activeTransportUpdated := client.ActiveTransportUpdated()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	var configuration singopenconnect.TunnelConfiguration
	select {
	case event := <-configurationEvents:
		configuration = event.Configuration
	case <-ctx.Done():
		t.Fatalf("wait for ocserv configuration: %v", ctx.Err())
	}
	for client.ActiveTransport() != singopenconnect.TransportDTLS {
		select {
		case <-activeTransportUpdated:
			activeTransportUpdated = client.ActiveTransportUpdated()
		case <-ctx.Done():
			t.Fatalf("wait for ocserv DTLS: %v", ctx.Err())
		}
	}
	var clientAddress netip.Addr
	for _, prefix := range configuration.Addresses {
		if prefix.Addr().Is4() {
			clientAddress = prefix.Addr()
			break
		}
	}
	if !clientAddress.IsValid() {
		t.Fatalf("ocserv did not assign an IPv4 address: %#v", configuration.Addresses)
	}
	request, err := BuildIPv4ICMPEchoRequest(clientAddress, netip.MustParseAddr("192.168.77.1"), 23, 29, []byte("mihomo-ocserv-dtls"))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteDataPacket(request); err != nil {
		t.Fatal(err)
	}
	readContext, cancelRead := context.WithTimeout(ctx, 10*time.Second)
	defer cancelRead()
	for {
		reply, readErr := client.ReadDataPacket(readContext)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if len(reply) >= 28 && reply[20] == 0 && string(reply[28:]) == "mihomo-ocserv-dtls" {
			break
		}
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func testOCServOutboundDriver(t *testing.T, ctx context.Context, containerID string, tcpAddress string, udpAddress string, roots *x509.CertPool, certificatePEM []byte) {
	t.Helper()
	cookie, err := RunAnyConnectAuthProbe(ctx, AnyConnectAuthProbeOptions{
		Address:    tcpAddress,
		ServerName: fakeGatewayServerName,
		RootCAs:    roots,
		Username:   ocservUsername,
		Password:   ocservPassword,
	})
	if err != nil {
		t.Fatalf("obtain ocserv cookie for outbound: %v", err)
	}
	_, port, err := net.SplitHostPort(tcpAddress)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := adapter.ParseProxy(map[string]any{
		"name":        "ocserv-anyconnect",
		"type":        "openconnect",
		"server":      fakeGatewayServerName,
		"port":        port,
		"cookie":      cookie,
		"ca":          string(certificatePEM),
		"server-name": fakeGatewayServerName,
		"dtls-mode":   "off",
		"compression": "stateless",
	}, adapter.WithDialerForAPI(&ocservOutboundDialer{tcpAddress: tcpAddress, udpAddress: udpAddress}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })

	target := netip.MustParseAddr("192.168.77.1")
	tcpConnection, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: target, DstPort: 18080})
	if err != nil {
		logs, _ := dockerOutput(ctx, "logs", containerID)
		t.Fatalf("dial ocserv TCP echo through outbound: %v\n%s", err, logs)
	}
	tcpPayload := []byte(strings.Repeat("mihomo-ocserv-outbound-compression-", 24))
	if _, err := tcpConnection.Write(tcpPayload); err != nil {
		t.Fatal(err)
	}
	tcpReply := make([]byte, len(tcpPayload))
	if _, err := io.ReadFull(tcpConnection, tcpReply); err != nil {
		t.Fatal(err)
	}
	if string(tcpReply) != string(tcpPayload) {
		t.Fatalf("unexpected ocserv TCP echo: %q", tcpReply)
	}
	waitForOCServCSTPCompression(t, ctx, containerID, "lzs")
	if err := tcpConnection.Close(); err != nil {
		t.Fatal(err)
	}

	udpConnection, err := proxy.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: target, DstPort: 15353})
	if err != nil {
		t.Fatalf("dial ocserv UDP echo through outbound: %v", err)
	}
	udpPayload := []byte("mihomo-ocserv-outbound-udp")
	udpTarget := &net.UDPAddr{IP: target.AsSlice(), Port: 15353}
	if _, err := udpConnection.WriteTo(udpPayload, udpTarget); err != nil {
		t.Fatal(err)
	}
	udpReply := make([]byte, 128)
	count, _, err := udpConnection.ReadFrom(udpReply)
	if err != nil {
		t.Fatal(err)
	}
	if string(udpReply[:count]) != string(udpPayload) {
		t.Fatalf("unexpected ocserv UDP echo: %q", udpReply[:count])
	}
	if err := udpConnection.Close(); err != nil {
		t.Fatal(err)
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	testOCServDTLSOutbound(t, ctx, tcpAddress, udpAddress, port, roots, certificatePEM, target)
	authenticatedProxy, err := adapter.ParseProxy(map[string]any{
		"name":        "ocserv-anyconnect-authenticated",
		"type":        "openconnect",
		"server":      fakeGatewayServerName,
		"port":        port,
		"username":    ocservUsername,
		"password":    ocservPassword,
		"authgroup":   "users",
		"ca":          string(certificatePEM),
		"server-name": fakeGatewayServerName,
		"dtls-mode":   "off",
	}, adapter.WithDialerForAPI(&ocservOutboundDialer{tcpAddress: tcpAddress, udpAddress: udpAddress}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = authenticatedProxy.Close() }()
	authenticatedConnection, err := authenticatedProxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: target, DstPort: 18080})
	if err != nil {
		logs, _ := dockerOutput(ctx, "logs", containerID)
		t.Fatalf("authenticate ocserv outbound with username/password/authgroup: %v\n%s", err, logs)
	}
	if err := authenticatedConnection.Close(); err != nil {
		t.Fatal(err)
	}
	for _, capability := range []Capability{CapabilityCookieCSTP, CapabilityPacketIPv4, CapabilityCompression} {
		if err := capabilityMatrix.Record(Evidence{
			Capability: capability,
			Scenario:   "cookie-cstp-tcp-udp-echo",
			Driver:     DriverOutbound,
			Gateway:    "ocserv-1.3.0-2",
			Transport:  singopenconnect.TransportCSTP,
			Address:    "ipv4",
			Passed:     true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := capabilityMatrix.Record(Evidence{
		Capability: CapabilityAuth,
		Scenario:   "username-password-authgroup",
		Driver:     DriverOutbound,
		Gateway:    "ocserv-1.3.0-2",
		Transport:  singopenconnect.TransportCSTP,
		Address:    "ipv4",
		Passed:     true,
	}); err != nil {
		t.Fatal(err)
	}
}

func testOCServDTLSOutbound(t *testing.T, ctx context.Context, tcpAddress string, udpAddress string, port string, roots *x509.CertPool, certificatePEM []byte, target netip.Addr) {
	t.Helper()
	cookie, err := RunAnyConnectAuthProbe(ctx, AnyConnectAuthProbeOptions{
		Address:    tcpAddress,
		ServerName: fakeGatewayServerName,
		RootCAs:    roots,
		Username:   ocservUsername,
		Password:   ocservPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := adapter.ParseProxy(map[string]any{
		"name":        "ocserv-anyconnect-dtls",
		"type":        "openconnect",
		"server":      fakeGatewayServerName,
		"port":        port,
		"cookie":      cookie,
		"ca":          string(certificatePEM),
		"server-name": fakeGatewayServerName,
		"dtls-mode":   "require",
	}, adapter.WithDialerForAPI(&ocservOutboundDialer{tcpAddress: tcpAddress, udpAddress: udpAddress}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Close() }()
	tcpConnection, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: target, DstPort: 18080})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("mihomo-ocserv-modern-dtls-tcp")
	if _, err := tcpConnection.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(tcpConnection, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != string(payload) {
		t.Fatalf("unexpected ocserv DTLS TCP echo: %q", reply)
	}
	_ = tcpConnection.Close()
	udpConnection, err := proxy.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: target, DstPort: 15353})
	if err != nil {
		t.Fatal(err)
	}
	udpTarget := &net.UDPAddr{IP: target.AsSlice(), Port: 15353}
	if _, err := udpConnection.WriteTo([]byte("mihomo-ocserv-modern-dtls-udp"), udpTarget); err != nil {
		t.Fatal(err)
	}
	udpReply := make([]byte, 128)
	count, _, err := udpConnection.ReadFrom(udpReply)
	if err != nil {
		t.Fatal(err)
	}
	if string(udpReply[:count]) != "mihomo-ocserv-modern-dtls-udp" {
		t.Fatalf("unexpected ocserv DTLS UDP echo: %q", udpReply[:count])
	}
	_ = udpConnection.Close()
	if err := capabilityMatrix.Record(Evidence{
		Capability: CapabilityModernDTLS,
		Scenario:   "outbound-tcp-udp-modern-dtls",
		Driver:     DriverOutbound,
		Gateway:    "ocserv-1.3.0-2",
		Transport:  singopenconnect.TransportDTLS,
		Address:    "ipv4",
		Passed:     true,
	}); err != nil {
		t.Fatal(err)
	}
}

func waitForOCServCSTPCompression(t *testing.T, ctx context.Context, containerID string, algorithm string) {
	t.Helper()
	waitContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var latest string
	for {
		output, err := dockerOutput(waitContext, "logs", containerID)
		if err == nil {
			latest = output
			if strings.Contains(output, "selected CSTP compression method "+algorithm) && strings.Contains(output, "decompressed ") {
				return
			}
		} else {
			latest = err.Error()
		}
		select {
		case <-waitContext.Done():
			t.Fatalf("ocserv did not negotiate and receive outbound CSTP compression:\n%s", latest)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func runDocker(t testing.TB, ctx context.Context, arguments ...string) string {
	t.Helper()
	output, err := dockerOutput(ctx, arguments...)
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func dockerOutput(ctx context.Context, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}
