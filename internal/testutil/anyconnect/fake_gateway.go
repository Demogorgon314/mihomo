package anyconnect

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3"
)

const (
	fakeGatewayServerName = "localhost"
	fakeGatewayTimeout    = 5 * time.Second
)

// Gateway is a hermetic TLS/CSTP server used only by protocol tests.
type Gateway struct {
	scenario       Scenario
	peer           PacketPeer
	recorder       *Recorder
	listener       net.Listener
	dtlsListener   net.Listener
	legacyDTLSConn *net.UDPConn
	roots          *x509.CertPool
	ctx            context.Context

	cancel                  context.CancelFunc
	waitGroup               sync.WaitGroup
	closeOnce               sync.Once
	closeErr                error
	errorLock               sync.Mutex
	errors                  []error
	connLock                sync.Mutex
	conns                   map[net.Conn]struct{}
	pskLock                 sync.RWMutex
	psk                     []byte
	dtlsMasterSecret        []byte
	dtlsOwnerActive         bool
	authLock                sync.Mutex
	authGeneration          uint64
	authChallengePending    bool
	activeCookie            string
	activeCookieUses        int
	cstpLock                sync.Mutex
	cstpConnections         map[net.Conn]struct{}
	cstpDropped             map[net.Conn]struct{}
	cstpAttempts            atomic.Uint64
	dtlsConnLock            sync.Mutex
	dtlsConnections         map[net.Conn]struct{}
	dtlsDropped             map[net.Conn]struct{}
	dtlsBlackhole           atomic.Bool
	dtlsAppIDObserved       atomic.Bool
	dtlsResumeObserved      atomic.Bool
	modernDTLSPSKOffered    atomic.Bool
	legacyHandshakeObserved atomic.Bool
	legacyDTLSOffered       atomic.Bool
	legacyLock              sync.Mutex
	legacySession           *fakeLegacyDTLSSession
}

var (
	//go:embed testdata/fake_gateway/ca.pem
	fakeGatewayCAPEM []byte

	//go:embed testdata/fake_gateway/server.pem
	fakeGatewayServerPEM []byte

	//go:embed testdata/fake_gateway/server-key.pem
	fakeGatewayServerKeyPEM []byte
)

// StartGateway starts an independent fake gateway on an ephemeral loopback port.
func StartGateway(parent context.Context, scenario Scenario, peer PacketPeer, recorder *Recorder) (*Gateway, error) {
	if parent == nil {
		return nil, errors.New("gateway context is required")
	}
	if err := scenario.Validate(); err != nil {
		return nil, fmt.Errorf("validate gateway scenario: %w", err)
	}
	if peer == nil {
		return nil, errors.New("gateway packet peer is required")
	}
	serverTLS, roots, err := newFakeGatewayTLS()
	if err != nil {
		return nil, err
	}
	if len(scenario.Authentication.ClientCertificateAuthority) > 0 {
		clientRoots := x509.NewCertPool()
		if !clientRoots.AppendCertsFromPEM(scenario.Authentication.ClientCertificateAuthority) {
			return nil, errors.New("load fake gateway client certificate authority")
		}
		serverTLS.ClientAuth = tls.RequireAndVerifyClientCert
		serverTLS.ClientCAs = clientRoots
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		return nil, fmt.Errorf("listen for fake gateway: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	gateway := &Gateway{
		scenario:        cloneScenario(scenario),
		peer:            peer,
		recorder:        recorder,
		listener:        listener,
		roots:           roots,
		ctx:             ctx,
		cancel:          cancel,
		conns:           make(map[net.Conn]struct{}),
		cstpConnections: make(map[net.Conn]struct{}),
		cstpDropped:     make(map[net.Conn]struct{}),
		dtlsConnections: make(map[net.Conn]struct{}),
		dtlsDropped:     make(map[net.Conn]struct{}),
	}
	if scenario.ModernDTLS {
		dtlsOptions := []dtls.ServerOption{
			dtls.WithPSK(gateway.dtlsPSK),
			dtls.WithPSKIdentityHint([]byte("psk")),
			dtls.WithCipherSuites(
				dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
				dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
				dtls.TLS_PSK_WITH_AES_128_CCM,
			),
			dtls.WithSessionStore(gateway),
		}
		if scenario.InjectedDTLS {
			dtlsOptions = append(dtlsOptions, dtls.WithExtendedMasterSecret(dtls.DisableExtendedMasterSecret))
		}
		gateway.dtlsListener, err = dtls.ListenWithOptions("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, dtlsOptions...)
		if err != nil {
			cancel()
			_ = listener.Close()
			return nil, fmt.Errorf("configure fake DTLS gateway: %w", err)
		}
	}
	if scenario.LegacyDTLS {
		gateway.legacyDTLSConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			cancel()
			_ = listener.Close()
			return nil, fmt.Errorf("configure fake legacy DTLS gateway: %w", err)
		}
	}
	gateway.waitGroup.Add(2)
	go gateway.acceptLoop()
	if gateway.dtlsListener != nil {
		gateway.waitGroup.Add(1)
		go gateway.acceptDTLSLoop()
	}
	if gateway.legacyDTLSConn != nil {
		gateway.waitGroup.Add(1)
		go gateway.runLegacyDTLS()
	}
	go func() {
		defer gateway.waitGroup.Done()
		<-ctx.Done()
		_ = listener.Close()
		if gateway.dtlsListener != nil {
			_ = gateway.dtlsListener.Close()
		}
		if gateway.legacyDTLSConn != nil {
			_ = gateway.legacyDTLSConn.Close()
		}
	}()
	return gateway, nil
}

// Address returns the ephemeral TCP address of the gateway.
func (g *Gateway) Address() string {
	if g == nil || g.listener == nil {
		return ""
	}
	return g.listener.Addr().String()
}

// DropCSTPConnections forces an established-tunnel EOF and returns the number closed.
func (g *Gateway) DropCSTPConnections() int {
	if g == nil {
		return 0
	}
	g.cstpLock.Lock()
	connections := make([]net.Conn, 0, len(g.cstpConnections))
	for connection := range g.cstpConnections {
		connections = append(connections, connection)
		g.cstpDropped[connection] = struct{}{}
	}
	g.cstpLock.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	if len(connections) > 0 {
		g.record("cstp-eof", "dropped active CSTP connection")
	}
	return len(connections)
}

// ServerName returns the certificate name expected by the fake gateway.
func (g *Gateway) ServerName() string {
	return fakeGatewayServerName
}

// RootCAs returns a clone of the trust roots for this gateway instance.
func (g *Gateway) RootCAs() *x509.CertPool {
	if g == nil || g.roots == nil {
		return nil
	}
	return g.roots.Clone()
}

// RootCAPEM returns a caller-owned copy of the fixed fake gateway CA.
func RootCAPEM() []byte {
	return append([]byte(nil), fakeGatewayCAPEM...)
}

// ServerSPKISHA256 returns the fake gateway server's OpenConnect pin form.
func ServerSPKISHA256() (string, error) {
	block, _ := pem.Decode(fakeGatewayServerPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("decode fake gateway server certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse fake gateway server certificate: %w", err)
	}
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return fmt.Sprintf("sha256:%x", digest), nil
}

// Close stops the listener, waits for handlers, and returns unexpected server failures.
func (g *Gateway) Close() error {
	if g == nil {
		return nil
	}
	g.closeOnce.Do(func() {
		g.cancel()
		listenerErr := g.listener.Close()
		if listenerErr != nil && !errors.Is(listenerErr, net.ErrClosed) {
			g.closeErr = fmt.Errorf("close fake gateway listener: %w", listenerErr)
		}
		if g.dtlsListener != nil {
			dtlsListenerErr := g.dtlsListener.Close()
			if dtlsListenerErr != nil && !errors.Is(dtlsListenerErr, net.ErrClosed) {
				g.closeErr = errors.Join(g.closeErr, fmt.Errorf("close fake DTLS listener: %w", dtlsListenerErr))
			}
		}
		if g.legacyDTLSConn != nil {
			legacyErr := g.legacyDTLSConn.Close()
			if legacyErr != nil && !errors.Is(legacyErr, net.ErrClosed) {
				g.closeErr = errors.Join(g.closeErr, fmt.Errorf("close fake legacy DTLS listener: %w", legacyErr))
			}
		}
		g.connLock.Lock()
		connections := make([]net.Conn, 0, len(g.conns))
		for connection := range g.conns {
			connections = append(connections, connection)
		}
		g.connLock.Unlock()
		for _, connection := range connections {
			_ = connection.Close()
		}
		g.waitGroup.Wait()
		g.errorLock.Lock()
		g.closeErr = errors.Join(append([]error{g.closeErr}, g.errors...)...)
		g.errorLock.Unlock()
	})
	return g.closeErr
}

func (g *Gateway) acceptLoop() {
	defer g.waitGroup.Done()
	for {
		connection, err := g.listener.Accept()
		if err != nil {
			if g.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				g.addError(fmt.Errorf("accept fake gateway connection: %w", err))
			}
			return
		}
		g.connLock.Lock()
		g.conns[connection] = struct{}{}
		g.connLock.Unlock()
		g.waitGroup.Add(1)
		go func() {
			defer g.waitGroup.Done()
			defer func() {
				g.connLock.Lock()
				delete(g.conns, connection)
				g.connLock.Unlock()
			}()
			defer connection.Close()
			handleErr := g.handleConnection(connection)
			expectedClose := g.consumeDroppedCSTPConnection(connection)
			if handleErr != nil && !expectedClose && !errors.Is(handleErr, net.ErrClosed) {
				g.addError(handleErr)
			}
		}()
	}
}

func (g *Gateway) consumeDroppedCSTPConnection(connection net.Conn) bool {
	g.cstpLock.Lock()
	_, dropped := g.cstpDropped[connection]
	delete(g.cstpDropped, connection)
	g.cstpLock.Unlock()
	return dropped
}

func (g *Gateway) handleConnection(connection net.Conn) error {
	if err := connection.SetDeadline(time.Now().Add(fakeGatewayTimeout)); err != nil {
		return fmt.Errorf("set fake gateway connection deadline: %w", err)
	}
	reader := bufio.NewReader(connection)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return fmt.Errorf("read fake CSTP CONNECT request: %w", err)
	}
	if request.Body != nil {
		defer request.Body.Close()
	}
	if request.Method == http.MethodPost {
		return g.handleAuthRequest(connection, request)
	}
	if request.Method != http.MethodConnect || request.URL.Path != "/CSCOSSLC/tunnel" {
		return fmt.Errorf("unexpected CSTP request: %s %s", request.Method, request.URL.Path)
	}
	cookie, cookieErr := request.Cookie("webvpn")
	if cookieErr != nil || !g.consumeTunnelCookie(cookie.Value) {
		g.record("cstp-auth", "rejected CONNECT cookie")
		return writeHTTPRejection(connection, http.StatusUnauthorized)
	}
	if g.scenario.CSTP.RejectStatus != 0 {
		g.record("cstp-connect", fmt.Sprintf("rejected with HTTP %d", g.scenario.CSTP.RejectStatus))
		return writeHTTPRejection(connection, g.scenario.CSTP.RejectStatus)
	}
	if g.scenario.ModernDTLS || g.scenario.LegacyDTLS {
		if strings.Contains(request.Header.Get("X-DTLS-CipherSuite"), "PSK-NEGOTIATE") {
			g.modernDTLSPSKOffered.Store(true)
		}
		if strings.Contains(request.Header.Get("X-DTLS-CipherSuite"), "AES128-SHA") {
			g.legacyDTLSOffered.Store(true)
		}
		tlsConnection, ok := connection.(*tls.Conn)
		if !ok {
			return errors.New("fake CSTP connection is not TLS")
		}
		var psk []byte
		if g.scenario.ModernDTLS {
			connectionState := tlsConnection.ConnectionState()
			exportedPSK, exportErr := connectionState.ExportKeyingMaterial("EXPORTER-openconnect-psk", nil, 32)
			if exportErr != nil {
				return fmt.Errorf("export fake DTLS PSK: %w", exportErr)
			}
			psk = exportedPSK
		}
		var masterSecret []byte
		if masterSecretHeader := request.Header.Get("X-DTLS-Master-Secret"); masterSecretHeader != "" {
			decodedMasterSecret, decodeErr := hex.DecodeString(masterSecretHeader)
			masterSecret = decodedMasterSecret
			if decodeErr != nil || len(masterSecret) != 48 {
				return errors.New("fake CSTP request did not contain a valid DTLS master secret")
			}
		} else if g.scenario.InjectedDTLS || g.scenario.LegacyDTLS {
			return errors.New("injected DTLS request did not contain a master secret")
		}
		if !g.claimDTLSSession(psk, masterSecret) {
			return writeHTTPRejection(connection, http.StatusConflict)
		}
		defer g.releaseDTLSSession()
	}
	if delay := g.scenario.CSTP.ResponseDelay; delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-g.ctx.Done():
			return nil
		}
	}
	configuration := g.scenario.Configuration
	cstpAttempt := g.cstpAttempts.Add(1)
	if cstpAttempt > 1 && g.scenario.CSTP.ReconnectConfiguration != nil {
		configuration = *g.scenario.CSTP.ReconnectConfiguration
	}
	if err := g.writeConnectResponse(connection, configuration); err != nil {
		return err
	}
	g.cstpLock.Lock()
	g.cstpConnections[connection] = struct{}{}
	g.cstpLock.Unlock()
	defer func() {
		g.cstpLock.Lock()
		delete(g.cstpConnections, connection)
		g.cstpLock.Unlock()
	}()
	g.record("cstp-connect", "accepted")
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear fake gateway connection deadline: %w", err)
	}
	compressedFaultsSent := false
	for {
		frame, frameErr := readCSTPFrame(reader, cstpMaximumPayloadSize)
		if frameErr != nil {
			if errors.Is(frameErr, net.ErrClosed) || errors.Is(frameErr, context.Canceled) || errors.Is(frameErr, io.EOF) {
				return nil
			}
			return frameErr
		}
		switch frame.packetType {
		case cstpPacketData:
			if !compressedFaultsSent {
				for _, payload := range g.scenario.CSTP.CompressedPackets {
					if writeErr := writeCSTPFrame(connection, cstpPacketCompressed, payload); writeErr != nil {
						return writeErr
					}
				}
				compressedFaultsSent = true
			}
			replies, peerErr := handlePeerPackets(g.peer, frame.payload)
			if peerErr != nil {
				return fmt.Errorf("handle tunneled packet: %w", peerErr)
			}
			for _, reply := range replies {
				if g.scenario.CSTP.MalformedDataHeader {
					malformed := append([]byte("BAD!\x00\x00\x00\x00"), reply...)
					return writeFull(connection, malformed)
				}
				if writeErr := writeCSTPFrame(connection, cstpPacketData, reply); writeErr != nil {
					return writeErr
				}
				g.record("cstp-data", fmt.Sprintf("replied with %d-byte packet", len(reply)))
			}
		case cstpPacketDPDRequest:
			if g.scenario.CSTP.BlackholeDPD && cstpAttempt == 1 {
				g.record("cstp-dpd-blackhole", "ignored dead-peer probe")
				continue
			}
			g.record("cstp-dpd", "answered dead-peer probe")
			if writeErr := writeCSTPFrame(connection, cstpPacketDPDResponse, frame.payload); writeErr != nil {
				return writeErr
			}
		case cstpPacketCompressed:
			g.record("cstp-compressed", g.scenario.Compression)
		case cstpPacketKeepalive:
			continue
		case cstpPacketDisconnect:
			return nil
		default:
			return fmt.Errorf("unexpected CSTP packet type: %d", frame.packetType)
		}
	}
}

func (g *Gateway) writeConnectResponse(connection net.Conn, configuration NetworkConfiguration) error {
	var response strings.Builder
	response.WriteString("HTTP/1.1 200 CONNECTED\r\n")
	response.WriteString("X-CSTP-Version: 1\r\n")
	response.WriteString("X-CSTP-MTU: ")
	response.WriteString(strconv.Itoa(int(configuration.MTU)))
	response.WriteString("\r\n")
	for _, prefix := range configuration.Addresses {
		if prefix.Addr().Is4() {
			response.WriteString("X-CSTP-Address: ")
			response.WriteString(prefix.Addr().String())
			response.WriteString("\r\nX-CSTP-Netmask: ")
			response.WriteString(net.IP(net.CIDRMask(prefix.Bits(), 32)).String())
			response.WriteString("\r\n")
		} else {
			response.WriteString("X-CSTP-Address-IP6: ")
			response.WriteString(prefix.String())
			response.WriteString("\r\n")
		}
	}
	for _, address := range configuration.DNS {
		if address.Is4() {
			response.WriteString("X-CSTP-DNS: ")
		} else {
			response.WriteString("X-CSTP-DNS-IP6: ")
		}
		response.WriteString(address.String())
		response.WriteString("\r\n")
	}
	for _, prefix := range configuration.Routes {
		if prefix.Addr().Is4() {
			response.WriteString("X-CSTP-Split-Include: ")
		} else {
			response.WriteString("X-CSTP-Split-Include-IP6: ")
		}
		response.WriteString(prefix.String())
		response.WriteString("\r\n")
	}
	for _, prefix := range configuration.ExcludedRoutes {
		if prefix.Addr().Is4() {
			response.WriteString("X-CSTP-Split-Exclude: ")
		} else {
			response.WriteString("X-CSTP-Split-Exclude-IP6: ")
		}
		response.WriteString(prefix.String())
		response.WriteString("\r\n")
	}
	for _, domain := range configuration.SearchDomains {
		response.WriteString("X-CSTP-Default-Domain: ")
		response.WriteString(domain)
		response.WriteString("\r\n")
	}
	for _, domain := range configuration.SplitDNS {
		response.WriteString("X-CSTP-Split-DNS: ")
		response.WriteString(domain)
		response.WriteString("\r\n")
	}
	if configuration.Banner != "" {
		response.WriteString("X-CSTP-Banner: ")
		response.WriteString(configuration.Banner)
		response.WriteString("\r\n")
	}
	if configuration.TunnelAllDNS {
		response.WriteString("X-CSTP-Tunnel-All-DNS: true\r\n")
	}
	if g.scenario.Compression != "" {
		response.WriteString("X-CSTP-Content-Encoding: ")
		response.WriteString(g.scenario.Compression)
		response.WriteString("\r\n")
	}
	if g.scenario.CSTP.RekeyInterval > 0 {
		response.WriteString("X-CSTP-Rekey-Time: ")
		response.WriteString(strconv.FormatInt(int64(g.scenario.CSTP.RekeyInterval/time.Second), 10))
		response.WriteString("\r\nX-CSTP-Rekey-Method: new-tunnel\r\n")
	}
	if g.scenario.ModernDTLS {
		_, port, err := net.SplitHostPort(g.dtlsListener.Addr().String())
		if err != nil {
			return fmt.Errorf("parse fake DTLS port: %w", err)
		}
		if g.scenario.InjectedDTLS {
			response.WriteString("X-DTLS12-CipherSuite: OC2-DTLS1_2-CHACHA20-POLY1305\r\nX-DTLS12-Session-ID: ")
			response.WriteString(hex.EncodeToString(fakeDTLSSessionID()))
			response.WriteString("\r\n")
		} else {
			response.WriteString("X-DTLS12-CipherSuite: PSK-NEGOTIATE\r\n")
		}
		response.WriteString("X-DTLS12-Port: ")
		response.WriteString(port)
		response.WriteString("\r\nX-DTLS12-MTU: ")
		dtlsMTU := configuration.MTU
		if g.scenario.DTLSMTU != 0 {
			dtlsMTU = g.scenario.DTLSMTU
		}
		response.WriteString(strconv.Itoa(int(dtlsMTU)))
		if len(g.scenario.DTLSAppID) > 0 {
			response.WriteString("\r\nX-DTLS-App-ID: ")
			response.WriteString(hex.EncodeToString(g.scenario.DTLSAppID))
		}
		response.WriteString("\r\n")
	} else if g.scenario.LegacyDTLS {
		_, port, err := net.SplitHostPort(g.legacyDTLSConn.LocalAddr().String())
		if err != nil {
			return fmt.Errorf("parse fake legacy DTLS port: %w", err)
		}
		response.WriteString("X-DTLS-CipherSuite: AES128-SHA\r\nX-DTLS-Session-ID: ")
		response.WriteString(hex.EncodeToString(fakeDTLSSessionID()))
		response.WriteString("\r\nX-DTLS-Port: ")
		response.WriteString(port)
		response.WriteString("\r\nX-DTLS-MTU: ")
		response.WriteString(strconv.Itoa(int(configuration.MTU)))
		response.WriteString("\r\n")
	}
	response.WriteString("X-CSTP-Keepalive: 30\r\nX-CSTP-DPD: 30\r\n\r\n")
	content := []byte(response.String())
	chunkSize := g.scenario.CSTP.ResponseChunkSize
	if chunkSize <= 0 {
		return writeFull(connection, content)
	}
	for len(content) > 0 {
		size := chunkSize
		if size > len(content) {
			size = len(content)
		}
		if err := writeFull(connection, content[:size]); err != nil {
			return fmt.Errorf("write chunked CSTP response: %w", err)
		}
		content = content[size:]
	}
	return nil
}

func (g *Gateway) addError(err error) {
	if err == nil {
		return
	}
	g.errorLock.Lock()
	g.errors = append(g.errors, err)
	g.errorLock.Unlock()
}

func (g *Gateway) record(kind string, message string) {
	if g.recorder != nil {
		g.recorder.Add(kind, message)
	}
}

func writeHTTPRejection(writer net.Conn, status int) error {
	statusText := http.StatusText(status)
	if statusText == "" {
		statusText = "Rejected"
	}
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, statusText)
	return writeFull(writer, []byte(response))
}

func cloneScenario(scenario Scenario) Scenario {
	scenario.Configuration = cloneNetworkConfiguration(scenario.Configuration)
	scenario.DTLSAppID = append([]byte(nil), scenario.DTLSAppID...)
	if scenario.CSTP.ReconnectConfiguration != nil {
		configuration := cloneNetworkConfiguration(*scenario.CSTP.ReconnectConfiguration)
		scenario.CSTP.ReconnectConfiguration = &configuration
	}
	scenario.CSTP.CompressedPackets = make([][]byte, len(scenario.CSTP.CompressedPackets))
	for index := range scenario.CSTP.CompressedPackets {
		scenario.CSTP.CompressedPackets[index] = append([]byte(nil), scenario.CSTP.CompressedPackets[index]...)
	}
	scenario.Authentication.ChallengeResponses = append([]string(nil), scenario.Authentication.ChallengeResponses...)
	scenario.Authentication.ClientCertificateAuthority = append([]byte(nil), scenario.Authentication.ClientCertificateAuthority...)
	return scenario
}

func cloneNetworkConfiguration(configuration NetworkConfiguration) NetworkConfiguration {
	configuration.Addresses = append([]netip.Prefix(nil), configuration.Addresses...)
	configuration.Routes = append([]netip.Prefix(nil), configuration.Routes...)
	configuration.ExcludedRoutes = append([]netip.Prefix(nil), configuration.ExcludedRoutes...)
	configuration.DNS = append([]netip.Addr(nil), configuration.DNS...)
	configuration.SearchDomains = append([]string(nil), configuration.SearchDomains...)
	configuration.SplitDNS = append([]string(nil), configuration.SplitDNS...)
	return configuration
}

func newFakeGatewayTLS() (*tls.Config, *x509.CertPool, error) {
	serverCertificate, err := tls.X509KeyPair(fakeGatewayServerPEM, fakeGatewayServerKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("load fake gateway server certificate: %w", err)
	}
	if len(serverCertificate.Certificate) == 0 {
		return nil, nil, errors.New("fake gateway server certificate chain is empty")
	}
	serverCertificate.Leaf, err = x509.ParseCertificate(serverCertificate.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parse fake gateway server certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(fakeGatewayCAPEM) {
		return nil, nil, errors.New("load fake gateway CA certificate")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{serverCertificate},
	}, roots, nil
}
