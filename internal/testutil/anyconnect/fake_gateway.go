package anyconnect

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
)

const (
	fakeGatewayServerName = "localhost"
	fakeGatewayTimeout    = 5 * time.Second
)

// Gateway is a hermetic TLS/CSTP server used only by protocol tests.
type Gateway struct {
	scenario     Scenario
	peer         PacketPeer
	recorder     *Recorder
	listener     net.Listener
	dtlsListener net.Listener
	roots        *x509.CertPool
	ctx          context.Context

	cancel               context.CancelFunc
	waitGroup            sync.WaitGroup
	closeOnce            sync.Once
	closeErr             error
	errorLock            sync.Mutex
	errors               []error
	connLock             sync.Mutex
	conns                map[net.Conn]struct{}
	pskLock              sync.RWMutex
	psk                  []byte
	dtlsOwnerActive      bool
	authLock             sync.Mutex
	authGeneration       uint64
	authChallengePending bool
	activeCookie         string
	activeCookieUses     int
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
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		return nil, fmt.Errorf("listen for fake gateway: %w", err)
	}
	ctx, cancel := context.WithCancel(parent)
	gateway := &Gateway{
		scenario: cloneScenario(scenario),
		peer:     peer,
		recorder: recorder,
		listener: listener,
		roots:    roots,
		ctx:      ctx,
		cancel:   cancel,
		conns:    make(map[net.Conn]struct{}),
	}
	if scenario.ModernDTLS {
		gateway.dtlsListener, err = dtls.ListenWithOptions("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
			dtls.WithPSK(gateway.dtlsPSK),
			dtls.WithPSKIdentityHint([]byte("psk")),
			dtls.WithCipherSuites(
				dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
				dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
				dtls.TLS_PSK_WITH_AES_128_CCM,
			),
		)
		if err != nil {
			cancel()
			_ = listener.Close()
			return nil, fmt.Errorf("configure fake DTLS gateway: %w", err)
		}
	}
	gateway.waitGroup.Add(2)
	go gateway.acceptLoop()
	if gateway.dtlsListener != nil {
		gateway.waitGroup.Add(1)
		go gateway.acceptDTLSLoop()
	}
	go func() {
		defer gateway.waitGroup.Done()
		<-ctx.Done()
		_ = listener.Close()
		if gateway.dtlsListener != nil {
			_ = gateway.dtlsListener.Close()
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
			if handleErr := g.handleConnection(connection); handleErr != nil {
				g.addError(handleErr)
			}
		}()
	}
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
	if g.scenario.ModernDTLS {
		tlsConnection, ok := connection.(*tls.Conn)
		if !ok {
			return errors.New("fake CSTP connection is not TLS")
		}
		connectionState := tlsConnection.ConnectionState()
		psk, exportErr := connectionState.ExportKeyingMaterial("EXPORTER-openconnect-psk", nil, 32)
		if exportErr != nil {
			return fmt.Errorf("export fake DTLS PSK: %w", exportErr)
		}
		if !g.claimDTLSSession(psk) {
			return writeHTTPRejection(connection, http.StatusConflict)
		}
		defer g.releaseDTLSSession()
	}
	if err := g.writeConnectResponse(connection); err != nil {
		return err
	}
	g.record("cstp-connect", "accepted")
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear fake gateway connection deadline: %w", err)
	}
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
			reply, peerErr := g.peer.HandlePacket(frame.payload)
			if peerErr != nil {
				return fmt.Errorf("handle tunneled packet: %w", peerErr)
			}
			if g.scenario.CSTP.MalformedDataHeader {
				malformed := append([]byte("BAD!\x00\x00\x00\x00"), reply...)
				return writeFull(connection, malformed)
			}
			if writeErr := writeCSTPFrame(connection, cstpPacketData, reply); writeErr != nil {
				return writeErr
			}
			g.record("cstp-data", fmt.Sprintf("replied with %d-byte packet", len(reply)))
		case cstpPacketDPDRequest:
			if writeErr := writeCSTPFrame(connection, cstpPacketDPDResponse, frame.payload); writeErr != nil {
				return writeErr
			}
		case cstpPacketKeepalive:
			continue
		case cstpPacketDisconnect:
			return nil
		default:
			return fmt.Errorf("unexpected CSTP packet type: %d", frame.packetType)
		}
	}
}

func (g *Gateway) writeConnectResponse(connection net.Conn) error {
	configuration := g.scenario.Configuration
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
	if g.scenario.ModernDTLS {
		_, port, err := net.SplitHostPort(g.dtlsListener.Addr().String())
		if err != nil {
			return fmt.Errorf("parse fake DTLS port: %w", err)
		}
		response.WriteString("X-DTLS12-CipherSuite: PSK-NEGOTIATE\r\n")
		response.WriteString("X-DTLS12-Port: ")
		response.WriteString(port)
		response.WriteString("\r\nX-DTLS12-MTU: ")
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
	scenario.Configuration.Addresses = append([]netip.Prefix(nil), scenario.Configuration.Addresses...)
	scenario.Configuration.DNS = append([]netip.Addr(nil), scenario.Configuration.DNS...)
	return scenario
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
