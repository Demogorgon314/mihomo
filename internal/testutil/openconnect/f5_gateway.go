package openconnect

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	testanyconnect "github.com/metacubex/mihomo/internal/testutil/anyconnect"

	"github.com/pion/dtls/v3"
)

const (
	f5PPPMagic        = 0xf500
	pppProtocolIPv4   = 0x0021
	pppProtocolLCP    = 0xc021
	pppProtocolIPCP   = 0x8021
	pppConfigureReq   = 1
	pppConfigureAck   = 2
	pppConfigureNak   = 3
	pppTerminateReq   = 5
	pppTerminateAck   = 6
	pppEchoReq        = 9
	pppEchoReply      = 10
	pppLCPOptionMRU   = 1
	pppIPCPOptionAddr = 3
)

// F5Scenario describes the minimal F5 BIG-IP behavior exercised by the
// OpenConnect integration tests.
type F5Scenario struct {
	Cookie        string
	SessionID     string
	URZ           string
	ClientAddress netip.Addr
	PeerAddress   netip.Addr
	DNS           netip.Addr
	DTLS          bool
	Username      string
	Password      string
}

// BasicF5Scenario returns an IPv4, PPP-over-TLS F5 scenario.
func BasicF5Scenario() F5Scenario {
	return F5Scenario{
		Cookie:        "f5-session",
		SessionID:     "f5-session-id",
		URZ:           "f5-urz",
		ClientAddress: netip.MustParseAddr("192.0.2.2"),
		PeerAddress:   netip.MustParseAddr("192.0.2.1"),
		DNS:           netip.MustParseAddr("192.0.2.53"),
		Username:      "f5-user",
		Password:      "f5-password",
	}
}

// F5Gateway is a hermetic F5 HTTPS and PPP-over-TLS gateway.
type F5Gateway struct {
	ctx      context.Context
	cancel   context.CancelFunc
	scenario F5Scenario
	peer     testanyconnect.PacketPeer
	server   *httptest.Server
	dtls     net.Listener
	caPEM    []byte

	tunnelCount atomic.Int64
	dtlsCount   atomic.Int64
	authCount   atomic.Int64
	connAccess  sync.Mutex
	connections map[net.Conn]struct{}
	dtlsConns   map[net.Conn]struct{}
	dtlsDropped map[net.Conn]struct{}
	errorAccess sync.Mutex
	errors      []error
	closeOnce   sync.Once
	waitGroup   sync.WaitGroup
}

// StartF5Gateway starts a hermetic F5 gateway on loopback.
func StartF5Gateway(parent context.Context, scenario F5Scenario, peer testanyconnect.PacketPeer) (*F5Gateway, error) {
	if parent == nil {
		return nil, errors.New("F5 gateway context is required")
	}
	if peer == nil {
		return nil, errors.New("F5 gateway packet peer is required")
	}
	if scenario.Cookie == "" || scenario.SessionID == "" || scenario.URZ == "" {
		return nil, errors.New("F5 gateway cookie, session ID, and ur_Z are required")
	}
	if !scenario.ClientAddress.Is4() || !scenario.PeerAddress.Is4() || !scenario.DNS.Is4() {
		return nil, errors.New("F5 gateway scenario requires IPv4 client, peer, and DNS addresses")
	}
	ctx, cancel := context.WithCancel(parent)
	gateway := &F5Gateway{
		ctx:         ctx,
		cancel:      cancel,
		scenario:    scenario,
		peer:        peer,
		connections: make(map[net.Conn]struct{}),
		dtlsConns:   make(map[net.Conn]struct{}),
		dtlsDropped: make(map[net.Conn]struct{}),
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(gateway.serveHTTP))
	server.EnableHTTP2 = false
	server.StartTLS()
	certificate := server.Certificate()
	if certificate == nil {
		cancel()
		server.Close()
		return nil, errors.New("F5 gateway did not expose its TLS certificate")
	}
	gateway.server = server
	gateway.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if scenario.DTLS {
		dtlsListener, err := dtls.ListenWithOptions("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, dtls.WithCertificates(server.TLS.Certificates...))
		if err != nil {
			cancel()
			server.Close()
			return nil, fmt.Errorf("start F5 DTLS listener: %w", err)
		}
		gateway.dtls = dtlsListener
		gateway.waitGroup.Add(1)
		go gateway.acceptDTLS()
	}
	go func() {
		<-ctx.Done()
		_ = gateway.Close()
	}()
	return gateway, nil
}

// Address returns the loopback TCP address of the gateway.
func (g *F5Gateway) Address() string {
	if g == nil || g.server == nil {
		return ""
	}
	parsed, err := url.Parse(g.server.URL)
	if err != nil {
		return ""
	}
	return parsed.Host
}

// ServerName returns the TLS name on the gateway certificate.
func (g *F5Gateway) ServerName() string {
	if g == nil || g.server == nil || g.server.Certificate() == nil {
		return ""
	}
	certificate := g.server.Certificate()
	if len(certificate.DNSNames) != 0 {
		return certificate.DNSNames[0]
	}
	if len(certificate.IPAddresses) != 0 {
		return certificate.IPAddresses[0].String()
	}
	return certificate.Subject.CommonName
}

// CAPEM returns a caller-owned trust anchor for the gateway.
func (g *F5Gateway) CAPEM() []byte {
	if g == nil {
		return nil
	}
	return append([]byte(nil), g.caPEM...)
}

// TunnelConnections reports the number of accepted PPP tunnel connections.
func (g *F5Gateway) TunnelConnections() int64 {
	if g == nil {
		return 0
	}
	return g.tunnelCount.Load()
}

// DTLSConnections reports the number of accepted certificate-DTLS tunnels.
func (g *F5Gateway) DTLSConnections() int64 {
	if g == nil {
		return 0
	}
	return g.dtlsCount.Load()
}

// AuthenticationRequests reports successful username/password exchanges.
func (g *F5Gateway) AuthenticationRequests() int64 {
	if g == nil {
		return 0
	}
	return g.authCount.Load()
}

// DropDTLSConnections closes every active certificate-DTLS tunnel.
func (g *F5Gateway) DropDTLSConnections() int {
	if g == nil {
		return 0
	}
	g.connAccess.Lock()
	connections := make([]net.Conn, 0, len(g.dtlsConns))
	for connection := range g.dtlsConns {
		g.dtlsDropped[connection] = struct{}{}
		connections = append(connections, connection)
	}
	g.connAccess.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	return len(connections)
}

// Close stops the gateway and all hijacked PPP connections.
func (g *F5Gateway) Close() error {
	if g == nil {
		return nil
	}
	g.closeOnce.Do(func() {
		g.cancel()
		if g.dtls != nil {
			_ = g.dtls.Close()
		}
		g.connAccess.Lock()
		for connection := range g.connections {
			_ = connection.Close()
		}
		for connection := range g.dtlsConns {
			_ = connection.Close()
		}
		g.connections = make(map[net.Conn]struct{})
		g.dtlsConns = make(map[net.Conn]struct{})
		g.dtlsDropped = make(map[net.Conn]struct{})
		g.connAccess.Unlock()
		if g.server != nil {
			g.server.Close()
		}
		g.waitGroup.Wait()
	})
	g.errorAccess.Lock()
	defer g.errorAccess.Unlock()
	return errors.Join(g.errors...)
}

func (g *F5Gateway) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/":
		if request.Method != http.MethodGet {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte(`<html><body><form id="auth_form" method="post" action="/my.policy"><input type="text" name="username"><input type="password" name="password"></form></body></html>`))
	case "/my.policy":
		if request.Method != http.MethodPost || request.ParseForm() != nil || request.PostForm.Get("username") != g.scenario.Username || request.PostForm.Get("password") != g.scenario.Password {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		now := time.Now().Unix()
		http.SetCookie(writer, &http.Cookie{Name: "MRHSession", Value: g.scenario.Cookie, Path: "/", Secure: true})
		http.SetCookie(writer, &http.Cookie{Name: "F5_ST", Value: fmt.Sprintf("1z1z1z%dz3600", now), Path: "/", Secure: true})
		g.authCount.Add(1)
		_, _ = writer.Write([]byte(`<html><body>authenticated</body></html>`))
	case "/vdesk/vpn/index.php3":
		if !g.validCookie(request) {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/xml")
		_, _ = writer.Write([]byte(`<favorites type="VPN"><favorite><params>resourcename=test</params></favorite></favorites>`))
	case "/vdesk/vpn/connect.php3":
		if !g.validCookie(request) {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/xml")
		dtlsEnabled := 0
		dtlsPort := 0
		if g.dtls != nil {
			dtlsEnabled = 1
			dtlsPort = g.dtls.Addr().(*net.UDPAddr).Port
		}
		_, _ = fmt.Fprintf(writer, `<favorite><object><ur_Z>%s</ur_Z><Session_ID>%s</Session_ID><IPV4_0>1</IPV4_0><IPV6_0>0</IPV6_0><hdlc_framing>0</hdlc_framing><tunnel_dtls>%d</tunnel_dtls><tunnel_port_dtls>%d</tunnel_port_dtls><dtls_v1_2_supported>1</dtls_v1_2_supported><UseDefaultGateway0>1</UseDefaultGateway0><DNS0>%s</DNS0></object></favorite>`, g.scenario.URZ, g.scenario.SessionID, dtlsEnabled, dtlsPort, g.scenario.DNS)
	case "/myvpn":
		g.serveTunnel(writer, request)
	default:
		http.NotFound(writer, request)
	}
}

func (g *F5Gateway) validCookie(request *http.Request) bool {
	cookie, err := request.Cookie("MRHSession")
	return err == nil && cookie.Value == g.scenario.Cookie
}

func (g *F5Gateway) acceptDTLS() {
	defer g.waitGroup.Done()
	for {
		connection, err := g.dtls.Accept()
		if err != nil {
			if g.ctx.Err() == nil {
				g.recordError(fmt.Errorf("accept F5 DTLS connection: %w", err))
			}
			return
		}
		g.waitGroup.Add(1)
		go g.serveDTLS(connection)
	}
}

func (g *F5Gateway) serveDTLS(connection net.Conn) {
	defer g.waitGroup.Done()
	g.connAccess.Lock()
	g.dtlsConns[connection] = struct{}{}
	g.connAccess.Unlock()
	defer func() {
		g.connAccess.Lock()
		delete(g.dtlsConns, connection)
		g.connAccess.Unlock()
		_ = connection.Close()
	}()
	request := make([]byte, 65535)
	count, err := connection.Read(request)
	if err != nil {
		if g.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
			g.recordError(fmt.Errorf("read F5 DTLS probe: %w", err))
		}
		return
	}
	const requestPrefix = "GET /myvpn?"
	requestText := string(request[:count])
	if count < len(requestPrefix) || requestText[:len(requestPrefix)] != requestPrefix ||
		!strings.Contains(requestText, "sess="+g.scenario.SessionID+"&") ||
		!strings.Contains(requestText, "&Z="+g.scenario.URZ+"&") {
		g.recordError(errors.New("F5 DTLS probe did not contain the tunnel request"))
		return
	}
	response := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nX-VPN-client-IP: %s\r\n\r\n", g.scenario.ClientAddress))
	if _, err := connection.Write(response); err != nil {
		g.recordError(fmt.Errorf("write F5 DTLS probe response: %w", err))
		return
	}
	g.dtlsCount.Add(1)
	err = g.servePPP(bufio.NewReader(connection), connection)
	g.connAccess.Lock()
	_, expectedDrop := g.dtlsDropped[connection]
	delete(g.dtlsDropped, connection)
	g.connAccess.Unlock()
	if err != nil && !expectedDrop && g.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
		g.recordError(err)
	}
}

func (g *F5Gateway) serveTunnel(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Query().Get("sess") != g.scenario.SessionID || request.URL.Query().Get("Z") != g.scenario.URZ {
		http.Error(writer, "invalid tunnel session", http.StatusForbidden)
		return
	}
	hijacker, loaded := writer.(http.Hijacker)
	if !loaded {
		http.Error(writer, "hijacking unavailable", http.StatusInternalServerError)
		return
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		g.recordError(fmt.Errorf("hijack F5 tunnel: %w", err))
		return
	}
	g.connAccess.Lock()
	g.connections[connection] = struct{}{}
	g.connAccess.Unlock()
	defer func() {
		g.connAccess.Lock()
		delete(g.connections, connection)
		g.connAccess.Unlock()
		_ = connection.Close()
	}()
	_, err = fmt.Fprintf(buffered, "HTTP/1.1 200 OK\r\nX-VPN-client-IP: %s\r\n\r\n", g.scenario.ClientAddress)
	if err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		g.recordError(fmt.Errorf("write F5 tunnel response: %w", err))
		return
	}
	g.tunnelCount.Add(1)
	if err := g.servePPP(buffered.Reader, connection); err != nil && g.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
		g.recordError(err)
	}
}

func (g *F5Gateway) servePPP(reader *bufio.Reader, connection net.Conn) error {
	peerLCPRequestSent := false
	peerIPCPRequestSent := false
	for {
		packet, err := readF5PPPFrame(reader)
		if err != nil {
			return err
		}
		protocol, payload, err := parsePPPPacket(packet)
		if err != nil {
			return err
		}
		switch protocol {
		case pppProtocolLCP, pppProtocolIPCP:
			code, identifier, options, err := parsePPPControl(payload)
			if err != nil {
				return err
			}
			switch code {
			case pppConfigureReq:
				if protocol == pppProtocolIPCP && pppIPv4Option(options) != g.scenario.ClientAddress {
					address := g.scenario.ClientAddress.As4()
					if err := writePPPControl(connection, protocol, pppConfigureNak, identifier, appendPPPOption(nil, pppIPCPOptionAddr, address[:])); err != nil {
						return err
					}
				} else if err := writePPPControl(connection, protocol, pppConfigureAck, identifier, options); err != nil {
					return err
				}
				if protocol == pppProtocolLCP && !peerLCPRequestSent {
					peerLCPRequestSent = true
					var mru [2]byte
					binary.BigEndian.PutUint16(mru[:], 1400)
					if err := writePPPControl(connection, pppProtocolLCP, pppConfigureReq, 101, appendPPPOption(nil, pppLCPOptionMRU, mru[:])); err != nil {
						return err
					}
				}
				if protocol == pppProtocolIPCP && !peerIPCPRequestSent {
					peerIPCPRequestSent = true
					address := g.scenario.PeerAddress.As4()
					if err := writePPPControl(connection, pppProtocolIPCP, pppConfigureReq, 102, appendPPPOption(nil, pppIPCPOptionAddr, address[:])); err != nil {
						return err
					}
				}
			case pppTerminateReq:
				return writePPPControl(connection, protocol, pppTerminateAck, identifier, nil)
			case pppEchoReq:
				if err := writePPPControl(connection, protocol, pppEchoReply, identifier, options); err != nil {
					return err
				}
			}
		case pppProtocolIPv4:
			replies, err := handlePacket(g.peer, payload)
			if err != nil {
				return fmt.Errorf("handle F5 tunnel packet: %w", err)
			}
			for _, reply := range replies {
				if err := writePPPPacket(connection, pppProtocolIPv4, reply); err != nil {
					return err
				}
			}
		}
	}
}

func (g *F5Gateway) recordError(err error) {
	if err == nil {
		return
	}
	g.errorAccess.Lock()
	g.errors = append(g.errors, err)
	g.errorAccess.Unlock()
}

type packetBatchPeer interface {
	HandlePackets(packet []byte) ([][]byte, error)
}

func handlePacket(peer testanyconnect.PacketPeer, packet []byte) ([][]byte, error) {
	if batchPeer, loaded := peer.(packetBatchPeer); loaded {
		return batchPeer.HandlePackets(packet)
	}
	reply, err := peer.HandlePacket(packet)
	if err != nil || len(reply) == 0 {
		return nil, err
	}
	return [][]byte{reply}, nil
}

func readF5PPPFrame(reader *bufio.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint16(header[:2]) != f5PPPMagic {
		return nil, errors.New("invalid F5 PPP frame magic")
	}
	length := int(binary.BigEndian.Uint16(header[2:]))
	if length == 0 {
		return nil, errors.New("empty F5 PPP frame")
	}
	packet := make([]byte, length)
	if _, err := io.ReadFull(reader, packet); err != nil {
		return nil, err
	}
	return packet, nil
}

func parsePPPPacket(packet []byte) (uint16, []byte, error) {
	position := 0
	if len(packet) >= 2 && packet[0] == 0xff && packet[1] == 0x03 {
		position = 2
	}
	if position >= len(packet) {
		return 0, nil, errors.New("PPP packet is missing its protocol")
	}
	protocol := uint16(packet[position])
	position++
	if protocol&1 == 0 {
		if position >= len(packet) {
			return 0, nil, errors.New("PPP packet has a truncated protocol")
		}
		protocol = protocol<<8 | uint16(packet[position])
		position++
	}
	return protocol, packet[position:], nil
}

func parsePPPControl(packet []byte) (byte, byte, []byte, error) {
	if len(packet) < 4 {
		return 0, 0, nil, errors.New("PPP control packet is too short")
	}
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	if length < 4 || length > len(packet) {
		return 0, 0, nil, errors.New("PPP control packet has an invalid length")
	}
	return packet[0], packet[1], packet[4:length], nil
}

func pppIPv4Option(options []byte) netip.Addr {
	for len(options) >= 2 {
		length := int(options[1])
		if length < 2 || length > len(options) {
			return netip.Addr{}
		}
		if options[0] == pppIPCPOptionAddr && length == 6 {
			var address [4]byte
			copy(address[:], options[2:6])
			return netip.AddrFrom4(address)
		}
		options = options[length:]
	}
	return netip.Addr{}
}

func appendPPPOption(destination []byte, kind byte, value []byte) []byte {
	destination = append(destination, kind, byte(len(value)+2))
	return append(destination, value...)
}

func writePPPControl(connection net.Conn, protocol uint16, code byte, identifier byte, options []byte) error {
	control := make([]byte, 4+len(options))
	control[0] = code
	control[1] = identifier
	binary.BigEndian.PutUint16(control[2:4], uint16(len(control)))
	copy(control[4:], options)
	return writePPPPacket(connection, protocol, control)
}

func writePPPPacket(connection net.Conn, protocol uint16, payload []byte) error {
	packet := make([]byte, 4+len(payload))
	packet[0] = 0xff
	packet[1] = 0x03
	binary.BigEndian.PutUint16(packet[2:4], protocol)
	copy(packet[4:], payload)
	frame := make([]byte, 4+len(packet))
	binary.BigEndian.PutUint16(frame[:2], f5PPPMagic)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(packet)))
	copy(frame[4:], packet)
	written := 0
	for written < len(frame) {
		count, err := connection.Write(frame[written:])
		if err != nil {
			return err
		}
		if count == 0 {
			return errors.New("short F5 PPP frame write")
		}
		written += count
	}
	return nil
}

func (s F5Scenario) CookieHeader() string {
	return "MRHSession=" + s.Cookie
}

func (g *F5Gateway) Port() int {
	_, portText, err := net.SplitHostPort(g.Address())
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(portText)
	return port
}
