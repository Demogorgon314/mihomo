package openconnect

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/pion/dtls/v3"
)

const probeDTLSExporterLabel = "EXPORTER-openconnect-psk"

// AnyConnectProbeOptions configures the independent Phase 0 CSTP probe.
type AnyConnectProbeOptions struct {
	Address    string
	ServerName string
	RootCAs    *x509.CertPool
	Cookie     string
	Packet     []byte
}

// AnyConnectProbeResult contains the independently parsed tunnel configuration and packet reply.
type AnyConnectProbeResult struct {
	Configuration AnyConnectNetworkConfiguration
	Packet        []byte
}

// AnyConnectDTLSProbeOptions configures the independent modern-DTLS probe. PSKOverride
// is only used by negative tests to prove that the fake gateway authenticates
// the DTLS channel against the live CSTP TLS session.
type AnyConnectDTLSProbeOptions struct {
	AnyConnectProbeOptions
	PSKOverride []byte
}

// RunAnyConnectCSTPProbe establishes TLS, negotiates CSTP, and exchanges one raw IP packet.
func RunAnyConnectCSTPProbe(ctx context.Context, options AnyConnectProbeOptions) (AnyConnectProbeResult, error) {
	connection, reader, configuration, _, err := openProbeCSTP(ctx, options)
	if err != nil {
		return AnyConnectProbeResult{}, err
	}
	defer connection.Close()
	if err := writeCSTPFrame(connection, cstpPacketData, options.Packet); err != nil {
		return AnyConnectProbeResult{}, err
	}
	frame, err := readCSTPFrame(reader, int(configuration.MTU))
	if err != nil {
		return AnyConnectProbeResult{}, fmt.Errorf("read tunneled probe reply: %w", err)
	}
	if frame.packetType != cstpPacketData {
		return AnyConnectProbeResult{}, fmt.Errorf("unexpected CSTP probe reply type: %d", frame.packetType)
	}
	return AnyConnectProbeResult{Configuration: configuration, Packet: frame.payload}, nil
}

// RunAnyConnectDTLSProbe establishes the CSTP control channel, derives its exporter PSK,
// then exchanges one raw packet over an independently negotiated DTLS channel.
func RunAnyConnectDTLSProbe(ctx context.Context, options AnyConnectDTLSProbeOptions) (AnyConnectProbeResult, error) {
	connection, _, configuration, headers, err := openProbeCSTP(ctx, options.AnyConnectProbeOptions)
	if err != nil {
		return AnyConnectProbeResult{}, err
	}
	defer connection.Close()
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		return AnyConnectProbeResult{}, fmt.Errorf("probe CSTP connection is not TLS")
	}
	portValue := headers.Get("X-DTLS12-Port")
	if headers.Get("X-DTLS12-CipherSuite") != "PSK-NEGOTIATE" || portValue == "" {
		return AnyConnectProbeResult{}, fmt.Errorf("fake gateway did not advertise modern PSK DTLS")
	}
	port, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil || port == 0 {
		return AnyConnectProbeResult{}, fmt.Errorf("invalid DTLS port: %q", portValue)
	}
	connectionState := tlsConnection.ConnectionState()
	psk, err := connectionState.ExportKeyingMaterial(probeDTLSExporterLabel, nil, 32)
	if err != nil {
		return AnyConnectProbeResult{}, fmt.Errorf("export probe DTLS PSK: %w", err)
	}
	if options.PSKOverride != nil {
		psk = append([]byte(nil), options.PSKOverride...)
	}
	host, _, err := net.SplitHostPort(options.Address)
	if err != nil {
		return AnyConnectProbeResult{}, fmt.Errorf("parse probe gateway address: %w", err)
	}
	remoteAddress, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.FormatUint(port, 10)))
	if err != nil {
		return AnyConnectProbeResult{}, fmt.Errorf("resolve probe DTLS address: %w", err)
	}
	dtlsConnection, err := dtls.DialWithOptions("udp", remoteAddress,
		dtls.WithPSK(func([]byte) ([]byte, error) { return append([]byte(nil), psk...), nil }),
		dtls.WithPSKIdentityHint([]byte("psk")),
		dtls.WithCipherSuites(
			dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
			dtls.TLS_PSK_WITH_AES_128_CCM,
		),
		dtls.WithFlightInterval(25*time.Millisecond),
	)
	if err != nil {
		return AnyConnectProbeResult{}, fmt.Errorf("create probe DTLS client: %w", err)
	}
	defer dtlsConnection.Close()
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		if err := dtlsConnection.SetDeadline(deadline); err != nil {
			return AnyConnectProbeResult{}, fmt.Errorf("set probe DTLS deadline: %w", err)
		}
	}
	if err := dtlsConnection.HandshakeContext(ctx); err != nil {
		return AnyConnectProbeResult{}, fmt.Errorf("handshake probe DTLS: %w", err)
	}
	request := make([]byte, len(options.Packet)+1)
	request[0] = cstpPacketData
	copy(request[1:], options.Packet)
	if _, err := dtlsConnection.Write(request); err != nil {
		return AnyConnectProbeResult{}, fmt.Errorf("write tunneled DTLS probe packet: %w", err)
	}
	reply := make([]byte, int(configuration.MTU)+1)
	length, err := dtlsConnection.Read(reply)
	if err != nil {
		return AnyConnectProbeResult{}, fmt.Errorf("read tunneled DTLS probe reply: %w", err)
	}
	if length < 1 || reply[0] != cstpPacketData {
		return AnyConnectProbeResult{}, fmt.Errorf("unexpected DTLS probe reply type or length")
	}
	return AnyConnectProbeResult{Configuration: configuration, Packet: append([]byte(nil), reply[1:length]...)}, nil
}

func openProbeCSTP(ctx context.Context, options AnyConnectProbeOptions) (net.Conn, *bufio.Reader, AnyConnectNetworkConfiguration, textproto.MIMEHeader, error) {
	if ctx == nil {
		return nil, nil, AnyConnectNetworkConfiguration{}, nil, fmt.Errorf("probe context is required")
	}
	if options.Address == "" || options.ServerName == "" || options.RootCAs == nil || options.Cookie == "" || len(options.Packet) == 0 {
		return nil, nil, AnyConnectNetworkConfiguration{}, nil, fmt.Errorf("probe address, server name, roots, cookie, and packet are required")
	}
	if strings.ContainsAny(options.Cookie, "\r\n") {
		return nil, nil, AnyConnectNetworkConfiguration{}, nil, fmt.Errorf("probe cookie contains an invalid header character")
	}
	dialer := tls.Dialer{Config: &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: options.ServerName,
		RootCAs:    options.RootCAs,
		NextProtos: []string{"http/1.1"},
	}}
	connection, err := dialer.DialContext(ctx, "tcp", options.Address)
	if err != nil {
		return nil, nil, AnyConnectNetworkConfiguration{}, nil, fmt.Errorf("dial fake CSTP gateway: %w", err)
	}
	closeWithError := func(err error) (net.Conn, *bufio.Reader, AnyConnectNetworkConfiguration, textproto.MIMEHeader, error) {
		_ = connection.Close()
		return nil, nil, AnyConnectNetworkConfiguration{}, nil, err
	}
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		if err := connection.SetDeadline(deadline); err != nil {
			return closeWithError(fmt.Errorf("set probe deadline: %w", err))
		}
	}
	request := "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n" +
		"Host: " + options.ServerName + "\r\n" +
		"User-Agent: mihomo-anyconnect-phase0-probe\r\n" +
		"Cookie: webvpn=" + options.Cookie + "\r\n" +
		"X-CSTP-Version: 1\r\n" +
		"X-CSTP-MTU: 1400\r\n" +
		"X-CSTP-Address-Type: IPv4,IPv6\r\n\r\n"
	if err := writeFull(connection, []byte(request)); err != nil {
		return closeWithError(fmt.Errorf("write CSTP CONNECT: %w", err))
	}
	reader := bufio.NewReader(connection)
	configuration, headers, err := readProbeConnectResponse(reader)
	if err != nil {
		return closeWithError(err)
	}
	return connection, reader, configuration, headers, nil
}

func readProbeConnectResponse(reader *bufio.Reader) (AnyConnectNetworkConfiguration, textproto.MIMEHeader, error) {
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return AnyConnectNetworkConfiguration{}, nil, fmt.Errorf("read CSTP response status: %w", err)
	}
	statusFields := strings.Fields(statusLine)
	if len(statusFields) < 2 || !strings.HasPrefix(statusFields[0], "HTTP/1.") {
		return AnyConnectNetworkConfiguration{}, nil, fmt.Errorf("invalid CSTP response status: %s", strings.TrimSpace(statusLine))
	}
	status, err := strconv.Atoi(statusFields[1])
	if err != nil {
		return AnyConnectNetworkConfiguration{}, nil, fmt.Errorf("invalid CSTP response code: %s", statusFields[1])
	}
	headers, err := textproto.NewReader(reader).ReadMIMEHeader()
	if err != nil {
		return AnyConnectNetworkConfiguration{}, nil, fmt.Errorf("read CSTP response headers: %w", err)
	}
	if status != 200 {
		return AnyConnectNetworkConfiguration{}, headers, fmt.Errorf("CSTP CONNECT rejected with HTTP %d", status)
	}
	mtuValue, err := strconv.ParseUint(headers.Get("X-CSTP-MTU"), 10, 16)
	if err != nil || mtuValue == 0 {
		return AnyConnectNetworkConfiguration{}, headers, fmt.Errorf("invalid CSTP MTU: %q", headers.Get("X-CSTP-MTU"))
	}
	configuration := AnyConnectNetworkConfiguration{MTU: uint16(mtuValue)}
	netmasks := headers.Values("X-CSTP-Netmask")
	for index, value := range headers.Values("X-CSTP-Address") {
		address, parseErr := netip.ParseAddr(strings.TrimSpace(value))
		if parseErr != nil {
			return AnyConnectNetworkConfiguration{}, headers, fmt.Errorf("parse CSTP address: %w", parseErr)
		}
		bits := address.BitLen()
		if address.Is4() && index < len(netmasks) {
			maskAddress := net.ParseIP(strings.TrimSpace(netmasks[index])).To4()
			if maskAddress == nil {
				return AnyConnectNetworkConfiguration{}, headers, fmt.Errorf("invalid CSTP IPv4 netmask: %q", netmasks[index])
			}
			ones, maskBits := net.IPMask(maskAddress).Size()
			if ones == 0 && maskBits == 0 && !maskAddress.Equal(net.IPv4zero) {
				return AnyConnectNetworkConfiguration{}, headers, fmt.Errorf("non-contiguous CSTP IPv4 netmask: %q", netmasks[index])
			}
			bits = ones
		}
		configuration.Addresses = append(configuration.Addresses, netip.PrefixFrom(address, bits))
	}
	for _, value := range headers.Values("X-CSTP-Address-IP6") {
		prefix, parseErr := netip.ParsePrefix(strings.TrimSpace(value))
		if parseErr != nil {
			return AnyConnectNetworkConfiguration{}, headers, fmt.Errorf("parse CSTP IPv6 address: %w", parseErr)
		}
		configuration.Addresses = append(configuration.Addresses, prefix)
	}
	for _, value := range append(headers.Values("X-CSTP-DNS"), headers.Values("X-CSTP-DNS-IP6")...) {
		address, parseErr := netip.ParseAddr(strings.TrimSpace(value))
		if parseErr != nil {
			return AnyConnectNetworkConfiguration{}, headers, fmt.Errorf("parse CSTP DNS address: %w", parseErr)
		}
		configuration.DNS = append(configuration.DNS, address)
	}
	if len(configuration.Addresses) == 0 {
		return AnyConnectNetworkConfiguration{}, headers, fmt.Errorf("CSTP response has no tunnel address")
	}
	return configuration, headers, nil
}
