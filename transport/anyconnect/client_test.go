package anyconnect

import (
	"context"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	testanyconnect "github.com/metacubex/mihomo/internal/testutil/anyconnect"
)

type recordingDialer struct {
	access    sync.Mutex
	networks  []string
	addresses []string
}

func (d *recordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.access.Lock()
	d.networks = append(d.networks, network)
	d.addresses = append(d.addresses, address)
	d.access.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (d *recordingDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, errors.New("unexpected UDP underlay")
}

func (d *recordingDialer) calls() ([]string, []string) {
	d.access.Lock()
	defer d.access.Unlock()
	return append([]string(nil), d.networks...), append([]string(nil), d.addresses...)
}

func TestClientCookieCSTP(t *testing.T) {
	scenario := testanyconnect.BasicCSTPScenario()
	scenario.Cookie = "opaque-cookie=with=padding"
	scenario.CSTP.ResponseChunkSize = 1
	peer, err := testanyconnect.NewIPv4ICMPEchoPeer(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := gateway.Close(); err != nil {
			t.Error(err)
		}
	}()
	_, port, err := net.SplitHostPort(gateway.Address())
	if err != nil {
		t.Fatal(err)
	}
	dialer := new(recordingDialer)
	client, err := NewClient(ctx, Config{
		Server:               "https://" + gateway.ServerName() + ":" + port,
		Cookie:               scenario.Cookie,
		ServerName:           gateway.ServerName(),
		CertificateAuthority: testanyconnect.RootCAPEM(),
	}, dialer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	configuration, err := client.WaitReady(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(configuration.Addresses) != 1 || configuration.Addresses[0] != scenario.Configuration.Addresses[0] || configuration.MTU != uint32(scenario.Configuration.MTU) {
		t.Fatalf("unexpected network configuration: %#v", configuration)
	}
	configuration.Addresses[0] = netip.MustParsePrefix("198.51.100.2/24")
	configurationAgain, err := client.WaitReady(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if configurationAgain.Addresses[0] != scenario.Configuration.Addresses[0] {
		t.Fatalf("network configuration was not caller-owned: %#v", configurationAgain)
	}
	request, err := testanyconnect.BuildIPv4ICMPEchoRequest(scenario.Configuration.Addresses[0].Addr(), netip.MustParseAddr("192.0.2.1"), 1, 1, []byte("facade"))
	if err != nil {
		t.Fatal(err)
	}
	writtenRequest := append([]byte(nil), request...)
	if err := client.WritePacket(writtenRequest); err != nil {
		t.Fatal(err)
	}
	clear(writtenRequest)
	reply, err := client.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) < 28 || string(reply[28:]) != "facade" {
		t.Fatalf("unexpected packet reply: %x", reply)
	}
	if client.ActiveTransport() != "cstp" {
		t.Fatalf("unexpected active transport: %q", client.ActiveTransport())
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second close failed: %v", err)
	}
	networks, addresses := dialer.calls()
	if len(networks) == 0 || networks[0] != "tcp" || len(addresses) == 0 || !strings.HasSuffix(addresses[0], ":"+port) {
		t.Fatalf("protocol bypassed injected underlay: networks=%v addresses=%v", networks, addresses)
	}
	pin, err := testanyconnect.ServerSPKISHA256()
	if err != nil {
		t.Fatal(err)
	}
	pinnedClient, err := NewClient(ctx, Config{
		Server:          "https://" + gateway.ServerName() + ":" + port,
		Cookie:          scenario.Cookie,
		ServerName:      gateway.ServerName(),
		PeerFingerprint: pin,
	}, new(recordingDialer), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pinnedClient.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := pinnedClient.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pinnedClient.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClientRejectsInvalidConfigWithoutLeakingCookie(t *testing.T) {
	secret := "do-not-leak-this-cookie"
	for _, testCase := range []struct {
		name   string
		config Config
	}{
		{name: "missing server", config: Config{Cookie: secret}},
		{name: "non HTTPS", config: Config{Server: "http://vpn.example", Cookie: secret}},
		{name: "missing cookie", config: Config{Server: "https://vpn.example"}},
		{name: "invalid cookie", config: Config{Server: "https://vpn.example", Cookie: secret + "\n"}},
		{name: "conflicting TLS trust", config: Config{Server: "https://vpn.example", Cookie: secret, CertificateAuthority: []byte("test CA"), PeerFingerprint: "sha256:0000"}},
		{name: "invalid server name", config: Config{Server: "https://vpn.example", Cookie: secret, ServerName: "bad\nname"}},
		{name: "unbounded packet queue", config: Config{Server: "https://vpn.example", Cookie: secret, QueueLength: MaximumQueueLength + 1}},
		{name: "invalid DTLS mode", config: Config{Server: "https://vpn.example", Cookie: secret, DTLSMode: "invalid"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewClient(context.Background(), testCase.config, new(recordingDialer), nil)
			if err == nil {
				t.Fatal("expected configuration error")
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("expected ErrInvalidConfig, got %v", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("configuration error leaked cookie: %v", err)
			}
		})
	}
}

func TestClientRejectsMissingContextDialerAndInvalidCA(t *testing.T) {
	config := Config{Server: "https://vpn.example", Cookie: "test-cookie"}
	if _, err := NewClient(nil, config, new(recordingDialer), nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected invalid context error, got %v", err)
	}
	if _, err := NewClient(context.Background(), config, nil, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected invalid dialer error, got %v", err)
	}
	config.CertificateAuthority = []byte("not PEM")
	if _, err := NewClient(context.Background(), config, new(recordingDialer), nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected invalid CA error, got %v", err)
	}
}

func TestClientRejectsTLSFailures(t *testing.T) {
	scenario := testanyconnect.BasicCSTPScenario()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	peer, err := testanyconnect.NewIPv4ICMPEchoPeer(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	_, port, err := net.SplitHostPort(gateway.Address())
	if err != nil {
		t.Fatal(err)
	}
	unrelatedServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	unrelatedCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: unrelatedServer.Certificate().Raw})
	unrelatedServer.Close()
	for _, testCase := range []struct {
		name   string
		config Config
		match  string
	}{
		{name: "unknown CA", config: Config{Server: "https://" + gateway.ServerName() + ":" + port, Cookie: scenario.Cookie, ServerName: gateway.ServerName(), CertificateAuthority: unrelatedCA}, match: "certificate"},
		{name: "wrong hostname", config: Config{Server: "https://" + gateway.ServerName() + ":" + port, Cookie: scenario.Cookie, ServerName: "wrong.example", CertificateAuthority: testanyconnect.RootCAPEM()}, match: "wrong.example"},
		{name: "wrong pin", config: Config{Server: "https://" + gateway.ServerName() + ":" + port, Cookie: scenario.Cookie, ServerName: gateway.ServerName(), PeerFingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}, match: "fingerprint"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			caseContext, cancelCase := context.WithTimeout(ctx, 2*time.Second)
			defer cancelCase()
			client, clientErr := NewClient(caseContext, testCase.config, new(recordingDialer), nil)
			if clientErr != nil {
				t.Fatal(clientErr)
			}
			if err := client.Start(); err != nil {
				t.Fatal(err)
			}
			_, clientErr = client.WaitReady(caseContext)
			_ = client.Close()
			if clientErr == nil || !strings.Contains(strings.ToLower(clientErr.Error()), strings.ToLower(testCase.match)) {
				t.Fatalf("expected %q TLS rejection, got %v", testCase.match, clientErr)
			}
		})
	}
}
