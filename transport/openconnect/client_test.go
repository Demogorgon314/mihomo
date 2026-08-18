package openconnect

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

	testopenconnect "github.com/metacubex/mihomo/internal/testutil/openconnect"
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
	scenario := testopenconnect.BasicAnyConnectScenario()
	scenario.Cookie = "opaque-cookie=with=padding"
	scenario.CSTP.ResponseChunkSize = 1
	peer, err := testopenconnect.NewIPv4ICMPEchoPeer(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	gateway, err := testopenconnect.StartAnyConnectGateway(ctx, scenario, peer, nil)
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
		CertificateAuthority: testopenconnect.AnyConnectRootCAPEM(),
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
	request, err := testopenconnect.BuildIPv4ICMPEchoRequest(scenario.Configuration.Addresses[0].Addr(), netip.MustParseAddr("192.0.2.1"), 1, 1, []byte("facade"))
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
	pin, err := testopenconnect.AnyConnectServerSPKISHA256()
	if err != nil {
		t.Fatal(err)
	}
	pinnedClient, err := NewClient(ctx, Config{
		Server:     "https://" + gateway.ServerName() + ":" + port,
		Cookie:     scenario.Cookie,
		ServerName: gateway.ServerName(),
		PeerFingerprints: []string{
			"sha256:0000000000000000000000000000000000000000000000000000000000000000",
			pin,
		},
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

func TestClientMobileIdentityMatchesOpenConnectDefaults(t *testing.T) {
	scenario := testopenconnect.BasicAnyConnectScenario()
	scenario.CSTP.ExpectedRequestHeaders = map[string]string{
		"User-Agent":                              "OpenConnect mobile test",
		"X-CSTP-Hostname":                         "mobile-client",
		"X-AnyConnect-Identifier-ClientVersion":   "9.99",
		"X-AnyConnect-Identifier-Platform":        "android",
		"X-AnyConnect-Identifier-PlatformVersion": "1.0",
		"X-AnyConnect-Identifier-DeviceType":      "android",
		"X-AnyConnect-Identifier-Device-UniqueID": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	client, gateway, cancel := newTLSScenarioClient(t, scenario, Config{
		Cookie:        scenario.Cookie,
		ReportedOS:    "android",
		UserAgent:     "OpenConnect mobile test",
		Version:       "9.99",
		LocalHostname: "mobile-client",
	})
	defer cancel()
	defer func() { _ = gateway.Close() }()
	defer func() { _ = client.Close() }()
	ctx, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWait()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WaitReady(ctx); err != nil {
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
		{name: "invalid reported OS", config: Config{Server: "https://vpn.example", Cookie: secret, ReportedOS: "plan9"}},
		{name: "invalid user agent", config: Config{Server: "https://vpn.example", Cookie: secret, UserAgent: "bad\r\nagent"}},
		{name: "incomplete mobile identity", config: Config{Server: "https://vpn.example", Cookie: secret, Mobile: &MobileConfig{PlatformVersion: "1.0", DeviceType: "android"}}},
		{name: "empty peer fingerprint", config: Config{Server: "https://vpn.example", Cookie: secret, PeerFingerprints: []string{""}}},
		{name: "promoted form value", config: Config{Server: "https://vpn.example", Cookie: secret, FormEntries: []FormEntry{{SubmissionKey: "answer", Value: "value", Promote: true}}}},
		{name: "MCA certificate without key", config: Config{Server: "https://vpn.example", Cookie: secret, MCACertificate: []byte("certificate")}},
		{name: "MCA key password without key", config: Config{Server: "https://vpn.example", Cookie: secret, MCAKeyPassword: "private-secret"}},
		{name: "negative certificate expiry warning", config: Config{Server: "https://vpn.example", Cookie: secret, CertificateExpiryWarning: -time.Second}},
		{name: "disabled configured certificate expiry warning", config: Config{Server: "https://vpn.example", Cookie: secret, CertificateExpiryWarning: time.Hour, CertificateExpiryWarningDisabled: true}},
		{name: "unbounded packet queue", config: Config{Server: "https://vpn.example", Cookie: secret, QueueLength: MaximumQueueLength + 1}},
		{name: "unsupported protocol", config: Config{Server: "https://vpn.example", Protocol: "gp", Cookie: secret}},
		{name: "invalid DTLS mode", config: Config{Server: "https://vpn.example", Cookie: secret, DTLSMode: "invalid"}},
		{name: "invalid DTLS key exchange", config: Config{Server: "https://vpn.example", Cookie: secret, DTLSKeyExchange: "invalid"}},
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
	scenario := testopenconnect.BasicAnyConnectScenario()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	peer, err := testopenconnect.NewIPv4ICMPEchoPeer(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := testopenconnect.StartAnyConnectGateway(ctx, scenario, peer, nil)
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
		{name: "wrong hostname", config: Config{Server: "https://" + gateway.ServerName() + ":" + port, Cookie: scenario.Cookie, ServerName: "wrong.example", CertificateAuthority: testopenconnect.AnyConnectRootCAPEM()}, match: "wrong.example"},
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
