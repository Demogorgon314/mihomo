package anyconnect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	testanyconnect "github.com/metacubex/mihomo/internal/testutil/anyconnect"
)

func TestClientEncryptedClientCertificate(t *testing.T) {
	password := "phase2-key-password"
	caPEM, certificatePEM, encryptedKeyPEM := newClientCertificate(t, password, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	scenario := testanyconnect.BasicCSTPScenario()
	scenario.Authentication.ClientCertificateAuthority = caPEM
	client, gateway, cancel := newTLSScenarioClient(t, scenario, Config{
		Cookie:            scenario.Cookie,
		ClientCertificate: certificatePEM,
		ClientKey:         encryptedKeyPEM,
		ClientKeyPassword: password,
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

func TestClientRejectsClientCertificateFailuresBeforeDial(t *testing.T) {
	password := "phase2-key-password"
	_, certificatePEM, encryptedKeyPEM := newClientCertificate(t, password, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	_, _, otherKeyPEM := newClientCertificate(t, password, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	_, expiredCertificatePEM, expiredKeyPEM := newClientCertificate(t, password, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	base := Config{Server: "https://vpn.invalid", Cookie: "phase2-cookie"}
	for _, testCase := range []struct {
		name        string
		certificate []byte
		key         []byte
		password    string
	}{
		{name: "wrong password", certificate: certificatePEM, key: encryptedKeyPEM, password: "wrong-password"},
		{name: "mismatched key", certificate: certificatePEM, key: otherKeyPEM, password: password},
		{name: "expired certificate", certificate: expiredCertificatePEM, key: expiredKeyPEM, password: password},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			config := base
			config.ClientCertificate = testCase.certificate
			config.ClientKey = testCase.key
			config.ClientKeyPassword = testCase.password
			_, err := NewClient(context.Background(), config, new(recordingDialer), nil)
			if !errors.Is(err, ErrTLSRejected) || !IsTerminal(err) {
				t.Fatalf("expected terminal TLS rejection, got %v", err)
			}
			if containsBytes(err.Error(), testCase.key) || containsBytes(err.Error(), []byte(testCase.password)) {
				t.Fatalf("TLS error leaked private material: %v", err)
			}
		})
	}
}

func TestClientExplicitSkipCertificateVerify(t *testing.T) {
	scenario := testanyconnect.BasicCSTPScenario()
	client, gateway, cancel := newTLSScenarioClient(t, scenario, Config{
		Cookie:         scenario.Cookie,
		ServerName:     "intentionally-wrong.invalid",
		SkipCertVerify: true,
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

func newTLSScenarioClient(t *testing.T, scenario testanyconnect.Scenario, overrides Config) (*Client, *testanyconnect.Gateway, context.CancelFunc) {
	t.Helper()
	peer, err := testanyconnect.NewIPv4ICMPEchoPeer(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(gateway.Address())
	if err != nil {
		_ = gateway.Close()
		cancel()
		t.Fatal(err)
	}
	config := overrides
	config.Server = "https://" + gateway.ServerName() + ":" + port
	if config.ServerName == "" {
		config.ServerName = gateway.ServerName()
	}
	if len(config.CertificateAuthority) == 0 && !config.SkipCertVerify && config.PeerFingerprint == "" {
		config.CertificateAuthority = testanyconnect.RootCAPEM()
	}
	client, err := NewClient(ctx, config, new(recordingDialer), nil)
	if err != nil {
		_ = gateway.Close()
		cancel()
		t.Fatal(err)
	}
	return client, gateway, cancel
}

func newClientCertificate(t *testing.T, password string, notBefore time.Time, notAfter time.Time) ([]byte, []byte, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AnyConnect phase 2 client CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "phase2-client"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	//nolint:staticcheck // Deliberately verifies supported legacy encrypted PEM input.
	encryptedKey, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", keyDER, []byte(password), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}),
		pem.EncodeToMemory(encryptedKey)
}

func containsBytes(message string, value []byte) bool {
	return len(value) > 0 && strings.Contains(message, string(value))
}
