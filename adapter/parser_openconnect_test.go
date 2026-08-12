package adapter

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

func TestParseOpenConnect(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":           "vpn",
		"type":           "openconnect",
		"protocol":       "anyconnect",
		"server":         "vpn.example.com",
		"cookie":         "test-cookie",
		"reported-os":    "linux-64",
		"user-agent":     "OpenConnect test agent",
		"version":        "9.21",
		"local-hostname": "test-client",
		"mobile": map[string]any{
			"platform-version": "14",
			"device-type":      "android",
			"device-unique-id": "test-device",
		},
		"peer-fingerprints":                []string{"sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		"system-trust-disabled":            true,
		"http-keepalive-disabled":          true,
		"xml-post-disabled":                true,
		"external-auth-disabled":           true,
		"password-authentication-disabled": true,
		"pfs":                              true,
		"allow-insecure-crypto":            true,
		"mca-certificate":                  "test MCA certificate",
		"mca-key":                          "test MCA key",
		"mca-key-password":                 "test MCA password",
		"cert-expire-warning":              30,
		"token-mode":                       "rsa",
		"token-secret":                     "rsa-token",
		"token-pin":                        "1234",
		"token-password":                   "token-password",
		"token-device-id":                  "device-id",
		"dtls-mode":                        "off",
		"dtls-local-port":                  44444,
		"legacy-dtls":                      false,
		"handshake-timeout":                10,
		"ipv6-disabled":                    true,
		"mtu":                              1200,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Close() }()
	if proxy.Type() != C.OpenConnect || proxy.Name() != "vpn" || !proxy.SupportUDP() {
		t.Fatalf("unexpected parsed proxy: type=%s name=%q udp=%v", proxy.Type(), proxy.Name(), proxy.SupportUDP())
	}
}

func TestNewOpenConnectAcceptsIPv6Gateway(t *testing.T) {
	proxy, err := outbound.NewOpenConnect(outbound.OpenConnectOption{
		Name:   "ipv6-vpn",
		Server: "2001:db8::1",
		Cookie: "test-cookie",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Close() }()
	if proxy.Addr() != "[2001:db8::1]:443" {
		t.Fatalf("unexpected IPv6 gateway address: %q", proxy.Addr())
	}
}

func TestParseOpenConnectAcceptsF5Protocol(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":          "f5-vpn",
		"type":          "openconnect",
		"protocol":      "f5",
		"server":        "vpn.example.com",
		"cookie":        "MRHSession=test-cookie",
		"ipv6-disabled": true,
		"dtls-mode":     "off",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Close() }()
	if proxy.Type() != C.OpenConnect || proxy.Name() != "f5-vpn" {
		t.Fatalf("unexpected parsed F5 proxy: type=%s name=%q", proxy.Type(), proxy.Name())
	}
}

func TestParseOpenConnectRejectsInvalidOptions(t *testing.T) {
	secret := "parser-secret-cookie"
	for _, testCase := range []struct {
		name   string
		change func(map[string]any)
	}{
		{name: "missing server", change: func(mapping map[string]any) { delete(mapping, "server") }},
		{name: "URL server", change: func(mapping map[string]any) { mapping["server"] = "https://vpn.example.com/path" }},
		{name: "port overflow", change: func(mapping map[string]any) { mapping["port"] = 65536 }},
		{name: "missing cookie", change: func(mapping map[string]any) { delete(mapping, "cookie") }},
		{name: "invalid cookie", change: func(mapping map[string]any) { mapping["cookie"] = secret + "\n" }},
		{name: "invalid reported OS", change: func(mapping map[string]any) { mapping["reported-os"] = "plan9" }},
		{name: "invalid user agent", change: func(mapping map[string]any) { mapping["user-agent"] = "bad\r\nagent" }},
		{name: "incomplete mobile identity", change: func(mapping map[string]any) {
			mapping["mobile"] = map[string]any{"platform-version": "14", "device-type": "android"}
		}},
		{name: "conflicting TLS trust", change: func(mapping map[string]any) {
			mapping["ca"] = "test CA"
			mapping["peer-fingerprint"] = "sha256:0000"
		}},
		{name: "CA with skip verify", change: func(mapping map[string]any) {
			mapping["ca"] = "test CA"
			mapping["skip-cert-verify"] = true
		}},
		{name: "certificate without key", change: func(mapping map[string]any) { mapping["cert"] = "client certificate" }},
		{name: "key password without key", change: func(mapping map[string]any) { mapping["key-password"] = "private-secret" }},
		{name: "MCA certificate without key", change: func(mapping map[string]any) { mapping["mca-certificate"] = "MCA certificate" }},
		{name: "MCA key password without key", change: func(mapping map[string]any) { mapping["mca-key-password"] = "private-secret" }},
		{name: "invalid token mode", change: func(mapping map[string]any) {
			mapping["token-mode"] = "invalid"
			mapping["token-secret"] = "private-secret"
		}},
		{name: "HOTP without counter persistence", change: func(mapping map[string]any) {
			mapping["token-mode"] = "hotp"
			mapping["token-secret"] = "AA"
		}},
		{name: "invalid DTLS mode", change: func(mapping map[string]any) { mapping["dtls-mode"] = "invalid" }},
		{name: "unsupported protocol", change: func(mapping map[string]any) { mapping["protocol"] = "gp" }},
		{name: "invalid DTLS key exchange", change: func(mapping map[string]any) { mapping["dtls-key-exchange"] = "invalid" }},
		{name: "negative timeout", change: func(mapping map[string]any) { mapping["handshake-timeout"] = -1 }},
		{name: "small MTU", change: func(mapping map[string]any) { mapping["mtu"] = 575 }},
		{name: "small IPv6 MTU", change: func(mapping map[string]any) { mapping["mtu"] = 1279 }},
		{name: "small base MTU", change: func(mapping map[string]any) { mapping["base-mtu"] = 575 }},
		{name: "negative DPD interval", change: func(mapping map[string]any) { mapping["dpd-interval"] = -1 }},
		{name: "negative reconnect timeout", change: func(mapping map[string]any) { mapping["reconnect-timeout"] = -1 }},
		{name: "DTLS local port overflow", change: func(mapping map[string]any) { mapping["dtls-local-port"] = 65536 }},
		{name: "negative certificate expiry warning", change: func(mapping map[string]any) { mapping["cert-expire-warning"] = -1 }},
		{name: "promoted form value", change: func(mapping map[string]any) {
			mapping["form-entries"] = []map[string]any{{"submission-key": "answer", "value": "value", "promote": true}}
		}},
		{name: "invalid compression", change: func(mapping map[string]any) { mapping["compression"] = "deflate" }},
		{name: "unbounded packet queue", change: func(mapping map[string]any) { mapping["queue-length"] = 4097 }},
		{name: "DNS override without remote resolve", change: func(mapping map[string]any) { mapping["dns"] = []string{"192.0.2.53"} }},
		{name: "DNS hostname override", change: func(mapping map[string]any) {
			mapping["remote-dns-resolve"] = true
			mapping["dns"] = []string{"resolver.example"}
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			mapping := map[string]any{
				"name":   "vpn",
				"type":   "openconnect",
				"server": "vpn.example.com",
				"port":   443,
				"cookie": secret,
			}
			testCase.change(mapping)
			_, err := ParseProxy(mapping)
			if err == nil {
				t.Fatal("expected parser error")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("parser error leaked cookie: %v", err)
			}
		})
	}
}
