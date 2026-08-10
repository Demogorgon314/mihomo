package adapter

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

func TestParseAnyConnect(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":              "vpn",
		"type":              "anyconnect",
		"server":            "vpn.example.com",
		"port":              443,
		"cookie":            "test-cookie",
		"dtls-mode":         "off",
		"handshake-timeout": 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Close() }()
	if proxy.Type() != C.AnyConnect || proxy.Name() != "vpn" || !proxy.SupportUDP() {
		t.Fatalf("unexpected parsed proxy: type=%s name=%q udp=%v", proxy.Type(), proxy.Name(), proxy.SupportUDP())
	}
}

func TestNewAnyConnectAcceptsIPv6Gateway(t *testing.T) {
	proxy, err := outbound.NewAnyConnect(outbound.AnyConnectOption{
		Name:   "ipv6-vpn",
		Server: "2001:db8::1",
		Port:   443,
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

func TestParseAnyConnectRejectsInvalidOptions(t *testing.T) {
	secret := "parser-secret-cookie"
	for _, testCase := range []struct {
		name   string
		change func(map[string]any)
	}{
		{name: "missing server", change: func(mapping map[string]any) { delete(mapping, "server") }},
		{name: "URL server", change: func(mapping map[string]any) { mapping["server"] = "https://vpn.example.com/path" }},
		{name: "port zero", change: func(mapping map[string]any) { mapping["port"] = 0 }},
		{name: "port overflow", change: func(mapping map[string]any) { mapping["port"] = 65536 }},
		{name: "missing cookie", change: func(mapping map[string]any) { delete(mapping, "cookie") }},
		{name: "invalid cookie", change: func(mapping map[string]any) { mapping["cookie"] = secret + "\n" }},
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
		{name: "invalid token mode", change: func(mapping map[string]any) {
			mapping["token-mode"] = "invalid"
			mapping["token-secret"] = "private-secret"
		}},
		{name: "HOTP without counter persistence", change: func(mapping map[string]any) {
			mapping["token-mode"] = "hotp"
			mapping["token-secret"] = "AA"
		}},
		{name: "unsupported DTLS", change: func(mapping map[string]any) { mapping["dtls-mode"] = "auto" }},
		{name: "negative timeout", change: func(mapping map[string]any) { mapping["handshake-timeout"] = -1 }},
		{name: "small MTU", change: func(mapping map[string]any) { mapping["mtu"] = 575 }},
		{name: "small IPv6 MTU", change: func(mapping map[string]any) {
			mapping["ipv6"] = true
			mapping["mtu"] = 1279
		}},
		{name: "small base MTU", change: func(mapping map[string]any) { mapping["base-mtu"] = 575 }},
		{name: "negative DPD interval", change: func(mapping map[string]any) { mapping["dpd-interval"] = -1 }},
		{name: "negative reconnect timeout", change: func(mapping map[string]any) { mapping["reconnect-timeout"] = -1 }},
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
				"type":   "anyconnect",
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
