package openconnect

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestFakeAuthenticationProbeMultiroundExpiryAndReauthentication(t *testing.T) {
	scenario := BasicAnyConnectScenario()
	scenario.Authentication = AnyConnectAuthenticationScenario{
		Enabled:           true,
		Username:          "phase0-user",
		Password:          "phase0-password",
		Challenge:         "Enter second factor",
		ChallengeResponse: "654321",
		CookieUses:        1,
	}
	serverAddress := netip.MustParseAddr("192.0.2.1")
	peer, err := NewIPv4ICMPEchoPeer(serverAddress)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	recorder := NewRecorder(scenario.Cookie, scenario.Authentication.Password, scenario.Authentication.ChallengeResponse)
	gateway, err := StartAnyConnectGateway(ctx, scenario, peer, recorder)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateway.Close() }()
	probeOptions := AnyConnectAuthProbeOptions{
		Address:           gateway.Address(),
		ServerName:        gateway.ServerName(),
		RootCAs:           gateway.RootCAs(),
		Username:          scenario.Authentication.Username,
		Password:          scenario.Authentication.Password,
		ChallengeResponse: scenario.Authentication.ChallengeResponse,
	}
	firstCookie, err := RunAnyConnectAuthProbe(ctx, probeOptions)
	if err != nil {
		t.Fatal(err)
	}
	if firstCookie != scenario.Cookie+"-1" {
		t.Fatalf("unexpected first authentication cookie: %q", firstCookie)
	}
	request, err := BuildIPv4ICMPEchoRequest(scenario.Configuration.Addresses[0].Addr(), serverAddress, 9, 1, []byte("authenticated"))
	if err != nil {
		t.Fatal(err)
	}
	cstpOptions := AnyConnectProbeOptions{Address: gateway.Address(), ServerName: gateway.ServerName(), RootCAs: gateway.RootCAs(), Cookie: firstCookie, Packet: request}
	if _, err := RunAnyConnectCSTPProbe(ctx, cstpOptions); err != nil {
		t.Fatal(err)
	}
	if _, err := RunAnyConnectCSTPProbe(ctx, cstpOptions); err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("expected expired cookie rejection, got %v", err)
	}
	secondCookie, err := RunAnyConnectAuthProbe(ctx, probeOptions)
	if err != nil {
		t.Fatal(err)
	}
	if secondCookie != scenario.Cookie+"-2" || secondCookie == firstCookie {
		t.Fatalf("unexpected reauthentication cookie: %q", secondCookie)
	}
	cstpOptions.Cookie = secondCookie
	if _, err := RunAnyConnectCSTPProbe(ctx, cstpOptions); err != nil {
		t.Fatal(err)
	}
	if err := phase0CapabilityMatrix.Record(Evidence{
		Capability: CapabilityAuth,
		Scenario:   "multiround-expiry-reauthentication",
		Driver:     DriverProbe,
		Gateway:    "fake",
		Transport:  "https",
		Address:    "ipv4",
		Passed:     true,
	}); err != nil {
		t.Fatal(err)
	}
	for _, record := range recorder.Records() {
		for _, secret := range []string{scenario.Authentication.Password, scenario.Authentication.ChallengeResponse, firstCookie, secondCookie} {
			if strings.Contains(record.Message, secret) {
				t.Fatalf("authentication secret leaked into record %#v", record)
			}
		}
	}
}

func TestFakeAuthenticationProbeRejectsCredentialsAndChallenge(t *testing.T) {
	scenario := BasicAnyConnectScenario()
	scenario.Authentication = AnyConnectAuthenticationScenario{
		Enabled:           true,
		Username:          "phase0-user",
		Password:          "phase0-password",
		Challenge:         "Second factor",
		ChallengeResponse: "654321",
	}
	gateway, _, ctx := startProbeTestGateway(t, scenario)
	base := AnyConnectAuthProbeOptions{
		Address:           gateway.Address(),
		ServerName:        gateway.ServerName(),
		RootCAs:           gateway.RootCAs(),
		Username:          scenario.Authentication.Username,
		Password:          "wrong-password",
		ChallengeResponse: scenario.Authentication.ChallengeResponse,
	}
	if _, err := RunAnyConnectAuthProbe(ctx, base); err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("expected credential rejection, got %v", err)
	}
	base.Password = scenario.Authentication.Password
	base.ChallengeResponse = "wrong-code"
	if _, err := RunAnyConnectAuthProbe(ctx, base); err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("expected challenge rejection, got %v", err)
	}
}

func TestAuthenticationScenarioValidation(t *testing.T) {
	tests := []struct {
		name    string
		value   AnyConnectAuthenticationScenario
		message string
	}{
		{name: "credentials", value: AnyConnectAuthenticationScenario{Enabled: true}, message: "username"},
		{name: "challenge", value: AnyConnectAuthenticationScenario{Enabled: true, Username: "u", Password: "p", Challenge: "value"}, message: "together"},
		{name: "cookie uses", value: AnyConnectAuthenticationScenario{Enabled: true, Username: "u", Password: "p", CookieUses: -1}, message: "uses"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scenario := BasicAnyConnectScenario()
			scenario.Authentication = test.value
			if err := scenario.Validate(); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("expected error containing %q, got %v", test.message, err)
			}
		})
	}
}
