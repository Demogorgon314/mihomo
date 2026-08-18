package openconnect

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	testopenconnect "github.com/metacubex/mihomo/internal/testutil/openconnect"
	openconnect "github.com/sagernet/sing-openconnect"
)

type authProviderFunc func(ctx context.Context, challenge AuthChallenge) (AuthResponse, error)

type secretTerminalError string

func (e secretTerminalError) Error() string  { return string(e) }
func (e secretTerminalError) Terminal() bool { return true }

func (f authProviderFunc) Respond(ctx context.Context, challenge AuthChallenge) (AuthResponse, error) {
	return f(ctx, challenge)
}

func TestClientStaticCredentialsAndFormEntry(t *testing.T) {
	client, _, closeGateway := newAuthenticatedTestClient(t, nil, func(config *Config) {
		config.Username = "phase2-user"
		config.Password = "phase2-password"
		config.FormEntries = []FormEntry{{FormID: "challenge", Name: "answer", Value: "phase2-answer"}}
	})
	defer closeGateway()
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case event := <-client.Events():
			if event.Type != EventNetworkConfig && event.Type != EventActiveTransport {
				t.Fatalf("static authentication unexpectedly emitted an auth event: %#v", event)
			}
		default:
			return
		}
	}
}

func TestClientAuthProvidersIsolateConcurrentChallenges(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type fixture struct {
		client    *Client
		challenge string
		observed  chan AuthChallenge
		close     func()
	}
	fixtures := make([]fixture, 0, 2)
	for index := range 2 {
		challengeText := fmt.Sprintf("session-%d-challenge", index)
		answer := fmt.Sprintf("session-%d-answer", index)
		observed := make(chan AuthChallenge, 1)
		provider := authProviderFunc(func(_ context.Context, challenge AuthChallenge) (AuthResponse, error) {
			observed <- challenge
			if challenge.Message != challengeText || challenge.Form == nil || len(challenge.Form.Fields) != 1 {
				return AuthResponse{}, errors.New("challenge crossed authentication sessions")
			}
			field := challenge.Form.Fields[0]
			if field.Kind != AuthFormFieldPassword || field.Name != "answer" {
				return AuthResponse{}, errors.New("unexpected challenge field")
			}
			return AuthResponse{FormValues: map[string]string{field.SubmissionKey: answer}}, nil
		})
		client, _, closeGateway := newAuthenticatedTestClientWithScenario(t, provider, func(scenario *testopenconnect.AnyConnectScenario) {
			scenario.Name = fmt.Sprintf("auth-session-%d", index)
			scenario.Authentication.Challenge = challengeText
			scenario.Authentication.ChallengeResponse = answer
		}, func(config *Config) {
			config.Username = "phase2-user"
			config.Password = "phase2-password"
		})
		fixtures = append(fixtures, fixture{client: client, challenge: challengeText, observed: observed, close: closeGateway})
	}
	defer func() {
		for _, fixture := range fixtures {
			_ = fixture.client.Close()
			fixture.close()
		}
	}()
	results := make(chan error, len(fixtures))
	var wait sync.WaitGroup
	for _, fixture := range fixtures {
		wait.Add(1)
		go func(client *Client) {
			defer wait.Done()
			if err := client.Start(); err != nil {
				results <- err
				return
			}
			_, err := client.WaitReady(ctx)
			results <- err
		}(fixture.client)
	}
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, fixture := range fixtures {
		select {
		case challenge := <-fixture.observed:
			if challenge.Message != fixture.challenge {
				t.Fatalf("provider observed the wrong challenge: %#v", challenge)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		select {
		case event := <-fixture.client.Events():
			if event.Type != EventAuthChallenge || event.Challenge == nil || event.Challenge.Message != fixture.challenge {
				t.Fatalf("unexpected auth event: %#v", event)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func TestClientMissingProviderReturnsTypedAuthRequired(t *testing.T) {
	client, _, closeGateway := newAuthenticatedTestClient(t, nil, func(config *Config) {
		config.Username = "phase2-user"
	})
	defer closeGateway()
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	_, err := client.WaitReady(ctx)
	if !errors.Is(err, ErrAuthRequired) || !IsTerminal(err) {
		t.Fatalf("expected terminal auth-required error, got %v", err)
	}
}

func TestClientProviderFailureIsTerminalAndRedacted(t *testing.T) {
	secret := "provider-answer-must-not-leak"
	provider := authProviderFunc(func(context.Context, AuthChallenge) (AuthResponse, error) {
		return AuthResponse{}, errors.New(secret)
	})
	client, _, closeGateway := newAuthenticatedTestClient(t, provider, func(config *Config) {
		config.Username = "phase2-user"
	})
	defer closeGateway()
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	_, err := client.WaitReady(ctx)
	if !errors.Is(err, ErrAuthProvider) || !IsTerminal(err) {
		t.Fatalf("expected terminal provider error, got %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("provider error leaked a form answer: %v", err)
	}
}

func TestTerminalErrorRedactionDoesNotExposeSecretCause(t *testing.T) {
	secret := "terminal-secret"
	err := classifyClientError(secretTerminalError("authentication failed: "+secret), []string{secret})
	if !IsTerminal(err) || strings.Contains(err.Error(), secret) {
		t.Fatalf("terminal error was not safely redacted: %v", err)
	}
	for cause := errors.Unwrap(err); cause != nil; cause = errors.Unwrap(cause) {
		if strings.Contains(cause.Error(), secret) {
			t.Fatalf("terminal error chain exposed a secret: %v", cause)
		}
	}
}

func TestAuthChallengeHidesPrefilledSecretsAndPreservesAutomaticValues(t *testing.T) {
	password := "configured-password"
	formAnswer := "configured-form-answer"
	coreChallenge := openconnect.AuthChallenge{
		Banner: "do not expose " + formAnswer,
		Form: &openconnect.AuthForm{Fields: []openconnect.AuthFormField{
			{SubmissionKey: "main:password:0", Name: "password", Kind: openconnect.AuthFormFieldPassword, Value: password},
			{SubmissionKey: "main:answer:1", Name: "answer", Kind: openconnect.AuthFormFieldText, Value: formAnswer},
			{SubmissionKey: "main:otp:2", Name: "otp", Kind: openconnect.AuthFormFieldPassword},
		}},
	}
	challenge := sanitizeAuthChallenge(authChallengeFromCore(coreChallenge), []string{password, formAnswer})
	if challenge.Form.Fields[0].Value != "" || challenge.Form.Fields[1].Value != "[redacted]" || strings.Contains(challenge.Banner, formAnswer) {
		t.Fatalf("authentication challenge exposed a configured secret: %#v", challenge)
	}
	response := authResponseToCore(AuthResponse{FormValues: map[string]string{
		"main:password:0": challenge.Form.Fields[0].Value,
		"main:answer:1":   challenge.Form.Fields[1].Value,
		"main:otp:2":      "provider-otp",
	}})
	mergeCoreFormValues(coreChallenge, challenge, &response)
	if response.Form.Values["main:password:0"] != password || response.Form.Values["main:answer:1"] != formAnswer || response.Form.Values["main:otp:2"] != "provider-otp" {
		t.Fatalf("automatic and provider authentication values were not merged: %#v", response.Form.Values)
	}
}

func TestClientCloseCancelsPendingAuthProvider(t *testing.T) {
	providerStarted := make(chan struct{})
	providerCanceled := make(chan struct{})
	provider := authProviderFunc(func(ctx context.Context, _ AuthChallenge) (AuthResponse, error) {
		close(providerStarted)
		<-ctx.Done()
		close(providerCanceled)
		return AuthResponse{}, ctx.Err()
	})
	client, _, closeGateway := newAuthenticatedTestClient(t, provider, func(config *Config) {
		config.Username = "phase2-user"
	})
	defer closeGateway()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	select {
	case <-providerStarted:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-providerCanceled:
	case <-ctx.Done():
		t.Fatal("Close did not cancel the pending authentication provider")
	}
}

func TestClientAuthGroupSelectProvider(t *testing.T) {
	provider := authProviderFunc(func(_ context.Context, challenge AuthChallenge) (AuthResponse, error) {
		if challenge.Form == nil || len(challenge.Form.Fields) != 1 {
			return AuthResponse{}, errors.New("expected one authgroup field")
		}
		field := challenge.Form.Fields[0]
		if field.Kind != AuthFormFieldSelect || field.Name != "group_list" || len(field.Options) != 2 {
			return AuthResponse{}, errors.New("unexpected authgroup field")
		}
		return AuthResponse{FormValues: map[string]string{field.SubmissionKey: "engineering"}}, nil
	})
	client, _, closeGateway := newAuthenticatedTestClientWithScenario(t, provider, func(scenario *testopenconnect.AnyConnectScenario) {
		scenario.Authentication.AuthGroup = "engineering"
		scenario.Authentication.Challenge = ""
		scenario.Authentication.ChallengeResponse = ""
	}, func(config *Config) {
		config.Username = "phase2-user"
		config.Password = "phase2-password"
	})
	defer closeGateway()
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestClientAutomaticTOTPAndHOTP(t *testing.T) {
	secretBytes := []byte("phase2-token-secret")
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)
	t.Run("totp", func(t *testing.T) {
		counter := uint64(time.Now().Unix() / 30)
		responses := []string{oathCode(secretBytes, counter-1), oathCode(secretBytes, counter), oathCode(secretBytes, counter+1)}
		client, _, closeGateway := newAuthenticatedTestClientWithScenario(t, nil, func(scenario *testopenconnect.AnyConnectScenario) {
			scenario.Authentication.ChallengeResponses = responses
			scenario.Authentication.ChallengeResponse = ""
		}, func(config *Config) {
			config.Username = "phase2-user"
			config.Password = "phase2-password"
			config.Token = &TokenConfig{Mode: TokenModeTOTP, Secret: secret}
		})
		defer closeGateway()
		defer func() { _ = client.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.Start(); err != nil {
			t.Fatal(err)
		}
		if _, err := client.WaitReady(ctx); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("hotp", func(t *testing.T) {
		var persisted atomic.Uint64
		client, _, closeGateway := newAuthenticatedTestClientWithScenario(t, nil, func(scenario *testopenconnect.AnyConnectScenario) {
			scenario.Authentication.ChallengeResponse = oathCode(secretBytes, 7)
		}, func(config *Config) {
			config.Username = "phase2-user"
			config.Password = "phase2-password"
			config.Token = &TokenConfig{
				Mode:    TokenModeHOTP,
				Secret:  secret,
				Counter: 7,
				UpdateCounter: func(_ context.Context, counter uint64) error {
					persisted.Store(counter)
					return nil
				},
			}
		})
		defer closeGateway()
		defer func() { _ = client.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.Start(); err != nil {
			t.Fatal(err)
		}
		if _, err := client.WaitReady(ctx); err != nil {
			t.Fatal(err)
		}
		if persisted.Load() != 8 {
			t.Fatalf("HOTP counter was not persisted: %d", persisted.Load())
		}
	})
}

func TestClientWithoutProviderDisablesExternalAuthentication(t *testing.T) {
	client, _, closeGateway := newAuthenticatedTestClientWithScenario(t, nil, func(scenario *testopenconnect.AnyConnectScenario) {
		scenario.Authentication.Browser = true
		scenario.Authentication.Challenge = ""
		scenario.Authentication.ChallengeResponse = ""
	}, func(config *Config) {
		config.Username = "phase2-user"
	})
	defer closeGateway()
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	_, err := client.WaitReady(ctx)
	if err == nil || !IsTerminal(err) || !strings.Contains(err.Error(), "disabled external authentication") {
		t.Fatalf("expected disabled external authentication error, got %v", err)
	}
}

func TestClientBrowserRequestEmitsEventWithProvider(t *testing.T) {
	provider := authProviderFunc(func(context.Context, AuthChallenge) (AuthResponse, error) {
		return AuthResponse{}, errors.New("stop browser authentication")
	})
	client, _, closeGateway := newAuthenticatedTestClientWithScenario(t, provider, func(scenario *testopenconnect.AnyConnectScenario) {
		scenario.Authentication.Browser = true
		scenario.Authentication.Challenge = ""
		scenario.Authentication.ChallengeResponse = ""
	}, func(config *Config) {
		config.Username = "phase2-user"
	})
	defer closeGateway()
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WaitReady(ctx); !errors.Is(err, ErrAuthProvider) || !IsTerminal(err) {
		t.Fatalf("expected browser provider error, got %v", err)
	}
	select {
	case event := <-client.Events():
		if event.Type != EventBrowserRequested || event.Challenge == nil || event.Challenge.Browser == nil || event.Challenge.Browser.URL == "" {
			t.Fatalf("unexpected browser event: %#v", event)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestClientHostScanIsReportedAndBlockedByPolicy(t *testing.T) {
	client, _, closeGateway := newAuthenticatedTestClientWithScenario(t, nil, func(scenario *testopenconnect.AnyConnectScenario) {
		scenario.Authentication.HostScan = true
		scenario.Authentication.Challenge = ""
		scenario.Authentication.ChallengeResponse = ""
	}, func(config *Config) {
		config.Username = "phase2-user"
	})
	defer closeGateway()
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	_, err := client.WaitReady(ctx)
	if !errors.Is(err, ErrHostScanPolicy) || !IsTerminal(err) {
		t.Fatalf("expected terminal host-scan policy error, got %v", err)
	}
	select {
	case event := <-client.Events():
		if event.Type != EventHostScanRequested || event.Challenge != nil {
			t.Fatalf("unexpected host-scan event: %#v", event)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func newAuthenticatedTestClient(t *testing.T, provider AuthProvider, mutate func(config *Config)) (*Client, testopenconnect.AnyConnectScenario, func()) {
	return newAuthenticatedTestClientWithScenario(t, provider, nil, mutate)
}

func newAuthenticatedTestClientWithScenario(t *testing.T, provider AuthProvider, mutateScenario func(*testopenconnect.AnyConnectScenario), mutate func(config *Config)) (*Client, testopenconnect.AnyConnectScenario, func()) {
	t.Helper()
	scenario := testopenconnect.BasicAnyConnectScenario()
	scenario.Authentication = testopenconnect.AnyConnectAuthenticationScenario{
		Enabled:           true,
		Username:          "phase2-user",
		Password:          "phase2-password",
		Challenge:         "Phase 2 second factor",
		ChallengeResponse: "phase2-answer",
	}
	if mutateScenario != nil {
		mutateScenario(&scenario)
	}
	peer, err := testopenconnect.NewIPv4ICMPEchoPeer(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	gateway, err := testopenconnect.StartAnyConnectGateway(ctx, scenario, peer, testopenconnect.NewRecorder(
		scenario.Cookie,
		scenario.Authentication.Password,
		scenario.Authentication.ChallengeResponse,
	))
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
	config := Config{
		Server:               "https://" + gateway.ServerName() + ":" + port,
		ServerName:           gateway.ServerName(),
		CertificateAuthority: testopenconnect.AnyConnectRootCAPEM(),
	}
	mutate(&config)
	client, err := NewClient(ctx, config, new(recordingDialer), provider)
	if err != nil {
		_ = gateway.Close()
		cancel()
		t.Fatal(err)
	}
	return client, scenario, func() {
		_ = gateway.Close()
		cancel()
	}
}

func oathCode(secret []byte, counter uint64) string {
	message := [8]byte{}
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(message[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}
