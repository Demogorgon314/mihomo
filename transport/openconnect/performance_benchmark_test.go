package openconnect

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	testopenconnect "github.com/metacubex/mihomo/internal/testutil/openconnect"
)

// BenchmarkAnyConnectP3DataPlaneReady isolates the steady-state revision and
// DTLS readiness gate. Setup first proves that a revision-tagged packet makes a
// complete modern-DTLS round trip; every timed lookup must return that revision.
func BenchmarkAnyConnectP3DataPlaneReady(b *testing.B) {
	scenario := testopenconnect.BasicAnyConnectScenario()
	scenario.ModernDTLS = true
	scenario.DTLSMTU = 1200
	scenario.DTLSAppID = []byte("mihomo-dtls-app")
	client, gateway, _, ctx := newDTLSTestClientForScenarioWithLegacyTimeout(
		b,
		scenario,
		DTLSModeRequire,
		false,
		"",
		false,
		30*time.Second,
	)
	b.Cleanup(func() {
		if err := client.Close(); err != nil {
			b.Errorf("close AnyConnect client: %v", err)
		}
		if err := gateway.Close(); err != nil {
			b.Errorf("close AnyConnect gateway: %v", err)
		}
	})

	if _, err := client.WaitReady(ctx); err != nil {
		b.Fatal(err)
	}
	revision, err := client.WaitDataPlaneReady(ctx)
	if err != nil {
		b.Fatal(err)
	}
	if revision == 0 || client.ActiveTransport() != "dtls" {
		b.Fatalf("invalid benchmark data plane: revision=%d transport=%q", revision, client.ActiveTransport())
	}
	request, err := testopenconnect.BuildIPv4ICMPEchoRequest(
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.1"),
		73,
		1,
		[]byte("p3-correctness"),
	)
	if err != nil {
		b.Fatal(err)
	}
	if err = client.WritePacketAtRevision(request, revision); err != nil {
		b.Fatal(err)
	}
	reply, replyRevision, err := client.ReadPacketWithRevision(ctx)
	if err != nil {
		b.Fatal(err)
	}
	if replyRevision != revision || len(reply) < 28 || string(reply[28:]) != "p3-correctness" {
		b.Fatalf("revision-tagged DTLS preflight failed: revision=%d payload=%q", replyRevision, reply[28:])
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		readyRevision, readyErr := client.WaitDataPlaneReady(context.Background())
		if readyErr != nil {
			b.Fatal(readyErr)
		}
		if readyRevision != revision {
			b.Fatal(fmt.Errorf("data-plane revision changed: got %d, want %d", readyRevision, revision))
		}
	}
}
