package anyconnect

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	testanyconnect "github.com/metacubex/mihomo/internal/testutil/anyconnect"
)

type dtlsTestDialer struct {
	recordingDialer
	access    sync.Mutex
	udp       int
	failUDP   bool
	fault     string
	faulted   bool
	faultConn *dtlsFaultConn
}

func (d *dtlsTestDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "udp" {
		return d.recordingDialer.DialContext(ctx, network, address)
	}
	d.access.Lock()
	d.udp++
	fail := d.failUDP
	fault := d.fault
	d.access.Unlock()
	if fail {
		return nil, errors.New("injected UDP underlay failure")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil || fault == "" {
		return connection, err
	}
	faultConnection := &dtlsFaultConn{Conn: connection, onFault: func() {
		d.access.Lock()
		d.faulted = true
		d.access.Unlock()
	}}
	if fault == "handshake-blackhole" || fault == "wrong-server-flight" {
		faultConnection.arm(fault)
	}
	d.access.Lock()
	d.faultConn = faultConnection
	d.access.Unlock()
	return faultConnection, nil
}

func (d *dtlsTestDialer) ListenPacket(ctx context.Context, network, _ string, _ netip.AddrPort) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, network, "")
}

func (d *dtlsTestDialer) udpCalls() int {
	d.access.Lock()
	defer d.access.Unlock()
	return d.udp
}

func (d *dtlsTestDialer) faultApplied() bool {
	d.access.Lock()
	defer d.access.Unlock()
	return d.faulted
}

func (d *dtlsTestDialer) armFault() bool {
	d.access.Lock()
	connection := d.faultConn
	fault := d.fault
	d.access.Unlock()
	if connection == nil || fault == "" {
		return false
	}
	connection.arm(fault)
	return true
}

type dtlsFaultConn struct {
	net.Conn
	access  sync.Mutex
	mode    string
	armed   bool
	writes  int
	pending []byte
	onFault func()
}

func (c *dtlsFaultConn) arm(mode string) {
	c.access.Lock()
	c.mode = mode
	c.armed = true
	c.writes = 0
	c.pending = nil
	c.access.Unlock()
}

func (c *dtlsFaultConn) Write(payload []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if !c.armed {
		return c.Conn.Write(payload)
	}
	c.writes++
	switch c.mode {
	case "handshake-blackhole":
		if c.writes == 1 {
			c.onFault()
		}
		return len(payload), nil
	case "loss":
		if c.writes == 1 {
			c.onFault()
			c.armed = false
			return len(payload), nil
		}
	case "duplicate":
		if c.writes == 1 {
			c.onFault()
			if _, err := c.Conn.Write(payload); err != nil {
				return 0, err
			}
			if _, err := c.Conn.Write(payload); err != nil {
				return 0, err
			}
			c.armed = false
			return len(payload), nil
		}
	case "reorder":
		if c.writes == 1 {
			c.pending = append([]byte(nil), payload...)
			return len(payload), nil
		}
		if c.writes == 2 {
			c.onFault()
			if _, err := c.Conn.Write(payload); err != nil {
				return 0, err
			}
			if _, err := c.Conn.Write(c.pending); err != nil {
				return 0, err
			}
			c.pending = nil
			c.armed = false
			return len(payload), nil
		}
	}
	return c.Conn.Write(payload)
}

func (c *dtlsFaultConn) Read(payload []byte) (int, error) {
	c.access.Lock()
	wrongFlight := c.armed && c.mode == "wrong-server-flight"
	c.access.Unlock()
	if !wrongFlight {
		return c.Conn.Read(payload)
	}
	buffer := make([]byte, len(payload))
	if _, err := c.Conn.Read(buffer); err != nil {
		return 0, err
	}
	c.onFault()
	return copy(payload, []byte{0xff, 0x00, 0xff}), nil
}

func TestClientDTLSModesAndFallback(t *testing.T) {
	t.Run("off", func(t *testing.T) {
		client, gateway, dialer, ctx := newDTLSTestClient(t, DTLSModeOff, false, "")
		defer func() { _ = client.Close() }()
		defer func() { _ = gateway.Close() }()
		if _, err := client.WaitReady(ctx); err != nil {
			t.Fatal(err)
		}
		waitForTransportEvent(t, ctx, client, "cstp")
		if dialer.udpCalls() != 0 || client.ActiveTransport() != "cstp" {
			t.Fatalf("DTLS off used UDP or selected the wrong transport: udp=%d transport=%q", dialer.udpCalls(), client.ActiveTransport())
		}
	})

	t.Run("auto fallback", func(t *testing.T) {
		client, gateway, _, ctx := newDTLSTestClient(t, DTLSModeAuto, false, "")
		defer func() { _ = client.Close() }()
		defer func() { _ = gateway.Close() }()
		configuration, err := client.WaitReady(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if configuration.MTU != 1200 {
			t.Fatalf("DTLS path MTU was not applied: %d", configuration.MTU)
		}
		waitForTransportEvent(t, ctx, client, "dtls")
		if !gateway.DTLSAppIDObserved() {
			t.Fatal("modern DTLS ClientHello did not carry the advertised App ID")
		}
		exchangeFacadeICMP(t, ctx, client, "dtls")
		if gateway.DropDTLSConnections() != 1 {
			t.Fatal("fake gateway did not have one active DTLS connection")
		}
		waitForTransportEvent(t, ctx, client, "cstp")
		exchangeFacadeICMP(t, ctx, client, "cstp-fallback")
	})

	t.Run("require initial failure", func(t *testing.T) {
		client, gateway, dialer, ctx := newDTLSTestClient(t, DTLSModeRequire, true, "")
		defer func() { _ = client.Close() }()
		defer func() { _ = gateway.Close() }()
		waitCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		_, err := client.WaitReady(waitCtx)
		if !errors.Is(err, ErrDTLSRequired) || dialer.udpCalls() == 0 {
			t.Fatalf("require mode did not fail closed after a UDP attempt: err=%v udp=%d", err, dialer.udpCalls())
		}
	})

	t.Run("require runtime failure", func(t *testing.T) {
		client, gateway, _, ctx := newDTLSTestClient(t, DTLSModeRequire, false, "")
		defer func() { _ = client.Close() }()
		defer func() { _ = gateway.Close() }()
		if _, err := client.WaitReady(ctx); err != nil {
			t.Fatal(err)
		}
		waitForTransportEvent(t, ctx, client, "dtls")
		if gateway.DropDTLSConnections() != 1 {
			t.Fatal("fake gateway did not have one active DTLS connection")
		}
		waitForTransportEvent(t, ctx, client, "cstp")
		if err := client.transportFailure(); !errors.Is(err, ErrDTLSRequired) {
			t.Fatalf("require mode did not latch runtime CSTP fallback: %v", err)
		}
	})
}

func TestClientDTLSDataDatagramFaults(t *testing.T) {
	for _, fault := range []string{"loss", "duplicate", "reorder"} {
		t.Run(fault, func(t *testing.T) {
			client, gateway, dialer, ctx := newDTLSTestClient(t, DTLSModeAuto, false, fault)
			defer func() { _ = client.Close() }()
			defer func() { _ = gateway.Close() }()
			if _, err := client.WaitReady(ctx); err != nil {
				t.Fatal(err)
			}
			waitForTransportEvent(t, ctx, client, "dtls")
			if !dialer.armFault() {
				t.Fatalf("could not arm %s fault on the established DTLS connection", fault)
			}
			writeFacadeICMP(t, client, 1, "first")
			writeFacadeICMP(t, client, 2, "second")
			if !dialer.faultApplied() {
				t.Fatalf("%s fault was not applied to DTLS data records", fault)
			}
			first := readFacadeICMP(t, ctx, client)
			switch fault {
			case "loss":
				if first != "second" {
					t.Fatalf("lost DTLS record was delivered: %q", first)
				}
			case "duplicate":
				second := readFacadeICMP(t, ctx, client)
				if first != "first" || second != "second" {
					t.Fatalf("duplicate DTLS record was not filtered: first=%q second=%q", first, second)
				}
			case "reorder":
				second := readFacadeICMP(t, ctx, client)
				if first != "second" || second != "first" {
					t.Fatalf("DTLS records were not reordered: first=%q second=%q", first, second)
				}
			}
		})
	}
}

func TestClientDTLSHandshakeFailures(t *testing.T) {
	for _, fault := range []string{"handshake-blackhole", "wrong-server-flight"} {
		t.Run(fault, func(t *testing.T) {
			client, gateway, dialer, ctx := newDTLSTestClient(t, DTLSModeRequire, false, fault)
			defer func() { _ = client.Close() }()
			defer func() { _ = gateway.Close() }()
			waitCtx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
			defer cancel()
			if _, err := client.WaitReady(waitCtx); !errors.Is(err, ErrDTLSRequired) {
				t.Fatalf("require mode accepted %s: %v", fault, err)
			}
			if !dialer.faultApplied() {
				t.Fatalf("%s was not applied to the DTLS handshake", fault)
			}
		})
	}
}

func TestClientDTLSInjectedResumption(t *testing.T) {
	scenario := testanyconnect.BasicCSTPScenario()
	scenario.ModernDTLS = true
	scenario.InjectedDTLS = true
	client, gateway, _, ctx := newDTLSTestClientForScenario(t, scenario, DTLSModeRequire, false, "")
	defer func() { _ = client.Close() }()
	defer func() { _ = gateway.Close() }()
	if _, err := client.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	waitForTransportEvent(t, ctx, client, "dtls")
	if !gateway.DTLSInjectedResumptionObserved() {
		t.Fatal("fake gateway did not observe the injected DTLS session resumption")
	}
	exchangeFacadeICMP(t, ctx, client, "injected-resumption")
}

func newDTLSTestClient(t *testing.T, mode string, failUDP bool, fault string) (*Client, *testanyconnect.Gateway, *dtlsTestDialer, context.Context) {
	t.Helper()
	scenario := testanyconnect.BasicCSTPScenario()
	scenario.ModernDTLS = true
	scenario.DTLSMTU = 1200
	scenario.DTLSAppID = []byte("mihomo-dtls-app")
	return newDTLSTestClientForScenario(t, scenario, mode, failUDP, fault)
}

func newDTLSTestClientForScenario(t *testing.T, scenario testanyconnect.Scenario, mode string, failUDP bool, fault string) (*Client, *testanyconnect.Gateway, *dtlsTestDialer, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	peer, err := testanyconnect.NewIPv4ICMPEchoPeer(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := testanyconnect.StartGateway(ctx, scenario, peer, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(gateway.Address())
	if err != nil {
		t.Fatal(err)
	}
	dialer := &dtlsTestDialer{failUDP: failUDP, fault: fault}
	client, err := NewClient(ctx, Config{
		Server:               "https://" + gateway.ServerName() + ":" + port,
		Cookie:               scenario.Cookie,
		ServerName:           gateway.ServerName(),
		CertificateAuthority: testanyconnect.RootCAPEM(),
		DTLSMode:             mode,
	}, dialer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	return client, gateway, dialer, ctx
}

func waitForTransportEvent(t *testing.T, ctx context.Context, client *Client, transport string) {
	t.Helper()
	for {
		select {
		case event, open := <-client.Events():
			if !open {
				t.Fatal("client event stream closed before transport transition")
			}
			if event.Type == EventActiveTransport && event.ActiveTransport == transport {
				return
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func exchangeFacadeICMP(t *testing.T, ctx context.Context, client *Client, payload string) {
	t.Helper()
	writeFacadeICMP(t, client, 1, payload)
	if reply := readFacadeICMP(t, ctx, client); reply != payload {
		t.Fatalf("unexpected %s reply: %q", payload, reply)
	}
}

func writeFacadeICMP(t *testing.T, client *Client, sequence uint16, payload string) {
	t.Helper()
	request, err := testanyconnect.BuildIPv4ICMPEchoRequest(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"), 61, sequence, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WritePacket(request); err != nil {
		t.Fatal(err)
	}
}

func readFacadeICMP(t *testing.T, ctx context.Context, client *Client) string {
	t.Helper()
	reply, err := client.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) < 28 {
		t.Fatalf("short ICMP reply: %x", reply)
	}
	return string(reply[28:])
}
