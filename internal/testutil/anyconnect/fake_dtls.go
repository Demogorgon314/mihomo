package anyconnect

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/pion/dtls/v3"
)

const maximumDTLSPacketSize = maximumCSTPMTU + 1

func (g *Gateway) Set([]byte, dtls.Session) error { return nil }

func (g *Gateway) Get(key []byte) (dtls.Session, error) {
	if g.scenario.InjectedDTLS {
		if !bytes.Equal(key, fakeDTLSSessionID()) {
			return dtls.Session{}, errors.New("DTLS ClientHello did not contain the injected session ID")
		}
		g.pskLock.RLock()
		secret := append([]byte(nil), g.dtlsMasterSecret...)
		g.pskLock.RUnlock()
		if len(secret) != 48 {
			return dtls.Session{}, errors.New("fake gateway DTLS master secret is not ready")
		}
		g.dtlsResumeObserved.Store(true)
		g.record("dtls-injected-resumption", "resumed the injected DTLS session")
		return dtls.Session{ID: append([]byte(nil), key...), Secret: secret}, nil
	}
	if len(g.scenario.DTLSAppID) == 0 {
		return dtls.Session{}, nil
	}
	if !bytes.Equal(key, g.scenario.DTLSAppID) {
		return dtls.Session{}, errors.New("DTLS ClientHello did not contain the advertised App ID")
	}
	g.dtlsAppIDObserved.Store(true)
	g.record("dtls-app-id", "observed advertised App ID in ClientHello")
	return dtls.Session{}, nil
}

func (g *Gateway) Del([]byte) error { return nil }

func (g *Gateway) DTLSAppIDObserved() bool { return g != nil && g.dtlsAppIDObserved.Load() }

func (g *Gateway) DTLSInjectedResumptionObserved() bool {
	return g != nil && g.dtlsResumeObserved.Load()
}

// ModernDTLSPSKOffered reports whether the CSTP client advertised modern PSK negotiation.
func (g *Gateway) ModernDTLSPSKOffered() bool {
	return g != nil && g.modernDTLSPSKOffered.Load()
}

func (g *Gateway) dtlsPSK([]byte) ([]byte, error) {
	g.pskLock.RLock()
	defer g.pskLock.RUnlock()
	secret := g.psk
	if g.scenario.InjectedDTLS {
		secret = g.dtlsMasterSecret
	}
	if len(secret) == 0 {
		return nil, errors.New("fake gateway DTLS PSK is not ready")
	}
	return append([]byte(nil), secret...), nil
}

func (g *Gateway) claimDTLSSession(psk []byte, masterSecret []byte) bool {
	g.pskLock.Lock()
	defer g.pskLock.Unlock()
	if g.dtlsOwnerActive {
		return false
	}
	g.dtlsOwnerActive = true
	g.psk = append(g.psk[:0], psk...)
	g.dtlsMasterSecret = append(g.dtlsMasterSecret[:0], masterSecret...)
	return true
}

func (g *Gateway) releaseDTLSSession() {
	g.pskLock.Lock()
	g.dtlsOwnerActive = false
	clear(g.psk)
	g.psk = nil
	clear(g.dtlsMasterSecret)
	g.dtlsMasterSecret = nil
	g.pskLock.Unlock()
	g.legacyLock.Lock()
	if g.legacySession != nil {
		g.legacySession.destroy()
	}
	g.legacySession = nil
	g.legacyLock.Unlock()
	g.dropDTLSConnections(false)
}

func fakeDTLSSessionID() []byte { return bytes.Repeat([]byte{0x42}, 32) }

// DropDTLSConnections simulates an unavailable UDP data channel while leaving CSTP alive.
func (g *Gateway) DropDTLSConnections() int {
	return g.dropDTLSConnections(true)
}

// SetDTLSBlackhole controls whether established DTLS application packets are discarded.
func (g *Gateway) SetDTLSBlackhole(enabled bool) {
	if g == nil {
		return
	}
	g.dtlsBlackhole.Store(enabled)
	if enabled {
		g.record("dtls-blackhole", "discarding DTLS application packets")
	}
}

func (g *Gateway) dropDTLSConnections(record bool) int {
	if g == nil {
		return 0
	}
	g.dtlsConnLock.Lock()
	connections := make([]net.Conn, 0, len(g.dtlsConnections))
	for connection := range g.dtlsConnections {
		connections = append(connections, connection)
		g.dtlsDropped[connection] = struct{}{}
	}
	g.dtlsConnLock.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	if record && len(connections) > 0 {
		g.record("dtls-eof", "dropped active DTLS connection")
	}
	return len(connections)
}

func (g *Gateway) acceptDTLSLoop() {
	defer g.waitGroup.Done()
	for {
		connection, err := g.dtlsListener.Accept()
		if err != nil {
			if g.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				g.addError(fmt.Errorf("accept fake DTLS connection: %w", err))
			}
			return
		}
		g.connLock.Lock()
		g.conns[connection] = struct{}{}
		g.connLock.Unlock()
		g.dtlsConnLock.Lock()
		g.dtlsConnections[connection] = struct{}{}
		g.dtlsConnLock.Unlock()
		g.waitGroup.Add(1)
		go func() {
			defer g.waitGroup.Done()
			defer func() {
				g.connLock.Lock()
				delete(g.conns, connection)
				g.connLock.Unlock()
				g.dtlsConnLock.Lock()
				delete(g.dtlsConnections, connection)
				g.dtlsConnLock.Unlock()
			}()
			defer connection.Close()
			handleErr := g.handleDTLSConnection(connection)
			expectedClose := g.consumeDroppedDTLSConnection(connection)
			if handleErr != nil && !expectedClose {
				g.addError(handleErr)
			}
		}()
	}
}

func (g *Gateway) consumeDroppedDTLSConnection(connection net.Conn) bool {
	g.dtlsConnLock.Lock()
	_, dropped := g.dtlsDropped[connection]
	delete(g.dtlsDropped, connection)
	g.dtlsConnLock.Unlock()
	return dropped
}

func (g *Gateway) handleDTLSConnection(connection net.Conn) error {
	packet := make([]byte, maximumDTLSPacketSize)
	for {
		length, err := connection.Read(packet)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read fake DTLS packet: %w", err)
		}
		if length == 0 {
			return errors.New("read empty fake DTLS packet")
		}
		if g.dtlsBlackhole.Load() {
			continue
		}
		switch packet[0] {
		case cstpPacketData:
			replies, peerErr := handlePeerPackets(g.peer, packet[1:length])
			if peerErr != nil {
				return fmt.Errorf("handle DTLS tunneled packet: %w", peerErr)
			}
			for _, reply := range replies {
				response := make([]byte, len(reply)+1)
				response[0] = cstpPacketData
				copy(response[1:], reply)
				if _, writeErr := connection.Write(response); writeErr != nil {
					return fmt.Errorf("write fake DTLS data packet: %w", writeErr)
				}
				g.record("dtls-data", fmt.Sprintf("replied with %d-byte packet", len(reply)))
			}
		case cstpPacketDPDRequest:
			if g.scenario.DTLSMTU != 0 && length > int(g.scenario.DTLSMTU)+1 {
				continue
			}
			response := append([]byte(nil), packet[:length]...)
			response[0] = cstpPacketDPDResponse
			if _, writeErr := connection.Write(response); writeErr != nil {
				return fmt.Errorf("write fake DTLS DPD response: %w", writeErr)
			}
		case cstpPacketKeepalive:
			continue
		default:
			return fmt.Errorf("unexpected DTLS packet type: %d", packet[0])
		}
	}
}
