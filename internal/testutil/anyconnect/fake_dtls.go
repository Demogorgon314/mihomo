package anyconnect

import (
	"errors"
	"fmt"
	"io"
	"net"
)

const maximumDTLSPacketSize = maximumCSTPMTU + 1

func (g *Gateway) dtlsPSK([]byte) ([]byte, error) {
	g.pskLock.RLock()
	defer g.pskLock.RUnlock()
	if len(g.psk) == 0 {
		return nil, errors.New("fake gateway DTLS PSK is not ready")
	}
	return append([]byte(nil), g.psk...), nil
}

func (g *Gateway) claimDTLSSession(psk []byte) bool {
	g.pskLock.Lock()
	defer g.pskLock.Unlock()
	if g.dtlsOwnerActive {
		return false
	}
	g.dtlsOwnerActive = true
	g.psk = append(g.psk[:0], psk...)
	return true
}

func (g *Gateway) releaseDTLSSession() {
	g.pskLock.Lock()
	g.dtlsOwnerActive = false
	clear(g.psk)
	g.psk = nil
	g.pskLock.Unlock()
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
		g.waitGroup.Add(1)
		go func() {
			defer g.waitGroup.Done()
			defer func() {
				g.connLock.Lock()
				delete(g.conns, connection)
				g.connLock.Unlock()
			}()
			defer connection.Close()
			if handleErr := g.handleDTLSConnection(connection); handleErr != nil {
				g.addError(handleErr)
			}
		}()
	}
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
		switch packet[0] {
		case cstpPacketData:
			reply, peerErr := g.peer.HandlePacket(packet[1:length])
			if peerErr != nil {
				return fmt.Errorf("handle DTLS tunneled packet: %w", peerErr)
			}
			response := make([]byte, len(reply)+1)
			response[0] = cstpPacketData
			copy(response[1:], reply)
			if _, writeErr := connection.Write(response); writeErr != nil {
				return fmt.Errorf("write fake DTLS data packet: %w", writeErr)
			}
			g.record("dtls-data", fmt.Sprintf("replied with %d-byte packet", len(reply)))
		case cstpPacketDPDRequest:
			if _, writeErr := connection.Write([]byte{cstpPacketDPDResponse}); writeErr != nil {
				return fmt.Errorf("write fake DTLS DPD response: %w", writeErr)
			}
		case cstpPacketKeepalive:
			continue
		default:
			return fmt.Errorf("unexpected DTLS packet type: %d", packet[0])
		}
	}
}
