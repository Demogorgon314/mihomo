package openconnect

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	cstpHeaderSize         = 8
	cstpMaximumPayloadSize = 65535
	cstpPacketData         = byte(0)
	cstpPacketDPDRequest   = byte(3)
	cstpPacketDPDResponse  = byte(4)
	cstpPacketDisconnect   = byte(5)
	cstpPacketKeepalive    = byte(7)
	cstpPacketCompressed   = byte(8)
)

var cstpMagic = [4]byte{'S', 'T', 'F', 1}

type cstpFrame struct {
	packetType byte
	payload    []byte
}

func writeCSTPFrame(writer io.Writer, packetType byte, payload []byte) error {
	if len(payload) > cstpMaximumPayloadSize {
		return fmt.Errorf("CSTP payload exceeds %d bytes: %d", cstpMaximumPayloadSize, len(payload))
	}
	header := [cstpHeaderSize]byte{}
	copy(header[:4], cstpMagic[:])
	binary.BigEndian.PutUint16(header[4:6], uint16(len(payload)))
	header[6] = packetType
	if err := writeFull(writer, header[:]); err != nil {
		return fmt.Errorf("write CSTP header: %w", err)
	}
	if err := writeFull(writer, payload); err != nil {
		return fmt.Errorf("write CSTP payload: %w", err)
	}
	return nil
}

func readCSTPFrame(reader io.Reader, maximumPayloadSize int) (cstpFrame, error) {
	header := [cstpHeaderSize]byte{}
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return cstpFrame{}, fmt.Errorf("read CSTP header: %w", err)
	}
	if !bytes.Equal(header[:4], cstpMagic[:]) {
		return cstpFrame{}, errors.New("invalid CSTP magic")
	}
	if header[7] != 0 {
		return cstpFrame{}, errors.New("invalid CSTP reserved byte")
	}
	payloadSize := int(binary.BigEndian.Uint16(header[4:6]))
	if maximumPayloadSize > 0 && payloadSize > maximumPayloadSize {
		return cstpFrame{}, fmt.Errorf("CSTP payload exceeds receive limit: %d > %d", payloadSize, maximumPayloadSize)
	}
	payload := make([]byte, payloadSize)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return cstpFrame{}, fmt.Errorf("read CSTP payload: %w", err)
	}
	return cstpFrame{packetType: header[6], payload: payload}, nil
}

func writeFull(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		written, err := writer.Write(content)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}
