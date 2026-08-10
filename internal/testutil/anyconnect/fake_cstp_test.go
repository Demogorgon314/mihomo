package anyconnect

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

type shortWriter struct {
	w bytes.Buffer
}

func (w *shortWriter) Write(content []byte) (int, error) {
	if len(content) > 2 {
		content = content[:2]
	}
	return w.w.Write(content)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestCSTPFramePartialWriteAndCoalescedRead(t *testing.T) {
	writer := new(shortWriter)
	if err := writeCSTPFrame(writer, cstpPacketData, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := writeCSTPFrame(writer, cstpPacketDPDRequest, []byte("second")); err != nil {
		t.Fatal(err)
	}
	first, err := readCSTPFrame(&writer.w, 64)
	if err != nil {
		t.Fatal(err)
	}
	second, err := readCSTPFrame(&writer.w, 64)
	if err != nil {
		t.Fatal(err)
	}
	if first.packetType != cstpPacketData || string(first.payload) != "first" {
		t.Fatalf("unexpected first frame: %#v", first)
	}
	if second.packetType != cstpPacketDPDRequest || string(second.payload) != "second" {
		t.Fatalf("unexpected second frame: %#v", second)
	}
}

func TestCSTPFrameRejectsMalformedInput(t *testing.T) {
	valid := new(bytes.Buffer)
	if err := writeCSTPFrame(valid, cstpPacketData, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		content func() []byte
		limit   int
		message string
	}{
		{name: "short header", content: func() []byte { return []byte("STF") }, limit: 64, message: "header"},
		{name: "magic", content: func() []byte { content := append([]byte(nil), valid.Bytes()...); content[0] = 'B'; return content }, limit: 64, message: "magic"},
		{name: "reserved", content: func() []byte { content := append([]byte(nil), valid.Bytes()...); content[7] = 1; return content }, limit: 64, message: "reserved"},
		{name: "receive limit", content: func() []byte { return append([]byte(nil), valid.Bytes()...) }, limit: 3, message: "receive limit"},
		{name: "short payload", content: func() []byte { content := append([]byte(nil), valid.Bytes()...); return content[:len(content)-1] }, limit: 64, message: "payload"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := readCSTPFrame(bytes.NewReader(test.content()), test.limit)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("expected error containing %q, got %v", test.message, err)
			}
		})
	}
}

func TestCSTPFrameRejectsOversizeAndZeroWrite(t *testing.T) {
	if err := writeCSTPFrame(io.Discard, cstpPacketData, make([]byte, cstpMaximumPayloadSize+1)); err == nil {
		t.Fatal("expected oversize payload error")
	}
	if err := writeCSTPFrame(zeroWriter{}, cstpPacketData, nil); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected short write, got %v", err)
	}
}

func TestCSTPFrameLengthIsBigEndian(t *testing.T) {
	buffer := new(bytes.Buffer)
	if err := writeCSTPFrame(buffer, cstpPacketData, make([]byte, 258)); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(buffer.Bytes()[4:6]); got != 258 {
		t.Fatalf("unexpected encoded length: %d", got)
	}
}
