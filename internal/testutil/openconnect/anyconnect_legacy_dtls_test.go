package openconnect

import (
	"bytes"
	"testing"
)

func TestFakeLegacyDTLSRecordAuthenticationAndReplay(t *testing.T) {
	record := fakeLegacyDTLSRecord{contentType: fakeLegacyContentData, epoch: 1, sequence: 0x010203040506, payload: []byte("legacy-record")}
	encoded, err := marshalFakeLegacyRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded[1:3], []byte{1, 0}) || !bytes.Equal(encoded[5:11], []byte{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("legacy BAD_VER or 48-bit sequence was not encoded: %x", encoded[:13])
	}
	key := bytes.Repeat([]byte{0x11}, 16)
	macKey := bytes.Repeat([]byte{0x22}, 20)
	encrypted, err := encryptFakeLegacyRecord(record, key, macKey)
	if err != nil {
		t.Fatal(err)
	}
	records, err := parseFakeLegacyRecords(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := decryptFakeLegacyRecord(records[0], key, macKey)
	if err != nil || !bytes.Equal(plaintext, record.payload) {
		t.Fatalf("legacy record roundtrip failed: payload=%x err=%v", plaintext, err)
	}
	wrongMAC := append([]byte(nil), macKey...)
	wrongMAC[0] ^= 0xff
	if _, err := decryptFakeLegacyRecord(records[0], key, wrongMAC); err == nil {
		t.Fatal("legacy record accepted an invalid MAC")
	}
	badPadding := append([]byte(nil), encrypted...)
	badPadding[len(badPadding)-1] ^= 0xff
	badRecords, err := parseFakeLegacyRecords(badPadding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptFakeLegacyRecord(badRecords[0], key, macKey); err == nil {
		t.Fatal("legacy record accepted invalid CBC padding")
	}

	var replay fakeLegacyReplayWindow
	for _, sequence := range []uint64{5, 3, 4, 70, 69} {
		if !replay.accept(sequence) {
			t.Fatalf("legacy replay window rejected new sequence %d", sequence)
		}
	}
	if replay.accept(69) || replay.accept(5) {
		t.Fatal("legacy replay window accepted duplicate or stale data")
	}
}
