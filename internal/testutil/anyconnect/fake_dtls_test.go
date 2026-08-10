package anyconnect

import (
	"bytes"
	"testing"
)

func TestGatewayDTLSSessionOwnership(t *testing.T) {
	gateway := new(Gateway)
	firstKey := []byte("first-session-key")
	if !gateway.claimDTLSSession(firstKey, nil) {
		t.Fatal("first DTLS session was rejected")
	}
	if gateway.claimDTLSSession([]byte("second-session-key"), nil) {
		t.Fatal("concurrent DTLS session replaced the active PSK")
	}
	storedKey, err := gateway.dtlsPSK(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedKey, firstKey) {
		t.Fatalf("active DTLS PSK changed: %x", storedKey)
	}
	storedKey[0] ^= 0xff
	secondRead, err := gateway.dtlsPSK(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secondRead, firstKey) {
		t.Fatal("DTLS PSK callback returned aliased key material")
	}
	gateway.releaseDTLSSession()
	if _, err := gateway.dtlsPSK(nil); err == nil {
		t.Fatal("released DTLS session retained its PSK")
	}
	if !gateway.claimDTLSSession([]byte("replacement-key"), nil) {
		t.Fatal("replacement DTLS session was rejected after release")
	}
}
