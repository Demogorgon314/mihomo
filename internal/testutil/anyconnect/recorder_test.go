package anyconnect

import (
	"strings"
	"testing"
)

func TestRecorderRedactsAndCopies(t *testing.T) {
	recorder := NewRecorder("cookie-value", "")
	recorder.Add("auth", "accepted cookie-value")
	records := recorder.Records()
	if len(records) != 1 || records[0].Message != "accepted "+redactedValue {
		t.Fatalf("unexpected records: %#v", records)
	}
	records[0].Message = "changed"
	if got := recorder.Records()[0].Message; got != "accepted "+redactedValue {
		t.Fatalf("snapshot mutation changed recorder: %q", got)
	}
	for _, record := range recorder.Records() {
		if strings.Contains(record.Message, "cookie-value") {
			t.Fatalf("secret retained in record: %#v", record)
		}
	}
}

func TestNilRecorder(t *testing.T) {
	var recorder *Recorder
	recorder.Add("ignored", "ignored")
	if records := recorder.Records(); records != nil {
		t.Fatalf("nil recorder returned records: %#v", records)
	}
}
