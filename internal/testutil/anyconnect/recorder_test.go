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
	if count := recorder.Count("ignored"); count != 0 {
		t.Fatalf("nil recorder returned count %d", count)
	}
	if records := recorder.Records(); records != nil {
		t.Fatalf("nil recorder returned records: %#v", records)
	}
}

func TestCountingRecorder(t *testing.T) {
	recorder := NewCountingRecorder()
	recorder.Add("dtls-data", "first")
	recorder.Add("dtls-data", "second")
	recorder.Add("cstp-data", "fallback")
	if count := recorder.Count("dtls-data"); count != 2 {
		t.Fatalf("unexpected DTLS count: %d", count)
	}
	if count := recorder.Count("cstp-data"); count != 1 {
		t.Fatalf("unexpected CSTP count: %d", count)
	}
	if records := recorder.Records(); records != nil {
		t.Fatalf("counting recorder retained messages: %v", records)
	}
}
