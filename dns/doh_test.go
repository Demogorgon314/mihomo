package dns

import (
	"fmt"
	"net"
	"net/url"
	"testing"
)

func TestDoHRetriesClosedConnection(t *testing.T) {
	doh := &dnsOverHTTPS{}
	// as a query cut by ResetConnection fails, wrapped by net/http
	closed := &url.Error{Op: "Get", URL: "https://223.5.5.5/dns-query", Err: &net.OpError{Op: "read", Net: "tcp", Err: net.ErrClosed}}
	if !doh.shouldRetry(fmt.Errorf("requesting https://223.5.5.5/dns-query: %w", closed)) {
		t.Error("a query on a connection closed under it is not retried")
	}
	if doh.shouldRetry(fmt.Errorf("bad status")) || doh.shouldRetry(nil) {
		t.Error("retried an error that a new client does not fix")
	}
}
