package outbound

import (
	"testing"
	"time"
)

func TestNewOpenConnectMapsCertificateExpiryWarning(t *testing.T) {
	zeroDays := 0
	thirtyDays := 30
	for _, testCase := range []struct {
		name     string
		days     *int
		warning  time.Duration
		disabled bool
	}{
		{name: "default"},
		{name: "disabled", days: &zeroDays, disabled: true},
		{name: "thirty days", days: &thirtyDays, warning: 30 * 24 * time.Hour},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			outbound, err := NewOpenConnect(OpenConnectOption{
				Name:              "vpn",
				Server:            "vpn.example.com",
				Cookie:            "test-cookie",
				CertExpireWarning: testCase.days,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = outbound.Close() }()
			if outbound.config.CertificateExpiryWarning != testCase.warning || outbound.config.CertificateExpiryWarningDisabled != testCase.disabled {
				t.Fatalf("unexpected certificate expiry warning: duration=%s disabled=%v", outbound.config.CertificateExpiryWarning, outbound.config.CertificateExpiryWarningDisabled)
			}
		})
	}
}

func TestNewOpenConnectRejectsCertificateExpiryWarningOverflow(t *testing.T) {
	days := 106752
	_, err := NewOpenConnect(OpenConnectOption{
		Name:              "vpn",
		Server:            "vpn.example.com",
		Cookie:            "test-cookie",
		CertExpireWarning: &days,
	})
	if err == nil {
		t.Fatal("expected certificate expiry warning overflow")
	}
}
