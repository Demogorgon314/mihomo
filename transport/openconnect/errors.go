package openconnect

import (
	"context"
	"errors"
	"fmt"
	"strings"

	openconnect "github.com/sagernet/sing-openconnect"
)

// ErrInvalidConfig identifies configuration failures that happen before any
// gateway connection is attempted.
var ErrInvalidConfig = errors.New("invalid openconnect configuration")

var (
	ErrAuthRequired        = errors.New("openconnect authentication provider is required")
	ErrAuthRejected        = errors.New("openconnect authentication was rejected")
	ErrAuthProvider        = errors.New("openconnect authentication provider failed")
	ErrTLSRejected         = errors.New("openconnect TLS verification failed")
	ErrHostScanPolicy      = errors.New("openconnect host scan is disabled by policy")
	ErrDataChannelNotReady = openconnect.ErrDataChannelNotReady
	ErrReconnectTimeout    = openconnect.ErrReconnectTimeout
	ErrDTLSRequired        = errors.New("openconnect DTLS is required but unavailable")
)

var ErrDataPacketDeliveryUnknown = openconnect.ErrDataPacketDeliveryUnknown

func invalidConfig(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, message)
}

type terminalError struct {
	category error
	message  string
}

func (e *terminalError) Error() string  { return e.message }
func (e *terminalError) Unwrap() error  { return e.category }
func (e *terminalError) Terminal() bool { return true }

// IsTerminal reports whether retrying the same adapter configuration can
// reasonably succeed without new authentication or trust input.
func IsTerminal(err error) bool {
	var terminal interface{ Terminal() bool }
	return errors.As(err, &terminal) && terminal.Terminal()
}

func newTerminalError(category error, message string) error {
	return &terminalError{category: category, message: message}
}

func classifyClientError(err error, secrets []string) error {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	switch {
	case errors.Is(err, ErrHostScanPolicy):
		return newTerminalError(ErrHostScanPolicy, ErrHostScanPolicy.Error())
	case errors.Is(err, openconnect.ErrAuthenticationFailed), errors.Is(err, openconnect.ErrAuthChallengeCanceled):
		return newTerminalError(ErrAuthRejected, ErrAuthRejected.Error())
	case errors.Is(err, openconnect.ErrInvalidTLSMaterial),
		strings.Contains(strings.ToLower(err.Error()), "certificate"),
		strings.Contains(strings.ToLower(err.Error()), "fingerprint"),
		strings.Contains(strings.ToLower(err.Error()), "client key"),
		strings.Contains(strings.ToLower(err.Error()), "mca key"),
		strings.Contains(strings.ToLower(err.Error()), "private key"):
		return newTerminalError(ErrTLSRejected, redactErrorMessage(err.Error(), secrets))
	}
	var terminal interface{ Terminal() bool }
	if errors.As(err, &terminal) && terminal.Terminal() {
		message := redactErrorMessage(err.Error(), secrets)
		cause := err
		if message != err.Error() {
			cause = nil
		}
		return newTerminalError(cause, message)
	}
	message := redactErrorMessage(err.Error(), secrets)
	cause := err
	if message != err.Error() {
		cause = nil
	}
	return &redactedError{cause: cause, message: message}
}

type redactedError struct {
	cause   error
	message string
}

func (e *redactedError) Error() string { return e.message }
func (e *redactedError) Unwrap() error { return e.cause }

func redactErrorMessage(message string, secrets []string) string {
	for _, secret := range secrets {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
	}
	return message
}
