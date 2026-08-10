package anyconnect

import (
	"errors"
	"fmt"
)

// ErrInvalidConfig identifies configuration failures that happen before any
// gateway connection is attempted.
var ErrInvalidConfig = errors.New("invalid anyconnect configuration")

func invalidConfig(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidConfig, message)
}
