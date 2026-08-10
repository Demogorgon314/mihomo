package anyconnect

type EventType string

const (
	EventAuthChallenge     EventType = "auth-challenge"
	EventBrowserRequested  EventType = "browser-auth-requested"
	EventHostScanRequested EventType = "host-scan-requested"
	EventNetworkConfig     EventType = "network-config"
	EventActiveTransport   EventType = "active-transport"
)

// Event contains policy-relevant, non-response authentication state. It never
// contains passwords, form answers, cookies, private keys, or token secrets.
type Event struct {
	Type            EventType
	Challenge       *AuthChallenge
	NetworkConfig   *NetworkConfig
	NetworkReason   NetworkConfigEventReason
	ActiveTransport string
}
