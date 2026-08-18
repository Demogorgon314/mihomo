# OpenConnect outbound

The OpenConnect outbound is a pure-Go, userspace L3 client. It does not create
an OS TUN device or change system routes. Protocol handling comes from the
pinned `Demogorgon314/sing-openconnect` fork; mihomo owns configuration,
policy, underlay dialing, DNS, and the userspace TCP/UDP stack.

This outbound is experimental until the capabilities used by a deployment pass
the real Cisco gateway checks described below. Passing the fake gateway and
ocserv suites alone does not make modern or legacy DTLS a supported capability.

## Configuration and authentication

See [`config.yaml`](config.yaml) for every YAML field. Important constraints:

- Use `type: openconnect`. `protocol` accepts `anyconnect` and `f5`, and defaults
  to `anyconnect`. The former `type: anyconnect` spelling is intentionally not
  accepted.
- `port` defaults to `443`.
- `ca`, peer fingerprint(s), and `skip-cert-verify` are mutually exclusive.
  `peer-fingerprints` accepts multiple pins for certificate rotation. System CA
  roots remain enabled with a custom CA unless `system-trust-disabled: true`;
  when no trust option is configured, verification uses the system roots.
- `cert` and `key` must be configured together. Encrypted keys also require the
  matching `key-password`.
- `mca-certificate` and `mca-key` configure the separate signing identity used
  by AnyConnect multiple-certificate authentication. Encrypted MCA keys require
  `mca-key-password`; private material is redacted like the normal client key.
- `cert-expire-warning` matches OpenConnect's day-based option. It defaults to
  `60`; set it to `0` to disable client and MCA certificate expiry warnings.
- `dns` accepts IP literals only and requires `remote-dns-resolve: true`. This
  prevents the tunnel's private resolver from recursively resolving itself.
- For `protocol: f5`, a direct cookie may be either the bare `MRHSession` value
  or a cookie string such as `MRHSession=...; F5_ST=...`. Username/password F5
  HTML form authentication is also supported.
- `dtls-mode: auto` prefers DTLS and falls back to CSTP for AnyConnect or
  PPP-over-TLS for F5. `require` fails closed if DTLS becomes unavailable;
  `off` uses the corresponding TLS transport only.
- `compression` defaults to `stateless`, matching OpenConnect. For AnyConnect
  this negotiates per-packet `oc-lz4` or `lzs`; use `off` to disable compression
  explicitly. F5 PPP does not use this AnyConnect compression setting.
- IPv6 is enabled by default, matching OpenConnect. Set `ipv6-disabled: true`
  to request and use IPv4 tunnel configuration only.
- With AnyConnect, `base-mtu: 0` probes the CSTP TCP socket for the path MTU (or
  TCP MSS) and falls back to `1406` when the socket does not expose that
  information. F5 applies the base MTU to its PPP carrier overhead calculation.
- `handshake-timeout` defaults to `0`, so mihomo does not impose one deadline
  across authentication and tunnel startup. Individual network and protocol
  operations remain bounded; set a positive number of seconds to add an overall
  deadline.
- For AnyConnect, `dtls-key-exchange` defaults to `auto`, matching OpenConnect
  by advertising the supported PSK, injected-resumption, and compatibility
  suites and letting the gateway select. `resumption` narrows the offer to
  injected AES-GCM session resumption, which can substantially reduce CPU use
  on AES-accelerated systems. Gateways without that mechanism fall back
  according to `dtls-mode`; validate this override against the target gateway
  before deployment.
- For AnyConnect, `legacy-dtls` defaults to `true`, matching OpenConnect
  compatibility behavior. Set it to `false` to prevent negotiation of Cisco
  DTLS 0.9 and its deprecated MD5/SHA-1/AES-CBC cryptography.
- F5 uses certificate-authenticated DTLS instead of the AnyConnect key exchange
  and legacy-DTLS controls. F5 gateways that only advertise DTLS 1.0 require
  the explicit `allow-insecure-crypto: true` compatibility opt-in.
- `dtls-local-port` binds the DTLS underlay to a fixed local UDP port; `0`
  lets the operating system select one. IPv4 and IPv6 use their corresponding
  wildcard bind address while preserving mihomo's interface and routing-mark
  policy.
- `reported-os: android` and `apple-ios` use OpenConnect-compatible generic
  mobile identity fields when `mobile` is omitted. Configure all three nested
  mobile fields to override them.
- `pfs: true` rejects non-forward-secret TLS cipher suites.
  `allow-insecure-crypto: true` enables legacy TLS and cipher compatibility and
  should only be used for gateways that cannot negotiate modern cryptography.
- YAML supports a pre-authenticated cookie, username/password, authgroup,
  static form entries, client certificates, TOTP, RSA SecurID, and OIDC bearer
  tokens. RSA mode accepts an optional PIN, encrypted-token password, and device
  ID. HOTP is rejected from YAML because its counter needs a persistent
  programmatic callback.
- Interactive forms, browser login, and host scan require an embedding
  application to provide the corresponding policy callbacks. Without an
  authentication provider, the standard outbound automatically disables
  external authentication capability advertisement and does not open a
  browser. Host scan is disabled by default and is never executed implicitly.

Authentication values, cookies, private keys, token secrets, and form answers
are removed from public events and errors. Do not enable packet captures or
external debug logging that records TLS plaintext in production.

## Errors and retry behavior

The transport façade wraps its validation and client-construction failures with
`openconnect.ErrInvalidConfig`. The outbound also rejects invalid name, server,
port, cookie, timeout, MTU, queue, DNS, and DTLS fields before dialing with a
descriptive error; these parser-level errors do not all share that category.
The façade exposes stable categories for authentication, TLS verification,
host-scan policy, reconnect timeout, and required-DTLS failures.

Errors for rejected credentials, rejected certificates or fingerprints,
missing policy input, and protocol policy violations are terminal. A terminal
startup error is latched by the outbound so repeated traffic cannot create a
login or MFA storm. Correct the configuration or credentials and recreate the
outbound (normally by reloading configuration).

Temporary transport failures are handled by the bounded core supervisor.
Rekey, DPD recovery, and reconnect preserve the userspace network generation
when the assigned address and MTU are unchanged. An address or MTU change
replaces the generation and closes old flows. `Close` cancels startup or
reconnect and waits for packet loops to finish; it does not allow the supervisor
to revive the session afterward. If bounded reconnect is exhausted, the failed
session remains stopped; recreate the outbound after the underlay problem is
corrected.

## Health checks and URLTest

The normal mihomo URLTest path calls this outbound's `DialContext`, so the first
check may include authentication and tunnel establishment. A successful check
proves that the configured HTTP target is reachable over a TCP flow through the
tunnel. It does **not** independently prove UDP, DTLS, DPD, rekey, private DNS,
or IPv6 health.

With `dtls-mode: auto`, a URLTest can remain healthy after DTLS falls back to
CSTP. Standard outbound users cannot infer the active transport from URLTest;
use capability test artifacts instead. Programs that directly embed the
`transport/openconnect` façade may subscribe to its active-transport event. With
`dtls-mode: require`, loss of DTLS ends the session and subsequent health checks
fail with the required-DTLS category.

Avoid very short health intervals on gateways that frequently require
interactive authentication. Terminal failures are latched, but successful
adapter recreation still starts a new gateway login.

## Diagnostics and capability evidence

The AnyConnect interop workflow uploads `anyconnect-capability-matrices` JSON.
Each record identifies the driver, scenario, transport, address family, and
capability that passed. The matrix is evidence for that exact layer only:

- fake gateway results cover deterministic protocol and fault injection;
- ocserv results cover independent server interoperability;
- Cisco results are required before claiming the corresponding Cisco modern or
  legacy capability as supported.

F5 has a separate hermetic gateway test covering cookie and username/password
authentication, configuration fetch, PPP negotiation, certificate DTLS,
PPP-over-TLS fallback, and outbound TCP/UDP. Validate those capabilities against
the target BIG-IP version before deployment; the AnyConnect capability matrix
does not describe F5.

The release workflow also runs bounded parser fuzzing, race tests, coverage
floors, 1/100/1000-flow stress, repeated startup/close, and accelerated CSTP,
modern-DTLS, and legacy-DTLS soak tests. Failed fuzz inputs are uploaded as
`anyconnect-fuzz-failures` and should be added to the appropriate seed corpus
with a regression fix.

For local diagnosis, start with:

```sh
go test -race -tags=with_gvisor ./transport/openconnect ./adapter/outbound ./internal/testutil/openconnect
go test -tags=anyconnect_ocserv,with_gvisor ./internal/testutil/openconnect -run '^TestOCServFixture$' -v
```

Never attach configuration files, capability artifacts, or logs without first
checking them for deployment hostnames and credentials. The built-in recorder
does not intentionally store authentication responses.

## Dependency upgrades and support claims

The fork is pinned by one pseudo-version in the root and test modules and by the
same full commit SHA in the interop workflow. An upgrade must update all three
locations together, run `go mod tidy -diff` in both modules, and pass:

1. hermetic, race, fuzz, coverage, stress, and soak gates;
2. the complete pinned ocserv matrix;
3. real Cisco checks for every capability that will be described as supported;
4. vulnerability, license/notice, SBOM, secret, checksum, and binary-size
   review for release artifacts.

Do not pin a floating branch. A fake or ocserv pass must not be used to remove
the experimental label for Cisco-specific DTLS behavior.
