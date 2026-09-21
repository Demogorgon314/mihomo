# AnyConnect performance benchmark

## Comparing internal TCP/UDP stacks

The outbound's `stack: gvisor` (default) and `stack: mips` can be compared with
the same local gateway and peer. These commands use the dependencies pinned
in this repository, with no sibling checkouts or Docker required:

```sh
for stack in gvisor mips; do
  go test -tags=with_gvisor ./adapter/outbound \
    -run 'Test(AnyConnect|OpenConnect|F5)' -count=1 \
    -args -openconnect-stack="$stack"
  go test -tags=with_gvisor ./adapter/outbound -run '^$' \
    -bench '^BenchmarkAnyConnect(DataPlane|TCPDownload)E2E$' \
    -benchmem -benchtime=2s -count=5 \
    -args -openconnect-stack="$stack" > "/tmp/openconnect-$stack.txt"
done
```

Run each backend sequentially on an otherwise idle machine. `with_gvisor` is
needed by the test gateway's peer even when the client uses mips. The test-only
`-openconnect-stack` flag selects the client backend for the AnyConnect/F5
integration tests, generation replacement tests, and end-to-end benchmarks.
It does not change production defaults or the peer's stack.

The UDP benchmark validates every echoed datagram at four payload sizes. The
TCP benchmark validates downloaded blocks from a synthetic fixed-window peer.
Both use real local DTLS, but neither models Internet loss, latency, gateway
limits, or real congestion control. Allocation results include the client and
local gateway; bytes allocated per operation are not resident memory usage.

### Local comparison, 2026-09-21

Measured on an Apple M3 Pro, darwin/arm64, Go 1.26.1, with GOMAXPROCS=12.
Both backends used the same compiled test binary and pinned dependencies.
The gVisor run preceded the mips run; no other verification commands ran during
measurement. Each row reports the median of five 2-second samples. Throughput
ranges show the minimum and maximum of those samples, not confidence intervals.

| Scenario | gVisor MB/s (range) | mips MB/s (range) | Median throughput change | gVisor B/op | mips B/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| UDP echo, 128 B | 6.51 (5.19–7.19) | 8.07 (7.96–8.20) | +24.0% | 7,622 | 6,609 |
| UDP echo, 512 B | 26.88 (16.69–27.85) | 28.46 (28.12–28.85) | +5.9% | 13,093 | 12,104 |
| UDP echo, 1200 B | 53.32 (50.37–55.71) | 57.81 (57.12–58.24) | +8.4% | 22,494 | 21,595 |
| UDP echo, 1372 B | 61.02 (58.28–62.08) | 62.72 (58.07–64.48) | +2.8% | 25,019 | 24,092 |
| TCP download, 32 KiB blocks | 70.39 (59.35–77.58) | 81.10 (78.45–81.59) | +15.2% | 376,902 | 389,680 |

UDP allocation counts fell from 132–136 to 119–121 per operation. TCP download
allocations increased from 2,040 to 2,077 per block, with allocated bytes up
3.4%. Thus mips did not reduce allocation in every workload. These measurements
are an initial local comparison: sample variation and fixed backend order limit
performance conclusions, particularly the small difference at 1372 B. They do
not establish lower resident memory, lower CPU usage, or better WAN behavior.
The default remains gVisor.

## Transport optimization suite

The local suite separates five optimization targets and a final end-to-end
gate. It uses the sibling `sing-openconnect` and `dtls` checkouts through a
temporary root-module override; it never edits those modules or contacts a
real VPN server. The override is important because dependency-module
`replace` directives are otherwise ignored by Go.

```sh
# Quick check of one optimization target.
test/benchmark_anyconnect.sh p2-record

# Stable before/after samples for benchstat.
ANYCONNECT_BENCH_TIME=3s ANYCONNECT_BENCH_COUNT=10 \
  test/benchmark_anyconnect.sh p2 > /tmp/anyconnect-p2-before.txt
ANYCONNECT_BENCH_TIME=3s ANYCONNECT_BENCH_COUNT=10 \
  test/benchmark_anyconnect.sh p2 > /tmp/anyconnect-p2-after.txt
go run golang.org/x/perf/cmd/benchstat@latest \
  /tmp/anyconnect-p2-before.txt /tmp/anyconnect-p2-after.txt

# Run every microbenchmark and the local end-to-end gate.
test/benchmark_anyconnect.sh all

# Run the real ocserv end-to-end benchmark in Docker.
MIHOMO_ANYCONNECT_OCSERV=1 test/benchmark_anyconnect.sh docker-e2e
```

The phases are:

- `p1`: sing-openconnect payload copy, queue, completion, revision gate, and
  session write.
- `p2-record`: the steady-state DTLS 1.2 application-record construction and
  encryption path, without handshake, queue, socket, or peer scheduling. It
  covers AES-256-GCM used by the Cisco injected-resumption deployment and
  ChaCha20-Poly1305 used by standard PSK ocserv.
- `p2`: Pion DTLS record protection and connected UDP I/O.
- `p3`: mihomo's steady-state data-plane readiness/revision gate.
- `p4`: sing-openconnect packet copy and protocol headroom allocation.
- `p5`: sing-openconnect queue empty/full notification path.
- `e2e`: local fake gateway, real modern DTLS, sing-openconnect, and mihomo's
  packet stack.
- `docker-e2e`: pinned Docker ocserv, real modern DTLS, and a persistent TCP
  echo stream through the complete mihomo packet stack. It is intentionally
  separate from `all` because it requires Docker and `/dev/net/tun`.

Each timed path validates packet length, sequence, complement canary, and full
payload. Ordered stages reject reordering; the UDP end-to-end gate accepts safe
reordering inside one bounded window while rejecting missing, duplicate, and
out-of-window packets. The end-to-end gate also requires a stable revision,
keeps DTLS active, and fails if data appears on CSTP. A faster result is invalid
unless the relevant microbenchmark and `e2e` both pass.

For a Go CPU profile, run one phase and one repetition so profile files are not
overwritten:

```sh
ANYCONNECT_BENCH_TIME=10s ANYCONNECT_BENCH_COUNT=1 \
  test/benchmark_anyconnect.sh p2 -cpuprofile=/tmp/anyconnect-p2.cpu
go tool pprof -http=:0 /tmp/anyconnect-p2.cpu
```

On Linux, the same benchmark can be compiled and inspected with `perf`:

```sh
cd ../dtls
go test -c -o /tmp/anyconnect-p2.test
perf record -g -- /tmp/anyconnect-p2.test \
  -test.run '^$' -test.bench '^BenchmarkAnyConnectP2DTLSUDP$' \
  -test.benchtime 10s -test.count 1
perf report
```
