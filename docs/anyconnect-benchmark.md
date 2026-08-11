# AnyConnect performance benchmark

The local suite separates five optimization targets and a final end-to-end
gate. It uses the sibling `sing-openconnect` and `dtls` checkouts through a
temporary root-module override; it never edits those modules or contacts a
real VPN server. The override is important because dependency-module
`replace` directives are otherwise ignored by Go.

```sh
# Quick check of one optimization target.
test/benchmark_anyconnect.sh p2

# Stable before/after samples for benchstat.
ANYCONNECT_BENCH_TIME=3s ANYCONNECT_BENCH_COUNT=10 \
  test/benchmark_anyconnect.sh p2 > /tmp/anyconnect-p2-before.txt
ANYCONNECT_BENCH_TIME=3s ANYCONNECT_BENCH_COUNT=10 \
  test/benchmark_anyconnect.sh p2 > /tmp/anyconnect-p2-after.txt
go run golang.org/x/perf/cmd/benchstat@latest \
  /tmp/anyconnect-p2-before.txt /tmp/anyconnect-p2-after.txt

# Run every microbenchmark and the local end-to-end gate.
test/benchmark_anyconnect.sh all
```

The phases are:

- `p1`: sing-openconnect payload copy, queue, completion, revision gate, and
  session write.
- `p2`: Pion DTLS record protection and connected UDP I/O.
- `p3`: mihomo's steady-state data-plane readiness/revision gate.
- `p4`: sing-openconnect packet copy and protocol headroom allocation.
- `p5`: sing-openconnect queue empty/full notification path.
- `e2e`: local fake gateway, real modern DTLS, sing-openconnect, and mihomo's
  packet stack.

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
