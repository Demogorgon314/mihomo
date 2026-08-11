#!/bin/sh

set -eu

usage() {
	cat <<'EOF'
Usage: test/benchmark_anyconnect.sh <p1|p2|p3|p4|p5|e2e|all> [go test flags]

Environment:
  ANYCONNECT_BENCH_TIME   Go benchmark duration (default: 1s)
  ANYCONNECT_BENCH_COUNT  Repetitions (default: 3)
  SING_OPENCONNECT_DIR    Local sing-openconnect checkout
  PION_DTLS_DIR           Local Pion DTLS checkout

Phases:
  p1   sing-openconnect copy/queue/completion/session-write pipeline
  p2   Pion DTLS encryption plus connected UDP I/O
  p3   mihomo steady-state data-plane revision/readiness gate
  p4   sing-openconnect packet copy and protocol headroom allocation
  p5   sing-openconnect empty/full queue notification path
  e2e  local fake gateway + DTLS + sing-openconnect + mihomo packet stack

Every benchmark contains a correctness oracle. A missing, duplicate, corrupted,
stale-revision, or CSTP-leaked packet fails the run. Ordered stages also reject
reordering; the UDP end-to-end gate accepts safe reordering within its window.
EOF
}

if [ "$#" -eq 0 ]; then
	usage
	exit 2
fi

phase=$1
shift

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
sing_dir=${SING_OPENCONNECT_DIR:-"$repo_dir/../sing-openconnect"}
dtls_dir=${PION_DTLS_DIR:-"$repo_dir/../dtls"}
bench_time=${ANYCONNECT_BENCH_TIME:-1s}
bench_count=${ANYCONNECT_BENCH_COUNT:-3}

for module_file in "$repo_dir/go.mod" "$sing_dir/go.mod" "$dtls_dir/go.mod"; do
	if [ ! -f "$module_file" ]; then
		echo "missing benchmark module: $module_file" >&2
		exit 1
	fi
done

workspace_dir=$(mktemp -d "${TMPDIR:-/tmp}/mihomo-anyconnect-bench.XXXXXX")
trap 'rm -rf "$workspace_dir"' EXIT HUP INT TERM
(
	cd "$workspace_dir"
	go work init "$repo_dir" "$sing_dir" "$dtls_dir"
)
workspace_file=$workspace_dir/go.work

run_benchmark() {
	name=$1
	directory=$2
	pattern=$3
	tags=$4
	shift 4
	echo "==> $name"
	if [ -n "$tags" ]; then
		(
			cd "$directory"
			GOWORK="$workspace_file" go test -outputdir="$workspace_dir" -tags="$tags" -run '^$' -bench "$pattern" -benchmem -benchtime="$bench_time" -count="$bench_count" "$@"
		)
	else
		(
			cd "$directory"
			GOWORK="$workspace_file" go test -outputdir="$workspace_dir" -run '^$' -bench "$pattern" -benchmem -benchtime="$bench_time" -count="$bench_count" "$@"
		)
	fi
}

run_phase() {
	current_phase=$1
	shift
	case "$current_phase" in
		p1)
			run_benchmark P1 "$sing_dir" '^BenchmarkAnyConnectP1OutboundPipeline$' '' "$@"
			;;
		p2)
			run_benchmark P2 "$dtls_dir" '^BenchmarkAnyConnectP2DTLSUDP$' '' "$@"
			;;
		p3)
			run_benchmark P3 "$repo_dir/transport/anyconnect" '^BenchmarkAnyConnectP3DataPlaneReady$' '' "$@"
			;;
		p4)
			run_benchmark P4 "$sing_dir" '^BenchmarkAnyConnectP4PacketBufferCopy$' '' "$@"
			;;
		p5)
			run_benchmark P5 "$sing_dir" '^BenchmarkAnyConnectP5QueueWakeup$' '' "$@"
			;;
		e2e)
			run_benchmark E2E "$repo_dir/adapter/outbound" '^BenchmarkAnyConnectDataPlaneE2E$' with_gvisor "$@"
			;;
		*)
			echo "unknown AnyConnect benchmark phase: $current_phase" >&2
			usage >&2
			exit 2
			;;
	esac
}

case "$phase" in
	all)
		for current_phase in p1 p2 p3 p4 p5 e2e; do
			run_phase "$current_phase" "$@"
		done
		;;
	*)
		run_phase "$phase" "$@"
		;;
esac
