#!/bin/bash
# Throughput of a dnsd production binary under dnsperf, for the PERF work
# (CLAUDE-perf.md). Seeds host00000..host09999.example.local A records into
# Valkey, runs each query set for DURATION seconds with UDP_WORKERS workers,
# prints queries/s, then removes the seeded records.
#
# usage: bench/run_perf.sh <dns_server binary> <label> [workers] [duration]
set -u
BIN=$1
LABEL=$2
WORKERS=${3:-4}
DURATION=${4:-10}
PORT=5399
VC=$(command -v valkey-cli || command -v redis-cli)
cd "$(dirname "$0")/.."
OUT=bench/out/perf_$LABEL.txt

for i in $(seq 0 9999); do
    printf 'SET zone:example.local:A:host%05d.example.local 300|10.%d.%d.%d\n' \
        "$i" $((i / 65536)) $(((i / 256) % 256)) $((i % 256))
done | $VC --pipe > /dev/null

UDP_WORKERS=$WORKERS LISTEN_PORT=$PORT CONSOLE_LEVEL=err "$BIN" > /tmp/dnsd_perf_$LABEL.log 2>&1 &
D=$!
sleep 3

: > "$OUT"
run() {
    local name=$1 file=$2
    shift 2
    local q
    local o
    o=$(dnsperf -s 127.0.0.1 -p $PORT -d "bench/q/$file" -l "$DURATION" -c 8 -q 200 "$@" 2>&1)
    q=$(echo "$o" | awk '/Queries per second/ {print $4}')
    local codes
    codes=$(echo "$o" | sed -n 's/.*Response codes: *//p')
    printf '%-16s %10s qps   %s\n' "$name" "${q:-NA}" "$codes" | tee -a "$OUT"
}
run positive-hot hot.txt
run positive-spread spread.txt
run nxdomain nxdomain.txt
run nxdomain-do nxdomain.txt -D
run mixed mixed.txt
run positive-tcp hot.txt -m tcp

kill $D 2>/dev/null
wait $D 2>/dev/null
for i in $(seq 0 9999); do
    printf 'DEL zone:example.local:A:host%05d.example.local stale:zone:example.local:A:host%05d.example.local\n' "$i" "$i"
done | $VC --pipe > /dev/null
echo "[$LABEL] results in $OUT"
