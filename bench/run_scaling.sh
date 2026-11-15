#!/bin/bash
cd /home/lucian/Work/simple-dns
LOADGEN_CORES=16-23
echo "worker-scaling sweep (cache-miss/spread, dnsperf -T8, offered 200k, 12s)"
for W in 1 2 4 8; do
  # pin server to W cores starting at core 2
  hi=$((2 + W - 1))
  UDP_WORKERS=$W taskset -c 2-$hi env ASAN_OPTIONS=detect_leaks=0 \
    ./bench/out/dns_server_workers > /tmp/workers_$W.log 2>&1 &
  SP=$!
  sleep 2
  # warmup
  dnsperf -s 127.0.0.1 -p 5399 -d bench/q/spread.txt -T 8 -c 32 -Q 200000 -l 4 >/dev/null 2>&1
  # measured run
  out=$(taskset -c $LOADGEN_CORES dnsperf -s 127.0.0.1 -p 5399 -d bench/q/spread.txt \
        -T 8 -c 32 -Q 200000 -l 12 2>&1)
  qps=$(echo "$out" | grep -i 'Queries per second' | grep -oE '[0-9.]+')
  lost=$(echo "$out" | grep -i 'Queries lost' | grep -oE '\([0-9.]+%\)')
  lat=$(echo "$out" | grep -i 'Average Latency' | sed 's/.*): //; s/.*: //')
  printf 'workers=%-2d  achieved=%-12s loss=%-9s avglat=%s\n' "$W" "${qps:-NA}" "${lost:-NA}" "${lat:-NA}"
  kill $SP 2>/dev/null; sleep 2
done
echo "=== SCALING DONE ==="
