#!/bin/bash
cd /home/lucian/Work/simple-dns
PORT=5399
run_knee() {
  local name="$1" file="$2" extra="$3"
  echo "### $name ($file) $extra"
  for r in 1 2 3; do
    taskset -c 4-7 resperf -s 127.0.0.1 -p $PORT -d "bench/q/$file" -R -m 100000 -r 30 -c 0 -L 5 $extra \
      > "bench/out/clean_${name}_${r}.txt" 2>&1
    q=$(grep -i 'Maximum throughput' "bench/out/clean_${name}_${r}.txt" | grep -oE '[0-9]+\.[0-9]+' | head -1)
    l=$(grep -i 'Lost at' "bench/out/clean_${name}_${r}.txt" | grep -oE '[0-9.]+%' | head -1)
    avg=$(grep -i 'Average response latency' "bench/out/clean_${name}_${r}.txt" | grep -oE '[0-9.]+' | head -1)
    printf '  run %d: %s qps  loss %s  avglat %ss\n' "$r" "${q:-NA}" "${l:-NA}" "${avg:-NA}"
    sleep 5   # recovery: let the single-threaded backlog drain before next run
  done
}
run_knee cachehit  hot.txt
run_knee cachemiss spread.txt
run_knee nxdomain  nxdomain.txt
run_knee mixed     mixed.txt
echo "=== CLEAN KNEES DONE ==="
