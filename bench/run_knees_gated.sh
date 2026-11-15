#!/bin/bash
cd /home/lucian/Work/simple-dns
for sc in cachehit:hot spread:spread nxdomain:nxdomain mixed:mixed; do
  name=${sc%%:*}; file=${sc##*:}
  echo "### $name ($file.txt)"
  for r in 1 2 3; do
    taskset -c 4-7 resperf -s 127.0.0.1 -p 5399 -d "bench/q/$file.txt" -R -m 100000 -r 30 -c 0 -L 5 \
      > "bench/out/clean_gated_${name}_${r}.txt" 2>&1
    q=$(grep -i 'Maximum throughput' "bench/out/clean_gated_${name}_${r}.txt" | grep -oE '[0-9]+\.[0-9]+' | head -1)
    l=$(grep -i 'Lost at' "bench/out/clean_gated_${name}_${r}.txt" | grep -oE '[0-9.]+%' | head -1)
    printf '  run %d: %s qps  loss %s\n' "$r" "${q:-NA}" "${l:-NA}"
    sleep 5
  done
done
echo "=== GATED KNEES DONE ==="
