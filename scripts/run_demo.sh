#!/usr/bin/env bash
# Build everything, run the controlled leak experiment, then show the leak over
# a real TCP connection (vulnerable vs secure oracle on the same key).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> building"
make >/dev/null

echo
echo "==> [1/3] Hamming-weight experiment -> hamming.csv"
./bench hamming 300 > hamming.csv
echo "    (popcount, naive_us, ladder_us) — first and last:"
sed -n '2p;$p' hamming.csv | sed 's/^/    /'

echo
echo "==> [2/3] Montgomery extra-reduction experiment -> reduction.csv"
./bench reduction 60 > reduction.csv
echo "    wrote $(($(wc -l < reduction.csv) - 1)) samples"

echo
echo "==> [3/3] remote timing over TCP (same key, two modes)"
SEED=4
./server --port 9401 --bits 1024 --seed "$SEED" --vulnerable 2>/dev/null &
PV=$!
./server --port 9402 --bits 1024 --seed "$SEED" --secure     2>/dev/null &
PS=$!
sleep 0.6
echo "    -- vulnerable --"; ./client --port 9401 --reps 3000 | sed 's/^/    /'
echo "    -- secure --";     ./client --port 9402 --reps 3000 | sed 's/^/    /'
kill "$PV" "$PS" 2>/dev/null || true
wait "$PV" "$PS" 2>/dev/null || true

echo
echo "==> done. Plot with: python3 scripts/plot.py hamming.csv"
