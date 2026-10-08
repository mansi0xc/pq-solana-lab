#!/bin/sh
# Benchmark pilot run (separate from the short demo; ~2-3 minutes). The full
# profile is slower still (SLH-DSA dominates) and should be run deliberately:
#   cargo run --release --locked -- benchmark --config configs/full.json
set -e
cd "$(dirname "$0")/.."

echo "== Benchmark pilot (configs/quick.json) =="
cargo run --release --locked -- benchmark --config configs/quick.json
