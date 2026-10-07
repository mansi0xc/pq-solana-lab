#!/bin/sh
# Two-minute demonstration script. Produces genuine output from the actual
# commands; nothing here is fabricated.
set -e
cd "$(dirname "$0")/.."

echo "== 1. Signature adapters and authorization (demo) =="
cargo run --release --locked -- demo

echo
echo "== 2. Transaction sizing (serialized) =="
cargo run --release --locked -- transport

echo
echo "== 3. Benchmark pilot (2-3 min) =="
cargo run --release --locked -- benchmark --config configs/quick.json
