#!/bin/sh
# Short demonstration script (~seconds; genuine output from the actual
# commands, nothing fabricated). The long benchmark runs are a separate step:
# see scripts/bench-pilot.sh.
set -e
cd "$(dirname "$0")/.."

echo "== 1. Signature adapters and authorization (demo) =="
cargo run --release --locked -- demo

echo
echo "== 2. Transaction sizing (serialized) =="
cargo run --release --locked -- transport
