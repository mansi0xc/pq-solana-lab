#!/bin/sh
# Probe v1 transaction submission against a local validator.
#
# Agave 3.1.x has no `enable_tx_v1` feature (present only from the 4.2.x
# feature set), so v1 submissions are expected to be rejected by the RPC. This
# records the exact errors.
#
# Requires a running `solana-test-validator` on 127.0.0.1:8899, `PAYER` set to a
# funded keypair, and a deployed program id.
#
# Usage: PAYER=... sh experiments/outcome/probe-v1.sh <program_id> <data.bin> <label>
set -e
URL=http://127.0.0.1:8899
CLIENT=experiments/invoke-client/target/release/invoke-client
PROGRAM=$1
FIXTURE=$2
LABEL=$3
TMP=$(mktemp -d)

BLOCKHASH=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[{"commitment":"finalized"}]}' \
  "$URL" | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['value']['blockhash'])")

"$CLIENT" build-v1-tx "$PAYER" "$PROGRAM" "$FIXTURE" "$BLOCKHASH" > "$TMP/b64" 2> "$TMP/note"
B64=$(cat "$TMP/b64")

python3 - "$B64" "$URL" > "$TMP/send" <<'PY'
import json, sys, urllib.request
tx, url = sys.argv[1], sys.argv[2]
body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "sendTransaction",
                   "params": [tx, {"encoding": "base64"}]}).encode()
req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
try:
    print(urllib.request.urlopen(req, timeout=20).read().decode())
except Exception as e:
    print("HTTP error:", e)
PY

echo "--- $LABEL (v1/wincode) ---"
echo "build : $(cat "$TMP/note")"
echo "send  : $(cat "$TMP/send")"
rm -rf "$TMP"
