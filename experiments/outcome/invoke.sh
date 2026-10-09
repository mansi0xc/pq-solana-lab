#!/bin/sh
# Execute a deployed program on a local validator with a real transaction.
#
#   - builds a signed v1 transaction carrying the fixture (invoke-client)
#   - submits it with curl JSON-RPC (no RPC client crate needed)
#   - prints the execution err, compute units, and program logs
#
# Requires a running `solana-test-validator` on 127.0.0.1:8899 and `PAYER`
# pointing at a funded keypair. Usage:
#   PAYER=/path/payer.json sh experiments/outcome/invoke.sh <program_id> <fixture.bin> [label]
set -e
URL=http://127.0.0.1:8899
CLIENT=experiments/invoke-client/target/release/invoke-client
PROGRAM=$1
FIXTURE=$2
LABEL=${3:-$2}
shift 3 2>/dev/null || shift $#
ACCOUNTS="$*"

rpc() { curl -s -X POST -H 'Content-Type: application/json' -d "$1" "$URL"; }

BLOCKHASH=$(rpc '{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[{"commitment":"finalized"}]}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['value']['blockhash'])")

TX=$($CLIENT build-tx "$PAYER" "$PROGRAM" "$FIXTURE" "$BLOCKHASH" $ACCOUNTS 2>/dev/null)

SEND=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sendTransaction\",\"params\":[\"$TX\",{\"encoding\":\"base64\",\"preflightCommitment\":\"finalized\"}]}")
SIG=$(echo "$SEND" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('result') or 'ERROR:'+json.dumps(d.get('error')))")

echo "--- $LABEL ---"
echo "program : $PROGRAM"
echo "data    : $FIXTURE ($(wc -c < "$FIXTURE" | tr -d ' ') bytes)  accounts: ${ACCOUNTS:-none}"
echo "send    : $SIG"
case "$SIG" in
  ERROR:*) exit 0 ;;
esac

for _ in 1 2 3 4 5 6 7 8 9 10; do
  RES=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTransaction\",\"params\":[\"$SIG\",{\"encoding\":\"json\",\"maxSupportedTransactionVersion\":0,\"commitment\":\"confirmed\"}]}")
  OK=$(echo "$RES" | python3 -c "import sys,json;print('yes' if json.load(sys.stdin).get('result') else 'no')")
  [ "$OK" = "yes" ] && break
  sleep 1
done

echo "$RES" | python3 -c '
import sys, json
d = json.load(sys.stdin)
r = d.get("result")
if not r:
    print("result  :", json.dumps(d.get("error")))
else:
    meta = r["meta"]
    print("err     :", json.dumps(meta["err"]))
    print("compute :", meta.get("computeUnitsConsumed"))
    print("status  :", "SUCCESS" if meta["err"] is None else "FAILED")
    for line in meta.get("logMessages", []):
        print("  log   :", line)
'
