# Two-minute demo outline

The short demo is `scripts/demo.sh` (genuine output, no timing gates, roughly a
minute). The benchmark pilot is a **separate** step (`scripts/bench-pilot.sh`,
2-3 minutes) and the full profile is slower still; neither is part of the
two-minute recording.

## Suggested script (~2 minutes)

1. **Question and architecture (20s).** One sentence on the research question;
   point at `docs/report.md` §1 for the finding and the design summary in the
   README.
2. **Adapters + authorization (50s).** `cargo run --release -- demo`. Show:
   four schemes with public-key/signature sizes; a valid withdrawal accepted
   (asset preserved, nonce consumed); then replay, tampered amount, expired
   request, and correctly-signed wrong-network request rejected.
3. **Transport (30s).** `cargo run --release -- transport`. Show the corrected
   v1 numbers: legacy/v0 exceeds 1,232 bytes even when registered; v1 admits
   ML-DSA-44 on the minimal template but not the operational one; staged upload
   (modeled) makes each transaction fit at extra total cost.
4. **Runtime result + limitation (20s).** The `fips204` verifier compiles for
   sBPF but fails the 4,096-byte stack-frame check before execution; no compute
   units are claimed. State the scope: one implementation, one machine, no
   universal infeasibility.

## What not to say

- Do not present host microseconds as Solana compute units.
- Do not present the staged model as an executed on-chain sequence.
- Do not claim production security, a proof, or quantum security for Solana.
