# sBPF verifier experiment — outcome evidence

This directory holds the evidence for the M5/Batch-3 sBPF outcome. It corrects
the earlier claim that the ML-DSA-44 verifier is "rejected by the runtime's
program loader": in fact it **loads, verifies, and deploys successfully**, and
then **aborts at runtime with an access violation** before producing any
verdict.

## Toolchain / runtime

- `solana-cli` 3.1.10 (Agave), `solana-cargo-build-sbf` 3.1.10
- platform-tools v1.52, `rustc` 1.89.0 (sBPF target)
- `solana-sbpf` 0.13.1 (the SBF VM crate Agave 3.1.x pins)
- host: Apple M4, macOS

## Files

| File | Contents |
| --- | --- |
| `validator-deploy.log` | `solana program deploy` of both programs against a local validator (exit 0) |
| `execution.log` | real transactions via JSON-RPC: control program success; `fips204` and RustCrypto verifier runtime traps |
| `validator.log` | `solana-test-validator` stdout (quiet) |
| `invoke.sh` | the exact invocation script (builds a legacy tx, submits with curl, prints err/CU/logs) |

## What was run

```sh
# 1. build (compiler evidence; both exit 0, oversized-frame diagnostics)
(cd experiments/sbpf-control          && cargo-build-sbf)   # clean, 17,320 B ELF
(cd experiments/sbpf-verifier         && cargo-build-sbf)   # 17 stack diagnostics
(cd experiments/sbpf-verifier-rustcrypto && cargo-build-sbf) # 2 stack diagnostics

# 2. loader-class check (Agave SBF VM + RequisiteVerifier)
(cd experiments/loader-harness && cargo run --release -- probe control  ../sbpf-control/target/deploy/sbpf_control.so)
(cd experiments/loader-harness && cargo run --release -- probe fips204  ../sbpf-verifier/target/deploy/sbpf_verifier.so)
(cd experiments/loader-harness && cargo run --release -- probe rustcrypto ../sbpf-verifier-rustcrypto/target/deploy/sbpf_verifier_rustcrypto.so)

# 3. authentic load + execute on a local validator
solana-test-validator --reset --account <fixture_acct> <account.json> ...
solana program deploy ... sbpf_control.so      # exit 0
solana program deploy ... sbpf_verifier.so     # exit 0  (loader ACCEPTS it)
solana program deploy ... sbpf_verifier_rustcrypto.so   # exit 0
PAYER=<payer.json> sh experiments/outcome/invoke.sh <program_id> <data.bin> "<label>" [fixture_account]
```

The fixture (`pk||sig||msg`, 3,783 B) exceeds the 1,232-byte transaction packet
limit, so it is supplied through **account data** preloaded with
`solana-test-validator --account`.

## Results

| Case | Load | Verify (RequisiteVerifier) | Deploy | Execute | Verdict reached | CU (log) |
| --- | --- | --- | --- | --- | --- | --- |
| control program | OK | OK | OK | **SUCCESS** | n/a (no-op) | 539 |
| `fips204` ML-DSA-44 | OK | OK | OK | **trap** | no | 418 |
| RustCrypto `ml-dsa` ML-DSA-44 | OK | OK | OK | **trap** | no | 323 |

Runtime traps (from `execution.log`):

- `fips204`: `Access violation in stack frame 3 at address 0x200003400 of size 1024`
- RustCrypto: `Access violation in program section at address 0x1ffffdbca of size 1`

Both abort before any `verify` result, so **valid / altered-message /
invalid-signature all fail identically** and no completed-verification compute
measurement exists. The `unitsConsumed` field reports the full limit (200,000)
when the program aborts, while the program log reports the pre-trap count
(418 / 323); both are recorded rather than reconciled.

## What this establishes, and what it does not

- **Establishes:** the compiler's stack-frame diagnostics are *compiler*
  evidence, not loader rejection; the Agave loader accepts and deploys these
  programs; execution fails at runtime with an access violation before any
  verdict.
- **Does not establish:** that ML-DSA verification is impossible on Solana. Two
  specific library builds under one toolchain/runtime fail this way; a
  verifier that heap-allocates its large buffers may differ. No compute-unit
  figure for a *successful* verification is claimed.
