# ML-DSA-44 verifier feasibility experiment (M5) — corrected outcome

## Question and scope

Can the ML-DSA-44 verification path, as implemented by `fips204` 0.4.6 (and,
for the controlled comparison, RustCrypto `ml-dsa` 0.1.1), compile to Solana's
sBPF, load and deploy on a local validator, and execute correctly?

**Correction.** An earlier version of this document claimed the program was
"rejected by the runtime's program loader". That was wrong: the loader
**accepts** it. The failure is a **runtime access violation** during execution.
The original evidence (compiler stack-frame diagnostics) is compiler evidence,
not loader rejection; the experiment below establishes the actual loader and
execution outcomes.

## Method

1. Confirm the toolchain with a minimal control program (`experiments/sbpf-control/`).
2. Build verification-only programs and keep their build logs as compiler evidence.
3. Check the ELF with the Agave SBF VM (`solana-sbpf` 0.13.1, the crate Agave
   3.1.x pins) and its loader verifier (`RequisiteVerifier`) —
   `experiments/loader-harness/`.
4. Deploy to a local `solana-test-validator` and execute real transactions
   carrying a genuine host-verified fixture — `experiments/invoke-client/` and
   `experiments/outcome/invoke.sh`.

The fixture (`pk (1312) || sig (2420) || message`) is 3,783 bytes, which exceeds
the 1,232-byte transaction packet limit, so it is supplied through **account
data** (preloaded with `solana-test-validator --account`); the program reads it
from the first account.

## Environment

- solana-cli 3.1.10 (Agave); solana-cargo-build-sbf 3.1.10; platform-tools v1.52; rustc 1.89.0 (sBPF)
- solana-sbpf 0.13.1; fips204 0.4.6; ml-dsa 0.1.1; solana-program 5.1.0
- host: Apple M4, macOS 27.0.1

## Compiler evidence (as before, and now labelled as such)

`cargo-build-sbf` exits **0** for both verifier programs while emitting
stack-frame diagnostics. `experiments/sbpf-verifier/build.log` records 17 lines
such as `verify_internal` ~62,016 bytes and `ntt::ntt` ~8,320 bytes;
`experiments/sbpf-verifier-rustcrypto/build.log` records 2 (`verify_slice`
~68,480 bytes). The control program builds with no such diagnostics. These are
**compiler** diagnostics: they warn that execution *may* be undefined, they do
not by themselves establish rejection.

## Loader and execution outcome

| Stage | control | `fips204` ML-DSA-44 | RustCrypto `ml-dsa` |
| --- | --- | --- | --- |
| `cargo-build-sbf` | exit 0, no frame diagnostics | exit 0, 17 frame diagnostics | exit 0, 2 frame diagnostics |
| ELF load + `RequisiteVerifier` | OK | **OK** | **OK** |
| `solana program deploy` | exit 0 | **exit 0 (loader accepts it)** | exit 0 |
| execution (real tx) | **SUCCESS**, 539 CU | **abort: access violation in stack frame 3** | **abort: access violation in program section** |
| verdict reached | n/a | **no** | **no** |

The control program executes and logs
`sbpf-control: ok (32 bytes of instruction data)` (`execution.log`). Both
verifier programs are accepted by the loader and deployed; on invocation they
abort before any `verify` result:

- `fips204`: `Access violation in stack frame 3 at address 0x200003400 of size 1024`
- RustCrypto: `Access violation in program section at address 0x1ffffdbca of size 1`

Because they abort before producing a verdict, valid / altered-message /
invalid-signature inputs all fail identically, and **no completed-verification
compute measurement exists**. (The RPC `unitsConsumed` reports the full 200,000
limit on abort while the program log reports 418 / 323 pre-trap; both are
recorded, not reconciled.)

## Classification

For these two builds on this toolchain and runtime, the outcome is a
**reproducible runtime access violation before execution completes** — not a
compile failure, not a load-time rejection, and not compute-budget exhaustion.
It is consistent with the compiler's warning that the oversized stack frames
cause undefined behaviour, but the loader-level check the earlier document
relied on does not exist.

## What is NOT concluded

- ML-DSA is not shown to be universally infeasible on Solana. Both failures are
  stack-frame-specific: a verifier that heap-allocates its large buffers, or
  otherwise reduces per-frame stack, may behave differently. This is specific to
  `fips204` 0.4.6 and `ml-dsa` 0.1.1 under the stated toolchain and runtime.
- No successful-verification compute units are claimed.
- This is a local validator, not mainnet; it is evidence about that harness.

## Reproduce

```sh
(cd experiments/sbpf-control && cargo-build-sbf)             # clean control
(cd experiments/sbpf-verifier && cargo-build-sbf)            # 17 frame diagnostics
(cd experiments/loader-harness && cargo run --release -- probe fips204 \
    ../sbpf-verifier/target/deploy/sbpf_verifier.so)         # load+verify OK

solana-test-validator --reset --account <fixture_account> <account.json>
solana program deploy ... experiments/sbpf-verifier/target/deploy/sbpf_verifier.so
PAYER=<payer.json> sh experiments/outcome/invoke.sh <program_id> <data.bin> "<label>" <fixture_account>
```

See `experiments/outcome/README.md` for the recorded evidence and
`docs/technical-note.md` for how this limits the project's conclusions.
