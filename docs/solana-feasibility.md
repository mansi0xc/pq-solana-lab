# ML-DSA-44 verifier feasibility experiment (M5)

## Question and scope

Can the ML-DSA-44 verification path, as implemented by `fips204` 0.4.6,
compile to and pass Solana's sBPF program verification, and then execute?

## Method

1. Confirm the toolchain with a minimal no-op Solana program (`cargo build-sbf`).
2. Build a verification-only program (`experiments/sbpf-verifier/`) that parses
   `[public key (1312)] [signature (2420)] [message]` from instruction data and
   calls `ml_dsa_44::PublicKey::try_from_bytes` + `verify` (empty context), with
   `fips204` built `default-features = false, features = ["ml-dsa-44"]` (no RNG;
   keygen is intentionally unavailable in the program).
3. Run the sBPF build; the ELF is checked against the 4,096-byte stack-frame
   limit.

## Environment

- solana-cli 3.1.10 (Agave)
- solana-cargo-build-sbf 3.1.10, platform-tools v1.52, rustc 1.89.0
- fips204 0.4.6 (pinned), solana-program 5.1.0
- host: Apple M4, macOS 27.0.1

## Result: reproducible stack-frame blocker (before execution)

The verifier **compiles** for sBF (fips204 is `no_std`), but the sBPF ELF
checker rejects the program: several fips204 functions exceed the 4,096-byte
stack-frame limit. The full log is preserved at
`experiments/sbpf-verifier/build.log`.

Relevant rejected functions (frame size vs 4,096-byte limit):

| Function (fips204 0.4.6) | Frame size |
| --- | --- |
| `ml_dsa::verify_internal` | 62,016 bytes |
| `ml_dsa::sign_internal` | 69,184 bytes |
| `ml_dsa_44::PublicKey::try_from_bytes` | 24,128 bytes |
| `high_low::power2round` | 13,376 bytes |
| `ntt::ntt` / `ntt::inv_ntt` | 8,320 / 8,256 bytes |
| `helpers::mat_vec_mul` | 8,256 bytes |
| program `entrypoint` | 10,880 bytes |

The smallest verification-path function (`ntt::ntt`, 8,320 bytes) still exceeds
the limit. The `.so` is produced (73,280 bytes) but would be rejected by the
runtime's program loader, which enforces the same stack-frame bound.

## Classification

This is a **stack-frame-size limitation**, not a compile/build failure (the
crate compiled), not a heap-memory-allocation failure, and not
compute-budget exhaustion (the program never reached execution, so there are
no compute-unit measurements — and none are claimed).

## What is NOT concluded

- This does not show ML-DSA is universally infeasible on Solana. The stack
  frame is implementation-dependent; a verifier that heap-allocates its
  large buffers, or otherwise reduces per-function stack usage, may behave
  differently. This result is specific to `fips204` 0.4.6 under the stated
  toolchain and configuration.
- No signature, memory, or compute-verdict behavior was executed or measured.

## Reproduce

```sh
cd experiments/sbpf-verifier
cargo build-sbf   # see build.log for the stack-frame errors
```

The minimal (Phase 1) program builds and produces a valid 11,336-byte ELF;
that is the evidence that the toolchain itself is functional and that the
blocker is specific to the ML-DSA verification code, not the toolchain.
