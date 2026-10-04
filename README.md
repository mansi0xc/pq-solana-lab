# PQ-Solana Lab

An applied cryptography research prototype investigating whether standardized
post-quantum signatures (FIPS 204 ML-DSA) are practical for application-level
authorization on Solana, measured against an Ed25519 baseline.

**Research question:** Under a specified Solana transaction format and
execution environment, what limits the practicality of standardized
post-quantum signatures for application authorization: payload size,
verification resources, or integration constraints?

Status: early implementation. See `docs/progress.md` for milestone state and
`idea.md` / `plan.md` for the project definition and milestone plan.

## Quick start

```sh
cargo run --release -- demo   # Ed25519 + ML-DSA-44 sign/verify demo
cargo test --release          # correctness and rejection tests
```

## What this project is (and is not)

- It uses existing, audited-at-the-library-level crates for all cryptographic
  primitives (`ed25519-dalek`, `fips204`). No new cryptography is implemented
  here.
- It studies application-level authorization. It does not make Solana, a
  wallet, or native transaction signing quantum secure.
- Host benchmark timings describe one implementation on one machine; they are
  never converted into Solana compute units.
