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
cargo run --release -- demo   # Ed25519 + ML-DSA-44 sign/verify + authorization demo
cargo test --release          # correctness, rejection, and known-answer tests
```

## What this project is (and is not)

- It reuses published cryptographic libraries for all primitives
  (`ed25519-dalek`, `fips204`). No new cryptography is implemented here.
- It studies application-level authorization. It does not make Solana, a
  wallet, or native transaction signing quantum secure.
- Host benchmark timings describe one implementation on one machine; they are
  never converted into Solana compute units.

## Attribution of cryptographic implementations

The cryptographic primitives come from third-party Rust crates, credited here
rather than reimplemented:

| Primitive | Crate | Pinned | Standard | Independent correctness evidence in this repo |
| --- | --- | --- | --- | --- |
| Ed25519 | `ed25519-dalek` | 3.0.0 | RFC 8032 | RFC 8032 §7.1 known-answer tests (`tests/ed25519_known_answer.rs`) |
| ML-DSA-44 | `fips204` | 0.4.6 | FIPS 204 | self round-trip only so far; external-API known-answer check is a documented gap |

"Standardization" (a scheme appearing in a NIST FIPS), "testing" (this repo's
own tests), "independent conformance evidence" (e.g. known-answer vectors from
a primary source), and "implementation audits" (a published third-party audit
of a specific crate release) are four different things. This project provides
the first two; the Ed25519 row cites primary-source vectors for the third;
no third-party audit report is relied upon or claimed for these pinned crate
versions.
