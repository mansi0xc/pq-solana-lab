# AI usage record

This document records how AI assistance was used in `pq-solana-lab`. It does
not claim any personal contribution, reading history, or understanding on the
author's behalf; those are the author's to describe.

## What AI assisted with

| Area | Assistance | How the output was checked |
| --- | --- | --- |
| Scaffolding | Cargo package layout, pinned toolchain/dependencies, CLI subcommands | Builds and tests were run; versions checked against crates.io |
| Crypto adapters | `src/crypto/*` wrappers over `ed25519-dalek`, `fips204`, `fips205` public APIs | Round-trip, rejection, RFC 8032 known-answer, and cross-implementation interop tests |
| Authorization | `src/intent.rs` encoding, `src/authorization.rs` registry/authorizer | Encoding golden fixture + adversarial tests; weak-key and strict-verify regressions |
| Benchmarks | `src/bench.rs` timing harness, config/result schemas | Raw/summary consistency test; boundary documentation in `docs/methodology.md` |
| Transport | `src/transport.rs` serialization and staged model | Wire round-trip/decode tests; reviewer-probe ladder reproduction |
| Analysis | `scripts/*.py` table/plot generation | `report_tables.py check` and `tests/report_consistency.rs` |
| Documentation | Drafting of `docs/*` from measured outputs and primary sources | Numbers regenerated from artifacts; citations checked against primary sources |

## Correction batch (reviewer findings)

A reviewer examined commit `71b171f` and found problems in v1 transaction
encoding, report statistics, staged-upload modeling, and security wording. The
corrections in this batch (v1 `wincode` encoding, explicit templates, a
concrete staged-upload protocol, regenerated tables, and the EUF-CMA/SUF-CMA
correction) were drafted with AI assistance and are listed in
`docs/progress.md`. Each change is backed by a test or a regenerated artifact.

## Boundaries

- Cryptographic algorithms were **not** modified; only library public APIs are
  used.
- No AI-produced number is published without a regenerable source
  (`results/raw/`, `results/transport*.json`) and a consistency check.
- The security section is an elementary, conditional application argument; it is
  not a proof, and AI assistance does not make it one.
- Nothing here implies the author has studied every cited result in depth. Where
  a source was not fully traced (the threshold-paper theorem), that is stated in
  the report's limitations.
