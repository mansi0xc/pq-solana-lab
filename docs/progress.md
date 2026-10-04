# Progress log

## Milestone status

| Milestone | Status | Evidence |
| --- | --- | --- |
| M1: Working primitives | **Complete** (pending review/commit) | `cargo test --release` → 10/10 pass; `cargo run --release -- demo` genuine output |
| M2: Authorization semantics | Not started | |
| M3: Benchmark protocol | Not started | |
| M4: Solana transport analysis | Not started | |
| M5: sBPF verifier experiment | Not started | |
| M6: Results and report | Not started | |
| M7: Release | Not started | |

## M1 — what was done (2026-10-04)

- Created the `pq-solana-lab` Cargo package with pinned toolchain
  (rust-toolchain.toml: 1.91.1) and pinned dependencies:
  `ed25519-dalek =3.0.0`, `fips204 =0.4.6` (features `default-rng`,
  `ml-dsa-44`), `getrandom =0.4.3`. Versions verified against crates.io on
  2026-10-04: all are the current latest releases (fips204 unchanged since
  2024-12; ed25519-dalek 3.0.0 released 2026-07).
- Implemented a byte-oriented shared interface (`src/crypto.rs`, with
  submodules under `src/crypto/` — no `mod.rs`, per project convention):
  `Scheme::{keygen, sign, verify}` plus length constants and stable scheme
  IDs (Ed25519 = 1, ML-DSA-44 = 2) reserved for the M2 intent encoding.
- Adapters use only documented public APIs. Ed25519: 32-byte seed from
  `getrandom::fill`, `SigningKey::from_bytes`. ML-DSA-44: pure mode, empty
  context string, randomized (hedged) signing via `fips204`'s internal
  OS-backed RNG. RNG trait versions were not unified across libraries, per
  plan task M1.4.
- Error model: `Ok(bool)` verdicts for well-formed inputs;
  `Err(InvalidLength)` / `Err(MalformedEncoding)` for unparseable input.
  No panics on malformed bytes (tested).
- Tests (`tests/crypto_roundtrip.rs`, 10 tests, release mode): round-trip
  after serialization, repeated signing, altered message, wrong key,
  corrupted signature, truncated signature, wrong-length key/sig/secret,
  empty message, scheme-ID stability, standard parameter sizes
  (32/64 and 1312/2560/2420 bytes).
- Demo (`src/main.rs`, `demo` subcommand): prints scheme, category label,
  public-key/signature sizes, and accept/reject verdicts. Never prints
  secret keys.
- Docs: `docs/research-question.md` (question, hypotheses H1–H3, FIPS 204
  references including the NIST errata planning note of 2026-07-31),
  `results/environment.json` (host, toolchain, release profile, dependency
  versions, signing modes).

## Commands actually run

- `cargo test --release` → 10 passed, 0 failed (twice; before and after
  fmt/clippy cleanup)
- `cargo run --release -- demo` → both schemes sign/verify, tamper and
  wrong-key rejection shown
- `cargo clippy --release --all-targets` → clean after one fix
- `cargo fmt` → applied; `cargo fmt --check` → clean

## Problems encountered

- ed25519-dalek 3.0.0 requires the `Verifier` trait in scope for
  `VerifyingKey::verify` (trait method, not inherent). Fixed by importing
  `ed25519_dalek::Verifier`. Confirmed cause: API change vs 2.x.
- The plan's note "fips204 0.4.6, ed25519-dalek 3.0.0" matched current
  releases; no version surprises.
- Initial claim "no FIPS 204 errata noted" was wrong; NIST's page has a
  2026-07-31 planning note linking an errata spreadsheet of minor issues.
  Corrected in `docs/research-question.md`.

## Known limitations (by design this milestone)

- Secret keys are plain heap bytes in `KeyPair`; no zeroize. Prototype
  custody only, documented in code.
- ML-DSA correctness is self-round-trip only so far; an independent
  known-answer/interoperability check is scheduled in M3.
- No Solana dependencies yet (deferred to M4 per plan stop rule).

## Next concrete action

M2: canonical withdrawal intent — specify the byte encoding in
`docs/encoding.md` first, then implement intent encode/decode, trusted key
registry, environment binding, expiry, and atomic nonce consumption with the
plan's adversarial test matrix. Waiting for the user to commit M1 first.
