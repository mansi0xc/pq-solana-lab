# Progress log

## Milestone status

| Milestone | Status | Evidence |
| --- | --- | --- |
| M1: Working primitives | **Complete** (committed) | `cargo test --release` → 10/10; demo genuine output |
| M2: Authorization semantics | **Complete** (pending review/commit) | 46 tests pass (incl. Ed25519 RFC 8032 known-answer, weak-key rejection); demo genuine |
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

## M2 — what was done (2026-10-04)

- Specified the canonical encoding in `docs/encoding.md` (166 bytes: 8-byte
  domain, 1-byte version, 1-byte scheme, 4-byte key id, four 32-byte
  identifiers, three u64 big-endian ints) *before* implementing. Exact-length
  rule makes trailing bytes impossible.
- `src/intent.rs`: `WithdrawalIntent::encode/decode` with strict rejection of
  wrong length, unsupported version, and unknown scheme. Decoder deliberately
  does not check domain/network/program — those are policy, not parsing.
- `src/authorization.rs`: `KeyRegistry` (key id → scheme + public key, rejects
  duplicates and malformed key material), `Environment`, and `Authorizer` with
  the check order decode → bounds → registered key + scheme match → signature
  → environment (domain/network/program) → expiry (`current_slot <=
  expiry_slot`) → nonce → atomic commit. Nonce increments only on success;
  overflow is rejected.
- `docs/threat-model.md`: trusted components, adversary model, the conditional
  authorization argument, and the explicit in-memory replay-state limitation.
- Tests: `tests/encoding.rs` (6, incl. a golden fixture pinned to a hex string
  asserted verbatim) and `tests/authorization.rs` (17) covering every scenario
  in the plan's M2 table plus a `nonce_overflow` unit test. Integrity vs policy
  rejections are tested separately (tampered fields → `InvalidSignature`;
  correctly signed wrong-network/domain/program → policy errors).
- Demo extended with an authorization section: accept, replay rejection,
  tampered-amount rejection, expiry rejection, wrong-network rejection.

## Commands actually run (M2)

- `cargo test --release` → 34 passed, 0 failed (1 unit + 17 auth + 10 crypto +
  6 encoding)
- `cargo run --release -- demo` → full crypto + authorization output
- `cargo clippy --release --all-targets` → clean; `cargo fmt` → applied

## Problems encountered (M2)

- Two test-authoring bugs caught by the test run itself: a leftover
  `Vec::new()` tuple in the valid-request test (type inference), and a
  wrong-length test that clamped a 167-byte buffer back to 166. Both were
  straightforward to fix; no production-code defects.

## Correction batch (reviewer findings, 2026-10-04)

Six issues fixed, with verification:

1. **Weak Ed25519 keys allowed secretless authorization.** Registration now
   validates via `Scheme::validate_public_key` (dalek `from_bytes` +
   `is_weak`), and the authorization path uses `verify_strict`. Regression
   tests: weak/malformed registration rejection, and a unit test that forces a
   weak key past registration and shows `verify_strict` rejects the
   identity-R/zero-S forgery with nonce/ledger unchanged.
2. **Authorization records omitted the asset.** `AuthorizationRecord.asset`
   added; demo and tests assert the signed asset is preserved and distinct
   assets stay distinguishable.
3. **Configurable environment version was ignored.** Removed `Environment.version`; the
   encoding version is a parser-only concern enforced by the decoder. Tests and
   docs updated.
4. **Verification-result docs misclassified malformed signatures.** Rewrote the
   contract: `Ok(false)` is an opaque backend rejection (does not identify a
   failure stage); adapter-detected length/decoding errors are `Err`. Input
   classes are documented to come from fixtures, not from `Ok(false)`.
5. **README audit claim.** Replaced with precise reuse/attribution language
   distinguishing standardization, testing, conformance evidence, and audits.
6. **Broken links.** Fixed `crypto.rs` `[`Scheme::verify`]` and `idea.md`'s
   companion-plan link (`plan.md`).

Evidence strengthened: authorization scenarios now run for both schemes;
independent Ed25519 correctness via RFC 8032 §7.1 known-answer vectors
(provenance recorded in `tests/ed25519_known_answer.rs`); a minimal
prepared-key path (`prepare_signer`/`prepare_verifier`) establishes the
"already-parsed key" vs "byte adapter" vs "complete authorization" measurement
boundaries without starting the benchmark campaign.

### ML-DSA independent-correctness gap (recorded, not claimed complete)

The ML-DSA external sign API uses randomized ("hedged") signing, so no fixed
published signature can be reproduced; verification is deterministic but no
NIST ACVP sigVer vector (empty context) has been sourced/transcribed yet. The
crate documents that NIST vectors apply to its internal functions only. Current
ML-DSA validation is therefore a self round-trip; an interop cross-check is
scheduled for M3.

### Commands run (this batch)

- `cargo fmt --check` → clean
- `cargo test --release --locked` → 46 passed, 0 failed
- `cargo clippy --release --all-targets --locked -- -D warnings` → clean
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked` → clean
- `cargo run --release --locked -- demo` → genuine output
- `git diff --check` → clean

## Next concrete action

M3: benchmark harness — add ML-DSA-65 and SLH-DSA-SHA2-128s via `fips204`/
`fips205`, use the prepared-key path to separate primitive from byte-adapter
timings, write the raw-sample schema and config profiles, and add the
independent ML-DSA interop cross-check. Waiting for the user to commit this
correction batch first.
