# Progress log

## Milestone status

| Milestone | Status | Evidence |
| --- | --- | --- |
| M1: Working primitives | Complete (committed) | 10 crypto round-trip tests; demo genuine output |
| M2: Authorization semantics | Complete (committed) | encoding (6), authorization (24), Ed25519 RFC 8032 known-answer (1) tests; demo genuine |
| M3: Benchmark protocol | Complete (committed) | 4 schemes benchmarked; ML-DSA interop cross-check (3 tests); raw→summary consistency test |
| M4: Solana transport analysis | Complete; **revised in correction batch 1** | legacy/v0 bincode + v1 `wincode`; minimal/operational templates; serialized staged protocol; 20 transport tests |
| M5: sBPF verifier experiment | Complete; **corrected in Batch 3** | compiler emits stack-frame diagnostics (exit 0); ELF loads/verifies; deploys to a local validator; **aborts at runtime** (access violation) before any verdict |
| M6: Results and report | Complete; **revised in correction batch 1** | full profile: 94,545 raw rows + 100 summary rows; 3 plots; generated tables; report; AI-usage doc |
| M7: Release | Complete; **revised in correction batch 1** | README; CI; short demo + separate benchmark pilot; demo outline; interview Q&A |
| Correction batch 1 (reviewer findings on `71b171f`) | Complete (committed `dd9d971`) | v1 wire encoding fixed; staged protocol defined; report statistics regenerated; security wording corrected |
| Correction batch 2 (benchmarking) | Complete (committed `05389df`) | `black_box` + result validation; four measurement boundaries; provenance capture; three independent full runs (`full-r1`–`full-r3`) |
| Correction batch 3 (sBPF outcome, comparison, note) | Complete (committed `b95de43`) | control program executes; verifiers load/verify/deploy then **trap at runtime**; RustCrypto comparison; `docs/technical-note.md` |
| Correction batch 4 (v1 submission scope) | Complete (pending author review/commit) | v1 rejection reproduced and explained: `enable_tx_v1` absent from the Agave 3.1.x feature set |

Counts in the historical sections below describe the state at each milestone;
the current suite is **78 tests** (`cargo test --release --locked`, all green).

## Evidence taxonomy

- **Implemented** — code paths and their tests: crypto adapters, canonical
  intent, authorizer, benchmark harness, transport serialization, analysis
  scripts.
- **Measured** — host wall-clock samples (`results/raw/*.csv`), actual
  transaction wire bytes (`results/transport.json`), and sBPF compiler
  diagnostics (`experiments/sbpf-verifier/build.log`).
- **Modeled** — the staged-upload lifecycle: each component transaction is
  serialized, but the sequence is not executed; treated as a lower-bound
  estimate (`results/transport-staged.json`, evidence type `modeled`).
- **Inferred** — nothing is presented as measured that was not measured.
- **Unresolved** — persistent replay state; independent conformance for
  ML-DSA-65/SLH-DSA; a specific numbered theorem from the threshold paper; and
  on-chain execution of the verifier (blocked before execution).


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

## M3.1 — benchmark harness (2026-10-05)

- Added pinned `serde =1.0.229` (derive) and `serde_json =1.0.151` for config
  and result/metadata serialization.
- `src/bench.rs`: config schema, timing engine (warm-up, per-case time budget,
  actual sample counts), raw-sample and summary schemas, and summary
  statistics (median, Q1/Q3 via linear-interpolation quantile; p95 only when
  `sample_count >= min_samples`). Valid fixtures are produced and checked once
  *outside* the timed loop; keys/messages are prepared before timing.
- `src/main.rs`: `benchmark --config <path>` subcommand writes
  `results/raw/<run_id>.csv`, `results/summaries/<run_id>.csv`, and
  `results/<run_id>.json` (config + `git rev-parse HEAD` + dirty status).
- `configs/quick.json`, `configs/full.json`; `docs/methodology.md` documents
  measurement boundaries (prepared vs byte vs keygen), sampling policy, key
  reuse, signing modes, input classes, and sub-resolution-timing caveats.
- Pilot run (`quick`): 2 schemes × {keygen, sign, verify} × {32, 166, 1024}
  byte messages × {prepared, byte} modes × {valid, corrupted, invalid_len}
  classes → 15,000 raw rows, 50 summary rows. Genuine data at
  `results/raw/quick.csv` and `results/summaries/quick.csv`.

### Pilot observations (host, Apple M4; not conclusions)

- ML-DSA-44 is roughly 6–9× slower to sign and ~2× slower to verify than
  Ed25519 on this host (e.g. sign ~126–177 µs vs ~10–18 µs; verify ~40–50 µs
  vs ~19–21 µs). These are host wall-clock observations only.
- `byte`-mode `invalid_len` still pays public-key reconstruction before the
  length check, while `prepared`-mode rejects wrong-length input at ~0 ns
  (below timer resolution); documented in `docs/methodology.md`.

## M3.2 — additional schemes + interop cross-check (2026-10-05)

- Added `fips205 =0.4.1` (SLH-DSA-SHA2-128s) and enabled `fips204`'s
  `ml-dsa-65` feature. Renamed `src/crypto/ml_dsa.rs` → `ml_dsa_44.rs`, added
  `ml_dsa_65.rs` and `slh_dsa.rs` adapters, and added `Scheme::MlDsa65` (id 3)
  and `Scheme::SlhDsaSha2128s` (id 4) with full dispatch through the shared
  interface (keygen/sign/verify/verify_strict/validate/prepared keys).
- Independent ML-DSA interop cross-check (`tests/ml_dsa_interop.rs`, 3 tests):
  a `fips204` signature verifies under the RustCrypto `ml-dsa` 0.1.1 crate (a
  separate FIPS 204 final implementation) and vice versa, with a
  tampered-message rejection. Closes the previously documented "self
  round-trip only" gap for ML-DSA-44.
- Updated `configs/quick.json` (warmup 10, 15s/case budget) and
  `configs/full.json` (1000 samples, 60s/case budget) to cover all four
  schemes. Re-ran the quick profile in 2m30s; the `full` profile is the
  documented ~8-minute run deferred to M6.

### M3.2 pilot observations (host, Apple M4; not conclusions)

- SLH-DSA-SHA2-128s is far slower than the other schemes on this host: sign
  ~512–580 ms, keygen ~66 ms, verify ~0.49 ms. Its sign cases hit the 15s/case
  budget in the quick profile and therefore record only ~26–117 samples
  (explicitly reported, no p95). The `s` variants trade fast signing for slow
  keygen and small signatures (7,856-byte signatures here).
- ML-DSA-65 keygen ~132 µs (vs ML-DSA-44 ~76 µs), sign and verify slightly
  slower than ML-DSA-44, with 1,952-byte keys and 3,309-byte signatures.

## M4.1 — actual legacy/v0 serialization + direct sizing (2026-10-05)

- Added pinned `solana-sdk =5.0.0` and `bincode =1.3.3`. Verified the current
  (split-crate) SDK API against its source: `Pubkey` is now an alias for
  `Address`; legacy `Transaction::new_signed_with_payer`, v0
  `Message::try_compile` + `VersionedTransaction::try_new`; the SDK also
  exposes a `VersionedMessage::V1` variant (used in M4.2).
- `src/transport.rs`: builds and serializes a real legacy and v0 transaction
  per scheme × key placement, carrying the intent (166 B) + signature in
  instruction data (inline adds the public key). `cargo run --release --
  transport` prints the table and writes `results/transport.json`.
- `tests/transport.rs` (5 tests): all 16 rows are `serialized` evidence;
  Ed25519 inline fits; ML-DSA-44 exceeds 1,232 even when registered;
  registration removes exactly the public-key bytes; v0 ≈ legacy + version
  prefix.
- `docs/transport.md`: measured results + assumptions (fee payer, key
  registration, account lifecycle, v1 deferred).

### M4.1 measured result (solana-sdk 5.0.0, bincode)

Every post-quantum scheme's authorization payload exceeds the 1,232-byte
legacy/v0 packet budget even with the key registered: ML-DSA-44 = 2,758 bytes,
ML-DSA-65 = 3,647, SLH-DSA-SHA2-128s = 8,194 (registered). Ed25519 = 402
bytes. Registration saves exactly the public-key bytes (e.g. 1,312 for
ML-DSA-44) but does not address signature size.

## M4.2 — v1 serialization + staged upload (2026-10-05)

- Extended `src/transport.rs` to serialize v1 transactions via the SDK's
  `v1::Message::try_compile_with_config` (`VersionedMessage::V1`); the v1 limit
  is the SDK's `v1::MAX_TRANSACTION_SIZE` = 4,096.
- Added a staged-upload model: initialization + N chunk uploads + final
  reference. The largest safe chunk per format is derived by binary search over
  the actually-serialized 3-account upload template (stated margin 0).
- `tests/transport.rs` (8 tests) pins the findings, incl. "v1 lifts ML-DSA-44
  but not ML-DSA-65/SLH-DSA" and "staged chunking is consistent and labeled
  modeled".

### M4 measured results

- **Direct**: ML-DSA-44 fits v1 inline (4,089 bytes, 7-byte headroom) and
  comfortably when registered; ML-DSA-65 fits v1 only when registered (3,666);
  SLH-DSA-SHA2-128s exceeds even v1 (8,213 registered).
- **Staged (modeled)**: chunk sizes ~1,027 (legacy/v0) and ~3,872 (v1);
  SLH-DSA needs 8 legacy chunks / 3 v1 chunks. Staging makes each transaction
  fit but raises total transport bytes (repeated per-transaction overhead) and
  introduces on-chain state; it does not reduce verification cost.

## M5 — sBPF verifier experiment (2026-10-06, time-boxed)

- Confirmed the toolchain works: a minimal no-op program builds to a valid
  11,336-byte sBPF ELF with `solana-cargo-build-sbf 3.1.10` / platform-tools
  v1.52 / rustc 1.89.0.
- Built a verification-only ML-DSA-44 program (`experiments/sbpf-verifier/`,
  `fips204` 0.4.6 with `default-features = false, features = ["ml-dsa-44"]`,
  no RNG). It **compiles** for sBF, but the sBPF ELF checker rejects it:
  several functions exceed the 4,096-byte stack-frame limit — `verify_internal`
  ~62 KB, `PublicKey::try_from_bytes` ~24 KB, `ntt::ntt` ~8.3 KB, `entrypoint`
  ~10.9 KB. Full log: `experiments/sbpf-verifier/build.log`.
- **Outcome: reproducible stack-frame blocker (before execution).** This is a
  stack-frame-size limitation, not a build failure, not a heap failure, and not
  compute-budget exhaustion. No execution occurred, so no compute-unit
  measurements exist or are claimed.
- Documented in `docs/solana-feasibility.md`, which also states the scope
  limit: this is `fips204` 0.4.6-specific; a verifier that heap-allocates its
  large buffers (or otherwise reduces per-function stack) may differ, and no
  universal infeasibility is inferred.

## M6 — results and report (2026-10-06)

- Ran the frozen `full` profile (4 schemes, 1,000 samples/case, 60 s/case
  budget, warm-up 20): **94,545 raw data rows** (94,546 lines including the
  header) + 100 summary rows, at `results/raw/full.csv` and
  `results/summaries/full.csv`, with metadata in `results/full.json`.
- `scripts/plot_results.py` generates three plots from result artifacts (median
  recomputed from raw rows; sizes read from summary metadata) into
  `results/plots/`: verification latency, key/signature bytes, transport
  headroom.
- `docs/report.md`: four-to-six-page report — finding first, then related work,
  design, methodology, results, conditional security argument, limitations,
  future work, attribution. (At M6 an `docs/ai-usage.md` was *claimed* here but
  was **not** written in the reviewed checkout; it exists now, added in
  correction batch 1.)
- Report numbers are traced to the raw/summary files; the threshold-ML-DSA
  paper (ePrint 2026/013) is cited from its abstract, and the limitation that a
  specific numbered theorem from its proof was not traced is stated explicitly.

## M7 — reviewable release (2026-10-06)

- Rewrote `README.md` in reviewer order (question, finding, reproduction,
  plot, demo, report, design, limitations, attribution) with an accurate
  résumé bullet.
- Added `.github/workflows/ci.yml`: fmt, clippy `-D warnings`, release tests,
  rustdoc `-D warnings`, plus `demo`/`transport` smoke runs (no timing gates,
  no expensive benchmark/sBPF in CI).
- `scripts/demo.sh` (chmod +x) for the short recording. Note: at M7 this log
  also claimed `docs/demo-outline.md` and `docs/interview-qa.md`, but **neither
  existed in the reviewed checkout**; both are now written (correction batch 1),
  and the demo script was split so its duration matches its description
  (`scripts/bench-pilot.sh` carries the long pilot run).

## Correction batch 1 — transport, statistics, and security claims (reviewer findings on `71b171f`)

Issues found in the reviewer's inspection of the committed release, and what
was done:

1. **v1 transaction wire encoding was wrong.** `src/transport.rs` used
   `bincode::serialize` for v1, but `solana-message` 5.1.0 states the v1 format
   does not support bincode. v1 now uses the SDK's own `wincode` encoder (and
   decoder), including the `0x81` prefix and fixed-length signature suffix.
   Tests cover wire decoding, message equality, native signature verification,
   the version prefix, and that a bincode v1 buffer is rejected. Legacy/v0 remain
   bincode. The superseded numbers are preserved in
   `results/transport.bincode-v1-superseded.json`.
2. **Templates and v1 limits.** Explicit `minimal` (2-account) and
   `operational` (4-account: payer + registry + authorization state + program)
   templates; the operational v1 rows set `compute_unit_limit = 200_000` and
   `loaded_accounts_data_size_limit = 65_536`. Signed intents now carry the row's
   scheme id and the environment's program/network ids. The reviewer's
   diagnostic ladder (4,074 / 4,082 / 4,115, plus the 4-account 4,148) is
   reproduced by a test.
3. **Staged upload is now a concrete protocol, not raw byte counts.** `Init` /
   `Write` / `Seal` / `Authorize` instructions with defined encodings,
   uploader/session/key binding, expected length, sequential offsets, sealing,
   and session metadata + signature storage. Chunk capacity is derived from the
   complete serialized `Write` transaction. Still labeled **modeled** (lower
   bound); rent/registration/cleanup excluded.
4. **Report statistics were wrong.** The report's "median" column actually held
   first-quartile values (e.g. ML-DSA-44 sign reported as 95.1 µs when Q1 =
   95,125 ns and the median = 127,625 ns). Tables are now generated from the raw
   samples by `scripts/report_tables.py`, with `report_tables.py check` and
   `tests/report_consistency.rs` failing on drift. Plots read sizes from result
   metadata and error on missing data instead of plotting zero.
5. **Security wording corrected.** The report described SUF-CMA as forgery on a
   never-queried message (that is EUF-CMA). It now distinguishes EUF-CMA from
   SUF-CMA, states that FIPS 204 §3.1 designs ML-DSA to be SUF-CMA, and explains
   that the application's anti-forgery step needs EUF-CMA while replay is handled
   by nonce/state.
6. **Release/completion claims corrected.** The three missing documents were
   created (`docs/ai-usage.md`, `docs/demo-outline.md`, `docs/interview-qa.md`);
   the demo was split; the Python environment is documented
   (`scripts/requirements.txt`); stale counts and statuses are fixed above.

Commands run for this batch: `cargo fmt --check`; `cargo test --release
--locked` (70 tests); `cargo clippy --release --all-targets --locked -- -D
warnings`; `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked`; `cargo run
--release --locked -- demo`; `cargo run --release --locked -- transport`;
`python3 scripts/report_tables.py check`; `git diff --check`.

## Correction batch 2 — benchmarking observability, boundaries, and repetitions

Reviewer findings addressed:

1. **Timed operations are observable and failures explicit.** The harness wraps
   inputs and outputs in `std::hint::black_box` and validates each operation's
   result *after* the second timestamp (key lengths; sign-then-verify; verdict
   vs intended class; authorization accept/replay). Every case reports
   `sample_count`, `valid_count`, `budget_limited`, and a `status`
   (`ok`/`partial`/`failed`/`skipped`); an empty or all-invalid case reports no
   times, never a successful zero. Allocation/randomness/key-expansion inclusion
   is documented in `docs/methodology.md`.
2. **Missing measurement boundaries added.** The harness now measures prepared-key
   primitives, the serialized-byte adapter, `verify_strict` (the path
   authorization uses), and complete `authorize` (registry lookup, decoding,
   environment/expiry policy, strict verification, atomic nonce/ledger update).
   Successful authorization samples use valid state progression (each request
   consumes the next nonce); the replay class is a separate rejection workload.
   Key reuse, message reuse, signing randomness, and rejection classes are
   documented.
3. **Independent repetitions with provenance.** Three independent full runs
   (`full-r1`–`full-r3`, 180 cases / ~173,640 raw rows each) with unique run
   identifiers and no overwrite. Before writing outputs each run captures the
   revision, dirty-tree patch (`results/patches/<id>.patch`), SHA-256 hashes of
   the source tree / `Cargo.toml` / `Cargo.lock` / config, toolchain and host
   identity, and sampling settings. Report §5.6 shows between-run spread.
4. **New tests.** `tests/bench.rs` covers statistics (quantile reference),
   configuration validation, empty/failed status handling, output consistency,
   authorization state progression, and budget-limited marking.
5. **Documentation.** `docs/methodology.md` rewritten; `results/provenance.md`
   updated; the pre-review `full`/`quick` runs are marked historical.

Commands run for this batch: `cargo fmt --check`; `cargo clippy --release
--all-targets --locked -- -D warnings`; `cargo test --release --locked` (78
tests); `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked`; `cargo run
--release --locked -- demo`; `cargo run --release --locked -- transport`;
`python3 scripts/plot_results.py …`; `python3 scripts/report_tables.py
check`; `git diff --check`.

## Correction batch 3 — actual sBPF outcome, controlled comparison, technical note

Fixes the reviewer's finding that the compiler log did not establish loader
rejection, and that no execution had been attempted.

1. **Control program.** `experiments/sbpf-control/` (minimal no-op) builds with
   **no** frame diagnostics (17,320-byte ELF) and **executes** on a local
   validator: `sbpf-control: ok`, 539 CU.
2. **Loader evidence.** A host harness (`experiments/loader-harness/`, using the
   Agave SBF VM `solana-sbpf` 0.13.1 and `RequisiteVerifier`) loads both verifier
   ELFs and **passes verification** — the compiler diagnostics are not loader
   rejection.
3. **Authentic load + execute.** On `solana-test-validator` 3.1.10, both
   verifier programs **deploy successfully** (exit 0) and then **abort at
   runtime** with an access violation before any verdict: `fips204` — "Access
   violation in stack frame 3" after 418 CU; RustCrypto `ml-dsa` — "Access
   violation in program section" after 323 CU. Valid / altered / invalid inputs
   fail identically; no completed-verification compute figure exists. The
   oversized fixture is supplied through account data because the RPC enforces
   the 1,232-byte packet limit.
4. **Controlled comparison.** `experiments/sbpf-verifier-rustcrypto/` is the same
   program structure using RustCrypto `ml-dsa` 0.1.1 (same parameter set, mode,
   fixture, toolchain, runtime): 2 frame diagnostics instead of 17, but the same
   deploy-then-trap outcome. Unsupported comparisons are left incomplete.
5. **Technical note.** `docs/technical-note.md` covers rejection sampling,
   EUF-CMA vs SUF-CMA, the authorization/replay argument, why staged transport
   does not establish verifier feasibility, a specific FIPS 204 definition and
   requirement (§3.1, §3.6.2) with exact references, the experiment's limits, and
   a self-test.
6. **Docs corrected.** `docs/solana-feasibility.md`, `docs/report.md` (§1, §2,
   §5.7, §7), and `README.md` no longer claim loader rejection.

Commands run for this batch: `cargo-build-sbf` (control, fips204, rustcrypto);
`loader-harness probe`; `solana program deploy`; `experiments/outcome/invoke.sh`
— logs in `experiments/outcome/`. Root checks: `cargo fmt --check`; `cargo
clippy --release --all-targets --locked -- -D warnings`; `cargo test --release
--locked` (78 tests); `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked`;
`python3 scripts/report_tables.py check`; `git diff --check`.

## Correction batch 4 — v1 submission scope

The Batch-3 commit message flagged that v1 transactions were rejected by the
local validator. Investigated and resolved as a runtime-support fact, not a
defect in the transport analysis:

- `enable_tx_v1` ("SIMD-0385: Transaction V1") is defined in
  `agave-feature-set` 4.2.x but is **absent from `agave-feature-set` 3.1.14**
  (matching the 3.1.10 validator), so the 3.1.x runtime has no v1 support.
- Reproduced both rejection modes with `experiments/outcome/probe-v1.sh`
  (`experiments/outcome/v1-rejection.log`): a small v1 tx fails to deserialize
  (the RPC decodes bincode/serde; the v1 `0x81` prefix reads as 129
  signatures), and a large v1 tx exceeds the 1,232-byte packet limit.
- Documented in `docs/transport.md` (new section), `docs/report.md`
  (limitations), and `experiments/outcome/README.md`. The v1 tables remain
  `serialized` evidence; the execution experiment used legacy transactions with
  the fixture in account data.

## Next action

Correction batches 1–4 are complete and await the author's review and commit.
