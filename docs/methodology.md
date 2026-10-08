# Benchmark methodology

This documents the measurement protocol behind `cargo run --release --
benchmark --config configs/<profile>.json`. The numbers describe one
implementation (`ed25519-dalek` 3.0.0, `fips204` 0.4.6, `fips205` 0.4.1) on one
machine (Apple M4, macOS 27.0.1); they are not a universal ranking, not
constant-time evidence, and are never converted into Solana compute units.

## Measurement boundaries

| Operation | What is timed | What is excluded |
| --- | --- | --- |
| `keygen` | fresh key generation per iteration | nothing (keygen is self-contained) |
| `sign`, mode `prepared` | signing with a key parsed once via `Scheme::prepare_signer` | key reconstruction before the loop |
| `sign`, mode `byte` | signing via the serialized-byte adapter (includes per-call secret-key parse and key expansion) | nothing besides the adapter call |
| `verify`, mode `prepared` | verification with a key parsed once via `Scheme::prepare_verifier` | key reconstruction before the loop |
| `verify`, mode `byte` | verification via the byte adapter (includes per-call public-key parse) | nothing besides the adapter call |
| `verify_strict`, both modes | the strict path `authorization` uses (Ed25519 additionally rejects weak keys and small-order components) | as above |
| `authorize` | registry lookup, intent decoding, environment/expiry policy, strict verification, and the atomic nonce/ledger update | fixture signing (done in batches between timed samples); the wall-clock cost of that signing still counts against the case budget |

## What is included in a timed interval

- **Included:** the operation call and everything it does internally. For
  ML-DSA/SLH-DSA signing that includes internal randomness acquisition (hedged
  signing) and key expansion; `PreparedSigner::sign` returns a `Vec`, so
  **output allocation is inside** the timed interval (allocation is not claimed
  to be excluded).
- **Excluded:** fixture construction, key/message preparation, warm-up, result
  validation, and — for `authorize` — signing the fixtures.

## Observable operations

Timing is `Instant::now()` → operation → `Instant::now()`. The operation's
result is passed through `std::hint::black_box` (as are the inputs) so the call
cannot be optimized away, and it is **validated after** the second timestamp:

- `keygen` — the produced key pair has the scheme's public/secret lengths.
- `sign` — the produced signature has the scheme's signature length and verifies
  under the key.
- `verify`/`verify_strict` — the verdict matches the fixture's intended class.
- `authorize` — the request is accepted (or, for the replay class, rejected with
  a nonce mismatch).

Each raw row records whether the result was expected. A case whose results are
unexpected gets an explicit `status` (`partial` / `failed`) and a note; an empty
or all-invalid case reports **no** times (`null`), never a successful zero. A
case that stopped early because of the per-case budget is flagged
`budget_limited`.

## Message cases

32 bytes (short), 166 bytes (the actual encoded withdrawal intent, see
`docs/encoding.md`), and 1,024 bytes. For `authorize` the message is the encoded
intent (166 bytes). The **same key and the same message bytes are reused** for
every sample in a case — these are warm single-key timings, not rotating-key
performance.

## Signing randomness and signature reuse

- Ed25519 signing is deterministic (RFC 8032 pure): every sample produces the
  same signature.
- ML-DSA-44/65 and SLH-DSA use randomized ("hedged") signing, so each signature
  differs; the measured distribution therefore includes the rejection-sampling
  spread (visible as the wide ML-DSA sign quartiles).
- For `verify` the same signature bytes are reused across samples (one fixture
  per class). For `sign` no signature is reused. For `authorize`, each accepted
  request uses a **fresh signature over the next nonce** (valid state
  progression), never a replay.

## Key reuse

One key pair per scheme is generated outside the loop and reused for all
message lengths and modes. `keygen` is the only operation that measures fresh
key generation, and it does so per iteration.

## Input classes

- Verify: `valid` (expected `Ok(true)`), `corrupted` (one signature byte
  flipped; expected `Ok(false)`), `invalid_len` (truncated signature; expected
  `Err`). Classes are **constructed**, not inferred from the verdict (see the
  verification-result contract in `src/crypto.rs`).
- Authorization: `valid` (state-advancing accept) and `replay` (resubmission of
  an already-consumed nonce; expected nonce-mismatch rejection).

## Sampling and statistics

- **Warm-up**: `warmup` untimed iterations before each timed case.
- **Samples**: up to `samples` iterations per case, bounded by
  `budget_seconds` of wall-clock per case.
- **Statistics**: median and first/third quartiles (linear-interpolation
  quantile); p95 only when the actual valid sample count is at least
  `min_samples` (project rule: ≥ 200).
- **Repetitions**: the principal comparison uses three independent full runs
  (`full-r1`–`full-r3`) with unique run identifiers; within-run spread is the
  interquartile range, between-run variability is reported as
  `(max − min) / min` of the per-run medians (see `docs/report.md` §5.6).

## Configuration validation

`bench::validate` rejects an empty/unknown scheme, mode, operation, or input
class, a non-positive sample/min-sample count or budget, an empty message-length
list, and a `run_id` that is not `[A-Za-z0-9_-]+`. `run_id` uniqueness is
enforced at the CLI (a run refuses to overwrite an existing metadata file unless
`--force` is given), so previous runs are never silently replaced.

## Signing modes recorded

Ed25519: deterministic RFC 8032 (pure, no context). ML-DSA-44/65: FIPS 204 pure
mode, empty context, randomized ("hedged") signing. SLH-DSA-SHA2-128s: FIPS 205
pure mode, empty context, hedged signing — recorded in
`results/environment.json` and per-run metadata.

## Reproducibility and provenance

Dependencies and toolchain are pinned. Before writing any output, each run
captures provenance into `results/<run_id>.json`: the source revision, whether
the tree was dirty (with a recoverable patch saved to
`results/patches/<run_id>.patch`), SHA-256 hashes of `Cargo.toml`, `Cargo.lock`,
the config file, and every `src/**/*.rs` file, plus the compiler/cargo versions,
host OS/arch/CPU, and the sampling settings. Provenance is captured **before**
the run's own outputs are written, so result files are never mistaken for
source changes. Raw samples go to `results/raw/<run_id>.csv`; summaries to
`results/summaries/<run_id>.csv`.

## Timing resolution

`std::time::Instant` is used. Its resolution is finer than the operations being
measured (the smallest meaningful medians are on the order of microseconds), but
very short operations still carry timer-call overhead. Timings are wall-clock
observations, not cycle counts. Sub-resolution cases are reported honestly: for
example, `verify` with `invalid_len` in `prepared` mode is a length check that
returns before any cryptographic work and reports as `0` ns. Read such values as
"at or below measurement resolution", never as "free".
