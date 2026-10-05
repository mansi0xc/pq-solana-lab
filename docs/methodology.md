# Benchmark methodology

This documents the measurement protocol behind `cargo run --release --
benchmark --config configs/<profile>.json`. The numbers describe one
implementation (`ed25519-dalek` 3.0.0, `fips204` 0.4.6) on one machine
(Apple M4, macOS 27.0.1); they are not a universal ranking, not constant-time
evidence, and are never converted into Solana compute units.

## Measurement boundaries

| Operation | What is timed | What is excluded |
| --- | --- | --- |
| `keygen` | fresh key generation per iteration | none (keygen is self-contained) |
| `sign`, mode `prepared` | signing with a key parsed once via `Scheme::prepare_signer` | key reconstruction/allocation |
| `sign`, mode `byte` | signing via the serialized-byte adapter (includes per-call secret-key parse + allocation) | nothing inside the loop besides the adapter call |
| `verify`, mode `prepared` | verification with a key parsed once via `Scheme::prepare_verifier` | key reconstruction/allocation |
| `verify`, mode `byte` | verification via the byte adapter (includes per-call public-key parse + allocation) | nothing besides the adapter call |
| complete authorization | *not in this harness* | M3.2 measures it separately |

For `sign`/`verify`, keys and messages are prepared before the timed loop, and
a fixture signature is produced and checked *once, outside* the loop. The
timed loop only calls the operation under test.

## Message cases

32 bytes (short), 166 bytes (the actual encoded withdrawal intent, see
`docs/encoding.md`), and 1,024 bytes. The same key is reused within a run for
all message lengths — these are warm single-key timings, not rotating-key
performance, and are labeled as such.

## Input classes (verify only)

- `valid` — a correctly signed message; expected verdict `Ok(true)`.
- `corrupted` — a correctly sized signature with one byte flipped; expected
  verdict `Ok(false)`. Classified by construction, not inferred from the
  verdict (see the verification-result contract in `src/crypto.rs`).
- `invalid_len` — a truncated signature; expected verdict `Err(InvalidLength)`.

`sign` has only the `valid` class (signing always produces a valid signature).

## Sampling and statistics

- **Warm-up**: `warmup` untimed iterations before each timed case.
- **Samples**: up to `samples` iterations per case, bounded by
  `budget_seconds` of wall-clock per case (the loop stops early and records the
  actual count when the budget is hit).
- **Statistics**: median and first/third quartiles (linear-interpolation
  quantile); p95 only when the actual sample count is at least `min_samples`
  (project rule: ≥ 200). Smaller counts are reported without p95, never
  presented as if they supported it.

## Signing modes recorded

Ed25519: deterministic RFC 8032 (pure, no context). ML-DSA-44: FIPS 204 pure
mode, empty context, randomized ("hedged") signing — recorded in
`results/environment.json` and per-run metadata.

## Reproducibility

Dependencies are pinned and the toolchain is pinned (`rust-toolchain.toml`).
Each run writes a metadata file (`results/<run_id>.json`) with the exact
config, source revision (`git rev-parse HEAD`), and working-tree dirty status,
so any row can be traced back to the code that produced it. Raw samples go to
`results/raw/<run_id>.csv`; summaries to `results/summaries/<run_id>.csv`.

## Timing resolution

`std::time::Instant` is used. On this host its resolution is finer than the
operations being measured (the smallest median reported is on the order of
microseconds for Ed25519), but very short operations still carry timer-call
overhead. Timings are wall-clock observations, not cycle counts.

## Sub-resolution timings

Some measured values are below the timer's effective resolution and report as
`0` ns. In particular, `verify` with the `invalid_len` class in `prepared` mode
is a plain length check (a few nanoseconds) that returns an error before any
cryptographic work, so its median is `0`. Read such values as "at or below
measurement resolution", never as "free". The contrast with `byte` mode is the
real observation: the byte path still pays public-key reconstruction (point
decompression / ML-DSA key expansion) before rejecting a wrong-length
signature, while the prepared path does not.
