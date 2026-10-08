# PQ-Solana Lab — Research Report

**Question.** Under a specified Solana transaction format and execution
environment, what limits the practicality of standardized post-quantum
signatures for application authorization: payload size, verification
resources, or integration constraints?

**Scope.** One machine (Apple M4), pinned toolchain and libraries, host
wall-clock measurements, and offline Solana transaction *serialization*.
Nothing here establishes production security, a cryptographic proof, or
quantum security for Solana as a whole.

## 1. Finding (stated first)

The answer is **both, at different layers**, and a third factor does not remove
either:

1. **Payload size limits transport.** A canonical withdrawal intent (166 bytes)
   plus an ML-DSA-44 signature (2,420 bytes) exceeds the 1,232-byte legacy/v0
   packet budget *even with the public key registered out of band* (measured:
   2,758 bytes on the minimal template). ML-DSA-65 (3,647) and SLH-DSA-SHA2-128s
   (8,194) are worse. The 4,096-byte v1 format admits ML-DSA-44 — 2,762 bytes
   registered, or 4,074 bytes inline on a minimal two-account template — but an
   *operational* template (a read-only key-registry account, a writable
   authorization-state account, and explicit compute/loaded-data limits) pushes
   the inline case to 4,148 bytes, 52 bytes over the limit; registered it is
   2,836. ML-DSA-65 fits v1 only when registered (3,651 minimal / 3,725
   operational). SLH-DSA does not fit at any tested placement.
2. **Verification resources limit execution.** The `fips204` 0.4.6 ML-DSA-44
   verifier compiles for sBPF but is rejected by the 4,096-byte stack-frame
   check (`verify_internal` alone has a ~62 KB frame). No execution occurred, so
   no compute-unit numbers exist. This is one implementation under one
   toolchain, not a universal infeasibility result.
3. **Integration choices shift but do not eliminate cost.** Registering the key
   saves exactly the public-key bytes per transaction; staging the signature
   makes each transaction fit but raises total transport bytes and adds on-chain
   state. Neither reduces verification cost.

A correction matters for (1): v1 does **not** support bincode binary
serialization. The SDK states this explicitly for the v1 message format, and its
v1 decoder rejects a bincode buffer. The tables below therefore serialize v1
with the SDK's own `wincode` encoder. The superseded bincode-based v1 numbers
are preserved under `results/transport.bincode-v1-superseded.json`.

## 2. Related work

- **FIPS 204 (ML-DSA)** and **FIPS 205 (SLH-DSA)** define the standardized
  post-quantum signature schemes evaluated here. Parameter sizes are taken from
  the standards and cross-checked against the libraries. FIPS 204 §3.1 states
  ML-DSA is designed to be *strongly* existentially unforgeable under chosen
  message attack (SUF-CMA); §3.6.2 notes that public-key and signature length
  checks are required for that property.
- **RFC 8032 (Ed25519)** is the classical baseline; its §7.1 test vectors are
  used as known-answer evidence.
- **Libraries** (reused, not reimplemented): `fips204` 0.4.6 and `fips205` 0.4.1
  (IntegrityChain, pure Rust), `ed25519-dalek` 3.0.0, and — for independent
  ML-DSA conformance — the RustCrypto `ml-dsa` 0.1.1 crate.
- **Solana transaction formats.** `solana-sdk` 5.0.0 and the split crates it
  depends on (`solana-message` 5.1.0, `solana-transaction` 5.1.0) define the
  legacy/v0 (bincode) and v1 (`wincode`, SIMD-0385) wire formats.
- **Efficient Threshold ML-DSA** (Celi, del Pino, Espitau, Niot, Prest;
  ePrint 2026/013, USENIX Security '26) presents a threshold scheme compatible
  with standardized ML-DSA, using short secret sharing and optimized rejection
  sampling. Referenced only as future work; this project does not implement it.

## 3. Design

A byte-oriented signature interface dispatches four schemes (Ed25519, ML-DSA-44,
ML-DSA-65, SLH-DSA-SHA2-128s) behind key generation, signing, verification,
strict verification, key validation, and prepared-key operations. A canonical
166-byte withdrawal intent binds domain, encoding version, scheme, key id,
network, program, asset, recipient, amount, nonce, and expiry. A local
authorizer validates registration (rejecting weak Ed25519 keys), verifies
strictly, enforces environment binding and expiry, and consumes a nonce
atomically on success only. Transport uses two templates — a minimal two-account
payload template and an operational four-account authorization template — and a
serialized staged-upload protocol.

## 4. Methodology

- **Benchmarks** (`cargo run --release -- benchmark --config configs/full.json`):
  prepared-key and byte-adapter paths are measured separately; valid fixtures
  are produced and checked *once outside* the timed loop; warm-up (20) precedes
  timed sampling (up to 1,000 per case, bounded by 60 s/case). Median and
  quartiles are recomputed from the raw samples; p95 only when ≥200 samples.
  Host timings are wall-clock observations and are never converted into compute
  units. See `docs/methodology.md`.
- **Transport** (`cargo run --release -- transport`): sizes are actual wire
  serializations of `solana-sdk` 5.0.0 transactions — bincode for legacy/v0,
  `wincode` for v1. Staged upload is a **model** whose component transactions
  are serialized with full instruction framing. See `docs/transport.md`.
- **Verifier**: a verification-only ML-DSA-44 program is built with
  `cargo build-sbf` (platform-tools v1.52, rustc 1.89.0).

Every numeric table below is generated from identified artifacts by
`scripts/report_tables.py`; `scripts/report_tables.py check` fails if a published
table drifts from the raw evidence, and `tests/report_consistency.rs`
independently recomputes the summaries from the raw samples.

## 5. Results

### 5.1 Host primitives (prepared, valid, 166-byte messages)

<!-- BEGIN GENERATED: host_primitives -->
_Source: run `full` (`configs/full.json`), mode `prepared`, input class `valid`, 166-byte messages; raw `results/raw/full.csv`. Medians recomputed from raw samples._

| Scheme | keygen | sign (166 B) | verify (166 B) | pubkey (B) | signature (B) |
| --- | --- | --- | --- | --- | --- |
| Ed25519 | 10.9 µs | 8.8 µs | 18.7 µs | 32 | 64 |
| ML-DSA-44 | 76.6 µs | 127.6 µs | 40.3 µs | 1312 | 2420 |
| ML-DSA-65 | 130.8 µs | 228.8 µs | 66.0 µs | 1952 | 3309 |
| SLH-DSA-SHA2-128s | 66.6 ms (n=889) | 511.0 ms (n=116) | 581.8 µs | 32 | 7856 |
<!-- END GENERATED: host_primitives -->

### 5.2 Host quartiles (prepared, valid, 166-byte messages)

<!-- BEGIN GENERATED: host_quartiles -->
_Source: run `full` (`configs/full.json`), mode `prepared`, input class `valid`, 166-byte messages; raw `results/raw/full.csv`. Quartiles recomputed from raw samples (linear interpolation); p95 omitted below 200 samples._

| Scheme | operation | n | median | Q1 | Q3 | p95 |
| --- | --- | --- | --- | --- | --- | --- |
| Ed25519 | keygen | 1000 | 10.9 µs | 10.8 µs | 11.4 µs | 16.0 µs |
| Ed25519 | sign | 1000 | 8.8 µs | 8.3 µs | 8.9 µs | 9.4 µs |
| Ed25519 | verify | 1000 | 18.7 µs | 18.6 µs | 18.7 µs | 18.9 µs |
| ML-DSA-44 | keygen | 1000 | 76.6 µs | 76.3 µs | 76.8 µs | 78.6 µs |
| ML-DSA-44 | sign | 1000 | 127.6 µs | 95.1 µs | 223.1 µs | 444.6 µs |
| ML-DSA-44 | verify | 1000 | 40.3 µs | 40.2 µs | 40.4 µs | 42.8 µs |
| ML-DSA-65 | keygen | 1000 | 130.8 µs | 130.5 µs | 131.3 µs | 135.8 µs |
| ML-DSA-65 | sign | 1000 | 228.8 µs | 141.7 µs | 361.1 µs | 676.3 µs |
| ML-DSA-65 | verify | 1000 | 66.0 µs | 65.8 µs | 66.2 µs | 71.8 µs |
| SLH-DSA-SHA2-128s | keygen | 889 | 66.6 ms | 66.4 ms | 67.4 ms | 71.7 ms |
| SLH-DSA-SHA2-128s | sign | 116 | 511.0 ms | 508.8 ms | 516.4 ms | — |
| SLH-DSA-SHA2-128s | verify | 1000 | 581.8 µs | 561.1 µs | 607.7 µs | 692.3 µs |
<!-- END GENERATED: host_quartiles -->

The reported signing distribution is wide (ML-DSA-44 median 127.6 µs with Q1
95.1 µs, Q3 223.1 µs) because ML-DSA signing is rejection-sampled: each
signature takes a variable number of loop iterations. Reporting the first
quartile as if it were the median understates the typical cost; the generator
and its consistency check prevent that regression.

### 5.3 Transport, direct inclusion (serialized)

<!-- BEGIN GENERATED: transport_direct -->
_Source: `results/transport.json` — actually serialized `solana-sdk` 5.0.0 transactions; legacy/v0 use bincode, v1 uses the SDK `wincode` wire encoder. Evidence type: `serialized`. Limits: legacy/v0 = 1,232 B, v1 = 4,096 B._

| Scheme | Template | Placement | legacy (B) | v0 (B) | v1 (B) | accounts | v1 config |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Ed25519 | minimal | inline | 434 | 436 | 438 | 2 | empty |
| Ed25519 | minimal | registered | 402 | 404 | 406 | 2 | empty |
| Ed25519 | operational | inline | 500 | 502 | 512 | 4 | explicit |
| Ed25519 | operational | registered | 468 | 470 | 480 | 4 | explicit |
| ML-DSA-44 | minimal | inline | 4070 | 4072 | 4074 | 2 | empty |
| ML-DSA-44 | minimal | registered | 2758 | 2760 | 2762 | 2 | empty |
| ML-DSA-44 | operational | inline | 4136 | 4138 | 4148 | 4 | explicit |
| ML-DSA-44 | operational | registered | 2824 | 2826 | 2836 | 4 | explicit |
| ML-DSA-65 | minimal | inline | 5599 | 5601 | 5603 | 2 | empty |
| ML-DSA-65 | minimal | registered | 3647 | 3649 | 3651 | 2 | empty |
| ML-DSA-65 | operational | inline | 5665 | 5667 | 5677 | 4 | explicit |
| ML-DSA-65 | operational | registered | 3713 | 3715 | 3725 | 4 | explicit |
| SLH-DSA-SHA2-128s | minimal | inline | 8226 | 8228 | 8230 | 2 | empty |
| SLH-DSA-SHA2-128s | minimal | registered | 8194 | 8196 | 8198 | 2 | empty |
| SLH-DSA-SHA2-128s | operational | inline | 8292 | 8294 | 8304 | 4 | explicit |
| SLH-DSA-SHA2-128s | operational | registered | 8260 | 8262 | 8272 | 4 | explicit |
<!-- END GENERATED: transport_direct -->

Legacy/v0 is limited to 1,232 bytes; v1 to 4,096. The `minimal` template is the
fee payer + program (2 accounts) with an empty v1 config; the `operational`
template adds a read-only key-registry account and a writable
authorization-state account (4 accounts) and sets `compute_unit_limit` and
`loaded_accounts_data_size_limit` explicitly. Every post-quantum scheme exceeds
the legacy/v0 budget even when registered; registration removes exactly the
public-key bytes. Evidence type: `serialized`.

### 5.4 Transport, staged upload (modeled)

<!-- BEGIN GENERATED: transport_staged -->
_Source: `results/transport-staged.json` — a **model** (each transaction serialized, lifecycle not executed). Includes init/write/seal/authorize transaction bytes and session metadata + signature storage; excludes key registration, account rent, cleanup, and compute._

| Scheme | Format | signature (B) | storage (B) | chunk (B) | chunks | transactions | total transport (B) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Ed25519 | legacy | 64 | 141 | 957 | 1 | 4 | 1396 |
| Ed25519 | v0 | 64 | 141 | 955 | 1 | 4 | 1404 |
| Ed25519 | v1 | 64 | 141 | 3809 | 1 | 4 | 1447 |
| ML-DSA-44 | legacy | 2420 | 2497 | 957 | 3 | 6 | 4303 |
| ML-DSA-44 | v0 | 2420 | 2497 | 955 | 3 | 6 | 4315 |
| ML-DSA-44 | v1 | 2420 | 2497 | 3809 | 1 | 4 | 3803 |
| ML-DSA-65 | legacy | 3309 | 3386 | 957 | 4 | 7 | 5467 |
| ML-DSA-65 | v0 | 3309 | 3386 | 955 | 4 | 7 | 5481 |
| ML-DSA-65 | v1 | 3309 | 3386 | 3809 | 1 | 4 | 4692 |
| SLH-DSA-SHA2-128s | legacy | 7856 | 7933 | 957 | 9 | 12 | 11389 |
| SLH-DSA-SHA2-128s | v0 | 7856 | 7933 | 955 | 9 | 12 | 11413 |
| SLH-DSA-SHA2-128s | v1 | 7856 | 7933 | 3809 | 3 | 6 | 9813 |
<!-- END GENERATED: transport_staged -->

Staging splits the signature across `Init` + `Write`… + `Seal` + `Authorize`
transactions. Each transaction is serialized with its full framing, so the
chunk capacity is derived from a complete transaction rather than from raw
signature bytes; the lifecycle is **not** executed, and account rent, key
registration, and cleanup are excluded. Staging makes each transaction fit but
increases total transported bytes and adds on-chain state; it does not reduce
verification cost.

### 5.5 Verifier feasibility (blocked before execution)

`fips204` 0.4.6 ML-DSA-44 verification compiles for sBPF but is rejected by the
4,096-byte stack-frame check. `verify_internal` has a ~62 KB frame,
`PublicKey::try_from_bytes` ~24 KB, `ntt::ntt` ~8.3 KB, and the program
`entrypoint` ~10.9 KB. Full log: `experiments/sbpf-verifier/build.log`. No
compute measurements exist because the program never executed.

## 6. Security argument (conditional application argument)

### 6.1 Two unforgeability notions

- **EUF-CMA** (existential unforgeability under chosen-message attack): with the
  public key and a signing oracle, an adversary cannot produce a valid `(m, σ)`
  on a message `m` it never queried.
- **SUF-CMA** (strong unforgeability): an adversary cannot produce *any* new
  valid `(m, σ)` pair — including a *different* signature `σ' ≠ σ` on a message
  `m` the oracle already signed. SUF-CMA implies EUF-CMA.

FIPS 204 §3.1 states that ML-DSA "is designed to be strongly existentially
unforgeable under chosen message attack (SUF-CMA) … the adversary cannot create
any additional valid signatures based on the signer's public key, including on
messages for which the signer has already provided a signature." (An earlier
draft of this section described SUF-CMA as ordinary EUF-CMA; that was wrong and
is corrected here.)

### 6.2 Which property the authorization argument needs

The prototype assumes a correctly populated trusted key registry, correct
environment identifiers, trustworthy key generation, and correct library
behavior. Under those assumptions the anti-forgery step is **EUF-CMA-scale**:
accepting a *new* canonical intent that the registered signer never signed
would require a signature that verifies under a registered public key on
unsigned bytes — a forgery on a message never queried. EUF-CMA, not SUF-CMA, is
sufficient for that step.

Strong unforgeability is *not* what protects replays here. The intent encoding
already carries a unique, monotonic nonce, and the authorizer consumes it
atomically, so a re-submitted intent — or a different valid signature on the
same intent — is rejected by **state**, not by the signature scheme. A design
that deduplicated requests by signature bytes, or that had no replay state,
would additionally depend on SUF-CMA. ML-DSA provides SUF-CMA; the classical
Ed25519 path does not (non-strict verification accepts small-order malleable
signatures), which is why authorization uses `verify_strict`.

### 6.3 What replay prevention depends on

Replay prevention rests on the nonce/ledger state, which here is **in-memory
only**: a process restart resets it, so a previously accepted request could be
replayed after restart. Persistent, durable replay state is future work. The
expiry field bounds how long a signed intent is usable but does not, by itself,
provide replay protection.

### 6.4 Assumptions and what the tests establish

The argument is conditional on: (a) a trusted, correctly populated registry;
(b) unambiguous, exact-length canonical encoding with the scheme and key id
inside the signed bytes; (c) correct environment binding (network/program); and
(d) correct atomic nonce handling. Weak Ed25519 keys are rejected at
registration and authorization verifies strictly, so a low-order key does not
enable secretless authorization.

The project's tests are **behavioral evidence of the application policy**, not a
proof of ML-DSA or Ed25519 and not an audit of any deployment. They show that
tampering, replay, expiry, wrong-environment, and malformed-input cases are
rejected while state is left unchanged on rejection — nothing more.

## 7. Limitations

- Host timings are one implementation on one machine; not constant-time
  evidence, not a ranking, and not convertible to compute units.
- SLH-DSA uses reduced sample counts; sub-resolution timings are reported as ~0.
- Staged upload is a model (component transactions serialized, lifecycle not
  executed); registration, account rent, cleanup, and compute are excluded.
- The v1 `wincode` encoding is exercised only through the SDK's own encoder and
  decoder; no validator accepted or executed these transactions.
- The sBPF blocker is specific to `fips204` 0.4.6 under the stated toolchain; a
  heap-allocating verifier might differ. No universal infeasibility is claimed.
- ML-DSA-65 and SLH-DSA lack independent conformance checks (only ML-DSA-44 has
  the cross-implementation interop test).
- The threshold-paper claim is cited from its abstract; a specific numbered
  theorem from its security proof was not traced (the full PDF was not
  retrievable through the available tooling). Recorded as unresolved.

## 8. Future work

Persistent replay state; additional implementations/hardware; a stack-efficient
or heap-allocating ML-DSA verifier for sBPF; independent conformance for
ML-DSA-65/SLH-DSA; threshold ML-DSA (per ePrint 2026/013); and proof-based
verification aggregation, whose proof system would carry its own assumptions.

## 9. Attribution

All cryptographic primitives are third-party crates (`ed25519-dalek`,
`fips204`, `fips205`); the independent ML-DSA check uses RustCrypto `ml-dsa`.
This project's contribution is the experimental design, the authorization
integration and adversarial tests, the transport analysis, and this analysis.
Plots in `results/plots/` are regenerated from the committed samples by
`scripts/plot_results.py`; the numerical tables are generated by
`scripts/report_tables.py` into `results/tables/`.
