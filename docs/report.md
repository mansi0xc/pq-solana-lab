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
   verifier compiles for sBPF (with stack-frame diagnostics: `verify_internal`
   ~62 KB), **loads and deploys successfully** on a local validator, and then
   **aborts at runtime with an access violation in a stack frame** after 418
   compute units — before producing any verdict. A second, independent
   implementation (RustCrypto `ml-dsa` 0.1.1) behaves the same way under the
   same configuration. A control program executes normally (539 CUs), so the
   failure is specific to the verifiers, not the harness. This is one toolchain
   and one runtime; no completed-verification compute figure exists.
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
  ML-DSA conformance and for the controlled verifier comparison — the RustCrypto
  `ml-dsa` 0.1.1 crate.
- **Solana execution.** `solana-cargo-build-sbf` 3.1.10 / platform-tools v1.52
  compile to sBPF; `solana-sbpf` 0.13.1 is the SBF VM and loader verifier Agave
  3.1.x pins; `solana-test-validator` 3.1.10 provides the local runtime used for
  the deploy/execute evidence.
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
_Source: run `full-r1` (`configs/full.json`), mode `prepared`, input class `valid`, 166-byte messages; raw `results/raw/full-r1.csv`. Medians recomputed from raw samples._

| Scheme | keygen | sign (166 B) | verify (166 B) | pubkey (B) | signature (B) |
| --- | --- | --- | --- | --- | --- |
| Ed25519 | 8.2 µs | 8.9 µs | 18.5 µs | 32 | 64 |
| ML-DSA-44 | 76.3 µs | 127.3 µs | 40.1 µs | 1312 | 2420 |
| ML-DSA-65 | 131.3 µs | 227.1 µs | 65.9 µs | 1952 | 3309 |
| SLH-DSA-SHA2-128s | 65.9 ms (n=910) | 504.1 ms (n=119) | 490.8 µs | 32 | 7856 |
<!-- END GENERATED: host_primitives -->

### 5.2 Measurement boundaries

The four boundaries requested by the review are measured separately: prepared-key
primitives, the serialized-byte adapter, the strict Ed25519 verification used by
authorization, and complete authorization (registry lookup, decoding, policy,
strict verification, and the atomic nonce/ledger update). The authorization
`accept` row uses valid state progression (each request consumes the next
nonce); the `replay reject` row is a rejection workload, not a rejected success.

<!-- BEGIN GENERATED: boundaries -->
_Source: run `full-r1` (`configs/full.json`), 166-byte messages; medians recomputed from `results/raw/full-r1.csv`. `authorize` includes registry lookup, intent decoding, environment/expiry policy, strict verification, and the atomic nonce/ledger update; the reject row is a replay workload._

| Scheme | verify prepared | verify byte | strict verify prepared | strict verify byte | authorize (accept) | authorize (replay reject) |
| --- | --- | --- | --- | --- | --- | --- |
| Ed25519 | 18.5 µs | 21.2 µs | 21.2 µs | 24.0 µs | 24.1 µs | 23.4 µs |
| ML-DSA-44 | 40.1 µs | 49.0 µs | 40.2 µs | 49.1 µs | 49.3 µs | 49.2 µs |
| ML-DSA-65 | 65.9 µs | 79.5 µs | 66.0 µs | 79.3 µs | 80.0 µs | 79.6 µs |
| SLH-DSA-SHA2-128s | 490.8 µs | 466.7 µs | 511.1 µs | 507.7 µs | 501.5 µs | 490.8 µs |
<!-- END GENERATED: boundaries -->

### 5.3 Host quartiles (prepared, valid, 166-byte messages)

<!-- BEGIN GENERATED: host_quartiles -->
_Source: run `full-r1` (`configs/full.json`), mode `prepared`, input class `valid`, 166-byte messages; raw `results/raw/full-r1.csv`. Quartiles recomputed from raw samples (linear interpolation); p95 omitted below 200 samples._

| Scheme | operation | n | median | Q1 | Q3 | p95 |
| --- | --- | --- | --- | --- | --- | --- |
| Ed25519 | keygen | 1000 | 8.2 µs | 8.2 µs | 8.3 µs | 9.3 µs |
| Ed25519 | sign | 1000 | 8.9 µs | 8.9 µs | 8.9 µs | 9.0 µs |
| Ed25519 | verify | 1000 | 18.5 µs | 18.5 µs | 18.6 µs | 18.7 µs |
| ML-DSA-44 | keygen | 1000 | 76.3 µs | 76.0 µs | 76.6 µs | 78.8 µs |
| ML-DSA-44 | sign | 1000 | 127.3 µs | 93.8 µs | 223.0 µs | 412.9 µs |
| ML-DSA-44 | verify | 1000 | 40.1 µs | 40.0 µs | 40.2 µs | 40.9 µs |
| ML-DSA-65 | keygen | 1000 | 131.3 µs | 130.9 µs | 131.9 µs | 310.1 µs |
| ML-DSA-65 | sign | 1000 | 227.1 µs | 140.3 µs | 357.9 µs | 705.7 µs |
| ML-DSA-65 | verify | 1000 | 65.9 µs | 65.7 µs | 66.0 µs | 66.6 µs |
| SLH-DSA-SHA2-128s | keygen | 910 | 65.9 ms | 65.6 ms | 66.1 ms | 66.5 ms |
| SLH-DSA-SHA2-128s | sign | 119 | 504.1 ms | 503.7 ms | 504.4 ms | — |
| SLH-DSA-SHA2-128s | verify | 1000 | 490.8 µs | 490.3 µs | 493.0 µs | 498.2 µs |
<!-- END GENERATED: host_quartiles -->

The signing distribution for ML-DSA-44/65 is wide: the first quartile sits well
below the median because ML-DSA signing is rejection-sampled, so each signature
takes a variable number of loop iterations. Reporting the first quartile as if
it were the median understates the typical cost; §5.3's generated table and its
consistency check prevent that regression.

### 5.4 Transport, direct inclusion (serialized)

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

### 5.5 Transport, staged upload (modeled)

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

### 5.6 Between-run variability

Three independent full runs were recorded (`full-r1`, `full-r2`, `full-r3`) with
unique run identifiers and per-run provenance. The table shows each run's median
and the spread `(max − min) / min`; within-run spread is the interquartile range
in §5.3.

<!-- BEGIN GENERATED: between_runs -->
_Source: independent runs `full-r1`, `full-r2`, `full-r3` (`configs/full.json`), prepared/valid, 166-byte messages. Medians read from each run's summary; spread = (max − min) / min._

| Scheme | operation | full-r1 | full-r2 | full-r3 | spread |
| --- | --- | --- | --- | --- | --- |
| Ed25519 | keygen | 8.2 µs | 9.0 µs | 9.0 µs | 10.1% |
| Ed25519 | sign 166 B | 8.9 µs | 8.9 µs | 8.9 µs | 0.0% |
| Ed25519 | verify 166 B | 18.5 µs | 18.6 µs | 18.5 µs | 0.7% |
| Ed25519 | strict verify | 21.2 µs | 21.2 µs | 21.2 µs | 0.4% |
| Ed25519 | authorize | 24.1 µs | 24.1 µs | 24.2 µs | 0.2% |
| ML-DSA-44 | keygen | 76.3 µs | 76.4 µs | 76.4 µs | 0.1% |
| ML-DSA-44 | sign 166 B | 127.3 µs | 126.1 µs | 126.0 µs | 1.0% |
| ML-DSA-44 | verify 166 B | 40.1 µs | 40.2 µs | 40.3 µs | 0.4% |
| ML-DSA-44 | strict verify | 40.2 µs | 40.1 µs | 40.2 µs | 0.3% |
| ML-DSA-44 | authorize | 49.3 µs | 49.4 µs | 49.4 µs | 0.1% |
| ML-DSA-65 | keygen | 131.3 µs | 131.8 µs | 131.4 µs | 0.3% |
| ML-DSA-65 | sign 166 B | 227.1 µs | 227.4 µs | 227.4 µs | 0.1% |
| ML-DSA-65 | verify 166 B | 65.9 µs | 65.9 µs | 66.1 µs | 0.3% |
| ML-DSA-65 | strict verify | 66.0 µs | 65.9 µs | 66.0 µs | 0.1% |
| ML-DSA-65 | authorize | 80.0 µs | 80.1 µs | 80.0 µs | 0.2% |
| SLH-DSA-SHA2-128s | keygen | 65.9 ms | 66.2 ms | 66.4 ms | 0.8% |
| SLH-DSA-SHA2-128s | sign 166 B | 504.1 ms | 504.9 ms | 505.8 ms | 0.3% |
| SLH-DSA-SHA2-128s | verify 166 B | 490.8 µs | 514.9 µs | 502.0 µs | 4.9% |
| SLH-DSA-SHA2-128s | strict verify | 511.1 µs | 463.3 µs | 524.2 µs | 13.2% |
| SLH-DSA-SHA2-128s | authorize | 501.5 µs | 503.8 µs | 505.2 µs | 0.7% |
<!-- END GENERATED: between_runs -->

### 5.7 Verifier feasibility (loads and deploys; traps at execution)

`cargo-build-sbf` exits 0 for the `fips204` ML-DSA-44 verifier while emitting
stack-frame diagnostics (`verify_internal` ~62 KB, `PublicKey::try_from_bytes`
~24 KB, `ntt::ntt` ~8.3 KB; `experiments/sbpf-verifier/build.log`). Those are
**compiler** diagnostics, not loader rejection: the Agave SBF VM loads the ELF
and passes `RequisiteVerifier`, the program deploys to a local validator
(exit 0), and a control program executes normally (539 CU). On invocation with a
genuine fixture, the verifier **aborts at runtime** after 418 CU with
`Access violation in stack frame 3` — before any verdict, so valid, altered, and
invalid inputs fail identically. The controlled comparison (RustCrypto
`ml-dsa` 0.1.1, same parameter set/mode/fixture/toolchain/runtime) also loads,
verifies, deploys, and then aborts (access violation in the program section,
323 CU). No completed-verification compute figure exists. Evidence:
`experiments/outcome/`; analysis: `docs/solana-feasibility.md`,
`docs/technical-note.md`.

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
- The sBPF result is a runtime access violation before any verdict, for two
  library builds under one toolchain and one local validator. A heap-allocating
  verifier might differ. No universal infeasibility, and no completed-verification
  compute figure, is claimed.
- The local-validator harness supplies the oversized fixture through account
  data because the RPC enforces the 1,232-byte packet limit; v1 transactions
  were not accepted by this validator's RPC, so no v1 transaction was executed
  on chain.
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
