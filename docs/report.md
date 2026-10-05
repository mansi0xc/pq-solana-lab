# PQ-Solana Lab — Research Report

**Question.** Under a specified Solana transaction format and execution
environment, what limits the practicality of standardized post-quantum
signatures for application authorization: payload size, verification
resources, or integration constraints?

## 1. Finding (stated first)

The answer is **both, at different layers**, and a third factor does not remove
either:

1. **Payload size limits transport.** A canonical withdrawal intent (166 bytes)
   plus an ML-DSA-44 signature (2,420 bytes) already exceeds the 1,232-byte
   legacy/v0 transaction packet budget even with the public key registered
   out-of-band (measured: 2,758 bytes). ML-DSA-65 (3,647 bytes) and
   SLH-DSA-SHA2-128s (8,194 bytes) are worse. The 4,096-byte v1 format lets
   ML-DSA-44 fit (4,089 bytes inline) and ML-DSA-65 fit when registered, but
   SLH-DSA still does not.
2. **Verification resources limit execution.** The `fips204` 0.4.6 ML-DSA-44
   verifier compiles for sBPF but is rejected by the 4,096-byte stack-frame
   check (`verify_internal` alone has a ~62 KB frame). No execution occurred,
   so no compute-unit numbers exist.
3. **Integration choices shift but do not eliminate cost.** Registering the key
   saves exactly the public-key bytes per transaction; staging the signature
   makes each transaction fit but raises total transport bytes and adds on-chain
   state. Neither reduces verification cost.

## 2. Related work

- **FIPS 204 (ML-DSA)** and **FIPS 205 (SLH-DSA)** define the standardized
  post-quantum signature schemes evaluated here. Parameter sizes are taken from
  the standards and cross-checked against the libraries.
- **RFC 8032 (Ed25519)** is the classical baseline; its §7.1 test vectors are
  used as known-answer evidence.
- **Libraries** (reused, not reimplemented): `fips204` 0.4.6 and `fips205` 0.4.1
  (IntegrityChain, pure Rust), `ed25519-dalek` 3.0.0, and — for independent
  ML-DSA conformance — the RustCrypto `ml-dsa` 0.1.1 crate.
- **Efficient Threshold ML-DSA** (Celi, del Pino, Espitau, Niot, Prest;
  ePrint 2026/013, USENIX Security '26) presents the first threshold scheme
  compatible with standardized ML-DSA, using short secret sharing and optimized
  rejection sampling (≈1 MB/party communication up to 6 parties). This is
  referenced only as future work; this project does not implement it.

## 3. Design

A byte-oriented signature interface dispatches four schemes (Ed25519, ML-DSA-44,
ML-DSA-65, SLH-DSA-SHA2-128s) behind key generation, signing, verification,
strict verification, key validation, and prepared-key operations. A canonical
166-byte withdrawal intent binds domain, encoding version, scheme, key id,
network, program, asset, recipient, amount, nonce, and expiry. A local
authorizer validates registration (rejecting weak Ed25519 keys), verifies
strictly, enforces environment binding and expiry, and consumes a nonce
atomically on success only.

## 4. Methodology

- **Benchmarks** (`cargo run --release -- benchmark --config configs/full.json`):
  prepared-key and byte-adapter paths are measured separately; valid fixtures
  are produced and checked once outside the timed loop; warm-up (20) precedes
  timed sampling (up to 1,000 per case, bounded by 60 s/case). Median and
  quartiles are reported; p95 only when ≥200 samples. Host timings are wall-clock
  observations on an Apple M4 and are never converted into compute units.
- **Transport** (`cargo run --release -- transport`): sizes are actual bincode
  serializations of `solana-sdk` 5.0.0 transactions; staged upload is a model
  whose chunk size is derived from serialized templates.
- **Verifier**: a verification-only ML-DSA-44 program is built with
  `cargo build-sbf` (platform-tools v1.52, rustc 1.89.0).

## 5. Results

### 5.1 Host primitives (Apple M4, release, median)

| Scheme | keygen | sign (166 B) | verify (166 B) | pk | sig |
| --- | --- | --- | --- | --- | --- |
| ed25519 | 10.9 µs | 8.3 µs | 18.6 µs | 32 | 64 |
| ml-dsa-44 | 76.6 µs | 95.1 µs | 40.3 µs | 1,312 | 2,420 |
| ml-dsa-65 | 130.8 µs | 141.7 µs | 65.8 µs | 1,952 | 3,309 |
| slh-dsa-sha2-128s | 66.6 ms | 508.8 ms (116) | 561 µs | 32 | 7,856 |

Parentheses mark a reduced sample count (the 60 s/case budget). The `byte`
adapter path (not shown) includes per-call key reconstruction and is therefore
slower; the `invalid_len` verify class is sub-resolution (~0 ns) in prepared
mode because it returns before any cryptographic work.

### 5.2 Transport (measured for legacy/v0/v1; staged is modeled)

| Scheme | inline legacy | registered legacy | inline v1 | registered v1 |
| --- | --- | --- | --- | --- |
| ed25519 | 434 | 402 | 419 | 421 |
| ml-dsa-44 | 4,070 | 2,758 | 4,089 | 2,777 |
| ml-dsa-65 | 5,599 | 3,647 | 5,618 | 3,666 |
| slh-dsa-sha2-128s | 8,226 | 8,194 | 8,245 | 8,213 |

Legacy/v0 limit 1,232; v1 limit 4,096. Staged upload (modeled) derives chunk
sizes ~1,027 (legacy/v0) and ~3,872 (v1): SLH-DSA needs 8 legacy / 3 v1 chunks;
ML-DSA-44 needs 3 legacy / 1 v1 chunk. Staging raises total transport bytes
(e.g. SLH-DSA ~10,072 bytes legacy) and adds on-chain storage equal to the
signature.

### 5.3 Verifier feasibility (blocked before execution)

`fips204` 0.4.6 ML-DSA-44 verification compiles for sBPF but is rejected by the
4,096-byte stack-frame check. `verify_internal` has a ~62 KB frame,
`PublicKey::try_from_bytes` ~24 KB, `ntt::ntt` ~8.3 KB, and the program
`entrypoint` ~10.9 KB. Full log: `experiments/sbpf-verifier/build.log`. No
compute measurements exist because the program never executed.

## 6. Security argument (conditional application argument)

Assume (a) a correctly populated trusted key registry, (b) correct environment
identifiers, and (c) an unforgeable signature scheme. The canonical encoding is
fixed-width and exact-length, and it includes the scheme and key id inside the
signed bytes, so a signature cannot be reinterpreted across schemes or keys.
Under (a)–(c), accepting a *new* unauthorized canonical intent would require a
signature that verifies under a registered public key on bytes the signer never
signed — a forgery. Replay of an already-signed intent is handled separately by
monotonic nonce state (in-memory only, in this prototype). The standard
unforgeability game (from FIPS 204) is the SUF-CMA notion: the adversary holds
the public key and a signing oracle, and must output a valid signature on a
message never queried. This project's tests are behavioral evidence of the
*application* policy, not a proof of ML-DSA/Ed25519.

Weak-key handling is explicit: Ed25519 registration rejects low-order keys, and
authorization uses strict verification, so a low-order key does not enable
secretless authorization.

## 7. Limitations

- Host timings are one implementation on one machine; not constant-time
  evidence, not a ranking, and not convertible to compute units.
- SLH-DSA uses reduced sample counts; sub-resolution timings are reported as ~0.
- Staged upload is a model (serializable, not executed); registration cost and
  account cleanup are not modeled.
- The sBPF blocker is specific to `fips204` 0.4.6 under the stated toolchain; a
  heap-allocating verifier might differ. No universal infeasibility is claimed.
- ML-DSA-65 and SLH-DSA lack independent conformance checks (only ML-DSA-44 has
  the cross-implementation interop test).
- The threshold-paper claim is cited from its abstract; a specific numbered
  theorem from its security proof was not traced (the full PDF was not
  retrievable through the available tooling). This is recorded as an unresolved
  item, not filled in with invented detail.

## 8. Future work

Persistent replay state; additional implementations/hardware; a stack-efficient
or heap-allocating ML-DSA verifier for sBPF; independent conformance for
ML-DSA-65/SLH-DSA; threshold ML-DSA (per ePrint 2026/013); and proof-based
verification aggregation (whose proof system would carry its own assumptions).

## 9. Attribution

All cryptographic primitives are third-party crates (`ed25519-dalek`,
`fips204`, `fips205`); the independent ML-DSA check uses RustCrypto `ml-dsa`.
This project's contribution is the experimental design, the authorization
integration and adversarial tests, the transport analysis, and this analysis.
Plots in `results/plots/` are regenerated from raw data by
`scripts/plot_results.py`; raw samples are in `results/raw/`.
