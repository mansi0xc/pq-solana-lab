# PQ-Solana Lab

An applied research prototype measuring whether standardized post-quantum
signatures are practical for **application-level authorization on Solana**,
against an Ed25519 baseline. Reuses published cryptographic libraries; the
contribution is the experimental design, integration, adversarial tests, and
analysis.

## Research question

> Under a specified Solana transaction format and execution environment, what
> limits the practicality of standardized post-quantum signatures for
> application authorization: payload size, verification resources, or
> integration constraints?

## The finding, with scope

**Both, at different layers.** A 2,420-byte ML-DSA-44 signature plus the
166-byte intent already exceeds the 1,232-byte legacy/v0 transaction budget
*even with the key registered* (measured 2,758 bytes); SLH-DSA-SHA2-128s is
worse (8,194 bytes). Separately, the `fips204` ML-DSA-44 verifier compiles for
Solana's sBPF but is rejected by its 4,096-byte stack-frame check
(`verify_internal` ~62 KB) — so verification resources, not just transport,
limit it. Scope: one implementation (`fips204` 0.4.6) on one machine; host
timings are never converted into compute units; no universal infeasibility is
claimed.

## Reproduce

```sh
rustup toolchain install 1.91.1   # pinned via rust-toolchain.toml
cargo test --release --locked                     # 57 tests: correctness, adversarial, KAT, interop, transport
cargo run --release --locked -- demo               # sign/verify + authorization accept/reject
cargo run --release --locked -- transport          # actual legacy/v0/v1 serialization + staged model
cargo run --release --locked -- benchmark --config configs/quick.json   # ~2.5 min pilot
cargo run --release --locked -- benchmark --config configs/full.json    # ~8 min full profile (SLH-DSA dominates)
python3 scripts/plot_results.py results/raw/full.csv results/transport.json results/plots
```

![Host verification latency](results/plots/verification_latency.png)

## Demo

`cargo run --release -- demo` prints, with genuine output: signature adapters
for four schemes (sizes + accept/reject), then a withdrawal authorization that
accepts one request and rejects replay, a tampered amount, an expired request,
and a correctly-signed wrong-network request.

## Report, design, threat model

- `docs/report.md` — the research report (finding, methodology, results,
  security argument, limitations).
- `docs/encoding.md`, `docs/threat-model.md`, `docs/methodology.md`,
  `docs/transport.md`, `docs/solana-feasibility.md`, `docs/progress.md`.
- `idea.md` / `plan.md` — project definition and milestone plan.

## Design summary

A byte-oriented signature interface (`src/crypto.rs`) dispatches Ed25519,
ML-DSA-44, ML-DSA-65, and SLH-DSA-SHA2-128s behind keygen/sign/verify/strict
verify/key validation/prepared keys. A canonical 166-byte intent
(`src/intent.rs`) and a local authorizer (`src/authorization.rs`) bind requests
to registered keys, environment, expiry, and monotonic nonces; weak Ed25519
keys are rejected and authorization verifies strictly. `src/bench.rs` measures
primitives with documented boundaries; `src/transport.rs` serializes real
transactions; `experiments/sbpf-verifier/` is the bounded on-chain experiment.

## Limitations

- Host timings are one implementation on one machine; not constant-time
  evidence, not a ranking, and not convertible to compute units.
- Staged upload is a model (serializable, not executed); registration cost and
  account cleanup are not modeled.
- The sBPF blocker is `fips204` 0.4.6-specific; a heap-allocating verifier may
  differ.
- Replay state is in-memory only; production persistence is future work.

## Attribution

| Primitive | Crate (pinned) | Standard | Independent evidence here |
| --- | --- | --- | --- |
| Ed25519 | `ed25519-dalek` 3.0.0 | RFC 8032 | §7.1 known-answer tests |
| ML-DSA-44/65 | `fips204` 0.4.6 | FIPS 204 | ML-DSA-44 interop vs RustCrypto `ml-dsa` 0.1.1 |
| SLH-DSA-SHA2-128s | `fips205` 0.4.1 | FIPS 205 | self round-trip |
| transactions | `solana-sdk` 5.0.0 | — | actual serialization |

No new cryptography is implemented here. This does not make Solana, a wallet,
or native transaction signing quantum secure, and provides no production
custody.