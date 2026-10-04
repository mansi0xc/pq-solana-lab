# PQ-Solana: Seven-Day Milestone Plan

**Project:** A Rust research lab for post-quantum transaction authorization on Solana.  
**Audience:** A developer with Rust and Solana experience and an introductory cryptography course.  
**Budget:** Approximately 40 focused hours across seven days. Reading, debugging, and documentation are included.  
**Prepared:** 4 October 2026. Dependency and network facts must be recorded again when implementation starts.  
**Status:** Implementation plan. No implementation, benchmark result, deployment, or security proof has been completed by this document.

The outcome is a runnable authorization prototype, reproducible signature benchmarks, a Solana transport analysis, a bounded verifier experiment, and a short research report. The central question is:

> Under a specified Solana transaction format and execution environment, what prevents standardized post-quantum signatures from being practical for application authorization: bytes, verification cost, or integration constraints?

Your original contribution will be the experimental design, authorization integration, negative tests, transport comparison, and analysis. The cryptographic primitives come from existing libraries, which must be credited. Recruiters should be able to distinguish those contributions immediately.

## 1. Scope and priorities

| Priority | Deliverable | Required evidence |
| --- | --- | --- |
| Core | Ed25519 and ML-DSA-44 adapters | Valid signatures accepted; modified messages and wrong keys rejected |
| Core | Local withdrawal-authorization prototype | Canonical encoding, registered keys, environment binding, expiry, and nonce checks |
| Core | Reproducible host benchmarks | Raw samples, actual sample counts, environment metadata, and documented measurement boundaries |
| Core | Solana transaction analysis | Actual legacy/v0 serialization; v1 measured or explicitly modeled; direct and staged payload cases |
| Core | Report and demonstration | Findings linked to evidence, limitations, and clear ownership of work |
| Planned extension | ML-DSA-65 and one SLH-DSA configuration | Same adapters and benchmark methodology |
| Bounded experiment | ML-DSA-44 verifier under sBPF | Executed verification with compute measurements, or a reproducible implementation blocker |
| After the week | Threshold signing, proof aggregation, persistent production state | Separate research questions and implementation plans |

Finish the core before adding a dashboard, extra signature schemes, or token transfers. Threshold signing and proof aggregation are future work; they are not deliverables for this week. A collection of independent signatures is not an MPC threshold-signature implementation.

The prototype provides application-level authorization. Native Solana transactions, fee payment, and any classical administrative authority retain their existing security assumptions. Do not describe the result as making Solana or an entire wallet quantum secure.

## 2. Schedule and dependencies

| Milestone | Target | Budget | Depends on | Completion gate |
| --- | --- | --- | --- | --- |
| M1: Establish working primitives | Day 1 | 5 hours | None | Ed25519 and ML-DSA-44 work through a shared interface |
| M2: Build secure authorization semantics | Day 2 | 6 hours | M1 | All defined authorization and rejection scenarios pass |
| M3: Establish the benchmark protocol | Day 3 | 6 hours | M1 | Pilot data is valid; methodology and output schema are frozen |
| M4: Analyze Solana transport | Day 4 | 6 hours | M1, M2 | Direct/staged sizes and assumptions are reproducible |
| M5: Test verifier feasibility | Day 5 | 5 hours | M1, M4 | Success or exact blocker recorded within the time limit |
| M6: Produce results and research analysis | Day 6 | 6 hours | M2–M5 | Plots and report claims trace back to raw evidence |
| M7: Prepare the reviewable release | Day 7 | 6 hours | M6 | Fresh-checkout instructions and two-minute demo work |

M3 does not depend on the application implementation, but the actual withdrawal encoding should become one of its workloads. Begin a daily 20–30 minute reading log on Day 1, included within the milestone budgets.

If you have only 20–25 hours, retain Ed25519 and ML-DSA-44, the authorization tests, actual legacy/v0 sizing, and the report. Reduce extra algorithms and benchmark cases. Reserve at least four hours for the report and reproduction instructions.

## 3. Suggested implementation structure

Use one Cargo package at first. A multi-crate workspace is optional if the Solana verifier experiment requires a separate target.

```text
pq-solana/
  Cargo.toml
  Cargo.lock
  rust-toolchain.toml
  README.md
  src/
    lib.rs
    main.rs
    crypto/
      mod.rs
      ed25519.rs
      ml_dsa.rs
      slh_dsa.rs
    intent.rs
    authorization.rs
    bench.rs
    transport.rs
  tests/
    crypto_roundtrip.rs
    authorization.rs
    encoding.rs
    transport.rs
  examples/
    demo.rs
  experiments/
    sbpf-verifier/       # Only add when M5 starts
  configs/
    quick.json
    full.json
  results/
    raw/
    summaries/
    plots/
    environment.json
  docs/
    research-question.md
    encoding.md
    threat-model.md
    methodology.md
    solana-feasibility.md
    security-notes.md
    report.md
    ai-usage.md
```

These names are proposed repository paths, not files already created by this plan.

Use `ed25519-dalek` for the classical baseline and start with `fips204` for ML-DSA. Add `fips205` for SLH-DSA if time permits. The current documentation describes pure Rust implementations and standard signing/verification APIs. Pin versions after confirming they build with your selected toolchain. The documentation checked for this plan showed `fips204` 0.4.6, `fips205` 0.4.1, and `ed25519-dalek` 3.0.0. [ML-DSA library](https://docs.rs/fips204/latest/fips204/), [SLH-DSA library](https://docs.rs/fips205/latest/fips205/), [Ed25519 library](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/).

Use a small shared interface for key generation, signing, verification, public-key encoding, and signature encoding. Avoid implementing lattice arithmetic or modifying cryptographic internals. Keep host-specific command-line, file, and benchmark code outside the verifier code so the sBPF experiment does not inherit those dependencies.

The CLI commands below are acceptance targets to implement; they do not exist yet:

```text
cargo run --release -- demo
cargo run --release -- benchmark --config configs/quick.json
cargo run --release -- benchmark --config configs/full.json
cargo run --release -- transport
```

## M1 — Establish working primitives

**Purpose:** Remove dependency and API uncertainty before building the application.

### Tasks

1. Create the package and add the initial dependencies. Record the Rust version, operating system, CPU, dependency versions, and intended release profile.
2. Write a short research-question document with three hypotheses to test: signature bytes may prevent direct transport; transport solutions may leave verification constraints unresolved; host verification speed may differ substantially from runtime feasibility. These are hypotheses, not results.
3. Implement Ed25519 and ML-DSA-44 adapters using their public APIs. Generate a key, sign message bytes, serialize, deserialize, and verify.
4. Use OS-backed randomness through the API compatible with each library. Different libraries may require different randomness-trait versions; do not spend time forcing one RNG type across all adapters.
5. Add positive and negative tests: original message succeeds, altered message fails, unrelated key fails, truncated signature fails, and incorrect byte length returns an error without panicking.
6. Add a small demo showing both schemes and their public-key/signature sizes. Never print secret keys.
7. Read the public signing/verification descriptions and parameter tables in [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final). Record the signing mode and context used, and check the standard's current errata page.

### Deliverables

- Two working crypto adapters.
- Round-trip and rejection tests.
- A demo command with real output.
- Research-question and environment records.

### Completion gate

- Tests pass for both schemes after a release build.
- Repeated signing produces signatures that verify after serialization.
- You can explain the distinction between a signature, a public key, and an application request.

**Stop rule:** If the shared interface takes longer than one hour, use a simple enum with direct dispatch. If Solana dependencies cause trouble, postpone them until M4; the first milestone does not require them.

**Suggested checkpoint commit:** `Add Ed25519 and ML-DSA signing adapters and correctness tests`.

## M2 — Build authorization semantics and adversarial tests

**Purpose:** Demonstrate correct use of cryptography in an application with explicit state and trust assumptions.

### Tasks

1. Define a withdrawal intent with a fixed domain prefix, encoding version, scheme identifier, key identifier, network/genesis identifier, program identifier, asset identifier, recipient, integer amount in base units, monotonic nonce, and expiry slot.
2. Specify the byte encoding before writing the encoder. Use fixed-width identifiers and integers with an explicit byte order. Reject unsupported versions, unknown schemes, invalid lengths, and trailing bytes. Avoid floating-point amounts and ambiguous text concatenation.
3. Include the scheme and key identifier inside the signed intent. Use the same canonical intent bytes across scheme adapters. Record any additional FIPS context; do not silently switch between pure and prehash signing modes.
4. Create a local key registry mapping each key identifier to its permitted scheme, public key, and application identity. Select verification keys from this trusted registry, not from an arbitrary key supplied with a request.
5. Implement a single-process authorization function that checks request bounds, the registered key, signature validity, configured network/program/domain, expiry, and the expected nonce. Increment the nonce only after a successful authorization.
6. Inject a trusted current slot into the local verifier for deterministic tests. Define the expiry boundary explicitly, such as accepting while `current_slot <= expiry_slot`.
7. Keep successful authorization and nonce consumption atomic within the local process. Reject nonce overflow. Be explicit that an in-memory registry/ledger does not preserve replay protection after a restart.
8. Create a demonstration that accepts an original request and then rejects tampering, replay, and expiry.

### Required test scenarios

| Scenario | Expected result |
| --- | --- |
| Valid request under a registered key | Accept; consume exactly one nonce |
| Recipient, amount, asset, or expiry changed after signing | Reject |
| Valid signature from an unregistered key | Reject |
| Wrong network, program, or domain | Reject even if the attacker signed those bytes correctly |
| Previously accepted request submitted again | Reject |
| Nonce below or above the expected value | Reject under the chosen sequential-nonce policy |
| Expiry exactly at the boundary | Match the documented policy |
| Malformed encoding or truncated signature | Error without panic |
| Rejected request | Leave the expected nonce unchanged |
| Nonce increment would overflow | Reject |

Separate tests for signature binding from tests for application policy. For example, modifying a network identifier without resigning tests integrity; correctly signing a request for the wrong network tests policy enforcement.

### Deliverables and gate

- Canonical encoding specification and one golden encoded fixture.
- Authorization implementation and scenario tests.
- Threat-model document and a scripted demo.
- Every accepted request uses the registered scheme/key and consumes its nonce once; every rejected request leaves state unchanged.

**Stop rule:** Keep this local and use mock assets. A token-vault integration is not necessary to demonstrate the authorization properties.

**Suggested checkpoint commit:** `Bind withdrawal intents to keys, environment, expiry, and nonce state`.

## M3 — Establish a defensible benchmark protocol

**Purpose:** Produce evidence another developer can reproduce and interpret.

### Tasks

1. Add ML-DSA-65 and SLH-DSA-SHA2-128s through existing APIs. If a library integration exceeds 90 minutes, defer that extra scheme and retain the working baseline.
2. Benchmark key generation, signing, and verification separately. Prepare keys, messages, and valid signatures outside the verification timing loop. Exclude printing, disk writes, and transaction construction from primitive timings.
3. Add a separate end-to-end authorization measurement using M2. Report it separately from primitive verification.
4. Use three message cases: 32 bytes, the actual encoded withdrawal intent, and 1,024 bytes. State whether the same key is reused; do not describe warm single-key timings as rotating-key performance.
5. Start with a tiny pilot. Choose fixed quick/full profiles after seeing operation times, then freeze the profiles before the final run.
6. Use release builds, warm-up iterations, repeated runs, and actual sample counts. Give every scheme its category label. Report randomized/hedged/deterministic signing choices so results are not silently mixed.
7. Aim for at least 1,000 samples per fast operation per run across three runs. Give slow operations a per-case elapsed-time budget, for example 60 seconds, and record the smaller actual count. A soft deadline can finish the current operation; do not pretend every case ran the same number of samples.
8. Report median and interquartile range. Add p95 only where sample counts support it; use a documented project rule such as at least 200 samples per run. Avoid publishing a meaningful-looking p99 from a tiny dataset.
9. Benchmark structurally invalid inputs separately from correctly sized corrupted signatures. Early parsing rejection is a different workload from cryptographic rejection.

### Data schema

Raw samples should include run ID, scheme, security category, operation, message length, input class, sample index, and elapsed nanoseconds. Metadata should include exact crate versions, toolchain, build settings, CPU/OS, signing mode, context, warm-up count, and configured time budget.

Summary rows should include sample count, median, first/third quartiles, optional p95, public-key bytes, signature bytes, and status. Record skips and failures as explicit rows, not zero-time successes.

Timing values describe the selected implementation on the measured machine. They do not establish universal rankings, constant-time behavior, or Solana compute-unit consumption. CPU timings must never be converted into compute units using an invented factor.

### Validation and gate

- Every timed valid signature is checked for correctness outside the timer.
- There are no unreported failures or silently missing cases.
- Published sizes agree with the selected standard/library parameter set.
- If feasible, add an independent ML-DSA interoperability check with the same mode/context. A self-round-trip test alone is not independent conformance validation; disclose when that is the extent of validation.
- The quick profile finishes in a few minutes, and every raw row has enough metadata to explain its measurement.

**Suggested checkpoint commit:** `Add reproducible benchmark profiles and raw result exports`.

## M4 — Analyze actual Solana transport constraints

**Purpose:** Show how signature bytes interact with a real transaction envelope.

Solana's documentation currently distinguishes legacy/v0 at 1,232 bytes and v1 at 4,096 bytes. Native transaction signatures remain 64-byte Ed25519 signatures in those layouts. Use the exact format and SDK/runtime version in every conclusion. [Solana transaction format documentation](https://solana.com/docs/core/transactions/versioned-transactions).

### Tasks

1. Build a minimal legacy and v0 transaction containing one application instruction, a fee payer, required accounts, a fixed test blockhash, and a genuine native signature. Put the PQ authorization material in instruction data, not in the native signature array.
2. Serialize actual example transactions and report total bytes, instruction payload bytes, signature bytes, key material placement, and remaining headroom. Include ordinary transaction overhead.
3. Compare two key-placement cases: public key registered in an existing data account, or full public key transported with the request. An inline key must still match a trusted registered key or key commitment; its presence in a request does not establish trust. These are different application assumptions; label them.
4. Investigate v1 SDK support for at most 45 minutes. If supported, serialize it too. Otherwise use an explicit model from the documented layout and mark it as modeled. Never present a manual estimate as SDK serialization or a network-tested transaction.
5. Calculate staged transport: initialize storage, append signature chunks, then reference the completed account. Determine the largest safe chunk from the fully serialized transaction template and a stated margin. Recalculate for each transaction format.
6. Include initialization, upload, and final-reference transactions in total counts. State whether cleanup/key registration is included. Calculate storage bytes separately from transport bytes.
7. Document staged-data requirements: registered-key binding, session identifier, uploader authorization, maximum length, sequential offsets, no overwrite after sealing, and a completeness check. If you only model this lifecycle, say so; account upload does not establish signature validity.

### Output schema

Each transport row should contain scheme, transaction format, transport mode, key placement, signature bytes, total bytes, applicable limit, upload count, storage bytes, and evidence type: `serialized`, `modeled`, or `executed`. A size check alone must not be labeled a successful on-chain authorization.

### Deliverables and gate

- Actual legacy/v0 serialized examples and boundary checks.
- Direct-versus-staged comparison table.
- v1 serialization or a clearly labeled model.
- Written assumptions covering key registration, account lifecycle, and classical fee payment.
- Changing the algorithm or transport mode recalculates the result rather than editing a hard-coded table.

**Stop rule:** A staging program is optional. Prioritize actual transaction serialization and a correct transport model. Do not spend this day implementing a vault.

**Suggested checkpoint commit:** `Compare direct and staged PQ payload transport on Solana`.

## M5 — Run a four-hour verifier feasibility experiment

**Purpose:** Determine what the selected verifier implementation can do in a specified Solana runtime.

Use four hours for experimentation and one hour for documenting the result. Solana documents 4,096-byte stack frames and constrained heap sizes, so a host-compatible Rust implementation may still encounter runtime-specific limitations. `no_std` support alone does not establish sBPF compatibility. [Solana program limits](https://solana.com/docs/core/programs).

### Experiment sequence

1. Confirm a minimal program builds and executes in the selected test environment. Record the Solana/Agave toolchain, runtime, and feature configuration.
2. Prepare a genuine host-generated ML-DSA-44 fixture. Check it with the host verifier first.
3. Compile verification-only code, with RNG and host I/O outside the program. Use stored fixture/data-account bytes rather than trying to inline an oversized payload into a legacy/v0 transaction.
4. If compilation succeeds, execute a valid case, a tampered message, and a correctly sized corrupted signature. Confirm that the program's verdict comes from signature verification, not a stub.
5. If execution succeeds, record runtime compute use and requested limits. Where possible, run a baseline invocation without verification to separate harness overhead. Capture logs and environment metadata.
6. If blocked, save the smallest failing example, exact command, dependency version, error, and configuration. Distinguish build failure, stack/memory failure, and compute-budget exhaustion.

### Completion gate

Either valid/invalid signatures receive the right executed verdicts with measurements, or a specific reproducible blocker is documented. Both outcomes complete this bounded experiment.

Do not infer that all post-quantum schemes are infeasible from one library's failure. State, for example, that a selected version failed under a stated configuration. A local execution harness is evidence about that harness, not automatically evidence about mainnet deployment.

**Stop rule:** At four hours, freeze the experimental state. Do not rewrite the NTT, hash implementation, or signature algorithm during this week.

**Suggested checkpoint commit:** `Document ML-DSA verifier execution results or reproducible sBPF blocker`.

## M6 — Analyze results and write the research report

**Purpose:** Turn working code and collected data into an assessable research artifact.

### Tasks

1. Run the frozen full benchmark profile. Keep the machine conditions reasonably stable and record interruptions. Repeat a questionable case only for a stated reason; retain the original record.
2. Check raw counts, operation labels, units, verification verdicts, and missing cases. Summaries must derive from raw records.
3. Generate three plots: host verification latency; public-key/signature bytes; and transaction headroom or total staged transaction counts. Label units, scheme/category, format, and measurement type.
4. Write a four-to-six-page report with research question, related work, design, methodology, results, security argument, limitations, and future work. Start with the observed finding, not a promised speedup.
5. Write an elementary authorization argument under explicit assumptions. With a trusted registered key, unambiguous encoding, and an unforgeable signature scheme, accepting a new unauthorized canonical intent would imply a signature forgery. Replaying an already signed intent is handled separately by nonce state. Environment restrictions are enforced by verifier policy. This is a conditional application argument, not a proof of ML-DSA or an audited system.
6. Read the unforgeability game and relevant rejection-sampling discussion in [Efficient Threshold ML-DSA](https://eprint.iacr.org/2026/013). Explain the adversary's goal and one proof step you can trace to a specific definition or theorem. Separate the paper's claims from your interpretation. Write down unresolved questions rather than filling them with AI-generated certainty.
7. Record AI assistance: task, tool, what it helped produce, and how you checked it. Source-check explanations and understand every included code path.

### Report questions to answer

- Which bottleneck was observed for each tested configuration?
- How do registered versus transported public keys change the byte budget?
- What does staging solve, and which verification problems remain?
- Which authorization attacks do the tests cover?
- Where are conclusions measured, modeled, or still unknown?
- What changes would be required for persistence, threshold signing, or deployment?

### Gate

Every numeric claim points to a result row and configuration. Every literature claim has a primary-source citation. Tests are reported as evidence of behavior, not as proof of cryptographic security. If the verifier did not execute, there are no invented compute measurements.

**Suggested checkpoint commit:** `Add measured results, plots, security analysis, and research report`.

## M7 — Prepare the reviewable release

**Purpose:** Make the project easy to reproduce and discuss.

### Tasks

1. Write the README in reviewer order: question; one real finding with scope; reproduction commands; one plot; demo; report; design; limitations; attribution.
2. State exactly what you wrote and which library handles each primitive. Use a descriptive project title and avoid claims of inventing a signature scheme.
3. Test from a fresh checkout or clean directory with the pinned toolchain and lockfile. Run the demo, quick benchmark, transport analysis, formatting, static checks, and relevant tests. Make expensive SLH-DSA/full measurements explicit rather than part of every routine test run.
4. Add CI for correctness and a small smoke run. Do not gate CI on precise timing; shared runners are unsuitable for performance thresholds.
5. Record a two-minute demonstration: question and architecture; accepted request; tampering/replay rejection; benchmark/transport finding; runtime result or blocker; limitation and next research question.
6. Prepare one accurate résumé bullet using only measured accomplishments. Do not invent throughput numbers, publication status, or deployed security guarantees.
7. Prepare short answers to the interview questions below. Tag the completed local release if using Git; publishing is a separate action.

### Interview preparation

- Why does a larger transaction limit not establish affordable verification?
- Why are host microseconds different from Solana compute units?
- How can a valid signature still represent an invalid application request?
- What fails if nonce state disappears on restart?
- Which public key is trusted, and how was it registered?
- Why is multisignature authorization different from threshold signing?
- Which signing mode and context did you benchmark?
- What did the academic security game prove, and what did your tests establish?
- Which result did you expect differently, and how did you investigate it?
- What would you study next if given three more months?

### Release checklist

- [ ] Core primitives and authorization scenarios work.
- [ ] Encoding and trust assumptions are documented.
- [ ] Raw benchmark data and environment metadata are present.
- [ ] Actual and modeled transport outputs are distinguished.
- [ ] Runtime experiment has either genuine results or a reproducible blocker.
- [ ] Plots can be regenerated from the data.
- [ ] README commands work from a clean checkout.
- [ ] Report distinguishes facts, hypotheses, assumptions, and limitations.
- [ ] Demo is concise and uses genuine output.
- [ ] Dependencies and AI assistance are attributed.

**Suggested checkpoint commit:** `Prepare reproducible project release and reviewer demonstration`.

## 4. When progress slips

| Situation | Adjustment |
| --- | --- |
| Crypto adapters still failing after Day 1 | Complete Ed25519 and ML-DSA-44; defer extra schemes |
| Application encoding/state consumes Day 2 | Keep the single-process ledger and mock assets; document restart limitations |
| SLH-DSA is too slow for the full profile | Retain smaller labeled sample counts; omit unsupported percentiles |
| Solana SDK lacks v1 support | Serialize legacy/v0 and publish an explicitly modeled v1 analysis |
| sBPF verifier fails to compile | Save a reproducible blocker and finish the report |
| Staging implementation grows too large | Keep actual chunk-transaction size calculations and documented lifecycle requirements |
| Day 6 arrives with unfinished features | Freeze scope and spend the remaining time on valid evidence and reproduction |

A smaller completed experiment with sound claims is a good portfolio result. The project is an applied research exercise; it does not by itself establish expertise in every subject in the job description. The posting's PhD requirement remains an independent eligibility consideration.

## 5. Your first 90 minutes

1. **0–15 minutes:** Create the package; write the research question and the core deliverables in the README.
2. **15–30 minutes:** Choose the toolchain, add Ed25519/ML-DSA dependencies, and confirm a release build.
3. **30–60 minutes:** Generate an ML-DSA-44 key, sign one message, verify it, and print only public sizes and verdicts.
4. **60–80 minutes:** Add altered-message and wrong-key tests. Confirm malformed input fails without panicking.
5. **80–90 minutes:** Save the toolchain/dependency details and commit the working slice.

The first checkpoint is simple: a real ML-DSA signature verifies, tampering fails, and you can explain the code you wrote. That is the foundation for every later milestone.
