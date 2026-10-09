# Technical note

A short, defensive note connecting the project's observations to the underlying
cryptography. It is written to be checked against primary sources, not taken on
faith. Numbers cited here are from `docs/report.md` and
`experiments/outcome/`.

## 1. Why ML-DSA uses rejection sampling

ML-DSA is a Fiat–Shamir-with-aborts signature. In the underlying interactive
protocol the prover commits to `w = A·y`, receives a challenge `c`, and returns
`z = y + c·s1`. Releasing `z` as-is leaks the secret: FIPS 204 §3.3 says the
response "will be biased in a direction related to the private value `S1`", so
"the signer applies rejection sampling to `z`; if coefficients of `z` fall
outside of a specified range, the signing process is aborted, and the signer
starts over from a new value of `y`." A second rejection stage bounds the hint
weight and `‖c·t0‖∞`.

The purpose is distributional: the *accepted* responses are distributed
independently of the secret, which is what lets the transcript be simulated. The
cost is a variable number of loop iterations per signature. That is why the
project's ML-DSA signing timings have a wide spread (in run `full-r1`, the
first quartile of ML-DSA-44 signing is well below the median) while Ed25519
signing, which has no such loop, is nearly constant. It is also why "signing
time" for ML-DSA is a distribution, not a single number, and why a single
median would be misleading.

## 2. EUF-CMA versus SUF-CMA

- **EUF-CMA** — with the public key and a signing oracle, no adversary can
  output a valid `(m, σ)` for a message `m` it never queried.
- **SUF-CMA** — no adversary can output *any* new valid `(m, σ)`, including a
  different `σ' ≠ σ` for a message the oracle already signed. SUF-CMA implies
  EUF-CMA.

FIPS 204 §3.1: "ML-DSA is designed to be strongly existentially unforgeable
under chosen message attack (SUF-CMA). That is, it is expected that even if an
adversary can get the honest party to sign arbitrary messages, the adversary
cannot create any additional valid signatures based on the signer's public key,
including on messages for which the signer has already provided a signature."

## 3. The authorization argument, and replay

Under a trusted registry, correct environment identifiers, and an unforgeable
scheme, accepting a *new* canonical intent the registered signer never signed
would require a signature verifying on unsigned bytes — a forgery on a message
never queried, i.e. **EUF-CMA**. The canonical 166-byte encoding fixes widths,
is exact-length, and puts the scheme and key id inside the signed bytes, so a
signature cannot be reinterpreted across schemes or keys.

Replay is a *different* property. It is prevented by monotonic nonce state, not
by strong unforgeability: a resubmitted intent, or a different valid signature
on the same intent, fails the nonce check. The prototype's nonce ledger is
in-memory only, so replay protection does **not** survive a restart — that is a
stated limitation, not a cryptographic claim. A design that deduplicated by
signature bytes, or had no replay state, would additionally depend on SUF-CMA.

These are assumptions and a conditional argument. The project's tests are
behavioural evidence of the policy layer, not a proof and not an audit.

## 4. Why staged transport does not establish verifier feasibility

Staged upload (`docs/transport.md`) is a **byte-transport** model: it splits a
signature across several transactions so each fits the size limit. Its numbers
are serialized sizes — e.g. a ~3,809-byte v1 `Write` chunk — and it is not even
executed. Nothing about fitting bytes in a transaction says anything about what
happens when a verifier runs inside the SBF VM: stack-frame limits, heap, and
compute budget are execution-time resources. The two are independent, and the
experiment shows the gap directly: the `fips204` verifier's payload can be
transported (registered in v1) and the program can be deployed, yet execution
aborts after 418 compute units before producing any verdict. Transport fit is
necessary for the naïve on-chain flow and sufficient for none of feasibility.

## 5. One definition and one proof-relevant step, with references

- **Definition (primary source).** SUF-CMA is defined and claimed for ML-DSA in
  FIPS 204 §3.1 (quoted in §2 above). Exact reference: National Institute of
  Standards and Technology, *Module-Lattice-Based Digital Signature Standard*,
  FIPS 204, August 2024, §3.1 "Security Properties",
  <https://doi.org/10.6028/NIST.FIPS.204>.
- **Proof-relevant step and its assumption.** FIPS 204 §3.6.2 ("Public-Key and
  Signature Length Checks") requires an implementation to reject public keys and
  signatures whose lengths differ from the parameter set, and states the reason:
  "Failing to check the length of `pk` or `σ` may interfere with the security
  properties that ML-DSA is designed to have, like strong unforgeability." The
  assumption is therefore a **canonical, fixed-length encoding** enforced at the
  trust boundary; the step is rejecting any other length before verification.
  This project implements exactly that (fixed lengths, exact-length intents) and
  the library length checks are relied upon, not re-derived.

Two honest limitations: (i) FIPS 204 states the security properties and the
requirements that support them, but this note does **not** trace a full
reduction proof from it; (ii) the threshold paper cited as future work
(*Efficient Threshold ML-DSA*, ePrint 2026/013; Celi, del Pino, Espitau, Niot,
Prest; USENIX Security '26) had its abstract retrieved but its PDF was
unavailable, so **no numbered theorem from it was traced** and it is cited only
as future work.

## 6. What the controlled experiment supports and limits

- **Supports.** Under one toolchain (cargo-build-sbf 3.1.10 / platform-tools
  v1.52 / rustc 1.89.0), one runtime (local `solana-test-validator` 3.1.10),
  the same parameter set (ML-DSA-44), mode (pure, empty context), fixture, and
  program structure, *two independent implementations* (`fips204` 0.4.6 and
  RustCrypto `ml-dsa` 0.1.1) both load, verify, and deploy, then both abort at
  runtime before any verdict. So the blocker is not specific to one library in
  this configuration.
- **Limits.** Two library builds, one toolchain, one local validator, and no
  successful verification: no compute units for a completed verification are
  claimed. A verifier that heap-allocates its large buffers, or otherwise
  reduces per-frame stack, is untested here and may differ. Nothing is concluded
  about ML-DSA on Solana in general, or about mainnet.

## 7. Self-test

Answer these before an interview; each has a one-line check.

1. In one sentence, why is the ML-DSA response `z` rejected sometimes?
   *Because releasing an unbounded `z = y + c·s1` leaks the secret; rejection
   sampling keeps the accepted distribution independent of the secret.*
2. What is the difference between EUF-CMA and SUF-CMA?
   *SUF-CMA also forbids a new signature on an already-signed message.*
3. Which of the two does the authorization argument actually need, and why?
   *EUF-CMA: a new intent is a never-signed message; replays are caught by
   nonce state, not by strong unforgeability.*
4. What breaks if the nonce ledger is lost on restart?
   *Replay protection; a previously accepted intent could be accepted again.*
5. Why doesn't "the signature fits in a v1 transaction" imply "the verifier can
   run on chain"?
   *Size is a transport property; execution depends on stack/heap/compute, which
   the experiment shows fail (trap at 418 CU).*
6. What did the compiler emit, and what did the loader do?
   *Compiler: stack-frame diagnostics, exit 0. Loader: accepted the ELF and
   deployed it; failure appears only at execution (access violation).*
7. State one assumption behind FIPS 204 §3.6.2's length check.
   *Canonical fixed-length encodings; wrong-length `pk`/`σ` must be rejected,
   else strong unforgeability is not guaranteed.*
8. Why is the ML-DSA signing median alone misleading?
   *Signing is rejection-sampled, so the distribution is wide; report the
   quartiles.*
