# Interview questions and answers

Answers are grounded in this repository's measured evidence. Treat them as
study notes to verify against the artifacts, not as a claim that any particular
point has been mastered.

**Why does a larger transaction limit not establish affordable verification?**
A larger limit only changes how many bytes a transaction can carry. Verification
cost depends on the verifier's execution resources (stack, heap, compute) and is
measured separately. v1's 4,096-byte limit lets ML-DSA-44's payload fit on a
minimal template, but the `fips204` verifier still fails the 4,096-byte
stack-frame check before executing (see `docs/solana-feasibility.md`).

**Why are host microseconds different from Solana compute units?**
They measure different machines and different work. Host timings include
OS/allocator effects on an Apple M4; compute units are the runtime's own
accounting inside sBPF. There is no defensible conversion factor, so the project
never converts host timings into compute units and reports none where execution
did not occur.

**How can a valid signature still represent an invalid application request?**
A signature only proves that the holder of a key signed those exact bytes. The
authorizer separately enforces that the key is registered for the right scheme,
that the environment (network/program/domain) matches, that the request has not
expired, and that the nonce is the expected one. The tests sign *correctly* for
the wrong network/expired/stale cases and expect a policy rejection, distinct
from an integrity rejection.

**What fails if nonce state disappears on restart?**
Replay protection. The nonce ledger is in-memory here, so a restart resets it and
a previously accepted intent could be accepted again. Persistent, durable replay
state is future work (`docs/threat-model.md`, "What is NOT protected").

**Which public key is trusted, and how was it registered?**
Only keys in the trusted `KeyRegistry`, keyed by the intent's `key_id`. A key is
registered out of band; registration runs `Scheme::validate_public_key`, which
for Ed25519 rejects non-decompressible and weak (low-order) keys. An inline key
in a request is never trusted on its own — it must match the registration.

**Why is multisignature authorization different from threshold signing?**
Independent signatures are collected and each verified; the secrets remain
separate and the signatures are not combined. Threshold ML-DSA (ePrint 2026/013)
produces a single standardized signature from a distributed key, with its own
rejection-sampling and security model. The project only cites the latter as
future work and does not implement it.

**Which signing mode and context did you benchmark?**
Ed25519: RFC 8032 pure, deterministic. ML-DSA-44/65: FIPS 204 pure mode, empty
context, randomized ("hedged") signing as implemented by `fips204`. SLH-DSA:
FIPS 205 pure mode, empty context, hedged. Recorded in
`results/environment.json` and per-run metadata.

**What did the academic security game prove, and what did your tests establish?**
FIPS 204 §3.1 states ML-DSA is designed to be *strongly* unforgeable under
chosen-message attack (SUF-CMA): no new valid `(m, σ)` pair, even for an
already-signed message. The application's anti-forgery step only needs EUF-CMA
(no valid `(m, σ)` for a never-signed message); replay is handled by nonce
state, not by strong unforgeability. The tests establish behavioral policy
properties (accept/reject and unchanged state on rejection), not a proof and not
the scheme's forgery-resistance.

**Which result did you expect differently, and how did you investigate it?**
The v1 sizing. The first release used bincode for v1 and reported ML-DSA-44
inline at 4,089 bytes with 7 bytes of headroom. The SDK documents that v1 does
not support bincode; switching to the SDK's `wincode` encoder gives 4,074 bytes
on a 2-account minimal template, and 4,148 bytes on a 4-account operational
template (registry + authorization-state accounts + explicit config), which is
52 bytes over the limit. The superseded numbers are preserved and the correction
is pinned by tests.

**What would you study next if given three more months?**
A stack-efficient or heap-allocating ML-DSA verifier for sBPF with a real
execution harness and compute measurements; independent conformance for
ML-DSA-65/SLH-DSA; persistent replay state; and the threshold-ML-DSA design,
which needs its own scope.
