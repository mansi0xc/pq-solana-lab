# Research question and hypotheses

## Question

> Under a specified Solana transaction format and execution environment, what
> limits the practicality of standardized post-quantum signatures for
> application authorization: payload size, verification resources, or
> integration constraints?

Narrower questions (from `idea.md`):

1. How do selected signature schemes compare in host key-generation, signing,
   and verification time, public-key size, and signature size?
2. How much transaction space remains when an authorization request and its
   signature are included in instruction data?
3. How does registering the public key separately change the transport budget?
4. What does staged signature upload solve, and which verification or
   state-management problems remain?
5. Can the selected ML-DSA verifier compile and execute correctly under the
   tested Solana runtime configuration?

## Hypotheses (expectations to test, not findings)

- **H1 (payload):** Signature and public-key bytes may prevent direct
  inclusion in some Solana transaction formats even when host verification
  is fast.
- **H2 (staging):** Storing a signature in an account may solve transport
  constraints while leaving verification-resource constraints unresolved.
- **H3 (host vs runtime):** Host verification speed may differ substantially
  from feasibility inside Solana's execution environment (stack, heap, and
  compute-budget limits).

## Scope boundaries

- Application-level authorization only. Native Solana transaction signing,
  fee payment, and administrative keys keep their own (classical) security
  assumptions.
- Cryptographic primitives come from published libraries (`ed25519-dalek`,
  `fips204`, later `fips205`). This project's contribution is the
  experimental design, integration, adversarial tests, and analysis.

## Standard references checked at M1

- FIPS 204 (ML-DSA), final, August 2024: parameter table — ML-DSA-44 has a
  1,312-byte public key, 2,560-byte secret key, 2,420-byte signature; claimed
  security strength category 2. Signing API used here is the "pure" mode with
  a context string (we use the empty context) and randomized ("hedged")
  signing as implemented by `fips204` 0.4.6.
- FIPS 204 errata: checked https://csrc.nist.gov/pubs/fips/204/final on
  2026-10-04. A NIST planning note (dated 2026-07-31) links an errata
  spreadsheet listing "several minor issues" to be corrected in a future
  revision of the publication. The errata items were not individually
  evaluated here; the project tests the published standard as implemented by
  `fips204` 0.4.6, and any erratum affecting the external KeyGen/Sign/Verify
  behavior would surface as a test failure. The `fips204` crate documents that
  NIST test vectors are applied to its internal functions (see its deprecation
  notes on `_internal_sign`/`_internal_verify`).

## Independent correctness evidence status (updated M2 correction batch)

- Ed25519: known-answer tests against RFC 8032 §7.1 (a primary source) now
  cover key derivation, exact signature bytes, and verification.
  See `tests/ed25519_known_answer.rs`.
- ML-DSA-44: the external sign API uses randomized ("hedged") signing, so
  there is no fixed expected signature to reproduce from a published vector.
  Independent conformance is instead established by an interoperability
  cross-check (`tests/ml_dsa_interop.rs`, added in M3): a signature produced by
  `fips204` (the library behind this project's adapter) verifies under the
  RustCrypto `ml-dsa` 0.1.1 crate, an independent FIPS 204 (final)
  implementation, and vice versa, with a tampered-message rejection. This is
  cross-implementation evidence, not a self round-trip. No NIST ACVP sigVer
  vector has been transcribed; that remains a possible additional check, not a
  blocking gap.
