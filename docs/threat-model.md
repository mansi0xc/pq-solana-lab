# Threat model and assumptions (local authorization prototype)

## Trusted components (assumptions, not established facts)

1. **Key registry** is trusted and correctly populated: each `key_id` maps to
   exactly one scheme and public key, recorded out-of-band before any request
   is accepted. Verification keys are selected *only* from this registry.
2. **Environment identifiers** (domain, network/genesis id, program id) are
   configured correctly in the verifier.
3. **Slot input** (`current_slot`) is trustworthy: a real deployment would
   source it from the chain clock, not from the request. The prototype takes
   it as an explicit argument for deterministic tests.
4. **Key generation** is correct and the secret key stays secret.
5. **Signature libraries** behave as specified (ed25519-dalek, fips204).

## Adversary capabilities

The adversary may:

- Alter any request field after signing (integrity attack).
- Replay a previously accepted request (replay attack).
- Submit an intent signed by any key, registered or not (key confusion).
- Submit a correctly signed intent for the wrong network/program/domain
  (environment/domain-separation attack).
- Submit malformed bytes, wrong-length signatures, or corrupt signatures
  (parsing attacks).
- Submit a request whose expiry has passed or whose nonce is out of order.

The adversary cannot sign under a registered key (no secret-key compromise is
in scope for this prototype).

## Conditional authorization argument

With a trusted registry (assumption 1), correct environment identifiers
(assumption 2), and an unforgeable signature scheme (assumption 5), accepting
a *new* unauthorized canonical intent would require producing a signature that
verifies under a registered public key for bytes the signer never signed — a
forgery. The canonical encoding (fixed-width, exact-length, scheme and key id
inside the signed bytes) prevents cross-scheme and cross-key reinterpretation.

This is a *conditional application argument*, not a proof of ML-DSA or Ed25519
and not an audit of a production system.

## What is NOT protected

- **Replay across restarts:** nonce state (`next_nonce`, ledger) is in-memory
  only. A process restart resets it, so a previously accepted request could be
  replayed after restart. Persistent, durable replay state is future work.
- **Native Solana transaction signing, fee payment, key registration, and any
  administrative authority** keep their own (classical) security assumptions.
- **No constant-time or side-channel claims** are made about this prototype;
  timing measurements are host observations, not security claims.

## Separation of concerns in tests

- **Signature integrity** tests mutate intent bytes *without* resigning and
  expect `InvalidSignature` (or a parse error for malformed input).
- **Application policy** tests sign *correctly* (often with a registered key)
  and expect an environment/expiry/nonce rejection, proving the policy layer
  — not the signature — caught the violation.
- **Replay** is a nonce-state property, distinct from signature validity.
