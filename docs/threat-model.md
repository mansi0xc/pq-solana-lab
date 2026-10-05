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

## Key validation and strict verification

- **Registration validates keys.** `KeyRegistry::register` runs
  `Scheme::validate_public_key`: Ed25519 rejects non-decompressible encodings
  and weak (low-order) keys such as the identity point; ML-DSA validates the
  fixed-size key deserializes. A weak Ed25519 key would otherwise let an
  attacker forge a valid signature with no secret key.
- **Authorization verifies strictly.** The authorization path uses
  `Scheme::verify_strict`, which for Ed25519 additionally rejects weak public
  keys and small-order signature components (`ed25519-dalek` 3.0's
  `verify_strict`). This is defense in depth on top of registration: even if a
  weak key were admitted to the registry, strict verification rejects the
  identity-R / zero-S forgery. See the `secretless_authorization_*` tests.
- **Ed25519 verification is non-strict in the generic byte path** (`verify`),
  matching RFC 8032; the strict path is used only where application
  authorization requires it.

## Encoding version is a parser concern, not environment configuration

The intent encoding version is fixed (`ENCODING_VERSION = 1`) and enforced by
the intent decoder, which rejects any other version byte before policy checks.
There is no configurable "environment version": an environment does not
advertise support for version 2, and version 2 intents cannot be parsed. This
keeps parser support and application policy consistent.

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
