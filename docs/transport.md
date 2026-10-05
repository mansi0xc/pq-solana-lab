# Solana transport analysis

This documents the M4 transport measurements. The numbers are produced by
`cargo run --release -- transport` and are the sizes of *actually serialized*
transactions built with `solana-sdk` 5.0.0 (bincode wire format), not manual
estimates.

## What is measured

For each of the four schemes and two key placements, a minimal transaction is
built containing one application instruction whose data is the canonical
withdrawal intent (166 bytes) plus the scheme's signature, plus — for the
"inline" placement — the scheme's public key. The transaction has a single
classical Ed25519 fee-payer signer and one program account (2 accounts total),
a fixed blockhash, and one genuine native signature.

- `total_bytes` — size of the serialized transaction.
- `headroom` — `1232 - total_bytes` for legacy/v0 (the documented packet limit).
- `evidence_type` — always `serialized`.

## Direct-inclusion results (host, solana-sdk 5.0.0, bincode)

| Scheme | sig | pk | inline (legacy/v0) | registered (legacy/v0) | Fits in 1232? |
| --- | --- | --- | --- | --- | --- |
| ed25519 | 64 | 32 | 434 / 436 | 402 / 404 | yes |
| ml-dsa-44 | 2420 | 1312 | 4070 / 4072 | 2758 / 2760 | no |
| ml-dsa-65 | 3309 | 1952 | 5599 / 5601 | 3647 / 3649 | no |
| slh-dsa-sha2-128s | 7856 | 32 | 8226 / 8228 | 8194 / 8196 | no |

**Observation (measured, not a conclusion about verification):** every
post-quantum scheme here has a signature large enough that the authorization
payload alone exceeds the legacy/v0 1,232-byte packet budget — even with the
public key registered out-of-band. Registration removes exactly the public-key
bytes per transaction but does not address the signature size.

## Assumptions

- **Fee payment** is a separate, classical Ed25519 concern; the fee payer here
  is a native Solana keypair and its 64-byte signature is ordinary overhead.
- **Key registration**: in the "registered" placement, the verification key is
  assumed to already exist in trusted on-chain state keyed by the `key_id`
  inside the intent; the transaction carries only the `key_id`. An inline key
  still has to match a trusted registration or commitment — presence in a
  request does not establish trust.
- **Account lifecycle**: the two accounts (payer + program) are assumed to
  exist; no rent/cleanup is modeled here (staged upload in M4.2).
- **v1**: the SDK exposes a v1 message variant; serialization of v1 and the
  staged-upload chunking are deferred to M4.2.
- A size result is a transport measurement, not an executed authorization and
  not a claim about verification cost or compute units.
