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
- **v1**: serialized with the SDK's `v1::Message` (`solana-sdk` 5.0.0). The
  v1 limit is the SDK's `v1::MAX_TRANSACTION_SIZE` = 4,096 bytes.
- A size result is a transport measurement, not an executed authorization and
  not a claim about verification cost or compute units.

## v1 direct-inclusion results

v1's 4,096-byte limit changes the picture for the smaller post-quantum scheme:

| Scheme | inline (v1) | registered (v1) | Fits in v1? |
| --- | --- | --- | --- |
| ed25519 | 419 | 421 | yes |
| ml-dsa-44 | 4089 | 2777 | inline barely (7-byte headroom); registered yes |
| ml-dsa-65 | 5618 | 3666 | inline no; registered yes |
| slh-dsa-sha2-128s | 8245 | 8213 | no |

ML-DSA-44 fits in v1 (inline by 7 bytes; comfortably when registered);
ML-DSA-65 fits only when registered; SLH-DSA-SHA2-128s still does not fit.

## Staged upload (modeled)

Staged uploads split the signature across multiple "store chunk" transactions
(initialization, N chunk uploads, and a final reference transaction). The
largest safe chunk per format is derived by binary search over the
actually-serialized upload-transaction template (a 3-account transaction: fee
payer + program + storage account), with a stated margin of zero because the
template already includes all accounts, signatures, and framing.

| Scheme | format | sig | chunk | chunks | transactions | total transport bytes |
| --- | --- | --- | --- | --- | --- | --- |
| ml-dsa-44 | legacy/v0 | 2420 | 1027/1025 | 3 | 5 | 3611/3621 |
| ml-dsa-44 | v1 | 2420 | 3872 | 1 | 3 | 3258 |
| ml-dsa-65 | legacy/v0 | 3309 | 1027/1025 | 4 | 6 | 4705/4717 |
| ml-dsa-65 | v1 | 3309 | 3872 | 1 | 3 | 4147 |
| slh-dsa-sha2-128s | legacy/v0 | 7856 | 1027/1025 | 8 | 10 | 10072/10092 |
| slh-dsa-sha2-128s | v1 | 7856 | 3872 | 3 | 5 | 9141 |

**Observation (modeled):** staging makes each individual transaction fit the
format limit, but it increases the *total* transported bytes (per-transaction
overhead is repeated) and introduces on-chain storage and upload state. It does
not address verification cost. Storage bytes equal the signature size; the
upload lifecycle itself is a model, not an executed sequence, and the
initialization/upload/final transactions are serialized but not executed.

## Direct vs staged

- Direct inclusion is one transaction but fails the limit for every
  post-quantum scheme here (in legacy/v0, and for ML-DSA-65/SLH-DSA in v1).
- Staged upload always fits per transaction, at the cost of more total bytes,
  more transactions, and on-chain state.
- Neither approach changes the fact that the signature must still be verified
  on chain.
