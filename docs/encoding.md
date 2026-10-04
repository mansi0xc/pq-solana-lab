# Canonical withdrawal intent encoding (v1)

This document is the specification. `src/intent.rs` implements exactly this
layout; `tests/encoding.rs` holds the golden fixture that pins it.

Design rules:

- Fixed-width fields only. No variable-length data, no text, no floats.
- Multi-byte integers are **big-endian**.
- The encoding is **exact-length**: a buffer shorter or longer than 166 bytes
  is rejected, so trailing bytes are impossible by construction.
- The scheme identifier and registered-key identifier are *inside* the signed
  bytes, so a signature cannot be replayed across schemes or keys.
- Domain separation comes from the domain prefix, encoding version, network
  identifier, and program identifier — not from the signature scheme's
  context string (which is empty; see `src/crypto/ml_dsa.rs`).

## Layout (166 bytes total)

| Offset | Bytes | Field | Type |
| --- | --- | --- | --- |
| 0 | 8 | domain prefix | ASCII `PQSOL-WD` |
| 8 | 1 | encoding version | `0x01` |
| 9 | 1 | signature scheme | `0x01` = Ed25519, `0x02` = ML-DSA-44 |
| 10 | 4 | key identifier | u32 BE, assigned by the trusted registry |
| 14 | 32 | network / genesis identifier | opaque 32 bytes |
| 46 | 32 | program identifier | opaque 32 bytes (Solana pubkey-sized) |
| 78 | 32 | asset identifier | opaque 32 bytes (mint-like) |
| 110 | 32 | recipient | opaque 32 bytes (account-like) |
| 142 | 8 | amount | u64 BE, base units |
| 150 | 8 | nonce | u64 BE, strictly sequential per key |
| 158 | 8 | expiry slot | u64 BE; accepted while `current_slot <= expiry_slot` |

## Decoder rejection rules

| Input | Result |
| --- | --- |
| length ≠ 166 | `InvalidLength` error |
| version ≠ 1 | `UnsupportedVersion` error |
| scheme byte not in {1, 2} | `UnknownScheme` error |
| any other 166-byte buffer | decodes; environment/policy checks are the authorizer's job, not the decoder's |

The decoder deliberately does **not** compare the domain, network, or program
fields against expected values. Those are authorization-policy checks in
`src/authorization.rs`, so that a correctly signed intent for the wrong
environment is a *policy* rejection, distinguishable from a malformed input.

## Golden fixture

Intent: scheme ML-DSA-44, key id 7, network id `0x11…` (×32), program id
`0x22…` (×32), asset `0x33…` (×32), recipient `0x44…` (×32), amount
1,000,000 base units, nonce 0, expiry slot 500.

Hex (166 bytes = 332 hex chars), asserted verbatim in
`tests/encoding.rs::golden_fixture`:

```
5051534f4c2d5744010200000007
1111111111111111111111111111111111111111111111111111111111111111
2222222222222222222222222222222222222222222222222222222222222222
3333333333333333333333333333333333333333333333333333333333333333
4444444444444444444444444444444444444444444444444444444444444444
00000000000f4240000000000000000000000000000001f4
```
