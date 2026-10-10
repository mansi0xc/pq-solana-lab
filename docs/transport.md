# Solana transport analysis

This documents the M4 transport measurements. The numbers are produced by
`cargo run --release -- transport` and written to `results/transport.json` and
`results/transport-staged.json`.

## Wire encodings (important correction)

- **legacy / v0** — classic Solana bincode wire format (`bincode` 1.3.3), which
  matches the 1,232-byte packet limit.
- **v1** — the SDK's own wire encoder, **not bincode**. `solana-message` 5.1.0
  states for the v1 message type: *"This message format does not support bincode
  binary serialization. Use the provided `serialize` and `deserialize`
  functions."* This project serializes v1 with `wincode` 0.6.2 (the crate the
  SDK uses) and decodes it back with the same, so the bytes are the actual wire
  form: message-with-`0x81`-prefix first, then the fixed-length signature array
  with no length prefix.

A bincode-encoded v1 buffer is not a valid wire transaction and is rejected by
the v1 decoder; `tests/transport.rs::bincode_v1_buffer_is_not_a_valid_wire_transaction`
pins this. The superseded bincode-based v1 sizes are preserved in
`results/transport.bincode-v1-superseded.json`.

## Templates (minimal vs operational)

Every direct row names a template so a payload floor is never confused with a
realistic authorization transaction:

- **`minimal`** — fee payer + program (2 accounts), empty v1 config. The raw
  payload + envelope floor.
- **`operational`** — fee payer + read-only key-registry account + writable
  authorization-state / nonce-ledger account + program (4 accounts). v1 rows
  additionally set `compute_unit_limit = 200_000` and
  `loaded_accounts_data_size_limit = 65_536` explicitly (an unset v1 field means
  `0`).

The signed intent is bound to the configured environment: the scheme byte is the
row's scheme, the intent `program_id` equals the transaction's program account,
and the intent `network_id` equals the configured `NETWORK_ID`.

## Direct-inclusion results (host, solana-sdk 5.0.0)

Source: `results/transport.json`, evidence type `serialized`. The full table is
generated into `docs/report.md` (§5.3) and `results/tables/transport_direct.*`.
Highlights:

- Every post-quantum scheme's payload exceeds the legacy/v0 1,232-byte budget
  even with the key registered (ML-DSA-44 = 2,758 B, ML-DSA-65 = 3,647 B,
  SLH-DSA = 8,194 B; minimal template).
- **v1 (4,096 B)** admits ML-DSA-44: 2,762 B registered or 4,074 B inline on the
  **minimal** template. On the **operational** template ML-DSA-44 is 2,836 B
  registered but 4,148 B inline — **52 bytes over the limit**. ML-DSA-65 fits
  only when registered (3,651 / 3,725 B). SLH-DSA-SHA2-128s does not fit.
- Registration removes exactly the public-key bytes per transaction.

### Reproducing the reviewer's v1 diagnostic ladder

Independent reviewer probes of the v1 wire encoder for the ML-DSA-44 inline
payload (166-byte intent + 2,420-byte signature + 1,312-byte key) are reproduced
by `tests/transport.rs::v1_wire_size_matches_the_reviewer_probe_ladder`:

| Construction | v1 wire bytes | delta |
| --- | --- | --- |
| 2 accounts, empty config | 4,074 | — |
| 2 accounts, +2 resource-limit fields (u32 ×2) | 4,082 | +8 |
| 3 accounts (+1 state), +2 resource-limit fields | 4,115 | +33 (32-byte address + 1-byte index) |

The operational 4-account template used by the analysis (registry + state) is
4,148 = 4,115 + 33. These values describe this specific one-instruction
template; they are regression pins, not universal constants. A bincode buffer of
the same payload is 4,089 bytes and is rejected by the v1 decoder.

## Staged upload (modeled)

Staged upload moves the signature into an on-chain session account so that no
single transaction must carry it. The protocol is defined and serialized here;
the lifecycle is **not** executed.

### Protocol

Instruction tags and encodings (little-endian u32 fields):

| Tag | Instruction | Data |
| --- | --- | --- |
| 1 | `Init` | `session_id[32] ‖ key_id u32 ‖ expected_len u32 ‖ uploader[32]` |
| 2 | `Write` | `session_id[32] ‖ offset u32 ‖ chunk[N]` |
| 3 | `Seal` | `session_id[32] ‖ total_len u32` |
| 4 | `Authorize` | `session_id[32] ‖ key_id u32 ‖ intent[166]` |

Policy the program enforces (stated, not executed here):

- **Account binding / uploader:** the session account is keyed by `session_id`;
  `Init` binds the authorized `uploader`, which must sign `Write`/`Seal`.
- **Registered-key binding:** `Init` and `Authorize` carry `key_id`, resolved
  against the trusted registry account; the key material is never transported.
- **Expected length / position:** `Init` fixes `expected_len`; each `Write` must
  use `offset == bytes_written` (sequential, append-only).
- **Sealing / overwrite:** `Seal` requires `total_len == expected_len`, sets the
  sealed flag, and rejects any later `Write`.
- **Final authorization:** `Authorize` requires a sealed session of the exact
  expected length, then verifies the stored signature over the supplied intent
  and consumes the nonce in the authorization-state account.

### Modeled sizes

Source: `results/transport-staged.json`, evidence type `modeled`. The chunk
capacity is the largest `Write` payload such that the **complete serialized
`Write` transaction** (accounts, signature, config, and the 37-byte `Write`
framing) fits the format limit; `tests/transport.rs` re-derives the boundary and
checks maximality.

**Included:** `Init`, all `Write`, `Seal`, and `Authorize` transaction wire
bytes; session metadata (77 B: session id + uploader + key id + expected length
+ bytes-written + sealed flag) plus the signature as storage.
**Excluded:** key registration, account creation and rent, cleanup/close, and
compute.

This is a **lower-bound** model: a real uploader would also pay rent for the
session account over its lifetime and the cost of registering the key. Staging
makes each transaction fit (legacy/v0 chunk ~957 B, v1 ~3,809 B) but increases
total transported bytes and adds on-chain state; it does not reduce verification
cost. A size result is a transport measurement, not an executed authorization.

## v1 submission is not supported by the tested runtime

The v1 numbers above are **serialization** results. They were not, and cannot
be, submitted to the runtime used for the execution experiment: the Agave 3.1.x
runtime has no v1 support. The `enable_tx_v1` feature ("SIMD-0385: Transaction
V1") is defined in `agave-feature-set` 4.2.x but is **absent from
`agave-feature-set` 3.1.14** (the version matching the 3.1.10 validator), so the
3.1.x RPC neither parses the v1 wire format nor allows a v1-sized packet.

`experiments/outcome/probe-v1.sh` records both rejection modes against a local
`solana-test-validator` 3.1.10 (`experiments/outcome/v1-rejection.log`):

| v1 tx | RPC response |
| --- | --- |
| small (206 B, 32-byte data) | `-32602 failed to deserialize ... VersionedTransaction: io error: failed to fill whole buffer` |
| large (3,957 B, 3,783-byte data) | `-32602 base64 encoded ... too large: 5276 bytes (max: encoded/raw 1644/1232)` |

The first is the RPC decoding the submitted bytes as bincode/serde: the v1 wire
form starts with `0x81`, which bincode reads as a 129-entry signature array.
The second is the 1,232-byte packet limit applied to the base64 string
(3,957 × 4/3 = 5,276; the encoded maximum is 1,644 = ⌈1,232 × 4/3⌉). Legacy/v0
transactions are unaffected and are what the execution experiment used.

**Conclusion:** "v1 admits ML-DSA-44" is a claim about the *wire format*, with
evidence type `serialized`. On this runtime the format is not submittable at
all, so no v1 transaction was accepted or executed on chain.

## Assumptions

- **Fee payment** is a separate, classical Ed25519 concern; the fee payer is a
  native Solana keypair and its 64-byte signature is ordinary overhead.
- **Key registration**: in the "registered" placement the verification key is
  assumed to already exist in trusted on-chain state keyed by the intent's
  `key_id`; the transaction carries only the `key_id`. An inline key must still
  match a trusted registration or commitment — presence in a request does not
  establish trust.
- **v1**: serialized with the SDK's `wincode` encoder; the v1 limit is the SDK's
  `v1::MAX_TRANSACTION_SIZE` = 4,096 bytes.
