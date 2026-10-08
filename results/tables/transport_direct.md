_Source: `results/transport.json` — actually serialized `solana-sdk` 5.0.0 transactions; legacy/v0 use bincode, v1 uses the SDK `wincode` wire encoder. Evidence type: `serialized`. Limits: legacy/v0 = 1,232 B, v1 = 4,096 B._

| Scheme | Template | Placement | legacy (B) | v0 (B) | v1 (B) | accounts | v1 config |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Ed25519 | minimal | inline | 434 | 436 | 438 | 2 | empty |
| Ed25519 | minimal | registered | 402 | 404 | 406 | 2 | empty |
| Ed25519 | operational | inline | 500 | 502 | 512 | 4 | explicit |
| Ed25519 | operational | registered | 468 | 470 | 480 | 4 | explicit |
| ML-DSA-44 | minimal | inline | 4070 | 4072 | 4074 | 2 | empty |
| ML-DSA-44 | minimal | registered | 2758 | 2760 | 2762 | 2 | empty |
| ML-DSA-44 | operational | inline | 4136 | 4138 | 4148 | 4 | explicit |
| ML-DSA-44 | operational | registered | 2824 | 2826 | 2836 | 4 | explicit |
| ML-DSA-65 | minimal | inline | 5599 | 5601 | 5603 | 2 | empty |
| ML-DSA-65 | minimal | registered | 3647 | 3649 | 3651 | 2 | empty |
| ML-DSA-65 | operational | inline | 5665 | 5667 | 5677 | 4 | explicit |
| ML-DSA-65 | operational | registered | 3713 | 3715 | 3725 | 4 | explicit |
| SLH-DSA-SHA2-128s | minimal | inline | 8226 | 8228 | 8230 | 2 | empty |
| SLH-DSA-SHA2-128s | minimal | registered | 8194 | 8196 | 8198 | 2 | empty |
| SLH-DSA-SHA2-128s | operational | inline | 8292 | 8294 | 8304 | 4 | explicit |
| SLH-DSA-SHA2-128s | operational | registered | 8260 | 8262 | 8272 | 4 | explicit |
