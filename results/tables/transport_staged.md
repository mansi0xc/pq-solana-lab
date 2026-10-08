_Source: `results/transport-staged.json` — a **model** (each transaction serialized, lifecycle not executed). Includes init/write/seal/authorize transaction bytes and session metadata + signature storage; excludes key registration, account rent, cleanup, and compute._

| Scheme | Format | signature (B) | storage (B) | chunk (B) | chunks | transactions | total transport (B) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Ed25519 | legacy | 64 | 141 | 957 | 1 | 4 | 1396 |
| Ed25519 | v0 | 64 | 141 | 955 | 1 | 4 | 1404 |
| Ed25519 | v1 | 64 | 141 | 3809 | 1 | 4 | 1447 |
| ML-DSA-44 | legacy | 2420 | 2497 | 957 | 3 | 6 | 4303 |
| ML-DSA-44 | v0 | 2420 | 2497 | 955 | 3 | 6 | 4315 |
| ML-DSA-44 | v1 | 2420 | 2497 | 3809 | 1 | 4 | 3803 |
| ML-DSA-65 | legacy | 3309 | 3386 | 957 | 4 | 7 | 5467 |
| ML-DSA-65 | v0 | 3309 | 3386 | 955 | 4 | 7 | 5481 |
| ML-DSA-65 | v1 | 3309 | 3386 | 3809 | 1 | 4 | 4692 |
| SLH-DSA-SHA2-128s | legacy | 7856 | 7933 | 957 | 9 | 12 | 11389 |
| SLH-DSA-SHA2-128s | v0 | 7856 | 7933 | 955 | 9 | 12 | 11413 |
| SLH-DSA-SHA2-128s | v1 | 7856 | 7933 | 3809 | 3 | 6 | 9813 |
