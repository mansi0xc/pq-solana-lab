_Source: run `full-r1` (`configs/full.json`), 166-byte messages; medians recomputed from `results/raw/full-r1.csv`. `authorize` includes registry lookup, intent decoding, environment/expiry policy, strict verification, and the atomic nonce/ledger update; the reject row is a replay workload._

| Scheme | verify prepared | verify byte | strict verify prepared | strict verify byte | authorize (accept) | authorize (replay reject) |
| --- | --- | --- | --- | --- | --- | --- |
| Ed25519 | 18.5 µs | 21.2 µs | 21.2 µs | 24.0 µs | 24.1 µs | 23.4 µs |
| ML-DSA-44 | 40.1 µs | 49.0 µs | 40.2 µs | 49.1 µs | 49.3 µs | 49.2 µs |
| ML-DSA-65 | 65.9 µs | 79.5 µs | 66.0 µs | 79.3 µs | 80.0 µs | 79.6 µs |
| SLH-DSA-SHA2-128s | 490.8 µs | 466.7 µs | 511.1 µs | 507.7 µs | 501.5 µs | 490.8 µs |
