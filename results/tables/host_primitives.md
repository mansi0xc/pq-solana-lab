_Source: run `full-r1` (`configs/full.json`), mode `prepared`, input class `valid`, 166-byte messages; raw `results/raw/full-r1.csv`. Medians recomputed from raw samples._

| Scheme | keygen | sign (166 B) | verify (166 B) | pubkey (B) | signature (B) |
| --- | --- | --- | --- | --- | --- |
| Ed25519 | 8.2 µs | 8.9 µs | 18.5 µs | 32 | 64 |
| ML-DSA-44 | 76.3 µs | 127.3 µs | 40.1 µs | 1312 | 2420 |
| ML-DSA-65 | 131.3 µs | 227.1 µs | 65.9 µs | 1952 | 3309 |
| SLH-DSA-SHA2-128s | 65.9 ms (n=910) | 504.1 ms (n=119) | 490.8 µs | 32 | 7856 |
