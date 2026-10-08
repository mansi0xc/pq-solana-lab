_Source: run `full` (`configs/full.json`), mode `prepared`, input class `valid`, 166-byte messages; raw `results/raw/full.csv`. Medians recomputed from raw samples._

| Scheme | keygen | sign (166 B) | verify (166 B) | pubkey (B) | signature (B) |
| --- | --- | --- | --- | --- | --- |
| Ed25519 | 10.9 µs | 8.8 µs | 18.7 µs | 32 | 64 |
| ML-DSA-44 | 76.6 µs | 127.6 µs | 40.3 µs | 1312 | 2420 |
| ML-DSA-65 | 130.8 µs | 228.8 µs | 66.0 µs | 1952 | 3309 |
| SLH-DSA-SHA2-128s | 66.6 ms (n=889) | 511.0 ms (n=116) | 581.8 µs | 32 | 7856 |
