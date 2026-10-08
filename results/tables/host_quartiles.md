_Source: run `full-r1` (`configs/full.json`), mode `prepared`, input class `valid`, 166-byte messages; raw `results/raw/full-r1.csv`. Quartiles recomputed from raw samples (linear interpolation); p95 omitted below 200 samples._

| Scheme | operation | n | median | Q1 | Q3 | p95 |
| --- | --- | --- | --- | --- | --- | --- |
| Ed25519 | keygen | 1000 | 8.2 µs | 8.2 µs | 8.3 µs | 9.3 µs |
| Ed25519 | sign | 1000 | 8.9 µs | 8.9 µs | 8.9 µs | 9.0 µs |
| Ed25519 | verify | 1000 | 18.5 µs | 18.5 µs | 18.6 µs | 18.7 µs |
| ML-DSA-44 | keygen | 1000 | 76.3 µs | 76.0 µs | 76.6 µs | 78.8 µs |
| ML-DSA-44 | sign | 1000 | 127.3 µs | 93.8 µs | 223.0 µs | 412.9 µs |
| ML-DSA-44 | verify | 1000 | 40.1 µs | 40.0 µs | 40.2 µs | 40.9 µs |
| ML-DSA-65 | keygen | 1000 | 131.3 µs | 130.9 µs | 131.9 µs | 310.1 µs |
| ML-DSA-65 | sign | 1000 | 227.1 µs | 140.3 µs | 357.9 µs | 705.7 µs |
| ML-DSA-65 | verify | 1000 | 65.9 µs | 65.7 µs | 66.0 µs | 66.6 µs |
| SLH-DSA-SHA2-128s | keygen | 910 | 65.9 ms | 65.6 ms | 66.1 ms | 66.5 ms |
| SLH-DSA-SHA2-128s | sign | 119 | 504.1 ms | 503.7 ms | 504.4 ms | — |
| SLH-DSA-SHA2-128s | verify | 1000 | 490.8 µs | 490.3 µs | 493.0 µs | 498.2 µs |
