_Source: run `full` (`configs/full.json`), mode `prepared`, input class `valid`, 166-byte messages; raw `results/raw/full.csv`. Quartiles recomputed from raw samples (linear interpolation); p95 omitted below 200 samples._

| Scheme | operation | n | median | Q1 | Q3 | p95 |
| --- | --- | --- | --- | --- | --- | --- |
| Ed25519 | keygen | 1000 | 10.9 µs | 10.8 µs | 11.4 µs | 16.0 µs |
| Ed25519 | sign | 1000 | 8.8 µs | 8.3 µs | 8.9 µs | 9.4 µs |
| Ed25519 | verify | 1000 | 18.7 µs | 18.6 µs | 18.7 µs | 18.9 µs |
| ML-DSA-44 | keygen | 1000 | 76.6 µs | 76.3 µs | 76.8 µs | 78.6 µs |
| ML-DSA-44 | sign | 1000 | 127.6 µs | 95.1 µs | 223.1 µs | 444.6 µs |
| ML-DSA-44 | verify | 1000 | 40.3 µs | 40.2 µs | 40.4 µs | 42.8 µs |
| ML-DSA-65 | keygen | 1000 | 130.8 µs | 130.5 µs | 131.3 µs | 135.8 µs |
| ML-DSA-65 | sign | 1000 | 228.8 µs | 141.7 µs | 361.1 µs | 676.3 µs |
| ML-DSA-65 | verify | 1000 | 66.0 µs | 65.8 µs | 66.2 µs | 71.8 µs |
| SLH-DSA-SHA2-128s | keygen | 889 | 66.6 ms | 66.4 ms | 67.4 ms | 71.7 ms |
| SLH-DSA-SHA2-128s | sign | 116 | 511.0 ms | 508.8 ms | 516.4 ms | — |
| SLH-DSA-SHA2-128s | verify | 1000 | 581.8 µs | 561.1 µs | 607.7 µs | 692.3 µs |
