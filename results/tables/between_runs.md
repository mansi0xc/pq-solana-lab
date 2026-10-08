_Source: independent runs `full-r1`, `full-r2`, `full-r3` (`configs/full.json`), prepared/valid, 166-byte messages. Medians read from each run's summary; spread = (max − min) / min._

| Scheme | operation | full-r1 | full-r2 | full-r3 | spread |
| --- | --- | --- | --- | --- | --- |
| Ed25519 | keygen | 8.2 µs | 9.0 µs | 9.0 µs | 10.1% |
| Ed25519 | sign 166 B | 8.9 µs | 8.9 µs | 8.9 µs | 0.0% |
| Ed25519 | verify 166 B | 18.5 µs | 18.6 µs | 18.5 µs | 0.7% |
| Ed25519 | strict verify | 21.2 µs | 21.2 µs | 21.2 µs | 0.4% |
| Ed25519 | authorize | 24.1 µs | 24.1 µs | 24.2 µs | 0.2% |
| ML-DSA-44 | keygen | 76.3 µs | 76.4 µs | 76.4 µs | 0.1% |
| ML-DSA-44 | sign 166 B | 127.3 µs | 126.1 µs | 126.0 µs | 1.0% |
| ML-DSA-44 | verify 166 B | 40.1 µs | 40.2 µs | 40.3 µs | 0.4% |
| ML-DSA-44 | strict verify | 40.2 µs | 40.1 µs | 40.2 µs | 0.3% |
| ML-DSA-44 | authorize | 49.3 µs | 49.4 µs | 49.4 µs | 0.1% |
| ML-DSA-65 | keygen | 131.3 µs | 131.8 µs | 131.4 µs | 0.3% |
| ML-DSA-65 | sign 166 B | 227.1 µs | 227.4 µs | 227.4 µs | 0.1% |
| ML-DSA-65 | verify 166 B | 65.9 µs | 65.9 µs | 66.1 µs | 0.3% |
| ML-DSA-65 | strict verify | 66.0 µs | 65.9 µs | 66.0 µs | 0.1% |
| ML-DSA-65 | authorize | 80.0 µs | 80.1 µs | 80.0 µs | 0.2% |
| SLH-DSA-SHA2-128s | keygen | 65.9 ms | 66.2 ms | 66.4 ms | 0.8% |
| SLH-DSA-SHA2-128s | sign 166 B | 504.1 ms | 504.9 ms | 505.8 ms | 0.3% |
| SLH-DSA-SHA2-128s | verify 166 B | 490.8 µs | 514.9 µs | 502.0 µs | 4.9% |
| SLH-DSA-SHA2-128s | strict verify | 511.1 µs | 463.3 µs | 524.2 µs | 13.2% |
| SLH-DSA-SHA2-128s | authorize | 501.5 µs | 503.8 µs | 505.2 µs | 0.7% |
