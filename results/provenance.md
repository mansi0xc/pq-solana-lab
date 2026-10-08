# Result provenance

## Current artifacts (Batch 2 campaign)

| Artifact | Produced by | Evidence type |
| --- | --- | --- |
| `raw/full-r1.csv`, `summaries/full-r1.csv`, `full-r1.json`, `patches/full-r1.patch` | `cargo run --release -- benchmark --config configs/full.json --run-id full-r1` | measured (host wall-clock) |
| `raw/full-r2.csv`, `summaries/full-r2.csv`, `full-r2.json`, `patches/full-r2.patch` | same, `--run-id full-r2` | measured (host wall-clock) |
| `raw/full-r3.csv`, `summaries/full-r3.csv`, `full-r3.json`, `patches/full-r3.patch` | same, `--run-id full-r3` | measured (host wall-clock) |
| `transport.json` | `cargo run --release -- transport` | serialized (bincode legacy/v0, `wincode` v1) |
| `transport-staged.json` | `cargo run --release -- transport` | modeled (components serialized, lifecycle not executed) |
| `tables/*.csv`, `tables/*.md` | `python3 scripts/report_tables.py generate` | derived from the above |
| `plots/*.png` | `python3 scripts/plot_results.py …` | derived from the above |
| `environment.json` | hand-written at M1, updated for `wincode` | metadata |

The three `full-r*` runs are independent repetitions of the same frozen config,
with unique run identifiers and per-run provenance recorded **before** outputs
were written. The report's tables are generated from `full-r1`; §5.6 shows
between-run variability across all three.

## Superseded artifacts (kept for provenance)

| Artifact | Why superseded |
| --- | --- |
| `raw/full.csv`, `summaries/full.csv`, `full.json` | produced by the pre-review harness (no `verify_strict`/`authorize` boundaries, no result validation, no `valid` column) on 2026-10-06. Kept as the historical M6 run; superseded by the `full-r*` campaign. |
| `raw/quick.csv`, `summaries/quick.csv`, `quick.json` | historical M3 pilot from the same pre-review harness. Kept. |
| `transport.bincode-v1-superseded.json` | v1 rows used `bincode`, which is not the v1 wire format. Replaced by `transport.json` (v1 via `wincode`). |
| `transport-staged.chunk-model-superseded.json` | the staged model counted raw signature bytes with a 1-byte init payload and no protocol framing. Replaced by `transport-staged.json`. |

The historical raw and summary files were **not** rewritten: their samples are
unchanged and the report's earlier error was in a derived table, not in the
samples. `tests/report_consistency.rs` checks every raw/summary pair (old and
new schema) against the raw samples.
