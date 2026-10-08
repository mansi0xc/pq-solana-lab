# Result provenance

## Current artifacts

| Artifact | Produced by | Evidence type |
| --- | --- | --- |
| `raw/full.csv`, `summaries/full.csv`, `full.json` | `cargo run --release -- benchmark --config configs/full.json` | measured (host wall-clock) |
| `raw/quick.csv`, `summaries/quick.csv`, `quick.json` | `cargo run --release -- benchmark --config configs/quick.json` | measured (host wall-clock) |
| `transport.json` | `cargo run --release -- transport` | serialized (bincode v0/legacy, `wincode` v1) |
| `transport-staged.json` | `cargo run --release -- transport` | modeled (components serialized, lifecycle not executed) |
| `tables/*.csv`, `tables/*.md` | `python3 scripts/report_tables.py generate` | derived from the above |
| `plots/*.png` | `python3 scripts/plot_results.py …` | derived from the above |
| `environment.json` | hand-written at M1 | metadata |

## Superseded artifacts (kept for provenance)

| Artifact | Why superseded |
| --- | --- |
| `transport.bincode-v1-superseded.json` | v1 rows used `bincode`, which is not the v1 wire format. Replaced by `transport.json` (v1 via `wincode`). |
| `transport-staged.chunk-model-superseded.json` | the staged model counted raw signature bytes with a 1-byte init payload and no protocol framing. Replaced by `transport-staged.json` (serialized `Init`/`Write`/`Seal`/`Authorize`). |

The raw and summary benchmark files were **not** superseded: the samples are
unchanged. The error was in the report's derived table, which took first-quartile
values and labeled them medians; the tables are now regenerated from the raw
samples (see `docs/progress.md`, correction batch 1).
