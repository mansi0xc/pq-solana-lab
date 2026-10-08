//! Fast consistency check: every committed summary statistic must equal the
//! value recomputed from the committed raw samples, using the same quantile
//! rule as `src/bench.rs`. A stale or hand-edited summary is reported here
//! rather than silently published.
//!
//! Every `results/raw/<id>.csv` with a matching `results/summaries/<id>.csv`
//! is checked, so all recorded runs are covered. The check is skipped (with a
//! note) when no result files are present, but fails loudly on any mismatch.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Linear-interpolation quantile, identical to `src/bench.rs::quantile`.
fn quantile(sorted: &[u64], q: f64) -> f64 {
    let n = sorted.len();
    assert!(n > 0, "quantile of an empty sample set");
    if n == 1 {
        return sorted[0] as f64;
    }
    let pos = q * (n - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    let frac = pos - lo as f64;
    sorted[lo] as f64 * (1.0 - frac) + sorted[hi] as f64 * frac
}

/// Parse a CSV file into (header, rows), splitting each line into at most
/// `header.len()` fields so a trailing free-text column may contain separators.
fn parse_csv(path: &str) -> (Vec<String>, Vec<Vec<String>>) {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let mut lines = text.lines();
    let header: Vec<String> = lines
        .next()
        .expect("empty csv")
        .split(',')
        .map(|s| s.to_string())
        .collect();
    let n = header.len();
    let rows = lines
        .filter(|l| !l.is_empty())
        .map(|l| l.splitn(n, ',').map(|s| s.to_string()).collect())
        .collect();
    (header, rows)
}

fn col(header: &[String], name: &str) -> usize {
    header
        .iter()
        .position(|h| h == name)
        .unwrap_or_else(|| panic!("missing column {name}"))
}

fn get(row: &[String], idx: usize) -> &str {
    row.get(idx).map(String::as_str).unwrap_or("")
}

struct Group {
    total: usize,
    times: Vec<u64>,
}

fn check_pair(raw_path: &str, sum_path: &str) {
    let (raw_header, raw_rows) = parse_csv(raw_path);
    let (sum_header, sum_rows) = parse_csv(sum_path);

    let rc = |name: &str| col(&raw_header, name);
    let sc = |name: &str| col(&sum_header, name);
    let has_valid_raw = raw_header.iter().any(|h| h == "valid");

    let mut groups: HashMap<String, Group> = HashMap::new();
    for r in &raw_rows {
        let key = format!(
            "{}|{}|{}|{}|{}",
            get(r, rc("scheme")),
            get(r, rc("operation")),
            get(r, rc("mode")),
            get(r, rc("message_len")),
            get(r, rc("input_class"))
        );
        let elapsed = get(r, rc("elapsed_ns")).parse::<u64>().unwrap();
        let valid = if has_valid_raw {
            get(r, rc("valid")) == "1"
        } else {
            true
        };
        let g = groups.entry(key).or_insert(Group {
            total: 0,
            times: Vec::new(),
        });
        g.total += 1;
        if valid {
            g.times.push(elapsed);
        }
    }
    assert!(!groups.is_empty(), "no raw samples in {raw_path}");

    let has_valid_count = sum_header.iter().any(|h| h == "valid_count");
    let mut checked = 0usize;
    for s in &sum_rows {
        let key = format!(
            "{}|{}|{}|{}|{}",
            get(s, sc("scheme")),
            get(s, sc("operation")),
            get(s, sc("mode")),
            get(s, sc("message_len")),
            get(s, sc("input_class"))
        );
        let g = groups
            .get(&key)
            .unwrap_or_else(|| panic!("summary row has no raw samples: {key}"));

        let sample_count = get(s, sc("sample_count")).parse::<usize>().unwrap();
        assert_eq!(sample_count, g.total, "sample_count {key} in {sum_path}");

        if has_valid_count {
            let valid_count = get(s, sc("valid_count")).parse::<usize>().unwrap();
            assert_eq!(valid_count, g.times.len(), "valid_count {key}");
            let expected_status = if g.total == 0 {
                "skipped"
            } else if g.times.is_empty() {
                "failed"
            } else if g.times.len() < g.total {
                "partial"
            } else {
                "ok"
            };
            assert_eq!(get(s, sc("status")), expected_status, "status {key}");
        }

        let mut sorted = g.times.clone();
        sorted.sort_unstable();
        let median = get(s, sc("median_ns"));
        if sorted.is_empty() {
            assert!(median.is_empty(), "empty case must have no median: {key}");
        } else {
            assert_eq!(
                median.parse::<u64>().unwrap(),
                quantile(&sorted, 0.50).round() as u64,
                "median {key}"
            );
            assert_eq!(
                get(s, sc("q1_ns")).parse::<u64>().unwrap(),
                quantile(&sorted, 0.25).round() as u64,
                "q1 {key}"
            );
            assert_eq!(
                get(s, sc("q3_ns")).parse::<u64>().unwrap(),
                quantile(&sorted, 0.75).round() as u64,
                "q3 {key}"
            );
            let p95 = get(s, sc("p95_ns"));
            if !p95.is_empty() {
                assert_eq!(
                    p95.parse::<u64>().unwrap(),
                    quantile(&sorted, 0.95).round() as u64,
                    "p95 {key}"
                );
            }
        }
        checked += 1;
    }
    assert!(checked > 0, "no summary rows checked in {sum_path}");
}

#[test]
fn summaries_match_raw_samples_for_every_run() {
    let raw_dir = Path::new("results/raw");
    if !raw_dir.exists() {
        eprintln!("skipping: results/raw not present");
        return;
    }
    let mut pairs = 0usize;
    for entry in fs::read_dir(raw_dir).unwrap().flatten() {
        let raw_path = entry.path();
        if raw_path.extension().map(|e| e != "csv").unwrap_or(true) {
            continue;
        }
        let stem = raw_path.file_stem().unwrap().to_string_lossy().to_string();
        let sum_path = format!("results/summaries/{stem}.csv");
        if !Path::new(&sum_path).exists() {
            continue;
        }
        check_pair(raw_path.to_str().unwrap(), &sum_path);
        pairs += 1;
    }
    assert!(pairs >= 1, "expected at least one raw/summary pair");
    eprintln!("checked {pairs} run(s)");
}
