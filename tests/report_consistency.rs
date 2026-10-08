//! Fast consistency check: every committed summary statistic must equal the
//! value recomputed from the committed raw samples, using the same quantile
//! rule as `src/bench.rs`. A stale or hand-edited summary is reported here
//! rather than silently published.
//!
//! The check is skipped (with a note) when the committed result files are
//! absent, but fails loudly when they disagree.

use std::collections::HashMap;
use std::fs;

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

fn round_half_away(x: f64) -> u64 {
    x.round() as u64
}

fn stats(samples: &[u64]) -> (usize, u64, u64, u64) {
    let mut xs = samples.to_vec();
    xs.sort_unstable();
    (
        xs.len(),
        round_half_away(quantile(&xs, 0.50)),
        round_half_away(quantile(&xs, 0.25)),
        round_half_away(quantile(&xs, 0.75)),
    )
}

#[test]
fn summaries_match_raw_samples() {
    let raw_path = "results/raw/full.csv";
    let sum_path = "results/summaries/full.csv";
    if !std::path::Path::new(raw_path).exists() || !std::path::Path::new(sum_path).exists() {
        eprintln!("skipping: {raw_path} or {sum_path} not present");
        return;
    }

    let mut groups: HashMap<String, Vec<u64>> = HashMap::new();
    for (i, line) in fs::read_to_string(raw_path).unwrap().lines().enumerate() {
        if i == 0 {
            continue; // header
        }
        let f: Vec<&str> = line.split(',').collect();
        assert_eq!(f.len(), 9, "unexpected raw row: {line}");
        let key = format!("{}|{}|{}|{}|{}", f[1], f[3], f[4], f[5], f[6]);
        groups
            .entry(key)
            .or_default()
            .push(f[8].parse::<u64>().unwrap());
    }
    assert!(!groups.is_empty(), "no raw samples parsed from {raw_path}");

    let mut checked = 0usize;
    for (i, line) in fs::read_to_string(sum_path).unwrap().lines().enumerate() {
        if i == 0 {
            continue;
        }
        let f: Vec<&str> = line.split(',').collect();
        assert_eq!(f.len(), 15, "unexpected summary row: {line}");
        let key = format!("{}|{}|{}|{}|{}", f[1], f[3], f[4], f[5], f[6]);
        let samples = groups
            .get(&key)
            .unwrap_or_else(|| panic!("summary row has no raw samples: {key}"));
        let (n, median, q1, q3) = stats(samples);
        assert_eq!(n, f[7].parse::<usize>().unwrap(), "sample_count {key}");
        assert_eq!(median, f[8].parse::<u64>().unwrap(), "median {key}");
        assert_eq!(q1, f[9].parse::<u64>().unwrap(), "q1 {key}");
        assert_eq!(q3, f[10].parse::<u64>().unwrap(), "q3 {key}");
        checked += 1;
    }
    assert!(
        checked >= 100,
        "expected >=100 summary rows, checked {checked}"
    );
}
