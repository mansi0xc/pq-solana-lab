//! Tests for the benchmark harness: statistics, configuration validation,
//! failure/empty handling, output consistency, and the authorization boundary.

use std::collections::HashMap;

use pq_solana_lab::bench::{
    case_status, quantile, run, validate, BenchConfig, ConfigError, RawSample, SummaryRow,
};

fn base_config(run_id: &str) -> BenchConfig {
    BenchConfig {
        run_id: run_id.to_string(),
        warmup: 2,
        samples: 30,
        budget_seconds: 30,
        min_samples: 200,
        operations: vec![
            "keygen".into(),
            "sign".into(),
            "verify".into(),
            "verify_strict".into(),
            "authorize".into(),
        ],
        message_lengths: vec![166],
        schemes: vec!["ed25519".into()],
        modes: vec!["prepared".into()],
        input_classes: vec!["valid".into(), "corrupted".into(), "invalid_len".into()],
    }
}

#[test]
fn quantile_matches_the_linear_reference() {
    let xs = [1u64, 2, 3, 4];
    assert_eq!(quantile(&xs, 0.0), 1.0);
    assert_eq!(quantile(&xs, 0.5), 2.5);
    assert_eq!(quantile(&xs, 0.25), 1.75);
    assert_eq!(quantile(&xs, 1.0), 4.0);
    assert_eq!(quantile(&[7], 0.9), 7.0);
}

#[test]
fn case_status_never_calls_empty_or_failed_ok() {
    assert_eq!(case_status(0, 0), "skipped");
    assert_eq!(case_status(10, 0), "failed");
    assert_eq!(case_status(10, 4), "partial");
    assert_eq!(case_status(10, 10), "ok");
}

#[test]
fn validate_rejects_bad_configurations() {
    let mut c = base_config("t");
    c.schemes = vec!["dsa-99".into()];
    assert!(matches!(
        validate(&c),
        Err(ConfigError::UnknownValue { .. })
    ));

    let mut c = base_config("t");
    c.modes = vec!["turbo".into()];
    assert!(matches!(
        validate(&c),
        Err(ConfigError::UnknownValue { .. })
    ));

    let mut c = base_config("t");
    c.operations = vec!["teleport".into()];
    assert!(matches!(
        validate(&c),
        Err(ConfigError::UnknownValue { .. })
    ));

    let mut c = base_config("t");
    c.input_classes = vec!["maybe".into()];
    assert!(matches!(
        validate(&c),
        Err(ConfigError::UnknownValue { .. })
    ));

    let mut c = base_config("t");
    c.samples = 0;
    assert!(matches!(
        validate(&c),
        Err(ConfigError::ZeroField("samples"))
    ));

    let mut c = base_config("t");
    c.budget_seconds = 0;
    assert!(matches!(
        validate(&c),
        Err(ConfigError::ZeroField("budget_seconds"))
    ));

    let mut c = base_config("t");
    c.message_lengths = vec![];
    assert!(matches!(
        validate(&c),
        Err(ConfigError::EmptyList("message_lengths"))
    ));

    let mut c = base_config("t");
    c.run_id = "bad id".into();
    assert!(matches!(validate(&c), Err(ConfigError::InvalidRunId(_))));

    assert!(validate(&base_config("t")).is_ok());
}

#[test]
fn operations_default_when_absent_from_json() {
    let json = r#"{
        "run_id": "t", "warmup": 1, "samples": 5, "budget_seconds": 5,
        "min_samples": 2, "message_lengths": [32], "schemes": ["ed25519"],
        "modes": ["prepared"], "input_classes": ["valid"]
    }"#;
    let c: BenchConfig = serde_json::from_str(json).unwrap();
    assert_eq!(c.operations.len(), 5);
    assert!(validate(&c).is_ok());
}

#[test]
fn run_rejects_invalid_config_without_panicking() {
    let mut c = base_config("t");
    c.schemes = vec!["nope".into()];
    assert!(run(&c).is_err());
}

#[test]
fn run_output_is_internally_consistent() {
    let c = base_config("test-consistency");
    let (raw, summaries) = run(&c).expect("valid config");
    assert!(!raw.is_empty() && !summaries.is_empty());

    // Rows are only produced for the requested operations.
    let ops: std::collections::HashSet<&str> =
        summaries.iter().map(|s| s.operation.as_str()).collect();
    for expected in ["keygen", "sign", "verify", "verify_strict", "authorize"] {
        assert!(ops.contains(expected), "missing {expected}");
    }

    // Every case succeeded and every raw sample was valid.
    for r in &summaries {
        assert_eq!(r.status, "ok", "{r:?}");
        assert_eq!(r.valid_count, r.sample_count, "{r:?}");
        assert!(r.median_ns.is_some(), "{r:?}");
        assert!(r.p95_ns.is_none(), "p95 needs >=200 samples: {r:?}");
    }
    assert!(raw.iter().all(|r| r.valid), "all raw samples valid");

    // Recompute each summary's statistics from the raw rows it names.
    let mut groups: HashMap<String, Vec<u64>> = HashMap::new();
    for r in &raw {
        let key = format!(
            "{}|{}|{}|{}|{}",
            r.scheme, r.operation, r.mode, r.message_len, r.input_class
        );
        if r.valid {
            groups.entry(key).or_default().push(r.elapsed_ns);
        }
    }
    for s in &summaries {
        let key = format!(
            "{}|{}|{}|{}|{}",
            s.scheme, s.operation, s.mode, s.message_len, s.input_class
        );
        let xs = &groups[&key];
        let mut sorted = xs.clone();
        sorted.sort_unstable();
        assert_eq!(s.sample_count, count_raw(&raw, s), "{s:?}");
        assert_eq!(s.median_ns.unwrap(), quantile(&sorted, 0.50).round() as u64);
        assert_eq!(s.q1_ns.unwrap(), quantile(&sorted, 0.25).round() as u64);
        assert_eq!(s.q3_ns.unwrap(), quantile(&sorted, 0.75).round() as u64);
    }

    // Raw row count equals the sum of case sample counts.
    let total: usize = summaries.iter().map(|s| s.sample_count).sum();
    assert_eq!(total, raw.len());
}

fn count_raw(raw: &[RawSample], s: &SummaryRow) -> usize {
    raw.iter()
        .filter(|r| {
            r.scheme == s.scheme
                && r.operation == s.operation
                && r.mode == s.mode
                && r.message_len == s.message_len
                && r.input_class == s.input_class
        })
        .count()
}

#[test]
fn authorize_uses_valid_state_progression_and_rejects_replay() {
    let mut c = base_config("test-authorize");
    c.operations = vec!["authorize".into()];
    c.samples = 40;
    let (raw, summaries) = run(&c).expect("valid config");

    let valid = summaries
        .iter()
        .find(|s| s.input_class == "valid")
        .expect("valid authorize row");
    let replay = summaries
        .iter()
        .find(|s| s.input_class == "replay")
        .expect("replay authorize row");

    // State advances: every accepted request used the next nonce, so all
    // samples are successes (a repeated nonce would be a rejection workload).
    assert_eq!(valid.status, "ok", "{valid:?}");
    assert_eq!(valid.valid_count, valid.sample_count);
    assert_eq!(replay.status, "ok", "{replay:?}");
    assert_eq!(replay.valid_count, replay.sample_count);
    assert!(raw.iter().all(|r| r.valid));
}

#[test]
fn budget_limited_cases_are_flagged() {
    let mut c = base_config("test-budget");
    c.operations = vec!["sign".into()];
    c.message_lengths = vec![32];
    c.warmup = 0;
    c.samples = 5_000_000;
    c.budget_seconds = 1;
    let (_raw, summaries) = run(&c).expect("valid config");
    let sign = summaries.iter().find(|s| s.operation == "sign").unwrap();
    assert!(sign.budget_limited, "{sign:?}");
    assert!(sign.sample_count < 5_000_000);
    assert_eq!(sign.status, "ok");
}
