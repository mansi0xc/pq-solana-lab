//! Reproducible benchmark harness for primitive operations.
//!
//! Measurement boundaries (see `docs/methodology.md`):
//! - `mode = "prepared"`: key parsed once via `Scheme::prepare_*`; the timed
//!   loop calls the already-parsed key directly (no reconstruction).
//! - `mode = "byte"`: the timed loop goes through the serialized-byte adapter,
//!   including per-call key reconstruction and allocation.
//! - `operation = "keygen"`: fresh key generation per iteration.
//! - Complete authorization is measured separately (M3.2), not here.
//!
//! Valid fixtures are produced and verified *once, outside* the timed loop;
//! the loop only measures the operation under test. Setup and I/O are kept
//! out of timing loops.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::crypto::Scheme;
use crate::intent::WithdrawalIntent;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BenchConfig {
    pub run_id: String,
    pub warmup: usize,
    pub samples: usize,
    pub budget_seconds: u64,
    pub min_samples: usize,
    pub message_lengths: Vec<usize>,
    pub schemes: Vec<String>,
    pub modes: Vec<String>,
    pub input_classes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RawSample {
    pub run_id: String,
    pub scheme: String,
    pub category: String,
    pub operation: String,
    pub mode: String,
    pub message_len: usize,
    pub input_class: String,
    pub sample_index: usize,
    pub elapsed_ns: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SummaryRow {
    pub run_id: String,
    pub scheme: String,
    pub category: String,
    pub operation: String,
    pub mode: String,
    pub message_len: usize,
    pub input_class: String,
    pub sample_count: usize,
    pub median_ns: u64,
    pub q1_ns: u64,
    pub q3_ns: u64,
    pub p95_ns: Option<u64>,
    pub public_key_bytes: usize,
    pub signature_bytes: usize,
    pub status: String,
}

/// Run the benchmark described by `config`. Returns raw samples and one
/// summary row per (scheme, operation, mode, message length, input class).
pub fn run(config: &BenchConfig) -> (Vec<RawSample>, Vec<SummaryRow>) {
    let mut raw = Vec::new();
    let mut summaries = Vec::new();

    for scheme_name in &config.schemes {
        let scheme = scheme_from_name(scheme_name)
            .unwrap_or_else(|| panic!("unknown scheme in config: {scheme_name}"));

        measure_keygen(config, &mut raw, &mut summaries, scheme);

        let kp = scheme.keygen().expect("keygen");
        let signer = scheme.prepare_signer(&kp.secret).expect("prepare signer");
        let verifier = scheme
            .prepare_verifier(&kp.public)
            .expect("prepare verifier");

        for &mlen in &config.message_lengths {
            let msg = message_for(mlen);
            for mode in &config.modes {
                measure_sign(
                    config,
                    &mut raw,
                    &mut summaries,
                    scheme,
                    mode,
                    &kp,
                    &signer,
                    &verifier,
                    mlen,
                    &msg,
                );
                measure_verify(
                    config,
                    &mut raw,
                    &mut summaries,
                    scheme,
                    mode,
                    &kp,
                    &signer,
                    &verifier,
                    mlen,
                    &msg,
                    &config.input_classes,
                );
            }
        }
    }

    (raw, summaries)
}

fn scheme_from_name(name: &str) -> Option<Scheme> {
    match name {
        "ed25519" => Some(Scheme::Ed25519),
        "ml-dsa-44" => Some(Scheme::MlDsa44),
        _ => None,
    }
}

/// Deterministic message for a requested length. Length 166 is the actual
/// encoded withdrawal intent (see `docs/encoding.md`).
fn message_for(len: usize) -> Vec<u8> {
    match len {
        166 => WithdrawalIntent::new(
            Scheme::Ed25519,
            7,
            [0xab; 32],
            [0xcd; 32],
            [0x01; 32],
            [0x02; 32],
            100,
            0,
            1000,
        )
        .encode()
        .to_vec(),
        32 => vec![0xab; 32],
        _ => vec![0xcd; len],
    }
}

fn measure_keygen(
    config: &BenchConfig,
    raw: &mut Vec<RawSample>,
    summaries: &mut Vec<SummaryRow>,
    scheme: Scheme,
) {
    let class = "n/a";
    let mode = "n/a";
    let mut times = Vec::with_capacity(config.samples);
    for _ in 0..config.warmup {
        let _ = scheme.keygen();
    }
    let budget = Duration::from_secs(config.budget_seconds);
    let start = Instant::now();
    for i in 0..config.samples {
        let t0 = Instant::now();
        let _ = scheme.keygen().expect("keygen in loop");
        times.push(t0.elapsed().as_nanos() as u64);
        raw.push(RawSample {
            run_id: config.run_id.clone(),
            scheme: scheme.name().to_string(),
            category: scheme.category_label().to_string(),
            operation: "keygen".to_string(),
            mode: mode.to_string(),
            message_len: 0,
            input_class: class.to_string(),
            sample_index: i,
            elapsed_ns: *times.last().unwrap(),
        });
        if start.elapsed() > budget {
            break;
        }
    }
    summaries.push(summarize(config, scheme, "keygen", mode, 0, class, &times));
}

#[allow(clippy::too_many_arguments)]
fn measure_sign(
    config: &BenchConfig,
    raw: &mut Vec<RawSample>,
    summaries: &mut Vec<SummaryRow>,
    scheme: Scheme,
    mode: &str,
    kp: &crate::crypto::KeyPair,
    signer: &crate::crypto::PreparedSigner,
    verifier: &crate::crypto::PreparedVerifier,
    mlen: usize,
    msg: &[u8],
) {
    // Produce and validate one signature outside the timed loop.
    let fixture = signer.sign(msg).expect("fixture sign");
    assert!(verifier.verify(msg, &fixture).expect("fixture verify"));

    let mut times = Vec::with_capacity(config.samples);
    for _ in 0..config.warmup {
        match mode {
            "prepared" => {
                let _ = signer.sign(msg);
            }
            "byte" => {
                let _ = scheme.sign(&kp.secret, msg);
            }
            other => panic!("unknown mode: {other}"),
        }
    }
    let budget = Duration::from_secs(config.budget_seconds);
    let start = Instant::now();
    for i in 0..config.samples {
        let t0 = Instant::now();
        match mode {
            "prepared" => {
                let _ = signer.sign(msg);
            }
            "byte" => {
                let _ = scheme.sign(&kp.secret, msg);
            }
            other => panic!("unknown mode: {other}"),
        }
        times.push(t0.elapsed().as_nanos() as u64);
        raw.push(RawSample {
            run_id: config.run_id.clone(),
            scheme: scheme.name().to_string(),
            category: scheme.category_label().to_string(),
            operation: "sign".to_string(),
            mode: mode.to_string(),
            message_len: mlen,
            input_class: "valid".to_string(),
            sample_index: i,
            elapsed_ns: *times.last().unwrap(),
        });
        if start.elapsed() > budget {
            break;
        }
    }
    summaries.push(summarize(
        config, scheme, "sign", mode, mlen, "valid", &times,
    ));
}

#[allow(clippy::too_many_arguments)]
fn measure_verify(
    config: &BenchConfig,
    raw: &mut Vec<RawSample>,
    summaries: &mut Vec<SummaryRow>,
    scheme: Scheme,
    mode: &str,
    kp: &crate::crypto::KeyPair,
    signer: &crate::crypto::PreparedSigner,
    verifier: &crate::crypto::PreparedVerifier,
    mlen: usize,
    msg: &[u8],
    classes: &[String],
) {
    // Build the valid fixture once, outside the timed loop.
    let sig = signer.sign(msg).expect("fixture sign");
    assert!(verifier.verify(msg, &sig).expect("fixture verify ok"));

    for class in classes {
        // Build the class-specific signature and confirm the expected verdict
        // once, outside the timed loop.
        let sig = match class.as_str() {
            "valid" => {
                assert!(verifier.verify(msg, &sig).expect("valid verifies"));
                sig.clone()
            }
            "corrupted" => {
                let mut c = sig.clone();
                let mid = c.len() / 2;
                c[mid] ^= 0x01;
                assert_eq!(verifier.verify(msg, &c), Ok(false));
                c
            }
            "invalid_len" => {
                let mut t = sig.clone();
                t.pop();
                assert!(verifier.verify(msg, &t).is_err());
                t
            }
            other => panic!("unknown input class: {other}"),
        };

        let mut times = Vec::with_capacity(config.samples);
        for _ in 0..config.warmup {
            match mode {
                "prepared" => {
                    let _ = verifier.verify(msg, &sig);
                }
                "byte" => {
                    let _ = scheme.verify(&kp.public, msg, &sig);
                }
                other => panic!("unknown mode: {other}"),
            }
        }
        let budget = Duration::from_secs(config.budget_seconds);
        let start = Instant::now();
        for i in 0..config.samples {
            let t0 = Instant::now();
            match mode {
                "prepared" => {
                    let _ = verifier.verify(msg, &sig);
                }
                "byte" => {
                    let _ = scheme.verify(&kp.public, msg, &sig);
                }
                other => panic!("unknown mode: {other}"),
            }
            times.push(t0.elapsed().as_nanos() as u64);
            raw.push(RawSample {
                run_id: config.run_id.clone(),
                scheme: scheme.name().to_string(),
                category: scheme.category_label().to_string(),
                operation: "verify".to_string(),
                mode: mode.to_string(),
                message_len: mlen,
                input_class: class.to_string(),
                sample_index: i,
                elapsed_ns: *times.last().unwrap(),
            });
            if start.elapsed() > budget {
                break;
            }
        }
        summaries.push(summarize(
            config, scheme, "verify", mode, mlen, class, &times,
        ));
    }
}

fn summarize(
    config: &BenchConfig,
    scheme: Scheme,
    op: &str,
    mode: &str,
    mlen: usize,
    class: &str,
    times: &[u64],
) -> SummaryRow {
    let mut sorted = times.to_vec();
    sorted.sort_unstable();
    let p95 = (sorted.len() >= config.min_samples).then(|| quantile(&sorted, 0.95).round() as u64);
    SummaryRow {
        run_id: config.run_id.clone(),
        scheme: scheme.name().to_string(),
        category: scheme.category_label().to_string(),
        operation: op.to_string(),
        mode: mode.to_string(),
        message_len: mlen,
        input_class: class.to_string(),
        sample_count: sorted.len(),
        median_ns: quantile(&sorted, 0.50).round() as u64,
        q1_ns: quantile(&sorted, 0.25).round() as u64,
        q3_ns: quantile(&sorted, 0.75).round() as u64,
        p95_ns: p95,
        public_key_bytes: scheme.public_key_len(),
        signature_bytes: scheme.signature_len(),
        status: "ok".to_string(),
    }
}

/// Linear-interpolation quantile over sorted values (0.0 <= q <= 1.0).
/// This matches the common "linear" method; it is the documented project rule.
fn quantile(sorted: &[u64], q: f64) -> f64 {
    let n = sorted.len();
    if n == 0 {
        return 0.0;
    }
    if n == 1 {
        return sorted[0] as f64;
    }
    let pos = q * (n - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    let frac = pos - lo as f64;
    sorted[lo] as f64 * (1.0 - frac) + sorted[hi] as f64 * frac
}
