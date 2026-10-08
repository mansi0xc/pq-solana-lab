//! Reproducible benchmark harness for signature primitives and complete
//! authorization.
//!
//! # Measurement boundaries
//!
//! Each operation is measured at a distinct boundary (see
//! `docs/methodology.md`):
//!
//! - `keygen` — fresh key generation per iteration.
//! - `sign` / `verify`, mode `prepared` — keys parsed once via
//!   `Scheme::prepare_*`; the timed loop calls the parsed key directly.
//! - `sign` / `verify`, mode `byte` — the serialized-byte adapter, which
//!   reconstructs the typed key (and, for ML-DSA, expands it) on every call.
//! - `verify_strict` — the strict-verification path the authorizer uses (for
//!   Ed25519 it additionally rejects weak keys and small-order components).
//! - `authorize` — complete authorization: registry lookup, intent decoding,
//!   policy checks (environment, expiry), strict verification, and atomic
//!   nonce/ledger update.
//!
//! # Observable timed operations
//!
//! The timed interval is `Instant::now()` → operation → `Instant::now()`. The
//! operation's *result* is consumed with `std::hint::black_box` and validated
//! **after** the second timestamp, so a failing or optimized-away operation can
//! never be reported as a fast success. Inputs are black-boxed too.
//!
//! Every timed case records the raw elapsed time and whether the result was the
//! expected one; summary rows carry `sample_count`, `valid_count`,
//! `budget_limited`, an explicit `status` (`ok` / `partial` / `failed` /
//! `skipped`) and a note. An empty or all-invalid case reports `null` times,
//! never a successful zero.
//!
//! # What is included / excluded
//!
//! - Included in timing: the operation call itself and whatever that call does
//!   internally (for ML-DSA/SLH-DSA signing that includes internal randomness
//!   acquisition and key expansion; `PreparedSigner::sign` returns a `Vec`, so
//!   output allocation is inside the interval).
//! - Excluded from timing but performed for validation: result checks,
//!   fixture construction, key/message preparation, warm-up.
//!
//! Cryptographic algorithms are not modified.

use std::hint::black_box;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::authorization::{AuthError, Authorizer, Environment, KeyRegistry, RegisteredKey};
use crate::crypto::{CryptoError, KeyPair, PreparedSigner, PreparedVerifier, Scheme};
use crate::intent::{WithdrawalIntent, INTENT_LEN};

/// Operations the harness can measure. `keygen` runs once per scheme; `sign`
/// and the verify operations run per (mode, message length); `authorize` runs
/// once per scheme.
pub const OPERATIONS: [&str; 5] = ["keygen", "sign", "verify", "verify_strict", "authorize"];
/// Key-handling modes for sign/verify.
pub const MODES: [&str; 2] = ["prepared", "byte"];
/// Verify input classes (fixtures are constructed, not inferred from verdicts).
pub const INPUT_CLASSES: [&str; 3] = ["valid", "corrupted", "invalid_len"];
/// Authorization classes: state-advancing successes and replay rejections.
pub const AUTHORIZE_CLASSES: [&str; 2] = ["valid", "replay"];

/// Fixed fixture parameters for the authorization boundary.
pub const AUTHORIZE_KEY_ID: u32 = 7;
pub const AUTHORIZE_NETWORK: [u8; 32] = [0x0a; 32];
pub const AUTHORIZE_PROGRAM: [u8; 32] = [0x0b; 32];
pub const AUTHORIZE_ASSET: [u8; 32] = [0x0c; 32];
pub const AUTHORIZE_RECIPIENT: [u8; 32] = [0x0d; 32];
pub const AUTHORIZE_SLOT: u64 = 500;
pub const AUTHORIZE_EXPIRY: u64 = 1000;
pub const AUTHORIZE_AMOUNT: u64 = 100;

/// Fixtures are signed in batches between timed samples so key-independent
/// signing cost is amortized outside the timed interval.
const AUTHORIZE_BATCH: usize = 64;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BenchConfig {
    pub run_id: String,
    pub warmup: usize,
    pub samples: usize,
    pub budget_seconds: u64,
    pub min_samples: usize,
    #[serde(default = "default_operations")]
    pub operations: Vec<String>,
    pub message_lengths: Vec<usize>,
    pub schemes: Vec<String>,
    pub modes: Vec<String>,
    pub input_classes: Vec<String>,
}

fn default_operations() -> Vec<String> {
    OPERATIONS.iter().map(|s| s.to_string()).collect()
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
    /// Whether the operation produced the expected result for this case.
    pub valid: bool,
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
    pub valid_count: usize,
    pub budget_limited: bool,
    pub median_ns: Option<u64>,
    pub q1_ns: Option<u64>,
    pub q3_ns: Option<u64>,
    pub p95_ns: Option<u64>,
    pub public_key_bytes: usize,
    pub signature_bytes: usize,
    pub status: String,
    pub note: String,
}

/// Configuration problems that must stop a run rather than silently produce a
/// misleading table.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    EmptyField(&'static str),
    ZeroField(&'static str),
    EmptyList(&'static str),
    UnknownValue { field: &'static str, value: String },
    InvalidRunId(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::EmptyField(field) => write!(f, "{field} must not be empty"),
            ConfigError::ZeroField(field) => write!(f, "{field} must be greater than zero"),
            ConfigError::EmptyList(field) => write!(f, "{field} must not be empty"),
            ConfigError::UnknownValue { field, value } => {
                write!(f, "unknown {field}: {value}")
            }
            ConfigError::InvalidRunId(id) => write!(
                f,
                "run_id {id:?} must be non-empty and contain only [A-Za-z0-9_-]"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Validate a configuration before running it.
pub fn validate(config: &BenchConfig) -> Result<(), ConfigError> {
    if config.run_id.is_empty()
        || !config
            .run_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ConfigError::InvalidRunId(config.run_id.clone()));
    }
    if config.samples == 0 {
        return Err(ConfigError::ZeroField("samples"));
    }
    if config.budget_seconds == 0 {
        return Err(ConfigError::ZeroField("budget_seconds"));
    }
    if config.min_samples == 0 {
        return Err(ConfigError::ZeroField("min_samples"));
    }
    if config.operations.is_empty() {
        return Err(ConfigError::EmptyList("operations"));
    }
    for op in &config.operations {
        if !OPERATIONS.contains(&op.as_str()) {
            return Err(ConfigError::UnknownValue {
                field: "operation",
                value: op.clone(),
            });
        }
    }
    if config.modes.is_empty() {
        return Err(ConfigError::EmptyList("modes"));
    }
    for mode in &config.modes {
        if !MODES.contains(&mode.as_str()) {
            return Err(ConfigError::UnknownValue {
                field: "mode",
                value: mode.clone(),
            });
        }
    }
    if config.message_lengths.is_empty() {
        return Err(ConfigError::EmptyList("message_lengths"));
    }
    if config.message_lengths.contains(&0) {
        return Err(ConfigError::ZeroField("message_length"));
    }
    if config.schemes.is_empty() {
        return Err(ConfigError::EmptyList("schemes"));
    }
    for scheme in &config.schemes {
        if scheme_from_name(scheme).is_none() {
            return Err(ConfigError::UnknownValue {
                field: "scheme",
                value: scheme.clone(),
            });
        }
    }
    if config.input_classes.is_empty() {
        return Err(ConfigError::EmptyList("input_classes"));
    }
    for class in &config.input_classes {
        if !INPUT_CLASSES.contains(&class.as_str()) {
            return Err(ConfigError::UnknownValue {
                field: "input_class",
                value: class.clone(),
            });
        }
    }
    Ok(())
}

/// Run the benchmark described by `config`. Returns raw samples and one
/// summary row per case, or a configuration error.
pub fn run(config: &BenchConfig) -> Result<(Vec<RawSample>, Vec<SummaryRow>), ConfigError> {
    validate(config)?;
    let mut raw = Vec::new();
    let mut summaries = Vec::new();

    for scheme_name in &config.schemes {
        let scheme = scheme_from_name(scheme_name)
            .unwrap_or_else(|| panic!("unknown scheme in config: {scheme_name}"));

        if config.operations.iter().any(|o| o == "keygen") {
            measure_keygen(config, &mut raw, &mut summaries, scheme);
        }

        let kp = scheme.keygen().expect("keygen");
        let signer = scheme.prepare_signer(&kp.secret).expect("prepare signer");
        let verifier = scheme
            .prepare_verifier(&kp.public)
            .expect("prepare verifier");

        for &mlen in &config.message_lengths {
            let msg = message_for(mlen);
            for mode in &config.modes {
                if config.operations.iter().any(|o| o == "sign") {
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
                }
                if config.operations.iter().any(|o| o == "verify") {
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
                        false,
                    );
                }
                if config.operations.iter().any(|o| o == "verify_strict") {
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
                        true,
                    );
                }
            }
        }

        if config.operations.iter().any(|o| o == "authorize") {
            measure_authorize(config, &mut raw, &mut summaries, scheme);
        }
    }

    Ok((raw, summaries))
}

fn scheme_from_name(name: &str) -> Option<Scheme> {
    match name {
        "ed25519" => Some(Scheme::Ed25519),
        "ml-dsa-44" => Some(Scheme::MlDsa44),
        "ml-dsa-65" => Some(Scheme::MlDsa65),
        "slh-dsa-sha2-128s" => Some(Scheme::SlhDsaSha2128s),
        _ => None,
    }
}

/// Deterministic message for a requested length. Length 166 is the actual
/// encoded withdrawal intent (see `docs/encoding.md`).
fn message_for(len: usize) -> Vec<u8> {
    match len {
        INTENT_LEN => WithdrawalIntent::new(
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

/// Time `f`, return `(elapsed_ns, black_box(result))`. The result is black-boxed
/// so the call cannot be optimized away; it is consumed after the timestamp.
#[inline(always)]
fn timed<T>(f: impl FnOnce() -> T) -> (u64, T) {
    let t0 = Instant::now();
    let out = f();
    let ns = t0.elapsed().as_nanos() as u64;
    (ns, black_box(out))
}

struct CaseStats {
    total: usize,
    valid: usize,
    times: Vec<u64>,
    budget_limited: bool,
}

#[allow(clippy::too_many_arguments)]
fn collect(
    config: &BenchConfig,
    raw: &mut Vec<RawSample>,
    scheme: Scheme,
    operation: &str,
    mode: &str,
    message_len: usize,
    input_class: &str,
    mut sample: impl FnMut(usize) -> (u64, bool),
) -> CaseStats {
    let budget = Duration::from_secs(config.budget_seconds);
    let start = Instant::now();
    let mut times = Vec::with_capacity(config.samples.min(4096));
    let mut valid = 0usize;
    let mut i = 0usize;
    while i < config.samples {
        let (elapsed_ns, ok) = sample(i);
        if ok {
            times.push(elapsed_ns);
            valid += 1;
        }
        raw.push(RawSample {
            run_id: config.run_id.clone(),
            scheme: scheme.name().to_string(),
            category: scheme.category_label().to_string(),
            operation: operation.to_string(),
            mode: mode.to_string(),
            message_len,
            input_class: input_class.to_string(),
            sample_index: i,
            elapsed_ns,
            valid: ok,
        });
        i += 1;
        if start.elapsed() > budget {
            break;
        }
    }
    CaseStats {
        total: i,
        valid,
        times,
        budget_limited: i < config.samples,
    }
}

fn measure_keygen(
    config: &BenchConfig,
    raw: &mut Vec<RawSample>,
    summaries: &mut Vec<SummaryRow>,
    scheme: Scheme,
) {
    for _ in 0..config.warmup {
        let _ = black_box(scheme.keygen());
    }
    let stats = collect(config, raw, scheme, "keygen", "n/a", 0, "n/a", |_| {
        let (ns, out) = timed(|| scheme.keygen());
        let ok = matches!(&out, Ok(kp) if keypair_well_formed(kp, scheme));
        (ns, ok)
    });
    summaries.push(summarize(config, scheme, "keygen", "n/a", 0, "n/a", stats));
}

fn keypair_well_formed(kp: &KeyPair, scheme: Scheme) -> bool {
    kp.scheme == scheme
        && kp.public.len() == scheme.public_key_len()
        && kp.secret.len() == scheme.secret_key_len()
}

#[allow(clippy::too_many_arguments)]
fn measure_sign(
    config: &BenchConfig,
    raw: &mut Vec<RawSample>,
    summaries: &mut Vec<SummaryRow>,
    scheme: Scheme,
    mode: &str,
    kp: &KeyPair,
    signer: &PreparedSigner,
    verifier: &PreparedVerifier,
    mlen: usize,
    msg: &[u8],
) {
    for _ in 0..config.warmup {
        match mode {
            "prepared" => {
                let _ = black_box(signer.sign(black_box(msg)));
            }
            "byte" => {
                let _ = black_box(scheme.sign(&kp.secret, black_box(msg)));
            }
            other => panic!("unknown mode: {other}"),
        }
    }
    let stats = collect(config, raw, scheme, "sign", mode, mlen, "valid", |_| {
        let (ns, out) = timed(|| match mode {
            "prepared" => signer.sign(black_box(msg)),
            "byte" => scheme.sign(&kp.secret, black_box(msg)),
            other => panic!("unknown mode: {other}"),
        });
        // Validate the signing output *outside* the measured interval.
        let ok = match &out {
            Ok(sig) => sig.len() == scheme.signature_len() && verifier.verify(msg, sig) == Ok(true),
            Err(_) => false,
        };
        (ns, ok)
    });
    summaries.push(summarize(
        config, scheme, "sign", mode, mlen, "valid", stats,
    ));
}

/// Expected verdict for a verify input class (the contract in `src/crypto.rs`).
fn verdict_matches(result: &Result<bool, CryptoError>, class: &str) -> bool {
    match class {
        "valid" => matches!(result, Ok(true)),
        "corrupted" => matches!(result, Ok(false)),
        "invalid_len" => result.is_err(),
        other => panic!("unknown input class: {other}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn measure_verify(
    config: &BenchConfig,
    raw: &mut Vec<RawSample>,
    summaries: &mut Vec<SummaryRow>,
    scheme: Scheme,
    mode: &str,
    kp: &KeyPair,
    signer: &PreparedSigner,
    verifier: &PreparedVerifier,
    mlen: usize,
    msg: &[u8],
    strict: bool,
) {
    let operation = if strict { "verify_strict" } else { "verify" };
    let base = signer.sign(msg).expect("fixture sign");

    for class in &config.input_classes {
        // Build the class-specific signature and confirm the intended verdict
        // once, outside the timed loop.
        let sig = match class.as_str() {
            "valid" => {
                assert_eq!(verifier.verify(msg, &base), Ok(true), "valid fixture");
                base.clone()
            }
            "corrupted" => {
                let mut c = base.clone();
                let mid = c.len() / 2;
                c[mid] ^= 0x01;
                assert_eq!(verifier.verify(msg, &c), Ok(false), "corrupted fixture");
                c
            }
            "invalid_len" => {
                let mut t = base.clone();
                t.pop();
                assert!(verifier.verify(msg, &t).is_err(), "invalid_len fixture");
                t
            }
            other => panic!("unknown input class: {other}"),
        };

        for _ in 0..config.warmup {
            let _ = black_box(run_verify(scheme, mode, strict, kp, verifier, msg, &sig));
        }
        let stats = collect(config, raw, scheme, operation, mode, mlen, class, |_| {
            let (ns, out) = timed(|| run_verify(scheme, mode, strict, kp, verifier, msg, &sig));
            let ok = verdict_matches(&out, class);
            (ns, ok)
        });
        summaries.push(summarize(
            config, scheme, operation, mode, mlen, class, stats,
        ));
    }
}

fn run_verify(
    scheme: Scheme,
    mode: &str,
    strict: bool,
    kp: &KeyPair,
    verifier: &PreparedVerifier,
    msg: &[u8],
    sig: &[u8],
) -> Result<bool, CryptoError> {
    match (mode, strict) {
        ("prepared", false) => verifier.verify(black_box(msg), black_box(sig)),
        ("prepared", true) => verifier.verify_strict(black_box(msg), black_box(sig)),
        ("byte", false) => scheme.verify(&kp.public, black_box(msg), black_box(sig)),
        ("byte", true) => scheme.verify_strict(&kp.public, black_box(msg), black_box(sig)),
        _ => panic!("unknown mode: {mode}"),
    }
}

/// A fresh authorizer with the scheme's key registered under `AUTHORIZE_KEY_ID`.
fn build_authorizer(scheme: Scheme) -> (Authorizer, KeyPair) {
    let kp = scheme.keygen().expect("keygen");
    let mut registry = KeyRegistry::default();
    registry
        .register(RegisteredKey {
            key_id: AUTHORIZE_KEY_ID,
            scheme,
            public_key: kp.public.clone(),
        })
        .expect("register key");
    let authorizer = Authorizer::new(
        Environment::new(AUTHORIZE_NETWORK, AUTHORIZE_PROGRAM),
        registry,
    );
    (authorizer, kp)
}

fn authorize_fixture(kp: &KeyPair, scheme: Scheme, nonce: u64) -> (Vec<u8>, Vec<u8>) {
    let intent = WithdrawalIntent::new(
        scheme,
        AUTHORIZE_KEY_ID,
        AUTHORIZE_NETWORK,
        AUTHORIZE_PROGRAM,
        AUTHORIZE_ASSET,
        AUTHORIZE_RECIPIENT,
        AUTHORIZE_AMOUNT,
        nonce,
        AUTHORIZE_EXPIRY,
    );
    let bytes = intent.encode().to_vec();
    let sig = scheme.sign(&kp.secret, &bytes).expect("sign fixture");
    (bytes, sig)
}

fn measure_authorize(
    config: &BenchConfig,
    raw: &mut Vec<RawSample>,
    summaries: &mut Vec<SummaryRow>,
    scheme: Scheme,
) {
    // `valid`: state-advancing successes. Fixtures are signed in batches
    // *between* timed samples, so signing is outside the timed interval and no
    // nonce is ever replayed.
    let (mut authorizer, kp) = build_authorizer(scheme);
    let mut next_nonce = 0u64;
    for _ in 0..config.warmup {
        let (b, s) = authorize_fixture(&kp, scheme, next_nonce);
        next_nonce += 1;
        authorizer
            .authorize(&b, &s, AUTHORIZE_SLOT)
            .expect("warmup authorize");
    }
    let budget = Duration::from_secs(config.budget_seconds);
    let start = Instant::now();
    let mut times = Vec::new();
    let mut valid = 0usize;
    let mut total = 0usize;
    let mut pending: std::collections::VecDeque<(Vec<u8>, Vec<u8>)> =
        std::collections::VecDeque::new();
    while total < config.samples {
        if pending.is_empty() {
            for _ in 0..AUTHORIZE_BATCH {
                pending.push_back(authorize_fixture(&kp, scheme, next_nonce));
                next_nonce += 1;
            }
        }
        let (bytes, sig) = pending.pop_front().expect("batch fixture");
        let (ns, out) =
            timed(|| authorizer.authorize(black_box(&bytes), black_box(&sig), AUTHORIZE_SLOT));
        let ok = out.is_ok();
        raw.push(RawSample {
            run_id: config.run_id.clone(),
            scheme: scheme.name().to_string(),
            category: scheme.category_label().to_string(),
            operation: "authorize".to_string(),
            mode: "authorizer".to_string(),
            message_len: INTENT_LEN,
            input_class: "valid".to_string(),
            sample_index: total,
            elapsed_ns: ns,
            valid: ok,
        });
        total += 1;
        if ok {
            times.push(ns);
            valid += 1;
        }
        if start.elapsed() > budget {
            break;
        }
    }
    summaries.push(summarize(
        config,
        scheme,
        "authorize",
        "authorizer",
        INTENT_LEN,
        "valid",
        CaseStats {
            total,
            valid,
            times,
            budget_limited: total < config.samples,
        },
    ));

    // `replay`: one accepted request, then repeated resubmission of the same
    // signature — a rejection workload, classified by construction.
    let (mut authorizer, kp) = build_authorizer(scheme);
    let (bytes, sig) = authorize_fixture(&kp, scheme, 0);
    authorizer
        .authorize(&bytes, &sig, AUTHORIZE_SLOT)
        .expect("first accept consumes nonce");
    for _ in 0..config.warmup {
        assert!(matches!(
            authorizer.authorize(&bytes, &sig, AUTHORIZE_SLOT),
            Err(AuthError::NonceMismatch { .. })
        ));
    }
    let stats = collect(
        config,
        raw,
        scheme,
        "authorize",
        "authorizer",
        INTENT_LEN,
        "replay",
        |_| {
            let (ns, out) =
                timed(|| authorizer.authorize(black_box(&bytes), black_box(&sig), AUTHORIZE_SLOT));
            let ok = matches!(out, Err(AuthError::NonceMismatch { .. }));
            (ns, ok)
        },
    );
    summaries.push(summarize(
        config,
        scheme,
        "authorize",
        "authorizer",
        INTENT_LEN,
        "replay",
        stats,
    ));
}

/// Status of a timed case from its total and valid sample counts. An empty or
/// all-invalid case is never reported as `ok`.
pub fn case_status(total: usize, valid: usize) -> &'static str {
    if total == 0 {
        "skipped"
    } else if valid == 0 {
        "failed"
    } else if valid < total {
        "partial"
    } else {
        "ok"
    }
}

fn summarize(
    config: &BenchConfig,
    scheme: Scheme,
    op: &str,
    mode: &str,
    mlen: usize,
    class: &str,
    stats: CaseStats,
) -> SummaryRow {
    let status = case_status(stats.total, stats.valid).to_string();
    let note = match status.as_str() {
        "skipped" => "no samples were collected".to_string(),
        "failed" => format!("all {} samples produced an unexpected result", stats.total),
        "partial" => format!(
            "{} of {} samples produced an unexpected result",
            stats.total - stats.valid,
            stats.total
        ),
        _ => String::new(),
    };

    let mut sorted = stats.times.clone();
    sorted.sort_unstable();
    let p95 = (sorted.len() >= config.min_samples).then(|| quantile(&sorted, 0.95).round() as u64);
    let stat = |q: f64| (!sorted.is_empty()).then(|| quantile(&sorted, q).round() as u64);

    SummaryRow {
        run_id: config.run_id.clone(),
        scheme: scheme.name().to_string(),
        category: scheme.category_label().to_string(),
        operation: op.to_string(),
        mode: mode.to_string(),
        message_len: mlen,
        input_class: class.to_string(),
        sample_count: stats.total,
        valid_count: stats.valid,
        budget_limited: stats.budget_limited,
        median_ns: stat(0.50),
        q1_ns: stat(0.25),
        q3_ns: stat(0.75),
        p95_ns: p95,
        public_key_bytes: scheme.public_key_len(),
        signature_bytes: scheme.signature_len(),
        status,
        note,
    }
}

/// Linear-interpolation quantile over sorted values (0.0 <= q <= 1.0).
/// This matches the common "linear" method; it is the documented project rule.
pub fn quantile(sorted: &[u64], q: f64) -> f64 {
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
