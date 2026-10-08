//! Provenance capture for benchmark runs.
//!
//! Captured **before** any result file is written, so a run's own outputs are
//! never mistaken for pre-existing source modifications. Records the exact
//! source revision (and a recoverable patch when the tree is dirty), content
//! hashes of the source tree / manifest / lockfile / config, toolchain and host
//! identity, and the sampling settings.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

use crate::bench::BenchConfig;

fn cmd_output(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn git_revision() -> String {
    cmd_output("git", &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_string())
}

fn git_dirty() -> bool {
    cmd_output("git", &["status", "--porcelain"])
        .map(|s| !s.is_empty())
        .unwrap_or(true)
}

fn git_diff() -> Option<String> {
    let out = Command::new("git").args(["diff", "HEAD"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

/// SHA-256 of a byte buffer, using the host's `sha256sum` or `shasum`.
pub fn sha256_bytes(data: &[u8]) -> Option<String> {
    for (program, args) in [("sha256sum", vec![]), ("shasum", vec!["-a", "256"])] {
        let child = Command::new(program)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let Ok(mut child) = child else { continue };
        if let Some(mut stdin) = child.stdin.take() {
            if stdin.write_all(data).is_err() {
                continue;
            }
        }
        if let Ok(out) = child.wait_with_output() {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                if let Some(token) = text.split_whitespace().next() {
                    return Some(token.to_string());
                }
            }
        }
    }
    None
}

fn sha256_file(path: &str) -> Option<String> {
    std::fs::read(path).ok().and_then(|b| sha256_bytes(&b))
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
}

/// Content digest of all `src/**/*.rs` files, in sorted path order.
fn source_digest() -> Option<String> {
    let mut files = Vec::new();
    collect_rs_files(Path::new("src"), &mut files);
    files.sort();
    let mut buf = Vec::new();
    for path in files {
        buf.extend_from_slice(path.to_string_lossy().as_bytes());
        buf.push(0);
        buf.extend_from_slice(&std::fs::read(&path).ok()?);
        buf.push(0);
    }
    sha256_bytes(&buf)
}

/// Capture provenance. Call this **before** writing any result artifact.
pub fn capture(run_id: &str, config_path: &str, config: &BenchConfig) -> Value {
    let rustc = cmd_output("rustc", &["-Vv"]).unwrap_or_else(|| "unknown".to_string());
    let cargo = cmd_output("cargo", &["-V"]).unwrap_or_else(|| "unknown".to_string());
    let cpu = cmd_output("sysctl", &["-n", "machdep.cpu.brand_string"])
        .or_else(|| cmd_output("uname", &["-m"]))
        .unwrap_or_else(|| "unknown".to_string());

    json!({
        "run_id": run_id,
        "recorded_unix_s": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "git_revision": git_revision(),
        "working_tree_dirty": git_dirty(),
        "hashes": {
            "cargo_toml_sha256": sha256_file("Cargo.toml"),
            "cargo_lock_sha256": sha256_file("Cargo.lock"),
            "config_sha256": sha256_file(config_path),
            "source_tree_sha256": source_digest(),
        },
        "toolchain": { "rustc": rustc, "cargo": cargo },
        "host": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "cpu": cpu,
        },
        "build": { "profile": "release" },
        "sampling": {
            "warmup": config.warmup,
            "samples": config.samples,
            "budget_seconds": config.budget_seconds,
            "min_samples": config.min_samples,
            "operations": config.operations,
            "message_lengths": config.message_lengths,
            "schemes": config.schemes,
            "modes": config.modes,
            "input_classes": config.input_classes,
        },
        "note": "Host timings describe one implementation on one machine; not a universal ranking, not constant-time evidence, never converted to Solana compute units.",
    })
}

/// Save a recoverable patch of the working tree when it is dirty. Returns the
/// path written, or `None` for a clean tree.
pub fn write_dirty_patch(run_id: &str) -> Option<String> {
    if !git_dirty() {
        return None;
    }
    let diff = git_diff()?;
    let dir = Path::new("results/patches");
    if std::fs::create_dir_all(dir).is_err() {
        return None;
    }
    let path = dir.join(format!("{run_id}.patch"));
    std::fs::write(&path, diff).ok()?;
    Some(path.to_string_lossy().to_string())
}
