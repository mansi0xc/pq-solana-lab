use std::io::Write;

use pq_solana_lab::authorization::{Authorizer, Environment, KeyRegistry, RegisteredKey};
use pq_solana_lab::bench::{self, BenchConfig, RawSample, SummaryRow};
use pq_solana_lab::crypto::Scheme;
use pq_solana_lab::intent::WithdrawalIntent;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("demo") => run_demo(),
        Some("benchmark") => run_benchmark(&args[2..]),
        Some("transport") => run_transport(),
        Some(other) => {
            eprintln!("unknown command: {other}");
            eprintln!("usage: pq-solana-lab demo | benchmark --config <path>");
            std::process::exit(2);
        }
        None => {
            eprintln!("usage: pq-solana-lab demo | benchmark --config <path>");
            std::process::exit(2);
        }
    }
}

fn run_transport() {
    let rows = pq_solana_lab::transport::analyze();
    let path = "results/transport.json";
    std::fs::write(
        path,
        serde_json::to_string_pretty(&rows).expect("serialize transport"),
    )
    .unwrap_or_else(|e| panic!("write {path}: {e}"));
    println!("scheme              format  placement  sig      pk      total   limit  headroom");
    for r in &rows {
        println!(
            "{:<18} {:<7} {:<10} {:>7} {:>7} {:>7} {:>6} {:>8}",
            r.scheme,
            r.format,
            r.key_placement,
            r.signature_bytes,
            r.public_key_bytes,
            r.total_bytes,
            r.applicable_limit,
            r.headroom
        );
    }
    println!("wrote {path}");
}

fn run_benchmark(args: &[String]) {
    let config_path = args
        .iter()
        .position(|a| a == "--config")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .or_else(|| {
            args.iter()
                .find_map(|a| a.strip_prefix("--config=").map(String::from))
        })
        .unwrap_or_else(|| "configs/quick.json".to_string());
    let config: BenchConfig = serde_json::from_str(
        &std::fs::read_to_string(&config_path)
            .unwrap_or_else(|e| panic!("read config {config_path}: {e}")),
    )
    .unwrap_or_else(|e| panic!("parse config {config_path}: {e}"));

    let (raw, summaries) = bench::run(&config);

    std::fs::create_dir_all("results/raw").expect("mkdir results/raw");
    std::fs::create_dir_all("results/summaries").expect("mkdir results/summaries");
    write_raw_csv(&format!("results/raw/{}.csv", config.run_id), &raw);
    write_summary_csv(
        &format!("results/summaries/{}.csv", config.run_id),
        &summaries,
    );
    write_metadata(&config);

    print_summary_table(&summaries);
}

fn write_raw_csv(path: &str, rows: &[RawSample]) {
    let mut out = Vec::new();
    writeln!(
        out,
        "run_id,scheme,category,operation,mode,message_len,input_class,sample_index,elapsed_ns"
    )
    .unwrap();
    for r in rows {
        writeln!(
            out,
            "{},{},{},{},{},{},{},{},{}",
            r.run_id,
            r.scheme,
            csv(&r.category),
            r.operation,
            r.mode,
            r.message_len,
            r.input_class,
            r.sample_index,
            r.elapsed_ns
        )
        .unwrap();
    }
    std::fs::write(path, out).unwrap_or_else(|e| panic!("write {path}: {e}"));
}

fn write_summary_csv(path: &str, rows: &[SummaryRow]) {
    let mut out = Vec::new();
    writeln!(
        out,
        "run_id,scheme,category,operation,mode,message_len,input_class,sample_count,median_ns,q1_ns,q3_ns,p95_ns,public_key_bytes,signature_bytes,status"
    )
    .unwrap();
    for r in rows {
        let p95 = r.p95_ns.map(|v| v.to_string()).unwrap_or_default();
        writeln!(
            out,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            r.run_id,
            r.scheme,
            csv(&r.category),
            r.operation,
            r.mode,
            r.message_len,
            r.input_class,
            r.sample_count,
            r.median_ns,
            r.q1_ns,
            r.q3_ns,
            p95,
            r.public_key_bytes,
            r.signature_bytes,
            r.status
        )
        .unwrap();
    }
    std::fs::write(path, out).unwrap_or_else(|e| panic!("write {path}: {e}"));
}

fn write_metadata(config: &BenchConfig) {
    let git_rev = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let dirty = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(true);
    let meta = serde_json::json!({
        "run_id": config.run_id,
        "recorded_unix_s": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "git_revision": git_rev,
        "working_tree_dirty": dirty,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "config": config,
        "note": "Host timings describe one implementation on one machine; not a universal ranking, not constant-time evidence, never converted to Solana compute units.",
    });
    let path = format!("results/{}.json", config.run_id);
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&meta).expect("serialize metadata"),
    )
    .unwrap_or_else(|e| panic!("write {path}: {e}"));
}

fn print_summary_table(rows: &[SummaryRow]) {
    println!("summary (median ns):");
    for r in rows {
        println!(
            "  {:<10} {:<8} {:<9} len={:<4} class={:<11} n={:<5} median={}",
            r.scheme,
            r.operation,
            r.mode,
            r.message_len,
            r.input_class,
            r.sample_count,
            r.median_ns
        );
    }
}

/// Minimal CSV field quoting for fields that might contain separators.
fn csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn run_demo() {
    println!("pq-solana-lab demo (secret keys are never printed)");
    println!();
    crypto_section();
    println!();
    authorization_section();
}

fn crypto_section() {
    println!("== Signature adapters ==");
    let msg = b"pq-solana-lab demo message: withdraw 100 base units";
    for scheme in Scheme::ALL {
        let kp = scheme.keygen().expect("keygen");
        let sig = scheme.sign(&kp.secret, msg).expect("sign");
        let ok = scheme.verify(&kp.public, msg, &sig).expect("verify");

        let mut altered = msg.to_vec();
        altered[0] ^= 0x01;
        let altered_ok = scheme.verify(&kp.public, &altered, &sig).expect("verify");

        let other = scheme.keygen().expect("keygen");
        let wrong_key_ok = scheme.verify(&other.public, msg, &sig).expect("verify");

        println!("scheme:              {}", scheme.name());
        println!("  category:          {}", scheme.category_label());
        println!("  public key:        {} bytes", kp.public.len());
        println!("  signature:         {} bytes", sig.len());
        println!("  sign+serialize+verify: {ok}");
        println!("  altered message rejected: {}", !altered_ok);
        println!("  wrong key rejected:       {}", !wrong_key_ok);

        assert!(ok && !altered_ok && !wrong_key_ok, "crypto demo invariant");
    }
}

fn authorization_section() {
    println!("== Withdrawal authorization (mock assets, in-memory state) ==");

    let network_id = [0xab; 32];
    let program_id = [0xcd; 32];
    let asset = [0x01; 32];
    let recipient = [0x02; 32];

    let kp = Scheme::MlDsa44.keygen().expect("keygen");
    let mut registry = KeyRegistry::default();
    registry
        .register(RegisteredKey {
            key_id: 7,
            scheme: Scheme::MlDsa44,
            public_key: kp.public.clone(),
        })
        .expect("register key");
    let mut authorizer = Authorizer::new(Environment::new(network_id, program_id), registry);

    let intent = WithdrawalIntent::new(
        Scheme::MlDsa44,
        7,
        network_id,
        program_id,
        asset,
        recipient,
        100,
        0,
        1000,
    );
    let bytes = intent.encode();
    let sig = Scheme::MlDsa44.sign(&kp.secret, &bytes).expect("sign");

    println!("registered key id 7 (ml-dsa-44)");

    let rec = authorizer
        .authorize(&bytes, &sig, 500)
        .expect("valid request");
    assert_eq!(rec.asset, asset);
    println!(
        "valid request:       ACCEPTED (nonce {} consumed, amount {}, asset preserved, slot {})",
        rec.nonce, rec.amount, rec.at_slot
    );

    match authorizer.authorize(&bytes, &sig, 500) {
        Err(e) => println!("replay:              REJECTED ({e})"),
        Ok(_) => panic!("replay must be rejected"),
    }

    let mut tampered = intent.clone();
    tampered.amount = 101;
    match authorizer.authorize(&tampered.encode(), &sig, 500) {
        Err(e) => println!("tampered amount:     REJECTED ({e})"),
        Ok(_) => panic!("tampered amount must be rejected"),
    }

    let expired = WithdrawalIntent::new(
        Scheme::MlDsa44,
        7,
        network_id,
        program_id,
        asset,
        recipient,
        100,
        1,
        400,
    );
    let exp_bytes = expired.encode();
    let exp_sig = Scheme::MlDsa44.sign(&kp.secret, &exp_bytes).expect("sign");
    match authorizer.authorize(&exp_bytes, &exp_sig, 500) {
        Err(e) => println!("expired request:     REJECTED ({e})"),
        Ok(_) => panic!("expired request must be rejected"),
    }

    let wrong_net = WithdrawalIntent::new(
        Scheme::MlDsa44,
        7,
        [0x99; 32],
        program_id,
        asset,
        recipient,
        100,
        1,
        1000,
    );
    let wn_bytes = wrong_net.encode();
    let wn_sig = Scheme::MlDsa44.sign(&kp.secret, &wn_bytes).expect("sign");
    match authorizer.authorize(&wn_bytes, &wn_sig, 500) {
        Err(e) => println!("wrong network:       REJECTED ({e})"),
        Ok(_) => panic!("wrong network must be rejected"),
    }
}
