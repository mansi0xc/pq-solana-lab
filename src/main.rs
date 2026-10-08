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
    println!("== direct inclusion (serialized; v1 uses the SDK wincode encoder) ==");
    println!(
        "scheme              template     format  placement  accounts  config  sig      pk      total   limit  headroom"
    );
    for r in &rows {
        println!(
            "{:<18} {:<12} {:<7} {:<10} {:>8}  {:<6} {:>7} {:>7} {:>7} {:>6} {:>8}",
            r.scheme,
            r.template,
            r.format,
            r.key_placement,
            r.account_count,
            if r.v1_config == "n/a" { "-" } else { "set" },
            r.signature_bytes,
            r.public_key_bytes,
            r.total_bytes,
            r.applicable_limit,
            r.headroom
        );
    }

    let staged = pq_solana_lab::transport::staged();
    let spath = "results/transport-staged.json";
    std::fs::write(
        spath,
        serde_json::to_string_pretty(&staged).expect("serialize staged"),
    )
    .unwrap_or_else(|e| panic!("write {spath}: {e}"));
    println!();
    println!("== staged upload (modeled) ==");
    println!(
        "scheme              format  sig     meta   chunk  chunks  init    upload  seal    auth    total_tx  total_bytes  limit"
    );
    for r in &staged {
        println!(
            "{:<18} {:<7} {:>6} {:>6} {:>6} {:>7} {:>7} {:>7} {:>7} {:>7} {:>9} {:>12} {:>6}",
            r.scheme,
            r.format,
            r.signature_bytes,
            r.session_metadata_bytes,
            r.chunk_bytes,
            r.chunk_count,
            r.init_tx_bytes,
            r.upload_tx_total_bytes,
            r.seal_tx_bytes,
            r.authorize_tx_bytes,
            r.total_transactions,
            r.total_transport_bytes,
            r.applicable_limit
        );
    }
    println!("wrote {path} and {spath}");
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .or_else(|| {
            let prefix = format!("{name}=");
            args.iter()
                .find_map(|a| a.strip_prefix(&prefix).map(String::from))
        })
}

fn run_benchmark(args: &[String]) {
    let config_path =
        arg_value(args, "--config").unwrap_or_else(|| "configs/quick.json".to_string());
    let mut config: BenchConfig = serde_json::from_str(
        &std::fs::read_to_string(&config_path)
            .unwrap_or_else(|e| panic!("read config {config_path}: {e}")),
    )
    .unwrap_or_else(|e| panic!("parse config {config_path}: {e}"));
    if let Some(id) = arg_value(args, "--run-id") {
        config.run_id = id;
    }
    let force = args.iter().any(|a| a == "--force");

    if let Err(e) = bench::validate(&config) {
        eprintln!("invalid benchmark config {config_path}: {e}");
        std::process::exit(2);
    }

    let meta_path = format!("results/{}.json", config.run_id);
    if !force && std::path::Path::new(&meta_path).exists() {
        eprintln!(
            "run_id {:?} already has {meta_path}; choose a new --run-id or pass --force to overwrite",
            config.run_id
        );
        std::process::exit(2);
    }

    // Provenance is captured *before* any result file is written, so this run's
    // own outputs are never mistaken for pre-existing source changes.
    let mut meta = pq_solana_lab::provenance::capture(&config.run_id, &config_path, &config);
    if let Some(patch) = pq_solana_lab::provenance::write_dirty_patch(&config.run_id) {
        meta["dirty_patch"] = serde_json::json!(patch);
    }

    let (raw, summaries) = bench::run(&config).expect("validated config");

    std::fs::create_dir_all("results/raw").expect("mkdir results/raw");
    std::fs::create_dir_all("results/summaries").expect("mkdir results/summaries");
    write_raw_csv(&format!("results/raw/{}.csv", config.run_id), &raw);
    write_summary_csv(
        &format!("results/summaries/{}.csv", config.run_id),
        &summaries,
    );

    meta["status_counts"] = status_counts(&summaries);
    meta["raw_rows"] = serde_json::json!(raw.len());
    std::fs::write(
        &meta_path,
        serde_json::to_string_pretty(&meta).expect("serialize metadata"),
    )
    .unwrap_or_else(|e| panic!("write {meta_path}: {e}"));

    print_summary_table(&summaries);
    print_problems(&summaries);
    println!(
        "wrote results/raw/{0}.csv, results/summaries/{0}.csv, {1}",
        config.run_id, meta_path
    );
}

fn status_counts(rows: &[SummaryRow]) -> serde_json::Value {
    let mut ok = 0;
    let mut partial = 0;
    let mut failed = 0;
    let mut skipped = 0;
    for r in rows {
        match r.status.as_str() {
            "ok" => ok += 1,
            "partial" => partial += 1,
            "failed" => failed += 1,
            _ => skipped += 1,
        }
    }
    serde_json::json!({ "ok": ok, "partial": partial, "failed": failed, "skipped": skipped })
}

fn write_raw_csv(path: &str, rows: &[RawSample]) {
    let mut out = Vec::new();
    writeln!(
        out,
        "run_id,scheme,category,operation,mode,message_len,input_class,sample_index,elapsed_ns,valid"
    )
    .unwrap();
    for r in rows {
        writeln!(
            out,
            "{},{},{},{},{},{},{},{},{},{}",
            r.run_id,
            r.scheme,
            csv(&r.category),
            r.operation,
            r.mode,
            r.message_len,
            r.input_class,
            r.sample_index,
            r.elapsed_ns,
            u8::from(r.valid)
        )
        .unwrap();
    }
    std::fs::write(path, out).unwrap_or_else(|e| panic!("write {path}: {e}"));
}

fn write_summary_csv(path: &str, rows: &[SummaryRow]) {
    let mut out = Vec::new();
    writeln!(
        out,
        "run_id,scheme,category,operation,mode,message_len,input_class,sample_count,valid_count,budget_limited,median_ns,q1_ns,q3_ns,p95_ns,public_key_bytes,signature_bytes,status,note"
    )
    .unwrap();
    for r in rows {
        let opt = |v: Option<u64>| v.map(|n| n.to_string()).unwrap_or_default();
        writeln!(
            out,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            r.run_id,
            r.scheme,
            csv(&r.category),
            r.operation,
            r.mode,
            r.message_len,
            r.input_class,
            r.sample_count,
            r.valid_count,
            u8::from(r.budget_limited),
            opt(r.median_ns),
            opt(r.q1_ns),
            opt(r.q3_ns),
            opt(r.p95_ns),
            r.public_key_bytes,
            r.signature_bytes,
            r.status,
            csv(&r.note)
        )
        .unwrap();
    }
    std::fs::write(path, out).unwrap_or_else(|e| panic!("write {path}: {e}"));
}

fn print_summary_table(rows: &[SummaryRow]) {
    println!("summary (median ns):");
    for r in rows {
        let median = r
            .median_ns
            .map(|m| m.to_string())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "  {:<10} {:<13} {:<10} len={:<4} class={:<11} n={:<5}/{:<5} median={:<10} {}",
            r.scheme,
            r.operation,
            r.mode,
            r.message_len,
            r.input_class,
            r.valid_count,
            r.sample_count,
            median,
            r.status
        );
    }
}

fn print_problems(rows: &[SummaryRow]) {
    let problems: Vec<&SummaryRow> = rows.iter().filter(|r| r.status != "ok").collect();
    if problems.is_empty() {
        println!("all {} cases ok", rows.len());
        return;
    }
    println!("cases needing attention:");
    for r in problems {
        println!(
            "  {:<10} {:<13} {:<10} len={:<4} class={:<11} status={} ({})",
            r.scheme, r.operation, r.mode, r.message_len, r.input_class, r.status, r.note
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
