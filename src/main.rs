use pq_solana_lab::crypto::Scheme;

fn main() {
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        Some("demo") => run_demo(),
        Some(other) => {
            eprintln!("unknown command: {other}");
            eprintln!("usage: pq-solana-lab demo");
            std::process::exit(2);
        }
        None => {
            eprintln!("usage: pq-solana-lab demo");
            std::process::exit(2);
        }
    }
}

fn run_demo() {
    println!("pq-solana-lab demo: signature adapters (secret keys are never printed)");
    println!();

    let msg = b"pq-solana-lab demo message: withdraw 100 base units";

    for scheme in Scheme::ALL {
        let kp = scheme.keygen().expect("keygen");
        let sig = scheme.sign(&kp.secret, msg).expect("sign");

        // Round-trip through canonical bytes, as transport/storage would.
        let pk_bytes = kp.public.clone();
        let sig_bytes = sig.clone();

        let ok = scheme
            .verify(&pk_bytes, msg, &sig_bytes)
            .expect("verify well-formed inputs");

        let mut altered = msg.to_vec();
        altered[0] ^= 0x01;
        let altered_ok = scheme
            .verify(&pk_bytes, &altered, &sig_bytes)
            .expect("verify well-formed inputs");

        let other = scheme.keygen().expect("keygen");
        let wrong_key_ok = scheme
            .verify(&other.public, msg, &sig_bytes)
            .expect("verify well-formed inputs");

        println!("scheme:            {}", scheme.name());
        println!("  category:        {}", scheme.category_label());
        println!("  public key:      {} bytes", pk_bytes.len());
        println!("  signature:       {} bytes", sig_bytes.len());
        println!("  sign+serialize+verify: {ok}");
        println!("  altered message rejected: {}", !altered_ok);
        println!("  wrong key rejected:       {}", !wrong_key_ok);
        println!();

        assert!(
            ok && !altered_ok && !wrong_key_ok,
            "demo invariant violated"
        );
    }
}
