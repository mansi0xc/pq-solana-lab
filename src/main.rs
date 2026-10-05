use pq_solana_lab::authorization::{Authorizer, Environment, KeyRegistry, RegisteredKey};
use pq_solana_lab::crypto::Scheme;
use pq_solana_lab::intent::WithdrawalIntent;

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

    // Accept.
    let rec = authorizer
        .authorize(&bytes, &sig, 500)
        .expect("valid request");
    assert_eq!(rec.asset, asset);
    println!(
        "valid request:       ACCEPTED (nonce {} consumed, amount {}, asset preserved, slot {})",
        rec.nonce, rec.amount, rec.at_slot
    );

    // Replay.
    match authorizer.authorize(&bytes, &sig, 500) {
        Err(e) => println!("replay:              REJECTED ({e})"),
        Ok(_) => panic!("replay must be rejected"),
    }

    // Tampered amount after signing.
    let mut tampered = intent.clone();
    tampered.amount = 101;
    match authorizer.authorize(&tampered.encode(), &sig, 500) {
        Err(e) => println!("tampered amount:     REJECTED ({e})"),
        Ok(_) => panic!("tampered amount must be rejected"),
    }

    // Expired.
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

    // Wrong network, correctly signed by the registered key (policy, not
    // integrity).
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
