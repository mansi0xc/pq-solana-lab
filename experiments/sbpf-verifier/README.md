# sBPF ML-DSA-44 verifier experiment (M5)

Verification-only Solana program. Outcome and full analysis:
`../../docs/solana-feasibility.md`.

Build:

```sh
cargo build-sbf
```

Result: compiles for sBF, but the sBPF ELF checker rejects it because several
`fips204` functions exceed the 4,096-byte stack-frame limit (e.g.
`verify_internal` ~62 KB, `ntt::ntt` ~8.3 KB). See `build.log`.
