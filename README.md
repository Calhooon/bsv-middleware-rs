# bsv-middleware-rs

Framework-independent BRC-31 authentication and BRC-29 payment middleware for
BSV, with an optional Axum payment gate. **0.4.3** depends on **bsv-rs =0.4.5**.
Supply storage and a header service; the crate supplies protocol verification.

## Install

```toml
[dependencies]
bsv-middleware-rs = { version = "=0.4.3", features = ["axum"] }
```

[Cargo.toml](Cargo.toml) defines the optional features. Authentication uses
`SessionStorage`; payment persistence uses `PaymentStorage`.
[src/lib.rs](src/lib.rs) lists the public exports.

## Payment verification

`verify_payment` and `verify_payment_async` read BEEF through the SDK's streaming
reader, check the derived payment output and price, execute unproven spends,
and compare proof roots with the configured `HeaderService`. They do not fetch
missing proofs or impose a payment byte-count limit. Platform and evaluator
resources still matter; an inability to finish is not proof of invalidity.

| PaymentVerdict | Meaning |
|---|---|
| `Verified` | Payment output and ancestry checks passed. |
| `Underpaid` | Output pays less than required. |
| `WrongScript` | Output does not pay the derived script. |
| `NoHeaderService` | Server has no configured header service. |
| `RootMismatch` | Proof root differs from the header's root. |
| `Unverifiable` | Reason distinguishes a payer-side failure from an unavailable header service. |

The output-only verifier is explicitly separate and requires the host to
provide full verification elsewhere. The payment core is
[src/payment_core.rs](src/payment_core.rs); its vector contract is
[tests/vectors/brc29-payment-vectors.json](tests/vectors/brc29-payment-vectors.json).

## The Axum door

The `axum` feature exports `require_payment` and `VerifiedPayment`. The gate
streams a body-carried payment instead of collecting the whole BEEF.
[examples/axum_server.rs](examples/axum_server.rs) shows the surrounding auth
and server integration. A host must handle the payment verdict before serving
a paid request and distinguish its own header-service failure from bad input.

## Build and gate

```sh
cargo build --lib --features axum
cargo test --test conformance_brc29
cargo fmt --all -- --check
```

[.github/workflows/ci.yml](.github/workflows/ci.yml) runs tests with all features,
formatting, clippy, payment vectors and a wasm build on each PR and main push.
[RELEASING.md](RELEASING.md) defines the machine gate and tag-based trusted
publishing. [CHANGELOG.md](CHANGELOG.md) records API and behavior changes;
[tests](tests) contains the streaming and resource witnesses.

Licensed under MIT OR Apache-2.0, as declared in [Cargo.toml](Cargo.toml).
