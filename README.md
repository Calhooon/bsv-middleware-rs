# bsv-middleware-rs

Framework-independent BRC-31 authentication and BRC-29 payment middleware for
BSV, with an optional Axum payment gate. Supply storage and a header service;
the crate supplies protocol verification.

The release of record is the tag **v0.5.0**, published on crates.io as
**0.5.0** (the same version; `Cargo.toml` says 0.5.0). It depends on
**bsv-rs 0.6.0** by caret, and the re-exported bsv-rs types come from that
line, so a consumer moves bsv-rs and this crate together.
[CHANGELOG.md](CHANGELOG.md) records each release; the repository's Releases
page carries one Release per tag.

## Install

```toml
[dependencies]
bsv-middleware-rs = { version = "0.5.0", features = ["axum"] }
```

The `axum` feature (off by default) adds the Axum 0.8 gate in `axum_layer`.
Authentication uses `SessionStorage`; payment persistence uses
`PaymentStorage`. [src/lib.rs](src/lib.rs) lists the public exports.

## Payment verification

`verify_payment` (over a `std::io::Read`) and `verify_payment_async` (over an
`AsyncByteSource`) read the BEEF once through the SDK's streaming reader,
check the derived payment output and price, execute the spends of unproven
transactions, and compare each proof root with the configured
`HeaderService`. They do not fetch missing proofs and refuse nothing for its
size or its counts. An `Err` is the byte source's failure: it says nothing
about the payment and is never an acceptance.

| PaymentVerdict | Meaning |
|---|---|
| `Verified` | The output pays the derived key at least the price and every merkle root is a block header's. |
| `Underpaid` | The output pays the derived key less than the price. |
| `WrongScript` | The output is not locked to the expected BRC-29 script. |
| `NoHeaderService` | No header service is configured: a server fault, checked before anything else. |
| `RootMismatch` | The header at the proof's height carries a different merkle root. |
| `Unverifiable` | The payment cannot be verified; `UnverifiableReason::is_server_side()` says whether the server (header lookup failed, mining context unavailable) or the payer is why. |

`verify_payment_output_only` and its async form check the output alone (no
header service, no BEEF structure, no spends, no roots), for a host whose next
step checks the transaction itself. The payment core is
[src/payment_core.rs](src/payment_core.rs); its vector contract is the 22
cases of
[tests/vectors/brc29-payment-vectors.json](tests/vectors/brc29-payment-vectors.json),
run by `tests/conformance_brc29.rs`.

## The Axum door

The `axum` feature exports `PaymentGate`, `require_payment` and
`VerifiedPayment`. The gate runs after authentication (it reads the request's
`AuthContext`) and before the handler. It accepts the payment in the
`x-bsv-payment` header or, when that header names no `transaction`, as the
request body, which it streams through `verify_payment_async`; the 402
challenge names both transports (`x-bsv-payment-transports: header,body`).
Underpaid and wrong-script payments get a 402 with a fresh challenge, a
server-side `Unverifiable` gets 503, `NoHeaderService` gets 500, and other
refusals get 400. The gate does not internalize the payment or guard it
against replay: the handler receives `VerifiedPayment` and internalizes it
with its wallet.

[examples/axum_server.rs](examples/axum_server.rs) wires the gate behind a
BRC-31 auth layer with in-memory sessions:

```sh
cargo run --example axum_server --features axum
```

It listens on port 3000 with `POST /.well-known/auth` (the handshake),
`GET /api/hello` (authenticated) and `POST /api/generate` (authenticated, 100
satoshis). The example configures no header service, so the paid route
refuses every payment with a 500 until a `HeaderService` is supplied.

## Build and gate

```sh
cargo test --all-features
cargo build --lib --features axum
cargo test --test conformance_brc29
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

[.github/workflows/ci.yml](.github/workflows/ci.yml) runs the tests with all
features, formatting, clippy, the payment vectors and a
`wasm32-unknown-unknown` build on each PR and push to main.
[RELEASING.md](RELEASING.md) defines the required checks and tag-based trusted
publishing. [deny.toml](deny.toml) is the stack's template for
`cargo deny check`. [tests](tests) contains the streaming and resource
witnesses.

Dependabot moves the stack's crates daily at 18:00Z under
[.github/dependabot.yml](.github/dependabot.yml).

Licensed under MIT OR Apache-2.0, as declared in [Cargo.toml](Cargo.toml).
