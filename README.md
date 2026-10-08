# bsv-middleware-rs

Framework-agnostic BRC-31 authentication and BRC-29 payment middleware for BSV.

Provides the protocol logic for authenticating HTTP requests using BSV cryptographic identity and processing micropayments. Bring your own HTTP framework and storage backend.

## Install

```toml
[dependencies]
bsv-middleware-rs = "0.3"            # features = ["axum"] for the Axum payment gate
bsv-rs = { version = "0.3", features = ["auth", "wallet"] }
```

## What's included

| Module | What it does |
|--------|-------------|
| **auth** | BRC-31 message signing/verification, `SessionStorage` trait |
| **payment** | BRC-29 HMAC nonce creation/verification, 402 flow helpers, `PaymentStorage` trait |
| **payment_core** | The payment-output rule with no runtime types: `verify_payment` answers one of six words (`PaymentVerdict`), takes a `HeaderService` trait, fails closed without one |
| **axum_layer** (feature `axum`) | `require_payment` (the gate) and the `VerifiedPayment` extractor for Axum 0.8 |
| **transport** | BRC-104 header constants, binary payload serialization (varints) |
| **types** | `AuthContext`, `StoredSession`, `BsvPayment`, `PaymentContext` |
| **error** | `AuthError` with HTTP status codes and machine-readable error codes |

## Quick start

Implement `SessionStorage` for your backend, then use the protocol functions:

```rust
use bsv_middleware_rs::{SessionStorage, sign_message, verify_message_signature};
use bsv_middleware_rs::payment::{create_derivation_prefix, verify_derivation_prefix};

// Verify a client's signed request
let valid = verify_message_signature(&wallet, &auth_message, &session)?;

// Sign your response
sign_message(&wallet, &mut response_message, &session)?;

// Create a payment nonce (stateless, HMAC-verified)
let nonce = create_derivation_prefix(&wallet)?;

// Verify a payment nonce was issued by this server
let valid = verify_derivation_prefix(&wallet, &nonce)?;
```

## Verifying a payment

```rust
use bsv_middleware_rs::{brc29_locking_script, verify_payment, PaymentToVerify, PaymentVerdict};

let script = brc29_locking_script(&wallet, &prefix, &suffix, &sender_identity_key)?;
let verdict = verify_payment(
    &PaymentToVerify { transaction: &beef, output_index: 0, expected_script: &script, required_satoshis: 100 },
    Some(&my_header_service), // None answers NoHeaderService: a server fault
).await;
match verdict {
    PaymentVerdict::Verified { satoshis } => { /* internalize, then serve */ }
    PaymentVerdict::Underpaid { .. } | PaymentVerdict::WrongScript { .. } => { /* 402, a fresh challenge */ }
    PaymentVerdict::NoHeaderService => { /* 500: configure a header service */ }
    PaymentVerdict::RootMismatch { .. } => { /* 400: the proof is not on the chain */ }
    PaymentVerdict::Unverifiable(reason) => { /* 503 if reason.is_server_side(), else 400 */ }
}
```

The rule is pinned by `conformance/brc29-payment-vectors.json` (20 cases), run by
`tests/conformance_brc29.rs`. `verify_payment_output_only` is the output check without SPV,
for a host whose next step verifies the transaction itself; it is opted into by name.

## Example: Axum server

See [`examples/axum_server.rs`](examples/axum_server.rs) for a complete server with:

- BRC-31 mutual authentication handshake
- Request signature verification middleware
- BRC-29 micropayment flow (402 Payment Required)
- Signed responses

```bash
cargo run --features axum --example axum_server
```

## Architecture

```
+---------------------------------------------+
|  Your HTTP Framework (Axum, Actix, Warp...)  |
+---------------------------------------------+
|  bsv-middleware-rs                           |
|  - SessionStorage / PaymentStorage traits    |
|  - sign / verify messages                    |
|  - HMAC nonce creation                       |
|  - BRC-104 payload serialization             |
+---------------------------------------------+
|  bsv-rs (BSV SDK)                            |
|  - ProtoWallet (key derivation, signing)     |
|  - AuthMessage (BRC-31 protocol types)       |
|  - PublicKey / PrivateKey                    |
+---------------------------------------------+
```

## Storage backends

Implement `SessionStorage` and `PaymentStorage` for your backend:

- **In-memory** (HashMap) — see the Axum example
- **Redis** — good for horizontal scaling
- **PostgreSQL/SQLite** — if you want persistence
- **Cloudflare KV** — for Workers deployments

## Related crates

- [`bsv-rs`](https://crates.io/crates/bsv-rs) — BSV SDK (foundation)
- [`bsv-wallet-toolbox-rs`](https://crates.io/crates/bsv-wallet-toolbox-rs) — Wallet operations

## License

MIT OR Apache-2.0
