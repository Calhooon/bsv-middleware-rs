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

The six words are the whole answer; `PaymentVerdict` is exhaustive, so a host handles each in one
match with no catch-all arm:

| word | accept | meaning |
|------|--------|---------|
| `Verified { satoshis }` | yes | the output pays the derived key at least the price and every merkle root is a block header's; `satoshis` is the amount read from the output |
| `Underpaid { paid, required }` | no | the output pays the derived key less than the price |
| `WrongScript { expected, actual }` | no | the output is not locked to the expected BRC-29 script |
| `NoHeaderService` | no | no header service is configured: a server fault (5xx), answered before the payment is read |
| `RootMismatch { height, merkle_root }` | no | the header at that height carries a different merkle root than the proof computes |
| `Unverifiable(reason)` | no | the payment cannot be verified; `reason.is_server_side()` says whose fault (a header lookup that could not answer is the server's; it fails closed) |

The header service is a trait: implement it over whatever serves your block headers. It returns the
root and the verifier compares, so the comparison lives in one place.

```rust
use async_trait::async_trait;
use bsv_middleware_rs::{HeaderLookupError, HeaderService};

struct MyHeaders { /* a client for your header service */ }

#[async_trait]
impl HeaderService for MyHeaders {
    async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError> {
        // the merkle root (hex) of the block at `height`, or why it cannot say
        self.fetch_root(height).await.map_err(|e| HeaderLookupError(e.to_string()))
    }
}
```

`header_service_url` reads a configured base URL and answers `None` for a value that names no
service (unset, blank, a `.invalid` host): pass `None` to `verify_payment` then.

Before it parses, the verifier refuses a payment over `MAX_PAYMENT_BYTES` (4 MiB) and a BEEF whose
counts exceed `PAYMENT_BEEF_LIMITS` (128 transactions, 32 BUMPs): `Unverifiable` with
`PaymentTooLarge`, `BeefTransactionsExceeded` or `BeefBumpsExceeded`, each naming the count and the
bound. `verify_payment_with_limits` and `verify_payment_output_only_with_limits` take a caller's own
budgets. `UnverifiableReason` and `AuthError` are `#[non_exhaustive]`: match them with a catch-all
arm.

The rule is pinned by `tests/vectors/brc29-payment-vectors.json` (20 cases, 20 exact), run by
`cargo test --test conformance_brc29`. `verify_payment_output_only` is the output check without SPV,
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
