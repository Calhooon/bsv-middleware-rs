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
| **payment_core** | The payment-output rule with no runtime types: `verify_payment` reads the payment from a byte source through the streaming BEEF reader of bsv-rs 0.4.0, answers one of six words (`PaymentVerdict`), takes a `HeaderService` trait, fails closed without one, and refuses nothing for its size |
| **axum_layer** (feature `axum`) | `require_payment` (the gate, which streams a payment sent in the request body) and the `VerifiedPayment` extractor for Axum 0.8 |
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
    &PaymentToVerify { output_index: 0, expected_script: &script, required_satoshis: 100 },
    &beef[..],                // any std::io::Read: a slice, a file, a decoder over a transport
    Some(&my_header_service), // None answers NoHeaderService: a server fault
).await?;                     // Err is the source's failure, never a verdict on the payment
match verdict {
    PaymentVerdict::Verified { satoshis } => { /* internalize, then serve */ }
    PaymentVerdict::Underpaid { .. } | PaymentVerdict::WrongScript { .. } => { /* 402, a fresh challenge */ }
    PaymentVerdict::NoHeaderService => { /* 500: configure a header service */ }
    PaymentVerdict::RootMismatch { .. } => { /* 400: the proof is not on the chain */ }
    PaymentVerdict::Unverifiable(reason) => { /* 503 if reason.is_server_side(), else 400 */ }
}
```

A body that arrives in chunks (a request body, an object store's body stream) implements
`AsyncByteSource`, the trait bsv-rs 0.4.0 ships, and goes through `verify_payment_async`: the same
checks, the same words.

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

### A payment of any size

A valid payment is never refused for its size or its counts. The payment is read once, as a stream,
through `verify_stream` of bsv-rs 0.4.0: the verifier holds one element of the BEEF (one
transaction, one BUMP) and the reader's index (about 128 bytes an element), never the BEEF. Read
from a source that writes itself, a payment of 100,000 unproven transactions under one proven
parent (6.2 MB) is verified with a peak heap of 12.8 MB, 2,684 bytes over the SDK reader's own, and
the output check alone holds 16,988 bytes at every depth (`tests/payment_flat_memory.rs`). The crate
exports no bound: `MAX_PAYMENT_BYTES`, `PAYMENT_BEEF_LIMITS` and the `_with_limits` verifiers of
0.2.2 and 0.3.0 are gone.

A refusal is for invalid bytes and names them: `Unverifiable(InvalidBeef { offset, kind, reason })`
carries the stream offset of the byte and one of the reader's eighteen kinds (`Kind`: a truncated
field, a tree height over 64, an input that names no earlier transaction, a subject that is not the
tip, ...), none of which is a size or a count. `SpendRefused` is the script interpreter's refusal
of an unproven transaction's spend: since 0.4.0 the full check runs the scripts of every unproven
transaction against the parent output the BEEF carries. `NoProof` is a valid BEEF that gives no
root to check. `UnverifiableReason` and `AuthError` are `#[non_exhaustive]`: match them with a
catch-all arm.

The rule is pinned by `tests/vectors/brc29-payment-vectors.json` (22 cases, 22 exact), run by
`cargo test --test conformance_brc29`. `verify_payment_output_only` is the output check without SPV,
for a host whose next step verifies the transaction itself; it is opted into by name, reads a raw
transaction as well as a BEEF, and keeps no index.

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
