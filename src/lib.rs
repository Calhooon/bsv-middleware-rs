//! Framework-agnostic BRC-31 authentication and BRC-29 payment middleware for BSV.
//!
//! This crate provides the core protocol logic for authenticating HTTP requests
//! using BSV cryptographic identity (BRC-31) and processing micropayments (BRC-29).
//! It is designed to be used with any HTTP framework — bring your own
//! `Request`/`Response` types and storage backend.
//!
//! # Architecture
//!
//! The crate is split into framework-agnostic protocol logic and trait abstractions:
//!
//! - **Types** — Core data structures (`AuthContext`, `PaymentContext`, `StoredSession`, etc.)
//! - **Errors** — Error types with HTTP status codes and machine-readable error codes
//! - **Transport** — BRC-104 header constants and binary payload serialization (varints)
//! - **Auth** — BRC-31 handshake, signature verification, session lifecycle
//! - **Payment** — BRC-29 HMAC nonce creation/verification, payment parsing, 402 flow
//! - **Storage traits** — `SessionStorage` and `PaymentStorage` for pluggable backends
//!
//! # Usage
//!
//! Implement `SessionStorage` for your backend (Redis, KV, in-memory, etc.),
//! then use the protocol functions to build your framework-specific middleware.

pub mod auth;
#[cfg(feature = "axum")]
pub mod axum_layer;
pub mod error;
pub mod payment;
pub mod payment_core;
pub mod transport;
pub mod types;

pub use auth::{sign_message, verify_message_signature, SessionStorage};
pub use error::{AuthError, Result};
pub use payment::{payment_headers, PaymentStorage};
pub use payment_core::{
    brc29_locking_script, header_service_url, verify_payment, verify_payment_output_only,
    verify_payment_output_only_with_limits, verify_payment_with_limits, HeaderLookupError,
    HeaderService, PaymentToVerify, PaymentVerdict, UnverifiableReason, MAX_PAYMENT_BEEF_BUMPS,
    MAX_PAYMENT_BEEF_TXS, MAX_PAYMENT_BYTES, PAYMENT_BEEF_LIMITS,
};
pub use transport::auth_headers;
pub use types::{
    AuthContext, BsvPayment, ErrorResponse, PaymentContext, StoredPayment, StoredSession,
};
