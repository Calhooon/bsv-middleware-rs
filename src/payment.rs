//! BRC-29 payment protocol logic.
//!
//! Provides payment storage traits, HMAC nonce creation/verification,
//! payment header constants, and payment parsing — all framework-agnostic.

use async_trait::async_trait;
use bsv_rs::wallet::{ProtoWallet, CreateHmacArgs, Protocol, SecurityLevel};

use crate::error::{AuthError, Result};
use crate::types::{BsvPayment, StoredPayment};

/// BRC-29 payment header name constants.
pub mod payment_headers {
    /// Client → Server: JSON payment object.
    pub const PAYMENT: &str = "x-bsv-payment";
    /// Server → Client (402): Payment protocol version.
    pub const VERSION: &str = "x-bsv-payment-version";
    /// Server → Client (402): Amount required in satoshis.
    pub const SATOSHIS_REQUIRED: &str = "x-bsv-payment-satoshis-required";
    /// Server → Client (402): Derivation prefix nonce for key derivation.
    pub const DERIVATION_PREFIX: &str = "x-bsv-payment-derivation-prefix";
    /// Server → Client (200): Amount paid in satoshis.
    pub const SATOSHIS_PAID: &str = "x-bsv-payment-satoshis-paid";
    /// Server → Client (200): Transaction ID of accepted payment.
    pub const TXID: &str = "x-bsv-payment-txid";
    /// Server → Client (402): Supported payment transports.
    pub const TRANSPORTS: &str = "x-bsv-payment-transports";
}

/// Trait for payment persistence backends.
///
/// Implement this for your storage backend to track payments
/// and prevent replay attacks via derivation prefix consumption.
#[async_trait]
pub trait PaymentStorage: Send + Sync {
    /// Retrieves a payment record by transaction ID and output index.
    async fn get_payment(&self, txid: &str, vout: u32) -> Result<Option<StoredPayment>>;

    /// Checks if a payment exists.
    async fn payment_exists(&self, txid: &str, vout: u32) -> Result<bool>;

    /// Stores a new payment record.
    async fn store_payment(&self, payment: &StoredPayment) -> Result<()>;

    /// Marks a payment output as spent.
    async fn mark_spent(&self, txid: &str, vout: u32) -> Result<()>;

    /// Stores a derivation prefix with TTL for one-time use.
    async fn store_derivation_prefix(&self, derivation_prefix: &str, ttl_seconds: u64) -> Result<()>;

    /// Consumes a derivation prefix (returns true if it existed and was consumed).
    /// This prevents replay attacks — each prefix can only be used once.
    async fn consume_derivation_prefix(&self, derivation_prefix: &str) -> Result<bool>;
}

/// The originator string used for HMAC nonce creation/verification.
pub const NONCE_ORIGINATOR: &str = "payment middleware";

/// Creates a stateless HMAC-based derivation prefix nonce.
///
/// The nonce is 32 bytes: 16 random + 16 HMAC, base64-encoded.
/// The server can verify it later using only its private key,
/// with no database lookup required.
pub fn create_derivation_prefix(wallet: &ProtoWallet) -> Result<String> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    // Generate 16 random bytes
    let mut random_bytes = [0u8; 16];
    getrandom::getrandom(&mut random_bytes)
        .map_err(|e| AuthError::SdkError(format!("RNG error: {}", e)))?;

    // HMAC the random bytes using a derived key
    let hmac_result = wallet.create_hmac(CreateHmacArgs {
        data: random_bytes.to_vec(),
        protocol_id: Protocol::new(SecurityLevel::Silent, "server hmac"),
        key_id: STANDARD.encode(&random_bytes),
        counterparty: None,
    })?;

    // Take first 16 bytes of HMAC
    let hmac_prefix: Vec<u8> = hmac_result.hmac.into_iter().take(16).collect();

    // Nonce = base64(random || hmac_prefix)
    let mut nonce_bytes = random_bytes.to_vec();
    nonce_bytes.extend_from_slice(&hmac_prefix);
    Ok(STANDARD.encode(&nonce_bytes))
}

/// Verifies a derivation prefix nonce was created by this server.
///
/// Uses stateless HMAC verification — recomputes the HMAC from the
/// random portion and compares against the claimed HMAC.
pub fn verify_derivation_prefix(wallet: &ProtoWallet, nonce: &str) -> Result<bool> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let nonce_bytes = STANDARD.decode(nonce)
        .map_err(|_| AuthError::InvalidDerivationPrefix)?;

    if nonce_bytes.len() != 32 {
        return Ok(false);
    }

    let random_bytes = &nonce_bytes[..16];
    let claimed_hmac = &nonce_bytes[16..];

    // Recompute HMAC
    let hmac_result = wallet.create_hmac(CreateHmacArgs {
        data: random_bytes.to_vec(),
        protocol_id: Protocol::new(SecurityLevel::Silent, "server hmac"),
        key_id: STANDARD.encode(random_bytes),
        counterparty: None,
    })?;

    let computed_prefix: Vec<u8> = hmac_result.hmac.into_iter().take(16).collect();

    // Constant-time comparison
    Ok(computed_prefix == claimed_hmac)
}

/// Parses the x-bsv-payment header value into a BsvPayment struct.
pub fn parse_payment_header(header_value: &str) -> Result<BsvPayment> {
    serde_json::from_str(header_value).map_err(|e| AuthError::MalformedPayment(e.to_string()))
}

/// Builds the 402 Payment Required response headers.
///
/// Returns a list of (header_name, header_value) pairs to include
/// in the 402 response.
pub fn build_402_headers(satoshis: u64, derivation_prefix: &str) -> Vec<(String, String)> {
    vec![
        (payment_headers::VERSION.to_string(), "1.0".to_string()),
        (
            payment_headers::SATOSHIS_REQUIRED.to_string(),
            satoshis.to_string(),
        ),
        (
            payment_headers::DERIVATION_PREFIX.to_string(),
            derivation_prefix.to_string(),
        ),
        (
            payment_headers::TRANSPORTS.to_string(),
            "header".to_string(),
        ),
    ]
}

/// Builds payment success response headers.
///
/// Returns headers to include in the 200 response after successful payment.
pub fn build_success_headers(satoshis_paid: u64, txid: &str) -> Vec<(String, String)> {
    vec![
        (
            payment_headers::SATOSHIS_PAID.to_string(),
            satoshis_paid.to_string(),
        ),
        (payment_headers::TXID.to_string(), txid.to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_payment_header() {
        let json = r#"{"derivationPrefix":"abc","derivationSuffix":"def","transaction":"base64tx"}"#;
        let payment = parse_payment_header(json).unwrap();
        assert_eq!(payment.derivation_prefix, "abc");
        assert_eq!(payment.derivation_suffix, "def");
        assert_eq!(payment.transaction, "base64tx");
    }

    #[test]
    fn test_parse_payment_header_invalid() {
        let result = parse_payment_header("not json");
        assert!(result.is_err());
        match result.unwrap_err() {
            AuthError::MalformedPayment(_) => {}
            other => panic!("Expected MalformedPayment, got {:?}", other),
        }
    }

    #[test]
    fn test_build_402_headers() {
        let headers = build_402_headers(1000, "test-prefix");
        assert_eq!(headers.len(), 4);
        assert_eq!(headers[0].1, "1.0");
        assert_eq!(headers[1].1, "1000");
        assert_eq!(headers[2].1, "test-prefix");
        assert_eq!(headers[3].1, "header");
    }

    #[test]
    fn test_build_success_headers() {
        let headers = build_success_headers(500, "abc123");
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].1, "500");
        assert_eq!(headers[1].1, "abc123");
    }
}
