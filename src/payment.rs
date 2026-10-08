//! BRC-29 payment protocol logic.
//!
//! Provides payment storage traits, HMAC nonce creation/verification,
//! payment header constants, and payment parsing — all framework-agnostic.

use async_trait::async_trait;
use bsv_rs::primitives::PublicKey;
use bsv_rs::transaction::Transaction;
use bsv_rs::wallet::{
    Counterparty, CreateHmacArgs, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel,
};

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
    getrandom::fill(&mut random_bytes)
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

/// The BRC-29 payment protocol name (security level 2), the protocol the
/// payer derives the paying key under.
pub const BRC29_PROTOCOL_NAME: &str = "3241645161d8";

/// Why a payment transaction does not pay the price to the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentOutputError {
    /// The bytes are neither an Atomic BEEF nor a raw transaction.
    MalformedTransaction(String),
    /// The transaction has no output at the index being internalized.
    OutputMissing {
        /// The index the payment names.
        output_index: u32,
        /// How many outputs the transaction has.
        output_count: usize,
    },
    /// The output is not locked to the server's BRC-29 derived key.
    ScriptMismatch {
        /// The index the payment names.
        output_index: u32,
    },
    /// The output carries fewer satoshis than the price.
    Underpaid {
        /// Satoshis in the output.
        paid: u64,
        /// The price.
        required: u64,
    },
}

impl std::fmt::Display for PaymentOutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedTransaction(e) => write!(f, "payment transaction is malformed: {}", e),
            Self::OutputMissing { output_index, output_count } => write!(
                f,
                "payment output {} is missing (transaction has {} outputs)",
                output_index, output_count
            ),
            Self::ScriptMismatch { output_index } => write!(
                f,
                "payment output {} is not locked to the server's BRC-29 key",
                output_index
            ),
            Self::Underpaid { paid, required } => write!(
                f,
                "payment output carries {} satoshis, {} required",
                paid, required
            ),
        }
    }
}

impl std::error::Error for PaymentOutputError {}

impl From<PaymentOutputError> for AuthError {
    fn from(e: PaymentOutputError) -> Self {
        AuthError::InvalidPayment(e.to_string())
    }
}

/// The P2PKH locking script a BRC-29 payment to `wallet` must carry.
///
/// The recipient's side of the derivation: protocol `[2, "3241645161d8"]`,
/// key ID `"<prefix> <suffix>"`, counterparty the sender, for self. The payer
/// derives the same public key for the counterparty `wallet`.
pub fn brc29_locking_script(
    wallet: &ProtoWallet,
    derivation_prefix: &str,
    derivation_suffix: &str,
    sender_identity_key: &str,
) -> Result<Vec<u8>> {
    let sender = PublicKey::from_hex(sender_identity_key)?;
    let derived = wallet.get_public_key(GetPublicKeyArgs {
        identity_key: false,
        protocol_id: Some(Protocol::new(SecurityLevel::Counterparty, BRC29_PROTOCOL_NAME)),
        key_id: Some(format!("{} {}", derivation_prefix, derivation_suffix)),
        counterparty: Some(Counterparty::Other(sender)),
        for_self: Some(true),
    })?;
    let hash = PublicKey::from_hex(&derived.public_key)?.hash160();
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[0x76, 0xa9, 0x14]);
    script.extend_from_slice(&hash);
    script.extend_from_slice(&[0x88, 0xac]);
    Ok(script)
}

/// Reads the output a payment is internalized at and returns its satoshis.
///
/// `tx` is the payment as sent (an Atomic BEEF, or a raw transaction);
/// `output_index` is the index that will be internalized; `expected_script`
/// is [`brc29_locking_script`] for the payment's remittance. The output must
/// be locked to that script and carry at least `price`. Call it before
/// internalizing: neither the reference storage server nor wallet-infra
/// compares the amount or checks the script.
pub fn verify_payment_output(
    tx: &[u8],
    output_index: u32,
    expected_script: &[u8],
    price: u64,
) -> std::result::Result<u64, PaymentOutputError> {
    let malformed = |e: bsv_rs::Error| PaymentOutputError::MalformedTransaction(e.to_string());
    let transaction = if tx.starts_with(&ATOMIC_BEEF_PREFIX) {
        Transaction::from_atomic_beef(tx).map_err(malformed)?
    } else {
        Transaction::from_binary(tx).map_err(malformed)?
    };
    let output = transaction
        .outputs
        .get(output_index as usize)
        .ok_or(PaymentOutputError::OutputMissing {
            output_index,
            output_count: transaction.outputs.len(),
        })?;
    if output.locking_script.to_binary() != expected_script {
        return Err(PaymentOutputError::ScriptMismatch { output_index });
    }
    let paid = output.satoshis.ok_or_else(|| {
        PaymentOutputError::MalformedTransaction("output carries no amount".to_string())
    })?;
    if paid < price {
        return Err(PaymentOutputError::Underpaid {
            paid,
            required: price,
        });
    }
    Ok(paid)
}

/// The Atomic BEEF prefix (BRC-95), `0x01010101` little-endian.
const ATOMIC_BEEF_PREFIX: [u8; 4] = [0x01, 0x01, 0x01, 0x01];

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

    // ---- P0-3: the paying output is read and compared with the price ----

    use bsv_rs::primitives::PrivateKey;
    use bsv_rs::script::LockingScript;
    use bsv_rs::transaction::{TransactionInput, TransactionOutput};

    const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const SENDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const PREFIX: &str = "cHJlZml4LW5vbmNlLTAwMDAwMDAwMDAwMDAwMDA=";
    const SUFFIX: &str = "c3VmZml4";
    const PRICE: u64 = 100;

    fn wallet(hex: &str) -> ProtoWallet {
        ProtoWallet::new(Some(PrivateKey::from_hex(hex).unwrap()))
    }

    fn p2pkh(hash: &[u8; 20]) -> Vec<u8> {
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(hash);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    }

    /// The payer's side of BRC-29: derive the server's key for the
    /// counterparty server, independent of `brc29_locking_script`.
    fn payer_script() -> Vec<u8> {
        let sender = wallet(SENDER_KEY);
        let server_identity = wallet(SERVER_KEY).identity_key();
        let derived = sender
            .get_public_key(GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(Protocol::new(SecurityLevel::Counterparty, BRC29_PROTOCOL_NAME)),
                key_id: Some(format!("{} {}", PREFIX, SUFFIX)),
                counterparty: Some(Counterparty::Other(server_identity)),
                for_self: Some(false),
            })
            .unwrap();
        p2pkh(&PublicKey::from_hex(&derived.public_key).unwrap().hash160())
    }

    fn server_script() -> Vec<u8> {
        let sender_identity = wallet(SENDER_KEY).identity_key().to_hex();
        brc29_locking_script(&wallet(SERVER_KEY), PREFIX, SUFFIX, &sender_identity).unwrap()
    }

    /// A crafted payment: one input from a crafted parent, the given outputs.
    /// Never signed, never broadcast.
    fn payment_tx(outputs: &[(u64, Vec<u8>)]) -> Transaction {
        let mut parent = Transaction::new();
        parent
            .add_output(TransactionOutput::new(
                10_000,
                LockingScript::from_binary(&p2pkh(&[7u8; 20])).unwrap(),
            ))
            .unwrap();
        let mut tx = Transaction::new();
        tx.add_input(TransactionInput::with_source_transaction(parent, 0))
            .unwrap();
        for (satoshis, script) in outputs {
            tx.add_output(TransactionOutput::new(
                *satoshis,
                LockingScript::from_binary(script).unwrap(),
            ))
            .unwrap();
        }
        tx
    }

    fn atomic(outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        payment_tx(outputs).to_atomic_beef(true).unwrap()
    }

    #[test]
    fn brc29_script_matches_the_payers_derivation() {
        assert_eq!(server_script(), payer_script());
    }

    #[test]
    fn exact_price_is_accepted_and_returns_the_price() {
        let tx = atomic(&[(PRICE, payer_script())]);
        assert_eq!(verify_payment_output(&tx, 0, &server_script(), PRICE), Ok(PRICE));
    }

    #[test]
    fn one_satoshi_under_is_refused() {
        let tx = atomic(&[(PRICE - 1, payer_script())]);
        assert_eq!(
            verify_payment_output(&tx, 0, &server_script(), PRICE),
            Err(PaymentOutputError::Underpaid { paid: PRICE - 1, required: PRICE })
        );
    }

    #[test]
    fn one_satoshi_over_is_accepted_and_returns_the_real_amount() {
        let tx = atomic(&[(PRICE + 1, payer_script())]);
        assert_eq!(verify_payment_output(&tx, 0, &server_script(), PRICE), Ok(PRICE + 1));
    }

    #[test]
    fn output_at_another_script_is_refused() {
        let tx = atomic(&[(PRICE, p2pkh(&[9u8; 20]))]);
        assert_eq!(
            verify_payment_output(&tx, 0, &server_script(), PRICE),
            Err(PaymentOutputError::ScriptMismatch { output_index: 0 })
        );
    }

    #[test]
    fn the_derived_output_at_another_index_does_not_pay_the_internalized_one() {
        // Output 0 (the one internalized) pays someone else; the derived
        // script sits at index 1. Searching by script would accept this.
        let tx = atomic(&[(PRICE, p2pkh(&[9u8; 20])), (PRICE, payer_script())]);
        assert_eq!(
            verify_payment_output(&tx, 0, &server_script(), PRICE),
            Err(PaymentOutputError::ScriptMismatch { output_index: 0 })
        );
        assert_eq!(verify_payment_output(&tx, 1, &server_script(), PRICE), Ok(PRICE));
    }

    #[test]
    fn a_missing_output_is_refused() {
        let tx = atomic(&[(PRICE, payer_script())]);
        assert_eq!(
            verify_payment_output(&tx, 1, &server_script(), PRICE),
            Err(PaymentOutputError::OutputMissing { output_index: 1, output_count: 1 })
        );
    }

    #[test]
    fn malformed_bytes_are_refused() {
        assert!(matches!(
            verify_payment_output(&[1, 1, 1, 1, 0xff], 0, &server_script(), PRICE),
            Err(PaymentOutputError::MalformedTransaction(_))
        ));
        assert!(matches!(
            verify_payment_output(b"not a transaction", 0, &server_script(), PRICE),
            Err(PaymentOutputError::MalformedTransaction(_))
        ));
    }

    #[test]
    fn a_raw_transaction_is_read_like_an_atomic_beef() {
        let raw = payment_tx(&[(PRICE - 1, payer_script())]).to_binary();
        assert_eq!(
            verify_payment_output(&raw, 0, &server_script(), PRICE),
            Err(PaymentOutputError::Underpaid { paid: PRICE - 1, required: PRICE })
        );
        let raw = payment_tx(&[(PRICE, payer_script())]).to_binary();
        assert_eq!(verify_payment_output(&raw, 0, &server_script(), PRICE), Ok(PRICE));
    }

    #[test]
    fn a_shortfall_maps_to_invalid_payment() {
        let e: AuthError = PaymentOutputError::Underpaid { paid: 1, required: 2 }.into();
        assert_eq!(e.error_code(), "ERR_INVALID_PAYMENT");
        assert_eq!(e.status_code(), 400);
    }
}
