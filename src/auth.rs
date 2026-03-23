//! BRC-31 authentication protocol logic.
//!
//! Provides session storage traits, message signing/verification,
//! and the core handshake state machine — all framework-agnostic.

use async_trait::async_trait;
use bsv_sdk::wallet::{ProtoWallet, CreateSignatureArgs, VerifySignatureArgs, Protocol, SecurityLevel, Counterparty};
use bsv_sdk::auth::AuthMessage;
use bsv_sdk::PublicKey;

use crate::error::Result;
use crate::types::StoredSession;

/// Trait for session persistence backends.
///
/// Implement this for your storage backend (Redis, KV, in-memory, SQL, etc.).
/// The middleware uses this to store and retrieve BRC-31 session state.
#[async_trait]
pub trait SessionStorage: Send + Sync {
    /// Retrieves a session by its nonce.
    async fn get_session(&self, session_nonce: &str) -> Result<Option<StoredSession>>;

    /// Persists a session. Should use TTL-based expiration.
    async fn save_session(&self, session: &StoredSession) -> Result<()>;

    /// Removes a session by its nonce.
    async fn remove_session(&self, session_nonce: &str) -> Result<()>;

    /// Updates an existing session (touch timestamp, update peer nonce, etc.).
    async fn update_session(&self, session: &StoredSession) -> Result<()>;

    /// Checks if a session exists.
    async fn has_session(&self, session_nonce: &str) -> Result<bool>;

    /// Finds an existing session for an identity key.
    /// Returns the most recent session if multiple exist.
    async fn get_session_by_identity(&self, identity_key_hex: &str) -> Result<Option<StoredSession>>;
}

/// Session info needed for response signing.
///
/// After successful authentication, this struct contains the keys and nonces
/// needed to sign responses back to the client.
#[derive(Debug, Clone)]
pub struct AuthSession {
    /// Server's private key (hex).
    pub server_private_key: String,
    /// Server's session nonce.
    pub session_nonce: String,
    /// Peer's last nonce (from handshake).
    pub peer_nonce: Option<String>,
    /// Peer's identity key (hex).
    pub peer_identity_key: String,
    /// 32-byte request correlation ID.
    pub request_id: [u8; 32],
}

/// Signs a BRC-31 auth message using the server's wallet and session context.
///
/// This sets the signature field on the message using key derivation
/// with protocol `[2, "auth message signature"]` and keyID based on session nonces.
pub fn sign_message(
    wallet: &ProtoWallet,
    message: &mut AuthMessage,
    session: &StoredSession,
) -> Result<()> {
    let key_id = format!(
        "{} {}",
        session
            .peer_nonce
            .as_deref()
            .unwrap_or(&session.session_nonce),
        session.session_nonce
    );

    let data_to_sign = if let Some(ref payload) = message.payload {
        payload.clone()
    } else {
        Vec::new()
    };

    let counterparty_key = PublicKey::from_hex(&session.peer_identity_key)
        .map_err(|e| crate::error::AuthError::SdkError(e.to_string()))?;

    let result = wallet.create_signature(CreateSignatureArgs {
        data: Some(data_to_sign),
        hash_to_directly_sign: None,
        protocol_id: Protocol::new(SecurityLevel::App, "auth message signature"),
        key_id,
        counterparty: Some(Counterparty::Other(counterparty_key)),
    })?;

    message.signature = Some(result.signature);
    Ok(())
}

/// Verifies a BRC-31 auth message signature from a peer.
///
/// Uses the peer's identity key and session nonces to derive the verification key,
/// then checks the signature against the message payload.
pub fn verify_message_signature(
    wallet: &ProtoWallet,
    message: &AuthMessage,
    session: &StoredSession,
) -> Result<bool> {
    let signature = match &message.signature {
        Some(sig) => sig,
        None => return Ok(false),
    };

    let key_id = format!(
        "{} {}",
        session.session_nonce,
        session
            .peer_nonce
            .as_deref()
            .unwrap_or(&session.session_nonce),
    );

    let data = if let Some(ref payload) = message.payload {
        payload.clone()
    } else {
        Vec::new()
    };

    let counterparty_key = PublicKey::from_hex(&session.peer_identity_key)
        .map_err(|e| crate::error::AuthError::SdkError(e.to_string()))?;

    let result = wallet.verify_signature(VerifySignatureArgs {
        data: Some(data),
        hash_to_directly_verify: None,
        signature: signature.clone(),
        protocol_id: Protocol::new(SecurityLevel::App, "auth message signature"),
        key_id,
        counterparty: Some(Counterparty::Other(counterparty_key)),
        for_self: Some(true),
    })?;

    Ok(result.valid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_session_debug() {
        let session = AuthSession {
            server_private_key: "abc".to_string(),
            session_nonce: "nonce1".to_string(),
            peer_nonce: Some("nonce2".to_string()),
            peer_identity_key: "03abcdef".to_string(),
            request_id: [0u8; 32],
        };
        // Ensure Debug impl works
        let _debug = format!("{:?}", session);
    }
}
