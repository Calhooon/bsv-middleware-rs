//! BRC-31 authentication protocol logic.
//!
//! Provides session storage traits, message signing/verification,
//! and the core handshake state machine — all framework-agnostic.

use async_trait::async_trait;
use bsv_rs::auth::AuthMessage;
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel, VerifySignatureArgs,
};
use bsv_rs::PublicKey;

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
    async fn get_session_by_identity(
        &self,
        identity_key_hex: &str,
    ) -> Result<Option<StoredSession>>;
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
    // Canonical BRC-31: key_id and signing-data come from the AuthMessage
    // itself (identical to `bsv-middleware-cloudflare` and `bsv_rs::auth::Peer`).
    // For a General message: key_id = "{msg.nonce} {peer_session_nonce}",
    // signing_data = the BRC-104 payload. Deriving key_id from the per-message
    // nonce (NOT the static session/handshake nonces) is what makes a canonical
    // `Peer` client interoperate with this server.
    let key_id = message.get_key_id(session.peer_nonce.as_deref());
    let data_to_sign = message.signing_data();

    let counterparty_key = PublicKey::from_hex(&session.peer_identity_key)
        .map_err(|e| crate::error::AuthError::SdkError(e.to_string()))?;

    let result = wallet.create_signature(CreateSignatureArgs {
        data: Some(data_to_sign),
        hash_to_directly_sign: None,
        // Canonical auth uses SecurityLevel::Counterparty (matches
        // `bsv_rs::auth::Peer` peer.rs:586 and `bsv-middleware-cloudflare`).
        protocol_id: Protocol::new(SecurityLevel::Counterparty, "auth message signature"),
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

    // Canonical BRC-31: reconstruct the SAME key_id the sender used —
    // "{msg.nonce} {our_session_nonce}" via AuthMessage::get_key_id — and verify
    // over signing_data() with SecurityLevel::Counterparty + `for_self: None`,
    // exactly as `bsv_rs::auth::Peer` (peer.rs:616-635) and
    // `bsv-middleware-cloudflare` do. The previous impl derived the key_id from
    // the static session/handshake nonces, used SecurityLevel::App, and forced
    // `for_self: true` — which rejected canonical-client signatures (a real
    // `Peer` could not authenticate). Verified by the regression test below.
    let key_id = message.get_key_id(Some(session.session_nonce.as_str()));
    let data = message.signing_data();

    let counterparty_key = PublicKey::from_hex(&session.peer_identity_key)
        .map_err(|e| crate::error::AuthError::SdkError(e.to_string()))?;

    let result = wallet.verify_signature(VerifySignatureArgs {
        data: Some(data),
        hash_to_directly_verify: None,
        signature: signature.clone(),
        // Canonical auth uses SecurityLevel::Counterparty + for_self: None
        // (matches `bsv_rs::auth::Peer` peer.rs:623/635 and `bsv-middleware-cloudflare`).
        protocol_id: Protocol::new(SecurityLevel::Counterparty, "auth message signature"),
        key_id,
        counterparty: Some(Counterparty::Other(counterparty_key)),
        for_self: None,
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

    /// Regression: a General message signed by a CANONICAL client (the exact
    /// `bsv_rs::auth::Peer` path — `AuthMessage::get_key_id` + `signing_data`)
    /// MUST verify against this server. Pre-fix, `verify_message_signature`
    /// derived its key_id from the static session/handshake nonces and forced
    /// `for_self: true`, which rejected canonical-client signatures (a real
    /// `Peer` could not authenticate). Mirrors `bsv-middleware-cloudflare`.
    #[test]
    fn canonical_peer_client_general_message_verifies() {
        use crate::transport::build_request_payload;
        use crate::types::StoredSession;
        use base64::Engine;
        use bsv_rs::auth::{AuthMessage, MessageType};
        use bsv_rs::primitives::PrivateKey;

        // Real BRC-31 nonces are base64-encoded 32-byte values; bsv-rs key
        // derivation decodes the keyID nonce tokens, so the test must use
        // realistic base64 nonces (not arbitrary ASCII).
        let b64 = |seed: u8| base64::engine::general_purpose::STANDARD.encode([seed; 32]);

        let client = ProtoWallet::new(Some(PrivateKey::random()));
        let server = ProtoWallet::new(Some(PrivateKey::random()));
        let client_id = client.identity_key();
        let server_id = server.identity_key();

        // Post-handshake server session.
        let server_session_nonce = b64(0xA1);
        let mut session = StoredSession::new(server_session_nonce.clone(), client_id.to_hex());
        session.peer_nonce = Some(b64(0xB2));
        session.is_authenticated = true;

        // Canonical client builds + signs a General request.
        let request_id = [7u8; 32];
        let payload = build_request_payload(&request_id, "POST", "/api/x", "", &[], b"{\"k\":1}");
        let mut msg = AuthMessage::new(MessageType::General, client_id.clone());
        msg.nonce = Some(b64(0xC3));
        msg.your_nonce = Some(server_session_nonce.clone());
        msg.payload = Some(payload);
        let key_id = msg.get_key_id(Some(server_session_nonce.as_str()));
        let data = msg.signing_data();
        let sig = client
            .create_signature(CreateSignatureArgs {
                data: Some(data),
                hash_to_directly_sign: None,
                // Canonical client level (bsv_rs::auth::Peer peer.rs:586).
                protocol_id: Protocol::new(SecurityLevel::Counterparty, "auth message signature"),
                key_id,
                counterparty: Some(Counterparty::Other(server_id.clone())),
            })
            .unwrap();
        msg.signature = Some(sig.signature);

        // MUST accept the canonical client's signature.
        assert!(
            verify_message_signature(&server, &msg, &session).unwrap(),
            "canonical Peer-client General message must verify"
        );

        // A session bound to a different identity MUST reject it.
        let stranger = ProtoWallet::new(Some(PrivateKey::random()));
        let mut bad_session = session.clone();
        bad_session.peer_identity_key = stranger.identity_key().to_hex();
        assert!(
            !verify_message_signature(&server, &msg, &bad_session).unwrap_or(false),
            "signature must not verify against a stranger-bound session"
        );
    }
}
