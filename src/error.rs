//! Error types for BSV auth and payment middleware.
//!
//! Error codes and HTTP status codes match the Express middleware exactly
//! (`auth-express-middleware` and `payment-express-middleware`).

use thiserror::Error;

/// Error type for BSV auth and payment middleware.
#[derive(Error, Debug)]
pub enum AuthError {
    // Auth errors (match auth-express-middleware)
    /// Authentication is required but not provided.
    #[error("Mutual-authentication failed!")]
    Unauthorized,

    /// Authentication headers or signature is invalid.
    #[error("Invalid authentication: {0}")]
    InvalidAuthentication(String),

    /// Session not found in storage.
    #[error("Session not found: {0}")]
    SessionNotFound(String),

    // Payment errors (match payment-express-middleware)
    /// Payment middleware was run before auth middleware.
    #[error("The payment middleware must be executed after the Auth middleware.")]
    ServerMisconfigured,

    /// Error calculating request price.
    #[error("An internal error occurred while determining the payment required for this request.")]
    PaymentInternal(String),

    /// Payment is required to access this resource.
    #[error(
        "A BSV payment is required to complete this request. Provide the X-BSV-Payment header."
    )]
    PaymentRequired {
        /// Amount required in satoshis.
        satoshis: u64,
        /// Derivation prefix for payment address generation.
        derivation_prefix: String,
    },

    /// Payment data is malformed or cannot be parsed.
    #[error("The X-BSV-Payment header is not valid JSON.")]
    MalformedPayment(String),

    /// Derivation prefix is invalid or not recognized.
    #[error("The X-BSV-Payment-Derivation-Prefix header is not valid.")]
    InvalidDerivationPrefix,

    /// Payment verification failed (wallet rejected).
    #[error("{0}")]
    PaymentFailed(String),

    /// Payment provided is invalid (duplicate, etc).
    #[error("Invalid payment: {0}")]
    InvalidPayment(String),

    // Infrastructure errors
    /// Error interacting with storage backend.
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Error from the BSV SDK.
    #[error("SDK error: {0}")]
    SdkError(String),

    /// Error in the transport layer.
    #[error("Transport error: {0}")]
    TransportError(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Serialization/deserialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<bsv_rs::Error> for AuthError {
    fn from(e: bsv_rs::Error) -> Self {
        AuthError::SdkError(e.to_string())
    }
}

impl From<serde_json::Error> for AuthError {
    fn from(e: serde_json::Error) -> Self {
        AuthError::SerializationError(e.to_string())
    }
}

/// Result type alias for BSV auth middleware.
pub type Result<T> = std::result::Result<T, AuthError>;

impl AuthError {
    /// Returns the HTTP status code appropriate for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            // Auth errors
            Self::Unauthorized => 401,
            Self::InvalidAuthentication(_) => 401,
            Self::SessionNotFound(_) => 401,
            // Payment errors (matching Express exactly)
            Self::ServerMisconfigured => 500,
            Self::PaymentInternal(_) => 500,
            Self::PaymentRequired { .. } => 402,
            Self::MalformedPayment(_) => 400,
            Self::InvalidDerivationPrefix => 400,
            Self::PaymentFailed(_) => 400,
            Self::InvalidPayment(_) => 400,
            // Infrastructure errors
            Self::StorageError(_) => 500,
            Self::SdkError(_) => 500,
            Self::TransportError(_) => 500,
            Self::ConfigError(_) => 500,
            Self::SerializationError(_) => 400,
        }
    }

    /// Returns a machine-readable error code for this error.
    /// These match the Express middleware error codes exactly.
    pub fn error_code(&self) -> &'static str {
        match self {
            // Auth errors
            Self::Unauthorized => "UNAUTHORIZED",
            Self::InvalidAuthentication(_) => "ERR_INVALID_AUTH",
            Self::SessionNotFound(_) => "ERR_SESSION_NOT_FOUND",
            // Payment errors
            Self::ServerMisconfigured => "ERR_SERVER_MISCONFIGURED",
            Self::PaymentInternal(_) => "ERR_PAYMENT_INTERNAL",
            Self::PaymentRequired { .. } => "ERR_PAYMENT_REQUIRED",
            Self::MalformedPayment(_) => "ERR_MALFORMED_PAYMENT",
            Self::InvalidDerivationPrefix => "ERR_INVALID_DERIVATION_PREFIX",
            Self::PaymentFailed(_) => "ERR_PAYMENT_FAILED",
            Self::InvalidPayment(_) => "ERR_INVALID_PAYMENT",
            // Infrastructure errors
            Self::StorageError(_) => "ERR_STORAGE",
            Self::SdkError(_) => "ERR_SDK",
            Self::TransportError(_) => "ERR_TRANSPORT",
            Self::ConfigError(_) => "ERR_CONFIG",
            Self::SerializationError(_) => "ERR_SERIALIZATION",
        }
    }

    /// Converts this error to a JSON response body string.
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "status": "error",
            "code": self.error_code(),
            "description": self.to_string()
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_codes_match_express() {
        assert_eq!(AuthError::Unauthorized.status_code(), 401);
        assert_eq!(
            AuthError::InvalidAuthentication("x".into()).status_code(),
            401
        );
        assert_eq!(AuthError::SessionNotFound("x".into()).status_code(), 401);
        assert_eq!(AuthError::ServerMisconfigured.status_code(), 500);
        assert_eq!(AuthError::PaymentInternal("x".into()).status_code(), 500);
        assert_eq!(
            AuthError::PaymentRequired {
                satoshis: 100,
                derivation_prefix: "x".into()
            }
            .status_code(),
            402
        );
        assert_eq!(AuthError::MalformedPayment("x".into()).status_code(), 400);
        assert_eq!(AuthError::InvalidDerivationPrefix.status_code(), 400);
        assert_eq!(AuthError::PaymentFailed("x".into()).status_code(), 400);
        assert_eq!(AuthError::InvalidPayment("x".into()).status_code(), 400);
    }

    #[test]
    fn test_error_codes_match_express() {
        assert_eq!(AuthError::Unauthorized.error_code(), "UNAUTHORIZED");
        assert_eq!(
            AuthError::ServerMisconfigured.error_code(),
            "ERR_SERVER_MISCONFIGURED"
        );
        assert_eq!(
            AuthError::PaymentRequired {
                satoshis: 100,
                derivation_prefix: "x".into()
            }
            .error_code(),
            "ERR_PAYMENT_REQUIRED"
        );
        assert_eq!(
            AuthError::InvalidDerivationPrefix.error_code(),
            "ERR_INVALID_DERIVATION_PREFIX"
        );
    }

    #[test]
    fn test_error_json_format() {
        let json = AuthError::Unauthorized.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["status"], "error");
        assert_eq!(parsed["code"], "UNAUTHORIZED");
        assert_eq!(parsed["description"], "Mutual-authentication failed!");
    }
}
