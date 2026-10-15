//! BRC-104 HTTP transport: header constants and binary payload serialization.
//!
//! This module provides the wire format for BSV authentication headers
//! and the varint-based payload serialization used for message signing.
//! Every varint is bsv-rs's canonical one (`bsv_rs::primitives::to_var_int`).

use bsv_rs::primitives::to_var_int;

/// BRC-104 authentication header names.
pub mod auth_headers {
    pub const VERSION: &str = "x-bsv-auth-version";
    pub const IDENTITY_KEY: &str = "x-bsv-auth-identity-key";
    pub const NONCE: &str = "x-bsv-auth-nonce";
    pub const INITIAL_NONCE: &str = "x-bsv-auth-initial-nonce";
    pub const YOUR_NONCE: &str = "x-bsv-auth-your-nonce";
    pub const SIGNATURE: &str = "x-bsv-auth-signature";
    pub const MESSAGE_TYPE: &str = "x-bsv-auth-message-type";
    pub const REQUEST_ID: &str = "x-bsv-auth-request-id";
    pub const REQUESTED_CERTIFICATES: &str = "x-bsv-auth-requested-certificates";
}

/// Deserialized HTTP request data for signature verification.
#[derive(Debug, Clone)]
pub struct HttpRequestData {
    /// 32-byte request correlation ID.
    pub request_id: [u8; 32],
    /// HTTP method (GET, POST, etc.).
    pub method: String,
    /// URL path.
    pub path: String,
    /// URL query string.
    pub search: String,
    /// Headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// Request body bytes.
    pub body: Vec<u8>,
}

impl HttpRequestData {
    /// Combines path and search into a full URL path.
    pub fn url(&self) -> String {
        if self.search.is_empty() {
            self.path.clone()
        } else {
            format!("{}?{}", self.path, self.search)
        }
    }

    /// Builds the binary payload for signature verification.
    pub fn to_payload(&self) -> Vec<u8> {
        build_request_payload(
            &self.request_id,
            &self.method,
            &self.path,
            &self.search,
            &self.headers,
            &self.body,
        )
    }
}

/// HTTP response data for signature construction.
#[derive(Debug, Clone)]
pub struct HttpResponseData {
    /// 32-byte request correlation ID (must match request).
    pub request_id: [u8; 32],
    /// HTTP status code.
    pub status: u16,
    /// Response headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

impl HttpResponseData {
    /// Builds the binary payload for response signing.
    pub fn to_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();

        // Version byte
        payload.push(0x00);

        // Request ID (32 bytes)
        payload.extend_from_slice(&self.request_id);

        // Status code as varint
        payload.extend_from_slice(&to_var_int(self.status as u64));

        // Number of headers as varint
        let signable = filter_signable_headers(&self.headers);
        payload.extend_from_slice(&to_var_int(signable.len() as u64));

        // Each header: key_len + key + value_len + value
        for (key, value) in &signable {
            let key_bytes = key.as_bytes();
            let value_bytes = value.as_bytes();
            payload.extend_from_slice(&to_var_int(key_bytes.len() as u64));
            payload.extend_from_slice(key_bytes);
            payload.extend_from_slice(&to_var_int(value_bytes.len() as u64));
            payload.extend_from_slice(value_bytes);
        }

        // Body length as varint + body bytes
        payload.extend_from_slice(&to_var_int(self.body.len() as u64));
        payload.extend_from_slice(&self.body);

        payload
    }
}

/// Builds a binary request payload for BRC-104 signature verification.
///
/// Format: version(1) || request_id(32) || method || path || search || headers || body
/// All strings are varint-length-prefixed.
pub fn build_request_payload(
    request_id: &[u8; 32],
    method: &str,
    path: &str,
    search: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();

    // Version byte
    payload.push(0x00);

    // Request ID (32 bytes)
    payload.extend_from_slice(request_id);

    // Method
    let method_bytes = method.as_bytes();
    payload.extend_from_slice(&to_var_int(method_bytes.len() as u64));
    payload.extend_from_slice(method_bytes);

    // Path
    let path_bytes = path.as_bytes();
    payload.extend_from_slice(&to_var_int(path_bytes.len() as u64));
    payload.extend_from_slice(path_bytes);

    // Search/query
    let search_bytes = search.as_bytes();
    payload.extend_from_slice(&to_var_int(search_bytes.len() as u64));
    payload.extend_from_slice(search_bytes);

    // Headers (only signable ones)
    let signable = filter_signable_headers(headers);
    payload.extend_from_slice(&to_var_int(signable.len() as u64));
    for (key, value) in &signable {
        let key_bytes = key.as_bytes();
        let value_bytes = value.as_bytes();
        payload.extend_from_slice(&to_var_int(key_bytes.len() as u64));
        payload.extend_from_slice(key_bytes);
        payload.extend_from_slice(&to_var_int(value_bytes.len() as u64));
        payload.extend_from_slice(value_bytes);
    }

    // Body
    payload.extend_from_slice(&to_var_int(body.len() as u64));
    payload.extend_from_slice(body);

    payload
}

/// Filters headers to only include those that should be signed.
///
/// Signable headers:
/// - `x-bsv-*` (excluding `x-bsv-auth-*` which are protocol headers)
/// - `authorization`
/// - `content-type` (media type only, parameters stripped)
pub fn filter_signable_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for (key, value) in headers {
        let lower = key.to_lowercase();
        if (lower.starts_with("x-bsv-") && !lower.starts_with("x-bsv-auth-"))
            || lower == "authorization"
        {
            result.push((lower, value.clone()));
        } else if lower == "content-type" {
            // Strip parameters (e.g., "; charset=utf-8"), keep only media type
            let media_type = value.split(';').next().unwrap_or(value).trim().to_string();
            result.push((lower, media_type));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // The three tests below ran the transport's own `write_varint`, deleted
    // in 0.5.0 for bsv-rs's `to_var_int`; they now hold the bytes the payload
    // writes through bsv-rs to the same values.
    #[test]
    fn test_write_varint_small() {
        assert_eq!(to_var_int(0), vec![0]);
        assert_eq!(to_var_int(1), vec![1]);
        assert_eq!(to_var_int(252), vec![252]);
    }

    #[test]
    fn test_write_varint_medium() {
        let result = to_var_int(253);
        assert_eq!(result[0], 253);
        assert_eq!(result.len(), 3);
    }

    // `write_varint(-1)` wrote `[0]`; no payload field can be negative (each
    // is a `u16` status or a length), so bsv-rs's `u64` makes the case
    // unwritable. The test now holds what the old one guarded: an empty body
    // is written as the one byte 0.
    #[test]
    fn test_write_varint_negative() {
        let payload = build_request_payload(&[0u8; 32], "", "", "", &[], &[]);
        assert_eq!(payload, [&[0u8][..], &[0u8; 32], &[0, 0, 0, 0, 0]].concat());
    }

    #[test]
    fn test_filter_signable_headers() {
        let headers = vec![
            ("x-bsv-payment".to_string(), "data".to_string()),
            ("x-bsv-auth-signature".to_string(), "sig".to_string()),
            ("authorization".to_string(), "Bearer tok".to_string()),
            (
                "content-type".to_string(),
                "application/json; charset=utf-8".to_string(),
            ),
            ("x-random".to_string(), "ignored".to_string()),
        ];
        let result = filter_signable_headers(&headers);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, "x-bsv-payment");
        assert_eq!(result[1].0, "authorization");
        assert_eq!(result[2].0, "content-type");
        assert_eq!(result[2].1, "application/json"); // params stripped
    }

    #[test]
    fn test_http_request_data_url() {
        let data = HttpRequestData {
            request_id: [0u8; 32],
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            search: "foo=bar".to_string(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(data.url(), "/api/test?foo=bar");
    }

    #[test]
    fn test_http_request_data_url_no_search() {
        let data = HttpRequestData {
            request_id: [0u8; 32],
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            search: "".to_string(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(data.url(), "/api/test");
    }
}
