//! BRC-104 HTTP transport: header constants and binary payload serialization.
//!
//! This module provides the wire format for BSV authentication headers
//! and the varint-based payload serialization used for message signing.

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
        payload.extend_from_slice(&write_varint(self.status as i64));

        // Number of headers as varint
        let signable = filter_signable_headers(&self.headers);
        payload.extend_from_slice(&write_varint(signable.len() as i64));

        // Each header: key_len + key + value_len + value
        for (key, value) in &signable {
            let key_bytes = key.as_bytes();
            let value_bytes = value.as_bytes();
            payload.extend_from_slice(&write_varint(key_bytes.len() as i64));
            payload.extend_from_slice(key_bytes);
            payload.extend_from_slice(&write_varint(value_bytes.len() as i64));
            payload.extend_from_slice(value_bytes);
        }

        // Body length as varint + body bytes
        payload.extend_from_slice(&write_varint(self.body.len() as i64));
        payload.extend_from_slice(&self.body);

        payload
    }
}

/// Builds a binary request payload for BRC-104 signature verification.
///
/// This delegates to the canonical `bsv-rs` builder
/// ([`bsv_rs::auth::transports::HttpRequest::to_payload`]) so the bytes are
/// guaranteed byte-identical to the canonical `@bsv` wire used by
/// `bsv-middleware-cloudflare`. There is exactly one payload encoder in the
/// stack — we do not hand-maintain a second one here.
///
/// Canonical layout (NO leading version byte):
/// `[request_id 32B][method: varint+str][path: varint(-1 if empty)+str]
///  [search: varint(-1 if empty)+str][headers: varint(count)+(klen,key,vlen,val)*]
///  [body: varint(-1 if empty)+bytes]`
///
/// Headers are filtered to the signable set ([`filter_signable_headers`]) and
/// sorted alphabetically by key before encoding.
pub fn build_request_payload(
    request_id: &[u8; 32],
    method: &str,
    path: &str,
    search: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    // 1. Filter to the signable header set, 2. sorted alphabetically by key.
    let sorted_signable = filter_signable_headers(headers);

    // 3. Construct the canonical request and serialize via the single source
    //    of truth in bsv-rs.
    let request = bsv_rs::auth::transports::HttpRequest {
        request_id: *request_id,
        method: method.to_string(),
        path: path.to_string(),
        search: search.to_string(),
        headers: sorted_signable,
        body: body.to_vec(),
    };

    request.to_payload()
}

/// Filters headers to only include those that should be signed, then sorts
/// them alphabetically by key.
///
/// Signable headers:
/// - `x-bsv-*` (excluding `x-bsv-auth-*` which are protocol headers)
/// - `authorization`
/// - `content-type` (media type only, parameters stripped)
///
/// The result is sorted alphabetically by (lowercased) key to match the
/// canonical `@bsv` wire format (and the canonical `bsv-rs` SDK), so that a
/// payload built here is byte-identical regardless of the caller's header
/// order.
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
    // Sort alphabetically by key to match the canonical wire format.
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

/// Encodes an integer as a Bitcoin-style varint.
///
/// This matches the BRC-104 binary serialization format used by all BSV SDKs.
pub fn write_varint(value: i64) -> Vec<u8> {
    if value < 0 {
        return vec![0];
    }
    let v = value as u64;
    if v < 253 {
        vec![v as u8]
    } else if v <= 0xFFFF {
        let mut buf = vec![253u8];
        buf.extend_from_slice(&(v as u16).to_le_bytes());
        buf
    } else if v <= 0xFFFF_FFFF {
        let mut buf = vec![254u8];
        buf.extend_from_slice(&(v as u32).to_le_bytes());
        buf
    } else {
        let mut buf = vec![255u8];
        buf.extend_from_slice(&v.to_le_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_varint_small() {
        assert_eq!(write_varint(0), vec![0]);
        assert_eq!(write_varint(1), vec![1]);
        assert_eq!(write_varint(252), vec![252]);
    }

    #[test]
    fn test_write_varint_medium() {
        let result = write_varint(253);
        assert_eq!(result[0], 253);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_write_varint_negative() {
        assert_eq!(write_varint(-1), vec![0]);
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
        // Result is sorted alphabetically by key (canonical wire order).
        assert_eq!(result[0].0, "authorization");
        assert_eq!(result[1].0, "content-type");
        assert_eq!(result[1].1, "application/json"); // params stripped
        assert_eq!(result[2].0, "x-bsv-payment");
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

    /// Conformance: `build_request_payload` MUST be byte-identical to the
    /// canonical `bsv-rs` wire (`HttpRequest::to_payload`), which is what
    /// `bsv-middleware-cloudflare` and the canonical `@bsv` SDK verify against.
    ///
    /// This guards the fund-critical bug where the pre-fix encoder prepended a
    /// `0x00` version byte, used `varint(0)` for empty fields (canonical uses
    /// `varint(-1)`), and did not sort the signable headers — making a
    /// `bsv-middleware-rs`-signed request fail to verify on a canonical server.
    ///
    /// Each case constructs the expected `HttpRequest` with the SAME
    /// filtered + sorted headers that `build_request_payload` produces, then
    /// asserts exact byte equality.
    #[test]
    fn build_request_payload_is_byte_identical_to_canonical() {
        // Helper: build the expected canonical bytes from already-prepared
        // (filtered + sorted) headers.
        let canonical = |request_id: [u8; 32],
                         method: &str,
                         path: &str,
                         search: &str,
                         headers: Vec<(String, String)>,
                         body: &[u8]|
         -> Vec<u8> {
            bsv_rs::auth::transports::HttpRequest {
                request_id,
                method: method.to_string(),
                path: path.to_string(),
                search: search.to_string(),
                headers,
                body: body.to_vec(),
            }
            .to_payload()
        };

        // (a) non-empty path + EMPTY search + non-empty body — the
        //     `/custody/put-share` shape that fails in production.
        {
            let request_id = [7u8; 32];
            let body = b"{\"share\":\"abc\"}";
            let raw = vec![("content-type".to_string(), "application/json".to_string())];
            let got =
                build_request_payload(&request_id, "POST", "/custody/put-share", "", &raw, body);
            let expected = canonical(
                request_id,
                "POST",
                "/custody/put-share",
                "",
                vec![("content-type".to_string(), "application/json".to_string())],
                body,
            );
            assert_eq!(got, expected, "case (a): put-share shape must be canonical");
            // Empty search → canonical -1 varint (0xFF * 9), never 0x00 nor varint(0).
            assert_ne!(
                got[0], 0x00,
                "case (a): must NOT have a leading version byte"
            );
        }

        // (b) empty body (and empty search) — both must use varint(-1).
        {
            let request_id = [0u8; 32];
            let raw: Vec<(String, String)> = vec![];
            let got = build_request_payload(&request_id, "GET", "/health", "", &raw, b"");
            let expected = canonical(request_id, "GET", "/health", "", vec![], b"");
            assert_eq!(got, expected, "case (b): empty body must be canonical");
        }

        // (c) multiple signable headers given OUT of alphabetical order —
        //     proves the builder sorts them (x-bsv-payment, authorization,
        //     content-type → authorization, content-type, x-bsv-payment).
        {
            let request_id = [3u8; 32];
            let body = b"payload";
            let raw = vec![
                ("x-bsv-payment".to_string(), "pmt".to_string()),
                ("authorization".to_string(), "Bearer tok".to_string()),
                ("content-type".to_string(), "application/json".to_string()),
            ];
            let got = build_request_payload(&request_id, "POST", "/pay", "", &raw, body);
            // Expected headers are the filtered + sorted set.
            let expected = canonical(
                request_id,
                "POST",
                "/pay",
                "",
                vec![
                    ("authorization".to_string(), "Bearer tok".to_string()),
                    ("content-type".to_string(), "application/json".to_string()),
                    ("x-bsv-payment".to_string(), "pmt".to_string()),
                ],
                body,
            );
            assert_eq!(
                got, expected,
                "case (c): headers must be sorted alphabetically"
            );
        }

        // (d) content-type with parameters — proves media-type stripping
        //     ("application/json; charset=utf-8" → "application/json").
        {
            let request_id = [9u8; 32];
            let body = b"{}";
            let raw = vec![(
                "content-type".to_string(),
                "application/json; charset=utf-8".to_string(),
            )];
            let got = build_request_payload(&request_id, "PUT", "/data", "", &raw, body);
            let expected = canonical(
                request_id,
                "PUT",
                "/data",
                "",
                vec![("content-type".to_string(), "application/json".to_string())],
                body,
            );
            assert_eq!(
                got, expected,
                "case (d): content-type params must be stripped"
            );
        }

        // (e) non-empty search — exercises the search field encoding too.
        {
            let request_id = [5u8; 32];
            let raw: Vec<(String, String)> = vec![];
            let got = build_request_payload(&request_id, "GET", "/list", "limit=10", &raw, b"");
            let expected = canonical(request_id, "GET", "/list", "limit=10", vec![], b"");
            assert_eq!(
                got, expected,
                "case (e): non-empty search must be canonical"
            );
        }
    }
}
