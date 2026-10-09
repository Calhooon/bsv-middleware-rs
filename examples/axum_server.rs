//! # Axum Server with BRC-31 Auth + BRC-29 Micropayments
//!
//! A complete BSV-authenticated API server using Axum.
//!
//! ```bash
//! cargo run --example axum_server
//! ```
//!
//! ## Endpoints
//!
//! | Method | Path                | Auth | Payment | Description            |
//! |--------|---------------------|------|---------|------------------------|
//! | POST   | `/.well-known/auth` | No   | No      | BRC-31 handshake       |
//! | GET    | `/api/hello`        | Yes  | No      | Free authenticated API |
//! | POST   | `/api/generate`     | Yes  | 100 sat | Paid API endpoint      |

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bsv_middleware_rs::payment::{
    build_402_headers, create_derivation_prefix, parse_payment_header, payment_headers,
    verify_derivation_prefix,
};
use bsv_middleware_rs::transport::{
    auth_headers, build_request_payload, filter_signable_headers, HttpResponseData,
};
use bsv_middleware_rs::{sign_message, verify_message_signature, SessionStorage, StoredSession};
use bsv_rs::auth::{AuthMessage, MessageType, AUTH_VERSION};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::{Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel};
use bsv_rs::PublicKey;
use serde_json::json;
use tokio::sync::RwLock;

// ─── In-Memory Session Storage ──────────────────────────────────────────
//
// Replace this with Redis, PostgreSQL, etc. in production.

struct MemorySessionStorage {
    by_nonce: RwLock<HashMap<String, StoredSession>>,
    by_identity: RwLock<HashMap<String, String>>,
}

impl MemorySessionStorage {
    fn new() -> Self {
        Self {
            by_nonce: RwLock::new(HashMap::new()),
            by_identity: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl SessionStorage for MemorySessionStorage {
    async fn get_session(&self, nonce: &str) -> bsv_middleware_rs::Result<Option<StoredSession>> {
        Ok(self.by_nonce.read().await.get(nonce).cloned())
    }

    async fn save_session(&self, session: &StoredSession) -> bsv_middleware_rs::Result<()> {
        self.by_identity.write().await.insert(
            session.peer_identity_key.clone(),
            session.session_nonce.clone(),
        );
        self.by_nonce
            .write()
            .await
            .insert(session.session_nonce.clone(), session.clone());
        Ok(())
    }

    async fn remove_session(&self, nonce: &str) -> bsv_middleware_rs::Result<()> {
        if let Some(s) = self.by_nonce.write().await.remove(nonce) {
            self.by_identity.write().await.remove(&s.peer_identity_key);
        }
        Ok(())
    }

    async fn update_session(&self, session: &StoredSession) -> bsv_middleware_rs::Result<()> {
        self.save_session(session).await
    }

    async fn has_session(&self, nonce: &str) -> bsv_middleware_rs::Result<bool> {
        Ok(self.by_nonce.read().await.contains_key(nonce))
    }

    async fn get_session_by_identity(
        &self,
        identity_key: &str,
    ) -> bsv_middleware_rs::Result<Option<StoredSession>> {
        let ids = self.by_identity.read().await;
        match ids.get(identity_key) {
            Some(nonce) => Ok(self.by_nonce.read().await.get(nonce).cloned()),
            None => Ok(None),
        }
    }
}

// ─── App State ──────────────────────────────────────────────────────────

struct AppState {
    wallet: ProtoWallet,
    sessions: MemorySessionStorage,
}

// ─── BRC-31 Handshake ───────────────────────────────────────────────────
//
// The client sends an InitialRequest, and we return an InitialResponse
// with our identity key and a signed session nonce.

async fn auth_handshake(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let msg: AuthMessage = match serde_json::from_slice(&body) {
        Ok(m) => m,
        Err(e) => return err_json(StatusCode::BAD_REQUEST, "ERR_PARSE", &e.to_string()),
    };

    if msg.message_type != MessageType::InitialRequest {
        return err_json(
            StatusCode::BAD_REQUEST,
            "ERR_TYPE",
            "Expected initialRequest",
        );
    }

    // Generate server session nonce (HMAC-based, stateless-verifiable)
    let session_nonce = match create_derivation_prefix(&state.wallet) {
        Ok(n) => n,
        Err(e) => {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_NONCE",
                &e.to_string(),
            )
        }
    };

    let peer_nonce = msg.initial_nonce.clone().or_else(|| msg.nonce.clone());

    // Create and persist session
    let mut session = StoredSession::new(session_nonce.clone(), msg.identity_key.to_hex());
    session.peer_nonce = peer_nonce.clone();
    session.is_authenticated = true;

    if let Err(e) = state.sessions.save_session(&session).await {
        return err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_STORAGE",
            &e.to_string(),
        );
    }

    // Build InitialResponse
    let server_key = state.wallet.identity_key();
    let mut resp = AuthMessage::new(MessageType::InitialResponse, server_key.clone());
    resp.nonce = Some(session_nonce.clone());
    resp.initial_nonce = Some(session_nonce);
    resp.your_nonce = peer_nonce;

    // Sign — InitialResponse uses its own signing_data() and get_key_id()
    let data = resp.signing_data();
    let key_id = resp.get_key_id(None);
    match state.wallet.create_signature(CreateSignatureArgs {
        data: Some(data),
        hash_to_directly_sign: None,
        protocol_id: Protocol::new(SecurityLevel::App, "auth message signature"),
        key_id,
        counterparty: Some(Counterparty::Other(msg.identity_key.clone())),
    }) {
        Ok(r) => resp.signature = Some(r.signature),
        Err(e) => {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_SIGN",
                &e.to_string(),
            )
        }
    }

    // Return JSON body + BRC-104 headers
    let mut headers = HeaderMap::new();
    headers.insert(auth_headers::VERSION, AUTH_VERSION.parse().unwrap());
    headers.insert(
        auth_headers::IDENTITY_KEY,
        server_key.to_hex().parse().unwrap(),
    );
    headers.insert(
        auth_headers::MESSAGE_TYPE,
        "initialResponse".parse().unwrap(),
    );
    headers.insert("content-type", "application/json".parse().unwrap());

    let body = serde_json::to_string(&resp).unwrap();
    (StatusCode::OK, headers, body).into_response()
}

// ─── Auth Middleware ────────────────────────────────────────────────────
//
// Verifies BRC-31 auth headers on every request. Extracts the binary
// request payload (method + path + query + headers + body), verifies
// the signature, and passes `Authenticated` to the handler.

#[derive(Clone)]
struct Authenticated {
    pub identity_key: String,
    pub session: StoredSession,
    pub request_id: [u8; 32],
    pub body: Bytes,
}

async fn require_auth(
    State(state): State<Arc<AppState>>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let hdrs = request.headers();

    if !hdrs.contains_key(auth_headers::SIGNATURE) {
        return err_json(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Auth required");
    }

    // Extract BRC-104 headers
    let hdr = |name: &str| {
        hdrs.get(name)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    };
    let identity_hex = require_hdr!(hdr(auth_headers::IDENTITY_KEY), "Missing identity key");
    let sig_hex = require_hdr!(hdr(auth_headers::SIGNATURE), "Missing signature");
    let req_id_b64 = require_hdr!(hdr(auth_headers::REQUEST_ID), "Missing request ID");
    let nonce = hdr(auth_headers::NONCE);
    let your_nonce = hdr(auth_headers::YOUR_NONCE);

    // Decode request ID (32 bytes, base64)
    let request_id: [u8; 32] = match B64.decode(&req_id_b64) {
        Ok(b) if b.len() == 32 => b.try_into().unwrap(),
        _ => return err_json(StatusCode::UNAUTHORIZED, "ERR_AUTH", "Bad request ID"),
    };

    // Decode DER signature
    let signature = match hex::decode(&sig_hex) {
        Ok(s) => s,
        Err(_) => return err_json(StatusCode::UNAUTHORIZED, "ERR_AUTH", "Bad signature hex"),
    };

    // Look up session — your_nonce is the server's session nonce
    let session = match &your_nonce {
        Some(yn) => state.sessions.get_session(yn).await.ok().flatten(),
        None => state
            .sessions
            .get_session_by_identity(&identity_hex)
            .await
            .ok()
            .flatten(),
    };
    let session = match session {
        Some(s) if s.is_authenticated => s,
        _ => {
            return err_json(
                StatusCode::UNAUTHORIZED,
                "ERR_SESSION",
                "No session. POST /.well-known/auth first.",
            )
        }
    };

    // Capture request metadata before consuming body
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let query = request.uri().query().unwrap_or("").to_string();
    let raw_headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let signable = filter_signable_headers(&raw_headers);

    // Consume body
    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 10_000_000).await {
        Ok(b) => b,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "ERR_BODY", "Body too large"),
    };

    // Build BRC-104 binary payload and verify signature
    let payload =
        build_request_payload(&request_id, &method, &path, &query, &signable, &body_bytes);

    let peer_key = match PublicKey::from_hex(&identity_hex) {
        Ok(k) => k,
        Err(_) => return err_json(StatusCode::UNAUTHORIZED, "ERR_AUTH", "Invalid identity key"),
    };

    let mut auth_msg = AuthMessage::new(MessageType::General, peer_key);
    auth_msg.nonce = nonce;
    auth_msg.your_nonce = your_nonce;
    auth_msg.signature = Some(signature);
    auth_msg.payload = Some(payload);

    match verify_message_signature(&state.wallet, &auth_msg, &session) {
        Ok(true) => {}
        Ok(false) => return err_json(StatusCode::UNAUTHORIZED, "ERR_AUTH", "Signature invalid"),
        Err(e) => {
            return err_json(
                StatusCode::UNAUTHORIZED,
                "ERR_AUTH",
                &format!("Verify error: {}", e),
            )
        }
    }

    // Pass auth context to handler via extension
    let auth = Authenticated {
        identity_key: identity_hex,
        session,
        request_id,
        body: body_bytes,
    };
    let mut req = axum::http::Request::from_parts(parts, axum::body::Body::empty());
    req.extensions_mut().insert(auth);
    next.run(req).await
}

/// Helper macro — returns 401 if a header is missing.
macro_rules! require_hdr {
    ($expr:expr, $msg:literal) => {
        match $expr {
            Some(v) => v,
            None => return err_json(StatusCode::UNAUTHORIZED, "ERR_AUTH", $msg),
        }
    };
}
use require_hdr;

// ─── Signed Response Helper ────────────────────────────────────────────
//
// Signs a JSON response body using BRC-104 and attaches all auth headers.

fn signed_response(
    wallet: &ProtoWallet,
    session: &StoredSession,
    request_id: &[u8; 32],
    status: StatusCode,
    data: serde_json::Value,
    extra_headers: Vec<(String, String)>,
) -> Response {
    let body_bytes = serde_json::to_vec(&data).unwrap();

    // Build response payload for signing
    let resp_data = HttpResponseData {
        request_id: *request_id,
        status: status.as_u16(),
        headers: extra_headers.clone(),
        body: body_bytes.clone(),
    };
    let payload = resp_data.to_payload();

    // Create General response message with random nonce
    let server_key = wallet.identity_key();
    let mut msg = AuthMessage::new(MessageType::General, server_key.clone());
    let mut rng = [0u8; 32];
    getrandom::fill(&mut rng).unwrap();
    msg.nonce = Some(B64.encode(rng));
    msg.your_nonce = session.peer_nonce.clone();
    msg.payload = Some(payload);

    // Sign using middleware (handles key derivation for General messages)
    if let Err(e) = sign_message(wallet, &mut msg, session) {
        return err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_SIGN",
            &e.to_string(),
        );
    }

    // Attach BRC-104 auth headers
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/json".parse().unwrap());
    headers.insert(auth_headers::VERSION, AUTH_VERSION.parse().unwrap());
    headers.insert(
        auth_headers::IDENTITY_KEY,
        server_key.to_hex().parse().unwrap(),
    );
    headers.insert(auth_headers::MESSAGE_TYPE, "general".parse().unwrap());
    headers.insert(auth_headers::NONCE, msg.nonce.unwrap().parse().unwrap());
    if let Some(ref yn) = msg.your_nonce {
        headers.insert(auth_headers::YOUR_NONCE, yn.parse().unwrap());
    }
    headers.insert(
        auth_headers::SIGNATURE,
        hex::encode(msg.signature.unwrap()).parse().unwrap(),
    );
    headers.insert(
        auth_headers::REQUEST_ID,
        B64.encode(request_id).parse().unwrap(),
    );

    for (k, v) in &extra_headers {
        if let (Ok(name), Ok(val)) = (
            k.parse::<axum::http::HeaderName>(),
            v.parse::<axum::http::HeaderValue>(),
        ) {
            headers.insert(name, val);
        }
    }

    (status, headers, body_bytes).into_response()
}

// ─── Route Handlers ─────────────────────────────────────────────────────

/// GET /api/hello — free, authenticated endpoint.
async fn hello(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<Authenticated>,
) -> Response {
    let short_key = &auth.identity_key[..12];
    signed_response(
        &state.wallet,
        &auth.session,
        &auth.request_id,
        StatusCode::OK,
        json!({ "message": format!("Hello, {}...!", short_key) }),
        vec![],
    )
}

/// POST /api/generate — paid endpoint, 100 satoshis per request.
async fn generate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(auth): Extension<Authenticated>,
) -> Response {
    let price: u64 = 100;

    // Check for payment header
    let payment_value = headers
        .get(payment_headers::PAYMENT)
        .and_then(|v| v.to_str().ok());

    match payment_value {
        // No payment → return 402 with payment instructions
        None => {
            let prefix = match create_derivation_prefix(&state.wallet) {
                Ok(p) => p,
                Err(e) => {
                    return err_json(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "ERR_NONCE",
                        &e.to_string(),
                    )
                }
            };

            let pay_headers = build_402_headers(price, &prefix);
            let mut hdrs = HeaderMap::new();
            for (k, v) in &pay_headers {
                if let (Ok(name), Ok(val)) = (
                    k.parse::<axum::http::HeaderName>(),
                    v.parse::<axum::http::HeaderValue>(),
                ) {
                    hdrs.insert(name, val);
                }
            }

            let body = json!({
                "status": "error",
                "code": "ERR_PAYMENT_REQUIRED",
                "satoshisRequired": price,
                "description": "Send 100 satoshis to access this endpoint."
            });

            (
                StatusCode::PAYMENT_REQUIRED,
                hdrs,
                serde_json::to_string(&body).unwrap(),
            )
                .into_response()
        }

        // Payment provided → verify and fulfill
        Some(payment_json) => {
            let payment = match parse_payment_header(payment_json) {
                Ok(p) => p,
                Err(_) => {
                    return err_json(
                        StatusCode::BAD_REQUEST,
                        "ERR_PAYMENT",
                        "Invalid payment JSON",
                    )
                }
            };

            // Verify the derivation prefix was issued by this server
            match verify_derivation_prefix(&state.wallet, &payment.derivation_prefix) {
                Ok(true) => {}
                _ => {
                    return err_json(
                        StatusCode::BAD_REQUEST,
                        "ERR_PAYMENT",
                        "Invalid derivation prefix",
                    )
                }
            }

            // TODO: In production, internalize the transaction via your wallet:
            //   wallet.internalize_action(payment.transaction, outputs, ...)
            // This example accepts the payment on trust for demonstration.

            signed_response(
                &state.wallet,
                &auth.session,
                &auth.request_id,
                StatusCode::OK,
                json!({
                    "result": "Here is your generated content!",
                    "satoshis_paid": price,
                }),
                vec![(
                    payment_headers::SATOSHIS_PAID.to_string(),
                    price.to_string(),
                )],
            )
        }
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────

fn err_json(status: StatusCode, code: &str, desc: &str) -> Response {
    (
        status,
        Json(json!({ "status": "error", "code": code, "description": desc })),
    )
        .into_response()
}

// ─── Main ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // In production, load from env: SERVER_PRIVATE_KEY
    let server_key = PrivateKey::random();
    let wallet = ProtoWallet::new(Some(server_key));

    println!("BSV Auth Server starting");
    println!("  Identity: {}", wallet.identity_key_hex());
    println!("  Endpoints:");
    println!("    POST /.well-known/auth  — BRC-31 handshake");
    println!("    GET  /api/hello         — authenticated (free)");
    println!("    POST /api/generate      — authenticated (100 sat)");
    println!();

    let state = Arc::new(AppState {
        wallet,
        sessions: MemorySessionStorage::new(),
    });

    // Protected routes with auth middleware
    let api = Router::new()
        .route("/api/hello", get(hello))
        .route("/api/generate", post(generate))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let app = Router::new()
        .route("/.well-known/auth", post(auth_handshake))
        .merge(api)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Listening on http://localhost:3000");
    axum::serve(listener, app).await.unwrap();
}
