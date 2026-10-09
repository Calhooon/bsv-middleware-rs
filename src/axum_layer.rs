//! The payment gate for Axum 0.8 (feature `axum`): the Axum wiring over
//! `crate::payment_core`, and nothing of the rule itself.
//!
//! ```ignore
//! let gate = Arc::new(PaymentGate::new(wallet, 100, Some(headers)));
//! let paid = Router::new()
//!     .route("/api/generate", post(generate)) // takes `VerifiedPayment`
//!     .layer(axum::middleware::from_fn_with_state(gate, require_payment))
//!     .layer(/* the BRC-103/104 auth layer, which inserts `AuthContext` */);
//! ```
//!
//! The gate runs after authentication (it reads the session identity from the
//! request's [`AuthContext`], the payer the BRC-29 key is derived for) and
//! before the handler. The flow and codes follow the reference express
//! middleware (`[SRC] ts-stack@fb1b2da
//! packages/middleware/payment-express-middleware/src/index.ts:244-327`):
//! no auth is 500 `ERR_SERVER_MISCONFIGURED`; no `x-bsv-payment` header is
//! 402 with a challenge; a header that does not parse is 400
//! `ERR_MALFORMED_PAYMENT`; a prefix this server did not issue is 400
//! `ERR_INVALID_DERIVATION_PREFIX`. The verdict is then answered in one match
//! in [`require_payment`]; there the gate departs from the reference, which
//! answers every refusal 400 (`index.ts:318-327`): a payment that pays the
//! wrong key or too little is answered 402 with a fresh challenge, so the
//! client can pay again.
//!
//! The gate does not internalize the payment or claim it against replay: the
//! handler receives [`VerifiedPayment`] (the transaction, the remittance and
//! the amount read) and internalizes it with its wallet.
//!
//! # A payment of any size: the body transport
//!
//! The reference carries the payment in the `x-bsv-payment` header as base64
//! inside JSON, so the HTTP server's header budget decides how large a
//! payment can be. This gate reads that transport unchanged, and a second
//! one for a payment a header cannot carry: the header's JSON names
//! `derivationPrefix` and `derivationSuffix` and no `transaction`, and the
//! request body is the BEEF's bytes as they are (no base64, no JSON). The
//! gate streams the body frame by frame through the verifier
//! ([`verify_payment_async`]): it never waits for the whole body before it
//! judges, it stops reading at the soonest invalid byte, and it refuses
//! nothing for its size or its counts. The 402 challenge names both
//! transports (`x-bsv-payment-transports: header,body`). The body transport
//! is this crate's own; the reference at the pin has the header alone.
//!
//! The verifier's memory is one element of the BEEF and its index. The gate
//! itself keeps the bytes it read, because [`VerifiedPayment::transaction`]
//! hands them to the handler to internalize; the handler's request body is
//! empty, the body having been the payment.

use std::pin::Pin;
use std::sync::Arc;

use axum::body::{Body, HttpBody};
use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bsv_rs::primitives::PublicKey;
use bsv_rs::wallet::ProtoWallet;
use serde::Deserialize;
use serde_json::json;

use crate::payment::{
    build_402_headers, create_derivation_prefix, payment_headers, verify_derivation_prefix,
};
use crate::payment_core::{
    brc29_locking_script, verify_payment, verify_payment_async, AsyncByteSource, HeaderService,
    PaymentToVerify, PaymentVerdict,
};
use crate::types::AuthContext;

/// The output a payment is internalized at: the reference internalizes
/// output 0 (`index.ts:339`).
pub const PAYMENT_OUTPUT_INDEX: u32 = 0;

/// The transports the challenge names: the reference's header, and the
/// request body for a payment a header cannot carry.
pub const PAYMENT_TRANSPORTS: &str = "header,body";

/// The `x-bsv-payment` header: the remittance, and the transaction when it
/// travels in the header. Without one, the request body is the transaction.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PaymentHeader {
    derivation_prefix: String,
    derivation_suffix: String,
    #[serde(default)]
    transaction: Option<String>,
}

/// The request body as the verifier's byte source, one frame at a time. The
/// bytes read are kept for the handler.
struct BodySource {
    body: Body,
    read: Vec<u8>,
}

impl AsyncByteSource for BodySource {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            let frame = std::future::poll_fn(|cx| Pin::new(&mut self.body).poll_frame(cx)).await;
            match frame {
                None => return Ok(None),
                Some(Err(e)) => return Err(std::io::Error::other(e)),
                // A frame that is not data (trailers) carries no payment byte.
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.read.extend_from_slice(&data);
                        return Ok(Some(data.to_vec()));
                    }
                }
            }
        }
    }
}

/// The gate's configuration: the server's wallet (the BRC-29 recipient and the
/// challenge's HMAC key), the price, and the header service (`None` refuses
/// every payment as a server fault).
pub struct PaymentGate {
    wallet: ProtoWallet,
    satoshis_required: u64,
    header_service: Option<Arc<dyn HeaderService>>,
}

impl PaymentGate {
    /// A gate charging `satoshis_required` (0 serves without a payment).
    pub fn new(
        wallet: ProtoWallet,
        satoshis_required: u64,
        header_service: Option<Arc<dyn HeaderService>>,
    ) -> Self {
        Self {
            wallet,
            satoshis_required,
            header_service,
        }
    }
}

/// A payment the gate verified, for the handler: extract it as an argument.
/// Without the gate in front, extracting it is a 500.
#[derive(Debug, Clone)]
pub struct VerifiedPayment {
    /// Satoshis read from the paying output (at least the price).
    pub satoshis_paid: u64,
    /// The transaction as sent (BEEF bytes, from the header or the body), to
    /// internalize.
    pub transaction: Vec<u8>,
    /// The output that pays ([`PAYMENT_OUTPUT_INDEX`]).
    pub output_index: u32,
    /// The derivation prefix (issued by this server).
    pub derivation_prefix: String,
    /// The derivation suffix (chosen by the payer).
    pub derivation_suffix: String,
    /// The payer: the authenticated session's identity key.
    pub sender_identity_key: String,
}

/// The gate: `axum::middleware::from_fn_with_state(gate, require_payment)`.
pub async fn require_payment(
    State(gate): State<Arc<PaymentGate>>,
    mut request: Request,
    next: Next,
) -> Response {
    let sender = match request.extensions().get::<AuthContext>() {
        Some(auth) if auth.is_authenticated && PublicKey::from_hex(&auth.identity_key).is_ok() => {
            auth.identity_key.clone()
        }
        _ => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_SERVER_MISCONFIGURED",
                "The payment middleware must run after successful Auth middleware.",
            )
        }
    };
    if gate.satoshis_required == 0 {
        return next.run(request).await;
    }
    let Some(header) = request.headers().get(payment_headers::PAYMENT) else {
        return challenge(
            &gate,
            "ERR_PAYMENT_REQUIRED",
            "A BSV payment is required. Provide the X-BSV-Payment header.",
        );
    };
    let Some(payment) = header
        .to_str()
        .ok()
        .and_then(|h| serde_json::from_str::<PaymentHeader>(h).ok())
    else {
        return error(
            StatusCode::BAD_REQUEST,
            "ERR_MALFORMED_PAYMENT",
            "The X-BSV-Payment header is malformed.",
        );
    };
    if !verify_derivation_prefix(&gate.wallet, &payment.derivation_prefix).unwrap_or(false) {
        return error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_DERIVATION_PREFIX",
            "The payment derivation prefix is invalid.",
        );
    }
    let expected_script = match brc29_locking_script(
        &gate.wallet,
        &payment.derivation_prefix,
        &payment.derivation_suffix,
        &sender,
    ) {
        Ok(script) => script,
        Err(reason) => {
            return error(
                StatusCode::BAD_REQUEST,
                "ERR_INVALID_PAYMENT",
                &reason.to_string(),
            )
        }
    };
    let to_verify = PaymentToVerify {
        output_index: PAYMENT_OUTPUT_INDEX,
        expected_script: &expected_script,
        required_satoshis: gate.satoshis_required,
    };
    let headers = gate.header_service.as_deref();
    let (read, transaction) = match &payment.transaction {
        // The reference's transport: the transaction in the header.
        Some(encoded) => {
            let Ok(transaction) = STANDARD.decode(encoded) else {
                return error(
                    StatusCode::BAD_REQUEST,
                    "ERR_INVALID_PAYMENT",
                    "The payment transaction is not base64.",
                );
            };
            let read = verify_payment(&to_verify, &transaction[..], headers).await;
            (read, transaction)
        }
        // The body transport: the body is the transaction, streamed.
        None => {
            let (parts, body) = request.into_parts();
            let mut source = BodySource {
                body,
                read: Vec::new(),
            };
            let read = verify_payment_async(&to_verify, &mut source, headers).await;
            request = Request::from_parts(parts, Body::empty());
            (read, source.read)
        }
    };
    // The source failed (a body cut off in flight): no verdict on the payment.
    let Ok(verdict) = read else {
        return error(
            StatusCode::BAD_REQUEST,
            "ERR_INVALID_PAYMENT",
            "The payment body could not be read.",
        );
    };
    // The six words to HTTP, in one match.
    let description = verdict.to_string();
    let satoshis_paid = match verdict {
        PaymentVerdict::Verified { satoshis } => satoshis,
        PaymentVerdict::Underpaid { .. } | PaymentVerdict::WrongScript { .. } => {
            return challenge(&gate, "ERR_INVALID_PAYMENT", &description)
        }
        PaymentVerdict::NoHeaderService => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_SERVER_MISCONFIGURED",
                &description,
            )
        }
        PaymentVerdict::RootMismatch { .. } => {
            return error(StatusCode::BAD_REQUEST, "ERR_INVALID_PAYMENT", &description)
        }
        PaymentVerdict::Unverifiable(reason) if reason.is_server_side() => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_PAYMENT_UNAVAILABLE",
                &description,
            )
        }
        PaymentVerdict::Unverifiable(_) => {
            return error(StatusCode::BAD_REQUEST, "ERR_INVALID_PAYMENT", &description)
        }
    };
    request.extensions_mut().insert(VerifiedPayment {
        satoshis_paid,
        transaction,
        output_index: PAYMENT_OUTPUT_INDEX,
        derivation_prefix: payment.derivation_prefix,
        derivation_suffix: payment.derivation_suffix,
        sender_identity_key: sender,
    });
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        HeaderName::from_static(payment_headers::SATOSHIS_PAID),
        HeaderValue::from(satoshis_paid),
    );
    response
}

/// 402 with a fresh derivation prefix (`index.ts:183-208`); 503 if none can
/// be made.
fn challenge(gate: &PaymentGate, code: &str, description: &str) -> Response {
    let Ok(prefix) = create_derivation_prefix(&gate.wallet) else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_PAYMENT_UNAVAILABLE",
            "Payment processing is temporarily unavailable.",
        );
    };
    let mut response = (
        StatusCode::PAYMENT_REQUIRED,
        axum::Json(json!({
            "status": "error",
            "code": code,
            "satoshisRequired": gate.satoshis_required,
            "description": description,
        })),
    )
        .into_response();
    for (name, value) in build_402_headers(gate.satoshis_required, &prefix) {
        if let (Ok(name), Ok(value)) = (HeaderName::try_from(name), HeaderValue::try_from(value)) {
            response.headers_mut().insert(name, value);
        }
    }
    response.headers_mut().insert(
        HeaderName::from_static(payment_headers::TRANSPORTS),
        HeaderValue::from_static(PAYMENT_TRANSPORTS),
    );
    response
}

/// The reference's error body (`index.ts:124-137`).
fn error(status: StatusCode, code: &str, description: &str) -> Response {
    (
        status,
        axum::Json(json!({ "status": "error", "code": code, "description": description })),
    )
        .into_response()
}

impl<S: Send + Sync> FromRequestParts<S> for VerifiedPayment {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<VerifiedPayment>()
            .cloned()
            .ok_or_else(|| {
                error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ERR_SERVER_MISCONFIGURED",
                    "No verified payment: the payment gate is not in front of this route.",
                )
            })
    }
}
