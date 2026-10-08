//! The Axum payment gate end to end: a router with `require_payment` in
//! front of a handler that takes `VerifiedPayment`, driven by crafted
//! payments (never signed, never broadcast) and a stub header service.
#![cfg(feature = "axum")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bsv_middleware_rs::axum_layer::{require_payment, PaymentGate, VerifiedPayment};
use bsv_middleware_rs::payment::{
    create_derivation_prefix, payment_headers, verify_derivation_prefix,
};
use bsv_middleware_rs::payment_core::BRC29_PROTOCOL_NAME;
use bsv_middleware_rs::{AuthContext, HeaderLookupError, HeaderService};
use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::wallet::{Counterparty, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel};
use serde_json::{json, Value};
use tower::ServiceExt;

const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const SENDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const OTHER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";
const SUFFIX: &str = "c3VmZml4";
const PRICE: u64 = 100;
const HEIGHT: u32 = 850_000;

fn wallet(hex: &str) -> ProtoWallet {
    ProtoWallet::new(Some(PrivateKey::from_hex(hex).unwrap()))
}

fn identity(hex: &str) -> String {
    wallet(hex).identity_key().to_hex()
}

fn p2pkh(hash: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(hash);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

/// The payer's side of BRC-29: the server's key for (prefix, suffix).
fn payer_script(payer: &str, prefix: &str) -> Vec<u8> {
    let derived = wallet(payer)
        .get_public_key(GetPublicKeyArgs {
            identity_key: false,
            protocol_id: Some(Protocol::new(
                SecurityLevel::Counterparty,
                BRC29_PROTOCOL_NAME,
            )),
            key_id: Some(format!("{} {}", prefix, SUFFIX)),
            counterparty: Some(Counterparty::Other(wallet(SERVER_KEY).identity_key())),
            for_self: Some(false),
        })
        .unwrap();
    p2pkh(&PublicKey::from_hex(&derived.public_key).unwrap().hash160())
}

/// A BEEF of one payment proven by a one-leaf BUMP at `HEIGHT`; the root is
/// the txid.
fn proven_beef(satoshis: u64, script: &[u8]) -> (Vec<u8>, String) {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput {
        source_txid: Some("11".repeat(32)),
        source_output_index: 0,
        ..Default::default()
    })
    .unwrap();
    tx.add_output(TransactionOutput::new(
        satoshis,
        LockingScript::from_binary(script).unwrap(),
    ))
    .unwrap();
    let txid = tx.id();
    let bump = MerklePath::new(
        HEIGHT,
        vec![vec![MerklePathLeaf::new_txid(0, txid.clone())]],
    )
    .unwrap();
    let mut beef = Beef::new();
    beef.merge_bump(bump);
    beef.merge_transaction(tx);
    (beef.to_binary(), txid)
}

/// Answers one root at `HEIGHT`, or fails every lookup.
struct StubHeaders(Result<String, HeaderLookupError>, Mutex<Vec<u32>>);

#[async_trait]
impl HeaderService for StubHeaders {
    async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError> {
        self.1.lock().unwrap().push(height);
        if height == HEIGHT {
            self.0.clone()
        } else {
            Err(HeaderLookupError("not indexed".into()))
        }
    }
}

struct App {
    router: Router,
    served: Arc<AtomicUsize>,
}

fn app(headers: Option<Arc<dyn HeaderService>>) -> App {
    let gate = Arc::new(PaymentGate::new(wallet(SERVER_KEY), PRICE, headers));
    let served = Arc::new(AtomicUsize::new(0));
    let count = served.clone();
    let router = Router::new()
        .route(
            "/paid",
            post(move |payment: VerifiedPayment| async move {
                count.fetch_add(1, Ordering::SeqCst);
                axum::Json(json!({
                    "satoshis_paid": payment.satoshis_paid,
                    "sender": payment.sender_identity_key,
                    "prefix": payment.derivation_prefix,
                    "suffix": payment.derivation_suffix,
                    "tx_len": payment.transaction.len(),
                }))
            }),
        )
        .layer(axum::middleware::from_fn_with_state(gate, require_payment));
    App { router, served }
}

fn headers_answering_root(root: &str) -> Option<Arc<dyn HeaderService>> {
    Some(Arc::new(StubHeaders(
        Ok(root.to_string()),
        Mutex::new(Vec::new()),
    )))
}

fn prefix() -> String {
    create_derivation_prefix(&wallet(SERVER_KEY)).unwrap()
}

fn payment_header(prefix: &str, tx: &[u8]) -> String {
    json!({ "derivationPrefix": prefix, "derivationSuffix": SUFFIX, "transaction": B64.encode(tx) })
        .to_string()
}

async fn send(
    app: &App,
    auth: Option<&str>,
    payment: Option<String>,
) -> (StatusCode, Response, Value) {
    let mut request = Request::post("/paid");
    if let Some(p) = payment {
        request = request.header(payment_headers::PAYMENT, p);
    }
    let mut request = request.body(Body::empty()).unwrap();
    if let Some(sender) = auth {
        request
            .extensions_mut()
            .insert(AuthContext::authenticated(sender.to_string()));
    }
    let response = app.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, Response::from_parts(parts, Body::empty()), body)
}

fn header<'a>(response: &'a Response, name: &str) -> Option<&'a str> {
    response.headers().get(name).and_then(|v| v.to_str().ok())
}

/// A fresh challenge: the price and a prefix this server issued, not `spent`.
fn assert_fresh_challenge(response: &Response, spent: Option<&str>) {
    assert_eq!(header(response, payment_headers::VERSION), Some("1.0"));
    assert_eq!(
        header(response, payment_headers::SATOSHIS_REQUIRED),
        Some("100")
    );
    let prefix = header(response, payment_headers::DERIVATION_PREFIX).expect("a challenge prefix");
    assert!(verify_derivation_prefix(&wallet(SERVER_KEY), prefix).unwrap());
    assert_ne!(Some(prefix), spent);
}

#[tokio::test]
async fn no_payment_is_answered_402_with_a_challenge() {
    let app = app(headers_answering_root(""));
    let (status, response, body) = send(&app, Some(&identity(SENDER_KEY)), None).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(body["code"], "ERR_PAYMENT_REQUIRED");
    assert_eq!(body["satoshisRequired"], PRICE);
    assert_fresh_challenge(&response, None);
    assert_eq!(app.served.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn exact_and_over_are_served_with_the_amount_read() {
    for paid in [PRICE, PRICE + 1] {
        let prefix = prefix();
        let (beef, root) = proven_beef(paid, &payer_script(SENDER_KEY, &prefix));
        let app = app(headers_answering_root(&root));
        let (status, response, body) = send(
            &app,
            Some(&identity(SENDER_KEY)),
            Some(payment_header(&prefix, &beef)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["satoshis_paid"], paid);
        assert_eq!(body["sender"], identity(SENDER_KEY));
        assert_eq!(body["prefix"], prefix);
        assert_eq!(body["suffix"], SUFFIX);
        assert_eq!(body["tx_len"], beef.len());
        assert_eq!(
            header(&response, payment_headers::SATOSHIS_PAID),
            Some(paid.to_string().as_str())
        );
        assert_eq!(app.served.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn underpaid_is_answered_402_with_a_fresh_challenge() {
    let prefix = prefix();
    let (beef, root) = proven_beef(PRICE - 1, &payer_script(SENDER_KEY, &prefix));
    let app = app(headers_answering_root(&root));
    let (status, response, body) = send(
        &app,
        Some(&identity(SENDER_KEY)),
        Some(payment_header(&prefix, &beef)),
    )
    .await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(body["code"], "ERR_INVALID_PAYMENT");
    assert_eq!(body["satoshisRequired"], PRICE);
    assert_fresh_challenge(&response, Some(&prefix));
    assert_eq!(app.served.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn wrong_script_is_answered_402_with_a_fresh_challenge() {
    let prefix = prefix();
    let (beef, root) = proven_beef(PRICE, &p2pkh(&[9u8; 20]));
    let app = app(headers_answering_root(&root));
    let (status, response, body) = send(
        &app,
        Some(&identity(SENDER_KEY)),
        Some(payment_header(&prefix, &beef)),
    )
    .await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(body["code"], "ERR_INVALID_PAYMENT");
    assert_fresh_challenge(&response, Some(&prefix));
    assert_eq!(app.served.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_session_identity_feeds_the_derivation() {
    // Paid for SENDER's derivation, but the session is OTHER's: not our key.
    let prefix = prefix();
    let (beef, root) = proven_beef(PRICE, &payer_script(SENDER_KEY, &prefix));
    let app = app(headers_answering_root(&root));
    let (status, response, _) = send(
        &app,
        Some(&identity(OTHER_KEY)),
        Some(payment_header(&prefix, &beef)),
    )
    .await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    assert_fresh_challenge(&response, Some(&prefix));
    assert_eq!(app.served.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_unreadable_transaction_is_400() {
    let app = app(headers_answering_root(""));
    for tx in [&b"not a transaction"[..], &[1, 1, 1, 1, 0xff]] {
        let (status, _, body) = send(
            &app,
            Some(&identity(SENDER_KEY)),
            Some(payment_header(&prefix(), tx)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "ERR_INVALID_PAYMENT");
    }
    let not_base64 =
        json!({ "derivationPrefix": prefix(), "derivationSuffix": SUFFIX, "transaction": "%%%" });
    let (status, _, body) = send(
        &app,
        Some(&identity(SENDER_KEY)),
        Some(not_base64.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "ERR_INVALID_PAYMENT");
    assert_eq!(app.served.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_malformed_header_or_a_foreign_prefix_is_400() {
    let app = app(headers_answering_root(""));
    let (status, _, body) = send(&app, Some(&identity(SENDER_KEY)), Some("{not json".into())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "ERR_MALFORMED_PAYMENT");
    let foreign = create_derivation_prefix(&wallet(OTHER_KEY)).unwrap();
    let (beef, _) = proven_beef(PRICE, &payer_script(SENDER_KEY, &foreign));
    let (status, _, body) = send(
        &app,
        Some(&identity(SENDER_KEY)),
        Some(payment_header(&foreign, &beef)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "ERR_INVALID_DERIVATION_PREFIX");
    assert_eq!(app.served.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn no_header_service_is_a_server_fault_even_for_a_good_payment() {
    let prefix = prefix();
    let (beef, _) = proven_beef(PRICE, &payer_script(SENDER_KEY, &prefix));
    let app = app(None);
    let (status, _, body) = send(
        &app,
        Some(&identity(SENDER_KEY)),
        Some(payment_header(&prefix, &beef)),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["code"], "ERR_SERVER_MISCONFIGURED");
    assert_eq!(app.served.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_root_mismatch_is_400_and_a_lookup_failure_is_503() {
    let prefix = prefix();
    let (beef, _) = proven_beef(PRICE, &payer_script(SENDER_KEY, &prefix));
    let app_mismatch = app(headers_answering_root(&"00".repeat(32)));
    let (status, _, body) = send(
        &app_mismatch,
        Some(&identity(SENDER_KEY)),
        Some(payment_header(&prefix, &beef)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "ERR_INVALID_PAYMENT");
    let down: Option<Arc<dyn HeaderService>> = Some(Arc::new(StubHeaders(
        Err(HeaderLookupError("HTTP 503".into())),
        Mutex::new(Vec::new()),
    )));
    let app_down = app(down);
    let (status, _, body) = send(
        &app_down,
        Some(&identity(SENDER_KEY)),
        Some(payment_header(&prefix, &beef)),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["code"], "ERR_PAYMENT_UNAVAILABLE");
    assert_eq!(
        app_mismatch.served.load(Ordering::SeqCst) + app_down.served.load(Ordering::SeqCst),
        0
    );
}

#[tokio::test]
async fn without_the_auth_layer_the_gate_is_misconfigured() {
    let app = app(headers_answering_root(""));
    for auth in [None, Some("not a key")] {
        let (status, _, body) = send(&app, auth, None).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["code"], "ERR_SERVER_MISCONFIGURED");
    }
    assert_eq!(app.served.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_extractor_without_the_gate_is_a_server_fault() {
    let router: Router =
        Router::new().route("/paid", post(|_: VerifiedPayment| async { "served" }));
    let response = router
        .oneshot(Request::post("/paid").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
