//! The Axum payment gate end to end: a router with `require_payment` in
//! front of a handler that takes `VerifiedPayment`, driven by crafted
//! payments (never signed, never broadcast) and a stub header service.
#![cfg(feature = "axum")]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bsv_middleware_rs::axum_layer::{
    require_payment, MemoryPaymentStorage, PaymentGate, VerifiedPayment, PAYMENT_TRANSPORTS,
};
use bsv_middleware_rs::payment::{
    create_derivation_prefix, payment_headers, verify_derivation_prefix,
};
use bsv_middleware_rs::payment_core::BRC29_PROTOCOL_NAME;
use bsv_middleware_rs::{AuthContext, HeaderLookupError, HeaderService, PaymentStorage};
use bsv_rs::primitives::{sha256d, to_var_int, PrivateKey, PublicKey};
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::wallet::{Counterparty, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel};
use futures::StreamExt;
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
    proven_beef_at(HEIGHT, satoshis, script)
}

/// [`proven_beef`] proven at `height`, which it also spends from, so two
/// heights make two transactions.
fn proven_beef_at(height: u32, satoshis: u64, script: &[u8]) -> (Vec<u8>, String) {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput {
        source_txid: Some(format!("{:064x}", height)),
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
        height,
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

/// The prefix store every gate here shares, so a prefix issued by
/// [`prefix`] is one the gate recorded.
static PREFIXES: LazyLock<Arc<MemoryPaymentStorage>> = LazyLock::new(Default::default);

fn gate(server: ProtoWallet, price: u64, headers: Option<Arc<dyn HeaderService>>) -> PaymentGate {
    PaymentGate::new(server, price, headers).with_prefix_store(PREFIXES.clone(), 3600)
}

fn app(headers: Option<Arc<dyn HeaderService>>) -> App {
    let gate = Arc::new(gate(wallet(SERVER_KEY), PRICE, headers));
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

/// A prefix as a 402 issues it: made by the server's key and recorded.
fn prefix() -> String {
    issued(create_derivation_prefix(&wallet(SERVER_KEY)).unwrap())
}

fn issued(prefix: String) -> String {
    futures::executor::block_on(PREFIXES.store_derivation_prefix(&prefix, 3600)).unwrap();
    prefix
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
    send_with_body(app, auth, payment, Body::empty()).await
}

async fn send_with_body(
    app: &App,
    auth: Option<&str>,
    payment: Option<String>,
    body: Body,
) -> (StatusCode, Response, Value) {
    let mut request = Request::post("/paid");
    if let Some(p) = payment {
        request = request.header(payment_headers::PAYMENT, p);
    }
    let mut request = request.body(body).unwrap();
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

/// Answers each root it holds at the height its proof names.
struct Roots(Vec<(u32, String)>);

#[async_trait]
impl HeaderService for Roots {
    async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError> {
        self.0
            .iter()
            .find(|(h, _)| *h == height)
            .map(|(_, root)| root.clone())
            .ok_or_else(|| HeaderLookupError("not indexed".into()))
    }
}

/// M14, the witness `paid-request-prefix-reused-with-a-new-transaction`:
/// one prefix, two transactions. The first is served; the second, and the
/// first again, are refused 402 with a fresh challenge, and the handler (the
/// wallet's caller) runs once.
#[tokio::test]
async fn a_prefix_paid_with_a_second_transaction_is_refused_and_the_wallet_called_once() {
    let prefix = prefix();
    let script = payer_script(SENDER_KEY, &prefix);
    let (t1, root1) = proven_beef_at(HEIGHT, PRICE, &script);
    let (t2, root2) = proven_beef_at(HEIGHT + 1, PRICE, &script);
    assert_ne!(root1, root2, "two transactions");
    let headers: Arc<dyn HeaderService> =
        Arc::new(Roots(vec![(HEIGHT, root1), (HEIGHT + 1, root2)]));
    let app = app(Some(headers));
    let sender = identity(SENDER_KEY);
    let (status, _, body) = send(&app, Some(&sender), Some(payment_header(&prefix, &t1))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["prefix"], prefix);
    for tx in [&t2, &t1] {
        let (status, response, body) =
            send(&app, Some(&sender), Some(payment_header(&prefix, tx))).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{body}");
        assert_eq!(body["code"], "ERR_INVALID_DERIVATION_PREFIX");
        assert_eq!(body["satoshisRequired"], PRICE);
        assert_fresh_challenge(&response, Some(&prefix));
    }
    assert_eq!(app.served.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_prefix_the_gate_never_issued_or_past_its_window_is_refused() {
    let sender = identity(SENDER_KEY);
    // HMAC-valid but never recorded: another instance's, or forged by a key holder.
    let unrecorded = create_derivation_prefix(&wallet(SERVER_KEY)).unwrap();
    let (beef, root) = proven_beef(PRICE, &payer_script(SENDER_KEY, &unrecorded));
    let app = app(headers_answering_root(&root));
    let (status, _, body) = send(
        &app,
        Some(&sender),
        Some(payment_header(&unrecorded, &beef)),
    )
    .await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{body}");
    assert_eq!(body["code"], "ERR_INVALID_DERIVATION_PREFIX");
    // A window of zero seconds: recorded, and expired by the time it is paid.
    let store = Arc::new(MemoryPaymentStorage::default());
    let gate = Arc::new(
        PaymentGate::new(wallet(SERVER_KEY), PRICE, headers_answering_root(&root))
            .with_prefix_store(store.clone(), 0),
    );
    store.store_derivation_prefix(&unrecorded, 0).await.unwrap();
    let router = Router::new()
        .route("/paid", post(|_: VerifiedPayment| async { "served" }))
        .layer(axum::middleware::from_fn_with_state(gate, require_payment));
    let expired = App {
        router,
        served: Arc::new(AtomicUsize::new(0)),
    };
    let (status, _, body) = send(
        &expired,
        Some(&sender),
        Some(payment_header(&unrecorded, &beef)),
    )
    .await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{body}");
    assert_eq!(body["code"], "ERR_INVALID_DERIVATION_PREFIX");
    assert_eq!(app.served.load(Ordering::SeqCst), 0);
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

// ---- the body transport: a payment of any size, streamed ----

/// The header of a payment whose transaction is the request body.
fn body_payment_header(prefix: &str) -> String {
    json!({ "derivationPrefix": prefix, "derivationSuffix": SUFFIX }).to_string()
}

/// A body that arrives `chunk` bytes at a time.
fn in_pieces(bytes: &[u8], chunk: usize) -> Body {
    let pieces: Vec<Result<Vec<u8>, std::io::Error>> =
        bytes.chunks(chunk).map(|c| Ok(c.to_vec())).collect();
    Body::from_stream(futures::stream::iter(pieces))
}

/// A raw transaction spending `source:0` with an empty unlock, paying
/// `satoshis` to `script` and, when `padding` is not 0, a second output of no
/// satoshis carrying `padding` bytes nothing spends.
fn raw_tx(source: &[u8; 32], satoshis: u64, script: &[u8], padding: usize) -> Vec<u8> {
    let mut v = 1u32.to_le_bytes().to_vec();
    v.push(1);
    v.extend_from_slice(source);
    v.extend_from_slice(&0u32.to_le_bytes());
    v.push(0);
    v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    v.push(if padding == 0 { 1 } else { 2 });
    v.extend_from_slice(&satoshis.to_le_bytes());
    v.extend(to_var_int(script.len() as u64));
    v.extend_from_slice(script);
    if padding != 0 {
        v.extend_from_slice(&0u64.to_le_bytes());
        v.extend(to_var_int(padding as u64 + 7));
        v.extend_from_slice(&[0x00, 0x6a, 0x4e]);
        v.extend_from_slice(&(padding as u32).to_le_bytes());
        v.resize(v.len() + padding, 0xAB);
    }
    v.extend_from_slice(&0u32.to_le_bytes());
    v
}

/// A funding transaction proven by a one-leaf BUMP at `HEIGHT`, `links`
/// unproven `OP_TRUE` transactions each spending the one before, and the
/// payment spending the last: `satoshis` to `script`, with `padding` bytes.
/// Returns the BEEF V2 and its one root.
fn chain_beef(links: usize, satoshis: u64, script: &[u8], padding: usize) -> (Vec<u8>, String) {
    let funding = raw_tx(&[0xAA; 32], 10 * PRICE, &[0x51], 0);
    let mut prev = sha256d(&funding);
    let mut root = prev;
    root.reverse();
    let mut v = 0xEFBE_0002u32.to_le_bytes().to_vec();
    v.push(1);
    v.extend(to_var_int(u64::from(HEIGHT)));
    v.extend_from_slice(&[1, 1, 0, 2]);
    v.extend_from_slice(&prev);
    v.extend(to_var_int(links as u64 + 2));
    v.extend_from_slice(&[1, 0]);
    v.extend_from_slice(&funding);
    for _ in 0..links {
        let link = raw_tx(&prev, 10 * PRICE, &[0x51], 0);
        prev = sha256d(&link);
        v.push(0);
        v.extend_from_slice(&link);
    }
    v.push(0);
    v.extend_from_slice(&raw_tx(&prev, satoshis, script, padding));
    (v, hex::encode(root))
}

#[tokio::test]
async fn the_challenge_names_both_transports() {
    let app = app(headers_answering_root(""));
    let (status, response, _) = send(&app, Some(&identity(SENDER_KEY)), None).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(PAYMENT_TRANSPORTS, "header,body");
    assert_eq!(
        header(&response, payment_headers::TRANSPORTS),
        Some(PAYMENT_TRANSPORTS)
    );
}

#[tokio::test]
async fn a_payment_in_the_body_is_streamed_verified_and_served() {
    // 300 transactions: over the 128 that 0.2.2 and 0.3.0 refused.
    let prefix = prefix();
    let (beef, root) = chain_beef(298, PRICE, &payer_script(SENDER_KEY, &prefix), 0);
    for chunk in [1, 7, 4096, beef.len()] {
        // A fresh server per reading, which issued this prefix.
        issued(prefix.clone());
        let app = app(headers_answering_root(&root));
        let (status, response, body) = send_with_body(
            &app,
            Some(&identity(SENDER_KEY)),
            Some(body_payment_header(&prefix)),
            in_pieces(&beef, chunk),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{chunk} at a time: {body}");
        assert_eq!(body["satoshis_paid"], PRICE);
        assert_eq!(body["tx_len"], beef.len());
        assert_eq!(body["prefix"], prefix);
        assert_eq!(
            header(&response, payment_headers::SATOSHIS_PAID),
            Some("100")
        );
        assert_eq!(app.served.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn a_payment_over_four_mebibytes_in_the_body_is_served() {
    let prefix = prefix();
    let (beef, root) = chain_beef(
        1,
        PRICE,
        &payer_script(SENDER_KEY, &prefix),
        4 * 1024 * 1024,
    );
    assert!(beef.len() > 4 * 1024 * 1024);
    let app = app(headers_answering_root(&root));
    let (status, _, body) = send_with_body(
        &app,
        Some(&identity(SENDER_KEY)),
        Some(body_payment_header(&prefix)),
        in_pieces(&beef, 64 * 1024),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tx_len"], beef.len());
    assert_eq!(app.served.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_same_payment_in_the_header_is_served_as_before() {
    let prefix = prefix();
    let (beef, root) = chain_beef(298, PRICE, &payer_script(SENDER_KEY, &prefix), 0);
    let app = app(headers_answering_root(&root));
    let (status, _, body) = send(
        &app,
        Some(&identity(SENDER_KEY)),
        Some(payment_header(&prefix, &beef)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tx_len"], beef.len());
}

#[tokio::test]
async fn an_underpaying_body_is_answered_402_with_a_fresh_challenge() {
    let prefix = prefix();
    let (beef, root) = chain_beef(3, PRICE - 1, &payer_script(SENDER_KEY, &prefix), 0);
    let app = app(headers_answering_root(&root));
    let (status, response, body) = send_with_body(
        &app,
        Some(&identity(SENDER_KEY)),
        Some(body_payment_header(&prefix)),
        in_pieces(&beef, 11),
    )
    .await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(body["code"], "ERR_INVALID_PAYMENT");
    assert_fresh_challenge(&response, Some(&prefix));
    assert_eq!(app.served.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_invalid_body_is_400_naming_the_offset_and_the_kind() {
    let prefix = prefix();
    let (mut beef, root) = chain_beef(298, PRICE, &payer_script(SENDER_KEY, &prefix), 0);
    // The version word, the BUMP count, the height as a five-byte varint: the
    // tree-height byte is at offset 10.
    assert_eq!(beef[10], 1);
    beef[10] = 65;
    let app = app(headers_answering_root(&root));
    let (status, _, body) = send_with_body(
        &app,
        Some(&identity(SENDER_KEY)),
        Some(body_payment_header(&prefix)),
        in_pieces(&beef, 7),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "ERR_INVALID_PAYMENT");
    let description = body["description"].as_str().unwrap();
    assert!(description.contains("offset 10"), "{description}");
    assert!(description.contains("TreeHeightOver64"), "{description}");
    // An empty body is no BEEF either: the version word ran out at offset 0.
    let (status, _, body) = send_with_body(
        &app,
        Some(&identity(SENDER_KEY)),
        Some(body_payment_header(&prefix)),
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["description"].as_str().unwrap().contains("offset 0"),
        "{body}"
    );
    assert_eq!(app.served.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_reading_stops_at_the_invalid_byte() {
    // A bad version word, then a body that would fail if it were read on.
    let polled_past = Arc::new(AtomicBool::new(false));
    let flag = polled_past.clone();
    let pieces = futures::stream::iter(0..3).map(move |i| {
        if i == 2 {
            flag.store(true, Ordering::SeqCst);
        }
        Ok::<_, std::io::Error>(vec![0x07u8; 8])
    });
    let app = app(headers_answering_root(""));
    let (status, _, body) = send_with_body(
        &app,
        Some(&identity(SENDER_KEY)),
        Some(body_payment_header(&prefix())),
        Body::from_stream(pieces),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let description = body["description"].as_str().unwrap();
    assert!(description.contains("offset 0"), "{description}");
    assert!(description.contains("BadVersion"), "{description}");
    assert!(!polled_past.load(Ordering::SeqCst), "read past the refusal");
}

#[tokio::test]
async fn a_body_cut_off_in_flight_is_400_and_never_served() {
    let prefix = prefix();
    let (beef, root) = chain_beef(3, PRICE, &payer_script(SENDER_KEY, &prefix), 0);
    let half = beef[..beef.len() / 2].to_vec();
    let pieces = futures::stream::iter([
        Ok(half),
        Err(std::io::Error::other("the connection closed")),
    ]);
    let app = app(headers_answering_root(&root));
    let (status, _, body) = send_with_body(
        &app,
        Some(&identity(SENDER_KEY)),
        Some(body_payment_header(&prefix)),
        Body::from_stream(pieces),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "ERR_INVALID_PAYMENT");
    assert_eq!(body["description"], "The payment body could not be read.");
    assert_eq!(app.served.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn no_header_service_is_answered_before_the_body_is_read() {
    let polled = Arc::new(AtomicBool::new(false));
    let flag = polled.clone();
    let pieces = futures::stream::iter(0..1).map(move |_| {
        flag.store(true, Ordering::SeqCst);
        Ok::<_, std::io::Error>(vec![0u8; 8])
    });
    let app = app(None);
    let (status, _, body) = send_with_body(
        &app,
        Some(&identity(SENDER_KEY)),
        Some(body_payment_header(&prefix())),
        Body::from_stream(pieces),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["code"], "ERR_SERVER_MISCONFIGURED");
    assert!(!polled.load(Ordering::SeqCst), "the body was read");
}

/// Replay all canonical cases at the HTTP door. The wire fixtures use a
/// static derivation prefix that is not an issued challenge. Rebuild only
/// the synthetic payment scripts and their proof roots for a fresh challenge,
/// preserving amounts, output order, wrong scripts and header-answer classes.
#[tokio::test]
async fn all_22_vector_cases_reach_the_axum_door() {
    let vectors: Value =
        serde_json::from_str(include_str!("vectors/brc29-payment-vectors.json")).unwrap();
    let cases = vectors["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 22);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let server = wallet(case["server_private_key"].as_str().unwrap());
        let prefix = issued(create_derivation_prefix(&server).unwrap());
        let sender = case["sender_identity_key"].as_str().unwrap();
        let suffix = case["derivation_suffix"].as_str().unwrap();
        let script =
            bsv_middleware_rs::brc29_locking_script(&server, &prefix, suffix, sender).unwrap();
        let mut tx = Transaction::new();
        tx.add_input(TransactionInput::new("11".repeat(32), 0))
            .unwrap();
        for output in case["transaction"]["outputs"].as_array().unwrap() {
            let original = output["locking_script"].as_str().unwrap();
            let locking = if original == case["expected_locking_script"].as_str().unwrap() {
                script.clone()
            } else {
                hex::decode(original).unwrap()
            };
            tx.add_output(TransactionOutput::new(
                output["satoshis"].as_u64().unwrap(),
                LockingScript::from_binary(&locking).unwrap(),
            ))
            .unwrap();
        }
        let root = tx.id();
        let mut beef = Beef::new();
        if !case["transaction"]["proof"].is_null() {
            beef.merge_bump(
                MerklePath::new(
                    HEIGHT,
                    vec![vec![MerklePathLeaf::new_txid(0, root.clone())]],
                )
                .unwrap(),
            );
        }
        beef.merge_transaction(tx);
        let lookup = &case["header_service"]["lookup"];
        let word = case["expected"]["word"].as_str().unwrap();
        let headers = if case["stage"] == "config" {
            None
        } else {
            let answer = if lookup["answer"] == "error" {
                Err(HeaderLookupError("synthetic lookup failure".into()))
            } else if word == "RootMismatch" {
                Ok("00".repeat(32))
            } else if name == "spv-root-match-uppercase" {
                Ok(root.to_uppercase())
            } else {
                Ok(root.clone())
            };
            Some(Arc::new(StubHeaders(answer, Mutex::new(Vec::new()))) as Arc<dyn HeaderService>)
        };
        let gate = Arc::new(gate(
            server,
            case["required_satoshis"].as_u64().unwrap(),
            headers,
        ));
        let served = Arc::new(AtomicUsize::new(0));
        let count = served.clone();
        let router = Router::new()
            .route(
                "/paid",
                post(move |p: VerifiedPayment| async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    axum::Json(json!({"satoshis_paid": p.satoshis_paid}))
                }),
            )
            .layer(axum::middleware::from_fn_with_state(gate, require_payment));
        let app = App { router, served };
        let payment = json!({"derivationPrefix": prefix, "derivationSuffix": suffix, "transaction": B64.encode(beef.to_binary())}).to_string();
        let (status, _, body) = send(&app, Some(sender), Some(payment)).await;
        let expected = match word {
            "Verified" => StatusCode::OK,
            "Underpaid" | "WrongScript" => StatusCode::PAYMENT_REQUIRED,
            "NoHeaderService" => StatusCode::INTERNAL_SERVER_ERROR,
            "RootMismatch" => StatusCode::BAD_REQUEST,
            "Unverifiable" if case["expected"]["fields"].get("height").is_some() => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            "Unverifiable" => StatusCode::BAD_REQUEST,
            other => panic!("unexpected word {other}"),
        };
        assert_eq!(status, expected, "{name}: {body}");
        assert_eq!(
            app.served.load(Ordering::SeqCst),
            usize::from(word == "Verified"),
            "{name}"
        );
        if word == "Verified" {
            assert_eq!(
                body["satoshis_paid"], case["expected"]["fields"]["satoshis"],
                "{name}"
            );
        }
        println!("{name}: {status}");
    }
    println!("22 of 22 cases through the Axum door");
}

#[tokio::test]
async fn missing_mining_context_is_503_and_never_served() {
    let prefix = prefix();
    let script = payer_script(SENDER_KEY, &prefix);
    let (mut beef, root) = chain_beef(1, PRICE, &script, 0);
    let subject_len = raw_tx(&[0; 32], PRICE, &script, 0).len();
    let subject_at = beef.len() - subject_len;
    beef[subject_at + 42..subject_at + 46].copy_from_slice(&0u32.to_le_bytes());
    let end = beef.len();
    beef[end - 4..].copy_from_slice(&1u32.to_le_bytes());
    let app = app(headers_answering_root(&root));
    let (status, _, body) = send_with_body(
        &app,
        Some(&identity(SENDER_KEY)),
        Some(body_payment_header(&prefix)),
        in_pieces(&beef, 7),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "ERR_PAYMENT_UNAVAILABLE");
    assert!(
        body["description"].as_str().unwrap().contains("Finality"),
        "{body}"
    );
    assert_eq!(app.served.load(Ordering::SeqCst), 0);
}
