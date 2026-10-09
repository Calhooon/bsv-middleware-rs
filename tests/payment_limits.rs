//! The shared payment door reads a BEEF of any size (bsv-stack-lean, the
//! no-limits program, NL-5; the charter `docs/charters/beef-of-any-size.md`).
//!
//! These are 0.2.2's boundary witnesses (P0-5d, issue #57) inverted: what the
//! door refused for its bytes or its counts it now reads, and accepts when it
//! is valid; what it refuses, it refuses for invalid bytes, naming the offset
//! and the kind. The numbers 4 MiB, 128 and 32 below are the bounds 0.2.2
//! carried, kept here as plain numbers: the crate exports none of them.

use async_trait::async_trait;
use bsv_middleware_rs::{
    verify_payment, verify_payment_output_only, HeaderLookupError, HeaderService, Kind,
    PaymentToVerify, PaymentVerdict, Reason, UnverifiableReason,
};
use bsv_rs::primitives::sha256d;
use bsv_rs::transaction::{Beef, MerklePath};
use std::collections::HashMap;
use std::sync::Mutex;

const SCRIPT: &[u8] = &[0x51];
const PRICE: u64 = 100;
const PAID: PaymentVerdict = PaymentVerdict::Verified { satoshis: PRICE };
const HEIGHT: u32 = 800_000;

/// The bounds of 0.2.2, which no longer decide anything.
const OLD_MAX_BYTES: usize = 4 * 1024 * 1024;
const OLD_MAX_TXS: usize = 128;
const OLD_MAX_BUMPS: usize = 32;

/// The headers of a payment: the root at each height, and the heights asked.
struct Roots {
    roots: HashMap<u32, String>,
    asked: Mutex<Vec<u32>>,
}

impl Roots {
    fn of(roots: &[(u32, String)]) -> Self {
        Self {
            roots: roots.iter().cloned().collect(),
            asked: Mutex::new(Vec::new()),
        }
    }

    fn asked(&self) -> Vec<u32> {
        self.asked.lock().unwrap().clone()
    }
}

#[async_trait]
impl HeaderService for Roots {
    async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError> {
        self.asked.lock().unwrap().push(height);
        self.roots
            .get(&height)
            .cloned()
            .ok_or_else(|| HeaderLookupError(format!("no header at {height}")))
    }
}

const PAYMENT: PaymentToVerify<'static> = PaymentToVerify {
    output_index: 0,
    expected_script: SCRIPT,
    required_satoshis: PRICE,
};

/// The output check alone. A slice is a source that does not fail.
fn check(transaction: &[u8]) -> PaymentVerdict {
    verify_payment_output_only(&PAYMENT, transaction).expect("a slice does not fail")
}

/// The full check against `headers`.
async fn full(transaction: &[u8], headers: Option<&Roots>) -> PaymentVerdict {
    verify_payment(
        &PAYMENT,
        transaction,
        headers.map(|h| h as &dyn HeaderService),
    )
    .await
    .expect("a slice does not fail")
}

/// A refusal of the bytes: the offset and the kind.
fn invalid(offset: u64, reason: Reason) -> PaymentVerdict {
    PaymentVerdict::Unverifiable(UnverifiableReason::InvalidBeef {
        offset,
        kind: reason.kind(),
        reason,
    })
}

/// The text of a refusal; panics on any other word.
fn refusal(verdict: PaymentVerdict, what: &str) -> String {
    match verdict {
        PaymentVerdict::Unverifiable(reason) => reason.to_string(),
        other => panic!("{what}: expected Unverifiable, got {other:?}"),
    }
}

fn varint(n: u64) -> Vec<u8> {
    match n {
        0..=0xFC => vec![n as u8],
        0xFD..=0xFFFF => [&[0xFD][..], &(n as u16).to_le_bytes()].concat(),
        0x1_0000..=0xFFFF_FFFF => [&[0xFE][..], &(n as u32).to_le_bytes()].concat(),
        _ => [&[0xFF][..], &n.to_le_bytes()].concat(),
    }
}

/// A raw transaction with one input per source, each spending output 0 with
/// an empty unlock, paying `PRICE` to `OP_TRUE` at output 0 and, when
/// `padding` is not 0, a second output of no satoshis whose script is
/// `OP_FALSE OP_RETURN` and one push of `padding` bytes. Never signed, never
/// broadcast.
fn raw_tx(sources: &[[u8; 32]], nonce: u32, padding: usize) -> Vec<u8> {
    let mut v = 1u32.to_le_bytes().to_vec();
    v.extend(varint(sources.len() as u64));
    for source in sources {
        v.extend_from_slice(source);
        v.extend_from_slice(&0u32.to_le_bytes());
        v.push(0);
        v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }
    v.push(if padding == 0 { 1 } else { 2 });
    v.extend_from_slice(&PRICE.to_le_bytes());
    v.extend(varint(SCRIPT.len() as u64));
    v.extend_from_slice(SCRIPT);
    if padding != 0 {
        v.extend_from_slice(&0u64.to_le_bytes());
        v.extend(varint(padding as u64 + 7));
        v.extend_from_slice(&[0x00, 0x6a, 0x4e]);
        v.extend_from_slice(&(padding as u32).to_le_bytes());
        v.resize(v.len() + padding, 0xAB);
    }
    v.extend_from_slice(&nonce.to_le_bytes());
    v
}

/// The txid of a raw transaction, in wire order.
fn txid(raw: &[u8]) -> [u8; 32] {
    sha256d(raw)
}

/// A txid as the SDK names it (the bytes reversed, in hex).
fn display(txid: &[u8; 32]) -> String {
    let mut bytes = *txid;
    bytes.reverse();
    hex::encode(bytes)
}

/// The P0-5 shape: a funding transaction proven by a one-leaf BUMP at
/// `HEIGHT` and `count - 1` unproven transactions, each spending the one
/// before. The last carries `padding` bytes nothing spends. Returns the
/// Atomic BEEF and its one root.
fn chain_atomic(count: usize, padding: usize) -> (Vec<u8>, Vec<(u32, String)>) {
    let funding = raw_tx(&[[0xAA; 32]], 0, 0);
    let mut subject = txid(&funding);
    let root = display(&subject);
    let mut beef = Beef::new();
    let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&root, HEIGHT));
    beef.merge_raw_tx(funding, Some(bump));
    for nonce in 1..count {
        let last = nonce + 1 == count;
        let raw = raw_tx(&[subject], nonce as u32, if last { padding } else { 0 });
        subject = txid(&raw);
        beef.merge_raw_tx(raw, None);
    }
    assert_eq!(beef.txs.len(), count);
    let bytes = beef
        .to_binary_atomic(&display(&subject))
        .expect("Atomic BEEF");
    (bytes, vec![(HEIGHT, root)])
}

/// A subject funded by `bump_count` transactions, each proven by its own
/// one-leaf BUMP at its own height. Returns the Atomic BEEF and its roots.
fn funded_atomic(bump_count: usize) -> (Vec<u8>, Vec<(u32, String)>) {
    let mut beef = Beef::new();
    let mut sources = Vec::new();
    let mut roots = Vec::new();
    for nonce in 0..bump_count {
        let funding = raw_tx(&[[0xAA; 32]], nonce as u32, 0);
        let id = txid(&funding);
        let height = HEIGHT + nonce as u32;
        let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&display(&id), height));
        beef.merge_raw_tx(funding, Some(bump));
        sources.push(id);
        roots.push((height, display(&id)));
    }
    let subject = raw_tx(&sources, 0, 0);
    let id = display(&txid(&subject));
    beef.merge_raw_tx(subject, None);
    assert_eq!(beef.bumps.len(), bump_count);
    assert_eq!(beef.txs.len(), bump_count + 1);
    (beef.to_binary_atomic(&id).expect("Atomic BEEF"), roots)
}

/// The heights of `roots`, lowest first: the order the door asks in.
fn heights(roots: &[(u32, String)]) -> Vec<u32> {
    let mut heights: Vec<u32> = roots.iter().map(|(h, _)| *h).collect();
    heights.sort_unstable();
    heights
}

// ---- a valid payment is never refused for its bytes ----

#[tokio::test]
async fn a_valid_payment_over_the_old_byte_bound_is_verified() {
    let (bytes, roots) = chain_atomic(2, OLD_MAX_BYTES);
    assert!(bytes.len() > OLD_MAX_BYTES + 1);
    assert_eq!(check(&bytes), PAID);
    let headers = Roots::of(&roots);
    assert_eq!(full(&bytes, Some(&headers)).await, PAID);
    assert_eq!(headers.asked(), vec![HEIGHT]);
}

#[test]
fn a_raw_transaction_over_the_old_byte_bound_passes_the_output_check() {
    let raw = raw_tx(&[[0xAA; 32]], 0, OLD_MAX_BYTES);
    assert!(raw.len() > OLD_MAX_BYTES + 1);
    assert_eq!(check(&raw), PAID);
}

#[tokio::test]
async fn garbage_over_the_old_byte_bound_is_refused_for_its_bytes_not_its_length() {
    // The Atomic prefix, then an inner version word of zero, then zeros.
    let mut bytes = vec![0; OLD_MAX_BYTES + 1];
    bytes[..4].copy_from_slice(&[1, 1, 1, 1]);
    let headers = Roots::of(&[]);
    assert_eq!(check(&bytes), invalid(36, Reason::BadVersion { word: 0 }));
    for text in [
        refusal(check(&bytes), "a zero version word"),
        refusal(full(&bytes, Some(&headers)).await, "a zero version word"),
    ] {
        assert!(text.contains("offset 36"), "names the offset: {text}");
        assert!(text.contains("BadVersion"), "names the kind: {text}");
        assert!(!text.contains("max_bytes"), "names no bound: {text}");
        assert!(!text.contains("4194305"), "names no length: {text}");
    }
    assert!(headers.asked().is_empty());
}

// ---- nor for its counts ----

#[tokio::test]
async fn the_old_transaction_bound_and_one_over_are_both_verified() {
    for count in [OLD_MAX_TXS, OLD_MAX_TXS + 1, 1_000] {
        let (bytes, roots) = chain_atomic(count, 0);
        assert_eq!(check(&bytes), PAID, "{count} transactions");
        let headers = Roots::of(&roots);
        assert_eq!(
            full(&bytes, Some(&headers)).await,
            PAID,
            "{count} transactions"
        );
        assert_eq!(headers.asked(), vec![HEIGHT]);
    }
}

#[tokio::test]
async fn the_old_bump_bound_and_one_over_are_both_verified() {
    for count in [OLD_MAX_BUMPS, OLD_MAX_BUMPS + 1, 200] {
        let (bytes, roots) = funded_atomic(count);
        assert_eq!(check(&bytes), PAID, "{count} BUMPs");
        let headers = Roots::of(&roots);
        assert_eq!(full(&bytes, Some(&headers)).await, PAID, "{count} BUMPs");
        // Every root is asked once, lowest height first.
        assert_eq!(headers.asked(), heights(&roots));
    }
}

// ---- a refusal is for invalid bytes, and names them ----

#[tokio::test]
async fn a_tree_height_of_65_is_refused_at_its_offset_with_its_kind() {
    let (mut bytes, roots) = funded_atomic(OLD_MAX_BUMPS + 1);
    // 36 bytes of Atomic prefix, the version word, the BUMP count, the block
    // height as a five-byte varint: the tree-height byte of BUMP 0 is at 46.
    assert_eq!(bytes[41], 0xFE);
    assert_eq!(bytes[46], 1);
    bytes[46] = 65;
    let headers = Roots::of(&roots);
    let refused = invalid(46, Reason::TreeHeightOver64 { height: 65 });
    assert_eq!(check(&bytes), refused);
    assert_eq!(full(&bytes, Some(&headers)).await, refused);
    for text in [
        refusal(check(&bytes), "tree height 65"),
        refusal(full(&bytes, Some(&headers)).await, "tree height 65"),
    ] {
        assert!(text.contains("offset 46"), "names the offset: {text}");
        assert!(text.contains("TreeHeightOver64"), "names the kind: {text}");
    }
    assert!(headers.asked().is_empty(), "no header for invalid bytes");
}

#[tokio::test]
async fn a_payment_cut_short_is_refused_at_the_field_that_ran_out() {
    let (mut bytes, roots) = chain_atomic(OLD_MAX_TXS + 1, 0);
    // The last transaction ends: satoshis (8), script length (1), script (1),
    // lock time (4). Ten bytes off leaves four of the eight satoshi bytes.
    let field = bytes.len() - 14;
    bytes.truncate(bytes.len() - 10);
    let headers = Roots::of(&roots);
    let refused = invalid(field as u64, Reason::Truncated { needed: 8 });
    assert_eq!(check(&bytes), refused);
    assert_eq!(full(&bytes, Some(&headers)).await, refused);
    for text in [
        refusal(check(&bytes), "cut short"),
        refusal(full(&bytes, Some(&headers)).await, "cut short"),
    ] {
        assert!(
            text.contains(&format!("offset {field}")),
            "names the offset {field}: {text}"
        );
        assert!(text.contains("Truncated"), "names the kind: {text}");
    }
    assert!(headers.asked().is_empty(), "no header for invalid bytes");
}

#[tokio::test]
async fn a_claimed_count_is_refused_for_the_bytes_it_does_not_have() {
    // A plain BEEF V2 claiming 4,294,967,295 BUMPs and carrying none.
    let mut bytes = 0xEFBE_0002u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0xFE, 0xFF, 0xFF, 0xFF, 0xFF]);
    let headers = Roots::of(&[]);
    assert_eq!(check(&bytes), invalid(9, Reason::BadVarint));
    assert_eq!(
        full(&bytes, Some(&headers)).await,
        invalid(9, Reason::BadVarint)
    );
    for text in [
        refusal(check(&bytes), "a claimed count"),
        refusal(full(&bytes, Some(&headers)).await, "a claimed count"),
    ] {
        assert!(text.contains("offset 9"), "names the offset: {text}");
        assert!(text.contains("BadVarint"), "names the kind: {text}");
        assert!(!text.contains("4294967295"), "names no count: {text}");
    }
}

// ---- what does not move ----

#[tokio::test]
async fn no_header_service_is_answered_before_the_payment_is_read() {
    let (bytes, _) = chain_atomic(OLD_MAX_TXS + 1, 0);
    assert_eq!(full(&bytes, None).await, PaymentVerdict::NoHeaderService);
    assert_eq!(
        full(b"garbage", None).await,
        PaymentVerdict::NoHeaderService
    );
}

#[tokio::test]
async fn a_root_the_headers_do_not_carry_is_a_mismatch_at_any_size() {
    let (bytes, _) = chain_atomic(OLD_MAX_TXS + 1, 0);
    let headers = Roots::of(&[(HEIGHT, "00".repeat(32))]);
    assert!(matches!(
        full(&bytes, Some(&headers)).await,
        PaymentVerdict::RootMismatch { height: HEIGHT, .. }
    ));
}

#[tokio::test]
async fn the_output_check_reads_the_declared_atomic_subject() {
    let (bytes, _) = chain_atomic(3, 0);
    let mut beef = Beef::from_binary(&bytes).expect("honest BEEF");
    let subject = beef.atomic_txid.clone().expect("Atomic subject");
    // A retained descendant that underpays sorts after the declared subject.
    let mut wire = [0u8; 32];
    wire.copy_from_slice(&hex::decode(&subject).unwrap());
    wire.reverse();
    let mut descendant = raw_tx(&[wire], 99, 0);
    let satoshis = descendant.len() - 14;
    descendant[satoshis..satoshis + 8].copy_from_slice(&(PRICE - 1).to_le_bytes());
    beef.merge_raw_tx(descendant, None);
    let bytes = beef.to_binary_atomic(&subject).expect("Atomic BEEF");
    assert_eq!(check(&bytes), PAID);
    // The full check holds an Atomic BEEF to the reader's rule: the subject
    // is the tip of its ancestry. 0.2.2 read past the descendant.
    let headers = Roots::of(&[(HEIGHT, "00".repeat(32))]);
    assert_eq!(
        full(&bytes, Some(&headers)).await,
        invalid(4, Reason::SubjectMissing { subject: wire })
    );
    assert!(headers.asked().is_empty());
}

#[test]
fn an_atomic_subject_the_beef_does_not_carry_is_refused() {
    let (mut bytes, _) = chain_atomic(2, 0);
    bytes[4..36].fill(0);
    let refused = invalid(4, Reason::SubjectMissing { subject: [0; 32] });
    assert_eq!(check(&bytes), refused);
    assert_eq!(
        Kind::SubjectMissing,
        Reason::SubjectMissing { subject: [0; 32] }.kind()
    );
}

/// The crate's sources name no bound on a payment's bytes or counts.
#[test]
fn the_crate_names_no_payment_bound() {
    let sources = [
        ("src/lib.rs", include_str!("../src/lib.rs")),
        ("src/payment.rs", include_str!("../src/payment.rs")),
        (
            "src/payment_core.rs",
            include_str!("../src/payment_core.rs"),
        ),
        ("src/axum_layer.rs", include_str!("../src/axum_layer.rs")),
    ];
    for (path, source) in sources {
        for gone in [
            "MAX_PAYMENT_BYTES",
            "MAX_PAYMENT_BEEF_TXS",
            "MAX_PAYMENT_BEEF_BUMPS",
            "PAYMENT_BEEF_LIMITS",
            "_with_limits",
            "BeefLimits",
            "PaymentTooLarge",
            "BeefTransactionsExceeded",
            "BeefBumpsExceeded",
        ] {
            assert!(!source.contains(gone), "{path} still names {gone}");
        }
    }
}
