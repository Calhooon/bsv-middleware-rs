//! Small boundary witnesses for the shared payment door (P0-5d, issue #57).
//! No exhaustion shapes: at most 129 transactions or 33 single-leaf BUMPs.
//!
//! Since 0.3.0 the door answers in the six words: a refusal by a limit is
//! `Unverifiable` with the reason naming the count and the bound, before the
//! parse; the output-only check is used so no header service is in play.

use async_trait::async_trait;
use bsv_middleware_rs::{
    verify_payment, verify_payment_output_only, verify_payment_output_only_with_limits,
    verify_payment_with_limits, HeaderLookupError, HeaderService, PaymentToVerify, PaymentVerdict,
    UnverifiableReason, MAX_PAYMENT_BEEF_BUMPS, MAX_PAYMENT_BEEF_TXS, MAX_PAYMENT_BYTES,
    PAYMENT_BEEF_LIMITS,
};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, BeefLimits, MerklePath, Transaction, TransactionInput, TransactionOutput,
};
const SCRIPT: &[u8] = &[0x51];
const PRICE: u64 = 100;
const PAID: PaymentVerdict = PaymentVerdict::Verified { satoshis: PRICE };

fn payment(transaction: &[u8]) -> PaymentToVerify<'_> {
    PaymentToVerify {
        transaction,
        output_index: 0,
        expected_script: SCRIPT,
        required_satoshis: PRICE,
    }
}

fn check(transaction: &[u8]) -> PaymentVerdict {
    verify_payment_output_only(&payment(transaction))
}

fn check_with(transaction: &[u8], max_bytes: usize, limits: &BeefLimits) -> PaymentVerdict {
    verify_payment_output_only_with_limits(&payment(transaction), max_bytes, limits)
}

fn refused(reason: UnverifiableReason) -> PaymentVerdict {
    PaymentVerdict::Unverifiable(reason)
}

/// The reason of a refusal, as text; panics on any other word.
fn reason(verdict: PaymentVerdict, what: &str) -> UnverifiableReason {
    match verdict {
        PaymentVerdict::Unverifiable(reason) => reason,
        other => panic!("{what}: expected Unverifiable, got {other:?}"),
    }
}

fn small_transaction(source: String, nonce: u32) -> Transaction {
    let mut tx = Transaction::new();
    let mut input = TransactionInput::new(source, 0);
    input.unlocking_script = Some(UnlockingScript::new());
    tx.inputs.push(input);
    tx.outputs.push(TransactionOutput::new(
        PRICE,
        LockingScript::from_binary(SCRIPT).expect("OP_TRUE"),
    ));
    tx.lock_time = nonce;
    tx
}

// P0-5 tests/beef_limits.rs shape: a proven root and small unproven ancestors.
fn chain_atomic(count: usize) -> Vec<u8> {
    let funding = small_transaction("aa".repeat(32), 0);
    let mut subject = funding.id();
    let mut beef = Beef::new();
    let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&subject, 800_000));
    beef.merge_raw_tx(funding.to_binary(), Some(bump));
    for nonce in 1..count {
        let tx = small_transaction(subject, nonce as u32);
        subject = tx.id();
        beef.merge_raw_tx(tx.to_binary(), None);
    }
    assert_eq!(beef.txs.len(), count);
    beef.to_binary_atomic(&subject).expect("Atomic BEEF")
}

// Every proof belongs to a funding input of the subject. Distinct heights keep
// the single-leaf BUMPs separate; no unrelated padding branches are needed.
fn funded_atomic(bump_count: usize) -> Vec<u8> {
    let mut beef = Beef::new();
    let mut subject = Transaction::new();
    subject.outputs.push(TransactionOutput::new(
        PRICE,
        LockingScript::from_binary(SCRIPT).expect("OP_TRUE"),
    ));
    for nonce in 0..bump_count {
        let funding = small_transaction("aa".repeat(32), nonce as u32);
        let txid = funding.id();
        let bump = beef.merge_bump(MerklePath::from_coinbase_txid(
            &txid,
            800_000 + nonce as u32,
        ));
        beef.merge_raw_tx(funding.to_binary(), Some(bump));
        let mut input = TransactionInput::new(txid, 0);
        input.unlocking_script = Some(UnlockingScript::new());
        subject.inputs.push(input);
    }
    let txid = subject.id();
    beef.merge_raw_tx(subject.to_binary(), None);
    assert_eq!(beef.bumps.len(), bump_count);
    assert_eq!(beef.txs.len(), bump_count + 1);
    beef.to_binary_atomic(&txid).expect("Atomic BEEF")
}

fn malformed_atomic(length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&[1, 1, 1, 1]);
    // The inner version is zero, so parsing stops without walking any entries.
    bytes
}

#[test]
fn one_byte_over_is_refused_before_atomic_parsing() {
    let bytes = malformed_atomic(MAX_PAYMENT_BYTES + 1);
    let error = reason(check(&bytes), "over byte bound");
    let message = error.to_string();
    assert!(message.contains("4194305"), "names the length: {message}");
    assert!(
        message.contains("max_bytes 4194304"),
        "names the bound: {message}"
    );
}

#[test]
fn one_byte_over_is_refused_before_raw_parsing() {
    let bytes = vec![0; MAX_PAYMENT_BYTES + 1];
    let error = reason(check(&bytes), "over byte bound");
    let message = error.to_string();
    assert!(message.contains("4194305"), "names the length: {message}");
    assert!(
        message.contains("max_bytes 4194304"),
        "names the bound: {message}"
    );
}

#[test]
fn exactly_the_byte_bound_reaches_the_parser() {
    let bytes = malformed_atomic(MAX_PAYMENT_BYTES);
    let error = reason(check(&bytes), "invalid inner version");
    assert!(matches!(error, UnverifiableReason::MalformedTransaction(_)));
    assert!(error.to_string().contains("Invalid BEEF version"));
}

#[test]
fn exactly_the_transaction_bound_is_admitted() {
    let bytes = chain_atomic(MAX_PAYMENT_BEEF_TXS);
    assert_eq!(check(&bytes), PAID);
}

#[test]
fn one_transaction_over_is_refused_with_the_count_and_bound() {
    let bytes = chain_atomic(MAX_PAYMENT_BEEF_TXS + 1);
    let error = reason(check(&bytes), "129 transactions");
    let message = error.to_string();
    assert!(
        message.contains("129 transactions"),
        "names the count: {message}"
    );
    assert!(
        message.contains("max_txs 128"),
        "names the bound: {message}"
    );
}

#[test]
fn exactly_the_bump_bound_is_admitted() {
    let bytes = funded_atomic(MAX_PAYMENT_BEEF_BUMPS);
    assert_eq!(check(&bytes), PAID);
}

#[test]
fn one_bump_over_is_refused_with_the_count_and_bound() {
    let bytes = funded_atomic(MAX_PAYMENT_BEEF_BUMPS + 1);
    let error = reason(check(&bytes), "33 BUMPs");
    let message = error.to_string();
    assert!(message.contains("33 BUMPs"), "names the count: {message}");
    assert!(
        message.contains("max_bumps 32"),
        "names the bound: {message}"
    );
}

#[test]
fn custom_byte_budget_is_checked_before_parsing_either_format() {
    for bytes in [vec![0; 41], malformed_atomic(41)] {
        assert_eq!(
            check_with(&bytes, 40, &PAYMENT_BEEF_LIMITS),
            refused(UnverifiableReason::PaymentTooLarge {
                bytes: 41,
                max_bytes: 40,
            })
        );
    }
}

#[test]
fn custom_beef_byte_budget_can_be_smaller_than_the_outer_budget() {
    let bytes = malformed_atomic(41);
    let limits = BeefLimits {
        max_bytes: 40,
        ..PAYMENT_BEEF_LIMITS
    };
    assert_eq!(
        check_with(&bytes, 41, &limits),
        refused(UnverifiableReason::PaymentTooLarge {
            bytes: 41,
            max_bytes: 40
        })
    );
}

#[test]
fn custom_beef_counts_admit_at_the_bound_and_refuse_one_over() {
    let limits = BeefLimits {
        max_txs: 4,
        max_bumps: 2,
        max_bytes: MAX_PAYMENT_BYTES,
    };
    let at_bound = chain_atomic(4);
    assert_eq!(check_with(&at_bound, at_bound.len(), &limits), PAID);
    let one_over = chain_atomic(5);
    assert_eq!(
        check_with(&one_over, one_over.len(), &limits),
        refused(UnverifiableReason::BeefTransactionsExceeded {
            count: 5,
            max_txs: 4
        })
    );
    let at_bound = funded_atomic(2);
    assert_eq!(check_with(&at_bound, at_bound.len(), &limits), PAID);
    let one_over = funded_atomic(3);
    assert_eq!(
        check_with(&one_over, one_over.len(), &limits),
        refused(UnverifiableReason::BeefBumpsExceeded {
            count: 3,
            max_bumps: 2
        })
    );
}

#[test]
fn a_caller_can_admit_counts_above_the_default_budgets() {
    let limits = BeefLimits {
        max_txs: MAX_PAYMENT_BEEF_TXS + 1,
        max_bumps: MAX_PAYMENT_BEEF_BUMPS + 1,
        max_bytes: MAX_PAYMENT_BYTES,
    };
    for bytes in [
        chain_atomic(limits.max_txs),
        funded_atomic(limits.max_bumps),
    ] {
        assert_eq!(check_with(&bytes, bytes.len(), &limits), PAID);
    }
}

#[test]
fn raw_transactions_ignore_beef_budgets_and_admit_the_exact_byte_budget() {
    let raw = small_transaction("aa".repeat(32), 0).to_binary();
    let limits = BeefLimits {
        max_txs: 0,
        max_bumps: 0,
        max_bytes: 0,
    };
    assert_eq!(check_with(&raw, raw.len(), &limits), PAID);
    assert_eq!(
        check_with(&raw, raw.len() - 1, &limits),
        refused(UnverifiableReason::PaymentTooLarge {
            bytes: raw.len(),
            max_bytes: raw.len() - 1
        })
    );
}

#[test]
fn the_declared_atomic_subject_is_used_even_when_it_is_not_last() {
    let mut beef = Beef::from_binary(&chain_atomic(3)).expect("honest BEEF");
    let subject = beef.atomic_txid.clone().expect("Atomic subject");
    // A retained descendant sorts after the declared subject. Historical
    // Atomic writers could retain branches beyond the subject (reference
    // payment-express-middleware/src/index.ts:110-112 at fb1b2da).
    let mut different = small_transaction(subject.clone(), 99);
    different.outputs[0].satoshis = Some(PRICE - 1);
    beef.merge_raw_tx(different.to_binary(), None);
    let bytes = beef.to_binary_atomic(&subject).expect("Atomic BEEF");
    assert_ne!(
        Beef::from_binary(&bytes)
            .expect("BEEF")
            .txs
            .last()
            .unwrap()
            .txid(),
        subject
    );
    assert_eq!(check(&bytes), PAID);
}

#[test]
fn malformed_atomic_subject_is_still_a_parse_error() {
    let mut bytes = chain_atomic(2);
    bytes[4..36].fill(0);
    assert!(matches!(
        check(&bytes),
        PaymentVerdict::Unverifiable(UnverifiableReason::MalformedTransaction(message))
            if message == "Atomic transaction not found"
    ));
}

/// A header service that must never be asked.
struct NeverAsked;

#[async_trait]
impl HeaderService for NeverAsked {
    async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError> {
        panic!("a refusal by a limit asks no header (height {height})");
    }
}

#[tokio::test]
async fn the_full_check_refuses_by_the_same_limits_before_any_lookup() {
    let headers = NeverAsked;
    let over_bytes = malformed_atomic(MAX_PAYMENT_BYTES + 1);
    assert_eq!(
        verify_payment(&payment(&over_bytes), Some(&headers)).await,
        refused(UnverifiableReason::PaymentTooLarge {
            bytes: MAX_PAYMENT_BYTES + 1,
            max_bytes: MAX_PAYMENT_BYTES,
        })
    );
    let over_txs = chain_atomic(MAX_PAYMENT_BEEF_TXS + 1);
    assert_eq!(
        verify_payment(&payment(&over_txs), Some(&headers)).await,
        refused(UnverifiableReason::BeefTransactionsExceeded {
            count: MAX_PAYMENT_BEEF_TXS + 1,
            max_txs: MAX_PAYMENT_BEEF_TXS,
        })
    );
    let over_bumps = funded_atomic(MAX_PAYMENT_BEEF_BUMPS + 1);
    assert_eq!(
        verify_payment(&payment(&over_bumps), Some(&headers)).await,
        refused(UnverifiableReason::BeefBumpsExceeded {
            count: MAX_PAYMENT_BEEF_BUMPS + 1,
            max_bumps: MAX_PAYMENT_BEEF_BUMPS,
        })
    );
    let small = chain_atomic(2);
    assert_eq!(
        verify_payment_with_limits(&payment(&small), Some(&headers), 40, &PAYMENT_BEEF_LIMITS)
            .await,
        refused(UnverifiableReason::PaymentTooLarge {
            bytes: small.len(),
            max_bytes: 40,
        })
    );
    // No header service is the server's fault and is answered first.
    assert_eq!(
        verify_payment(&payment(&over_bytes), None).await,
        PaymentVerdict::NoHeaderService
    );
}
