//! Small boundary witnesses for the shared payment door (P0-5d, issue #57).
//! No exhaustion shapes: at most 129 transactions or 33 single-leaf BUMPs.

use bsv_middleware_rs::{verify_payment_output, PaymentOutputError};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{Beef, MerklePath, Transaction, TransactionInput, TransactionOutput};

// Kept local for the red run: these proposed defaults do not exist at 20c1a65.
const MAX_PAYMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PAYMENT_BEEF_TXS: usize = 128;
const MAX_PAYMENT_BEEF_BUMPS: usize = 32;
const SCRIPT: &[u8] = &[0x51];
const PRICE: u64 = 100;

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
    let error = verify_payment_output(&bytes, 0, SCRIPT, PRICE).expect_err("over byte bound");
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
    let error = verify_payment_output(&bytes, 0, SCRIPT, PRICE).expect_err("over byte bound");
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
    let error = verify_payment_output(&bytes, 0, SCRIPT, PRICE).expect_err("invalid inner version");
    assert!(matches!(error, PaymentOutputError::MalformedTransaction(_)));
    assert!(error.to_string().contains("Invalid BEEF version"));
}

#[test]
fn exactly_the_transaction_bound_is_admitted() {
    let bytes = chain_atomic(MAX_PAYMENT_BEEF_TXS);
    assert_eq!(verify_payment_output(&bytes, 0, SCRIPT, PRICE), Ok(PRICE));
}

#[test]
fn one_transaction_over_is_refused_with_the_count_and_bound() {
    let bytes = chain_atomic(MAX_PAYMENT_BEEF_TXS + 1);
    let error = verify_payment_output(&bytes, 0, SCRIPT, PRICE).expect_err("129 transactions");
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
    assert_eq!(verify_payment_output(&bytes, 0, SCRIPT, PRICE), Ok(PRICE));
}

#[test]
fn one_bump_over_is_refused_with_the_count_and_bound() {
    let bytes = funded_atomic(MAX_PAYMENT_BEEF_BUMPS + 1);
    let error = verify_payment_output(&bytes, 0, SCRIPT, PRICE).expect_err("33 BUMPs");
    let message = error.to_string();
    assert!(message.contains("33 BUMPs"), "names the count: {message}");
    assert!(
        message.contains("max_bumps 32"),
        "names the bound: {message}"
    );
}
