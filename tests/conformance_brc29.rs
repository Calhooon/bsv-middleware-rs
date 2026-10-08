//! The BRC-29 payment conformance vectors, run against this crate.
//!
//! `conformance/brc29-payment-vectors.json` is copied byte for byte from
//! `bsv-middleware-cloudflare@dabfb78 conformance/brc29-payment-vectors.json`
//! (sha256 d36abf96399f6e5b654ded3d6a04d20c6a504ff135aa9c27880dc1b2e5fef176);
//! its README there gives the schema and the run recipe. Never edit it by hand.
//!
//! Every case goes through `brc29_locking_script` (the derivation) and
//! `verify_payment_output` (the output check), and the result is mapped onto
//! the vector's words. Step 1 of the Phase B brief: run the file against the
//! crate as it is (0.2.1) and record which cases fail and why.

use bsv_middleware_rs::{brc29_locking_script, verify_payment_output, PaymentOutputError};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::transaction::Transaction;
use bsv_rs::wallet::ProtoWallet;
use serde_json::{json, Value};

const VECTORS: &str = include_str!("../conformance/brc29-payment-vectors.json");

/// What the crate answered, as a vector word and its fields.
#[derive(Debug, Clone, PartialEq)]
struct Observed {
    word: String,
    fields: Value,
}

fn observed(word: &str, fields: Value) -> Observed {
    Observed {
        word: word.to_string(),
        fields,
    }
}

fn run_case(case: &Value, tx: &[u8]) -> Observed {
    let s = |k: &str| case[k].as_str().unwrap().to_string();
    let wallet = ProtoWallet::new(Some(PrivateKey::from_hex(&s("server_private_key")).unwrap()));
    let script = brc29_locking_script(
        &wallet,
        &s("derivation_prefix"),
        &s("derivation_suffix"),
        &s("sender_identity_key"),
    )
    .unwrap();
    assert_eq!(
        hex::encode(&script),
        s("expected_locking_script"),
        "{}: derivation",
        s("name")
    );
    let index = case["output_index"].as_u64().unwrap() as u32;
    let price = case["required_satoshis"].as_u64().unwrap();
    // 0.2.1 has no header-service parameter: `header_service` cannot be passed.
    match verify_payment_output(tx, index, &script, price) {
        Ok(satoshis) => observed("Verified", json!({ "satoshis": satoshis })),
        Err(PaymentOutputError::Underpaid { paid, required }) => {
            observed("Underpaid", json!({ "paid": paid, "required": required }))
        }
        // 0.2.1 does not carry the two scripts.
        Err(PaymentOutputError::ScriptMismatch { .. }) => observed("WrongScript", json!({})),
        Err(e) => observed(&format!("(no word) {:?}", e), json!({})),
    }
}

#[test]
fn every_vector_case() {
    let file: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(file["schema"], "brc29-payment-vectors/1");
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let expected = observed(
            case["expected"]["word"].as_str().unwrap(),
            case["expected"]["fields"].clone(),
        );
        let beef = hex::decode(case["transaction"]["beef_hex"].as_str().unwrap()).unwrap();
        let got = run_case(case, &beef);
        // Diagnostic only: the same subject re-wrapped as an Atomic BEEF (what
        // 0.2.1 reads), so the table also shows what the crate answers once
        // the envelope is not the obstacle.
        let atomic = Transaction::from_beef(&beef, None)
            .unwrap()
            .to_atomic_beef(true)
            .unwrap();
        let rewrapped = run_case(case, &atomic);
        let verdict = if got == expected { "ok" } else { "FAIL" };
        println!(
            "{verdict:4} {name:42} expected {} {} | as sent: {} {} | as Atomic BEEF: {} {}",
            expected.word, expected.fields, got.word, got.fields, rewrapped.word, rewrapped.fields
        );
        if got != expected {
            failures.push(name.to_string());
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases fail: {:?}",
        failures.len(),
        cases.len(),
        failures
    );
}
