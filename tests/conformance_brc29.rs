//! The BRC-29 payment conformance vectors, run against this crate.
//!
//! `conformance/brc29-payment-vectors.json` is copied byte for byte from
//! `bsv-middleware-cloudflare@dabfb78 conformance/brc29-payment-vectors.json`
//! (sha256 d36abf96399f6e5b654ded3d6a04d20c6a504ff135aa9c27880dc1b2e5fef176);
//! its README there gives the schema and the run recipe. Never edit it by hand.
//!
//! Every case: the derivation through `brc29_locking_script`; the configured
//! URL through `header_service_url` (a `config` case must name no service);
//! the payment through `verify_payment` with the header service replaced by a
//! stub answering from `header_service.lookup`; `output` cases also through
//! `verify_payment_output_only`. The verdict is mapped onto the vector words
//! and compared with `expected` exactly.
//!
//! One case diverges by design and is declared below: the vectors' sixth word
//! is `AcceptedUnverified` (fail open when the header service cannot answer);
//! Rule 27 (epoch `NETWORK-ENFORCEMENT-RULES.md` at 2f4ef72) has `Unverifiable`
//! in its place and fails closed. The runner requires that case to answer
//! exactly the declared word, and fails if the declaration goes stale.

use async_trait::async_trait;
use bsv_middleware_rs::{
    brc29_locking_script, header_service_url, verify_payment, verify_payment_output_only,
    HeaderLookupError, HeaderService, PaymentToVerify, PaymentVerdict, UnverifiableReason,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::ProtoWallet;
use serde_json::{json, Value};
use std::sync::Mutex;

const VECTORS: &str = include_str!("../conformance/brc29-payment-vectors.json");

/// Cases whose expected word this crate answers differently on purpose:
/// (case, the vector's word, this crate's word and fields).
fn declared_divergences() -> Vec<(&'static str, &'static str, Observed)> {
    vec![(
        "spv-lookup-error",
        "AcceptedUnverified",
        observed(
            "Unverifiable",
            json!({ "reason": "HeaderLookupFailed", "height": 850000 }),
        ),
    )]
}

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

fn word(verdict: PaymentVerdict) -> Observed {
    match verdict {
        PaymentVerdict::Verified { satoshis } => {
            observed("Verified", json!({ "satoshis": satoshis }))
        }
        PaymentVerdict::Underpaid { paid, required } => {
            observed("Underpaid", json!({ "paid": paid, "required": required }))
        }
        PaymentVerdict::WrongScript { expected, actual } => observed(
            "WrongScript",
            json!({ "expected_script": hex::encode(expected), "actual_script": hex::encode(actual) }),
        ),
        PaymentVerdict::NoHeaderService => observed("NoHeaderService", json!({})),
        PaymentVerdict::RootMismatch {
            height,
            merkle_root,
        } => observed(
            "RootMismatch",
            json!({ "height": height, "merkle_root": merkle_root }),
        ),
        PaymentVerdict::Unverifiable(UnverifiableReason::HeaderLookupFailed { height, .. }) => {
            observed(
                "Unverifiable",
                json!({ "reason": "HeaderLookupFailed", "height": height }),
            )
        }
        PaymentVerdict::Unverifiable(reason) => {
            observed("Unverifiable", json!({ "reason": format!("{:?}", reason) }))
        }
    }
}

/// The header service of a case: `{"answer":"root","height":h,"merkle_root":r}`
/// answers `r` at `h` and nothing elsewhere; `{"answer":"error","reason":s}`
/// answers nothing. Records every height asked.
struct VectorHeaders {
    lookup: Value,
    asked: Mutex<Vec<u32>>,
}

#[async_trait]
impl HeaderService for VectorHeaders {
    async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError> {
        self.asked.lock().unwrap().push(height);
        match self.lookup["answer"].as_str() {
            Some("root") if self.lookup["height"].as_u64() == Some(u64::from(height)) => {
                Ok(self.lookup["merkle_root"].as_str().unwrap().to_string())
            }
            Some("root") => Err(HeaderLookupError(format!("no header at {}", height))),
            Some("error") => Err(HeaderLookupError(
                self.lookup["reason"].as_str().unwrap().to_string(),
            )),
            other => panic!("unknown lookup answer {:?}", other),
        }
    }
}

async fn run_case(case: &Value) -> Observed {
    let s = |k: &str| case[k].as_str().unwrap().to_string();
    let name = s("name");
    let wallet = ProtoWallet::new(Some(
        PrivateKey::from_hex(&s("server_private_key")).unwrap(),
    ));
    assert_eq!(
        wallet.identity_key().to_hex(),
        s("server_identity_key"),
        "{name}: server identity"
    );
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
        "{name}: derivation"
    );
    let tx = hex::decode(case["transaction"]["beef_hex"].as_str().unwrap()).unwrap();
    let payment = PaymentToVerify {
        transaction: &tx,
        output_index: case["output_index"].as_u64().unwrap() as u32,
        expected_script: &script,
        required_satoshis: case["required_satoshis"].as_u64().unwrap(),
    };
    let url = case["header_service"]["url"].as_str();
    let stage = s("stage");
    if stage == "config" {
        assert_eq!(
            header_service_url(url),
            None,
            "{name}: the URL must name no service"
        );
        return word(verify_payment(&payment, None).await);
    }
    assert!(
        header_service_url(url).is_some(),
        "{name}: the URL must name a service"
    );
    let headers = VectorHeaders {
        lookup: case["header_service"]["lookup"].clone(),
        asked: Mutex::new(Vec::new()),
    };
    let got = word(verify_payment(&payment, Some(&headers)).await);
    let asked = headers.asked.lock().unwrap().clone();
    if stage == "output" {
        assert_eq!(
            word(verify_payment_output_only(&payment)).word,
            got.word,
            "{name}: the output check alone gives the same word"
        );
        if got.word != "Verified" {
            assert!(asked.is_empty(), "{name}: refused before any lookup");
        }
    }
    if case["requires_merkle_lookup"].as_bool().unwrap() {
        assert_eq!(
            asked,
            vec![case["transaction"]["proof"]["height"].as_u64().unwrap() as u32]
        );
    }
    got
}

#[tokio::test]
async fn every_vector_case() {
    let file: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(file["schema"], "brc29-payment-vectors/1");
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    let divergences = declared_divergences();
    let mut failures = Vec::new();
    let (mut exact, mut declared) = (0, 0);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let expected = observed(
            case["expected"]["word"].as_str().unwrap(),
            case["expected"]["fields"].clone(),
        );
        let got = run_case(case).await;
        let verdict = match divergences.iter().find(|(n, _, _)| *n == name) {
            Some((_, vector_word, ours)) if expected.word == *vector_word && got == *ours => {
                declared += 1;
                "DECLARED"
            }
            Some(_) => "FAIL",
            None if got == expected => {
                exact += 1;
                "ok"
            }
            None => "FAIL",
        };
        println!(
            "{verdict:8} {name:40} expected {} {} got {} {}",
            expected.word, expected.fields, got.word, got.fields
        );
        if verdict == "FAIL" {
            failures.push(name.to_string());
        }
    }
    println!(
        "{exact} exact, {declared} declared divergence(s), {} failing",
        failures.len()
    );
    assert!(failures.is_empty(), "failing cases: {:?}", failures);
    assert_eq!(
        declared,
        divergences.len(),
        "a declared divergence went stale"
    );
}
