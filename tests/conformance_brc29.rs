//! The BRC-29 payment conformance vectors, run against this crate.
//!
//! `tests/vectors/brc29-payment-vectors.json` is a byte-pinned copy of the
//! canonical file, `conformance/brc29-payment-vectors.json` of the stack
//! review repository (bsv-stack-lean), which owns the vectors; its README
//! there gives the schema and the run recipe. Never edit the copy by hand: a
//! change starts in the canonical file and the copy follows, with
//! `VECTORS_SHA256` below. `the_vectors_are_the_pinned_bytes` holds the copy
//! to that digest wherever the tests run, and
//! `the_pinned_copy_is_the_canonical_file` compares it byte for byte with the
//! canonical file when that checkout is present (`BRC29_VECTORS_CANONICAL`,
//! else a sibling `bsv-stack-lean`), and says so when it is not.
//!
//! Every case: the derivation through `brc29_locking_script`; the configured
//! URL through `header_service_url` (a `config` case must name no service);
//! the payment through `verify_payment` with the header service replaced by a
//! stub answering from `header_service.lookup`; `output` cases also through
//! `verify_payment_output_only`. The verdict is mapped onto the vector words
//! and compared with `expected` exactly: 20 of 20, no declared divergence.
//! The file's `rulings` list records the ruling of 2026-10-08 that
//! `spv-lookup-error` is `Unverifiable` (fail closed when the header service
//! cannot answer), which is what this crate answers.

use async_trait::async_trait;
use bsv_middleware_rs::{
    brc29_locking_script, header_service_url, verify_payment, verify_payment_output_only,
    HeaderLookupError, HeaderService, PaymentToVerify, PaymentVerdict, UnverifiableReason,
};
use bsv_rs::primitives::{sha256, PrivateKey};
use bsv_rs::wallet::ProtoWallet;
use serde_json::{json, Value};
use std::sync::Mutex;

const VECTORS: &str = include_str!("vectors/brc29-payment-vectors.json");

/// The sha256 of the pinned copy (the canonical file's bytes).
const VECTORS_SHA256: &str = "dae68f0b2999b44088e67206b1c34866a2c3f0fee8f0a8c8f4829d313ba13a8d";

/// Where the canonical file is, when its checkout sits beside this one.
const CANONICAL_SIBLING: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../bsv-stack-lean/conformance/brc29-payment-vectors.json"
);

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
        // The vectors give `Unverifiable` the height of the first root whose
        // lookup failed, and nothing else.
        PaymentVerdict::Unverifiable(UnverifiableReason::HeaderLookupFailed { height, .. }) => {
            observed("Unverifiable", json!({ "height": height }))
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

#[test]
fn the_vectors_are_the_pinned_bytes() {
    assert_eq!(
        hex::encode(sha256(VECTORS.as_bytes())),
        VECTORS_SHA256,
        "tests/vectors/brc29-payment-vectors.json is stale or hand-edited: it is a copy of the \
         canonical file; copy that file again and update VECTORS_SHA256 in the same change"
    );
}

/// The copy is the canonical file, byte for byte. A hosted runner has no
/// checkout of the canonical repository: there the digest above is the pin
/// and this test says that it compared nothing.
#[test]
fn the_pinned_copy_is_the_canonical_file() {
    let path =
        std::env::var("BRC29_VECTORS_CANONICAL").unwrap_or_else(|_| CANONICAL_SIBLING.to_string());
    match std::fs::read(&path) {
        Ok(canonical) => assert!(
            canonical == VECTORS.as_bytes(),
            "tests/vectors/brc29-payment-vectors.json differs from the canonical file {path}"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("no canonical file at {path}; the copy is held by its sha256 alone");
        }
        Err(e) => panic!("cannot read {path}: {e}"),
    }
}

#[tokio::test]
async fn every_vector_case() {
    let file: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(file["schema"], "brc29-payment-vectors/1");
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    assert_eq!(
        file["words"].as_object().unwrap().len(),
        6,
        "six words in the glossary"
    );
    let mut failures = Vec::new();
    let mut exact = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let expected = observed(
            case["expected"]["word"].as_str().unwrap(),
            case["expected"]["fields"].clone(),
        );
        let got = run_case(case).await;
        let verdict = if got == expected {
            exact += 1;
            "ok"
        } else {
            failures.push(name.to_string());
            "FAIL"
        };
        println!(
            "{verdict:8} {name:40} expected {} {} got {} {}",
            expected.word, expected.fields, got.word, got.fields
        );
    }
    println!(
        "{exact} of {} exact, {} failing",
        cases.len(),
        failures.len()
    );
    assert!(failures.is_empty(), "failing cases: {:?}", failures);
    assert_eq!(exact, 20, "20 of 20 exact");
}
