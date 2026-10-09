//! The payment door reads the P0-5 deep chain in time linear in its links
//! (bsv-stack-lean, the no-limits program, NL-5; the Lean's `work_linear`).
//! The memory of the same readings is `tests/payment_flat_memory.rs`.

mod support {
    pub mod beef_chain;
}

use std::time::Instant;

use async_trait::async_trait;
use bsv_middleware_rs::{
    verify_payment, verify_payment_output_only, HeaderLookupError, HeaderService, PaymentToVerify,
    PaymentVerdict,
};
use bsv_rs::transaction::verify_stream;
use std::collections::HashMap;
use support::beef_chain::{funding_root, ChainSource, HEIGHT, OP_TRUE, SATS};

const PAYMENT: PaymentToVerify<'static> = PaymentToVerify {
    output_index: 0,
    expected_script: &[OP_TRUE],
    required_satoshis: SATS,
};

struct OneHeader(String);

#[async_trait]
impl HeaderService for OneHeader {
    async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError> {
        if u64::from(height) == HEIGHT {
            Ok(self.0.clone())
        } else {
            Err(HeaderLookupError(format!("no header at {height}")))
        }
    }
}

#[tokio::test]
async fn the_door_reads_the_deep_chain_in_linear_time() {
    let mut root = funding_root();
    root.reverse();
    let headers = OneHeader(hex::encode(root));
    let paid = PaymentVerdict::Verified { satoshis: SATS };
    println!("\n=== the payment door, the P0-5 deep chain, time ===");
    let mut per_link = Vec::new();
    for links in [1_000usize, 10_000, 100_000] {
        let n = links + 1;
        let started = Instant::now();
        let carried = HashMap::from([(HEIGHT, funding_root())]);
        assert!(verify_stream(ChainSource::new(n), &carried, None)
            .unwrap()
            .is_valid());
        let sdk = started.elapsed();

        let started = Instant::now();
        let verdict = verify_payment(&PAYMENT, ChainSource::new(n), Some(&headers))
            .await
            .unwrap();
        let door = started.elapsed();
        assert_eq!(verdict, paid, "{links} links");

        let started = Instant::now();
        let verdict = verify_payment_output_only(&PAYMENT, ChainSource::new(n)).unwrap();
        let output_only = started.elapsed();
        assert_eq!(verdict, paid, "{links} links, the output check");

        println!(
            "  {links} unproven links: verify_stream {:.3} s; the door {:.3} s ({:.2} us a link); \
             the output check {:.3} s",
            sdk.as_secs_f64(),
            door.as_secs_f64(),
            door.as_secs_f64() * 1e6 / links as f64,
            output_only.as_secs_f64()
        );
        per_link.push(door.as_secs_f64() / links as f64);
    }
    // Linear: a hundred times the links costs no more per link, with room for
    // a loaded machine: a quadratic reading would be a hundred times here.
    assert!(per_link[2] < per_link[0] * 25.0, "per link: {:?}", per_link);
}
