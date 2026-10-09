//! The payment door's memory does not grow with the payment (bsv-stack-lean,
//! the no-limits program, NL-5; the Lean's `memory_bounded_per_element`).
//!
//! The P0-5 deep chain (a proven funding transaction and unproven links, each
//! spending the one before) is read at 1,000, 10,000 and 100,000 unproven
//! links from a source that writes itself link by link, so the heap holds no
//! BEEF and the peak is the door's own. Three readings at each depth:
//!
//! - the output check alone: one chunk and one element, the same peak at
//!   every depth;
//! - the SDK's `verify_stream` alone (bsv-rs 0.4.0): its index, a bounded
//!   number of bytes per element;
//! - the door's full check: the SDK's reading plus a constant (a second
//!   element in hand), never a byte that grows with the depth.
//!
//! One test, so the profiles do not overlap.

mod support {
    pub mod beef_chain;
}

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use async_trait::async_trait;
use bsv_middleware_rs::{
    verify_payment, verify_payment_output_only, HeaderLookupError, HeaderService, PaymentToVerify,
    PaymentVerdict,
};
use bsv_rs::transaction::verify_stream;
use support::beef_chain::{funding_root, ChainSource, HEIGHT, OP_TRUE, SATS};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const PAYMENT: PaymentToVerify<'static> = PaymentToVerify {
    output_index: 0,
    expected_script: &[OP_TRUE],
    required_satoshis: SATS,
};

/// The one header the chain needs, and the heights asked.
struct OneHeader {
    root: String,
    asked: Mutex<Vec<u32>>,
}

#[async_trait]
impl HeaderService for OneHeader {
    async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError> {
        self.asked.lock().unwrap().push(height);
        if u64::from(height) == HEIGHT {
            Ok(self.root.clone())
        } else {
            Err(HeaderLookupError(format!("no header at {height}")))
        }
    }
}

/// The peak heap of `f`, in bytes, counted from an empty profile.
fn peak<T>(f: impl FnOnce() -> T) -> (u64, T) {
    let _profiler = dhat::Profiler::builder().testing().build();
    let value = f();
    (dhat::HeapStats::get().max_bytes as u64, value)
}

#[test]
fn the_door_reads_100_000_unproven_links_with_flat_memory() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut root = funding_root();
    root.reverse();
    let headers = OneHeader {
        root: hex::encode(root),
        asked: Mutex::new(Vec::new()),
    };
    let paid = PaymentVerdict::Verified { satoshis: SATS };

    println!("\n=== the payment door, the P0-5 deep chain ===");
    let mut rows = Vec::new();
    for links in [1_000usize, 10_000, 100_000] {
        // The proven funding transaction and `links` unproven ones.
        let n = links + 1;

        let (output_only, (verdict, bytes)) = peak(|| {
            let mut source = ChainSource::new(n);
            let verdict = verify_payment_output_only(&PAYMENT, &mut source).unwrap();
            (verdict, source.total)
        });
        assert_eq!(verdict, paid, "{links} links, the output check");

        let (sdk, valid) = peak(|| {
            let carried = HashMap::from([(HEIGHT, funding_root())]);
            verify_stream(ChainSource::new(n), &carried, None)
                .unwrap()
                .is_valid()
        });
        assert!(valid, "{links} links, the SDK's reading");

        let started = Instant::now();
        let (door, verdict) = peak(|| {
            runtime
                .block_on(verify_payment(
                    &PAYMENT,
                    ChainSource::new(n),
                    Some(&headers),
                ))
                .unwrap()
        });
        let elapsed = started.elapsed();
        assert_eq!(verdict, paid, "{links} links, the full check");

        println!(
            "  {links} unproven links, {bytes} bytes: output check {output_only} B; \
             verify_stream {sdk} B; the door {door} B ({:.1} B per element, {} B over \
             verify_stream); {:.3} s",
            door as f64 / n as f64,
            door as i64 - sdk as i64,
            elapsed.as_secs_f64()
        );
        rows.push((links, n, bytes, output_only, sdk, door));
    }

    // One header, asked once for each reading: the root is held to it.
    assert_eq!(*headers.asked.lock().unwrap(), vec![HEIGHT as u32; 3]);

    // The output check: one chunk and one element at any depth.
    let (_, _, _, first, ..) = rows[0];
    for (links, _, _, output_only, ..) in &rows {
        assert_eq!(
            *output_only, first,
            "the output check's peak moved with the depth at {links} links"
        );
        assert!(*output_only < 64 * 1024, "more than a chunk and an element");
    }
    for (links, n, bytes, _, sdk, door) in &rows {
        // The door adds a constant to the SDK's reading: the tap's decoder
        // and the one element it holds.
        assert!(
            door.abs_diff(*sdk) < 16 * 1024,
            "{links} links: the door holds {} B over verify_stream",
            *door as i64 - *sdk as i64
        );
        // The index is a bounded number of bytes per element (bsv-rs's own
        // bound, tests/memory_profiling.rs: under 320 B).
        assert!(
            (*door as f64) / (*n as f64) < 320.0 + 64.0 * 1024.0 / (*n as f64),
            "{links} links: {door} B"
        );
        // Never the BEEF: at depth the peak is a fraction of the bytes read
        // and an in-memory parse would hold all of them and more.
        if *links >= 10_000 {
            assert!(door * 2 < bytes * 7, "{links} links: {door} B of {bytes}");
        }
    }
    // A hundred times the depth costs no more per element.
    let per = |i: usize| rows[i].5 as f64 / rows[i].1 as f64;
    assert!(
        per(2) <= per(0),
        "{} B then {} B per element",
        per(0),
        per(2)
    );
    // The bytes are the P0-5 chain's: 62 a link.
    assert_eq!(rows[2].2, 6_200_124);
}
