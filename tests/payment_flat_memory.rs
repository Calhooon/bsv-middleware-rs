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
//! - the SDK's `verify_stream` alone: its index, a bounded
//!   number of bytes per element;
//! - the door's full check: the SDK's reading plus a constant (a second
//!   element in hand), never a byte that grows with the depth.
//!
//! At 100,000 links a second body pads every unproven locking script with 4 KiB.
//! Equal element counts with very different body sizes must have heap peaks
//! within a constant band, in addition to the measured per-link ceiling.
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
use support::beef_chain::{funding_root, padded_lock, ChainSource, HEIGHT, OP_TRUE, SATS};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

// bsv-rs 0.8.1 measured 20,661,204 B / 100,000 links = 206.6 B/link in
// this harness, here and on the hosted runner (0.5.0: 175.2): the index held
// to a subject keeps every raw transaction's input txids for the atomic walk
// (`TxEntry::prevs`, bsv-rs bf46677 `transaction/beef_stream.rs:1777`), one
// 32-byte hash per link. 228 leaves 10.4% for runner variation, under the
// SDK's own ceiling (400 B/element at 0.8.1, `tests/memory_profiling.rs`).
// It is a heap regression witness, never an acceptance limit on a payment.
const MAX_BYTES_PER_LINK: u64 = 228;
// The existing one-element/chunk allowance: independent of the total body's
// bytes. A 4 KiB locking script may change transient element allocations, not the index.
const BODY_FLATNESS_BAND: u64 = 64 * 1024;
const OUTPUT_PADDING: usize = 4096;

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

    // Check the padded parent is spendable before the long heap profiles.
    assert!(verify_stream(
        ChainSource::with_output_padding(3, OUTPUT_PADDING),
        HashMap::from([(HEIGHT, funding_root())]),
        None,
    )
    .unwrap()
    .is_valid());

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
    // The rule: the peak does not grow with the depth. Equality was too strict
    // for an allocator's first-touch cost (a hosted runner measured 900 bytes
    // more at the first depth than at the deeper ones, bsv-middleware-rs #8);
    // a 4 KiB band around the first measurement states the rule and no more.
    for (links, _, _, output_only, ..) in &rows {
        assert!(
            output_only.abs_diff(first) <= 4096,
            "the output check's peak moved with the depth at {links} links: {output_only} against {first}"
        );
        assert!(*output_only < 64 * 1024, "more than a chunk and an element");
    }
    for (links, n, _, _, sdk, door) in &rows {
        // The door adds a constant to the SDK's reading: the tap's decoder
        // and the one element it holds.
        assert!(
            door.abs_diff(*sdk) < 16 * 1024,
            "{links} links: the door holds {} B over verify_stream",
            *door as i64 - *sdk as i64
        );
        // The index is a bounded number of bytes per element: under 320 B,
        // bsv-rs's own bound through 0.8.0 (tests/memory_profiling.rs; 400 B
        // at 0.8.1), so tighter than the SDK's.
        assert!(
            (*door as f64) / (*n as f64) < 320.0 + 64.0 * 1024.0 / (*n as f64),
            "{links} links: {door} B"
        );
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

    let (links, n, small_bytes, _, _, small_heap) = rows[2];
    assert!(small_heap < MAX_BYTES_PER_LINK * links as u64);
    let padded_script = padded_lock(OUTPUT_PADDING);
    let padded_payment = PaymentToVerify {
        expected_script: &padded_script,
        ..PAYMENT
    };
    let started = Instant::now();
    let (large_heap, (verdict, large_bytes)) = peak(|| {
        let mut source = ChainSource::with_output_padding(n, OUTPUT_PADDING);
        let verdict = runtime
            .block_on(verify_payment(&padded_payment, &mut source, Some(&headers)))
            .unwrap();
        (verdict, source.total)
    });
    assert_eq!(verdict, paid, "the padded body's full check");
    assert_eq!(*headers.asked.lock().unwrap(), vec![HEIGHT as u32; 4]);
    // The same proven funding and 100,000 links; only the locking scripts grew.
    assert_eq!(large_bytes, small_bytes + links as u64 * 4102);
    assert!(
        large_bytes > small_bytes * 64,
        "the bodies must differ greatly"
    );
    println!(
        "  flatness: {links} links each; small {small_bytes} B / {small_heap} B heap; \
         padded {large_bytes} B / {large_heap} B heap; delta {} B; {:.3} s",
        large_heap.abs_diff(small_heap),
        started.elapsed().as_secs_f64()
    );
    // These replace the body-byte ratio, which penalized small valid links
    // without testing retention of body bytes. Neither bound grows with bytes.
    assert!(
        large_heap < MAX_BYTES_PER_LINK * links as u64,
        "padded body: {large_heap} B exceeds {MAX_BYTES_PER_LINK} B/link"
    );
    assert!(
        large_heap.abs_diff(small_heap) <= BODY_FLATNESS_BAND,
        "equal counts: {small_heap} B vs {large_heap} B heap"
    );
}
