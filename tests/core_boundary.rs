//! The boundary the core crate moves along: `src/payment_core.rs` (outside its
//! tests) names no runtime and nothing else in this crate, so publishing
//! `bsv-middleware-core` replaces it with a re-export.

const CORE: &str = include_str!("../src/payment_core.rs");

#[test]
fn the_core_module_names_no_runtime_and_nothing_of_this_crate() {
    let body = CORE.split("#[cfg(test)]").next().unwrap();
    for forbidden in [
        "axum", "tokio", "reqwest", "worker", "hyper", "tower", "crate::",
    ] {
        let hits: Vec<&str> = body
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .filter(|l| l.contains(forbidden))
            .collect();
        assert!(hits.is_empty(), "payment_core names {forbidden}: {hits:?}");
    }
    let uses: Vec<&str> = body.lines().filter(|l| l.starts_with("use ")).collect();
    for line in &uses {
        assert!(
            ["use async_trait::", "use bsv_rs::", "use std::"]
                .iter()
                .any(|ok| line.starts_with(ok)),
            "payment_core imports outside bsv-rs, async-trait and std: {line}"
        );
    }
    assert!(!uses.is_empty());
}
