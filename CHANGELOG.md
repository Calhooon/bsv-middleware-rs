# Changelog

## [Unreleased]

## [0.3.0] - 2026-10-09

### Changed (breaking)

- The payment surface answers in six words. `verify_payment` returns a
  `PaymentVerdict`: `Verified { satoshis }`, `Underpaid { paid, required }`,
  `WrongScript { expected, actual }`, `NoHeaderService`,
  `RootMismatch { height, merkle_root }` or `Unverifiable(UnverifiableReason)`.
  It takes a `PaymentToVerify` and the header service as a trait
  (`Option<&dyn HeaderService>`, `merkle_root_at(height)`); `None` is
  `NoHeaderService`, a server fault, before the payment is read. A header
  lookup that cannot answer is `Unverifiable` (fail closed), never an accept.
- `verify_payment_output`, `verify_payment_output_with_limits` and
  `PaymentOutputError` are removed: one implementation, in `payment_core`.
  Callers move to `verify_payment` (with a header service) or, by name, to
  `verify_payment_output_only` (the output check without SPV); the `_with_limits`
  forms of both take a caller's byte and `BeefLimits` budgets.
  `ScriptMismatch` is the word `WrongScript`, now carrying both scripts.
- `brc29_locking_script` returns `Result<Vec<u8>, UnverifiableReason>`
  (`KeyDerivation`) in place of `AuthError`.
- Plain BEEF (V1, V2) is read as well as Atomic BEEF; the subject is the Atomic
  BEEF's named transaction, else the last. A raw transaction is read by the
  output-only check and is `Unverifiable(NoProof)` under `verify_payment`.
- `UnverifiableReason` and `AuthError` are `#[non_exhaustive]`. Why: 0.2.2
  added three variants (`PaymentTooLarge`, `BeefTransactionsExceeded`,
  `BeefBumpsExceeded`) to the exhaustive `PaymentOutputError`, which broke
  exhaustive matches on a patch version. Those three are now reasons of
  `Unverifiable`, with the same fields and text, and a reason added later is a
  minor release, not a break: match these two enums with a catch-all arm. The
  six words of `PaymentVerdict` are the contract and stay exhaustive.

### Added

- `payment_core`: `PaymentVerdict`, `UnverifiableReason` (`is_server_side`),
  `HeaderService`, `HeaderLookupError`, `PaymentToVerify`, `verify_payment`,
  `verify_payment_with_limits`, `verify_payment_output_only`,
  `verify_payment_output_only_with_limits`, `header_service_url`. The module
  names no axum, tokio or reqwest type (`tests/core_boundary.rs`).
- Feature `axum`: `axum_layer` with `PaymentGate`, `require_payment` and the
  `VerifiedPayment` extractor for Axum 0.8. The example needs the feature:
  `cargo run --features axum --example axum_server`.
- `tests/conformance_brc29.rs` runs the BRC-29 payment conformance vectors,
  20 of 20 exact, from a byte-pinned copy under `tests/vectors/`; the gate's
  `vectors` job runs it.

### Unchanged

- The 0.2.2 limits: 4 MiB, 128 BEEF transactions, 32 BUMPs
  (`MAX_PAYMENT_BYTES`, `MAX_PAYMENT_BEEF_TXS`, `MAX_PAYMENT_BEEF_BUMPS`,
  `PAYMENT_BEEF_LIMITS`, still exported from the crate root and `payment`).
  They bound the bytes before either format is parsed and the counts before
  the entries are read; the six words are the verdict after that.
- 0.2.2 stays published; nothing is yanked. Existing stored payments are
  unchanged.

## [0.2.2] - 2026-10-08

### Added

- Named payment parser budgets: 4 MiB, 128 BEEF transactions and 32 BUMPs;
  `PAYMENT_BEEF_LIMITS` combines them. These are configurable door policies.
- `verify_payment_output_with_limits` for callers with their own byte and
  `BeefLimits` budgets; the original function keeps its signature.
- `PaymentTooLarge`, `BeefTransactionsExceeded` and `BeefBumpsExceeded` payment
  errors, each carrying the offending count and bound.

### Changed

- Refuse oversized payments before parsing. Parse Atomic BEEF with
  `Beef::from_binary_with_limits`, then extract its declared subject with
  `Beef::find_atomic_transaction`. Requires bsv-rs 0.3.35 (the dependency line says so).
- `PaymentOutputError` was exhaustive in 0.2.1. The added variants break
  downstream exhaustive matches: handle them or add a catch-all arm. Released
  as 0.2.2 under the owner's 0.3.35 precedent (bsv-stack-lean #57): every
  caller pins the 0.2 line and a 0.3.0 would reach none of them by
  `cargo update`; the migration is one catch-all arm or the three new arms.
- Existing stored payments are unchanged. Callers must bound transport reads
  before decoding; payments above their parser budgets are refused on recheck.
