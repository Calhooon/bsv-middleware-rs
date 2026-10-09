# Changelog

## [Unreleased]

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
