# Changelog

## [0.6.2] - 2026-10-22

- bsv-rs ^0.8 (`bsv-rs = "0.8.0"` by caret; 0.8.1 resolves): the atomic rule judged on the subject's graph (BRC-95; the owner's ruling of 2026-10-22), `Error` non_exhaustive, the typed `WalletBusy`; no source change in this crate, no wire change.
- Breaking by the dependency: the re-exported bsv-rs types and `From<bsv_rs::Error>` now come from bsv-rs 0.8; a host matching on `bsv_rs::Error` adds a wildcard arm.
- `the_output_check_reads_the_declared_atomic_subject` re-read under the rule: its retained descendant is framed by hand (0.8.1's `to_binary_atomic` writes the subject's closure) and refused as `UnrelatedTransaction` at its offset, the headers carrying the BUMP's root; the module's order of checks names the graph rule (a doc sentence; no code change); the flat-memory witness's per-link ceiling 192 to 228 B, the index's input txids per link (measured 206.6 B).

## [0.6.1] - 2026-10-19

- The Axum gate refuses a reused derivation prefix (BRC-105: "each `derivationPrefix` can only be used once"; rule M14 of the stack's messaging charter, the owner's ruling of 2026-10-19). Each prefix a 402 issues is recorded with `PaymentStorage::store_derivation_prefix` for the store's TTL, and `consume_derivation_prefix` claims it when a payment under it is verified, before the handler runs. A second payment under the same prefix, whatever its transaction, a prefix past its window, and an HMAC-valid prefix the store never recorded are refused 402 `ERR_INVALID_DERIVATION_PREFIX` with a fresh challenge; the handler (the wallet's caller) is not reached. A store fault is 503 `ERR_PAYMENT_UNAVAILABLE`. The reference keys replay by the txid and serves the second payment: that is the divergence, witnessed by `a_prefix_paid_with_a_second_transaction_is_refused_and_the_wallet_called_once`.
- `PaymentGate::new` keeps its signature and keeps prefixes in `MemoryPaymentStorage` (new) for `DEFAULT_PREFIX_TTL_SECONDS` (3600); `PaymentGate::with_prefix_store(store, ttl_seconds)` supplies a shared store. A server of several instances behind one door must share one store, or a prefix issued by one instance is refused by another.

## [0.6.0] - 2026-10-18

- bsv-rs 0.7.0, declared by caret (`bsv-rs = "0.7.0"`). Its default signing digest is the node's: the dispatch (BIP143 for a type with `SIGHASH_FORKID` and without `SIGHASH_CHRONICLE`, the original digest otherwise), the `SIGHASH_SINGLE` sentinel, and an explicit scriptCode. The crate compiled and every test passed unchanged; no source change was needed.
- The payment door's spends are judged by bsv-rs's interpreter, so the digest it verifies against is that dispatch. `the_door_verifies_against_the_sdks_dispatched_signing_digest` pins it: a P2PKH spend signed through `SigningContext` verifies under `ALL|FORKID` and `ALL|FORKID|CHRONICLE`, and a `ALL|FORKID|CHRONICLE` signature over the BIP143 digest (what bsv-rs 0.6.1's context signed) is refused as `SpendRefused { why: Script(_) }`.
- The 22 BRC-29 conformance vectors pass unchanged; no verdict moved.
- Breaking: the re-exported bsv-rs types (`Kind`, `Reason`, `AsyncByteSource`, `MiningCheck`, `SpendRefusal`) and `From<bsv_rs::Error>` now come from bsv-rs 0.7.0, a new compatibility line under cargo; a consumer moves bsv-rs and this crate together.

## [0.5.0] - 2026-10-15

- bsv-rs 0.6.0, declared by caret (`bsv-rs = "0.6.0"`), is the home of the varint: every BRC-104 payload length and status is written by `bsv_rs::primitives::to_var_int`. The payload bytes are unchanged for every value the transport writes.
- Breaking: `transport::write_varint` is removed; call `bsv_rs::primitives::to_var_int` (it takes a `u64`; the removed function wrote `[0]` for a negative value, which no payload field can be).
- Breaking: the re-exported bsv-rs types (`Kind`, `Reason`, `AsyncByteSource`, `MiningCheck`, `SpendRefusal`) and `From<bsv_rs::Error>` now come from bsv-rs 0.6.0, a new compatibility line under cargo; a consumer moves bsv-rs and this crate together.
- The stack's template `deny.toml` is adopted byte for byte: the crypto crates banned outside bsv-rs, advisories, licenses and sources, checked by `cargo deny check`.
- The tests' own varint helpers and one hand-written BUMP height use bsv-rs's `to_var_int` too.

## [0.4.4] - 2026-10-12

- State the flat-memory witness as a measured per-link band and equal-count body flatness, retaining the output-check and SDK-overhead checks.

- Preserve the SDK's missing mining context decline as `Unverifiable(MiningContextUnavailable)` with its offset, transaction, input and check. It is a server integration fault (503 at the Axum door), never invalid bytes or an accepted payment. The existing header adapter supplies no mining tip; non-final time locks and coinbase spends requiring that context fail closed.
- Replay all 22 canonical payment cases through Axum with synthetic issued-challenge fixtures, retaining their amounts, output order and header-answer classes.

- Declare `bsv-rs = "0.5.0"` by caret in the published libraries. The update loop can deliver compatible SDK patches to consumers without another library release; deployables keep their exact pins and committed locks.
- Resolve bsv-rs 0.5.0, including its streaming mining checks. Stored BEEF and old BSC1 cursors require the SDK's revalidation or restart rules; no stored-data migration is performed here.

## [Unreleased]

## [0.4.3] - 2026-10-12

The release of 0.4.2 never published (its release run failed on the heap-peak fixture that #9 fixed, and a `v*` tag cannot be deleted under the repository's rules); 0.4.3 is the same re-pin plus that test fix.

## [0.4.2] - 2026-10-12 (not published)

bsv-rs 0.4.5 (the lone leaf at offset 0 only; the LOCAL work bound inside one input's script); no behavior change under the defaults. The L2 re-pin of bsv-stack-lean item 2.

- bsv-rs 0.4.5: the lone leaf at offset 0 only; the LOCAL work bound; no behavior change under the defaults.

## [0.4.1] - 2026-10-09

- bsv-rs 0.4.1: a transaction with no input is invalid bytes. Under
  `verify_payment` an unproven one is now the reader's refusal,
  `Unverifiable(InvalidBeef { kind: NoInputs, .. })` at the transaction's
  leading byte, before the door's own `NoProof`, which stays beneath it.
  `verify_payment_output_only` reads a BEEF through the same reader and
  refuses the same bytes at the same offset, where 0.4.0 judged the output.
  No other behavior changes: the 22 vectors, `payment_limits` and the Axum
  tests are unchanged. The unit tests' synthetic roots take the coinbase's
  one input (the null outpoint); the one transaction with no input is built
  in the refusal test. (bsv-stack-lean #58, #59.)

## [0.4.0] - 2026-10-09

The payment door reads a BEEF of any size. The posture, as a rule: a valid
BEEF is never refused for its size or its counts; a refusal is for invalid
bytes only, and names them. It is the owner's ruling of 2026-10-09 and the
charter `docs/charters/beef-of-any-size.md` of the stack review repository
(bsv-stack-lean; this release is its lane NL-5). The limits 0.2.2 added
(P0-5d) and 0.3.0 carried were the fix of their hour; they refused valid
payments by a number, and they go.

### Removed (breaking)

- `MAX_PAYMENT_BYTES` (4 MiB), `MAX_PAYMENT_BEEF_TXS` (128),
  `MAX_PAYMENT_BEEF_BUMPS` (32) and `PAYMENT_BEEF_LIMITS`; the verifiers
  `verify_payment_with_limits` and `verify_payment_output_only_with_limits`
  (0.2.2's `verify_payment_output_with_limits` under its 0.3.0 names;
  `verify_payment_output` itself left in 0.3.0). The crate exports no bound.
- The reasons `PaymentTooLarge`, `BeefTransactionsExceeded` and
  `BeefBumpsExceeded` of `UnverifiableReason`: nothing is refused for a
  size or a count. `IncompleteBeef` and `OutputWithoutAmount` also go:
  the first is now the reader's own refusal, with its offset and kind;
  the second cannot arise from bytes.
- `PaymentToVerify::transaction`: the payment's bytes are a source handed to
  the verifier, not a slice held in the struct.

### Changed (breaking)

- `verify_payment(payment, transaction, header_service)` takes the payment
  as a byte source (`transaction: impl std::io::Read`; a slice is one:
  `&beef[..]`) and returns `std::io::Result<PaymentVerdict>`. It reads the
  source once through `verify_stream` of bsv-rs 0.4.0 and holds one element
  of the BEEF and the reader's index. `Err` is the source's failure: it says
  nothing about the payment and is never an acceptance. The six words of
  `PaymentVerdict` are unchanged.
- `verify_payment_output_only(payment, transaction)` takes the same source
  and returns `std::io::Result<PaymentVerdict>`; it cuts a BEEF into its
  elements as it reads and keeps no index. A raw transaction is read whole
  (it is one element).
- The order of checks of the full check: no header service; the BEEF's own
  validity by the streaming reader, at the soonest fault in stream order;
  the subject's output (`WrongScript`, then `Underpaid`); a proof exists;
  each root against the header service, lowest height first; `Verified`.
  0.3.0 judged the output before the BEEF's structure: a payment with both
  a wrong output and an invalid BEEF was `WrongScript` or `Underpaid` and is
  now `Unverifiable`. No header is asked before the output is judged, as
  before.
- The full check runs the scripts. An unproven transaction's inputs are
  executed against the parent outputs the BEEF carries, and a transaction
  may not create value: `Unverifiable(SpendRefused { .. })`. 0.3.0 checked
  the structure alone (`Beef::verify_valid`).
- An Atomic BEEF is held to the reader's rule: the subject is the last raw
  transaction and every other transaction is spent by a later one
  (`InvalidBeef` with `SubjectMissing` or `UnrelatedTransaction`). 0.3.0
  read past a retained descendant. The output-only check still reads the
  named subject wherever it is.
- An unproven transaction with no input is `Unverifiable(NoProof)` under
  the full check: the reader holds an unproven transaction by its inputs,
  and one with no input has nothing proven beneath it.
- A raw transaction under the full check is `InvalidBeef` (`BadVersion` at
  offset 0), where 0.3.0 judged its output and then answered `NoProof`.
- A source of fewer than four bytes, or one that does not lead with a BEEF
  version word, is read by the output-only check as a raw transaction; a
  source that leads with one is a BEEF and is refused as one.

### Added

- `UnverifiableReason::InvalidBeef { offset, kind, reason }`: the stream
  offset of the invalid byte and one of the streaming reader's eighteen
  kinds (`Kind`, `Reason`, re-exported from bsv-rs; the Lean definition
  `BeefOfAnySize`). `SpendRefused { offset, txid, input, why }`
  (`SpendRefusal`, re-exported). `NoTransaction` (a BEEF with no raw
  transaction). All three are on the payer's side (`is_server_side()` is
  false; 400 in the Axum layer). No reason is a size or a count.
- `verify_payment_async` and `verify_payment_output_only_async`: the same
  checks over an `AsyncByteSource` (the trait bsv-rs 0.4.0 ships,
  re-exported), for a request body or an object store's body stream, on
  `wasm32-unknown-unknown` as on native.
- `axum_layer`: the body transport. A request whose `x-bsv-payment` header
  names `derivationPrefix` and `derivationSuffix` and no `transaction` pays
  with its body, the BEEF's bytes as they are; the gate streams the body
  frame by frame through `verify_payment_async`, stops reading at the
  soonest invalid byte, and refuses nothing for its size. The challenge
  names both transports (`x-bsv-payment-transports: header,body`,
  `PAYMENT_TRANSPORTS`). The header transport is unchanged. The body
  transport is this crate's own: the reference middleware has the header
  alone. The gate keeps the bytes it read for the handler
  (`VerifiedPayment::transaction`), whose request body is then empty.

### Tests

- `tests/payment_limits.rs`: 0.2.2's boundary witnesses inverted (a valid
  payment over 4 MiB, of 129 and 1,000 transactions, of 33 and 200 BUMPs is
  `Verified`; a malformed one is refused with its offset and kind; the
  sources name no bound).
- `tests/payment_flat_memory.rs`: a payment of 100,000 unproven
  transactions under one proven parent, read from a source that writes
  itself: the output check's peak heap is the same at 1,000, 10,000 and
  100,000 links, and the full check's is the SDK reader's plus a constant.
- `tests/payment_deep_chain.rs`: the same readings, timed.
- The BRC-29 vectors: the canonical file at 22 cases (the two no-root cases
  of 2026-10-09), 22 exact; the runner holds each verdict to its HTTP class
  by the reason's side, and a payer-side reason carries no fields.

### Dependencies

- `bsv-rs` 0.4.0 (was 0.3.35): the streaming BEEF reader.

### Upgrade

- `verify_payment(&PaymentToVerify { transaction: &beef, .. }, headers).await`
  becomes `verify_payment(&PaymentToVerify { .. }, &beef[..], headers).await?`;
  the output-only check likewise. A host holding a body stream implements
  `AsyncByteSource` over it and calls `verify_payment_async`.
- Delete any use of the four constants and the `_with_limits` verifiers; a
  host that wants a transport budget sets it on its transport.
- A match on `UnverifiableReason` drops the five removed reasons; the enum
  is non-exhaustive, so the catch-all arm it already carries takes the new
  ones.
- 0.3.0 is not yanked.

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
  `cargo run --features axum --example axum_server`. The feature builds on
  its own (axum without default features, `json` named) and for
  `wasm32-unknown-unknown`.
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
