//! The BRC-29 payment-output rule: one verifier, six words, no runtime.
//!
//! This module is the API `bsv-middleware-core` is to provide (bsv-stack-lean
//! #50; epoch `NETWORK-ENFORCEMENT-RULES.md` Rule 27 at 2f4ef72). It names no
//! axum, tokio, reqwest or worker type and nothing else in this crate: it uses
//! `bsv-rs` (the streaming BEEF reader, keys), `async-trait` and `std` only,
//! so when the core crate is published the module is replaced by a re-export
//! of it and the Axum layer above (`crate::axum_layer`) is unchanged.
//!
//! The verdict is a word, never a boolean ([`PaymentVerdict`]); the header
//! service is a trait ([`HeaderService`]) passed as an `Option`, and `None` is
//! [`PaymentVerdict::NoHeaderService`] before any other check. The rule is
//! pinned by `tests/vectors/brc29-payment-vectors.json` (22 cases, a
//! byte-pinned copy of the canonical file the stack review repository owns),
//! run in `tests/conformance_brc29.rs`.
//!
//! # A payment of any size
//!
//! A valid payment is never refused for its size or its counts (the ruling
//! of 2026-10-09; bsv-stack-lean `docs/charters/beef-of-any-size.md`). The
//! payment is a byte source, read once through the streaming reader of bsv-rs
//! 0.4.0 ([`bsv_rs::transaction::verify_stream`]): one element of the BEEF in
//! hand and the reader's index, never the BEEF. A refusal of the bytes names
//! the offset and one of the reader's eighteen kinds
//! ([`UnverifiableReason::InvalidBeef`]), none of which is a size or a count.
//! This module carries no bound and exports none.
//!
//! Order of checks:
//! 1. a header service is configured, else `NoHeaderService`, before the
//!    source is read;
//! 2. the source is a valid BEEF (V1, V2 or Atomic) by the streaming reader:
//!    the frame, every BUMP's own root, every unproven transaction's inputs
//!    naming earlier transactions and spending them (the scripts run), the
//!    Atomic subject the tip of its ancestry; else `Unverifiable`, at the
//!    soonest fault in stream order;
//! 3. the subject (the Atomic BEEF's named transaction, else the last raw
//!    transaction) has output `output_index`, else `Unverifiable`; the
//!    output's script equals the expected BRC-29 script, else `WrongScript`;
//!    its satoshis are at least the price, else `Underpaid`;
//! 4. the BEEF carries a proof and every unproven transaction has an input
//!    (so every ancestry ends at a proven transaction), else `Unverifiable`;
//! 5. every merkle root the BUMPs compute, lowest height first, is the header
//!    service's root at that height (case-insensitive hex): a different root
//!    is `RootMismatch`, a lookup that cannot answer is `Unverifiable` (fail
//!    closed; a mismatch at any height still wins over an outage at another);
//! 6. `Verified { satoshis }`, the amount read from the output.
//!
//! The roots are asked after the output is judged (no header is asked for a
//! payment the output already refuses), so the reader runs with every root
//! granted and step 5 is where a root is held to a header: nothing is
//! `Verified` with a root unchecked.

use async_trait::async_trait;
use bsv_rs::primitives::PublicKey;
use bsv_rs::transaction::beef_stream::{display_hex, Hash32, Step, TxBody};
use bsv_rs::transaction::{
    verify_stream, verify_stream_async, AlwaysValidChainTracker, BeefDecoder, Element, Refusal,
    Transaction, Verdict, ATOMIC_BEEF, BEEF_V1, BEEF_V2,
};
use bsv_rs::wallet::{Counterparty, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel};
use std::io::Read;

pub use bsv_rs::transaction::beef_stream::SpendRefusal;
pub use bsv_rs::transaction::{AsyncByteSource, Kind, Reason};

/// The BRC-29 payment protocol name (security level 2), the protocol the
/// payer derives the paying key under.
pub const BRC29_PROTOCOL_NAME: &str = "3241645161d8";

/// The bytes read from a source at a time by the output-only check.
const CHUNK: usize = 16 * 1024;

/// What a payment verifier answers: six words, never a boolean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentVerdict {
    /// Accept: the output pays the derived key at least the price and every
    /// merkle root is a block header's. `satoshis` is the amount read from
    /// the output, which may exceed the price.
    Verified {
        /// Satoshis in the paying output.
        satoshis: u64,
    },
    /// Refuse: the output pays the derived key less than the price.
    Underpaid {
        /// Satoshis in the paying output.
        paid: u64,
        /// The price.
        required: u64,
    },
    /// Refuse: the output is not locked to the expected BRC-29 script.
    WrongScript {
        /// The script the server derived.
        expected: Vec<u8>,
        /// The script the output carries.
        actual: Vec<u8>,
    },
    /// Refuse: no header service is configured. A server fault (5xx), never a
    /// client error; checked before anything else.
    NoHeaderService,
    /// Refuse: the header at `height` carries a different merkle root than the
    /// proof computes. A fraud signal.
    RootMismatch {
        /// The proof's block height.
        height: u32,
        /// The root the proof computes (not the header service's).
        merkle_root: String,
    },
    /// Refuse: the payment cannot be verified; the reason says whose fault.
    Unverifiable(UnverifiableReason),
}

/// Why a payment is [`PaymentVerdict::Unverifiable`].
///
/// No reason is a size or a count: a payment is refused for what its bytes
/// say, never for how many they are.
///
/// Non-exhaustive: a reason may be added in a minor release, so a match on
/// it carries a catch-all arm. The six words of [`PaymentVerdict`] are the
/// contract and stay exhaustive.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnverifiableReason {
    /// The BEEF's bytes are invalid: the offset of the byte and one of the
    /// streaming reader's eighteen kinds (bsv-rs 0.4.0, the Lean definition
    /// `BeefOfAnySize`). The reading stopped there.
    InvalidBeef {
        /// The stream offset of the byte the refusal names.
        offset: u64,
        /// The kind.
        kind: Kind,
        /// The kind with its data.
        reason: Reason,
    },
    /// The BEEF's bytes are well formed up to `offset` and the script
    /// interpreter refused a spend of an unproven transaction.
    SpendRefused {
        /// The offset of the input (or of the transaction, for the value
        /// rule).
        offset: u64,
        /// The spending transaction (display hex).
        txid: String,
        /// The input, when one input is named.
        input: Option<u32>,
        /// Why.
        why: SpendRefusal,
    },
    /// The bytes are not a BEEF and not a raw transaction (the output-only
    /// check, which reads a raw transaction).
    MalformedTransaction(String),
    /// The BEEF carries no raw transaction: nothing pays.
    NoTransaction,
    /// The subject transaction has no output at the index that is paid.
    OutputMissing {
        /// The index the payment names.
        output_index: u32,
        /// How many outputs the transaction has.
        output_count: usize,
    },
    /// The derivation inputs do not name a key (the sender identity is not a
    /// public key).
    KeyDerivation(String),
    /// The BEEF is valid and gives no root to check: it carries no BUMP, or
    /// an unproven transaction has no input, so nothing beneath it is proven.
    NoProof,
    /// The header service could not answer for `height` (outage, timeout,
    /// height not indexed). The server's side, not the payer's.
    HeaderLookupFailed {
        /// The height asked for.
        height: u32,
        /// What the service said.
        reason: String,
    },
}

impl UnverifiableReason {
    /// True when the server, not the payment, is why it cannot be verified.
    pub fn is_server_side(&self) -> bool {
        matches!(self, Self::HeaderLookupFailed { .. })
    }

    fn invalid(refusal: Refusal) -> Self {
        Self::InvalidBeef {
            offset: refusal.offset,
            kind: refusal.reason.kind(),
            reason: refusal.reason,
        }
    }
}

impl PaymentVerdict {
    /// True only for [`PaymentVerdict::Verified`].
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }
}

impl std::fmt::Display for PaymentVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verified { satoshis } => write!(f, "payment verified: {} satoshis", satoshis),
            Self::Underpaid { paid, required } => write!(
                f,
                "payment output carries {} satoshis, {} required",
                paid, required
            ),
            Self::WrongScript { .. } => {
                write!(f, "payment output is not locked to the server's BRC-29 key")
            }
            Self::NoHeaderService => write!(f, "no header service is configured"),
            Self::RootMismatch {
                height,
                merkle_root,
            } => write!(
                f,
                "merkle root {} does not match the block header at height {}",
                merkle_root, height
            ),
            Self::Unverifiable(reason) => write!(f, "payment cannot be verified: {}", reason),
        }
    }
}

impl std::fmt::Display for UnverifiableReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBeef { offset, kind, .. } => {
                write!(f, "BEEF is invalid at offset {}: {:?}", offset, kind)
            }
            Self::SpendRefused {
                offset,
                txid,
                input,
                why,
            } => {
                write!(f, "transaction {} at offset {} ", txid, offset)?;
                if let Some(input) = input {
                    write!(f, "input {} ", input)?;
                }
                write!(f, "does not spend: {:?}", why)
            }
            Self::MalformedTransaction(e) => write!(f, "transaction is malformed: {}", e),
            Self::NoTransaction => write!(f, "BEEF carries no raw transaction"),
            Self::OutputMissing {
                output_index,
                output_count,
            } => write!(
                f,
                "output {} is missing (transaction has {} outputs)",
                output_index, output_count
            ),
            Self::KeyDerivation(e) => write!(f, "key derivation failed: {}", e),
            Self::NoProof => write!(
                f,
                "BEEF gives no merkle root to check (no BUMP, or an unproven transaction with no input)"
            ),
            Self::HeaderLookupFailed { height, reason } => {
                write!(
                    f,
                    "header service could not answer at height {}: {}",
                    height, reason
                )
            }
        }
    }
}

/// The header service could not answer (outage, timeout, height not indexed,
/// unreadable reply).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderLookupError(pub String);

/// A source of block headers: the merkle root of the block at a height.
///
/// The verifier compares the answer with the proof's root, so the comparison
/// rules (case-insensitive hex; a different root is fraud, no answer is not)
/// live in one place and an implementation only fetches.
#[async_trait]
pub trait HeaderService: Send + Sync {
    /// The merkle root (hex) of the block at `height`, or why it cannot say.
    async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError>;
}

/// One payment to verify: the output that is paid, the script it must carry
/// ([`brc29_locking_script`]) and the price. The transaction is the byte
/// source handed to the verifier beside it.
#[derive(Debug, Clone, Copy)]
pub struct PaymentToVerify<'a> {
    /// The output that is internalized (the reference uses 0).
    pub output_index: u32,
    /// The P2PKH script the server derived for this payment.
    pub expected_script: &'a [u8],
    /// The price in satoshis.
    pub required_satoshis: u64,
}

/// The P2PKH locking script a BRC-29 payment to `wallet` must carry.
///
/// The recipient's side of the derivation: protocol `[2, "3241645161d8"]`,
/// key ID `"<prefix> <suffix>"`, counterparty the sender, for self. The payer
/// derives the same public key for the counterparty `wallet` (BRC-42).
pub fn brc29_locking_script(
    wallet: &ProtoWallet,
    derivation_prefix: &str,
    derivation_suffix: &str,
    sender_identity_key: &str,
) -> Result<Vec<u8>, UnverifiableReason> {
    let derivation = |e: bsv_rs::Error| UnverifiableReason::KeyDerivation(e.to_string());
    let sender = PublicKey::from_hex(sender_identity_key).map_err(derivation)?;
    let derived = wallet
        .get_public_key(GetPublicKeyArgs {
            identity_key: false,
            protocol_id: Some(Protocol::new(
                SecurityLevel::Counterparty,
                BRC29_PROTOCOL_NAME,
            )),
            key_id: Some(format!("{} {}", derivation_prefix, derivation_suffix)),
            counterparty: Some(Counterparty::Other(sender)),
            for_self: Some(true),
        })
        .map_err(derivation)?;
    let hash = PublicKey::from_hex(&derived.public_key)
        .map_err(derivation)?
        .hash160();
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[0x76, 0xa9, 0x14]);
    script.extend_from_slice(&hash);
    script.extend_from_slice(&[0x88, 0xac]);
    Ok(script)
}

/// The full check of a payment read from `transaction`: header service, the
/// BEEF by the streaming reader, the output, the merkle roots.
///
/// `transaction` is any [`Read`] positioned at the BEEF's leading byte: a
/// slice (`&bytes[..]`), a file, a decoder over a transport. It is read once,
/// through [`verify_stream`]; the verifier holds one element of the BEEF and
/// the reader's index, and refuses nothing for its size or its counts. For a
/// body that arrives in chunks use [`verify_payment_async`].
///
/// `header_service` is `None` when the deployment has none: the answer is
/// [`PaymentVerdict::NoHeaderService`] before the source is read.
///
/// The source is read inside this future, before the first header is asked:
/// a `Read` that blocks holds the task while it does.
///
/// `Err` is the source's failure. It says nothing about the payment and is
/// never an acceptance.
pub async fn verify_payment<R: Read>(
    payment: &PaymentToVerify<'_>,
    transaction: R,
    header_service: Option<&dyn HeaderService>,
) -> std::io::Result<PaymentVerdict> {
    let Some(headers) = header_service else {
        return Ok(PaymentVerdict::NoHeaderService);
    };
    let mut tap = Tap::new(payment);
    let source = Tee {
        source: transaction,
        tap: &mut tap,
    };
    let verdict = verify_stream(source, RootsAskedAfter, None)?;
    Ok(tap.conclude(verdict, headers).await)
}

/// [`verify_payment`] over a source that yields its chunks asynchronously
/// ([`AsyncByteSource`], the trait bsv-rs 0.4.0 ships): a request body, an
/// object store's body stream. The same order of checks and the same
/// verdicts, through [`verify_stream_async`].
pub async fn verify_payment_async<S: AsyncByteSource>(
    payment: &PaymentToVerify<'_>,
    transaction: &mut S,
    header_service: Option<&dyn HeaderService>,
) -> std::io::Result<PaymentVerdict> {
    let Some(headers) = header_service else {
        return Ok(PaymentVerdict::NoHeaderService);
    };
    let mut tap = Tap::new(payment);
    let mut source = AsyncTee {
        source: transaction,
        tap: &mut tap,
    };
    let granted = AlwaysValidChainTracker::new(0);
    let verdict = verify_stream_async(&mut source, &granted, None)
        .await
        .map_err(|e| match e {
            bsv_rs::transaction::beef_stream::AsyncVerifyError::Source(e) => e,
            other => std::io::Error::other(other.to_string()),
        })?;
    Ok(tap.conclude(verdict, headers).await)
}

/// The output check alone: no header service, no BEEF structure, no spends,
/// no merkle roots. Opted into by name (Rule 27) by a host whose next step
/// checks the transaction itself (a storage that verifies the BEEF before it
/// records it); it never answers `NoHeaderService` or `RootMismatch`.
///
/// A BEEF is cut into its elements as it is read, one in hand and no index;
/// its frame must be whole, and the subject is the Atomic BEEF's named
/// transaction, else the last raw transaction. A source that does not lead
/// with a BEEF version word is read to its end as one raw transaction.
/// Nothing is refused for its size or its counts.
///
/// `Err` is the source's failure and says nothing about the payment.
pub fn verify_payment_output_only<R: Read>(
    payment: &PaymentToVerify<'_>,
    mut transaction: R,
) -> std::io::Result<PaymentVerdict> {
    let mut read = |buf: &mut [u8]| loop {
        match transaction.read(buf) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            other => return other,
        }
    };
    let mut lead = [0u8; 4];
    let mut have = 0;
    while have < lead.len() {
        match read(&mut lead[have..])? {
            0 => break,
            n => have += n,
        }
    }
    let mut chunk = vec![0u8; CHUNK].into_boxed_slice();
    if !leads_with_beef(&lead[..have]) {
        let mut raw = lead[..have].to_vec();
        loop {
            match read(&mut chunk)? {
                0 => return Ok(raw_transaction_output(payment, &raw)),
                n => raw.extend_from_slice(&chunk[..n]),
            }
        }
    }
    let mut tap = Tap::new(payment);
    tap.feed(&lead);
    while tap.refusal.is_none() {
        match read(&mut chunk)? {
            0 => break,
            n => tap.feed(&chunk[..n]),
        }
    }
    Ok(tap.output_only())
}

/// [`verify_payment_output_only`] over an [`AsyncByteSource`].
pub async fn verify_payment_output_only_async<S: AsyncByteSource>(
    payment: &PaymentToVerify<'_>,
    transaction: &mut S,
) -> std::io::Result<PaymentVerdict> {
    let mut lead = Vec::new();
    let mut ended = false;
    while lead.len() < 4 && !ended {
        match transaction.next_chunk().await? {
            Some(chunk) => lead.extend_from_slice(&chunk),
            None => ended = true,
        }
    }
    if !leads_with_beef(&lead) {
        while let Some(chunk) = transaction.next_chunk().await? {
            lead.extend_from_slice(&chunk);
        }
        return Ok(raw_transaction_output(payment, &lead));
    }
    let mut tap = Tap::new(payment);
    tap.feed(&lead);
    drop(lead);
    while tap.refusal.is_none() {
        match transaction.next_chunk().await? {
            Some(chunk) => tap.feed(&chunk),
            None => break,
        }
    }
    Ok(tap.output_only())
}

/// The bytes lead with a BEEF version word (V1, V2 or the Atomic prefix).
fn leads_with_beef(lead: &[u8]) -> bool {
    matches!(
        lead.get(..4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
        Some(ATOMIC_BEEF | BEEF_V1 | BEEF_V2)
    )
}

/// The reader's headers while the BEEF streams: every root is granted here
/// and held to the header service afterwards, lowest height first, once the
/// output is judged ([`Tap::conclude`]). The reader's verdict hands the roots
/// back; none is accepted unasked.
struct RootsAskedAfter;

impl bsv_rs::transaction::Headers for RootsAskedAfter {
    fn carries(&self, _height: u64, _root: &Hash32) -> bool {
        true
    }
}

/// What the door notes of the bytes as they pass to the reader: the subject's
/// output, judged. One element in hand, nothing kept of the others.
struct Tap<'p> {
    payment: &'p PaymentToVerify<'p>,
    decoder: BeefDecoder,
    /// The frame's own fault, where the cutting stopped.
    refusal: Option<Refusal>,
    /// The output check of the subject: the Atomic BEEF's named transaction,
    /// else the last raw transaction read so far.
    paid: Option<Result<u64, PaymentVerdict>>,
    /// An unproven transaction with no input was read: nothing beneath it is
    /// proven, and the reader's structure rule has no input to hold it by.
    unanchored: bool,
    /// A BUMP claims a height no header service can be asked for.
    beyond_headers: Option<Refusal>,
}

impl<'p> Tap<'p> {
    fn new(payment: &'p PaymentToVerify<'p>) -> Self {
        Self {
            payment,
            decoder: BeefDecoder::new(),
            refusal: None,
            paid: None,
            unanchored: false,
            beyond_headers: None,
        }
    }

    /// The next bytes of the source.
    fn feed(&mut self, mut input: &[u8]) {
        if self.refusal.is_some() {
            return;
        }
        loop {
            match self.decoder.next(&mut input) {
                Ok(Step::Element(element)) => self.note(&element),
                Ok(Step::NeedMore | Step::Done) => return,
                Err(refusal) => {
                    self.refusal = Some(refusal);
                    return;
                }
            }
        }
    }

    fn note(&mut self, element: &Element) {
        match element {
            Element::Bump(bump) => {
                if bump.block_height > u64::from(u32::MAX) && self.beyond_headers.is_none() {
                    self.beyond_headers = Some(Refusal {
                        offset: bump.offset,
                        reason: Reason::RootNotCarried {
                            height: bump.block_height,
                            root: bump.root,
                        },
                    });
                }
            }
            Element::Tx {
                txid,
                bump_index,
                body,
                ..
            } => {
                if bump_index.is_none() && body.inputs.is_empty() {
                    self.unanchored = true;
                }
                let subject = match self.decoder.subject() {
                    Some(named) => named == *txid && self.paid.is_none(),
                    None => true,
                };
                if subject {
                    self.paid = Some(streamed_output(self.payment, body));
                }
            }
            Element::TxidOnly { .. } => {}
        }
    }

    /// The six words over the reader's verdict.
    async fn conclude(self, verdict: Verdict, headers: &dyn HeaderService) -> PaymentVerdict {
        let Tap {
            paid,
            unanchored,
            beyond_headers,
            ..
        } = self;
        let roots = match verdict {
            Verdict::Valid { roots, .. } => roots,
            Verdict::Invalid {
                offset,
                kind,
                reason,
            } => {
                return PaymentVerdict::Unverifiable(UnverifiableReason::InvalidBeef {
                    offset,
                    kind,
                    reason,
                })
            }
            Verdict::SpendRefused {
                offset,
                txid,
                input,
                why,
            } => {
                return PaymentVerdict::Unverifiable(UnverifiableReason::SpendRefused {
                    offset,
                    txid: display_hex(&txid),
                    input,
                    why,
                })
            }
        };
        let satoshis = match paid {
            None => return PaymentVerdict::Unverifiable(UnverifiableReason::NoTransaction),
            Some(Err(verdict)) => return verdict,
            Some(Ok(satoshis)) => satoshis,
        };
        if unanchored || roots.is_empty() {
            return PaymentVerdict::Unverifiable(UnverifiableReason::NoProof);
        }
        if let Some(refusal) = beyond_headers {
            return PaymentVerdict::Unverifiable(UnverifiableReason::invalid(refusal));
        }
        // Each distinct root once, lowest height first. Two BUMPs that claim
        // one height with two roots are two questions, and one is a mismatch.
        let mut roots: Vec<(u32, String)> = roots
            .iter()
            .map(|(height, root)| (*height as u32, display_hex(root)))
            .collect();
        roots.sort_unstable();
        roots.dedup();
        let mut first_failure = None;
        for (height, root) in roots {
            match headers.merkle_root_at(height).await {
                Ok(header_root) if header_root.eq_ignore_ascii_case(&root) => {}
                Ok(_) => {
                    return PaymentVerdict::RootMismatch {
                        height,
                        merkle_root: root,
                    }
                }
                Err(HeaderLookupError(reason)) => {
                    first_failure
                        .get_or_insert(UnverifiableReason::HeaderLookupFailed { height, reason });
                }
            }
        }
        match first_failure {
            Some(reason) => PaymentVerdict::Unverifiable(reason),
            None => PaymentVerdict::Verified { satoshis },
        }
    }

    /// The output check alone, at the source's end: the frame was whole and
    /// the subject's output pays.
    fn output_only(mut self) -> PaymentVerdict {
        let refusal = match self.refusal.take() {
            Some(refusal) => Some(refusal),
            None => self.decoder.finish().err(),
        };
        if let Some(refusal) = refusal {
            return PaymentVerdict::Unverifiable(UnverifiableReason::invalid(refusal));
        }
        match (self.paid, self.decoder.subject()) {
            (Some(Ok(satoshis)), _) => PaymentVerdict::Verified { satoshis },
            (Some(Err(verdict)), _) => verdict,
            // The reader's own word for an Atomic subject the BEEF does not
            // carry, at the prefix's 32 bytes.
            (None, Some(subject)) => {
                PaymentVerdict::Unverifiable(UnverifiableReason::invalid(Refusal {
                    offset: 4,
                    reason: Reason::SubjectMissing { subject },
                }))
            }
            (None, None) => PaymentVerdict::Unverifiable(UnverifiableReason::NoTransaction),
        }
    }
}

/// The source, with each chunk the reader takes shown to the tap.
struct Tee<'t, 'p, R> {
    source: R,
    tap: &'t mut Tap<'p>,
}

impl<R: Read> Read for Tee<'_, '_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.source.read(buf)?;
        self.tap.feed(&buf[..n]);
        Ok(n)
    }
}

/// [`Tee`] over an asynchronous source.
struct AsyncTee<'t, 'p, S> {
    source: &'t mut S,
    tap: &'t mut Tap<'p>,
}

impl<S: AsyncByteSource> AsyncByteSource for AsyncTee<'_, '_, S> {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let chunk = self.source.next_chunk().await?;
        if let Some(chunk) = &chunk {
            self.tap.feed(chunk);
        }
        Ok(chunk)
    }
}

/// The output check of a transaction the stream yielded.
fn streamed_output(payment: &PaymentToVerify<'_>, body: &TxBody) -> Result<u64, PaymentVerdict> {
    let output = body.outputs.get(payment.output_index as usize);
    check_output(
        payment,
        body.outputs.len(),
        output.map(|o| (o.satoshis, &body.raw[o.script.clone()])),
    )
}

/// The output check of a raw transaction, read whole (one element).
fn raw_transaction_output(payment: &PaymentToVerify<'_>, raw: &[u8]) -> PaymentVerdict {
    let malformed =
        |e: String| PaymentVerdict::Unverifiable(UnverifiableReason::MalformedTransaction(e));
    let transaction = match Transaction::from_binary(raw) {
        Ok(transaction) => transaction,
        Err(e) => return malformed(e.to_string()),
    };
    let output = match transaction.outputs.get(payment.output_index as usize) {
        None => None,
        Some(output) => match output.satoshis {
            Some(satoshis) => Some((satoshis, output.locking_script.to_binary())),
            None => return malformed("output carries no amount".to_string()),
        },
    };
    let checked = check_output(
        payment,
        transaction.outputs.len(),
        output
            .as_ref()
            .map(|(satoshis, script)| (*satoshis, &script[..])),
    );
    match checked {
        Ok(satoshis) => PaymentVerdict::Verified { satoshis },
        Err(verdict) => verdict,
    }
}

/// Script first, then amount; the satoshis on success.
fn check_output(
    payment: &PaymentToVerify<'_>,
    output_count: usize,
    output: Option<(u64, &[u8])>,
) -> Result<u64, PaymentVerdict> {
    let (paid, actual) = output.ok_or(PaymentVerdict::Unverifiable(
        UnverifiableReason::OutputMissing {
            output_index: payment.output_index,
            output_count,
        },
    ))?;
    if actual != payment.expected_script {
        return Err(PaymentVerdict::WrongScript {
            expected: payment.expected_script.to_vec(),
            actual: actual.to_vec(),
        });
    }
    if paid < payment.required_satoshis {
        return Err(PaymentVerdict::Underpaid {
            paid,
            required: payment.required_satoshis,
        });
    }
    Ok(paid)
}

/// The base URL of a configured header service, or `None` when the value
/// names none: unset, blank, the reserved `.invalid` TLD in any spelling, or
/// a value whose host cannot be classified without decoding.
///
/// For a [`HeaderService`] built from a configured URL: `None` here means the
/// host passes `None` to [`verify_payment`] and gets `NoHeaderService`. Ported
/// from `bsv-middleware-cloudflare@dabfb78 src/payment_verify.rs:204-287`
/// (`header_service_host`, `resolve_header_service`); trims surrounding
/// whitespace and trailing slashes, then requires an `http`/`https` scheme, an
/// ASCII authority with no userinfo (`@`) or percent-encoding, no backslash,
/// whitespace or control character anywhere, a host that is a bracketed IPv6
/// literal or dot-separated hostname labels (one optional trailing dot), and
/// an optional decimal port that fits 16 bits. The host is lowercased and its
/// trailing dot stripped before the `.invalid` test.
pub fn header_service_url(configured: Option<&str>) -> Option<&str> {
    let base = configured
        .map(str::trim)
        .unwrap_or("")
        .trim_end_matches('/');
    if base.is_empty() {
        return None;
    }
    let host = header_service_host(base)?;
    if host == "invalid" || host.ends_with(".invalid") {
        return None;
    }
    Some(base)
}

fn header_service_host(base: &str) -> Option<String> {
    if base
        .chars()
        .any(|c| c == '\\' || c.is_whitespace() || c.is_control())
    {
        return None;
    }
    let (scheme, rest) = base.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || !authority.is_ascii() || authority.contains(['@', '%']) {
        return None;
    }
    let (host, port_suffix) = match authority.strip_prefix('[') {
        Some(after_bracket) => {
            let (literal, after) = after_bracket.split_once(']')?;
            literal.parse::<std::net::Ipv6Addr>().ok()?;
            (literal, after)
        }
        None => authority.split_at(authority.find(':').unwrap_or(authority.len())),
    };
    match port_suffix.strip_prefix(':') {
        Some(port) => {
            if port.is_empty()
                || !port.bytes().all(|b| b.is_ascii_digit())
                || port.parse::<u16>().is_err()
            {
                return None;
            }
        }
        None if port_suffix.is_empty() => {}
        None => return None,
    }
    let host = host.to_ascii_lowercase();
    if authority.starts_with('[') {
        return Some(host);
    }
    let name = host.strip_suffix('.').unwrap_or(&host);
    let label_ok = |label: &str| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if name.is_empty() || !name.split('.').all(label_ok) {
        return None;
    }
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_rs::primitives::PrivateKey;
    use bsv_rs::script::LockingScript;
    use bsv_rs::transaction::{
        Beef, MerklePath, MerklePathLeaf, TransactionInput, TransactionOutput,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;

    const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const SENDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const PREFIX: &str = "cHJlZml4LW5vbmNlLTAwMDAwMDAwMDAwMDAwMDA=";
    const SUFFIX: &str = "c3VmZml4";
    const PRICE: u64 = 100;
    const HEIGHT: u32 = 850_000;

    fn wallet(hex: &str) -> ProtoWallet {
        ProtoWallet::new(Some(PrivateKey::from_hex(hex).unwrap()))
    }

    fn p2pkh(hash: &[u8; 20]) -> Vec<u8> {
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(hash);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    }

    /// The payer's side of BRC-29, independent of `brc29_locking_script`.
    fn payer_script() -> Vec<u8> {
        let derived = wallet(SENDER_KEY)
            .get_public_key(GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(Protocol::new(
                    SecurityLevel::Counterparty,
                    BRC29_PROTOCOL_NAME,
                )),
                key_id: Some(format!("{} {}", PREFIX, SUFFIX)),
                counterparty: Some(Counterparty::Other(wallet(SERVER_KEY).identity_key())),
                for_self: Some(false),
            })
            .unwrap();
        p2pkh(&PublicKey::from_hex(&derived.public_key).unwrap().hash160())
    }

    fn server_script() -> Vec<u8> {
        let sender = wallet(SENDER_KEY).identity_key().to_hex();
        brc29_locking_script(&wallet(SERVER_KEY), PREFIX, SUFFIX, &sender).unwrap()
    }

    /// A crafted payment spending a crafted, unproven parent. Never signed,
    /// never broadcast.
    fn unproven_tx(outputs: &[(u64, Vec<u8>)]) -> Transaction {
        let mut parent = Transaction::new();
        parent
            .add_output(TransactionOutput::new(
                10_000,
                LockingScript::from_binary(&p2pkh(&[7u8; 20])).unwrap(),
            ))
            .unwrap();
        let mut tx = Transaction::new();
        tx.add_input(TransactionInput::with_source_transaction(parent, 0))
            .unwrap();
        for (satoshis, script) in outputs {
            tx.add_output(TransactionOutput::new(
                *satoshis,
                LockingScript::from_binary(script).unwrap(),
            ))
            .unwrap();
        }
        tx
    }

    /// A BEEF of one payment proven by a one-leaf BUMP at `HEIGHT` (a block of
    /// one transaction: the root is the txid). Returns the BEEF and the root.
    fn proven_beef(outputs: &[(u64, Vec<u8>)]) -> (Vec<u8>, String) {
        let mut tx = Transaction::new();
        tx.add_input(TransactionInput {
            source_txid: Some("11".repeat(32)),
            source_output_index: 0,
            ..Default::default()
        })
        .unwrap();
        for (satoshis, script) in outputs {
            tx.add_output(TransactionOutput::new(
                *satoshis,
                LockingScript::from_binary(script).unwrap(),
            ))
            .unwrap();
        }
        let txid = tx.id();
        let bump = MerklePath::new(
            HEIGHT,
            vec![vec![MerklePathLeaf::new_txid(0, txid.clone())]],
        )
        .unwrap();
        let mut beef = Beef::new();
        beef.merge_bump(bump);
        beef.merge_transaction(tx);
        (beef.to_binary(), txid)
    }

    /// A header service answering from a table; records the heights asked.
    struct StubHeaders {
        answers: HashMap<u32, Result<String, HeaderLookupError>>,
        asked: Mutex<Vec<u32>>,
    }

    impl StubHeaders {
        fn answering(height: u32, answer: Result<String, HeaderLookupError>) -> Self {
            Self {
                answers: HashMap::from([(height, answer)]),
                asked: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl HeaderService for StubHeaders {
        async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError> {
            self.asked.lock().unwrap().push(height);
            self.answers
                .get(&height)
                .cloned()
                .unwrap_or_else(|| Err(HeaderLookupError("height not indexed".into())))
        }
    }

    fn payment(index: u32, script: &[u8]) -> PaymentToVerify<'_> {
        PaymentToVerify {
            output_index: index,
            expected_script: script,
            required_satoshis: PRICE,
        }
    }

    fn output_only(tx: &[u8], index: u32) -> PaymentVerdict {
        verify_payment_output_only(&payment(index, &server_script()), tx).unwrap()
    }

    // ---- the output check (P0-3's ten cases, now in words) ----

    #[test]
    fn brc29_script_matches_the_payers_derivation() {
        assert_eq!(server_script(), payer_script());
    }

    #[test]
    fn exact_price_is_verified_with_the_amount_read() {
        let tx = unproven_tx(&[(PRICE, payer_script())])
            .to_atomic_beef(true)
            .unwrap();
        assert_eq!(
            output_only(&tx, 0),
            PaymentVerdict::Verified { satoshis: PRICE }
        );
    }

    #[test]
    fn one_satoshi_under_is_underpaid() {
        let tx = unproven_tx(&[(PRICE - 1, payer_script())])
            .to_atomic_beef(true)
            .unwrap();
        assert_eq!(
            output_only(&tx, 0),
            PaymentVerdict::Underpaid {
                paid: PRICE - 1,
                required: PRICE
            }
        );
    }

    #[test]
    fn one_satoshi_over_is_verified_with_the_real_amount() {
        let tx = unproven_tx(&[(PRICE + 1, payer_script())])
            .to_atomic_beef(true)
            .unwrap();
        assert_eq!(
            output_only(&tx, 0),
            PaymentVerdict::Verified {
                satoshis: PRICE + 1
            }
        );
    }

    #[test]
    fn another_script_is_wrong_script_and_carries_both() {
        let tx = unproven_tx(&[(PRICE, p2pkh(&[9u8; 20]))])
            .to_atomic_beef(true)
            .unwrap();
        assert_eq!(
            output_only(&tx, 0),
            PaymentVerdict::WrongScript {
                expected: server_script(),
                actual: p2pkh(&[9u8; 20])
            }
        );
    }

    #[test]
    fn the_derived_output_at_another_index_does_not_pay_the_named_one() {
        let tx = unproven_tx(&[(PRICE, p2pkh(&[9u8; 20])), (PRICE, payer_script())])
            .to_atomic_beef(true)
            .unwrap();
        assert!(matches!(
            output_only(&tx, 0),
            PaymentVerdict::WrongScript { .. }
        ));
        assert_eq!(
            output_only(&tx, 1),
            PaymentVerdict::Verified { satoshis: PRICE }
        );
    }

    #[test]
    fn a_missing_output_is_unverifiable() {
        let tx = unproven_tx(&[(PRICE, payer_script())])
            .to_atomic_beef(true)
            .unwrap();
        assert_eq!(
            output_only(&tx, 1),
            PaymentVerdict::Unverifiable(UnverifiableReason::OutputMissing {
                output_index: 1,
                output_count: 1
            })
        );
    }

    #[test]
    fn malformed_bytes_are_unverifiable() {
        // No BEEF version word leads: read as a raw transaction, and it is none.
        for bytes in [&b"not a transaction"[..], &[], &[1, 1, 1]] {
            assert!(matches!(
                output_only(bytes, 0),
                PaymentVerdict::Unverifiable(UnverifiableReason::MalformedTransaction(_))
            ));
        }
        // The Atomic prefix leads and the 32 bytes of its subject are cut
        // short: the reader names the field and where it starts.
        assert_eq!(
            output_only(&[1, 1, 1, 1, 0xff], 0),
            PaymentVerdict::Unverifiable(UnverifiableReason::InvalidBeef {
                offset: 4,
                kind: Kind::Truncated,
                reason: Reason::Truncated { needed: 32 },
            })
        );
    }

    #[test]
    fn raw_plain_and_atomic_beef_are_read_alike_by_the_output_check() {
        let tx = unproven_tx(&[(PRICE - 1, payer_script())]);
        let underpaid = PaymentVerdict::Underpaid {
            paid: PRICE - 1,
            required: PRICE,
        };
        assert_eq!(output_only(&tx.to_binary(), 0), underpaid);
        assert_eq!(output_only(&tx.to_beef(true).unwrap(), 0), underpaid);
        assert_eq!(output_only(&tx.to_atomic_beef(true).unwrap(), 0), underpaid);
    }

    #[test]
    fn a_bad_sender_key_is_a_derivation_failure() {
        assert!(matches!(
            brc29_locking_script(&wallet(SERVER_KEY), PREFIX, SUFFIX, "02zz"),
            Err(UnverifiableReason::KeyDerivation(_))
        ));
    }

    // ---- the header service and the merkle roots ----

    #[tokio::test]
    async fn no_header_service_is_refused_before_the_payment_is_read() {
        let script = server_script();
        for bytes in [&b"garbage"[..], &proven_beef(&[(PRICE, payer_script())]).0] {
            assert_eq!(
                verify_payment(&payment(0, &script), bytes, None)
                    .await
                    .unwrap(),
                PaymentVerdict::NoHeaderService
            );
        }
    }

    #[tokio::test]
    async fn matching_root_in_either_case_is_verified() {
        let (beef, root) = proven_beef(&[(PRICE + 5, payer_script())]);
        for answer in [root.clone(), root.to_uppercase()] {
            let headers = StubHeaders::answering(HEIGHT, Ok(answer));
            assert_eq!(
                verify_payment(&payment(0, &server_script()), &beef[..], Some(&headers))
                    .await
                    .unwrap(),
                PaymentVerdict::Verified {
                    satoshis: PRICE + 5
                }
            );
            assert_eq!(*headers.asked.lock().unwrap(), vec![HEIGHT]);
        }
    }

    #[tokio::test]
    async fn another_root_is_root_mismatch_carrying_the_proofs_root() {
        let (beef, root) = proven_beef(&[(PRICE, payer_script())]);
        let headers = StubHeaders::answering(HEIGHT, Ok("00".repeat(32)));
        assert_eq!(
            verify_payment(&payment(0, &server_script()), &beef[..], Some(&headers))
                .await
                .unwrap(),
            PaymentVerdict::RootMismatch {
                height: HEIGHT,
                merkle_root: root
            }
        );
    }

    #[tokio::test]
    async fn a_lookup_that_cannot_answer_fails_closed_on_the_servers_side() {
        let (beef, _) = proven_beef(&[(PRICE, payer_script())]);
        let headers = StubHeaders::answering(HEIGHT, Err(HeaderLookupError("HTTP 503".into())));
        let verdict = verify_payment(&payment(0, &server_script()), &beef[..], Some(&headers))
            .await
            .unwrap();
        assert_eq!(
            verdict,
            PaymentVerdict::Unverifiable(UnverifiableReason::HeaderLookupFailed {
                height: HEIGHT,
                reason: "HTTP 503".into()
            })
        );
        let PaymentVerdict::Unverifiable(reason) = verdict else {
            unreachable!()
        };
        assert!(reason.is_server_side());
    }

    #[tokio::test]
    async fn the_output_is_checked_before_any_lookup() {
        let (beef, root) = proven_beef(&[(PRICE - 1, payer_script())]);
        let headers = StubHeaders::answering(HEIGHT, Ok(root));
        assert_eq!(
            verify_payment(&payment(0, &server_script()), &beef[..], Some(&headers))
                .await
                .unwrap(),
            PaymentVerdict::Underpaid {
                paid: PRICE - 1,
                required: PRICE
            }
        );
        assert!(headers.asked.lock().unwrap().is_empty());
    }

    /// A transaction with no input, paying `outputs`: nothing can prove it
    /// and nothing beneath it exists.
    fn rootless(outputs: &[(u64, Vec<u8>)]) -> Transaction {
        let mut tx = Transaction::new();
        for (satoshis, script) in outputs {
            tx.add_output(TransactionOutput::new(
                *satoshis,
                LockingScript::from_binary(script).unwrap(),
            ))
            .unwrap();
        }
        tx
    }

    /// A transaction spending `parent:0` with an empty unlock.
    fn spending(parent: &Transaction, outputs: &[(u64, Vec<u8>)]) -> Transaction {
        let mut tx = rootless(outputs);
        let mut input = TransactionInput::new(parent.id(), 0);
        input.unlocking_script = Some(bsv_rs::script::UnlockingScript::new());
        tx.inputs.push(input);
        tx
    }

    /// A BEEF of `txs` in order, the first proven by a one-leaf BUMP at
    /// `HEIGHT` when `proven`. Returns the BEEF and the first txid.
    fn beef_of(txs: &[&Transaction], proven: bool) -> (Vec<u8>, String) {
        let mut beef = Beef::new();
        let root = txs[0].id();
        let bump = proven.then(|| {
            beef.merge_bump(
                MerklePath::new(
                    HEIGHT,
                    vec![vec![MerklePathLeaf::new_txid(0, root.clone())]],
                )
                .unwrap(),
            )
        });
        for (i, tx) in txs.iter().enumerate() {
            beef.merge_raw_tx(tx.to_binary(), bump.filter(|_| i == 0));
        }
        (beef.to_binary(), root)
    }

    const OP_TRUE: &[u8] = &[0x51];

    async fn full(beef: &[u8], script: &[u8], headers: &StubHeaders) -> PaymentVerdict {
        verify_payment(&payment(0, script), beef, Some(headers))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn an_unproven_beef_or_a_raw_transaction_is_unverifiable_with_spv() {
        let headers = StubHeaders::answering(HEIGHT, Ok("00".repeat(32)));
        let script = server_script();
        let tx = unproven_tx(&[(PRICE, payer_script())]);
        let missing_parent = {
            let mut beef = Beef::new();
            let mut lone = Transaction::new();
            lone.add_input(TransactionInput {
                source_txid: Some("22".repeat(32)),
                source_output_index: 0,
                ..Default::default()
            })
            .unwrap();
            lone.add_output(TransactionOutput::new(
                PRICE,
                LockingScript::from_binary(&payer_script()).unwrap(),
            ))
            .unwrap();
            beef.merge_transaction(lone);
            beef.to_binary()
        };
        // The input's previous txid is at offset 4 + 1 + 1 + 1 + 4 + 1 = 12.
        assert_eq!(
            full(&missing_parent, &script, &headers).await,
            PaymentVerdict::Unverifiable(UnverifiableReason::InvalidBeef {
                offset: 12,
                kind: Kind::InputNamesNoElement,
                reason: Reason::InputNamesNoElement { txid: [0x22; 32] },
            })
        );
        // A raw transaction is no BEEF: its version word is not one.
        assert_eq!(
            full(&tx.to_binary(), &script, &headers).await,
            PaymentVerdict::Unverifiable(UnverifiableReason::InvalidBeef {
                offset: 0,
                kind: Kind::BadVersion,
                reason: Reason::BadVersion { word: 1 },
            })
        );
        assert!(headers.asked.lock().unwrap().is_empty());
    }

    // ---- what Verified means: the ancestry ends at a proven transaction ----

    #[tokio::test]
    async fn a_transaction_with_no_input_and_no_proof_anchors_nothing() {
        // The reader's structure rule holds an unproven transaction by its
        // inputs; one with no input passes it with nothing beneath. Alone,
        // under a paying subject, or beside a proven stranger, it is no proof.
        let headers = StubHeaders::answering(HEIGHT, Ok("00".repeat(32)));
        let parent = rootless(&[(PRICE, OP_TRUE.to_vec())]);
        let subject = spending(&parent, &[(PRICE, OP_TRUE.to_vec())]);
        let (alone, _) = beef_of(&[&rootless(&[(PRICE, OP_TRUE.to_vec())])], false);
        let (under, _) = beef_of(&[&parent, &subject], false);
        let stranger = spending(&rootless(&[(1, vec![0x52])]), &[(7, vec![0x53])]);
        let (beside, root) = beef_of(&[&stranger, &parent, &subject], true);
        for beef in [&alone, &under] {
            assert_eq!(
                full(beef, OP_TRUE, &headers).await,
                PaymentVerdict::Unverifiable(UnverifiableReason::NoProof)
            );
        }
        assert!(headers.asked.lock().unwrap().is_empty());
        // Every root the BEEF carries is the header's, and it is still no
        // proof of the subject.
        let carried = StubHeaders::answering(HEIGHT, Ok(root));
        assert_eq!(
            full(&beside, OP_TRUE, &carried).await,
            PaymentVerdict::Unverifiable(UnverifiableReason::NoProof)
        );
        assert!(carried.asked.lock().unwrap().is_empty());
        // The output check alone, opted into by name, reads the output.
        assert_eq!(
            verify_payment_output_only(&payment(0, OP_TRUE), &under[..]).unwrap(),
            PaymentVerdict::Verified { satoshis: PRICE }
        );
    }

    #[tokio::test]
    async fn an_unproven_subject_under_a_proven_parent_is_verified_when_it_spends() {
        let parent = spending(&rootless(&[(1, vec![0x52])]), &[(PRICE, OP_TRUE.to_vec())]);
        let subject = spending(&parent, &[(PRICE, OP_TRUE.to_vec())]);
        let (beef, root) = beef_of(&[&parent, &subject], true);
        let headers = StubHeaders::answering(HEIGHT, Ok(root));
        assert_eq!(
            full(&beef, OP_TRUE, &headers).await,
            PaymentVerdict::Verified { satoshis: PRICE }
        );
        assert_eq!(*headers.asked.lock().unwrap(), vec![HEIGHT]);
    }

    #[tokio::test]
    async fn a_spend_the_interpreter_refuses_is_unverifiable_and_asks_no_header() {
        // The parent is locked to a key; the subject offers no signature.
        let parent = spending(&rootless(&[(1, vec![0x52])]), &[(PRICE, p2pkh(&[7u8; 20]))]);
        let subject = spending(&parent, &[(PRICE, OP_TRUE.to_vec())]);
        let (beef, root) = beef_of(&[&parent, &subject], true);
        let headers = StubHeaders::answering(HEIGHT, Ok(root));
        let verdict = full(&beef, OP_TRUE, &headers).await;
        let PaymentVerdict::Unverifiable(UnverifiableReason::SpendRefused {
            txid, input, why, ..
        }) = &verdict
        else {
            panic!("expected SpendRefused, got {verdict:?}");
        };
        assert_eq!(*txid, subject.id());
        assert_eq!(*input, Some(0));
        assert!(matches!(why, SpendRefusal::Script(_)), "{why:?}");
        assert!(headers.asked.lock().unwrap().is_empty());
        // 0.3.0 read the structure alone and answered Verified here.
        assert_eq!(
            verify_payment_output_only(&payment(0, OP_TRUE), &beef[..]).unwrap(),
            PaymentVerdict::Verified { satoshis: PRICE }
        );
    }

    #[tokio::test]
    async fn a_transaction_that_creates_value_is_unverifiable() {
        let parent = spending(&rootless(&[(1, vec![0x52])]), &[(PRICE, OP_TRUE.to_vec())]);
        let subject = spending(&parent, &[(PRICE + 1, OP_TRUE.to_vec())]);
        let (beef, root) = beef_of(&[&parent, &subject], true);
        let headers = StubHeaders::answering(HEIGHT, Ok(root));
        assert!(matches!(
            full(&beef, OP_TRUE, &headers).await,
            PaymentVerdict::Unverifiable(UnverifiableReason::SpendRefused {
                why: SpendRefusal::CreatesValue,
                input: None,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn the_beefs_own_fault_is_answered_before_the_output_is_judged() {
        // The subject pays the wrong script and names a parent the BEEF does
        // not carry: the reading stops at the invalid bytes.
        let headers = StubHeaders::answering(HEIGHT, Ok("00".repeat(32)));
        let orphan = spending(&rootless(&[(1, vec![0x52])]), &[(PRICE, vec![0x53])]);
        let (beef, _) = beef_of(&[&orphan], false);
        assert!(matches!(
            full(&beef, OP_TRUE, &headers).await,
            PaymentVerdict::Unverifiable(UnverifiableReason::InvalidBeef {
                kind: Kind::InputNamesNoElement,
                ..
            })
        ));
        // The output check alone reads no structure and answers the script.
        assert!(matches!(
            verify_payment_output_only(&payment(0, OP_TRUE), &beef[..]).unwrap(),
            PaymentVerdict::WrongScript { .. }
        ));
    }

    #[tokio::test]
    async fn a_beef_with_no_transaction_pays_nothing() {
        let headers = StubHeaders::answering(HEIGHT, Ok("00".repeat(32)));
        let empty = Beef::new().to_binary();
        assert_eq!(
            full(&empty, OP_TRUE, &headers).await,
            PaymentVerdict::Unverifiable(UnverifiableReason::NoTransaction)
        );
        assert_eq!(
            verify_payment_output_only(&payment(0, OP_TRUE), &empty[..]).unwrap(),
            PaymentVerdict::Unverifiable(UnverifiableReason::NoTransaction)
        );
    }

    // ---- the source ----

    /// A source that hands out `chunk` bytes at a time, then fails or ends.
    struct Chunks<'a> {
        bytes: &'a [u8],
        chunk: usize,
        fail_at_end: bool,
    }

    impl Read for Chunks<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.bytes.is_empty() && self.fail_at_end {
                return Err(std::io::Error::other("the source broke"));
            }
            let n = self.chunk.min(buf.len()).min(self.bytes.len());
            buf[..n].copy_from_slice(&self.bytes[..n]);
            self.bytes = &self.bytes[n..];
            Ok(n)
        }
    }

    impl AsyncByteSource for Chunks<'_> {
        async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
            let mut buf = vec![0u8; self.chunk];
            let n = self.read(&mut buf)?;
            buf.truncate(n);
            Ok((n > 0).then_some(buf))
        }
    }

    #[tokio::test]
    async fn every_source_and_every_chunk_size_gives_the_same_verdict() {
        let parent = spending(&rootless(&[(1, vec![0x52])]), &[(PRICE, OP_TRUE.to_vec())]);
        let subject = spending(&parent, &[(PRICE, OP_TRUE.to_vec())]);
        let (good, root) = beef_of(&[&parent, &subject], true);
        let (wrong, _) = proven_beef(&[(PRICE, p2pkh(&[9u8; 20]))]);
        let mut cut = good.clone();
        cut.truncate(good.len() - 3);
        let atomic = unproven_tx(&[(PRICE - 1, OP_TRUE.to_vec())])
            .to_atomic_beef(true)
            .unwrap();
        for bytes in [&good, &wrong, &cut, &atomic] {
            let headers = StubHeaders::answering(HEIGHT, Ok(root.clone()));
            let whole = full(bytes, OP_TRUE, &headers).await;
            let whole_output = verify_payment_output_only(&payment(0, OP_TRUE), &bytes[..]);
            for chunk in [1, 2, 3, 5, 7, 64, 4096] {
                let source = |fail_at_end| Chunks {
                    bytes,
                    chunk,
                    fail_at_end,
                };
                let p = payment(0, OP_TRUE);
                assert_eq!(
                    verify_payment(&p, source(false), Some(&headers))
                        .await
                        .unwrap(),
                    whole,
                    "Read, {chunk} at a time"
                );
                assert_eq!(
                    verify_payment_async(&p, &mut source(false), Some(&headers))
                        .await
                        .unwrap(),
                    whole,
                    "asynchronous, {chunk} at a time"
                );
                assert_eq!(
                    verify_payment_output_only(&p, source(false)).unwrap(),
                    *whole_output.as_ref().unwrap(),
                    "output only, Read, {chunk} at a time"
                );
                assert_eq!(
                    verify_payment_output_only_async(&p, &mut source(false))
                        .await
                        .unwrap(),
                    *whole_output.as_ref().unwrap(),
                    "output only, asynchronous, {chunk} at a time"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_source_that_fails_is_an_error_and_never_a_verdict() {
        let (beef, root) = proven_beef(&[(PRICE, OP_TRUE.to_vec())]);
        let headers = StubHeaders::answering(HEIGHT, Ok(root));
        let p = payment(0, OP_TRUE);
        let broken = || Chunks {
            bytes: &beef,
            chunk: 16,
            fail_at_end: true,
        };
        assert!(verify_payment(&p, broken(), Some(&headers)).await.is_err());
        assert!(verify_payment_async(&p, &mut broken(), Some(&headers))
            .await
            .is_err());
        assert!(verify_payment_output_only(&p, broken()).is_err());
        assert!(verify_payment_output_only_async(&p, &mut broken())
            .await
            .is_err());
        assert!(headers.asked.lock().unwrap().is_empty());
        // No header service is answered before the source is touched.
        assert_eq!(
            verify_payment(&p, broken(), None).await.unwrap(),
            PaymentVerdict::NoHeaderService
        );
    }

    // ---- the roots ----

    /// A BEEF V2 of one BUMP at `height` (one leaf, the txid) and the
    /// transaction it proves, written by hand: the SDK's in-memory BUMP has
    /// no height above `u32::MAX`.
    fn proven_at(height: u64, tx: &Transaction) -> Vec<u8> {
        let raw = tx.to_binary();
        let txid = bsv_rs::primitives::sha256d(&raw);
        let mut v = BEEF_V2.to_le_bytes().to_vec();
        v.push(1);
        v.push(0xFF);
        v.extend_from_slice(&height.to_le_bytes());
        v.extend_from_slice(&[1, 1, 0, 2]);
        v.extend_from_slice(&txid);
        v.extend_from_slice(&[1, 1, 0]);
        v.extend_from_slice(&raw);
        v
    }

    #[tokio::test]
    async fn a_height_no_header_service_can_be_asked_for_is_a_root_not_carried() {
        let tx = spending(&rootless(&[(1, vec![0x52])]), &[(PRICE, OP_TRUE.to_vec())]);
        let headers = StubHeaders::answering(HEIGHT, Ok("00".repeat(32)));
        let height = u64::from(u32::MAX) + 1 + u64::from(HEIGHT);
        let verdict = full(&proven_at(height, &tx), OP_TRUE, &headers).await;
        assert!(
            matches!(
                verdict,
                PaymentVerdict::Unverifiable(UnverifiableReason::InvalidBeef {
                    offset: 5,
                    kind: Kind::RootNotCarried,
                    reason: Reason::RootNotCarried { height: h, .. },
                }) if h == height
            ),
            "{verdict:?}"
        );
        // Never asked at the height's low 32 bits.
        assert!(headers.asked.lock().unwrap().is_empty());
        // The same bytes at a height a header service has are verified.
        let root = tx.id();
        let headers = StubHeaders::answering(HEIGHT, Ok(root));
        assert_eq!(
            full(&proven_at(u64::from(HEIGHT), &tx), OP_TRUE, &headers).await,
            PaymentVerdict::Verified { satoshis: PRICE }
        );
    }

    #[test]
    fn header_service_url_refuses_every_shape_of_none() {
        for none in [
            None,
            Some(""),
            Some("  / "),
            Some("https://chaintracks.invalid"),
            Some("HTTPS://ChainTracks.INVALID./"),
            Some("https://chaintracks%2Einvalid"),
            Some("https://real.example\\@chaintracks.invalid"),
            Some("https://user@headers.example"),
            Some("ftp://headers.example"),
            Some("headers.example"),
            Some("https://headers.example:99999"),
            Some("https://-bad-.example"),
        ] {
            assert_eq!(header_service_url(none), None, "{:?}", none);
        }
        assert_eq!(
            header_service_url(Some(" https://headers.example/ ")),
            Some("https://headers.example")
        );
        assert_eq!(
            header_service_url(Some("http://[::1]:8080")),
            Some("http://[::1]:8080")
        );
    }
}
