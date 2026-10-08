//! The BRC-29 payment-output rule: one verifier, six words, no runtime.
//!
//! This module is the API `bsv-middleware-core` is to provide (bsv-stack-lean
//! #50; epoch `NETWORK-ENFORCEMENT-RULES.md` Rule 27 at 2f4ef72). It names no
//! axum, tokio, reqwest or worker type and nothing else in this crate: it uses
//! `bsv-rs` (BEEF, keys), `async-trait` and `hex` only, so when the core crate
//! is published the module is replaced by a re-export of it and the Axum layer
//! above (`crate::axum`) is unchanged.
//!
//! The verdict is a word, never a boolean ([`PaymentVerdict`]); the header
//! service is a trait ([`HeaderService`]) passed as an `Option`, and `None` is
//! [`PaymentVerdict::NoHeaderService`] before any other check. The rule is
//! pinned by `conformance/brc29-payment-vectors.json` (copied from
//! `bsv-middleware-cloudflare@dabfb78`), run in `tests/conformance_brc29.rs`.
//!
//! Order of checks (the vectors' `conformance/README.md`, "Order of checks"):
//! 1. a header service is configured, else `NoHeaderService`;
//! 2. the payment is within its byte budget ([`MAX_PAYMENT_BYTES`]) and, for
//!    a BEEF, its transaction and BUMP counts are within theirs
//!    ([`PAYMENT_BEEF_LIMITS`]), each checked before the entries are read,
//!    else `Unverifiable` naming the count and the bound; then the payment
//!    parses (BEEF V1/V2 or Atomic BEEF; the subject is the
//!    Atomic BEEF's named transaction, else the last), and output
//!    `output_index` exists and carries an amount, else `Unverifiable`;
//! 3. the output's script equals the expected BRC-29 script, else
//!    `WrongScript`; then its satoshis are at least the price, else
//!    `Underpaid`;
//! 4. the BEEF is structurally complete, else `Unverifiable`; every merkle
//!    root it computes, lowest height first, is the header service's root at
//!    that height (case-insensitive hex): a different root is `RootMismatch`,
//!    a lookup that cannot answer is `Unverifiable` (fail closed; a mismatch
//!    at any height still wins over an outage at another);
//! 5. `Verified { satoshis }`, the amount read from the output.

use async_trait::async_trait;
use bsv_rs::primitives::PublicKey;
use bsv_rs::transaction::{Beef, BeefLimits, Transaction, ATOMIC_BEEF, BEEF_V1, BEEF_V2};
use bsv_rs::wallet::{Counterparty, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel};

/// The BRC-29 payment protocol name (security level 2), the protocol the
/// payer derives the paying key under.
pub const BRC29_PROTOCOL_NAME: &str = "3241645161d8";

/// Maximum decoded payment size: 4 MiB, matching the message box's standard
/// body budget (`ts-stack@fb1b2da infra/message-box-server/src/app.ts:195-208`).
/// The reference middleware uses a base64 JSON `x-bsv-payment` header with no
/// code size cap (`payment-express-middleware/src/index.ts:67-107`); Node's
/// default HTTP header budget is 16 KiB. The larger shared bound also serves
/// body callers and accommodates the known 1.9 MB ancestor (Zanaadu #357).
/// Callers must bound their transport before reading or decoding the payment.
pub const MAX_PAYMENT_BYTES: usize = 4 * 1024 * 1024;

/// Maximum payment BEEF transactions: room for the subject and 127 ancestors
/// through its proven funding roots. This is a door policy with headroom for
/// branching unproven funding, not a limit on valid chain transactions. A
/// large proven ancestor (Zanaadu #357) needs bytes, not thousands of entries.
pub const MAX_PAYMENT_BEEF_TXS: usize = 128;

/// Maximum payment BUMPs: 32 distinct proof blocks allow consolidated funding
/// within the 128-transaction budget. A BUMP may prove several ancestors;
/// this counts proof blocks, not leaves. The byte bound and the SDK's bounded
/// parser also apply. Callers with a different policy can supply their limits.
pub const MAX_PAYMENT_BEEF_BUMPS: usize = 32;

/// Default bounds for the shared payment door, including the Atomic prefix.
pub const PAYMENT_BEEF_LIMITS: BeefLimits = BeefLimits {
    max_txs: MAX_PAYMENT_BEEF_TXS,
    max_bumps: MAX_PAYMENT_BEEF_BUMPS,
    max_bytes: MAX_PAYMENT_BYTES,
};

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
/// Non-exhaustive: a reason may be added in a minor release, so a match on
/// it carries a catch-all arm. The six words of [`PaymentVerdict`] are the
/// contract and stay exhaustive.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnverifiableReason {
    /// The payment exceeds its byte budget, checked before parsing.
    PaymentTooLarge {
        /// The complete serialized payment length.
        bytes: usize,
        /// The byte budget that was exceeded.
        max_bytes: usize,
    },
    /// The BEEF transaction count prefix exceeds the door's budget.
    BeefTransactionsExceeded {
        /// The count claimed by the BEEF.
        count: usize,
        /// The maximum transaction count.
        max_txs: usize,
    },
    /// The BEEF BUMP count prefix exceeds the door's budget.
    BeefBumpsExceeded {
        /// The count claimed by the BEEF.
        count: usize,
        /// The maximum BUMP count.
        max_bumps: usize,
    },
    /// The bytes are neither a BEEF nor a raw transaction.
    MalformedTransaction(String),
    /// The subject transaction has no output at the index that is paid.
    OutputMissing {
        /// The index the payment names.
        output_index: u32,
        /// How many outputs the transaction has.
        output_count: usize,
    },
    /// The output carries no amount.
    OutputWithoutAmount,
    /// The derivation inputs do not name a key (the sender identity is not a
    /// public key).
    KeyDerivation(String),
    /// A raw transaction carries no merkle proof to check against headers.
    NoProof,
    /// The BEEF is not structurally complete: missing inputs, txid-only gaps,
    /// or a proof chain that does not verify.
    IncompleteBeef,
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
            Self::PaymentTooLarge { bytes, max_bytes } => write!(
                f,
                "payment transaction is {} bytes, over max_bytes {}",
                bytes, max_bytes
            ),
            Self::BeefTransactionsExceeded { count, max_txs } => write!(
                f,
                "payment BEEF claims {} transactions, over max_txs {}",
                count, max_txs
            ),
            Self::BeefBumpsExceeded { count, max_bumps } => write!(
                f,
                "payment BEEF claims {} BUMPs, over max_bumps {}",
                count, max_bumps
            ),
            Self::MalformedTransaction(e) => write!(f, "transaction is malformed: {}", e),
            Self::OutputMissing {
                output_index,
                output_count,
            } => write!(
                f,
                "output {} is missing (transaction has {} outputs)",
                output_index, output_count
            ),
            Self::OutputWithoutAmount => write!(f, "output carries no amount"),
            Self::KeyDerivation(e) => write!(f, "key derivation failed: {}", e),
            Self::NoProof => write!(f, "a raw transaction carries no merkle proof"),
            Self::IncompleteBeef => write!(
                f,
                "BEEF is incomplete (missing inputs, txid-only gaps, or a broken proof chain)"
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

/// One payment to verify: the transaction as sent, the output that is paid,
/// the script it must carry ([`brc29_locking_script`]) and the price.
#[derive(Debug, Clone, Copy)]
pub struct PaymentToVerify<'a> {
    /// A BEEF (V1, V2 or Atomic) or, for [`verify_payment_output_only`], a raw
    /// transaction.
    pub transaction: &'a [u8],
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

/// The full check: header service, output, BEEF structure, merkle roots.
///
/// `header_service` is `None` when the deployment has none: the answer is
/// [`PaymentVerdict::NoHeaderService`] before the payment is read.
///
/// Payments over [`MAX_PAYMENT_BYTES`] are refused before parsing and BEEF
/// counts are bounded by [`PAYMENT_BEEF_LIMITS`]. Use
/// [`verify_payment_with_limits`] for a caller's own budgets.
pub async fn verify_payment(
    payment: &PaymentToVerify<'_>,
    header_service: Option<&dyn HeaderService>,
) -> PaymentVerdict {
    verify_payment_with_limits(
        payment,
        header_service,
        MAX_PAYMENT_BYTES,
        &PAYMENT_BEEF_LIMITS,
    )
    .await
}

/// [`verify_payment`] with caller-supplied byte and BEEF budgets.
///
/// `max_bytes` bounds every format before parsing; `beef_limits.max_bytes`
/// additionally bounds a BEEF, so the smaller byte budget wins there. BEEF
/// count prefixes are checked before their entries are read
/// (`Beef::from_binary_with_limits`, bsv-rs 0.3.35). The caller must also
/// bound transport reads and decoding before this call.
pub async fn verify_payment_with_limits(
    payment: &PaymentToVerify<'_>,
    header_service: Option<&dyn HeaderService>,
    max_bytes: usize,
    beef_limits: &BeefLimits,
) -> PaymentVerdict {
    let Some(headers) = header_service else {
        return PaymentVerdict::NoHeaderService;
    };
    let (transaction, beef) = match read_payment(payment.transaction, max_bytes, beef_limits) {
        Ok(read) => read,
        Err(reason) => return PaymentVerdict::Unverifiable(reason),
    };
    let satoshis = match check_output(&transaction, payment) {
        Ok(satoshis) => satoshis,
        Err(verdict) => return verdict,
    };
    let Some(mut beef) = beef else {
        return PaymentVerdict::Unverifiable(UnverifiableReason::NoProof);
    };
    let validation = beef.verify_valid(false);
    if !validation.valid {
        return PaymentVerdict::Unverifiable(UnverifiableReason::IncompleteBeef);
    }
    if validation.roots.is_empty() {
        return PaymentVerdict::Unverifiable(UnverifiableReason::NoProof);
    }
    let mut roots: Vec<(u32, String)> = validation.roots.into_iter().collect();
    roots.sort_unstable();
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

/// The output check alone: no header service, no BEEF structure, no merkle
/// roots. Opted into by name (Rule 27) by a host whose next step checks the
/// transaction itself (a storage that verifies the BEEF before it records
/// it); it never answers `NoHeaderService` or `RootMismatch`. Reads a raw
/// transaction as well as a BEEF.
///
/// Payments over [`MAX_PAYMENT_BYTES`] are refused before parsing and BEEF
/// counts are bounded by [`PAYMENT_BEEF_LIMITS`]. Use
/// [`verify_payment_output_only_with_limits`] for a caller's own budgets.
pub fn verify_payment_output_only(payment: &PaymentToVerify<'_>) -> PaymentVerdict {
    verify_payment_output_only_with_limits(payment, MAX_PAYMENT_BYTES, &PAYMENT_BEEF_LIMITS)
}

/// [`verify_payment_output_only`] with caller-supplied byte and BEEF budgets
/// (see [`verify_payment_with_limits`]). A raw transaction is bounded by
/// `max_bytes` alone.
pub fn verify_payment_output_only_with_limits(
    payment: &PaymentToVerify<'_>,
    max_bytes: usize,
    beef_limits: &BeefLimits,
) -> PaymentVerdict {
    match read_payment(payment.transaction, max_bytes, beef_limits) {
        Err(reason) => PaymentVerdict::Unverifiable(reason),
        Ok((transaction, _)) => match check_output(&transaction, payment) {
            Ok(satoshis) => PaymentVerdict::Verified { satoshis },
            Err(verdict) => verdict,
        },
    }
}

/// The subject transaction and, when the bytes are a BEEF, the BEEF.
///
/// The byte budget is checked before either format is parsed and the BEEF
/// counts before their entries are read; the BEEF is parsed once and the
/// subject taken from it (the Atomic BEEF's named transaction, else the
/// last), the resolution order of `Transaction::from_beef` in bsv-rs 0.3.35.
fn read_payment(
    bytes: &[u8],
    max_bytes: usize,
    beef_limits: &BeefLimits,
) -> Result<(Transaction, Option<Beef>), UnverifiableReason> {
    if bytes.len() > max_bytes {
        return Err(UnverifiableReason::PaymentTooLarge {
            bytes: bytes.len(),
            max_bytes,
        });
    }
    let malformed = |e: bsv_rs::Error| UnverifiableReason::MalformedTransaction(e.to_string());
    let magic = bytes
        .get(..4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    if matches!(magic, Some(ATOMIC_BEEF | BEEF_V1 | BEEF_V2)) {
        if bytes.len() > beef_limits.max_bytes {
            return Err(UnverifiableReason::PaymentTooLarge {
                bytes: bytes.len(),
                max_bytes: beef_limits.max_bytes,
            });
        }
        let beef = Beef::from_binary_with_limits(bytes, beef_limits).map_err(bounded_beef_error)?;
        let not_found = |what: &str| UnverifiableReason::MalformedTransaction(what.to_string());
        let transaction = match beef.atomic_txid.as_deref() {
            Some(txid) => beef
                .find_atomic_transaction(txid)
                .ok_or_else(|| not_found("Atomic transaction not found"))?,
            None => {
                let txid = beef
                    .txs
                    .last()
                    .map(|tx| tx.txid())
                    .ok_or_else(|| not_found("No transactions in BEEF"))?;
                beef.find_atomic_transaction(&txid)
                    .ok_or_else(|| not_found("Subject transaction not found in BEEF"))?
            }
        };
        Ok((transaction, Some(beef)))
    } else {
        Ok((Transaction::from_binary(bytes).map_err(malformed)?, None))
    }
}

// bsv-rs 0.3.35 exposes limit diagnostics as BeefError(String). Translate its
// exact count diagnostics; other parser errors retain the malformed reason.
fn bounded_beef_error(error: bsv_rs::Error) -> UnverifiableReason {
    if let bsv_rs::Error::BeefError(message) = &error {
        if let Some((count, max_txs)) = beef_limit_counts(message, " transactions, over max_txs ") {
            return UnverifiableReason::BeefTransactionsExceeded { count, max_txs };
        }
        if let Some((count, max_bumps)) = beef_limit_counts(message, " BUMPs, over max_bumps ") {
            return UnverifiableReason::BeefBumpsExceeded { count, max_bumps };
        }
    }
    UnverifiableReason::MalformedTransaction(error.to_string())
}

fn beef_limit_counts(message: &str, separator: &str) -> Option<(usize, usize)> {
    let claimed = message.strip_prefix("BEEF claims ")?;
    let (count, bound) = claimed.split_once(separator)?;
    Some((count.parse().ok()?, bound.parse().ok()?))
}

/// Script first, then amount; the satoshis on success.
fn check_output(
    transaction: &Transaction,
    payment: &PaymentToVerify<'_>,
) -> Result<u64, PaymentVerdict> {
    let output = transaction
        .outputs
        .get(payment.output_index as usize)
        .ok_or(PaymentVerdict::Unverifiable(
            UnverifiableReason::OutputMissing {
                output_index: payment.output_index,
                output_count: transaction.outputs.len(),
            },
        ))?;
    let actual = output.locking_script.to_binary();
    if actual != payment.expected_script {
        return Err(PaymentVerdict::WrongScript {
            expected: payment.expected_script.to_vec(),
            actual,
        });
    }
    let paid = output.satoshis.ok_or(PaymentVerdict::Unverifiable(
        UnverifiableReason::OutputWithoutAmount,
    ))?;
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
    use bsv_rs::transaction::{MerklePath, MerklePathLeaf, TransactionInput, TransactionOutput};
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

    fn payment<'a>(tx: &'a [u8], index: u32, script: &'a [u8]) -> PaymentToVerify<'a> {
        PaymentToVerify {
            transaction: tx,
            output_index: index,
            expected_script: script,
            required_satoshis: PRICE,
        }
    }

    fn output_only(tx: &[u8], index: u32) -> PaymentVerdict {
        verify_payment_output_only(&payment(tx, index, &server_script()))
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
        for bytes in [&[1u8, 1, 1, 1, 0xff][..], b"not a transaction", &[]] {
            assert!(matches!(
                output_only(bytes, 0),
                PaymentVerdict::Unverifiable(UnverifiableReason::MalformedTransaction(_))
            ));
        }
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
                verify_payment(&payment(bytes, 0, &script), None).await,
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
                verify_payment(&payment(&beef, 0, &server_script()), Some(&headers)).await,
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
            verify_payment(&payment(&beef, 0, &server_script()), Some(&headers)).await,
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
        let verdict = verify_payment(&payment(&beef, 0, &server_script()), Some(&headers)).await;
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
            verify_payment(&payment(&beef, 0, &server_script()), Some(&headers)).await,
            PaymentVerdict::Underpaid {
                paid: PRICE - 1,
                required: PRICE
            }
        );
        assert!(headers.asked.lock().unwrap().is_empty());
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
        assert_eq!(
            verify_payment(&payment(&missing_parent, 0, &script), Some(&headers)).await,
            PaymentVerdict::Unverifiable(UnverifiableReason::IncompleteBeef)
        );
        assert_eq!(
            verify_payment(&payment(&tx.to_binary(), 0, &script), Some(&headers)).await,
            PaymentVerdict::Unverifiable(UnverifiableReason::NoProof)
        );
        assert!(headers.asked.lock().unwrap().is_empty());
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
