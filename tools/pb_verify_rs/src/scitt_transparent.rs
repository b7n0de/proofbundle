//! scitt-ccf/v1 (ADR 0009): a Transparent Statement against a target's canonical root.
//!
//! The Rust side of `proofbundle.scitt_ccf.verify_transparent_statement`. The statement is read by
//! `scitt.rs` (the reader, the statement's CDDL pass, its key selector and its signature); this file
//! adds what a Transparent Statement carries beyond it: the receipts under label 394, the CDDL pass of
//! each receipt and of every proof family of a CCF receipt (draft-ietf-scitt-receipts-ccf-profile-05),
//! the roots the proofs compute, the receipt signature under the relying party's service keys, and the
//! order that combines the statuses into one. None of it is shared with the Python module.
//!
//! The result carries the fields of Python's `TransparentStatementCheck` and `ReceiptCheck` that are
//! verdicts or computed values; the prose of `detail` and of `ignored_trust` is not ported, only the
//! number of ignored trust entries.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::scitt::{
    self, get, is_int, is_label, is_uint, Cose, Item, Key, PubKey, Selector, ALG, CONFIRMED, CRIT,
    CTY, CWT, INVALID, KID, MALFORMED, MAX_TRUSTED_KEYS, NEEDS_RP_TRUST, OUTSIDE, PAYLOAD_HASH_ALG,
    PAYLOAD_LOCATION, PREIMAGE_CTY, X5CHAIN,
};

const RECEIPTS: i128 = 394;
const VDS: i128 = 395;
const VDP: i128 = 396;
const INCLUSION: i128 = -1;
const CONSISTENCY: i128 = -2;
/// The value -05 asks IANA for (TBD_1), not yet assigned.
const CCF_LEDGER_SHA256: i128 = 2;
const SHA256_ALG: i128 = -16;

/// ADR 0009, Decision 8.
const MAX_RECEIPTS: usize = 8;
const MAX_INCLUSION_PROOFS: usize = 8;
const MAX_CONSISTENCY_PROOFS: usize = 8;
const MAX_PATH: usize = 64;
const MAX_EVIDENCE_BYTES: usize = 1024;

const STATEMENT_ALGS: [i128; 4] = [-7, -35, -37, -38];
const RECEIPT_ALGS: [i128; 2] = [-7, -35];
/// The crit labels v1 processes (ADR 0009, Decision 7).
const STATEMENT_CRIT_PROCESSED: [i128; 2] = [ALG, PAYLOAD_HASH_ALG];
const RECEIPT_CRIT_PROCESSED: [i128; 4] = [ALG, KID, CWT, VDS];

const UNBOUND: &str = "unbound";
const ROOT_MISMATCH: &str = "root_mismatch";
const SIGNATURE_INVALID: &str = "signature_invalid";
const RECEIPT_NOT_BOUND: &str = "receipt_not_bound";

/// The order that decides an entry without a confirmed receipt (Python's STATUS_ORDER).
const STATUS_ORDER: [&str; 9] = [
    "no_lib",
    MALFORMED,
    OUTSIDE,
    UNBOUND,
    INVALID,
    ROOT_MISMATCH,
    SIGNATURE_INVALID,
    RECEIPT_NOT_BOUND,
    NEEDS_RP_TRUST,
];

type Hash = [u8; 32];

fn sha256(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

// ---------------------------------------------------------------------------------------------------
// Relying-party trust, read from JSON: a key entry is SubjectPublicKeyInfo DER as hex, or an object
// {"spki": hex, "kid": hex or null}. Anything else is ignored, and ignored trust is absent trust.
// ---------------------------------------------------------------------------------------------------
pub(crate) struct TrustKey {
    spki: Vec<u8>,
    kid: Option<Vec<u8>>,
    key: PubKey,
}

/// `_normalize_keys`: the first `MAX_TRUSTED_KEYS` entries v1 verifies with, and how many entries
/// were ignored (an absent or null list counts none, any other non-list one).
fn normalize_keys(entries: Option<&Value>) -> (Vec<TrustKey>, usize) {
    let list = match entries {
        None | Some(Value::Null) => return (Vec::new(), 0),
        Some(Value::Array(list)) => list,
        Some(_) => return (Vec::new(), 1),
    };
    let mut usable = Vec::new();
    let mut ignored = 0;
    for entry in list.iter().take(MAX_TRUSTED_KEYS) {
        let parsed = match entry {
            Value::String(h) => hex::decode(h).ok().map(|spki| (spki, None)),
            Value::Object(o) => match (o.get("spki"), o.get("kid")) {
                (Some(Value::String(s)), None | Some(Value::Null)) => {
                    hex::decode(s).ok().map(|spki| (spki, None))
                }
                (Some(Value::String(s)), Some(Value::String(k))) => {
                    match (hex::decode(s), hex::decode(k)) {
                        (Ok(spki), Ok(kid)) => Some((spki, Some(kid))),
                        _ => None,
                    }
                }
                _ => None,
            },
            _ => None,
        };
        match parsed.and_then(|(spki, kid)| {
            scitt::key_from_spki(&spki)
                .ok()
                .map(|key| TrustKey { spki, kid, key })
        }) {
            Some(k) => usable.push(k),
            None => ignored += 1,
        }
    }
    if list.len() > MAX_TRUSTED_KEYS {
        ignored += 1;
    }
    (usable, ignored)
}

/// The self-binding measured on every -05 receipt: hex(SHA-256(SubjectPublicKeyInfo)), as ASCII.
fn derived_kid(spki: &[u8]) -> Vec<u8> {
    hex::encode(sha256(&[spki])).into_bytes()
}

// ---------------------------------------------------------------------------------------------------
// The CDDL pass of a receipt and of its proofs
// ---------------------------------------------------------------------------------------------------
fn in_either(c: &Cose, label: i128, ok: fn(&Item) -> bool) -> bool {
    [&c.protected, &c.unprotected]
        .iter()
        .all(|bucket| get(bucket, label).is_none_or(ok))
}

/// A CWT claim, where present, has its type, in the CWT claims map of either bucket.
fn cwt_claim_in_either(c: &Cose, claim: i128, ok: fn(&Item) -> bool) -> bool {
    [&c.protected, &c.unprotected]
        .iter()
        .all(|bucket| match get(bucket, CWT) {
            Some(Item::Map(cwt)) => get(cwt, claim).is_none_or(ok),
            _ => true,
        })
}

/// `_RECEIPT_RULES`: the header types every receipt carries, RFC 9052, RFC 9597, RFC 8392, RFC 9942.
fn receipt_types_hold(rc: &Cose) -> bool {
    in_either(rc, ALG, |v| is_int(v) || matches!(v, Item::Text(_)))
        && in_either(
            rc,
            CRIT,
            |v| matches!(v, Item::Array(a) if !a.is_empty() && a.iter().all(is_label)),
        )
        && in_either(rc, CTY, |v| is_uint(v) || matches!(v, Item::Text(_)))
        && in_either(rc, KID, |v| matches!(v, Item::Bytes(_)))
        && in_either(rc, CWT, |v| matches!(v, Item::Map(_)))
        && cwt_claim_in_either(rc, 1, |v| matches!(v, Item::Text(_)))
        && cwt_claim_in_either(rc, 6, is_int)
        && in_either(rc, VDS, is_int)
        && in_either(rc, VDP, |v| matches!(v, Item::Map(_)))
}

fn is_ccf(rc: &Cose) -> bool {
    matches!(get(&rc.protected, VDS), Some(Item::Int(v)) if *v == CCF_LEDGER_SHA256)
}

/// vdp is read from the unprotected bucket only.
fn vdp_of(rc: &Cose) -> Option<&Item> {
    get(&rc.unprotected, VDP)
}

fn family(rc: &Cose, key: i128) -> Option<&Item> {
    match vdp_of(rc) {
        Some(Item::Map(vdp)) => get(vdp, key),
        _ => None,
    }
}

/// `_CCF_RULES`: the -05 CDDL of the protected alg and of every vdp family.
fn ccf_rules_hold(rc: &Cose) -> bool {
    if get(&rc.protected, ALG).is_some_and(|a| !is_int(a)) {
        return false;
    }
    if let Some(Item::Map(vdp)) = vdp_of(rc) {
        let known = |k: &Key| *k == Key::Int(INCLUSION) || *k == Key::Int(CONSISTENCY);
        if !vdp.iter().all(|(k, _)| known(k)) || !vdp.iter().any(|(k, _)| known(k)) {
            return false;
        }
    }
    [
        (INCLUSION, MAX_INCLUSION_PROOFS),
        (CONSISTENCY, MAX_CONSISTENCY_PROOFS),
    ]
    .iter()
    .all(|(key, limit)| match family(rc, *key) {
        None => true,
        Some(Item::Array(proofs)) => !proofs.is_empty() && proofs.len() <= *limit,
        Some(_) => false,
    })
}

fn bytes32(v: &Item) -> Option<Hash> {
    match v {
        Item::Bytes(b) => b.as_slice().try_into().ok(),
        _ => None,
    }
}

/// `_PROOF_RULES`: a byte string that decodes to exactly {1: ..., 2: path}, the path 1 to MAX_PATH
/// elements of [bool, bstr .size 32]. -> (part 1, path).
fn proof(raw: &Item) -> Result<(Item, Vec<(bool, Hash)>), ()> {
    let Item::Bytes(raw) = raw else {
        return Err(());
    };
    let Item::Map(m) = scitt::scan(raw, scitt::no_tags)? else {
        return Err(());
    };
    let (Some(first), Some(Item::Array(steps))) = (get(&m, 1), get(&m, 2)) else {
        return Err(());
    };
    if m.len() != 2 || steps.is_empty() || steps.len() > MAX_PATH {
        return Err(());
    }
    let path = steps
        .iter()
        .map(|e| match e {
            Item::Array(pair) if pair.len() == 2 => match (&pair[0], bytes32(&pair[1])) {
                (Item::Bool(left), Some(sib)) => Ok((*left, sib)),
                _ => Err(()),
            },
            _ => Err(()),
        })
        .collect::<Result<Vec<_>, ()>>()?;
    Ok((first.clone(), path))
}

/// -05 section 3.2 compute_root of one ccf-inclusion-proof, after `_LEAF_RULES`: -> (root, the
/// data-hash of its leaf).
fn inclusion_root(raw: &Item) -> Result<(Hash, Hash), ()> {
    let (leaf, path) = proof(raw)?;
    let Item::Array(parts) = leaf else {
        return Err(());
    };
    let [itx, ev, dh] = parts.as_slice() else {
        return Err(());
    };
    let (Some(itx), Item::Text(ev), Some(dh)) = (bytes32(itx), ev, bytes32(dh)) else {
        return Err(());
    };
    if ev.is_empty() || ev.len() > MAX_EVIDENCE_BYTES {
        return Err(()); // internal-evidence is tstr .size (1..MAX_EVIDENCE_BYTES), counted in bytes
    }
    let mut h = sha256(&[&itx, &sha256(&[ev.as_bytes()]), &dh]);
    for (left, sib) in path {
        h = if left {
            sha256(&[&sib, &h])
        } else {
            sha256(&[&h, &sib])
        };
    }
    Ok((h, dh))
}

/// -05 section 4.2 compute_roots of one ccf-consistency-proof, after `_ANCHOR_RULES`: -> the newer
/// root (the older one and the first tag are the consistency surface's, not read here).
fn consistency_newer_root(raw: &Item) -> Result<Hash, ()> {
    let (anchor, path) = proof(raw)?;
    let Some(mut newer) = bytes32(&anchor) else {
        return Err(());
    };
    for (left, sib) in path {
        newer = if left {
            sha256(&[&sib, &newer])
        } else {
            sha256(&[&newer, &sib])
        };
    }
    Ok(newer)
}

/// A receipt the CDDL pass accepted, with what the status logic reads.
struct ValidReceipt {
    rc: Cose,
    readable: bool,
    kid: Option<Vec<u8>>,
    iss: Option<String>,
    iat: Option<i128>,
    txid: Option<String>,
    consistency_present: bool,
    inclusion: Vec<(Hash, Hash)>,
    consistency_newer: Vec<Hash>,
}

/// `_validate_receipt` for a Transparent Statement (the family it verifies is -1). `Err` is
/// `malformed`, for this receipt alone.
fn validate_receipt(raw: &Item) -> Result<ValidReceipt, ()> {
    let Item::Bytes(bytes) = raw else {
        return Err(());
    };
    let rc = scitt::decode_cose(bytes, scitt::no_tags)?;
    if !receipt_types_hold(&rc) {
        return Err(());
    }
    let ccf = is_ccf(&rc);
    let mut inclusion = Vec::new();
    let mut consistency_newer = Vec::new();
    if ccf {
        if !ccf_rules_hold(&rc) {
            return Err(());
        }
        if let Some(Item::Array(proofs)) = family(&rc, INCLUSION) {
            inclusion = proofs
                .iter()
                .map(inclusion_root)
                .collect::<Result<_, ()>>()?;
        }
        if let Some(Item::Array(proofs)) = family(&rc, CONSISTENCY) {
            consistency_newer = proofs
                .iter()
                .map(consistency_newer_root)
                .collect::<Result<_, ()>>()?;
        }
    }
    let ph = &rc.protected;
    let cwt: &[(Key, Item)] = match get(ph, CWT) {
        Some(Item::Map(m)) => m,
        _ => &[],
    };
    let ccf_header: &[(Key, Item)] = match ph.iter().find(|(k, _)| *k == Key::Text("ccf.v1".into()))
    {
        Some((_, Item::Map(m))) => m,
        _ => &[],
    };
    let kid = match get(ph, KID) {
        Some(Item::Bytes(b)) => Some(b.clone()),
        _ => None,
    };
    let iss = match get(cwt, 1) {
        Some(Item::Text(t)) => Some(t.clone()),
        _ => None,
    };
    let iat = match get(cwt, 6) {
        Some(Item::Int(n)) => Some(*n),
        _ => None,
    };
    let txid = match ccf_header
        .iter()
        .find(|(k, _)| *k == Key::Text("txid".into()))
    {
        Some((_, Item::Text(t))) => Some(t.clone()),
        _ => None,
    };
    let consistency_present =
        matches!(vdp_of(&rc), Some(Item::Map(vdp)) if get(vdp, CONSISTENCY).is_some());
    Ok(ValidReceipt {
        // Python's `_receipt` (base 3010d4bd): an untagged receipt's proofs parse, but it is not one that
        // parses under the -05 CDDL, so it is not readable.
        readable: ccf && !inclusion.is_empty() && rc.tagged,
        rc,
        kid,
        iss,
        iat,
        txid,
        consistency_present,
        inclusion,
        consistency_newer,
    })
}

// ---------------------------------------------------------------------------------------------------
// The status logic
// ---------------------------------------------------------------------------------------------------
/// One receipt's result: Python's `ReceiptCheck` without `detail`.
#[derive(Default)]
pub struct ReceiptCheck {
    pub index: usize,
    pub status: &'static str,
    pub readable: bool,
    pub signature_valid: Option<bool>,
    pub bound: Option<bool>,
    pub issuer: Option<String>,
    pub kid: Option<Vec<u8>>,
    pub kid_bound_to_key: Option<bool>,
    pub merkle_root: Option<Hash>,
    pub data_hashes: Vec<Hash>,
    pub receipt_iat: Option<i128>,
    pub ccf_txid: Option<String>,
    pub consistency_proofs_present: bool,
}

/// `_crit_ok`: every label crit lists is in the protected header and one v1 processes.
fn crit_ok(ph: &[(Key, Item)], processed: &[i128]) -> bool {
    let Some(Item::Array(crit)) = get(ph, CRIT) else {
        return true;
    };
    crit.iter().all(|label| match label {
        Item::Int(n) => get(ph, *n).is_some() && processed.contains(n),
        _ => false, // a text label is never one v1 processes
    })
}

/// `_receipt_outside`, the attached payload and `_receipt_crit`: the -05 rules a receipt is held to.
fn receipt_outside(v: &ValidReceipt) -> bool {
    let rc = &v.rc;
    let alg_ok = matches!(get(&rc.protected, ALG), Some(Item::Int(a)) if RECEIPT_ALGS.contains(a));
    !rc.tagged
        || !alg_ok
        || !is_ccf(rc)
        || v.kid.is_none()
        || v.iss.is_none()
        || rc.payload.is_some()
        || get(&rc.unprotected, CRIT).is_some()
        || !crit_ok(&rc.protected, &RECEIPT_CRIT_PROCESSED)
}

/// `_receipt_status`: the status of one receipt the CDDL pass accepted.
fn receipt_status(
    index: usize,
    v: &ValidReceipt,
    data_hash: &[u8],
    services: Option<&Value>,
) -> ReceiptCheck {
    let mut out = ReceiptCheck {
        index,
        readable: v.readable,
        issuer: v.iss.clone(),
        kid: v.kid.clone(),
        receipt_iat: v.iat,
        ccf_txid: v.txid.clone(),
        consistency_proofs_present: v.consistency_present,
        ..Default::default()
    };
    if receipt_outside(v) || v.inclusion.is_empty() {
        out.status = OUTSIDE;
        return out;
    }
    let root = v.inclusion[0].0;
    out.merkle_root = Some(root);
    out.data_hashes = v.inclusion.iter().map(|(_, dh)| *dh).collect();
    if v.inclusion.iter().any(|(r, _)| *r != root) || v.consistency_newer.iter().any(|n| *n != root)
    {
        out.status = ROOT_MISMATCH;
        return out;
    }
    let bound = out.data_hashes.iter().all(|dh| dh.as_slice() == data_hash);
    out.bound = Some(bound);
    let trusted = match (services, &v.iss) {
        (Some(Value::Object(s)), Some(iss)) => s.get(iss),
        _ => None,
    };
    let (keys, _) = normalize_keys(trusted);
    let candidates: Vec<&TrustKey> = keys
        .iter()
        .filter(|k| {
            k.kid
                .clone()
                .unwrap_or_else(|| derived_kid(&k.spki))
                .as_slice()
                == v.kid.as_deref().unwrap_or_default()
        })
        .collect();
    if candidates.is_empty() {
        out.status = NEEDS_RP_TRUST;
        return out;
    }
    let tbs = scitt::sig_structure(&v.rc.protected_raw, &root);
    let alg = get(&v.rc.protected, ALG);
    let Some(good) = candidates
        .iter()
        .find(|k| scitt::verify(alg, &k.key, &tbs, &v.rc.signature))
    else {
        out.status = SIGNATURE_INVALID;
        out.signature_valid = Some(false);
        return out;
    };
    out.signature_valid = Some(true);
    out.kid_bound_to_key = Some(Some(derived_kid(&good.spki)) == v.kid);
    out.status = if bound { CONFIRMED } else { RECEIPT_NOT_BOUND };
    out
}

/// `_statement_profile`: is the statement a v1 hash envelope?
fn statement_in_profile(st: &Cose) -> bool {
    let (ph, uh) = (&st.protected, &st.unprotected);
    let alg_ok = matches!(get(ph, ALG), Some(Item::Int(a)) if STATEMENT_ALGS.contains(a));
    st.tagged
        && alg_ok
        && matches!(get(ph, PAYLOAD_HASH_ALG), Some(Item::Int(a)) if *a == SHA256_ALG)
        && get(uh, PREIMAGE_CTY).is_none()
        && get(uh, PAYLOAD_LOCATION).is_none()
        && get(ph, CTY).is_none()
        && get(uh, CTY).is_none()
        && crit_ok(ph, &STATEMENT_CRIT_PROCESSED)
        && get(uh, CRIT).is_none()
        && statement_cwt_in_profile(st)
        && get(ph, X5CHAIN).is_some()
        && st.payload.as_ref().is_some_and(|p| p.len() == 32)
}

/// RFC 9943 section 6, as `_statement_profile` reads it: CWT Claims (label 15) stand in the
/// protected header only, and carry a non-empty text iss (1) and sub (2).
fn statement_cwt_in_profile(st: &Cose) -> bool {
    if get(&st.unprotected, CWT).is_some() {
        return false;
    }
    let Some(Item::Map(cwt)) = get(&st.protected, CWT) else {
        return false;
    };
    [1, 2]
        .iter()
        .all(|c| matches!(get(cwt, *c), Some(Item::Text(t)) if !t.is_empty()))
}

/// Python's `_first`: the first status of STATUS_ORDER among those that are not `confirmed`.
fn first(statuses: &[&'static str]) -> &'static str {
    STATUS_ORDER
        .iter()
        .find(|s| statuses.contains(s))
        .copied()
        .unwrap_or(CONFIRMED)
}

/// Python's `TransparentStatementCheck`, without `detail` and with the number of ignored trust
/// entries in place of their descriptions.
pub struct TransparentStatementCheck {
    pub status: &'static str,
    pub readable: bool,
    pub signature_valid: bool,
    pub statement_status: &'static str,
    pub statement_signature_valid: Option<bool>,
    pub payload_digest: Option<Vec<u8>>,
    pub data_hash: Option<Hash>,
    pub receipts: Vec<ReceiptCheck>,
    pub ignored_trust: usize,
}

impl TransparentStatementCheck {
    fn refused(status: &'static str) -> Self {
        TransparentStatementCheck {
            status,
            readable: false,
            signature_valid: false,
            statement_status: status,
            statement_signature_valid: None,
            payload_digest: None,
            data_hash: None,
            receipts: Vec::new(),
            ignored_trust: 0,
        }
    }

    /// The bytes the input budget refuses before reading are `malformed`, as Python reads them.
    pub fn malformed() -> Self {
        Self::refused(MALFORMED)
    }
}

/// `proofbundle.scitt_ccf.verify_transparent_statement`: a Transparent Statement under
/// `scitt-ccf/v1` against a target's canonical root, under relying-party trust
/// (`scitt_statement_keys`, `scitt_ccf_services`).
pub fn verify_transparent_statement(
    proof: &[u8],
    canonical_root: &[u8],
    rp_trust: &Value,
) -> TransparentStatementCheck {
    let trust = rp_trust.as_object();
    let Ok((st, selector)) = scitt::validate_statement(proof) else {
        return TransparentStatementCheck::malformed();
    };
    // THE CDDL PASS: label 394 in the unprotected header, then every receipt on its own.
    let passed: Option<Vec<Result<ValidReceipt, ()>>> = match get(&st.unprotected, RECEIPTS) {
        Some(Item::Array(receipts)) if !receipts.is_empty() && receipts.len() <= MAX_RECEIPTS => {
            Some(receipts.iter().map(validate_receipt).collect())
        }
        _ => None,
    };
    // readable needs the statement itself to be tagged 18 too (base 3010d4bd, ADR 0009 Decision 10).
    let readable = st.tagged
        && passed
            .as_ref()
            .is_some_and(|p| p.iter().any(|r| r.as_ref().is_ok_and(|v| v.readable)));

    // THE STATUS LOGIC
    let payload_digest = st.payload.clone().filter(|p| p.len() == 32);
    let (statement_status, stmt_valid, ignored) = if !statement_in_profile(&st) {
        (OUTSIDE, None, 0)
    } else if canonical_root.len() != 32 || st.payload.as_deref() != Some(canonical_root) {
        (UNBOUND, None, 0)
    } else {
        statement_signature(
            &st,
            &selector,
            trust.and_then(|t| t.get("scitt_statement_keys")),
        )
    };
    let Some(passed) = passed else {
        return TransparentStatementCheck {
            statement_status,
            statement_signature_valid: stmt_valid,
            payload_digest,
            ..TransparentStatementCheck::malformed()
        };
    };
    let data_hash = st.tagged.then(|| {
        let e = &st.elements;
        sha256(&[&[0xD2, 0x84], &e[0], &[0xA0], &e[2], &e[3]])
    });
    let services = trust.and_then(|t| t.get("scitt_ccf_services"));
    let receipts: Vec<ReceiptCheck> = passed
        .iter()
        .enumerate()
        .map(|(i, r)| match r {
            Ok(v) => receipt_status(
                i,
                v,
                data_hash.as_ref().map_or(&[][..], |h| &h[..]),
                services,
            ),
            Err(()) => ReceiptCheck {
                index: i,
                status: MALFORMED,
                ..Default::default()
            },
        })
        .collect();
    let statuses: Vec<&'static str> = receipts.iter().map(|c| c.status).collect();
    let best = if statuses.contains(&CONFIRMED) {
        CONFIRMED
    } else {
        first(&statuses)
    };
    let status = if statement_status == CONFIRMED {
        best
    } else {
        first(&[statement_status, best])
    };
    TransparentStatementCheck {
        status,
        readable,
        signature_valid: receipts.iter().any(|c| c.signature_valid == Some(true)),
        statement_status,
        statement_signature_valid: stmt_valid,
        payload_digest,
        data_hash,
        receipts,
        ignored_trust: ignored,
    }
}

/// `_statement_signature` under trust read from JSON: (status, valid, ignored entries).
fn statement_signature(
    st: &Cose,
    selector: &Selector,
    entries: Option<&Value>,
) -> (&'static str, Option<bool>, usize) {
    let (keys, ignored) = normalize_keys(entries);
    let keys: Vec<PubKey> = keys.into_iter().map(|k| k.key).collect();
    let (status, valid) = scitt::statement_signature(st, selector, &keys);
    (status, valid, ignored)
}

// ---------------------------------------------------------------------------------------------------
// The result as JSON, the fields and names of Python's `to_dict()` (bytes as hex)
// ---------------------------------------------------------------------------------------------------
fn hex_or_null<T: AsRef<[u8]>>(v: &Option<T>) -> Value {
    v.as_ref()
        .map_or(Value::Null, |b| Value::String(hex::encode(b)))
}

impl TransparentStatementCheck {
    /// One JSON object; `receipt_iat` is written as the integer it is, beyond 64 bits included.
    pub fn to_json(&self) -> String {
        let receipts: Vec<String> = self
            .receipts
            .iter()
            .map(|c| {
                let mut head = serde_json::Map::new();
                head.insert("index".into(), c.index.into());
                head.insert("status".into(), c.status.into());
                head.insert("readable".into(), c.readable.into());
                head.insert("signature_valid".into(), c.signature_valid.into());
                head.insert("bound".into(), c.bound.into());
                head.insert("issuer".into(), c.issuer.clone().into());
                head.insert("kid".into(), hex_or_null(&c.kid));
                head.insert("kid_bound_to_key".into(), c.kid_bound_to_key.into());
                head.insert("merkle_root".into(), hex_or_null(&c.merkle_root));
                head.insert(
                    "data_hashes".into(),
                    c.data_hashes
                        .iter()
                        .map(hex::encode)
                        .collect::<Vec<_>>()
                        .into(),
                );
                head.insert("ccf_txid".into(), c.ccf_txid.clone().into());
                head.insert(
                    "consistency_proofs_present".into(),
                    c.consistency_proofs_present.into(),
                );
                let head = Value::Object(head).to_string();
                let iat = c.receipt_iat.map_or("null".to_string(), |n| n.to_string());
                format!("{},\"receipt_iat\":{iat}}}", &head[..head.len() - 1])
            })
            .collect();
        let mut top = serde_json::Map::new();
        top.insert("status".into(), self.status.into());
        top.insert("readable".into(), self.readable.into());
        top.insert("signature_valid".into(), self.signature_valid.into());
        top.insert(
            "profile_satisfied".into(),
            (self.status == CONFIRMED).into(),
        );
        top.insert("statement_status".into(), self.statement_status.into());
        top.insert(
            "statement_signature_valid".into(),
            self.statement_signature_valid.into(),
        );
        top.insert("payload_digest".into(), hex_or_null(&self.payload_digest));
        top.insert("data_hash".into(), hex_or_null(&self.data_hash));
        top.insert("profile".into(), "scitt-ccf/v1".into());
        top.insert("ignored_trust_count".into(), self.ignored_trust.into());
        let top = Value::Object(top).to_string();
        format!(
            "{},\"receipts\":[{}]}}",
            &top[..top.len() - 1],
            receipts.join(",")
        )
    }

    /// 0 confirmed; 1 a check over the evidence failed; 3 a status that is no verdict about it.
    pub fn exit_class(&self) -> i32 {
        match self.status {
            CONFIRMED => 0,
            UNBOUND | INVALID | ROOT_MISMATCH | SIGNATURE_INVALID | RECEIPT_NOT_BOUND => 1,
            _ => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_order_decides_without_a_confirmed_receipt() {
        assert_eq!(first(&[NEEDS_RP_TRUST, ROOT_MISMATCH]), ROOT_MISMATCH);
        assert_eq!(first(&[CONFIRMED]), CONFIRMED);
        assert_eq!(first(&[OUTSIDE, MALFORMED]), MALFORMED);
    }

    #[test]
    fn the_derived_kid_is_lowercase_hex_of_the_spki_digest() {
        let kid = derived_kid(b"");
        assert_eq!(
            kid,
            b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_vec()
        );
    }

    #[test]
    fn trust_that_is_not_a_list_is_one_ignored_entry() {
        assert_eq!(normalize_keys(None).1, 0);
        assert_eq!(normalize_keys(Some(&Value::Null)).1, 0);
        assert_eq!(normalize_keys(Some(&Value::from("00"))).1, 1);
        assert_eq!(
            normalize_keys(Some(&serde_json::json!(["00", 5, {"spki": 1}]))).1,
            3
        );
    }
}
