//! scitt-ccf/v1 (ADR 0009): a CCF consistency receipt against an older root the caller holds.
//!
//! The Rust side of `proofbundle.scitt_ccf.verify_consistency_receipt`
//! (draft-ietf-scitt-receipts-ccf-profile-05, section 4). The receipt is read by the CDDL pass of
//! `scitt_transparent.rs`, run for the -2 family; this file adds the status logic of section 4 and
//! the order of Python's `CONSISTENCY_STATUS_ORDER`. None of it is shared with the Python module.
//!
//! The result carries the fields of Python's `ConsistencyCheck` but the prose of `detail`.
//!
//! THE TREE SIZES. The command line takes no `older_size` and no `newer_size`, so every call is
//! Python's call without them, and the result is what Python gives for that call: the success is
//! `confirmed_without_tree_sizes`, never `confirmed`; `older_size` is null; `newer_size` is the
//! seqno of this receipt's `ccf.v1` txid, read by Python's rule, once the newer roots agree;
//! neither anchor rule of the sizes runs, so `anchor_rule_checked` and `left_siblings_checked` are
//! false. The exit class of `confirmed_without_tree_sizes` is 0, as for `confirmed`: the status
//! carries the difference.

use serde_json::Value;

use crate::scitt::{self, get, Item, ALG, CONFIRMED, MALFORMED, NEEDS_RP_TRUST, OUTSIDE};
use crate::scitt_transparent::{
    candidates, derived_kid, hex_or_null, receipt_rules_outside, validate_receipt, Hash,
    CONSISTENCY, SIGNATURE_INVALID,
};

const PROOF_MISSING: &str = "consistency_proof_missing";
const PAYLOAD_ATTACHED: &str = "consistency_payload_attached";
const NEWER_ROOTS_DIFFER: &str = "consistency_newer_roots_differ";
const ANCHOR_NOT_CANONICAL: &str = "consistency_anchor_not_canonical";
const OLDER_ROOT_MISMATCH: &str = "consistency_older_root_mismatch";
const ISSUER_MISMATCH: &str = "consistency_issuer_mismatch";
/// Python's `CONFIRMED_WITHOUT_TREE_SIZES`: every check of a call without tree sizes passed. It does
/// not establish strict growth (0 < m < n) or the full anchor rule of section 4.
const CONFIRMED_WITHOUT_TREE_SIZES: &str = "confirmed_without_tree_sizes";
/// Python's `_SIZE_FROM_HEADER`, the source of a newer size the caller did not give.
const SIZE_FROM_HEADER: &str = "protected header ccf.v1 txid";

/// Python's `ConsistencyCheck`, without `detail`.
#[derive(Default)]
pub struct ConsistencyCheck {
    pub status: &'static str,
    pub readable: bool,
    pub signature_valid: Option<bool>,
    pub older_root_matches: Option<bool>,
    pub newer_root: Option<Hash>,
    pub proofs: usize,
    pub issuer: Option<String>,
    pub kid: Option<Vec<u8>>,
    pub kid_bound_to_key: Option<bool>,
    pub receipt_iat: Option<i128>,
    pub ccf_txid: Option<String>,
    pub inclusion_proofs_present: bool,
    /// The seqno of the txid: twenty digits reach past 64 bits, as Python's int does.
    pub newer_size: Option<u128>,
    pub newer_size_source: Option<&'static str>,
}

impl ConsistencyCheck {
    /// The bytes the input budget refuses before reading are `malformed`, as Python reads them.
    pub fn malformed() -> Self {
        ConsistencyCheck {
            status: MALFORMED,
            ..Default::default()
        }
    }
}

/// `proofbundle.scitt_ccf.verify_consistency_receipt`: a CCF consistency receipt against an older
/// root the caller has already verified and the issuer of the receipt it came from, under the
/// relying party's service keys (`scitt_ccf_services`).
pub fn verify_consistency_receipt(
    receipt: &[u8],
    older_root: &[u8],
    older_issuer: &str,
    rp_trust: &Value,
) -> ConsistencyCheck {
    // THE CDDL PASS, before any status: readable is decided there, -2 parsed.
    let Ok(v) = validate_receipt(&Item::Bytes(receipt.to_vec()), CONSISTENCY) else {
        return ConsistencyCheck::malformed();
    };
    let mut out = ConsistencyCheck {
        readable: v.readable,
        issuer: v.iss.clone(),
        kid: v.kid.clone(),
        receipt_iat: v.iat,
        ccf_txid: v.txid.clone(),
        inclusion_proofs_present: v.inclusion_present,
        proofs: v.consistency.len(),
        ..Default::default()
    };
    let done = |mut out: ConsistencyCheck, status| {
        out.status = status;
        out
    };

    // THE STATUS LOGIC, on what the pass accepted
    if receipt_rules_outside(&v) {
        return done(out, OUTSIDE);
    }
    if !v.vdp_present || v.consistency.is_empty() {
        return done(out, PROOF_MISSING); // 4.1: vdp carries -2 with one or more proofs
    }
    if v.rc.payload.is_some() {
        return done(out, PAYLOAD_ATTACHED); // 4.1: the newer root is detached
    }
    let newer = v.consistency[0].1;
    out.newer_root = Some(newer);
    if v.consistency.iter().any(|(_, n, _)| *n != newer)
        || v.inclusion.iter().any(|(r, _)| *r != newer)
    {
        return done(out, NEWER_ROOTS_DIFFER); // 4.1 and section 5: all proofs, one root
    }
    let older_ok =
        older_root.len() == 32 && v.consistency.iter().any(|(o, _, _)| o[..] == *older_root);
    out.older_root_matches = Some(older_ok);

    let services = rp_trust
        .as_object()
        .and_then(|t| t.get("scitt_ccf_services"));
    let keys = candidates(services, &v);
    let tbs = scitt::sig_structure(&v.rc.protected_raw, &newer);
    let alg = get(&v.rc.protected, ALG);
    let good = keys
        .iter()
        .find(|k| scitt::verify(alg, &k.key, &tbs, &v.rc.signature));
    if !keys.is_empty() {
        out.signature_valid = Some(good.is_some());
        out.kid_bound_to_key = good.map(|k| Some(derived_kid(&k.spki)) == v.kid);
    }
    // The tree sizes, where Python sets them: the newer one from the txid, the older one unknown.
    out.newer_size = v.txid.as_deref().and_then(txid_tree_size);
    out.newer_size_source = out.newer_size.map(|_| SIZE_FROM_HEADER);

    if v.consistency.iter().any(|(_, _, first_left)| *first_left) {
        return done(out, ANCHOR_NOT_CANONICAL); // section 4: the anchor's sibling is on its right
    }
    if !older_ok {
        return done(out, OLDER_ROOT_MISMATCH); // 4.2: no proof recomputes the older root held
    }
    if v.iss.as_deref() != Some(older_issuer) {
        return done(out, ISSUER_MISMATCH); // proofbundle's own rule, not a requirement of -05
    }
    if keys.is_empty() {
        return done(out, NEEDS_RP_TRUST);
    }
    if good.is_none() {
        return done(out, SIGNATURE_INVALID);
    }
    // Without the older size neither anchor rule of section 4 ran, nor 0 < m < n.
    done(out, CONFIRMED_WITHOUT_TREE_SIZES)
}

/// Python's `_txid_tree_size`: the seqno of a txid "view.seqno", each part ASCII digits, 0 or
/// without a leading zero, at most twenty of them; anything else is None. That the seqno is the
/// tree size the signature covers is proofbundle's own rule, not a requirement of -05
/// (SECTION4_WGLC.md, G5). Python reports the seqno of a call without sizes as it is, 0 and
/// beyond 2^64 included.
fn txid_tree_size(txid: &str) -> Option<u128> {
    let part = |p: &str| {
        (1..=20).contains(&p.len())
            && p.bytes().all(|b| b.is_ascii_digit())
            && (p == "0" || !p.starts_with('0'))
    };
    let (view, seqno) = txid.split_once('.')?;
    if part(view) && part(seqno) {
        seqno.parse().ok()
    } else {
        None
    }
}

impl ConsistencyCheck {
    /// One JSON object with the fields and names of Python's `to_dict()` but `detail`;
    /// `receipt_iat` and `newer_size` are written as the integers they are, beyond 64 bits included.
    pub fn to_json(&self) -> String {
        let mut m = serde_json::Map::new();
        m.insert("status".into(), self.status.into());
        m.insert("readable".into(), self.readable.into());
        m.insert("signature_valid".into(), self.signature_valid.into());
        m.insert("older_root_matches".into(), self.older_root_matches.into());
        m.insert("newer_root".into(), hex_or_null(&self.newer_root));
        m.insert("proofs".into(), self.proofs.into());
        m.insert("issuer".into(), self.issuer.clone().into());
        m.insert("kid".into(), hex_or_null(&self.kid));
        m.insert("kid_bound_to_key".into(), self.kid_bound_to_key.into());
        m.insert("ccf_txid".into(), self.ccf_txid.clone().into());
        m.insert(
            "inclusion_proofs_present".into(),
            self.inclusion_proofs_present.into(),
        );
        // The command line takes no tree sizes: no older size, and no anchor rule of the sizes ran.
        m.insert("older_size".into(), Value::Null);
        m.insert("newer_size_source".into(), self.newer_size_source.into());
        m.insert("anchor_rule_checked".into(), false.into());
        m.insert("left_siblings_checked".into(), false.into());
        m.insert("profile".into(), "scitt-ccf/v1".into());
        let head = Value::Object(m).to_string();
        let number = |n: Option<String>| n.unwrap_or_else(|| "null".to_string());
        let iat = number(self.receipt_iat.map(|n| n.to_string()));
        let newer_size = number(self.newer_size.map(|n| n.to_string()));
        format!(
            "{},\"newer_size\":{newer_size},\"receipt_iat\":{iat}}}",
            &head[..head.len() - 1]
        )
    }

    /// 0 confirmed or confirmed_without_tree_sizes, the status says which; 1 a check over the
    /// evidence failed; 3 a status that is no verdict about it.
    pub fn exit_class(&self) -> i32 {
        match self.status {
            CONFIRMED | CONFIRMED_WITHOUT_TREE_SIZES => 0,
            NEWER_ROOTS_DIFFER | ANCHOR_NOT_CANONICAL | OLDER_ROOT_MISMATCH | ISSUER_MISMATCH
            | SIGNATURE_INVALID => 1,
            _ => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_that_are_no_receipt_are_malformed_and_unreadable() {
        for bad in [&b""[..], b"\xd2\x84", b"not cbor \xff"] {
            let c = verify_consistency_receipt(bad, &[0; 32], "svc", &Value::Null);
            assert_eq!(
                (c.status, c.readable, c.exit_class()),
                (MALFORMED, false, 3)
            );
        }
    }

    #[test]
    fn the_exit_class_says_whether_a_check_over_the_evidence_failed() {
        let class = |status| {
            ConsistencyCheck {
                status,
                ..Default::default()
            }
            .exit_class()
        };
        assert_eq!(class(CONFIRMED), 0);
        assert_eq!(class(CONFIRMED_WITHOUT_TREE_SIZES), 0);
        for s in [
            NEWER_ROOTS_DIFFER,
            ANCHOR_NOT_CANONICAL,
            OLDER_ROOT_MISMATCH,
            ISSUER_MISMATCH,
            SIGNATURE_INVALID,
        ] {
            assert_eq!(class(s), 1, "{s}");
        }
        for s in [
            MALFORMED,
            OUTSIDE,
            PROOF_MISSING,
            PAYLOAD_ATTACHED,
            NEEDS_RP_TRUST,
        ] {
            assert_eq!(class(s), 3, "{s}");
        }
    }

    #[test]
    fn the_newer_size_is_the_seqno_of_a_txid_by_pythons_rule() {
        let twenty = "9".repeat(20);
        for (txid, want) in [
            ("2.24", Some(24)),
            ("0.0", Some(0)),
            ("2.18446744073709551616", Some(1u128 << 64)),
            (
                &format!("{twenty}.{twenty}")[..],
                Some(twenty.parse().unwrap()),
            ),
            (&format!("2.1{twenty}")[..], None),
            ("2.024", None),
            ("02.24", None),
            ("2.", None),
            (".24", None),
            ("224", None),
            ("2.24.1", None),
            ("2.24\n", None),
            (" 2.24", None),
            ("+2.24", None),
            ("2.2\u{664}", None),
            ("2.2\u{ff14}", None),
        ] {
            assert_eq!(txid_tree_size(txid), want, "{txid:?}");
        }
    }

    #[test]
    fn a_newer_size_past_64_bits_is_written_as_the_integer_it_is() {
        let c = ConsistencyCheck {
            status: CONFIRMED_WITHOUT_TREE_SIZES,
            newer_size: Some(u128::from(u64::MAX) + 1),
            newer_size_source: Some(SIZE_FROM_HEADER),
            ..Default::default()
        };
        let json = c.to_json();
        // serde_json reads past u64 as a float, so the integer is checked in the text itself.
        assert!(
            json.contains("\"newer_size\":18446744073709551616,"),
            "{json}"
        );
        let got: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(got["newer_size_source"], SIZE_FROM_HEADER);
        assert_eq!(got["older_size"], Value::Null);
        assert_eq!(
            (&got["anchor_rule_checked"], &got["left_siblings_checked"]),
            (&Value::Bool(false), &Value::Bool(false))
        );
        assert_eq!(c.exit_class(), 0);
    }
}
