//! scitt-ccf/v1 (ADR 0009): the signature of a SCITT Signed Statement under relying-party keys.
//!
//! The Rust side of `proofbundle.scitt_ccf.verify_statement_signature`. It shares no code with the
//! Python reader: the CBOR reading, the COSE_Sign1 shape, the header types, the x5chain walk and the
//! key checks are written here, and the signatures are verified by the RustCrypto crates `p256`,
//! `p384` and `rsa` (Python uses `cryptography` over OpenSSL). The certificate is parsed by
//! `x509-cert`. Both sides are held to the same vectors in tests/fixtures/scitt_statement_signature/.
//!
//! The result is the pair Python returns: a status and `Some(valid)` for a verdict about the
//! signature, `None` otherwise.

use std::collections::HashSet;

use p256::ecdsa::signature::Verifier;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, Pss, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384};
use x509_cert::der::Decode;

/// ADR 0009, Decision 8: the limits of the profile, counted in bytes of encoded input.
pub const MAX_STATEMENT_BYTES: usize = 65536;
pub(crate) const MAX_DEPTH: usize = 16;
/// Relying-party keys beyond this many are ignored, as in Python.
pub const MAX_TRUSTED_KEYS: usize = 64;
/// The range of a tag-1 time Python accepts: cbor2 turns it into a datetime, whose years run from 1
/// to 9999 (measured with cbor2 6.1.4: one second outside either end is `malformed`).
const TIME_MIN: i128 = -62_135_596_800;
const TIME_MAX: i128 = 253_402_300_799;

pub(crate) const ALG: i128 = 1;
pub(crate) const CRIT: i128 = 2;
pub(crate) const CTY: i128 = 3;
pub(crate) const KID: i128 = 4;
pub(crate) const CWT: i128 = 15;
pub(crate) const X5CHAIN: i128 = 33;
pub(crate) const PAYLOAD_HASH_ALG: i128 = 258;
pub(crate) const PREIMAGE_CTY: i128 = 259;
pub(crate) const PAYLOAD_LOCATION: i128 = 260;
const RSA_BITS: (usize, usize) = (2048, 8192);

pub const CONFIRMED: &str = "confirmed";
pub const INVALID: &str = "statement_signature_invalid";
pub const MALFORMED: &str = "malformed";
pub(crate) const OUTSIDE: &str = "outside_profile";
pub(crate) const NEEDS_RP_TRUST: &str = "needs_rp_trust";

// ---------------------------------------------------------------------------------------------------
// The CBOR reader: one data item over the whole input, definite lengths, shortest heads, integers,
// strings, arrays, maps with integer or text keys each once, false, true and null, and tags only where
// the policy allows them. Anything else is refused, and a refusal is `malformed`.
// ---------------------------------------------------------------------------------------------------
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Key {
    Int(i128),
    Text(String),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Item {
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Item>),
    Map(Vec<(Key, Item)>),
    Tag(u64, Box<Item>),
    Bool(bool),
    Null,
}

/// A step of the position of an item: a map key or an array index read as an integer, or a text
/// key. The position of a map key itself is the text step `<key>`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Step {
    Int(i128),
    Text(String),
}

pub(crate) type TagPolicy = fn(&[Step], u64) -> bool;

pub(crate) fn root_18(path: &[Step], number: u64) -> bool {
    path.is_empty() && number == 18
}

/// Tag 1 around a CWT time claim (4, 5 or 6) of the statement's protected header (owner decision Q8 a).
fn statement_protected_tags(path: &[Step], number: u64) -> bool {
    number == 1
        && path.len() == 2
        && path[0] == Step::Int(CWT)
        && matches!(path[1], Step::Int(4) | Step::Int(5) | Step::Int(6))
}

struct Reader<'a> {
    b: &'a [u8],
    policy: TagPolicy,
}

impl Reader<'_> {
    fn head(&self, i: usize) -> Result<(u8, u64, usize), ()> {
        let ib = *self.b.get(i).ok_or(())?;
        let (mt, ai) = (ib >> 5, ib & 0x1F);
        if ai < 24 {
            return Ok((mt, u64::from(ai), i + 1));
        }
        if (24..=27).contains(&ai) {
            let width = 1usize << (ai - 24);
            let bytes = self.b.get(i + 1..i + 1 + width).ok_or(())?;
            let arg = bytes.iter().fold(0u64, |acc, x| (acc << 8) | u64::from(*x));
            if mt == 7 {
                return Err(()); // a float or an extended simple value
            }
            let smallest = if ai == 24 {
                24
            } else {
                1u64 << (8 * (width / 2))
            };
            if arg < smallest {
                return Err(()); // a head not in its shortest form
            }
            return Ok((mt, arg, i + 1 + width));
        }
        Err(()) // indefinite length, or reserved additional information
    }

    fn item(&self, i: usize, depth: usize, path: &mut Vec<Step>) -> Result<(Item, usize), ()> {
        if depth > MAX_DEPTH {
            return Err(());
        }
        let (mt, arg, i) = self.head(i)?;
        let rest = (self.b.len() - i) as u64;
        match mt {
            0 => Ok((Item::Int(i128::from(arg)), i)),
            1 => Ok((Item::Int(-1 - i128::from(arg)), i)),
            2 | 3 => {
                if arg > rest {
                    return Err(());
                }
                let end = i + arg as usize;
                let raw = self.b[i..end].to_vec();
                if mt == 2 {
                    return Ok((Item::Bytes(raw), end));
                }
                String::from_utf8(raw)
                    .map(|s| (Item::Text(s), end))
                    .map_err(|_| ())
            }
            4 => {
                if arg > rest {
                    return Err(());
                }
                let mut out = Vec::new();
                let mut pos = i;
                for k in 0..arg {
                    path.push(Step::Int(i128::from(k)));
                    let r = self.item(pos, depth + 1, path);
                    path.pop();
                    let (v, next) = r?;
                    out.push(v);
                    pos = next;
                }
                Ok((Item::Array(out), pos))
            }
            5 => {
                if arg > rest / 2 {
                    return Err(());
                }
                let mut out = Vec::new();
                let mut seen: HashSet<Key> = HashSet::new();
                let mut pos = i;
                for _ in 0..arg {
                    path.push(Step::Text("<key>".to_string()));
                    let r = self.item(pos, depth + 1, path);
                    path.pop();
                    let (k, next) = r?;
                    let key = match k {
                        Item::Int(n) => Key::Int(n),
                        Item::Text(t) => Key::Text(t),
                        _ => return Err(()), // a key that is neither an integer nor a text string
                    };
                    if !seen.insert(key.clone()) {
                        return Err(()); // a duplicate map key
                    }
                    path.push(match &key {
                        Key::Int(n) => Step::Int(*n),
                        Key::Text(t) => Step::Text(t.clone()),
                    });
                    let r = self.item(next, depth + 1, path);
                    path.pop();
                    let (v, after) = r?;
                    out.push((key, v));
                    pos = after;
                }
                Ok((Item::Map(out), pos))
            }
            6 => {
                if !(self.policy)(path, arg) {
                    return Err(());
                }
                let (v, next) = self.item(i, depth + 1, path)?;
                match (arg, &v) {
                    (1, Item::Int(t)) if (TIME_MIN..=TIME_MAX).contains(t) => {}
                    (1, _) => return Err(()),
                    (18, Item::Array(_)) => {}
                    (18, _) => return Err(()),
                    _ => {}
                }
                Ok((Item::Tag(arg, Box::new(v)), next))
            }
            _ => match arg {
                20 | 21 => Ok((Item::Bool(arg == 21), i)),
                22 => Ok((Item::Null, i)),
                _ => Err(()), // any other simple value
            },
        }
    }
}

/// Exactly one data item that covers all of `data`, at most `MAX_STATEMENT_BYTES` of it.
pub(crate) fn scan(data: &[u8], policy: TagPolicy) -> Result<Item, ()> {
    scan_spans(data, policy).map(|(v, _)| v)
}

/// `scan`, and the (start, end) offsets of the elements of a top-level array, looked through at most
/// one tag; empty for any other top-level item.
pub(crate) fn scan_spans(
    data: &[u8],
    policy: TagPolicy,
) -> Result<(Item, Vec<(usize, usize)>), ()> {
    if data.len() > MAX_STATEMENT_BYTES {
        return Err(());
    }
    let r = Reader { b: data, policy };
    let (v, end) = r.item(0, 0, &mut Vec::new())?;
    if end != data.len() {
        return Err(()); // trailing bytes
    }
    let (mut mt, mut arg, mut next) = r.head(0)?;
    if mt == 6 {
        (mt, arg, next) = r.head(next)?;
    }
    let mut spans = Vec::new();
    if mt == 4 {
        for k in 0..arg {
            let (_, after) = r.item(next, 1, &mut vec![Step::Int(i128::from(k))])?;
            spans.push((next, after));
            next = after;
        }
    }
    Ok((v, spans))
}

pub(crate) fn get(map: &[(Key, Item)], label: i128) -> Option<&Item> {
    map.iter()
        .find(|(k, _)| *k == Key::Int(label))
        .map(|(_, v)| v)
}

// ---------------------------------------------------------------------------------------------------
// The COSE_Sign1 (RFC 9052 section 4.2) and the header types of a statement (the CDDL pass)
// ---------------------------------------------------------------------------------------------------
/// A COSE_Sign1 as served: its headers, payload and signature, whether it is tagged 18, and the
/// served bytes of its four elements.
pub(crate) struct Cose {
    pub(crate) tagged: bool,
    pub(crate) elements: Vec<Vec<u8>>,
    pub(crate) protected_raw: Vec<u8>,
    pub(crate) protected: Vec<(Key, Item)>,
    pub(crate) unprotected: Vec<(Key, Item)>,
    pub(crate) payload: Option<Vec<u8>>,
    pub(crate) signature: Vec<u8>,
}

/// No tag anywhere: the protected header of a receipt, and a proof.
pub(crate) fn no_tags(_path: &[Step], _number: u64) -> bool {
    false
}

/// Read a COSE_Sign1 (RFC 9052 section 4.2): tag 18 at most at the root, a four-element array, and
/// a protected header whose tags `protected_policy` allows.
pub(crate) fn decode_cose(data: &[u8], protected_policy: TagPolicy) -> Result<Cose, ()> {
    let (top, spans) = scan_spans(data, root_18)?;
    let (tagged, body) = match top {
        Item::Tag(n, inner) => (n == 18, *inner),
        other => (false, other),
    };
    let Item::Array(parts) = body else {
        return Err(());
    };
    if spans.len() != 4 {
        return Err(());
    }
    let [prot, unprot, payload, sig]: [Item; 4] = parts.try_into().map_err(|_| ())?;
    let Item::Bytes(protected_raw) = prot else {
        return Err(());
    };
    let Item::Map(unprotected) = unprot else {
        return Err(());
    };
    let payload = match payload {
        Item::Bytes(p) => Some(p),
        Item::Null => None,
        _ => return Err(()),
    };
    let Item::Bytes(signature) = sig else {
        return Err(());
    };
    if protected_raw.is_empty() {
        return Err(()); // alg must be protected
    }
    let Item::Map(protected) = scan(&protected_raw, protected_policy)? else {
        return Err(());
    };
    if protected
        .iter()
        .any(|(k, _)| unprotected.iter().any(|(u, _)| u == k))
    {
        return Err(()); // a label in both header buckets
    }
    Ok(Cose {
        tagged,
        elements: spans.iter().map(|(a, b)| data[*a..*b].to_vec()).collect(),
        protected_raw,
        protected,
        unprotected,
        payload,
        signature,
    })
}

pub(crate) fn is_int(v: &Item) -> bool {
    matches!(v, Item::Int(_))
}

pub(crate) fn is_uint(v: &Item) -> bool {
    matches!(v, Item::Int(n) if *n >= 0)
}

pub(crate) fn is_label(v: &Item) -> bool {
    matches!(v, Item::Int(_) | Item::Text(_))
}

/// RFC 9360: `COSE_X509 = bstr / [ 2*certs: bstr ]`.
fn is_cose_x509(v: &Item) -> bool {
    match v {
        Item::Bytes(_) => true,
        Item::Array(certs) => certs.len() >= 2 && certs.iter().all(|c| matches!(c, Item::Bytes(_))),
        _ => false,
    }
}

/// A header label and the type its value must have.
type TypeRule = (i128, fn(&Item) -> bool);

/// The statement's header types, in either bucket: RFC 9052, RFC 9360, RFC 9597 and RFC 9995.
fn statement_types_hold(st: &Cose) -> bool {
    let rules: [TypeRule; 9] = [
        (ALG, |v| is_int(v) || matches!(v, Item::Text(_))),
        (
            CRIT,
            |v| matches!(v, Item::Array(a) if !a.is_empty() && a.iter().all(is_label)),
        ),
        (CTY, |v| is_uint(v) || matches!(v, Item::Text(_))),
        (KID, |v| matches!(v, Item::Bytes(_))),
        (CWT, |v| matches!(v, Item::Map(_))),
        (X5CHAIN, is_cose_x509),
        (PAYLOAD_HASH_ALG, is_int),
        (PREIMAGE_CTY, |v| is_uint(v) || matches!(v, Item::Text(_))),
        (PAYLOAD_LOCATION, |v| matches!(v, Item::Text(_))),
    ];
    rules.iter().all(|(label, ok)| {
        [&st.protected, &st.unprotected]
            .iter()
            .all(|bucket| get(bucket, *label).is_none_or(ok))
    })
}

// ---------------------------------------------------------------------------------------------------
// DER, SubjectPublicKeyInfo and the keys v1 verifies with: EC on P-256 and P-384, RSA
// ---------------------------------------------------------------------------------------------------
/// One DER element in `buf[pos..end]` -> (tag, start of content, end of content). Definite,
/// shortest-form lengths of at most four bytes and low tag numbers only.
fn der(buf: &[u8], pos: usize, end: usize) -> Result<(u8, usize, usize), ()> {
    if end < pos + 2 || buf[pos] & 0x1F == 0x1F {
        return Err(());
    }
    let (tag, first) = (buf[pos], buf[pos + 1]);
    let mut pos = pos + 2;
    let length = if first & 0x80 != 0 {
        let n = usize::from(first & 0x7F);
        if !(1..=4).contains(&n) || end - pos < n || buf[pos] == 0 {
            return Err(());
        }
        let length = buf[pos..pos + n]
            .iter()
            .fold(0usize, |acc, x| (acc << 8) | usize::from(*x));
        pos += n;
        if length < 0x80 {
            return Err(());
        }
        length
    } else {
        usize::from(first)
    };
    if end - pos < length {
        return Err(());
    }
    Ok((tag, pos, pos + length))
}

/// A DER INTEGER that is positive and in its shortest form -> (value, end of the element).
fn der_uint(buf: &[u8], pos: usize, end: usize) -> Result<(BigUint, usize), ()> {
    let (tag, s, e) = der(buf, pos, end)?;
    if tag != 0x02
        || e == s
        || buf[s] & 0x80 != 0
        || (e - s > 1 && buf[s] == 0 && buf[s + 1] & 0x80 == 0)
    {
        return Err(());
    }
    Ok((BigUint::from_bytes_be(&buf[s..e]), e))
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum PubKey {
    P256(p256::PublicKey),
    P384(p384::PublicKey),
    Rsa { n: BigUint, e: BigUint },
}

const OID_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];

/// SubjectPublicKeyInfo DER -> a key of the type it names, or `Err` for any key v1 does not verify
/// with, before a key object exists. The RSA numbers are held to the checks `cryptography` makes
/// when it builds a key from them: n at least 3, e odd, at least 3 and below n.
pub(crate) fn key_from_spki(spki: &[u8]) -> Result<PubKey, ()> {
    let (tag, s, e) = der(spki, 0, spki.len())?;
    if tag != 0x30 || e != spki.len() {
        return Err(());
    }
    let (tag, a, a_end) = der(spki, s, e)?;
    if tag != 0x30 {
        return Err(());
    }
    let (tag, o, o_end) = der(spki, a, a_end)?;
    let (tag_bits, b, b_end) = der(spki, a_end, e)?;
    if tag != 0x06 || tag_bits != 0x03 || b_end != e || b_end == b || spki[b] != 0 {
        return Err(());
    }
    let (oid, params, bits) = (&spki[o..o_end], &spki[o_end..a_end], &spki[b + 1..b_end]);
    if oid == OID_EC {
        if params.is_empty() {
            return Err(());
        }
        let (tag, c, c_end) = der(params, 0, params.len())?;
        if tag != 0x06 || c_end != params.len() {
            return Err(());
        }
        let n = match &params[c..c_end] {
            x if x == OID_P256 => 32,
            x if x == OID_P384 => 48,
            _ => return Err(()),
        };
        let shape = (bits.len() == 1 + 2 * n && bits[0] == 4)
            || (bits.len() == 1 + n && (bits[0] == 2 || bits[0] == 3));
        if !shape {
            return Err(());
        }
        return if n == 32 {
            p256::PublicKey::from_sec1_bytes(bits)
                .map(PubKey::P256)
                .map_err(|_| ())
        } else {
            p384::PublicKey::from_sec1_bytes(bits)
                .map(PubKey::P384)
                .map_err(|_| ())
        };
    }
    if oid == OID_RSA {
        if params != [0x05, 0x00] {
            return Err(());
        }
        let (tag, r, r_end) = der(bits, 0, bits.len())?;
        if tag != 0x30 || r_end != bits.len() {
            return Err(());
        }
        let (n, r) = der_uint(bits, r, r_end)?;
        let (e, r) = der_uint(bits, r, r_end)?;
        if r != r_end {
            return Err(());
        }
        let three = BigUint::from(3u8);
        let e_odd = e.to_bytes_be().last().is_some_and(|b| b & 1 == 1);
        if n < three || e < three || e >= n || !e_odd {
            return Err(());
        }
        return Ok(PubKey::Rsa { n, e });
    }
    Err(())
}

/// The subjectPublicKeyInfo of a DER Certificate: its TBSCertificate, then after the optional
/// version, serialNumber, signature, issuer, validity and subject (RFC 5280, section 4.1).
fn certificate_spki(cert: &[u8]) -> Result<&[u8], ()> {
    let (tag, s, e) = der(cert, 0, cert.len())?;
    if tag != 0x30 {
        return Err(());
    }
    let (tag, t, t_end) = der(cert, s, e)?;
    if tag != 0x30 {
        return Err(());
    }
    let mut pos = t;
    let (tag, _, end) = der(cert, pos, t_end)?;
    if tag == 0xA0 {
        pos = end;
    }
    for want in [0x02, 0x30, 0x30, 0x30, 0x30] {
        let (tag, _, end) = der(cert, pos, t_end)?;
        if tag != want {
            return Err(());
        }
        pos = end;
    }
    let (tag, _, end) = der(cert, pos, t_end)?;
    if tag != 0x30 {
        return Err(());
    }
    Ok(&cert[pos..end])
}

// ---------------------------------------------------------------------------------------------------
// The signature
// ---------------------------------------------------------------------------------------------------
/// RFC 9052 section 4.4 ToBeSigned of a COSE_Sign1, external_aad empty by profile.
pub(crate) fn sig_structure(protected_raw: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x84, 0x6A];
    out.extend_from_slice(b"Signature1");
    out.extend(bstr_head(protected_raw.len()));
    out.extend_from_slice(protected_raw);
    out.push(0x40);
    out.extend(bstr_head(payload.len()));
    out.extend_from_slice(payload);
    out
}

pub(crate) fn bstr_head(len: usize) -> Vec<u8> {
    let len = len as u64;
    match len {
        0..=23 => vec![0x40 | len as u8],
        24..=0xFF => vec![0x58, len as u8],
        0x100..=0xFFFF => [vec![0x59], (len as u16).to_be_bytes().to_vec()].concat(),
        0x1_0000..=0xFFFF_FFFF => [vec![0x5A], (len as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![0x5B], len.to_be_bytes().to_vec()].concat(),
    }
}

/// True only if `alg` belongs to the key's type and curve AND the signature verifies.
pub(crate) fn verify(alg: Option<&Item>, key: &PubKey, tbs: &[u8], sig: &[u8]) -> bool {
    let Some(Item::Int(alg)) = alg else {
        return false;
    };
    match (*alg, key) {
        (-7, PubKey::P256(pk)) => {
            sig.len() == 64
                && p256::ecdsa::Signature::from_slice(sig)
                    .map(|s| p256::ecdsa::VerifyingKey::from(pk).verify(tbs, &s).is_ok())
                    .unwrap_or(false)
        }
        (-35, PubKey::P384(pk)) => {
            sig.len() == 96
                && p384::ecdsa::Signature::from_slice(sig)
                    .map(|s| p384::ecdsa::VerifyingKey::from(pk).verify(tbs, &s).is_ok())
                    .unwrap_or(false)
        }
        (-37 | -38, PubKey::Rsa { n, e }) => {
            let bits = n.bits();
            if !(RSA_BITS.0..=RSA_BITS.1).contains(&bits) {
                return false;
            }
            let Ok(pk) = RsaPublicKey::new_with_max_size(n.clone(), e.clone(), RSA_BITS.1) else {
                return false;
            };
            // Measured on the Python side (OpenSSL): a signature shorter than the modulus is read
            // as the number it encodes, one that is longer is refused.
            let k = pk.size();
            if sig.len() > k {
                return false;
            }
            let mut padded = vec![0u8; k - sig.len()];
            padded.extend_from_slice(sig);
            // The signature is a number below n (RFC 8017, RSASSA-PSS-VERIFY step 2a, as OpenSSL
            // checks it). The rsa crate reduces it modulo n without that check, so s + n would pass.
            if BigUint::from_bytes_be(&padded) >= *n {
                return false;
            }
            if *alg == -37 {
                pk.verify(
                    Pss::new_with_salt::<Sha256>(32),
                    &Sha256::digest(tbs),
                    &padded,
                )
                .is_ok()
            } else {
                pk.verify(
                    Pss::new_with_salt::<Sha384>(48),
                    &Sha384::digest(tbs),
                    &padded,
                )
                .is_ok()
            }
        }
        _ => false,
    }
}

/// The statement key selector (owner answer N4 b): `None` without a protected x5chain, else the
/// end-entity key, `Some(None)` when it is a key v1 does not verify with. Never trust.
pub(crate) type Selector = Option<Option<PubKey>>;

/// `_validate_statement`: the statement's COSE_Sign1, its header types and its x5chain certificate.
/// `Err` is `malformed`.
pub(crate) fn validate_statement(data: &[u8]) -> Result<(Cose, Selector), ()> {
    let st = decode_cose(data, statement_protected_tags)?;
    if !statement_types_hold(&st) {
        return Err(());
    }
    let selector = match get(&st.protected, X5CHAIN) {
        None => None,
        Some(chain) => {
            let leaf = match chain {
                Item::Bytes(b) => b,
                Item::Array(certs) => match certs.first() {
                    Some(Item::Bytes(b)) => b,
                    _ => return Err(()),
                },
                _ => return Err(()),
            };
            if x509_cert::Certificate::from_der(leaf).is_err() {
                return Err(()); // the end-entity certificate is not DER X.509
            }
            Some(certificate_spki(leaf).and_then(key_from_spki).ok())
        }
    };
    Ok((st, selector))
}

/// Relying-party keys, SubjectPublicKeyInfo DER as hex: the first `MAX_TRUSTED_KEYS`, each one v1
/// verifies with; any other entry is absent trust, never trust.
pub(crate) fn usable_keys(keys_hex: &[&str]) -> Vec<PubKey> {
    keys_hex
        .iter()
        .take(MAX_TRUSTED_KEYS)
        .filter_map(|h| hex::decode(h).ok())
        .filter_map(|spki| key_from_spki(&spki).ok())
        .collect()
}

/// `_statement_signature`: the statement's signature under the relying party's statement keys.
pub(crate) fn statement_signature(
    st: &Cose,
    selector: &Selector,
    keys: &[PubKey],
) -> (&'static str, Option<bool>) {
    let Some(payload) = &st.payload else {
        return (OUTSIDE, None); // a detached payload
    };
    let Some(leaf_key) = selector else {
        return (OUTSIDE, None); // no protected x5chain
    };
    if keys.is_empty() {
        return (NEEDS_RP_TRUST, None);
    }
    let candidates: Vec<&PubKey> = keys
        .iter()
        .filter(|k| leaf_key.as_ref() == Some(*k))
        .collect();
    if candidates.is_empty() {
        return (NEEDS_RP_TRUST, None);
    }
    let tbs = sig_structure(&st.protected_raw, payload);
    let alg = get(&st.protected, ALG);
    if candidates
        .iter()
        .any(|k| verify(alg, k, &tbs, &st.signature))
    {
        (CONFIRMED, Some(true))
    } else {
        (INVALID, Some(false))
    }
}

/// `proofbundle.scitt_ccf.verify_statement_signature`: the ToBeSigned of a statement and its
/// signature under relying-party statement keys (SubjectPublicKeyInfo DER, as hex).
pub fn verify_statement_signature(data: &[u8], keys_hex: &[&str]) -> (&'static str, Option<bool>) {
    let Ok((st, selector)) = validate_statement(data) else {
        return (MALFORMED, None);
    };
    statement_signature(&st, &selector, &usable_keys(keys_hex))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_head_not_in_its_shortest_form_is_refused() {
        assert!(scan(&[0x18, 0x17], root_18).is_err());
        assert!(scan(&[0x18, 0x18], root_18).is_ok());
    }

    #[test]
    fn a_duplicate_key_and_a_trailing_byte_are_refused() {
        assert!(scan(&[0xA2, 0x01, 0x01, 0x01, 0x02], root_18).is_err());
        assert!(scan(&[0x01, 0x00], root_18).is_err());
    }

    #[test]
    fn the_sig_structure_has_shortest_heads() {
        let tbs = sig_structure(&[0xA1, 0x01, 0x26], &[0x11; 32]);
        assert_eq!(&tbs[..2], &[0x84, 0x6A]);
        assert_eq!(tbs.len(), 2 + 10 + 1 + 3 + 1 + 2 + 32);
    }
}
