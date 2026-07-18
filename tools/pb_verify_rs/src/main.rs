//! Independent read-only proofbundle cross-implementation verifier (3.2.0 O8).
//!
//! This binary shares NO canonicalization or parser code with the Python implementation: it uses
//! the Rust `serde_jcs` crate for RFC 8785 (a different implementation than Python's `rfc8785`
//! package), `ed25519-dalek` for Ed25519 (RFC 8032), and `sha2` for SHA-256. Its job is to AGREE
//! with the Python verifier on the pinned conformance corpus and the shared crypto test vectors —
//! cross-implementation agreement, not a re-use of the same code.
//!
//! Subcommands (read-only; nothing is written, no network I/O):
//!   content-root <statement.json>              -> jcs-sha256-v1 content root (hex) of a statement
//!   verify-dsse  <envelope.json> <pubkey_b64>  -> DSSE Ed25519 verify over the exact PAE bytes
//!   merkle-root  <leaf_hex>...                 -> RFC 6962 tree head of the given leaves
//!   strict-parse <file.json>                   -> ok, or reject a duplicate JSON key (parser-differential)
//!   verify-bundle <bundle.json> [flags]        -> native proofbundle bundle exit-code contract
//!   verify-trust-pack-threshold <envelope.json> -> trust-pack/v0.1 root-of-trust THRESHOLD check (Ed25519
//!                                                  leg only; see VERIFIED_SUBCOMMANDS / Finding 11)
//!   coverage-report                            -> JSON self-declaration of the subcommands above (single
//!                                                  source of truth consumed by scripts/rust_parity_gate.py
//!                                                  in the Python repo — never hand-duplicate this list)

use std::collections::HashSet;
use std::fmt;
use std::process::exit;

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Strict JSON: reject a duplicate key at every object level (the C1 Bishop-Fox
// parser-differential defense — Python rejects it via _strict_json; we must too).
// ---------------------------------------------------------------------------
struct StrictValue(serde_json::Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = serde_json::Value;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("any JSON value with no duplicate object keys")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Number(v.into()))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Number(v.into()))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                serde_json::Number::from_f64(v)
                    .map(serde_json::Value::Number)
                    .ok_or_else(|| de::Error::custom("non-finite float is not valid JSON"))
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(serde_json::Value::String(v.to_owned()))
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Null)
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Null)
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut out = Vec::new();
                while let Some(StrictValue(v)) = seq.next_element()? {
                    out.push(v);
                }
                Ok(serde_json::Value::Array(out))
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut seen: HashSet<String> = HashSet::new();
                let mut obj = serde_json::Map::new();
                while let Some(k) = map.next_key::<String>()? {
                    if !seen.insert(k.clone()) {
                        return Err(de::Error::custom(format!("duplicate JSON key: {k}")));
                    }
                    let StrictValue(v) = map.next_value()?;
                    obj.insert(k, v);
                }
                Ok(serde_json::Value::Object(obj))
            }
        }
        d.deserialize_any(V).map(StrictValue)
    }
}

fn strict_parse(bytes: &[u8]) -> Result<serde_json::Value, String> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let v = StrictValue::deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(v.0)
}

// ---------------------------------------------------------------------------
// RFC 8785 JCS content root (jcs-sha256-v1): sha256 over the canonical bytes.
// serde_jcs is an INDEPENDENT RFC 8785 implementation (not Python's rfc8785).
// ---------------------------------------------------------------------------
fn jcs_bytes(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(value).map_err(|e| format!("JCS canonicalization failed: {e}"))
}

fn content_root_hex(value: &serde_json::Value) -> Result<String, String> {
    let canon = jcs_bytes(value)?;
    let mut h = Sha256::new();
    h.update(&canon);
    Ok(hex::encode(h.finalize()))
}

// ---------------------------------------------------------------------------
// DSSE PAE + Ed25519 verify (RFC 8032). PAE = "DSSEv1 SP LEN(type) SP type SP LEN(body) SP body".
// ---------------------------------------------------------------------------
fn dsse_pae(payload_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(body.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(body);
    out
}

fn b64_std(s: &str) -> Result<Vec<u8>, String> {
    // DSSE emits standard base64; accept standard, fall back to url-safe (spec allows either on verify).
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s.trim()))
        .map_err(|e| format!("base64 decode failed: {e}"))
}

// The in-toto Statement payload type every proofbundle receipt/statement is signed under. The
// relation paths pin it (mirror of Python's payload_type pin in dsse.verify_envelope); the generic
// verify-dsse subcommand passes None so it stays a type-agnostic DSSE primitive.
const INTOTO_STATEMENT_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

fn verify_dsse(
    envelope: &serde_json::Value,
    pubkey_b64: &str,
    expected_payload_type: Option<&str>,
) -> Result<bool, String> {
    let payload_type = envelope
        .get("payloadType")
        .and_then(|v| v.as_str())
        .ok_or("envelope has no string payloadType")?;
    // Type-confusion defense (mirror of Python dsse.verify_envelope's payload_type pin —
    // relation_statement.py:189-190 / cli.py:1241-1242): when an expected payloadType is given it
    // MUST equal the envelope's payloadType BEFORE the PAE is built. A Sign/Verify type mismatch
    // silently changes the PAE, so an envelope carrying the WRONG payloadType is rejected fail-closed
    // here instead of being authenticated under its own attacker-chosen type (Rust fail-open, fixed).
    if let Some(expected) = expected_payload_type {
        if payload_type != expected {
            return Ok(false);
        }
    }
    let payload_b64 = envelope
        .get("payload")
        .and_then(|v| v.as_str())
        .ok_or("envelope has no string payload")?;
    let body = b64_std(payload_b64)?;
    let msg = dsse_pae(payload_type, &body);

    let pk_bytes = b64_std(pubkey_b64)?;
    let pk_arr: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "public key is not 32 bytes".to_string())?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| format!("bad public key: {e}"))?;

    let sigs = envelope
        .get("signatures")
        .and_then(|v| v.as_array())
        .ok_or("envelope has no signatures array")?;
    for s in sigs {
        let Some(sig_b64) = s.get("sig").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(sig_bytes) = b64_std(sig_b64) else {
            continue;
        };
        let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.as_slice().try_into() else {
            continue;
        };
        let sig = Signature::from_bytes(&sig_arr);
        if vk.verify(&msg, &sig).is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}

// ---------------------------------------------------------------------------
// RFC 6962 Merkle tree head over given leaf hashes (leaves already hashed, hex).
// node = SHA256(0x01 || left || right); a single leaf is its own head.
// ---------------------------------------------------------------------------
fn rfc6962_tree_head(mut level: Vec<Vec<u8>>) -> Result<String, String> {
    if level.is_empty() {
        // RFC 6962 empty tree = SHA256() of the empty string.
        let mut h = Sha256::new();
        h.update([]);
        return Ok(hex::encode(h.finalize()));
    }
    while level.len() > 1 {
        let mut next = Vec::new();
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let mut h = Sha256::new();
                h.update([0x01]);
                h.update(&level[i]);
                h.update(&level[i + 1]);
                next.push(h.finalize().to_vec());
                i += 2;
            } else {
                next.push(level[i].clone());
                i += 1;
            }
        }
        level = next;
    }
    Ok(hex::encode(&level[0]))
}

// ---------------------------------------------------------------------------
// RFC 6962 / RFC 9162 inclusion-proof root recomputation (matches merkle.py exactly).
// ---------------------------------------------------------------------------
fn leaf_hash(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().to_vec()
}

fn node_hash(l: &[u8], r: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(l);
    h.update(r);
    h.finalize().to_vec()
}

fn root_from_inclusion(
    mut fnn: u64,
    tree_size: u64,
    computed_leaf: Vec<u8>,
    proof: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    if fnn >= tree_size {
        return Err("leaf_index out of range for tree_size".into());
    }
    let mut sn = tree_size - 1;
    let mut r = computed_leaf;
    for p in proof {
        if sn == 0 {
            return Err("inclusion proof too long".into());
        }
        if (fnn & 1) == 1 || fnn == sn {
            r = node_hash(p, &r);
            if (fnn & 1) == 0 {
                while (fnn & 1) == 0 && fnn != 0 {
                    fnn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnn >>= 1;
        sn >>= 1;
    }
    if sn != 0 {
        return Err("inclusion proof too short".into());
    }
    Ok(r)
}

fn b64url_nopad(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|e| format!("base64url decode failed: {e}"))
}

// ---------------------------------------------------------------------------
// SD-JWT VC issuer-authenticity slice (partial): verifies the issuer Ed25519 signature over the
// compact SD-JWT and fail-closes on a holder-bound (`cnf`) credential whose Key Binding JWT this
// slice does not yet verify. Reproduces the sd-jwt-unsigned / forged-issuer / signed-but-unbound
// corpus verdicts; the eval-root-graft and KB-JWT-detail checks are pending slices.
// Ok(true) => the sd-jwt part is acceptable; Ok(false) => reject (contributes exit 1).
// ---------------------------------------------------------------------------
fn verify_sdjwt_issuer(
    sd: &serde_json::Value,
    bundle_payload: &serde_json::Value,
    merkle_root_b64: &str,
) -> Result<bool, String> {
    let compact = sd
        .get("compact")
        .and_then(|v| v.as_str())
        .ok_or("sd_jwt_vc.compact must be a string")?;
    // No issuer public key supplied => the disclosures are unauthenticated (bundle.py WP-C2) => reject.
    let Some(issuer_pub_b64) = sd.get("issuer_public_key_b64").and_then(|v| v.as_str()) else {
        return Ok(false);
    };
    let parts: Vec<&str> = compact.split('~').collect();
    let jwt: Vec<&str> = parts[0].split('.').collect();
    if jwt.len() != 3 {
        return Ok(false);
    }
    let (hdr_b64, pl_b64, sig_b64) = (jwt[0], jwt[1], jwt[2]);
    // strict-parse header + payload (a duplicate JSON key here is a parser-differential => reject).
    let header = match strict_parse(&b64url_nopad(hdr_b64)?) {
        Ok(h) => h,
        Err(_) => return Ok(false),
    };
    let payload = match strict_parse(&b64url_nopad(pl_b64)?) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };
    if !header.is_object() || !payload.is_object() {
        return Ok(false);
    }
    if header.get("alg").and_then(|v| v.as_str()) != Some("EdDSA") {
        return Ok(false);
    }
    // issuer Ed25519 signature over the signing input `header_b64.payload_b64`.
    let pk = b64_std(issuer_pub_b64)?;
    let pk_arr: [u8; 32] = pk.as_slice().try_into().map_err(|_| "issuer key not 32 bytes")?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| format!("bad issuer key: {e}"))?;
    let signing_input = format!("{hdr_b64}.{pl_b64}");
    let sig_bytes = b64url_nopad(sig_b64)?;
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.as_slice().try_into() else {
        return Ok(false);
    };
    if vk.verify(signing_input.as_bytes(), &Signature::from_bytes(&sig_arr)).is_err() {
        return Ok(false);
    }
    // Holder binding: an issuer-bound `cnf` requires proof-of-possession (a valid KB-JWT). This slice
    // does not yet verify the KB-JWT, so it fail-closes on any `cnf`-bound credential rather than pass an
    // unverified holder binding (this is the correct fail-closed posture; the true KB-JWT check is pending).
    if payload.get("cnf").is_some() {
        return Ok(false);
    }
    // N1 eval-root-graft: an SD-JWT that carries the always-open eval commitment `receipt.root_b64` MUST
    // bind to a proofbundle eval-claim payload (its passed/threshold/comparator/suite/issuer match the
    // signed bundle payload AND its receipt.root_b64 equals the bundle merkle root). Grafted onto a
    // non-eval payload it has nothing to bind to -> reject (matches bundle.py check_binds_bundle + the
    // _sd_jwt_carries_eval_root_commitment elif). A generic SD-JWT with no receipt commitment is in scope.
    let sd_receipt_root = payload
        .get("receipt")
        .and_then(|r| r.get("root_b64"))
        .and_then(|v| v.as_str());
    if let Some(rroot) = sd_receipt_root {
        let binds = ["passed", "threshold", "comparator", "suite", "issuer"]
            .iter()
            .all(|f| bundle_payload.get(*f).is_some() && bundle_payload.get(*f) == payload.get(*f))
            && rroot == merkle_root_b64;
        if !binds {
            return Ok(false);
        }
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Native bundle verify — the CLI exit-code contract (0 crypto OK · 1 verification
// failure · 2 malformed · 3 policy unmet). This slice covers Ed25519 signature over
// the raw payload, RFC 6962 Merkle inclusion, and relying-party root/tree-size
// authentication. It does NOT yet verify the optional `sd_jwt_vc` block or external
// anchors (documented pending slices) — so it is used only for the cases whose
// deciding check is signature / merkle / root / tree-size / strict-parse.
// Err(..) => malformed (exit 2); Ok(true) => verified (0); Ok(false) => failure (1).
// ---------------------------------------------------------------------------
fn verify_bundle(
    b: &serde_json::Value,
    expected_root: Option<&str>,
    expected_tree_size: Option<u64>,
) -> Result<bool, String> {
    let payload_b64 = b
        .get("payload_b64")
        .and_then(|v| v.as_str())
        .ok_or("missing payload_b64")?;
    let payload = b64_std(payload_b64).map_err(|e| format!("payload_b64: {e}"))?;

    let sig = b.get("signature").ok_or("missing signature")?;
    let pub_b64 = sig
        .get("public_key_b64")
        .and_then(|v| v.as_str())
        .ok_or("missing signature.public_key_b64")?;
    let sig_b64 = sig
        .get("sig_b64")
        .and_then(|v| v.as_str())
        .ok_or("missing signature.sig_b64")?;
    let pk = b64_std(pub_b64)?;
    let pk_arr: [u8; 32] = pk.as_slice().try_into().map_err(|_| "public key not 32 bytes")?;
    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|e| format!("bad public key: {e}"))?;
    let sb = b64_std(sig_b64)?;
    let sa: [u8; 64] = sb.as_slice().try_into().map_err(|_| "signature not 64 bytes")?;
    // ed25519 over the RAW payload bytes (bundle.py: verify_ed25519(pub, raw_sig, payload)).
    if vk.verify(&payload, &Signature::from_bytes(&sa)).is_err() {
        return Ok(false);
    }

    let mk = b.get("merkle").ok_or("missing merkle")?;
    let leaf_index = mk
        .get("leaf_index")
        .and_then(|v| v.as_u64())
        .ok_or("missing merkle.leaf_index")?;
    let tree_size = mk
        .get("tree_size")
        .and_then(|v| v.as_u64())
        .ok_or("missing merkle.tree_size")?;
    let proof_list = mk
        .get("inclusion_proof_b64")
        .and_then(|v| v.as_array())
        .ok_or("missing merkle.inclusion_proof_b64")?;
    let mut proof = Vec::new();
    for p in proof_list {
        proof.push(b64_std(p.as_str().ok_or("inclusion proof entry not a string")?)?);
    }
    let root = b64_std(
        mk.get("root_b64")
            .and_then(|v| v.as_str())
            .ok_or("missing merkle.root_b64")?,
    )?;
    let computed = match root_from_inclusion(leaf_index, tree_size, leaf_hash(&payload), &proof) {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };
    if computed != root {
        return Ok(false);
    }
    // relying-party root authentication (P0-A): the stated root is not signed, so a supplied
    // expectation must match bit-exactly.
    if let Some(er) = expected_root {
        if root != b64_std(er)? {
            return Ok(false);
        }
    }
    if let Some(ets) = expected_tree_size {
        if tree_size != ets {
            return Ok(false);
        }
    }
    // optional SD-JWT VC block (issuer authenticity + eval-graft slice; see verify_sdjwt_issuer).
    if let Some(sd) = b.get("sd_jwt_vc") {
        let bundle_payload = strict_parse(&payload).unwrap_or(serde_json::Value::Null);
        let root_b64_str = mk.get("root_b64").and_then(|v| v.as_str()).unwrap_or("");
        if !verify_sdjwt_issuer(sd, &bundle_payload, root_b64_str)? {
            return Ok(false);
        }
    }
    Ok(true)
}

// WP-A1 anchor trust: a bundle's own `frozen` block header is producer-controlled and is NEVER trusted
// (reported as evidence only). An anchor is CONFIRMED only by relying-party trust material (a supplied
// Bitcoin block header for the attested height) — which this offline CLI does not accept — so under
// `--require-anchor` no anchor confirms and the requirement is unmet (exit 3), exactly like Python's
// _anchor_required_ok=False. This faithfully reproduces the SECURITY DECISION (reject own-frozen); it does
// not parse the OTS binary proof or verify a real block header, which would be needed to CONFIRM a genuine
// RP-supplied anchor (no corpus case exercises that — `--bitcoin-header` is not an allowed verifyArg).
fn anchor_rp_confirmed(_bundle: &serde_json::Value) -> bool {
    false
}

// ---------------------------------------------------------------------------
// Finding 11 (Rust second-verifier parity): the ONE list of subcommands this binary actually
// implements as a read-only cross-implementation CHECK (excludes `coverage-report` itself and the
// pure-utility `content-root` / `merkle-root` / `strict-parse` primitives — those are already
// self-evident from `main`'s usage line). `coverage-report` prints exactly this array as JSON, so
// scripts/rust_parity_gate.py (Python repo) can cross-check a claimed-COVERED registry entry
// against what the binary ACTUALLY exposes, instead of trusting a hand-maintained doc (the failure
// mode CROSS_IMPLEMENTATION_REPORT.md drifted into before this gate existed). Keep this array and
// the `match` arms in `main()` in sync BY HAND — `tests/test_rust_parity_gate.py` on the Python side
// greps main.rs's match arms independently and fails if this array and the real dispatch disagree.
const VERIFY_SUBCOMMANDS: &[&str] =
    &["verify-dsse", "verify-bundle", "verify-trust-pack-threshold", "verify-relation", "verify-relation-statement"];

// ---------------------------------------------------------------------------
// trust-pack/v0.1 root-of-trust THRESHOLD verify (Finding 11 first portation, Ed25519 leg only).
// Mirrors proofbundle.trust_pack.verify_trust_pack's `root_threshold_met` computation: count DISTINCT
// non-revoked ROOT KEY MATERIAL (not keyId labels — aliasing must not inflate the threshold, exactly
// like the Python `valid_root: dict[bytes, str]` dedup) with a valid Ed25519 signature over the exact
// DSSE PAE bytes, and require it to be >= the declared threshold.
//
// HONEST SCOPE (No-Overclaim): this slice covers ONLY `alg: "ed25519"` root keys (the default and by
// far the common case). `mldsa65` / `hybrid-ed25519-mldsa65` root keys are NOT implemented here (no
// ML-DSA crate in this binary) — a non-ed25519 root key is SKIPPED (never silently treated as valid,
// never fatal) and surfaced in the printed diagnostic as `skipped_non_ed25519`. It does NOT check
// `not_expired`, `version_monotone`, `prevVersionDigest` chaining, two-stage rotation authorization, or
// full predicate-shape validation — those remain Python-only (see CROSS_IMPLEMENTATION_REPORT.md /
// scripts/rust_parity_gate.py PENDING entries for trust_pack.verify_trust_pack).
// Ok(true)/Ok(false) => threshold met/not met (contributes exit 0/1); Err(..) => malformed (exit 2).
fn verify_trust_pack_threshold(envelope: &serde_json::Value) -> Result<(bool, u64, u64, u64), String> {
    let payload_type = envelope
        .get("payloadType")
        .and_then(|v| v.as_str())
        .ok_or("envelope has no string payloadType")?;
    let payload_b64 = envelope
        .get("payload")
        .and_then(|v| v.as_str())
        .ok_or("envelope has no string payload")?;
    let body = b64_std(payload_b64)?;
    let msg = dsse_pae(payload_type, &body);

    let statement = strict_parse(&body)?;
    let predicate = statement.get("predicate").ok_or("statement has no predicate")?;
    let keys = predicate.get("keys").and_then(|v| v.as_object()).ok_or("predicate.keys missing")?;
    let revoked: HashSet<String> = predicate
        .get("revoked")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let root_role = predicate
        .get("roles")
        .and_then(|r| r.get("root"))
        .ok_or("predicate.roles.root missing")?;
    let root_ids: HashSet<String> = root_role
        .get("keyIds")
        .and_then(|v| v.as_array())
        .ok_or("predicate.roles.root.keyIds missing")?
        .iter()
        .filter_map(|x| x.as_str().map(String::from))
        .filter(|k| !revoked.contains(k))
        .collect();
    let threshold = root_role
        .get("threshold")
        .and_then(|v| v.as_u64())
        .ok_or("predicate.roles.root.threshold missing")?;

    let mut valid_root: HashSet<[u8; 32]> = HashSet::new();
    let mut skipped_non_ed25519: u64 = 0;
    for entry in envelope.get("signatures").and_then(|v| v.as_array()).ok_or("envelope.signatures missing")? {
        let Some(kid) = entry.get("keyid").and_then(|v| v.as_str()) else { continue };
        if !root_ids.contains(kid) {
            continue;
        }
        let Some(kv) = keys.get(kid) else { continue };
        let alg = kv.get("alg").and_then(|v| v.as_str()).unwrap_or("ed25519");
        if alg != "ed25519" {
            skipped_non_ed25519 += 1; // honest scope: mldsa65 / hybrid legs are PENDING, never counted
            continue;
        }
        let Some(pub_b64) = kv.get("publicKey").and_then(|v| v.as_str()) else { continue };
        let Ok(pk_bytes) = b64_std(pub_b64) else { continue };
        let Ok(pk_arr): Result<[u8; 32], _> = pk_bytes.as_slice().try_into() else { continue };
        if valid_root.contains(&pk_arr) {
            continue; // same key material already counted under a different keyId (aliasing defense)
        }
        let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else { continue };
        let Some(sig_b64) = entry.get("sig").and_then(|v| v.as_str()) else { continue };
        let Ok(sig_bytes) = b64_std(sig_b64) else { continue };
        let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.as_slice().try_into() else { continue };
        if vk.verify(&msg, &Signature::from_bytes(&sig_arr)).is_ok() {
            valid_root.insert(pk_arr);
        }
    }
    let met = (valid_root.len() as u64) >= threshold;
    Ok((met, valid_root.len() as u64, threshold, skipped_non_ed25519))
}

// ===========================================================================
// relation/v0.1 + relation-statement/v0.1 lineage engine (3.5.0 WP-B, Rust parity).
//
// An INDEPENDENT port of proofbundle.relation (validate_relationships /
// verify_relationship_edges / successor_warning / evaluate_relations_policy) and the CLI
// _load_related plumbing. It shares NO canonicalizer/parser code with Python (serde_json +
// serde_jcs + ed25519-dalek only) — the whole point is two independent parsers agreeing on the
// SAME conformance vectors (differential agreement, NOT a correctness proof of either side).
//
// Fail-closed identical to Python: unknown fields/enums, malformed digests, cycles and depth
// violations are errors, never silent passes. lineage/policy NEVER touch the crypto verdict
// (lattice monotonicity): a retracts is a visible declared state, not a crypto kill.
// ===========================================================================
const RELATIONS: &[&str] = &[
    "supersedes", "revises", "corrects", "retracts", "renews", "derivedFrom", "amends",
];
const SUCCESSOR_RELATIONS: &[&str] = &["supersedes", "revises", "corrects"];
const REASON_CODES: &[&str] = &[
    "correction", "rerun", "data-update", "methodology-update", "policy-change", "withdrawal", "other",
];
const CONTENT_ROOT_ALGS: &[&str] = &["jcs-sha256-v1"];
const EDGE_ALLOWED: &[&str] = &[
    "relation", "targetReceiptDigest", "targetSubjectDigest", "reason", "reasonCode", "declaredAt",
];
const DIGEST_ALLOWED: &[&str] = &["digestAlgorithm", "digest"];
const MAX_CHAIN_DEPTH: u32 = 32;
const MAX_EDGES_PER_RECEIPT: usize = 64;

const LINEAGE_VERIFIED: &str = "VERIFIED";
const LINEAGE_DECLARED_UNRESOLVED: &str = "DECLARED_UNRESOLVED";
const LINEAGE_FAIL: &str = "FAIL";
const LINEAGE_NOT_EVALUATED: &str = "NOT_EVALUATED";

const RELATION_STATEMENT_PREDICATE_TYPE: &str =
    "https://b7n0de.com/proofbundle/predicates/relation-statement/v0.1";

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_rfc3339_z(s: &str) -> bool {
    // ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$ — a hand parser (no regex crate).
    let b = s.as_bytes();
    if b.len() < 20 || *b.last().unwrap() != b'Z' {
        return false;
    }
    let digit = |i: usize| b.get(i).map(|c| c.is_ascii_digit()).unwrap_or(false);
    let lit = |i: usize, c: u8| b.get(i) == Some(&c);
    if !(digit(0) && digit(1) && digit(2) && digit(3) && lit(4, b'-') && digit(5) && digit(6)
        && lit(7, b'-') && digit(8) && digit(9) && lit(10, b'T') && digit(11) && digit(12)
        && lit(13, b':') && digit(14) && digit(15) && lit(16, b':') && digit(17) && digit(18))
    {
        return false;
    }
    // position 19 is either 'Z' (len 20) or '.' followed by >=1 digit then 'Z'.
    if b.len() == 20 {
        return b[19] == b'Z';
    }
    if b[19] != b'.' {
        return false;
    }
    let frac = &b[20..b.len() - 1];
    !frac.is_empty() && frac.iter().all(|c| c.is_ascii_digit())
}

fn validate_edge_digest(obj: &serde_json::Value, errors: &mut Vec<String>) {
    let Some(map) = obj.as_object() else {
        errors.push("targetDigest must be an object".into());
        return;
    };
    for k in map.keys() {
        if !DIGEST_ALLOWED.contains(&k.as_str()) {
            errors.push(format!("digest unknown field {k}"));
        }
    }
    match map.get("digestAlgorithm").and_then(|v| v.as_str()) {
        None => errors.push("digestAlgorithm is required (never defaulted)".into()),
        Some(a) if !CONTENT_ROOT_ALGS.contains(&a) => {
            errors.push(format!("digestAlgorithm {a} not registered"))
        }
        _ => {}
    }
    match map.get("digest").and_then(|v| v.as_str()) {
        Some(d) if is_sha256_hex(d) => {}
        _ => errors.push("digest must be 64 lowercase hex chars".into()),
    }
}

/// Mirror of relation.validate_relationships — returns a list of errors (empty == valid).
fn validate_relationships(value: &serde_json::Value) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();
    let Some(arr) = value.as_array() else {
        return vec!["relationships must be a JSON array of edge objects".into()];
    };
    if arr.is_empty() {
        errors.push("relationships must not be an empty array".into());
    }
    if arr.len() > MAX_EDGES_PER_RECEIPT {
        errors.push(format!("relationships > hard cap {MAX_EDGES_PER_RECEIPT}"));
    }
    for edge in arr {
        let Some(map) = edge.as_object() else {
            errors.push("edge must be a JSON object".into());
            continue;
        };
        for k in map.keys() {
            if !EDGE_ALLOWED.contains(&k.as_str()) {
                errors.push(format!("edge unknown field {k}"));
            }
        }
        for req in ["relation", "targetReceiptDigest"] {
            if !map.contains_key(req) {
                errors.push(format!("edge.{req} is required"));
            }
        }
        if let Some(rel) = map.get("relation") {
            if !rel.as_str().map(|s| RELATIONS.contains(&s)).unwrap_or(false) {
                errors.push("edge.relation not in closed vocabulary".into());
            }
        }
        if let Some(t) = map.get("targetReceiptDigest") {
            validate_edge_digest(t, &mut errors);
        }
        if let Some(t) = map.get("targetSubjectDigest") {
            validate_edge_digest(t, &mut errors);
        }
        if let Some(rc) = map.get("reasonCode") {
            if !rc.as_str().map(|s| REASON_CODES.contains(&s)).unwrap_or(false) {
                errors.push("edge.reasonCode not in vocabulary".into());
            }
        }
        if let Some(reason) = map.get("reason") {
            if !reason.is_string() {
                errors.push("edge.reason must be a string".into());
            }
        }
        if let Some(da) = map.get("declaredAt") {
            if !da.as_str().map(is_rfc3339_z).unwrap_or(false) {
                errors.push("edge.declaredAt must be RFC3339 Z".into());
            }
        }
    }
    errors
}

fn edge_target_hex(edge: &serde_json::Value) -> Option<String> {
    edge.get("targetReceiptDigest")?.get("digest")?.as_str().map(String::from)
}
fn edge_subject_hex(edge: &serde_json::Value) -> Option<String> {
    edge.get("targetSubjectDigest")?.get("digest")?.as_str().map(String::from)
}

/// An attached target (mirrors the AttachedTarget mapping from _load_related).
struct TargetInfo {
    verified: bool,
    verified_under: String,
    subject_digest: Option<String>,
    relationships: Option<serde_json::Value>,
}

struct EdgeOut {
    relation: Option<String>,
    target_digest: Option<String>,
    resolution: String,
    verified_under: Option<String>,
}

struct LineageResult {
    lineage: String,
    edges: Vec<EdgeOut>,
    superseded_by_attached: Option<String>,
}

/// DFS per-path cycle + depth walk (mirror relation._walk_chain). Returns Some(error) on a cycle
/// or depth violation, else None. `proven_safe` memoises subtrees so a diamond DAG is not a cycle.
fn walk_chain(
    start_hex: &str,
    related: &std::collections::HashMap<String, TargetInfo>,
    seen: &HashSet<String>,
    max_depth: u32,
) -> Option<String> {
    let mut proven_safe: HashSet<String> = HashSet::new();
    fn dfs(
        node_hex: &str,
        depth: u32,
        path: &HashSet<String>,
        related: &std::collections::HashMap<String, TargetInfo>,
        proven_safe: &mut HashSet<String>,
        max_depth: u32,
    ) -> Option<String> {
        if depth > max_depth {
            return Some(format!("relation:depth_exceeded: chain deeper than {max_depth}"));
        }
        if path.contains(node_hex) {
            return Some("relation:cycle: attached chain revisits a receipt on its own ancestry path".into());
        }
        if proven_safe.contains(node_hex) {
            return None;
        }
        let Some(node) = related.get(node_hex) else {
            proven_safe.insert(node_hex.to_string());
            return None;
        };
        let Some(nested) = &node.relationships else {
            proven_safe.insert(node_hex.to_string());
            return None;
        };
        if !validate_relationships(nested).is_empty() {
            return Some("relation:malformed_ancestor: attached target carries a malformed relationships block".into());
        }
        let mut next_path = path.clone();
        next_path.insert(node_hex.to_string());
        if let Some(arr) = nested.as_array() {
            for edge in arr {
                if let Some(nxt) = edge_target_hex(edge) {
                    if related.contains_key(&nxt) || next_path.contains(&nxt) {
                        if let Some(err) = dfs(&nxt, depth + 1, &next_path, related, proven_safe, max_depth) {
                            return Some(err);
                        }
                    }
                }
            }
        }
        proven_safe.insert(node_hex.to_string());
        None
    }
    let mut path = seen.clone();
    // dfs treats `path` as the ancestry-in-progress; seed it empty of start but carry seen.
    dfs(start_hex, 1, &{ let mut p = HashSet::new(); p.extend(path.drain()); p }, related, &mut proven_safe, max_depth)
}

/// Mirror of relation.verify_relationship_edges.
fn verify_relationship_edges(
    relationships: Option<&serde_json::Value>,
    related: &std::collections::HashMap<String, TargetInfo>,
    subject_hex: Option<&str>,
) -> LineageResult {
    let Some(rels) = relationships else {
        return LineageResult { lineage: LINEAGE_NOT_EVALUATED.into(), edges: vec![], superseded_by_attached: None };
    };
    if !validate_relationships(rels).is_empty() {
        return LineageResult { lineage: LINEAGE_FAIL.into(), edges: vec![], superseded_by_attached: None };
    }
    let empty: Vec<serde_json::Value> = Vec::new();
    let arr = rels.as_array().unwrap_or(&empty);
    let mut edges_out: Vec<EdgeOut> = Vec::new();
    let (mut any_fail, mut any_unresolved, mut any_verified) = (false, false, false);
    for edge in arr {
        let target_hex = edge_target_hex(edge);
        let mut entry = EdgeOut {
            relation: edge.get("relation").and_then(|v| v.as_str()).map(String::from),
            target_digest: target_hex.clone(),
            resolution: LINEAGE_DECLARED_UNRESOLVED.into(),
            verified_under: None,
        };
        if subject_hex.is_some() && target_hex.as_deref() == subject_hex {
            entry.resolution = LINEAGE_FAIL.into();
        } else if let Some(th) = &target_hex {
            if let Some(target) = related.get(th) {
                if !target.verified {
                    entry.resolution = LINEAGE_FAIL.into(); // attached-but-unverified = present-and-wrong
                } else {
                    let mut seed: HashSet<String> = HashSet::new();
                    if let Some(s) = subject_hex {
                        seed.insert(s.to_string());
                    }
                    if walk_chain(th, related, &seed, MAX_CHAIN_DEPTH).is_some() {
                        entry.resolution = LINEAGE_FAIL.into();
                    } else {
                        entry.verified_under = Some(target.verified_under.clone());
                        // PB-2026-0717-01 fail-closed: a DECLARED targetSubjectDigest requires a
                        // present, well-formed, EQUAL actual subject. subject_digest is None whenever
                        // the resolved target subject is absent / ambiguous (>1) / malformed (the
                        // loader normalises those to None), and that case now FAILs — before 3.6.1 it
                        // fell into VERIFIED (the False Accept). No declared pin -> optional (verified).
                        let declared_subj = edge_subject_hex(edge);
                        entry.resolution = match declared_subj {
                            None => LINEAGE_VERIFIED.into(),
                            Some(d) => match &target.subject_digest {
                                Some(a) if &d == a => LINEAGE_VERIFIED.into(),
                                _ => LINEAGE_FAIL.into(), // absent / ambiguous / malformed / mismatch
                            },
                        };
                    }
                }
            }
            // else: target absent -> stays DECLARED_UNRESOLVED
        }
        match entry.resolution.as_str() {
            LINEAGE_FAIL => any_fail = true,
            LINEAGE_DECLARED_UNRESOLVED => any_unresolved = true,
            LINEAGE_VERIFIED => any_verified = true,
            _ => {}
        }
        edges_out.push(entry);
    }
    let lineage = if any_fail {
        LINEAGE_FAIL
    } else if any_unresolved {
        LINEAGE_DECLARED_UNRESOLVED
    } else if any_verified {
        LINEAGE_VERIFIED
    } else {
        LINEAGE_NOT_EVALUATED
    };
    LineageResult { lineage: lineage.into(), edges: edges_out, superseded_by_attached: None }
}

/// Mirror of relation.successor_warning: an attached, verified receipt declaring a successor/retracts
/// edge over `subject_hex`.
fn successor_warning(
    related: &std::collections::HashMap<String, TargetInfo>,
    subject_hex: Option<&str>,
) -> Option<String> {
    let subject = subject_hex?;
    for (other_hex, other) in related {
        if !other.verified {
            continue;
        }
        let Some(nested) = &other.relationships else { continue };
        if !nested.is_array() || !validate_relationships(nested).is_empty() {
            continue;
        }
        for edge in nested.as_array().unwrap() {
            let rel = edge.get("relation").and_then(|v| v.as_str());
            if edge_target_hex(edge).as_deref() == Some(subject) {
                if let Some(r) = rel {
                    if SUCCESSOR_RELATIONS.contains(&r) {
                        return Some(format!("superseded_by_attached: {} declares {r}", &other_hex[..12.min(other_hex.len())]));
                    }
                    if r == "retracts" {
                        return Some(format!("retracted_by_attached: {} declares retracts", &other_hex[..12.min(other_hex.len())]));
                    }
                }
            }
        }
    }
    None
}

fn keys_equal(a_b64: &str, b_b64: &str) -> bool {
    let da = base64::engine::general_purpose::STANDARD.decode(a_b64.trim());
    let db = base64::engine::general_purpose::STANDARD.decode(b_b64.trim());
    match (da, db) {
        (Ok(ra), Ok(rb)) => ra.len() == 32 && ra == rb,
        _ => false,
    }
}

struct Violation {
    // The stable policy-verdict code (RELATION_SIGNER_UNAUTHORIZED / RELATION_TARGET_MISMATCH /
    // LINEAGE_REQUIREMENT_FAILED). The differential compares exit CLASS + lineage, not the code text
    // (the code-text assertion is the Python side's errorContains), so the field is retained for
    // parity/debuggability but not emitted.
    #[allow(dead_code)]
    code: String,
}

/// Mirror of relation.evaluate_relations_policy (require_relation_resolution / reject_superseded /
/// relation_signer / require_relation_target). successor_key_b64 = the issuer key of the receipt/
/// statement under verification.
fn evaluate_relations_policy(
    relations: &serde_json::Value,
    lineage: &LineageResult,
    successor_key_b64: &str,
) -> Vec<Violation> {
    let mut out: Vec<Violation> = Vec::new();
    let Some(relmap) = relations.as_object() else { return out };

    // (1) require_relation_resolution
    if let Some(req) = relmap.get("require_relation_resolution").and_then(|v| v.as_array()) {
        let names: Vec<&str> = req.iter().filter_map(|v| v.as_str()).collect();
        for e in &lineage.edges {
            if let Some(r) = &e.relation {
                if names.contains(&r.as_str()) && e.resolution != LINEAGE_VERIFIED {
                    out.push(Violation { code: "LINEAGE_REQUIREMENT_FAILED".into() });
                }
            }
        }
    }
    // (2) reject_superseded
    if relmap.get("reject_superseded").and_then(|v| v.as_bool()).unwrap_or(false)
        && lineage.superseded_by_attached.is_some()
    {
        out.push(Violation { code: "LINEAGE_REQUIREMENT_FAILED".into() });
    }
    // (3) relation_signer
    if let Some(signer) = relmap.get("relation_signer").and_then(|v| v.as_object()) {
        for e in &lineage.edges {
            let Some(rel) = &e.relation else { continue };
            let Some(rule) = signer.get(rel).and_then(|v| v.as_object()) else { continue };
            match rule.get("mode").and_then(|v| v.as_str()) {
                Some("pinned") => {
                    let keys: Vec<&str> = rule
                        .get("keys").and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                        .unwrap_or_default();
                    if !keys.iter().any(|k| keys_equal(successor_key_b64, k)) {
                        out.push(Violation { code: "RELATION_SIGNER_UNAUTHORIZED".into() });
                    }
                }
                Some("same-key") => {
                    if e.resolution == LINEAGE_VERIFIED {
                        // PB-2026-0717-04 fail-closed: a VERIFIED same-key edge REQUIRES a present
                        // verified_under that byte-matches the successor key; a missing/None
                        // verified_under is unauthorized (was a fail-open footgun on the direct
                        // related-API path — before 3.6.1 it produced no violation).
                        match &e.verified_under {
                            Some(vu) if keys_equal(successor_key_b64, vu) => {}
                            _ => out.push(Violation { code: "RELATION_SIGNER_UNAUTHORIZED".into() }),
                        }
                    }
                }
                _ => {}
            }
        }
    }
    // (4) require_relation_target
    if let Some(pin) = relmap.get("require_relation_target").and_then(|v| v.as_object()) {
        for e in &lineage.edges {
            let Some(rel) = &e.relation else { continue };
            let Some(pinned) = pin.get(rel) else { continue };
            let allowed: Vec<String> = match pinned {
                serde_json::Value::Array(a) => a.iter().filter_map(|v| v.as_str().map(String::from)).collect(),
                serde_json::Value::String(s) => vec![s.clone()],
                _ => vec![],
            };
            let td = e.target_digest.clone().unwrap_or_default();
            if !allowed.iter().any(|x| x == &td) {
                out.push(Violation { code: "RELATION_TARGET_MISMATCH".into() });
            }
        }
    }
    out
}

// --- CLI plumbing: load attached targets, key by raw-payload content root (mirror _load_related) ---
fn statement_content_root_hex(payload: &[u8]) -> String {
    // Python statement_content_root = SHA-256 over the EXACT payload bytes (verifier path, never
    // re-canonicalized). We must key targets identically.
    let mut h = Sha256::new();
    h.update(payload);
    hex::encode(h.finalize())
}

fn load_related(
    paths: &[String],
    related_pubs: &[String],
    main_pub_b64: &str,
    expected_payload_type: &str,
) -> Result<std::collections::HashMap<String, TargetInfo>, String> {
    let mut related = std::collections::HashMap::new();
    for (i, path) in paths.iter().enumerate() {
        let rp = related_pubs.get(i).map(|s| s.as_str()).filter(|s| !s.is_empty());
        let verify_key_b64 = rp.unwrap_or(main_pub_b64);
        let env = strict_parse(&read_file(path)).map_err(|e| format!("cannot read --with-related {path}: {e}"))?;
        let payload_b64 = env.get("payload").and_then(|v| v.as_str()).ok_or("related has no payload")?;
        let body = b64_std(payload_b64)?;
        let root_hex = statement_content_root_hex(&body);
        // Pin the in-toto payloadType exactly like Python _load_related (cli.py:1241-1242): a related
        // target carrying the WRONG payloadType is attached-but-unverified, never authenticated.
        let verified = verify_dsse(&env, verify_key_b64, Some(expected_payload_type)).unwrap_or(false);
        let mut relationships = None;
        let mut subject_digest = None;
        if let Ok(stmt) = strict_parse(&body) {
            if let Some(pred) = stmt.get("predicate") {
                if let Some(r) = pred.get("relationships") {
                    relationships = Some(r.clone());
                }
            }
            // PB-2026-0717-01: only bind an UNAMBIGUOUS, well-formed actual subject. An empty subject
            // array (absent), MULTIPLE subjects (ambiguous — never silently take subject[0]), or a
            // malformed sha256 all leave subject_digest = None, which the verifier treats fail-closed
            // against a declared targetSubjectDigest pin.
            subject_digest = stmt
                .get("subject").and_then(|v| v.as_array())
                .filter(|a| a.len() == 1)
                .and_then(|a| a.first())
                .and_then(|s| s.get("digest"))
                .and_then(|d| d.get("sha256"))
                .and_then(|v| v.as_str())
                .filter(|s| is_sha256_hex(s))
                .map(String::from);
        }
        // verified_under = the base64 key the target actually verified under (main pub or --related-pub).
        let verified_under = base64::engine::general_purpose::STANDARD
            .encode(b64_std(verify_key_b64)?);
        related.insert(root_hex, TargetInfo { verified, verified_under, subject_digest, relationships });
    }
    Ok(related)
}

/// Shared relation verify: returns (exit_code, lineage_state). statement_mode enforces the
/// relation-statement predicateType + exactly-one-edge structure gate.
fn run_verify_relation(
    envelope: &serde_json::Value,
    pub_b64: &str,
    related_paths: &[String],
    related_pubs: &[String],
    policy: Option<&serde_json::Value>,
    statement_mode: bool,
) -> (i32, String) {
    // Crypto FIRST (exit 1 on failure). Pin the in-toto payloadType (mirror of Python
    // relation_statement.py:189-190 / the decision/outcome verify paths) so a statement/receipt
    // presented under the WRONG payloadType fails crypto here, never authenticated under a foreign type.
    let crypto_ok = verify_dsse(envelope, pub_b64, Some(INTOTO_STATEMENT_PAYLOAD_TYPE)).unwrap_or(false);
    if !crypto_ok {
        return (1, "null".into());
    }
    let Some(payload_b64) = envelope.get("payload").and_then(|v| v.as_str()) else {
        return (2, "null".into());
    };
    let Ok(body) = b64_std(payload_b64) else { return (2, "null".into()) };
    let Ok(statement) = strict_parse(&body) else { return (2, "null".into()) };
    let predicate = statement.get("predicate");

    // Structure gate — compute a flag but do NOT early-return: Python computes `lineage` over the
    // exact signed bytes REGARDLESS of a structure error (only after crypto passes), then applies the
    // exit ladder. Mirroring that ordering keeps BOTH the lineage state AND the exit class in sync on
    // every vector (SPEC §3.2). For the statement path structure = predicateType + closed top fields +
    // exactly-one-edge; the decision/outcome path's full predicate-schema validation is Python-only
    // (honestly PARTIAL in the registry) and never the deciding axis of a relation vector.
    let mut structure_ok = true;
    if statement_mode {
        if statement.get("predicateType").and_then(|v| v.as_str()) != Some(RELATION_STATEMENT_PREDICATE_TYPE) {
            structure_ok = false;
        }
        if let Some(pred) = predicate.and_then(|v| v.as_object()) {
            for k in pred.keys() {
                if !["schemaVersion", "statementId", "relationships"].contains(&k.as_str()) {
                    structure_ok = false; // additionalProperties:false, fail-closed
                }
            }
            match pred.get("relationships").and_then(|v| v.as_array()) {
                Some(a) if a.len() == 1 => {}
                _ => structure_ok = false,
            }
        } else {
            structure_ok = false;
        }
    }

    let relationships = predicate.and_then(|p| p.get("relationships"));
    let subject_hex = statement_content_root_hex(&body);

    let related = match load_related(related_paths, related_pubs, pub_b64, INTOTO_STATEMENT_PAYLOAD_TYPE) {
        Ok(r) => r,
        Err(_) => return (2, "null".into()),
    };

    let mut lineage = verify_relationship_edges(relationships, &related, Some(&subject_hex));
    lineage.superseded_by_attached = successor_warning(&related, Some(&subject_hex));
    let lineage_state = lineage.lineage.clone();

    // Exit ladder, mirroring Python order: structure (2) · lineage FAIL (2) · policy (3).
    if !structure_ok {
        return (2, lineage_state);
    }
    if lineage_state == LINEAGE_FAIL {
        return (2, lineage_state);
    }

    // Relations policy gate (exit 3 class).
    if let Some(pol) = policy {
        if let Some(relations) = pol.get("relations") {
            if relations.is_object() {
                let succ_key = base64::engine::general_purpose::STANDARD.encode(
                    b64_std(pub_b64).unwrap_or_default());
                let mut viol = evaluate_relations_policy(relations, &lineage, &succ_key);
                // Standalone self-assertion gate (relation-statement only): reject_retracted /
                // reject_superseded fire on the statement's OWN verified edge.
                if statement_mode {
                    if let Some(e0) = lineage.edges.first() {
                        let resolved = e0.resolution == LINEAGE_VERIFIED;
                        let rel0 = e0.relation.as_deref().unwrap_or("");
                        let relmap = relations.as_object();
                        let flag = |name: &str| relmap
                            .and_then(|m| m.get(name)).and_then(|v| v.as_bool()).unwrap_or(false);
                        if resolved && flag("reject_retracted") && rel0 == "retracts" {
                            viol.push(Violation { code: "LINEAGE_REQUIREMENT_FAILED".into() });
                        }
                        if resolved && flag("reject_superseded") && SUCCESSOR_RELATIONS.contains(&rel0) {
                            viol.push(Violation { code: "LINEAGE_REQUIREMENT_FAILED".into() });
                        }
                    }
                }
                if !viol.is_empty() {
                    return (3, lineage_state);
                }
            }
        }
    }
    (0, lineage_state)
}

/// CLI dispatch for the two relation subcommands: parse
/// `<envelope> <pub_b64> [--with-related P]... [--related-pub B]... [--policy P]`, run the shared
/// engine, print the lineage as a JSON report (so crosscheck.py maps it through the ONE
/// common_vocabulary.label_from_verify) and exit with the 0/1/2/3 contract.
fn dispatch_verify_relation(args: &[String], cmd: &str, statement_mode: bool) -> ! {
    let path = args.get(2).unwrap_or_else(|| fatal(&format!("{cmd} needs an envelope file")));
    let pub_b64 = args.get(3).unwrap_or_else(|| fatal(&format!("{cmd} needs a base64 public key")));
    let mut related_paths: Vec<String> = Vec::new();
    let mut related_pubs: Vec<String> = Vec::new();
    let mut policy_path: Option<String> = None;
    let mut i = 4;
    while i < args.len() {
        match args[i].as_str() {
            "--with-related" => {
                related_paths.push(args.get(i + 1).cloned().unwrap_or_else(|| fatal("--with-related needs a path")));
                i += 2;
            }
            "--related-pub" => {
                related_pubs.push(args.get(i + 1).cloned().unwrap_or_else(|| fatal("--related-pub needs a value")));
                i += 2;
            }
            "--policy" => {
                policy_path = Some(args.get(i + 1).cloned().unwrap_or_else(|| fatal("--policy needs a path")));
                i += 2;
            }
            other => fatal(&format!("unknown {cmd} flag: {other}")),
        }
    }
    let env = match strict_parse(&read_file(path)) {
        Ok(v) => v,
        Err(_) => {
            println!("{{\"lineage\":null}}");
            exit(2);
        }
    };
    let policy = policy_path
        .as_ref()
        .map(|p| strict_parse(&read_file(p)).unwrap_or_else(|e| fatal(&format!("bad --policy: {e}"))));
    let (code, lineage) =
        run_verify_relation(&env, pub_b64, &related_paths, &related_pubs, policy.as_ref(), statement_mode);
    if lineage == "null" {
        println!("{{\"lineage\":null}}");
    } else {
        println!("{{\"lineage\":\"{lineage}\"}}");
    }
    exit(code);
}

fn read_file(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| fatal(&format!("cannot read {path}: {e}")))
}

fn fatal(msg: &str) -> ! {
    eprintln!("error: {msg}");
    exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "usage: pb_verify_rs <content-root|verify-dsse|merkle-root|strict-parse|verify-bundle|\
verify-trust-pack-threshold|verify-relation|verify-relation-statement|coverage-report> ..."
        );
        exit(2);
    }
    match args[1].as_str() {
        "content-root" => {
            let path = args.get(2).unwrap_or_else(|| fatal("content-root needs a file"));
            let v = strict_parse(&read_file(path)).unwrap_or_else(|e| fatal(&e));
            match content_root_hex(&v) {
                Ok(root) => println!("{root}"),
                Err(e) => fatal(&e),
            }
        }
        "verify-dsse" => {
            let path = args.get(2).unwrap_or_else(|| fatal("verify-dsse needs an envelope file"));
            let pk = args.get(3).unwrap_or_else(|| fatal("verify-dsse needs a base64 public key"));
            let v = strict_parse(&read_file(path)).unwrap_or_else(|e| fatal(&e));
            // Generic DSSE primitive: no expected-type pin (the relation paths pin in-toto themselves).
            match verify_dsse(&v, pk, None) {
                Ok(true) => {
                    println!("OK");
                    exit(0);
                }
                Ok(false) => {
                    println!("FAIL");
                    exit(1);
                }
                Err(e) => fatal(&e),
            }
        }
        "merkle-root" => {
            let leaves: Result<Vec<Vec<u8>>, _> =
                args[2..].iter().map(|h| hex::decode(h)).collect();
            let leaves = leaves.unwrap_or_else(|e| fatal(&format!("bad leaf hex: {e}")));
            match rfc6962_tree_head(leaves) {
                Ok(root) => println!("{root}"),
                Err(e) => fatal(&e),
            }
        }
        "verify-bundle" => {
            let path = args.get(2).unwrap_or_else(|| fatal("verify-bundle needs a bundle file"));
            let mut expected_root: Option<String> = None;
            let mut expected_tree_size: Option<u64> = None;
            let mut require_anchor = false;
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--expected-root" => {
                        expected_root = Some(args.get(i + 1).cloned().unwrap_or_else(|| {
                            fatal("--expected-root needs a value")
                        }));
                        i += 2;
                    }
                    "--expected-tree-size" => {
                        expected_tree_size = Some(
                            args.get(i + 1)
                                .and_then(|s| s.parse().ok())
                                .unwrap_or_else(|| fatal("--expected-tree-size needs an integer")),
                        );
                        i += 2;
                    }
                    // --anchor-type / --anchor-target imply --require-anchor (WP-A1).
                    "--require-anchor" => {
                        require_anchor = true;
                        i += 1;
                    }
                    "--allow-pending" => i += 1,
                    "--anchor-type" | "--anchor-target" => {
                        require_anchor = true;
                        i += 2;
                    }
                    other => fatal(&format!("unknown verify-bundle flag: {other}")),
                }
            }
            // strict parse first: a duplicate JSON key / malformed bundle is exit 2 (malformed).
            let v = match strict_parse(&read_file(path)) {
                Ok(v) => v,
                Err(_) => {
                    println!("MALFORMED");
                    exit(2);
                }
            };
            match verify_bundle(&v, expected_root.as_deref(), expected_tree_size) {
                Ok(true) => {
                    // relying-party --require-anchor gate layered over the crypto result (exit 3 policy unmet).
                    if require_anchor && !anchor_rp_confirmed(&v) {
                        println!("POLICY_UNMET");
                        exit(3);
                    }
                    println!("OK");
                    exit(0);
                }
                Ok(false) => {
                    println!("FAIL");
                    exit(1);
                }
                Err(_) => {
                    println!("MALFORMED");
                    exit(2);
                }
            }
        }
        "strict-parse" => {
            let path = args.get(2).unwrap_or_else(|| fatal("strict-parse needs a file"));
            match strict_parse(&read_file(path)) {
                Ok(_) => {
                    println!("OK");
                    exit(0);
                }
                Err(e) => {
                    println!("REJECT: {e}");
                    exit(1);
                }
            }
        }
        "verify-trust-pack-threshold" => {
            let path = args
                .get(2)
                .unwrap_or_else(|| fatal("verify-trust-pack-threshold needs an envelope file"));
            let v = match strict_parse(&read_file(path)) {
                Ok(v) => v,
                Err(_) => {
                    println!("MALFORMED");
                    exit(2);
                }
            };
            match verify_trust_pack_threshold(&v) {
                Ok((true, signers, threshold, skipped)) => {
                    println!(
                        "OK root_threshold_met=true signers={signers} threshold={threshold} skipped_non_ed25519={skipped}"
                    );
                    exit(0);
                }
                Ok((false, signers, threshold, skipped)) => {
                    println!(
                        "FAIL root_threshold_met=false signers={signers} threshold={threshold} skipped_non_ed25519={skipped}"
                    );
                    exit(1);
                }
                Err(_) => {
                    println!("MALFORMED");
                    exit(2);
                }
            }
        }
        "coverage-report" => {
            // Self-declared, single source of truth (see VERIFY_SUBCOMMANDS doc comment above) — the
            // Python-side gate (scripts/rust_parity_gate.py) diffs this against main.rs's own match arms
            // AND against its registry, so a hand-edited drift in either direction is caught, not assumed.
            let list = VERIFY_SUBCOMMANDS
                .iter()
                .map(|s| format!("\"{s}\""))
                .collect::<Vec<_>>()
                .join(",");
            println!(
                "{{\"schema\":\"pb_verify_rs.coverage_report.v1\",\"binary\":\"pb_verify_rs\",\"verify_subcommands\":[{list}]}}"
            );
            exit(0);
        }
        // Two SEPARATE match arms (not a `|` pattern) so scripts/rust_parity_gate.py's match-arm
        // regex sees each subcommand as its own `"name" =>` dispatch. Both delegate to the shared
        // relation engine; the only difference is statement_mode.
        "verify-relation" => dispatch_verify_relation(&args, "verify-relation", false),
        "verify-relation-statement" => dispatch_verify_relation(&args, "verify-relation-statement", true),
        other => fatal(&format!("unknown subcommand: {other}")),
    }
}
