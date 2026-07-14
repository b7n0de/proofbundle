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

fn verify_dsse(envelope: &serde_json::Value, pubkey_b64: &str) -> Result<bool, String> {
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
    Ok(true)
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
        eprintln!("usage: pb_verify_rs <content-root|verify-dsse|merkle-root|strict-parse> ...");
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
            match verify_dsse(&v, pk) {
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
                    // anchor flags are accepted but the anchor policy slice is not implemented yet;
                    // a case that DEPENDS on them is not claimed as reproduced (see CROSS_IMPLEMENTATION_REPORT).
                    "--require-anchor" | "--allow-pending" => i += 1,
                    "--anchor-type" | "--anchor-target" => i += 2,
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
        other => fatal(&format!("unknown subcommand: {other}")),
    }
}
