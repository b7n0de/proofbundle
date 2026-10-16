//! The finite input domains of the Z381 proof. Each domain is a total enumeration: input k for
//! every k below its size, so "decided for every input of the domain" is a finite, checked fact.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::ffi::OsString;

use super::*;
use z381_pruefentscheidung::boundary::input_path_not_utf8;

pub struct Domain {
    pub name: &'static str,
    pub n: usize,
    pub gen: Box<dyn Fn(usize) -> Input + Sync>,
}

impl Domain {
    fn new(name: &'static str, n: usize, gen: impl Fn(usize) -> Input + Sync + 'static) -> Self {
        Domain {
            name,
            n,
            gen: Box::new(gen),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// D1: every byte string of length 0..=3 (all 256 byte values), no flags.
// ---------------------------------------------------------------------------------------------
pub fn d1() -> Domain {
    let alphabet: Vec<u8> = (0..=255u8).collect();
    Domain::new("D1_bytes_len_le_3", words(256, 3), move |k| {
        Input::new(bundle_argv(&[]), Some(word(&alphabet, 3, k)))
    })
}

// ---------------------------------------------------------------------------------------------
// D2: every string of length 0..=6 over the 16 symbols JSON structure is made of.
// ---------------------------------------------------------------------------------------------
pub const JSON16: &[u8; 16] = b"{}[]\":,01-.eat\\ ";

pub fn d2() -> Domain {
    Domain::new("D2_json16_len_le_6", words(16, 6), |k| {
        Input::new(bundle_argv(&[]), Some(word(JSON16, 6, k)))
    })
}

// ---------------------------------------------------------------------------------------------
// D3: structured bundles. Every field of the native bundle ranges over absent / wrong JSON type /
// invalid encoding / valid-but-wrong / valid-and-right, the product is decided in full. Real
// Ed25519 signatures and an independent RFC 6962 implementation make the deep paths (signature
// verified, inclusion verified, root pinned, SD-JWT checked) reachable, so PASS is in the domain.
// ---------------------------------------------------------------------------------------------
pub fn sha(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}

/// RFC 6962 MTH over raw leaves (independent of the verifier's code).
pub fn mth(leaves: &[Vec<u8>]) -> Vec<u8> {
    match leaves.len() {
        0 => sha(&[]),
        1 => sha(&[&[0u8], &leaves[0]]),
        n => {
            let k = n.next_power_of_two() / 2;
            sha(&[&[1u8], &mth(&leaves[..k]), &mth(&leaves[k..])])
        }
    }
}

/// RFC 6962 audit path PATH(m, D[n]).
pub fn path(m: usize, leaves: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let n = leaves.len();
    if n <= 1 {
        return vec![];
    }
    let k = n.next_power_of_two() / 2;
    if m < k {
        let mut p = path(m, &leaves[..k]);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = path(m - k, &leaves[k..]);
        p.push(mth(&leaves[..k]));
        p
    }
}

pub struct Keys {
    pub signer: SigningKey,
    pub other: SigningKey,
    pub issuer: SigningKey,
}

pub fn keys() -> Keys {
    Keys {
        signer: SigningKey::from_bytes(&[7u8; 32]),
        other: SigningKey::from_bytes(&[8u8; 32]),
        issuer: SigningKey::from_bytes(&[9u8; 32]),
    }
}

pub fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

pub fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

pub const PAYLOAD: &[u8] = br#"{"claim":"x"}"#;
pub const PAYLOAD_RAW: &[u8] = b"\xff\x00raw";

pub fn sdjwt(k: &SigningKey, header: &Value, payload: &Value) -> String {
    let h = b64url(&serde_json::to_vec(header).unwrap());
    let p = b64url(&serde_json::to_vec(payload).unwrap());
    let s = b64url(&k.sign(format!("{h}.{p}").as_bytes()).to_bytes());
    format!("{h}.{p}.{s}~")
}

/// The variants of each axis. `None` means the member is absent.
pub struct Axes {
    pub payload: Vec<(Option<Value>, Option<&'static [u8]>)>,
    pub sd: Vec<Option<Value>>,
}

pub const PUB_VARIANTS: usize = 7;
pub const SIG_VARIANTS: usize = 5;
pub const LEAF_INDEX: [Option<i64>; 5] = [None, Some(-1), Some(i64::MIN), Some(0), Some(1)];
pub const TREE_SIZE: [Option<i64>; 5] = [None, Some(0), Some(1), Some(2), Some(3)];
pub const PROOF_VARIANTS: usize = 6;
pub const ROOT_VARIANTS: usize = 4;
pub const MERKLE_VARIANTS: usize = 2 + 5 * 5 * PROOF_VARIANTS * ROOT_VARIANTS;

pub fn pub_variant(k: &Keys, i: usize) -> Option<Value> {
    match i {
        0 => None,
        1 => Some(json!(1)),
        2 => Some(json!("*")),
        3 => Some(json!(b64(&[1u8; 31]))),
        4 => Some(json!(b64(&[0xffu8; 32]))),
        5 => Some(json!(b64(k.signer.verifying_key().as_bytes()))),
        6 => Some(json!(b64(k.other.verifying_key().as_bytes()))),
        _ => unreachable!(),
    }
}

pub fn sig_variant(k: &Keys, i: usize, payload: Option<&[u8]>) -> Option<Value> {
    match i {
        0 => None,
        1 => Some(json!("*")),
        2 => Some(json!(b64(&[3u8; 63]))),
        3 => Some(json!(b64(&k
            .signer
            .sign(payload.unwrap_or(PAYLOAD))
            .to_bytes()))),
        4 => Some(json!(b64(&[0u8; 64]))),
        _ => unreachable!(),
    }
}

pub fn int_value(v: Option<i64>) -> Option<Value> {
    v.map(|n| {
        if n == i64::MIN {
            // the largest I-JSON integer: a valid u64, far past every tree
            json!(9_007_199_254_740_991u64)
        } else {
            json!(n)
        }
    })
}

/// Merkle variant m for the leaf `payload`; returns (merkle member, the right root if any).
pub fn merkle_variant(m: usize, payload: &[u8]) -> (Option<Value>, Option<String>) {
    match m {
        0 => return (None, None),
        1 => return (Some(json!("m")), None),
        _ => {}
    }
    let mut r = m - 2;
    let root_v = r % ROOT_VARIANTS;
    r /= ROOT_VARIANTS;
    let proof_v = r % PROOF_VARIANTS;
    r /= PROOF_VARIANTS;
    let ts = TREE_SIZE[r % 5];
    r /= 5;
    let li = LEAF_INDEX[r % 5];
    // the tree the right proof and root are taken from
    let (idx, size) = match (li, ts) {
        (Some(i), Some(s)) if i >= 0 && s > 0 && i < s => (i as usize, s as usize),
        _ => (0, 1),
    };
    let mut leaves: Vec<Vec<u8>> = (0..size)
        .map(|j| format!("leaf-{j}").into_bytes())
        .collect();
    leaves[idx] = payload.to_vec();
    let right_path: Vec<Value> = path(idx, &leaves).iter().map(|h| json!(b64(h))).collect();
    let right_root = b64(&mth(&leaves));
    let mut o = Map::new();
    if let Some(v) = int_value(li) {
        o.insert("leaf_index".into(), v);
    }
    if let Some(v) = int_value(ts) {
        o.insert("tree_size".into(), v);
    }
    match proof_v {
        0 => {}
        1 => {
            o.insert("inclusion_proof_b64".into(), json!("p"));
        }
        2 => {
            o.insert("inclusion_proof_b64".into(), json!([]));
        }
        3 => {
            o.insert("inclusion_proof_b64".into(), Value::Array(right_path));
        }
        4 => {
            o.insert("inclusion_proof_b64".into(), json!(["*"]));
        }
        5 => {
            o.insert("inclusion_proof_b64".into(), json!([7]));
        }
        _ => unreachable!(),
    }
    match root_v {
        0 => {}
        1 => {
            o.insert("root_b64".into(), json!("*"));
        }
        2 => {
            o.insert("root_b64".into(), json!(right_root.clone()));
        }
        3 => {
            o.insert("root_b64".into(), json!(b64(&[0u8; 32])));
        }
        _ => unreachable!(),
    }
    (Some(Value::Object(o)), Some(right_root))
}

pub fn axes(k: &Keys) -> Axes {
    let issuer_pub = b64(k.issuer.verifying_key().as_bytes());
    let hdr = json!({"alg": "EdDSA"});
    Axes {
        payload: vec![
            (None, None),
            (Some(json!(7)), None),
            (Some(json!("!!!!")), None),
            (Some(json!(b64(PAYLOAD))), Some(PAYLOAD)),
            (Some(json!(b64(PAYLOAD_RAW))), Some(PAYLOAD_RAW)),
        ],
        sd: vec![
            None,
            Some(json!("x")),
            Some(json!({})),
            Some(json!({"compact": "a.b.c", "issuer_public_key_b64": issuer_pub})),
            Some(json!({
                "compact": sdjwt(&k.issuer, &hdr, &json!({"iss": "x"})),
                "issuer_public_key_b64": issuer_pub
            })),
            Some(json!({
                "compact": sdjwt(&k.issuer, &hdr, &json!({"iss": "x", "cnf": {}})),
                "issuer_public_key_b64": issuer_pub
            })),
            Some(json!({
                "compact": sdjwt(&k.issuer, &json!({"alg": "EdDSA", "crit": ["x"], "x": 1}), &json!({"iss": "x"})),
                "issuer_public_key_b64": issuer_pub
            })),
        ],
    }
}

pub const SIGNATURE_VARIANTS: usize = 2 + PUB_VARIANTS * SIG_VARIANTS;

pub fn signature_variant(k: &Keys, s: usize, payload: Option<&[u8]>) -> Option<Value> {
    match s {
        0 => None,
        1 => Some(json!("s")),
        _ => {
            let (p, g) = ((s - 2) / SIG_VARIANTS, (s - 2) % SIG_VARIANTS);
            let mut o = Map::new();
            if let Some(v) = pub_variant(k, p) {
                o.insert("public_key_b64".into(), v);
            }
            if let Some(v) = sig_variant(k, g, payload) {
                o.insert("sig_b64".into(), v);
            }
            Some(Value::Object(o))
        }
    }
}

pub fn bundle(
    k: &Keys,
    ax: &Axes,
    p: usize,
    s: usize,
    m: usize,
    d: usize,
) -> (Vec<u8>, Option<String>) {
    let (pv, praw) = &ax.payload[p];
    let mut o = Map::new();
    if let Some(v) = pv {
        o.insert("payload_b64".into(), v.clone());
    }
    if let Some(v) = signature_variant(k, s, *praw) {
        o.insert("signature".into(), v);
    }
    let (mv, root) = merkle_variant(m, praw.unwrap_or(PAYLOAD));
    if let Some(v) = mv {
        o.insert("merkle".into(), v);
    }
    if let Some(v) = &ax.sd[d] {
        o.insert("sd_jwt_vc".into(), v.clone());
    }
    (serde_json::to_vec(&Value::Object(o)).unwrap(), root)
}

pub fn d3() -> Domain {
    let k = keys();
    let ax = axes(&k);
    let (np, ns, nm, nd) = (
        ax.payload.len(),
        SIGNATURE_VARIANTS,
        MERKLE_VARIANTS,
        ax.sd.len(),
    );
    let n = np * ns * nm * nd;
    Domain::new("D3_structured_bundles", n, move |mut i| {
        let d = i % nd;
        i /= nd;
        let m = i % nm;
        i /= nm;
        let s = i % ns;
        let p = i / ns;
        Input::new(bundle_argv(&[]), Some(bundle(&k, &ax, p, s, m, d).0))
    })
}

/// The relying-party flags, crossed with every bundle whose signature is right (the only bundles
/// on which a flag can still change the verdict: a wrong signature returns FAIL before any flag
/// is looked at).
pub fn d4() -> Domain {
    let k = keys();
    let ax = axes(&k);
    let nd = ax.sd.len();
    let right_sig = 2 + 5 * SIG_VARIANTS + 3; // public key = signer, sig = right signature
    let flag_sets: Vec<Vec<String>> = {
        let root = "@ROOT@".to_string();
        vec![
            vec![],
            vec!["--require-anchor".into()],
            vec!["--allow-pending".into()],
            vec!["--anchor-type".into(), "rfc3161".into()],
            vec!["--anchor-target".into()],
            vec!["--expected-root".into(), root.clone()],
            vec!["--expected-root".into(), "*".into()],
            vec!["--expected-root".into(), b64(&[0u8; 32])],
            vec!["--expected-root".into()],
            vec!["--expected-tree-size".into(), "1".into()],
            vec!["--expected-tree-size".into(), "2".into()],
            vec!["--expected-tree-size".into(), "x".into()],
            vec!["--expected-tree-size".into(), "18446744073709551616".into()],
            vec!["--bogus".into()],
            vec![
                "--require-anchor".into(),
                "--expected-root".into(),
                root.clone(),
                "--expected-tree-size".into(),
                "1".into(),
            ],
            vec!["--expected-root".into(), root, "--allow-pending".into()],
        ]
    };
    let nf = flag_sets.len();
    let payloads = [3usize, 4];
    let n = payloads.len() * MERKLE_VARIANTS * nd * nf;
    Domain::new("D4_bundles_times_flags", n, move |mut i| {
        let f = i % nf;
        i /= nf;
        let d = i % nd;
        i /= nd;
        let m = i % MERKLE_VARIANTS;
        let p = payloads[i / MERKLE_VARIANTS];
        let (bytes, root) = bundle(&k, &ax, p, right_sig, m, d);
        let root = root.unwrap_or_else(|| b64(&[9u8; 32]));
        let flags: Vec<String> = flag_sets[f]
            .iter()
            .map(|x| {
                if x == "@ROOT@" {
                    root.clone()
                } else {
                    x.clone()
                }
            })
            .collect();
        let fl: Vec<&str> = flags.iter().map(|s| s.as_str()).collect();
        Input::new(bundle_argv(&fl), Some(bytes))
    })
}

// ---------------------------------------------------------------------------------------------
// D5: argv. Every argument vector of length 0..=4 after the program name over an alphabet of
// subcommand, path, flag and value words, one of them NOT valid UTF-8 (a legal Unix file name),
// against three file states. Restricted to `verify-bundle` and to words that are no subcommand;
// the other subcommands are outside this proof.
// ---------------------------------------------------------------------------------------------

/// The 14 argv words of D5 and D6, and the valid bundle (right signature, right inclusion proof
/// for a one-leaf tree) the file states use.
pub fn argv_alphabet() -> (Vec<OsString>, Vec<u8>) {
    let k = keys();
    let ax = axes(&k);
    let right_sig = 2 + 5 * SIG_VARIANTS + 3;
    let (valid, root) = bundle(
        &k,
        &ax,
        3,
        right_sig,
        2 + 3 * 5 * 6 * 4 + 2 * 6 * 4 + 3 * 4 + 2,
        0,
    );
    let root = root.unwrap();
    let alphabet: Vec<OsString> = vec![
        "verify-bundle".into(),
        "input.json".into(),
        "missing.json".into(),
        "--expected-root".into(),
        root.into(),
        "--expected-tree-size".into(),
        "1".into(),
        "-1".into(),
        "--require-anchor".into(),
        "--allow-pending".into(),
        "--anchor-type".into(),
        "".into(),
        "x".into(),
        input_path_not_utf8(),
    ];
    (alphabet, valid)
}

/// argv[1] is verify-bundle or no subcommand at all (absent, unknown, not UTF-8).
fn first_ok(w: &[OsString]) -> bool {
    match w.first().and_then(|x| x.to_str()) {
        None => true,
        Some("verify-bundle") | Some("") | Some("x") => true,
        Some(s) => ![
            "budget",
            "content-root",
            "verify-dsse",
            "merkle-root",
            "strict-parse",
            "verify-trust-pack-threshold",
            "verify-relation",
            "verify-relation-statement",
            "coverage-report",
        ]
        .contains(&s),
    }
}

/// The argv words of D5/D6 number `w` (program name first).
pub fn argv_word(alphabet: &[OsString], w: usize) -> Vec<OsString> {
    let idx: Vec<u8> = (0..alphabet.len() as u8).collect();
    let words: Vec<OsString> = word(&idx, 4, w)
        .into_iter()
        .map(|j| alphabet[j as usize].clone())
        .collect();
    assert!(first_ok(&words));
    let mut argv: Vec<OsString> = vec!["pb_verify_rs".into()];
    argv.extend(words);
    argv
}

pub fn d5() -> Domain {
    let (alphabet, valid) = argv_alphabet();
    let files: [Option<Vec<u8>>; 3] = [Some(valid), Some(b"{}".to_vec()), None];
    let n = words(alphabet.len(), 4) * files.len();
    Domain::new("D5_argv_len_le_4", n, move |i| {
        Input::new(
            argv_word(&alphabet, i / files.len()),
            files[i % files.len()].clone(),
        )
    })
}

// ---------------------------------------------------------------------------------------------
// D6 (Z381 continuation): the argv of D5 against ONE file state, the valid bundle stored under the
// name that is not UTF-8 (`input.json` does not exist). This is the F1 reproduction as a domain:
// the file Python reads under that name must be read by the verifier too, so PASS is reachable.
// ---------------------------------------------------------------------------------------------
pub fn d6() -> Domain {
    let (alphabet, valid) = argv_alphabet();
    let n = words(alphabet.len(), 4);
    Domain::new("D6_argv_len_le_4_file_not_utf8", n, move |i| Input {
        argv: argv_word(&alphabet, i),
        name: input_path_not_utf8(),
        file: Some(valid.clone()),
    })
}
