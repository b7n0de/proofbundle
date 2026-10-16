// Z381 Kani harnesses. `build.rs` appends this file INSIDE the proof subject (under `cfg(kani)`),
// so the harnesses reach the verifier's private functions without any change to the verifier.
//
// STATUS: written for Kani 0.67.0, NOT RUN in the Z381 session (the tool could not be installed
// there, see the report). Run with:
//   cargo kani --harness-timeout 3600s
// Each harness states its input bound. Nothing here is counted as proven until a run says so.

use super::*;
use std::ffi::OsString;

fn run_main(argv: Vec<OsString>, file: Option<Vec<u8>>) {
    crate::boundary::set_input(argv, file);
    verifier_main();
    // `exit` checks the verdict and cuts the path; reaching this line is a path without a verdict.
    panic!("Z381: verifier_main returned without a verdict");
}

fn bundle_argv() -> Vec<OsString> {
    vec![
        "pb_verify_rs".into(),
        "verify-bundle".into(),
        crate::boundary::INPUT_PATH.into(),
    ]
}

fn symbolic_bytes<const N: usize>() -> Vec<u8> {
    let len: usize = kani::any();
    kani::assume(len <= N);
    let buf: [u8; N] = kani::any();
    buf[..len].to_vec()
}

/// P1 + P2 over every file content of at most 4 bytes, real parser, real crypto, no flags.
#[kani::proof]
#[kani::unwind(12)]
fn k1_decision_every_file_up_to_4_bytes() {
    run_main(bundle_argv(), Some(symbolic_bytes::<4>()));
}

/// P1 + P2 over argv: up to 3 words after `verify-bundle`, each from the flag alphabet or a
/// symbolic 2-byte word (which may be invalid UTF-8), file content `{}`.
#[kani::proof]
#[kani::unwind(12)]
fn k2_decision_every_argv_up_to_3_words() {
    const WORDS: [&str; 8] = [
        "--expected-root",
        "--expected-tree-size",
        "--require-anchor",
        "--allow-pending",
        "--anchor-type",
        "--anchor-target",
        "1",
        "input.json",
    ];
    let mut argv = bundle_argv();
    let n: usize = kani::any();
    kani::assume(n <= 3);
    for _ in 0..n {
        let pick: usize = kani::any();
        kani::assume(pick <= WORDS.len());
        if pick < WORDS.len() {
            argv.push(WORDS[pick].into());
        } else {
            use std::os::unix::ffi::OsStringExt;
            argv.push(OsString::from_vec(symbolic_bytes::<2>()));
        }
    }
    run_main(argv, Some(b"{}".to_vec()));
}

/// P3 for the parser: two runs on the same bytes give the same result.
#[kani::proof]
#[kani::unwind(12)]
fn k3_strict_parse_deterministic_up_to_4_bytes() {
    let b = symbolic_bytes::<4>();
    assert_eq!(strict_parse(&b), strict_parse(&b));
}

/// P3 for the bundle decision on every parsed value of at most 6 bytes.
#[kani::proof]
#[kani::unwind(14)]
fn k4_verify_bundle_deterministic_up_to_6_bytes() {
    let b = symbolic_bytes::<6>();
    if let Ok(v) = strict_parse(&b) {
        assert_eq!(verify_bundle(&v, None, None), verify_bundle(&v, None, None));
    }
}

fn node_hash_abstract(l: &[u8], r: &[u8]) -> Vec<u8> {
    // Assumption A1: SHA-256 is a total function to 32 bytes; the value is left unconstrained.
    let _ = (l, r);
    let h: [u8; 32] = kani::any();
    h.to_vec()
}

/// P1 for the inclusion walk over EVERY u64 leaf index and tree size and every proof of at most
/// 4 entries: no overflow, no panic, always a result (SHA-256 abstracted, assumption A1).
#[kani::proof]
#[kani::unwind(70)]
#[kani::stub(node_hash, node_hash_abstract)]
fn k5_root_from_inclusion_total() {
    let idx: u64 = kani::any();
    let size: u64 = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= 4);
    let mut proof = Vec::new();
    for _ in 0..n {
        let p: [u8; 32] = kani::any();
        proof.push(p.to_vec());
    }
    let leaf: [u8; 32] = kani::any();
    let r = root_from_inclusion(idx, size, leaf.to_vec(), &proof);
    assert!(r.is_ok() || r.is_err());
}
