// Z381 Kani harnesses. `build.rs` appends this file INSIDE the proof subject (under `cfg(kani)`),
// so the harnesses reach the verifier's private functions without any change to the verifier.
//
// STATUS: written for Kani 0.67.0 in the Z381 session and not run there. First run in the Z381
// continuation; the verdict of each harness, its time and its memory stand in that report, not
// here. The stub of k5 needs the unstable stubbing feature (without it the crate does not
// compile under Kani, measured), so run one harness at a time with:
//   cargo kani -Z stubbing --harness <name>
// Each harness states its input bound. Nothing here is counted as proven until a run says so.
// `PB_Z381_MUTANT=<name>` plants a counter-check (see build.rs): kani_underflow for P1 (k5),
// kani_fatal_stdout for P2 (k7, also reachable from k2), kani_walk_counter for P3 (k6);
// kani_two_lines (P2, k1) and kani_parse_counter (P3, k3) target the parser harnesses. The
// unwind bound 24 of k7 covers its longest word (20 bytes) plus the loop exit.

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

/// P1 + P2 over every file content of at most `N` bytes, real parser, real crypto, no flags.
fn k1_decision_every_file<const N: usize>() {
    run_main(bundle_argv(), Some(symbolic_bytes::<N>()));
}

// Z381 continuation: one harness per byte bound, so a bound the machine cannot decide (CBMC out
// of memory, or out of time) does not hide a smaller bound it can. The report names, per harness,
// VERIFIED, FAILED or not decided, and the largest decided bound.
#[kani::proof]
#[kani::unwind(12)]
fn k1_decision_every_file_up_to_1_byte() {
    k1_decision_every_file::<1>();
}

#[kani::proof]
#[kani::unwind(12)]
fn k1_decision_every_file_up_to_2_bytes() {
    k1_decision_every_file::<2>();
}

#[kani::proof]
#[kani::unwind(12)]
fn k1_decision_every_file_up_to_4_bytes() {
    k1_decision_every_file::<4>();
}

/// P1 + P2 over argv: up to `W` words after `verify-bundle`, each from the flag alphabet or a
/// symbolic 2-byte word (which may be invalid UTF-8), file content `{}`.
fn k2_decision_every_argv<const W: usize>() {
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
    kani::assume(n <= W);
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

#[kani::proof]
#[kani::unwind(12)]
fn k2_decision_every_argv_up_to_1_word() {
    k2_decision_every_argv::<1>();
}

#[kani::proof]
#[kani::unwind(12)]
fn k2_decision_every_argv_up_to_2_words() {
    k2_decision_every_argv::<2>();
}

#[kani::proof]
#[kani::unwind(12)]
fn k2_decision_every_argv_up_to_3_words() {
    k2_decision_every_argv::<3>();
}

/// P1 + P2 over argv, CONCRETE words: up to `W` words after `verify-bundle`, each one of nine fixed
/// words, among them a word that is not UTF-8 (a legal Unix file name), file content `{}`.
///
/// Z381 continuation: k2 with a symbolic 2-byte word was not decided in 1800 s at one word (the
/// word reaches `format!` in the usage error, symbolically). k7 keeps the choice symbolic and the
/// bytes concrete, so the property is the same over a smaller, named alphabet. It carries the P2
/// counter-check (kani_fatal_stdout) and the F1 counter-check (the verifier with `args()`, where
/// the non-UTF-8 word panics).
fn k7_decision_every_argv_over_nine_words<const W: usize>() {
    const WORDS: [&[u8]; 9] = [
        b"--expected-root",
        b"--expected-tree-size",
        b"--require-anchor",
        b"--allow-pending",
        b"--anchor-type",
        b"--anchor-target",
        b"1",
        b"input.json",
        b"input\xff.json",
    ];
    use std::os::unix::ffi::OsStringExt;
    let mut argv = bundle_argv();
    let n: usize = kani::any();
    kani::assume(n <= W);
    for _ in 0..n {
        let pick: usize = kani::any();
        kani::assume(pick < WORDS.len());
        argv.push(OsString::from_vec(WORDS[pick].to_vec()));
    }
    run_main(argv, Some(b"{}".to_vec()));
}

#[kani::proof]
#[kani::unwind(24)]
fn k7_decision_every_argv_over_nine_words_up_to_1() {
    k7_decision_every_argv_over_nine_words::<1>();
}

#[kani::proof]
#[kani::unwind(24)]
fn k7_decision_every_argv_over_nine_words_up_to_2() {
    k7_decision_every_argv_over_nine_words::<2>();
}

#[kani::proof]
#[kani::unwind(24)]
fn k7_decision_every_argv_over_nine_words_up_to_3() {
    k7_decision_every_argv_over_nine_words::<3>();
}

/// P3 for the parser: two runs on the same bytes (at most `N`) give the same result.
fn k3_strict_parse_deterministic<const N: usize>() {
    let b = symbolic_bytes::<N>();
    assert_eq!(strict_parse(&b), strict_parse(&b));
}

#[kani::proof]
#[kani::unwind(12)]
fn k3_strict_parse_deterministic_up_to_1_byte() {
    k3_strict_parse_deterministic::<1>();
}

#[kani::proof]
#[kani::unwind(12)]
fn k3_strict_parse_deterministic_up_to_2_bytes() {
    k3_strict_parse_deterministic::<2>();
}

#[kani::proof]
#[kani::unwind(12)]
fn k3_strict_parse_deterministic_up_to_4_bytes() {
    k3_strict_parse_deterministic::<4>();
}

/// P3 for the bundle decision on every parsed value of at most `N` bytes.
fn k4_verify_bundle_deterministic<const N: usize>() {
    let b = symbolic_bytes::<N>();
    if let Ok(v) = strict_parse(&b) {
        assert_eq!(verify_bundle(&v, None, None), verify_bundle(&v, None, None));
    }
}

#[kani::proof]
#[kani::unwind(14)]
fn k4_verify_bundle_deterministic_up_to_2_bytes() {
    k4_verify_bundle_deterministic::<2>();
}

#[kani::proof]
#[kani::unwind(14)]
fn k4_verify_bundle_deterministic_up_to_6_bytes() {
    k4_verify_bundle_deterministic::<6>();
}

fn node_hash_abstract(l: &[u8], r: &[u8]) -> Vec<u8> {
    // Assumption A1: SHA-256 is a total function to 32 bytes; the value is left unconstrained.
    let _ = (l, r);
    let h: [u8; 32] = kani::any();
    h.to_vec()
}

/// P1 for the inclusion walk over EVERY u64 leaf index and tree size and every proof of exactly
/// `N` entries: no overflow, no panic, always a result (SHA-256 abstracted, assumption A1).
///
/// Z381 continuation: the first form left the proof length symbolic (0..=4) under one unwind bound
/// of 70; CBMC then unrolls the inner `while` (up to 63 shifts of a u64) inside each of 70 copies
/// of the outer loop and ran out of memory after 15 minutes (measured, about 15 GB). One harness
/// per length keeps the outer loop at exactly `N` turns; the bound 66 covers the inner loop
/// (at most 63 turns, plus the exit test) and the 32-byte copies, and Kani's unwinding assertions
/// turn a bound that is too small into a failure, never into a silent cut.
fn k5_root_from_inclusion_total_len<const N: usize>() {
    let idx: u64 = kani::any();
    let size: u64 = kani::any();
    let mut proof = Vec::with_capacity(N);
    for _ in 0..N {
        let p: [u8; 32] = kani::any();
        proof.push(p.to_vec());
    }
    let leaf: [u8; 32] = kani::any();
    let r = root_from_inclusion(idx, size, leaf.to_vec(), &proof);
    assert!(r.is_ok() || r.is_err());
}

#[kani::proof]
#[kani::unwind(66)]
#[kani::stub(node_hash, node_hash_abstract)]
fn k5_root_from_inclusion_total_len0() {
    k5_root_from_inclusion_total_len::<0>();
}

#[kani::proof]
#[kani::unwind(66)]
#[kani::stub(node_hash, node_hash_abstract)]
fn k5_root_from_inclusion_total_len1() {
    k5_root_from_inclusion_total_len::<1>();
}

#[kani::proof]
#[kani::unwind(66)]
#[kani::stub(node_hash, node_hash_abstract)]
fn k5_root_from_inclusion_total_len2() {
    k5_root_from_inclusion_total_len::<2>();
}

#[kani::proof]
#[kani::unwind(66)]
#[kani::stub(node_hash, node_hash_abstract)]
fn k5_root_from_inclusion_total_len3() {
    k5_root_from_inclusion_total_len::<3>();
}

#[kani::proof]
#[kani::unwind(66)]
#[kani::stub(node_hash, node_hash_abstract)]
fn k5_root_from_inclusion_total_len4() {
    k5_root_from_inclusion_total_len::<4>();
}

fn node_hash_deterministic(l: &[u8], r: &[u8]) -> Vec<u8> {
    // Assumption A1 for P3: SHA-256 abstracted by a DETERMINISTIC total function to 32 bytes (the
    // unconstrained stub of k5 may answer differently on two calls and would fail P3 by itself).
    let mut h = [0u8; 32];
    h[0] = l.first().copied().unwrap_or(0) ^ r.first().copied().unwrap_or(0).rotate_left(1) ^ 1;
    h[31] = l.len() as u8 ^ (r.len() as u8).rotate_left(3);
    h.to_vec()
}

/// P3 for the inclusion walk over EVERY u64 leaf index and tree size and every proof of exactly
/// `N` entries: two runs on the same input give the same result (SHA-256 abstracted
/// deterministically, assumption A1). Z381 continuation: k3 and k4, the P3 harnesses over the
/// JSON parser, ran out of memory on the dev box; this one carries the P3 counter-check.
fn k6_root_from_inclusion_deterministic_len<const N: usize>() {
    let idx: u64 = kani::any();
    let size: u64 = kani::any();
    let mut proof = Vec::with_capacity(N);
    for _ in 0..N {
        let p: [u8; 32] = kani::any();
        proof.push(p.to_vec());
    }
    let leaf: [u8; 32] = kani::any();
    let a = root_from_inclusion(idx, size, leaf.to_vec(), &proof);
    let b = root_from_inclusion(idx, size, leaf.to_vec(), &proof);
    assert_eq!(a, b);
}

#[kani::proof]
#[kani::unwind(66)]
#[kani::stub(node_hash, node_hash_deterministic)]
fn k6_root_from_inclusion_deterministic_len0() {
    k6_root_from_inclusion_deterministic_len::<0>();
}

#[kani::proof]
#[kani::unwind(66)]
#[kani::stub(node_hash, node_hash_deterministic)]
fn k6_root_from_inclusion_deterministic_len1() {
    k6_root_from_inclusion_deterministic_len::<1>();
}

#[kani::proof]
#[kani::unwind(66)]
#[kani::stub(node_hash, node_hash_deterministic)]
fn k6_root_from_inclusion_deterministic_len2() {
    k6_root_from_inclusion_deterministic_len::<2>();
}

#[kani::proof]
#[kani::unwind(66)]
#[kani::stub(node_hash, node_hash_deterministic)]
fn k6_root_from_inclusion_deterministic_len3() {
    k6_root_from_inclusion_deterministic_len::<3>();
}

#[kani::proof]
#[kani::unwind(66)]
#[kani::stub(node_hash, node_hash_deterministic)]
fn k6_root_from_inclusion_deterministic_len4() {
    k6_root_from_inclusion_deterministic_len::<4>();
}
