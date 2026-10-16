//! Z381: P1 (terminates without panic), P2 (exactly one verdict of the closed list) and P3 (same
//! input, same verdict) for `pb_verify_rs verify-bundle`, decided over finite domains EXHAUSTIVELY
//! with the real verifier code and the real crypto. A domain is a proof for its inputs and for no
//! other input; the report names each domain and what lies outside.

mod common;

use common::domains::{d1, d2, d3, d4, d5, Domain};
use common::{assert_clean, run_domain, Report};

fn decide_all(d: Domain) -> Report {
    run_domain(d.name, d.n, |k| (d.gen)(k))
}

#[test]
fn d1_all_byte_strings_up_to_3() {
    let r = decide_all(d1());
    assert_eq!(r.inputs, 16_843_009);
    assert_clean(&r);
}

#[test]
fn d2_json_alphabet_up_to_6() {
    let r = decide_all(d2());
    assert_eq!(r.inputs, 17_895_697);
    assert_clean(&r);
}

#[test]
fn d3_structured_bundles_no_flags() {
    let r = decide_all(d3());
    assert!(
        r.histogram.contains_key("Ok"),
        "PASS must be reachable in D3"
    );
    assert_clean(&r);
}

#[test]
fn d4_structured_bundles_times_flags() {
    let r = decide_all(d4());
    for c in ["Ok", "Fail", "Malformed", "PolicyUnmet", "UsageError"] {
        assert!(
            r.histogram.contains_key(c),
            "class {c} must be reachable in D4"
        );
    }
    assert_clean(&r);
}

#[test]
fn d5_argv_up_to_4() {
    let r = decide_all(d5());
    assert!(
        r.histogram.contains_key("Ok"),
        "PASS must be reachable in D5"
    );
    assert_clean(&r);
}
