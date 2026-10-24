//! Z381: the verdict check itself refuses what it must refuse (no verdict, two verdicts, a reason
//! outside the list), so a green domain run cannot come from a check that accepts everything.

use z381_pruefentscheidung::verdict::{classify_parts, Class, CLOSED_LIST};

fn v(x: &[&str]) -> Vec<String> {
    x.iter().map(|s| s.to_string()).collect()
}

#[test]
fn each_entry_of_the_closed_list_is_accepted() {
    let cases = [
        (0, v(&["OK"]), v(&[]), Class::Ok),
        (1, v(&["FAIL"]), v(&[]), Class::Fail),
        (
            2,
            v(&["MALFORMED: missing payload_b64"]),
            v(&[]),
            Class::Malformed,
        ),
        (3, v(&["POLICY_UNMET"]), v(&[]), Class::PolicyUnmet),
        (
            2,
            v(&[]),
            v(&["error: unknown verify-bundle flag: --x"]),
            Class::UsageError,
        ),
        (
            2,
            v(&[]),
            v(&["usage: pb_verify_rs <...> ..."]),
            Class::UsageError,
        ),
    ];
    for (code, out, err, want) in cases {
        assert_eq!(classify_parts(code, &out, &err), Ok(want));
    }
    assert_eq!(CLOSED_LIST.len(), 5);
}

#[test]
fn everything_else_is_refused() {
    let refused = [
        (0, v(&[]), v(&[])),             // no verdict line
        (0, v(&["OK", "FAIL"]), v(&[])), // two verdicts
        (0, v(&["FAIL"]), v(&[])),       // line does not match the exit code
        (1, v(&["OK"]), v(&[])),
        (2, v(&["MALFORMED: x"]), v(&["error: y"])), // malformed and usage error at once
        (2, v(&["MALFORMED: "]), v(&[])),            // malformed without a reason
        (2, v(&[]), v(&["error: "])),
        (2, v(&[]), v(&["panicked at x"])),
        (3, v(&["POLICY_UNMET", "OK"]), v(&[])),
        (4, v(&["ANCHOR_PENDING"]), v(&[])), // reason outside the list
        (101, v(&[]), v(&["thread 'main' panicked"])),
        (0, v(&["OK"]), v(&["warning"])), // a second channel speaks
    ];
    for (code, out, err) in refused {
        assert!(
            classify_parts(code, &out, &err).is_err(),
            "{code} {out:?} {err:?}"
        );
    }
}
