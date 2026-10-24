//! The closed list of verdicts of `pb_verify_rs verify-bundle`, and the check that one observed run
//! carries exactly one of them.
//!
//! The list is the exit-code contract of the native bundle path (README "Exit codes", the comment
//! above `verify_bundle` in the verifier): 0 crypto OK, 1 verification failure, 2 malformed or usage
//! error, 3 policy unmet. PASS is `Ok`; every other entry is FAIL with that entry as its reason.
//! The free text after `MALFORMED: `, `error: ` and `usage: ` is NOT part of the closed list (see the report).

/// One entry of the closed list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// PASS: stdout `OK`, exit 0.
    Ok,
    /// FAIL, reason verification failure: stdout `FAIL`, exit 1.
    Fail,
    /// FAIL, reason malformed input: stdout `MALFORMED: <text>`, exit 2.
    Malformed,
    /// FAIL, reason relying-party policy unmet: stdout `POLICY_UNMET`, exit 3.
    PolicyUnmet,
    /// FAIL, reason usage error: no stdout line, one stderr line `error: <text>` or `usage: <text>`,
    /// exit 2.
    UsageError,
}

pub const CLOSED_LIST: [Class; 5] = [
    Class::Ok,
    Class::Fail,
    Class::Malformed,
    Class::PolicyUnmet,
    Class::UsageError,
];

fn single<'a>(lines: &'a [String]) -> Option<&'a str> {
    if lines.len() == 1 {
        Some(lines[0].as_str())
    } else {
        None
    }
}

/// Exactly one verdict from the closed list, or the reason why not.
///
/// Every entry fixes the exit code, the number of stdout lines (one, or none for a usage error) and
/// the stderr shape, so two verdicts on one run (two lines, a line and a usage error, a line that
/// does not match its exit code) are refused here as well as a verdict outside the list.
pub fn classify_parts(code: i32, out: &[String], err: &[String]) -> Result<Class, &'static str> {
    let line = single(out);
    match code {
        0 if line == Some("OK") && err.is_empty() => Ok(Class::Ok),
        1 if line == Some("FAIL") && err.is_empty() => Ok(Class::Fail),
        3 if line == Some("POLICY_UNMET") && err.is_empty() => Ok(Class::PolicyUnmet),
        2 if err.is_empty()
            && line
                .is_some_and(|l| l.starts_with("MALFORMED: ") && l.len() > "MALFORMED: ".len()) =>
        {
            Ok(Class::Malformed)
        }
        2 if out.is_empty()
            && single(err).is_some_and(|l| {
                ["error: ", "usage: "]
                    .iter()
                    .any(|p| l.starts_with(p) && l.len() > p.len())
            }) =>
        {
            Ok(Class::UsageError)
        }
        0..=3 => Err("exit code and output do not form exactly one verdict of the closed list"),
        _ => Err("exit code outside the closed list"),
    }
}
