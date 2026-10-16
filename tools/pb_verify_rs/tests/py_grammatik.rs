//! Z381 continuation (O381-2): `verify-bundle` and `verify-relation` answer the argv words after
//! the subcommand as `proofbundle verify` and `proofbundle decision verify` answer the same words.
//!
//! Every expected exit code below was MEASURED with the Python verifier (`proofbundle` at
//! 22aa954ea310b945a6a3565960298c25255e62a1, CPython 3.13.16, a real process per case), not
//! derived. One test per line of the release scope, so each line can be shown red before its fix
//! and green after it. `PB_VERIFY_RS_BIN` runs the cases against another binary (the red run).

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    std::env::var_os("PB_VERIFY_RS_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_pb_verify_rs")))
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The files of a case: the example bundle, the same bundle with a broken signature, and the
/// decision receipt, target, policy and keys of one relation corpus case.
struct Files {
    dir: PathBuf,
}

impl Files {
    fn new(tag: &str) -> Files {
        let dir = std::env::temp_dir().join(format!(
            "pb_verify_rs_grammatik_{tag}_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ex = std::fs::read(repo().join("examples/example_bundle.json")).unwrap();
        std::fs::write(dir.join("ok.json"), &ex).unwrap();
        let mut bad: serde_json::Value = serde_json::from_slice(&ex).unwrap();
        let s = bad["signature"]["sig_b64"].as_str().unwrap().to_string();
        let first = if s.starts_with('A') { "B" } else { "A" };
        bad["signature"]["sig_b64"] = serde_json::json!(format!("{first}{}", &s[1..]));
        std::fs::write(dir.join("bad.json"), serde_json::to_vec(&bad).unwrap()).unwrap();
        let case = repo().join("conformance/relation/relation-signer-same-key-explicit");
        let receipt = std::fs::read(case.join("receipt.json")).unwrap();
        std::fs::write(dir.join("r.json"), &receipt).unwrap();
        let mut env: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
        let s = env["signatures"][0]["sig"].as_str().unwrap().to_string();
        let first = if s.starts_with('A') { "B" } else { "A" };
        env["signatures"][0]["sig"] = serde_json::json!(format!("{first}{}", &s[1..]));
        std::fs::write(dir.join("rbad.json"), serde_json::to_vec(&env).unwrap()).unwrap();
        std::fs::copy(case.join("related_b.json"), dir.join("b.json")).unwrap();
        std::fs::copy(case.join("policy.json"), dir.join("p.json")).unwrap();
        // files whose names start with `-`: a word argparse never takes as a value or a path
        std::fs::copy(case.join("related_b.json"), dir.join("-b.json")).unwrap();
        std::fs::write(dir.join("-x.json"), &ex).unwrap();
        Files { dir }
    }

    fn root(&self) -> String {
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(self.dir.join("ok.json")).unwrap()).unwrap();
        v["merkle"]["root_b64"].as_str().unwrap().to_string()
    }

    fn pub_b64(&self) -> String {
        let case = repo().join("conformance/relation/relation-signer-same-key-explicit");
        String::from_utf8(std::fs::read(case.join("pub.b64")).unwrap())
            .unwrap()
            .trim()
            .to_string()
    }

    fn related_pub(&self) -> String {
        let case = repo().join("conformance/relation/relation-signer-same-key-explicit/case.json");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(case).unwrap()).unwrap();
        v["relatedPubs"][0].as_str().unwrap().to_string()
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A word of a case; `\u{FFFF}` stands for the byte 0xff, which is no UTF-8.
fn wort(w: &str) -> OsString {
    use std::os::unix::ffi::OsStringExt;
    let mut b = Vec::new();
    for c in w.chars() {
        if c == '\u{FFFF}' {
            b.push(0xff);
        } else {
            let mut buf = [0u8; 4];
            b.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    OsString::from_vec(b)
}

/// Run every case and fail with the list of cases whose exit is not Python's.
fn check(files: &Files, sub: &str, cases: &[(&str, Vec<String>, i32)]) {
    let mut falsch = Vec::new();
    for (name, argv, python) in cases {
        let out = Command::new(binary())
            .arg(sub)
            .args(argv.iter().map(|w| wort(w)))
            .current_dir(&files.dir)
            .env("RUST_BACKTRACE", "0")
            .output()
            .unwrap();
        let code = out.status.code().unwrap_or(-1);
        if code != *python {
            falsch.push(format!("{name}: Python {python}, Rust {code}"));
        }
    }
    assert!(
        falsch.is_empty(),
        "{} of {} cases differ from Python:\n{}",
        falsch.len(),
        cases.len(),
        falsch.join("\n")
    );
}

fn v(words: &[&str]) -> Vec<String> {
    words.iter().map(|s| s.to_string()).collect()
}

#[test]
fn g3_allow_pending_needs_an_anchor_requirement() {
    let f = Files::new("g3");
    check(
        &f,
        "verify-bundle",
        &[
            ("allow-pending alone", v(&["ok.json", "--allow-pending"]), 2),
            (
                "allow-pending alone, bad signature",
                v(&["bad.json", "--allow-pending"]),
                2,
            ),
            (
                "with require-anchor",
                v(&["ok.json", "--allow-pending", "--require-anchor"]),
                3,
            ),
            (
                "with anchor-type",
                v(&["ok.json", "--allow-pending", "--anchor-type", "x"]),
                3,
            ),
            (
                "with anchor-type empty",
                v(&["ok.json", "--allow-pending", "--anchor-type", ""]),
                3,
            ),
            (
                "with anchor-target",
                v(&["ok.json", "--allow-pending", "--anchor-target", "receipt"]),
                3,
            ),
        ],
    );
}

#[test]
fn f5_anchor_target_takes_only_the_three_choices() {
    let f = Files::new("f5");
    let mut cases = Vec::new();
    for t in ["receipt", "preRegistration", "statement"] {
        cases.push((t, v(&["ok.json", "--anchor-target", t]), 3));
    }
    for t in ["x", "", "Receipt", "rec", "receipt ", "receipt\u{FFFF}"] {
        cases.push((t, v(&["ok.json", "--anchor-target", t]), 2));
    }
    check(&f, "verify-bundle", &cases);
}

#[test]
fn f4_bundle_values_are_read_before_the_signature() {
    let f = Files::new("f4");
    let r = f.root();
    check(
        &f,
        "verify-bundle",
        &[
            (
                "expected-root not base64, bad signature",
                v(&["bad.json", "--expected-root", "\u{ff}"]),
                2,
            ),
            (
                "expected-root '*', bad signature",
                v(&["bad.json", "--expected-root", "*"]),
                2,
            ),
            (
                "expected-root unpadded, bad signature",
                v(&["bad.json", "--expected-root", "AAA"]),
                2,
            ),
            (
                "expected-root 3 bytes, valid bundle",
                v(&["ok.json", "--expected-root", "AAAA"]),
                1,
            ),
            (
                "expected-root right, bad signature",
                vec!["bad.json".into(), "--expected-root".into(), r.clone()],
                1,
            ),
            (
                "expected-root right, valid bundle",
                vec!["ok.json".into(), "--expected-root".into(), r],
                0,
            ),
        ],
    );
}

#[test]
fn f4_relation_values_are_read_before_the_signature() {
    let f = Files::new("f4r");
    // verify-relation in this verifier's own form (the key as the second word); the expected exit is
    // Python's for the same values in `decision verify ENVELOPE --pub KEY ...`.
    let pubk = f.pub_b64();
    let rp = f.related_pub();
    let s = |x: &str| x.to_string();
    check(
        &f,
        "verify-relation",
        &[
            ("empty key", vec![s("r.json"), s("")], 2),
            ("key '*', bad signature", vec![s("rbad.json"), s("*")], 2),
            (
                "key not base64, bad signature",
                vec![s("rbad.json"), s("\u{ff}")],
                2,
            ),
            (
                "key of 31 bytes",
                vec![
                    s("r.json"),
                    s("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="),
                ],
                1,
            ),
            (
                "--with-related missing, bad signature",
                vec![
                    s("rbad.json"),
                    pubk.clone(),
                    s("--with-related"),
                    s("missing.json"),
                ],
                2,
            ),
            (
                "--related-pub '*', bad signature",
                vec![
                    s("rbad.json"),
                    pubk.clone(),
                    s("--with-related"),
                    s("b.json"),
                    s("--related-pub"),
                    s("*"),
                ],
                2,
            ),
            (
                "bad signature",
                vec![
                    s("rbad.json"),
                    pubk.clone(),
                    s("--with-related"),
                    s("b.json"),
                    s("--related-pub"),
                    rp.clone(),
                    s("--policy"),
                    s("p.json"),
                ],
                1,
            ),
            (
                "valid",
                vec![
                    s("r.json"),
                    pubk,
                    s("--with-related"),
                    s("b.json"),
                    s("--related-pub"),
                    rp,
                    s("--policy"),
                    s("p.json"),
                ],
                0,
            ),
        ],
    );
}

#[test]
fn g2_an_option_value_is_never_an_option_word() {
    let f = Files::new("g2");
    check(
        &f,
        "verify-bundle",
        &[
            (
                "anchor-type without value",
                v(&["ok.json", "--anchor-type"]),
                2,
            ),
            (
                "anchor-type value is a flag",
                v(&["ok.json", "--anchor-type", "--require-anchor"]),
                2,
            ),
            (
                "anchor-type value is an unknown flag",
                v(&["ok.json", "--anchor-type", "--bogus"]),
                2,
            ),
            (
                "anchor-type value is a flag prefix",
                v(&["ok.json", "--anchor-type", "--req"]),
                2,
            ),
            (
                "anchor-type value -x",
                v(&["ok.json", "--anchor-type", "-x"]),
                2,
            ),
            (
                "anchor-type value is a file named -x.json",
                v(&["ok.json", "--anchor-type", "-x.json"]),
                2,
            ),
            (
                "anchor-type value -1",
                v(&["ok.json", "--anchor-type", "-1"]),
                3,
            ),
            (
                "anchor-type value -",
                v(&["ok.json", "--anchor-type", "-"]),
                3,
            ),
            (
                "anchor-type value '-x y'",
                v(&["ok.json", "--anchor-type", "-x y"]),
                3,
            ),
            (
                "expected-root value is a flag",
                v(&["ok.json", "--expected-root", "--require-anchor"]),
                2,
            ),
            (
                "expected-root without value",
                v(&["ok.json", "--expected-root"]),
                2,
            ),
            (
                "anchor-target value is a flag",
                v(&["ok.json", "--anchor-target", "--allow-pending"]),
                2,
            ),
            (
                "expected-tree-size value is a flag",
                v(&["ok.json", "--expected-tree-size", "--json"]),
                2,
            ),
        ],
    );
}

#[test]
fn g2_relation_option_value_is_never_an_option_word() {
    let f = Files::new("g2r");
    let (pubk, rp) = (f.pub_b64(), f.related_pub());
    let s = |x: &str| x.to_string();
    // this verifier's own form; Python's exit measured for `decision verify r.json --pub KEY ...`
    check(
        &f,
        "verify-relation",
        &[
            (
                "--with-related value is a file named -b.json",
                vec![
                    s("r.json"),
                    pubk.clone(),
                    s("--with-related"),
                    s("-b.json"),
                    s("--related-pub"),
                    rp.clone(),
                    s("--policy"),
                    s("p.json"),
                ],
                2,
            ),
            (
                "--with-related value is a flag",
                vec![
                    s("r.json"),
                    pubk.clone(),
                    s("--with-related"),
                    s("--policy"),
                    s("p.json"),
                ],
                2,
            ),
            (
                "the same with the file named b.json",
                vec![
                    s("r.json"),
                    pubk,
                    s("--with-related"),
                    s("b.json"),
                    s("--related-pub"),
                    rp,
                    s("--policy"),
                    s("p.json"),
                ],
                0,
            ),
        ],
    );
}
