//! Z381: builds the proof subject from the REAL verifier source, `tools/pb_verify_rs/src/main.rs`.
//!
//! The verifier is not copied and not edited. This script reads its bytes at build time and
//! substitutes exactly the process boundary — argv, exit, the file read, stdout/stderr — so the
//! decision logic that is proven is byte-identical to the shipped one. Every substitution states how
//! often it must apply; a count that differs aborts the build, so a refactor of the verifier cannot
//! silently move the proof onto a different shape.
//!
//! `PB_Z381_MUTANT` plants one defect into the copy (never into the verifier) for the
//! counter-check: a proof that stays green under a planted defect is no proof.

use std::env;
use std::fs;
use std::path::PathBuf;

const VERIFIER: &str = "../../tools/pb_verify_rs/src/main.rs";

fn replace_exact(src: &str, from: &str, to: &str, count: usize, what: &str) -> String {
    let n = src.matches(from).count();
    if n != count {
        panic!("z381 build: substitution `{what}` expected {count} occurrence(s), found {n}");
    }
    src.replace(from, to)
}

/// One planted defect per mutant, applied inside the `verify-bundle` arm or `verify_bundle` only.
fn plant(src: &str, mutant: &str) -> String {
    match mutant {
        // a path without a verdict: the FAIL branch prints but neither exits nor returns a verdict
        "no_verdict" => replace_exact(
            src,
            "                Ok(false) => {\n                    println!(\"FAIL\");\n                    exit(1);\n                }\n                Err(e) => {\n                    println!(\"MALFORMED: {e}\");\n                    exit(2);\n                }\n            }\n        }\n        \"strict-parse\"",
            "                Ok(false) => {}\n                Err(e) => {\n                    println!(\"MALFORMED: {e}\");\n                    exit(2);\n                }\n            }\n        }\n        \"strict-parse\"",
            1,
            "mutant no_verdict",
        ),
        // a path with two verdicts: OK and FAIL on the same run
        "two_verdicts" => replace_exact(
            src,
            "                    println!(\"OK\");\n                    exit(0);\n                }\n                Ok(false) => {\n                    println!(\"FAIL\");\n                    exit(1);\n                }\n                Err(e) => {\n                    println!(\"MALFORMED: {e}\");",
            "                    println!(\"OK\");\n                    println!(\"FAIL\");\n                    exit(0);\n                }\n                Ok(false) => {\n                    println!(\"FAIL\");\n                    exit(1);\n                }\n                Err(e) => {\n                    println!(\"MALFORMED: {e}\");",
            1,
            "mutant two_verdicts",
        ),
        // a reason outside the closed list
        "foreign_reason" => replace_exact(
            src,
            "                        println!(\"POLICY_UNMET\");\n                        exit(3);",
            "                        println!(\"ANCHOR_PENDING\");\n                        exit(4);",
            1,
            "mutant foreign_reason",
        ),
        // a possible panic: index the decoded public key before its length is checked
        "panic" => replace_exact(
            src,
            "    let pk = b64_strict(pub_b64)?;\n    let pk_arr: [u8; 32] = pk",
            "    let pk = b64_strict(pub_b64)?;\n    let _erstes_fehlendes = pk[31];\n    let pk_arr: [u8; 32] = pk",
            1,
            "mutant panic",
        ),
        // same input, different verdict: the verdict depends on how often the function ran
        "nondeterministic" => replace_exact(
            src,
            ") -> Result<bool, String> {\n    // Z381 F2: the three header fields",
            ") -> Result<bool, String> {\n    static AUFRUFE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);\n    if AUFRUFE.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 2 == 1 {\n        return Ok(false);\n    }\n    // Z381 F2: the three header fields",
            1,
            "mutant nondeterministic",
        ),
        // Kani counter-checks (Z381 continuation), one per property, each inside the reach of the
        // harness that must find it.
        // P1, harness k5: the subtraction moves in front of its range check, so a tree_size of 0
        // underflows.
        "kani_underflow" => replace_exact(
            src,
            "    if fnn >= tree_size {\n        return Err(\"leaf_index out of range for tree_size\".into());\n    }\n    let mut sn = tree_size - 1;\n",
            "    let mut sn = tree_size - 1;\n    if fnn >= tree_size {\n        return Err(\"leaf_index out of range for tree_size\".into());\n    }\n",
            1,
            "mutant kani_underflow",
        ),
        // P2, harness k1: the strict-parse failure of verify-bundle prints a second stdout line.
        "kani_two_lines" => replace_exact(
            src,
            "                    println!(\"MALFORMED: {e}\");\n                    exit(2);\n                }\n            };\n            match verify_bundle(&v, expected_root.as_deref(), expected_tree_size) {",
            "                    println!(\"MALFORMED: {e}\");\n                    println!(\"MALFORMED\");\n                    exit(2);\n                }\n            };\n            match verify_bundle(&v, expected_root.as_deref(), expected_tree_size) {",
            1,
            "mutant kani_two_lines",
        ),
        // P3, harness k3: the parse result depends on how often the parser ran.
        "kani_parse_counter" => replace_exact(
            src,
            "fn strict_parse(bytes: &[u8]) -> Result<serde_json::Value, String> {\n",
            "fn strict_parse(bytes: &[u8]) -> Result<serde_json::Value, String> {\n    static AUFRUFE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);\n    if AUFRUFE.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 2 == 1 {\n        return Err(\"second call\".into());\n    }\n",
            1,
            "mutant kani_parse_counter",
        ),
        // P2, harness k2: a usage error writes a stdout line besides its stderr line.
        "kani_fatal_stdout" => replace_exact(
            src,
            "fn fatal(msg: &str) -> ! {\n    eprintln!(\"error: {msg}\");\n    exit(2);\n}",
            "fn fatal(msg: &str) -> ! {\n    println!(\"ERROR\");\n    eprintln!(\"error: {msg}\");\n    exit(2);\n}",
            1,
            "mutant kani_fatal_stdout",
        ),
        // P3, harness k6: the inclusion walk answers differently on every second call.
        "kani_walk_counter" => replace_exact(
            src,
            "    proof: &[Vec<u8>],\n) -> Result<Vec<u8>, String> {\n",
            "    proof: &[Vec<u8>],\n) -> Result<Vec<u8>, String> {\n    static AUFRUFE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);\n    if AUFRUFE.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 2 == 1 {\n        return Err(\"second call\".into());\n    }\n",
            1,
            "mutant kani_walk_counter",
        ),
        "" => src.to_string(),
        other => panic!("z381 build: unknown PB_Z381_MUTANT `{other}`"),
    }
}

fn main() {
    println!("cargo:rerun-if-changed={VERIFIER}");
    println!("cargo:rerun-if-env-changed=PB_Z381_MUTANT");
    println!("cargo:rustc-check-cfg=cfg(kani)");
    let src = fs::read_to_string(VERIFIER).expect("z381 build: verifier source not readable");

    // The unit tests of the verifier stay with the verifier; they read real files.
    let cut = src
        .find("\n#[cfg(test)]\nmod tests {\n")
        .expect("z381 build: test module not found");
    if src[cut + 1..].matches("#[cfg(test)]").count() != 1 || !src.ends_with("}\n") {
        panic!("z381 build: the test module is not the last item of the verifier");
    }
    let mut s = src[..cut + 1].to_string();

    // `include!` takes items, not a crate root: the crate-level doc block (`//!`) becomes a plain
    // comment. Comment text only; no token of the program changes.
    let doc_lines = s.lines().take_while(|l| l.starts_with("//!")).count();
    if doc_lines == 0 || s.lines().skip(doc_lines).any(|l| l.starts_with("//!")) {
        panic!("z381 build: the crate doc block is not where it is expected");
    }
    s = s
        .lines()
        .map(|l| match l.strip_prefix("//!") {
            Some(rest) => format!("//{rest}"),
            None => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";

    // The boundary must be exactly the one substituted below — no other process exit, no other
    // stream, no other argv source, no other file read.
    for (needle, count) in [
        ("std::process::", 1usize),
        ("std::env::", 1),
        ("std::io::", 1),
        ("std::fs::", 3),
        ("print!(", 0),
        ("eprint!(", 0),
        ("write!(", 0),
        ("writeln!(", 0),
    ] {
        let n = s.matches(needle).count();
        if n != count {
            panic!("z381 build: boundary `{needle}` expected {count} occurrence(s), found {n}");
        }
    }

    s = replace_exact(
        &s,
        "use std::process::exit;\n",
        "use crate::boundary::exit;\nuse crate::boundary::read_file_begrenzt;\n",
        1,
        "exit",
    );
    // argv: before the Z381 fix the verifier reads `std::env::args()`, after it `args_os()`; the
    // boundary models both with std's documented semantics.
    let a = s.matches("std::env::args()").count();
    let b = s.matches("std::env::args_os()").count();
    if a + b != 1 {
        panic!("z381 build: argv source expected once, found args()={a} args_os()={b}");
    }
    s = s.replace("std::env::args()", "crate::boundary::args()");
    s = s.replace("std::env::args_os()", "crate::boundary::args_os()");
    // The capped file read: before the Z381 fix it takes the path as `&str`, after it as `&Path`
    // (a path that is not valid UTF-8 is still a path). Exactly one of the two signatures.
    let sig_str = "fn read_file_begrenzt(path: &str) -> Result<Vec<u8>, String> {";
    let sig_path = "fn read_file_begrenzt(path: &Path) -> Result<Vec<u8>, String> {";
    let (a, b) = (s.matches(sig_str).count(), s.matches(sig_path).count());
    if a + b != 1 {
        panic!("z381 build: read_file_begrenzt expected once, found &str={a} &Path={b}");
    }
    s = replace_exact(
        &s,
        "fn read_file_begrenzt(path: &",
        "#[allow(dead_code)]\nfn read_file_begrenzt_vom_dateisystem(path: &",
        1,
        "read_file_begrenzt",
    );
    s = replace_exact(
        &s,
        "\nfn main() {\n",
        "\npub(crate) fn verifier_main() {\n",
        1,
        "main",
    );

    let mutant = env::var("PB_Z381_MUTANT").unwrap_or_default();
    s = plant(&s, &mutant);

    // The Kani harnesses live INSIDE the proof subject so they reach private functions; under a
    // normal build this item is configured away.
    let inner = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("src/kani_inner.rs");
    println!("cargo:rerun-if-changed={}", inner.display());
    s.push_str(&format!(
        "\n#[cfg(kani)]\nmod z381_kani {{\n    include!({:?});\n}}\n",
        inner.display().to_string()
    ));

    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("verifier.rs");
    fs::write(out, s).expect("z381 build: cannot write the proof subject");
}
