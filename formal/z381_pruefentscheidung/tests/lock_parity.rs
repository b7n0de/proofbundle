//! Z381: the proof subject is built with the SAME dependency versions and checksums as the
//! verifier. A proof against a different serde_json or ed25519-dalek would be a proof about a
//! different program.

use std::collections::BTreeSet;

fn packages(lock: &str, skip: &str) -> BTreeSet<(String, String, String)> {
    let mut out = BTreeSet::new();
    for block in lock.split("[[package]]").skip(1) {
        let field = |k: &str| {
            block
                .lines()
                .find_map(|l| l.strip_prefix(&format!("{k} = \"")))
                .map(|v| v.trim_end_matches('"').to_string())
                .unwrap_or_default()
        };
        if field("name") != skip {
            out.insert((field("name"), field("version"), field("checksum")));
        }
    }
    out
}

#[test]
fn same_versions_and_checksums_as_the_verifier() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let ours = std::fs::read_to_string(format!("{dir}/Cargo.lock")).unwrap();
    let theirs =
        std::fs::read_to_string(format!("{dir}/../../tools/pb_verify_rs/Cargo.lock")).unwrap();
    let a = packages(&ours, "z381_pruefentscheidung");
    let b = packages(&theirs, "pb_verify_rs");
    assert!(a.len() > 20, "lock file not parsed");
    assert_eq!(a, b);
}

#[test]
fn same_dependency_lines_as_the_verifier() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let deps = |p: &str| -> Vec<String> {
        let s = std::fs::read_to_string(p).unwrap();
        let start = s.find("[dependencies]\n").expect("dependencies");
        s[start..]
            .lines()
            .skip(1)
            .take_while(|l| !l.starts_with('['))
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect()
    };
    assert_eq!(
        deps(&format!("{dir}/Cargo.toml")),
        deps(&format!("{dir}/../../tools/pb_verify_rs/Cargo.toml"))
    );
}
