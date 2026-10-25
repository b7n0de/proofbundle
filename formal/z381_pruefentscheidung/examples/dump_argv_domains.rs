//! Z381: write the inputs of the argv domains D5 and D6 as JSON lines, so a second program can run
//! the SAME inputs through the Python verifier and the real Rust binary (`paritaet_python.py`).
//! One line per input: domain, index, argv after the program name (hex), the file name (hex) and
//! the file content (hex, or null when the file does not exist).
//!
//! With `--d3-step N` / `--d4-step N` it also writes every N-th input of D3 / D4 (the bundle
//! domains), so the Python verdict can be compared on bundles too (Z381 continuation, F2).
//!
//!   cargo run --offline --example dump_argv_domains -- <out.jsonl> [--d3-step N] [--d4-step N]

#[path = "../tests/common/mod.rs"]
mod common;

use std::io::Write;
use std::os::unix::ffi::OsStrExt;

use common::domains::{d3, d4, d5, d6, Domain};

fn main() {
    let mut args = std::env::args().skip(1);
    let out = args
        .next()
        .expect("usage: dump_argv_domains <out.jsonl> [--d3-step N] [--d4-step N]");
    let mut domains: Vec<(Domain, usize)> = Vec::new();
    while let Some(flag) = args.next() {
        let step: usize = args
            .next()
            .and_then(|v| v.parse().ok())
            .filter(|&v| v > 0)
            .expect("a step must be a positive integer");
        match flag.as_str() {
            "--d3-step" => domains.push((d3(), step)),
            "--d4-step" => domains.push((d4(), step)),
            other => panic!("unknown flag {other}"),
        }
    }
    domains.push((d5(), 1));
    domains.push((d6(), 1));
    let mut w = std::io::BufWriter::new(std::fs::File::create(&out).expect("create"));
    for (d, step) in domains {
        let mut written = 0usize;
        for k in (0..d.n).step_by(step) {
            let i = (d.gen)(k);
            let line = serde_json::json!({
                "domain": d.name,
                "k": k,
                "argv": i.argv[1..].iter().map(|a| hex::encode(a.as_bytes())).collect::<Vec<_>>(),
                "name": hex::encode(i.name.as_bytes()),
                "file": i.file.as_ref().map(hex::encode),
            });
            writeln!(w, "{line}").expect("write");
            written += 1;
        }
        eprintln!(
            "Z381 DUMP {} inputs={written} of {} step={step}",
            d.name, d.n
        );
    }
}
