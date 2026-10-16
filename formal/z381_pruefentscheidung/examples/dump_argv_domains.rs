//! Z381: write the inputs of the argv domains D5 and D6 as JSON lines, so a second program can run
//! the SAME inputs through the Python verifier and the real Rust binary (`paritaet_python.py`).
//! One line per input: domain, index, argv after the program name (hex), the file name (hex) and
//! the file content (hex, or null when the file does not exist).
//!
//!   cargo run --offline --example dump_argv_domains -- <out.jsonl>

#[path = "../tests/common/mod.rs"]
mod common;

use std::io::Write;
use std::os::unix::ffi::OsStrExt;

use common::domains::{d5, d6};

fn main() {
    let out = std::env::args_os()
        .nth(1)
        .expect("usage: dump_argv_domains <out.jsonl>");
    let mut w = std::io::BufWriter::new(std::fs::File::create(&out).expect("create"));
    for d in [d5(), d6()] {
        for k in 0..d.n {
            let i = (d.gen)(k);
            let line = serde_json::json!({
                "domain": d.name,
                "k": k,
                "argv": i.argv[1..].iter().map(|a| hex::encode(a.as_bytes())).collect::<Vec<_>>(),
                "name": hex::encode(i.name.as_bytes()),
                "file": i.file.as_ref().map(hex::encode),
            });
            writeln!(w, "{line}").expect("write");
        }
        eprintln!("Z381 DUMP {} inputs={}", d.name, d.n);
    }
}
