//! Z381: the substituted boundary is checked against the REAL binary. A sample of every domain is
//! run through `tools/pb_verify_rs/target/release/pb_verify_rs` as a separate process (real argv,
//! real file, real exit) and must give the same exit code, the same stdout and the same stderr
//! lines as the proof subject. A panic must be a panic on both sides (exit 101).
//!
//! This is what makes the proof a statement about the shipped binary and not about the harness:
//! if the boundary model (assumptions A3, A4 of the report) were wrong, this test turns red.
//! It needs the binary built first: `cargo build --release --locked` in tools/pb_verify_rs.

mod common;

use std::path::PathBuf;
use std::process::Command;

use common::domains::{d1, d2, d3, d4, d5, d6};
use z381_pruefentscheidung::boundary::Observed;
use z381_pruefentscheidung::decide_at;

fn binary() -> PathBuf {
    let p = std::env::var_os("PB_VERIFY_RS_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tools/pb_verify_rs/target/release/pb_verify_rs")
        });
    assert!(
        p.is_file(),
        "real binary not found at {} — build it first (cargo build --release --locked in tools/pb_verify_rs); \
         this test is never skipped",
        p.display()
    );
    p
}

#[derive(Debug, PartialEq)]
enum Seen {
    Exit(i32, Vec<String>, Vec<String>),
    Panic,
}

fn lines(b: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(b)
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn harness_agrees_with_real_binary_on_samples() {
    let bin = binary();
    let dir = std::env::temp_dir().join(format!("z381_real_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut compared = 0usize;
    let mut panics = 0usize;
    let mut diffs: Vec<String> = Vec::new();
    let mut ndiff = 0usize;
    for (d, step) in [
        (d1(), 9_973usize),
        (d2(), 9_967),
        (d3(), 97),
        (d4(), 17),
        (d5(), 13),
        (d6(), 7),
    ] {
        let mut k = 0;
        while k < d.n {
            let input = (d.gen)(k);
            // the one file lives under `input.name` (raw bytes: D6 uses a name that is not UTF-8);
            // every other name is cleared, so no file of an earlier sample is visible
            for e in std::fs::read_dir(&dir).unwrap() {
                std::fs::remove_file(e.unwrap().path()).unwrap();
            }
            let file = dir.join(&input.name);
            if let Some(b) = &input.file {
                std::fs::write(&file, b).unwrap();
            }
            let out = Command::new(&bin)
                .args(&input.argv[1..])
                .current_dir(&dir)
                .env("RUST_BACKTRACE", "0")
                .output()
                .unwrap();
            let real = match out.status.code() {
                Some(101) => Seen::Panic,
                Some(c) => Seen::Exit(c, lines(&out.stdout), lines(&out.stderr)),
                None => panic!("real binary killed by a signal on {:?}", input.argv),
            };
            let model = match decide_at(input.argv.clone(), input.name.clone(), input.file.clone())
            {
                Observed::Exited { code, out, err } => Seen::Exit(code, out, err),
                Observed::Panicked { .. } => Seen::Panic,
                Observed::Returned { out, err } => Seen::Exit(0, out, err),
            };
            if real == Seen::Panic {
                panics += 1;
            }
            if real != model {
                ndiff += 1;
                if diffs.len() < 5 {
                    diffs.push(format!(
                        "{} k={k}: real {real:?} vs harness {model:?}",
                        d.name
                    ));
                }
            }
            compared += 1;
            k += step;
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    println!("Z381 REAL_BINARY compared={compared} panics_on_both_sides={panics} diffs={ndiff}");
    assert!(ndiff == 0, "harness and real binary disagree: {diffs:#?}");
}
