//! Z381 O381-3: a file under a name that is not valid UTF-8 gets the verdict its content gets.
//!
//! Before the fix every such name ended in a panic of `std::env::args()`, exit 101, measured at
//! 22aa954e for all three cases below; the Python implementation (`py/cap1_verify.py`) answers 0
//! for the positive control and 1 for the counter proof under the same names. `CAP1_VERIFY_RS_BIN`
//! runs the cases against another binary (the red run).

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    std::env::var_os("CAP1_VERIFY_RS_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_cap1_verify_rs")))
}

fn vector(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../conformance/cap1")
        .join(name)
        .join("document.json")
}

#[test]
fn a_file_name_that_is_not_utf8_is_read() {
    let dir = std::env::temp_dir().join(format!("cap1_argv_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pv = OsString::from_vec(b"pv\xff.json".to_vec());
    let nc = OsString::from_vec(b"nc\xff.json".to_vec());
    let missing = OsString::from_vec(b"missing\xff.json".to_vec());
    std::fs::copy(
        vector("cap1-positive-control-pv-01-complete-run-catalogued-basis"),
        dir.join(&pv),
    )
    .unwrap();
    std::fs::copy(
        vector("cap1-counter-proof-nc-05-examined-exceeds-eligible"),
        dir.join(&nc),
    )
    .unwrap();
    let mut wrong = Vec::new();
    for (name, exit, first_line) in [(&pv, 0, "CONFORMS"), (&nc, 1, "REFUSED"), (&missing, 2, "")] {
        let out = Command::new(binary())
            .arg(name)
            .current_dir(&dir)
            .env("RUST_BACKTRACE", "0")
            .output()
            .unwrap();
        let code = out.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&out.stdout);
        if code != exit || stdout.lines().next().unwrap_or("") != first_line {
            wrong.push(format!(
                "{}: expected {exit} {first_line:?}, got {code} {:?}",
                name.to_string_lossy(),
                stdout.lines().next().unwrap_or("")
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
