//! CAP-1 Verifier, zweite unabhaengige Umsetzung. Keine Abhaengigkeiten, kein Netz, keine Uhr.
mod json;
mod regeln;

use std::io::Read;
use std::path::PathBuf;

fn main() {
    // Z381 O381-3: argv is read as `OsString` and the path stays a `Path` up to the open. A file
    // name that is not valid UTF-8 is still a file name: `std::env::args()` panicked on it (exit
    // 101, no verdict), where the Python implementation reads the same file, measured.
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if args.len() != 2 {
        eprintln!("usage: cap1_verify_rs <attestation.json>");
        std::process::exit(2);
    }
    let path = PathBuf::from(&args[1]);
    let mut s = String::new();
    match std::fs::File::open(&path).and_then(|mut f| f.read_to_string(&mut s)) {
        Ok(_) => {}
        Err(e) => { eprintln!("konnte {} nicht lesen: {e}", path.display()); std::process::exit(2); }
    }
    let doc = match json::lies(&s) {
        Ok(d) => d,
        Err(e) => { println!("REFUSED"); println!("  JSON: {e}"); std::process::exit(1); }
    };
    let f = regeln::verify(&doc);
    if f.is_empty() {
        println!("CONFORMS");
        std::process::exit(0);
    }
    println!("REFUSED");
    for v in &f { println!("  {}: {}", v.regel, v.grund); }
    std::process::exit(1);
}
