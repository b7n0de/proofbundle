//! CAP-1 Verifier, zweite unabhaengige Umsetzung. Keine Abhaengigkeiten, kein Netz, keine Uhr.
mod json;
mod regeln;

use std::io::Read;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: cap1_verify_rs <attestation.json>");
        std::process::exit(2);
    }
    let mut s = String::new();
    match std::fs::File::open(&args[1]).and_then(|mut f| f.read_to_string(&mut s)) {
        Ok(_) => {}
        Err(e) => { eprintln!("konnte {} nicht lesen: {e}", args[1]); std::process::exit(2); }
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
