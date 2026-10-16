//! Z381: the decision function of `pb_verify_rs verify-bundle`, made callable for a proof.
//!
//! `verifier` is the real verifier source (see `build.rs`); `boundary` replaces the four process
//! primitives it touches. Nothing else is replaced. `decide` runs the verifier once on one input
//! and returns what a caller of the binary would observe: the exit code and the two streams, or
//! the fact that it panicked, or that it returned without any verdict.

#![allow(clippy::all)]

// Textual scope: these shadow std's macros inside `verifier`, so the verifier's own `println!`
// and `eprintln!` calls write into the boundary instead of the process streams.
macro_rules! println {
    ($($t:tt)*) => { $crate::boundary::out(format!($($t)*)) };
}
macro_rules! eprintln {
    ($($t:tt)*) => { $crate::boundary::err(format!($($t)*)) };
}

pub mod boundary;

#[allow(dead_code, unused_imports, clippy::all)]
mod verifier {
    include!(concat!(env!("OUT_DIR"), "/verifier.rs"));
}

pub mod verdict;

#[cfg(not(kani))]
pub use boundary::decide;
