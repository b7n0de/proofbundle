//! The process boundary of the verifier, replaced for the proof.
//!
//! Four primitives, each with the semantics std documents for the real one:
//! * `args()`  — `std::env::args()`: yields `String`s, PANICS on an argument that is not valid
//!   Unicode ("The returned iterator will panic during iteration if any argument to the process is
//!   not valid Unicode", std docs). This is the documented behaviour, measured on the real binary
//!   (exit 101), not an invention of the proof.
//! * `args_os()` — `std::env::args_os()`: yields `OsString`s, never panics.
//! * `exit(code)` — `std::process::exit`: never returns.
//! * `read_file_begrenzt(path)` — the verifier's own capped file read, on a virtual regular file
//!   whose content is the input bytes (assumption A4 of the report: the real function returns
//!   exactly these bytes for a regular file of at most `BUDGET_INPUT_BYTES`). The path is compared
//!   as raw bytes (`OsStr`), so a file under a name that is not valid UTF-8 is a file like any
//!   other; it takes `&str` (the verifier before the Z381 fix) and `&Path` (after it).
//! `out`/`err` collect what `println!`/`eprintln!` would have written, one entry per line.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// The default path of the virtual file system's one file.
pub const INPUT_PATH: &str = "input.json";
/// A legal Unix file name that is not valid UTF-8 (byte 0xff), used as an argv word and, in D6, as
/// the name the one file lives under.
pub const INPUT_PATH_NOT_UTF8: &[u8] = b"input\xff.json";
const BUDGET_INPUT_BYTES: usize = 8_388_608;

pub fn input_path_not_utf8() -> OsString {
    OsStr::from_bytes(INPUT_PATH_NOT_UTF8).to_os_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observed {
    /// The verifier called `exit(code)` — the only way it delivers a verdict.
    Exited {
        code: i32,
        out: Vec<String>,
        err: Vec<String>,
    },
    /// The verifier returned from `main` without calling `exit`: a path without a verdict.
    Returned { out: Vec<String>, err: Vec<String> },
    /// The verifier panicked.
    Panicked {
        message: String,
        out: Vec<String>,
        err: Vec<String>,
    },
}

#[derive(Default)]
struct Io {
    args: Vec<OsString>,
    /// The path the one file lives under (empty: `INPUT_PATH`).
    name: OsString,
    file: Option<Vec<u8>>,
    out: Vec<String>,
    err: Vec<String>,
}

fn virtual_read(
    io_name: &OsStr,
    io_file: Option<&Vec<u8>>,
    path: &Path,
) -> Result<Vec<u8>, String> {
    let name = if io_name.is_empty() {
        OsStr::new(INPUT_PATH)
    } else {
        io_name
    };
    match io_file {
        Some(bytes) if path.as_os_str() == name => {
            if bytes.len() > BUDGET_INPUT_BYTES {
                return Err(format!(
                    "verification budget exceeded: input_bytes = {} > limit {}",
                    bytes.len(),
                    BUDGET_INPUT_BYTES
                ));
            }
            Ok(bytes.clone())
        }
        // `Path::display` is what the verifier prints after the Z381 fix; for a UTF-8 path it is
        // the path itself, as before.
        _ => Err(format!(
            "cannot read {}: No such file or directory (os error 2)",
            path.display()
        )),
    }
}

// ---------------------------------------------------------------------------------------------
// Enumeration backend (plain `cargo test`): one verifier run per call, isolated per thread.
// ---------------------------------------------------------------------------------------------
#[cfg(not(kani))]
mod imp {
    use super::*;
    use std::cell::RefCell;
    use std::panic::{self, AssertUnwindSafe};
    use std::sync::Once;

    thread_local! {
        static IO: RefCell<Io> = RefCell::new(Io::default());
        static LAST_PANIC: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    struct ExitSignal(i32);

    pub fn args() -> impl Iterator<Item = String> {
        let a = IO.with(|io| io.borrow().args.clone());
        // std::env::Args::next: `self.inner.next().map(|s| s.into_string().unwrap())`
        a.into_iter().map(|s| s.into_string().unwrap())
    }

    pub fn args_os() -> impl Iterator<Item = OsString> {
        IO.with(|io| io.borrow().args.clone()).into_iter()
    }

    pub fn exit(code: i32) -> ! {
        // resume_unwind does not run the panic hook: an exit is not counted as a panic.
        panic::resume_unwind(Box::new(ExitSignal(code)))
    }

    pub fn read_file_begrenzt(path: impl AsRef<Path>) -> Result<Vec<u8>, String> {
        IO.with(|io| {
            let io = io.borrow();
            virtual_read(&io.name, io.file.as_ref(), path.as_ref())
        })
    }

    pub fn out(line: String) {
        IO.with(|io| io.borrow_mut().out.push(line));
    }

    pub fn err(line: String) {
        IO.with(|io| io.borrow_mut().err.push(line));
    }

    fn install_hook() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            panic::set_hook(Box::new(|info| {
                let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
                    (*s).to_string()
                } else if let Some(s) = info.payload().downcast_ref::<String>() {
                    s.clone()
                } else {
                    "<non-string panic payload>".to_string()
                };
                let loc = info
                    .location()
                    .map(|l| format!(" at {}:{}", l.file(), l.line()))
                    .unwrap_or_default();
                LAST_PANIC.with(|p| *p.borrow_mut() = Some(format!("{msg}{loc}")));
            }));
        });
    }

    /// Run the real verifier once: `argv` includes the program name, `file` is the content of
    /// `INPUT_PATH` (None: the path does not exist).
    pub fn decide(argv: Vec<OsString>, file: Option<Vec<u8>>) -> Observed {
        decide_at(argv, OsString::from(INPUT_PATH), file)
    }

    /// As `decide`, with the one file living under `name` instead of `INPUT_PATH`.
    pub fn decide_at(argv: Vec<OsString>, name: OsString, file: Option<Vec<u8>>) -> Observed {
        install_hook();
        IO.with(|io| {
            *io.borrow_mut() = Io {
                args: argv,
                name,
                file,
                out: Vec::new(),
                err: Vec::new(),
            }
        });
        LAST_PANIC.with(|p| *p.borrow_mut() = None);
        let r = panic::catch_unwind(AssertUnwindSafe(crate::verifier::verifier_main));
        let (out, err) = IO.with(|io| {
            let mut io = io.borrow_mut();
            (std::mem::take(&mut io.out), std::mem::take(&mut io.err))
        });
        match r {
            Ok(()) => Observed::Returned { out, err },
            Err(payload) => match payload.downcast::<ExitSignal>() {
                Ok(sig) => Observed::Exited {
                    code: sig.0,
                    out,
                    err,
                },
                Err(_) => Observed::Panicked {
                    message: LAST_PANIC
                        .with(|p| p.borrow_mut().take())
                        .unwrap_or_else(|| "<panic without hook record>".to_string()),
                    out,
                    err,
                },
            },
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Kani backend: the verdict is checked at the one place a verdict is delivered, `exit`. A panic
// anywhere is a Kani failure by itself; returning from `verifier_main` is asserted false by the
// harness. Written for Kani; NOT RUN in this session (see the report).
// ---------------------------------------------------------------------------------------------
#[cfg(kani)]
mod imp {
    use super::*;

    static mut IO: Option<Io> = None;

    #[allow(static_mut_refs)]
    fn io() -> &'static mut Io {
        unsafe { IO.get_or_insert_with(Io::default) }
    }

    pub fn set_input(argv: Vec<OsString>, file: Option<Vec<u8>>) {
        *io() = Io {
            args: argv,
            name: OsString::new(),
            file,
            out: Vec::new(),
            err: Vec::new(),
        };
    }

    pub fn args() -> impl Iterator<Item = String> {
        io().args
            .clone()
            .into_iter()
            .map(|s| s.into_string().unwrap())
    }

    pub fn args_os() -> impl Iterator<Item = OsString> {
        io().args.clone().into_iter()
    }

    pub fn exit(code: i32) -> ! {
        let io = io();
        assert!(
            crate::verdict::classify_parts(code, &io.out, &io.err).is_ok(),
            "Z381: exit without exactly one verdict of the closed list"
        );
        kani::assume(false);
        unreachable!()
    }

    pub fn read_file_begrenzt(path: impl AsRef<Path>) -> Result<Vec<u8>, String> {
        let io = io();
        virtual_read(&io.name, io.file.as_ref(), path.as_ref())
    }

    pub fn out(line: String) {
        io().out.push(line);
    }

    pub fn err(line: String) {
        io().err.push(line);
    }
}

pub use imp::*;
