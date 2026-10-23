//! Shared driver: decide every input of a finite domain twice, check exactly one verdict of the
//! closed list and equality of both runs, and report a histogram plus the first violations.

#![allow(dead_code)]

pub mod domains;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::sync::Mutex;
use std::time::Instant;

use z381_pruefentscheidung::boundary::{Observed, INPUT_PATH};
use z381_pruefentscheidung::decide_at;
use z381_pruefentscheidung::verdict::{classify_parts, Class};

#[derive(Clone)]
pub struct Input {
    pub argv: Vec<OsString>,
    /// The path the file lives under: `INPUT_PATH` in D1-D5, a name that is not UTF-8 in D6.
    pub name: OsString,
    pub file: Option<Vec<u8>>,
}

impl Input {
    /// An input whose file (if any) lives under `INPUT_PATH`.
    pub fn new(argv: Vec<OsString>, file: Option<Vec<u8>>) -> Self {
        Input {
            argv,
            name: INPUT_PATH.into(),
            file,
        }
    }
}

pub fn bundle_argv(flags: &[&str]) -> Vec<OsString> {
    let mut v: Vec<OsString> = vec![
        "pb_verify_rs".into(),
        "verify-bundle".into(),
        INPUT_PATH.into(),
    ];
    v.extend(flags.iter().map(OsString::from));
    v
}

fn show(i: &Input) -> String {
    let file = match &i.file {
        None => "<no file>".to_string(),
        Some(b) if b.len() <= 96 => format!("{:?}", String::from_utf8_lossy(b)),
        Some(b) => format!("{} bytes, sha-prefix {:02x?}", b.len(), &b[..8]),
    };
    format!("argv={:?} name={:?} file={file}", i.argv, i.name)
}

/// The three properties for one input. Ok(class) or the violated property.
pub fn check(i: &Input) -> Result<Class, String> {
    let a = decide_at(i.argv.clone(), i.name.clone(), i.file.clone());
    let b = decide_at(i.argv.clone(), i.name.clone(), i.file.clone());
    let class = match &a {
        Observed::Exited { code, out, err } => classify_parts(*code, out, err)
            .map_err(|e| format!("P2 (exactly one verdict) violated: {e}: {a:?}"))?,
        Observed::Returned { .. } => {
            return Err(format!(
                "P2 (exactly one verdict) violated: no verdict: {a:?}"
            ))
        }
        Observed::Panicked { .. } => return Err(format!("P1 (no panic) violated: {a:?}")),
    };
    if a != b {
        return Err(format!(
            "P3 (same input, same verdict) violated: {a:?} vs {b:?}"
        ));
    }
    Ok(class)
}

pub struct Report {
    pub name: &'static str,
    pub inputs: usize,
    pub histogram: BTreeMap<String, usize>,
    pub violations: usize,
    pub first: Vec<String>,
    pub seconds: f64,
}

/// Decide a whole domain on all cores. `gen(k)` builds input k of `n`.
pub fn run_domain<F>(name: &'static str, n: usize, gen: F) -> Report
where
    F: Fn(usize) -> Input + Sync,
{
    let t = Instant::now();
    let threads = std::thread::available_parallelism().map_or(1, |p| p.get());
    let hist: Mutex<BTreeMap<String, usize>> = Mutex::new(BTreeMap::new());
    let bad: Mutex<(usize, Vec<String>)> = Mutex::new((0, Vec::new()));
    std::thread::scope(|s| {
        for w in 0..threads {
            let (gen, hist, bad) = (&gen, &hist, &bad);
            s.spawn(move || {
                let mut local: BTreeMap<String, usize> = BTreeMap::new();
                let mut k = w;
                while k < n {
                    let i = gen(k);
                    match check(&i) {
                        Ok(c) => *local.entry(format!("{c:?}")).or_default() += 1,
                        Err(e) => {
                            let mut b = bad.lock().unwrap();
                            b.0 += 1;
                            if b.1.len() < 5 {
                                b.1.push(format!("{e}\n    input: {}", show(&i)));
                            }
                        }
                    }
                    k += threads;
                }
                let mut h = hist.lock().unwrap();
                for (c, v) in local {
                    *h.entry(c).or_default() += v;
                }
            });
        }
    });
    let (violations, first) = bad.into_inner().unwrap();
    let r = Report {
        name,
        inputs: n,
        histogram: hist.into_inner().unwrap(),
        violations,
        first,
        seconds: t.elapsed().as_secs_f64(),
    };
    println!(
        "Z381 DOMAIN {} inputs={} runs={} violations={} seconds={:.1} histogram={:?}",
        r.name,
        r.inputs,
        2 * r.inputs,
        r.violations,
        r.seconds,
        r.histogram
    );
    for f in &r.first {
        println!("Z381 VIOLATION {}: {f}", r.name);
    }
    r
}

pub fn assert_clean(r: &Report) {
    assert_eq!(
        r.violations, 0,
        "domain {}: {} of {} inputs violate P1/P2/P3; first: {:#?}",
        r.name, r.violations, r.inputs, r.first
    );
}

/// The words of a byte domain: every byte string over `alphabet` of length 0..=max, in order.
pub fn word(alphabet: &[u8], max: usize, mut k: usize) -> Vec<u8> {
    let a = alphabet.len();
    let mut len = 0;
    let mut block = 1usize;
    while k >= block {
        k -= block;
        len += 1;
        block *= a;
        assert!(len <= max, "index past the domain");
    }
    let mut w = vec![0u8; len];
    for slot in w.iter_mut().rev() {
        *slot = alphabet[k % a];
        k /= a;
    }
    w
}

pub fn words(alphabet_len: usize, max: usize) -> usize {
    (0..=max).map(|l| alphabet_len.pow(l as u32)).sum()
}
