# pb_verify_rs in the browser

A static page that runs the independent Rust verifier, `pb_verify_rs`, compiled to WebAssembly. A
receipt is verified in the browser tab: the files you pick are read into memory and handed to the
verifier, and the page makes no network request after it has loaded.

## How it works

`pb_verify_rs` is compiled unchanged for the `wasm32-wasip1` target, so the page runs the same
`main()`, argument parsing, checks and exit codes as the native binary. `site/wasi.mjs` provides the
few WASI calls the program makes: arguments, standard output and error, read-only files held in
memory, random bytes and the exit code. A file can only be opened for reading.

| File | Role |
|---|---|
| `build.sh` | Builds `site/pb_verify_rs.wasm` from `../pb_verify_rs` with its pinned toolchain and `Cargo.lock` |
| `site/index.html`, `site/app.mjs` | The page |
| `site/wasi.mjs` | The WASI calls, shared by the page and the Node runner |
| `run.mjs` | Runs the WebAssembly build under Node with the command line of the native binary |
| `parity/` | Measures the WebAssembly build against the native build and the Python verifier |

The `.wasm` file is a build output and is not committed.

## Build and open

```sh
rustup target add wasm32-wasip1 --toolchain "$(sed -n 's/^channel = "\(.*\)"/\1/p' ../pb_verify_rs/rust-toolchain.toml)"
./build.sh
cd site && python3 -m http.server 8000
```

Then open `http://localhost:8000/`. A page opened directly from disk does not work: browsers do not
run module scripts from `file://`.

## What runs in the browser

Every subcommand of `pb_verify_rs` runs in the browser: `verify-dsse`, `verify-relation`,
`verify-relation-statement`, `verify-bundle`, `verify-trust-pack-threshold`, `content-root`,
`strict-parse`, `merkle-root`, `budget` and `coverage-report`. The page offers the first seven.

Not applicable in the browser:

- The refusal of a FIFO, a device or a directory as input. A file picked in a browser is always a
  byte string. The Node runner reads the local file system and keeps this check.
- Checks the Python verifier makes that `pb_verify_rs` does not implement. The browser build can
  only do what the Rust verifier does; `crosscheck.py` names those checks in its output under
  "NOT RUN DIFFERENTIALLY".

One known difference in text, not in verdict: an error from the operating system names its error
number, and WASI numbers differ from Linux ones, so a missing file reads `os error 44` instead of
`os error 2`. The exit code is the same.

## Measure parity

With the native binary built (`cargo build --release` in `../pb_verify_rs`), `site/pb_verify_rs.wasm`
built, and the package importable:

```sh
python3 parity/parity.py --out /tmp/pb-verify-web-parity
```

It runs `crosscheck.py` with the native binary and with the WebAssembly build and compares the two
runs, then replays every recorded call of the native binary in Node and in a headless Chromium
(Playwright), through the page's own code, and counts the calls whose exit code, stdout and stderr
are identical. `--no-browser` skips Chromium.
