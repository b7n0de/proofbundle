#!/usr/bin/env node
// Command-line runner for the WebAssembly build of pb_verify_rs, under Node.
//
//   node run.mjs <subcommand> [args...]
//
// It runs site/pb_verify_rs.wasm through the same WASI module the page uses, with the local file
// system as the file backend, and exits with the program's exit code. Its arguments, output and
// exit code are those of the native binary, so the cross-check against the Python verifier can
// drive it in place of the native binary. PB_VERIFY_WASM names another .wasm file.

import { readFileSync, statSync } from "node:fs";
import { randomFillSync } from "node:crypto";
import { dirname, join, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";
import { runWasi } from "./site/wasi.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const wasmPath = process.env.PB_VERIFY_WASM || join(here, "site", "pb_verify_rs.wasm");

const fs = {
  stat(path) {
    try {
      const st = statSync(path);
      return { type: st.isFile() ? "file" : st.isDirectory() ? "dir" : "other", size: st.size };
    } catch {
      return null;
    }
  },
  read(path) {
    return new Uint8Array(readFileSync(path));
  },
};

// WASI sees one preopened root, so a relative argument is made absolute against this process's
// working directory, the way the native binary would resolve it.
const args = process.argv.slice(2).map((a) =>
  !a.startsWith("-") && !a.startsWith("/") && fs.stat(resolvePath(a)) ? resolvePath(a) : a,
);

const module = new WebAssembly.Module(readFileSync(wasmPath));
const result = await runWasi(module, {
  args: ["pb_verify_rs", ...args],
  fs,
  randomFill: (buf) => randomFillSync(buf),
});
process.stdout.write(result.stdout);
process.stderr.write(result.stderr);
if (result.trap !== undefined) {
  process.stderr.write(`pb_verify_rs.wasm trapped: ${result.trap}\n`);
  process.exitCode = 70;
} else {
  process.exitCode = result.exitCode;
}
