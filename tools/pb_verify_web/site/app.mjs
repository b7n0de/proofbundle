// The page: picks files, runs pb_verify_rs.wasm on them in memory, shows exit code and output.
import { runWasi } from "./wasi.mjs";

const NEEDS_KEY = new Set(["verify-dsse", "verify-relation", "verify-relation-statement"]);
const MEANING = { 0: "verified", 1: "verification failed", 2: "malformed input", 3: "policy not met" };
const MOUNT = "/in/";

let module = null;
const $ = (id) => document.getElementById(id);

async function useWasm(bytes) {
  module = await WebAssembly.compile(bytes);
  let digest = "";
  try {
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    digest = `, sha256 ${Array.from(hash, (b) => b.toString(16).padStart(2, "0")).join("")}`;
  } catch {
    // crypto.subtle is missing outside a secure context; the verifier itself does not need it.
  }
  $("build").textContent = `pb_verify_rs.wasm: ${bytes.byteLength} bytes${digest}`;
  $("verdict").textContent = "Ready. Nothing has been verified yet.";
  $("run").disabled = false;
}

/**
 * Run the verifier on files held in memory.
 * @param {string[]} args arguments after the program name, as on the command line
 * @param {Map<string, Uint8Array>} files absolute path -> content
 */
export async function run(args, files) {
  if (!module) throw new Error("the verifier is not loaded");
  const fs = {
    stat(path) {
      const data = files.get(path);
      if (data) return { type: "file", size: data.length };
      const dir = path.endsWith("/") ? path : path + "/";
      for (const name of files.keys()) if (name.startsWith(dir)) return { type: "dir", size: 0 };
      return null;
    },
    read(path) {
      return files.get(path);
    },
  };
  return runWasi(module, {
    args: ["pb_verify_rs", ...args],
    fs,
    randomFill: (buf) => crypto.getRandomValues(buf),
  });
}

async function readPicked(input, files) {
  const names = [];
  for (const f of input.files) {
    files.set(MOUNT + f.name, new Uint8Array(await f.arrayBuffer()));
    names.push(f.name);
  }
  return names;
}

async function onSubmit(event) {
  event.preventDefault();
  // A result on screen belongs to the last run only: clear it before anything else can fail.
  $("verdict").textContent = "Verifying…";
  $("verdict").className = "";
  $("output").hidden = true;
  const command = $("command").value;
  const files = new Map();
  const [main] = await readPicked($("file"), files);
  const further = new Set(await readPicked($("more"), files));
  if (!main) {
    $("verdict").textContent = "Pick a file first.";
    return;
  }
  const args = [command, MOUNT + main];
  if (NEEDS_KEY.has(command)) args.push($("key").value.trim());
  for (const token of $("options").value.split(/\s+/).filter(Boolean)) {
    args.push(further.has(token) ? MOUNT + token : token);
  }
  const result = await run(args, files);
  const dec = new TextDecoder();
  const verdict = $("verdict");
  if (result.trap !== undefined) {
    verdict.textContent = `The verifier stopped abnormally (${result.trap}). Nothing was verified.`;
    verdict.className = "bad";
  } else {
    const meaning = command.startsWith("verify-") ? `: ${MEANING[result.exitCode] ?? "unknown"}` : "";
    verdict.textContent = `exit ${result.exitCode}${meaning}`;
    verdict.className = result.exitCode === 0 ? "ok" : "bad";
  }
  const out = $("output");
  out.textContent = dec.decode(result.stdout) + dec.decode(result.stderr);
  out.hidden = false;
}

async function load() {
  $("form").addEventListener("submit", onSubmit);
  try {
    const resp = await fetch("pb_verify_rs.wasm");
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    await useWasm(new Uint8Array(await resp.arrayBuffer()));
  } catch (e) {
    $("verdict").textContent = `The verifier could not be loaded (${e.message}). Nothing can be verified.`;
    $("verdict").className = "bad";
  }
}

load();
