// Replay recorded pb_verify_rs calls against the WebAssembly build, in Node and in Chromium.
//
//   node replay.mjs <site dir> <record.jsonl> <result.json> [--no-browser]
//
// Every record holds a native call: arguments, input files, exit code, stdout and stderr. The
// replay runs the same arguments on the same bytes through the page's own run() in a headless
// Chromium served from <site dir>, and through the same WASI module in Node, with files held in
// memory in both. A call counts as identical only when exit code, stdout and stderr all match byte
// for byte. The browser part also drives the page's form once and counts every network request
// made after the verifier finished loading.

import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { execSync } from "node:child_process";
import { randomFillSync } from "node:crypto";
import http from "node:http";
import { extname, join, resolve } from "node:path";

const [siteArg, recordPath, outPath, flag] = process.argv.slice(2);
const site = resolve(siteArg);
const withBrowser = flag !== "--no-browser";
const { runWasi } = await import(join(site, "wasi.mjs"));
const records = readFileSync(recordPath, "utf8").trim().split("\n").map((l) => JSON.parse(l));
const b64 = (u8) => Buffer.from(u8).toString("base64");
const wasm = new WebAssembly.Module(readFileSync(join(site, "pb_verify_rs.wasm")));

function memoryFs(files) {
  return {
    stat(p) {
      const d = files.get(p);
      if (d) return { type: "file", size: d.length };
      const dir = p.endsWith("/") ? p : p + "/";
      for (const k of files.keys()) if (k.startsWith(dir)) return { type: "dir", size: 0 };
      return null;
    },
    read: (p) => files.get(p),
  };
}

async function nodeRun(rec) {
  const files = new Map(Object.entries(rec.files).map(([k, v]) => [k, new Uint8Array(Buffer.from(v, "base64"))]));
  const r = await runWasi(wasm, { args: ["pb_verify_rs", ...rec.argv], fs: memoryFs(files), randomFill: randomFillSync });
  return { exit: r.exitCode, trap: r.trap, stdout: b64(r.stdout), stderr: b64(r.stderr) };
}

function loadPlaywright() {
  try {
    return createRequire(import.meta.url)("playwright");
  } catch {
    const globalRoot = execSync("npm root -g", { encoding: "utf8" }).trim();
    return createRequire(join(globalRoot, "/"))("playwright");
  }
}

async function startBrowser() {
  const types = { ".html": "text/html", ".mjs": "text/javascript", ".wasm": "application/wasm" };
  const server = http.createServer((req, res) => {
    const name = req.url === "/" ? "index.html" : decodeURIComponent(req.url.slice(1).split("?")[0]);
    try {
      const body = readFileSync(join(site, name));
      res.writeHead(200, { "content-type": types[extname(name)] || "application/octet-stream" });
      res.end(body);
    } catch {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  const base = `http://127.0.0.1:${server.address().port}/`;
  const browser = await loadPlaywright().chromium.launch();
  const page = await browser.newPage();
  const requests = [];
  const errors = [];
  page.on("request", (r) => requests.push(`${r.method()} ${r.url().replace(base, "/")}`));
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  await page.goto(base + "index.html");
  await page.waitForSelector("#run:not([disabled])", { timeout: 30000 });
  return { server, browser, page, requests, errors, atReady: requests.length };
}

async function browserRun(page, rec) {
  return page.evaluate(async ({ argv, files }) => {
    const app = await import("./app.mjs");
    const dec = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
    const enc = (u) => {
      let s = "";
      for (let i = 0; i < u.length; i += 8192) s += String.fromCharCode.apply(null, u.subarray(i, i + 8192));
      return btoa(s);
    };
    const r = await app.run(argv, new Map(Object.entries(files).map(([k, v]) => [k, dec(v)])));
    return { exit: r.exitCode, trap: r.trap, stdout: enc(r.stdout), stderr: enc(r.stderr) };
  }, { argv: rec.argv, files: rec.files });
}

/** Drive the form the way a person would: pick the file, paste the key, press Verify. */
async function throughTheForm(page, rec) {
  await page.selectOption("#command", rec.argv[0]);
  await page.setInputFiles("#file", { name: "envelope.json", mimeType: "application/json",
                                      buffer: Buffer.from(rec.files[rec.argv[1]], "base64") });
  await page.fill("#key", rec.argv[2]);
  await page.click("#run");
  await page.waitForFunction(() => /^exit /.test(document.getElementById("verdict").textContent));
  return { verdict: await page.textContent("#verdict"), output: await page.textContent("#output") };
}

const same = (a, native) => a.trap === undefined && a.exit === native.exit && a.stdout === native.stdout
  && a.stderr === native.stderr;
const ctx = withBrowser ? await startBrowser() : null;
const rows = [];
for (const rec of records) {
  const native = { exit: rec.exit, stdout: rec.stdout, stderr: rec.stderr };
  const node = await nodeRun(rec);
  const row = { subcommand: rec.argv[0], nativeExit: rec.exit, node: same(node, native) };
  if (ctx) row.browser = same(await browserRun(ctx.page, rec), native);
  rows.push(row);
}
let form = null;
if (ctx) {
  const pick = (want) => records.find((r) => r.argv[0] === "verify-dsse" && r.exit === want && r.argv.length === 3);
  form = {};
  for (const want of [0, 1]) {
    const rec = pick(want);
    if (rec) form[`verify-dsse, native exit ${want}`] = await throughTheForm(ctx.page, rec);
  }
}

const bySubcommand = {};
for (const r of rows) {
  const s = (bySubcommand[r.subcommand] ||= { calls: 0, node_identical: 0, browser_identical: 0, native_exits: {} });
  s.calls++;
  s.node_identical += r.node ? 1 : 0;
  s.browser_identical += r.browser ? 1 : 0;
  s.native_exits[r.nativeExit] = (s.native_exits[r.nativeExit] || 0) + 1;
}
const summary = {
  calls: rows.length,
  node_identical: rows.filter((r) => r.node).length,
  browser: ctx ? `chromium ${ctx.browser.version()}` : "NOT MEASURED (--no-browser)",
  browser_identical: ctx ? rows.filter((r) => r.browser).length : null,
  requests_until_ready: ctx ? ctx.requests.slice(0, ctx.atReady) : null,
  requests_after_ready: ctx ? ctx.requests.slice(ctx.atReady) : null,
  page_errors: ctx ? ctx.errors : null,
  form,
  by_subcommand: bySubcommand,
};
if (ctx) {
  await ctx.browser.close();
  ctx.server.close();
}
writeFileSync(outPath, JSON.stringify({ summary, rows }, null, 2) + "\n");
console.log(JSON.stringify(summary, null, 2));
process.exitCode = summary.node_identical === rows.length
  && (!ctx || summary.browser_identical === rows.length) ? 0 : 1;
