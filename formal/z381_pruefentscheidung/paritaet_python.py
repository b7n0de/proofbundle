#!/usr/bin/env python3
"""Z381: Rust and Python verdict over the argv domains D5 and D6, measured with BOTH verifiers.

The inputs come from `cargo run --example dump_argv_domains` (the same enumeration the proof uses).
Every input is decided by the real Rust binary (`pb_verify_rs verify-bundle ...`, its own process)
and by the Python verifier (`proofbundle verify ...`, the CLI's `main` in a worker process, with
argv decoded the way CPython decodes a process argv: `os.fsdecode`, surrogateescape). The verdict
compared is the exit code, the one contract both verifiers share (0 PASS, 1 FAIL, 2 malformed or
usage, 3 policy unmet); the output text differs by design.

Three checks besides the comparison itself:
* the in-process Python verdict equals the verdict of a real `proofbundle` process on a sample,
  so the worker is not a model of Python but Python;
* no Rust run panics (exit 101) and every exit code is in 0..=3;
* TWIN PROPERTY. Every input that carries the word that is not UTF-8 (`input\\xff.json`) has a twin
  in which that word, and the file name, is the UTF-8 word `input_.json`. Each verifier must give
  the twin the verdict it gives the input. Where that holds, a disagreement between Rust and Python
  on an input with the non-UTF-8 word is also a disagreement on a UTF-8 input, i.e. it does not
  come from the bytes being no UTF-8.

The disagreements themselves are counted, grouped by the pair of verdicts and by the argument
shape, and printed with examples. They are a measurement, not an expectation: this script asserts
nothing about them.

  python paritaet_python.py --dump D.jsonl --rust-bin pb_verify_rs --out result.json

Run it with the interpreter that has proofbundle installed. Exit 0 when the three checks hold,
1 otherwise.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import contextlib
import io
import json
import multiprocessing as mp
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

NOT_UTF8 = b"input\xff.json"
TWIN = b"input_.json"
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "RUST_BACKTRACE": "0"}


def load(path: str) -> list[dict]:
    out = []
    with open(path, encoding="ascii") as f:
        for line in f:
            r = json.loads(line)
            out.append({
                "domain": r["domain"], "k": r["k"],
                "argv": [bytes.fromhex(a) for a in r["argv"]],
                "name": bytes.fromhex(r["name"]),
                "file": None if r["file"] is None else bytes.fromhex(r["file"]),
            })
    return out


def with_v01_fields(b: bytes) -> bytes:
    """The bundle of D5/D6 lacks `schema`, `signature.alg` and `merkle.hash_alg`; Python refuses it
    as malformed (exit 2), the Rust verifier accepts it (measured, Z381 continuation, F2). With
    `--v01-fields` both verifiers get the SAME bundle with the three fields added, so the argv
    grammar is compared on a bundle both accept. The signed payload and the tree are unchanged."""
    try:
        d = json.loads(b)
    except ValueError:
        return b
    if not isinstance(d, dict) or "payload_b64" not in d:
        return b
    d = {"schema": "proofbundle/v0.1", **d}
    if isinstance(d.get("signature"), dict):
        d["signature"] = {"alg": "ed25519", **d["signature"]}
    if isinstance(d.get("merkle"), dict):
        d["merkle"] = {"hash_alg": "sha256-rfc6962", **d["merkle"]}
    return json.dumps(d, separators=(",", ":")).encode()


def twin(i: dict) -> dict | None:
    if NOT_UTF8 not in i["argv"] and i["name"] != NOT_UTF8:
        return None
    return {**i, "domain": i["domain"] + "_twin",
            "argv": [TWIN if a == NOT_UTF8 else a for a in i["argv"]],
            "name": TWIN if i["name"] == NOT_UTF8 else i["name"]}


def python_argv(argv: list[bytes]) -> list[bytes]:
    """`pb_verify_rs verify-bundle` is `proofbundle verify`; only the subcommand word is mapped."""
    if argv and argv[0] == b"verify-bundle":
        return [b"verify", *argv[1:]]
    return list(argv)


def materialize(d: bytes, i: dict) -> None:
    for e in os.listdir(d):
        os.remove(os.path.join(d, e))
    if i["file"] is not None:
        with open(os.path.join(d, i["name"]), "wb") as f:
            f.write(i["file"])


# --- Rust: the real binary, one process per input --------------------------------------------------
def rust_chunk(args):
    binary, chunk = args
    d = tempfile.mkdtemp(prefix="z381_par_rs_").encode()
    try:
        res = []
        for i in chunk:
            materialize(d, i)
            p = subprocess.run([binary, *i["argv"]], cwd=d, env=ENV, capture_output=True, timeout=60)
            res.append(p.returncode)
        return res
    finally:
        shutil.rmtree(d)


# --- Python: the CLI's main in a worker process ----------------------------------------------------
def _py_decide(main, i: dict) -> int:
    out = io.TextIOWrapper(io.BytesIO(), encoding=sys.__stdout__.encoding,
                           errors=sys.__stdout__.errors)
    err = io.TextIOWrapper(io.BytesIO(), encoding=sys.__stderr__.encoding,
                           errors=sys.__stderr__.errors)
    argv = [os.fsdecode(a) for a in python_argv(i["argv"])]
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = main(argv)
        except SystemExit as e:
            rc = e.code
    if rc is None:
        return 0
    return rc if isinstance(rc, int) else 1


def py_chunk(chunk):
    from proofbundle.cli import main
    d = tempfile.mkdtemp(prefix="z381_par_py_").encode()
    old = os.getcwd()
    os.chdir(d)
    try:
        res = []
        for i in chunk:
            materialize(d, i)
            res.append(_py_decide(main, i))
        return res
    finally:
        os.chdir(old)
        shutil.rmtree(d)


def py_real(console: str, chunk):
    d = tempfile.mkdtemp(prefix="z381_par_pyreal_").encode()
    try:
        res = []
        for i in chunk:
            materialize(d, i)
            p = subprocess.run([console.encode(), *python_argv(i["argv"])], cwd=d, env=ENV,
                               capture_output=True, timeout=120)
            res.append(p.returncode)
        return res
    finally:
        shutil.rmtree(d)


def chunks(xs, n):
    size = max(1, len(xs) // (n * 8))
    return [xs[j:j + size] for j in range(0, len(xs), size)]


def run_rust(binary: str, inputs, workers):
    with cf.ThreadPoolExecutor(workers) as ex:
        parts = list(ex.map(rust_chunk, [(binary.encode(), c) for c in chunks(inputs, workers)]))
    return [r for p in parts for r in p]


def run_python(inputs, workers):
    with mp.get_context("spawn").Pool(workers) as pool:
        parts = pool.map(py_chunk, chunks(inputs, workers))
    return [r for p in parts for r in p]


def shape(i: dict) -> str:
    """A coarse, explicit description of the argument shape, for grouping only."""
    w = [a.decode("utf-8", "replace") for a in i["argv"]]
    tags = []
    if not w or w[0] != "verify-bundle":
        tags.append("no-verify-bundle-subcommand")
    rest = w[1:]
    if rest and rest[0].startswith("-") and rest[0] != "-1":
        tags.append("flag-where-rust-expects-the-path")
    if "--allow-pending" in rest and "--require-anchor" not in rest and "--anchor-type" not in rest:
        tags.append("allow-pending-without-requirement")
    if "--anchor-type" in rest:
        j = rest.index("--anchor-type")
        v = rest[j + 1] if j + 1 < len(rest) else None
        tags.append("anchor-type-without-value" if v is None else
                    "anchor-type-value-is-a-flag" if v.startswith("--") else "anchor-type-with-value")
    for f in ("--expected-root", "--expected-tree-size"):
        if f in rest:
            j = rest.index(f)
            v = rest[j + 1] if j + 1 < len(rest) else None
            tags.append(f"{f[2:]}-without-value" if v is None else
                        f"{f[2:]}-value-is-a-flag" if v.startswith("--") else f"{f[2:]}-with-value")
    if "-1" in rest:
        tags.append("minus-one-word")
    return ",".join(tags) or "plain"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", required=True)
    ap.add_argument("--rust-bin", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--sample-step", type=int, default=97)
    ap.add_argument("--v01-fields", action="store_true",
                    help="add schema, signature.alg and merkle.hash_alg to the bundle (both sides)")
    a = ap.parse_args()
    t0 = time.time()
    inputs = load(a.dump)
    if a.v01_fields:
        for i in inputs:
            if i["file"] is not None:
                i["file"] = with_v01_fields(i["file"])
    twins = [(n, t) for n, t in ((n, twin(i)) for n, i in enumerate(inputs)) if t is not None]
    allin = inputs + [t for _, t in twins]
    print(f"Z381 PARITY inputs={len(inputs)} twins={len(twins)} total_runs_per_verifier={len(allin)}",
          flush=True)

    t = time.time()
    rust = run_rust(a.rust_bin, allin, a.workers)
    print(f"Z381 PARITY rust_seconds={time.time() - t:.1f}", flush=True)
    t = time.time()
    py = run_python(allin, a.workers)
    print(f"Z381 PARITY python_seconds={time.time() - t:.1f}", flush=True)

    # in-process Python == real Python process, on a sample
    console = str(Path(sys.executable).with_name("proofbundle"))
    sample = list(range(0, len(allin), a.sample_step))
    t = time.time()
    with cf.ThreadPoolExecutor(a.workers) as ex:
        parts = list(ex.map(lambda c: py_real(console, [allin[j] for j in c]),
                            chunks(sample, a.workers)))
    real = [r for p in parts for r in p]
    sample_diffs = [(sample[n], py[sample[n]], r) for n, r in enumerate(real) if r != py[sample[n]]]
    print(f"Z381 PARITY python_sample_real_process={len(sample)} diffs={len(sample_diffs)} "
          f"seconds={time.time() - t:.1f}", flush=True)

    bad_rust = [n for n, r in enumerate(rust) if r not in (0, 1, 2, 3)]
    n_in = len(inputs)
    twin_rust = [(n, rust[n], rust[n_in + m]) for m, (n, _) in enumerate(twins) if rust[n] != rust[n_in + m]]
    twin_py = [(n, py[n], py[n_in + m]) for m, (n, _) in enumerate(twins) if py[n] != py[n_in + m]]

    per_domain = collections.defaultdict(lambda: {"inputs": 0, "agree": 0, "disagree": 0,
                                                   "with_not_utf8": 0, "disagree_with_not_utf8": 0})
    groups = collections.defaultdict(lambda: {"count": 0, "examples": []})
    has_nu = {n for n, _ in twins}
    for n, i in enumerate(inputs):
        s = per_domain[i["domain"]]
        s["inputs"] += 1
        s["with_not_utf8"] += n in has_nu
        if rust[n] == py[n]:
            s["agree"] += 1
            continue
        s["disagree"] += 1
        s["disagree_with_not_utf8"] += n in has_nu
        key = f"rust={rust[n]} python={py[n]} shape={shape(i)}"
        g = groups[key]
        g["count"] += 1
        if len(g["examples"]) < 3:
            g["examples"].append({"domain": i["domain"], "k": i["k"],
                                  "argv": [x.decode("utf-8", "backslashreplace") for x in i["argv"]],
                                  "file": "absent" if i["file"] is None else
                                  ("valid bundle" if len(i["file"]) > 2 else i["file"].decode()),
                                  "name": i["name"].decode("utf-8", "backslashreplace")})
    for d, s in sorted(per_domain.items()):
        print(f"Z381 PARITY {d} " + " ".join(f"{k}={v}" for k, v in s.items()), flush=True)
    print(f"Z381 PARITY rust_exit_outside_0_3={len(bad_rust)} twin_rust_diffs={len(twin_rust)} "
          f"twin_python_diffs={len(twin_py)}", flush=True)
    for key, g in sorted(groups.items(), key=lambda kv: -kv[1]["count"]):
        print(f"Z381 PARITY GROUP {g['count']:6d} {key}  e.g. {g['examples'][0]['argv']} "
              f"file={g['examples'][0]['file']}", flush=True)
    hist = collections.Counter((rust[n], py[n]) for n in range(n_in))
    result = {
        "v01_fields": a.v01_fields,
        "inputs": n_in, "twins": len(twins), "per_domain": per_domain,
        "verdict_pairs": {f"rust={r} python={p}": c for (r, p), c in sorted(hist.items())},
        "groups": groups, "rust_exit_outside_0_3": len(bad_rust),
        "twin_rust_diffs": twin_rust[:20], "twin_python_diffs": twin_py[:20],
        "python_sample": len(sample), "python_sample_diffs": sample_diffs[:20],
        "seconds": time.time() - t0,
    }
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1, default=dict)
    ok = not bad_rust and not twin_rust and not twin_py and not sample_diffs
    print(f"Z381 PARITY checks={'green' if ok else 'RED'} seconds={time.time() - t0:.1f}", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
