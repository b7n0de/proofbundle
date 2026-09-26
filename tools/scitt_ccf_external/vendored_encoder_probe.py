#!/usr/bin/env python3
"""A third oracle for the data-hash preimage: CCF's own vendored CBOR code, built by us, run on the corpus.

WHY. Owner answer 3 of 2026-09-26 (Nachtrag 7). preimage_candidates.py computes the candidates with an
own encoder and checks them with cbor2. Neither is the code the service runs. This probe runs the C ABI
that CCF 7.0.17 calls when it builds the hashed bytes, so the oracle is a foreign tool, built by us.

WHAT. vendored_encoder_probe/src/main.rs transcribes ccf::cose::edit::set_unprotected_header(input,
desc::Empty{}) (CCF ccf-7.0.17, src/crypto/cose.cpp lines 18-89) call for call onto the tav_cbor_* C ABI
of tee-attestation-verification-ffi 1.0.8, CCF's vendored copy, which the C++ wrapper tav::cbor calls.
The ABI serializes through EverCBOR (cborrs, cborrs-nondet). This tool:

  1. checks that --ccf-clone is CCF at the tag ccf-7.0.17 (commit cdcb74c7...) and records the digests
     of the vendored files the probe compiles;
  2. builds main.rs against the vendored ffi crate, starting from CCF's own vendored Cargo.lock, and
     refuses unless EverCBOR resolves to https://github.com/project-everest/everparse at 950bc938...,
     the commit CCF's vendored Cargo.toml pins (tag v2026.07.02);
  3. runs the binary on every request.hex of both corpus rounds, and for each accepted vector compares
     the output with the receipt's data-hash and with the served statement minus label 394;
  4. writes vendored_encoder_result.json.

``--check`` needs neither CCF nor Rust: it re-reads the corpus and holds the stored result to it (every
stored output digest against the receipt, and the counts).

usage:
    vendored_encoder_probe.py run --ccf-clone PATH [--work DIR]    # network for crates.io and EverParse
    vendored_encoder_probe.py --check
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROBE = HERE / "vendored_encoder_probe"
RESULT = HERE / "vendored_encoder_result.json"
CORPORA = ("differential_corpus", "differential_corpus_round2")
sys.path.insert(0, str(HERE))
import preimage_candidates as P  # noqa: E402 - the preimage tool of this directory

SHA = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731
CCF_REPO = "https://github.com/microsoft/CCF"
CCF_TAG = "ccf-7.0.17"
CCF_COMMIT = "cdcb74c7365dbe4b3fad739868bfa9802d77ed75"
TAV = "3rdparty/internal/tee-attestation-verification"
EVERPARSE_SOURCE = ("git+https://github.com/project-everest/everparse.git"
                    "?rev=950bc93838ac2faae51126d8acd0637cf8c8a569#950bc93838ac2faae51126d8acd0637cf8c8a569")
VENDORED_FILES = (f"{TAV}/Cargo.lock", f"{TAV}/cbor/Cargo.toml", f"{TAV}/cbor/src/lib.rs",
                  f"{TAV}/ffi/Cargo.toml", f"{TAV}/ffi/src/c_ffi/cbor.rs", f"{TAV}/ffi/include/tav/cbor.hpp",
                  "src/crypto/cose.cpp")

LABEL = ("foreign tool, built by us: CCF's vendored tee-attestation-verification-ffi 1.0.8 C ABI and "
         "EverCBOR, compiled from their pinned sources, driven by our transcription of "
         "set_unprotected_header (vendored_encoder_probe/src/main.rs)")


def _run(cmd, cwd=None, stdin=None) -> str:
    r = subprocess.run(cmd, cwd=cwd, input=stdin, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"REFUSED: {' '.join(map(str, cmd))} exited {r.returncode}\n{r.stderr[-2000:]}")
    return r.stdout


def _lock_packages(lock: Path) -> list:
    """[(name, version, source)] of a Cargo.lock, read line by line (the stdlib has no TOML writer,
    and tomllib is 3.11+)."""
    out, cur = [], {}
    for line in lock.read_text(encoding="utf-8").splitlines() + ["[[package]]"]:
        if line.strip() == "[[package]]":
            if cur:
                out.append((cur.get("name"), cur.get("version"), cur.get("source")))
            cur = {}
        elif " = " in line and not line.startswith(" "):
            k, v = line.split(" = ", 1)
            if v.startswith('"'):
                cur[k.strip()] = v.strip().strip('"')
    return out


def build(ccf: Path, work: Path) -> tuple:
    head = _run(["git", "-C", str(ccf), "rev-parse", "HEAD"]).strip()
    if head != CCF_COMMIT:
        raise SystemExit(f"REFUSED: {ccf} is at {head}, not {CCF_TAG} ({CCF_COMMIT})")
    vendored = {rel: SHA((ccf / rel).read_bytes()) for rel in VENDORED_FILES}
    (work / "src").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(PROBE / "src" / "main.rs", work / "src" / "main.rs")
    ffi = (ccf / TAV / "ffi").resolve()
    (work / "Cargo.toml").write_text(
        "[package]\nname = \"vendored_encoder_probe\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n"
        "[dependencies]\n"
        f"tee-attestation-verification-ffi = {{ path = \"{ffi.as_posix()}\", default-features = false, features = [\"crypto_openssl\"] }}\n\n"
        "[workspace]\n", encoding="utf-8")
    shutil.copyfile(ccf / TAV / "Cargo.lock", work / "Cargo.lock")
    _run(["cargo", "build", "--release", "--quiet"], cwd=work)
    pkgs = _lock_packages(work / "Cargo.lock")
    vendored_lock = set(_lock_packages(ccf / TAV / "Cargo.lock"))
    ever = sorted({src for name, _v, src in pkgs if name in ("cborrs", "cborrs-nondet")})
    if ever != [EVERPARSE_SOURCE]:
        raise SystemExit(f"REFUSED: EverCBOR resolved to {ever}, not {EVERPARSE_SOURCE}")
    registry = [p for p in pkgs if p[2] and p[2].startswith("registry+")]
    build_info = {
        "ccf": {"repository": CCF_REPO, "tag": CCF_TAG, "commit": CCF_COMMIT},
        "vendored_files_sha256": vendored,
        "everparse": {"repository": "https://github.com/project-everest/everparse",
                      "commit": "950bc93838ac2faae51126d8acd0637cf8c8a569", "tag": "v2026.07.02",
                      "resolved_source": EVERPARSE_SOURCE,
                      "pinned_by": f"{TAV}/cbor/Cargo.toml and {TAV}/Cargo.lock in CCF {CCF_TAG}"},
        "probe_source_sha256": SHA((PROBE / "src" / "main.rs").read_bytes()),
        "cargo_lock_sha256": SHA((work / "Cargo.lock").read_bytes()),
        "registry_packages": len(registry),
        "registry_packages_not_in_ccf_vendored_lock": sorted(f"{n} {v}" for n, v, s in registry
                                                              if (n, v, s) not in vendored_lock),
        "features": "tee-attestation-verification-ffi with default-features = false and crypto_openssl, the "
                    "backend its crypto build script requires on native targets; the CBOR functions use none",
        "rustc": _run(["rustc", "--version"]).strip(),
        "cargo": _run(["cargo", "--version"]).strip(),
        "platform": platform.platform(),
    }
    return work / "target" / "release" / "vendored_encoder_probe", build_info


def _vectors(corpus: Path):
    man = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    for vid in man["vectors"]:
        d = corpus / "vectors" / vid
        rec = json.loads((d / "record.json").read_text(encoding="utf-8"))
        raw = {}
        for name, want in rec["files"].items():
            if name.endswith(".hex"):
                raw[name] = P._hex(d / name)
                if SHA(raw[name]) != want["sha256"]:
                    raise SystemExit(f"REFUSED: {corpus.name}/{vid}/{name} is not the recorded bytes")
        yield vid, rec, raw


def _expected(raw: dict) -> dict:
    """What an accepted vector's output is compared with, all from the stored bytes."""
    dh = P.data_hash_own(raw["receipt.hex"])
    if len(set(dh)) != 1:
        raise SystemExit("REFUSED: inclusion proofs with differing data-hashes")
    cands, _facts = P.candidates(raw["request.hex"], raw["statement.hex"])
    return {"data_hash": dh[0], "served_minus_394_sha256": SHA(cands["3-tagged"]),
            "request_sha256": SHA(raw["request.hex"])}


def run(args) -> int:
    work = Path(args.work) if args.work else Path(tempfile.mkdtemp(prefix="vendored_encoder_probe_"))
    binary, build_info = build(Path(args.ccf_clone), work)
    corpora = {}
    for name in CORPORA:
        corpus = HERE / name
        vecs = list(_vectors(corpus))
        stdin = "".join(f"{vid} {raw['request.hex'].hex()}\n" for vid, _r, raw in vecs)
        lines = dict(line.split(" ", 1) for line in _run([str(binary)], stdin=stdin).splitlines())
        rows = []
        for vid, rec, raw in vecs:
            status, _sp, rest = lines[vid].partition(" ")
            row = {"id": vid, "accepted_by_service": rec["service"]["accepted"], "probe": status}
            if status == "OK":
                out = bytes.fromhex(rest)
                row.update(output_length=len(out), output_sha256=SHA(out))
            else:
                row["probe_error"] = rest
            if rec["service"]["accepted"]:
                exp = _expected(raw)
                row["receipt_data_hash"] = exp["data_hash"]
                if status == "OK":
                    row["output_sha256_equals_data_hash"] = row["output_sha256"] == exp["data_hash"]
                    row["output_equals_served_minus_394"] = row["output_sha256"] == exp["served_minus_394_sha256"]
                    row["output_equals_request"] = row["output_sha256"] == exp["request_sha256"]
            else:
                row["service_error"] = rec["service"].get("error")
            rows.append(row)
        corpora[name] = {"vectors": rows, "counts": counts(rows)}
    result = {
        "tool": "tools/scitt_ccf_external/vendored_encoder_probe.py",
        "oracle": LABEL,
        "measured_on": datetime.date.today().isoformat(),
        "build": build_info,
        "compared_with": {
            "receipt_data_hash": "the data-hash of the vector's receipt, read by preimage_candidates.data_hash_own",
            "served_minus_394": "the served statement with label 394 removed, every other byte as served "
                                "(preimage_candidates candidate 3-tagged), i.e. the service's own serialization",
            "request": "the submitted bytes",
        },
        "corpora": corpora,
    }
    RESULT.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    for name, c in corpora.items():
        print(name, json.dumps(c["counts"]))
    return 0


def counts(rows: list) -> dict:
    acc = [r for r in rows if r["accepted_by_service"]]
    ref = [r for r in rows if not r["accepted_by_service"]]
    return {
        "accepted": len(acc),
        "accepted_probe_ok": sum(r["probe"] == "OK" for r in acc),
        "accepted_output_equals_served_minus_394": sum(bool(r.get("output_equals_served_minus_394")) for r in acc),
        "accepted_output_sha256_equals_data_hash": sum(bool(r.get("output_sha256_equals_data_hash")) for r in acc),
        "accepted_output_equals_request": sum(bool(r.get("output_equals_request")) for r in acc),
        "refused_by_service": len(ref),
        "refused_probe_error": sum(r["probe"] != "OK" for r in ref),
    }


def check() -> int:
    """Hold the stored result to the corpus, offline: no CCF, no Rust."""
    stored = json.loads(RESULT.read_text(encoding="utf-8"))
    bad = []
    for name in CORPORA:
        rows = {r["id"]: r for r in stored["corpora"][name]["vectors"]}
        vecs = list(_vectors(HERE / name))
        if sorted(rows) != sorted(v for v, _r, _raw in vecs):
            bad.append(f"{name}: vector set")
            continue
        for vid, rec, raw in vecs:
            r = rows[vid]
            if r["accepted_by_service"] != rec["service"]["accepted"]:
                bad.append(f"{name}/{vid}: accepted")
            if rec["service"]["accepted"]:
                exp = _expected(raw)
                if r["receipt_data_hash"] != exp["data_hash"]:
                    bad.append(f"{name}/{vid}: data-hash")
                if r["probe"] == "OK" and (
                        r["output_sha256_equals_data_hash"] != (r["output_sha256"] == exp["data_hash"])
                        or r["output_equals_served_minus_394"] != (r["output_sha256"] == exp["served_minus_394_sha256"])
                        or r["output_equals_request"] != (r["output_sha256"] == exp["request_sha256"])):
                    bad.append(f"{name}/{vid}: comparison")
        if stored["corpora"][name]["counts"] != counts(list(rows.values())):
            bad.append(f"{name}: counts")
    if stored["build"]["probe_source_sha256"] != SHA((PROBE / "src" / "main.rs").read_bytes()):
        bad.append("main.rs is not the source the result was measured with")
    print("stored result agrees with the corpus" if not bad else "DIFFERS: " + ", ".join(bad))
    return 0 if not bad else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--check", action="store_true", help="hold the stored result to the corpus, offline")
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("run", help="build the probe against a CCF clone and run it on both corpus rounds")
    r.add_argument("--ccf-clone", required=True)
    r.add_argument("--work")
    a = ap.parse_args(argv)
    if a.cmd == "run":
        return run(a)
    if a.check:
        return check()
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
