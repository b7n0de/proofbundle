#!/usr/bin/env python3
"""Runtime baseline: each stage of a receipt, measured apart, on the machine it runs on.

Stages, each timed on its own with `time.perf_counter_ns` around one call, after a warm-up:

  capture        build_eval_claim from fixed inputs (salted commitments, the verdict computed)
  canonicalize   the RFC 8785 bytes of that claim, the payload that gets signed
  hash           SHA-256 of the payload, and the RFC 6962 leaf hash of it
  sign           Ed25519 over the payload
  emit           emit_bundle with no history (sign, root and inclusion path of a one-leaf tree)
  durable write  the bundle as JSON to a file in the output directory: write, flush, fsync, rename, fsync of the
                 directory
  policy         evaluate_policy over an already verified bundle, with a policy that passes
  verify         verify_bundle, the full offline check (signature, leaf, inclusion path, root)

And the growing history as its own case: emit_bundle with `prior_leaves` of length n, for n from 0 to
the largest size asked for, each size measured apart, with the number of SHA-256 calls of one emit
counted (not timed) and the Merkle part and the signature timed apart as well, so that the report can
say which of the two dominates at which n. emit_bundle rebuilds the whole tree on every call
(src/proofbundle/emit.py, `list(prior_leaves) + [payload]`, then merkle_tree_hash and inclusion_proof over
it); the counts show what that costs.

When tools/merkle_accumulator/accumulator.py is present, the same history sizes are measured for its
append (the root and the new leaf's inclusion path from the kept frontier) and for a bundle emitted
through it, with the same counting.

Percentiles are nearest-rank over the sorted samples: the p-th percentile is the ceil(p/100 * N)-th
smallest sample. Raw samples are written as they were taken, in nanoseconds. Nothing here is compared
with a target.

Usage: python benchmarks/runtime_baseline/run.py --out benchmarks/runtime_baseline/results/<run>
       [--warmup 20] [--samples 200] [--max-history 16384]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import importlib.metadata
import importlib.util
import json
import math
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import proofbundle
from proofbundle import merkle
from proofbundle.bundle import verify_bundle
from proofbundle.emit import emit_bundle
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt, issuer_fingerprint
from proofbundle.policy import evaluate_policy, load_policy

REPO = Path(__file__).resolve().parents[2]
_ACCUMULATOR = REPO / "tools" / "merkle_accumulator" / "accumulator.py"
_RESULTS = Path(__file__).resolve().parent / "results"


# ---- environment -----------------------------------------------------------------------------------------

def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _mount_of(pfad: Path) -> dict:
    """The mount the output directory lives on, from /proc/mounts (the longest matching mount point)."""
    bester = {"mount_point": None, "fs_type": None, "device": None}
    ziel = str(pfad.resolve())
    for zeile in _read("/proc/mounts").splitlines():
        teile = zeile.split()
        if len(teile) >= 3 and (ziel == teile[1] or ziel.startswith(teile[1].rstrip("/") + "/")):
            if bester["mount_point"] is None or len(teile[1]) > len(bester["mount_point"]):
                bester = {"mount_point": teile[1], "fs_type": teile[2], "device": teile[0]}
    return bester


def environment(out: Path) -> dict:
    cpu = [z.split(":", 1)[1].strip() for z in _read("/proc/cpuinfo").splitlines() if z.startswith("model name")]
    mem = {z.split(":")[0]: z.split(":")[1].strip() for z in _read("/proc/meminfo").splitlines()[:3] if ":" in z}
    os_rel = dict(z.split("=", 1) for z in _read("/etc/os-release").splitlines() if "=" in z)
    vfs = os.statvfs(out)
    try:
        kopf = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
        # The harness's own results are not source: an earlier run's files under results/ must not read as
        # a changed tree. They did in the first three runs of 2026-09-28, which were retaken.
        sauber = subprocess.run(["git", "-C", str(REPO), "status", "--porcelain", "--", "src", "benchmarks",
                                 "tools", ":(exclude)" + _RESULTS.relative_to(REPO).as_posix()],
                                capture_output=True, text=True, check=True).stdout.strip() == ""
    except (OSError, subprocess.CalledProcessError):
        kopf, sauber = None, None
    pakete = {}
    for name in ("cryptography", "rfc8785", "cffi"):
        try:
            pakete[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            pakete[name] = None
    return {
        "package": {"name": "proofbundle", "version": proofbundle.__version__, "source": str(Path(proofbundle.__file__).parent),
                    "commit": kopf, "tree_clean_for_src_benchmarks_tools": sauber},
        "python": {"version": platform.python_version(), "implementation": platform.python_implementation(),
                   "build": " ".join(platform.python_build()), "executable": sys.executable},
        "dependencies": pakete,
        "cpu": {"model": cpu[0] if cpu else platform.processor() or None, "logical_cpus": os.cpu_count(),
                "machine": platform.machine()},
        "memory": mem,
        "disk": {**_mount_of(out), "block_size": vfs.f_frsize, "free_bytes": vfs.f_bavail * vfs.f_frsize},
        "os": {"platform": platform.platform(), "release": os_rel.get("PRETTY_NAME", "").strip('"') or None,
               "kernel": platform.release()},
        "load_average_at_start": os.getloadavg(),
    }


# ---- measuring -------------------------------------------------------------------------------------------

def samples(fn, warmup: int, n: int, *, setup=None) -> list:
    """`n` timings of `fn()` in ns, after `warmup` untimed calls. `setup()` runs untimed before each call
    and its result is passed to `fn` when given."""
    for _ in range(warmup):
        fn(setup()) if setup else fn()
    zeiten = []
    for _ in range(n):
        if setup:
            arg = setup()
            t0 = time.perf_counter_ns()
            fn(arg)
        else:
            t0 = time.perf_counter_ns()
            fn()
        zeiten.append(time.perf_counter_ns() - t0)
    return zeiten


def percentile(werte: list, p: float) -> int:
    """Nearest rank: the ceil(p/100 * N)-th smallest value."""
    geordnet = sorted(werte)
    return geordnet[max(1, math.ceil(p / 100 * len(geordnet))) - 1]


def summary(werte: list) -> dict:
    return {"n": len(werte), "p50": percentile(werte, 50), "p95": percentile(werte, 95),
            "p99": percentile(werte, 99), "max": max(werte), "min": min(werte)}


def durable_write(bundle: dict, ort: Path) -> None:
    """The bundle as JSON to `ort/receipt.json`, durably: write a temporary file, flush and fsync it, rename it over
    the target, and fsync the directory, since the rename is durable only once the directory entry is. Codex thread
    4122623623 on pull request 306: the stage stopped after the rename and was reported as a durable write."""
    ziel, zwischen = ort / "receipt.json", ort / "receipt.json.tmp"
    with open(zwischen, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(zwischen, ziel)
    verzeichnis = os.open(ort, os.O_RDONLY)
    try:
        os.fsync(verzeichnis)
    finally:
        os.close(verzeichnis)


class _CountingHashlib:
    """The merkle module's `hashlib` for the duration of a count: every `sha256` call it makes is counted, every other
    name is the real module's."""

    def __init__(self, echt, zaehler) -> None:
        self._echt, self._zaehler = echt, zaehler

    def sha256(self, *args, **kwargs):
        self._zaehler.sha256 += 1
        return self._echt.sha256(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._echt, name)


class HashCounter:
    """Counts the RFC 6962 hash calls made through the merkle module (leaf and interior node), by wrapping the two
    functions every path of the module goes through, `_leaf_hash` and `_node_hash`, for the duration of a `with`
    block. Counting, not timing.

    The count is checked against an oracle that does not depend on those names: every `sha256` call the module makes
    in the block. Codex thread 4217194025 on pull request 306: the counter wrapped the public `leaf_hash`, main
    routed the tree through `_leaf_hash`, and a rerun at the head of the merge counted 0 leaf hashes for every size.
    A block whose two counts disagree raises instead of returning a count of a path the tree no longer takes."""

    def __enter__(self):
        self.leaf = self.node = self.sha256 = 0
        self._leaf, self._node, self._hashlib = merkle._leaf_hash, merkle._node_hash, merkle.hashlib

        def leaf(data):
            self.leaf += 1
            return self._leaf(data)

        def node(left, right):
            self.node += 1
            return self._node(left, right)
        merkle._leaf_hash, merkle._node_hash = leaf, node
        merkle.hashlib = _CountingHashlib(self._hashlib, self)
        return self

    def __exit__(self, exc_type, *exc):
        merkle._leaf_hash, merkle._node_hash, merkle.hashlib = self._leaf, self._node, self._hashlib
        if exc_type is None and self.sha256 != self.total():
            raise RuntimeError(f"the hash count missed the path: {self.total()} leaf and node calls counted, "
                               f"{self.sha256} SHA-256 calls made by the merkle module")
        return False

    def total(self) -> int:
        return self.leaf + self.node


def history_sizes(maximum: int) -> list:
    groessen, n = [0], 1
    while n <= maximum:
        groessen.append(n)
        n *= 2
    return groessen


def _load_accumulator():
    if not _ACCUMULATOR.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_merkle_accumulator", _ACCUMULATOR)
    modul = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modul)
    return modul


def run(out: Path, warmup: int, count: int, max_history: int) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    env = environment(out)
    signer = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"runtime baseline, not a key of anything").digest())
    fixed = dict(suite="baseline-suite", suite_version="1", metric="accuracy", comparator=">=", threshold="0.8",
                 score="0.85", n=100, model_id="model", dataset_id="dataset", issuer="",
                 timestamp="2026-09-28T00:00:00Z", model_salt=b"\x01" * 16, dataset_salt=b"\x02" * 16)
    claim, _ = build_eval_claim(**fixed)
    claim = dict(claim, issuer=issuer_fingerprint(signer))
    payload = rfc8785.dumps(claim)
    bundle = emit_eval_receipt(claim, signer)
    ergebnis = verify_bundle(bundle)
    assert ergebnis.ok, "the baseline bundle must verify"
    policy = load_policy({
        "schema": "proofbundle/trust-policy/v0.1", "policy_id": "runtime-baseline",
        "allowed_schema_versions": ["proofbundle/v0.1"],
        "allowed_issuers": [{"issuer": "baseline", "public_key_b64": bundle["signature"]["public_key_b64"],
                             "kid": "baseline"}],
        "signature": {"allowed_algs": ["ed25519"], "require_expected_signer": True},
        "merkle": {"required_hash_alg": "sha256-rfc6962"},
        "assurance": {"minimum_level": "self_attested", "reject_self_attested_without_prereg": False}})
    policy_ergebnis = evaluate_policy(bundle, ergebnis, policy)
    assert policy_ergebnis["policy_ok"] is True, policy_ergebnis
    schreibort = Path(tempfile.mkdtemp(prefix="durable-write-", dir=out))

    roh: dict = {}
    stufen = {
        "capture": lambda: build_eval_claim(**fixed),
        "canonicalize": lambda: rfc8785.dumps(claim),
        "hash_sha256": lambda: hashlib.sha256(payload).digest(),
        "hash_leaf": lambda: merkle.leaf_hash(payload),
        "sign": lambda: signer.sign(payload),
        "emit_empty_history": lambda: emit_bundle(payload, signer),
        "durable_write": lambda: durable_write(bundle, schreibort),
        "policy": lambda: evaluate_policy(bundle, ergebnis, policy),
        "verify": lambda: verify_bundle(bundle),
    }
    for name, fn in stufen.items():
        roh[name] = samples(fn, warmup, count)
    for datei in schreibort.iterdir():
        datei.unlink()
    schreibort.rmdir()

    geschichte = [f"history leaf {i}".encode() for i in range(max_history)]
    wachsend: dict = {}
    for n in history_sizes(max_history):
        vorher = geschichte[:n]
        leaves = vorher + [payload]
        with HashCounter() as zaehler:
            emit_bundle(payload, signer, prior_leaves=vorher)
        eintrag = {
            "hash_calls_per_emit": {"leaf": zaehler.leaf, "node": zaehler.node, "total": zaehler.total()},
            "emit": samples(lambda: emit_bundle(payload, signer, prior_leaves=vorher), warmup, count),
            "merkle_part": samples(lambda: (merkle.merkle_tree_hash(leaves), merkle.inclusion_proof(leaves, n)),
                                   warmup, count),
            "sign_part": samples(lambda: signer.sign(payload), warmup, count),
        }
        wachsend[str(n)] = eintrag
    roh["emit_growing_history"] = wachsend

    akku = _load_accumulator()
    if akku is not None:
        nach: dict = {}
        for n in history_sizes(max_history):
            basis = akku.MerkleAccumulator()
            for blatt in geschichte[:n]:
                basis.append(blatt)
            with HashCounter() as zaehler:
                basis.copy().append(payload)
            nach[str(n)] = {
                "hash_calls_per_append": {"leaf": zaehler.leaf, "node": zaehler.node, "total": zaehler.total()},
                "append": samples(lambda a: a.append(payload), warmup, count, setup=basis.copy),
                "emit_through_accumulator": samples(lambda a: akku.emit_bundle_incremental(payload, signer, a),
                                                    warmup, count, setup=basis.copy),
                "copy_only": samples(lambda a: a, warmup, count, setup=basis.copy),
            }
        roh["accumulator_growing_history"] = nach

    env["load_average_at_end"] = os.getloadavg()
    return {"format": "runtime-baseline/1",
            "measured_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "settings": {"warmup": warmup, "samples": count, "max_history": max_history,
                         "percentile_method": "nearest rank", "clock": "time.perf_counter_ns, one call per sample",
                         "payload_bytes": len(payload), "payload_sha256": hashlib.sha256(payload).hexdigest()},
            "environment": env, "raw_ns": roh}


def summarise(daten: dict) -> dict:
    roh = daten["raw_ns"]
    zus = {name: summary(werte) for name, werte in roh.items() if isinstance(werte, list)}
    for fall, schluessel in (("emit_growing_history", ("emit", "merkle_part", "sign_part")),
                             ("accumulator_growing_history", ("append", "emit_through_accumulator", "copy_only"))):
        if fall not in roh:
            continue
        zus[fall] = {}
        for n, eintrag in roh[fall].items():
            zus[fall][n] = {k: summary(eintrag[k]) for k in schluessel}
            zaehl = "hash_calls_per_emit" if fall == "emit_growing_history" else "hash_calls_per_append"
            zus[fall][n][zaehl] = eintrag[zaehl]
    return zus


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--warmup", type=int, default=20)
    p.add_argument("--samples", type=int, default=200)
    p.add_argument("--max-history", type=int, default=16384)
    a = p.parse_args(argv)
    daten = run(a.out, a.warmup, a.samples, a.max_history)
    (a.out / "raw.json").write_text(json.dumps(daten, indent=None, separators=(",", ":")) + "\n", encoding="utf-8")
    (a.out / "summary.json").write_text(json.dumps({"format": daten["format"], "measured_at": daten["measured_at"],
                                                    "settings": daten["settings"], "environment": daten["environment"],
                                                    "summary": summarise(daten)}, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {a.out / 'raw.json'} and {a.out / 'summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
