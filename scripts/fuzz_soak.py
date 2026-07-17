#!/usr/bin/env python3
"""WP-D — bounded fuzz-SOAK harness over the main parser classes (EXT §9 P2).

The acceptance criterion is a 24-hour soak per main parser with ZERO untriaged crash and ZERO false
accept. A 24h run is an OPERATIONAL artifact, not something a unit test does inline — so this harness
is built to run for an arbitrary wall-clock ``--duration-seconds`` (a few seconds in CI as a smoke, or
86400 on a soak box) and to WRITE its result as a reproducible artifact that the audit-candidate matrix
then reads. No-Fake: the artifact records the ACTUAL elapsed seconds and iteration count — a short run
says so, and the matrix marks the full 24h as DATA_BLOCKED until an artifact with >= 24h is present. A
short run never masquerades as the soak.

Two properties are asserted on every random input, across every parser class:
  * NEVER-RAISE — a verifier returns a value or raises a documented ``ProofBundleError`` / ``ValueError``.
    Any OTHER exception (AttributeError, KeyError, TypeError, RecursionError, UnicodeError, …) is an
    UNTRIAGED CRASH and is bucketed by (parser, exception-type) for triage.
  * NEVER FALSE-ACCEPT — random / garbage input must never verify. A truthy ``ok`` (dict result) or a
    ``True`` (bool verifier) on a random input is a FALSE ACCEPT — the most serious class (a verifier
    that says "authentic" for noise). Counted separately from crashes.

Parser classes (mirrors the EXT list): structured JSON receipts, text/JWT parsers, DSSE envelopes,
merkle openings, ecosystem/adapter. The verifier set is DISCOVERED from the AST (the same ground truth
F4 and the Rust-parity gate hold themselves to) — a new verify_* is soaked automatically, nothing here
is a hand-maintained target list.

CLI:
  python scripts/fuzz_soak.py [--duration-seconds N] [--seed S] [--out PATH] [--json] [--max-iters N]

Exit 0 iff zero untriaged crashes AND zero false accepts over the run. Writes the artifact to
``--out`` (default audit_artifacts/360/fuzz_soak_latest.json) unless ``--no-write``.
"""
from __future__ import annotations

import argparse
import base64
import importlib
import inspect
import json
import random
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
for _p in (str(SRC), str(REPO / "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from rust_parity_gate import discover_python_verify_functions  # noqa: E402
from type_confusion_gate import _benign_fixtures, _is_json_primary  # noqa: E402
from proofbundle.errors import ProofBundleError  # noqa: E402

_ALLOWED = (ProofBundleError, ValueError)
DEFAULT_OUT = REPO / "audit_artifacts" / "360" / "fuzz_soak_latest.json"
_TWENTY_FOUR_HOURS = 24 * 3600


# --- random input generators, one per parser class -------------------------------------------------

def _rand_scalar(rng: random.Random):
    return rng.choice([
        None, True, False, 0, -1, rng.randint(-(2 ** 63), 2 ** 63), rng.random() * 1e9,
        float("nan"), float("inf"), "", "x" * rng.randint(0, 64), "\x00\x01\x02",
        "🙈" * rng.randint(0, 8), "a" * 64,
    ])


def _rand_json(rng: random.Random, depth: int = 0):
    if depth > 5 or rng.random() < 0.35:
        return _rand_scalar(rng)
    if rng.random() < 0.5:
        return [_rand_json(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    keys = rng.sample(["payload", "signatures", "predicate", "predicateType", "schemaVersion",
                       "subject", "digest", "sha256", "keyid", "sig", "roles", "keys", "expires",
                       "", "\x00", "a" * 32], k=rng.randint(0, 6))
    return {k: _rand_json(rng, depth + 1) for k in keys}


def _rand_text(rng: random.Random) -> str:
    kinds = [
        lambda: "".join(chr(rng.randint(1, 0x2FFF)) for _ in range(rng.randint(0, 200))),
        lambda: ".".join(base64.urlsafe_b64encode(bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 40)))).decode()
                         for _ in range(rng.randint(0, 4))),
        lambda: "~".join("x" * rng.randint(0, 10) for _ in range(rng.randint(0, 6))),
        lambda: rng.choice(["", "{}", "null", "e30", "..", "a.b.c"]),
    ]
    return rng.choice(kinds)()


def _rand_envelope(rng: random.Random) -> dict:
    env: dict = {}
    if rng.random() < 0.8:
        env["payloadType"] = rng.choice(["application/vnd.in-toto+json", "x", "", 123, None])
    if rng.random() < 0.8:
        body = json.dumps(_rand_json(rng)).encode()
        env["payload"] = base64.b64encode(body).decode() if rng.random() < 0.7 else "!!not-b64!!"
    if rng.random() < 0.8:
        env["signatures"] = _rand_json(rng) if rng.random() < 0.3 else [
            {"sig": base64.b64encode(bytes(rng.randint(0, 255) for _ in range(64))).decode(),
             "keyid": "k"} for _ in range(rng.randint(0, 3))]
    return env


def _input_kind(fn) -> str:
    """Classify a verifier's primary parser class from its signature (reuses the F4 discovery)."""
    try:
        params = list(inspect.signature(fn).parameters.values())
    except (ValueError, TypeError):
        return "unknown"
    if not params:
        return "unknown"
    first = params[0]
    if _is_json_primary(first):
        name = first.name.lower()
        if name in {"envelope", "env"}:
            return "envelope"
        return "json_object"
    ann = str(first.annotation)
    if "bytes" in ann:
        return "bytes"
    return "text"


def _gen_for(kind: str, rng: random.Random):
    if kind == "json_object":
        return _rand_json(rng)
    if kind == "envelope":
        return _rand_envelope(rng)
    if kind == "bytes":
        return bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 200)))
    return _rand_text(rng)


def _is_false_accept(result) -> bool:
    if result is True:
        return True
    if isinstance(result, dict):
        return result.get("ok") is True
    return False


def _resolve_targets():
    """(qname, fn, kind, extra_kwargs) for every soakable verify_*; skips ones needing an
    unsatisfiable fixture (honestly, mirroring the F4 NEEDS_FIXTURE accountability)."""
    fixtures = _benign_fixtures()
    targets = []
    skipped = []
    for qname in sorted(discover_python_verify_functions()):
        module, fname = qname.split(".")[1], qname.split(".")[2]
        try:
            fn = getattr(importlib.import_module(f"proofbundle.{module}"), fname)
            params = list(inspect.signature(fn).parameters.values())
        except Exception:  # noqa: BLE001 - defensive
            skipped.append(qname)
            continue
        if not params:
            skipped.append(qname)
            continue
        extra: dict = {}
        unsat = False
        for p in params[1:]:
            if p.default is not inspect.Parameter.empty or p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
                continue
            if p.name in fixtures:
                extra[p.name] = fixtures[p.name]
            else:
                unsat = True
                break
        if unsat:
            skipped.append(qname)
            continue
        # A Union[dict, str] primary (e.g. verify_bundle) legitimately treats a str as a FILE PATH; a
        # bad path raising OSError/FileNotFoundError is correct API behaviour, not a robustness bug
        # (mirrors type_confusion_gate's exact reasoning — bare strings are a legit input class there).
        union_str = "str" in str(params[0].annotation)
        targets.append((qname, fn, _input_kind(fn), extra, union_str))
    return targets, skipped


def _record_crash(crashes: dict, qname: str, exc: BaseException, payload) -> None:
    key = f"{qname}::{type(exc).__name__}"
    rec = crashes.setdefault(key, {"parser": qname, "exc": type(exc).__name__,
                                   "count": 0, "sample_repr": repr(payload)[:120]})
    rec["count"] += 1


def soak(duration_seconds: float, seed: int = 0, max_iters: int | None = None) -> dict:
    rng = random.Random(seed)
    targets, skipped = _resolve_targets()
    crashes: dict[str, dict] = {}       # "qname::ExcType" -> {parser, exc, count, sample}
    false_accepts: list[dict] = []
    per_parser_iters: dict[str, int] = {}
    iters = 0
    start = time.monotonic()
    deadline = start + max(0.0, duration_seconds)
    # round-robin over targets so every parser is soaked roughly equally regardless of speed
    idx = 0
    n = len(targets)

    def _keep_going() -> bool:
        # Two INDEPENDENT budgets, EITHER of which can stop the loop; a fixed-iteration smoke run
        # (duration_seconds=0 + max_iters=N) is driven by max_iters alone, so the wall-clock deadline
        # only applies when a positive duration was asked for. Without this, a duration-0 + max_iters
        # run exited before the first iteration (Lens C P2 — it made a regression test assert nothing).
        if max_iters is not None and iters >= max_iters:
            return False
        if duration_seconds > 0 and time.monotonic() >= deadline:
            return False
        return max_iters is not None or duration_seconds > 0  # no budget at all -> stop

    while n and _keep_going():
        qname, fn, kind, extra, union_str = targets[idx % n]
        idx += 1
        payload = _gen_for(kind, rng)
        per_parser_iters[qname] = per_parser_iters.get(qname, 0) + 1
        iters += 1
        try:
            result = fn(payload, **extra)
        except _ALLOWED:
            continue
        except (KeyboardInterrupt, SystemExit):
            raise
        except OSError as exc:
            # a path-accepting Union[dict, str] verifier resolving a garbage str as a file path is
            # documented behaviour, NOT a robustness bug — only excused when the input IS a str.
            if union_str and isinstance(payload, str):
                continue
            _record_crash(crashes, qname, exc, payload)
            continue
        except BaseException as exc:  # noqa: BLE001 - the whole point is to catch the raw class
            _record_crash(crashes, qname, exc, payload)
            continue
        if _is_false_accept(result):
            false_accepts.append({"parser": qname, "input_repr": repr(payload)[:200]})
    elapsed = time.monotonic() - start
    return {
        "schema": "proofbundle.fuzz_soak.v1",
        "seed": seed,
        "requested_duration_seconds": duration_seconds,
        "elapsed_seconds": round(elapsed, 3),
        "is_full_soak_24h": elapsed >= _TWENTY_FOUR_HOURS,
        "iterations": iters,
        "parsers_soaked": len(targets),
        "per_parser_iterations": dict(sorted(per_parser_iters.items())),
        "parsers_skipped_needs_fixture": skipped,
        "untriaged_crashes": sorted(crashes.values(), key=lambda r: r["parser"]),
        "untriaged_crash_count": sum(r["count"] for r in crashes.values()),
        "false_accepts": false_accepts,
        "false_accept_count": len(false_accepts),
        "ok": not crashes and not false_accepts,
        "note": ("A short run is a SMOKE, not the 24h soak — is_full_soak_24h says which. The audit "
                 "matrix treats the full-24h criterion as DATA_BLOCKED until an artifact with "
                 "elapsed_seconds >= 86400 exists (No-Fake)."),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--duration-seconds", type=float, default=5.0)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--max-iters", type=int, default=None)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p.add_argument("--no-write", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    result = soak(args.duration_seconds, seed=args.seed, max_iters=args.max_iters)
    if not args.no_write:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"[fuzz-soak] {result['iterations']} iters over {result['parsers_soaked']} parser(s) in "
              f"{result['elapsed_seconds']}s (full_24h={result['is_full_soak_24h']}) · "
              f"crashes={result['untriaged_crash_count']} false_accepts={result['false_accept_count']} · "
              f"{'OK' if result['ok'] else 'FAIL'}")
        for c in result["untriaged_crashes"]:
            print(f"  CRASH {c['parser']} {c['exc']} ×{c['count']} — {c['sample_repr']}")
        for fa in result["false_accepts"]:
            print(f"  FALSE-ACCEPT {fa['parser']} — {fa['input_repr']}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
