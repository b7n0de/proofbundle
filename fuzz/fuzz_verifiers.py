#!/usr/bin/env python3
"""Atheris coverage-guided fuzz entrypoint for the ClusterFuzzLite CI leg (WP-D).

The bounded ``scripts/fuzz_soak.py`` is the runnable-here soak (random, wall-clock). THIS module is the
coverage-guided, corpus-accumulating CONTINUOUS leg: Atheris (libFuzzer for CPython) drives the same
NEVER-RAISE property with coverage feedback, so it reaches states random sampling does not, and stores
the crashing/interesting inputs into a persistent corpus (ClusterFuzzLite handles corpus dedup + the
coverage-regression gate). It reuses the SAME AST-discovered verifier set and the SAME "documented
error vs raw crash" contract as the soak — one property, two drivers.

Honest scope: Atheris is a dev/CI-only dependency (native build); this module no-ops with a clear
message when it is absent, exactly like the Hypothesis fuzz tests. The continuous ClusterFuzzLite run
is an OPERATIONAL/CI artifact (see .clusterfuzzlite/), not something the unit-test suite runs inline.

Run locally (if atheris is installed):  python fuzz/fuzz_verifiers.py -runs=100000
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import atheris  # type: ignore
except ImportError:  # pragma: no cover - native dev/CI-only dependency
    atheris = None

from proofbundle.errors import ProofBundleError  # noqa: E402

_ALLOWED = (ProofBundleError, ValueError, OSError)


def _targets():
    """The soakable verifier set, reusing fuzz_soak's resolver (same ground truth as F4 / rust-parity)."""
    from fuzz_soak import _resolve_targets  # noqa: PLC0415
    targets, _skipped = _resolve_targets()
    return targets


def _one_input(data: bytes, targets) -> None:
    if not targets:
        return
    fdp = atheris.FuzzedDataProvider(data)
    idx = fdp.ConsumeIntInRange(0, len(targets) - 1)
    qname, fn, kind, extra, union_str = targets[idx]
    raw = fdp.ConsumeBytes(fdp.remaining_bytes())
    # shape the bytes into the parser's input class
    if kind == "bytes":
        payload: object = raw
    elif kind in ("json_object", "envelope"):
        try:
            payload = json.loads(raw.decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            payload = base64.b64encode(raw).decode()  # exercise the base64/str path too
    else:
        payload = raw.decode("utf-8", "replace")
    try:
        fn(payload, **extra)
    except _ALLOWED:
        return  # documented malformed-input / path surface — fine
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:  # noqa: BLE001 - a raw crash is the bug Atheris must surface
        sys.stderr.write(f"UNTRIAGED CRASH in {qname} on shaped input\n")
        raise


def main() -> int:
    if atheris is None:
        print("atheris not installed — the ClusterFuzzLite continuous leg is a CI/operational artifact; "
              "use scripts/fuzz_soak.py for the runnable-here bounded soak.")
        return 0
    targets = _targets()
    atheris.Setup(sys.argv, lambda data: _one_input(data, targets))
    atheris.Fuzz()
    return 0


if __name__ == "__main__":
    sys.exit(main())
