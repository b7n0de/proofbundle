#!/usr/bin/env python3
"""Verify the thirteen vectors of the Certisyn containment pilot pack with proofbundle's reader.

Offline. No key is taken from any seal: every signature is checked under the key of pack/KEY.json, the trust
configuration agreed before the pilot, read by ``proofbundle.containment.load_trusted_key`` and compared with the
SHA-256 pinned below. The scope is integrity only: an accepted pair is the record that the holder of the pinned key
sealed, and nothing is said about whether its result is right.

Each vector is submitted as pack/run-all.mjs submits it: the record and seal of its own id, or of the id in its
``record`` field, with the input file of its ``input`` field or of its own id, where pack/inputs/ has one.

Run from a checkout of this branch:

    PYTHONPATH=src python examples/certisyn_containment_pilot/verify_all.py

The output is compared byte for byte with expected_output.txt by tests/test_certisyn_containment_reader.py. Exit 0
when every vector behaves as pack/expected.json says, else 1.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from proofbundle.containment import SCOPE_NOTE, load_trusted_key, verify_containment_record

PACK = Path(__file__).resolve().parent / "pack"

#: The SHA-256 of the raw pilot key, pinned on 2026-10-27 after the same key was read on three channels.
PINNED_KEY_SHA256 = "6d6ead37c11a2f09a6ec4d17b38d8ea0e9227234a27f6316e7c8e2bcbe0758b6"


def _manifest_mismatches() -> list[str]:
    bad = []
    for line in (PACK / "MANIFEST.sha256").read_text(encoding="ascii").splitlines():
        digest, _, path = line.partition("  ")
        if hashlib.sha256((PACK / path[2:]).read_bytes()).hexdigest() != digest:
            bad.append(path[2:])
    return bad


def main() -> int:
    lines = (PACK / "MANIFEST.sha256").read_text(encoding="ascii").splitlines()
    bad = _manifest_mismatches()
    print(f"pack: {len(lines) - len(bad)} of {len(lines)} files match MANIFEST.sha256")
    key = load_trusted_key((PACK / "KEY.json").read_bytes())
    key_sha256 = hashlib.sha256(key).hexdigest()
    print(f"trusted key: sha256 {key_sha256} ({'the pinned key' if key_sha256 == PINNED_KEY_SHA256 else 'NOT THE PINNED KEY'})")
    print(f"scope: {SCOPE_NOTE}")
    if bad or key_sha256 != PINNED_KEY_SHA256:
        print("=> STOP: the pack or its key is not the one agreed")
        return 1
    expected = json.loads((PACK / "expected.json").read_text(encoding="utf-8"))
    cases = [(vector_id, "ACCEPT", {}) for vector_id in expected["accept"]]
    cases += [(entry["id"], "REFUSE", entry) for entry in expected["refuse"]]
    mismatches = 0
    for vector_id, want, override in cases:
        record_id = override.get("record", vector_id)
        input_path = PACK / "inputs" / f"{override.get('input', vector_id)}.input.json"
        result = verify_containment_record(
            (PACK / "vectors" / f"{record_id}.record.json").read_bytes(),
            (PACK / "vectors" / f"{record_id}.seal.json").read_bytes(),
            trusted_key=key,
            input_series=input_path.read_bytes() if input_path.is_file() else None)
        got = result["outcome"]
        mismatches += got != want
        print(f"{vector_id} expected {want} got {got}  input_digest {result['steps']['input_digest']}")
        for failure in result["failures"]:
            print(f"    failed {failure['step']}: {failure['reason']}")
    print("limit: pack/README.md withdraws the record bc1b1b5e by a note and says it verifies under the pilot key; "
          "the format carries no withdrawal, so this reader cannot see one (that record is not in pack/, not run here)")
    if mismatches:
        print(f"=> MISMATCH ({mismatches} of {len(cases)} vectors)")
        return 1
    print(f"=> OK ({len(cases)} of {len(cases)} vectors behave as pack/expected.json says)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
