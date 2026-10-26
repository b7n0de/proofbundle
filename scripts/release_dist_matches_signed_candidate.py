#!/usr/bin/env python3
"""The sdist and wheel of a tag run are the pair the owner signed, compared before any upload.

FINDING (external review of the 6.4.0 preparation, 2026-10-26, RELEASEPLAN P4). release.yml compared the
files `publish-pypi` downloads with the digests `build-and-attest` recorded in the SAME run. That holds
the hand-over from the attested build to the upload. Nothing compared the tag build with the pair that
was frozen and approved before the tag, so a tag build with other bytes would have been attested and
published.

THE EXPECTATION IS SIGNED, NOT BUILT. The short soak (audit matrix row C6.2) and the Rust differential
(C8.2) are signed by a key of `audit_artifacts/readiness_trusted_pubkeys.txt` over a body whose
`candidate` block names the sdist and wheel digests of the frozen pair, and the release plan requires
that pair to be the one it records. This script verifies each signature with the audit matrix's own
check, requires the version of the tag and the schema of each source, requires all sources to name ONE
pair, and compares that pair with the version's one sdist and one wheel in `dist/`.

WHAT IT DOES NOT DECIDE. Whether the tagged commit may differ from the measured one, and the freshness
and gate line of the evidence: those belong to the release plan's order (P7) and to the audit matrix
before the tag. This is the comparison of bytes, at the last place before an upload.

CLI:
  python scripts/release_dist_matches_signed_candidate.py --version X.Y.Z [--repo DIR]

Exit 0 when `dist/` is the signed pair, 1 otherwise; every refusal says why.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _matrix():
    """`scripts/audit_candidate_matrix.py` as a module: its signature check, anchor reader and dist
    selection are used as they are, so that the tag run and the matrix judge one way."""
    spec = importlib.util.spec_from_file_location(
        "_acm_release_dist", str(REPO / "scripts" / "audit_candidate_matrix.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def _quellen(m) -> tuple[tuple[str, str], ...]:
    """The signed sources of the pair: (path, schema). Both are in the signing package of the plan."""
    return ((m._SOAK_ARTIFACT_REL, m._SOAK_SCHEMA),
            (m._DIFFERENTIAL_ARTIFACT_REL, m._DIFFERENTIAL_SCHEMA))


def _lies(repo: Path, rel: str) -> tuple[dict | None, str]:
    """One source, under the same input cap and strict reader as the matrix's admission path."""
    from proofbundle._strict_json import loads_strict  # noqa: PLC0415
    from proofbundle.budget import DEFAULT_BUDGET  # noqa: PLC0415
    from proofbundle.errors import ProofBundleError  # noqa: PLC0415
    p = repo / rel
    if not p.is_file():
        return None, f"{rel} is absent"
    kappe = int(DEFAULT_BUDGET.input_bytes)
    with p.open("rb") as fh:
        roh = fh.read(kappe + 1)
    if len(roh) > kappe:
        return None, f"{rel} is over the input_bytes budget of {kappe}"
    try:
        art = loads_strict(roh)
    except (ProofBundleError, ValueError, UnicodeDecodeError, RecursionError) as exc:
        return None, f"{rel} is not valid strict JSON: {exc}"
    if not isinstance(art, dict):
        return None, f"{rel} is not a JSON object"
    return art, "read"


def signed_pair(repo: Path, version: str) -> tuple[tuple[str, str] | None, list[str]]:
    """``(pair, lines)``: the one (sdist, wheel) pair every signed source names, or None with the reason.

    Fail-closed at each step: a missing, unreadable, unsigned or foreign-signed source, another version,
    another schema, a malformed candidate block and two sources that name different pairs each give
    None. A source counts only when the matrix's signature check says `verified`."""
    m = _matrix()
    zeilen: list[str] = []
    paare: set[tuple[str, str]] = set()
    trusted, anker = m._trust_anchor(repo)
    for rel, schema in _quellen(m):
        art, grund = _lies(repo, rel)
        if art is None:
            return None, [*zeilen, f"no signed pair: {grund}"]
        rumpf = {k: v for k, v in art.items() if k != "signature"}
        if rumpf.get("schema") != schema:
            return None, [*zeilen, f"no signed pair: {rel} declares schema {rumpf.get('schema')!r}, "
                                   f"expected {schema!r}"]
        if rumpf.get("version") != version:
            return None, [*zeilen, f"no signed pair: {rel} is signed for version "
                                   f"{rumpf.get('version')!r}, the tag is {version!r}"]
        kandidat = rumpf.get("candidate")
        sd = kandidat.get("sdist_sha256") if isinstance(kandidat, dict) else None
        wh = kandidat.get("wheel_sha256") if isinstance(kandidat, dict) else None
        if not (isinstance(sd, str) and m._HEX64.fullmatch(sd)
                and isinstance(wh, str) and m._HEX64.fullmatch(wh)):
            return None, [*zeilen, f"no signed pair: {rel} names no candidate sdist and wheel digest"]
        zustand, grund = m._artifact_signature_ok(art, trusted, anker, repo=repo)
        if zustand != m.ART_VERIFIED:
            return None, [*zeilen, f"no signed pair: {rel} is not admitted ({zustand}): {grund}"]
        zeilen.append(f"signed pair in {rel}: sdist {sd} wheel {wh}")
        paare.add((sd, wh))
    if len(paare) != 1:
        return None, [*zeilen, "no signed pair: the signed sources name different pairs"]
    return paare.pop(), zeilen


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--version", required=True, help="the version of the tag, without the leading v")
    p.add_argument("--repo", type=Path, default=REPO, help="the checkout (default: this repository)")
    args = p.parse_args(argv)
    repo = args.repo.resolve()
    paar, zeilen = signed_pair(repo, args.version)
    for z in zeilen:
        print(z)
    if paar is None:
        print("NOT THE SIGNED CANDIDATE: there is no signed pair to compare with, so nothing is "
              "uploaded")
        return 1
    sdist, wheel, grund = _matrix()._dist_files(repo, args.version)
    if sdist is None or wheel is None:
        print(f"NOT THE SIGNED CANDIDATE: {grund}")
        return 1
    ist = (hashlib.sha256(sdist.read_bytes()).hexdigest(),
           hashlib.sha256(wheel.read_bytes()).hexdigest())
    print(f"built sdist {sdist.name} {ist[0]}\nbuilt wheel {wheel.name} {ist[1]}")
    if ist != paar:
        print("NOT THE SIGNED CANDIDATE: the tag run built other bytes than the signed pair"
              f"\n  sdist built {ist[0]} signed {paar[0]}\n  wheel built {ist[1]} signed {paar[1]}")
        return 1
    print("OK: the tag run built the signed candidate pair")
    return 0


if __name__ == "__main__":
    sys.exit(main())
