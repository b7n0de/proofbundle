#!/usr/bin/env python3
"""Fundament F1 — the ONE cross-format comparator over the corpus.

Two structural jobs, both built on ``common_vocabulary.py`` (no second vocabulary):

  1. SCHEMA — every ``case.json`` in the manifest validates against ``vector_schema.json``.
     If ``jsonschema`` is installed the full Draft 2020-12 check runs; otherwise a
     dependency-free structural fallback checks the fail-closed floor (required keys, a
     non-empty ``expected``, pinned axes in-vocabulary). Either way a malformed/under-declared
     case is caught, never silently accepted.

  2. CROSS-FORMAT AGREEMENT — cases sharing a ``crossFormatId`` are the SAME logical scenario
     in different encodings/levels. Their EXPECTED common-vocabulary labels must agree on every
     axis both pin. This is the structural closure of the 3.4.0 F3 "circular comparator"
     finding: a scenario cannot claim VERIFIED as a native bundle and FAIL as a relation vector
     under one id — the corpus itself forbids the contradiction, no hand comparison.

This is a corpus-INTEGRITY check (are the declared expectations mutually consistent and
well-formed?), complementary to the runner's per-case EXECUTION check (does the real verifier
land on the declared expectation?). The runner calls this before executing, and the same entry
point is importable by crosscheck.py so the Rust differential shares one corpus view.

Exit 0 iff the corpus is schema-valid and cross-format-consistent.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))  # for `import common_vocabulary` when run as a script

from common_vocabulary import AXES, EXIT_CLASSES, LINEAGE_STATES, POLICY_VERDICTS, expected_label  # noqa: E402

SCHEMA_PATH = ROOT / "vector_schema.json"
MANIFEST_PATH = ROOT / "manifest.json"


def load_cases(manifest_path: pathlib.Path = MANIFEST_PATH) -> list[tuple[str, dict]]:
    """Return ``[(relpath, case_dict)]`` for every case in the manifest. A missing or malformed
    case.json raises — a corpus that cannot be loaded is a loud whole-corpus failure, matching
    run_conformance's manifest-level precondition."""
    manifest = json.loads(manifest_path.read_text())
    out: list[tuple[str, dict]] = []
    for rel in manifest.get("cases", []):
        case = json.loads((ROOT / rel / "case.json").read_text())
        out.append((rel, case))
    return out


def _structural_validate(case: dict) -> list[str]:
    """Dependency-free fallback for the fail-closed floor (used when jsonschema is absent).
    Deliberately conservative: it enforces exactly the invariants the runner relies on."""
    errs: list[str] = []
    for key in ("caseId", "kind", "expected"):
        if key not in case:
            errs.append(f"missing required key {key!r}")
    if case.get("kind") not in {"decision_crossimpl", "native_bundle", "decision_relation",
                                 "outcome_relation"}:
        errs.append(f"unknown kind {case.get('kind')!r}")
    exp = case.get("expected")
    if not isinstance(exp, dict) or not exp:
        errs.append("expected must be a non-empty object (fail-closed: a case must pin something)")
        return errs
    if "exitCode" in exp and exp["exitCode"] not in (0, 1, 2, 3):
        errs.append(f"exitCode {exp['exitCode']!r} out of the 0..3 contract")
    if "exitClass" in exp and exp["exitClass"] not in EXIT_CLASSES:
        errs.append(f"exitClass {exp['exitClass']!r} not in the F1 vocabulary")
    if "lineage" in exp and exp["lineage"] is not None and exp["lineage"] not in LINEAGE_STATES:
        errs.append(f"lineage {exp['lineage']!r} not in the F1 vocabulary")
    if "policyVerdict" in exp and exp["policyVerdict"] not in POLICY_VERDICTS:
        errs.append(f"policyVerdict {exp['policyVerdict']!r} not in the F1 vocabulary")
    return errs


def validate_schema(cases: list[tuple[str, dict]]) -> list[str]:
    problems: list[str] = []
    try:
        import jsonschema  # type: ignore
        schema = json.loads(SCHEMA_PATH.read_text())
        validator = jsonschema.Draft202012Validator(schema)
        for rel, case in cases:
            for err in validator.iter_errors(case):
                problems.append(f"{rel}: schema: {err.message}")
    except ImportError:
        for rel, case in cases:
            for msg in _structural_validate(case):
                problems.append(f"{rel}: {msg}")
    return problems


def check_cross_format(cases: list[tuple[str, dict]]) -> list[str]:
    """Group by crossFormatId; every axis two members of a group both pin must agree."""
    groups: dict[str, list[tuple[str, dict]]] = {}
    for rel, case in cases:
        xid = case.get("crossFormatId")
        if isinstance(xid, str) and xid:
            groups.setdefault(xid, []).append((rel, expected_label(case.get("expected", {}))))
    problems: list[str] = []
    for xid, members in groups.items():
        if len(members) < 2:
            continue
        for axis in AXES:
            pinned = [(rel, lbl[axis]) for rel, lbl in members if lbl.get(axis) is not None]
            distinct = {v for _, v in pinned}
            if len(distinct) > 1:
                where = ", ".join(f"{rel}={v!r}" for rel, v in pinned)
                problems.append(
                    f"crossFormatId {xid!r} disagrees on {axis}: {where} "
                    "(same logical scenario, contradictory declared verdicts)")
    return problems


def run(manifest_path: pathlib.Path = MANIFEST_PATH) -> tuple[bool, list[str]]:
    cases = load_cases(manifest_path)
    problems = validate_schema(cases) + check_cross_format(cases)
    return (not problems, problems)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="proofbundle conformance corpus integrity (F1)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    ok, problems = run()
    xids = {c.get("crossFormatId") for _, c in load_cases() if c.get("crossFormatId")}
    if args.json:
        print(json.dumps({"ok": ok, "problems": problems,
                          "crossFormatIds": sorted(xids)}, indent=2, ensure_ascii=False))
    else:
        n = len(load_cases())
        print(f"[cross-format] {n} case(s), {len(xids)} cross-format group(s): "
              f"{'OK' if ok else str(len(problems)) + ' PROBLEM(S)'}")
        for pr in problems:
            print("  -", pr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
