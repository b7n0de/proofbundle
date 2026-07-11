#!/usr/bin/env python3
"""Offline conformance harness for proofbundle.

Reads ``conformance/manifest.json`` (a list of case directories), loads each
``case.json``, dispatches by ``kind``, runs the checks purely offline (no calendar,
no network — any Bitcoin block header a case needs is frozen inside its ``case.json``),
and compares the result to the case's ``expected`` block. Exit 0 iff every case matches
its expectation.

Design: a case declares what it proves AND what it does not. A cross-implementation
decision case that is canonicalization-correct but not schema-conformant is an
*expected* 12-finding result, recorded, not hidden — so a green run never overclaims.

Anchors: verifying a confirmed OpenTimestamps proof needs the ``opentimestamps`` package
(the ``[anchors]`` extra). Without it the anchor sub-check is SKIPPED and reported;
pass ``--require-anchors`` (CI does) to turn a missing optional dependency into a failure
so the anchor line can never be silently skipped in the authoritative run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

from proofbundle import canonicalize_statement, statement_content_root
from proofbundle.decision import validate_decision_predicate

try:
    from proofbundle.anchors_ots import verify_opentimestamps
    import opentimestamps  # noqa: F401
    _HAS_OTS = True
except Exception:   # pragma: no cover - exercised in the no-extra CI leg
    _HAS_OTS = False

ROOT = pathlib.Path(__file__).resolve().parent


def _fail(case_id: str, msg: str) -> dict:
    return {"caseId": case_id, "ok": False, "detail": msg}


def _content_root_hex(statement: dict) -> str:
    r = statement_content_root(statement)
    return r.hex() if isinstance(r, (bytes, bytearray)) else str(r)


def _check_decision_crossimpl(case: dict, case_dir: pathlib.Path, *, require_anchors: bool) -> dict:
    cid = case["caseId"]
    exp = case["expected"]
    notes: list[str] = []

    man = json.loads((case_dir / "MANIFEST.json").read_text())
    for name, stem, mkey, ekey in [
        ("decision", "decision_receipt", "decision_content_root_sha256", "decision_content_root"),
        ("evidence", "evidence_eval_result", "evidence_content_root_sha256", "evidence_content_root"),
    ]:
        statement = json.loads((case_dir / f"{stem}.json").read_text())
        canon = canonicalize_statement(statement)
        canon = canon.encode() if isinstance(canon, str) else canon
        jcs = (case_dir / f"{stem}.jcs").read_bytes()
        if exp.get("jcs_byte_identical") and canon != jcs:
            return _fail(cid, f"{name}: .jcs not byte-identical to canonical output")
        root = _content_root_hex(statement)
        if exp.get("content_roots_match_manifest") and root != man.get(mkey):
            return _fail(cid, f"{name}: content root {root} != MANIFEST {man.get(mkey)}")
        if ekey in exp and root != exp[ekey]:
            return _fail(cid, f"{name}: content root {root} != expected {exp[ekey]}")
        notes.append(f"{name} root {root[:12]}… ok")

    # evidenceRef binds the evidence content root
    dec = json.loads((case_dir / "decision_receipt.json").read_text())
    ev_root = _content_root_hex(json.loads((case_dir / "evidence_eval_result.json").read_text()))
    refs = dec.get("predicate", {}).get("evidenceRefs") or []
    bound = any(isinstance(r, dict) and r.get("digest", {}).get("sha256") == ev_root for r in refs)
    if exp.get("evidence_ref_binds_content_root") and not bound:
        return _fail(cid, "evidenceRefs[*].digest does not bind the evidence content root")

    # schema conformance (expected-fail is a real, recorded expectation)
    findings = validate_decision_predicate(dec["predicate"])
    if "decision_predicate_findings" in exp and len(findings) != exp["decision_predicate_findings"]:
        return _fail(cid, f"validate_decision_predicate = {len(findings)} findings, "
                          f"expected {exp['decision_predicate_findings']}")
    if exp.get("schema_conformant") is True and findings:
        return _fail(cid, f"expected schema-conformant but got {len(findings)} findings")
    if exp.get("schema_conformant") is False and not findings:
        return _fail(cid, "expected non-conformant (findings) but predicate validates clean")
    notes.append(f"validator {len(findings)} findings (expected-fail)" if findings else "validator clean")

    # anchor
    anchor = exp.get("anchor")
    if anchor:
        want = anchor.get("status")
        if not _HAS_OTS:
            if require_anchors:
                return _fail(cid, "anchor check required but opentimestamps ([anchors]) is not installed")
            notes.append(f"anchor {want}: SKIPPED (opentimestamps not installed)")
        else:
            jcs = (case_dir / "decision_receipt.jcs").read_bytes()
            root = hashlib.sha256(jcs).digest()
            frozen = anchor.get("frozen") or {}
            res = verify_opentimestamps((case_dir / "decision_receipt.jcs.ots").read_bytes(),
                                        root, frozen=frozen)
            if res["status"] != want:
                return _fail(cid, f"anchor status {res['status']!r} != expected {want!r} ({res['detail']})")
            if want == "confirmed" and not res.get("ok"):
                return _fail(cid, "anchor expected confirmed but verify did not return ok")
            notes.append(f"anchor {res['status']} (offline{'' if frozen else ', no frozen header'})")

    return {"caseId": cid, "ok": True, "detail": " · ".join(notes)}


_DISPATCH = {"decision_crossimpl": _check_decision_crossimpl}


def run(*, require_anchors: bool = False) -> int:
    manifest = json.loads((ROOT / "manifest.json").read_text())
    cases = manifest.get("cases", [])
    results: list[dict] = []
    for rel in cases:
        case_dir = ROOT / rel
        case = json.loads((case_dir / "case.json").read_text())
        handler = _DISPATCH.get(case["kind"])
        if handler is None:
            results.append(_fail(case.get("caseId", rel), f"unknown kind {case['kind']!r}"))
            continue
        results.append(handler(case, case_dir, require_anchors=require_anchors))

    ok = all(r["ok"] for r in results)
    print(f"[conformance] {sum(r['ok'] for r in results)}/{len(results)} cases pass"
          f"{' (anchors required)' if require_anchors else ''}")
    for r in results:
        print(f"  {'PASS' if r['ok'] else 'FAIL'}  {r['caseId']}: {r['detail']}")
    if not _HAS_OTS and not require_anchors:
        print("  note: opentimestamps not installed — anchor sub-checks skipped "
              "(run in the [anchors] CI job or with --require-anchors for the full check)")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="proofbundle offline conformance harness")
    p.add_argument("--require-anchors", action="store_true",
                   help="fail (do not skip) if opentimestamps is unavailable for an anchor case")
    args = p.parse_args(argv)
    return run(require_anchors=args.require_anchors)


if __name__ == "__main__":
    sys.exit(main())
