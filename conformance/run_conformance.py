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


def _check_native_bundle(case: dict, case_dir: pathlib.Path, *, require_anchors: bool = False) -> dict:
    """A native proofbundle bundle checked against the CLI verify exit-code contract
    (0 crypto OK · 1 verification failure · 2 malformed · 3 policy unmet). The exit code IS the
    conformance contract, so a case declares the exact code it must produce. Fail-closed floor:
    a native_bundle case MUST declare `exitCode`."""
    from proofbundle.cli import main as _cli_main  # noqa: PLC0415
    cid = case["caseId"]
    exp = case["expected"]
    if "exitCode" not in exp:
        return _fail(cid, "native_bundle case under-declares its expectations (fail-closed): missing exitCode")
    inp = case.get("input", "bundle.json")
    bundle = (case_dir / inp).resolve()
    # confine the fixture to the case directory: a case.json is a reviewed fixture, but an absolute or
    # traversal `input` must never let the harness verify a file outside its own case dir.
    if not str(bundle).startswith(str(case_dir.resolve()) + "/"):
        return _fail(cid, f"input {inp!r} escapes the case directory")
    if not bundle.is_file():
        return _fail(cid, f"fixture {pathlib.Path(inp).name} missing")
    import contextlib  # noqa: PLC0415
    import io  # noqa: PLC0415
    # optional extra verify args (e.g. ["--require-anchor"]) — a relying-party gate the case exercises.
    # Confined to a small allowlist so a case cannot make the harness read files or reach the network.
    extra = case.get("verifyArgs") or []
    _ALLOWED = {"--require-anchor", "--anchor-type", "--allow-pending", "--anchor-target"}
    if not isinstance(extra, list) or any(
            not isinstance(a, str) or (a.startswith("--") and a not in _ALLOWED) for a in extra):
        return _fail(cid, f"verifyArgs must be a list drawn from {sorted(_ALLOWED)} (no file/network flags)")
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = _cli_main(["verify", str(bundle), *extra])
    if rc != exp["exitCode"]:
        return _fail(cid, f"verify exit {rc} != expected {exp['exitCode']}")
    if "rejected" in exp and bool(exp["rejected"]) != (rc != 0):
        return _fail(cid, f"rejected={exp['rejected']} but exit {rc}")
    verdict = {0: "verified", 1: "verification failed", 2: "malformed/rejected", 3: "policy unmet"}.get(rc, str(rc))
    return {"caseId": cid, "ok": True, "detail": f"verify exit {rc} ({verdict}) as expected"}


def _check_decision_crossimpl(case: dict, case_dir: pathlib.Path, *, require_anchors: bool) -> dict:
    cid = case["caseId"]
    exp = case["expected"]
    notes: list[str] = []

    # Required-expectations floor (fail-closed): every check below is gated on its key being
    # present in `expected`, so a case that DECLARES nothing would assert nothing and pass green.
    # A decision_crossimpl case MUST declare its bindings; an anchored case MUST declare its anchor.
    # This is what makes "a broken/under-declared fixture cannot pass" unconditional, not just true
    # for byte-tampering. Removing/weakening an expectation is caught here, not silently skipped.
    required = ["jcs_byte_identical", "content_roots_match_manifest", "decision_content_root",
                "evidence_content_root", "evidence_ref_binds_content_root",
                "decision_predicate_findings", "schema_conformant"]
    if (case_dir / "decision_receipt.jcs.ots").is_file():
        required.append("anchor")
    missing = [k for k in required if k not in exp]
    if missing:
        return _fail(cid, f"case under-declares its expectations (fail-closed): missing {missing}")

    # These are the DEFINING properties of a decision_crossimpl case, so they run UNCONDITIONALLY
    # (the `expected` values only supply the exact root/count/status to match). An `expected` value of
    # false or a dropped key can never silently disable them — the floor guarantees presence and the
    # checks below always execute, so the "ok" notes never claim a comparison that did not run.
    man = json.loads((case_dir / "MANIFEST.json").read_text())
    for name, stem, mkey, ekey in [
        ("decision", "decision_receipt", "decision_content_root_sha256", "decision_content_root"),
        ("evidence", "evidence_eval_result", "evidence_content_root_sha256", "evidence_content_root"),
    ]:
        statement = json.loads((case_dir / f"{stem}.json").read_text())
        canon = canonicalize_statement(statement)
        canon = canon.encode() if isinstance(canon, str) else canon
        jcs = (case_dir / f"{stem}.jcs").read_bytes()
        if canon != jcs:
            return _fail(cid, f"{name}: .jcs not byte-identical to canonical output")
        root = _content_root_hex(statement)
        if root != man.get(mkey):
            return _fail(cid, f"{name}: content root {root} != MANIFEST {man.get(mkey)}")
        if root != exp[ekey]:
            return _fail(cid, f"{name}: content root {root} != expected {exp[ekey]}")
        notes.append(f"{name} root {root[:12]}… ok")

    # evidenceRef binds the evidence content root (unconditional)
    dec = json.loads((case_dir / "decision_receipt.json").read_text())
    ev_root = _content_root_hex(json.loads((case_dir / "evidence_eval_result.json").read_text()))
    refs = dec.get("predicate", {}).get("evidenceRefs") or []
    bound = any(isinstance(r, dict) and r.get("digest", {}).get("sha256") == ev_root for r in refs)
    if not bound:
        return _fail(cid, "evidenceRefs[*].digest does not bind the evidence content root")

    # schema conformance (expected-fail is a real, recorded expectation; count is compared unconditionally)
    findings = validate_decision_predicate(dec["predicate"])
    if len(findings) != exp["decision_predicate_findings"]:
        return _fail(cid, f"validate_decision_predicate = {len(findings)} findings, "
                          f"expected {exp['decision_predicate_findings']}")
    if exp["schema_conformant"] is True and findings:
        return _fail(cid, f"expected schema-conformant but got {len(findings)} findings")
    if exp["schema_conformant"] is False and not findings:
        return _fail(cid, "expected non-conformant (findings) but predicate validates clean")
    notes.append(f"validator {len(findings)} findings (expected-fail)" if findings else "validator clean")

    # anchor — mandatory (floor) whenever the case ships a .jcs.ots; verified unconditionally so a
    # confirmed case cannot pass by simply not declaring its anchor.
    anchor = exp.get("anchor")
    if (case_dir / "decision_receipt.jcs.ots").is_file() and not anchor:
        return _fail(cid, "case ships a .jcs.ots but declares no anchor expectation (fail-closed)")
    if anchor:
        want = anchor.get("status")
        if not _HAS_OTS:
            if require_anchors:
                return _fail(cid, "anchor check required but opentimestamps ([anchors]) is not installed")
            notes.append(f"anchor {want}: SKIPPED (opentimestamps not installed)")
        else:
            jcs = (case_dir / "decision_receipt.jcs").read_bytes()
            root = hashlib.sha256(jcs).digest()
            # WP-A1: the Bitcoin block header is TRUST material and must come from the RELYING PARTY, not
            # the bundle's producer-controlled `frozen` block. A confirmed conformance case declares its
            # header under `rpTrust` (independently sourced — see the case's independent_source block); the
            # producer `frozen` is kept only as evidence. Passing it as rp_trust models a relying party who
            # independently obtained that header. A confirmed expectation with NO rpTrust is a case bug.
            rp_declared = anchor.get("rpTrust") or {}
            rp_trust = {"bitcoin_block_headers": rp_declared.get("bitcoinBlockHeaderMerkleRootsByHeight") or {}}
            frozen = anchor.get("frozen") or {}
            if want == "confirmed" and not rp_trust["bitcoin_block_headers"]:
                return _fail(cid, "case expects a confirmed anchor but declares no rpTrust header (WP-A1: "
                                  "frozen is not trust — a confirmed case must supply a relying-party header)")
            res = verify_opentimestamps((case_dir / "decision_receipt.jcs.ots").read_bytes(),
                                        root, frozen=frozen, rp_trust=rp_trust)
            if res["status"] != want:
                return _fail(cid, f"anchor status {res['status']!r} != expected {want!r} ({res['detail']})")
            if want == "confirmed" and not res.get("ok"):
                return _fail(cid, "anchor expected confirmed but verify did not return ok")
            # WP-A1 security counter-check: the SAME proof WITHOUT the relying-party header must NOT confirm
            if want == "confirmed":
                no_rp = verify_opentimestamps((case_dir / "decision_receipt.jcs.ots").read_bytes(),
                                              root, frozen=frozen)
                if no_rp.get("ok") or no_rp["status"] == "confirmed":
                    return _fail(cid, "anchor confirmed WITHOUT relying-party trust — frozen leaked as trust")
            notes.append(f"anchor {res['status']} (offline, relying-party header)")

    return {"caseId": cid, "ok": True, "detail": " · ".join(notes)}


_DISPATCH = {"decision_crossimpl": _check_decision_crossimpl, "native_bundle": _check_native_bundle}


def run(*, require_anchors: bool = False) -> int:
    manifest = json.loads((ROOT / "manifest.json").read_text())
    cases = manifest.get("cases", [])
    results: list[dict] = []
    for rel in cases:
        # EVERYTHING per-case is inside the try: a missing case dir, a malformed case.json, a case.json
        # with no `kind`, or an exception inside the handler is a per-case FAIL — never a run-aborting
        # crash that masks every later case's status. (The manifest-level parse above is a whole-corpus
        # precondition; a corrupt manifest failing loudly is correct.)
        case_dir = ROOT / rel
        try:
            case = json.loads((case_dir / "case.json").read_text())
            if "kind" not in case:
                results.append(_fail(rel, "case.json has no 'kind'"))
                continue
            handler = _DISPATCH.get(case["kind"])
            if handler is None:
                results.append(_fail(case.get("caseId", rel), f"unknown kind {case['kind']!r}"))
                continue
            results.append(handler(case, case_dir, require_anchors=require_anchors))
        except Exception as e:
            results.append(_fail(rel, f"{type(e).__name__}: {e}"))

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
