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

# F1: the ONE common vocabulary + corpus-integrity comparator (siblings of this file).
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import cross_format  # noqa: E402
from common_vocabulary import compare, expected_label, label_from_verify  # noqa: E402

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
    # A case whose intended rejection reason needs the [anchors] extra (e.g. a forged OpenTimestamps anchor
    # that must reach `needs_rp_trust`) MUST NOT false-pass on a base install, where the proof never parses
    # (no_lib) and the same exit 3 arises for an unrelated reason. Gate it like decision_crossimpl.
    if case.get("requiresAnchorsExtra") and not _HAS_OTS:
        if require_anchors:
            return _fail(cid, "case needs the [anchors] extra but opentimestamps is not installed")
        return {"caseId": cid, "ok": True, "detail": "SKIPPED (opentimestamps not installed)"}
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
    _ALLOWED = {"--require-anchor", "--anchor-type", "--allow-pending", "--anchor-target",
                "--expected-root", "--expected-tree-size"}
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


def _check_relation(case: dict, case_dir: pathlib.Path, *, verb: str) -> dict:
    """relation/v0.1 lineage vectors on the `decision` OR `outcome` verify path (WP-B mirrors the
    gate on both). Runs `<verb> verify` with the case's attached related receipts (optional
    per-target --related-pub for WP-A cross-issuer, optional --policy) and compares exit code +
    reported lineage state via the ONE common-vocabulary comparator. Fail-closed floor: exitCode is
    mandatory; every declared expectation is asserted. All referenced files are confined to the case
    directory (same rule as native_bundle)."""
    import base64  # noqa: PLC0415
    import contextlib  # noqa: PLC0415
    import io  # noqa: PLC0415
    from proofbundle.cli import main as _cli_main  # noqa: PLC0415
    cid = case["caseId"]
    exp = case["expected"]
    if "exitCode" not in exp:
        return _fail(cid, f"{verb}_relation case under-declares its expectations: missing exitCode")

    def _confined(name: str) -> pathlib.Path | None:
        f = (case_dir / name).resolve()
        if not str(f).startswith(str(case_dir.resolve()) + "/") or not f.is_file():
            return None
        return f

    receipt = _confined(case.get("input", "receipt.json"))
    pub_file = _confined(case.get("pub", "pub.b64"))
    if receipt is None or pub_file is None:
        return _fail(cid, "receipt/pub fixture missing or escapes the case directory")
    pub_b64 = pub_file.read_text(encoding="utf-8").strip()
    try:
        base64.b64decode(pub_b64, validate=True)
    except Exception:
        return _fail(cid, "pub.b64 is not valid base64")
    argv = [verb, "verify", str(receipt), "--pub", pub_b64, "--json"]
    related = case.get("related") or []
    for rel_name in related:
        rel = _confined(rel_name)
        if rel is None:
            return _fail(cid, f"related fixture {rel_name!r} missing or escapes the case directory")
        argv += ["--with-related", str(rel)]
    # WP-A: per-target issuer keys (position-paired with `related`) for cross-issuer chains. A raw b64
    # string, NOT a file — never confined (it is key material, not a path).
    related_pubs = case.get("relatedPubs")
    if related_pubs is not None:
        if not isinstance(related_pubs, list) or len(related_pubs) != len(related):
            return _fail(cid, "relatedPubs must be a list parallel to `related`")
        for rp in related_pubs:
            argv += ["--related-pub", str(rp)]
    if case.get("policy"):
        pol = _confined(case["policy"])
        if pol is None:
            return _fail(cid, "policy fixture missing or escapes the case directory")
        argv += ["--policy", str(pol)]
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = _cli_main(argv)
    if rc != exp["exitCode"]:
        return _fail(cid, f"{verb} verify exit {rc} != expected {exp['exitCode']} "
                          f"(stderr: {err.getvalue()[:200]!r})")
    report = None
    try:
        report = json.loads(out.getvalue())
    except ValueError:
        report = None
    # F1/F3: derive the run's common-vocabulary label from the REAL verifier --json output and compare
    # it, in ONE vocabulary, against the case's declared expectation (the same comparator the
    # cross-format and Rust differential layers use — never a hand-entered field_result). This is the
    # structural closure of the F3 "circular comparator" finding: the decoy vector falls with this
    # independently-derived label and would not with a hand-copied one.
    ok_lbl, diffs = compare(expected_label(exp), label_from_verify(rc, report))
    if not ok_lbl:
        return _fail(cid, "; ".join(diffs))
    if "errorContains" in exp:
        blob = json.dumps(report or {}) + err.getvalue()
        if exp["errorContains"] not in blob:
            return _fail(cid, f"expected error marker {exp['errorContains']!r} not found in report/stderr")
    return {"caseId": cid, "ok": True, "detail": f"{verb} verify exit {rc}, lineage as declared"}


def _check_decision_relation(case: dict, case_dir: pathlib.Path, *, require_anchors: bool = False) -> dict:
    del require_anchors
    return _check_relation(case, case_dir, verb="decision")


def _check_outcome_relation(case: dict, case_dir: pathlib.Path, *, require_anchors: bool = False) -> dict:
    del require_anchors
    return _check_relation(case, case_dir, verb="outcome")


def _check_relation_statement(case: dict, case_dir: pathlib.Path, *, require_anchors: bool = False) -> dict:
    # 3.5.0 WP-A: the standalone relation-statement/v0.1 verify path. `relation-statement` is a single
    # CLI subcommand token, so the shared _check_relation harness drives it unchanged.
    del require_anchors
    return _check_relation(case, case_dir, verb="relation-statement")


def _check_provenance_version_status(case: dict, case_dir: pathlib.Path, *,
                                     require_anchors: bool = False) -> dict:
    """A provenance block is checked against the reported-version status rule (v5.0.0).

    WHY THIS KIND EXISTS. A harness-reported version field used to be simply ABSENT when the
    harness reported none, so absence carried two meanings at once — "the harness reported
    nothing" and "nobody bound this field". For a verifier that ambiguity is the failure class
    the product exists against. v5.0.0 adds an explicit three-value status beside each such
    field; the corpus is the original authority for that rule, so the rule needs cases here and
    not only unit tests.

    The case declares `expected.issues`: the exact list of problem sentences the verifier must
    produce for that provenance block. An EMPTY list means the block is consistent. Declaring
    the exact list (rather than only a count) is deliberate — a case that merely asserted "some
    problem" would pass on the wrong problem.
    """
    cid = case.get("caseId", str(case_dir))
    exp = case.get("expected") or {}
    if "issues" not in exp:
        return _fail(cid, "provenance_version_status case under-declares its expectations "
                          "(fail-closed): missing `issues`")
    name = case.get("input") or "provenance.json"
    if pathlib.Path(name).is_absolute() or ".." in pathlib.PurePosixPath(name).parts:
        return _fail(cid, f"input {name!r} escapes the case directory")
    try:
        prov = json.loads((case_dir / name).read_text())
    except Exception as e:                                   # noqa: BLE001
        return _fail(cid, f"{name} unreadable ({type(e).__name__}: {e})")
    if not isinstance(prov, dict):
        return _fail(cid, f"{name} must contain a JSON object")
    sys.path.insert(0, str(ROOT.parent / "src"))
    from proofbundle.adapters._provenance import version_status_issues  # noqa: PLC0415
    got = sorted(version_status_issues(prov))
    want = sorted(str(x) for x in exp["issues"])
    if got != want:
        return _fail(cid, f"issues {got!r} != expected {want!r}")
    return {"caseId": cid, "ok": True,
            "detail": f"{len(got)} issue(s) as expected"}


def _check_envelope_profile_rule(case: dict, case_dir: pathlib.Path, *,
                                 require_anchors: bool = False) -> dict:
    """One rule of the receipt-envelope profile, checked through OUR OWN emit/verify path (5.1).

    WHY THIS KIND EXISTS. The profile (docs/RECEIPT_ENVELOPE_PROFILE.md) states in R6 that whoever
    claims it ships the executable counter-proofs. A profile whose rules are only prose is a
    statement of intent, and one whose vectors are checked by a purpose-built mock proves something
    about the mock. So each rule R1 to R5 gets one COUNTER-PROOF (the thing that must fail) and one
    POSITIVE CONTROL — without which a verifier that rejected everything would score perfectly.

    The case declares exactly ONE expectation axis. A case that declares none is a FAIL, not a skip:
    an under-declared case is the quiet way a corpus grows cases that cannot fail.
    """
    cid = case.get("caseId", str(case_dir))
    exp = case.get("expected") or {}
    sys.path.insert(0, str(ROOT.parent / "src"))
    from proofbundle.evalclaim import canonicalize, classify_eval_claim  # noqa: PLC0415

    # EXACTLY one axis, checked BEFORE any of them runs. Under-declaration was fail-closed from the
    # start; OVER-declaration was not, and that is the same hole seen from the other side: the
    # if-chain returns on the FIRST axis, so a case naming two had its second silently ignored and
    # went green on the first. Measured 2026-08-30: a case carrying a correct `contentRootHex` and a
    # nonsense `classification` passed. (Raised by the cross-read; confirmed at source before fixing.)
    _ACHSEN = ("contentRootHex", "nonConformantDiffers", "canonicalizeRefuses",
               "classification")
    genannt = [a for a in _ACHSEN if a in exp]
    if len(genannt) != 1:
        return _fail(cid, f"envelope_profile_rule case must declare EXACTLY ONE expectation axis "
                          f"(fail-closed), got {genannt or 'none'} — an under-declared case cannot "
                          f"fail, an over-declared one hides everything after the first")

    def _read(name):
        if pathlib.Path(name).is_absolute() or ".." in pathlib.PurePosixPath(name).parts:
            raise ValueError(f"input {name!r} escapes the case directory")
        return json.loads((case_dir / name).read_text())

    # R1 — one normative canonicalization.
    if "contentRootHex" in exp:
        got = hashlib.sha256(canonicalize(_read(case.get("input") or "object.json"))).hexdigest()
        if got != exp["contentRootHex"]:
            return _fail(cid, f"content root {got} != expected {exp['contentRootHex']}")
        return {"caseId": cid, "ok": True, "detail": "canonical content root reproduced"}

    if "nonConformantDiffers" in exp:
        obj = _read(case.get("input") or "object.json")
        konform = hashlib.sha256(canonicalize(obj)).hexdigest()
        legacy = hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=True,
                                           separators=(",", ":")).encode("utf-8")).hexdigest()
        differs = konform != legacy
        if differs is not bool(exp["nonConformantDiffers"]):
            return _fail(cid, f"divergence {differs} != expected {exp['nonConformantDiffers']} "
                              f"(conformant {konform[:16]}, legacy {legacy[:16]})")
        return {"caseId": cid, "ok": True,
                "detail": f"serializations differ as expected ({konform[:12]} vs {legacy[:12]})"}

    if "canonicalizeRefuses" in exp:
        from proofbundle.evalclaim import EvalClaimError  # noqa: PLC0415
        objs = _read(case.get("input") or "objects.json")
        if not isinstance(objs, list) or not objs:
            return _fail(cid, "canonicalizeRefuses case needs a non-empty list of objects")
        durchgelassen, hart = [], []
        for o in objs:
            try:
                canonicalize(o)
                durchgelassen.append(o)
            except EvalClaimError:
                pass                       # the principled refusal this axis is about
            except RecursionError:
                # A crash is ALSO a refusal to produce bytes, so it does not fake a pass. But it is
                # NOT the same thing as a typed rejection, and collapsing the two would hide a
                # robustness defect behind a green case. Measured: canonicalize lets RecursionError
                # escape on a deeply nested object. Counted as refused, reported separately.
                hart.append(type(o).__name__)
        refuses_all = not durchgelassen
        if refuses_all is not bool(exp["canonicalizeRefuses"]):
            return _fail(cid, f"refused_all={refuses_all} != expected {exp['canonicalizeRefuses']} "
                              f"(serialized instead of refusing: {durchgelassen!r})")
        zusatz = f", {len(hart)} of them by an UNTYPED crash (RecursionError), not a typed rejection" if hart else ""
        return {"caseId": cid, "ok": True,
                "detail": f"all {len(objs)} object(s) refused, as the counter-proof asserts{zusatz}"}

    # R2/R3/R4 — the three-outcome classification.
    if "classification" in exp:
        got, _claim = classify_eval_claim(_read(case.get("input") or "bundle.json"))
        if got != exp["classification"]:
            return _fail(cid, f"classification {got!r} != expected {exp['classification']!r}")
        return {"caseId": cid, "ok": True, "detail": f"classified {got}"}

    return _fail(cid, "envelope_profile_rule case under-declares its expectations (fail-closed): "
                      "none of contentRootHex / nonConformantDiffers / "
                      "canonicalizeRefuses / classification")



def _check_agent_review_predicate(case: dict, case_dir: pathlib.Path, *,
                                  require_anchors: bool = False) -> dict:
    """One rule of the agent-review predicate, checked through OUR OWN emit/verify path.

    WHY THIS KIND EXISTS. The predicate's whole claim is that a signature must not harden a weak
    self-report. That is a claim about what the code REFUSES, and a refusal is only real if some
    input actually hits it. So every rule brings a counter-proof (the thing that must fail) and the
    corpus carries positive controls — without which a verifier that rejected everything would score
    perfectly.

    Same fail-closed axis discipline as `_check_envelope_profile_rule`: EXACTLY one expectation axis,
    checked before any of them runs. Under-declaration is how a corpus grows cases that cannot fail;
    over-declaration is how the second axis gets silently ignored.

    Four classifications, and the difference between the last two is the point:
      valid    — emitted and verified
      invalid  — produced (or producible) but rejected by the verifier
      refused  — the producer would not build it at all (rejected at emit)
      (a case may reach `refused` from either the emit path or a digest helper that raises)
    """
    cid = case.get("caseId", str(case_dir))
    exp = case.get("expected") or {}
    sys.path.insert(0, str(ROOT.parent / "src"))
    from proofbundle import agent_review as ar  # noqa: PLC0415

    _ACHSEN = ("classification", "bodyCoreStable", "subjectExpectation",
               "currentReceipt", "chainIntegrity", "unverifiedSupersessionClaim",
               "versionStatus", "policyDecision")
    genannt = [a for a in _ACHSEN if a in exp]
    if len(genannt) != 1:
        return _fail(cid, f"agent_review_predicate case must declare EXACTLY ONE expectation axis "
                          f"(fail-closed), got {genannt or 'none'}")

    def _read(name):
        if pathlib.Path(name).is_absolute() or ".." in pathlib.PurePosixPath(name).parts:
            raise ValueError(f"input {name!r} escapes the case directory")
        return json.loads((case_dir / name).read_text())

    if "bodyCoreStable" in exp:
        bodies = _read(case.get("input") or "bodies.json")
        vorher = ar.body_core_digest(bodies["bodyBefore"])
        nachher = ar.body_core_digest(bodies["bodyAfter"])
        stable = vorher == nachher
        if stable is not bool(exp["bodyCoreStable"]):
            return _fail(cid, f"bodyCoreStable={stable} != expected {exp['bodyCoreStable']} "
                              f"({vorher[:12]} vs {nachher[:12]})")
        # DIE MELDUNG MUSS DAS GEMESSENE SAGEN, nicht den haeufigeren Fall. Die erste Fassung
        # schrieb immer "stable across re-render" — auch fuer die Gegenprobe, die INSTABILITAET
        # behauptet und bei der genau das der Befund ist. Ein Protokoll, aus dem der Leser das
        # Gegenteil des Gemessenen schliesst, ist schlimmer als keines.
        return {"caseId": cid, "ok": True,
                "detail": (f"body core digest stable across re-render ({vorher[:12]})" if stable
                           else f"body core digest MOVED, as this case asserts "
                                f"({vorher[:12]} -> {nachher[:12]})")}

    if "subjectExpectation" in exp:
        # Ob eine Erwartung von aussen gesetzt war, ist eine EIGENE Aussage — und dass ihre
        # Abwesenheit gemeldet wird, ist der Punkt: ohne sie prueft der Verifier nur die innere
        # Konsistenz, nicht die Bindung an das Objekt, das der Leser ansieht.
        doc = _read(case.get("input") or "envelope.json")
        key_hex = (case_dir.parent / "publickey.hex").read_text().strip()
        r = ar.verify_agent_review(doc, bytes.fromhex(key_hex))
        got = r.get("subject_expectation")
        if got != exp["subjectExpectation"]:
            return _fail(cid, f"subject_expectation {got!r} != expected {exp['subjectExpectation']!r}")
        if got == "not_supplied" and not any("expected_subject_digest" in w for w in r.get("warnings", [])):
            return _fail(cid, "absent expectation was not reported as a warning — a silent limit is "
                              "exactly what this case exists to prevent")
        return {"caseId": cid, "ok": True,
                "detail": f"subject expectation {got}, and the limit is stated"}

    if ("currentReceipt" in exp or "chainIntegrity" in exp
            or "unverifiedSupersessionClaim" in exp):
        # DIE SUPERSESSIONS-STRECKE (P0 Test 19). Die Gegenlese Runde 2 fuehrt Test 19 zweimal als
        # "WIDERLEGT als gefahrene Mutation": der Erstanwendungsbericht nannte ihn gefahren, und in
        # der vollstaendigen Fall-Liste existierte KEIN Supersessions-Fall.
        #
        # DER LAEUFER PRUEFT JEDEN UMSCHLAG SELBST, statt eine Liste gepruefter Digests aus dem Fall
        # zu uebernehmen. Das ist der ganze Punkt: `resolve_receipt_chain` ordnet nur nach dem, was
        # der Aufrufer kryptografisch geprueft HAT, und ein Fall, der sich diese Menge selbst
        # ausdenkt, wuerde die Abwehr des Uebernahmeangriffs nie beruehren. Ein fremd signierter
        # Umschlag faellt hier durch die Signaturpruefung und darf danach nichts mehr korrigieren.
        umschlaege, geprueft, kette = loese_kette(case, case_dir)
        if "currentReceipt" in exp:
            got = kette["current"]
            if got != exp["currentReceipt"]:
                return _fail(cid, f"current {got!r} != expected {exp['currentReceipt']!r} "
                                  f"(candidates {kette['current_candidates']}, "
                                  f"unverified claims {kette['unverified_supersession_claims']})")
            return {"caseId": cid, "ok": True,
                    "detail": (f"current receipt {str(got)[:12]}, "
                               f"{len(geprueft)}/{len(umschlaege)} envelope(s) verified")}
        if "unverifiedSupersessionClaim" in exp:
            # DIE UNTERSCHEIDENDE AUSSAGE. `current is None` allein wuerde hier NICHTS belegen:
            # dasselbe Ergebnis entstuende, wenn der Resolver Supersession gar nicht ansaehe. Erst
            # der GEMELDETE Anspruch zeigt, dass er ihn gesehen UND verworfen hat — ein abgewehrter
            # Uebernahmeversuch darf nicht aussehen wie ein leerer Eingang.
            gemeldet = kette["unverified_supersession_claims"]
            if exp["unverifiedSupersessionClaim"] not in gemeldet:
                return _fail(cid, f"der abgewehrte Anspruch wurde NICHT gemeldet: "
                                  f"{gemeldet!r} enthaelt nicht "
                                  f"{exp['unverifiedSupersessionClaim'][:12]!r}")
            if kette["corrected"]:
                return _fail(cid, f"ein ungepruefter Umschlag hat trotzdem korrigiert: "
                                  f"{kette['corrected_by']!r}")
            return {"caseId": cid, "ok": True,
                    "detail": (f"unverified supersession claim reported "
                               f"({exp['unverifiedSupersessionClaim'][:12]}), nothing corrected")}
        got_i = kette["integrity_ok"]
        if got_i is not bool(exp["chainIntegrity"]):
            return _fail(cid, f"integrity_ok={got_i} != expected {exp['chainIntegrity']} "
                              f"(missing {kette['missing_predecessors']}, "
                              f"unaddressable {kette['unaddressable']})")
        return {"caseId": cid, "ok": True,
                "detail": (f"chain integrity {got_i}, as this case asserts"
                           + (f" (missing predecessor {kette['missing_predecessors'][0][:12]})"
                              if kette["missing_predecessors"] else ""))}

    if "versionStatus" in exp:
        # A2, DIE WEICHE. Gemessen wird `verify_agent_review_any` — der eine Eintrittspunkt, der beide
        # Fassungen kennt. Ein Status ohne seinen Code ist eine halbe Auskunft, und eine Weiche, die
        # das v0.1-Urteil nachbessert, ist ein zweiter Verifizierer mit demselben Namen — beides
        # wird hier gegen dieselbe Eingabe gemessen, nicht angenommen.
        m = miss_versionsstatus(case, case_dir)
        want = exp["versionStatus"]
        if m["status"] != want:
            return _fail(cid, f"predicateVersionStatus {m['status']!r} != expected {want!r} "
                              f"(codes {m['codes']})")
        if want == "legacy":
            if "AGENT_REVIEW_LEGACY_V01" not in m["codes"]:
                return _fail(cid, "legacy without the AGENT_REVIEW_LEGACY_V01 reason code")
            if m["ok"] != m["ok_v01_direct"]:
                return _fail(cid, f"the dispatcher changed the v0.1 verdict: "
                                  f"ok {m['ok_v01_direct']} -> {m['ok']}")
        if want == "current" and "AGENT_REVIEW_LEGACY_V01" in m["codes"]:
            return _fail(cid, "a current receipt carries the legacy code")
        if want == "unknown" and (m["ok"] is not False
                                  or "AGENT_REVIEW_PREDICATE_TYPE_UNKNOWN" not in m["codes"]):
            return _fail(cid, f"an unknown version must be refused with "
                              f"AGENT_REVIEW_PREDICATE_TYPE_UNKNOWN, got ok={m['ok']} codes={m['codes']}")
        return {"caseId": cid, "ok": True,
                "detail": f"predicateVersionStatus {want}, codes {m['codes']}"}

    if "policyDecision" in exp:
        # A3, DIE POLICY. Der Fall NENNT, gegen welche Policy er gemessen wird (`params.policy`:
        # "default", "none" oder eine Datei im Fallverzeichnis). Eine Entscheidung ohne den Digest
        # der Policy, gegen die sie fiel, ist keine — und "nicht gefahren" muss als Code im Ergebnis
        # stehen, sonst sieht es aus wie "bestanden".
        m = miss_policy_entscheidung(case, case_dir)
        want = exp["policyDecision"]
        if m["decision"] != want:
            return _fail(cid, f"policy_decision {m['decision']!r} != expected {want!r} "
                              f"(codes {m['codes']})")
        if want is None:
            if "POLICY_NOT_EVALUATED" not in m["codes"]:
                return _fail(cid, "no policy, but POLICY_NOT_EVALUATED is missing from reason_codes")
        else:
            if not str(m["policy_digest"] or "").startswith("sha256:"):
                return _fail(cid, f"a decision without the digest of its policy: {m['policy_digest']!r}")
            if want == "accept" and m["ok"] is not True:
                return _fail(cid, f"accept, but ok={m['ok']} (errors {m['errors'][:2]})")
            if want in ("reject", "insufficient_evidence") and m["ok"] is not False:
                return _fail(cid, f"{want}, but ok={m['ok']} — a negative policy answer must not verify")
        return {"caseId": cid, "ok": True,
                "detail": f"policy_decision {want}, policy {m['policy_name']!r} {str(m['policy_digest'])[:23]}"}

    want = exp["classification"]
    got = klassifiziere_agent_review(case, case_dir)
    if got != want:
        return _fail(cid, f"classification {got!r} != expected {want!r}")
    return {"caseId": cid, "ok": True, "detail": f"classified {got}"}


def loese_kette(case: dict, case_dir: pathlib.Path):
    """WIE der Korpus eine Receipt-Kette aufloest — die EINE Messung, oeffentlich rufbar.

    Herausgehoben aus demselben Grund wie `klassifiziere_agent_review`: derselbe Ausfuehrer
    existiert noch einmal in `tests/test_agent_review_conformance_runner.py`, und zwei Fassungen
    derselben Entscheidung sind zwei Wahrheiten — die ungerufene altert still. Sie gibt die
    MESSUNG zurueck, nie ein Urteil: die Erwartung gehoert zum Pruefer.

    Jeder Umschlag wird HIER kryptografisch geprueft, statt eine Liste gepruefter Digests aus dem
    Fall zu uebernehmen. Das ist der Kern: `resolve_receipt_chain` ordnet nur nach dem, was der
    Aufrufer wirklich geprueft hat, und ein Fall, der sich diese Menge selbst ausdenkt, beruehrt
    die Abwehr des Uebernahmeangriffs nie.
    """
    from proofbundle import agent_review as ar  # noqa: PLC0415

    name = case.get("input") or "chain.json"
    if "/" in name or name.startswith("."):
        raise ValueError(f"input {name!r} escapes the case directory")
    umschlaege = json.loads((case_dir / name).read_text())["envelopes"]
    schluessel = bytes.fromhex((case_dir.parent / "publickey.hex").read_text().strip())
    geprueft = set()
    for env in umschlaege:
        try:
            if ar.verify_agent_review(env, schluessel).get("crypto_ok") is True:
                geprueft.add(ar.receipt_digest(env))
        except ar.AgentReviewError:
            continue
    return umschlaege, geprueft, ar.resolve_receipt_chain(umschlaege, verified=geprueft)


def klassifiziere_agent_review(case: dict, case_dir: pathlib.Path) -> str:
    """WIE der Korpus einen Praedikat-Fall einstuft — die EINE Weiche, oeffentlich rufbar.

    WARUM SIE HERAUSGEHOBEN IST (01.09.2026). Diese Entscheidung existierte ZWEIMAL: hier und
    noch einmal in `tests/test_agent_review_conformance_runner.py::_urteil`. Als die Strecke in
    derselben Runde auf den Erzeuger umgestellt wurde (N06/P0.5), wanderte nur DIESE Fassung
    mit. Der Positiv-Kontroll-Fall `emit-verify-roundtrip` traegt ein rohes Dokument, keinen
    Umschlag — der Test warf ihn in den Verifier und meldete "payload must be a base64 string".
    Richtige Meldung, falscher Pfad. Zwei Fassungen derselben Entscheidung sind zwei Wahrheiten,
    und die ungerufene altert still.

    Sie gibt die KLASSIFIKATION zurueck, nicht PASS/FAIL. Das ist der Unterschied, an dem ein
    erster Zusammenfuehrungs-Versuch scheiterte: `_check_...` vergleicht bereits mit der
    Erwartung des Falls, und wer das als Messwert nimmt, dreht bei `invalid`-Faellen das
    Vorzeichen um (acht rote Tests, gemessen). Die Erwartung gehoert zum Pruefer, nicht zur
    Messung.
    """
    from proofbundle import agent_review as ar  # noqa: PLC0415

    def _read(nm: str):
        if "/" in nm or nm.startswith("."):
            raise ValueError(f"input {nm!r} escapes the case directory")
        return json.loads((case_dir / nm).read_text())

    params = case.get("params") or {}
    name = case.get("input") or "envelope.json"
    doc = _read(name)

    # A body case: the digest helper itself is the subject under test.
    if name == "body.json":
        try:
            ar.body_core_digest(doc["body"])
            got = "valid"
        except ar.AgentReviewError:
            got = "refused"
    # A bare predicate: the emit path is the subject — can this even be produced?
    #
    # DER ECHTE EINTRITTSPUNKT, seit 01.09.2026 (Gegenlese Runde 2, N06 / P0.5.4). Bis hierher rief
    # dieser Zweig `require_valid_agent_review_predicate` — den VALIDATOR, nicht den Erzeuger. Die
    # Docstring dieser Funktion sagte gleichzeitig „checked through OUR OWN emit/verify path" und
    # „rejected at emit". Die Flaeche lehrte damit etwas, das die Mechanik nicht tat, und ein
    # Mutant, der nur den Emitter umgeht (Statement von Hand bauen, Validierung ueberspringen),
    # waere von dieser Strecke nie gefangen worden.
    #
    # `emit_agent_review` ist ein ECHTER Obermenge-Pfad: es validiert mit demselben Pruefer UND
    # signiert. Ein `refused` bleibt also ein `refused`, und ein `valid` heisst ab jetzt zusaetzlich
    # „liess sich wirklich erzeugen und danach verifizieren" statt nur „bestand die Validierung".
    #
    # DER SCHLUESSEL IST DER DES KORPUS-GENERATORS (`_generator/build_vectors.py`, bytes(range(32))),
    # und seine oeffentliche Haelfte liegt als publickey.hex daneben. Ein zweiter Schluessel waere
    # eine zweite Wahrheit ueber dieselbe Groesse; ein zufaelliger machte den Lauf undeterministisch.
    # Er ist ein TESTSCHLUESSEL und darf nie etwas signieren, das ein Leser als Beleg nimmt.
    elif name == "predicate.json":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
            Ed25519PrivateKey)
        _sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        # ERZEUGER UND PRUEFER TRAGEN DIESELBE FASSUNG, und sie steht ausdruecklich da.
        #
        # Seit 6.0.0 ist v0.2 die Vorgabe des Emitters. Der Verifizierer zwei Zeilen tiefer ist
        # `verify_agent_review`, also der v0.1-Pfad — ohne die Angabe hier waere das Paar
        # auseinandergelaufen und der Roundtrip haette `refused` gemeldet, obwohl weder der Fall
        # noch der Emitter defekt sind. Gemessen am 04.09.2026 an genau diesem Fall.
        #
        # DIESER KORPUS IST HEUTE v0.1. Kommen mit A5 die v0.2-Faelle dazu, muss die Wahl AUS DEM
        # FALL kommen und beide Zeilen zugleich umstellen — hier steht sie deshalb an EINER
        # Stelle, nicht zweimal.
        # DIE FASSUNG KOMMT AUS DEM FALL, nicht aus einem Vorgabewert (A5).
        #
        # Bis A5 stand hier fest `True`, mit dem Vermerk, dass die Wahl aus dem Fall kommen muss,
        # sobald v0.2-Faelle dazukommen. Jetzt kommen sie. Ein Fall OHNE Angabe bleibt v0.1 —
        # damit aendert sich fuer die siebzehn bestehenden Vektoren kein Byte, und ein neuer Fall
        # muss seine Fassung NENNEN statt sie zu erben.
        #
        # ERZEUGER UND PRUEFER TRAGEN DIESELBE FASSUNG. Das war schon vorher der Punkt; jetzt
        # haengen beide an derselben Variablen, und ein v0.2-Fall waehlt beide Seiten zugleich.
        _legacy = case.get("predicateVersion", "v0.1") != "v0.2"
        try:
            _env = ar.emit_agent_review(doc, _sk, legacy_v01=_legacy)
        except ar.AgentReviewError:
            got = "refused"
        else:
            # ROUNDTRIP: erzeugt UND wieder gelesen. Ein Emitter, dessen Ausgabe der eigene
            # Verifier nicht annimmt, ist kein bestandener Fall, auch wenn das Signieren gelang.
            # DIE STANDARD-POLICY GEHOERT ZUM v0.2-ROUNDTRIP (Folgefund aus A3).
            #
            # Seit A3 gibt es ohne benannte Policy kein `ok` — und dieser Laeufer verifizierte
            # ohne. Jeder v0.2-Fall wurde damit `invalid`, auch ein vollstaendig gueltiger:
            # gemessen 0 Validator-Fehler und trotzdem abgelehnt. Das ist kein Defekt von A3,
            # sondern ein Aufrufer, den der Vertragswechsel nicht erreicht hat.
            #
            # v0.1 bekommt KEINE Policy: sein Verifizierer kennt den Parameter nicht, und die
            # Altfassung soll sich nicht aendern.
            if _legacy:
                _r = ar.verify_agent_review(
                    _env, _sk.public_key().public_bytes_raw(),
                    expected_subject_digest=ar._subject_digest(doc))
            else:
                _r = ar.verify_agent_review_v02(
                    _env, _sk.public_key().public_bytes_raw(),
                    expected_subject_digest=ar._subject_digest(doc),
                    policy=ar.load_policy())
            got = "valid" if _r.get("ok") else "invalid"
    # A signed envelope: the verify path is the subject.
    else:
        key_hex = (case_dir.parent / "publickey.hex").read_text().strip()
        r = ar.verify_agent_review(doc, bytes.fromhex(key_hex),
                                   expected_subject_digest=params.get("expectedSubjectDigest"))
        got = "valid" if r.get("ok") else "invalid"

    return got


def _fall_datei(case_dir: pathlib.Path, name: str) -> pathlib.Path:
    """Eine Datei DES FALLS — nie eine ausserhalb. Dieselbe Regel wie `_read` in den Pruefern."""
    if "/" in name or name.startswith("."):
        raise ValueError(f"input {name!r} escapes the case directory")
    return case_dir / name


def miss_versionsstatus(case: dict, case_dir: pathlib.Path) -> dict:
    """WIE der Korpus die Weiche misst (A2) — die EINE Messung, oeffentlich rufbar.

    Gibt die MESSUNG zurueck, nie ein Urteil: Status, `ok`, Reason Codes, und fuer eine Altfassung
    zusaetzlich das `ok` des direkt gerufenen v0.1-Verifizierers, damit der Pruefer sehen kann, ob
    die Weiche das Urteil unveraendert durchreicht.
    """
    from proofbundle import agent_review as ar  # noqa: PLC0415

    params = case.get("params") or {}
    doc = json.loads(_fall_datei(case_dir, case.get("input") or "envelope.json").read_text())
    key = bytes.fromhex((case_dir.parent / "publickey.hex").read_text().strip())
    kw = {}
    if params.get("expectedSubjectDigest"):
        kw["expected_subject_digest"] = params["expectedSubjectDigest"]
    r = ar.verify_agent_review_any(doc, key, **kw)
    status = r.get("predicateVersionStatus")
    direkt = ar.verify_agent_review(doc, key, **kw) if status == "legacy" else None
    return {"status": status, "ok": r.get("ok"), "codes": list(r.get("reason_codes") or []),
            "ok_v01_direct": (direkt or {}).get("ok")}


def miss_policy_entscheidung(case: dict, case_dir: pathlib.Path) -> dict:
    """WIE der Korpus die Policy-Achse misst (A3) — die EINE Messung, oeffentlich rufbar.

    Der Fall traegt ein v0.2-Predicate; es wird mit dem Korpus-Schluessel WIRKLICH ausgestellt und
    danach mit `verify_agent_review_v02(policy=...)` gelesen. `params.policy` nennt die Policy:
    "default" (die benannte Standard-Policy), "none" (keine), oder eine Datei im Fallverzeichnis.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415
    from proofbundle import agent_review as ar  # noqa: PLC0415

    if case.get("predicateVersion") != "v0.2":
        raise ValueError("a policyDecision case is a v0.2 case and must say so (predicateVersion)")
    params = case.get("params") or {}
    doc = json.loads(_fall_datei(case_dir, case.get("input") or "predicate.json").read_text())
    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    env = ar.emit_agent_review(doc, sk)
    wahl = params.get("policy", "default")
    if wahl == "none":
        policy = None
    elif wahl == "default":
        policy = ar.load_policy()
    else:
        policy = ar.load_policy(_fall_datei(case_dir, str(wahl)))
    r = ar.verify_agent_review_v02(env, sk.public_key().public_bytes_raw(),
                                   expected_subject_digest=ar._subject_digest(doc), policy=policy)
    return {"decision": r.get("policy_decision"), "ok": r.get("ok"),
            "codes": list(r.get("reason_codes") or []), "policy_name": r.get("policy_name"),
            "policy_digest": r.get("policy_digest"), "errors": list(r.get("errors") or [])}


def _check_cap1_document(case: dict, case_dir: pathlib.Path, *,
                         require_anchors: bool = False) -> dict:
    """One CAP-1 vector (draft-hillier-coverage-attestation-00), checked through proofbundle.cap1.

    ONE AXIS, and it is a SET. `expected.cap1Rules` names exactly the rules that must fire; `[]`
    means conformant. The comparison is exact in both directions: a counter-proof that fires the
    wrong rule, or an extra one, fails — "refused" alone would let a checker pass that rejects for
    any reason at all (draft section 7.1). Fail-closed on the declaration: a case without the axis
    asserts nothing and is a corpus bug, not a pass.
    """
    cid = case.get("caseId", str(case_dir))
    exp = case.get("expected") or {}
    if "cap1Rules" not in exp or not isinstance(exp["cap1Rules"], list):
        return _fail(cid, "cap1_document case must declare the cap1Rules axis (a list; [] = conformant)")
    if len(exp) != 1:
        return _fail(cid, f"cap1_document case must declare EXACTLY ONE expectation axis, got {sorted(exp)}")
    name = case.get("input") or "document.json"
    if pathlib.Path(name).is_absolute() or ".." in pathlib.PurePosixPath(name).parts:
        return _fail(cid, f"input {name!r} escapes the case directory")
    sys.path.insert(0, str(ROOT.parent / "src"))
    from proofbundle import cap1  # noqa: PLC0415
    from proofbundle.errors import ProofBundleError  # noqa: PLC0415
    try:
        doc = cap1.load_cap1_document((case_dir / name).read_bytes())
    except (ProofBundleError, ValueError) as e:
        return _fail(cid, f"document does not parse strictly: {e}")
    gefeuert = sorted({f["rule"] for f in cap1.check_cap1_document(doc)})
    erwartet = sorted(set(exp["cap1Rules"]))
    if gefeuert != erwartet:
        return _fail(cid, f"rules fired {gefeuert} != expected {erwartet}")
    return {"caseId": cid, "ok": True,
            "detail": ("conformant, no rule fires" if not erwartet else f"refused by exactly {erwartet}")}


_DISPATCH = {"decision_crossimpl": _check_decision_crossimpl, "native_bundle": _check_native_bundle,
             "decision_relation": _check_decision_relation, "outcome_relation": _check_outcome_relation,
             "relation_statement": _check_relation_statement,
             "provenance_version_status": _check_provenance_version_status,
             "envelope_profile_rule": _check_envelope_profile_rule,
             "agent_review_predicate": _check_agent_review_predicate,
             "cap1_document": _check_cap1_document}


def run(*, require_anchors: bool = False) -> int:
    manifest = json.loads((ROOT / "manifest.json").read_text())
    cases = manifest.get("cases", [])
    # F1 corpus-integrity precondition (schema-valid + cross-format-consistent) before any case
    # executes: a malformed/under-declared or self-contradictory corpus is a whole-corpus FAIL,
    # not something a green per-case run should mask.
    cf_ok, cf_problems = cross_format.run()
    if not cf_ok:
        print(f"[conformance] corpus integrity FAIL ({len(cf_problems)} problem(s)):")
        for pr in cf_problems:
            print("  -", pr)
        return 1
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
