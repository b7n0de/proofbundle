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


def _check_content_root_vector(case: dict, case_dir: pathlib.Path, *, require_anchors: bool = False) -> dict:
    """Phase 1 / R51: action-chain content-root vectors (`conformance/action_chain_content_roots/`).

    Language-neutral golden pins for the ONE statement content-root primitive (ADR 0002,
    `jcs-sha256-v1`): the pinned `.jcs` bytes must equal the canonical output, the pinned root must
    recompute on BOTH sides of the two-part rule (object/producer and exact-bytes/verifier), a
    cross-predicate reference must bind the referenced statement's root byte-for-byte, the declared
    algorithm binding must reject an algorithm-confusion payload and accept the NAMED legacy wire,
    and envelope signature blocks must never move the root. Four modes, each with a fail-closed
    required-expectations floor (an under-declared case FAILs, it never passes green by asserting
    nothing). Vectors are self-generated golden pins from this implementation at the pinned commit;
    independent recomputation by a second implementation is OPEN (recorded in the case attribution
    and the corpus README — a pin regression is caught, cross-implementation agreement is not yet
    proven)."""
    # The declared-algorithm binding gate lives in intoto (module-internal on purpose: it guards the
    # DSSE verify paths). The vector exercises it as data so a second implementation can map the same
    # payload/verdict pair onto its own binding check.
    from proofbundle.intoto import _content_root_binding  # noqa: PLC0415
    cid = case["caseId"]
    exp = case["expected"]
    mode = case.get("mode")

    def _confined(name: str) -> pathlib.Path | None:
        f = (case_dir / name).resolve()
        if not str(f).startswith(str(case_dir.resolve()) + "/") or not f.is_file():
            return None
        return f

    def _floor(keys: list[str]) -> list[str]:
        return [k for k in keys if k not in exp]

    if mode == "canonical":
        missing = _floor(["jcsFile", "contentRoot", "objectAndBytesAgree"])
        if missing:
            return _fail(cid, f"under-declared (fail-closed): missing {missing}")
        inp = _confined(case.get("input", "statement.json"))
        jcs_f = _confined(exp["jcsFile"])
        if inp is None or jcs_f is None:
            return _fail(cid, "statement/jcs fixture missing or escapes the case directory")
        statement = json.loads(inp.read_text(encoding="utf-8"))
        canon = canonicalize_statement(statement)
        jcs = jcs_f.read_bytes()
        if canon != jcs:
            return _fail(cid, "canonical output is not byte-identical to the pinned .jcs")
        root_obj = _content_root_hex(statement)
        root_bytes = statement_content_root(jcs).hex()
        if root_obj != exp["contentRoot"]:
            return _fail(cid, f"object-path root {root_obj} != pinned {exp['contentRoot']}")
        if root_bytes != exp["contentRoot"]:
            return _fail(cid, f"bytes-path root {root_bytes} != pinned {exp['contentRoot']}")
        if bool(exp["objectAndBytesAgree"]) is not (root_obj == root_bytes):
            return _fail(cid, "objectAndBytesAgree expectation does not match the measurement")
        return {"caseId": cid, "ok": True, "detail": f"root {root_obj[:12]}… on both sides of the two-part rule"}

    if mode == "pair_reference":
        missing = _floor(["decisionRoot", "evidenceRoot", "evidenceRefBindsRoot",
                          "decisionJcsFile", "evidenceJcsFile"])
        if missing:
            return _fail(cid, f"under-declared (fail-closed): missing {missing}")
        dec_f = _confined(case.get("input", "decision.json"))
        ev_f = _confined("evidence.json")
        dj = _confined(exp["decisionJcsFile"])
        ej = _confined(exp["evidenceJcsFile"])
        if None in (dec_f, ev_f, dj, ej):
            return _fail(cid, "pair fixtures missing or escape the case directory")
        dec = json.loads(dec_f.read_text(encoding="utf-8"))
        ev = json.loads(ev_f.read_text(encoding="utf-8"))
        if canonicalize_statement(dec) != dj.read_bytes() or canonicalize_statement(ev) != ej.read_bytes():
            return _fail(cid, "pinned .jcs bytes do not match canonical output")
        dec_root = _content_root_hex(dec)
        ev_root = _content_root_hex(ev)
        if dec_root != exp["decisionRoot"] or ev_root != exp["evidenceRoot"]:
            return _fail(cid, f"roots {dec_root[:12]}…/{ev_root[:12]}… != pinned")
        refs = dec.get("predicate", {}).get("evidenceRefs") or []
        bound = any(isinstance(r, dict) and r.get("digest", {}).get("sha256") == ev_root for r in refs)
        if bound is not bool(exp["evidenceRefBindsRoot"]):
            return _fail(cid, f"evidenceRef binding {bound} != expected {exp['evidenceRefBindsRoot']}")
        return {"caseId": cid, "ok": True, "detail": f"decision {dec_root[:12]}… binds evidence {ev_root[:12]}…"}

    if mode == "binding":
        missing = _floor(["bindingOk", "alg"])
        if missing:
            return _fail(cid, f"under-declared (fail-closed): missing {missing}")
        pay_f = _confined(case.get("input", "payload.bytes"))
        if pay_f is None:
            return _fail(cid, "payload fixture missing or escapes the case directory")
        payload = pay_f.read_bytes()
        statement = json.loads(payload.decode("utf-8"))
        ok, alg, detail = _content_root_binding(statement, payload)
        if ok is not bool(exp["bindingOk"]):
            return _fail(cid, f"binding ok={ok} != expected {exp['bindingOk']} ({detail})")
        if alg != exp["alg"]:
            return _fail(cid, f"declared alg {alg!r} != expected {exp['alg']!r}")
        return {"caseId": cid, "ok": True, "detail": f"binding {ok} under declared alg {alg}"}

    if mode == "envelope_invariance":
        missing = _floor(["contentRoot", "secondEnvelope"])
        if missing:
            return _fail(cid, f"under-declared (fail-closed): missing {missing}")
        import base64  # noqa: PLC0415
        env_a_f = _confined(case.get("input", "envelope_a.json"))
        env_b_f = _confined(exp["secondEnvelope"])
        if env_a_f is None or env_b_f is None:
            return _fail(cid, "envelope fixtures missing or escape the case directory")
        pay_a = base64.standard_b64decode(json.loads(env_a_f.read_text())["payload"])
        pay_b = base64.standard_b64decode(json.loads(env_b_f.read_text())["payload"])
        if pay_a != pay_b:
            return _fail(cid, "the two envelopes do not carry the same payload bytes")
        sig_a = json.loads(env_a_f.read_text()).get("signatures")
        sig_b = json.loads(env_b_f.read_text()).get("signatures")
        if sig_a == sig_b:
            return _fail(cid, "vector degenerate: both envelopes carry identical signature blocks")
        root = statement_content_root(pay_a).hex()
        if root != exp["contentRoot"]:
            return _fail(cid, f"root {root} != pinned {exp['contentRoot']}")
        return {"caseId": cid, "ok": True, "detail": f"root {root[:12]}… invariant across differing signature blocks"}

    return _fail(cid, f"unknown content_root_vector mode {mode!r} (fail-closed)")


_DISPATCH = {"decision_crossimpl": _check_decision_crossimpl, "native_bundle": _check_native_bundle,
             "decision_relation": _check_decision_relation, "outcome_relation": _check_outcome_relation,
             "relation_statement": _check_relation_statement,
             "content_root_vector": _check_content_root_vector}


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
