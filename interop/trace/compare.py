"""Compare proofbundle's TRACE verifier with the TRACE reference, case by case, and write the table.

WHAT RUNS. Three corpora: every record vector of agentrust-io/trace-tests, the Trust Record
verification vectors of agentrust-io/trace-spec (signature-encoding, number-spelling,
canonicalization-boundary, verifier-compatibility), and the counter-cases of ``counter_cases.py``.
Each case runs through ``proofbundle.adapters.trace_record`` in this process and through
``agentrust_trace.verify_record`` in a SEPARATE interpreter (``reference_driver.py``), so this process
never imports the reference.

WHAT IS NOT COPIED. The trace-tests and trace-spec vectors are Apache-2.0 and Community Specification
material of other projects. They are read from checkouts at the commits pinned in ``pins.json``, and
every file is checked against its pinned SHA-256 before it is used; nothing of them is written into
this repository. The output directory, which does carry their exact bytes for every divergence, is
chosen by the caller and must lie outside the repository.

DIVERGENCES ARE REPORTED, NOT RECONCILED. A row where the two verifiers disagree, or where either
disagrees with the expectation, carries the exact input bytes (base64 and SHA-256).

Usage:
  python interop/trace/compare.py --trace-tests DIR --trace-spec DIR --reference-python PY --out DIR
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))

import counter_cases  # noqa: E402

from proofbundle.adapters.trace_record import exit_code, verify_trace_record  # noqa: E402

HARNESS_KEY = counter_cases.ed_jwk()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_head(path: Path) -> str:
    return subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True,
                          check=True).stdout.strip()


def verify_sources(pins: Dict[str, Any], trace_tests: Path, trace_spec: Path) -> None:
    for name, path in (("trace-tests", trace_tests), ("trace-spec", trace_spec)):
        want = pins["sources"][name]["commit"]
        have = git_head(path)
        if have != want:
            raise SystemExit(f"{name} at {path} is at {have}, the pin is {want}")
    for key, digest in pins["vectors"].items():
        repo, rel = key.split(":", 1)
        path = (trace_tests if repo == "trace-tests" else trace_spec) / rel
        if sha256(path.read_bytes()) != digest:
            raise SystemExit(f"{key}: SHA-256 differs from the pin")


def member_span(text: str, name: str) -> Optional[str]:
    """The exact source text of a top-level member's value, so a record inside a wrapper keeps its
    spelling (number forms, escapes, member order) instead of being re-serialised."""
    dec = json.JSONDecoder()
    i = text.index("{") + 1
    n = len(text)
    while i < n:
        while text[i] in " \t\r\n,":
            i += 1
        if text[i] == "}":
            return None
        key, i = dec.raw_decode(text, i)
        while text[i] in " \t\r\n:":
            i += 1
        start = i
        _, i = dec.raw_decode(text, i)
        if key == name:
            return text[start:i]
    return None


def plain_key(jwk: Any) -> Optional[Dict[str, Any]]:
    """The record's cnf.jwk when it is a usable Ed25519 key, else None."""
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        return None
    try:
        raw = base64.urlsafe_b64decode(jwk.get("x", "") + "==")
    except Exception:
        return None
    return {"kty": "OKP", "crv": "Ed25519", "x": jwk["x"]} if len(raw) == 32 else None


def vector_case(cid: str, corpus: str, raw: bytes, record: Any, *, expected: str, basis: str, section: str,
                description: str, own_axis: str, jwk: Any = None, now: Any = None,
                accepted_profiles: Any = None) -> Dict[str, Any]:
    cnf = record.get("cnf", {}).get("jwk") if isinstance(record, dict) and isinstance(record.get("cnf"), dict) else None
    key = jwk or plain_key(cnf) or HARNESS_KEY
    iat = record.get("iat") if isinstance(record, dict) else None
    if now is None:
        now = int(iat) if isinstance(iat, (int, float)) and not isinstance(iat, bool) and abs(iat) < 2**53 else counter_cases.NOW
    return {"id": cid, "corpus": corpus, "form": "embedded", "section": section, "description": description,
            "expected": expected, "basis": basis, "own_axis": own_axis, "raw": raw, "jwk": key, "now": int(now),
            "max_age_seconds": 86400, "max_future_skew_seconds": 300, "expected_nonce": None,
            "expected_policy_hashes": None, "expected_subjects": None, "expected_transcript_hash": None,
            "accepted_profiles": accepted_profiles, "pb_keys": None, "reference_input_gap": None,
            "key_source": "vector trusted_key" if jwk else ("record cnf.jwk" if plain_key(cnf) else "harness key")}


SIGNED_NONE = "reject"
NO_BINDING = "3.2.2: a record with no verifiable signature binding MUST be rejected"


def trace_tests_cases(root: Path) -> List[Dict[str, Any]]:
    out = []
    vec = root / "tests" / "vectors"
    for path in sorted(vec.glob("*.json")):
        raw = path.read_bytes()
        rec = json.loads(raw)
        name = path.stem
        if "cmcp_version" in rec:
            expected, basis = ("n/a", "cMCP RuntimeClaim envelope (3.2.2 names it): implemented by neither verifier")
            if name.startswith("invalid_canonical"):
                expected, basis = "reject", "3.2.2: the claim has no RFC 8785 form"
            own = "valid" if name.startswith("valid") else "invalid (trace-tests test_canonicalization_refusals)"
        elif "signature" in rec:
            if name == "invalid_canonical_plain_trace":
                expected, basis = "reject", "3.2.2: integer outside the safe range"
            else:
                expected, basis = "accept", "signed by its cnf key, judged at now = iat"
            own = "valid" if name.startswith(("signed", "valid")) else "invalid"
        else:
            expected, basis = "reject", NO_BINDING
            own = "valid at its level (unsigned)" if name.startswith("valid") else "invalid"
        out.append(vector_case(f"TT-{name}", "trace-tests", raw, rec, expected=expected, basis=basis,
                               section="3.2.2", description=f"tests/vectors/{path.name}", own_axis=own))
    for path in sorted((vec / "canonicalization").glob("*.json")):
        text = path.read_text(encoding="utf-8")
        doc = json.loads(text)
        raw = member_span(text, "record").encode("utf-8")
        out.append(vector_case(f"TT-canon-{path.stem}", "trace-tests", raw, doc["record"], expected="accept",
                               basis="3.2.2: RFC 8785 form, signed by its cnf key", section="3.2.2",
                               description=f"tests/vectors/canonicalization/{path.name}",
                               own_axis=f"expected_tr_sig {doc['expected_tr_sig']}"))
    for path in sorted((vec / "policy-resolution").glob("[0-9]*.json")):
        text = path.read_text(encoding="utf-8")
        doc = json.loads(text)
        raw = member_span(text, "record").encode("utf-8")
        out.append(vector_case(f"TT-polres-{path.stem}", "trace-tests", raw, doc["record"], expected=SIGNED_NONE,
                               basis=NO_BINDING, section="3.2.2",
                               description=f"tests/vectors/policy-resolution/{path.name}",
                               own_axis=f"TR-POL-003 {doc['expected']['tr_pol_003']}"))
    return out


def trace_spec_cases(root: Path) -> List[Dict[str, Any]]:
    out = []
    for folder in ("signature-encoding", "number-spelling", "canonicalization-boundary", "verifier-compatibility"):
        for path in sorted((root / "examples" / folder).glob("*.json")):
            text = path.read_text(encoding="utf-8")
            doc = json.loads(text)
            raw = member_span(text, "record").encode("utf-8")
            outcome = doc["expected"]["outcome"]
            expected = "accept" if outcome == "verified" else "reject"
            verifier = doc.get("verifier") or {}
            now = verifier.get("verification_time")
            if verifier.get("check_freshness") is False:
                iat = doc["record"].get("iat") if isinstance(doc["record"], dict) else None
                now = iat if isinstance(iat, int) else now
            out.append(vector_case(
                f"TS-{folder}-{path.stem}", "trace-spec", raw, doc["record"], expected=expected,
                basis=f"vector: {outcome}" + (f" ({doc['expected'].get('failure')})"
                                             if doc["expected"].get("failure") else ""),
                section=str(doc.get("spec", "3.2.2/3.3"))[:80], description=f"examples/{folder}/{path.name}",
                own_axis=json.dumps(doc["expected"])[:120], jwk=doc.get("trusted_key"), now=now,
                accepted_profiles=verifier.get("accepted_profiles")))
    return out


def run_proofbundle(case: Dict[str, Any]) -> Dict[str, Any]:
    verdict = verify_trace_record(
        case["raw"], trusted_keys=case["pb_keys"] or [case["jwk"]], now=case["now"],
        max_age_seconds=case["max_age_seconds"], max_future_skew_seconds=case["max_future_skew_seconds"],
        expected_nonce=case["expected_nonce"], expected_policy_hashes=case["expected_policy_hashes"],
        expected_subjects=case["expected_subjects"], expected_transcript_hash=case["expected_transcript_hash"],
        accepted_profiles=case["accepted_profiles"])
    code = exit_code(verdict)
    return {"verdict": "accept" if code == 0 else "reject", "exit_code": code,
            "failed_checks": [f"{c.name}: {c.detail}" for c in verdict.result.checks if c.ok is not True],
            "unknown_fields": [p for p, _ in verdict.unknown_fields]}


def run_reference(cases: List[Dict[str, Any]], python: str) -> Dict[str, Dict[str, Any]]:
    lines = []
    for c in cases:
        if c.get("reference"):
            continue
        lines.append(json.dumps({"id": c["id"], "raw_b64": base64.b64encode(c["raw"]).decode(), "jwk": c["jwk"],
                                 "now": c["now"], "max_age_seconds": c["max_age_seconds"],
                                 "max_future_skew_seconds": c["max_future_skew_seconds"],
                                 "expected_nonce": c["expected_nonce"],
                                 "accepted_profiles": c["accepted_profiles"]}))
    proc = subprocess.run([python, "-I", str(HERE / "reference_driver.py")], input="\n".join(lines) + "\n",
                          capture_output=True, text=True, check=True)
    results = {}
    for line in proc.stdout.splitlines():
        row = json.loads(line)
        results[row["id"]] = row
    return results


def agreement(a: str, b: str) -> str:
    if "n/a" in (a, b):
        return "n/a"
    return "same" if a == b else "DIFFERENT"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--trace-tests", required=True, type=Path)
    ap.add_argument("--trace-spec", required=True, type=Path)
    ap.add_argument("--reference-python", required=True)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args(argv)
    out_dir = args.out.resolve()
    if REPO in out_dir.parents or out_dir == REPO:
        raise SystemExit("--out must lie outside the repository: the output carries third-party vector bytes")
    pins = json.loads((HERE / "pins.json").read_text(encoding="utf-8"))
    verify_sources(pins, args.trace_tests, args.trace_spec)
    cases = trace_tests_cases(args.trace_tests) + trace_spec_cases(args.trace_spec) + counter_cases.build()
    reference = run_reference(cases, args.reference_python)
    ref_version = reference.pop("__reference__", {}).get("version")
    rows = []
    for c in cases:
        pb = run_proofbundle(c)
        if c.get("reference"):
            ref = {"verdict": "n/a", "exception": None, "detail": c["reference"]}
        else:
            ref = reference[c["id"]]
        row = {k: c[k] for k in ("id", "corpus", "form", "section", "description", "expected", "basis",
                                 "now", "expected_nonce", "expected_policy_hashes", "expected_subjects",
                                 "expected_transcript_hash", "accepted_profiles", "reference_input_gap")}
        row.update({"own_axis": c.get("own_axis"), "key_source": c.get("key_source", "counter-case key"),
                    "trusted_key": c["jwk"], "reference": ref, "proofbundle": pb,
                    "reference_vs_proofbundle": agreement(ref["verdict"], pb["verdict"]),
                    "reference_vs_expected": agreement(ref["verdict"], c["expected"]),
                    "proofbundle_vs_expected": agreement(pb["verdict"], c["expected"]),
                    "input_sha256": sha256(c["raw"]), "input_bytes": len(c["raw"])})
        if "DIFFERENT" in (row["reference_vs_proofbundle"], row["reference_vs_expected"],
                           row["proofbundle_vs_expected"]):
            row["input_b64"] = base64.b64encode(c["raw"]).decode("ascii")
        rows.append(row)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {"cases": len(rows), "by_corpus": {}, "reference_version": ref_version,
               "pins": {k: v.get("commit") or v.get("version") for k, v in pins["sources"].items()}}
    for corpus in ("trace-tests", "trace-spec", "counter-case"):
        sel = [r for r in rows if r["corpus"] == corpus]
        summary["by_corpus"][corpus] = {
            "cases": len(sel),
            "reference_vs_proofbundle": {k: sum(1 for r in sel if r["reference_vs_proofbundle"] == k)
                                         for k in ("same", "DIFFERENT", "n/a")},
            "reference_vs_expected": {k: sum(1 for r in sel if r["reference_vs_expected"] == k)
                                      for k in ("same", "DIFFERENT", "n/a")},
            "proofbundle_vs_expected": {k: sum(1 for r in sel if r["proofbundle_vs_expected"] == k)
                                        for k in ("same", "DIFFERENT", "n/a")}}
    (out_dir / "comparison.json").write_text(json.dumps({"summary": summary, "rows": rows}, indent=1,
                                                        ensure_ascii=False) + "\n", encoding="utf-8")
    (out_dir / "comparison.md").write_text(render_markdown(summary, rows), encoding="utf-8")
    print(json.dumps(summary, indent=1))
    return 0


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(summary: Dict[str, Any], rows: List[Dict[str, Any]]) -> str:
    lines = ["# TRACE comparison: proofbundle verify-trace against agentrust-trace " + str(summary["reference_version"]),
             "",
             "Generated by `interop/trace/compare.py`. Expectation is the full-verification verdict the cited text "
             "requires; `n/a` where no normative text decides. A divergence is reported, not reconciled; its exact "
             "input bytes are in the appendix and in `comparison.json`.",
             "", "## Summary", "", "```json", json.dumps(summary, indent=1), "```", "",
             "## Cases", "",
             "| Case | Section | Expectation | Reference | proofbundle | Ref = PB | Ref = Exp | PB = Exp |",
             "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        ref = r["reference"]
        ref_cell = ref["verdict"] + (f" ({ref['exception']})" if ref.get("exception") else "")
        pb = r["proofbundle"]
        pb_cell = f"{pb['verdict']} (exit {pb['exit_code']})"
        lines.append(f"| {_cell(r['id'])} | {_cell(r['section'])} | {r['expected']} | {_cell(ref_cell)} | "
                     f"{pb_cell} | {r['reference_vs_proofbundle']} | {r['reference_vs_expected']} | "
                     f"{r['proofbundle_vs_expected']} |")
    lines += ["", "## Divergences with exact bytes", ""]
    for r in rows:
        if "input_b64" not in r:
            continue
        lines += [f"### {r['id']}", "",
                  f"- Description: {_cell(r['description'])}",
                  f"- Expectation: {r['expected']} ({_cell(r['basis'])})",
                  f"- Reference: {_cell(r['reference'])}",
                  f"- proofbundle: exit {r['proofbundle']['exit_code']}; failed: "
                  f"{_cell('; '.join(r['proofbundle']['failed_checks']) or 'none')}",
                  f"- Relying-party input: key {_cell(json.dumps(r['trusted_key']))}, now {r['now']}"
                  + (f", nonce {r['expected_nonce']!r}" if r["expected_nonce"] else "")
                  + (f", policy hashes {r['expected_policy_hashes']}" if r["expected_policy_hashes"] else "")
                  + (f", subjects {r['expected_subjects']}" if r["expected_subjects"] else "")
                  + (f", transcript hash {r['expected_transcript_hash']}" if r["expected_transcript_hash"] else "")
                  + (f", accepted profiles {r['accepted_profiles']}" if r["accepted_profiles"] is not None else ""),
                  ] + ([f"- Reference input gap: {r['reference_input_gap']}"] if r["reference_input_gap"] else []) + [
                  f"- Input SHA-256: `{r['input_sha256']}` ({r['input_bytes']} bytes)",
                  "", "```", r["input_b64"], "```", ""]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
