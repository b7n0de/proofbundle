"""Run every derived vector and write the run record (run_record.json, RUN_RECORD.md) and the
requirement table (REQUIREMENTS.md).

Usage: python tools/make_run_record.py --head <commit> [--draft <draft.txt>]

The head is the commit whose implementation and vectors were run. The draft path, when given, is
hashed and its digest recorded; the draft text itself is not stored.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "vectors")]

import acde01  # noqa: E402
import build  # noqa: E402
import evaluate  # noqa: E402

FILES = ["acde01/__init__.py", "acde01/canon.py", "acde01/profile.py", "acde01/reconcile.py",
         "acde01/report_check.py", "vectors/build.py", "vectors/evaluate.py", "vectors/vectorfile.py",
         "vectors/generate_vectors.py", "vectors/acde01_vectors.json", "requirements.json",
         "requirements_map.json", "tools/extract_requirements.py"]


def sha(path):
    with open(os.path.join(ROOT, path), "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--head", required=True)
    ap.add_argument("--draft")
    ap.add_argument("--also", action="append", default=[],
                    help="another interpreter run, recorded verbatim, e.g. '3.10.20: 146/146 vectors'")
    a = ap.parse_args(argv[1:])
    with open(os.path.join(ROOT, "vectors", "acde01_vectors.json"), encoding="ascii") as fh:
        vf = json.load(fh)
    with open(os.path.join(ROOT, "requirements.json"), encoding="ascii") as fh:
        reqs = json.load(fh)
    with open(os.path.join(ROOT, "requirements_map.json"), encoding="ascii") as fh:
        rmap = json.load(fh)["requirements"]
    results = {}
    cov = {}
    for raw in vf["vectors"]:
        v = evaluate.expand(raw, vf)
        ok, fails, _ = evaluate.evaluate(v)
        results[v["id"]] = {"passed": ok, "failures": fails, "type": v["type"],
                            "conformance_cases": v["conformance_cases"]}
        for r, pol in build.requirement_polarity(v):
            cov.setdefault(r, {"positive": [], "negative": []})[pol].append(v["id"])
    rows = []
    for r in reqs["requirements"]:
        m = rmap[r["id"]]
        c = cov.get(r["id"], {"positive": [], "negative": []})
        vids = c["positive"] + c["negative"]
        row = {"id": r["id"], "section": r["section"], "lines": r["lines"], "keywords": r["keywords"],
               "category": m["category"], "positive_vectors": c["positive"], "negative_vectors": c["negative"],
               "vectors_passed": all(results[x]["passed"] for x in vids) if vids else None}
        for k in ("finding", "readings", "implemented", "why", "text_refs", "reason", "note"):
            if k in m:
                row[k] = m[k]
        rows.append(row)
    counts = {k: sum(1 for x in rows if x["category"] == k) for k in ("agreement", "contradiction", "ambiguity",
                                                                      "not_implemented")}
    cases = {}
    for vid, res in results.items():
        for cn in res["conformance_cases"]:
            cases.setdefault(str(cn), []).append(vid)
    draft = None
    if a.draft:
        with open(a.draft, "rb") as fh:
            data = fh.read()
        draft = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                 "lines": data.count(b"\n"), "form": "txt"}
    record = {
        "record": "acde01 run record",
        "draft": acde01.DRAFT, "draft_sha256_pinned": acde01.DRAFT_SHA256, "draft_copy_used": draft,
        "head": a.head,
        "command": "python interop/acde_01/tools/make_run_record.py --head <head> --draft <draft.txt>; "
                   "python -m pytest interop/acde_01/tests",
        "environment": {"python": platform.python_version(), "implementation": platform.python_implementation(),
                        "platform": platform.platform(terse=True), "acde01": acde01.IMPLEMENTATION_VERSION,
                        "utc_time_of_run": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "other_interpreter_runs": a.also},
        "file_sha256": {f: sha(f) for f in FILES},
        "vectors": {"total": len(results), "passed": sum(1 for x in results.values() if x["passed"]),
                    "failed": sorted(k for k, x in results.items() if not x["passed"])},
        "conformance_cases_covered": {k: sorted(v) for k, v in sorted(cases.items(), key=lambda kv: int(kv[0]))},
        "category_counts": counts,
        "requirements": rows,
    }
    data = (json.dumps(record, indent=1, ensure_ascii=True) + "\n").encode("ascii")
    with open(os.path.join(ROOT, "run_record.json"), "wb") as fh:
        fh.write(data)
    digest = hashlib.sha256(data).hexdigest()
    md = [f"# Run record: {acde01.DRAFT}", "",
          "Generated by `tools/make_run_record.py`. The machine-readable record is `run_record.json`.", "",
          f"- head: `{a.head}`",
          f"- run_record.json sha256: `{digest}`",
          f"- draft copy: {('txt, ' + str(draft['lines']) + ' lines, sha256 `' + draft['sha256'] + '`') if draft else 'NOT GIVEN'}",
          f"- environment: Python {record['environment']['python']} ({record['environment']['implementation']}), "
          f"{record['environment']['platform']}",
          f"- time of run (UTC): {record['environment']['utc_time_of_run']}",
          f"- other interpreter runs: {'; '.join(a.also) if a.also else 'none'}",
          f"- vectors: {record['vectors']['total']} run, {record['vectors']['passed']} passed, "
          f"failed: {record['vectors']['failed'] or 'none'}",
          f"- requirements: {len(rows)}; agreement {counts['agreement']}, contradiction {counts['contradiction']}, "
          f"ambiguity {counts['ambiguity']}, not implemented {counts['not_implemented']}",
          f"- conformance cases with at least one vector: {len(cases)} of 30", "",
          "## Ambiguities", ""]
    for x in rows:
        if x["category"] == "ambiguity":
            md += [f"### {x['id']} (lines {x['lines'][0]}-{x['lines'][1]}): {x['finding']}", ""]
            md += [f"- text: {', '.join(x['text_refs'])}"]
            md += [f"- reading {r}" for r in x["readings"]]
            md += [f"- implemented: {x['implemented']}", f"- why it is open: {x['why']}",
                   f"- vectors: positive {', '.join(x['positive_vectors'])}; negative {', '.join(x['negative_vectors'])}", ""]
    md += ["## Not implemented", ""]
    for x in rows:
        if x["category"] == "not_implemented":
            md += [f"- {x['id']} (lines {x['lines'][0]}-{x['lines'][1]}): {x['reason']}"]
    md += ["", "## Contradictions", "",
           "None found: no two requirement sentences were found that cannot both hold." if counts["contradiction"] == 0
           else "", "", "## All requirements", "",
           "| id | lines | key words | category | positive vectors | negative vectors | passed |",
           "|---|---|---|---|---|---|---|"]
    for x in rows:
        md.append(f"| {x['id']} | {x['lines'][0]}-{x['lines'][1]} | {', '.join(x['keywords'])} | {x['category']} | "
                  f"{', '.join(x['positive_vectors']) or '-'} | {', '.join(x['negative_vectors']) or '-'} | "
                  f"{'-' if x['vectors_passed'] is None else ('yes' if x['vectors_passed'] else 'NO')} |")
    with open(os.path.join(ROOT, "RUN_RECORD.md"), "w", encoding="ascii") as fh:
        fh.write("\n".join(md) + "\n")
    # Requirement table
    t = [f"# Requirements of {acde01.DRAFT}", "",
         f"Every sentence of the draft that carries a BCP 14 key word in upper case, outside Section 1.2. "
         f"Line numbers refer to the plain-text copy with SHA-256 `{acde01.DRAFT_SHA256}` (2576 lines). "
         "Generated from `requirements.json` and `requirements_map.json`.", "",
         "| id | section | lines | key words | requirement (quoted) | category |", "|---|---|---|---|---|---|"]
    for r in reqs["requirements"]:
        q = r["text"].replace("|", "\\|")
        t.append(f"| {r['id']} | {r['section']} | {r['lines'][0]}-{r['lines'][1]} | {', '.join(r['keywords'])} | {q} | "
                 f"{rmap[r['id']]['category']} |")
    with open(os.path.join(ROOT, "REQUIREMENTS.md"), "w", encoding="ascii") as fh:
        fh.write("\n".join(t) + "\n")
    print(f"run_record.json sha256 {digest}; vectors {record['vectors']['passed']}/{record['vectors']['total']}; "
          f"categories {counts}")
    return 0 if not record["vectors"]["failed"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
