#!/usr/bin/env python3
"""Builds the result table of the two-services lab from the run records (result.json) only.
Usage: python -I -B summarize.py <measurement folder>  -> writes <measurement folder>/result_table.md and prints it."""
import json
import sys
from pathlib import Path

M = Path(sys.argv[1])
statements = json.loads((M / "statements" / "statements.json").read_text(encoding="utf-8"))["statements"]
runs = {
    "ledger": [M / "ledger" / "result" / "result.json"],
    "scittles as built": sorted((M / "scittles" / "fresh").glob("*/result.json")),
    "scittles cbor2 5.9.0, fresh database each": sorted((M / "scittles_cbor2_5" / "fresh").glob("*/result.json")),
    "scittles cbor2 5.9.0, one database": [M / "scittles_cbor2_5" / "one_database" / "result.json"],
}
NAMES = {"unprotected_hex": "unprotected header", "tag18": "tag", "sha256_protected": "protected header",
         "sha256_payload": "payload", "sha256_signature": "signature"}


def cell(e):
    r = e["registration"]
    if r["status"] not in (200, 201):
        return "refused (%d): %s" % (r["status"], r["error"] or "")
    if "statement_returned" not in e:
        return "registered, statement not returned"
    kind = "bytes unchanged" if e.get("bytes_equal") else "changed: " + ", ".join(NAMES[d] for d in e["differences"])
    return "registered; %s; reference %s" % (kind, "equal" if e["reference_equal"] else "DIFFERENT")


table = {}
lookups = {}
for run, files in runs.items():
    for f in files:
        res = json.loads(f.read_text(encoding="utf-8"))
        for name, e in res["statements"].items():
            table.setdefault(name, {})[run] = cell(e)
            if e["registration"]["status"] not in (200, 201):
                continue  # looked up only for what the service registered
            for way, s in e.get("lookup", {}).items():
                key = (run, way.split(" ", 1)[1], way.split(" ", 1)[0])
                lookups.setdefault(key, {"found": 0, "not": 0, "status": set()})
                lookups[key]["found" if s["found"] else "not"] += 1
                lookups[key]["status"].add(s["status"])

out = ["| statement | " + " | ".join(runs) + " |", "|---|" + "---|" * len(runs)]
for name, s in statements.items():
    label = "%s (%s)" % (name, ", ".join(s["cases"])) if s["set"] == "R" else "%s (from %s, alg %s)" % (
        name, s["base_statement"], s["alg"])
    out.append("| " + label + " | " + " | ".join(table.get(name, {}).get(r, "not run") for r in runs) + " |")
out += ["", "Lookups for the statements each service registered:", "",
        "| service | path | looked up by | found | not found | status |", "|---|---|---|---|---|---|"]
for (run, way, kind), v in sorted(lookups.items()):
    out.append("| %s | %s | %s | %d | %d | %s |" % (
        run, way, {"reference_tbs": "-03 reference", "sha256_whole": "SHA-256 of the submitted bytes"}[kind],
        v["found"], v["not"], ", ".join(map(str, sorted(v["status"])))))
text = "\n".join(out) + "\n"
(M / "result_table.md").write_text(text, encoding="utf-8")
print(text)
