#!/usr/bin/env python3
"""Fundament F5 — validate the external-audit readiness pack against reality.

The pack (``docs/readiness_pack/``) is reviewer-oriented (conclusion -> ordered evidence). This gate
keeps it HONEST: it must not claim evidence that does not exist, and every release slot must be an
honest ``filled`` / ``reserved``. It also enforces the front-load contract — the required navigation
docs (tamper-resistance, open-questions, progress) exist and are wired into ``index.json``.

Checks (effect-based, No-Fake):
  1. index.json parses and declares the v1 schema.
  2. Every navigation doc referenced (README/tamper_resistance/OPEN_QUESTIONS/PROGRESS) exists.
  3. Every conclusion has a non-empty ordered evidence list, and every evidence ref resolves to a
     real file or directory in the repo (a claimed-but-absent artifact is a FAIL — the exact drift
     this gate is for).
  4. Every open_questions id a conclusion references is actually defined in OPEN_QUESTIONS.md.
  5. Every release slot has status in {filled, reserved}; a filled slot lists what it delivers, a
     reserved slot lists expected_evidence.

Exit 0 iff the pack is internally consistent and grounded in real artifacts.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACK = REPO / "docs" / "readiness_pack"
INDEX = PACK / "index.json"
NAV_DOCS = ["README.md", "tamper_resistance.md", "OPEN_QUESTIONS.md", "PROGRESS.md"]


def evaluate() -> dict:
    problems: list[str] = []
    if not INDEX.is_file():
        return {"ok": False, "problems": [f"missing {INDEX.relative_to(REPO)}"]}
    index = json.loads(INDEX.read_text())

    if index.get("schema") != "proofbundle.readiness_pack.index.v1":
        problems.append(f"index schema {index.get('schema')!r} != proofbundle.readiness_pack.index.v1")

    for doc in NAV_DOCS:
        if not (PACK / doc).is_file():
            problems.append(f"missing navigation doc docs/readiness_pack/{doc}")

    # the open-question ids actually defined in OPEN_QUESTIONS.md (for the cross-reference check)
    oq_text = (PACK / "OPEN_QUESTIONS.md").read_text() if (PACK / "OPEN_QUESTIONS.md").is_file() else ""
    defined_oq = set(re.findall(r"\bQ\d+_[A-Z0-9_]+\b", oq_text))

    conclusions = index.get("conclusions", [])
    if not conclusions:
        problems.append("index declares no conclusions")
    seen_ids: set[str] = set()
    for c in conclusions:
        cid = c.get("id", "<no id>")
        if cid in seen_ids:
            problems.append(f"duplicate conclusion id {cid}")
        seen_ids.add(cid)
        if not c.get("statement"):
            problems.append(f"conclusion {cid} has no statement")
        evidence = c.get("evidence_ordered", [])
        if not evidence:
            problems.append(f"conclusion {cid} has no ordered evidence")
        for ev in evidence:
            ref = ev.get("ref")
            if not ref:
                problems.append(f"conclusion {cid} has an evidence entry with no ref")
                continue
            if not (REPO / ref).exists():
                problems.append(f"conclusion {cid}: evidence ref {ref!r} does not exist in the repo")
        for q in c.get("open_questions", []):
            if q not in defined_oq:
                problems.append(f"conclusion {cid}: open question {q!r} not defined in OPEN_QUESTIONS.md")

    slots = index.get("release_evidence_slots", {})
    if not slots:
        problems.append("index declares no release_evidence_slots (front-load contract)")
    for name, slot in slots.items():
        status = slot.get("status")
        if status not in {"filled", "reserved"}:
            problems.append(f"release slot {name}: status {status!r} not in {{filled, reserved}}")
        elif status == "filled" and not slot.get("delivers"):
            problems.append(f"release slot {name}: filled but lists nothing under 'delivers'")
        elif status == "reserved" and not slot.get("expected_evidence"):
            problems.append(f"release slot {name}: reserved but lists no 'expected_evidence'")

    # navigation block must point at the real docs
    nav = index.get("navigation", {})
    for key, doc in nav.items():
        if not (PACK / doc).is_file():
            problems.append(f"navigation.{key} -> {doc} does not exist")

    return {
        "ok": not problems,
        "conclusions": len(conclusions),
        "release_slots": len(slots),
        "problems": problems,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="proofbundle readiness-pack integrity gate (F5)")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    result = evaluate()
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"[readiness-pack] {result.get('conclusions', 0)} conclusion(s), "
              f"{result.get('release_slots', 0)} slot(s): {'OK' if result['ok'] else 'PROBLEMS'}")
        for pr in result["problems"]:
            print("  -", pr)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
