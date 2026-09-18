#!/usr/bin/env python3
"""Die fuenfzehn CAP-1-Vektoren des Entwurfsautors als Faelle des Konformitaetslaeufers.

Quelle: conformance/cap1/vectors/{manifest.json, PV-*.json, NC-*.json, _author_conformance_run.json}
(Certisyn-Inc/certisyn-drafts, Commit 0980d32, Apache-2.0 — LICENSE.author liegt daneben). Je Vektor
entsteht ein Fallordner conformance/cap1/<caseId>/ mit document.json (Byte-Kopie des Vektors) und
case.json; die Erwartung ist die EXAKTE Regelmenge aus dem aufgezeichneten Lauf des Autors —
einschliesslich der Doppelung bei NC-05 (R1 UND R5). Deterministisch: zweimal laufen ergibt dieselben
Bytes (ein Test haelt das). `CAP1_CASES_ROOT` lenkt die Ausgabe um, damit der Test in ein
Temp-Verzeichnis bauen und vergleichen kann; der Manifest-Eintrag entsteht nur am echten Ort.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys

HIER = pathlib.Path(__file__).resolve().parent
VEKTOREN = HIER.parent / "vectors"
ZIEL = pathlib.Path(os.environ.get("CAP1_CASES_ROOT") or HIER.parent)
CONFORMANCE = HIER.parent.parent
MANIFEST = CONFORMANCE / "manifest.json"

ATTRIBUTION = ("CAP-1 conformance vectors by the draft author (Certisyn-Inc/certisyn-drafts, commit 0980d32, "
               "Apache-2.0; conformance/cap1/vectors/LICENSE.author). Case wrapper built 2026-09-05 for "
               "proofbundle, Thema 7 Teil B Block 3.")
SPEC = ["draft-hillier-coverage-attestation-00, section 7 (conformance class)"]


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:60].rstrip("-")


def _dump(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def baue() -> list[str]:
    manifest = json.loads((VEKTOREN / "manifest.json").read_text(encoding="utf-8"))
    lauf = {r["id"]: r for r in json.loads(
        (VEKTOREN / "_author_conformance_run.json").read_text(encoding="utf-8"))["results"]}
    faelle: list[str] = []
    for eintrag in manifest:
        vid = eintrag["id"]
        positiv = eintrag["kind"] == "positive"
        regeln = sorted(lauf[vid].get("rules") or [])
        if positiv:
            assert not regeln, f"{vid}: positiv, aber der Autor-Lauf nennt Regeln {regeln}"
        else:
            assert regeln, f"{vid}: negativ, aber der Autor-Lauf nennt keine Regel"
        rolle = "positive_control" if positiv else "counter_proof"
        case_id = f"cap1-{'positive-control' if positiv else 'counter-proof'}-{vid.lower()}-{_slug(eintrag['why'])}"
        ordner = ZIEL / case_id
        ordner.mkdir(parents=True, exist_ok=True)
        (ordner / "document.json").write_bytes((VEKTOREN / f"{vid}.json").read_bytes())
        case = {
            "attribution": ATTRIBUTION,
            "caseId": case_id,
            "expected": {"cap1Rules": regeln},
            "input": "document.json",
            "kind": "cap1_document",
            "rationale": (f"{vid}: {eintrag['why']}. "
                          + ("Conformant: no rule fires." if positiv else
                             f"Non-conformant: the author's run records exactly {regeln} firing; the case "
                             f"pins that set, not merely 'refused' — a counter-proof that fails for the "
                             f"wrong reason proves nothing about its rule (draft section 7.1).")),
            "role": rolle,
            "rule": eintrag.get("rule") or "PV",
            "specRefs": SPEC,
        }
        (ordner / "case.json").write_text(_dump(case), encoding="utf-8")
        faelle.append(case_id)
    return faelle


def manifest_nachziehen(faelle: list[str]) -> None:
    m = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rest = [c for c in m["cases"] if not c.startswith("cap1/")]
    m["cases"] = rest + [f"cap1/{c}" for c in faelle]
    MANIFEST.write_text(json.dumps(m, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    f = baue()
    if ZIEL == HIER.parent:
        manifest_nachziehen(f)
    print(f"{len(f)} Faelle geschrieben nach {ZIEL}", file=sys.stderr)
