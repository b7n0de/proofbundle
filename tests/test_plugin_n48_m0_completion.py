"""Nachtrag 48, point 1, with the owner answers of Nachtrag 51 (O48-1): stage M0 completed.

Cowork's check of M0 against the decision of 2026-10-20 and the checklist of the same day found: M2 without the name
Guard Preview, M3 (enforcement at the receiver) and M4 (pilots outside the house) missing; the triage in four questions
missing in all three texts; the delivery receipt not an acceptance case of M1; checklist no. 10 without "which the host does
not trust"; the owner answers O45-1 to O45-3 not recorded as decided. The texts of the triage and of no. 10 are
those the owner handed over in Nachtrag 51, word for word.

RED at fd897f99, the head of PLUGIN_N51 (measured, 6 of 7): every case but the control.
"""
from __future__ import annotations

import pathlib
import re

M0 = pathlib.Path(__file__).resolve().parents[1] / "plugins" / "proofbundle" / "m0"
TEXTS = ("PRODUCT_SPEC.md", "IMPLEMENTATION_GAP.md", "TEST_PLAN.md")

#: The triage of the decision, word for word (Nachtrag 51, O48-1), as the quoted lines of PRODUCT_SPEC.md hold it.
TRIAGE = [
    "Jede Karte zu einem Fund am Plugin beantwortet vier Fragen.",
    "1. Trifft der Fund eine zugesagte Eigenschaft von Verify? Dann hält er die Freigabe von Verify an.",
    "2. Trifft er nur einen Guard-Pfad, der im Auslieferungsprofil nicht aktiv ist? Dann hält er die Reifeaussage des "
    "Guard an, nicht Verify.",
    "3. Wirkt er über gemeinsamen Kern oder Paketierung auf Verify? Dann reicht die Trennung nicht, und der ganze "
    "betroffene Stand wird geprüft.",
    "4. Eine unbekannte Folge heißt NICHT GEMESSEN, keine Entwarnung.",
]
CHECKLIST_10 = "Ein Guard, der aus ist, nicht läuft oder dem der Wirt nicht vertraut, als Schutz."


def _text(name: str) -> str:
    return (M0 / name).read_text(encoding="utf-8")


def _quoted(text: str) -> str:
    """The quoted lines of a text joined to one line each item: `> ` taken off, continuation lines joined."""
    lines = [line[1:].strip() for line in text.splitlines() if line.startswith(">")]
    items, current = [], ""
    for line in lines:
        if not line:
            if current:
                items.append(current)
            current = ""
        elif re.match(r"\d\. ", line) and current:
            items.append(current)
            current = line
        else:
            current = f"{current} {line}".strip()
    if current:
        items.append(current)
    return "\n".join(items)


def test_N48_the_triage_stands_word_for_word_in_the_spec():
    quoted = _quoted(_text("PRODUCT_SPEC.md")).splitlines()
    for line in TRIAGE:
        assert line in quoted, line


def test_N48_the_gap_and_the_test_plan_point_to_the_triage():
    for name in ("IMPLEMENTATION_GAP.md", "TEST_PLAN.md"):
        assert "triage" in _text(name).lower(), name


def test_N48_the_stages_carry_the_names_of_the_decision():
    spec = _text("PRODUCT_SPEC.md")
    section = spec.split("\n## Stages\n", 1)[1].split("\n## ", 1)[0]
    rows = {line.split("|")[1].strip(): line for line in section.splitlines() if line.startswith("| M")}
    assert sorted(rows) == ["M0", "M1", "M2", "M3", "M4"], sorted(rows)
    assert "Guard Preview" in rows["M2"]
    assert "Durchsetzung beim Empfänger" in rows["M3"]
    assert "Piloten außerhalb des Hauses" in rows["M4"]
    assert "REQUIRES APPROVAL" not in section


def test_N48_checklist_no_10_is_complete_in_the_non_claims_and_the_status():
    spec = _text("PRODUCT_SPEC.md")
    non_claims = spec.split("\n## Non-claims\n", 1)[1]
    assert "that the host does not trust" in non_claims and CHECKLIST_10 in non_claims
    inactive = next(line for line in spec.splitlines() if line.startswith("| INACTIVE |"))
    assert "not trusted by the host" in inactive


def test_N48_the_delivery_receipt_is_an_acceptance_case_of_m1_positive_and_negative():
    plan = _text("TEST_PLAN.md")
    row = next(line for line in plan.splitlines() if line.startswith("| TV-8 |"))
    assert "Positive and negative" in row and "receipt" in row
    for words in ("one byte of the archive changed", "the receipt of another delivery", "a wrong key",
                  "no receipt at all", "never passed"):
        assert words in row, words
    acceptance = plan.split("\n## Acceptance for M1\n", 1)[1]
    assert "TV-8" in acceptance


def test_N48_the_owner_answers_o45_1_to_o45_3_stand_as_decided():
    spec, plan, gap = _text("PRODUCT_SPEC.md"), _text("TEST_PLAN.md"), _text("IMPLEMENTATION_GAP.md")
    assert "0.4.0" in spec and "no 1.0 before M3" in spec.replace("version 1.0", "1.0")
    assert "O45-3" in spec and "off (INACTIVE) until M2" in spec
    assert "REQUIRES APPROVAL)" not in spec.split("\n## Two profiles\n", 1)[1].split("\n## ", 1)[0]
    matrix = plan.split("\n## Host matrix for M1 (decided, O45-2)\n", 1)[1]
    assert "Codex | Guard | BLOCKED until TG-5" in matrix and "only after a run with a real model" in matrix
    p2 = next(line for line in gap.splitlines() if line.startswith("| P-2 |"))
    assert "O45-3" in p2 and "REQUIRES APPROVAL" not in p2


def test_N48_control_the_three_texts_and_their_status_rule_stand():
    for name in TEXTS:
        assert (M0 / name).is_file()
    assert "NOT MEASURED" in _text("IMPLEMENTATION_GAP.md")
