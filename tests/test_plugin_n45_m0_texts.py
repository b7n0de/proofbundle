"""Follow-up note 45, points 4 and 5: the written stage M0 of the plugin (plugins/proofbundle/m0/).

Owner decision of 2026-10-20: Verify and Guard in one plugin, released separately, two profiles, stages M0 to M4. M0 is
three texts: PRODUCT_SPEC.md, IMPLEMENTATION_GAP.md and TEST_PLAN.md. Every property carries exactly one status of six
(VERIFIED, FAILED, NOT MEASURED, BLOCKED, REQUIRES APPROVAL, INACTIVE), a VERIFIED or FAILED row names its measurement,
and no text says what the plugin cannot back (the non-claims of PRODUCT_SPEC.md). The phrases checked here are those a
text can carry by accident; the list in PRODUCT_SPEC.md is the rule, and a person reads every text against it.

RED at a309b185 (before the texts): 8 of 9, every case that reads m0/, which does not exist there; the case on the
manifests and the skills reads no file of m0/ and is green there as at the head.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "proofbundle"
M0 = PLUGIN / "m0"
TEXTS = ("PRODUCT_SPEC.md", "IMPLEMENTATION_GAP.md", "TEST_PLAN.md")
STATUSES = ("VERIFIED", "FAILED", "NOT MEASURED", "BLOCKED", "REQUIRES APPROVAL", "INACTIVE")
#: Phrases no text of the plugin may carry as a claim (PRODUCT_SPEC.md, Non-claims), matched without case.
CLAIMS = (r"tamper[- ]?proof", r"manipulationssicher", r"agent secured", r"prevents? every unauthori[sz]ed push",
          r"all mcp write actions are controlled", r"fully verified", r"completely checked", r"guaranteed")


def _rows(text: str) -> list[list[str]]:
    rows = []
    for line in text.splitlines():
        if line.startswith("|") and not re.fullmatch(r"\|(\s*-+\s*\|)+", line.strip()):
            rows.append([cell.strip() for cell in line.strip().strip("|").split("|")])
    return rows


def _outside_non_claims(text: str) -> str:
    head, _, rest = text.partition("\n## Non-claims\n")
    tail = rest.split("\n## ", 1)[1] if "\n## " in rest else ""
    return head + tail


def test_M0_the_three_texts_stand_in_the_plugin():
    assert sorted(p.name for p in M0.iterdir()) == sorted(TEXTS)


def test_M0_every_row_of_the_gap_carries_one_of_the_six_statuses():
    rows = [r for r in _rows((M0 / "IMPLEMENTATION_GAP.md").read_text(encoding="utf-8")) if r[0] != "ID"]
    assert len(rows) >= 30
    for row in rows:
        assert len(row) == 6, row
        assert any(row[3].startswith(s) for s in STATUSES), row


def test_M0_a_verified_or_failed_row_names_its_measurement():
    for row in _rows((M0 / "IMPLEMENTATION_GAP.md").read_text(encoding="utf-8")):
        if row[0] != "ID" and row[3].startswith(("VERIFIED", "FAILED")):
            assert row[5] not in ("", "n/a") and row[4] not in ("", "n/a"), row


def test_M0_the_status_table_of_the_spec_names_exactly_the_six():
    spec = (M0 / "PRODUCT_SPEC.md").read_text(encoding="utf-8")
    section = spec.split("\n## Status of a property\n", 1)[1].split("\n## ", 1)[0]
    assert [r[0] for r in _rows(section) if r[0] != "Status"] == list(STATUSES)


def test_M0_the_spec_lists_the_non_claims_of_the_order():
    spec = (M0 / "PRODUCT_SPEC.md").read_text(encoding="utf-8")
    section = spec.split("\n## Non-claims\n", 1)[1]
    for words in ("fulfil its task", "every unauthorized push is prevented", "all MCP write actions are controlled",
                  "tamper-proof", "valid receipt means a task is done", "`safe_for_automation: true` is an approval",
                  "synthetic only", "no protection at the receiving side is measured", "agent secured",
                  "Guard that is off, observing only, or not running"):
        assert words in section, words


@pytest.mark.parametrize("name", TEXTS)
def test_M0_no_text_carries_a_non_claim_outside_the_list(name):
    text = _outside_non_claims((M0 / name).read_text(encoding="utf-8"))
    found = [c for c in CLAIMS if re.search(c, text, re.I)]
    assert found == [], (name, found)


def test_M0_no_manifest_or_skill_description_carries_a_non_claim():
    texts = [json.loads((PLUGIN / folder / "plugin.json").read_text(encoding="utf-8"))["description"]
             for folder in (".claude-plugin", ".codex-plugin")]
    texts += [(p / "SKILL.md").read_text(encoding="utf-8") for p in sorted((PLUGIN / "skills").iterdir())]
    found = [(c, t[:60]) for t in texts for c in CLAIMS if re.search(c, t, re.I)]
    assert found == []
