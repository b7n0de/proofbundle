"""D58, Z405 signer service part 3: DECISIONS.md and the pilot's RUNBOOK.md say what the code does.

Each refusal name the service can give stands in D58, and D58 names no other; the time calculation of N405-b uses the
constants of the gate, the service and hooks.json, and holds for every PreToolUse hook; the remaining limit is said;
the owner choices O405-1 to O405-5 stand in both files with the date of the choice; the probe signer is for tests
only. RED at 5840e5aa, the head of Nachtrag 21: no D58 there.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

import test_plugin_fetch_github_profile as f

ROOT = pathlib.Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "proofbundle"
DECISIONS = (PLUGIN / "DECISIONS.md").read_text(encoding="utf-8")
RUNBOOK = (PLUGIN / "pilot" / "RUNBOOK.md").read_text(encoding="utf-8")
SERVICE = (PLUGIN / "pilot" / "signer_service.py").read_text(encoding="utf-8")
gate = f.gate


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    end = text.find("\n## ", start + len(heading))
    return text[start:] if end < 0 else text[start:end]


D58 = _section(DECISIONS, "## D58. ")


def _flat(text: str) -> str:
    return " ".join(text.split())


def _constant(name: str) -> float:
    match = re.search(rf"^{name} = ([0-9.]+)", SERVICE, re.M)
    assert match, name
    return float(match.group(1))


def test_d58_is_dated_and_the_last_decision_of_z405():
    """Over the quick round (Nachtrag 24, part 4 of Nachtrag 22) D59 to D63 follow D58: D58 is the last of Z405 and
    stands right before D59."""
    assert D58.startswith("## D58. ") and "2026-10-17" in D58.splitlines()[0]
    after = DECISIONS[DECISIONS.index(D58) + len(D58):].lstrip("\n")
    assert after.startswith("## D59. "), after[:40]


def test_every_refusal_name_of_the_service_stands_in_d58_and_no_other():
    raised = set(re.findall(r'Refused\("([a-z_]+)"', SERVICE))
    differs = set(re.findall(r'"([a-z_]+_differs?)"', SERVICE))
    names = raised | differs | {"internal_error"}
    assert {"workdir_unreadable", "outside_window", "verdict_differs", "gate_file_differs", "repository_not_safe"} <= names
    listed = set(re.search(r"The names: ([a-z_, ]+)\.", _flat(D58)).group(1).replace(" ", "").split(","))
    assert listed == names


def test_the_gate_names_the_refusal_and_the_timeout_as_d58_says():
    assert gate.PILOT_SIGNER_REFUSES == 3 and _constant("REFUSED") == 3
    assert "exits 3 (the gate's PILOT_SIGNER_REFUSES)" in _flat(D58)
    gate_text = (PLUGIN / "hooks" / "proofbundle_gate.py").read_text(encoding="utf-8")
    assert 'GateError(f"signer_refused_{refused}")' in gate_text and 'GateError("signer_timeout")' in gate_text
    assert "`signer_refused_<name>`" in D58 and "`signer_timeout`" in D58


def test_the_time_calculation_of_n405b_uses_the_constants_and_holds_for_every_pretooluse_hook():
    hooks = json.loads((PLUGIN / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
    timeouts = {h["timeout"] for entry in hooks for h in entry["hooks"]}
    assert timeouts == {120}
    deadline, signer, margin = gate.DEADLINE_SECONDS, gate.PILOT_SIGNER_SECONDS, _constant("MARGIN_SECONDS")
    assert (deadline, signer, margin) == (90.0, 10.0, 1.0)
    assert deadline + signer < min(timeouts)
    text = _flat(D58)
    assert "hooks.json gives each PreToolUse hook 120 s" in text
    assert "DEADLINE_SECONDS = 90 s" in text and "PILOT_SIGNER_SECONDS = 10 s" in text
    assert "90 s + 10 s = 100 s < 120 s: 20 s remain" in text
    assert "PILOT_SIGNER_SECONDS - MARGIN_SECONDS = 9 s" in text
    assert "at most 90 s + n x 10 s, and no host limit" in text


def test_the_window_and_the_clock_skew_are_the_services():
    assert _constant("CLOCK_SKEW_SECONDS") == 2
    assert "not 1 <= config[\"window_seconds\"] <= 300" in SERVICE
    assert "`window_seconds` (1 to 300)" in _flat(D58) and "CLOCK_SKEW_SECONDS (2)" in _flat(D58)


def test_the_remaining_limit_is_said_in_both_files():
    assert "the service decides the state it sees when it runs, not the state the gate saw" in _flat(D58)
    assert "the service decides on the new state" in _flat(D58)
    assert "the service decides on the new state" in _flat(RUNBOOK)


@pytest.mark.parametrize("choice", ["O405-1", "O405-2", "O405-3", "O405-4", "O405-5"])
def test_each_owner_choice_stands_in_both_files_with_its_date(choice):
    owner = _section(RUNBOOK, "## The owner's choices for the first pilot")
    assert "2026-10-17" in owner.splitlines()[0]
    assert f"- {choice}: " in owner
    assert choice in D58 and "2026-10-17, 02:2x Berlin" in D58


def test_the_owner_choices_say_what_was_chosen():
    owner = _flat(_section(RUNBOOK, "## The owner's choices for the first pilot"))
    for text in (_flat(D58), owner):
        assert "criterion 1 of the contract counts only for git.push in the first pilot" in text
        assert "6.3.1 or later" in text and "main's src" in text
        assert "byte-identical copies of main" in text and "without pilot_profile.md" in text
        assert "declare a check and have Level 2" in text


def test_the_probe_signer_is_for_tests_only():
    assert "The probe signer (`probe_signer.py`, a key derived from a public label) stays for tests only." in _flat(D58)
    assert "it is for tests only, never for the pilot" in _flat(RUNBOOK)
    probe = (PLUGIN / "pilot" / "probe_signer.py").read_text(encoding="utf-8")
    assert "for tests only" in _flat(probe.split('"""')[1])


def test_the_runbook_keeps_the_gate_file_and_names_no_value():
    assert "--gate <the service's copy of hooks/proofbundle_gate.py>" in RUNBOOK
    # measured with two accounts: a signer named without its absolute path is no pilot, a repository of another account
    # that the signer's git configuration does not name as safe.directory gets no signature
    assert '"<sudo, by its absolute path>"' in RUNBOOK and "signer program is not an absolute path" in _flat(RUNBOOK)
    assert "`safe.directory`" in RUNBOOK and "(repository_not_safe)" in RUNBOOK
    assert re.search(r"[0-9a-f]{64}", RUNBOOK) is None
    assert "/home/" not in RUNBOOK and "/Users/" not in RUNBOOK
