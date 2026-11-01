"""D129 (owner answer 9 of Nachtrag 7, 2026-10-26, option B): the standing GO of D87 needs a consent of its own.

The answer, translated: "House configuration D125: B, D87 split off, its GO needs its own protected consent." D125 took
--autonomous out of the public hook commands and left the flag to the house as an opt-in; started with it, the gate
still switched on the standing GO of D87 for a push to the own work branch, and the last paragraph of D125 named the
gap: a protected, explicit consent channel for that GO does not exist. Owner answer 5 of the same day: the protected
channel is to be a record signed with a key outside the session, which the house builds; until then a setting of the
hook's environment, documented as no protection.

The rule held here: with --autonomous alone a push D87 measured is not free; its GO applies only where the hook's
environment also sets PROOFBUNDLE_STANDING_GO to `protected` (the pattern of D124). Without it the push gets the answer
of the closed list of D85, here a card of D93 in the work profile of b7n0de; PROOFBUNDLE_OWNER_STATE of D124 is no
consent to the GO. With it the push passes as before. The setting frees nothing without the flag and nothing under
Codex. The repository, the hook environment and the pushes are those of the D87 tests
(tests/test_plugin_n35_work_branch_go_d87.py); this module does not take their consent (tests/_standing_go.py).

RED at f21f785d: each work-branch push of the D87 tests without the setting, with and without the owner state setting,
and the push with a value other than `protected`, passes under the standing GO; the gate has no reader of the setting;
the signer service with the operator's `"autonomous": true` frees the push without the setting in its environment
(D119). The pushes with the setting, the gate without the flag and Codex are controls, green at both.
"""
from __future__ import annotations

import json
import pathlib
import sys
import time

import pytest

import _gate_answer as ga
import test_plugin_n29_work_profile_d71 as d71
import test_plugin_n35_work_branch_go_d87 as d87

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean
PILOT = pathlib.Path(gate.__file__).resolve().parent.parent / "pilot"
#: D129: the house's statement in the hook's environment that it consents to the standing GO of D87.
CONSENT = {"PROOFBUNDLE_STANDING_GO": "protected"}
#: D124: the house's statement that it protects the owner files of the gate directory; it is no consent to the GO.
OWNER_STATE = {"no owner state": {}, "owner state protected": {"PROOFBUNDLE_OWNER_STATE": "protected"}}
PUSH = "git push origin claude/x"


@pytest.fixture(autouse=True)
def _no_consent(monkeypatch):
    """No consent unless a case states it: the D87 tests take theirs from tests/_standing_go.py, this module does not."""
    monkeypatch.delenv("PROOFBUNDLE_STANDING_GO", raising=False)


def _decision(answer) -> str | None:
    return None if answer is None else answer["hookSpecificOutput"].get("permissionDecision")


def _signer_service():
    sys.path.insert(0, str(PILOT))
    try:
        import signer_service
    finally:
        sys.path.pop(0)
    return signer_service


@pytest.mark.parametrize("state", list(OWNER_STATE))
@pytest.mark.parametrize("form", d87.FREE)
def test_D129_without_the_consent_a_push_to_the_own_work_branch_gets_no_standing_go(tmp_path, form, state):
    repo = d87._fixture(tmp_path)
    answer, entry = d87._hook(repo, tmp_path, form, extra=OWNER_STATE[state])
    assert "free_work_branch_go" not in entry["reason_ids"], (form, state, entry)
    # the answer of the closed list of D85 to a push: in the work profile of b7n0de a card of D93, a deny
    assert _decision(answer) == "deny" and "autonomy_card" in entry["reason_ids"], (form, state, answer)
    assert (entry["verdict"], entry["autonomy"]["klasse"], entry["autonomy"]["wirkung"]) == ("ask", "karte", ["push"])


@pytest.mark.parametrize("state", list(OWNER_STATE))
@pytest.mark.parametrize("form", d87.FREE)
def test_D129_control_with_the_consent_the_push_passes_under_the_standing_go_as_before(tmp_path, form, state):
    repo = d87._fixture(tmp_path)
    answer, entry = d87._hook(repo, tmp_path, form, extra={**CONSENT, **OWNER_STATE[state]})
    assert "permissionDecision" not in answer["hookSpecificOutput"], (form, state, answer)
    assert "(D92)." in ga.short_text(answer) and "free_work_branch_go" in entry["reason_ids"]
    assert (entry["verdict"], entry["decision"], entry["autonomy"]["klasse"]) == ("ask", "none", "go"), entry


@pytest.mark.parametrize("value", ["", "1", "yes", "Protected", "protected "])
def test_D129_only_the_value_protected_states_the_consent(tmp_path, value):
    repo = d87._fixture(tmp_path)
    answer, entry = d87._hook(repo, tmp_path, PUSH, extra={"PROOFBUNDLE_STANDING_GO": value})
    assert "free_work_branch_go" not in entry["reason_ids"], (value, entry)
    assert _decision(answer) == "deny" and "autonomy_card" in entry["reason_ids"], (value, answer)


def test_D129_control_without_the_flag_the_consent_changes_no_answer(tmp_path, monkeypatch):
    """The gate started without --autonomous, as the shipped hook starts it since D125, answers as decide() judges."""
    repo = d87._fixture(tmp_path)
    monkeypatch.setattr(d87, "AUTONOMOUS", [])
    answer, entry = d87._hook(repo, tmp_path, PUSH, extra=CONSENT)
    base, base_entry = d87._hook(repo, tmp_path, PUSH)
    assert _decision(answer) == "ask" and "autonomy" not in entry, answer
    assert "free_work_branch_go" not in entry["reason_ids"]
    assert (_decision(answer), entry["verdict"], entry["reason_ids"]) == \
        (_decision(base), base_entry["verdict"], base_entry["reason_ids"])


def test_D129_control_under_codex_the_consent_changes_no_answer(tmp_path):
    repo = d87._fixture(tmp_path)
    answer, entry = d87._hook(repo, tmp_path, PUSH, host="codex", extra=CONSENT)
    base, base_entry = d87._hook(repo, tmp_path, PUSH, host="codex")
    assert answer is not None and "free_work_branch_go" not in entry["reason_ids"], (answer, entry)
    assert (_decision(answer), entry["verdict"], entry["decision"], entry["reason_ids"]) == \
        (_decision(base), base_entry["verdict"], base_entry["decision"], base_entry["reason_ids"])


def test_D129_the_gate_reads_the_consent_from_its_own_setting_only():
    assert (gate.STANDING_GO_VARIABLE, gate.STANDING_GO_PROTECTED) == ("PROOFBUNDLE_STANDING_GO", "protected")
    assert gate._standing_go_consented(dict(CONSENT)) is True
    for environ in ({}, {"PROOFBUNDLE_OWNER_STATE": "protected"}, {"PROOFBUNDLE_STANDING_GO": "Protected"},
                    {"PROOFBUNDLE_STANDING_GO": "1"}, {"PROOFBUNDLE_STANDING_GO": ""}):
        assert gate._standing_go_consented(environ) is False, environ


@pytest.mark.parametrize("consent", [False, True], ids=["without the setting", "with the setting"])
def test_D129_the_signer_service_frees_the_push_only_where_its_own_environment_consents(tmp_path, monkeypatch,
                                                                                         consent):
    """D119: with the operator's `"autonomous": true` the service decides a Level 1 call with tool_outcome in
    os.environ, which it sets to the `environment` of its configuration; the consent there is the operator's statement,
    never one of the agent's session."""
    repo = d87._fixture(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", "s-d129")
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "service-data"))
    if consent:
        monkeypatch.setenv("PROOFBUNDLE_STANDING_GO", "protected")
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo), "session_id": "s-d129",
                        "tool_input": {"command": PUSH}})
    request = {"schema": gate.PILOT_SIGN_REQUEST, "level": 1, "host": "claude", "event": event, "statement": ""}
    action, _key, verdict, _reasons, _cwd = _signer_service().decide(gate, request, time.monotonic() + 60,
                                                                     autonomous=True)
    assert action["surface"] == "git.push" and verdict == ("ALLOW" if consent else "DENY"), (consent, verdict)
