"""D119, follow-up note 49 (O43-1): an owner's release is used exactly once, and only where the effect may run.

Measured in follow-up note 43 (point 1, O28B-1) and named O43-1: the hook wrote the use of a release (D111) to its plugin data
directory before the signer service decided the call again (D58). A service that decides with the autonomous answer in
the hook's environment (A1) then found the release used and judged DENY; one with a data directory of its own (A2) used
the same release a second time; the service as delivered (A0) knows no autonomous answer and judges ESCALATE. Owner
choice of 2026-10-20 (way A): the release is used once, and only where the service lets the effect run;
the line a card shows is the only one it frees; --admin, a forced push, a tag, a release, PyPI, a signature and root
stay the owner's own doors, which no card opens.

End to end here: the hook of Claude Code with --autonomous and pilot.json in the hook environment of D71, a repository
of the work profile of b7n0de, `gh pr create`, which the autonomous answer blocks as a card (D93) and a release lets run
(D111), and the signer service with its key signer under the test's account (keys from public labels):
A0 the service without the operator's setting (decides without the autonomous answer);
A1 the service with `"autonomous": true` and the hook's plugin data directory;
A2 the service with `"autonomous": true` and a plugin data directory of its own, empty.
And the double use, a release of another line, an expired one, one without a card, the hook without a pilot, the own
doors and the card's text.

RED at 380e9d2a (the head of follow-up note 47): A0 lets the call run and uses the release, a configuration with the
operator's setting is no configuration of the service, a rebuilt request is signed, the doors open with a release and
the card names no sha256. The other lines and the counter cases end as they did.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time

import pytest

import test_plugin_n29_work_profile_d71 as d71
import test_plugin_n42_release_d111 as d111
import test_plugin_z405_decision_receipt as p1
import test_plugin_z405_signer_service as s

gate = d71.gate
pytestmark = d71.pytestmark
SESSION = d111.SESSION
CREATE = "gh pr create -R b7n0de/proofbundle --base main --head topic --title t --body b"
REFUSED = 3


@pytest.fixture(autouse=True)
def _hook_environment(monkeypatch, tmp_path):
    d71._clean.__wrapped__(monkeypatch, tmp_path)


class World:
    """The hook's environment, the records with the signer service as the pilot's signer, a repository of b7n0de."""

    def __init__(self, tmp_path: pathlib.Path, pilot: bool = True):
        self.tmp = tmp_path
        self.env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                               "PROOFBUNDLE_GATE_DIR")}
        self.data = tmp_path / "data"
        self.data.mkdir()
        (tmp_path / "gatedir").mkdir(exist_ok=True)
        self.env.update(CLAUDE_PLUGIN_DATA=str(self.data), PLUGIN_DATA=str(self.data), CLAUDE_CODE_SESSION_ID=SESSION,
                        PYTHONPATH=str(pathlib.Path(p1.ROOT) / "src"))
        self.service = s.Service(self.env, tmp_path) if pilot else None
        self.repo = d71._repo(tmp_path / "b7", name="r")

    def variant(self, name: str, autonomous: bool | None, own_data: bool = False, **environment) -> pathlib.Path:
        """A configuration of the service in a folder of its own, set as the pilot's signer; returns that folder."""
        config = json.loads(self.service.config.read_text(encoding="utf-8"))
        folder = self.tmp / f"dienst_{name}"
        folder.mkdir()
        config["journal"] = str(folder / "journal.jsonl")
        if autonomous is not None:
            config["autonomous"] = autonomous
        if own_data:
            (folder / "data").mkdir()
            environment.update(CLAUDE_PLUGIN_DATA=str(folder / "data"), PLUGIN_DATA=str(folder / "data"))
        config["environment"] = {**config["environment"], **environment}
        path = folder / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        pilot_path = pathlib.Path(self.env["PROOFBUNDLE_GATE_DIR"]) / "pilot.json"
        pilot = json.loads(pilot_path.read_text(encoding="utf-8"))
        pilot["signer"] = [sys.executable, str(s.SERVICE), "--config", str(path)]
        pilot_path.write_text(json.dumps(pilot), encoding="utf-8")
        return folder

    def hook(self, command: str = CREATE) -> tuple[str, dict]:
        event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(self.repo),
                            "session_id": SESSION, "tool_input": {"command": command}})
        proc = subprocess.run([sys.executable, "-I", str(s.GATE_FILE), "--host", "claude", gate.AUTONOMOUS_FLAG],
                              input=event, capture_output=True, text=True, env=self.env, cwd=str(self.repo),
                              timeout=180, check=False)
        assert proc.returncode == 0, proc.stderr
        printed = json.loads(proc.stdout) if proc.stdout.strip() else {}
        log = p1.log_lines(self.env)
        return (printed.get("hookSpecificOutput") or {}).get("permissionDecision") or "pass", log[-1] if log else {}

    def release(self, command: str = CREATE, **kw) -> None:
        d111._release(self.tmp, command, **kw)

    def used(self) -> dict:
        path = self.data / gate.RELEASES_USED
        return json.loads(path.read_text(encoding="utf-8"))["genutzt"] if path.exists() else {}

    def receipts(self) -> list[str]:
        """The verdict of every signed receipt in the records."""
        found = []
        for envelope in p1.receipts_in(self.service.records):
            statement = json.loads(__import__("base64").b64decode(envelope["payload"]))
            found.append(statement["predicate"]["decision"]["verdict"])
        return found


def _honoured(folder: pathlib.Path) -> dict:
    path = folder / "freigaben-geehrt.json"
    return json.loads(path.read_text(encoding="utf-8"))["geehrt"] if path.exists() else {}


def _service_lines(folder: pathlib.Path) -> list[dict]:
    path = folder / "journal.jsonl"
    return [x for x in (json.loads(y) for y in path.read_text(encoding="utf-8").splitlines()) if "signed" in x] \
        if path.exists() else []


# --- A0, A1, A2 of follow-up note 43 ---------------------------------------------------------------------------------------

def test_A0_a_service_that_does_not_let_the_effect_run_uses_no_release_and_the_call_stays_blocked(tmp_path):
    world = World(tmp_path)
    a0 = world.variant("A0", None)
    world.release()
    decision, entry = world.hook()
    assert decision == "deny" and "released_by_owner" not in entry["reason_ids"], (decision, entry)
    assert entry["autonomy"]["klasse"] == "karte" and entry["autonomy"]["freigabe_offen"]["karte"] == d111.CARD, entry
    assert world.used() == {} and "ALLOW" not in world.receipts()
    assert [(x["signed"], x["reason"]) for x in _service_lines(a0)] == [(False, "verdict_differs")]
    # the release is still there: a service that lets the effect run lets the call run now, and uses it once
    a1 = world.variant("A1", True)
    assert world.hook()[0] == "pass" and len(world.used()) == 1 and len(_honoured(a1)) == 1
    assert world.hook()[0] == "deny" and len(world.used()) == 1


@pytest.mark.parametrize("own_data", [False, True], ids=["A1 the hook's data", "A2 a data directory of its own"])
def test_A1_A2_the_service_lets_it_run_and_the_release_is_used_exactly_once(tmp_path, own_data):
    world = World(tmp_path)
    folder = world.variant("A2" if own_data else "A1", True, own_data=own_data)
    world.release()
    decision, entry = world.hook()
    assert decision == "pass" and entry["autonomy"]["klasse"] == "freigabe", (decision, entry)
    assert world.receipts() == ["ALLOW"] and len(world.used()) == 1 and len(_honoured(folder)) == 1
    decision, entry = world.hook()
    assert decision == "deny" and entry["autonomy"]["klasse"] == "karte", (decision, entry)
    assert sorted(world.receipts()) == ["ALLOW", "DENY"], world.receipts()   # the second call's DENY is signed too
    assert len(world.used()) == 1 and len(_honoured(folder)) == 1
    assert [x["signed"] for x in _service_lines(folder)] == [True, True]


def test_A2_a_request_rebuilt_after_the_use_gets_no_second_signature(tmp_path):
    world = World(tmp_path)
    folder = world.variant("A2", True, own_data=True)
    world.release()
    assert world.hook()[0] == "pass"
    envelope = p1.receipts_in(world.service.records)[0]
    reasons = json.loads(__import__("base64").b64decode(envelope["payload"]))["predicate"]["decision"]["reasonCodes"]
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(world.repo),
                        "session_id": SESSION, "tool_input": {"command": CREATE}})
    request = s.proposal(world.env, world.service, event, "claude", "ALLOW", reasons=reasons)
    proc = subprocess.run([sys.executable, str(s.SERVICE), "--config", str(folder / "config.json")],
                          input=json.dumps(request).encode("utf-8"), capture_output=True, timeout=60, check=False)
    assert (proc.returncode, proc.stdout.decode().strip()) == (REFUSED, "verdict_differs"), proc
    assert world.receipts() == ["ALLOW"] and len(_honoured(folder)) == 1


def test_the_service_takes_the_session_of_the_decision_from_the_event_never_from_its_configuration(tmp_path):
    world = World(tmp_path)
    folder = world.variant("A2", True, own_data=True, CLAUDE_CODE_SESSION_ID="account A-session-7")
    world.release()
    assert world.hook()[0] == "pass" and world.receipts() == ["ALLOW"] and len(_honoured(folder)) == 1


@pytest.mark.parametrize("how", ["another line", "expired", "without a card", "another session"])
def test_a_release_that_does_not_bind_frees_nothing_and_nothing_is_used_or_signed(tmp_path, how):
    world = World(tmp_path)
    folder = world.variant("A1", True)
    if how == "another line":
        world.release(CREATE.replace("--title t", "--title u"))
    elif how == "expired":
        world.release(ago=16 * 60)
    elif how == "without a card":
        world.release(card=None)
    else:
        world.release(session="account A-session-7")
    decision, entry = world.hook()
    assert decision == "deny" and "released_by_owner" not in entry["reason_ids"], (how, decision)
    assert world.used() == {} and _honoured(folder) == {} and "ALLOW" not in world.receipts()


def test_control_without_a_pilot_the_hook_writes_the_use_itself_and_lets_it_run_once(tmp_path):
    world = World(tmp_path, pilot=False)
    world.release()
    assert world.hook()[0] == "pass" and len(world.used()) == 1
    assert world.hook()[0] == "deny" and len(world.used()) == 1


def test_control_a_record_of_uses_the_hook_cannot_read_lets_nothing_run(tmp_path):
    world = World(tmp_path)
    folder = world.variant("A1", True)
    world.release()
    (world.data / gate.RELEASES_USED).write_text("{")
    decision, _entry = world.hook()
    assert decision == "deny" and _honoured(folder) == {} and "ALLOW" not in world.receipts()


def test_the_service_configuration_takes_the_operators_setting_as_true_or_false_only(tmp_path):
    world = World(tmp_path)
    folder = world.variant("A1", True)
    config = json.loads((folder / "config.json").read_text(encoding="utf-8"))
    sys.path.insert(0, str(s.SERVICE.parent))
    try:
        import signer_service
    finally:
        sys.path.pop(0)
    assert signer_service.load_config(str(folder / "config.json"))["autonomous"] is True
    for value in ("true", 1, None):
        (folder / "bad.json").write_text(json.dumps(dict(config, autonomous=value)), encoding="utf-8")
        with pytest.raises(ValueError):
            signer_service.load_config(str(folder / "bad.json"))


# --- point 4: the lines a card frees, and the own doors no card opens -------------------------------------------------

HEAD = "0123456789abcdef0123456789abcdef01234567"
FREED = ["git push origin claude/n49-probe",
         "gh workflow run ci.yml -R b7n0de/proofbundle --ref claude/n49-probe",
         "gh api graphql -f query='mutation { resolveReviewThread(input: {threadId: \"PRRT_kwDOabc\"}) "
         "{ thread { isResolved } } }'",
         f"gh pr merge 388 -R b7n0de/proofbundle --squash --match-head-commit {HEAD}"]
DOORS = [("git push --force origin claude/n49-probe", "a forced push"),
         ("git push origin +claude/n49-probe", "a forced push"),
         ("git push --force-with-lease origin claude/n49-probe", "a forced push"),
         ("git push -fu origin claude/n49-probe", "a forced push"),
         ("git tag v6.3.1", "a tag"), ("git push origin v0", "a tag"), ("git push --tags origin", "a tag"),
         ("git push origin refs/tags/v6.3.1", "a tag"),
         ("gh release create v6.3.1 -R b7n0de/proofbundle --notes x", "a release"),
         ("gh pr merge 388 -R b7n0de/proofbundle --squash", "a merge without --match-head-commit")]


@pytest.fixture
def env(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(data))
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", SESSION)
    (tmp_path / "gatedir").mkdir(exist_ok=True)
    return tmp_path


@pytest.mark.parametrize("command", FREED)
def test_point_4_a_line_of_the_list_runs_once_with_a_release_and_not_without(env, command):
    repo = d71._repo(env)
    assert d111.answered(repo, command)[0] == "deny"
    d111._release(env, command)
    assert d111.answered(repo, command)[:1] == ("pass",)
    assert d111.answered(repo, command)[0] == "deny"


@pytest.mark.parametrize("command, door", DOORS)
def test_point_4_an_own_door_stays_closed_with_a_release_and_the_answer_says_so(env, command, door):
    repo = d71._repo(env)
    deadline = time.monotonic() + 60
    before = d111.answered(repo, command)
    assert before[0] == "deny", before
    d111._release(env, command)
    out = gate.decide(command, str(repo), deadline, "claude")
    answer = gate.autonomous_outcome(out, command, str(repo), deadline, "claude")
    assert answer.decision == "deny" and "released_by_owner" not in [v.reason_id for v in answer.verdicts], command
    assert f"touches {door}" in answer.text and answer.autonomy["freigabe_offen"]["karte"] == d111.CARD, answer.text
    assert not (pathlib.Path(os.environ["CLAUDE_PLUGIN_DATA"]) / gate.RELEASES_USED).exists()


def test_point_4_admin_stays_a_deny_of_decide_with_a_release(env):
    repo = d71._repo(env)
    command = f"gh pr merge 388 -R b7n0de/proofbundle --squash --admin --match-head-commit {HEAD}"
    d111._release(env, command)
    assert d111.answered(repo, command)[0] == "deny"


@pytest.mark.parametrize("command, door", [("sudo systemctl restart x", "root"), ("twine upload dist/x.tar.gz", "pypi"),
                                           ("uv publish dist/x.tar.gz", "pypi"), ("gpg --detach-sign dist/x", "signatur"),
                                           ("ssh-keygen -Y sign -n file -f k dist/x", "signatur"),
                                           ("cosign sign-blob dist/x", "signatur"), ("git commit -S -m x", "signatur"),
                                           ("bash -c 'sudo true'", "root"), ("gh api repos/o/r/releases", "release"),
                                           ("git push --force origin claude/x", "force"),
                                           ("git push --force-with-lease origin claude/x", "force"),
                                           ("git push -fu origin claude/x", "force"), ("git push origin +claude/x", "force"),
                                           ("git push --mirror origin", "force"), ("git tag -s v6.3.1", "tag"),
                                           ("git push --follow-tags origin claude/x", "tag"),
                                           ("gh release create v6.3.1", "release"),
                                           ("gh pr merge 388 --squash", "merge_kopf")])
def test_point_4_the_words_of_the_other_doors_are_read(command, door):
    """The words alone, without a reason of decide(): where the gate cannot name the target (a chain, an unknown remote)
    the reasons of D86 and D73 do not stand, and the words still hold the release back."""
    assert gate._release_door(command, gate.Outcome("deny", "", [])) == door


@pytest.mark.parametrize("command", FREED + [CREATE, "git add -A && git commit -m 'PR 328'"])
def test_point_4_control_a_line_of_the_list_touches_no_door(command):
    assert gate._release_door(command, gate.Outcome("deny", "", [])) is None


# --- point 3: the card carries the line and what it does outside ------------------------------------------------------

def test_point_3_the_card_names_the_sha256_of_the_line_and_how_a_release_binds(env):
    repo = d71._repo(env)
    deadline = time.monotonic() + 60
    out = gate.autonomous_outcome(gate.decide(CREATE, str(repo), deadline, "claude"), CREATE, str(repo), deadline,
                                  "claude")
    assert out.autonomy["klasse"] == "karte", out.autonomy
    assert gate.command_sha256(CREATE) in out.text and "a changed line needs a new card" in out.text, out.text
    assert "a pull request, an issue, a comment or a review" in out.text


def test_point_3_the_card_of_a_door_says_that_no_card_frees_it(env):
    repo = d71._repo(env)
    command = "gh release create v6.3.1 -R b7n0de/proofbundle --notes x"
    deadline = time.monotonic() + 60
    out = gate.autonomous_outcome(gate.decide(command, str(repo), deadline, "claude"), command, str(repo), deadline,
                                  "claude")
    assert out.autonomy["klasse"] == "karte" and "no card frees it" in out.text and "a release" in out.text, out.text


# --- point 2: once per card, and the hook's step on its own --------------------------------------------------------

def test_point_2_a_card_the_fetcher_writes_twice_frees_its_line_once(env):
    repo = d71._repo(env)
    command = FREED[1]
    d111._release(env, command, ago=60)
    d111._release(env, command, ago=30)   # the same card, another answer time
    assert d111.answered(repo, command)[0] == "pass"
    assert d111.answered(repo, command)[0] == "deny"


def _held(env, command):
    repo = d71._repo(env)
    deadline = time.monotonic() + 60
    d111._release(env, command)
    out = gate.autonomous_outcome(gate.decide(command, str(repo), deadline, "claude"), command, str(repo), deadline,
                                  "claude", take=False)
    assert out.decision == "pass" and out.release is not None and out.release["genutzt"] is False, out.text
    assert not (pathlib.Path(os.environ["CLAUDE_PLUGIN_DATA"]) / gate.RELEASES_USED).exists()
    return out


def _settle_env() -> dict:
    """The names the hook's step reads: the gate directory (pilot.json) and the plugin data directory."""
    return {name: os.environ[name] for name in ("PROOFBUNDLE_GATE_DIR", "CLAUDE_PLUGIN_DATA", "CLAUDE_CODE_SESSION_ID")}


def test_the_hooks_step_writes_the_use_once_where_no_pilot_reads_the_call(env):
    out = _held(env, FREED[1])
    answer, asked = gate.release_settle({"tool_name": "Bash"}, out, _settle_env())
    assert (answer.decision, asked, out.release["genutzt"]) == ("pass", False, True)
    assert len(json.loads((pathlib.Path(os.environ["CLAUDE_PLUGIN_DATA"]) / gate.RELEASES_USED).read_text())
               ["genutzt"]) == 1


def test_the_hooks_step_keeps_the_answer_where_the_release_was_used_meanwhile(env):
    out = _held(env, FREED[1])
    release = out.release["freigabe"]
    data = pathlib.Path(os.environ["CLAUDE_PLUGIN_DATA"])
    (data / gate.RELEASES_USED).write_text(json.dumps({"schema": gate.RELEASES_USED_SCHEMA, "genutzt": {
        f"{release['karte']}:{release['sha256']}:{release['sitzung']}": "2026-10-23T00:00:00Z"}}))
    answer, _asked = gate.release_settle({"tool_name": "Bash"}, out, _settle_env())
    assert answer.decision == "deny" and "released_by_owner" not in [v.reason_id for v in answer.verdicts]
    assert "was used before" in answer.text and answer.autonomy["freigabe_offen"]["karte"] == d111.CARD


def test_the_services_record_takes_a_release_once_even_for_two_requests_at_a_time(tmp_path):
    """The record of the service is checked again under its lock when it is written: of two requests that both found
    the release free, the second gets no signature (release_honoured)."""
    sys.path.insert(0, str(s.SERVICE.parent))
    try:
        import signer_service
    finally:
        sys.path.pop(0)
    config = {"journal": str(tmp_path / "dienst" / "journal.jsonl")}
    release = {"karte": d111.CARD, "sha256": "a" * 64, "sitzung": SESSION, "antwort": "2026-10-23T20:00:00Z"}
    signer_service.honour(config, release)
    with pytest.raises(signer_service.Refused, match="release_honoured"):
        signer_service.honour(config, release)
    assert list(signer_service.honoured(config)) == [f"{d111.CARD}:{'a' * 64}:{SESSION}"]
