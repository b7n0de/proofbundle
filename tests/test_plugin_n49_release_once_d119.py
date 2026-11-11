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
from _owner_state import owner_state_protected  # noqa: F401 - D124: a person's release is read

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
                                               "PROOFBUNDLE_GATE_DIR", "PROOFBUNDLE_OWNER_STATE")}
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
    return {name: os.environ[name] for name in ("PROOFBUNDLE_GATE_DIR", "CLAUDE_PLUGIN_DATA", "CLAUDE_CODE_SESSION_ID",
                                                "PROOFBUNDLE_OWNER_STATE")}


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
    config = {"journal": str(tmp_path / "dienst" / "journal.jsonl"), "records": str(tmp_path / "records")}
    release = {"karte": d111.CARD, "sha256": "a" * 64, "sitzung": SESSION, "antwort": "2026-10-23T20:00:00Z"}
    signer_service.honour(config, release)
    with pytest.raises(signer_service.Refused, match="release_honoured"):
        signer_service.honour(config, release)
    assert list(signer_service.honoured(config)) == [f"{d111.CARD}:{'a' * 64}:{SESSION}"]


# --- every spelling git takes (DELTA-GUARD-SIGNATUR-BUENDEL-20261110-01) ----------------------------------------------
# Main compared several words of a door in their full spelling only, while git takes a long option by any prefix that
# names it alone, a short one inside a bundle, and a push's targets also from its configuration. The cases below cover
# these spellings and effects, doors main already read, counter cases and named costs that stay free, and conservative
# refusals. The oracle tests below run the selected lines through real git in throwaway repositories.

#: A branch topic with a commit of its own, so that a merge into main makes a merge commit the oracle can see signed.
_TOPIC = "git switch -q -c topic && git commit -q -m t && git switch -q main && "
SPELLINGS = [
    ("git commit -qS -m x", "signatur"), ("git commit -aS -m x", "signatur"), ("git commit --gpg -m x", "signatur"),
    ("git commit --gpg-s -m x", "signatur"), ("git commit --gpg=k -m x", "signatur"),
    ("git push --signed origin claude/x", "signatur"), ("git push --si origin claude/x", "signatur"),
    ("git push --signed=if-asked origin claude/x", "signatur"),
    ("git push --tag origin claude/x", "tag"), ("git push --follow origin claude/x", "tag"),
    ("git -c push.followTags=true push origin claude/x", "tag"),
    ("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=push.followTags GIT_CONFIG_VALUE_0=true git push origin claude/x", "tag"),
    ("git push --mirro origin", "force"), ("git push --mir origin", "force"),
    ("git -c remote.origin.mirror=true push origin", "force"),
    ("git -c remote.origin.push=+HEAD:refs/heads/main push origin", "force"),
    ("git config remote.origin.push +HEAD:refs/heads/main && git push origin", "force"),
    # local review of 89922dec (two P1): a value set by its index or taken from another variable, and a quoted remote
    ("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=remote.origin.push GIT_CONFIG_VALUE_0=+HEAD:refs/heads/main git push origin",
     "force"),
    ("SPEC=+HEAD:refs/heads/main git --config-env=remote.origin.push=SPEC push origin", "force"),
    ("git -c 'remote.o(r).mirror=true' push 'o(r)'", "force"),
    ("GIT_CONFIG_PARAMETERS=\"'remote.origin.push'='+HEAD:refs/heads/main'\" git push origin", "force"),
    # local review of 5ee4b8bc (six P1): --config-env with its own argument, the last of two assignments, `.push=` in a
    # remote's name, the `tag <name>` of a refspec, and a quoted option value with a blank before the subcommand
    ("SPEC=+HEAD:refs/heads/main git --config-env remote.origin.push=SPEC push origin", "force"),
    ("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=remote.origin.push GIT_CONFIG_VALUE_0=HEAD:refs/heads/main "
     "GIT_CONFIG_VALUE_0=+HEAD:refs/heads/main git push origin", "force"),
    ("GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=remote.o.push=x.url GIT_CONFIG_VALUE_0=../origin.git "
     "GIT_CONFIG_KEY_1=remote.o.push=x.mirror GIT_CONFIG_VALUE_1=true git push o.push=x", "force"),
    ("git push origin tag v1", "tag"),
    ("git -c 'user.name=John Doe' push --tag origin claude/x", "tag"),
    ("git -c 'user.name=John Doe' push --mir origin", "force"),
    # local review of 56e79b09 (two P1): a wildcard refspec, and send-pack with its force, mirror and signature
    ("git push origin 'refs/*:refs/*'", "tag"),
    ("git send-pack --force ../origin.git HEAD:refs/heads/main", "force"),
    ("git send-pack --signed ../origin.git HEAD:refs/heads/fresh", "signatur"),
    # local review of e64f9ef5 (two P1): a short tag name of send-pack, a name below tags/, and git's exec path
    ("git send-pack ../origin.git v1", "tag"), ("git send-pack ../origin.git v1:another", "tag"),
    ("git push origin tags/v1", "tag"), ("git push origin tags/v1:another", "tag"),
    ("$(git --exec-path)/git-push --mirro origin", "force"),
    ("$(git --exec-path)/git-send-pack --force ../origin.git HEAD:refs/heads/main", "force"),
    ("$(git --exec-path)/git-commit -qS -m x", "signatur"),
    # local review of 566b7d16 (P1): a push started from git's exec path with a short tag name
    ("$(git --exec-path)/git-push ../origin.git v1", "tag"),
    ("$(git --exec-path)/git-push ../origin.git v1:another", "tag"),
    # local review of 38fdfcb3 (P1, open at main): a signing option given as the value of branch.<name>.mergeOptions
    (_TOPIC + "git -c branch.main.mergeOptions=-S merge --no-ff --no-edit topic", "signatur"),
    (_TOPIC + "git -c branch.main.mergeOptions=--gpg merge --no-ff --no-edit topic", "signatur"),
    (_TOPIC + "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=branch.main.mergeOptions GIT_CONFIG_VALUE_0=-qS "
     "git merge --no-ff --no-edit topic", "signatur"),
    # local review of fac72793 (P1, open at main): a push under another name, by the line's own autocorrection or alias
    ("git -c help.autocorrect=immediate puhs --mirro origin", "force"),
    ("git -c alias.p=push p --mirror origin", "force"),
]
#: Lines kept as cases. The two signing lines and the lines with an unread brace beside a read word are doors main
#: already read: the reading of git's exec path must not take an option for a program (local review of 566b7d16, P1, a
#: regression of the fourth form of this rule). The three abbreviated options at the limit of the brace reader are
#: doors of this rule, read at that limit.
KEPT = [("git commit -S/tmp/git-key -m x", "signatur"), ("git commit --gpg-sign=/tmp/git-key -m x", "signatur"),
        # at the limit of the brace reader (six groups, 64 words) the words are read and keep their own door
        ("git push --ta{,}{,}{,}{,}{,}{,} origin", "tag"), ("git push --mirro{,}{,}{,}{,}{,}{,} origin", "force"),
        ("git commit --gpg{,}{,}{,}{,}{,}{,} -q -m x", "signatur"),
        # local review of 8511dc09 (P1, a regression of the fifteenth form): an unread brace beside a read word must
        # leave the read word and the door main reads as they are
        ("env {X{0..0..1}=,git} push --mirror origin", "force"), ("env {X{0..0..1}=,git} push --tags origin", "tag"),
        ("env {X{0..0..1}=,git} commit -S -q -m x", "signatur")]
#: The same for gh, read by words only: a value with git- in it must not move gh's subcommand (local review of 7e2935f5,
#: P1, a regression of the fifth form, which inserted words).
KEPT_WORDS = [("gh -R b7n0de/git-repo release edit stable --notes x", "release"),
              ("gh -R b7n0de/git-repo pr merge 388 --squash", "merge_kopf")]
#: A refspec set by configuration is held back as a forced push whatever it says (the reader resolves no value against
#: the repository), and `send-pack --mirror` is read as the mirror it is; here git sends a tag with each, and the
#: third entry is the door git opens (send-pack --mirror does not force the diverged main, measured).
CONFIG_HELD = [("git send-pack --mirror ../origin.git", "force", "tag"),
               # local review of 1018aa84 (P1, open at main): the upstream of a branch chooses a tag as the target
               ("git -c push.default=upstream -c branch.main.remote=../origin.git -c branch.main.merge=refs/tags/r9 push",
                "force", "tag"),
               ("git -c 'remote.origin.push=refs/tags/*:refs/tags/*' push origin", "force", "tag"),
               ("KIND=tags; git -c remote.origin.push=HEAD:refs/$KIND/v2 push origin", "force", "tag"),
               ("git -c remote.origin.push=v1 push origin", "force", "tag"),
               # neighbours of that finding: a configuration the line brings in from a file the reader does not see
               ("git -c include.path=$PWD/../push.cfg push origin", "force", "tag"),
               ("git -c includeIf.onbranch:main.path=$PWD/../push.cfg push origin", "force", "tag"),
               ("GIT_CONFIG_GLOBAL=$PWD/../push.cfg git push origin", "force", "tag"),
               ("GIT_CONFIG_SYSTEM=$PWD/../push.cfg git push origin", "force", "tag"),
               ("env -u GIT_CONFIG_GLOBAL HOME=$PWD/../cfg_home git push origin", "force", "tag"),
               ("env -u GIT_CONFIG_GLOBAL XDG_CONFIG_HOME=$PWD/../xdg git push origin", "force", "tag"),
               ("git -c include.path=$PWD/../sign.cfg commit -q -m x", "force", "signatur"),
               # local review of 698f882b (P1, open at main): the shell sets these variables in more forms than NAME=
               ("unset GIT_CONFIG_GLOBAL; GIT_CONFIG_GLOBAL+=$PWD/../push.cfg git push origin", "force", "tag"),
               ("printf -v GIT_CONFIG_GLOBAL %s $PWD/../push.cfg; export GIT_CONFIG_GLOBAL; git push origin", "force", "tag"),
               ("unset GIT_CONFIG_SYSTEM; GIT_CONFIG_SYSTEM+=$PWD/../push.cfg git push origin", "force", "tag"),
               ("unset HOME GIT_CONFIG_GLOBAL; : ${HOME:=$PWD/../cfg_home}; export HOME; git push origin", "force", "tag"),
               ("unset GIT_CONFIG_GLOBAL; read -r XDG_CONFIG_HOME <<< $PWD/../xdg; export XDG_CONFIG_HOME; git push origin",
                "force", "tag"),
               # and a key of the configuration the reader cannot read, put together by the shell
               ("printf -v K %s%s incl ude.path; git -c \"$K=$PWD/../push.cfg\" push origin", "force", "tag"),
               ("printf -v K %s%s incl ude.path; GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=$K GIT_CONFIG_VALUE_0=$PWD/../push.cfg "
                "git push origin", "force", "tag"),
               ("GIT_CONFIG_COUNT=1 GIT_CONFIG_VALUE_0=$PWD/../push.cfg; printf -v GIT_CONFIG_KEY_0 %s%s incl ude.path; "
                "export GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0; git push origin", "force", "tag"),
               # local review of 06d45152 (P1, open at main): every expansion the gate does not resolve, backquotes too,
               # and a quoted value of GIT_CONFIG_PARAMETERS with blanks; and a name set through an expansion
               ("git -c \"`printf %s%s incl ude.path`=$PWD/../push.cfg\" push origin", "force", "tag"),
               ("git -c \"`printf %s%s rem ote.origin.mirror`=true\" push origin", "force", "tag"),
               ("GIT_CONFIG_PARAMETERS=\"'user.name'='a' '$(printf %s%s incl ude.path)'='$PWD/../push.cfg'\" git push origin",
                "force", "tag"),
               ("export X=$PWD/../push.cfg; git --config-env=\"`printf %s%s incl ude.path`=X\" push origin", "force", "tag"),
               ("N=GIT_CONFIG_GLO; export ${N}BAL=$PWD/../push.cfg; git push origin", "force", "tag"),
               ("N=GIT_CONFIG_GLO; printf -v \"${N}BAL\" %s $PWD/../push.cfg; export \"${N}BAL\"; git push origin",
                "force", "tag"),
               # local review of 5f569e59 (P1, open at main) and the class it belongs to: a word the gate cannot read in
               # a line of a door program may be any configuration, subcommand or option
               ("N=GIT_CONFIG_GLO; command export ${N}BAL=$PWD/../push.cfg; git push origin", "unread", "tag"),
               ("N=GIT_CONFIG_GLO; env \"${N}BAL=$PWD/../push.cfg\" git push origin", "unread", "tag"),
               ("C=-c; K=incl; git \"$C\" \"${K}ude.path=$PWD/../push.cfg\" push origin", "unread", "tag"),
               ("S=push; git $S --mirror origin", "unread", "tag"),
               ("O=--tags; git push $O origin", "unread", "tag"),
               ("O=$(printf -- -%s S); git commit $O -q -m x", "unread", "signatur"),
               # local review of 97b77526 (P1, open at main): a brace expansion of more words than the gate reads
               # (_SH_BRACE_MAX = 64) is a word it cannot read; seven groups of {,} make 128 words
               ("git push --ta{,}{,}{,}{,}{,}{,}{,} origin", "unread", "tag"),
               ("git push --mirro{,}{,}{,}{,}{,}{,}{,} origin", "unread", "tag"),
               ("git commit --gpg{,}{,}{,}{,}{,}{,}{,} -q -m x", "unread", "signatur"),
               # local review of 87bc823c (P1, open at main): a brace form the gate does not model, a range with a step
               ("git push --ta{g..g..1} origin", "unread", "tag"),
               ("git push --mirro{r..r..1} origin", "unread", "tag"),
               ("git commit --gpg-sig{n..n..1} -q -m x", "unread", "signatur"),
               # the program itself formed by a brace the gate does not model
               ("gi{t..t..1} push --tags origin", "unread", "tag"),
               # local review of 516d4490 (P1, open at main): a word bash forms from file names
               ("/usr/bin/g[i]t push --mirror origin", "unread", "tag"),
               ("/usr/bin/g[i]t push --tags origin", "unread", "tag"),
               ("/usr/bin/g[i]t commit -S -q -m x", "unread", "signatur"),
               ("touch ./--tags; git push --ta[g]s origin", "unread", "tag"),
               # local review of f9c16c41 (P1, open at main): a pattern the shell forms after the brace expansion, and
               # one a program reads again
               ("/usr/bin/{g..g}[i]t push --mirror origin", "unread", "tag"),
               ("/usr/bin/{g..g}[i]t push --tags origin", "unread", "tag"),
               ("/usr/bin/{g..g}[i]t commit -S -q -m x", "unread", "signatur"),
               ("bash -c '/usr/bin/g[i]t push --mirror origin'", "unread", "tag"),
               # local review of 3c79f5e0 (P1, open at main): the same test as _release_assembled for a text read again,
               # a command substitution and a runner the shell joins
               ('echo "$(/usr/bin/g[i]t push --mirror origin)"', "unread", "tag"),
               ('echo "$(/usr/bin/g[i]t push --tags origin)"', "unread", "tag"),
               ('echo "$(/usr/bin/g[i]t commit -S -q -m x)"', "unread", "signatur"),
               ("b''ash -c '/usr/bin/g[i]t push --mirror origin'", "unread", "tag"),
               # local review of c3ae95a6 (P1, open at main): a pattern in the place of the program, here a program of
               # git's exec path
               ('"$(git --exec-path)"/g[i]t-push --mirror origin', "unread", "tag"),
               ('"$(git --exec-path)"/g[i]t-push --tags origin', "unread", "tag"),
               ('"$(git --exec-path)"/g[i]t-commit $(printf -- -%s S) -q -m x', "unread", "signatur")]
#: The named cost of that rule: a plain refspec set by configuration is held back although git opens no door with it.
OVERCOUNT = [("git -c remote.origin.push=HEAD:refs/heads/main push origin", "force"),
             ("git -c remote.origin.pushurl=../origin.git push origin claude/x", "force"),
             ("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=remote.origin.push GIT_CONFIG_VALUE_0=HEAD:refs/heads/main "
              "git push origin", "force"),
             ("GIT_CONFIG_GLOBAL=/dev/null git push origin claude/x", "force"),
             ("git commit -q -m 'fix the HOME page'", "force"),
             # the cost of the rule for a pattern in the place of the program
             ("./build*.sh", "unread"),
             # the cost of the class rule for a word the gate cannot read: a plain read of $HOME, a value of -c, an
             # exported value; git opens no door with any of them
             ("git -C \"$HOME\"/repo push origin claude/x", "unread"), ("git -C ${HOME}/repo push origin claude/x", "unread"),
             ("git -c user.name=\"$USER\" push origin claude/x", "unread"),
             ("export GIT_AUTHOR_NAME=\"$USER\"; git push origin claude/x", "unread")]
#: No oracle runs these: git refuses `push --forc` as ambiguous, and a tag made locally does not reach the remote the
#: oracle reads. Both still hold a release back.
WORDS_ONLY = [("O=$(printf -- --%s admin); gh pr merge 388 -R b7n0de/proofbundle --squash --match-head-commit "
               "0123456789abcdef0123456789abcdef01234567 $O", "unread"),
              ("C=publish; uv $C", "unread"),
              ("/usr/lib/git-core/g[i]t-push --mirror origin", "unread"),
              ("env {X{0..0..1}=,gh} release create v1 -R b7n0de/proofbundle --notes x", "release"),
              ("env {X{0..0..1}=,sudo} cat /etc/hostname", "root"),
              ("git push --forc origin claude/x", "force"), ("git -c 'user.name=John Doe' tag v2", "tag"),
              ("/usr/lib/git-core/git-push --force origin HEAD:refs/heads/main", "force")]
SPELLING_COUNTERS = ["git commit -s -m x", "git commit -qm x", "git commit -am x", "git commit --no-gpg-sign -m x",
                     "git push -u origin claude/x", "git push --set-upstream origin claude/x",
                     "git push --no-signed origin claude/x", "git push --no-force origin claude/x",
                     "git -c 'user.name=John Doe' push origin claude/x",
                     _TOPIC + "git -c branch.main.mergeOptions=--no-ff merge --no-edit topic",
                     # an expansion in a line that runs no door program is no door
                     "printf '%s\\n' \"$PWD\" > /dev/null",
                     # a brace without a comma or a range is a word of its own, also in a line of git
                     "git log -1 --format='%H {x}'",
                     # a pattern in quotes and the test command [ are no words formed from file names
                     "git log -1 --grep='fix*'", "[ -f README ] || git status --short",
                     # a program that reads the text again, without a pattern in it
                     "bash -c 'git status --short'", 'echo "$(date)"',
                     # a pattern as an argument of a program that is no door program
                     "ls ./*.md > /dev/null"]


def _git_oracle(tmp_path: pathlib.Path, line: str) -> set:
    """What git does with `line`, in a repository of its own: `signatur` when it asked the signing program,
    `tag` when a tag arrived at the remote, `force` when the remote's main, which had diverged, now holds ours."""
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_CONFIG_SYSTEM": os.devnull, "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
    marker = tmp_path / "signed"
    program = tmp_path / "gpg"
    program.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n")
    program.chmod(0o700)
    bare, src = tmp_path / "origin.git", tmp_path / "src"
    # files a line may bring in as configuration (CONFIG_HELD): one that pushes the tags, one that signs each commit
    push_cfg = '[remote "origin"]\n\tpush = refs/tags/*:refs/tags/*\n'
    (tmp_path / "push.cfg").write_text(push_cfg)
    (tmp_path / "sign.cfg").write_text("[commit]\n\tgpgsign = true\n")
    (tmp_path / "cfg_home").mkdir()
    (tmp_path / "cfg_home" / ".gitconfig").write_text(push_cfg)
    (tmp_path / "xdg" / "git").mkdir(parents=True)
    (tmp_path / "xdg" / "git" / "config").write_text(push_cfg)

    def run(*args, cwd=src):
        subprocess.run(["git", *args], cwd=str(cwd), env=env, capture_output=True, check=True, timeout=60)

    run("init", "-q", "--bare", str(bare), cwd=tmp_path)
    run("config", "receive.certNonceSeed", "s", cwd=bare)
    run("init", "-q", "-b", "main", str(src), cwd=tmp_path)
    for key, value in (("user.name", "t"), ("user.email", "t@t"), ("gpg.program", str(program))):
        run("config", key, value)
    (src / "f").write_text("1")
    run("add", "f")
    run("commit", "-q", "-m", "one")
    run("push", "-q", str(bare), "main")
    run("commit", "-q", "--amend", "-m", "one again")      # the remote's main has diverged from ours
    run("tag", "-a", "v1", "-m", "v1")
    run("branch", "claude/x")
    run("remote", "add", "origin", str(bare))
    run("remote", "add", "o(r)", str(bare))                 # a remote name git takes once it is quoted
    (src / "f").write_text("2")
    (src / "g").write_text("g")
    run("add", "g")
    subprocess.run(["bash", "-c", line], cwd=str(src), env=env, capture_output=True, timeout=60, check=False)
    tags = subprocess.run(["git", "for-each-ref", "refs/tags"], cwd=str(bare), env=env, capture_output=True,
                          timeout=60, check=False).stdout.strip()
    ours, theirs = (subprocess.run(["git", "rev-parse", "-q", "--verify", "refs/heads/main"], cwd=str(d), env=env,
                                   capture_output=True, timeout=60, check=False).stdout.strip() for d in (src, bare))
    return {name for name, seen in (("signatur", marker.exists()), ("tag", bool(tags)), ("force", ours == theirs))
            if seen}


#: The pieces whose repetition made a search of the release reader rescan the rest of the line from each start (local
#: review of 770a375a, P2, measured with lines of 200000 characters: each took seconds to minutes where main took
#: milliseconds).
_RUNTIME_PIECES = ["remote.", "branch.", "includeif.", "-c ", " -c a", "--config-env ", "${", "$(", "bash -c "]


@pytest.mark.parametrize("piece", _RUNTIME_PIECES)
def test_a_line_at_the_read_bound_is_read_in_time_and_held_back(piece):
    """At the bound the reader still reads the line, in a few seconds at most, and the signature the line names
    holds it back."""
    head = "git commit -S -m x # "
    command = head + piece * ((gate._RELEASE_READ_MAX - len(head)) // len(piece))
    assert len(command) <= gate._RELEASE_READ_MAX
    start = time.monotonic()
    door = gate._release_door_words(command)
    assert time.monotonic() - start < 20
    assert door is not None


@pytest.mark.parametrize("piece", _RUNTIME_PIECES)
def test_a_text_the_brace_expansion_makes_longer_than_the_bound_is_held_back_in_time(piece):
    """The bound holds for every text the reader searches (local review of c8736cd8, P2): six brace groups make 64
    words of a line under the bound, and the searches ran on the text of 985684 characters the expansion made."""
    head = "gi{t..t} commit -S -m x # " + "{,}" * 6
    command = head + piece * ((gate._RELEASE_READ_MAX - len(head)) // len(piece))
    assert len(command) <= gate._RELEASE_READ_MAX
    start = time.monotonic()
    door = gate._release_door_words(command)
    assert time.monotonic() - start < 20
    assert door is not None


#: The heads the second runtime probe put before each piece: one whose door the words name at once, one whose words main
#: reads as no door, and one whose brace expansion makes the line longer (local review of d9ff9a8c and the probe of
#: 2026-11-11, where a word of stars, a word of `${` and a word of `{` and commas took seconds to minutes).
_RUNTIME_HEADS = ["git commit -S -m x # ", "en''v /usr/lib/git-core/g[i]t-push --mirror z # ",
                  "gi{t..t} commit -S -m x # " + "{,}" * 6]
_RUNTIME_WORD_PIECES = _RUNTIME_PIECES + ["*", "**", "*a", "{", ",", "{,", "?"]


@pytest.mark.parametrize("head", _RUNTIME_HEADS)
@pytest.mark.parametrize("piece", _RUNTIME_WORD_PIECES)
def test_every_head_and_piece_at_the_read_bound_is_read_in_time(head, piece):
    """Each head with each piece up to the bound is read within 20 seconds of elapsed time: the bound of the line, of
    every text the reader searches and of every word it hands to a helper keep each named input below that limit. This
    is a regression check per case, not a comparison with main. The two lines of the review of d9ff9a8c are among them:
    stars after `en''v ... g[i]t-push`, and a word of `{` and commas after six brace groups."""
    command = head + piece * ((gate._RELEASE_READ_MAX - len(head)) // len(piece))
    assert len(command) <= gate._RELEASE_READ_MAX
    start = time.monotonic()
    gate._release_door_words(command)
    assert time.monotonic() - start < 20


def test_the_two_lines_of_the_review_of_d9ff9a8c_are_read_in_time():
    """The lines the review of d9ff9a8c measured beyond the hook's 120 seconds and 55 seconds, cut to the bound, are read
    within a few seconds (local review of 7411ab31: a test that asked for unread in both failed). The first line names
    no door at main, `en''v` before a pattern in the program word is a form open at main (the list for plugin 0.4.1);
    its comment word is longer than _RELEASE_WORD_MAX and holds it back as unread, a release frees less. The second
    keeps the door signatur of its `commit -S`, as at main."""
    for head, tail, door in (("en''v /usr/lib/git-core/g[i]t-push --mirror ../ziel.git # ", "*", "unread"),
                             ("gi{t..t} commit -S -m x # " + "{,}" * 6 + "{", ",", "signatur")):
        command = head + tail * (gate._RELEASE_READ_MAX - len(head) - 1) + ("z" if tail == "*" else "")
        assert len(command) <= gate._RELEASE_READ_MAX
        start = time.monotonic()
        assert gate._release_door_words(command) == door
        assert time.monotonic() - start < 20


#: A bracket expression of two ranges that meet at a star, `#-*` and `*-z`, which together take every lowercase letter:
#: joining the stars in the written pattern made it `[#-*-z]` and lost them (local review of 7411ab31, P1).
_TWO_RANGES_AT_A_STAR = "[#-**-z]"


@pytest.mark.parametrize("name", sorted(gate._RELEASE_ROOT) + sorted(gate._RELEASE_SIGNERS))
@pytest.mark.parametrize("front", ["en''v ", "", "env "])
def test_a_range_that_ends_at_a_star_keeps_the_door_of_a_root_or_signer_program(name, front):
    """Every root and signer program written with its second letter as two ranges that meet at a star keeps its door,
    as at main (local review of 7411ab31: `en''v /usr/bin/s[#-**-z]do true` read root at main and nothing at the
    head)."""
    line = f"{front}/usr/bin/{name[0]}{_TWO_RANGES_AT_A_STAR}{name[2:]} --detach-sign x"
    assert gate._release_door_words(line) == ("root" if name in gate._RELEASE_ROOT else "signatur")


def test_a_comment_word_of_wide_ranges_is_held_back_in_time():
    """A comment word of 84 ranges up to U+10FFFF, 255 characters, under both bounds (local review of 7411ab31, P2: the
    comparison of D102 listed every character of each range and ran beyond the hook's 120 seconds, where main answered
    at once). The reader does not ask the comparison about a word with a bracket expression; it holds the line back as
    unread at once, a release frees less."""
    command = "en''v /usr/lib/git-core/g[i]t-push --mirror ../ziel.git # [" + "a-\U0010ffff" * 84 + "]z"
    assert len(command.split()[-1]) <= gate._RELEASE_WORD_MAX
    start = time.monotonic()
    assert gate._release_door_words(command) == "unread"
    assert time.monotonic() - start < 20


@pytest.mark.parametrize("word", [
    "*[" + "a-b" * 85 + "]",
    "*[" + "".join(chr(c) + "-" + chr(c) for c in range(0x10000, 0x10000 + 160, 2)) + "]",
    "[a-\U0010ffff]" * 18,
])
def test_a_pattern_word_with_a_bracket_or_a_backslash_is_not_handed_to_the_comparison(word):
    """The local reviews of 75b89f17 to 4673bbd4 found time and memory beyond main in the comparison of D102 for words
    of many ranges, many disjoint ranges and wide ranges. The reader does not ask the comparison about a word with a
    bracket expression or a backslash at all: it may name a door program, and the line is held back as unread. The
    comparison of D102 stays as at main (proofbundle_secrets.py has no change in this pull request)."""
    assert gate._release_pattern_may_name(gate._secrets(), word) is True
    assert gate._release_door_words("echo x # " + word) == "unread"


def test_a_pattern_part_with_a_backslash_is_not_handed_to_the_comparison():
    """A part with a backslash is held as one that may name a door program, unread to the comparison. In a line the
    shell reads `\\*` as a star of text, not a pattern, and so does the reader: `echo x # g\\*t` holds no pattern word
    and names no door."""
    assert gate._release_pattern_may_name(gate._secrets(), "g\\*t") is True
    assert gate._release_door_words("echo x # g\\*t") is None


@pytest.mark.parametrize("word, door", [("g**i***t", True), ("*w*i*n*e", True), ("****", True), ("a*b*c", False),
                                        ("x?z", False), ("?h", True), ("*" * 256, True), ("*" * 257, True)])
def test_a_pattern_word_without_a_bracket_is_compared_with_its_stars_joined(word, door):
    """A pattern word without a bracket expression and without a backslash is compared with each run of stars joined to
    one star, which takes the same names there; `g**i***t` may be git, `*w*i*n*e` may be twine, `a*b*c` names no door
    program. A word longer than _RELEASE_WORD_MAX may name one."""
    start = time.monotonic()
    assert gate._release_pattern_may_name(gate._secrets(), word) is door
    assert time.monotonic() - start < 5


@pytest.mark.parametrize("line", [
    "*" * 16000,
    "/usr/bin/" + "*" * 16000 + " push --tags z",
    "g" + "*" * 16000 + "t push --tags z",
    "env " + "*" * 16000 + " push --mirror z",
    "su" + "*a" * 8000 + "do id",
    "?" * 16000 + " commit -S -m x",
])
def test_a_program_word_of_a_long_pattern_is_held_back_in_time(line):
    """A program word of a long pattern (third runtime probe of 2026-11-11: 16000 stars took the comparison of D102
    beyond 60 seconds, at main as well) holds the line back within a few seconds."""
    assert len(line) <= gate._RELEASE_READ_MAX
    start = time.monotonic()
    assert gate._release_door_words(line) is not None
    assert time.monotonic() - start < 20


@pytest.mark.parametrize("line", ["/usr/bin/s*****u***do id", "/usr/bin/g**i***t commit -S -m x"])
def test_a_program_word_of_several_runs_of_stars_keeps_its_door(line):
    """A program word of several runs of stars that may be sudo or git keeps its door, by the comparison of D102 as at
    main."""
    assert gate._release_door_words(line) is not None


#: The keys of the readers of a configuration and the fillers that may follow one of them up to the read bound (local
#: review of 0692fed6: `-c` and 16000 blanks took 1.9 seconds where main took five thousandths, two parts of one
#: expression took the same blanks).
_CONFIG_KEYS = ["-c ", "--config-env ", "-c=", "--config-env=", "-c", "remote.", "branch.", "include.", "includeif.",
                "push.", "GIT_CONFIG_KEY_0", "GIT_CONFIG_PARAMETERS"]
_CONFIG_FILLERS = [" ", "\t", "=", "a", ".", ",", "-", "/", " =", "\n"]


@pytest.mark.parametrize("key", _CONFIG_KEYS)
@pytest.mark.parametrize("filler", _CONFIG_FILLERS)
def test_a_configuration_key_followed_by_a_long_run_is_read_in_time(key, filler):
    """Each key of a configuration reader, followed by a run of one filler up to the read bound and a last letter, is
    read within a few seconds; main read each at once."""
    head = "git push origin claude/x # " + key
    command = head + filler * ((gate._RELEASE_READ_MAX - len(head) - 1) // len(filler)) + "x"
    assert len(command) <= gate._RELEASE_READ_MAX
    start = time.monotonic()
    gate._release_door_words(command)
    assert time.monotonic() - start < 5


@pytest.mark.parametrize("piece", [" -c a", " -c ", " --config-env a", " -c a*", " -c a;", " -c=a", " -c\ta"])
def test_the_reader_of_a_configuration_option_reads_each_key_stretch_once(monkeypatch, piece):
    """The reader of a key of `-c` or `--config-env` reads each stretch of a key once, also where thousands of options
    share it (local review of a87d2034: `-c a` repeated up to the bound read 26.7 million characters of keys, ten times
    the time main took). Counted, not timed: the characters the reader of a key text reads stay within the line."""
    read = [0]

    class Counted:
        def __init__(self, inner):
            self.inner = inner

        def match(self, text, pos):
            m = self.inner.match(text, pos)
            read[0] += m.end() - pos
            return m
    monkeypatch.setattr(gate, "_GIT_CONFIG_KEY_TEXT", Counted(gate._GIT_CONFIG_KEY_TEXT))
    line = ("git push origin claude/x # " + piece * 4000)[:gate._RELEASE_READ_MAX - 1] + "x"
    gate._git_config_unread_option(line)
    assert read[0] <= len(line), (read[0], len(line))


def test_the_readers_of_push_and_include_keys_find_what_the_former_expressions_found():
    """Property: for 40000 short lines drawn from the parts of the keys of a push and of an include, in both cases and
    with line breaks, the readers that take the first start and the last ending of a line give the door and the include
    the former lazy expressions gave (local review of aa29242d), which read short lines in time."""
    import random
    import re
    push = re.compile(r"(push\.followtags)|remote\.[^\n]*?\.(?:mirror|push)|branch\.[^\n]*?\.(?:merge|remote|pushremote)(?![a-z])|"
                      r"push\.default(?![a-z])|remote\.pushdefault(?![a-z])", re.I)
    include = re.compile(r"\binclude(?:if\.[^\n]*?)?\.path(?![a-z])", re.I)
    rng = random.Random(510)
    parts = ["remote.", "branch.", "push.", "followtags", "include", "includeif.", "if.", ".path", ".push", ".mirror",
             ".merge", ".remote", "pushremote", "default", "pushdefault", "\n", "x", "s", ".", "REMOTE.", ".PUSH", " ",
             "BRANCH.", ".Path", "pushDefault"]
    for _ in range(40000):
        line = "".join(rng.choice(parts) for _ in range(rng.randint(0, 8)))
        found = push.search(line)
        assert gate._git_push_config_kind(line) == (None if not found else "tag" if found.group(1) else "force"), repr(line)
        assert gate._git_config_file_key(line) == bool(include.search(line)), repr(line)


@pytest.mark.parametrize("piece", ["remote.", "branch.", "includeif.", "include", "remote.x", "branch.x.",
                                   "remote.\n", ".push", ".merge"])
@pytest.mark.parametrize("head", ["git commit -S -m x # ", "git push origin claude/x # "])
def test_a_key_start_repeated_up_to_the_read_bound_is_read_in_time(head, piece):
    """A start of a key repeated up to the read bound is read in time (local review of aa29242d: `remote.` repeated took
    0.165 seconds where main took 0.00018, the lazy expression searched the rest of the line from each start)."""
    command = head + piece * ((gate._RELEASE_READ_MAX - len(head)) // len(piece))
    start = time.monotonic()
    gate._release_door_words(command)
    assert time.monotonic() - start < 5


def test_the_marker_of_expansions_gives_what_the_expression_gives():
    """Property: for 40000 short lines drawn from the openers and closers of every expansion the gate does not resolve,
    the marker that reads a line once gives the text `_RELEASE_EXPANSION.sub` gives (scaling probe of round 33: the
    expression searched from each opener to the end of the line where no closer came)."""
    import random
    rng = random.Random(510)
    parts = ["$", "{", "}", "(", ")", "((", "))", "`", "<", ">", "<(", ">(", "$(", "${", "$((", "a", "_", "1", "@", "#",
             "?", "!", "-", "*", " ", "\n", "x9", "$$", "'", '"']
    for _ in range(40000):
        line = "".join(rng.choice(parts) for _ in range(rng.randint(0, 12)))
        assert gate._release_mark_expansions(line) == gate._RELEASE_EXPANSION.sub(gate._RELEASE_UNKNOWN, line), repr(line)


@pytest.mark.parametrize("piece", ["${", "$(", "$((", "<(", ">(", "`", "$( ", "${a", "$((a)", "$(()"])
@pytest.mark.parametrize("head", ["git commit -S -m x # ", "git push origin claude/x # ", "", "echo x # "])
def test_an_opener_without_its_closer_repeated_up_to_the_read_bound_is_read_in_time(head, piece):
    """An opener of an expansion without its closer, repeated up to the read bound, is read in time: the marker reads the
    line once."""
    command = head + piece * ((gate._RELEASE_READ_MAX - len(head)) // len(piece))
    start = time.monotonic()
    gate._release_door_words(command)
    assert time.monotonic() - start < 5


@pytest.mark.parametrize("line", ["echo x # " + "a* " * 5000, "echo x # " + "/d/a* " * 2500,
                                  "echo " + " ".join(f"/p{i}/x?y" for i in range(1500))])
def test_each_pattern_name_is_compared_once_however_often_it_stands(monkeypatch, line):
    """A pattern name that stands thousands of times in a line, as itself or as the last part of different paths, is
    compared once with the door programs (local review of 19182f90: `a* ` repeated up to the read bound made 109160
    comparisons, 0.16 seconds where main took 0.013). Counted at the comparison of D102."""
    sec = gate._secrets()
    calls = [0]
    inner = sec.may_match

    def counted(pattern, name):
        calls[0] += 1
        return inner(pattern, name)
    monkeypatch.setattr(sec, "may_match", counted)
    gate._release_door_words(line)
    assert calls[0] <= 2 * len(gate._RELEASE_DOOR_PROGRAMS), calls[0]


def test_the_reader_of_a_configuration_option_finds_the_lines_the_former_expression_found():
    """Property: for 30000 short lines drawn from the characters that make an option, a separator, a key and its end,
    the linear reader of a key of `-c` or `--config-env` answers as the former expression did (local review of
    0692fed6), which reads short lines in time."""
    import random
    import re
    former = re.compile(r"(?:^|[\s;&|(])(?:-c|--config-env)[\s=]+[^=\n;&|]*?[" + gate._RELEASE_UNKNOWN + r"*?\[]")
    rng = random.Random(510)
    parts = ["-c", "--config-env", " ", "=", "\n", ";", "&", "|", "(", "a", "*", "?", "[", gate._RELEASE_UNKNOWN, "\t",
             "x.y", "-"]
    for _ in range(30000):
        line = "".join(rng.choice(parts) for _ in range(rng.randint(0, 12)))
        assert gate._git_config_unread_option(line) == bool(former.search(line)), repr(line)


def _former_glob_words(text):
    """_release_glob_words as it stood at 0692fed6, which read `text[i + 1:].split()` at every character."""
    words, cur = [], []
    glob, quote, i = False, "", 0

    def close():
        nonlocal cur, glob
        if cur:
            words.append(("".join(cur), glob))
        cur, glob = [], False
    while i < len(text):
        c = text[i]
        if quote != "'" and c == "\\" and i + 1 < len(text):
            cur.append(text[i + 1])
            i += 2
            continue
        if c in "'\"" and quote in ("", c):
            quote = "" if quote else c
            i += 1
            continue
        if not quote and (c.isspace() or c in ";&|()<>"):
            close()
            i += 1
            continue
        if not quote and (c == "*" or (c == "?" and not (cur and cur[-1] == "$")) or
                          (c == "[" and "]" in text[i + 1:].split()[0] if text[i + 1:].split() else False)):
            glob = True
        cur.append(c)
        i += 1
    close()
    return [w for w, g in words if g]


def test_the_glob_words_are_the_ones_the_former_reader_found():
    """Property: for 30000 short lines drawn from brackets, blanks, quotes, escapes and pattern characters, the reader of
    pattern words with its table of closing brackets finds the words the former reader found (second runtime probe of
    round 31: the former reader read the rest of the line at every character)."""
    import random
    rng = random.Random(510)
    parts = ["[", "]", " ", "\t", "a", "*", "?", "$", "'", '"', "\\", ";", "(", "x]", "[ ]", "\n"]
    for _ in range(30000):
        line = "".join(rng.choice(parts) for _ in range(rng.randint(0, 12)))
        assert gate._release_glob_words(line) == _former_glob_words(line), repr(line)


@pytest.mark.parametrize("piece", ["[", "[ ", " [", "[a", "]", " =", "a "])
def test_a_line_of_brackets_and_blanks_up_to_the_read_bound_is_read_in_time(piece):
    """A line of brackets and blanks up to the read bound is read in time; the reader of pattern words reads the rest of
    the line once, not at each character."""
    command = "git push origin claude/x # " + piece * ((gate._RELEASE_READ_MAX - 30) // len(piece))
    start = time.monotonic()
    gate._release_door_words(command)
    assert time.monotonic() - start < 5


@pytest.mark.parametrize("piece", _RUNTIME_PIECES + ["a"])
def test_a_line_above_the_read_bound_is_held_back_unread_at_once(piece):
    """Above the bound the line is not read: it is the door unread at once, which no card frees. With "a" the line
    names no door, the named cost of the bound."""
    command = "git commit -S -m x # " + piece * (gate._RELEASE_READ_MAX // len(piece) + 1)
    start = time.monotonic()
    assert gate._release_door_words(command) == "unread"
    assert time.monotonic() - start < 2
    assert gate._release_door_words("echo " + "a" * gate._RELEASE_READ_MAX) == "unread"


@pytest.mark.parametrize("command, door", SPELLINGS + KEPT + KEPT_WORDS + WORDS_ONLY + [c[:2] for c in CONFIG_HELD] +
                         OVERCOUNT)
def test_every_spelling_git_takes_is_the_door_it_opens(command, door):
    assert gate._release_door(command, gate.Outcome("deny", "", [])) == door, command


@pytest.mark.parametrize("command, _door, effect", CONFIG_HELD)
def test_oracle_git_opens_a_door_with_a_refspec_set_by_configuration(tmp_path, command, _door, effect):
    assert effect in _git_oracle(tmp_path, command), command


@pytest.mark.parametrize("command, _door", OVERCOUNT)
def test_oracle_the_named_cost_git_opens_no_door_with_a_plain_configured_refspec(tmp_path, command, _door):
    assert _git_oracle(tmp_path, command) == set(), command


@pytest.mark.parametrize("command", SPELLING_COUNTERS)
def test_control_a_spelling_that_opens_no_door_stays_free(command):
    assert gate._release_door(command, gate.Outcome("deny", "", [])) is None, command


@pytest.mark.parametrize("command, door", SPELLINGS + KEPT)
def test_oracle_git_does_what_the_door_of_the_spelling_names(tmp_path, command, door):
    assert door in _git_oracle(tmp_path, command), command


@pytest.mark.parametrize("command", SPELLING_COUNTERS)
def test_oracle_git_opens_no_door_for_a_counter_case(tmp_path, command):
    assert _git_oracle(tmp_path, command) == set(), command
