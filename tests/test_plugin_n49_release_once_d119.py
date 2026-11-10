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
# The words of a door were compared in their full spelling only. git takes a long option by any prefix that names it
# alone, a short one inside a bundle, and a push's targets also from its configuration; each line below passed a
# release at 5bdf225d, and each runs here once more through real git, which shows that git does what the door names.

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
#: Lines main already read as doors, kept as cases: the reading of git's exec path must not take an option for a
#: program (local review of 566b7d16, P1, a regression of the fourth form of this rule).
KEPT = [("git commit -S/tmp/git-key -m x", "signatur"), ("git commit --gpg-sign=/tmp/git-key -m x", "signatur"),
        # at the limit of the brace reader (six groups, 64 words) the words are read and keep their own door
        ("git push --ta{,}{,}{,}{,}{,}{,} origin", "tag"), ("git push --mirro{,}{,}{,}{,}{,}{,} origin", "force"),
        ("git commit --gpg{,}{,}{,}{,}{,}{,} -q -m x", "signatur")]
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
               ("git commit --gpg-sig{n..n..1} -q -m x", "unread", "signatur")]
#: The named cost of that rule: a plain refspec set by configuration is held back although git opens no door with it.
OVERCOUNT = [("git -c remote.origin.push=HEAD:refs/heads/main push origin", "force"),
             ("git -c remote.origin.pushurl=../origin.git push origin claude/x", "force"),
             ("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=remote.origin.push GIT_CONFIG_VALUE_0=HEAD:refs/heads/main "
              "git push origin", "force"),
             ("GIT_CONFIG_GLOBAL=/dev/null git push origin claude/x", "force"),
             ("git commit -q -m 'fix the HOME page'", "force"),
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
                     "git log -1 --format='%H {x}'"]


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
