"""The hand-over of a push from Level 1 to Level 2 (owner adoption of review round 18, DECISIONS.md D33,
plugins/proofbundle/DESIGN_gegenstelle.md section 7).

Level 1 does not read the remote, so since R9-1 every push asks at the destination check. A push whose one open reason
is the default destination case, whose source evidence is valid, whose transport a person approved and for which a bound
Level 2 is installed is handed over instead: Level 1 writes a one-time record and a pointer and makes no permission
decision, and git's pre-push hook checks the actual update against the expected order before it judges the evidence.

Through git itself, against local bare repositories, the catch cases of review round 18: a valid fast-forward, a wrong
done check, missing or falsified evidence, an invalid intermediate commit, a D20 change, the candidate alone, mixed
multiple updates, a new ref, an invalid hand-over, a disabled hook, an unexpected plugin version, a no-op, an abort and
a later server error; and the transport that is not approved asks before its effects. Under Codex Level 1 is unchanged.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

import pytest

import test_plugin_gate_n2c_push_done as base

gate = base.gate
GATE = base.GATE
PLUGIN = GATE.parent.parent
#: The pointer schema of D33, written out so that the module is collected where the gate does not know it yet.
POINTER_SCHEMA = "proofbundle-plugin/handover-pointer/v1"
pytestmark = pytest.mark.skipif(shutil.which("git") is None or shutil.which("sh") is None,
                                reason="git or sh is not installed")


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


@pytest.fixture
def env(tmp_path: pathlib.Path) -> dict:
    """PATH with a `uv` that runs the plugin server and a `python3` that is this interpreter, as the hook git starts
    runs the gate with it; the gate directory and the log in the test folder."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "uv").write_text(f'#!/bin/sh\nwhile [ "$1" != "--script" ]; do shift; done\nshift\n'
                                f'exec "{sys.executable}" "$@"\n', encoding="utf-8")
    (bin_dir / "python3").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    for name in ("uv", "python3"):
        (bin_dir / name).chmod(0o755)
    package_root = str(pathlib.Path(base.proofbundle.__file__).resolve().parent.parent)
    clean = dict(os.environ, PATH=os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]))
    clean["PYTHONPATH"] = os.pathsep.join(p for p in (package_root, os.environ.get("PYTHONPATH")) if p)
    clean["PROOFBUNDLE_GATE_DIR"] = str(tmp_path / "gate-dir")
    clean["CLAUDE_PLUGIN_DATA"] = clean["PLUGIN_DATA"] = str(tmp_path / "logs")
    return clean


# --- set-up -----------------------------------------------------------------------------------------------------

def _install(repo: pathlib.Path, gate_path: pathlib.Path = GATE) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(gate_path), "install-pre-push", "--repo", str(repo)],
                          capture_output=True, text=True, timeout=120, check=False)


def _approve(env: dict, repo: pathlib.Path, remote: str = "origin") -> dict:
    """What a person does once: the approval mode with-approvals, and the transport entry transport-digest prints."""
    gate_dir = pathlib.Path(env["PROOFBUNDLE_GATE_DIR"])
    gate_dir.mkdir(exist_ok=True)
    (gate_dir / "mode").write_text("with-approvals\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, "-I", str(GATE), "transport-digest", "--repo", str(repo), "--remote", remote],
                          capture_output=True, text=True, env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    digest, _, entry = proc.stdout.partition("\n")
    entry = json.loads(entry)
    assert entry["transport_digest"] == digest
    (gate_dir / gate.TRANSPORTS_FILE).write_text(json.dumps([entry]), encoding="utf-8")
    return entry


def _repo(tmp_path: pathlib.Path, env: dict, case: str = "valid", install: bool = True,
          approve: bool = True) -> base.Repo:
    """A repository whose main tracks origin/main, with evidence at every commit and a done check, one commit of work
    the push sends (a fast-forward of the remote's main), and the receipt of `case`."""
    r = base.Repo(tmp_path, evidence=True)
    r.make(case)
    if install:
        assert _install(r.path).returncode == 0
    if approve:
        _approve(env, r.path)
    return r


def _level1(env: dict, repo: pathlib.Path, command: str = "git push origin main", host: str = "claude"):
    return base._level1(env, repo, host=host, command=command)


def _push(env: dict, repo: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    """A plain `git push` as the agent runs it: no `-c`, so git hands the hook nothing the binding did not see."""
    return subprocess.run(["git", "-C", str(repo), "push", *(args or ("origin", "main"))], capture_output=True,
                          text=True, env=env, timeout=240, check=False)


def _remote(tmp_path: pathlib.Path, ref: str = "refs/heads/main") -> str | None:
    """The object of exactly this ref on the remote. `rev-parse refs/heads/main` would follow git's lookup rules and
    name refs/heads/refs/heads/main where main is missing."""
    out = base._git(tmp_path / "remote.git", "show-ref", "--verify", "--hash", ref, check=False)
    return out.stdout.strip() or None


def _pointer(repo: pathlib.Path) -> pathlib.Path:
    return repo / ".git" / gate.HANDOVER_POINTER


def _records(env: dict) -> list[pathlib.Path]:
    folder = pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / "handover"
    return sorted(folder.iterdir()) if folder.exists() else []


def _decision(answer: dict) -> str | None:
    return answer["hookSpecificOutput"].get("permissionDecision")


def assert_handed_over(answer: dict, entry: dict) -> None:
    assert _decision(answer) is None, answer
    assert (entry["verdict"], entry["decision"], entry["reason_ids"]) == ("handover", "none", ["handed_over"]), entry
    assert "hands this push over to Level 2" in answer["systemMessage"], answer


def assert_asked_without_handover(answer: dict, entry: dict, why: str) -> None:
    assert _decision(answer) == "ask", answer
    assert entry["reason_ids"] == ["push_not_measured"], entry
    assert "No hand-over to Level 2" in answer["systemMessage"] and why in answer["systemMessage"], answer


# --- 1. the valid fast-forward ----------------------------------------------------------------------------------

def test_a_valid_fast_forward_is_handed_over_and_level_2_moves_the_remote(env, tmp_path):
    r = _repo(tmp_path, env)
    before = _remote(tmp_path)
    answer, entry = _level1(env, r.path)
    assert_handed_over(answer, entry)
    assert _pointer(r.path).exists() and len(_records(env)) == 1
    proc = _push(env, r.path)
    assert proc.returncode == 0, proc.stderr
    assert _remote(tmp_path) == base._rev(r.path, "HEAD") != before
    assert "checked the update set of hand-over" in proc.stderr and "no successful remote update" in proc.stderr
    assert not _pointer(r.path).exists()
    assert [p.name.endswith(".json.consumed") for p in _records(env)] == [True], "the record is consumed"


def test_the_record_names_the_expected_order_and_the_binding(env, tmp_path):
    r = _repo(tmp_path, env)
    _level1(env, r.path)
    record = json.loads(_records(env)[0].read_text(encoding="utf-8"))
    assert set(record) == gate._HANDOVER_KEYS and set(record["binding"]) == gate._BINDING_KEYS
    assert record["updates"] == [{"source": base._rev(r.path, "HEAD"), "dest": "refs/heads/main"}]
    assert (record["remote"], record["url"]) == ("origin", str(tmp_path / "remote.git"))
    assert record["expires"] - record["created"] == gate.HANDOVER_TTL_SECONDS
    assert record["binding"]["gate"] == str(GATE.resolve()) and record["binding"]["plugin_version"] == gate.GATE_VERSION
    assert oct(_records(env)[0].stat().st_mode & 0o777) == "0o600"


# --- 2. what stays an ask -----------------------------------------------------------------------------------------

def test_without_an_approved_transport_level_1_asks(env, tmp_path):
    r = _repo(tmp_path, env, approve=False)
    (pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / "mode").parent.mkdir(exist_ok=True)
    (pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / "mode").write_text("with-approvals\n", encoding="utf-8")
    answer, entry = _level1(env, r.path)
    assert_asked_without_handover(answer, entry, "the transport is not approved")
    assert "transport-digest" in answer["systemMessage"] and not _pointer(r.path).exists() and _records(env) == []


def test_the_transport_that_is_not_approved_asks_before_its_effects(env, tmp_path):
    """G18-1: a receive program configured after the approval changes the transport digest, so Level 1 asks before the
    program could run; approved in its turn, the same program runs, and only then is the push handed over."""
    r = _repo(tmp_path, env)
    marker = tmp_path / "receive-program-ran"
    program = tmp_path / "receive.sh"
    program.write_text(f'#!/bin/sh\necho ran >> "{marker}"\nexec git-receive-pack "$@"\n', encoding="utf-8")
    program.chmod(0o755)
    base._git(r.path, "config", "remote.origin.receivepack", str(program))
    answer, entry = _level1(env, r.path)
    assert_asked_without_handover(answer, entry, "the transport is not approved")
    assert not marker.exists() and not _pointer(r.path).exists()
    _approve(env, r.path)
    answer, entry = _level1(env, r.path)
    assert_handed_over(answer, entry)
    proc = _push(env, r.path)
    assert proc.returncode == 0 and marker.exists(), proc.stderr


def test_in_strict_mode_level_1_asks(env, tmp_path):
    r = _repo(tmp_path, env)
    (pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / "mode").write_text("strict\n", encoding="utf-8")
    answer, entry = _level1(env, r.path)
    assert_asked_without_handover(answer, entry, "the approval mode is strict")


def test_without_level_2_level_1_asks_and_names_install_pre_push_as_a_voluntary_step(env, tmp_path):
    r = _repo(tmp_path, env, install=False)
    answer, entry = _level1(env, r.path)
    assert_asked_without_handover(answer, entry, "no bound Level 2: no pre-push hook is installed")
    assert "install-pre-push" in answer["systemMessage"] and "optional" in answer["systemMessage"]
    assert not (r.path / ".git" / "hooks" / "pre-push").exists(), "the gate installs nothing"


@pytest.mark.parametrize("change", ["not executable", "foreign bytes", "a link"])
def test_a_disabled_or_foreign_hook_is_no_bound_level_2(env, tmp_path, change):
    r = _repo(tmp_path, env)
    hook = r.path / ".git" / "hooks" / "pre-push"
    if change == "not executable":
        hook.chmod(0o644)
    elif change == "foreign bytes":
        hook.write_text(hook.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")
    else:
        target = tmp_path / "hook-elsewhere"
        target.write_text(hook.read_text(encoding="utf-8"), encoding="utf-8")
        target.chmod(0o755)
        hook.unlink()
        hook.symlink_to(target)
    answer, entry = _level1(env, r.path)
    # A link inside the git directory also leaves Level 1's local rules comparison unmade (D5, the narrow contract), so
    # that reason comes first; the hook binding refuses the link on its own as well.
    assert_asked_without_handover(answer, entry, "the evidence rules differ" if change == "a link" else "no bound Level 2")
    binding, why = gate._bound_level2(str(hook.parent), time.monotonic() + 30)
    assert binding is None and why, why


def test_a_hook_that_runs_another_plugin_version_is_no_bound_level_2(env, tmp_path):
    """An unexpected plugin version: the hook was installed from an installed copy, so at push time it runs that copy's
    gate, not the gate Level 1 runs."""
    copy = tmp_path / "cache" / "proofbundle" / "proofbundle" / "0.3.0"
    shutil.copytree(PLUGIN, copy, ignore=shutil.ignore_patterns("__pycache__"))
    r = _repo(tmp_path, env, install=False)
    assert _install(r.path, copy / "hooks" / "proofbundle_gate.py").returncode == 0
    answer, entry = _level1(env, r.path)
    assert_asked_without_handover(answer, entry, "not this gate")


@pytest.mark.parametrize("settings, why", [
    ([("push.gpgSign", "true")], "push.gpgSign"), ([("push.gpgSign", "if-asked")], "push.gpgSign"),
    ([("push.gpgSign", "false"), ("push.gpgSign", "true")], "push.gpgSign"),
    ([("push.pushOption", "ci.skip")], "push.pushOption"),
    ([("push.pushOption", ""), ("push.pushOption", "ci.skip")], "push.pushOption")])
def test_the_configured_counterpart_of_an_excluded_option_is_no_hand_over(env, tmp_path, settings, why):
    """Lens 1, F3: push.gpgSign signs the push as --signed does, push.pushOption sends options as -o does."""
    r = _repo(tmp_path, env)
    for key, value in settings:
        base._git(r.path, "config", "--add", key, value)
    answer, entry = _level1(env, r.path)
    assert_asked_without_handover(answer, entry, why)
    assert not _pointer(r.path).exists() and _records(env) == []


@pytest.mark.parametrize("settings", [[("push.gpgSign", "true"), ("push.gpgSign", "false")],
                                      [("push.pushOption", "ci.skip"), ("push.pushOption", "")]])
def test_a_counterpart_turned_off_again_is_handed_over(env, tmp_path, settings):
    """git takes the last push.gpgSign, and an empty push.pushOption clears the list before it."""
    r = _repo(tmp_path, env)
    for key, value in settings:
        base._git(r.path, "config", "--add", key, value)
    _approve(env, r.path)   # the configuration changed after the approval of _repo; a person approves it as it is now
    answer, entry = _level1(env, r.path)
    assert_handed_over(answer, entry)


def test_a_git_wrapper_earlier_on_path_is_no_hand_over(env, tmp_path):
    """Lens 1, F1: a `git` earlier on PATH that pushes with --no-verify starts no Level 2, so it must keep the ask."""
    r = _repo(tmp_path, env)
    real = shutil.which("git")
    wrapper = pathlib.Path(env["PATH"].split(os.pathsep)[0]) / "git"
    wrapper.write_text(f'#!/bin/sh\nfor a in "$@"; do [ "$a" = push ] && exec "{real}" "$@" --no-verify; done\n'
                       f'exec "{real}" "$@"\n', encoding="utf-8")
    wrapper.chmod(0o755)
    answer, entry = _level1(env, r.path)
    assert_asked_without_handover(answer, entry, "is not byte for byte the git of its exec path")
    assert not _pointer(r.path).exists() and _records(env) == []


def test_a_link_to_the_real_git_earlier_on_path_is_handed_over(env, tmp_path):
    r = _repo(tmp_path, env)
    (pathlib.Path(env["PATH"].split(os.pathsep)[0]) / "git").symlink_to(os.path.realpath(shutil.which("git")))
    answer, entry = _level1(env, r.path)
    assert_handed_over(answer, entry)


@pytest.mark.parametrize("command, why", [("git push --force origin main", "the option --force"),
                                          ("git push origin +main", "")])
def test_a_forced_update_is_no_hand_over(env, tmp_path, command, why):
    r = _repo(tmp_path, env)
    answer, entry = _level1(env, r.path, command=command)
    assert _decision(answer) == "ask" and entry["reason_ids"] == ["push_not_measured"], answer
    assert why in answer["systemMessage"] and not _pointer(r.path).exists()


@pytest.mark.parametrize("command", ["GIT_TERMINAL_PROMPT=0 git push origin main", "LANG=C git push origin main",
                                     "git-push origin main", '"git" push origin main', "\\git push origin main",
                                     "git -C . push origin main", "git push origin main > push.log"])
def test_only_the_plain_push_form_is_handed_over(env, tmp_path, command):
    """The binding measures the git a plain `git push` starts in the hook's environment. A prefix assignment runs that
    git in another environment (Level 2 would refuse the hand-over after Level 1 announced it), and a dashed, quoted or
    escaped command word, a global option or a redirection into a file is another form: each stays an ask."""
    r = _repo(tmp_path, env)
    answer, entry = _level1(env, r.path, command=command)
    assert _decision(answer) == "ask" and entry["verdict"] != "handover", answer
    assert "No hand-over to Level 2" in answer["systemMessage"] or "hands this push over" not in answer["systemMessage"]
    assert not _pointer(r.path).exists() and _records(env) == []


def test_a_prefix_assignment_is_named_as_the_reason(env, tmp_path):
    r = _repo(tmp_path, env)
    answer, entry = _level1(env, r.path, command="GIT_TERMINAL_PROMPT=0 git push origin main")
    assert_asked_without_handover(answer, entry, "the command is not the plain form `git push …`")


@pytest.mark.parametrize("command", ["git push origin main < /dev/null", "git push origin main 2>&1",
                                     "git push -q origin main"])
def test_a_plain_form_with_a_redirection_that_opens_no_file_is_handed_over(env, tmp_path, command):
    r = _repo(tmp_path, env)
    answer, entry = _level1(env, r.path, command=command)
    assert_handed_over(answer, entry)


def test_a_gh_call_is_no_hand_over(env, tmp_path):
    r = _repo(tmp_path, env)
    answer, _entry = _level1(env, r.path, command="gh pr create --fill")
    assert _decision(answer) == "ask" and "hands this push over" not in answer["systemMessage"]
    assert not _pointer(r.path).exists()


def test_a_d20_change_stays_an_ask_and_level_2_blocks_it(env, tmp_path):
    """The push changes the done policy against the remote's state: Level 1 sees the difference against its local
    record (owner choice 4 A) and hands nothing over; pushed anyway, Level 2 blocks it in standalone mode."""
    r = _repo(tmp_path, env)
    policy = r.path / base.POLICY
    other = base.generate_signer()
    base._write(policy, base._policy(other))
    r.sign_evidence()
    base._commit(r.path, "a new done key")
    base._receipt(r.path, other)
    answer, entry = _level1(env, r.path)
    assert_asked_without_handover(answer, entry, "the evidence rules differ")
    before = _remote(tmp_path)
    proc = _push(env, r.path)
    assert proc.returncode != 0 and _remote(tmp_path) == before and "evidence rules" in proc.stderr, proc.stderr


@pytest.mark.parametrize("case, reason", [("missing", "no_receipt"), ("red", "not_done")])
def test_a_wrong_done_check_is_denied_and_nothing_is_handed_over(env, tmp_path, case, reason):
    r = _repo(tmp_path, env, case=case)
    answer, entry = _level1(env, r.path)
    assert _decision(answer) == "deny" and entry["reason_ids"] == [reason], answer
    assert not _pointer(r.path).exists() and _records(env) == []


def test_falsified_evidence_is_denied_and_nothing_is_handed_over(env, tmp_path):
    r = _repo(tmp_path, env)
    bundle = r.path / ".proofbundle" / "b.json"
    document = json.loads(bundle.read_text(encoding="utf-8"))
    document["payload_b64"] = document["payload_b64"][:-4] + ("AAAA" if not document["payload_b64"].endswith("AAAA")
                                                              else "BBBB")
    base._write(bundle, document)
    base._git(r.path, "add", "-A")
    base._git(r.path, "commit", "-q", "--amend", "--no-edit")
    base._receipt(r.path, r.signer)
    answer, entry = _level1(env, r.path)
    assert _decision(answer) == "deny", answer
    assert not _pointer(r.path).exists()


def test_missing_evidence_is_denied_and_nothing_is_handed_over(env, tmp_path):
    """The declared bundle is gone from the commit the push sends: an evidenced failure, a deny, no hand-over."""
    r = _repo(tmp_path, env)
    base._git(r.path, "rm", "-q", "--cached", ".proofbundle/b.json")
    (r.path / ".proofbundle" / "b.json").unlink()
    base._git(r.path, "commit", "-q", "--amend", "--no-edit")
    base._receipt(r.path, r.signer)
    answer, entry = _level1(env, r.path)
    assert _decision(answer) == "deny" and entry["reason_ids"] == ["missing_file"], answer
    assert not _pointer(r.path).exists() and _records(env) == []


def test_a_push_that_declares_only_a_done_check_is_handed_over_where_the_check_passes(env, tmp_path):
    """The user path of D26 and D28: no evidence item, a done check at the sent commit that passes."""
    r = base.Repo(tmp_path)
    r.make("valid")
    assert _install(r.path).returncode == 0
    _approve(env, r.path)
    answer, entry = _level1(env, r.path)
    assert_handed_over(answer, entry)
    proc = _push(env, r.path)
    assert proc.returncode == 0 and _remote(tmp_path) == base._rev(r.path, "HEAD"), proc.stderr
    assert "The done check passed at the pushed commit" in proc.stderr, proc.stderr


def test_an_empty_evidence_list_is_no_valid_source(env, tmp_path):
    """A sent commit that declares an empty evidence list and no done check has nothing that verified: no hand-over."""
    path = tmp_path / "r"
    path.mkdir()
    base._git(path, "init", "-q", "-b", "main")
    base._write(path / gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA, "evidence": []})
    base._write(path / "src" / "module.py", "VALUE = 1\n")
    base._commit(path, "an empty declaration")
    subprocess.run(["git", "init", "--bare", "-q", str(tmp_path / "remote.git")], check=True, timeout=60)
    base._git(path, "remote", "add", "origin", str(tmp_path / "remote.git"))
    base._git(path, "push", "-q", "-u", "origin", "main")
    base._write(path / "src" / "module.py", "VALUE = 2\n")
    base._commit(path, "work")
    assert _install(path).returncode == 0
    _approve(env, path)
    answer, entry = _level1(env, path)
    assert_asked_without_handover(answer, entry, "did not verify as a pass (empty_declaration)")


def test_under_codex_level_1_is_unchanged(env, tmp_path):
    r = _repo(tmp_path, env)
    answer, entry = _level1(env, r.path, host="codex")
    assert _decision(answer) is None and (entry["verdict"], entry["reason_ids"]) == ("warn", ["codex_context_unbound"])
    assert not _pointer(r.path).exists()


# --- 3. what Level 2 refuses ---------------------------------------------------------------------------------------

def test_the_candidate_alone_is_refused_by_level_2_with_both_names(env, tmp_path):
    """The remote holds only refs/heads/refs/heads/main: git writes the candidate for `main`. Level 1 cannot see that
    and hands over; Level 2 sees git's own destination and refuses it."""
    r = _repo(tmp_path, env)
    remote = tmp_path / "remote.git"
    base._git(remote, "update-ref", "refs/heads/refs/heads/main", _remote(tmp_path))
    base._git(remote, "update-ref", "-d", "refs/heads/main")
    answer, entry = _level1(env, r.path)
    assert_handed_over(answer, entry)
    candidate = _remote(tmp_path, "refs/heads/refs/heads/main")
    proc = _push(env, r.path)
    assert proc.returncode != 0, proc.stderr
    assert _remote(tmp_path, "refs/heads/refs/heads/main") == candidate and _remote(tmp_path) is None
    assert "refs/heads/refs/heads/main where Level 1 expected refs/heads/main" in proc.stderr, proc.stderr


def test_a_new_ref_stays_blocked(env, tmp_path):
    """Answer 2: the remote lost main, the local record still names it; Level 1 hands over, and Level 2 blocks the
    creation (target_ref_absent)."""
    r = _repo(tmp_path, env)
    base._git(tmp_path / "remote.git", "update-ref", "-d", "refs/heads/main")
    answer, entry = _level1(env, r.path)
    assert_handed_over(answer, entry)
    proc = _push(env, r.path)
    assert proc.returncode != 0 and _remote(tmp_path) is None, proc.stderr
    assert "The target ref does not exist" in proc.stderr, proc.stderr


def test_an_invalid_intermediate_commit_is_refused_by_level_2(env, tmp_path):
    """Level 1 checks the source tip; Level 2 checks every commit the push newly sends. A middle commit whose evidence
    names another tree stops the push."""
    r = _repo(tmp_path, env)
    base._write(r.path / "src" / "module.py", "VALUE = 3\n")
    base._commit(r.path, "a commit whose evidence names the tree before it")
    base._write(r.path / "src" / "module.py", "VALUE = 4\n")
    base._commit(r.path, "the tip")
    r.sign_evidence()
    base._git(r.path, "add", "-A")
    base._git(r.path, "commit", "-q", "--amend", "--no-edit")
    base._receipt(r.path, r.signer)
    answer, entry = _level1(env, r.path)
    assert_handed_over(answer, entry)
    before = _remote(tmp_path)
    proc = _push(env, r.path)
    assert proc.returncode != 0 and _remote(tmp_path) == before, proc.stderr
    assert "does not match the tree" in proc.stderr, proc.stderr


def test_mixed_multiple_updates_are_refused(env, tmp_path):
    """Level 1 handed over `main`; a push of `main` and `other` carries an update the hand-over does not name."""
    r = _repo(tmp_path, env)
    base._git(r.path, "branch", "other")
    _level1(env, r.path)
    proc = _push(env, r.path, "origin", "main", "other")
    assert proc.returncode != 0 and _remote(tmp_path, "refs/heads/other") is None, proc.stderr
    assert "refs/heads/other, which is none of the updates the hand-over names" in proc.stderr, proc.stderr


def _record_path(env: dict) -> pathlib.Path:
    (path,) = [p for p in _records(env) if p.suffix == ".json"]
    return path


def _rewrite_record(env: dict, change) -> None:
    path = _record_path(env)
    record = json.loads(path.read_text(encoding="utf-8"))
    change(record)
    path.write_text(json.dumps(record), encoding="utf-8")


@pytest.mark.parametrize("change, why", [
    (lambda rec: rec.update(expires=int(time.time()) - 1), "it expired at"),
    (lambda rec: rec.update(created=int(time.time()) + 3600), "written in the future"),
    (lambda rec: rec.update(schema="proofbundle-plugin/handover/v0"), "not a hand-over of this plugin"),
    (lambda rec: rec.update(repo="/elsewhere"), "another repository"),
    (lambda rec: rec.update(url="/elsewhere/remote.git"), "the hand-over names remote"),
    (lambda rec: rec["binding"].update(plugin_version="9.9.9"), "Level 1 measured 9.9.9"),
    (lambda rec: rec["binding"].update(hook_sha256="0" * 64), "or its bytes changed"),
    (lambda rec: rec["binding"].update(gate_sha256="0" * 64), "or its bytes changed"),
    (lambda rec: rec["binding"].update(git_sha256="0" * 64), "git program"),
    (lambda rec: rec["binding"].update(exec_path="/nonexistent"), "GIT_EXEC_PATH"),
    (lambda rec: rec["binding"].update(interpreter=["/x", "/x", "0"]), "interpreter"),
    (lambda rec: rec["binding"].update(environment="0" * 64), "environment"),
    (lambda rec: rec["binding"].update(configuration="0" * 64), "configuration"),
    (lambda rec: rec["binding"].update(transport="0" * 64), "transport configuration"),
    (lambda rec: rec["updates"][0].update(source="0" * 39 + "1"), "the hand-over names"),
], ids=["expired", "future", "schema", "repository", "url", "plugin-version", "hook", "gate", "git", "exec-path",
        "interpreter", "environment", "configuration", "transport", "source"])
def test_an_invalid_hand_over_is_refused_and_consumed(env, tmp_path, change, why):
    r = _repo(tmp_path, env)
    answer, _entry = _level1(env, r.path)
    _rewrite_record(env, change)
    before = _remote(tmp_path)
    proc = _push(env, r.path)
    assert proc.returncode != 0 and _remote(tmp_path) == before, proc.stderr
    assert "Level 2 refuses the hand-over" in proc.stderr and why in proc.stderr, proc.stderr
    assert not _pointer(r.path).exists()
    assert [p.name.endswith(".json.consumed") for p in _records(env)] == [True], "the record is consumed"


@pytest.mark.parametrize("pointer, why", [
    ("not json", "no regular file Level 2 can read"),
    (json.dumps({"schema": POINTER_SCHEMA, "nonce": "z" * 32}), "not of the form Level 1 writes"),
    (json.dumps({"schema": POINTER_SCHEMA, "nonce": "0" * 32}), "is missing"),
])
def test_a_pointer_without_its_record_is_refused(env, tmp_path, pointer, why):
    r = _repo(tmp_path, env)
    _pointer(r.path).write_text(pointer, encoding="utf-8")
    before = _remote(tmp_path)
    proc = _push(env, r.path)
    assert proc.returncode != 0 and _remote(tmp_path) == before and why in proc.stderr, proc.stderr
    assert not _pointer(r.path).exists()


def test_a_consumed_hand_over_is_not_used_again(env, tmp_path):
    r = _repo(tmp_path, env)
    _level1(env, r.path)
    nonce = json.loads(_pointer(r.path).read_text(encoding="utf-8"))["nonce"]
    assert _push(env, r.path).returncode == 0
    _pointer(r.path).write_text(json.dumps({"schema": gate.HANDOVER_POINTER_SCHEMA, "nonce": nonce}),
                                encoding="utf-8")
    base._write(r.path / "src" / "module.py", "VALUE = 7\n")
    base._commit(r.path, "more work")
    r.sign_evidence()
    base._git(r.path, "add", "-A")
    base._git(r.path, "commit", "-q", "--amend", "--no-edit")
    base._receipt(r.path, r.signer)
    proc = _push(env, r.path)
    assert proc.returncode != 0 and "is missing (consumed already" in proc.stderr, proc.stderr


@pytest.mark.parametrize("what", ["environment", "configuration"])
def test_a_change_between_level_1_and_the_push_is_refused(env, tmp_path, what):
    r = _repo(tmp_path, env)
    _level1(env, r.path)
    push_env = dict(env)
    if what == "environment":
        push_env["GIT_TRACE2_EVENT_NESTING"] = "1"
    else:
        base._git(r.path, "config", "user.name", "someone else")
    proc = _push(push_env, r.path)
    assert proc.returncode != 0 and f"{what}" in proc.stderr, proc.stderr


@pytest.mark.parametrize("lines, why", [
    ([("refs/heads/main", "a" * 40, "refs/heads/main", "b" * 40)] * 2, "twice"),
    ([("refs/heads/main", "c" * 40, "refs/heads/main", "b" * 40)], "the hand-over names aaaaaaaaaaaa"),
    ([("refs/heads/main", "0" * 40, "refs/heads/main", "b" * 40)], "would delete"),
    ([("refs/heads/main", "a" * 40, "refs/tags/refs/heads/main", "0" * 40)], "where Level 1 expected refs/heads/main"),
    ([("refs/heads/x", "a" * 40, "refs/heads/x", "0" * 40)], "none of the updates the hand-over names"),
], ids=["twice", "contradicting", "deletion", "candidate", "other"])
def test_duplicate_contradicting_and_foreign_lines_are_refused(lines, why):
    """git never hands one ref twice; the update set is refused all the same, line by line (7.5 step 4)."""
    updates = [{"source": "a" * 40, "dest": "refs/heads/main"}]
    problem = gate._handover_update_problem(updates, lines)
    assert problem is not None and why in problem, problem
    assert gate._handover_update_problem(updates, [("refs/heads/main", "a" * 40, "refs/heads/main", "b" * 40)]) is None
    assert gate._handover_update_problem(updates, []) is None, "an expected update git left out is a no-op"


# --- 4. no-op, abort, a later server error ---------------------------------------------------------------------------

def test_a_no_op_claims_no_checked_update(env, tmp_path):
    """git runs the hook with no ref line for an up-to-date ref (measured with git 2.34.1): the hand-over is consumed and
    Level 2 says it checked nothing and claims no update."""
    r = _repo(tmp_path, env)
    _level1(env, r.path)
    assert _push(env, r.path).returncode == 0
    answer, entry = _level1(env, r.path)
    assert_handed_over(answer, entry)
    proc = _push(env, r.path)
    assert proc.returncode == 0, proc.stderr
    assert "checked nothing and claims no update" in proc.stderr and "a no-op" in proc.stderr, proc.stderr
    assert not _pointer(r.path).exists()


def test_an_abort_of_the_check_keeps_the_remote(env, tmp_path):
    """The verifier cannot run when the hook judges: the push stops, closed, and the hand-over is consumed."""
    r = _repo(tmp_path, env)
    _level1(env, r.path)
    (pathlib.Path(env["PATH"].split(os.pathsep)[0]) / "uv").write_text("#!/bin/sh\nexit 3\n", encoding="utf-8")
    before = _remote(tmp_path)
    proc = _push(env, r.path)
    assert proc.returncode != 0 and _remote(tmp_path) == before, proc.stderr
    assert not _pointer(r.path).exists()


def test_a_later_server_error_is_not_a_successful_update(env, tmp_path):
    """Level 2 passes, the remote's own pre-receive hook then refuses: git's end result stays separate."""
    r = _repo(tmp_path, env)
    refuse = tmp_path / "remote.git" / "hooks" / "pre-receive"
    refuse.write_text("#!/bin/sh\necho 'remote says no' >&2\nexit 1\n", encoding="utf-8")
    refuse.chmod(0o755)
    _level1(env, r.path)
    before = _remote(tmp_path)
    proc = _push(env, r.path)
    assert proc.returncode != 0 and _remote(tmp_path) == before, proc.stderr
    assert "no successful remote update" in proc.stderr and "remote says no" in proc.stderr, proc.stderr


# --- 5. the standalone mode ------------------------------------------------------------------------------------------

def test_without_a_hand_over_level_2_runs_standalone_and_says_so(env, tmp_path):
    r = _repo(tmp_path, env)
    proc = _push(env, r.path)
    assert proc.returncode == 0, proc.stderr
    assert "standalone mode" in proc.stderr and "not compared with an expected target" in proc.stderr


def test_transport_digest_prints_the_entry_a_person_copies(env, tmp_path):
    r = _repo(tmp_path, env, approve=False)
    proc = subprocess.run([sys.executable, "-I", str(GATE), "transport-digest", "--repo", str(r.path)],
                          capture_output=True, text=True, env=env, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    digest, _, entry = proc.stdout.partition("\n")
    assert json.loads(entry) == {"repo": str((r.path / ".git").resolve()), "remote": "origin",
                                 "url": str(tmp_path / "remote.git"), "transport_digest": digest}
    assert not (pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / gate.TRANSPORTS_FILE).exists(), "the gate writes no approval"


def test_a_file_tool_cannot_write_an_approval_or_a_hand_over(env, tmp_path, monkeypatch):
    monkeypatch.setenv("PROOFBUNDLE_GATE_DIR", env["PROOFBUNDLE_GATE_DIR"])
    for name in (gate.TRANSPORTS_FILE, "handover/0123456789abcdef0123456789abcdef.json"):
        target = os.path.join(env["PROOFBUNDLE_GATE_DIR"], name)
        outcome = gate.decide_write("Write", {"file_path": target}, str(tmp_path), time.monotonic() + 30)
        assert outcome is not None and outcome.decision == "deny", name
