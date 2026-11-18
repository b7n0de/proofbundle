"""D128 (owner answer 6 of Nachtrag 7, 2026-10-26, option A): no hook reads done state a session can write.

D124 switched the owner files of the gate directory off where no protected channel is stated, and named two more files
of the same class that it did not cover: the local done orders in done-orders/ (D38), which the Stop, TaskCompleted and
SessionStart hooks judge, and the record done-keys.json (B30-2, D79), whose key path the command of a block names. A
session of the same account writes both through a changed working directory, which the gate does not answer, and it may
run `done-order --repo` itself, which D38 leaves free (owner choice O2 of follow-up note 13). A key a session writes then
signs its own done receipt, and an order a session writes can drop a check. The owner's answer: switched off without a
protected channel.

The property held here: without PROOFBUNDLE_OWNER_STATE=protected in the hook's environment, no hook reads a local done
order, so the done check runs on the repository's declaration alone, and the command it builds takes no key path from
done-keys.json; with the setting both are read as before. Before each write of the session the measured gap is asserted:
the gate gives the Bash call no decision in the three hook forms (Claude Code without a flag, with --autonomous, Codex).
done-order and done-init, which a person runs, still write without the setting, and their output says that the hooks
read what they wrote only where the hook's environment states the protected channel.

RED at f21f785d: every case without the setting and both outputs. The cases with the setting are controls, green at
both.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import sys

import pytest

import test_plugin_done_check as d
import test_plugin_done_local_order as lo

pytestmark = d.pytestmark
_clean_git_config = d._clean_git_config
env, repo, keys, declared = d.env, d.repo, d.keys, d.declared
gate, GATE = d.gate, d.GATE
#: The setting of D124, written out: the house's statement that a channel the session cannot write holds the directory.
PROTECTED = {"PROOFBUNDLE_OWNER_STATE": "protected"}
#: The record of B30-2, written out.
RECORD = "done-keys.json"
HOOK_FORMS = {"claude": [], "claude --autonomous": ["--autonomous"], "codex": ["--host", "codex"]}
WAYS = ("written", "done-order")


@pytest.fixture(autouse=True)
def _no_opt_in(monkeypatch, env):
    """Guard Preview's default: no protected channel in the hook's environment; the gate directory exists."""
    monkeypatch.delenv("PROOFBUNDLE_OWNER_STATE", raising=False)
    env.pop("PROOFBUNDLE_OWNER_STATE", None)
    pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]).mkdir(parents=True, exist_ok=True)


def _gate_dir(env: dict) -> pathlib.Path:
    return pathlib.Path(env["PROOFBUNDLE_GATE_DIR"])


def _session_writes(env: dict, command: str, cwd: pathlib.Path, tmp_path: pathlib.Path) -> None:
    """The session's write: the gate gives the Bash call no decision in any hook form (the gap of D124), and it runs."""
    data = tmp_path / "hook-data"
    data.mkdir(exist_ok=True)
    event = json.dumps({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "cwd": str(cwd),
                        "tool_input": {"command": command}})
    for name, flags in HOOK_FORMS.items():
        proc = subprocess.run([sys.executable, "-I", str(GATE), *flags], input=event, capture_output=True, text=True,
                              env={**env, "CLAUDE_PLUGIN_DATA": str(data), "PLUGIN_DATA": str(data)}, cwd=cwd,
                              timeout=120, check=False)
        assert proc.returncode == 0, proc.stderr
        answer = json.loads(proc.stdout) if proc.stdout.strip() else {}
        decision = (answer.get("hookSpecificOutput") or {}).get("permissionDecision")
        assert decision in (None, "allow"), (name, command, answer)
    subprocess.run(["bash", "-c", command], cwd=cwd, env=env, check=True, capture_output=True, timeout=180)


def _order_files(clone: pathlib.Path, public: str, checks=None) -> tuple[str, bytes, bytes]:
    """An order and the gate's record of its digest in the form done-order writes them (D38), made by the session."""
    root, gitdir = os.path.realpath(clone), os.path.realpath(clone / ".git")
    done = ({"receipt": d.RECEIPT, "policy": d.POLICY} if checks is None
            else {"policy": d.POLICY, "checks": list(checks)})
    policy = base64.b64encode(json.dumps(d._policy(public)).encode("utf-8")).decode("ascii")
    order = json.dumps({"schema": gate.DONE_ORDER_SCHEMA, "repo": root, "gitdir": gitdir, "done": done,
                        "base": d._git(clone, "rev-parse", "HEAD"), "created": "2026-10-26T12:00:00Z",
                        "policy": policy}).encode("utf-8") + b"\n"
    seen = json.dumps({"schema": gate.DONE_ORDER_SEEN_SCHEMA, "sha256": hashlib.sha256(order).hexdigest(),
                       "written": "2026-10-26T12:00:00Z", "replaced": []}).encode("utf-8") + b"\n"
    return gate._order_key(root, gitdir), order, seen


def _printf(data: bytes, name: str) -> str:
    return f"printf '%s\\n' {shlex.quote(data.decode('utf-8').rstrip(chr(10)))} > {name}"


def _write_order(env: dict, clone: pathlib.Path, public: str, tmp_path: pathlib.Path, checks=None) -> pathlib.Path:
    """The session writes an order and the gate's record of it together, through a changed working directory (the
    limit of D38: a shell that rewrites both is not seen)."""
    key, order, seen = _order_files(clone, public, checks)
    command = (f"cd {shlex.quote(str(_gate_dir(env)))} && mkdir -p {gate.DONE_ORDERS_DIR} && cd {gate.DONE_ORDERS_DIR}"
               f" && {_printf(order, key + '.json')} && {_printf(seen, key + '.seen.json')}")
    _session_writes(env, command, lo._session_dir(tmp_path), tmp_path)
    path = _gate_dir(env) / gate.DONE_ORDERS_DIR / f"{key}.json"
    assert path.read_bytes() == order
    return path


def _session_order(env: dict, clone: pathlib.Path, public: str, tmp_path: pathlib.Path, way: str) -> pathlib.Path:
    """Variant E in the clone (D38), and an order of the session for it: written into done-orders/ with its record, or
    made by the session's own call of done-order, which D38 leaves free (O2)."""
    lo._variant_e(clone, public)
    if way == "written":
        return _write_order(env, clone, public, tmp_path)
    _session_writes(env, f"{shlex.quote(sys.executable)} {shlex.quote(str(GATE))} done-order --repo "
                         f"{shlex.quote(str(clone))}", lo._session_dir(tmp_path), tmp_path)
    (path,) = (_gate_dir(env) / gate.DONE_ORDERS_DIR).glob("*[0-9a-f].json")
    return path


def _start(env: dict, cwd: pathlib.Path) -> dict | None:
    """The SessionStart hook of D127 as the plugin starts it; None where it prints nothing."""
    event = {"hook_event_name": "SessionStart", "session_id": "next", "cwd": str(cwd), "source": "startup",
             "transcript_path": str(cwd / "next.jsonl")}
    proc = subprocess.run([sys.executable, "-I", str(GATE), "session-start"], input=json.dumps(event),
                          capture_output=True, text=True, env=env, cwd=cwd, timeout=180, check=False)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def _named_key(answer: dict | None) -> str:
    reason = d.blocked(answer)
    return reason.split("PROOFBUNDLE_KEY=", 1)[1].split(" ", 1)[0]


# --- done-orders/ (D38) ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("way", WAYS)
def test_D128_an_order_the_session_made_is_read_by_no_hook_without_the_setting(env, repo, keys, tmp_path, way, host):
    _session_order(env, repo, keys.public, tmp_path, way)
    session = lo._session_dir(tmp_path)
    assert lo._stop(env, session, host) is None
    assert "declaration is not committed" in d.blocked(lo._stop(env, repo, host))   # the repository's alone
    if host == "claude":
        assert d.task_completed(env, session).stdout == ""


@pytest.mark.parametrize("way", WAYS)
def test_D128_control_with_the_setting_the_order_is_read_as_before(env, repo, keys, tmp_path, way):
    order = _session_order(env, repo, keys.public, tmp_path, way)
    reason = d.blocked(lo._stop({**env, **PROTECTED}, lo._session_dir(tmp_path)))
    assert f"the local done order {order.name[:12]}: check tests is missing" in reason, reason


@pytest.mark.parametrize("protected", [False, True], ids=["without", "with"])
def test_D128_an_order_the_session_rewrote_drops_no_check_without_the_setting(env, repo, keys, tmp_path, protected):
    """A person's order names unit and integration; the session rewrites the order and the gate's record together with
    unit alone, and the receipt of unit is there. With the setting the rewrite is read as before, and the end passes
    on one check of two (the limit of D38 stays); without it no order is read, and the declaration in the work tree is
    refused as uncommitted, as in a repository without an order."""
    with open(repo / ".git" / "info" / "exclude", "a", encoding="utf-8") as handle:
        handle.write("/.proofbundle/\n")
    d._declare_order(repo, keys.public, checks=(d.UNIT, d.INTEGRATION))
    made = lo._done_order(env, "--repo", str(repo))
    assert made.returncode == 0, made.stderr
    _write_order(env, repo, keys.public, tmp_path, checks=(d.UNIT,))
    d._run(repo, keys.signer, d.UNIT)
    answer = lo._stop({**env, **PROTECTED} if protected else env, repo)
    if protected:
        d.done_end(answer)
    else:
        assert answer and answer.get("decision") == "block", getattr(answer, "entry", answer)   # not a done end
        assert "declaration is not committed" in d.blocked(answer)


@pytest.mark.parametrize("protected", [False, True], ids=["without", "with"])
def test_D128_a_refused_order_blocks_no_end_and_counts_nothing_without_the_setting(env, tmp_path, protected):
    """An order the gate cannot read is refused where orders are read (order_unreadable) and its blocks are counted
    beside it (O3); where they are not read, it blocks nothing and nothing is counted."""
    key = "ab" * 32
    command = (f"cd {shlex.quote(str(_gate_dir(env)))} && mkdir -p {gate.DONE_ORDERS_DIR} && cd {gate.DONE_ORDERS_DIR}"
               f" && printf 'no order\\n' > {key}.json")
    _session_writes(env, command, lo._session_dir(tmp_path), tmp_path)
    answer = lo._stop({**env, **PROTECTED} if protected else env, lo._session_dir(tmp_path))
    counted = _gate_dir(env) / gate.DONE_ORDERS_DIR / f"{key}.state.json"
    if protected:
        assert f"{key}.json" in d.blocked(answer) and "unreadable done order" in answer["systemMessage"], answer
        assert counted.is_file()
    else:
        assert answer is None and not counted.exists()


@pytest.mark.parametrize("protected", [False, True], ids=["without", "with"])
def test_D128_a_session_start_finds_no_blocker_through_an_order_the_session_wrote(env, repo, keys, tmp_path,
                                                                                   protected):
    """D127 hands on the blocker of each repository a local order binds; the order is the session's here."""
    _session_order(env, repo, keys.public, tmp_path, "written")
    blocker = repo / gate.DONE_BLOCKER
    blocker.parent.mkdir(parents=True, exist_ok=True)
    blocker.write_text("{}\n", encoding="utf-8")
    answer = _start({**env, **PROTECTED} if protected else env, lo._session_dir(tmp_path))
    if protected:
        context = answer["hookSpecificOutput"]["additionalContext"]
        assert "round 1 of the hand-over" in context and "tests (missing)" in context, context
    else:
        assert answer is None


# --- done-keys.json (B30-2, D79) ------------------------------------------------------------------------------------

@pytest.mark.parametrize("protected", [False, True], ids=["without", "with"])
def test_D128_a_key_record_the_session_wrote_is_named_by_no_block_without_the_setting(env, declared, tmp_path,
                                                                                       protected):
    own = tmp_path / "session" / "own.key"
    record = json.dumps({os.path.realpath(declared): str(own)})
    _session_writes(env, f"cd {shlex.quote(str(_gate_dir(env)))} && printf '%s\\n' {shlex.quote(record)} > {RECORD}",
                    declared, tmp_path)
    assert json.loads((_gate_dir(env) / RECORD).read_text(encoding="utf-8")) == json.loads(record)
    named = _named_key(lo._stop({**env, **PROTECTED} if protected else env, declared))
    assert named == (str(own) if protected else str(_gate_dir(env) / gate.DONE_KEY_FILE)), named


# --- what a person runs still writes, and says where the hooks read it -----------------------------------------------

def test_D128_done_order_still_writes_without_the_setting_and_says_where_the_hooks_read_it(env, repo, keys):
    lo._variant_e(repo, keys.public)
    made = lo._done_order(env, "--repo", str(repo))
    assert made.returncode == 0, made.stderr
    (order,) = (_gate_dir(env) / gate.DONE_ORDERS_DIR).glob("*[0-9a-f].json")
    assert order.with_name(order.name.replace(".json", ".seen.json")).is_file()
    listed = lo._done_order(env, "--list")
    assert listed.returncode == 0 and order.name[:-5] in listed.stdout, listed
    for output in (made.stdout, listed.stdout):
        assert "PROOFBUNDLE_OWNER_STATE=protected" in output and "D128" in output, output


def test_D128_done_init_still_records_the_key_file_and_says_where_the_hooks_read_it(env, repo, tmp_path):
    key = tmp_path / "keys" / "my-done.key"
    key.parent.mkdir()
    proc = subprocess.run([sys.executable, "-I", str(GATE), "done-init", "--repo", str(repo), "--key", str(key)],
                          capture_output=True, text=True, env=env, timeout=180, check=False)
    assert proc.returncode == 0, proc.stderr
    assert json.loads((_gate_dir(env) / RECORD).read_text(encoding="utf-8")) == {os.path.realpath(repo): str(key)}
    assert "PROOFBUNDLE_OWNER_STATE=protected" in proc.stdout and "D128" in proc.stdout, proc.stdout
    assert "PROOFBUNDLE_KEY=" + str(key) in proc.stdout
