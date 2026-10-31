"""R20-4 of review round 20: the hand-over record binds what Level 1 checked.

Level 1 checks the transport against a person's approval, the push configuration, and that the git on PATH is the git
of its exec path; then _handover_binding reads transport, configuration and git again and writes them into the record.
A change the gate itself reads between the check and the binding must not reach the record: the record would carry a
transport, a configuration or a git nobody approved or checked, and Level 2 later compares the push against that record.

Each case runs Level 1 as the host starts it, through a driver that wraps _handover_binding and makes one change on
entry (the reviewer's deterministic timing; approval, digests, git and the judgement are the gate's own). Red at
b34ba9a2 (a hand-over is written with the changed value), green after.

Follow-up note 11, part 2: the same driver wraps _handover_push_config_problem and makes the change as soon as the original
returns, the window between the check of the push configuration and the binding. The configuration digest the binding
is compared with must be read before that check; read only before the binding, it would already hold the change. Red at
b34ba9a2, green at 35214a8c and after.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess

import test_plugin_gate_push_destination_18 as g18

pytestmark = g18.pytestmark
_clean_git_environment = g18._clean_git_environment
env = g18.env
base, gate, GATE = g18.base, g18.gate, g18.GATE

DRIVER = '''
import importlib.util, subprocess, sys
gate_path, change, name, moment = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
spec = importlib.util.spec_from_file_location("proofbundle_gate", gate_path)
gate = importlib.util.module_from_spec(spec)
sys.modules["proofbundle_gate"] = gate
spec.loader.exec_module(gate)
original, done = getattr(gate, name), []
def wrapped(*args, **kwargs):
    result = original(*args, **kwargs) if moment == "after" else None
    if not done:
        done.append(True)
        subprocess.run(["sh", change], check=True)
    return result if moment == "after" else original(*args, **kwargs)
setattr(gate, name, wrapped)
sys.exit(gate.main(sys.argv[5:]))
'''


def _level1_changed(env: dict, tmp_path: pathlib.Path, repo: pathlib.Path, change: str,
                    wrap: str = "_handover_binding", moment: str = "before"):
    """Level 1 with `change` (a shell script) run once as the gate function `wrap` is entered (moment "before") or as
    soon as it returns (moment "after")."""
    driver, script = tmp_path / "driver.py", tmp_path / "change.sh"
    driver.write_text(DRIVER, encoding="utf-8")
    script.write_text(change, encoding="utf-8")
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                        "tool_input": {"command": "git push origin main"}})
    proc = subprocess.run([shutil.which("python3", path=env["PATH"]), "-I", str(driver), str(GATE), str(script), wrap,
                           moment, "--host", "claude"], input=event, capture_output=True, text=True, env=env,
                          timeout=180, check=False)
    assert proc.returncode == 0, proc.stderr
    log = pathlib.Path(env["PLUGIN_DATA"]) / gate.LOG_NAME
    return json.loads(proc.stdout), json.loads(log.read_text(encoding="utf-8").splitlines()[-1])


def _receive_program(tmp_path: pathlib.Path, repo: pathlib.Path, word: str) -> pathlib.Path:
    program = tmp_path / "receive.sh"
    program.write_text(f'#!/bin/sh\necho {word} >> "{tmp_path / "transport-marker"}"\nexec git-receive-pack "$@"\n',
                       encoding="utf-8")
    program.chmod(0o755)
    base._git(repo, "config", "remote.origin.receivepack", str(program))
    return program


def test_R20_4_a_transport_changed_between_approval_check_and_binding_gets_no_hand_over(env, tmp_path):
    r = g18._repo(tmp_path, env, approve=False)
    program = _receive_program(tmp_path, r.path, "APPROVED")
    approved = g18._approve(env, r.path)["transport_digest"]
    rewrite = (f"cat > '{program}' <<'EOF'\n#!/bin/sh\necho UNAPPROVED >> \"{tmp_path / 'transport-marker'}\"\n"
               'exec git-receive-pack "$@"\nEOF\n')
    answer, entry = _level1_changed(env, tmp_path, r.path, rewrite)
    assert "UNAPPROVED" in program.read_text(encoding="utf-8")
    assert g18._digest(env, r.path) != approved, "the change is one the transport digest reads"
    g18.assert_asked_without_handover(answer, entry, "the transport changed between the approval check and the binding")
    assert not g18._pointer(r.path).exists() and g18._records(env) == []


def test_R20_4_control_without_a_change_the_record_binds_the_approved_transport(env, tmp_path):
    r = g18._repo(tmp_path, env, approve=False)
    _receive_program(tmp_path, r.path, "APPROVED")
    approved = g18._approve(env, r.path)["transport_digest"]
    answer, entry = _level1_changed(env, tmp_path, r.path, "true\n")
    g18.assert_handed_over(answer, entry)
    record = json.loads(g18._records(env)[0].read_text(encoding="utf-8"))
    assert record["binding"]["transport"] == approved


def test_R20_4_sibling_a_configuration_changed_after_the_checks_gets_no_hand_over(env, tmp_path):
    """The push configuration is checked (_handover_push_config_problem); a change before the binding reads it again
    is one nobody checked. A harmless key stands for any key here."""
    r = g18._repo(tmp_path, env)
    answer, entry = _level1_changed(env, tmp_path, r.path, f"git -C '{r.path}' config review20.changed yes\n")
    g18.assert_asked_without_handover(answer, entry, "the effective git configuration changed between the checks")
    assert not g18._pointer(r.path).exists() and g18._records(env) == []


def test_R20_4_sibling_a_configuration_changed_right_after_its_check_gets_no_hand_over(env, tmp_path):
    """Follow-up note 11, part 2: the change lands as soon as _handover_push_config_problem returns. The check did not read
    it, and the digest the binding is compared with was read before the check, so the change shows."""
    r = g18._repo(tmp_path, env)
    answer, entry = _level1_changed(env, tmp_path, r.path, f"git -C '{r.path}' config review20.changed yes\n",
                                    wrap="_handover_push_config_problem", moment="after")
    g18.assert_asked_without_handover(answer, entry, "the effective git configuration changed between the checks")
    assert not g18._pointer(r.path).exists() and g18._records(env) == []


def test_R20_4_control_without_a_change_after_the_configuration_check_the_push_is_handed_over(env, tmp_path):
    """The same driver around _handover_push_config_problem with no change: the hand-over is written, so the case above
    differs only by the change."""
    r = g18._repo(tmp_path, env)
    answer, entry = _level1_changed(env, tmp_path, r.path, "true\n", wrap="_handover_push_config_problem",
                                    moment="after")
    g18.assert_handed_over(answer, entry)


def test_R20_4_sibling_a_git_changed_after_the_identity_check_gets_no_hand_over(env, tmp_path):
    """The git on PATH is checked to be byte for byte the git of its exec path; a git program rewritten before the
    binding reads it again would be recorded unchecked, and Level 2 compares the running git against that record."""
    bin_dir = pathlib.Path(env["PATH"].split(os.pathsep)[0])
    copy = bin_dir / "git"
    shutil.copyfile(os.path.realpath(shutil.which("git", path=env["PATH"])), copy)
    copy.chmod(0o755)
    r = g18._repo(tmp_path, env)
    answer, entry = _level1_changed(env, tmp_path, r.path, f"printf 'appended' >> '{copy}'\n")
    g18.assert_asked_without_handover(answer, entry, "the git program changed between the identity check")
    assert not g18._pointer(r.path).exists() and g18._records(env) == []


def test_R20_4_control_the_git_copy_alone_is_handed_over(env, tmp_path):
    """The copy of the exec path's git on PATH is byte for byte that git, so the sibling case above differs only by
    the change."""
    bin_dir = pathlib.Path(env["PATH"].split(os.pathsep)[0])
    shutil.copyfile(os.path.realpath(shutil.which("git", path=env["PATH"])), bin_dir / "git")
    (bin_dir / "git").chmod(0o755)
    r = g18._repo(tmp_path, env)
    answer, entry = _level1_changed(env, tmp_path, r.path, "true\n")
    g18.assert_handed_over(answer, entry)
