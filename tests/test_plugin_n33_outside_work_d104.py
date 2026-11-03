"""D104, follow-up note 33 (fallbook r01, S9): a recursive delete or an append outside the work folder is denied.

The order: recursive delete and append outside the work folder are denied. The work folder is the repository of cwd and
the scratch of the session, further ones only from a declaration with names. Measure on the corpus first which targets
occur today, and name every new ask. Found by account A's fallbook (gate 44db2056): `rm -rf <path>` and
`python3 <script> >> <audit log>` outside got no answer.

Measured before the rule (ziele_n33.py): the corpus (435 commands) has no `rm -r` and six appends, all to a relative
path in the repository; the Bash commands of this session (4846) delete recursively 211 times in its scratch, 94 times
through a variable of it, 60 times by a relative path, and three times in another place of /tmp, two of them the
fallbook's own forms written into a file; they append 137 times relatively, 67 times into the scratch, once to /dev,
twice to /tmp (the fallbook's S9) and five times to ~ (the forms of D97's tests).

Measured with Claude Code 2.1.303 (truth_host_n33.sh hint env): the hook's environment carries CLAUDE_PROJECT_DIR and
CLAUDE_CODE_SESSION_ID, not TMPDIR, and Claude Code keeps a folder of the session at
<temp>/claude-<uid>/<project>/<session id>/ (the scratch of this cloud session is a folder in it).

The rule: _guard_outside denies, under both hosts, `rm` with -r, -R or --recursive and `find … -delete` whose target is
not in a work folder or is the root of one, and an append (`>>`, `&>>`, `tee -a`) into a file not in a work folder; the
work folders are the repository of the step's directory (found by its .git, no git runs), the repository of
CLAUDE_PROJECT_DIR, the folder of the session under the temp folder, and every folder the file work-folders.json in
the gate's directory names with a name (a person writes it, D25). A path counts after the links its folder goes
through; an append also after the link of the file. /dev/null, /dev/stdout, /dev/stderr and /dev/tty open no file.

RED at 63b88d07 (the head of PLUGIN_N37): every form below; the controls are green at both.
"""
from __future__ import annotations

import json
import os
import time

import pytest
from _owner_state import owner_state_protected  # noqa: F401 - D124: a person's work folders are read

import test_plugin_n30_short_line_d72 as d72

gate = d72.gate
pytestmark = d72.pytestmark
_clean = d72._clean
HOSTS = ("claude", "codex")
SESSION = "sess-n33"


@pytest.fixture
def repo(tmp_path, monkeypatch):
    r = d72._repo(tmp_path)
    (r / "build").mkdir()
    (r / "f.txt").write_text("x\n")
    temp = tmp_path / "temp"
    scratch = temp / f"claude-{os.getuid()}" / "-proj" / SESSION / "scratchpad"
    scratch.mkdir(parents=True)
    monkeypatch.setenv("TMPDIR", str(temp))
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", SESSION)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    (tmp_path / "outside").mkdir()
    return r


def _ids(out):
    return [] if out is None else [v.reason_id for v in out.verdicts]


def _fill(form, repo):
    tmp = repo.parent
    scratch = tmp / "temp" / f"claude-{os.getuid()}" / "-proj" / SESSION / "scratchpad"
    return form.replace("{R}", str(repo)).replace("{O}", str(tmp / "outside")).replace("{S}", str(scratch))


def _out(repo, form, host="claude", cwd=None):
    return gate.decide(_fill(form, repo), str(cwd or repo), time.monotonic() + 60, host)


DELETES = ["rm -rf {O}", "rm -r {O}/x", "rm -Rf {O}/x", "rm --recursive --force {O}/x", "rm -fr ../outside",
           "rm -rf ~/x", "rm -rf /tmp/elsewhere-n33", "rm -rf {O}/x*", "rm -rf .", "rm -rf {R}", "rm -rf -- {O}/y",
           "find {O} -name '*.log' -delete", "bash -c 'rm -rf {O}/x'", "D={O}; rm -rf $D/x", "sudo rm -rf {O}/x",
           "rm -rf build {O}/x", "cd {R} && rm -rf {O}/z"]
APPENDS = ["python3 tool.py >> /tmp/audit-n33.log", "echo x >> {O}/a.log", "echo x &>> {O}/a.log",
           "tee -a {O}/a.log < f.txt", "tee --append {O}/a.log < f.txt", "echo x >> ~/notes-n33.txt",
           "echo x >> ../outside/a.log", "bash -c 'echo x >> {O}/a.log'"]


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", DELETES)
def test_D104_a_recursive_delete_outside_the_work_folder_is_denied(repo, form, host):
    out = _out(repo, form, host)
    assert out is not None and out.decision == "deny" and "delete_outside_work" in _ids(out), (form, host, _ids(out))


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", APPENDS)
def test_D104_an_append_outside_the_work_folder_is_denied(repo, form, host):
    out = _out(repo, form, host)
    assert out is not None and out.decision == "deny" and "append_outside_work" in _ids(out), (form, host, _ids(out))


def test_D104_an_append_through_a_link_into_an_outside_file_is_denied(repo):
    os.symlink(repo.parent / "outside" / "log.txt", repo / "log-link")
    out = _out(repo, "echo x >> log-link")
    assert out is not None and "append_outside_work" in _ids(out), _ids(out)


@pytest.mark.parametrize("form", ["rm -rf build", "rm -rf {R}/build", "rm -r build/x", "rm -rf {S}/x",
                                  "rm -rf {S}/../x", "echo x >> out.log", "python3 tool.py >> {R}/audit.log",
                                  "echo x >> {S}/log.txt", "echo x >> /dev/null", "echo x &>> /dev/stderr",
                                  "rm -f {O}/x", "rm {O}/x", "tee {O}/a.log < f.txt", "find {O} -name x",
                                  "find build -delete", "echo x > {O}/a.log", "rm -rf \"$UNSET_N33\"/x",
                                  "cd /nowhere-n33 && rm -rf x"])
def test_D104_control_inside_the_work_folder_and_other_forms_get_no_answer_of_D104(repo, form):
    assert not {"delete_outside_work", "append_outside_work"} & set(_ids(_out(repo, form))), form


def test_D104_the_project_of_claude_code_is_a_work_folder(repo, tmp_path, monkeypatch):
    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(project))
    assert "delete_outside_work" not in _ids(_out(repo, f"rm -rf {project}/build"))
    assert "delete_outside_work" in _ids(_out(repo, f"rm -rf {project}"))


def test_D104_a_folder_declared_with_a_name_in_the_gate_directory_is_a_work_folder(repo, tmp_path, monkeypatch):
    gate_dir = tmp_path / "gatedir"
    gate_dir.mkdir()
    monkeypatch.setenv("PROOFBUNDLE_GATE_DIR", str(gate_dir))
    form = "rm -rf {O}/cache"
    assert "delete_outside_work" in _ids(_out(repo, form))
    (gate_dir / "work-folders.json").write_text(json.dumps(
        {"schema": "proofbundle-plugin/work-folders/v0.1", "ordner": [{"name": "cache", "pfad": str(tmp_path / "outside")}]}))
    assert "delete_outside_work" not in _ids(_out(repo, form))
    (gate_dir / "work-folders.json").write_text(json.dumps(
        {"schema": "proofbundle-plugin/work-folders/v0.1", "ordner": [{"pfad": str(tmp_path / "outside")}]}))
    assert "delete_outside_work" in _ids(_out(repo, form)), "a folder without a name counts for nothing"
    (gate_dir / "work-folders.json").write_text("not json")
    assert "delete_outside_work" in _ids(_out(repo, form)), "an unreadable declaration counts for nothing"


def test_D104_without_a_session_the_scratch_is_no_work_folder(repo, monkeypatch):
    monkeypatch.delenv("CLAUDE_CODE_SESSION_ID")
    assert "delete_outside_work" in _ids(_out(repo, "rm -rf {S}/x"))


def test_D104_outside_a_repository_only_the_scratch_and_the_declared_folders_count(repo):
    out = _out(repo, "rm -rf x", cwd=repo.parent / "outside")
    assert out is not None and "delete_outside_work" in _ids(out), _ids(out)


def test_D104_the_reasons_catch_and_name_the_rule():
    for reason in ("delete_outside_work", "append_outside_work"):
        assert reason in gate.FANG_REASONS and gate._SHORT_REASONS[reason][0] == "D104"
