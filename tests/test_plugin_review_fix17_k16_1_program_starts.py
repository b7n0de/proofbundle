"""K16-1 of FIX-16, FIX-17 measurement E: the git calls the further reading adds, `rev-parse --verify --quiet
--end-of-options <name>` and the same with `--symbolic-full-name`, start no program the repository's configuration
names: no core.fsmonitor, no hook under core.hooksPath (reference-transaction, post-index-change and the others), no
clean, smudge or process filter, no signature program. The anti-vacuity half: plain git starts each marker in the same
repository. Run with git 2.43.0.
"""
from __future__ import annotations

import shlex
import time

import test_plugin_owner_choice1_undeclared_push as w1
import test_plugin_review_fix17_k16_1_further_records as k1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

HOOKS = ["reference-transaction", "post-index-change", "post-checkout", "pre-commit", "commit-msg", "post-commit",
         "post-rewrite", "pre-push", "pre-auto-gc", "fsmonitor-watchman"]


def _marker(folder, marks, name):
    folder.mkdir(parents=True, exist_ok=True)
    program = folder / name
    program.write_text(f"#!/bin/sh\ntouch {shlex.quote(str(marks / name))}\ncat >/dev/null 2>&1\nexit 0\n",
                       encoding="utf-8")
    program.chmod(0o700)
    return program


def test_the_further_reading_starts_no_program_the_configuration_names(env, tmp_path, monkeypatch):
    work, a, _declared = k1._declared_alone(tmp_path)
    marks, bin_dir, hooks = tmp_path / "marks", tmp_path / "bin", tmp_path / "hooks"
    marks.mkdir()
    for name in HOOKS:
        _marker(hooks, marks, name)
    w1._git(work, "config", "core.hooksPath", str(hooks))
    w1._git(work, "config", "core.fsmonitor", str(_marker(bin_dir, marks, "fsmonitor")))
    for kind in ("clean", "smudge"):
        w1._git(work, "config", f"filter.m.{kind}", str(_marker(bin_dir, marks, f"filter-{kind}")))
    w1._git(work, "config", "gpg.program", str(_marker(bin_dir, marks, "gpg")))
    w1._git(work, "config", "gpg.ssh.program", str(_marker(bin_dir, marks, "gpg-ssh")))
    w1._git(work, "config", "log.showSignature", "true")
    (work / ".git" / "info").mkdir(exist_ok=True)
    (work / ".git" / "info" / "attributes").write_text("* filter=m\n", encoding="utf-8")
    k1._write(work, "sub/foo", f"{a}\n".encode())                       # a further record git resolves
    k1._write(work, "notes/text", b"no record\n")                       # a further file git does not resolve
    real, names = gate._resolution, []

    def counted(repo, name, deadline):
        names.append(name)
        return real(repo, name, deadline)

    monkeypatch.setattr(gate, "_resolution", counted)
    present, broken = gate._present_refs(str(work), time.monotonic() + 120)
    assert present is not None and present["sub/foo"] == a and "notes/text" not in present, broken
    assert {"sub/foo", "notes/text"} <= set(names), "precondition: the new git calls ran for both files"
    assert sorted(p.name for p in marks.iterdir()) == [], "the further reading started a program"
    answer, _entry, text = w1._l1(env, work)                            # the whole hook, as the host starts it
    assert sorted(p.name for p in marks.iterdir()) == [], "the hook started a program"
    assert "permissionDecision" not in answer["hookSpecificOutput"], text   # inactive: condition d ran to its end

    # The anti-vacuity half: plain git starts each marker in this repository.
    (work / "new.txt").write_text("n\n", encoding="utf-8")
    w1.n2c._git(work, "status", "--short", check=False)
    w1.n2c._git(work, "add", "new.txt", check=False)
    w1.n2c._git(work, "-c", "commit.gpgsign=true", "-c", "gpg.format=openpgp", "commit", "-q", "-m", "n",
                check=False)
    w1.n2c._git(work, "update-ref", "refs/heads/probe", "HEAD", check=False)   # the signing marker gives no signature
    started = sorted(p.name for p in marks.iterdir())
    for name in ("fsmonitor", "filter-clean", "gpg", "pre-commit", "reference-transaction"):
        assert name in started, f"plain git does not start {name} here; the case would be vacuous: {started}"
