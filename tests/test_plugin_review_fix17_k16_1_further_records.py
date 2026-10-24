"""K16-1 of FIX-16 (owner choice of 2026-10-13, 20:0x, A) with the rule of review round 17: a file git resolves as a ref
counts to the ref store, and its silent absence is a finding.

Measured at a85ac78e with git 2.43.0 (FIX-16, probe_klasse16_gate): `git update-ref <name> D` for FOO, FOO_BAR, foo_HEAD,
Foo_HEAD, foo and sub/foo writes a file outside refs/ and outside the gate's root records; `git rev-parse` resolves each
name to D, `git for-each-ref` does not list it, and Level 1 answered inactive for `git push origin main` while D held a
declaration. The reviewer measured the same for logs/foo, objects/custom, info/custom, hooks/custom and
rebase-merge/orig-head with git 2.43.0 and 2.51.1.

The rule built (D5): the one git directory is read recursively beside the strict reading of refs/, packed-refs, HEAD and
the root records; every further regular file whose name git's ref rules take goes to git twice, `rev-parse --verify
--quiet --end-of-options <name>` and the same with `--symbolic-full-name`; only where the full name is the file's own
name has git resolved it, and then it must hold <oid>LF with the object git gives, which is read like any record. A
valid reflog under logs/ stays outside (owner choice 21:4x); a file there of only <oid>LF is a record. Every case below
uses a declared commit D that neither HEAD, nor the history the push sends, nor any other record names, so no other
path can hide a gap in the inventory. Run with git 2.43.0.
"""
from __future__ import annotations

import os
import subprocess
import time

import pytest

import test_plugin_owner_choice1_ask_names_the_record_20261013 as a1
import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

#: The six names of the FIX-16 probe, a name two folders deep, and the reviewer's folders.
NAMES = ["FOO", "FOO_BAR", "foo_HEAD", "Foo_HEAD", "foo", "sub/foo", "deep/er/foo",
         "logs/foo", "objects/custom", "info/custom", "hooks/custom", "rebase-merge/custom"]
CHANGED = ("the local refs changed while the gate read them, so its reading is no finished measurement that nothing is "
           "declared")


def _rev(work, name):
    probe = subprocess.run(["git", "-C", str(work), "rev-parse", "--verify", "--quiet", "--end-of-options", name],
                           capture_output=True, text=True, check=False)
    return probe.stdout.strip() if probe.returncode == 0 else None


def _declared_alone(tmp_path):
    """The undeclared repository and a declared D on top of A that nothing names."""
    work, _remote, a = w1._undeclared(tmp_path)
    return work, a, a1._declared_on_top(work, a)


def _write(work, name, data: bytes):
    path = work / ".git" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _declared_record(answer, entry, text, name, declared):
    w1._assert_exception_refused(answer, entry, text, f"the local ref {name} holds something at {gate.DECLARATION} or "
                                                      f"in place of its folder at {declared[:12]}; {a1.NOT_ESTABLISHED}")


def _local(work, deadline=None):
    head = w1.n2c._rev(work, "HEAD")
    return gate._local_inactivity(str(work), head, ["origin", "main"], [head], deadline or time.monotonic() + 120)


# --- each name alone on D, and on a clean commit ----------------------------------------------------------------

@pytest.mark.parametrize("name", NAMES)
def test_RED_a_further_record_git_writes_and_resolves_is_read(env, tmp_path, name):
    work, _a, declared = _declared_alone(tmp_path)
    w1._git(work, "update-ref", name, declared)
    assert _rev(work, name) == declared, "precondition: git writes the name and resolves it"
    assert name not in w1._git(work, "for-each-ref", "--format=%(refname)").stdout.split(), "precondition: not listed"
    _declared_record(*w1._l1(env, work), name, declared)


@pytest.mark.parametrize("name", NAMES)
def test_CONTROL_the_same_record_on_a_clean_commit_keeps_the_exception(env, tmp_path, name):
    work, a, _declared = _declared_alone(tmp_path)
    w1._git(work, "update-ref", name, a)
    w1._assert_inactive(*w1._l1(env, work))
    present, _broken = gate._present_refs(str(work), time.monotonic() + 120)
    assert present is not None and present[name] == a, "the record is read, not skipped"


# --- git's own administrative files -----------------------------------------------------------------------------

def _history(work, count=4):
    for n in range(count):
        w1._commit(work, f"h{n}.txt")


def test_CONTROL_a_bisect_started_on_a_branch(env, tmp_path):
    work, a, _declared = _declared_alone(tmp_path)
    _history(work)
    w1._git(work, "bisect", "start", "main", a)
    assert (work / ".git" / "BISECT_START").read_text() == "main\n", "precondition: the branch form"
    w1._assert_inactive(*w1._l1(env, work))


def test_CONTROL_a_bisect_started_detached_reads_its_start_as_a_record(env, tmp_path):
    work, a, _declared = _declared_alone(tmp_path)
    _history(work)
    tip = w1.n2c._rev(work, "main")
    w1._git(work, "checkout", "-q", "--detach", "main")
    w1._git(work, "bisect", "start", "HEAD", a)
    assert (work / ".git" / "BISECT_START").read_text() == f"{tip}\n", "precondition: the object form"
    w1._assert_inactive(*w1._l1(env, work))
    present, _broken = gate._present_refs(str(work), time.monotonic() + 120)
    assert present["BISECT_START"] == tip


def test_RED_a_bisect_whose_start_holds_the_declaration(env, tmp_path):
    work, a, declared = _declared_alone(tmp_path)
    _history(work)
    w1._git(work, "checkout", "-q", "--detach", declared)
    w1._git(work, "bisect", "start", "HEAD", a)
    for ref in w1._git(work, "for-each-ref", "--format=%(refname)", "refs/bisect/").stdout.split():
        w1._git(work, "update-ref", "-d", ref)                      # only BISECT_START still names D
    w1._git(work, "checkout", "-q", "--detach", a)                  # D is A's only child, so git stays at D itself
    assert (work / ".git" / "BISECT_START").read_text() == f"{declared}\n"
    assert w1.n2c._rev(work, "HEAD") != declared, "precondition: HEAD is a clean commit of the bisection"
    _declared_record(*w1._l1(env, work), "BISECT_START", declared)


def test_RED_bisect_start_naming_a_branch_git_does_not_list(env, tmp_path):
    work, a, _declared = _declared_alone(tmp_path)
    _history(work)
    w1._git(work, "bisect", "start", "main", a)
    (work / ".git" / "BISECT_START").write_text("gone-branch\n")
    w1._assert_exception_refused(*w1._l1(env, work), gate._further("BISECT_START in a form the gate does not read",
                                                                   "BISECT_START"))


def _conflict(work, a):
    w1._commit(work, "conflict.txt", "base\n")
    w1._git(work, "checkout", "-q", "-b", "topic")
    w1._commit(work, "conflict.txt", "topic\n")
    w1._commit(work, "other.txt", "o\n")
    w1._git(work, "checkout", "-q", "main")
    w1._commit(work, "conflict.txt", "main\n")


@pytest.mark.parametrize("how", ["merge", "rebase --merge", "rebase --apply", "cherry-pick"])
def test_CONTROL_an_operation_in_progress_with_a_conflict(env, tmp_path, how):
    work, a, _declared = _declared_alone(tmp_path)
    _conflict(work, a)
    if how.startswith("rebase"):
        w1._git(work, "checkout", "-q", "topic")
    args = {"merge": ["merge", "-q", "topic"], "cherry-pick": ["cherry-pick", "topic~1"]}.get(
        how, ["rebase", "-q", how.split()[-1], "main"])
    stopped = w1.n2c._git(work, *args, check=False)
    git_dir = work / ".git"
    state = {"merge": "MERGE_HEAD", "rebase --merge": "rebase-merge", "rebase --apply": "rebase-apply",
             "cherry-pick": "CHERRY_PICK_HEAD"}[how]
    assert stopped.returncode != 0 and (git_dir / state).exists(), "precondition: the operation stopped at its conflict"
    w1._assert_inactive(*w1._l1(env, work))
    present, _broken = gate._present_refs(str(work), time.monotonic() + 120)
    read = {"merge": ["MERGE_HEAD", "AUTO_MERGE"],
            "rebase --merge": ["rebase-merge/onto", "rebase-merge/orig-head", "rebase-merge/stopped-sha",
                               "REBASE_HEAD", "AUTO_MERGE"],
            "rebase --apply": ["rebase-apply/onto", "rebase-apply/orig-head", "rebase-apply/original-commit",
                               "rebase-apply/abort-safety"],
            "cherry-pick": ["CHERRY_PICK_HEAD", "AUTO_MERGE"]}[how]
    for name in read:
        if (git_dir / name).exists():
            assert name in present and present[name] == (git_dir / name).read_text().strip(), name


@pytest.mark.parametrize("declared_tree", [False, True], ids=["clean tree", "declared tree"])
def test_auto_merge_is_read_as_a_tree(env, tmp_path, declared_tree):
    work, a, declared = _declared_alone(tmp_path)
    tree = w1.n2c._rev(work, f"{declared if declared_tree else a}^{{tree}}")
    w1._git(work, "update-ref", "AUTO_MERGE", tree)
    answer, entry, text = w1._l1(env, work)
    if declared_tree:
        _declared_record(answer, entry, text, "AUTO_MERGE", tree)
    else:
        w1._assert_inactive(answer, entry, text)


# --- logs/ --------------------------------------------------------------------------------------------------------

def test_CONTROL_valid_reflog_history_with_an_old_declaration_stays_outside(env, tmp_path):
    work, a, declared = _declared_alone(tmp_path)
    w1._git(work, "branch", "-f", "side", declared)
    w1._git(work, "branch", "-f", "side", a)
    log = (work / ".git" / "logs" / "refs" / "heads" / "side").read_text()
    assert declared in log, "precondition: the reflog holds D"
    w1._assert_inactive(*w1._l1(env, work))


def test_RED_the_same_path_under_logs_with_only_the_object(env, tmp_path):
    work, a, declared = _declared_alone(tmp_path)
    w1._git(work, "branch", "-f", "side", a)
    _write(work, "logs/refs/heads/side", f"{declared}\n".encode())
    assert _rev(work, "logs/refs/heads/side") == declared
    _declared_record(*w1._l1(env, work), "logs/refs/heads/side", declared)


# --- broken, symbolic, linked, missing, unreadable ----------------------------------------------------------------

@pytest.mark.parametrize("data, reason", [
    (b"%s extra\n", "a record not of the form <object>LF"),
    (b"%s", "a record not of the form <object>LF"),
    (b"UPPER\n", "a record not of the form <object>LF"),
    (b"ref: refs/heads/main\n", "a symbolic record"),
    (b"ref: refs/heads/nowhere\n", "a symbolic record"),
])
def test_RED_a_further_record_in_another_form(env, tmp_path, data, reason):
    work, _a, declared = _declared_alone(tmp_path)
    raw = data.replace(b"UPPER", declared.upper().encode()) if b"UPPER" in data else (
        data % declared.encode() if b"%s" in data else data)
    _write(work, "sub/foo", raw)
    w1._assert_exception_refused(*w1._l1(env, work), gate._further(reason, "sub/foo"))


@pytest.mark.parametrize("name", ["foo", "sub/foo"])
def test_RED_a_recognizable_record_form_git_does_not_resolve(env, tmp_path, name):
    """Rule 5: an object name followed by other bytes is a record form, and git resolves it as nothing (at the top with
    no output, below a folder with its warning about a broken ref, measured with git 2.43.0)."""
    work, _a, declared = _declared_alone(tmp_path)
    _write(work, name, f"{declared}xyz\n".encode())
    assert _rev(work, name) is None, "precondition: git does not resolve the file"
    w1._assert_exception_refused(*w1._l1(env, work), gate._further("a record form git does not resolve", name))


def test_CONTROL_text_below_a_folder_is_no_former_ref_by_its_path(env, tmp_path):
    """Rule 5, the other half: git warns `ignoring broken ref` for any text below a folder of the git directory, and
    arbitrary text is not a damaged former ref by its path alone."""
    work, _a, _declared = _declared_alone(tmp_path)
    _write(work, "sub/notes", b"just a note\n")
    probe = subprocess.run(["git", "-C", str(work), "rev-parse", "--verify", "--quiet", "--end-of-options", "sub/notes"],
                           capture_output=True, text=True, check=False)
    assert (probe.returncode, probe.stderr) == (1, "warning: ignoring broken ref sub/notes\n"), "precondition"
    w1._assert_inactive(*w1._l1(env, work))


def test_RED_a_record_under_a_name_git_s_rules_refuse(env, tmp_path):
    work, _a, declared = _declared_alone(tmp_path)
    _write(work, "sub/foo.lock", f"{declared}\n".encode())
    w1._assert_exception_refused(*w1._l1(env, work),
                                 gate._further("a record under a name git's ref rules refuse", "sub/foo.lock"))


def test_RED_a_record_git_cannot_tell_from_a_branch_of_the_same_name(env, tmp_path):
    work, a, declared = _declared_alone(tmp_path)
    w1._git(work, "branch", "foo", a)
    _write(work, "foo", f"{declared}\n".encode())
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, "git warns while it resolves the name: error: refname 'foo' is "
                                                      "ambiguous")


def test_CONTROL_an_ordinary_file_whose_name_git_resolves_to_a_branch(env, tmp_path):
    """git's substitution of a name, no record: .git/description holds text, and a branch is called description."""
    work, a, _declared = _declared_alone(tmp_path)
    w1._git(work, "branch", "description", a)
    assert subprocess.run(["git", "-C", str(work), "rev-parse", "--verify", "--quiet", "--symbolic-full-name",
                           "description"], capture_output=True, text=True).stdout.strip() == "refs/heads/description"
    w1._assert_inactive(*w1._l1(env, work))


@pytest.mark.parametrize("what", ["file", "folder"])
def test_RED_a_symbolic_link_in_the_git_directory(env, tmp_path, what):
    work, a, _declared = _declared_alone(tmp_path)
    target = _write(work, "real/foo", f"{a}\n".encode())
    os.symlink(target if what == "file" else target.parent, work / ".git" / "linked")
    w1._assert_exception_refused(*w1._l1(env, work), f"{w1.n2c.gate._off_form('a symbolic link', 'linked')}")


def test_RED_a_further_record_naming_an_object_git_does_not_give(env, tmp_path):
    work, _a, _declared = _declared_alone(tmp_path)
    missing = "1" * 40
    _write(work, "sub/foo", f"{missing}\n".encode())
    w1._assert_exception_refused(*w1._l1(env, work), "the local ref sub/foo names an object git does not give here")


def test_RED_an_entry_that_is_no_regular_file(env, tmp_path):
    work, _a, _declared = _declared_alone(tmp_path)
    os.mkfifo(work / ".git" / "pipe")
    w1._assert_exception_refused(*w1._l1(env, work), gate._further("an entry that is no regular file", "pipe"))


def test_RED_an_entry_the_gate_cannot_read(tmp_path, monkeypatch):
    work, _a, _declared = _declared_alone(tmp_path)
    _write(work, "sub/foo", b"text\n")
    real = os.lstat

    def refuse(path, *args, **kwargs):
        if str(path).endswith(os.path.join("sub", "foo")):
            raise PermissionError(13, "Permission denied", str(path))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(gate.os, "lstat", refuse)
    verdict, why = _local(work)
    assert verdict is None and why == ("the git directory cannot be read whole, so a record of the destination may be "
                                       "unread"), why


# --- limits and change while reading -----------------------------------------------------------------------------

def test_RED_more_further_files_than_the_gate_reads(tmp_path, monkeypatch):
    work, _a, _declared = _declared_alone(tmp_path)
    monkeypatch.setattr(gate, "MAX_FURTHER_FILES", 3)
    verdict, why = _local(work)
    assert verdict is None and why.startswith("the git directory holds more than 3 further files"), why


def test_RED_a_reflog_larger_than_the_gate_reads(tmp_path, monkeypatch):
    work, _a, _declared = _declared_alone(tmp_path)
    size = (work / ".git" / "logs" / "HEAD").stat().st_size
    monkeypatch.setattr(gate, "MAX_RECORD_BYTES", size - 1)
    verdict, why = _local(work)
    assert verdict is None and why == gate._further("a record not of the form <object>LF", "logs/HEAD"), why


def test_RED_the_time_limit_while_git_answers_for_further_files(tmp_path, monkeypatch):
    work, _a, _declared = _declared_alone(tmp_path)
    real = gate._resolution
    monkeypatch.setattr(gate, "_resolution", lambda repo, name, deadline: real(repo, name, time.monotonic() - 1))
    verdict, why = _local(work)
    assert verdict is None and why == "the gate could not finish its reading (the gate ran out of time)", why


def test_CONTROL_within_the_limits_the_exception_holds(tmp_path):
    work, _a, _declared = _declared_alone(tmp_path)
    verdict, why = _local(work)
    assert why is None and verdict is not None and verdict.decision == "inactive", why
    assert ("every further file of its git directory whose exact name git resolves, valid reflogs left outside"
            in verdict.detail), "the answer names the boundary built"


def test_RED_a_further_file_that_changes_while_git_answers(tmp_path, monkeypatch):
    work, a, declared = _declared_alone(tmp_path)
    path = _write(work, "sub/foo", f"{a}\n".encode())
    real = gate._resolution

    def meanwhile(repo, name, deadline):
        answer = real(repo, name, deadline)
        if name == "sub/foo":
            path.write_bytes(f"{declared}\n".encode())
        return answer

    monkeypatch.setattr(gate, "_resolution", meanwhile)
    verdict, why = _local(work)
    assert verdict is None and why == gate._further("a file that changed while the gate read it", "sub/foo"), why


def test_RED_a_further_record_that_appears_before_the_final_reading(tmp_path, monkeypatch):
    """The property of R17-1 for further records: the map of the final reading holds what both readings gave."""
    work, a, declared = _declared_alone(tmp_path)
    path = _write(work, "sub/foo", f"{a}\n".encode())
    real, calls = gate._further_records, []

    def store(repo, paths, present, symbolic, deadline):
        calls.append(1)
        if len(calls) == 3:
            path.write_bytes(f"{declared}\n".encode())
        return real(repo, paths, present, symbolic, deadline)

    monkeypatch.setattr(gate, "_further_records", store)
    verdict, why = _local(work)
    assert len(calls) == 3 and verdict is None and why == CHANGED, why
    assert _rev(work, "sub/foo") == declared


# --- the positive path ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("step", ["fresh", "gc and pack-refs", "fetch"])
def test_CONTROL_the_positive_path_stays_reachable(env, tmp_path, step):
    work, _a, _declared = _declared_alone(tmp_path)
    if step == "gc and pack-refs":
        w1._git(work, "gc", "-q")
        w1._git(work, "pack-refs", "--all")
        assert (work / ".git" / "info" / "refs").exists(), "precondition: git gc wrote info/refs"
    if step == "fetch":
        w1._git(work, "fetch", "-q", "origin")
        w1._git(work, "fetch", "-q", "origin", "main")
    w1._assert_inactive(*w1._l1(env, work))
