"""K16-1 of review fix 16 with the rule of review round 17, the rebase on the positive path: git's rewritten lists of a stopped
rebase are records read line by line.

Measured at b3ce11d7 with git 2.43.0 (false-alarm run of review fix 17): a rebase stopped at a later pick leaves
rebase-merge/rewritten-list (--merge) or rebase-apply/rewritten (--apply) of `<old> <new>LF` lines, and a rebase -i
stopped inside a fixup chain leaves rebase-merge/rewritten-pending of `<oid>LF` lines. git resolves each name to the first
object of its first line, the full name is the file's own, and the gate asked (a record not of the form <object>LF),
so Level 1 asked for `git push origin main` in an ordinary rebase. Now each object of each line is a record, the first
under the file's name, and any other form is asked. Run with git 2.43.0.
"""
from __future__ import annotations

import time

import pytest

import test_plugin_owner_choice1_undeclared_push as w1
import test_plugin_review_fix17_k16_1_further_records as k1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

#: How each list comes about, the file, and the objects on one of its lines.
HOW = {"rebase --merge": ("rebase-merge/rewritten-list", 2), "rebase --apply": ("rebase-apply/rewritten", 2),
       "rebase -i fixup chain": ("rebase-merge/rewritten-pending", 1)}


def _stopped(tmp_path, how):
    """A rebase of topic onto main stopped at its third commit, after two it has rewritten or chained already."""
    work, a, declared = k1._declared_alone(tmp_path)
    w1._commit(work, "conflict.txt", "base\n")
    w1._git(work, "checkout", "-q", "-b", "topic")
    w1._commit(work, "clean0.txt", "0\n")
    w1._commit(work, "clean1.txt", "1\n")
    w1._commit(work, "conflict.txt", "topic\n")
    w1._git(work, "checkout", "-q", "main")
    w1._commit(work, "conflict.txt", "main\n")
    w1._git(work, "checkout", "-q", "topic")
    if how == "rebase -i fixup chain":
        editor = tmp_path / "fixup_chain.sh"
        editor.write_text("#!/bin/sh\nsed -i '2s/^pick/fixup/; 3s/^pick/fixup/' \"$1\"\n", encoding="utf-8")
        editor.chmod(0o755)
        stopped = w1.n2c._git(work, "-c", f"sequence.editor={editor}", "rebase", "-i", "main", check=False)
    else:
        stopped = w1.n2c._git(work, "rebase", how.split()[-1], "main", check=False)
    rel, width = HOW[how]
    lines = (work / ".git" / rel).read_text().splitlines()
    assert stopped.returncode != 0 and len(lines) == 2 and all(len(line.split()) == width for line in lines), \
        "precondition: the rebase stopped at its third commit with two lines in its list"
    assert k1._rev(work, rel) == lines[0].split()[0], "precondition: git resolves the name to the first object"
    return work, a, declared, rel, lines


@pytest.mark.parametrize("how", list(HOW))
def test_CONTROL_a_rebase_stopped_at_a_later_commit_keeps_the_exception(env, tmp_path, how):
    work, _a, _declared, rel, lines = _stopped(tmp_path, how)
    w1._assert_inactive(*w1._l1(env, work))
    present, _broken = gate._present_refs(str(work), time.monotonic() + 120)
    objects = [part for line in lines for part in line.split()]
    read = [present[rel]] + [present[f"{rel} (line {n}, object {m})"] for n, line in enumerate(lines, 1)
                             for m in range(1, len(line.split()) + 1) if (n, m) != (1, 1)]
    assert read == objects, "every object of every line is read as a record"


@pytest.mark.parametrize("how", list(HOW))
def test_RED_a_declared_commit_in_a_rewritten_list(env, tmp_path, how):
    work, a, declared, rel, _lines = _stopped(tmp_path, how)
    line = f"{a} {declared}\n" if HOW[how][1] == 2 else f"{declared}\n"
    with open(work / ".git" / rel, "a", encoding="ascii") as handle:
        handle.write(line)
    k1._declared_record(*w1._l1(env, work), f"{rel} (line 3, object {HOW[how][1]})", declared)


@pytest.mark.parametrize("change", ["one object", "three objects", "capitals", "no line feed", "empty line"])
def test_RED_a_rewritten_list_in_another_form(env, tmp_path, change):
    work, a, _declared, rel, lines = _stopped(tmp_path, "rebase --merge")
    path = work / ".git" / rel
    first = lines[0]
    if change == "one object":
        data = f"{first}\n{a}\n"
    elif change == "three objects":
        data = f"{first}\n{lines[1]} {a}\n"
    elif change == "capitals":
        data = f"{first}\n{lines[1].upper()}\n"
    elif change == "no line feed":
        data = f"{first}\n{lines[1]}"
    else:
        data = f"{first}\n\n{lines[1]}\n"
    path.write_text(data, encoding="ascii")
    w1._assert_exception_refused(*w1._l1(env, work), gate._further(gate._REWRITTEN_FORM, rel))


def test_RED_a_rewritten_list_that_changes_after_git_answered(tmp_path, monkeypatch):
    work, a, declared, rel, lines = _stopped(tmp_path, "rebase --merge")
    path = work / ".git" / rel
    real = gate._resolution

    def meanwhile(repo, name, deadline):
        answer = real(repo, name, deadline)
        if name == rel:
            path.write_text(f"{lines[0]}\n{a} {declared}\n", encoding="ascii")
        return answer

    monkeypatch.setattr(gate, "_resolution", meanwhile)
    verdict, why = k1._local(work)
    assert verdict is None and why == gate._further("a file that changed while the gate read it", rel), why


def test_RED_a_rewritten_list_larger_than_the_gate_reads(tmp_path, monkeypatch):
    """The limit of MAX_RECORD_BYTES for the list alone, since the reflog of HEAD is larger."""
    work, _a, _declared, rel, _lines = _stopped(tmp_path, "rebase --merge")
    real = gate._record_bytes
    monkeypatch.setattr(gate, "_record_bytes", lambda path: None if path.endswith(rel) else real(path))
    verdict, why = k1._local(work)
    assert verdict is None and why == gate._too_large(rel), why
