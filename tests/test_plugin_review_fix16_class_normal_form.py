"""Review round 16 of 2026-10-13, the class of R16-1 to R16-4: the normal form of the ref store, beyond the four cases.

Owner choice of 2026-10-13, 16:4x Berlin, A: condition d grants inactive only for a ref store in an exactly checked
normal form; whatever departs from it gives ask with the reason and the entry. Further departures, measured with git
2.43.0 (probe of review fix 16) before they were taken in: git reads a loose file or a root record with a blank, a second
line, no line feed, a carriage return or `ref:` with no space; packed-refs with an object in capitals or a name outside
refs/; and lists both names of packed-refs whose `sorted` header promises an order the lines do not keep, while its
lookup misses one. git follows a symbolic link at packed-refs, at refs/, at a root record, at a worktree's folder and
at a ref of another worktree. Each case first takes git's own answer, then requires the gate to ask with the reason and
the entry; the controls keep the exception where the store is in the normal form. Further cases kill mutants of the
mutation probe of review fix 16: a rule that only a direct call reaches, since git's own refusal comes first in the hook, and
the loose files that answer for a shared name.
"""
from __future__ import annotations

import os
import subprocess
import time

import pytest

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

OFF_FORM = "the ref store is not in the form the gate reads"
NOT_FILE = "a file not of the form <object>LF or ref: <name>LF"
NOT_ESTABLISHED = ("The gate cannot establish how this local record resolves in its worktree, so the exception does "
                   "not apply: ")


def _git_resolves(where, name):
    probe = subprocess.run(["git", "-C", str(where), "rev-parse", "--verify", "--quiet", name], capture_output=True,
                           text=True, check=False)
    return probe.returncode == 0 and bool(probe.stdout.strip())


def _listed(where):
    listing = subprocess.run(["git", "-C", str(where), "for-each-ref", "--format=%(refname)"], capture_output=True,
                             text=True, check=False)
    assert listing.returncode == 0 and not listing.stderr, listing
    return listing.stdout.split()


def _other(work, tmp_path, a):
    other = tmp_path / "other"
    w1._git(work, "worktree", "add", "-q", "--detach", str(other), a)
    return other


# --- loose files and root records in a form git reads and the gate does not ---------------------------------------

LOOSE_FORMS = [
    pytest.param(lambda a: f"{a} \n", NOT_FILE, id="blank"),
    pytest.param(lambda a: f"{a} extra\n", NOT_FILE, id="more"),
    pytest.param(lambda a: a, NOT_FILE, id="no_line_feed"),
    pytest.param(lambda a: f"{a}\r\n", NOT_FILE, id="carriage_return"),
    pytest.param(lambda a: f"{a}\n\n", NOT_FILE, id="second_line"),
    pytest.param(lambda a: "ref:refs/heads/main\n", NOT_FILE, id="ref_no_space"),
    pytest.param(lambda a: "ref: refs/heads/main \n", "a target git's ref rules refuse", id="ref_blank"),
]


@pytest.mark.parametrize("content, reason", LOOSE_FORMS)
def test_a_loose_file_in_a_form_git_reads(env, tmp_path, content, reason):
    work, _remote, a = w1._undeclared(tmp_path)
    (work / ".git" / "refs" / "heads" / "x").write_bytes(content(a).encode("ascii"))
    assert _git_resolves(work, "refs/heads/x") and "refs/heads/x" in _listed(work)
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"{OFF_FORM} ({reason}): refs/heads/x")


@pytest.mark.parametrize("content, reason", LOOSE_FORMS[:5])
def test_a_root_record_in_a_form_git_reads(env, tmp_path, content, reason):
    work, _remote, a = w1._undeclared(tmp_path)
    (work / ".git" / "ORIG_HEAD").write_bytes(content(a).encode("ascii"))
    assert _git_resolves(work, "ORIG_HEAD")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"{OFF_FORM} ({reason}): ORIG_HEAD")


def test_a_target_git_s_ref_rules_refuse_in_this_worktree(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    (work / ".git" / "ORIG_HEAD").write_bytes(b"ref: refs/heads/foo..bar\n")
    assert not _git_resolves(work, "ORIG_HEAD")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"{OFF_FORM} (a target git's ref rules refuse): ORIG_HEAD")


def test_merge_head_with_an_empty_line(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    (work / ".git" / "MERGE_HEAD").write_bytes(f"{a}\n\n{a}\n".encode("ascii"))
    assert _git_resolves(work, "MERGE_HEAD")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text,
                                 f"{OFF_FORM} (a line of MERGE_HEAD not of the form <object>LF): MERGE_HEAD")


def test_control_merge_head_with_one_object_per_merged_head_keeps_the_exception(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    (work / ".git" / "MERGE_HEAD").write_bytes(f"{a}\n{a}\n".encode("ascii"))
    assert _git_resolves(work, "MERGE_HEAD")
    w1._assert_inactive(*w1._l1(env, work))


# --- packed-refs ------------------------------------------------------------------------------------------------

def _packed(tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    w1._git(work, "branch", "side", a)
    w1._git(work, "pack-refs", "--all")
    packed = work / ".git" / "packed-refs"
    lines = packed.read_text(encoding="ascii").splitlines()
    assert lines[0].startswith("# pack-refs with:") and " sorted" in lines[0] and not any(
        line.startswith("^") for line in lines), lines
    return work, a, packed, lines


def test_packed_refs_out_of_the_order_its_header_promises(env, tmp_path):
    """side after refs/remotes/origin/main: git lists it, and its lookup in the sorted file misses it."""
    work, _a, packed, lines = _packed(tmp_path)
    names = [line.split(" ", 1)[1] for line in lines[1:]]
    assert names == ["refs/heads/main", "refs/heads/side", "refs/remotes/origin/main"], names
    packed.write_text("\n".join([lines[0], lines[1], lines[3], lines[2]]) + "\n", encoding="ascii")
    assert "refs/heads/side" in _listed(work) and not _git_resolves(work, "refs/heads/side")
    assert _git_resolves(work, "refs/heads/main") and _git_resolves(work, "refs/remotes/origin/main")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"{OFF_FORM} (packed-refs out of the order its header promises): "
                                                      "refs/heads/side")


def test_control_packed_refs_without_a_header_in_any_order_keeps_the_exception(env, tmp_path):
    work, _a, packed, lines = _packed(tmp_path)
    packed.write_text("\n".join(reversed(lines[1:])) + "\n", encoding="ascii")
    assert all(_git_resolves(work, line.split(" ", 1)[1]) for line in lines[1:])
    w1._assert_inactive(*w1._l1(env, work))


def test_packed_refs_with_an_object_in_capitals(env, tmp_path):
    work, a, packed, lines = _packed(tmp_path)
    packed.write_text("\n".join(line.replace(f"{a} refs/heads/side", f"{a.upper()} refs/heads/side")
                                for line in lines) + "\n", encoding="ascii")
    assert _git_resolves(work, "refs/heads/side")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text,
                                 f"{OFF_FORM} (a line of packed-refs not of the form <object> <name>): packed-refs")


def test_packed_refs_with_a_name_outside_refs(env, tmp_path):
    work, a, packed, lines = _packed(tmp_path)
    packed.write_text("\n".join([*lines, f"{a} foo"]) + "\n", encoding="ascii")
    assert "foo" in _listed(work) and not _git_resolves(work, "foo")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"{OFF_FORM} (a name outside refs/ in packed-refs): foo")


def test_control_a_name_with_bytes_above_0x7f_keeps_the_exception(env, tmp_path):
    work, a, packed, lines = _packed(tmp_path)
    entries = sorted([*lines[1:], f"{a} refs/heads/zä"], key=lambda line: line.split(" ", 1)[1].encode("utf-8"))
    packed.write_bytes(("\n".join([lines[0], *entries]) + "\n").encode("utf-8"))
    w1._git(work, "branch", "wä", a)
    assert {"refs/heads/zä", "refs/heads/wä"} <= set(_listed(work))
    w1._assert_inactive(*w1._l1(env, work))


def test_a_name_git_s_ref_rules_refuse_in_packed_refs_read_directly(tmp_path):
    """git warns about such a line before the gate reads packed-refs in the hook; the rule stands on its own."""
    work, a, packed, lines = _packed(tmp_path)
    packed.write_text("\n".join([lines[0], f"{a} refs/heads/foo..bar", *lines[1:]]) + "\n", encoding="ascii")
    deadline = time.monotonic() + 120
    paths, _why = gate._repo_paths(str(work), deadline)
    store, why = gate._stored_refs(str(work), paths, deadline)
    assert store is None and why == f"{OFF_FORM} (a name git's ref rules refuse): refs/heads/foo..bar", why


PACKED_LINES = [
    pytest.param(lambda head, body: head + body[:-1], id="no_final_line_feed"),
    pytest.param(lambda head, body: head + b"^" + body[:40] + b"\n" + body, id="peel_line_first"),
    pytest.param(lambda head, body: head + body + b"^" + body[:40] + b"\n" + b"^" + body[:40] + b"\n",
                 id="peel_line_twice"),
    pytest.param(lambda head, body: body + head, id="header_later"),
    pytest.param(lambda head, body: head + b"\n" + body, id="empty_line"),
    pytest.param(lambda head, body: head + body[:39] + body[40:], id="short_object"),
]


@pytest.mark.parametrize("shape", PACKED_LINES)
def test_a_line_of_packed_refs_git_refuses_read_directly(tmp_path, shape):
    """git ends with an error on each of these (measured with git 2.43.0), so the hook asks before the gate reads
    packed-refs; the rule stands on its own."""
    work, _a, packed, _lines = _packed(tmp_path)
    raw = packed.read_bytes()
    head, _nl, body = raw.partition(b"\n")
    packed.write_bytes(shape(head + b"\n", body))
    deadline = time.monotonic() + 120
    paths, _why = gate._repo_paths(str(work), deadline)
    store, why = gate._stored_refs(str(work), paths, deadline)
    assert store is None and why == (f"{OFF_FORM} (a line of packed-refs not of the form <object> <name>): "
                                     "packed-refs"), why


def test_a_name_git_s_ref_rules_refuse_in_git_s_listing(env, tmp_path, monkeypatch):
    """The listing as an input of its own: a name git lists that its ref rules refuse."""
    work, _remote, a = w1._undeclared(tmp_path)
    real = gate._git

    def widened(repo, *args, deadline):
        out = real(repo, *args, deadline=deadline)
        if args[:1] == ("for-each-ref",) and out.returncode == 0:
            out = subprocess.CompletedProcess(out.args, 0, out.stdout + f"refs/heads/foo..bar\0{a}\0\n".encode(),
                                              out.stderr)
        return out

    monkeypatch.setattr(gate, "_git", widened)
    present, why = gate._present_refs(str(work), time.monotonic() + 120)
    assert present is None and why == f"{OFF_FORM} (a name git's ref rules refuse): refs/heads/foo..bar", why


# --- symbolic links git follows ------------------------------------------------------------------------------------

def test_packed_refs_as_a_symbolic_link(env, tmp_path):
    work, _a, packed, _lines = _packed(tmp_path)
    real = packed.with_name("packed-refs.real")
    packed.rename(real)
    os.symlink("packed-refs.real", packed)
    assert _git_resolves(work, "refs/heads/side")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"{OFF_FORM} (a symbolic link): packed-refs")


def test_the_refs_folder_as_a_symbolic_link(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    refs = work / ".git" / "refs"
    refs.rename(refs.with_name("refs.real"))
    os.symlink("refs.real", refs)
    assert _git_resolves(work, "refs/heads/main")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"{OFF_FORM} (a symbolic link): refs")


def test_a_root_record_as_a_symbolic_link(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    (work / ".git" / "ORIG_HEAD.real").write_text(f"{a}\n", encoding="ascii")
    os.symlink("ORIG_HEAD.real", work / ".git" / "ORIG_HEAD")
    assert _git_resolves(work, "ORIG_HEAD")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"{OFF_FORM} (a symbolic link): ORIG_HEAD")


def test_a_ref_of_another_worktree_as_a_symbolic_link(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    other = _other(work, tmp_path, a)
    w1._git(other, "update-ref", "refs/bisect/real", a)
    os.symlink("real", work / ".git" / "worktrees" / "other" / "refs" / "bisect" / "x")
    assert _git_resolves(other, "refs/bisect/x")
    answer, entry, text = w1._l1(env, work)
    # Narrow contract of 2026-10-13, 17:0x: a further worktree lies outside its range and is asked first.
    w1._assert_outside(answer, entry, text, "a further worktree", "worktrees/other")


def test_the_refs_folder_of_another_worktree_as_a_symbolic_link(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    other = _other(work, tmp_path, a)
    w1._git(other, "update-ref", "refs/bisect/here", a)
    refs = work / ".git" / "worktrees" / "other" / "refs"
    refs.rename(refs.with_name("refs.real"))
    os.symlink("refs.real", refs)
    assert _git_resolves(other, "refs/bisect/here")
    answer, entry, text = w1._l1(env, work)
    # Narrow contract of 2026-10-13, 17:0x: a further worktree lies outside its range and is asked first.
    w1._assert_outside(answer, entry, text, "a further worktree", "worktrees/other")


def test_the_folder_of_another_worktree_as_a_symbolic_link(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    other = _other(work, tmp_path, a)
    folder = work / ".git" / "worktrees" / "other"
    (work / ".git" / "moved").mkdir()
    folder.rename(work / ".git" / "moved" / "other")   # the same depth below .git, for its commondir ../..
    os.symlink("../moved/other", folder)
    assert _git_resolves(other, "HEAD")
    answer, entry, text = w1._l1(env, work)
    # Narrow contract of 2026-10-13, 17:0x: a further worktree lies outside its range and is asked first.
    w1._assert_outside(answer, entry, text, "a further worktree", "worktrees/other")


# --- the loose files that answer for a shared name ---------------------------------------------------------------

def test_a_shared_name_in_a_linked_worktree_s_own_folder_answers_nothing(env, tmp_path):
    """git reads refs/heads/bridge from the common directory only; a file of that name under worktrees/linked/refs/
    is one git does not read, so it does not stand in for the shared ref's first step."""
    work, _remote, a = w1._undeclared(tmp_path)
    linked = tmp_path / "linked"
    w1._git(work, "worktree", "add", "-q", "-b", "side", str(linked))
    w1._git(linked, "update-ref", "refs/bisect/here", a)
    w1._git(linked, "symbolic-ref", "refs/heads/bridge", "refs/bisect/here")
    stray = work / ".git" / "worktrees" / "linked" / "refs" / "heads" / "bridge"
    stray.parent.mkdir(parents=True, exist_ok=True)
    stray.write_bytes(b"ref: refs/heads/main\n")
    assert not _git_resolves(work, "refs/heads/bridge") and _git_resolves(linked, "refs/heads/bridge")
    assert w1._git(linked, "symbolic-ref", "refs/heads/bridge").stdout.strip() == "refs/bisect/here"
    answer, entry, text = w1._l1(env, linked, "git push origin side")
    # Narrow contract of 2026-10-13, 17:0x: a linked worktree lies outside its range and is asked first.
    w1._assert_outside(answer, entry, text, "a linked worktree", str(linked))
