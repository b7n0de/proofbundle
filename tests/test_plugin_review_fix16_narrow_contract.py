"""The narrow contract of condition d (owner choice of 2026-10-13, 17:0x Berlin, A and A; Nachtrag ENGER-VERTRAG of
FIX-16), after the external design review of that day at 101bd167.

The review measured with git 2.51.1 that git's answer in each worktree was right where the gate's own rebuild of chains,
worktree contexts and depths was not, and that completeness and resolution are two measurements: git's listing leaves
out a symbolic ref it cannot resolve, lists both lines of a name packed twice, leaves out ORIG_HEAD and FETCH_HEAD, and
`git rev-parse FETCH_HEAD` reads its first line only. The owner chose a narrow range in which git resolves: inactive
only for one ordinary main worktree whose only symbolic refs are HEAD and refs/remotes/<remote>/HEAD, each naming a ref
git lists, with the ref store in the normal form of FIX-16 and read whole; anything else is asked with the reason and
the entry.

The cases follow the card: 3a R16-1 to R16-4 with their controls get no exception; 3b the worktree and depth probes of
rounds 12 to 15 stay closed, and a second worktree is asked at once; 3c positive controls reach inactive (a version that
always asks fails here); 3d a second line of FETCH_HEAD with a declaration blocks the exception, with not-for-merge too,
and a name twice is caught before it is assigned, in both orders; 3e the review's chain other/ORIG_HEAD ->
refs/heads/bridge -> refs/bisect/here is asked. Further cases hold one point each of the contract, for the mutation
probe. Each case first takes git's own answer where it names a record. Run with git 2.43.0.
"""
from __future__ import annotations

import os
import subprocess
import time

import pytest

import test_plugin_owner_choice1_ask_names_the_record_20261013 as a1
import test_plugin_owner_choice1_undeclared_push as w1
import test_plugin_review_fix12_r1_present_refs as p1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

OFF_FORM = "the ref store is not in the form the gate reads"
SYMBOLIC = "a symbolic ref other than HEAD and refs/remotes/<remote>/HEAD"
INDIRECT = "a symbolic ref whose target is not a ref git lists, named directly"


def _git_resolves(where, name):
    probe = subprocess.run(["git", "-C", str(where), "rev-parse", "--verify", "--quiet", "--end-of-options", name],
                           capture_output=True, text=True, check=False)
    return probe.returncode == 0 and bool(probe.stdout.strip())


def _other(work, tmp_path, a):
    other = tmp_path / "other"
    w1._git(work, "worktree", "add", "-q", "--detach", str(other), a)
    return other


# --- 3a: R16-1 to R16-4 in the narrow range ---------------------------------------------------------------------

@pytest.mark.parametrize("first", ["declared", "clean"])
def test_3a_r16_1_a_name_twice_in_packed_refs(env, tmp_path, first):
    work, _remote, a = w1._undeclared(tmp_path)
    declared = a1._declared_on_top(work, a)
    w1._git(work, "branch", "side", a)
    w1._git(work, "pack-refs", "--all")
    packed = work / ".git" / "packed-refs"
    lines = packed.read_text(encoding="ascii").splitlines()
    position = next(i for i, line in enumerate(lines) if line.endswith(" refs/heads/side"))
    pair = [f"{declared} refs/heads/side", f"{a} refs/heads/side"]
    lines[position:position + 1] = pair if first == "declared" else pair[::-1]
    packed.write_text("\n".join(lines) + "\n", encoding="ascii")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"{OFF_FORM} (a name twice in git's listing): refs/heads/side")


@pytest.mark.parametrize("target", ["no-target", "refs/bisect/here"])
def test_3a_r16_2_a_loose_ref_that_is_a_symbolic_link(env, tmp_path, target):
    work, _remote, a = w1._undeclared(tmp_path)
    w1._git(work, "branch", "side", a)
    w1._git(work, "pack-refs", "--all")
    (work / ".git" / "refs" / "heads").mkdir(parents=True, exist_ok=True)
    os.symlink(target, work / ".git" / "refs" / "heads" / "side")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"{OFF_FORM} (a symbolic link): refs/heads/side")


@pytest.mark.parametrize("name", ["foo..bar", ".hidden", "foo.lock", "foo bar"])
def test_3a_r16_3_a_name_git_s_rules_refuse_on_this_worktree_s_own_branch(env, tmp_path, name):
    work, _remote, a = w1._undeclared(tmp_path)
    (work / ".git" / "refs" / "bisect").mkdir(parents=True, exist_ok=True)
    (work / ".git" / "refs" / "bisect" / name).write_bytes(f"{a}\n".encode())
    (work / ".git" / "ORIG_HEAD").write_bytes(f"ref: refs/bisect/{name}\n".encode())
    assert not _git_resolves(work, "ORIG_HEAD")
    answer, entry, text = w1._l1(env, work)
    # git warns about foo..bar and "foo bar" and passes over .hidden and foo.lock in silence; each ask names the entry
    w1._assert_exception_refused(answer, entry, text, f"refs/bisect/{name}")


def test_3a_r16_4_an_empty_line_before_the_object(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    (work / ".git" / "ORIG_HEAD").write_bytes(f"\n{a}\n".encode())
    assert not _git_resolves(work, "ORIG_HEAD")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"{OFF_FORM} (a file not of the form <object>LF or ref: "
                                                      "<name>LF): ORIG_HEAD")


@pytest.mark.parametrize("setup", ["r16_2_without_the_link", "r16_3_a_name_git_takes", "r16_4_the_object_alone"])
def test_3a_the_controls_of_the_reviewer_with_their_second_worktree_are_asked(env, tmp_path, setup):
    work, _remote, a = w1._undeclared(tmp_path)
    other = _other(work, tmp_path, a)
    if setup == "r16_2_without_the_link":
        w1._git(work, "branch", "side", a)
        w1._git(work, "pack-refs", "--all")
        w1._git(other, "symbolic-ref", "ORIG_HEAD", "refs/heads/side")
    elif setup == "r16_3_a_name_git_takes":
        w1._git(other, "update-ref", "refs/bisect/good", a)
        w1._git(other, "symbolic-ref", "ORIG_HEAD", "refs/bisect/good")
    else:
        (work / ".git" / "worktrees" / "other" / "ORIG_HEAD").write_bytes(f"{a}\n".encode())
    w1._assert_outside(*w1._l1(env, work), "a further worktree", "worktrees/other")


# --- 3b and point 1: one ordinary main worktree -------------------------------------------------------------------

def test_3b_a_second_worktree_is_asked_at_once(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    _other(work, tmp_path, a)
    w1._assert_outside(*w1._l1(env, work), "a further worktree", "worktrees/other")


def test_3b_a_push_from_a_linked_worktree_is_asked(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    linked = tmp_path / "linked"
    w1._git(work, "worktree", "add", "-q", "-b", "side", str(linked))
    w1._assert_outside(*w1._l1(env, linked, "git push origin side"), "a linked worktree", str(linked))


def test_3b_an_entry_under_worktrees_git_does_not_list_is_asked(env, tmp_path):
    """Read from <git directory>/worktrees itself, not counted from `git worktree list`."""
    work, _remote, _a = w1._undeclared(tmp_path)
    (work / ".git" / "worktrees" / "stale").mkdir(parents=True)
    listed = w1._git(work, "worktree", "list", "--porcelain").stdout
    assert listed.count("worktree ") == 1, listed
    w1._assert_outside(*w1._l1(env, work), "a further worktree", "worktrees/stale")


def test_3b_worktrees_that_cannot_be_read_as_a_folder_is_asked(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    (work / ".git" / "worktrees").write_text("not a folder\n", encoding="utf-8")
    w1._assert_outside(*w1._l1(env, work), "an entry the gate cannot read", "worktrees")


def test_3b_an_inherited_git_dir_is_asked(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    moved = dict(env, GIT_DIR=str(work / ".git"))
    answer, entry, text = w1._l1(moved, work)
    assert answer["hookSpecificOutput"].get("permissionDecision") == "ask", answer
    assert "GIT_DIR" in text and "does not apply" in text, text


@pytest.mark.parametrize("steps", [2, 3])
def test_3b_a_chain_of_symbolic_refs_in_this_worktree_is_asked(env, tmp_path, steps):
    """The depth probes of round 15 in the narrow range: git resolves the chain, the contract takes no chain."""
    work, _remote, _a = w1._undeclared(tmp_path)
    names = [f"refs/heads/s{i}" for i in range(1, steps)]
    for here, there in zip(names, [*names[1:], "refs/heads/main"]):
        w1._git(work, "symbolic-ref", here, there)
    assert _git_resolves(work, "refs/heads/s1")
    w1._assert_outside(*w1._l1(env, work), SYMBOLIC, "refs/heads/s1")


# --- point 2: symbolic refs ---------------------------------------------------------------------------------------

def test_point_2_a_symbolic_branch_is_asked(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    w1._git(work, "symbolic-ref", "refs/heads/alias", "refs/heads/main")
    w1._assert_outside(*w1._l1(env, work), SYMBOLIC, "refs/heads/alias")


def test_point_2_a_symbolic_root_record_is_asked(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    w1._git(work, "symbolic-ref", "ORIG_HEAD", "refs/heads/main")
    w1._assert_outside(*w1._l1(env, work), SYMBOLIC, "ORIG_HEAD")


def test_point_2_a_name_that_only_ends_in_head_is_asked(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    w1._git(work, "symbolic-ref", "refs/heads/HEAD", "refs/heads/main")
    w1._assert_outside(*w1._l1(env, work), SYMBOLIC, "refs/heads/HEAD")


def test_point_2_the_head_of_a_remote_git_does_not_list_is_asked(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    w1._git(work, "update-ref", "refs/remotes/gone/main", "refs/remotes/origin/main")
    w1._git(work, "symbolic-ref", "refs/remotes/gone/HEAD", "refs/remotes/gone/main")
    w1._assert_outside(*w1._l1(env, work), SYMBOLIC, "refs/remotes/gone/HEAD")


def test_point_2_a_remote_head_through_a_chain_is_asked(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    w1._git(work, "symbolic-ref", "refs/remotes/origin/alias", "refs/remotes/origin/main")
    w1._git(work, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/alias")
    assert _git_resolves(work, "refs/remotes/origin/HEAD")
    w1._assert_outside(*w1._l1(env, work), INDIRECT, "refs/remotes/origin/HEAD")


def test_point_2_head_to_a_symbolic_ref_is_asked(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    w1._git(work, "remote", "set-head", "origin", "main")
    w1._git(work, "symbolic-ref", "HEAD", "refs/remotes/origin/HEAD")
    assert _git_resolves(work, "HEAD")
    answer, entry, text = w1._l1(env, work, "git push origin HEAD:refs/heads/main")
    w1._assert_outside(answer, entry, text, INDIRECT, "HEAD")


# --- 3c: positive controls ----------------------------------------------------------------------------------------

def test_3c_a_simple_clone_keeps_the_exception(env, tmp_path):
    _work, remote, _a = w1._undeclared(tmp_path)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(remote), str(clone)], check=True)
    assert w1._git(clone, "symbolic-ref", "refs/remotes/origin/HEAD").stdout.strip() == "refs/remotes/origin/main"
    w1._commit(clone, "d.txt")
    w1._assert_inactive(*w1._l1(env, clone))


def test_3c_the_allowed_head_and_remote_head_keep_the_exception(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    w1._git(work, "remote", "set-head", "origin", "main")
    assert w1._git(work, "symbolic-ref", "HEAD").stdout.strip() == "refs/heads/main"
    w1._assert_inactive(*w1._l1(env, work))


def test_3c_packed_refs_after_gc_and_pack_refs_keep_the_exception(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    w1._git(work, "remote", "set-head", "origin", "main")
    w1._git(work, "branch", "side", a)
    w1._git(work, "tag", "-a", "-m", "t", "v1", a)
    w1._git(work, "gc", "-q")
    w1._git(work, "pack-refs", "--all")
    assert not (work / ".git" / "refs" / "heads" / "side").exists()
    w1._assert_inactive(*w1._l1(env, work))


def test_3c_a_valid_loose_ref_before_its_packed_entry_keeps_the_exception(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    w1._git(work, "branch", "side", a)
    w1._git(work, "pack-refs", "--all")
    w1._git(work, "update-ref", "refs/heads/side", "HEAD")
    assert " refs/heads/side" in (work / ".git" / "packed-refs").read_text(encoding="ascii")
    assert (work / ".git" / "refs" / "heads" / "side").read_text(encoding="ascii") == w1.n2c._rev(work, "HEAD") + "\n"
    w1._assert_inactive(*w1._l1(env, work))


def test_3c_a_detached_head_keeps_the_exception(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    w1._git(work, "checkout", "-q", "--detach")
    w1._assert_inactive(*w1._l1(env, work, "git push origin HEAD:refs/heads/main"))


# --- 3d and points 4 and 5: the whole inventory, multi-line records ----------------------------------------------

@pytest.mark.parametrize("marker", ["", "not-for-merge"])
def test_3d_a_second_line_of_fetch_head_with_a_declaration(env, tmp_path, marker):
    work, _remote, a = w1._undeclared(tmp_path)
    declared = a1._declared_on_top(work, a)
    (work / ".git" / "FETCH_HEAD").write_text(f"{a}\t\tbranch 'main' of ../remote\n"
                                              f"{declared}\t{marker}\tbranch 'declared' of ../remote\n",
                                              encoding="utf-8")
    assert w1.n2c._rev(work, "FETCH_HEAD") == a          # git's own reading takes the first line only
    answer, entry, text = w1._l1(env, work)
    p1._refused_at(answer, entry, text, "FETCH_HEAD (line 2)", declared)


def test_3d_fetch_head_as_git_fetch_writes_it_keeps_the_exception(env, tmp_path):
    """Two lines, each not-for-merge, as `git fetch origin` writes them for two branches."""
    work, _remote, a = w1._undeclared(tmp_path)
    w1._git(work, "push", "-q", "--no-verify", "origin", f"{a}:refs/heads/side")
    w1._git(work, "fetch", "-q", "origin")
    lines = (work / ".git" / "FETCH_HEAD").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2 and all("\tnot-for-merge\t" in line for line in lines), lines
    w1._assert_inactive(*w1._l1(env, work))


@pytest.mark.parametrize("line", ["{a}\n", "{a} branch 'main' of ../remote\n", "{a}\tbranch 'main' of ../remote\n"])
def test_point_5_a_line_of_fetch_head_in_another_form(env, tmp_path, line):
    work, _remote, a = w1._undeclared(tmp_path)
    (work / ".git" / "FETCH_HEAD").write_text(line.format(a=a), encoding="utf-8")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"{OFF_FORM} (a line of FETCH_HEAD not of the form "
                                                      "<object>TAB[not-for-merge]TAB<note>LF): FETCH_HEAD")


def test_point_5_a_second_line_of_merge_head_with_a_declaration(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    declared = a1._declared_on_top(work, a)
    (work / ".git" / "MERGE_HEAD").write_text(f"{a}\n{declared}\n", encoding="utf-8")
    answer, entry, text = w1._l1(env, work)
    p1._refused_at(answer, entry, text, "MERGE_HEAD (line 2)", declared)


def _listing_changed(monkeypatch, change):
    real = gate._git

    def changed(repo, *args, deadline):
        out = real(repo, *args, deadline=deadline)
        if args[:1] == ("for-each-ref",) and out.returncode == 0:
            out = subprocess.CompletedProcess(out.args, 0, *change(out.stdout, out.stderr))
        return out

    monkeypatch.setattr(gate, "_git", changed)


@pytest.mark.parametrize("first", ["declared", "clean"])
def test_3d_a_name_twice_in_git_s_listing_before_any_assignment(tmp_path, monkeypatch, first):
    work, _remote, a = w1._undeclared(tmp_path)
    declared = a1._declared_on_top(work, a)
    pair = [f"refs/heads/side\0{declared}\0\n".encode(), f"refs/heads/side\0{a}\0\n".encode()]
    _listing_changed(monkeypatch, lambda out, err: (out + b"".join(pair if first == "declared" else pair[::-1]), err))
    present, why = gate._present_refs(str(work), time.monotonic() + 120)
    assert present is None and why == f"{OFF_FORM} (a name twice in git's listing): refs/heads/side", why


def test_point_4_a_ref_the_store_holds_and_git_does_not_list(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    w1._git(work, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/missing")
    assert "refs/remotes/origin/HEAD" not in w1._git(work, "for-each-ref", "--format=%(refname)").stdout.split()
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, "the local ref refs/remotes/origin/HEAD is present, but git does "
                                                      "not resolve it")


@pytest.mark.parametrize("change", [
    pytest.param(lambda out, err: (out + b"refs/heads/x\n", err), id="a_line_without_its_nul"),
    pytest.param(lambda out, err: (out[:-1], err), id="no_final_line_feed"),
    pytest.param(lambda out, err: (out + b"\n", err), id="an_empty_line"),
    pytest.param(lambda out, err: (out.replace(b"\0", b"\0" + b"0" * 40, 1), err), id="an_object_of_another_form")])
def test_point_4_a_line_of_git_s_listing_the_gate_cannot_read(tmp_path, monkeypatch, change):
    work, _remote, _a = w1._undeclared(tmp_path)
    _listing_changed(monkeypatch, change)
    present, why = gate._present_refs(str(work), time.monotonic() + 120)
    assert present is None and why == "git lists a line the gate cannot read, so a record of the destination may be " \
                                      "unread", why


# --- points 6 and 7: git's resolution, errors and limits --------------------------------------------------------

def test_point_6_an_object_git_does_not_give_is_no_absence(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    (work / ".git" / "refs" / "heads" / "ghost").write_text("1" * 40 + "\n", encoding="ascii")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, "the local ref refs/heads/ghost names an object git does not "
                                                      "give here")


@pytest.mark.parametrize("key", ["remote.origin.promisor", "extensions.partialClone"])
def test_point_6_the_reads_of_condition_d_refuse_promisor_configuration(tmp_path, key):
    """The refusal stands before each read of condition d itself, not only before the earlier reads of the hook
    (found by the mutation probe of the contract: without it in _git, the hook still refused at its state check)."""
    work, _remote, _a = w1._undeclared(tmp_path)
    w1._git(work, "config", key, "true" if key.endswith("promisor") else "origin")
    with pytest.raises(gate.GateError, match="promisor-related configuration that this gate does not evaluate"):
        gate._present_refs(str(work), time.monotonic() + 120)


def test_point_7_a_warning_beside_the_known_hint_is_asked(tmp_path, monkeypatch):
    work, _remote, _a = w1._undeclared(tmp_path)
    _listing_changed(monkeypatch, lambda out, err: (out, err + b"hint: something else\n"))
    present, why = gate._present_refs(str(work), time.monotonic() + 120)
    assert present is None and why.startswith("git warns while it lists"), why


def test_point_7_control_the_known_hint_alone_is_no_warning(tmp_path, monkeypatch):
    work, _remote, _a = w1._undeclared(tmp_path)
    hint = "".join(f"{line}\n" for line in (
        "hint: Support for <GIT_DIR>/info/grafts is deprecated", "hint: and will be removed in a future Git version.",
        "hint: ", "hint: Please use \"git replace --convert-graft-file\"",
        "hint: to convert the grafts into replace refs.", "hint: ", "hint: Turn this message off by running",
        "hint: \"git config advice.graftFileDeprecated false\""))
    _listing_changed(monkeypatch, lambda out, err: (out, err + hint.encode()))
    present, broken = gate._present_refs(str(work), time.monotonic() + 120)
    assert present is not None and "refs/heads/main" in present and broken == set(), broken


def test_point_7_a_record_larger_than_the_gate_reads(tmp_path, monkeypatch):
    work, _remote, a = w1._undeclared(tmp_path)
    (work / ".git" / "FETCH_HEAD").write_text(f"{a}\t\tbranch 'main' of ../remote\n", encoding="utf-8")
    monkeypatch.setattr(gate, "MAX_RECORD_BYTES", 41)                 # a loose ref, <oid>LF, holds 41
    present, why = gate._present_refs(str(work), time.monotonic() + 120)
    assert present is None and why.startswith("the record FETCH_HEAD holds more than 41 bytes"), why


def _local(work, deadline):
    head = w1.n2c._rev(work, "HEAD")
    return gate._local_inactivity(str(work), head, ["origin", "main"], [head], deadline)


def test_point_7_a_change_between_the_refs_and_their_objects(tmp_path, monkeypatch):
    work, _remote, a = w1._undeclared(tmp_path)
    real = gate._ref_trees

    def meanwhile(repo, refs, deadline):
        found = real(repo, refs, deadline)
        subprocess.run(["git", "-C", str(work), "update-ref", "refs/heads/meanwhile", a], check=True)
        return found

    monkeypatch.setattr(gate, "_ref_trees", meanwhile)
    verdict, why = _local(work, time.monotonic() + 120)
    assert verdict is None and why == ("the local refs changed while the gate read them, so its reading is no finished "
                                       "measurement that nothing is declared"), why


def test_point_7_control_no_change_keeps_the_exception(tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    verdict, why = _local(work, time.monotonic() + 120)
    assert why is None and verdict is not None and verdict.decision == "inactive", why


# --- 3e: the review's chain ---------------------------------------------------------------------------------------

def test_3e_the_reviewers_chain_through_a_shared_branch_to_a_name_only_the_main_worktree_holds(env, tmp_path):
    work, _remote, a = w1._undeclared(tmp_path)
    other = _other(work, tmp_path, a)
    w1._git(work, "update-ref", "refs/bisect/here", a)
    w1._git(work, "symbolic-ref", "refs/heads/bridge", "refs/bisect/here")
    w1._git(other, "symbolic-ref", "ORIG_HEAD", "refs/heads/bridge")
    assert not _git_resolves(other, "ORIG_HEAD")                      # git in the other worktree, exit 1
    assert _git_resolves(work, "worktrees/other/ORIG_HEAD")          # from the main worktree, exit 0
    w1._assert_outside(*w1._l1(env, work), "a further worktree", "worktrees/other")
