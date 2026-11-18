"""Review round 16 of 2026-10-13, R16-1: a ref name twice in the ref store.

Measured by the reviewer at 101bd167: a clean repository work with no declaration, a bare remote origin, a clean commit
A; a commit D with a declaration on a branch that was deleted again; refs/heads/side at A; `git pack-refs --all`; the
line of side in packed-refs replaced by "D refs/heads/side" and then "A refs/heads/side". `git for-each-ref` listed side
twice and ended with 0, and the real Level 1 hook for `git push origin main` answered inactive: the gate had kept the
last value of the name, A, and never read D. With the order A, D it asked.

Property (contract D5, condition d, owner choice of 2026-10-13, 16:4x Berlin, A): the exception applies only to a ref
store in the normal form the gate reads; no ref name twice, neither in packed-refs read raw nor in git's listing. Any
other store gives ask with the reason and the entry. Both inputs, both orders, and a store with the name once as
control. Red against 101bd167.
"""
from __future__ import annotations

import subprocess
import time

import pytest

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

OFF_FORM = "the ref store is not in the form the gate reads"


def _with_a_declared_object(tmp_path):
    """work as w1._undeclared leaves it, a commit D with a declaration no ref names, side at A, every ref packed."""
    work, _remote, a = w1._undeclared(tmp_path)
    w1._git(work, "checkout", "-q", "-b", "scratch")
    d = w1._commit(work, gate.DECLARATION, w1.EMPTY_LIST)
    w1._git(work, "checkout", "-q", "main")
    w1._git(work, "branch", "-q", "-D", "scratch")
    w1._git(work, "branch", "side", a)
    w1._git(work, "pack-refs", "--all")
    return work, a, d


def _side_lines(work, *oids):
    packed = work / ".git" / "packed-refs"
    lines = packed.read_text(encoding="ascii").splitlines()
    position = next(i for i, line in enumerate(lines) if line.endswith(" refs/heads/side"))
    lines[position:position + 1] = [f"{oid} refs/heads/side" for oid in oids]
    packed.write_text("\n".join(lines) + "\n", encoding="ascii")


def _listed(work, name):
    listing = subprocess.run(["git", "-C", str(work), "for-each-ref", "--format=%(refname)"], capture_output=True,
                             text=True, check=False)
    assert listing.returncode == 0 and not listing.stderr, listing
    return listing.stdout.split().count(name)


@pytest.mark.parametrize("order", ["declared_first", "declared_last"])
def test_the_reviewers_case_a_name_twice_in_packed_refs(env, tmp_path, order):
    work, a, d = _with_a_declared_object(tmp_path)
    _side_lines(work, *((d, a) if order == "declared_first" else (a, d)))
    assert _listed(work, "refs/heads/side") == 2
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"{OFF_FORM} (a name twice in git's listing): refs/heads/side")


@pytest.mark.parametrize("order", ["declared_first", "declared_last"])
def test_a_name_twice_in_packed_refs_behind_a_loose_file(env, tmp_path, order):
    """A loose file of the name does not make git list it once (measured with git 2.43.0)."""
    work, a, d = _with_a_declared_object(tmp_path)
    _side_lines(work, *((d, a) if order == "declared_first" else (a, d)))
    (work / ".git" / "refs" / "heads" / "side").write_text(f"{a}\n", encoding="ascii")
    assert _listed(work, "refs/heads/side") == 2
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"{OFF_FORM} (a name twice in git's listing): refs/heads/side")


@pytest.mark.parametrize("order", ["declared_first", "declared_last"])
def test_a_name_twice_in_packed_refs_read_directly(tmp_path, order):
    """packed-refs as an input of its own; in the hook git's listing names the duplicate first."""
    work, a, d = _with_a_declared_object(tmp_path)
    _side_lines(work, *((d, a) if order == "declared_first" else (a, d)))
    deadline = time.monotonic() + 120
    paths, _why = gate._repo_paths(str(work), deadline)
    store, why = gate._stored_refs(str(work), paths, deadline)
    assert store is None and why == f"{OFF_FORM} (a name twice in packed-refs): refs/heads/side", why


def test_a_name_twice_in_git_s_listing_alone(env, tmp_path, monkeypatch):
    """The listing as an input of its own: a name git lists twice where packed-refs holds it once."""
    work, _remote, _a = w1._undeclared(tmp_path)
    real = gate._git

    def doubled(repo, *args, deadline):
        out = real(repo, *args, deadline=deadline)
        if args[:1] == ("for-each-ref",) and out.returncode == 0:
            line = next(line for line in out.stdout.split(b"\n") if line.startswith(b"refs/heads/main\0"))
            out = subprocess.CompletedProcess(out.args, 0, out.stdout + line + b"\n", out.stderr)
        return out

    monkeypatch.setattr(gate, "_git", doubled)
    present, why = gate._present_refs(str(work), time.monotonic() + 120)
    assert present is None and why == f"{OFF_FORM} (a name twice in git's listing): refs/heads/main", why


def test_control_the_name_once_in_packed_refs_keeps_the_exception(env, tmp_path):
    work, a, _d = _with_a_declared_object(tmp_path)
    _side_lines(work, a)
    assert _listed(work, "refs/heads/side") == 1
    w1._assert_inactive(*w1._l1(env, work))
