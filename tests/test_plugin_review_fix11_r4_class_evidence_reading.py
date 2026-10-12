"""Review round 11 of 2026-10-12, the class of R11-4: the evidence reading gives no reading of a tree that names one entry
twice on the way to the path it reads.

Measured here at 85597f63 with git 2.43.0, in the class search of R11-4: a declared repository whose remote holds the
declared commit X; B with X's code and a root tree that names .proofbundle twice, X's folder first and a second folder
Y after it, written with `git hash-object --literally`. git's lookup of `B:.proofbundle/evidence.json`, which the gate's
reading uses, gives X's declaration; a checkout of B in a fresh clone writes Y's files (the last entry wins in the
index); `git fsck --full` reports duplicateEntries. The pre-push hook (Level 2) passed B with exit 0 and named the
evidence verified and the rules matching the remote's state, while the checkout of B declared an empty evidence list
or held another policy. CI mode (evaluate_repository) passed B at HEAD. With the empty folder first, or with two empty
folders, the lookup found nothing and the gate's absence reading came from the same tree.

Property (the class of R11-4: neither the first nor the last of two entries of one name is a whole reading): wherever
the gate reads a path of a commit, for its bytes, its object id or its absence, every tree on the way to it, the root
tree included, is read whole first; one that names an entry twice gives no reading, so no pass, no rules equality and
no absence rest on it. Red against 85597f63.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import time

import pytest

from proofbundle.emit import generate_signer

import test_claude_code_plugin_gate as cg
import test_plugin_gate_n2c_push_done as n2c

pytestmark = n2c.pytestmark
env = n2c.env
_clean_git_environment = n2c._clean_git_environment
_clean_git_config = cg._clean_git_config
repo = cg.repo
gate = cg.gate

TWICE = "names one entry twice"
EMPTY_LIST = json.dumps({"schema": gate.DECLARATION_SCHEMA, "evidence": []})


def _raw(work: pathlib.Path, kind: str, data: bytes) -> str:
    return subprocess.run(["git", "-C", str(work), "hash-object", "--literally", "-t", kind, "-w", "--stdin"],
                          input=data, capture_output=True, check=True).stdout.decode().strip()


def _entries(work: pathlib.Path, tree: str) -> list[tuple[bytes, bytes, bytes]]:
    raw = subprocess.run(["git", "-C", str(work), "cat-file", "tree", tree], capture_output=True, check=True).stdout
    entries, i = [], 0
    while i < len(raw):
        space = raw.index(b" ", i)
        nul = raw.index(b"\0", space)
        entries.append((raw[i:space], raw[space + 1:nul], raw[nul + 1:nul + 21]))
        i = nul + 21
    return entries


def _tree(work: pathlib.Path, entries: list[tuple[bytes, bytes, bytes]]) -> str:
    return _raw(work, "tree", b"".join(mode + b" " + name + b"\0" + oid for mode, name, oid in entries))


def _replace(work: pathlib.Path, tree: str, name: bytes, folders: list[str]) -> str:
    """`tree` with its entry `name` replaced by one folder entry per id in `folders`, in that order."""
    out, placed = [], False
    for mode, each, oid in _entries(work, tree):
        if each != name:
            out.append((mode, each, oid))
        elif not placed:
            out += [(b"40000", name, bytes.fromhex(f)) for f in folders]
            placed = True
    return _tree(work, out)


def _second_folder(work: pathlib.Path, variant: str) -> str:
    """Y: a .proofbundle folder whose declaration lists no evidence, or X's folder with another pinned policy."""
    if variant == "an empty evidence list":
        return _tree(work, [(b"100644", b"evidence.json", bytes.fromhex(_raw(work, "blob", EMPTY_LIST.encode())))])
    policy = bytes.fromhex(_raw(work, "blob", json.dumps(cg._pinned_policy(generate_signer())).encode()))
    return _tree(work, [(m, n, policy if n == b"policy.json" else o)
                        for m, n, o in _entries(work, "HEAD:.proofbundle")])


def _twice(work: pathlib.Path, variant: str) -> tuple[str, str]:
    """B on top of X: X's root tree with X's .proofbundle folder first and Y after it; main at B. (B, Y)."""
    head = n2c._rev(work, "HEAD")
    second = _second_folder(work, variant)
    root = _replace(work, f"{head}^{{tree}}", b".proofbundle", [n2c._rev(work, "HEAD:.proofbundle"), second])
    b = n2c._git(work, "commit-tree", root, "-p", head, "-m", "B").stdout.strip()
    n2c._git(work, "update-ref", "refs/heads/main", b)
    return b, second


VARIANTS = ("an empty evidence list", "another policy")


@pytest.mark.parametrize("variant", VARIANTS)
def test_the_two_readings_of_b_differ(repo, tmp_path, variant):
    """Non-vacuous: the lookup the gate's reading uses gives X's files, a checkout writes Y's, fsck names the duplicate,
    and a push to a bare repository with the default configuration exits 0."""
    x_declaration = n2c._git(repo, "show", f"HEAD:{gate.DECLARATION}").stdout
    x_policy = n2c._git(repo, "show", f"HEAD:{cg.POLICY}").stdout
    b, second = _twice(repo, variant)
    assert n2c._git(repo, "show", f"{b}:{gate.DECLARATION}").stdout == x_declaration
    assert n2c._git(repo, "show", f"{b}:{cg.POLICY}").stdout == x_policy
    clone = tmp_path / "view"
    subprocess.run(["git", "init", "-q", str(clone)], check=True)
    n2c._git(clone, "fetch", "-q", "--no-tags", str(repo), b)
    n2c._git(clone, "checkout", "-q", "--detach", b)
    if variant == "an empty evidence list":
        assert (clone / gate.DECLARATION).read_text(encoding="utf-8") == EMPTY_LIST
    else:
        assert (clone / cg.POLICY).read_text(encoding="utf-8") != x_policy
        assert (clone / cg.POLICY).read_text(encoding="utf-8") == n2c._git(repo, "show",
                                                                           f"{second}:policy.json").stdout
    fsck = subprocess.run(["git", "-C", str(repo), "fsck", "--full"], capture_output=True, text=True, check=False)
    assert "duplicateEntries" in fsck.stdout + fsck.stderr, fsck.stdout + fsck.stderr
    target = tmp_path / "target.git"
    subprocess.run(["git", "init", "-q", "--bare", str(target)], check=True)
    push = subprocess.run(["git", "-C", str(repo), "push", "-q", "--no-verify", str(target), "main"],
                          capture_output=True, text=True, check=False)
    assert push.returncode == 0, push.stderr


@pytest.mark.parametrize("variant", VARIANTS)
def test_level_2_gives_no_pass_for_a_folder_named_twice(env, repo, variant):
    b, _second = _twice(repo, variant)
    proc = cg.run_level2(env, repo, source=b)
    assert proc.returncode == 1, proc.stderr
    assert TWICE in proc.stderr, proc.stderr
    assert "verified" not in proc.stderr, proc.stderr


@pytest.mark.parametrize("variant", VARIANTS)
def test_ci_mode_gives_no_pass_for_a_folder_named_twice(repo, variant):
    _twice(repo, variant)
    verdict = gate.evaluate_repository(str(repo), time.monotonic() + 120)
    assert verdict.decision == "ask", verdict.detail
    assert verdict.reason_id != "verified", verdict.detail


def test_level_1_names_the_tree_and_no_clean_source(env, repo):
    _twice(repo, "an empty evidence list")
    answer, entry = n2c._level1(env, repo)
    text = answer["systemMessage"]
    assert answer["hookSpecificOutput"].get("permissionDecision") == "deny", answer
    assert entry["reason_ids"] == ["gate_error"] and TWICE in text, (entry, text)
    assert n2c.SOURCES_CLEAN not in text, text


def test_a_policy_in_a_folder_that_names_it_twice_gives_no_rules(repo):
    """The object id of a declared policy is read whole too: .proofbundle/sub/ names policy.json twice; git's lookup
    gives the first, so its id alone would make two rule sets equal that a checkout tells apart."""
    head = n2c._rev(repo, "HEAD")
    first = _raw(repo, "blob", b'{"first": true}')
    last = _raw(repo, "blob", b'{"last": true}')
    sub = _raw(repo, "tree", b"".join(b"100644 policy.json\0" + bytes.fromhex(o) for o in (first, last)))
    declaration = json.dumps({"schema": gate.DECLARATION_SCHEMA, "evidence": [
        {"kind": "bundle", "path": cg.BUNDLE, "policy": ".proofbundle/sub/policy.json",
         "subject": cg._subject(cg._head_digest(repo))}]}).encode()
    folder = [(m, n, bytes.fromhex(_raw(repo, "blob", declaration)) if n == b"evidence.json" else o)
              for m, n, o in _entries(repo, "HEAD:.proofbundle")] + [(b"40000", b"sub", bytes.fromhex(sub))]
    root = _replace(repo, f"{head}^{{tree}}", b".proofbundle", [_tree(repo, folder)])
    b = n2c._git(repo, "commit-tree", root, "-p", head, "-m", "B").stdout.strip()
    assert n2c._rev(repo, f"{b}:.proofbundle/sub/policy.json") == first
    rules = gate._rules_at(str(repo), b, time.monotonic() + 120)
    assert rules[0] == "unreadable" and TWICE in rules[1], rules


@pytest.mark.parametrize("folders", ["the empty folder twice", "the empty folder and a folder with a note"])
def test_no_absence_from_a_root_that_names_the_folder_twice(tmp_path, folders):
    """A repository without a declaration whose HEAD names .proofbundle twice: git's lookup and ls-tree find nothing,
    and neither is a whole reading of the absence."""
    work = cg._plain(tmp_path)
    empty = _raw(work, "tree", b"")
    other = _raw(work, "tree", b"100644 notes.txt\0" + bytes.fromhex(_raw(work, "blob", b"n\n")))
    head = n2c._rev(work, "HEAD")
    pairs = [empty, empty] if folders == "the empty folder twice" else [empty, other]
    root = _tree(work, sorted(_entries(work, f"{head}^{{tree}}") + [(b"40000", b".proofbundle", bytes.fromhex(p))
                                                                    for p in pairs], key=lambda e: e[1] + b"/"))
    b = n2c._git(work, "commit-tree", root, "-p", head, "-m", "B").stdout.strip()
    n2c._git(work, "update-ref", "refs/heads/main", b)
    listing = n2c._git(work, "ls-tree", "-z", "--full-tree", b, "--", gate.DECLARATION).stdout
    assert listing == ""
    verdict = gate.evaluate_repository(str(work), time.monotonic() + 120)
    assert verdict.decision == "ask" and verdict.reason_id == "absence_not_measured", verdict.detail
    with pytest.raises(gate.GateError, match=TWICE):
        gate._blob(str(work), b, gate.DECLARATION, time.monotonic() + 120, gate.MAX_DECLARATION_BYTES)


def test_control_x_alone_passes_at_level_2(env, repo):
    head = n2c._rev(repo, "HEAD")
    proc = cg.run_level2(env, repo, source=head)
    assert proc.returncode == 0 and "verified" in proc.stderr, proc.stderr


def test_control_a_repository_without_a_declaration_stays_inactive(tmp_path):
    work = cg._plain(tmp_path)
    verdict = gate.evaluate_repository(str(work), time.monotonic() + 120)
    assert (verdict.decision, verdict.reason_id) == ("inactive", "nothing_declared"), verdict.detail
