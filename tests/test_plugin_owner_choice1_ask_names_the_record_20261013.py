"""Owner choice of 2026-10-13 on owner choice 1: the ask names the local record and leaves its relation to the destination
open.

Owner's word: owner choice 1 stays as strict as N2 built it, every record of every configured remote for the same ref
leaves the exception unapplied. The ask names the concrete local record and says that its relation to the actual
destination is not established. It claims no equality of remotes: a record of another remote may be relevant, it is not
shown to be a record of the destination.

At 7588fe4a the ask said "the local record <ref> of the destination holds something at ...", for the record of origin as
for the record of a second remote, which claims what the gate does not know. Red against 7588fe4a.
"""
from __future__ import annotations

import pathlib
import subprocess

import pytest

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

NOT_ESTABLISHED = "it may record the ref this push writes, but whether it records the actual destination is not established"


def _declared_on_top(work: pathlib.Path, parent: str) -> str:
    def raw(kind: str, data: bytes) -> str:
        return subprocess.run(["git", "-C", str(work), "hash-object", "-t", kind, "-w", "--stdin"], input=data,
                              capture_output=True, check=True).stdout.decode().strip()
    folder = raw("tree", b"100644 evidence.json\x00" + bytes.fromhex(raw("blob", w1.EMPTY_LIST.encode())))
    root = raw("tree", b"40000 .proofbundle\x00" + bytes.fromhex(folder))
    return w1._git(work, "commit-tree", root, "-p", parent, "-m", "declared").stdout.strip()


@pytest.mark.parametrize("record", ["refs/remotes/mirror/main", "refs/remotes/origin/main"])
def test_the_ask_names_the_record_and_leaves_its_relation_to_the_destination_open(env, tmp_path, record):
    work, _remote, a = w1._undeclared(tmp_path)
    w1._git(work, "remote", "add", "mirror", "https://example.invalid/o/r.git")
    declared = _declared_on_top(work, a)
    w1._git(work, "update-ref", record, declared)
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, f"the local ref {record} holds something at {gate.DECLARATION} "
                                                      f"or in place of its folder at {declared[:12]}; {NOT_ESTABLISHED}")
    assert "of the destination holds" not in text, text
    assert "same" not in text.split(gate._LOCAL_EXCEPTION)[-1], text


def test_a_record_naming_no_commit_is_named_without_a_claim_on_the_destination(env, tmp_path):
    work, _remote, _a = w1._undeclared(tmp_path)
    w1._git(work, "remote", "add", "mirror", "https://example.invalid/o/r.git")
    missing = work / ".git" / "refs" / "remotes" / "mirror" / "main"
    missing.parent.mkdir(parents=True)
    missing.write_text("0" * 39 + "1\n", encoding="utf-8")
    answer, entry, text = w1._l1(env, work)
    w1._assert_exception_refused(answer, entry, text, "the local ref refs/remotes/mirror/main, which may record the "
                                                      "ref this push writes, names no commit this repository holds")
