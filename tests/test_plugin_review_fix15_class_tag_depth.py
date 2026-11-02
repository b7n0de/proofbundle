"""Review round 15 of 2026-10-13, the class of R15-2: a limit of the gate's own says that it is the gate's.

Measured at e6815eff with git 2.43.0, in the class search of R15-2 (every limit the gate models that counts otherwise than
git): MAX_TAG_DEPTH, 16, is the gate's own limit; git peels a chain of 17 annotated tags to the commit (`git rev-parse
--verify t16^{commit}`). Level 1 asked, rightly by the gate's limit, but its reason said "names an object git does not give
here", a claim about git that does not hold.

Property: the ask for a chain of tags longer than the gate peels names the gate's limit and claims nothing about git;
16 tags keep the exception. Red against e6815eff.
"""
from __future__ import annotations

import subprocess

import pytest

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate


def _tags(work, a, depth):
    target = a
    for i in range(depth):
        w1._git(work, "tag", "-a", "-m", f"t{i}", f"t{i}", target)
        target = f"t{i}"
    peeled = subprocess.run(["git", "-C", str(work), "rev-parse", "--verify", "--quiet", f"t{depth - 1}^{{commit}}"],
                            capture_output=True, text=True, check=False)
    assert peeled.stdout.strip() == a, peeled          # git peels the whole chain


@pytest.mark.parametrize("depth", [gate.MAX_TAG_DEPTH, gate.MAX_TAG_DEPTH + 1])
def test_a_chain_of_tags_longer_than_the_gate_peels_names_the_gates_limit(env, tmp_path, depth):
    work, _remote, a = w1._undeclared(tmp_path)
    _tags(work, a, depth)
    answer, entry, text = w1._l1(env, work)
    if depth <= gate.MAX_TAG_DEPTH:
        w1._assert_inactive(answer, entry, text)
        return
    w1._assert_exception_refused(answer, entry, text, f"the local ref refs/tags/t{depth - 1} names a chain of more "
                                                      f"than {gate.MAX_TAG_DEPTH} tags, more than the gate peels")
    assert "git does not give" not in text, text
