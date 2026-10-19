"""Review round 3 of 2026-10-09: the second locks of R3-2 and R3-3 hold on their own.

The mutation probe of R3-1 to R3-3 at ab266437 left two mutants alive whose line is a second lock behind another
check. R3-2: `_strict_git` makes the directory of a `-C` value the shell may rewrite unknown, while gated_calls
already leaves such a call NOT MEASURED through the rewrite check of review round 2, so no decision changed when the
line was removed (840 decide calls measured, none differed). R3-3: a core.attributesFile git cannot resolve leaves the
digest unknown, while for `~no-such-user` git itself dies on the attribute file, so the digest was None either way.

These tests hold each lock without the other check: `_strict_git` called alone, and a bare repository whose relative
core.attributesFile has no work tree to be read against, the one state measured that reaches that line by itself.
Green at ab266437; each test is red with its mutant (M2b, M3d of the probe).
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import time

import _git_version as _gv
import pytest

import test_plugin_gate_n24 as n24
from _plugin_env import plugin_env

gate = n24.gate
_clean_git_config = n24._clean_git_config


def _rewrites(words: list[str]) -> list[bool]:
    """The rewrite flags gated_calls hands _strict_git, with the tilde of a `-C` value modelled as there."""
    return [gate._shell_rewrites(w, tilde_modelled=k > 0 and words[k - 1] == "-C") for k, w in enumerate(words)]


@pytest.mark.parametrize("value", ["~pb_review_named", "~root/x", "d*", "{a,b}", "~+", "~1"])
def test_strict_git_alone_leaves_a_rewritten_c_value_unknown(value):
    words = ["-C", value, "push", "origin", "main"]
    flags = _rewrites(words)
    assert flags[1], "non-vacuous: the shell may rewrite this value"
    name, directory, _detail = gate._strict_git(words, "/work", rewrites=flags, raws=words)
    assert name == "git push" and directory is gate.UNKNOWN, directory


@pytest.mark.parametrize("value,joined", [("sub", "/work/sub"), ("~/x", os.path.expanduser("~/x"))])
def test_control_strict_git_joins_a_literal_or_plain_tilde_value(value, joined):
    words = ["-C", value, "push", "origin", "main"]
    _name, directory, _detail = gate._strict_git(words, "/work", rewrites=_rewrites(words), raws=words)
    assert directory == os.path.join("/work", joined)


def _bare(tmp_path: pathlib.Path, attributes: str) -> str:
    bare = tmp_path / "b.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True, timeout=60)
    subprocess.run(["git", "--git-dir", str(bare), "config", "core.attributesFile", attributes], check=True,
                   timeout=60)
    return str(bare)


def test_a_relative_attribute_file_without_a_work_tree_leaves_the_digest_unknown(tmp_path):
    bare = _bare(tmp_path, "rel/attrs")
    assert gate._bound_state_digest(bare, time.monotonic() + 30, plugin_env()) is None


@_gv.needs_git(2, 42, "git var names the configuration and attribute files git reads")
def test_control_an_absolute_attribute_file_of_a_bare_repository_is_bound(tmp_path):
    attrs = tmp_path / "attrs"
    attrs.write_text("a review=one\n", encoding="utf-8")
    bare = _bare(tmp_path, str(attrs))
    before = gate._bound_state_digest(bare, time.monotonic() + 30, plugin_env())
    attrs.write_text("a review=two\n", encoding="utf-8")
    after = gate._bound_state_digest(bare, time.monotonic() + 30, plugin_env())
    assert before is not None and after is not None and before != after
