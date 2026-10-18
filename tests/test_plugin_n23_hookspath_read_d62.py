"""D62, Nachtrag 23 part 2: a read of core.hooksPath turns no hook off and is not denied.

Counted at delta: `git config --get core.hooksPath`, a pure read, was denied with hooks_disabled since 2026-10-16
17:42Z, a false alarm. The gate denied every `git config` whose words named core.hooksPath (Punkt 5). The rule: a read
of it (`--get`, `--get-all`, `--get-regexp`, `--list`, the key alone, with the switches of scope, origin, type and
separators, _config_reads_only) is judged as any read form, which for `git config` was the ask of D3 (git_form_not_free)
until Nachtrag 27: since D68 the four read actions with at most --show-origin and --null before the name are read forms
of class a, free after the read profile; every other read keeps the ask of D3.
Setting, unsetting, adding, replacing, a value, an option the gate does not read as a read (`--file`, `--default`,
`--edit` …), a word the shell may rewrite and a `-c core.hooksPath=…` override keep the deny. RED at 9f578c2a and
ab14e1ae: every read; the denies are controls, green at both.
"""
from __future__ import annotations

import subprocess
import time

import pytest

import test_plugin_gate_n2c_push_done as n2c

gate = n2c.gate
pytestmark = n2c.pytestmark
_clean_git_environment = n2c._clean_git_environment

READS = ["config --get core.hooksPath", "config --get-all core.hooksPath", "config --get-regexp core.hooksPath",
         "config core.hooksPath", "config --get core.hookspath", "config --show-origin --get core.hooksPath",
         "config --local --get core.hooksPath", "config --global --get-all core.hooksPath",
         "config -z --show-scope --get core.hooksPath", "config --type=path --get core.hooksPath",
         "config --get core.hooksPath '^/'"]
#: The reads among them that are read forms of class a since D68 (Nachtrag 27, O23-7): free after the read profile.
READS_D68 = {"config --get core.hooksPath", "config --get-all core.hooksPath", "config --get-regexp core.hooksPath",
             "config --get core.hookspath", "config --show-origin --get core.hooksPath",
             "config --get core.hooksPath '^/'",
             # the scope switches, -z and --show-scope since Nachtrag 28 (O27-4)
             "config --local --get core.hooksPath", "config --global --get-all core.hooksPath",
             "config -z --show-scope --get core.hooksPath"}
DENIES = ["config core.hooksPath /x", "config core.hooksPath ''", "config --unset core.hooksPath",
          "config --unset-all core.hooksPath", "config --add core.hooksPath /x", "config --replace-all core.hooksPath /x",
          "config --file other --get core.hooksPath", "config --default /x --get core.hooksPath",
          "config --get core.hooksPath a b", "config --get --list core.hooksPath", "config --g* core.hooksPath",
          "-c core.hooksPath=/x config --get core.hooksPath", "config --get core.hooksPath /x --add"]


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path / "r")], check=True, timeout=60)
    return tmp_path / "r"


def _decide(repo, words: str, prefix: str, host: str = "claude"):
    command = f"git -C {repo} {words}" if prefix == "-C" else f"git {words}"
    return gate.decide(command, str(repo), time.monotonic() + 60, host)


@pytest.mark.parametrize("prefix", ["-C", "bare"])
@pytest.mark.parametrize("words", READS)
def test_D62_a_read_of_core_hookspath_is_not_denied(repo, words, prefix):
    out = _decide(repo, words, prefix)
    expected = ("pass", ["free_after_read_profile"]) if words in READS_D68 else ("ask", ["git_form_not_free"])
    assert out is not None and (out.decision, [v.reason_id for v in out.verdicts]) == expected, (words, out and out.text)


@pytest.mark.parametrize("words", READS[:3])
def test_D62_under_codex_a_read_is_no_hook_disabling_either(repo, words):
    out = _decide(repo, words, "-C", host="codex")
    assert "hooks_disabled" not in [v.reason_id for v in out.verdicts], words


@pytest.mark.parametrize("words", DENIES)
def test_D62_control_setting_unsetting_and_every_other_form_keep_the_deny(repo, words):
    out = _decide(repo, words, "-C")
    assert (out.decision, [v.reason_id for v in out.verdicts]) == ("deny", ["hooks_disabled"]), words


@pytest.mark.parametrize("args, read", [(["--get", "core.hooksPath"], True), (["core.hooksPath"], True),
                                        (["--list"], True), (["-l", "x"], False), (["core.hooksPath", "/x"], False),
                                        (["--get", "--get-all", "core.hooksPath"], False), (["--get"], False),
                                        (["--unset", "core.hooksPath"], False), (["--get", "$X"], False)])
def test_D62_the_reads_the_gate_knows(args, read):
    assert gate._config_reads_only(args) is read, args
