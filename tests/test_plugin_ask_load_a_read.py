"""Class a of the ask load (FIX-18 part B, DESIGN_ask_load.md 3.1, D34): a read form is free after a read profile.

The owner's answers of 2026-10-14 (equal to the reviewer's recommendations): a read profile only as a narrow piece
newly built for the plugin (answer 1); the git-lfs standard filter is not inert (answer 2); the pipe of the Bash tool
and with it an inert pager only for a bound host adapter, and the plugin binds none, so every pager key counts (answer
3); class a is off under Codex (answer 10). Every git read the gate makes for the profile goes through its own git
path, and the submodule listing runs with fsmonitor and hooks off (Q18-2).

FREE: asked at 6da239e4, the parent of this build, free here. KEEP: not free at the parent and here; each names the
rule of the build it guards, and the mutant of that rule frees it. TRUTH: the read form runs for real with git in a
throwaway repository whose configuration names a marker program; where the gate frees the form, the marker must not
have run, and every source starts its marker for at least one form (no vacuous case). Every repository lives under
tmp_path and has no remote. Run with git 2.43.0.
"""
from __future__ import annotations

import os
import pathlib
import shlex
import shutil
import subprocess
import time

import pytest

import test_plugin_gate_n2c_push_done as n2c
from _plugin_env import plugin_env

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
gate = n2c.gate
FREE = ("pass", "inactive", "allow")


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    """The hook's environment: no GIT_* name but empty global and system files, a home of its own, and a bin folder for
    marker programs first on PATH."""
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LC_ALL", "C")
    (tmp_path / "bin").mkdir()
    (tmp_path / "marker").mkdir()
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "bin"), os.environ.get("PATH", "")]))


def _git(repo: pathlib.Path, *args: str, stdin: str | None = None) -> str:
    out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, input=stdin, timeout=60,
                         check=True)
    return out.stdout


def _repo(tmp_path: pathlib.Path, name: str = "r") -> pathlib.Path:
    """Two commits, a tag, an unstaged change; no remote."""
    repo = tmp_path / name
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True, timeout=60)
    for key, value in (("user.name", "t"), ("user.email", "t@example.org"), ("commit.gpgsign", "false")):
        _git(repo, "config", key, value)
    (repo / "a.txt").write_text("foo one\n")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "one")
    (repo / "a.txt").write_text("foo one\nfoo two\n")
    _git(repo, "commit", "-q", "-am", "two")
    _git(repo, "tag", "v1")
    (repo / "a.txt").write_text("foo one\nfoo two\nfoo three\n")
    return repo


def _marker(tmp_path: pathlib.Path, name: str, body: str = "exit 0") -> str:
    path = tmp_path / "bin" / name
    path.write_text(f'#!/bin/sh\necho "$0 $*" >> {tmp_path / "marker" / name}.log\n{body}\n')
    path.chmod(0o755)
    return str(path)


def _started(tmp_path: pathlib.Path) -> list[str]:
    return sorted(p.stem for p in (tmp_path / "marker").glob("*.log"))


def _clear(tmp_path: pathlib.Path) -> None:
    for p in (tmp_path / "marker").glob("*.log"):
        p.unlink()


def _decide(repo: pathlib.Path, command: str, host: str = "claude") -> tuple[str | None, list[str]]:
    out = gate.decide(command, str(repo), time.monotonic() + 120, host, plugin_env())
    return (None, []) if out is None else (out.decision, [v.reason_id for v in out.verdicts])


def _signed_head(repo: pathlib.Path) -> None:
    body = _git(repo, "cat-file", "commit", "HEAD")
    head, _, msg = body.partition("\n\n")
    sig = "gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQ==\n -----END PGP SIGNATURE-----"
    oid = _git(repo, "hash-object", "-t", "commit", "-w", "--stdin", stdin=head + "\n" + sig + "\n\n" + msg).strip()
    _git(repo, "update-ref", "refs/heads/main", oid)


# --- FREE: the read forms of the grammar in a clean repository ----------------------------------------------------

READ_FORMS = [
    "git status", "git status -sb", "git status --porcelain=v2 --branch", "git diff", "git diff --cached",
    "git diff HEAD~1 --stat", "git diff --name-only HEAD~1 -- a.txt", "git log --oneline -5", "git log -n 3",
    "git log --format='%h %s' -3", "git log --graph --oneline --all", "git log -p -1 -- a.txt",
    "git log --since='2 weeks ago' --oneline", "git show HEAD", "git show --stat HEAD", "git show HEAD:a.txt",
    "git grep -n foo", "git grep -n -e foo -- '*.txt'", "git ls-files", "git ls-files -m",
    "git rev-parse --show-toplevel", "git rev-parse --abbrev-ref HEAD", "git for-each-ref --format='%(refname)'",
    "git for-each-ref --sort=-committerdate refs/heads", "git branch", "git branch -a", "git branch --show-current",
    "git branch --list 'ma*'", "git worktree list", "git cat-file -p HEAD", "git cat-file -t HEAD",
    "git describe --always", "git ls-tree -r HEAD", "git show-ref", "git merge-base HEAD HEAD~1",
    "git rev-list --count HEAD",
]
#: Read forms inside a longer command, judged by class c step by step (D33).
IN_CHAINS = [
    "git log --oneline -20 | head -20", "git status && git log --oneline -1", "git diff --stat | tail -1",
    "git log --format='%h %s' -15 | cat", "LC_ALL=C git log -1", "git status; git diff --stat",
]


@pytest.mark.parametrize("command", READ_FORMS + IN_CHAINS)
def test_FREE_a_read_form_is_free_after_the_read_profile(tmp_path, command):
    repo = _repo(tmp_path)
    decision, reasons = _decide(repo, command)
    assert decision == "pass" and set(reasons) == {"free_after_read_profile"}, (decision, reasons)


def test_FREE_one_literal_minus_C_names_the_repository(tmp_path):
    repo = _repo(tmp_path)
    decision, reasons = _decide(tmp_path, f"git -C {repo} log --oneline -1")
    assert decision == "pass" and reasons == ["free_after_read_profile"], (decision, reasons)


@pytest.mark.parametrize("command", ["git status", "git log --oneline -5", "git log --oneline -20 | head -20"])
def test_KEEP_class_a_is_off_under_codex(tmp_path, command):
    """Owner answer 10: under Codex a read form keeps the answer of D3, denied by the host answer."""
    repo = _repo(tmp_path)
    out = gate.decide(command, str(repo), time.monotonic() + 120, "codex", plugin_env())
    assert out is not None and out.decision == "ask" and "git_form_not_free" in [v.reason_id for v in out.verdicts]
    assert gate.answer(out.decision, out.text, host="codex")["hookSpecificOutput"]["permissionDecision"] == "deny"


# --- KEEP: the option grammar (rule 1) -------------------------------------------------------------------------

OPTIONS = {
    "ext_diff": "git log --ext-diff -p -1",
    "textconv": "git show --textconv HEAD",
    "output": "git log --output=out.txt -1",
    "show_signature": "git log --show-signature -1",
    "signature_placeholder": "git log --format='%G? %h' -2",
    "signature_modifier": "git log --format=%+GS -1",
    "user_format": "git log --pretty=sig -1",
    "describe_placeholder": "git log --format='%(describe)' -1",
    "ref_signature_atom": "git for-each-ref --format='%(signature)'",
    "ref_describe_atom": "git branch --format='%(describe)'",
    "color_without_never": "git log --color -1",
    "color_then_ext_diff": "git log --color --ext-diff -p -1",
    "no_index": "git diff --no-index a.txt b.txt",
    "open_files_in_pager": "git grep -O foo",
    "pattern_file": "git grep -f patterns.txt",
    "recurse_submodules": "git grep --recurse-submodules foo",
    "dirty": "git describe --always --dirty",
    "status_verbose": "git status -v",
    "line_log": "git log -L1,2:a.txt",
    "missing_value": "git log -n",
    "branch_create": "git branch topic",
    "branch_verbose_create": "git branch -v topic",
    "worktree_add": "git worktree add ../w",
    "cat_file_textconv": "git cat-file --textconv HEAD:a.txt",
    "superproject": "git rev-parse --show-superproject-working-tree",
    "shortlog": "git shortlog -s",
    "stdin": "git diff -",
    "unknown_form": "git whatchanged -1",
    "config_read_class_g": "git config --includes --get user.name",   # a switch outside the set of D68
}


@pytest.mark.parametrize("name", OPTIONS)
def test_KEEP_an_option_off_the_grammar_keeps_the_ask(tmp_path, name):
    repo = _repo(tmp_path)
    (repo / "patterns.txt").write_text("foo\n")
    decision, reasons = _decide(repo, OPTIONS[name])
    assert decision not in FREE and decision is not None, (name, decision, reasons)


@pytest.mark.parametrize("command", ["git -c color.ui=never log -1", "git --no-pager log -1", "git -C . -C . log -1",
                                     "git --git-dir=.git log -1", "git --work-tree=. status"])
def test_KEEP_a_global_option_other_than_one_minus_C(tmp_path, command):
    """Rule 2: one literal -C at most and no other global option."""
    repo = _repo(tmp_path)
    decision, reasons = _decide(repo, command)
    assert decision not in FREE, (decision, reasons)


@pytest.mark.parametrize("command", ["git log -1 *.txt", "git diff ?.txt", "git log --format=%h -1 a.tx[t]"])
def test_KEEP_a_word_the_shell_may_rewrite_before_the_double_dash(tmp_path, command):
    """Rule 3: a glob before `--` may become an option (F2)."""
    repo = _repo(tmp_path)
    decision, reasons = _decide(repo, command)
    assert decision not in FREE, (decision, reasons)


def test_FREE_a_glob_after_the_double_dash_is_a_path(tmp_path):
    repo = _repo(tmp_path)
    decision, reasons = _decide(repo, "git log --oneline -- *.txt")
    assert decision == "pass", (decision, reasons)


@pytest.mark.parametrize("command", ["git log -1 > out.txt", "git status 2> err.txt"])
def test_KEEP_a_redirection(tmp_path, command):
    """Rule 4: free only without a redirection, as K-NW-2 B."""
    repo = _repo(tmp_path)
    decision, reasons = _decide(repo, command)
    assert decision not in FREE, (decision, reasons)


def test_KEEP_outside_a_work_tree(tmp_path):
    """Rule 5: a bare repository and a directory outside every repository keep the ask."""
    repo = _repo(tmp_path)
    bare = tmp_path / "bare.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(repo), str(bare)], check=True, timeout=60)
    outside = tmp_path / "outside"
    outside.mkdir()
    for where in (bare, outside):
        decision, reasons = _decide(where, "git log --oneline -1")
        assert decision not in FREE, (where.name, decision, reasons)


# --- KEEP: the read profile (rules 6 to 12) --------------------------------------------------------------------

def _config(repo, *pairs):
    for key, value in pairs:
        _git(repo, "config", key, value)


@pytest.mark.parametrize("pairs", [
    (("log.showSignature", "true"),), (("format.pretty", "%G? %h"),), (("pretty.sig", "%h"),),
    (("submodule.recurse", "true"),), (("core.untrackedCache", "true"),), (("diff.drv.textconv", "cat"),),
    (("diff.external", "true"),), (("grep.fallbackToNoIndex", "true"),), (("status.submoduleSummary", "true"),),
    (("feature.manyFiles", "true"),), (("hook.x.command", "true"),),
], ids=lambda p: p[0][0])
def test_KEEP_a_key_the_profile_does_not_know(tmp_path, pairs):
    """Rule 6: the profile is an allow-list; an unknown key keeps the ask for every form."""
    repo = _repo(tmp_path)
    _config(repo, *pairs)
    for command in ("git log --oneline -1", "git status"):
        decision, reasons = _decide(repo, command)
        assert decision not in FREE, (pairs, command, decision, reasons)


def test_FREE_the_display_keys_the_profile_knows(tmp_path):
    repo = _repo(tmp_path)
    _config(repo, ("log.date", "iso"), ("color.ui", "never"), ("core.abbrev", "10"), ("status.short", "true"),
            ("diff.renames", "copies"), ("grep.lineNumber", "true"), ("merge.conflictStyle", "diff3"),
            ("gpg.format", "ssh"), ("user.signingKey", "/nowhere"), ("commit.gpgSign", "true"))
    for command in ("git log --oneline -1", "git status", "git diff"):
        decision, reasons = _decide(repo, command)
        assert decision == "pass", (command, decision, reasons)


def test_KEEP_a_promisor_remote(tmp_path):
    """Rule 7: a promisor key, read by its presence (C-5), keeps every form asked."""
    repo = _repo(tmp_path)
    _config(repo, ("remote.origin.promisor", "false"))
    decision, reasons = _decide(repo, "git log --oneline -1")
    assert decision not in FREE, (decision, reasons)


@pytest.mark.parametrize("source", ["core.pager", "pager.log", "GIT_PAGER", "PAGER"])
def test_KEEP_a_pager_key_counts_without_a_bound_host_adapter(tmp_path, monkeypatch, source):
    """Rule 8, owner answer 3: no host adapter is bound, so the pipe of the Bash tool is not relied on. PAGER, which
    git reads to choose the pager like GIT_PAGER, counts like its key (review Runde 6, point 1)."""
    repo = _repo(tmp_path)
    if source in ("GIT_PAGER", "PAGER"):
        monkeypatch.setenv(source, "cat")
    else:
        _config(repo, (source, "cat"))
    decision, reasons = _decide(repo, "git log --oneline -1")
    assert decision not in FREE, (decision, reasons)


@pytest.mark.parametrize("command", ["GIT_PAGER=cat git log --oneline -1", "PAGER=cat git log --oneline -1",
                                     "GIT_PAGER= git show HEAD", "GIT_TRACE=1 git log --oneline -1"])
def test_KEEP_a_prefix_assignment_counts_as_the_hooks_environment_does(tmp_path, command):
    """Rules 8 and 13 for a prefix assignment of the command: a vetted pager value or a GIT_TRACE name keeps a read
    form asked, as it does in the hook's environment (_read_env_problem)."""
    repo = _repo(tmp_path)
    decision, reasons = _decide(repo, command)
    assert decision not in FREE, (decision, reasons)


@pytest.mark.parametrize("command", ["LC_ALL=C git log --oneline -1", "GIT_TERMINAL_PROMPT=0 git status",
                                     "TZ=UTC git log -1 --format=%cd"])
def test_FREE_a_prefix_assignment_the_profile_accepts(tmp_path, command):
    repo = _repo(tmp_path)
    assert _decide(repo, command)[0] == "pass"


#: Words that name an index entry as a revision: resolving one reads the index, and reading the index queries
#: fsmonitor for these forms too (measured, a/fsmonitor_index2.py). A path after `--` names no revision.
INDEX_WORDS = ["git rev-parse :a.txt", "git rev-parse --verify :0:a.txt", "git show :a.txt", "git show :0:a.txt",
               "git log --oneline :a.txt", "git log --oneline -1 ^:a.txt HEAD", "git log --oneline HEAD~1..:a.txt",
               "git rev-list :a.txt", "git describe --always :a.txt", "git ls-tree :a.txt",
               "git merge-base :a.txt HEAD", "git cat-file -p :a.txt", "git cat-file -s :0:a.txt",
               "git for-each-ref --points-at=:a.txt", "git branch --list --contains=:a.txt"]


@pytest.mark.parametrize("command", INDEX_WORDS)
def test_KEEP_a_word_that_names_an_index_entry(tmp_path, command):
    """Rule 14: a revision word or an option value before `--` that may name an index entry keeps the ask, with or
    without fsmonitor: the profile judges fsmonitor only for the forms that walk the work tree."""
    repo = _repo(tmp_path)
    decision, reasons = _decide(repo, command)
    assert decision not in FREE, (decision, reasons)


@pytest.mark.parametrize("command", ["git log --oneline -1 -- :a.txt", "git log --oneline -1 -- ':(top)a.txt'",
                                     "git show HEAD:a.txt", "git cat-file -p HEAD:a.txt"])
def test_FREE_a_path_after_the_double_dash_and_a_tree_path_name_no_index_entry(tmp_path, command):
    repo = _repo(tmp_path)
    assert _decide(repo, command)[0] == "pass"


#: Sources that start a program only for the forms that walk the work tree (rules 9 to 12; measured, a/wahrheit_a.py).
WALK_SOURCES = ["fsmonitor", "lfs_standard_filter", "hook_default", "hook_hooks_path", "hook_environment",
                "submodule_gitmodules", "submodule_gitlink_only"]
WALKING = ["git status", "git diff", "git diff --stat", "git grep -n foo", "git ls-files"]
LFS_SYSTEM = ('[filter "lfs"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n'
              "\tprocess = git-lfs filter-process\n\trequired = true\n")


def _walk_source(tmp_path, repo, monkeypatch, source):
    if source == "fsmonitor":
        _config(repo, ("core.fsmonitor", _marker(tmp_path, "fsmonitor")))
    elif source == "lfs_standard_filter":       # owner answer 2: what `git lfs install` writes to the system file
        (tmp_path / "gitconfig").write_text(LFS_SYSTEM)
        monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(tmp_path / "gitconfig"))
    elif source.startswith("hook_"):            # post-index-change runs on status
        hooks = repo / ".git" / "hooks" if source == "hook_default" else tmp_path / "hooks"
        hooks.mkdir(exist_ok=True)
        (hooks / "post-index-change").write_text(f"#!/bin/sh\necho hook >> {tmp_path / 'marker' / 'hook'}.log\n")
        (hooks / "post-index-change").chmod(0o755)
        if source == "hook_hooks_path":
            _config(repo, ("core.hooksPath", str(hooks)))
        elif source == "hook_environment":
            monkeypatch.setenv("GIT_CONFIG_PARAMETERS", f"'core.hooksPath'='{hooks}'")
    elif source == "submodule_gitmodules":
        (repo / ".gitmodules").write_text('[submodule "s"]\n\tpath = s\n\turl = ./s\n')
    elif source == "submodule_gitlink_only":    # no key and no .gitmodules: the gate finds it in the index (Q18-2)
        head = _git(repo, "rev-parse", "HEAD").strip()
        _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{head},s")


@pytest.mark.parametrize("source", WALK_SOURCES)
def test_KEEP_a_form_that_walks_the_work_tree_beside_its_sources(tmp_path, monkeypatch, source):
    """Rules 9 to 12: fsmonitor that git does not read as false, a filter (the git-lfs standard filter of the system
    configuration included, owner answer 2), any hook that is not a sample, a submodule. The gate starts none of
    them."""
    repo = _repo(tmp_path)
    _walk_source(tmp_path, repo, monkeypatch, source)
    for command in WALKING:
        decision, reasons = _decide(repo, command)
        assert decision not in FREE, (source, command, decision, reasons)
    assert _started(tmp_path) == [], "the gate started what it checks for"


@pytest.mark.parametrize("source", WALK_SOURCES)
def test_FREE_a_form_that_does_not_walk_beside_the_same_sources(tmp_path, monkeypatch, source):
    """The same sources start nothing for log and show (measured), so those stay free."""
    repo = _repo(tmp_path)
    _walk_source(tmp_path, repo, monkeypatch, source)
    for command in ("git log --oneline -1", "git show --stat HEAD"):
        decision, reasons = _decide(repo, command)
        assert decision == "pass", (source, command, decision, reasons)


@pytest.mark.parametrize("value", ["false", "0", "no"])
def test_FREE_fsmonitor_git_reads_as_false(tmp_path, value):
    repo = _repo(tmp_path)
    _config(repo, ("core.fsmonitor", value))
    assert _decide(repo, "git status")[0] == "pass"


@pytest.mark.parametrize("name,value", [("GIT_EXTERNAL_DIFF", "true"), ("GIT_DIR", ".git"),
                                        ("GIT_INDEX_FILE", "x"), ("GIT_NO_LAZY_FETCH", "0")])
def test_KEEP_a_git_environment_name_the_profile_does_not_know(tmp_path, monkeypatch, name, value):
    """Rule 13: the hook's GIT_* names, as K-NW-2 B, less GIT_PAGER."""
    repo = _repo(tmp_path)
    monkeypatch.setenv(name, value)
    assert _decide(repo, "git log --oneline -1")[0] not in FREE


# --- KEEP: class c around a read form ----------------------------------------------------------------------------

@pytest.mark.parametrize("command", [
    "cp a.txt .git/hooks/post-index-change && git status",       # a step before may change the state (class c)
    "X=1; git log --oneline -1",
    "FOO=1 git log --oneline -1",                                  # a prefix assignment that is not neutral
    "mytool --setup && git log --oneline -1",
    "cd . && git status",                                          # class e is not built
    "git log --format=%s | sh",                                    # a carrier reads the output (Vorfall 12:52Z)
    "python3 -c \"import os; os.system('git log')\"",              # Q18-1: code that names git asks at least
    "awk 'BEGIN{system(\"git status\")}'",
])
def test_KEEP_a_read_form_where_class_c_keeps_the_ask(tmp_path, command):
    repo = _repo(tmp_path)
    decision, reasons = _decide(repo, command)
    assert decision not in FREE and decision is not None, (decision, reasons)


def _embedded(tmp_path: pathlib.Path, repo: pathlib.Path) -> None:
    """An embedded repository `sub` with its own fsmonitor marker and a change, not yet in the index."""
    sub = repo / "sub"
    _git(tmp_path, "init", "-q", "-b", "main", str(sub))
    (sub / "s.txt").write_text("s\n")
    _git(sub, "add", "s.txt")
    _git(sub, "-c", "user.name=t", "-c", "user.email=t@e", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "s")
    _git(sub, "config", "core.fsmonitor", _marker(tmp_path, "subfsmonitor"))
    (sub / "s.txt").write_text("s2\n")


@pytest.mark.parametrize("command", ["git add sub && git status", "git add sub; git status", "git add sub && git diff",
                                     "git add sub && git commit -m x && git status", "git add sub && git -C . status",
                                     "git add a.txt && git status"])
def test_KEEP_a_walking_read_form_after_git_add(tmp_path, command):
    """Rule 15: `git add` of an embedded repository adds a gitlink, and a later status or diff starts that
    submodule's fsmonitor (measured, a/kette_index.py). The read profile read the index before the add, so a `git add`
    counts as a state change before a form that walks the work tree, whatever it adds."""
    repo = _repo(tmp_path)
    _embedded(tmp_path, repo)
    decision, reasons = _decide(repo, command)
    assert decision not in FREE, (decision, reasons)
    assert _started(tmp_path) == [], "the gate started what it checks for"
    if "sub" in command:
        subprocess.run(["bash", "-c", command], cwd=repo, capture_output=True, timeout=60, stdin=subprocess.DEVNULL,
                       env=plugin_env())
        assert _started(tmp_path), "the real run started no program; the case would be vacuous"


@pytest.mark.parametrize("command", ["git add sub && git log --oneline -1", "git add sub && git commit -m x"])
def test_FREE_git_add_before_a_form_that_does_not_walk(tmp_path, command):
    repo = _repo(tmp_path)
    _embedded(tmp_path, repo)
    assert _decide(repo, command)[0] == "pass"
    subprocess.run(["bash", "-c", command], cwd=repo, capture_output=True, timeout=60, stdin=subprocess.DEVNULL,
                   env=plugin_env())
    assert _started(tmp_path) == []


# --- TRUTH: the real run against the gate's answer ----------------------------------------------------------------

def _source(tmp_path: pathlib.Path, repo: pathlib.Path, name: str, monkeypatch) -> None:
    m = lambda n, body="exit 0": _marker(tmp_path, n, body)  # noqa: E731
    if name == "fsmonitor":
        _config(repo, ("core.fsmonitor", m("fsmonitor")))
    elif name == "textconv":
        (repo / ".gitattributes").write_text("*.txt diff=drv\n")
        _config(repo, ("diff.drv.textconv", m("textconv", 'cat "$1"')))
    elif name == "diff_external":
        _config(repo, ("diff.external", m("diffexternal")))
    elif name == "filter_clean":
        (repo / ".gitattributes").write_text("*.txt filter=f\n")
        _config(repo, ("filter.f.clean", m("filterclean", "cat")))
    elif name == "hooks":
        hook = repo / ".git" / "hooks" / "post-index-change"
        hook.write_text(f"#!/bin/sh\necho hook >> {tmp_path / 'marker' / 'hook'}.log\n")
        hook.chmod(0o755)
    elif name == "show_signature":
        _signed_head(repo)
        _config(repo, ("gpg.program", m("gpg_cfg", "exit 1")), ("log.showSignature", "true"))
    elif name == "gpg_on_path":
        _signed_head(repo)
        m("gpg", "exit 1")
        _config(repo, ("pretty.sig", "%G? %h"), ("format.pretty", "%G? %h"))
    elif name == "gpg_without_show":
        _signed_head(repo)
        _config(repo, ("gpg.program", m("gpg_cfg", "exit 1")))
    elif name == "promisor":
        blob = _git(repo, "rev-parse", "HEAD:a.txt").strip()
        _config(repo, ("extensions.partialClone", "origin"), ("core.repositoryformatversion", "1"),
                ("remote.origin.url", str(tmp_path / "nowhere.git")), ("remote.origin.promisor", "true"),
                ("remote.origin.uploadpack", m("uploadpack", "exit 1")))
        (repo / ".git" / "objects" / blob[:2] / blob[2:]).unlink()
    elif name == "env_external_diff":
        monkeypatch.setenv("GIT_EXTERNAL_DIFF", m("envexternaldiff"))
    elif name == "env_config_fsmonitor":
        monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", m("envfsmonitor"))
    elif name == "lfs":
        m("git-lfs", "cat")
        (repo / ".gitattributes").write_text("*.txt filter=lfs\n")
        _config(repo, ("filter.lfs.clean", "git-lfs clean -- %f"), ("filter.lfs.smudge", "git-lfs smudge -- %f"),
                ("filter.lfs.process", "git-lfs filter-process"), ("filter.lfs.required", "true"))


#: Sources that start their program for at least one of TRUTH_FORMS (measured, a/wahrheit_a.py).
SOURCES = ["fsmonitor", "textconv", "diff_external", "filter_clean", "hooks", "show_signature", "gpg_on_path",
           "gpg_without_show", "promisor", "env_external_diff", "env_config_fsmonitor", "lfs"]
TRUTH_FORMS = READ_FORMS + ["git log --format='%G? %h' -2", "git log --show-signature -1", "git log --pretty=sig -1",
                            "git log --ext-diff -p -1", "git describe --always --dirty", "git rev-parse :a.txt",
                            "git show :a.txt", "git cat-file -p :a.txt", "git for-each-ref --points-at=:a.txt",
                            "git log --oneline -1 -- :a.txt"]


@pytest.mark.parametrize("source", SOURCES)
def test_TRUTH_no_free_read_form_starts_a_program(tmp_path, monkeypatch, source):
    repo = _repo(tmp_path)
    _source(tmp_path, repo, source, monkeypatch)
    started_any, freed = [], []
    for command in TRUTH_FORMS:
        _clear(tmp_path)
        decision, reasons = _decide(repo, command)
        assert _started(tmp_path) == [], (command, "the gate started", _started(tmp_path))
        subprocess.run(shlex.split(command), cwd=repo, capture_output=True, timeout=60, stdin=subprocess.DEVNULL,
                       env=plugin_env())
        ran = _started(tmp_path)
        started_any += ran
        if decision in FREE:
            freed.append(command)
            assert ran == [], (source, command, decision, reasons, ran)
    assert started_any, f"{source} started no program for any form; the case would be vacuous"
