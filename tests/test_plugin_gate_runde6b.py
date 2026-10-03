"""Nachtrag 19b (S1): before Ebene 1 frees an allow-listed git form it reads the bound repository's effective
configuration (local, global, system, every included file) and its effective hook directory with the hook's
environment. The form stays free only when no key that selects a program for this subcommand is set and no
executable hook this subcommand starts is present; an unknown directory, unreadable configuration or an
unsure mapping is NOT MEASURED. Writes by the file tools to a repository's configuration or hooks are NOT
MEASURED too: ask under Claude, deny under Codex.

These tests judge only the gate's verdict. They run no helper program, no hook and no editor, and transfer
nothing: every helper path below is a file that is never executed. Red against c159b817, green after.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "plugins" / "proofbundle" / "hooks" / "proofbundle_gate.py"

_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


#: The program-selecting variables the gate reads from the hook's environment; the host running these tests
#: may set some of them (a CI runner or a cloud container often sets GIT_ASKPASS or GIT_EDITOR).
_PROGRAM_ENV = ["EDITOR", "GIT_ASKPASS", "GIT_EDITOR", "GIT_EXEC_PATH", "GIT_EXTERNAL_DIFF", "GIT_PAGER",
                "GIT_PROXY_COMMAND", "GIT_SSH", "GIT_SSH_COMMAND", "PAGER", "SSH_ASKPASS", "VISUAL"]


@pytest.fixture(autouse=True)
def _clean_git_config(monkeypatch):
    for key in [k for k in os.environ if k.startswith("GIT_CONFIG")] + _PROGRAM_ENV:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)


def _git(repo: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org",
                           "-c", "commit.gpgsign=false", *args], check=True, capture_output=True, text=True)


def _repo(tmp_path: pathlib.Path, name: str = "r") -> pathlib.Path:
    """A plain repository with one commit, a branch `side`, a bare remote `origin`, and no hook or helper.
    git init's sample hooks (*.sample) stay; git never runs them, and the gate must not count them."""
    repo, bare = tmp_path / name, tmp_path / f"{name}.git"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "branch", "side")
    _git(repo, "init", "-q", "--bare", str(bare))
    _git(repo, "remote", "add", "origin", str(bare))
    return repo


def _helper(tmp_path: pathlib.Path) -> str:
    """A path that names a program. It is never executed by these tests."""
    path = tmp_path / "helper-never-run.sh"
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _hook(hooks_dir: pathlib.Path, name: str) -> None:
    hooks_dir.mkdir(parents=True, exist_ok=True)
    path = hooks_dir / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _deadline() -> float:
    return gate.time.monotonic() + 30


def _decision(command: str, repo: pathlib.Path, host: str = "claude") -> tuple[str | None, str]:
    outcome = gate.decide(command, str(repo), _deadline(), host=host)
    if outcome is None:
        return None, ""
    return outcome.decision, outcome.text


# --- the six S1 forms: with a program-selecting key or hook NOT MEASURED, without it free -------------------

def _set_fsmonitor(repo, tmp_path):
    _git(repo, "config", "core.fsmonitor", _helper(tmp_path))


def _set_clean_filter(repo, tmp_path):
    (repo / ".gitattributes").write_text("*.txt filter=f\n", encoding="utf-8")
    _git(repo, "config", "filter.f.clean", _helper(tmp_path))


def _set_diff_driver(repo, tmp_path):
    (repo / ".gitattributes").write_text("*.txt diff=d\n", encoding="utf-8")
    _git(repo, "config", "diff.d.command", _helper(tmp_path))


def _set_post_checkout(repo, tmp_path):
    _hook(repo / ".git" / "hooks", "post-checkout")


def _set_editor(repo, tmp_path):
    _git(repo, "config", "core.editor", _helper(tmp_path))


def _set_uploadpack(repo, tmp_path):
    _git(repo, "config", "remote.origin.uploadpack", _helper(tmp_path))


S1_FORMS = [
    ("git status --short", _set_fsmonitor),
    ("git add a.txt", _set_clean_filter),
    ("git diff HEAD", _set_diff_driver),
    ("git checkout side", _set_post_checkout),
    ("git commit", _set_editor),
    ("git fetch origin", _set_uploadpack),
]


@pytest.mark.parametrize("command, setup", S1_FORMS, ids=[c for c, _ in S1_FORMS])
def test_s1_form_with_a_program_selecting_key_or_hook_is_not_measured(tmp_path, command, setup):
    repo = _repo(tmp_path)
    setup(repo, tmp_path)
    decision, text = _decision(command, repo)
    assert decision == "ask", (command, decision, text)
    assert text.startswith("NOT MEASURED:"), text
    assert "selects a program" in text or "hook" in text, text


@pytest.mark.parametrize("command", [c for c, _ in S1_FORMS])
def test_s1_form_in_a_repository_without_such_keys_or_hooks_stays_free(tmp_path, command):
    repo = _repo(tmp_path)
    assert _decision(command, repo) == (None, ""), command


def test_a_pre_commit_hook_makes_git_commit_not_measured_but_leaves_git_status_free(tmp_path):
    """Point 4: a repository with a pre-commit hook, as the pre-commit framework installs it."""
    repo = _repo(tmp_path)
    _hook(repo / ".git" / "hooks", "pre-commit")
    assert _decision("git commit", repo)[0] == "ask"
    assert _decision("git status", repo) == (None, "")


# --- unreadable configuration, core.hooksPath ---------------------------------------------------------------

def test_an_included_file_that_cannot_be_read_is_not_measured(tmp_path, monkeypatch):
    """As root, a mode-000 file stays readable; an include that names a directory is a read failure git
    itself reports (measured: `unable to access ...: Is a directory`, exit 128)."""
    repo = _repo(tmp_path)
    unreadable = tmp_path / "included-dir"
    unreadable.mkdir()
    cfg = tmp_path / "global.gitconfig"
    cfg.write_text(f"[include]\n\tpath = {unreadable}\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    decision, text = _decision("git status", repo)
    assert decision == "ask" and text.startswith("NOT MEASURED:"), text
    assert "configuration" in text, text


def test_core_hookspath_to_another_directory_is_where_hooks_are_read(tmp_path):
    repo = _repo(tmp_path)
    elsewhere = tmp_path / "shared-hooks"
    _git(repo, "config", "core.hooksPath", str(elsewhere))
    _hook(elsewhere, "post-checkout")
    assert _decision("git checkout side", repo)[0] == "ask"
    # a hook in .git/hooks is not the effective one while core.hooksPath points elsewhere
    repo2 = _repo(tmp_path, "r2")
    empty = tmp_path / "empty-hooks"
    empty.mkdir()
    _git(repo2, "config", "core.hooksPath", str(empty))
    _hook(repo2 / ".git" / "hooks", "post-checkout")
    assert _decision("git checkout side", repo2) == (None, "")


def test_a_global_program_key_counts(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    cfg = tmp_path / "global.gitconfig"
    cfg.write_text(f"[core]\n\tpager = {_helper(tmp_path)}\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    assert _decision("git log --oneline", repo)[0] == "ask"


# --- unknown directory, wrappers, entries that left the list (A) --------------------------------------------

def test_a_free_form_after_a_directory_change_is_not_measured(tmp_path):
    repo = _repo(tmp_path)
    assert _decision("cd . && git status", repo)[0] == "ask"
    assert _decision("git status && git log --oneline -n 3", repo) == (None, "")


@pytest.mark.parametrize("command", ["git merge side", "git pull", "git rebase side", "git cherry-pick side",
                                     "git clone x y", "git gc", "git worktree list", "git verify-commit HEAD"])
def test_entries_whose_program_list_is_not_fully_justified_left_the_allow_list(tmp_path, command):
    repo = _repo(tmp_path)
    assert _decision(command, repo)[0] == "ask", command


def test_under_codex_a_free_form_is_not_measured_because_the_directory_is_not_bound(tmp_path):
    repo = _repo(tmp_path)
    assert _decision("git status", repo, host="codex")[0] == "ask"   # the host answer turns ask into deny


# --- the write path: file tools on configuration and hooks ------------------------------------------------

def _run(event: dict, host: str = "claude") -> dict:
    args = [sys.executable, "-I", str(GATE)] + (["--host", "codex"] if host == "codex" else [])
    out = subprocess.run(args, input=json.dumps(event), capture_output=True, text=True, timeout=120,
                         env=dict(os.environ))
    return json.loads(out.stdout) if out.stdout.strip() else {}


def _file_event(tool: str, path: pathlib.Path, cwd: pathlib.Path) -> dict:
    key = "notebook_path" if tool == "NotebookEdit" else "file_path"
    tool_input = {key: str(path)}
    if tool == "Write":
        tool_input["content"] = "x\n"
    elif tool == "Edit":
        tool_input.update(old_string="a", new_string="b")
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": str(cwd), "tool_input": tool_input}


def _patch_event(paths: list[str], cwd: pathlib.Path) -> dict:
    body = "".join(f"*** Update File: {p}\n@@\n-a\n+b\n" for p in paths)
    return {"hook_event_name": "PreToolUse", "tool_name": "apply_patch", "cwd": str(cwd),
            "tool_input": {"command": f"*** Begin Patch\n{body}*** End Patch"}}


def _decision_of(answer: dict) -> str | None:
    return answer.get("hookSpecificOutput", {}).get("permissionDecision")


@pytest.mark.parametrize("tool", ["Write", "Edit"])
@pytest.mark.parametrize("target", [".git/config", ".git/hooks/pre-push"])
def test_a_file_tool_write_to_configuration_or_hooks_asks_under_claude(tmp_path, tool, target):
    repo = _repo(tmp_path)
    answer = _run(_file_event(tool, repo / target, repo))
    assert _decision_of(answer) == "ask", answer
    assert answer["systemMessage"].startswith("NOT MEASURED:"), answer
    assert "configuration or hooks" in answer["systemMessage"], answer


@pytest.mark.parametrize("tool", ["Write", "Edit", "apply_patch"])
@pytest.mark.parametrize("target", [".git/config", ".git/hooks/pre-push"])
def test_a_file_tool_write_to_configuration_or_hooks_denies_under_codex(tmp_path, tool, target):
    repo = _repo(tmp_path)
    event = _patch_event([target], repo) if tool == "apply_patch" else _file_event(tool, repo / target, repo)
    answer = _run(event, host="codex")
    assert _decision_of(answer) == "deny", answer
    assert answer["systemMessage"].startswith("NOT MEASURED:"), answer


def test_a_write_through_a_symlink_into_the_hooks_is_resolved(tmp_path):
    repo = _repo(tmp_path)
    link = tmp_path / "innocent-looking"
    link.symlink_to(repo / ".git" / "hooks")
    answer = _run(_file_event("Write", link / "post-checkout", repo))
    assert _decision_of(answer) == "ask", answer


def test_a_write_to_an_included_configuration_file_asks(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    included = tmp_path / "included.gitconfig"   # not yet existing: git skips it, a write would create it
    _git(repo, "config", "include.path", str(included))
    answer = _run(_file_event("Write", included, repo))
    assert _decision_of(answer) == "ask", answer


def test_a_write_to_an_ordinary_file_gets_no_decision(tmp_path):
    repo = _repo(tmp_path)
    assert _run(_file_event("Write", repo / "notes.md", repo)) == {}
    assert _run(_file_event("Edit", repo / "a.txt", repo)) == {}


def test_the_hook_matcher_covers_the_file_tools():
    hooks = json.loads((GATE.parent / "hooks.json").read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
    matchers = [h["matcher"] for h in hooks]
    import re
    for tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        assert any(re.fullmatch(m, tool) for m in matchers), (tool, matchers)
    assert not any(re.fullmatch(m, "Read") for m in matchers)


# --- siblings found while writing the per-entry table of D3 (Nachtrag 19b, Punkt 9) --------------------------

def test_git_init_left_the_allow_list(tmp_path):
    """git init writes the configuration and copies hooks from a template directory (git-init(1) TEMPLATE
    DIRECTORY), so a later call in the repository runs them; its list is not justified, so it left (A)."""
    repo = _repo(tmp_path)
    for command in ("git init", "git init fresh"):
        decision, text = _decision(command, repo)
        assert decision == "ask" and text.startswith("NOT MEASURED:"), (command, text)


@pytest.mark.parametrize("command", ["git rev-parse :a.txt", "git cat-file -p :a.txt", "git grep a",
                                     "git log --oneline -n 1", "git check-attr diff a.txt",
                                     "git check-ignore a.txt", "git ls-tree HEAD", "git show HEAD", "git branch",
                                     "git config --get user.name"])
def test_a_fsmonitor_hook_counts_for_every_entry_because_any_index_read_queries_it(tmp_path, command):
    """read-cache.c post_read_index_from calls tweak_fsmonitor, which queries the hook (fsmonitor.c), and a
    revision :<path> reads the index; the gate does not try to tell which entry reads the index."""
    repo = _repo(tmp_path)
    _git(repo, "config", "core.fsmonitor", _helper(tmp_path))
    decision, text = _decision(command, repo)
    assert decision == "ask", (command, text)
    assert "core.fsmonitor" in text, text


def test_the_built_in_fsmonitor_daemon_is_a_boolean_and_selects_no_configured_program(tmp_path):
    repo = _repo(tmp_path)
    _git(repo, "config", "core.fsmonitor", "true")
    assert _decision("git rev-parse HEAD", repo) == (None, "")
    assert _decision("git status", repo) == (None, "")


@pytest.mark.parametrize("command", ["git log --format=%G?", "git log --pretty=format:%GS",
                                     "git show -s --format=%GK HEAD",
                                     "git for-each-ref --format='%(signature:grade)'",
                                     "git for-each-ref --format '%(signature)'", "git branch --sort=signature",
                                     "git tag -l --sort signature", "git branch --format='%(signature:signer)'"])
def test_a_format_or_sort_value_that_verifies_signatures_is_not_measured(tmp_path, command):
    """%G… (pretty.c) and the ref-filter atom signature (ref-filter.c) run gpg.program, gpg or ssh-keygen;
    the value may be attached or the next word."""
    repo = _repo(tmp_path)
    assert _decision(command, repo)[0] == "ask", command


@pytest.mark.parametrize("command", ["git log --format=%h", "git log --pretty=oneline",
                                     "git for-each-ref --format='%(refname)'", "git branch --sort=-committerdate",
                                     "git tag -l --sort=version:refname"])
def test_a_format_or_sort_value_without_a_signature_stays_free(tmp_path, command):
    repo = _repo(tmp_path)
    assert _decision(command, repo) == (None, ""), command


@pytest.mark.parametrize("key, value, command", [
    ("format.pretty", "%G? %h", "git log"), ("pretty.sig", "format:%GS", "git show"),
    ("tag.sort", "signature", "git tag -l"), ("branch.sort", "signature:grade", "git branch")])
def test_a_configured_default_format_or_sort_that_verifies_signatures_counts(tmp_path, key, value, command):
    repo = _repo(tmp_path)
    _git(repo, "config", key, value)
    decision, text = _decision(command, repo)
    assert decision == "ask" and key in text, (command, text)
    assert _decision("git status", repo) == (None, "")


def test_a_default_format_without_a_signature_stays_free(tmp_path):
    repo = _repo(tmp_path)
    _git(repo, "config", "format.pretty", "oneline")
    assert _decision("git log", repo) == (None, "")


@pytest.mark.parametrize("args, output", [
    (("config", "--list"), b"local\0file:.git/config\0core.bare\nfalse\0local\0file:.git/config"),
    (("rev-parse", "--path-format=absolute", "--git-common-dir"), b"/x/.git\n/x/.git\n")])
def test_git_output_the_gate_cannot_read_is_not_measured_not_a_partial_read(tmp_path, monkeypatch, args, output):
    """A check that branches on the shape of git's output has an else branch: an unexpected shape is
    unreadable, never a shorter list of keys or paths."""
    repo = _repo(tmp_path)
    real = gate._git

    def fake(directory, *a, deadline):
        if a[:len(args)] == args:
            return subprocess.CompletedProcess(["git", *a], 0, output, b"")
        return real(directory, *a, deadline=deadline)

    monkeypatch.setattr(gate, "_git", fake)
    decision, text = _decision("git status", repo)
    assert decision == "ask" and "cannot read" in text, text


def test_a_write_to_the_system_file_git_var_names_asks(tmp_path, monkeypatch):
    """git var GIT_CONFIG_SYSTEM names the file git itself would read (a build with another prefix has another
    path than /etc/gitconfig); a write that would create it is NOT MEASURED."""
    repo = _repo(tmp_path)
    system = tmp_path / "prefix" / "etc" / "gitconfig"
    monkeypatch.delenv("GIT_CONFIG_SYSTEM", raising=False)
    real = gate._git

    def fake(directory, *a, deadline):
        if a == ("var", "GIT_CONFIG_SYSTEM"):
            return subprocess.CompletedProcess(["git", *a], 0, f"{system}\n".encode(), b"")
        return real(directory, *a, deadline=deadline)

    monkeypatch.setattr(gate, "_git", fake)
    outcome = gate.decide_write("Write", {"file_path": str(system), "content": "x"}, str(repo), _deadline())
    assert outcome is not None and outcome.decision == "ask", outcome


def test_a_write_into_a_submodule_git_directory_asks(tmp_path):
    repo = _repo(tmp_path)
    _git(repo, "init", "-q", "--bare", str(repo / ".git" / "modules" / "sub"))
    for target in (".git/modules/sub/config", ".git/modules/sub/hooks/post-checkout"):
        answer = _run(_file_event("Write", repo / target, repo))
        assert _decision_of(answer) == "ask", (target, answer)


@pytest.mark.parametrize("name, value, command", [
    ("GIT_EXTERNAL_DIFF", "HELPER", "git diff"), ("GIT_ASKPASS", "HELPER", "git fetch origin"),
    ("SSH_ASKPASS", "HELPER", "git ls-remote origin"), ("GIT_SSH_COMMAND", "HELPER", "git fetch origin"),
    ("GIT_EDITOR", "HELPER", "git commit"), ("EDITOR", "vim", "git commit"), ("PAGER", "less", "git log"),
    ("GIT_PAGER", "HELPER", "git show HEAD"), ("GIT_EXEC_PATH", "DIR", "git rev-parse HEAD")])
def test_a_program_selecting_variable_in_the_hooks_environment_counts_like_its_key(tmp_path, monkeypatch, name,
                                                                                  value, command):
    """Point 1: the hook's own environment is read; the command inherits it from the same host."""
    repo = _repo(tmp_path)
    monkeypatch.setenv(name, {"HELPER": _helper(tmp_path), "DIR": str(tmp_path)}.get(value, value))
    decision, text = _decision(command, repo)
    assert decision == "ask" and f"${name}" in text, (command, text)


@pytest.mark.parametrize("name, value, command", [
    ("GIT_EDITOR", "true", "git commit"), ("GIT_EDITOR", ":", "git commit"), ("PAGER", "cat", "git log"),
    ("GIT_PAGER", "", "git log"), ("GIT_EXTERNAL_DIFF", "HELPER", "git status"), ("GIT_ASKPASS", "HELPER", "git log")])
def test_a_neutral_value_or_a_variable_the_entry_does_not_use_stays_free(tmp_path, monkeypatch, name, value, command):
    repo = _repo(tmp_path)
    monkeypatch.setenv(name, {"HELPER": _helper(tmp_path)}.get(value, value))
    assert _decision(command, repo) == (None, ""), (name, command)


def test_the_gate_reads_exactly_the_program_selecting_variables_these_tests_clean():
    read = {n for names, _ in gate._ENV_FAMILIES.values() for n in names} | set(gate._ENV_EVERY_ENTRY)
    assert read == set(_PROGRAM_ENV)


# --- D3 names, per allow-list entry, what is checked (Nachtrag 19b, Punkt 9); the text is the code's -------

DECISIONS = GATE.parent.parent / "DECISIONS.md"
_BEGIN, _END = "<!-- d3-entries:begin (generated from the gate; tests/test_plugin_gate_runde6b.py) -->", \
    "<!-- d3-entries:end -->"
#: What counts in each family, in words; the citation is the gate's own source string.
_FAMILY_WORDS = {
    "fsmonitor": "`core.fsmonitor` with a value other than a boolean (a boolean selects git's built-in daemon)",
    "filter": "`filter.<driver>.clean`, `filter.<driver>.smudge`, `filter.<driver>.process`",
    "diff-driver": "`diff.external`, `diff.<driver>.command`, `diff.<driver>.textconv`",
    "merge-driver": "`merge.<driver>.driver`",
    "editor": "`core.editor`",
    "transport": "`core.sshCommand`, `core.gitProxy`, `core.askPass`, `core.alternateRefsCommand`, "
                 "`credential.helper`, `credential.<url>.helper`, `remote.<name>.uploadpack`, `remote.<name>.vcs`",
    "transport-helper-url": "`remote.<name>.url`, `remote.<name>.pushurl` with a `<transport>::<address>` value",
    "rewrite-to-helper": "`url.<base>.insteadOf`, `url.<base>.pushInsteadOf` with a `<transport>::` base",
    "protocol": "`protocol.allow` of `always` or `user`; `protocol.ext.allow`, `protocol.fd.allow` other than "
                "`never`",
    "pager": "`core.pager` for an entry that pages by default; `pager.<entry>` for every entry unless false",
    "signature-format": "`format.pretty`, `pretty.<name>` with a value containing `%G`",
    "signature-sort": "`branch.sort`, `tag.sort` with a value containing `signature`",
    "promisor": "`extensions.partialClone`, `remote.<name>.promisor`, `remote.<name>.partialclonefilter`, "
                "whatever the value",
}


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def _d3_entries_block() -> str:
    out = [_BEGIN, "",
           "Every entry, in addition to its row: `core.fsmonitor` (family fsmonitor), the partial-clone keys "
           "(family promisor), `pager.<entry>`, "
           "`$GIT_EXEC_PATH` in the hook's environment, and the hook `fsmonitor-watchman` only through "
           "`core.fsmonitor`. A row with *submodules* also counts every `submodule.*` key and a `.gitmodules` "
           "file, because the gate does not read a submodule's own configuration.", "",
           "| Family | Keys and values that count | Variables in the hook's environment | Source |",
           "|---|---|---|---|"]
    for name, (_pattern, _test, source) in gate._KEY_FAMILIES.items():
        names, _ = gate._ENV_FAMILIES.get(name, ((), None))
        env = ", ".join(f"`${n}`" for n in names) or "none"
        out.append(f"| {name} | {_cell(_FAMILY_WORDS[name])} | {env} | {_cell(source)} |")
    out += ["", "| Entry | Options vetted beyond the bare form | Keys that make it NOT MEASURED | Hooks git starts "
                "for it (githooks(5)) | Source |", "|---|---|---|---|---|"]
    for sub in sorted(gate._GIT_LOCAL_SUBCOMMANDS):
        prof = gate._REPO_PROFILE[sub]
        if sub == "config":
            options = ("reads: " + ", ".join(f"`{o}`" for o in sorted(gate._CONFIG_READ_OPTIONS))
                       + ", " + ", ".join(f"`git config {s}`" for s in sorted(gate._CONFIG_READ_SUBCOMMANDS))
                       + "; writes only of " + ", ".join(f"`{k}`" for k in sorted(gate._CONFIG_INERT_KEYS))
                       + "; with " + ", ".join(f"`{o}`" for o in sorted(gate._CONFIG_VETTED_OPTIONS
                                                                       - gate._CONFIG_READ_OPTIONS)))
        else:
            vetted = sorted(gate._GIT_VETTED_OPTIONS.get(sub, ()))
            options = ", ".join(f"`{o}`" for o in vetted) or "none, the bare form only"
        if sub in gate._SIGNATURE_WORDS:
            options += f"; a word containing `{gate._SIGNATURE_WORDS[sub]}` is NOT MEASURED"
        keys = sorted(prof["keys"]) + (["pager (`core.pager`)"] if prof["pages"] else [])
        keys += [f"`{t}` true" for t in sorted(prof["triggers"])] + (["*submodules*"] if prof["submodules"] else [])
        hooks = ("every githooks(5) name" if prof["hooks"] == gate._ALL
                 else ", ".join(f"`{h}`" for h in sorted(prof["hooks"])) or "none")
        out.append(f"| `{sub}` | {_cell(options)} | {_cell(', '.join(keys) or 'only the every-entry keys')} | "
                   f"{hooks} | {_cell(prof['sources'])} |")
    out += ["", _END]
    return "\n".join(out)


def test_d3_names_the_checked_options_keys_and_hooks_of_every_allow_list_entry_as_the_code_has_them():
    assert set(_FAMILY_WORDS) == set(gate._KEY_FAMILIES)
    text = DECISIONS.read_text(encoding="utf-8")
    assert text.count(_BEGIN) == 1 and text.count(_END) == 1
    block = text[text.index(_BEGIN):text.index(_END) + len(_END)]
    assert block == _d3_entries_block()


# --- hooks per githooks(5): commit and fetch carry the hooks named for them, not every name ----------------

@pytest.mark.parametrize("command", ["git fetch origin", "git commit", "git status", "git log --oneline -n 1"])
def test_the_ebene_2_pre_push_hook_does_not_make_a_form_that_never_pushes_not_measured(tmp_path, command):
    """githooks(5): pre-push is called by git-push(1) only. Measured in Nachtrag 19b: with every githooks(5)
    name counted for fetch, the installed Ebene-2 hook made every git fetch NOT MEASURED."""
    repo = _repo(tmp_path)
    _hook(repo / ".git" / "hooks", "pre-push")
    assert _decision(command, repo) == (None, ""), command


@pytest.mark.parametrize("hook, command", [
    ("pre-commit", "git commit"), ("prepare-commit-msg", "git commit"), ("commit-msg", "git commit"),
    ("post-commit", "git commit"), ("reference-transaction", "git commit"), ("post-index-change", "git commit"),
    ("pre-auto-gc", "git commit"), ("reference-transaction", "git fetch origin"), ("pre-auto-gc", "git fetch origin"),
    ("pre-push", "git stash"), ("post-checkout", "git stash")])
def test_a_hook_githooks_names_for_the_entry_counts(tmp_path, hook, command):
    repo = _repo(tmp_path)
    _hook(repo / ".git" / "hooks", hook)
    decision, text = _decision(command, repo)
    assert decision == "ask" and hook in text, (hook, command, text)



# --- the signing program alone starts nothing; what triggers signing or verification counts -----------------

@pytest.mark.parametrize("command", ["git log", "git show HEAD", "git branch", "git tag -l", "git commit",
                                     "git stash list"])
def test_a_configured_signing_program_alone_leaves_the_form_free(tmp_path, command):
    """gpg.program and gpg.<format>.program choose which program signs or verifies; log and show verify only
    under show_signature (log-tree.c), stash never signs (builtin/stash.c). Measured in Nachtrag 19b: the
    shape of this cloud container (gpg.ssh.program set) made git log NOT MEASURED while it ran nothing."""
    repo = _repo(tmp_path)
    _git(repo, "config", "gpg.format", "ssh")
    _git(repo, "config", "gpg.ssh.program", _helper(tmp_path))
    _git(repo, "config", "gpg.program", _helper(tmp_path))
    assert _decision(command, repo) == (None, ""), command


@pytest.mark.parametrize("key, command", [("commit.gpgsign", "git commit"), ("log.showsignature", "git log"),
                                          ("log.showsignature", "git show HEAD"), ("tag.gpgsign", "git tag -l")])
def test_the_key_that_triggers_signing_or_verification_counts(tmp_path, key, command):
    repo = _repo(tmp_path)
    _git(repo, "config", key, "true")
    decision, text = _decision(command, repo)
    assert decision == "ask" and key in text.lower(), (command, text)
