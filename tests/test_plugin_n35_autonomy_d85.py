"""D85, Nachtrag 35: the autonomous answer under Claude Code. The gate asks only for a closed list of external effects;
every other ask of decide() becomes a deny that names a rewrite the gate checked free, or no way at all.

Owner word of 2026-10-18, 20:40 Berlin: "ich muss sehr viel bestätigen das muss so aufhören" and "das plugin muss
weitestgehend autonom funktionieren". delta measured 97 real asks (D3, D27, D33, D34 the most), four of them on the
owner's screens: `git status` in a chain, `git status --short | head`, a here-document with `git push` as text and
`git rev-parse` in `$( )`.

The rule: decide() judges as before. Under Claude Code the hook answers an ask
- with the ask, where the command is one call with an external effect (AUTONOMY_EFFECTS: a push, a deleted remote
  branch, a tag, a release, a merge without --auto, a pull request, issue, comment or review, a setting of a repository,
  a gh call that writes, a change of a done order), and for a gated MCP tool: a click of the owner;
- with a deny whose reason leads with a rewrite, where the gate split the command into calls (a chain into its steps, a
  `cd` into `git -C`, a `$( )` into a call of its own, a pipe into its git or gh call, a here-document into a Write, a
  commit message into a file and `git commit -F`) and judged every call free or an external effect it asks for: a
  detour the session takes without a person;
- with a deny that names no way, where no rewrite is free: a block.
The rewrite also stands in a field of its own (rewriteHint): Claude Code accepts it, measured, but only the reason of a
deny reaches the model (n35/messung/deny_path_summary.txt). Under Codex nothing changes. Nothing gets freer: an ask
becomes an ask or a deny, every other answer stays.

RED at bbf576ff (the head of Nachtrag 36 before Nachtrag 35): every detour and every block (the hook asked). The asks of
the closed list, the answers under Codex, a free call and a gated MCP tool are controls, green at both.
"""
from __future__ import annotations

import json
import os
import pathlib
import shlex
import sys
import time

import pytest

import _gate_answer as ga
import test_plugin_n29_work_profile_d71 as d71

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean
#: The flag with which the plugin's hook of Claude Code starts the gate (hooks.json, D85); a gate without the autonomous
#: answer (the base of the red run) is started as it always was.
AUTONOMOUS = [gate.AUTONOMOUS_FLAG] if hasattr(gate, "AUTONOMOUS_FLAG") else []

COMMIT = "git commit -m \"$(cat <<'EOF'\nfix: x\n\ngit push later\nEOF\n)\""
#: Detours: (form, first hint, the calls the rewrite names, {R} the repository); each asked at bbf576ff.
DETOURS = [
    ("cd {R} && git status", "git_C_statt_cd", ["git -C {R} status"]),
    ("git add README.md && git status", "kette_teilen", ["git add README.md", "git status"]),
    ("git log --oneline $(git rev-parse HEAD)", "git_nicht_in_subst",
     ["git rev-parse HEAD", "git log --oneline <output of call 1>"]),
    ("H=$(git rev-parse HEAD); echo $H", "git_nicht_in_subst", ["git rev-parse HEAD", "echo <output of call 1>"]),
    (COMMIT, "nachricht_als_datei",
     ["Write <a file outside the repository>", "git commit -F <a file outside the repository>"]),
    ("git worktree list | head", "pipe_teilen", ["git worktree list"]),
    ("git fetch origin && git log --oneline HEAD..origin/main", "kette_teilen",
     ["git fetch origin", "git log --oneline HEAD..origin/main"]),
    ("git push origin $(git rev-parse --abbrev-ref HEAD)", "push_HEAD", ["git push origin HEAD"]),
    ("git push -u origin \"$(git branch --show-current)\"", "push_HEAD", ["git push -u origin HEAD"]),
    ("git commit -F - <<'EOF'\ndocs: notes\n\nchecked with git log\nEOF", "nachricht_als_datei",
     ["Write <a file outside the repository>", "git commit -F <a file outside the repository>"]),
    ("git -C \"$(pwd)\" status --short", "woertlich", ["git -C {R} status --short"]),
    ("cat > {T}/notes.md <<'EOF'\ngit push origin main\nEOF\ngit log --oneline $(git rev-parse HEAD)",
     "git_nicht_in_subst", ["Write {T}/notes.md", "git rev-parse HEAD", "git log --oneline <output of call 2>"]),
]
#: Blocks: no rewrite is free and no external effect; each asked at bbf576ff.
BLOCKS = ["git reset --hard HEAD~1", "git rebase -i main", "git stash; git stash drop",
          "python3 -c \"import os; os.system('git push origin main')\"", "git status > .git/hooks/post-index-change",
          "git show HEAD~1:SPEC.md | wc -l", "git clean -fd", "git checkout -- README.md", "git commit --amend",
          # found in the corpus's harm group by a first version of D85, which named them as detours: a script written
          # by a here-document and run, an unquoted here-document whose body runs a push, a pipe into tee .git/config
          "cat > x.sh <<'EOF'\ngit push origin main\nEOF\nbash x.sh",
          "cat > x.sh <<'EOF'\ngit push origin main\nEOF\nchmod +x x.sh && ./x.sh",
          "cat > notes.md <<EOF\n$(git push origin main)\nEOF", "git log --oneline | tee .git/config",
          "git commit -F - <<EOF\nx $(git push origin main)\nEOF", "make && git log --oneline $(git rev-parse HEAD)",
          "cat > {T}/.notes <<'EOF'\ngit push origin main\nEOF\ngit log --oneline $(git rev-parse HEAD)",
          "cat > {R}/.git/info/x <<'EOF'\ngit push\nEOF\ngit log --oneline $(git rev-parse HEAD)"]
#: The closed list: one call with an external effect keeps the ask (an owner click), at bbf576ff and at the head.
EXTERNAL = [("git push origin topic", "push"), ("gh pr create --fill", "pr"), ("git tag v1", "tag"),
            ("gh pr comment 12 --body x", "pr"), ("gh release create v9 --notes x", "release"),
            ("gh api -X DELETE repos/b7n0de/proofbundle/git/refs/heads/x", "gh_write"),
            ("gh pr merge 12 -R b7n0de/proofbundle --merge", "merge"), ("gh issue create --title t --body b", "pr"),
            ("gh repo edit --visibility public", "settings")]


def _form(form, repo):
    return form.replace("{R}", str(repo)).replace("{T}", str(repo.parent))


def _hook(repo, tmp_path, command, host="claude", tool="Bash", tool_input=None):
    event = {"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": str(repo), "session_id": "s-d85",
             "tool_input": tool_input if tool_input is not None else {"command": command}}
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR")}
    env["CLAUDE_PLUGIN_DATA"] = env["PLUGIN_DATA"] = str(tmp_path / "data")
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", host, *AUTONOMOUS], json.dumps(event), env,
                              cwd=str(repo))
    assert proc.returncode == 0, proc.stderr
    return ga.parsed(proc, entry), entry


def _on_topic(tmp_path):
    """The repository of the D71 tests on its branch topic: a push of HEAD is no push to main."""
    repo = d71._repo(tmp_path)
    d71._git(repo, "checkout", "-q", "topic")
    return repo


def _outside(tmp_path):
    """The same repository of another owner: outside the work profile of b7n0de, where the closed list keeps its ask.
    Changed in Nachtrag 37 (D93): in the work profile of b7n0de an ask of the closed list is a card in the Leitstand."""
    return d71._repo(tmp_path, url="https://github.com/someone/proofbundle.git")


@pytest.mark.parametrize("form, first, calls", DETOURS)
def test_D85_an_ask_with_a_free_rewrite_becomes_a_deny_that_names_it(tmp_path, form, first, calls):
    repo = _on_topic(tmp_path)
    answer, entry = _hook(repo, tmp_path, _form(form, repo))
    specific = answer["hookSpecificOutput"]
    assert specific["permissionDecision"] == "deny", answer
    reason = specific["permissionDecisionReason"]
    assert reason.startswith("proofbundle gate, autonomous operation (D85)"), reason
    for call in calls:
        assert f"`{_form(call, repo)}`" in reason, (call, reason)
    assert answer["rewriteHint"]["ids"][0] == first, answer["rewriteHint"]
    assert answer["rewriteHint"]["calls"] == [_form(c, repo) for c in calls]
    assert "(D85)." in ga.short_text(answer)
    assert (entry["verdict"], entry["decision"], entry["autonomy"]["klasse"]) == ("ask", "deny", "umweg"), entry


@pytest.mark.parametrize("form", BLOCKS)
def test_D85_an_ask_with_no_free_rewrite_and_no_external_effect_is_blocked(tmp_path, form):
    repo = d71._repo(tmp_path)
    answer, entry = _hook(repo, tmp_path, _form(form, repo))
    specific = answer["hookSpecificOutput"]
    assert specific["permissionDecision"] == "deny", answer
    assert "no form of this call is free" in specific["permissionDecisionReason"]
    assert answer["rewriteHint"]["ids"] == ["kein_freier_weg"] and answer["rewriteHint"]["calls"] == []
    assert (entry["verdict"], entry["decision"], entry["autonomy"]["klasse"]) == ("ask", "deny", "sperre"), entry


@pytest.mark.parametrize("form, effect", EXTERNAL)
def test_D85_control_one_call_with_an_external_effect_keeps_the_ask(tmp_path, form, effect):
    repo = _outside(tmp_path)
    answer, _entry = _hook(repo, tmp_path, form)
    assert answer["hookSpecificOutput"]["permissionDecision"] == "ask", answer
    assert "rewriteHint" not in answer


@pytest.mark.parametrize("form, effect", EXTERNAL)
def test_D85_the_log_names_the_external_effect_of_a_kept_ask(tmp_path, form, effect):
    repo = _outside(tmp_path)
    _answer, entry = _hook(repo, tmp_path, form)
    assert entry["autonomy"] == {"klasse": "aussen", "wirkung": [effect]}, entry


@pytest.mark.parametrize("form", [d[0] for d in DETOURS] + BLOCKS + [e[0] for e in EXTERNAL])
def test_D85_control_codex_answers_as_before(tmp_path, form):
    repo = d71._repo(tmp_path)
    answer, entry = _hook(repo, tmp_path, _form(form, repo), host="codex")
    assert answer["hookSpecificOutput"].get("permissionDecision") in ("deny", None), answer   # a plain push warns
    assert "rewriteHint" not in answer and "autonomy" not in entry
    assert "autonomous operation" not in json.dumps(answer)


@pytest.mark.parametrize("form", ["git status", "git -C {R} status --short | head -5", "ls -la", "git log --oneline -3"])
def test_D85_control_a_free_call_stays_free(tmp_path, form):
    repo = d71._repo(tmp_path)
    answer, _entry = _hook(repo, tmp_path, _form(form, repo))
    assert answer is None or isinstance(answer, ga.Silent), answer


def test_D85_control_a_gated_mcp_tool_keeps_the_ask(tmp_path):
    repo = _outside(tmp_path)
    answer, entry = _hook(repo, tmp_path, None, tool="mcp__github__create_pull_request",
                          tool_input={"owner": "b7n0de", "repo": "proofbundle", "title": "t", "head": "x", "base": "main"})
    assert answer["hookSpecificOutput"]["permissionDecision"] == "ask", answer


def test_D85_the_ask_of_a_file_tool_on_the_hooks_is_blocked(tmp_path):
    repo = d71._repo(tmp_path)
    answer, entry = _hook(repo, tmp_path, None, tool="Write",
                          tool_input={"file_path": str(repo / ".git" / "hooks" / "pre-push"), "content": "x"})
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny", answer
    assert entry["autonomy"]["klasse"] == "sperre"


@pytest.mark.parametrize("form, _first, _calls", DETOURS)
def test_D85_every_call_a_rewrite_names_is_free_or_an_external_ask_and_stood_in_the_command(tmp_path, form, _first,
                                                                                         _calls):
    """The property behind every detour: the gate itself judges each call of the rewrite, with the hole filled by a
    literal word, free or one call of the closed list; and every git or gh call of the rewrite stands in the command."""
    repo = _on_topic(tmp_path)
    command = _form(form, repo)
    environ = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                          "PROOFBUNDLE_GATE_DIR")}
    hints, calls, judged = gate._autonomy_checked(command, str(repo), time.monotonic() + 60, environ)
    assert hints is not None and all(kind in ("free", "external") for kind, _why in judged), judged
    for call in calls:
        if call["kind"] != "bash":
            continue
        text = gate._autonomy_text(call, shown=False)
        out = gate.decide(text, call["directory"] or str(repo), time.monotonic() + 60, "claude")
        answered = gate._autonomy_external(out, text, call["directory"] or str(repo), time.monotonic() + 60,
                                           environ) if out is not None and out.decision == "ask" else out
        assert answered is None or answered.decision in ("pass", "inactive", "handover", "ask"), text
        words = call["words"] if "words" in call else [w for stage in call["pipe"] for w in stage]
        if words[0] in ("git", "gh"):
            sub = [w for w in words[1:] if isinstance(w, str) and not w.startswith("-") and w != str(repo)][:1]
            sub = [] if sub == ["HEAD"] else sub
            assert all(w in command for w in sub), (sub, command)


def test_D85_a_rewrite_is_named_only_where_the_gate_frees_it(tmp_path, monkeypatch):
    """A rewrite whose call the gate does not free is no detour: `cd` into a repository whose read profile finds a
    pager keeps `git -C <path> status` asking, so the chain is blocked."""
    repo = d71._repo(tmp_path)
    d71._git(repo, "config", "core.pager", "less")
    answer, entry = _hook(repo, tmp_path, f"cd {repo} && git status")
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert entry["autonomy"]["klasse"] == "sperre", entry


@pytest.mark.parametrize("form, _first, _calls", DETOURS)
def test_D85_a_rewrite_holds_only_git_and_gh_calls_writes_and_data_steps(tmp_path, form, _first, _calls):
    """No call of a rewrite runs a program the gate does not judge as such: a carrier, an interpreter, a script a Write
    wrote, a step that writes."""
    repo = _on_topic(tmp_path)
    _hints, calls = gate._autonomy_rewrite(_form(form, repo), str(repo))
    for call in calls:
        if call["kind"] == "bash" and "words" in call and call["words"][0] not in ("git", "gh"):
            assert gate._ShStep(gate._sh_parse(gate._autonomy_text(call, shown=False)).items[0][0][0][0], None, True, 1,
                                []).kind == "data", call


@pytest.mark.parametrize("path, allowed", [("{R}/notes.md", True), ("{R}/docs/a.md", True), ("{T}/notes.md", True),
                                           ("{R}/.git/info/x", False), ("{R}/.github/x.yml", False),
                                           ("{T}/.bashrc", False), ("/etc/x", False), ("{H}/x.md", False)])
def test_D85_a_write_of_a_rewrite_goes_into_the_work_tree_or_the_temp_folder_to_no_hidden_file(tmp_path, monkeypatch,
                                                                                                path, allowed):
    repo = _on_topic(tmp_path)
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    import tempfile
    monkeypatch.setattr(tempfile, "tempdir", None)
    target = path.replace("{R}", str(repo)).replace("{T}", str(tmp_path)).replace("{H}", "/home/nobody")
    assert gate._autonomy_write_place(target, str(repo), time.monotonic() + 60) is allowed, target


def test_D85_a_chain_of_external_calls_only_keeps_the_ask_of_the_whole(tmp_path):
    """Splitting two external calls would ask twice for what one ask covered: the ask of the whole stays."""
    repo = _outside(tmp_path)
    answer, entry = _hook(repo, tmp_path, "gh pr comment 1 --body a && gh pr comment 2 --body b")
    assert answer["hookSpecificOutput"]["permissionDecision"] == "ask", answer
    assert entry["autonomy"]["klasse"] == "aussen"


@pytest.mark.parametrize("command, words", [
    ("git push origin $(git rev-parse --abbrev-ref HEAD)", ["git", "push", "origin", "HEAD"]),
    ("git push origin \"$(git symbolic-ref --short HEAD)\"", ["git", "push", "origin", "HEAD"]),
    ("echo $(git rev-parse --abbrev-ref HEAD)", ["echo", 1]),
    ("git log $(git branch --show-current)", ["git", "log", 1]),
])
def test_D85_the_branch_name_from_a_substitution_is_HEAD_only_in_a_push(command, words):
    _hints, calls = gate._autonomy_rewrite(command, "/r")
    assert calls[-1]["words"] == words, calls


def test_D85_the_rewrite_of_a_commit_message_matches_only_the_whole_form():
    assert gate._autonomy_rewrite(COMMIT, "/r")[0] == ["nachricht_als_datei"]
    assert gate._autonomy_rewrite(COMMIT + "; git push", "/r") is None
    assert gate._autonomy_rewrite(COMMIT.replace("cat <<", "tee x <<"), "/r") is None


@pytest.mark.parametrize("command", ["cd .. && ls && git status", "cd $D && git status", "cd /r && gh pr list",
                                     "X=1; git status", "git status 2>&1 | tee out.txt", "(git status)",
                                     "git $(echo status)", "git status | xargs echo"])
def test_D85_control_forms_the_rewrite_does_not_read_have_none(command):
    assert gate._autonomy_rewrite(command, "/r") is None, command


def test_D85_the_plugin_hook_of_claude_code_starts_the_gate_with_the_flag_and_codex_without():
    """The autonomous answer is what the plugin ships: every PreToolUse hook of hooks.json (Bash, the gated MCP tools,
    the file tools) starts the gate with the flag; the Codex manifest never does, and the Stop and TaskCompleted hooks
    take no flag."""
    plugin = pathlib.Path(gate.__file__).resolve().parent.parent
    claude = json.loads((plugin / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
    for group in claude["PreToolUse"]:
        # D102 (Nachtrag 33): the hook of Read and Grep starts the small script of the key paths, which hands a key path
        # to the gate with the same flag
        script = "proofbundle_secrets.py" if group["matcher"] == "^(Read|Grep)$" else "proofbundle_gate.py"
        assert group["hooks"][0]["command"].startswith(
            f'python3 -I "${{CLAUDE_PLUGIN_ROOT}}/hooks/{script}" --autonomous ||'), group
    for event in ("Stop", "TaskCompleted"):
        assert gate.AUTONOMOUS_FLAG not in json.dumps(claude[event])
    codex = (plugin / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
    assert gate.AUTONOMOUS_FLAG not in codex and "--host codex" in codex


def test_D85_without_the_flag_the_hook_answers_as_decide_judges(tmp_path):
    """Started without the flag, as every test before Nachtrag 35 starts it, the gate asks as decide() asks."""
    repo = d71._repo(tmp_path)
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo), "session_id": "s",
             "tool_input": {"command": "git reset --hard HEAD~1"}}
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                      "PROOFBUNDLE_GATE_DIR")}
    env["CLAUDE_PLUGIN_DATA"] = str(tmp_path / "data")
    proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__], json.dumps(event), env, cwd=str(repo))
    answer = ga.parsed(proc, entry)
    assert answer["hookSpecificOutput"]["permissionDecision"] == "ask" and "autonomy" not in entry


def test_D85_the_closed_list_of_external_effects():
    # changed in Nachtrag 37 (D91): a local form that starts a program of the clone keeps the ask (owner question O37-1);
    # in Nachtrag 33 (D103): a file or data sent to a host outside keeps the ask
    assert set(gate.AUTONOMY_EFFECTS) - {"programm", "upload"} == {"push", "push_delete", "tag", "release", "merge",
                                                                   "pr", "settings", "gh_write", "done_order"}
    assert gate._autonomy_effect(shlex.split("git -C /r push origin x")) == "push"
    assert gate._autonomy_effect(shlex.split("git tag -l")) is None
    assert gate._autonomy_effect(shlex.split("gh api repos/a/b")) is None
    assert gate._autonomy_effect(shlex.split("gh api repos/a/b -f x=1")) == "gh_write"
    assert gate._autonomy_effect(shlex.split("gh api -X GET repos/a/b -f x=1")) is None
    assert gate._autonomy_effect(shlex.split("gh pr view 1")) is None
