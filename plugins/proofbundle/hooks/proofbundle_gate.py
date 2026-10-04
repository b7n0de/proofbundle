"""Pre-tool gate of the proofbundle plugin.

Before a shell call that pushes (`git push`), opens a pull request (`gh pr create`) or creates a
release (`gh release create`), and before an MCP tool that opens a pull request, a merge request or a
release, pushes files, writes a file or merges a pull request, the gate verifies the evidence the
repository declares, with the plugin's own MCP server, and answers the host in its hook format. A
`git push` is judged at every commit it newly sends to each target it can resolve (DECISIONS.md, D3);
a `gh` call and an MCP tool, whose remote target the gate cannot read, are judged at HEAD:

- every declared item verifies: the gate makes no permission decision, so the host's normal
  permission flow applies, and a message names what was verified; the gate never grants a call;
- a declared item fails, is missing, or the declaration cannot be read: deny, with the reason;
- the gate measured that the repository has no declaration, neither at HEAD nor in the working tree:
  NOT MEASURED, and no permission decision under either host, because the gate is not active in a
  repository that declares nothing (DECISIONS.md, D5);
- any other case where nothing was verified (a declaration only in the working tree, an empty list, no
  repository or no commit, or a repository the gate cannot tell): NOT MEASURED, and the host asks the
  user; a host without an ask (Codex) gets deny instead.

The gate reads the declaration and the evidence from the commit at HEAD, not from the working tree, so
an uncommitted file can neither satisfy nor break it. The declaration lives at DECLARATION and is
described in DECISIONS.md next to this file's plugin.

Every declared item names its subject: the proofbundle-tree-sha256/v1 digest of the tree at HEAD without
the .proofbundle/ folder (see tree_manifest). The subject must stand in the declaration and inside the
signed evidence, and both must equal the digest the gate computes; otherwise the call is denied.

Usage as a hook: proofbundle_gate.py [--host claude|codex]. stdin: the host's PreToolUse event (JSON).
stdout: one JSON answer, or nothing for a call the gate does not gate. The exit code is always 0; a
failure inside the gate is answered as deny.

Usage for a producer: proofbundle_gate.py tree-digest [--repo DIR] [--rev REV] [--statement] prints the
tree digest of REV (default HEAD), or with --statement the JSON a bundle signs to name it.

Usage in CI: proofbundle_gate.py ci-check --repo DIR --require-declaration true|false prints one JSON
report and exits 0 (verified, or nothing declared where none is required), 1 (everything else) or 2 (a
wrong call); see DECISIONS.md, D22.

Usage for a test run: proofbundle_gate.py run-evidence --repo DIR --out FILE [--timeout SECONDS] -- COMMAND...
runs a pytest command on the clean working tree of HEAD and writes the unsigned statement of a green run
that left the tree as it was; see DECISIONS.md, D23. Standard library only, so the gate itself needs no
package.
"""
from __future__ import annotations

import base64
import binascii
import collections
import hashlib
import json
import os
import pathlib
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time

EVIDENCE_DIR = ".proofbundle/"
DECLARATION = EVIDENCE_DIR + "evidence.json"
DECLARATION_SCHEMA = "proofbundle-plugin/evidence/v0.2"
MAX_DECLARATION_BYTES = 64 * 1024
MAX_ITEMS = 32
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
#: Evidence kinds a declaration may name. An outcome receipt is not among them: it has no field that
#: can carry a tree subject (DECISIONS.md, D16).
KINDS = ("bundle", "decision")
ITEM_KEYS = frozenset({"kind", "path", "public_key", "policy", "subject"})
SUBJECT_KEYS = frozenset({"algorithm", "digest"})
#: The tree digest every item is bound to (DECISIONS.md, D2).
TREE_ALGORITHM = "proofbundle-tree-sha256/v1"
TREE_HEADER = (TREE_ALGORITHM + "\n").encode()
TREE_MODES = frozenset({b"100644", b"100755", b"120000"})
#: The inputSnapshot uri under which a decision receipt names its tree subject.
TREE_SUBJECT_URI = "urn:proofbundle-plugin:subject:" + TREE_ALGORITHM
_HEX64 = re.compile(r"[0-9a-f]{64}")
#: MCP tools, by the last segment of their name, that open a pull request, a merge request or a release,
#: push files, write a file or merge a pull request (DECISIONS.md, D8). Any other MCP tool gets no answer
#: from the gate.
MCP_GATED_TOOLS = ("create_pull_request", "create_merge_request", "create_release",
                   "push_files", "create_or_update_file", "merge_pull_request")
#: What the gate cannot see for each gated MCP tool. It judges the local repository at HEAD, and the tool
#: acts on a remote: the branch it publishes, the pull request it merges, or bytes from its own arguments.
_MCP_UNSEEN = {
    "push_files": "the bytes the tool writes come from its own arguments, and the gate does not compare "
                  "them with that tree",
    "create_or_update_file": "the bytes the tool writes come from its own arguments, and the gate does not "
                             "compare them with that tree",
    "merge_pull_request": "it cannot see the pull request the tool merges",
}
MCP_MATCHER = "^mcp__.+__(" + "|".join(MCP_GATED_TOOLS) + ")$"
#: Seconds for the whole gate. The hook timeout in the plugin manifests is 120 s; the gate answers deny
#: well before it, because a host that times a hook out may let the call run.
DEADLINE_SECONDS = 90.0
MAX_NESTING = 4
#: The hosts the gate answers. Claude Code has an "ask" decision; Codex has none. Codex's PreToolUse
#: parser marks an "ask" answer as a failed hook and lets the call run (openai/codex
#: codex-rs/hooks/src/engine/output_parser.rs and events/pre_tool_use.rs), so for Codex the gate turns
#: every NOT MEASURED ask into a deny. The one NOT MEASURED case that is no ask, a repository the gate
#: measured to declare nothing, carries no decision under either host (D5, D12).
HOSTS = ("claude", "codex")

SERVER = pathlib.Path(__file__).resolve().parent.parent / "server" / "proofbundle_mcp.py"
#: The plugin's version, the one of every manifest; a test holds them equal.
GATE_VERSION = "0.3.0"
#: The local log of every gate call (DECISIONS.md, D21): one JSON line each, in the first named plugin data
#: directory the host gives the hook that is a writable directory. Measured: Claude Code 2.1.285 gives a
#: PreToolUse hook CLAUDE_PLUGIN_DATA; Codex 0.159.2 gives PLUGIN_DATA and CLAUDE_PLUGIN_DATA
#: (codex-rs/hooks/src/engine/discovery.rs, lines 262 to 270, read in the source, not in a run).
LOG_NAME = "gate-log.jsonl"
LOG_DIR_VARIABLES = {"claude": ("CLAUDE_PLUGIN_DATA",), "codex": ("PLUGIN_DATA", "CLAUDE_PLUGIN_DATA")}
MAX_LOG_BYTES = 1024 * 1024

_GH_OPTIONS_WITH_VALUE = frozenset({"-R", "--repo"})
_GH_GATED = frozenset({("pr", "create"), ("pr", "new"), ("release", "create"), ("release", "new")})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
#: A redirection operator at a token start, with an optional leading file-descriptor number. `<<` and
#: `<<<` (here-document, here-string) match too; the caller treats them as unknown-forcing. Every other
#: redirection and its target word are consumed and dropped, so they never become words of a call
#: (`git push origin main 2>&1` keeps only `origin main`; review Nachtrag 12).
_REDIR = re.compile(r"&>>|&>|<<<|<<|\d*(?:>>|>&|>\||<>|<&|>|<)")
#: Used only when the command cannot be tokenised: any mention of a gated call counts as one. Since review Runde 9
#: every git form is gated, so the word `git` alone counts (`git-push` included); the push-only search let an
#: unparsable `git config` or `git commit` through ungated (review Runde 10, R10-1).
_FALLBACK = re.compile(r"\bgit\b|\bgh\b.*\b(?:pr|release)\b.*\b(?:create|new)\b", re.DOTALL)
#: Plain text for _drop_comments: words without a quote, an escape, an expansion, a substitution, a glob, a bracket or
#: a brace, blanks, newlines, and the control and redirection operators (a here-document excepted).
_PLAIN = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./:=@%+,~^-;&|<> \t\n")
#: The characters after which a `#` begins a word in plain text.
_WORD_BREAK = frozenset(";&|<> \t\n")
UNKNOWN = None

#: `git push` options the gate models as target-neutral: they change neither the endpoint, the refs nor
#: the commits a push sends. Every other option — an abbreviation (git takes --mir for --mirror), a
#: target option (--all, --mirror, --tags, --delete, --repo), or anything unknown — makes the target NOT
#: MEASURED, so the gate never resolves a push it does not fully model (review R3-1).
_PUSH_FLAGS_NEUTRAL = frozenset({
    "-f", "--force", "--no-force", "-u", "--set-upstream", "-q", "--quiet", "-v", "--verbose",
    "--progress", "--no-progress", "--porcelain", "-n", "--dry-run", "--no-dry-run",
    "--no-verify", "--verify", "--atomic", "--no-atomic", "--thin", "--no-thin",
    "-4", "--ipv4", "-6", "--ipv6", "--force-with-lease", "--no-force-with-lease",
    "--force-if-includes", "--no-force-if-includes", "--signed", "--no-signed",
})
#: Target-neutral options taking a value as `--opt value` (or the short `-o value`). `--receive-pack` and its
#: alias `--exec` are deliberately absent: they name the program that runs as the receiving end, which a
#: local (path or file://) transport starts on this machine, so the option selects a helper program and the
#: push is NOT MEASURED (review Runde 6, R6-2 class).
_PUSH_OPTS_NEUTRAL_VALUE = frozenset({"-o", "--push-option"})
#: Target-neutral options accepted in the inline `--opt=value` form.
_PUSH_OPTS_NEUTRAL_INLINE = frozenset({"--push-option", "--force-with-lease", "--signed"})
class GateError(Exception):
    """The gate cannot reach a verdict. Answered as deny."""


# --- which calls are gated, and in which directory ---------------------------------------------------

def _consume_subst(s: str, i: int) -> int | None:
    """From a `$` at index `i`, the index just past the substitution it begins (`$(...)`, `${...}` or
    `$name`), or None when the form is one the lexer does not model and the whole command must fall back to
    the text search (review Runde 11, R11-1): a `$(` or `${` that never closes, and `$'…'`/`$"…"`, whose
    quoting differs from the lexer's own `'`/`"`. A `$` that begins no substitution at all — a `$` before a
    space, an operator, a newline or the end of the text — consumes only the dollar, so the next character
    keeps its meaning (`$` then a newline leaves the newline a separator, R11-1 case 1)."""
    n = len(s)
    if i + 1 >= n:
        return i + 1
    c = s[i + 1]
    if c == "(":
        # Track quotes so a `)` inside '…' or "…" does not close the substitution (R11-1 case 3).
        depth, j, quote = 0, i + 1, None
        while j < n:
            ch = s[j]
            if quote is not None:
                if ch == quote:
                    quote = None
            elif ch in "'\"":
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        return None
    if c in "'\"":
        return None  # $'…' / $"…": an unmodelled quote form; fall back to the text search (R11-1 case 2)
    if c == "{":
        j = s.find("}", i + 2)
        return j + 1 if j >= 0 else None
    j = i + 1
    if s[j].isalpha() or s[j] == "_":
        j += 1
        while j < n and (s[j].isalnum() or s[j] == "_"):
            j += 1
        return j
    return i + 1  # a bare `$` that starts no name or substitution: consume only the dollar (R11-1 case 1)


def _drop_comments(command: str) -> str:
    """The command without its shell comments (review Runde 10, R10-1). A `#` that begins a word starts a comment
    that runs to the end of its line (sh, bash, dash and zsh; measured for bash 5.2 and dash): the shell runs the
    command before it as if the comment were absent, so a comment adds no word, and an apostrophe in it does not
    make the command unparsable. A comment is dropped only while every character before it, outside the comments
    already dropped, is plain text (_PLAIN, no `<<`), where the gate's words are the shell's. From the first other
    character on — a quote, an escape, a `$`, a backtick, a glob, a bracket, a brace or a here-document — the rest is
    kept as it is: there a `#` after a blank may sit in a string, a here-document or an arithmetic command the shell
    runs, and the gate does not model where. A command that is then unparsable falls back to the text search."""
    kept, i, start, n = [], 0, 0, len(command)
    while i < n:
        c = command[i]
        if c == "#" and (i == 0 or command[i - 1] in _WORD_BREAK):
            kept.append(command[start:i])
            end = command.find("\n", i)
            i = start = n if end < 0 else end
            continue
        if c not in _PLAIN or command.startswith("<<", i):
            break
        i += 1
    kept.append(command[start:])
    return "".join(kept)


def _lex(command: str) -> list | None:
    """Scan a shell command into tokens for the closed grammar, or None if a quote or `$(`/`${` is not
    closed (the caller then falls back to the over-matching regex). A token is ('op', <operator>) for a
    control operator (';', '&&', '||', '|', '&', '(', ')', '{', '}', '<<') or ('word', <value>, <has_subst>,
    <raw>), where <value> is the word with its quotes removed, <has_subst> says whether an unquoted or
    double-quoted parameter or command substitution appeared in it, and <raw> is the original slice. A
    newline is a ';'. Output redirections are consumed with their target and dropped; a here-document or
    here-string is reported as '<<'. A bare `{` or `}` word is reported as that operator."""
    s = command
    i, n = 0, len(s)
    toks: list = []
    drop_target = False  # the next word is the target of a redirection just read, and is dropped
    while i < n:
        c = s[i]
        if c in " \t":
            i += 1
            continue
        if c == "\n":
            toks.append(("op", ";")); i += 1; continue
        if s.startswith("&&", i):
            toks.append(("op", "&&")); i += 2; continue
        if s.startswith("||", i):
            toks.append(("op", "||")); i += 2; continue
        if s.startswith(";;", i):
            toks.append(("op", ";")); i += 2; continue
        m = _REDIR.match(s, i)
        if m:
            i = m.end()
            if m.group().startswith("<<"):
                toks.append(("op", "<<"))  # here-document / here-string: unknown-forcing
            else:
                drop_target = True
            continue
        if c in ";|&":
            toks.append(("op", c)); i += 1; continue
        if c in "()":
            toks.append(("op", c)); i += 1; continue
        start = i
        buf: list = []
        has_subst = False
        while i < n:
            c = s[i]
            if c in " \t\n" or c in ";&|()<>":
                break
            if c == "'":
                j = s.find("'", i + 1)
                if j < 0:
                    return None
                buf.append(s[i + 1:j]); i = j + 1; continue
            if c == '"':
                i += 1
                while i < n and s[i] != '"':
                    d = s[i]
                    if d == "\\" and i + 1 < n and s[i + 1] in '"\\$`':
                        buf.append(s[i + 1]); i += 2; continue
                    if d == "$":
                        has_subst = True
                        e = _consume_subst(s, i)
                        if e is None:
                            return None
                        buf.append(s[i:e]); i = e; continue
                    if d == "`":
                        j = s.find("`", i + 1)
                        if j < 0:
                            return None
                        has_subst = True; buf.append(s[i:j + 1]); i = j + 1; continue
                    buf.append(d); i += 1
                if i >= n:
                    return None
                i += 1; continue
            if c == "\\":
                if i + 1 < n:
                    if s[i + 1] != "\n":
                        buf.append(s[i + 1])
                    i += 2
                else:
                    i += 1
                continue
            if c == "$":
                has_subst = True
                e = _consume_subst(s, i)
                if e is None:
                    return None
                buf.append(s[i:e]); i = e; continue
            if c == "`":
                j = s.find("`", i + 1)
                if j < 0:
                    return None
                has_subst = True; buf.append(s[i:j + 1]); i = j + 1; continue
            buf.append(c); i += 1
        raw = s[start:i]
        if raw in ("{", "}"):
            toks.append(("op", raw))
        elif drop_target:
            drop_target = False
        else:
            toks.append(("word", "".join(buf), has_subst, raw))
    return toks


#: A detail marker (first element): the command would turn off the real-push check — `git push --no-verify`,
#: a command-level `core.hooksPath` override, or a `git config core.hooksPath` — so the gate denies it rather
#: than let an unchecked push through (review Nachtrag 15, Ebene 1, Punkt 5).
_HOOKS_DISABLE = "\x00hooks-disabled"
#: Detail marker for a git command Ebene 1 recognises as a possible object transfer to a remote but does
#: not model (an unknown subcommand, `send-pack`, a per-command `-c alias.*`, a `rebase --exec`, …). It is
#: never resolved and never inactive; the judge reports it NOT MEASURED (review Runde 5, Punkt 6/7/8).
_MAYBE_PUSH = "\x00maybe-push"
#: Detail marker for a git form that acts on a repository and is not a push the gate resolves: it is never free
#: (owner choice B of 2026-10-03, review Runde 9). It asks under Claude Code and is denied under Codex.
_NOT_FREE = "\x00not-free"
#: Detail marker for the safety net (review Runde 11, owner choice A of 2026-10-04): the raw command names git
#: or gh as a command word that the structured scan reached no decision for. It is never free and never a push
#: the gate resolves; it asks under Claude Code and is denied under Codex.
_NET = "\x00net"
#: git global options (before the subcommand) that take their value as the next word.
_GIT_GLOBAL_VALUE = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path",
                               "--config-env", "--super-prefix"})

#: The git subcommands Ebene 1 names as acting on the local repository. Until review Runde 9 this was the list
#: of forms Ebene 1 could leave free; since the owner's choice B of 2026-10-03 none of them is free in any form,
#: and the list only chooses the wording of the NOT MEASURED answer (_NOT_FREE instead of a possible transfer,
#: _MAYBE_PUSH). The entries that left it in Nachtrag 19b and review Runde 7 (`fetch`, `ls-remote`, `init`, the
#: exec-capable rebase, bisect and submodule, and the 43 named in DECISIONS.md D3) get the _MAYBE_PUSH answer.
_GIT_LOCAL_SUBCOMMANDS = frozenset({
    "add", "annotate", "blame", "branch", "cat-file", "check-attr", "check-ignore", "check-mailmap",
    "check-ref-format", "checkout", "cherry", "commit", "config", "count-objects", "describe", "diff",
    "diff-files", "diff-index", "diff-tree", "for-each-ref", "grep", "log", "ls-files",
    "ls-tree", "merge-base", "mv", "name-rev", "reset", "restore", "rev-list", "rev-parse", "rm",
    "shortlog", "show", "show-branch", "show-ref", "stash", "status", "switch", "symbolic-ref", "tag", "var",
    "whatchanged",
})
#: THE FREE LIST IS GONE (owner choice B of 2026-10-03, review Runde 9). Until then Ebene 1 left an allow-listed
#: form free when every option word was vetted inert for its entry and the bound repository's effective
#: configuration and hooks held no key or hook of the entry's profile (Nachtrag 19b). Rounds 7, 8 and 9 each found
#: git starting a program through configuration, a configured value or an indirect path that list did not know
#: (numeric booleans, empty driver names, automatic maintenance). The vetted options, the signature markers, the
#: per-entry profiles, the key and environment families and the repository-state check are removed, not patched.
#: The former free list for local git commands has been removed. Those forms ask under Claude Code and are denied
#: under Codex; a literal `-C` does not change that decision. Only the exact bare command text `git --version` is
#: exempt. The separate push path remains: under Claude Code it may return `pass` or `inactive` after its checks;
#: under Codex every push is denied because its execution context is unbound (review Runde 11, R11-5). The two
#: readers below remain for the write gate.


def _config_entries(directory: str, deadline: float) -> tuple[list | None, str]:
    """The effective configuration as git itself reads it in directory, with the hook's environment:
    (scope, origin, key, value) per entry, value None for a key without '='. None when git cannot read it
    (an unreadable or malformed file, an include it cannot open: measured, `git config --list` exits 128)."""
    out = _git(directory, "config", "--list", "--null", "--show-origin", "--show-scope", deadline=deadline)
    if out.returncode != 0:
        why = out.stderr.decode("utf-8", "replace").strip().splitlines()
        return None, (why[-1] if why else f"git config exited {out.returncode}")
    parts = out.stdout.split(b"\0")
    if parts[-1] != b"" or (len(parts) - 1) % 3:
        return None, "git config --list --null --show-origin --show-scope gave output the gate cannot read"
    entries = []
    for i in range(0, len(parts) - 1, 3):
        scope, origin, kv = (x.decode("utf-8", "replace") for x in parts[i:i + 3])
        key, nl, value = kv.partition("\n")
        entries.append((scope, origin, key, value if nl else None))
    return entries, ""


def _repo_paths(directory: str, deadline: float) -> tuple[dict | None, str]:
    """{'hooks', 'common', 'gitdir', 'toplevel'} of the repository at directory (all None outside one)."""
    out = _git(directory, "rev-parse", "--path-format=absolute", "--git-common-dir", "--git-dir",
               "--git-path", "hooks", deadline=deadline)
    if out.returncode != 0:
        if b"not a git repository" in out.stderr:
            return {"hooks": None, "common": None, "gitdir": None, "toplevel": None}, ""
        return None, out.stderr.decode("utf-8", "replace").strip() or f"git rev-parse exited {out.returncode}"
    lines = out.stdout.decode("utf-8", "replace").splitlines()
    if len(lines) != 3:
        return None, "git rev-parse gave output the gate cannot read"
    common, gitdir, hooks = lines
    top = _git(directory, "rev-parse", "--path-format=absolute", "--show-toplevel", deadline=deadline)
    toplevel = top.stdout.decode("utf-8", "replace").strip() if top.returncode == 0 else None
    return {"hooks": hooks, "common": common, "gitdir": gitdir, "toplevel": toplevel}, ""


def _expansion_present(command: str) -> bool:
    """Whether the command carries a parameter or command expansion outside single quotes (`$`, `${…}`,
    `$(…)`, or a backtick). Such an expansion runs before the words are final, so the command is not the one
    strict simple command the gate resolves, and it is NOT MEASURED (review R4-3, R4-4)."""
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if c == "'":
            j = command.find("'", i + 1)
            if j < 0:
                return False
            i = j + 1
        elif c == "\\":
            i += 2
        elif c in "$`":
            return True
        else:
            i += 1
    return False


def _hooks_off(key: str) -> bool:
    """Whether a git config key is `core.hooksPath` (any case), which would redirect or disable the hook."""
    return key.strip().lower() == "core.hookspath"


#: The default of _strict_git's free_base: the call is the whole command, headed by a bare `git` (from
#: _resolve_single). Anything else passes UNKNOWN: a program path, a wrapper, a nested shell, a chain, a
#: pipeline, a background job, a substitution or a later run of a chain (review Runde 7, R7-4; Runde 8, R8-5).
#: Only `git --version` reads it since the free list is gone (review Runde 9).
_FROM_DIRECTORY = object()

#: The whole command text of the one free form (review Runde 9, owner choice B): the bare `git --version`, with
#: nothing before or after it. The lexer drops redirections and quotes, so the word check of _strict_git alone
#: would also free `git --version > <file>`, `"git" --version` or a neutral prefix assignment; the free form is
#: held to its text as well. Any other spelling asks.
_BARE_VERSION = re.compile(r"[ \t]*git[ \t]+--version[ \t]*")


def _strict_git(words: list[str], directory: str | None,
                free_base: object = _FROM_DIRECTORY) -> tuple[str, str | None, list[str] | None] | None:
    """Parse one strict `git …` simple command (the words after a bare `git`). Returns the gated call, or None
    only for the bare `git --version` that is the whole command (free_base _FROM_DIRECTORY): since review Runde 9
    (owner choice B) no other git form is free, and every form that acts on a repository is NOT MEASURED
    (`_NOT_FREE`, asked under Claude Code, denied under Codex). A `push` resolves its target as before:
    at most one literal `-C` is joined onto the directory (not normalised, so the judge resolves it
    physically through symlinks, R4-2); more than one `-C`, or any other global option (`-c`, `--git-dir`,
    `--work-tree`, `--namespace`, `--exec-path`, `--no-pager`, …), makes the push NOT MEASURED (R4-6).
    `--no-verify`, a `-c core.hooksPath` override, or a `git config core.hooksPath` denies (Punkt 5). A
    subcommand that is not a local one (`_GIT_LOCAL_SUBCOMMANDS`) — an unknown word, `send-pack`, `rebase
    --exec`, `bisect run`, `submodule foreach` — is NOT MEASURED as a possible transfer (`_MAYBE_PUSH`), and a
    per-command `-c alias.*` makes a local subcommand a possible transfer too, because the alias may name any
    command the gate does not see (review Runde 5, Punkt 6/7/8). Its arguments are never read with the push parser."""
    i, c_count, not_measured, deny, alias_config = 0, 0, False, False, False
    start, c_values = directory, []
    while i < len(words) and words[i].startswith("-"):
        option, eq, inline = words[i].partition("=")
        has_value = option in _GIT_GLOBAL_VALUE
        value = inline if eq else (words[i + 1] if has_value and i + 1 < len(words) else "")
        if option == "-C" and value and "$" not in value:
            c_count += 1
            c_values.append(os.path.expanduser(value))
            directory = (os.path.join(directory, os.path.expanduser(value))
                         if directory is not UNKNOWN else UNKNOWN)
        elif option in ("-c", "--config-env"):
            key = value.partition("=")[0].strip()
            if _hooks_off(key):
                deny = True
            if key.lower().startswith("alias."):
                alias_config = True  # a per-command alias may name any command, push included (Punkt 7)
            not_measured = True  # any per-command config is a global option the strict form does not model
        else:
            not_measured = True  # --git-dir, --work-tree, --namespace, --exec-path, --no-pager, a 2nd -C, …
        i += 2 if (has_value and not eq) else 1
    if i < len(words) and words[i] == "config" and any(_hooks_off(w) for w in words[i + 1:]):
        return "git config core.hooksPath", directory, [_HOOKS_DISABLE]
    if deny:  # a `-c core.hooksPath=…` override would turn the hook off, whatever the subcommand is (Punkt 5)
        return "git push", directory, [_HOOKS_DISABLE]
    sub = words[i] if i < len(words) else None
    args = words[i + 1:]
    if sub == "push":
        if "--no-verify" in args:
            return "git push", directory, [_HOOKS_DISABLE]
        if c_count > 1:
            not_measured = True
        if not_measured:
            return "git push", UNKNOWN, None
        return "git push", directory, args
    if alias_config:  # NOT MEASURED even without the word push, so a `-c alias.*` cannot slip through (Punkt 7)
        return (f"git {sub}" if sub else "git"), UNKNOWN, [_MAYBE_PUSH]
    if sub is None:
        # Only `git --version` as the whole command, headed by a bare `git`, stays free: it reads no repository.
        # Through a program path, a wrapper, a nested shell, a chain, a substitution or after another command the
        # word may name another program (review Runde 8, R8-5), and every other option-only form (`git`,
        # `git --help`, `git -c …`) asks (review Runde 9, owner choice B).
        if words == ["--version"] and free_base is _FROM_DIRECTORY and start is not UNKNOWN:
            return None
        return ("git --version" if words == ["--version"] else "git"), UNKNOWN, [_NOT_FREE]
    if sub in _GIT_LOCAL_SUBCOMMANDS:
        # No free form (review Runde 9, owner choice B): options, configuration, configured values, hooks and
        # indirect paths can make git start a program the gate does not see.
        return f"git {sub}", UNKNOWN, [_NOT_FREE]
    # unknown subcommand, send-pack, any unmodelled transport, and the entries that left the list (S1, A)
    return f"git {sub}", UNKNOWN, [_MAYBE_PUSH]


def _gh_call(words: list[str]) -> str | None:
    positional, i = [], 0
    while i < len(words) and len(positional) < 2:
        word = words[i]
        if word in _GH_OPTIONS_WITH_VALUE:
            i += 2
            continue
        if not word.startswith("-"):
            positional.append(word)
        i += 1
    if tuple(positional) in _GH_GATED:
        return f"gh {positional[0]} {positional[1]}"
    return None


#: Environment names a prefix assignment (or an `env NAME=value` carrier) may set and still leave the
#: repository and push target resolvable. Every other name, GIT_* or not — `PATH` included — makes the
#: directory NOT MEASURED, so the gate judges no repository rather than the wrong one (review Nachtrag 11,
#: Nachtrag 12).
#: Prefix assignments vetted inert: they select no helper, filter, hook, editor, pager or transport program
#: and touch neither the repository nor the configuration.
_INERT_ASSIGN = frozenset({"GIT_TERMINAL_PROMPT", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "TZ"})
#: Assignments that select a program (a pager, an editor, an askpass helper) are inert only with a vetted
#: value: the environment is configuration by another name (GIT_EXTERNAL_DIFF is diff.external, GIT_PAGER is
#: core.pager), so any other value, and any other name, makes the call NOT MEASURED (review Runde 6, R6-2).
_PROGRAM_ASSIGN_VETTED = {
    "GIT_PAGER": frozenset({"cat", ""}), "PAGER": frozenset({"cat", ""}),
    "GIT_EDITOR": frozenset({"true", ":"}), "EDITOR": frozenset({"true", ":"}), "VISUAL": frozenset({"true", ":"}),
    "GIT_SEQUENCE_EDITOR": frozenset({"true", ":"}),
    "GIT_ASKPASS": frozenset({"true", ":"}), "SSH_ASKPASS": frozenset({"true", ":"}),
}
#: Names whose command-level assignment sets the git configuration the gate's separate reads never see, so
#: the push is NOT MEASURED through the configuration sentinel. The gate's reads inherit only the host
#: process's own environment, never a configuration assigned in the command (review Nachtrag 11, Befund 2).
_CONFIG_ASSIGN = frozenset({"HOME", "XDG_CONFIG_HOME"})
def _assign_class(name: str, value: str | None = None) -> str:
    """How a command-level assignment `name=value` bears on a git call: 'config' (the git configuration the
    gate's reads never see), 'neutral' (vetted inert: it selects no program and touches neither the
    repository nor the configuration), or 'other' (everything else, which makes the call NOT MEASURED). A
    program-selecting name is neutral only with a vetted value (_PROGRAM_ASSIGN_VETTED); value None means the
    value is unknown, which is never vetted."""
    if name in _CONFIG_ASSIGN or name.startswith("GIT_CONFIG"):
        return "config"
    if name in _INERT_ASSIGN or name.startswith("GIT_TRACE"):
        return "neutral"
    if name in _PROGRAM_ASSIGN_VETTED and value is not None and value in _PROGRAM_ASSIGN_VETTED[name]:
        return "neutral"
    return "other"


def _assignment_neutral(word: str) -> bool:
    name, _, value = word.partition("=")
    return _assign_class(name, value) == "neutral"


def _subst_bodies(raw: str) -> list[str]:
    """The command bodies inside a word's command substitutions (`$(...)`, `` `...` ``); single quotes
    suppress substitution, and `$((...))` arithmetic is not a command body."""
    bodies, i, n = [], 0, len(raw)
    while i < n:
        c = raw[i]
        if c == "'":
            j = raw.find("'", i + 1)
            if j < 0:
                break
            i = j + 1; continue
        if c == "`":
            j = raw.find("`", i + 1)
            if j < 0:
                break
            bodies.append(raw[i + 1:j]); i = j + 1; continue
        if c == "$" and i + 1 < n and raw[i + 1] == "(":
            depth, j, quote = 0, i + 1, None
            while j < n:  # track quotes so a `)` inside '…'/"…" does not close the body (R11-1 case 3)
                ch = raw[j]
                if quote is not None:
                    if ch == quote:
                        quote = None
                elif ch in "'\"":
                    quote = ch
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if j >= n:
                break
            if not raw[i + 2:j].startswith("("):  # not $(( )) arithmetic
                bodies.append(raw[i + 2:j])
            i = j + 1; continue
        i += 1
    return bodies


def _resolve_single(words: list[tuple], directory: str | None,
                    inherited_env: bool = False) -> list[tuple[str, str | None, list[str] | None]] | None:
    """One strict simple command (word tokens (value, has_subst, raw)). Returns the gated call list, or []
    when the command is not one the gate gates. The repository and target resolve only when `git`/`gh` is
    the bare command word and every prefix assignment is from the neutral list; a path invocation or any
    non-neutral assignment leaves the call NOT MEASURED. A `--no-verify`/`core.hooksPath` form denies
    regardless (review Nachtrag 15, Ebene 1)."""
    i, neutral_only = 0, not inherited_env
    while i < len(words) and _ASSIGNMENT.match(words[i][0]):
        if not _assignment_neutral(words[i][0]):
            neutral_only = False
        i += 1
    if i >= len(words):
        return []
    head = words[i][0]
    base = os.path.basename(head)
    rest = [w[0] for w in words[i + 1:]]
    if base not in ("git", "git-push", "gh"):
        return []
    bare = head == base
    if base == "gh":
        name = _gh_call(rest)
        if name is None:
            return []
        return [(name, directory if (bare and neutral_only) else UNKNOWN, None)]
    # A program path (`./git`, `/opt/x/git`) names a program the gate does not know, so even `git --version` there
    # is NOT MEASURED (review Runde 7, R7-4; Runde 8, R8-5).
    call = (("git push", directory, rest) if base == "git-push"
            else _strict_git(rest, directory, free_base=_FROM_DIRECTORY if bare else UNKNOWN))
    if call is None:
        # The free `git --version` is free only without an unvetted prefix assignment: the environment selects
        # programs as configuration does (review Runde 6, R6-2 class), so it is NOT MEASURED.
        return [] if neutral_only else [("git --version", UNKNOWN, [_NOT_FREE])]
    name, cdir, detail = call
    if detail in ([_HOOKS_DISABLE], [_NOT_FREE]):
        return [call]  # a hook-disabling form denies and a repository form asks, whatever the context
    if not (bare and neutral_only):
        return [(name, UNKNOWN, None)]
    return [call]


#: Commands whose string argument is executed as a command, so the gate scans inside it for a gated call.
_SHELL_DASH_C = frozenset({"bash", "sh", "dash", "zsh", "ksh"})
_STRING_EXECUTORS = frozenset({"eval", "source", "."})


def _shell_c_arg(args: list[str]) -> str | None:
    """The command string a shell runs via `-c`, or None. A short-flag bundle that carries `c` — `-c`,
    `-lc`, `-cl`, `-ilc`, in any order — puts the shell in command mode, exactly as `bash`/`sh` run it;
    the command string is then the first following word that is not itself an option. A `--` is skipped.
    The gate must see the string whichever bundle introduces it, or `bash -lc "git push"` (the Codex host's
    own form) would slip past as an unchecked push (review R4-1, the bypass probes)."""
    c_at = next((i for i, w in enumerate(args)
                 if w.startswith("-") and not w.startswith("--") and w != "-" and "c" in w[1:]), None)
    if c_at is None:
        return None
    for w in args[c_at + 1:]:
        if w == "--" or (w.startswith("-") and w != "-"):
            continue
        return w
    return None


def _git_label(words: list[str]) -> str:
    """`git <subcommand>` for a message, skipping global options and their values (as _strict_git does)."""
    i = 0
    while i < len(words) and words[i].startswith("-"):
        option, eq, _ = words[i].partition("=")
        i += 2 if (option in _GIT_GLOBAL_VALUE and not eq) else 1
    return f"git {words[i]}" if i < len(words) else "git"


def _scan_run(words: list[tuple], emit, depth: int, env_set: bool = False) -> None:
    """Report every gated call a single run of words (between control operators) executes, each NOT
    MEASURED. A `git`/`git-push`/`gh` word anywhere in the run (so after a wrapper such as `env`, `sudo`,
    `command`, `nice`, `timeout`) counts; a shell executor word anywhere (`bash`/`sh`/`dash`/`zsh`/`ksh`,
    by basename, so a path form too) has its `-c` command string scanned in turn, and `eval`/`source`/`.`
    have their string arguments scanned. The scan is an over-approximation on purpose: it never misses a
    nested push, including through a wrapper or a `-lc`/`-cl` bundle (review R4-1, the bypass probes), at
    the cost of a rare harmless ask. No git form here is free, `git --version` included: it is not the whole
    command (review Runde 7, R7-4; Runde 9, owner choice B)."""
    for k, (value, _has, _raw) in enumerate(words):
        base = os.path.basename(value)
        rest = [w[0] for w in words[k + 1:]]
        if base == "git":
            emit([_strict_git(rest, UNKNOWN, free_base=UNKNOWN)])
        elif base == "git-push":
            emit([("git push", UNKNOWN, None)])
        elif base == "gh":
            name = _gh_call(rest)
            if name is not None:
                emit([(name, UNKNOWN, None)])
        elif base in _SHELL_DASH_C and depth < MAX_NESTING:
            cmd = _shell_c_arg(rest)
            if cmd is not None:
                emit(gated_calls(cmd, UNKNOWN, depth + 1, inherited_env=env_set))
        elif base in _STRING_EXECUTORS and depth < MAX_NESTING:
            for arg in rest:
                if not arg.startswith("-"):
                    emit(gated_calls(arg, UNKNOWN, depth + 1, inherited_env=env_set))


def _overmatch(command: str, toks: list, depth: int,
               inherited_env: bool = False) -> list[tuple[str, str | None, list[str] | None]]:
    """A command that is not one strict simple `git`/`gh` command: every gated call that occurs anywhere
    is reported NOT MEASURED (never resolved, never inactive), and a hook-disabling form denies. No call may
    be missed, so each control-operator-separated run of words is scanned, and every command substitution
    in the raw text — including a dropped redirection target — is scanned in turn (R4-1, R4-3, R4-4, R4-5)."""
    calls: list[tuple[str, str | None, list[str] | None]] = []
    # An unvetted assignment anywhere in the command (a prefix, `env X=…`, `export X=…`) may select a helper
    # for any git call in it, so an otherwise free git call is NOT MEASURED too (review Runde 6, R6-2 class).
    env_set = inherited_env or any(t[0] == "word" and _ASSIGNMENT.match(t[1]) and not _assignment_neutral(t[1])
                                   for t in toks)

    def emit(found: list) -> None:
        for name, _dir, detail in found:
            calls.append((name, UNKNOWN, detail if detail in ([_HOOKS_DISABLE], [_NOT_FREE]) else None))

    run: list = []
    for t in toks:
        if t[0] == "word":
            run.append(t[1:])
        else:  # a control operator ends the run
            if run:
                _scan_run(run, emit, depth, env_set)
            run = []
    if run:
        _scan_run(run, emit, depth, env_set)
    if depth < MAX_NESTING:
        for body in _subst_bodies(command):
            emit(gated_calls(body, UNKNOWN, depth + 1, inherited_env=env_set))
    return calls


#: The separators (D8) that split the net's normal form into words: whitespace and the shell control bytes.
_NET_SEP = " \t\n;&|(){}`"
_NET_BEFORE = frozenset(_NET_SEP)
_NET_SPLIT = re.compile("[" + re.escape(_NET_SEP) + "]+")


#: Byte for byte, the one-letter ANSI-C escapes of a `$'…'` quote (the bash manual, QUOTING). chr() keeps this
#: source free of backslash literals, which the gate's own normal form would otherwise have to re-escape.
_BACKSLASH = chr(92)
_ANSI_C_SIMPLE = {"a": chr(7), "b": chr(8), "e": chr(27), "E": chr(27), "f": chr(12), "n": chr(10), "r": chr(13),
                  "t": chr(9), "v": chr(11), _BACKSLASH: _BACKSLASH, "'": "'", '"': '"', "?": "?"}
_HEX_DIGITS = "0123456789abcdefABCDEF"
_OCTAL_DIGITS = "01234567"


def _safe_chr(code: int) -> str:
    """chr() for a decoded escape, but never a crash: a code point out of range is not a letter, so it cannot form
    a git or gh command word; it is dropped. Dropping a non-letter can at worst merge neighbours, i.e. overmatch."""
    try:
        return chr(code)
    except ValueError:
        return ""


def _decode_ansi_c(text: str, i: int) -> tuple[str, int]:
    """Decode the body of an ANSI-C quote `$'…'` to the exact bytes bash runs, from text[i] (the first byte after
    `$'`). Returns the decoded string and the index just past the closing quote (or the end of the text, for an
    unterminated quote). The escapes are the bash manual's: the one-letter set above, octal `\\nnn`, hex `\\xHH`,
    Unicode `\\uHHHH`/`\\UHHHHHHHH`, and control `\\cX`. An unrecognised escape keeps its backslash, exactly as
    bash does — measured on bash 5.2: `$'\\z'` is the two bytes `\\z`, `$'\\x'` is `\\x`, `$'\\xZZ'` is `\\xZZ`
    (Nachtrag 33, K1)."""
    out: list[str] = []
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "'":
            return "".join(out), i + 1
        if ch != _BACKSLASH or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        nxt = text[i + 1]
        if nxt in _ANSI_C_SIMPLE:
            out.append(_ANSI_C_SIMPLE[nxt])
            i += 2
        elif nxt in _OCTAL_DIGITS:
            j, digits = i + 1, ""
            while j < n and len(digits) < 3 and text[j] in _OCTAL_DIGITS:
                digits, j = digits + text[j], j + 1
            out.append(_safe_chr(int(digits, 8) & 0xFF))
            i = j
        elif nxt == "x":
            j, digits = i + 2, ""
            while j < n and len(digits) < 2 and text[j] in _HEX_DIGITS:
                digits, j = digits + text[j], j + 1
            if digits:
                out.append(_safe_chr(int(digits, 16)))
                i = j
            else:
                out.append(_BACKSLASH)  # a lone \x keeps its backslash (measured)
                i += 1
        elif nxt in "uU":
            width = 4 if nxt == "u" else 8
            j, digits = i + 2, ""
            while j < n and len(digits) < width and text[j] in _HEX_DIGITS:
                digits, j = digits + text[j], j + 1
            if digits:
                out.append(_safe_chr(int(digits, 16)))
                i = j
            else:
                out.append(_BACKSLASH + nxt)
                i += 2
        elif nxt == "c" and i + 2 < n:
            out.append(_safe_chr(ord(text[i + 2]) & 0x1F))
            i += 3
        else:
            out.append(_BACKSLASH + nxt)  # an unrecognised escape: the backslash stays, as in bash
            i += 2
    return "".join(out), i


def _net_fold(ch: str) -> str:
    """Lower-case only A to Z, each code point in place, so an expanding case fold (U+0130 and the like) cannot
    shift the word boundaries against the search (review Runde 12, R12-3)."""
    return chr(ord(ch) + 32) if "A" <= ch <= "Z" else ch


def _balanced_paren(text: str, start: int) -> tuple[str, int, bool]:
    """From text[start] == '(', the inner text up to the matching ')', the index just past it, and whether it
    was balanced. Quotes inside suppress a `)` (review Runde 11, R11-1 case 3). An unbalanced opener yields the
    rest of the text and ok=False, so the caller treats the context as NOT MEASURED."""
    depth, j, quote, n = 0, start, None, len(text)
    while j < n:
        ch = text[j]
        if quote is not None:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:j], j + 1, True
        j += 1
    return text[start + 1:], n, False


#: Command-prefix words that keep the next word in command-word position (the net's brace/glob test, R13-4).
_NET_EXPANSION_WRAPPERS = frozenset({"sudo", "env", "command", "builtin", "exec", "time", "nice", "nohup",
                                     "ionice", "setsid", "stdbuf", "nocorrect", "then", "do", "else", "elif"})


def _unquoted_active_expansion(raw: str) -> bool:
    """Whether a word's raw text carries an unquoted active expansion: a pathname glob (`*`, `?`, `[`) or a brace
    group with a top-level `,` or `..` (`{a,b}`, `{1..9}`). A quoted metacharacter is literal, `${…}` is a
    parameter expansion not a brace, and a `{…}` with neither `,` nor `..` is a literal brace (review Runde 14,
    R13-4)."""
    i, n = 0, len(raw)
    while i < n:
        c = raw[i]
        if c == "'":
            j = raw.find("'", i + 1)
            if j < 0:
                return False
            i = j + 1
        elif c == '"':
            i += 1
            while i < n and raw[i] != '"':
                i += 2 if raw[i] == _BACKSLASH else 1
            i += 1
        elif c == _BACKSLASH:
            i += 2
        elif c == "$" and i + 1 < n and raw[i + 1] == "{":
            depth, j = 0, i + 1
            while j < n:
                if raw[j] == "{":
                    depth += 1
                elif raw[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            i = j + 1
        elif c in "*?[":
            return True
        elif c == "{":
            depth, j, active = 0, i, False
            while j < n:
                cj = raw[j]
                if cj == "{":
                    depth += 1
                elif cj == "}":
                    depth -= 1
                    if depth == 0:
                        break
                elif depth == 1 and (cj == "," or raw.startswith("..", j)):
                    active = True
                j += 1
            if active and j < n:
                return True
            i += 1
        else:
            i += 1
    return False


def _net_expansion_in_command_word(command: str) -> bool:
    """Whether an active expansion (brace or pathname glob) sits in a command-word position (review Runde 14,
    R13-4): such a word can expand to a git/gh program name (`g{i..i}t`, `gi*`, `g?`), so it is NOT MEASURED. An
    expansion safely in an argument position (`ls *.py`, `cp f.{txt,bak}`) stays free. The command word is the
    first word of each simple command after a control operator, past leading assignments and known wrappers. An
    unparsable command yields False here; the lexer fallback and the net's word test handle it."""
    toks = _lex(_drop_comments(command))
    if toks is None:
        return False
    at_cmd = True
    for t in toks:
        if t[0] == "op":
            at_cmd = t[1] in (";", "&&", "||", "|", "&", "(", "{")
            continue
        value, raw = t[1], t[3]
        if not at_cmd:
            continue
        if _ASSIGNMENT.match(value) or os.path.basename(value) in _NET_EXPANSION_WRAPPERS:
            continue  # a leading assignment or a known wrapper keeps command-word position
        if _unquoted_active_expansion(raw):
            return True
        at_cmd = False
    return False


def _net_render(text: str, depth: int = 0) -> tuple[str, bool]:
    """The recursive core of the net's normal form (review Runde 12; Nachtrag 35, R13-1/R13-2/R13-3). It walks the
    text with its own quote state and reads every embedded executable context as its own command: a command
    substitution `$(…)` or backtick (also inside double quotes) and a process substitution `<(…)`/`>(…)` are
    scanned recursively, so a git word their own ANSI-C quotes build is seen (R13-3); a global quote-state
    variable alone would miss it. An active backslash line-continuation (`\\` then newline) is removed before the
    word test, outside and inside double quotes (R13-2). An ANSI-C quote `$'…'` is evaluated to the bytes bash
    runs; a decoded NUL byte makes the command NOT MEASURED, because bash truncates the sub-word there and the
    net does not model the resulting concatenation (R13-1). A locale quote `$"…"` is NOT MEASURED (its
    translation is not knowable). An unbalanced substitution, or nesting past the limit, is NOT MEASURED."""
    out: list[str] = []
    unresolved = False
    i, n = 0, len(text)
    single = double = False
    while i < n:
        ch = text[i]
        if single:
            if ch == "'":
                single = False
            else:
                out.append(_net_fold(ch))
            i += 1
            continue
        # executable contexts, read as their own command (not as data of an outer double quote)
        if ch == "$" and i + 1 < n and text[i + 1] == "(" and not (i + 2 < n and text[i + 2] == "("):
            inner, j, ok = _balanced_paren(text, i + 1)
            if not ok or depth >= MAX_NESTING:
                unresolved = True
            else:
                s, u = _net_render(inner, depth + 1)
                out.append(" " + s + " ")
                unresolved = unresolved or u
            i = j if ok else n
            continue
        if ch == chr(96):  # a backtick command substitution, in a double quote too
            j = text.find(chr(96), i + 1)
            if j < 0 or depth >= MAX_NESTING:
                unresolved = True
                i = n
            else:
                s, u = _net_render(text[i + 1:j], depth + 1)
                out.append(" " + s + " ")
                unresolved = unresolved or u
                i = j + 1
            continue
        if not double and ch in "<>" and i + 1 < n and text[i + 1] == "(":
            inner, j, ok = _balanced_paren(text, i + 1)
            if not ok or depth >= MAX_NESTING:
                unresolved = True
            else:
                s, u = _net_render(inner, depth + 1)
                out.append(" " + s + " ")
                unresolved = unresolved or u
            i = j if ok else n
            continue
        if double:
            if ch == '"':
                double = False
                i += 1
            elif ch == _BACKSLASH and i + 1 < n and text[i + 1] in ("$", chr(96), '"', _BACKSLASH, chr(10)):
                if text[i + 1] != chr(10):  # in "…" a backslash is literal except before $ ` " \ newline
                    out.append(_net_fold(text[i + 1]))
                i += 2
            else:
                out.append(_net_fold(ch))
                i += 1
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == "'":
            decoded, i = _decode_ansi_c(text, i + 2)
            if chr(0) in decoded:  # bash truncates the sub-word at a NUL; the concatenation is not modelled (R13-1)
                unresolved = True
            out.append("".join(_net_fold(c) for c in decoded))
        elif ch == "$" and i + 1 < n and text[i + 1] == '"':
            unresolved, double, i = True, True, i + 2
        elif ch == "'":
            single, i = True, i + 1
        elif ch == '"':
            double, i = True, i + 1
        elif ch == _BACKSLASH:
            if i + 1 < n and text[i + 1] == chr(10):
                i += 2  # an active line continuation is removed before the word test (R13-2)
            elif i + 1 < n:
                out.append(_net_fold(text[i + 1]))
                i += 2
            else:
                i += 1
        else:
            out.append(_net_fold(ch))
            i += 1
    return "".join(out), unresolved


def _net_scan(command: str) -> tuple[str, bool]:
    """(normal form, unresolved) for the net's word test (review Runde 12/14). The normal form is the command
    text rendered by _net_render (ANSI-C quotes evaluated, quotes and backslashes removed, line continuations
    removed, substitutions read as their own commands, only A to Z lower-cased in place). `unresolved` is True
    when the text holds a form whose executed bytes the normal form cannot build safely and completely, so the
    whole command is NOT MEASURED (Nachtrag 35): a locale quote, a decoded NUL byte, an unbalanced or too-deep
    substitution, or an active brace/glob in a command-word position. Exact evaluation stays only where it is
    provably complete (DECISIONS.md D8). The scan is total: every command yields a normal form."""
    normal, unresolved = _net_render(command)
    return normal, unresolved or _net_expansion_in_command_word(command)


def _net_normal_form(command: str) -> str:
    """The normal form of _net_scan (its string half). See _net_scan for the transform."""
    return _net_scan(command)[0]


def _net_unresolved(command: str) -> bool:
    """Whether the command holds a form whose executed bytes the normal form cannot build safely and completely,
    so the whole command is NOT MEASURED (Nachtrag 35). See _net_scan."""
    return _net_scan(command)[1]


def _net_command_word(token: str) -> bool:
    """Whether a word of the normal form names git or gh as a command, behind a path or not: its basename is
    `git`, `gh`, or a `git-<subcommand>`. A longer word (gitignore, foo-git, digit, a value such as X=git that
    the separators leave whole) is not a command word. The quote and name= exceptions of earlier rounds fall
    away: the normal form has already removed the quotes, and an assignment stays one word that is not a name."""
    base = token.rsplit("/", 1)[-1]
    return base in ("git", "gh") or base.startswith("git-")


def _net_words(command: str) -> int:
    """How many command words of the normal form name git or gh (review Runde 12). The net always runs; the
    caller compares this count with the calls the structured scan resolved, so a command word the scan did not
    account for is NOT MEASURED, never a pass or an inactive gate. An overmatch asks under Claude Code and
    denies under Codex."""
    return sum(1 for token in _NET_SPLIT.split(_net_normal_form(command)) if token and _net_command_word(token))


def _net_hit(command: str) -> bool:
    """Whether the normal form names git or gh as a command word at all (review Runde 12; owner choice A of
    Runde 11). An overmatch asks under Claude Code and denies under Codex."""
    return _net_words(command) > 0


def gated_calls(command: str, directory: str | None = ".", depth: int = 0,
                inherited_env: bool = False) -> list[tuple[str, str | None, list[str] | None]]:
    """Every gated call in a shell command: its name, the directory it acts in (UNKNOWN = NOT MEASURED),
    and for `git push` the words after `push`. The gate resolves the repository and target of a gated call
    ONLY when the whole command is exactly one simple command headed by a bare `git`/`git-push`/`gh` — at
    most one literal `git -C`, only neutral prefix assignments, trailing redirections with a literal
    target, no expansion anywhere (Nachtrag 15, Ebene 1). Every other form a gated call occurs in — a
    `;`/`&&`/`||`/`|`/`&`/newline chain, a pre-command or wrapper, `cd`, a subshell, a group, a keyword, a
    function, `eval`, `source`, `sh -c`, a command or parameter substitution anywhere (even in a redirection
    target), a here-document — is NOT MEASURED, never inactive. `--no-verify` or a `core.hooksPath` override
    denies, because it would turn off the real-push check (Punkt 5)."""
    text = _drop_comments(command)   # the shell ignores a comment, and so does the rest of the scan (R10-1)
    toks = _lex(text)
    if toks is None or depth > MAX_NESTING:
        return [("unparsed command", UNKNOWN, None)] if _FALLBACK.search(text) else []
    words = [t[1:] for t in toks if t[0] == "word"]
    h = 0
    while h < len(words) and _ASSIGNMENT.match(words[h][0]):
        h += 1
    single = not any(t[0] == "op" for t in toks) and not _expansion_present(text)
    head_gated = h < len(words) and os.path.basename(words[h][0]) in ("git", "git-push", "gh")
    if single and head_gated:
        calls = _resolve_single(words, directory, inherited_env)
        if not calls and os.path.basename(words[h][0]) == "git" and not _BARE_VERSION.fullmatch(command):
            return [("git --version", UNKNOWN, [_NOT_FREE])]  # free only as its exact text (review Runde 9)
        return calls
    return _overmatch(text, toks, depth, inherited_env)


# --- the declaration and the evidence at HEAD --------------------------------------------------------

#: Options that make every gate read see the objects a push would transfer, not a local rewrite of them
#: (DECISIONS.md, D20; review R3-8). --no-replace-objects turns off refs/replace/*; the environment names
#: turn off replace refs and the deprecated .git/info/grafts for any git the gate starts, including the
#: cat-file batch reader.
_READ_ONLY_GIT = ("--no-replace-objects",)


def _read_env() -> dict:
    """The environment for the gate's own git reads: the host's own (so the gate reads the same git
    configuration the push will use, including a GIT_CONFIG_* injection the push would honour), plus
    GIT_NO_REPLACE_OBJECTS so no git honours a replace ref and GIT_GRAFT_FILE set to the empty device so
    none honours a .git/info/grafts rewrite of the parent chain. Replace refs and grafts both rewrite the
    view git reads while the pack transfer sends the originals, so the range or tree the gate judges would
    otherwise differ from what the push sends (review R3-8). Measured: a graft that reparents the tip hid a
    middle commit from the gate's rev-list until GIT_GRAFT_FILE was emptied; object alternates cannot change
    what an object id resolves to, so they are not such a rewrite. GIT_NO_LAZY_FETCH=1 keeps a git that
    honours it from fetching a missing object of a partial clone (review Runde 7, R7-7; measured effective on
    git 2.43.0 as Ubuntu builds it, 1:2.43.0-1ubuntu7.3). A git that ignores it is caught by
    _refuse_partial_clone, which does not depend on the version. That refusal carries the case end to end; this
    variable is a second lock with a function contract only (review Runde 8, R8-3)."""
    env = dict(os.environ)
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    env["GIT_GRAFT_FILE"] = os.devnull
    env["GIT_NO_LAZY_FETCH"] = "1"
    return env


#: The configuration keys that make a repository a partial clone, as `git config --get-regexp` matches them
#: (review Runde 7, R7-7; the same pattern as the release funnel's refusal, Z309, commit 6e05e186). git fetches
#: an object a partial clone does not hold from the promisor remote the moment a command asks for it, and the
#: fetch starts the program that remote's configuration names (remote.<name>.uploadpack, an ssh command, a
#: remote helper). Measured by the reviewer and again here on git 2.43.0: `git cat-file -p <missing>` started a
#: marker uploadpack, and decide_mcp's diagnosis started it while it read a declaration this clone did not hold.
#: git makes a remote a promisor through remote.<name>.promisor and remote.<name>.partialclonefilter and through
#: the repository format's extensions.partialClone; whatever the value, the gate reads no object from such a
#: repository. The remote's subsection may be empty (remote..promisor, review Runde 8, R8-2), hence `.*`.
_PARTIAL_CLONE_KEYS = r"^(extensions\.partialclone|remote\..*\.(promisor|partialclonefilter))$"


def _run_git(repo: str, args: tuple, deadline: float) -> subprocess.CompletedProcess:
    left = deadline - time.monotonic()
    if left <= 0:
        raise GateError("the gate ran out of time")
    try:
        return subprocess.run(["git", *_READ_ONLY_GIT, "-C", repo, *args], capture_output=True,
                              timeout=left, check=False, env=_read_env())
    except FileNotFoundError as exc:
        raise GateError("git is not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise GateError("git did not answer in time") from exc


def _refuse_partial_clone(repo: str, deadline: float) -> None:
    """GateError when repo is a partial clone (_PARTIAL_CLONE_KEYS), asked before an object read, so no read of
    the gate can fetch. `git config --get-regexp` reads the configuration and no object; exit 1 with no output
    is "no such key", anything else refuses. A directory that does not exist is left to the call itself, which
    then fails as before without reading an object."""
    if not os.path.isdir(repo):
        return
    probe = _run_git(repo, ("config", "-z", "--get-regexp", _PARTIAL_CLONE_KEYS), deadline)
    if probe.returncode == 0 and probe.stdout:
        names = sorted({e.split(b"\n", 1)[0].decode("utf-8", "replace") for e in probe.stdout.split(b"\0") if e})
        raise GateError(f"{repo} is a partial clone ({', '.join(names)[:160]}): git fetches an object it does not "
                        "hold from the promisor remote and starts the program that remote's configuration names, "
                        "so the gate reads no object from it (NOT MEASURED); clone the repository in full")
    if probe.returncode != 1 or probe.stdout:
        why = probe.stderr.decode("utf-8", "replace").strip().splitlines()
        raise GateError(f"git could not say whether {repo} is a partial clone" + (f": {why[0]}" if why else ""))


#: The gate's git calls that read the configuration or the repository layout and no object: the reads of the
#: state check (_config_entries, _repo_paths) and of the write gate (_state_files). Every other call is asked
#: _refuse_partial_clone first, so a call not on this list is treated as an object read.
_OBJECT_FREE_CALLS = frozenset({
    ("config", "--list", "--null", "--show-origin", "--show-scope"),
    ("rev-parse", "--path-format=absolute", "--git-common-dir", "--git-dir", "--git-path", "hooks"),
    ("rev-parse", "--path-format=absolute", "--show-toplevel"),
    ("var", "GIT_CONFIG_GLOBAL"), ("var", "GIT_CONFIG_SYSTEM"),
})


def _git(repo: str, *args: str, deadline: float) -> subprocess.CompletedProcess:
    """One git call of the gate. Unless the call is one of _OBJECT_FREE_CALLS, the repository must not be a
    partial clone (review Runde 7, R7-7)."""
    if args not in _OBJECT_FREE_CALLS:
        _refuse_partial_clone(repo, deadline)
    return _run_git(repo, args, deadline)


def _blob(repo: str, head: str, path: str, deadline: float, limit: int) -> bytes | None:
    """The bytes of path at the commit; None only when the commit's tree is readable and holds no such file;
    GateError when the commit or its tree is not available locally. A failed `cat-file` is never silently
    read as absence — a remote object this clone does not have (a deletion against an unknown remote state,
    a partial clone) must be NOT MEASURED, not 'absent' (review Runde 5, R5-1)."""
    kind = _git(repo, "cat-file", "-t", f"{head}:{path}", deadline=deadline)
    if kind.returncode != 0:
        listing = _git(repo, "ls-tree", "-z", "--full-tree", head, "--", path, deadline=deadline)
        if listing.returncode == 0 and listing.stdout == b"":
            return None  # a measured absence: the tree is readable and holds no such path
        raise GateError(f"the gate could not read {path} at {head[:12]}: the commit or its tree is not "
                        "available in this repository")
    if kind.stdout.strip() != b"blob":
        raise GateError(f"{path} at HEAD is a {kind.stdout.strip().decode(errors='replace')}, not a file")
    size = _git(repo, "cat-file", "-s", f"{head}:{path}", deadline=deadline)
    if size.returncode != 0 or int(size.stdout.strip() or b"0") > limit:
        raise GateError(f"{path} at HEAD is larger than {limit} bytes")
    content = _git(repo, "cat-file", "blob", f"{head}:{path}", deadline=deadline)
    if content.returncode != 0:
        raise GateError(f"git could not read {path} at HEAD")
    return content.stdout


# --- the tree the evidence speaks for ----------------------------------------------------------------

def _feed(stream, data: bytes) -> None:
    try:
        stream.write(data)
        stream.close()
    except (BrokenPipeError, OSError):
        pass


def _blob_sha256s(repo: str, oids: list[bytes], deadline: float) -> list[str]:
    """sha256 of each object's bytes, read through one `git cat-file --batch`, in order."""
    # Its own lock, as it reads through Popen and not _git; end to end, tree_manifest's ls-tree through _git
    # refuses first (review Runde 8, R8-3).
    _refuse_partial_clone(repo, deadline)
    left = deadline - time.monotonic()
    if left <= 0:
        raise GateError("the gate ran out of time")
    try:
        proc = subprocess.Popen(["git", *_READ_ONLY_GIT, "-C", repo, "cat-file", "--batch"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=_read_env())
    except FileNotFoundError as exc:
        raise GateError("git is not on PATH") from exc
    timer = threading.Timer(left, proc.kill)
    timer.start()
    writer = threading.Thread(target=_feed, args=(proc.stdin, b"".join(o + b"\n" for o in oids)))
    writer.start()
    digests = []
    try:
        for oid in oids:
            header = proc.stdout.readline().split()
            if len(header) != 3 or header[0] != oid or header[1] != b"blob":
                raise GateError(f"git could not read object {oid.decode(errors='replace')} of the tree")
            remaining, hasher = int(header[2]), hashlib.sha256()
            while remaining:
                chunk = proc.stdout.read(min(remaining, 1 << 20))
                if not chunk:
                    raise GateError("git stopped while the gate read the tree")
                hasher.update(chunk)
                remaining -= len(chunk)
            if proc.stdout.read(1) != b"\n":
                raise GateError("git gave an object the gate cannot read")
            digests.append(hasher.hexdigest())
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
        writer.join()
        proc.stdout.close()
        proc.wait()
    if time.monotonic() >= deadline:
        raise GateError("the gate ran out of time while it read the tree")
    return digests


def tree_manifest(repo: str, rev: str = "HEAD", deadline: float | None = None) -> bytes:
    """The bytes the proofbundle-tree-sha256/v1 digest is taken over.

    Covered: every file of the commit's tree except the top-level .proofbundle/ folder, where the
    declaration and the evidence live, so the evidence never covers itself. One record per file, sorted
    by the path's bytes: `<mode> <sha256 of the file's bytes> <path>` and a NUL byte, after the line
    `proofbundle-tree-sha256/v1`. The mode is git's (100644, 100755 or 120000); the bytes are the
    committed blob, so checkout settings play no part. A submodule has no bytes in the commit, so a
    tree with one has no digest.
    """
    if deadline is None:
        deadline = time.monotonic() + DEADLINE_SECONDS
    if not rev or rev.startswith("-"):
        raise GateError(f"not a revision: {rev!r}")
    listing = _git(repo, "ls-tree", "-r", "-z", "--full-tree", rev, deadline=deadline)
    if listing.returncode != 0:
        raise GateError(f"git could not list the tree of {rev}")
    entries = []
    for record in listing.stdout.split(b"\0"):
        if not record:
            continue
        meta, tab, path = record.partition(b"\t")
        fields = meta.split(b" ")
        if not tab or len(fields) != 3:
            raise GateError("git ls-tree gave a line the gate cannot read")
        mode, kind, oid = fields
        if path.startswith(EVIDENCE_DIR.encode()):
            continue
        if kind != b"blob" or mode not in TREE_MODES:
            raise GateError(f"the tree holds a {kind.decode(errors='replace')} at {path.decode(errors='replace')} "
                            f"(a submodule?); {TREE_ALGORITHM} covers files only, so the tree has no digest")
        entries.append((path, mode, oid))
    entries.sort(key=lambda entry: entry[0])
    digests = _blob_sha256s(repo, [oid for _, _, oid in entries], deadline)
    return TREE_HEADER + b"".join(mode + b" " + digest.encode() + b" " + path + b"\0"
                                  for (path, mode, _), digest in zip(entries, digests))


def tree_digest(repo: str, rev: str = "HEAD", deadline: float | None = None) -> str:
    """The proofbundle-tree-sha256/v1 digest of the commit's tree: sha256 of tree_manifest."""
    return hashlib.sha256(tree_manifest(repo, rev, deadline)).hexdigest()


def subject_statement(digest: str) -> bytes:
    """The payload a bundle signs to name its tree subject."""
    return json.dumps({"subject": {"algorithm": TREE_ALGORITHM, "digest": digest}}).encode()


class AmbiguousJSON(ValueError):
    """A JSON object that repeats a key. Readers disagree on which value counts (Python keeps the last), so the
    gate reads no value from it (review Runde 9, R9-4)."""


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise AmbiguousJSON(f"repeats the key {key!r}")
        seen.add(key)
    return dict(pairs)


def strict_json(data: str | bytes) -> object:
    """json.loads that refuses a repeated key in every object, at any depth (AmbiguousJSON, a ValueError)."""
    return json.loads(data.decode("utf-8") if isinstance(data, bytes) else data, object_pairs_hook=_unique_pairs)


def signed_payload_ambiguity(kind: str, content: bytes) -> str | None:
    """What makes the evidence document or its signed payload ambiguous, or None. A repeated key in any object
    at any depth is refused before the subject, the run record or the counts are read: a correctly signed
    payload with first a red and then a green run, or first a wrong and then the matching subject, was read by
    its last value and passed (review Runde 9, R9-4, measured by the reviewer). Unreadable evidence is left to
    the readers below, which bind nothing for it."""
    try:
        document = strict_json(content)
    except AmbiguousJSON as exc:
        return f"the evidence document {exc}, so it is ambiguous"
    except (ValueError, UnicodeDecodeError):
        return None
    field = "payload_b64" if kind == "bundle" else "payload"
    if not isinstance(document, dict) or not isinstance(document.get(field), str):
        return None
    try:
        strict_json(base64.b64decode(document[field], validate=True))
    except AmbiguousJSON as exc:
        return f"the signed payload {exc}, so it is ambiguous"
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None
    return None


def signed_subjects(kind: str, content: bytes) -> list[str]:
    """The tree digests the signed part of the evidence names; empty when it names none.

    Read only after the evidence verified, from the same committed bytes the verifier read. A bundle
    names its subject as its whole payload, the JSON of subject_statement, or beside a run record that
    shows a green run on that tree (D23). A decision receipt names it as an inputSnapshot entry with uri
    TREE_SUBJECT_URI and its digest in sha256.
    """
    try:
        document = strict_json(content)
        if kind == "bundle":
            statement = strict_json(base64.b64decode(document["payload_b64"], validate=True))
            keys = set(statement) if isinstance(statement, dict) else set()
            subject = statement["subject"] if keys in ({"subject"}, {"subject", "run"}) else None
            if (isinstance(subject, dict) and set(subject) == SUBJECT_KEYS
                    and subject["algorithm"] == TREE_ALGORITHM and isinstance(subject["digest"], str)):
                if "run" in keys and run_record_problem(statement["run"], subject["digest"]) is not None:
                    return []
                return [subject["digest"]]
            return []
        statement = strict_json(base64.b64decode(document["payload"], validate=True))
        snapshot = statement["predicate"]["inputSnapshot"]
        return [entry["digest"]["sha256"] for entry in snapshot
                if isinstance(entry, dict) and entry.get("uri") == TREE_SUBJECT_URI
                and isinstance(entry.get("digest"), dict) and isinstance(entry["digest"].get("sha256"), str)]
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, binascii.Error):
        return []


# --- the declaration ---------------------------------------------------------------------------------

def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise GateError("the declaration repeats a key")
    return dict(pairs)


def _relative(value: object, where: str) -> str:
    """A normalised path under .proofbundle/, the folder the tree digest leaves out."""
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise GateError(f"{where} must be a non-empty path string")
    parts = value.split("/")
    if value.startswith("/") or "\\" in value or any(p in ("", ".", "..") for p in parts):
        raise GateError(f"{where} must be a normalised path inside the repository: {value!r}")
    if not value.startswith(EVIDENCE_DIR) or value == EVIDENCE_DIR:
        raise GateError(f"{where} must lie under {EVIDENCE_DIR}, which the tree digest leaves out; evidence "
                        f"elsewhere would be part of the tree it names: {value!r}")
    return value


def _subject(value: object, where: str) -> dict:
    if not (isinstance(value, dict) and set(value) == SUBJECT_KEYS and value["algorithm"] == TREE_ALGORITHM
            and isinstance(value["digest"], str) and _HEX64.fullmatch(value["digest"])):
        raise GateError(f"{where} must be {{\"algorithm\": \"{TREE_ALGORITHM}\", \"digest\": <64 lowercase hex>}}")
    return {"algorithm": value["algorithm"], "digest": value["digest"]}


def parse_declaration(raw: bytes) -> list[dict]:
    """The declared items. Raises GateError for anything but the exact form DECISIONS.md describes."""
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError) as exc:
        raise GateError(f"{DECLARATION} is not JSON: {exc}") from exc
    if not isinstance(doc, dict) or set(doc) != {"schema", "evidence"}:
        raise GateError(f"{DECLARATION} must be an object with exactly the keys schema and evidence")
    if doc["schema"] != DECLARATION_SCHEMA:
        raise GateError(f"{DECLARATION} schema must be {DECLARATION_SCHEMA!r}")
    evidence = doc["evidence"]
    if not isinstance(evidence, list) or len(evidence) > MAX_ITEMS:
        raise GateError(f"evidence must be a list of at most {MAX_ITEMS} items")
    items = []
    for n, item in enumerate(evidence):
        where = f"evidence[{n}]"
        if not isinstance(item, dict) or not set(item) <= ITEM_KEYS:
            raise GateError(f"{where} must be an object with keys from {sorted(ITEM_KEYS)}")
        if item.get("kind") == "outcome":
            raise GateError(f"{where}: an outcome receipt has no field that can carry a tree subject; "
                            "declare a decision receipt or a bundle")
        if item.get("kind") not in KINDS:
            raise GateError(f"{where}.kind must be one of {', '.join(KINDS)}")
        checked = {"kind": item["kind"], "path": _relative(item.get("path"), f"{where}.path")}
        if "policy" in item:
            checked["policy"] = _relative(item["policy"], f"{where}.policy")
        if item["kind"] == "bundle":
            if "public_key" in item:
                raise GateError(f"{where}: a bundle names its trusted signer in its policy, not in public_key")
            if "policy" not in item:
                raise GateError(f"{where}: a bundle needs a policy; without one no signer is pinned")
        else:
            key = item.get("public_key")
            try:
                raw_key = base64.b64decode(key, validate=True) if isinstance(key, str) else b""
            except (binascii.Error, ValueError):
                raw_key = b""
            if len(raw_key) != 32:
                raise GateError(f"{where}.public_key must be a base64 Ed25519 public key (32 bytes)")
            checked["public_key"] = key
        checked["subject"] = _subject(item.get("subject"), f"{where}.subject")
        items.append(checked)
    return items


# --- verification through the plugin's MCP server ---------------------------------------------------

def require_pinned_signer(raw: bytes, where: str) -> None:
    """A bundle carries its own public key, so only its policy can say whose key it must be.

    The gate asks the least that makes a pass mean something: at least one allowed issuer and the
    expected-signer rule switched on. Everything else about the policy is the verifier's to judge.
    """
    try:
        policy = strict_json(raw)
    except AmbiguousJSON as exc:
        raise GateError(f"{where} {exc}, so it is ambiguous") from exc
    except (UnicodeDecodeError, ValueError) as exc:
        raise GateError(f"{where} is not JSON") from exc
    issuers = policy.get("allowed_issuers") if isinstance(policy, dict) else None
    signature = policy.get("signature") if isinstance(policy, dict) else None
    if not (isinstance(issuers, list) and issuers and isinstance(signature, dict)
            and signature.get("require_expected_signer") is True):
        raise GateError(f"{where} does not pin a signer: it needs a non-empty allowed_issuers and "
                        "signature.require_expected_signer true")


#: Environment names that can make Python load code from the checked repository (a PYTHONPATH entry, a
#: start-up file). The gate strips every PYTHON* name before it starts the verifier, so no file of the
#: checked repository decides which code verifies (DECISIONS.md, D11; review N4). PATH, uv and the
#: interpreter installation stay as the user's own trusted inputs.
def _isolated_env() -> dict:
    return {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}


def verify_items(requests: list[dict], deadline: float) -> list[dict]:
    """Call verify_receipt once per request on the plugin's MCP server and return the tool results."""
    uv = shutil.which("uv")
    if uv is None:
        raise GateError("uv is not on PATH, so the verifier cannot start")
    lines = [{"jsonrpc": "2.0", "id": 0, "method": "initialize",
              "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                         "clientInfo": {"name": "proofbundle-gate", "version": "1"}}},
             {"jsonrpc": "2.0", "method": "notifications/initialized"}]
    lines += [{"jsonrpc": "2.0", "id": n + 1, "method": "tools/call",
               "params": {"name": "verify_receipt", "arguments": arguments}}
              for n, arguments in enumerate(requests)]
    left = deadline - time.monotonic()
    if left <= 0:
        raise GateError("the gate ran out of time before the verifier started")
    try:
        with tempfile.TemporaryDirectory(prefix="proofbundle-verify-") as clean:
            proc = subprocess.run([uv, "run", "--quiet", "--no-config", "--script", str(SERVER)], cwd=clean,
                                  env=_isolated_env(), input="".join(json.dumps(m) + "\n" for m in lines),
                                  capture_output=True, text=True, timeout=left, check=False)
    except subprocess.TimeoutExpired as exc:
        raise GateError("the verifier did not finish in time") from exc
    # A reply line that repeats a key could be read as an answer to any request, and a second reply for the same
    # request leaves two answers to choose from: either refuses the whole run, so no other reply counts and no
    # reply is overwritten (review Runde 10, R10-2). The MCP server reserves stdout for JSON messages and stderr
    # for diagnostics, so any non-empty stdout line that is not JSON is a protocol error that refuses the whole
    # run too; a later valid reply does not heal it (review Runde 11, R11-4, Geschwister 8). Blank lines carry no
    # message and are skipped.
    replies = {}
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        try:
            reply = strict_json(line)
        except AmbiguousJSON as exc:
            raise GateError(f"a reply line of the verifier {exc}, which refuses the whole verifier run") from exc
        except ValueError as exc:
            raise GateError("the verifier wrote a non-empty stdout line that is not JSON, which refuses the "
                            "whole verifier run") from exc
        # The whole run is refused for any line that is not a well-formed JSON-RPC 2.0 message (review Runde 12,
        # R12-4): the envelope must say jsonrpc 2.0; a notification carries a method and no id and is set aside;
        # a response carries an id that is a real integer (a boolean, string, float or null id is not an answer
        # the gate numbered — bool is a subclass of int, so it is excluded), exactly one of result or error, and
        # no method. An invalid object is never silently skipped, so a later valid reply cannot heal it.
        if not isinstance(reply, dict) or reply.get("jsonrpc") != "2.0":
            raise GateError("the verifier wrote a line that is not a JSON-RPC 2.0 message, which refuses the "
                            "whole verifier run")
        if "id" not in reply:
            # A notification is validated before it is set aside (review Runde 14, R13-5): it carries a string
            # method, and, when params is present, that params is an object (the MCP schema). A string method with
            # a non-object params (for example `params: 0`) is a contract break, not a message to skip.
            if not isinstance(reply.get("method"), str):
                raise GateError("the verifier sent a message with neither an id nor a method, which refuses the "
                                "whole verifier run")
            if "params" in reply and not isinstance(reply["params"], dict):
                raise GateError("the verifier sent a notification whose params is not an object, which refuses the "
                                "whole verifier run")
            continue  # a valid notification carries no answer; it is set aside
        rid = reply["id"]
        if not isinstance(rid, int) or isinstance(rid, bool):
            raise GateError("the verifier sent a reply whose id is not an integer, which refuses the whole "
                            "verifier run")
        if "method" in reply:
            raise GateError("the verifier sent a request (an id and a method), which the gate does not answer "
                            "and which refuses the whole verifier run")
        if ("result" in reply) == ("error" in reply):
            raise GateError("the verifier sent a reply that does not carry exactly one of result or error, "
                            "which refuses the whole verifier run")
        if rid in replies:
            raise GateError(f"the verifier sent a second reply for request {rid}, which refuses the whole "
                            "verifier run")
        replies[rid] = reply
    # The initialisation response (id 0) is evaluated, not set aside (review Runde 14, R13-5): it must be present
    # and carry a result. A failed initialisation (an error on id 0) or a missing one refuses the whole run, so a
    # later valid reply cannot ride a broken handshake.
    init = replies.get(0)
    if init is None or "result" not in init:
        tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no output"]
        raise GateError(f"the verifier did not initialise (exit {proc.returncode}: {tail[0]}), which refuses the "
                        "whole verifier run")
    results = []
    for n in range(len(requests)):
        reply = replies.get(n + 1)
        if reply is None or "result" not in reply:
            tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no output"]
            raise GateError(f"the verifier gave no answer for item {n} (exit {proc.returncode}: {tail[0]})")
        result_obj = reply["result"]
        content = result_obj.get("content") if isinstance(result_obj, dict) else None
        # Every element of content is checked against the measured contract, not only the first (review Runde 13,
        # K2). Measured at proofbundle 6.1.0: the MCP server wraps each tool result as content with exactly one
        # element, the object {"type": "text", "text": <json string>} (server _call_tool). A schema-breaking
        # sibling block — a second element, a non-object, a wrong type, a non-string text — is not ignored; it
        # refuses the whole run with GateError, so an invalid stream can never reach a pass (envelope-error status,
        # R12-4). There is no element the reader leaves unexamined.
        if not isinstance(content, list) or len(content) != 1:
            raise GateError(f"the verifier's result for item {n} does not carry exactly one content element, as the "
                            "proofbundle 6.1.0 tool-result contract requires, which refuses the whole verifier run")
        block = content[0]
        if not (isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str)):
            raise GateError(f"the verifier's result for item {n} is not one text block the gate can read, which "
                            "refuses the whole verifier run")
        try:
            parsed = strict_json(block["text"])
        except ValueError as exc:
            raise GateError(f"the verifier's answer for item {n} is not one unambiguous JSON object ({exc})") from exc
        if not isinstance(parsed, dict):
            raise GateError(f"the verifier's answer for item {n} is not a JSON object")
        # The envelope's tool-error status is authoritative; the payload never overrides it (review Runde 12,
        # R12-4). A present isError must be a real boolean; its absence is a valid false (review Runde 14, R13-5):
        # bool([]) / bool(None) / bool(0) would have read a schema-breaking isError as not-an-error. is_error is
        # written last, so a parsed is_error cannot weaken the envelope's isError.
        if "isError" in result_obj and not isinstance(result_obj["isError"], bool):
            raise GateError(f"the verifier's result for item {n} has an isError that is not a boolean, which "
                            "refuses the whole verifier run")
        results.append({**parsed, "is_error": result_obj.get("isError", False)})
    return results


# --- verdicts ---------------------------------------------------------------------------------------

#: The rule every rejection, every skill and the server's instructions repeat word for word (D19).
WEAKEN_RULE = ("Never weaken the evidence declaration, a trust policy or an expected key to get past the gate; "
               "obtain the missing evidence instead or ask the user.")


class Verdict:
    """What the gate found for one repository.

    For a deny or an ask it also names, in short, the evidence it concerns (kind and path), what failed
    and the next step (DECISIONS.md, D19); the detail text stays behind them. reason_id is a stable name
    for the case, and digests are the sha256 of every evidence and policy file the gate read.
    """

    __slots__ = ("decision", "detail", "reason_id", "evidence", "failed", "next_step", "digests", "repo", "head")

    def __init__(self, decision: str, detail: str, reason_id: str, evidence: str = "", failed: str = "",
                 next_step: str = "", digests: tuple = (), repo: str | None = None, head: str | None = None):
        self.decision, self.detail, self.reason_id = decision, detail, reason_id
        self.evidence, self.failed, self.next_step = evidence, failed, next_step
        self.digests, self.repo, self.head = tuple(digests), repo, head

    def text(self) -> str:
        if self.decision in ("pass", "inactive"):
            return self.detail
        if self.detail.startswith("NOT MEASURED: "):
            prefix, detail = "NOT MEASURED: ", self.detail[len("NOT MEASURED: "):]
        else:
            prefix, detail = "proofbundle gate: ", self.detail.removeprefix("proofbundle gate: ")
        return (f"{prefix}Evidence: {self.evidence.rstrip('.')}. Failed: {self.failed.rstrip('.')}. "
                f"Next step: {self.next_step.rstrip('.')}. {WEAKEN_RULE} Details: {detail}")

    def __iter__(self):
        return iter((self.decision, self.text()))

    def __getitem__(self, index: int):
        return (self.decision, self.text())[index]


def _item(n: int, item: dict) -> str:
    return f"{item['kind']} {item['path']} (evidence[{n}])"


def _absent_at_head(repo: str, commit: str, deadline: float) -> bool:
    """True only when git lists nothing at DECLARATION in the commit's tree and says so with exit 0."""
    listing = _git(repo, "ls-tree", "-z", "--full-tree", commit, "--", DECLARATION, deadline=deadline)
    return listing.returncode == 0 and listing.stdout == b""


def _absent_in_working_tree(repo: str) -> bool:
    """True only when the working tree has nothing at DECLARATION, not even a link or a folder.

    Any answer but "no such file" (no permission, a file where the folder should be) is not a
    measurement of absence, and the gate keeps its NOT MEASURED ask.
    """
    try:
        os.lstat(os.path.join(repo, DECLARATION))
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


# --- the evidence rules a push changes (DECISIONS.md, D20) ------------------------------------------

def _rules_at(repo: str, commit: str, deadline: float) -> tuple:
    """The evidence rules at a commit: whether a declaration exists, its items without their per-release
    subject (kind, path, policy, public_key), and the blob of each declared policy. Evidence files and any
    other file under .proofbundle/ are not rules."""
    try:
        raw = _blob(repo, commit, DECLARATION, deadline, MAX_DECLARATION_BYTES)
    except GateError as exc:
        return ("unreadable", str(exc))
    if raw is None:
        return ("absent",)
    try:
        items = parse_declaration(raw)
    except GateError:
        return ("malformed", hashlib.sha256(raw).hexdigest())
    rules = tuple(sorted((i["kind"], i["path"], i.get("policy", ""), i.get("public_key", "")) for i in items))
    policies = []
    for path in sorted({i["policy"] for i in items if "policy" in i}):
        blob = _git(repo, "rev-parse", "--verify", "--quiet", f"{commit}:{path}", deadline=deadline)
        policies.append((path, blob.stdout.decode().strip() if blob.returncode == 0 else ""))
    return ("declared", rules, tuple(policies))


def _rules_difference(base: tuple, head: tuple) -> str:
    if base[0] != head[0]:
        return {("absent", "declared"): "the push adds the declaration",
                ("declared", "absent"): "the push removes the declaration"}.get(
                    (base[0], head[0]), f"the declaration goes from {base[0]} to {head[0]}")
    if base[0] != "declared":
        return "the declaration changes"
    parts = []
    if base[1] != head[1]:
        parts.append("the declared items change (kind, path, policy or public_key)")
    before, after = dict(base[2]), dict(head[2])
    parts += [f"the policy {path} changes" for path in sorted(set(before) | set(after))
              if before.get(path) != after.get(path)]
    return "; ".join(parts)


#: A push the gate resolves to more commits than this against one target is NOT MEASURED: the gate cannot
#: evaluate the whole range inside its deadline, and a tip alone does not vouch for what it hides (D3, N3).
MAX_RANGE_COMMITS = 64

#: One ref update a `git push` performs: the pushed commit (None for a deletion), the ref it writes on the
#: remote, and the local remote-tracking ref that records that ref's last known state (None when there is
#: none, which makes the whole push NOT MEASURED, N1). remote_absent is True only when the absence of the
#: target ref is MEASURED — a null object id for the remote side of a pre-push line — and False when merely
#: no local tracking ref is known (review Runde 6, Befund 2).
PushTarget = collections.namedtuple("PushTarget", "source dest tracking remote_absent", defaults=(False,))

_TRACKABLE = ("refs/heads/", "refs/tags/")


def _remote_names(repo: str, deadline: float) -> set:
    out = _git(repo, "remote", deadline=deadline)
    return set(out.stdout.decode().split()) if out.returncode == 0 else set()


def _config(repo: str, key: str, deadline: float) -> str | None:
    out = _git(repo, "config", "--get", key, deadline=deadline)
    return out.stdout.decode().strip() if out.returncode == 0 else None


def _config_bool(repo: str, key: str, deadline: float) -> bool:
    """A git boolean config value, normalised by git itself (so 1, yes and on read as true). False when the
    key is unset. A value git cannot read as a boolean, or a multi-valued key, raises GateError, which the
    caller turns into NOT MEASURED (review R3-3)."""
    out = _git(repo, "config", "--bool", "--get", key, deadline=deadline)
    if out.returncode == 1 and not out.stdout.strip():
        return False
    if out.returncode != 0:
        raise GateError(f"git could not read {key} as a boolean")
    return out.stdout.decode().strip() == "true"


def _config_present(repo: str, key: str, deadline: float) -> bool:
    """Whether a (possibly multi-valued) config key has any value. A git error other than 'not set' raises
    GateError (NOT MEASURED)."""
    out = _git(repo, "config", "--get-all", key, deadline=deadline)
    if out.returncode in (0, 1):
        return out.returncode == 0
    raise GateError(f"git could not read {key}")


def _push_adds_unnamed_refs(repo: str, remote: str, deadline: float) -> bool:
    """Whether the remote's configuration adds ref updates a plain push to it does not name: a configured
    remote.<name>.push, a mirror remote, or push.followTags. Each is a git boolean or a value list; a value
    the gate cannot read raises GateError (NOT MEASURED, review R3-3). A pushurl is covered by the endpoint
    check below."""
    return (_config_present(repo, f"remote.{remote}.push", deadline)
            or _config_bool(repo, f"remote.{remote}.mirror", deadline)
            or _config_bool(repo, "push.followTags", deadline))


def _config_all(repo: str, key: str, deadline: float) -> list[str]:
    """Every value of a (possibly multi-valued) config key, as git reads it; [] when unset. A git error
    other than 'not set' raises GateError (NOT MEASURED)."""
    out = _git(repo, "config", "--get-all", key, deadline=deadline)
    if out.returncode == 1:
        return []
    if out.returncode != 0:
        raise GateError(f"git could not read {key}")
    return out.stdout.decode().splitlines()


def _rewrite_rules(repo: str, deadline: float) -> list[tuple[str, str, str]]:
    """Every `url.<base>.insteadOf` and `url.<base>.pushInsteadOf` rule git reads here, from any scope, as
    (kind, base, prefix). A read failure raises GateError (NOT MEASURED)."""
    out = _git(repo, "config", "--null", "--get-regexp", r"^url\..*\.(push)?insteadof$", deadline=deadline)
    if out.returncode == 1:  # no rule
        return []
    if out.returncode != 0:
        raise GateError("git could not read the url.*.insteadOf / pushInsteadOf configuration")
    rules = []
    for entry in out.stdout.split(b"\0"):
        if not entry:
            continue
        key, _, value = entry.partition(b"\n")
        name = key.decode("utf-8", "replace")
        for suffix, kind in ((".pushinsteadof", "pushInsteadOf"), (".insteadof", "insteadOf")):
            if name.lower().endswith(suffix):
                rules.append((kind, name[len("url."):-len(suffix)], value.decode("utf-8", "replace")))
                break
    return rules


def _longest_rule(url: str, rules: list[tuple[str, str]]) -> tuple[str, str] | None:
    """The (base, prefix) rule git applies to url: of all rules whose prefix starts url, the longest
    (git-config, url.<base>.insteadOf: "When more than one insteadOf strings match a given URL, the longest
    match is used")."""
    best = None
    for base, prefix in rules:
        if url.startswith(prefix) and (best is None or len(prefix) > len(best[1])):
            best = (base, prefix)
    return best


def _applicable_rewrites(repo: str, remote: str, deadline: float) -> list[str]:
    """The URL rewrites git applies to this remote, resolved by git's own rules (review Runde 6, Punkt 2):
    an insteadOf rule rewrites each configured url and each explicit pushurl it is the longest matching
    prefix of; a pushInsteadOf rule rewrites the push side of each url, but only when the remote has no
    explicit pushurl ("If a remote has an explicit pushurl, Git will ignore this setting for that remote").
    A rule that matches none of these provably does not rewrite this remote and is excluded, so a common
    global rule for another host no longer makes the push NOT MEASURED. Each returned entry names the rule
    and the URL it rewrites. A read failure raises GateError (NOT MEASURED)."""
    urls = _config_all(repo, f"remote.{remote}.url", deadline)
    pushurls = _config_all(repo, f"remote.{remote}.pushurl", deadline)
    rules = _rewrite_rules(repo, deadline)
    instead = [(b, p) for k, b, p in rules if k == "insteadOf"]
    push_instead = [(b, p) for k, b, p in rules if k == "pushInsteadOf"]
    applied = []
    for url in [*urls, *pushurls]:
        hit = _longest_rule(url, instead)
        if hit is not None:
            applied.append(f"url.{hit[0]}.insteadOf = {hit[1]} rewrites {url}")
    if not pushurls:
        for url in urls:
            hit = _longest_rule(url, push_instead)
            if hit is not None:
                applied.append(f"url.{hit[0]}.pushInsteadOf = {hit[1]} rewrites the push to {url}")
    return applied


def _endpoint_consistent(repo: str, remote: str, deadline: float) -> bool:
    """Whether the remote resolves to exactly one push endpoint equal to its one fetch endpoint, with no
    push-only rewrite in play. git's `remote get-url` applies pushurl and url.<base>.insteadOf /
    pushInsteadOf and lists every value, so the string comparison catches a pushurl or a second URL that
    sends the push to a different or a further endpoint than the remote-tracking ref records (Befund 1).
    String equality alone is not a proof the push endpoint matches the comparison-state origin, though
    (review R4-7, Runde 5 Punkt 9): equal effective fetch and push URLs do not prove where an existing
    tracking ref came from — a rule configured after the last fetch rewrites both, and the tracking ref still
    records the old endpoint. So the gate additionally requires that no rewrite applies to this remote, push-
    only or symmetric, resolved by git's own rules (_applicable_rewrites, review Runde 6, Punkt 2). A rule for
    another host does not count; how common a rule is (an SSH rewrite, say) is no reason to release a
    comparison it does apply to. A git error raises GateError (NOT MEASURED)."""
    if _applicable_rewrites(repo, remote, deadline):
        return False
    push = _git(repo, "remote", "get-url", "--push", "--all", remote, deadline=deadline)
    fetch = _git(repo, "remote", "get-url", "--all", remote, deadline=deadline)
    if push.returncode != 0 or fetch.returncode != 0:
        raise GateError(f"git could not read the URLs of remote {remote}")
    push_urls = [u for u in push.stdout.decode().splitlines() if u.strip()]
    fetch_urls = [u for u in fetch.stdout.decode().splitlines() if u.strip()]
    return len(push_urls) == 1 and len(fetch_urls) == 1 and push_urls[0] == fetch_urls[0]


def _refspec_apply(src: str, dst: str, ref: str) -> str | None:
    """The ref `src:dst` maps `ref` to, or None when it does not match. Both sides are full refs, wildcard
    only as a trailing `*` on both sides. A negative or malformed spec matches nothing."""
    if src.startswith("^") or dst.startswith("^") or not dst:
        return None
    if src.endswith("*") and dst.endswith("*"):
        return dst[:-1] + ref[len(src) - 1:] if ref.startswith(src[:-1]) else None
    if "*" in src or "*" in dst:
        return None
    return dst if ref == src else None


def _fetch_maps_cleanly(repo: str, remote: str, dest: str, tracking: str, deadline: float) -> bool:
    """Whether the remote's fetch refspecs map the destination branch `dest` to exactly the tracking ref
    `tracking`, and map nothing else onto `tracking`. Otherwise the tracking ref does not record the state
    of `dest` on the remote (a remapped or colliding refspec), so the comparison the gate would make is
    against the wrong state and the target is NOT MEASURED (review R3-2)."""
    out = _git(repo, "config", "--get-all", f"remote.{remote}.fetch", deadline=deadline)
    if out.returncode not in (0, 1):
        return False
    specs = [line for line in out.stdout.decode().splitlines() if line.strip()]
    dest_maps_to, maps_to_tracking = set(), set()
    for spec in specs:
        src, sep, dst = spec.lstrip("+").partition(":")
        if not sep:
            continue  # a fetch spec with no destination writes FETCH_HEAD, not a tracking ref
        forward = _refspec_apply(src, dst, dest)
        if forward is not None:
            dest_maps_to.add(forward)
        reverse = _refspec_apply(dst, src, tracking)
        if reverse is not None:
            maps_to_tracking.add(reverse)
    return dest_maps_to == {tracking} and maps_to_tracking == {dest}


def _tracking_ref(repo: str, remote: str, dest: str, deadline: float) -> str | None:
    """The one local remote-tracking ref for `dest` on `remote`, or None. A tag writes no per-remote
    tracking ref, so a tag push has no locally known target state and stays NOT MEASURED (N1). The ref must
    both exist and be the one the remote's fetch refspecs map `dest` to (review R3-2)."""
    if not dest.startswith("refs/heads/"):
        return None
    candidate = f"refs/remotes/{remote}/{dest[len('refs/heads/'):]}"
    out = _git(repo, "rev-parse", "--verify", "--quiet", candidate + "^{commit}", deadline=deadline)
    if not (out.returncode == 0 and out.stdout.strip()):
        return None
    return candidate if _fetch_maps_cleanly(repo, remote, dest, candidate, deadline) else None


def _qualify_dest(value: str) -> str | None:
    """The full ref a push destination names, or None when it is not a literal branch or tag ref.
    A bare name is a branch (git may also match a tag, which the gate treats as unresolved by returning
    the branch form only when it is unambiguous here; a tag destination must be given in full)."""
    if not value or "*" in value or value.startswith("^") or "$" in value:
        return None
    if value.startswith("refs/"):
        return value if value.startswith(_TRACKABLE) else None
    if "/" in value or value in ("HEAD",):
        return None
    return "refs/heads/" + value


def resolve_push_targets(repo: str, args: list[str] | None, deadline: float) -> list[PushTarget] | None:
    """The ref updates a `git push` performs, each with its locally known target state, or None when the
    gate cannot resolve them completely (DECISIONS.md, D3 option B; N1, N2, N3).

    None (NOT MEASURED) for: an over-matched push with no literal arguments; a remote given as a URL or a
    path rather than a configured name; --all, --mirror, --tags, --prune, a delete flag, a wildcard or
    negative refspec, or any option the gate does not model; a configured remote.<name>.push, a pushurl, a
    mirror remote, or push.followTags, all of which add ref updates the command does not name; a bare push
    whose current branch has no tracking ref under the chosen remote; a destination that is not a literal
    branch or tag, or a branch with no uniquely mapped remote-tracking ref. There is no default-branch
    fallback: an unknown target state is NOT MEASURED, never 'unchanged' (N1). args is None for a
    `gh pr/release create`, read as a bare push of the current branch to its upstream.
    """
    if args is None:
        args = []
    remotes = _remote_names(repo, deadline)
    remote, refspecs, i, options_done = None, [], 0, False
    while i < len(args):
        word = args[i]
        if not options_done and word == "--":  # end of options; what follows is <remote> <refspec>...
            options_done = True
            i += 1
            continue
        if not options_done and word.startswith("-") and word != "-":
            opt, eq, _ = word.partition("=")
            if word in _PUSH_FLAGS_NEUTRAL:
                i += 1
                continue
            if eq and opt in _PUSH_OPTS_NEUTRAL_INLINE:
                i += 1
                continue
            if not eq and word in _PUSH_OPTS_NEUTRAL_VALUE:
                i += 2
                continue
            return None  # an abbreviation, a target option (--all/--mirror/--tags/--delete/--repo), unknown
        if remote is None:
            remote = word
        else:
            refspecs.append(word)
        i += 1
    if remote is None:  # a bare `git push`: the current branch to its chosen remote, same name
        return _default_targets(repo, deadline, remotes)
    if remote not in remotes:  # a URL or a filesystem path, not a configured remote name
        return None
    try:
        if _push_adds_unnamed_refs(repo, remote, deadline) or not _endpoint_consistent(repo, remote, deadline):
            return None
    except GateError:
        return None  # a malformed bool or an unreadable endpoint: NOT MEASURED (review R3-1, R3-3)
    if not refspecs:
        return _default_targets(repo, deadline, remotes, remote=remote)
    targets = []
    for spec in refspecs:
        spec = spec[1:] if spec.startswith("+") else spec
        if "*" in spec or spec.startswith("^"):
            return None
        src, sep, dst = spec.partition(":")
        if not sep:  # `name` pushes the ref `name` to the same ref on the remote
            dst = src
        dest = _qualify_dest(dst)
        if dest is None:
            return None
        tracking = _tracking_ref(repo, remote, dest, deadline)
        if tracking is None:  # no uniquely mapped local target state: NOT MEASURED, no fallback (N1)
            return None
        if src == "":  # `:dst` deletes the destination ref
            targets.append(PushTarget(source=None, dest=dest, tracking=tracking))
            continue
        commit = _git(repo, "rev-parse", "--verify", "--quiet", src + "^{commit}", deadline=deadline)
        if commit.returncode != 0 or not commit.stdout.strip():
            return None
        targets.append(PushTarget(source=commit.stdout.decode().strip(), dest=dest, tracking=tracking))
    return targets or None


def _default_targets(repo: str, deadline: float, remotes: set, remote: str | None = None) -> list[PushTarget] | None:
    """A push with no refspec: the current branch to the chosen remote under the same name, but only when
    git's push configuration makes that faithful. push.default matching, a configured remote.push, a
    pushurl, a mirror or push.followTags add updates the gate cannot name, so those are NOT MEASURED."""
    branch = _git(repo, "symbolic-ref", "--quiet", "--short", "HEAD", deadline=deadline)
    if branch.returncode != 0 or not branch.stdout.strip():
        return None  # a detached HEAD names no branch to push
    name = branch.stdout.decode().strip()
    if remote is None:
        remote = (_config(repo, f"branch.{name}.pushRemote", deadline)
                  or _config(repo, "remote.pushDefault", deadline)
                  or _config(repo, f"branch.{name}.remote", deadline)
                  or ("origin" if "origin" in remotes else None))
    if remote is None or remote not in remotes:
        return None
    try:
        if _push_adds_unnamed_refs(repo, remote, deadline) or not _endpoint_consistent(repo, remote, deadline):
            return None
    except GateError:
        return None  # a malformed bool or an unreadable endpoint: NOT MEASURED (review R3-1, R3-3)
    default = (_config(repo, "push.default", deadline) or "simple").lower()
    if default not in ("simple", "current", "upstream", "tracking"):
        return None  # matching, or anything the gate does not model, pushes more than the current branch
    if default in ("upstream", "tracking"):
        merge = _config(repo, f"branch.{name}.merge", deadline)
        dest = merge if merge and merge.startswith("refs/heads/") else None
    else:  # simple, current: the branch of the same name on the remote
        dest = "refs/heads/" + name
    if dest is None:
        return None
    tracking = _tracking_ref(repo, remote, dest, deadline)
    if tracking is None:
        return None
    head = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", deadline=deadline)
    if head.returncode != 0 or not head.stdout.strip():
        return None
    return [PushTarget(source=head.stdout.decode().strip(), dest=dest, tracking=tracking)]


def _newly_reachable(repo: str, source: str, tracking: str, deadline: float) -> list[str] | None:
    """Every commit reachable from the pushed source but not from the target's known remote-tracking ref,
    newest first, or None when git cannot list them, the repository is shallow, or there are too many to
    evaluate inside the deadline. A shallow clone hides ancestors, so the range is NOT MEASURED (N3)."""
    shallow = _git(repo, "rev-parse", "--is-shallow-repository", deadline=deadline)
    if shallow.returncode != 0 or shallow.stdout.decode().strip() != "false":
        return None
    listing = _git(repo, "rev-list", f"--max-count={MAX_RANGE_COMMITS + 1}", source, "--not", tracking,
                   deadline=deadline)
    if listing.returncode != 0:
        return None
    commits = listing.stdout.decode().split()
    return None if len(commits) > MAX_RANGE_COMMITS else commits


_RULES_NEXT = ("have a person review the change to the evidence rules, then push; the gate reports every "
               "such change")


def _rules_verdict(repo: str, commit: str, what: str, digests: tuple = ()) -> Verdict:
    return Verdict("ask", f"proofbundle gate: the push changes the evidence rules under {EVIDENCE_DIR} at "
                          f"{commit[:12]}: {what}. Changes to the evidence rules need a review.",
                   "rules_changed", evidence=f"the evidence rules under {EVIDENCE_DIR} ({DECLARATION} and its policies)",
                   failed=what, next_step=_RULES_NEXT, digests=digests, repo=repo, head=commit)


#: Befund 2 (review Runde 6), verbatim: the message for a target ref whose absence is measured.
TARGET_ABSENT_TEXT = ("NOT MEASURED: The target ref does not exist; this gate does not yet implement the history "
                      "and initial-policy checks for creating it.")


def _push_sources(repo: str, args: list[str] | None, deadline: float) -> tuple[list[str] | None, str | None]:
    """The local commits a `git push` (or a `gh`, args None, read as a bare push) uniquely sends, determined
    from the command and the local branch alone — independent of whether its target comparison can be
    resolved — and the remote word it names (review Runde 6, Befund 1). ([], remote) for a push that only
    deletes. (None, remote) when the source is unclear: an option the gate does not model (--all, --mirror,
    --tags, a delete flag, an abbreviation, --receive-pack), a wildcard or negative refspec, a refspec that
    names no commit, or a bare push whose current branch git would not push alone (a detached HEAD, a
    configured remote.<name>.push, push.default matching or one the gate does not model). There is no
    substitute: an unclear source is never replaced by HEAD. A read failure raises GateError."""
    args = [] if args is None else args
    remote, refspecs, i, options_done = None, [], 0, False
    while i < len(args):
        word = args[i]
        if not options_done and word == "--":
            options_done, i = True, i + 1
            continue
        if not options_done and word.startswith("-") and word != "-":
            opt, eq, _ = word.partition("=")
            if word in _PUSH_FLAGS_NEUTRAL or (eq and opt in _PUSH_OPTS_NEUTRAL_INLINE):
                i += 1
                continue
            if not eq and word in _PUSH_OPTS_NEUTRAL_VALUE:
                i += 2
                continue
            return None, remote
        if remote is None:
            remote = word
        else:
            refspecs.append(word)
        i += 1
    if refspecs:
        sources = []
        for spec in refspecs:
            spec = spec[1:] if spec.startswith("+") else spec
            if "*" in spec or spec.startswith("^"):
                return None, remote
            src = spec.partition(":")[0]
            if src == "":
                continue  # `:dst` deletes; it sends no commit
            commit = _git(repo, "rev-parse", "--verify", "--quiet", src + "^{commit}", deadline=deadline)
            if commit.returncode != 0 or not commit.stdout.strip():
                return None, remote
            sources.append(commit.stdout.decode().strip())
        return sources, remote
    branch = _git(repo, "symbolic-ref", "--quiet", "--short", "HEAD", deadline=deadline)
    if branch.returncode != 0 or not branch.stdout.strip():
        return None, remote
    name = branch.stdout.decode().strip()
    chosen = remote or (_config(repo, f"branch.{name}.pushRemote", deadline)
                        or _config(repo, "remote.pushDefault", deadline)
                        or _config(repo, f"branch.{name}.remote", deadline) or "origin")
    if _config_present(repo, f"remote.{chosen}.push", deadline):
        return None, remote
    if (_config(repo, "push.default", deadline) or "simple").lower() not in ("simple", "current", "upstream",
                                                                             "tracking"):
        return None, remote
    head = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", deadline=deadline)
    if head.returncode != 0 or not head.stdout.strip():
        return None, remote
    return [head.stdout.decode().strip()], remote


def _source_denial(repo: str, head_commit: str, sources: list[str], deadline: float, why: str) -> Verdict | None:
    """Befund 1 (review Runde 6): the evidence at uniquely determined source commits is checked even when the
    comparison with the target is NOT MEASURED. A proven evidence failure stays a deny, and the comparison
    that was not measured is named separately in it; anything else returns None, so the caller's NOT
    MEASURED stands — a pass at a source is never a verdict on a push whose comparison is unknown."""
    for commit in dict.fromkeys(sources):
        where = f"HEAD {commit[:12]}" if commit == head_commit else f"the pushed commit {commit[:12]}"
        verdict = _evaluate_tree(repo, commit, deadline, where, "")
        if verdict.decision == "deny":
            return Verdict("deny", verdict.detail.rstrip() + " Separately, the comparison with the target was NOT "
                                  f"MEASURED: {why.rstrip('.')}.", verdict.reason_id, evidence=verdict.evidence,
                           failed=verdict.failed, next_step=verdict.next_step, digests=verdict.digests,
                           repo=verdict.repo or repo, head=verdict.head or commit)
    return None


def _unresolved_verdict(repo: str, head: str | None, why: str) -> Verdict:
    return Verdict("ask", f"NOT MEASURED: the gate cannot resolve what this push sends, so it checked nothing: "
                          f"{why}.", "push_not_measured",
                   evidence="the commits and refs this push would send",
                   failed=why, next_step="push with an explicit remote name and refspec whose target this "
                                         "repository already tracks, or have a person review the push",
                   repo=repo, head=head)


# --- one tree ----------------------------------------------------------------------------------------

def _evaluate_tree(repo: str, commit: str, deadline: float, where: str, pass_tail: str) -> Verdict:
    """The verdict for the evidence a single commit's tree declares: pass, inactive, ask (empty list) or
    deny. No working-tree read and no range comparison; `where` names the commit in every message and
    `pass_tail` is appended to a pass. parse_declaration and the evidence-file _blob reads raise GateError,
    which the caller turns into a deny, so a tree whose evidence cannot be read is never silently treated as
    declaring nothing. The DECLARATION read is the one exception: an unreadable or unconfirmable declaration
    returns 'inactive' here, and the caller's absence nuance (D5) turns an UNMEASURED absence into a NOT
    MEASURED ask and only a MEASURED absence (git lists the path empty with exit 0) into inactive — so a
    failed `cat-file` is still never silently 'absent' (review Runde 5, R5-1)."""
    try:
        raw = _blob(repo, commit, DECLARATION, deadline, MAX_DECLARATION_BYTES)
    except GateError:
        raw = None  # unreadable/unconfirmed: the caller's absence nuance decides ask vs inactive
    if raw is None:
        return Verdict("inactive", f"NOT MEASURED: no evidence is declared at {where} ({DECLARATION} is absent).",
                       "nothing_declared", repo=repo, head=commit)
    items = parse_declaration(raw)
    if not items:
        return Verdict("ask", f"NOT MEASURED: {DECLARATION} at {where} declares an empty evidence list. "
                              "Nothing was verified.", "empty_declaration",
                       evidence=f"the declaration {DECLARATION}", failed="its evidence list is empty",
                       next_step="declare the evidence this tree needs and commit it", repo=repo, head=commit)
    tree = tree_digest(repo, commit, deadline)
    stale = [(n, item) for n, item in enumerate(items) if item["subject"]["digest"] != tree]
    if stale:
        return Verdict("deny", f"proofbundle gate: the declared subject does not match the tree at {where}, "
                               f"which is {TREE_ALGORITHM} {tree}. "
                               + " | ".join(f"evidence[{n}] {i['path']} names {i['subject']['digest']}" for n, i in stale)
                               + ". The evidence speaks for another tree.", "stale_subject",
                       evidence=", ".join(_item(n, i) for n, i in stale),
                       failed=f"its subject is not the tree digest of {where} ({TREE_ALGORITHM} {tree})",
                       next_step="build and sign the evidence for the tree at the pushed commit, then commit it "
                                 "under .proofbundle/",
                       repo=repo, head=commit)
    requests, contents, digests = [], [], []
    with tempfile.TemporaryDirectory(prefix="proofbundle-gate-") as scratch:
        for n, item in enumerate(items):
            arguments = {"kind": item["kind"]}
            for field in ("path", "policy"):
                if field not in item:
                    continue
                limit = MAX_EVIDENCE_BYTES if field == "path" else MAX_DECLARATION_BYTES
                content = _blob(repo, commit, item[field], deadline, limit)
                if content is None:
                    return Verdict("deny", f"proofbundle gate: declared {field} {item[field]} of evidence[{n}] is "
                                           f"missing at {where}. Nothing may be published without it.",
                                   "missing_file", evidence=f"{field} {item[field]} of {_item(n, item)}",
                                   failed=f"the file is missing at {where}",
                                   next_step="obtain the declared file and commit it under .proofbundle/",
                                   digests=digests, repo=repo, head=commit)
                digests.append(f"{item[field]} sha256:{hashlib.sha256(content).hexdigest()}")
                if field == "policy" and item["kind"] == "bundle":
                    try:
                        require_pinned_signer(content, f"the policy {item[field]} of evidence[{n}]")
                    except GateError as exc:
                        return Verdict("deny", f"proofbundle gate: {exc}.", "policy_pins_no_signer",
                                       evidence=f"policy {item[field]} of {_item(n, item)}",
                                       failed="the policy pins no signer",
                                       next_step="obtain a policy that pins the expected signer (a non-empty "
                                                 "allowed_issuers and signature.require_expected_signer true)",
                                       digests=digests, repo=repo, head=commit)
                if field == "path":
                    contents.append(content)
                target = os.path.join(scratch, f"{n}-{field}.json")
                with open(target, "wb") as handle:
                    handle.write(content)
                arguments["path" if field == "path" else "policy_path"] = target
            if "public_key" in item:
                arguments["public_key"] = item["public_key"]
            requests.append(arguments)
        results = verify_items(requests, deadline)
    failed, version = [], "unknown"
    for n, (item, result) in enumerate(zip(items, results)):
        version = result.get("proofbundle_version", version)
        # exit_code counts only as a real integer: a boolean (false) is not success, though bool == int 0 in
        # Python, and a missing or non-integer exit_code is a failure, not a pass (review Runde 12, R12-4).
        exit_code = result.get("exit_code")
        ok_exit = isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code == 0
        if result["is_error"] or not ok_exit:
            why = result.get("error") or f"exit {exit_code!r}: {result.get('meaning')}"
            failed.append((n, item, why))
    if failed:
        return Verdict("deny", f"proofbundle gate: verification failed at {where} (proofbundle {version}). "
                               + " | ".join(f"evidence[{n}] {i['kind']} {i['path']}: {why}" for n, i, why in failed),
                       "verification_failed", evidence=", ".join(_item(n, i) for n, i, _ in failed),
                       failed="; ".join(why for _, _, why in failed),
                       next_step="obtain evidence that verifies under the declared key or policy",
                       digests=digests, repo=repo, head=commit)
    unbound = []
    for n, (item, content) in enumerate(zip(items, contents)):
        ambiguity = signed_payload_ambiguity(item["kind"], content)
        if ambiguity is not None:   # refused before the subject, the run record or the counts are read (R9-4)
            unbound.append((n, item, ambiguity))
            continue
        problem = signed_run_problem(item["kind"], content)
        named = signed_subjects(item["kind"], content)
        if problem is not None:
            unbound.append((n, item, problem))
        elif not named:
            unbound.append((n, item, "the signed evidence names no tree subject"))
        elif item["subject"]["digest"] not in named:
            unbound.append((n, item, f"the signed evidence names {', '.join(named)}, not the declared subject "
                                     f"{item['subject']['digest']}"))
    if unbound:
        return Verdict("deny", f"proofbundle gate: the evidence verified but is not bound to the tree at {where}. "
                               + " | ".join(f"evidence[{n}] {i['path']}: {why}" for n, i, why in unbound),
                       "not_bound", evidence=", ".join(_item(n, i) for n, i, _ in unbound),
                       failed="; ".join(why for _, _, why in unbound),
                       next_step="sign a statement that names the tree digest of the pushed commit and commit it",
                       digests=digests, repo=repo, head=commit)
    counts = next((c for item, content in zip(items, contents)
                   if (c := signed_run_counts(item["kind"], content)) is not None), None)
    run_note = (" No run record: this evidence does not attest a test run." if counts is None else
                f" The signed run record reports {counts['passed']} of {counts['tests']} tests passed with exit 0; "
                "the gate checked the record, not the run.")
    return Verdict("pass", f"proofbundle gate: {len(items)} of {len(items)} declared items verified at {where} "
                           f"for {TREE_ALGORITHM} {tree} with proofbundle {version}. This proves who signed the "
                           f"recorded bytes and which tree they name, not that the recorded values are "
                           f"true.{run_note}{pass_tail}",
                   "verified", digests=tuple(digests), repo=repo, head=commit)


def _absence_nuance(repo: str, commit: str, deadline: float) -> Verdict | None:
    """When the committed tree declares nothing, say whether that is a measured absence (None, so the gate
    is inactive) or a NOT MEASURED ask: git could not confirm the path is empty, or an uncommitted
    declaration sits in the working tree and the gate reads the commit (DECISIONS.md, D5)."""
    if _absent_at_head(repo, commit, deadline) and _absent_in_working_tree(repo):
        return None
    in_tree = os.path.exists(os.path.join(repo, DECLARATION))
    hint = " A declaration exists in the working tree but is not committed; the gate reads the commit." if in_tree else ""
    return Verdict("ask", f"NOT MEASURED: {repo} declares no evidence at {commit[:12]} ({DECLARATION} is absent). "
                          f"Nothing was verified.{hint}",
                   "declaration_uncommitted" if in_tree else "absence_not_measured",
                   evidence=f"the declaration {DECLARATION}" + (" (working tree only)" if in_tree else ""),
                   failed=("the declaration is not committed, and the gate reads the commit" if in_tree
                           else "the gate could not confirm that nothing is declared"),
                   next_step=("commit the declaration and the evidence it names, then retry" if in_tree
                              else f"check what stands at {DECLARATION} in the working tree and at the commit"),
                   repo=repo, head=commit)


# --- one repository at HEAD (CI mode and MCP tools) --------------------------------------------------

def evaluate_repository(directory: str, deadline: float, check_range: bool = False) -> Verdict:
    """The verdict for the repository at directory, judged at HEAD, with no range comparison (DECISIONS.md,
    D22 for CI; decide_mcp's local diagnosis for an MCP tool, never its decision). A shell `git push`
    does not use this path; it resolves its targets through evaluate_push. check_range is accepted for
    compatibility and ignored: the range is never read at HEAD alone."""
    top = _git(directory, "rev-parse", "--show-toplevel", deadline=deadline)
    if top.returncode != 0:
        return Verdict("ask", f"NOT MEASURED: {directory} is not inside a git work tree, so no evidence was checked.",
                       "not_a_work_tree", evidence=f"none, {directory} is not inside a git work tree",
                       failed="there is no repository to check",
                       next_step="run the call inside the repository it acts on, or confirm it yourself",
                       repo=directory)
    repo = top.stdout.decode().strip()
    head = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", deadline=deadline)
    if head.returncode != 0:
        return Verdict("ask", f"NOT MEASURED: {repo} has no commit at HEAD, so no evidence was checked.",
                       "no_commit", evidence=f"the declaration {DECLARATION}", failed="the repository has no commit",
                       next_step="commit first, then retry", repo=repo)
    commit = head.stdout.decode().strip()
    verdict = _evaluate_tree(repo, commit, deadline, f"HEAD {commit[:12]}",
                             " The evidence rules were not compared with any earlier state.")
    if verdict.decision == "inactive":
        nuance = _absence_nuance(repo, commit, deadline)
        if nuance is not None:
            return nuance
        return Verdict("inactive", f"NOT MEASURED: {repo} declares no evidence, neither at HEAD {commit[:12]} "
                                   f"nor in the working tree ({DECLARATION} is absent). The gate is not active in "
                                   "this repository, because nothing is declared. Nothing was verified.",
                       "nothing_declared", repo=repo, head=commit)
    return verdict


# --- a push, resolved to its targets and the commits it sends (DECISIONS.md, D3 option B, D20) --------

def evaluate_push(directory: str, push_args: list[str] | None, deadline: float) -> Verdict:
    """The verdict for a `git push` (push_args) or a `gh pr/release create` (push_args None, the current
    branch to its upstream): the evidence at every commit the push newly sends to each target, and whether
    those commits change the evidence rules against the target's locally known state. An unresolved push,
    or one whose range or comparison state the gate cannot determine, is NOT MEASURED (N1, N2, N3)."""
    top = _git(directory, "rev-parse", "--show-toplevel", deadline=deadline)
    if top.returncode != 0:
        return Verdict("ask", f"NOT MEASURED: {directory} is not inside a git work tree, so no evidence was checked.",
                       "not_a_work_tree", evidence=f"none, {directory} is not inside a git work tree",
                       failed="there is no repository to check",
                       next_step="run the call inside the repository it acts on, or confirm it yourself",
                       repo=directory)
    repo = top.stdout.decode().strip()
    head = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", deadline=deadline)
    if head.returncode != 0:
        return Verdict("ask", f"NOT MEASURED: {repo} has no commit at HEAD, so no evidence was checked.",
                       "no_commit", evidence=f"the declaration {DECLARATION}", failed="the repository has no commit",
                       next_step="commit first, then retry", repo=repo)
    head_commit = head.stdout.decode().strip()
    targets = resolve_push_targets(repo, push_args, deadline)
    if targets is None:
        why = ("the remote, a refspec, or the push configuration names updates the gate cannot map to a locally "
               "tracked target (a URL or path remote, --all/--mirror/--tags, a wildcard refspec, a configured "
               "remote push list, or a branch this repository does not track)")
        try:
            sources, remote = _push_sources(repo, push_args, deadline)
            rewrites = (_applicable_rewrites(repo, remote, deadline)
                        if remote is not None and remote in _remote_names(repo, deadline) else [])
        except GateError:
            sources, rewrites = None, []
        if rewrites:
            why += ("; a URL rewrite applies to this remote (" + "; ".join(rewrites) + "), and equal effective "
                    "fetch and push URLs do not prove where the existing tracking ref came from")
        if sources is None:
            return _unresolved_verdict(repo, head_commit, why + "; the gate cannot tell which commits the push sends, "
                                       "so it checked no evidence, and no check of HEAD stands in for that")
        denial = _source_denial(repo, head_commit, sources, deadline, why)
        if denial is not None:
            return denial
        checked = ", ".join(c[:12] for c in dict.fromkeys(sources)) or "none (the push only deletes)"
        return _unresolved_verdict(repo, head_commit, why + f"; the evidence at the sent source commit(s) {checked} "
                                   "showed no failure, which is not a verdict on the push")
    return _evaluate_targets(repo, head_commit, targets, deadline)


def _evaluate_targets(repo: str, head_commit: str, targets: list, deadline: float,
                      remote_state: bool = False) -> Verdict:
    """The verdict for a resolved set of push targets: the evidence at every commit the push newly sends to
    each target, and whether those commits change the evidence rules against the target's known state. Both
    the shell-command path (evaluate_push, targets from resolve_push_targets) and the prototype pre-push
    hook (pre_push_verdict, targets from git's own stdin) share this core. remote_state is True on Ebene 2,
    where the comparison state is the remote's as git reported it, and False on Ebene 1, where it is this
    repository's last known state of the target; every comparison verdict says which (review Runde 6,
    Punkt 5, R4-7K)."""
    def where(commit: str) -> str:
        return f"HEAD {commit[:12]}" if commit == head_commit else f"the pushed commit {commit[:12]}"

    known = ("the remote's state of the target as git reported it to the pre-push hook" if remote_state else
             "the last known state of the target in this repository, not a state read from the remote")
    sent = [t.source for t in targets if t.source is not None]

    # R5-4: a target that sends commits to a ref this repository does not track (a brand-new remote ref,
    # remote-sha all-zero in the pre-push path) has no comparison state, so the gate cannot tell which
    # commits are new. Owner choice (D24): NOT MEASURED with a block, not a traceback into rev-list(None).
    for t in targets:
        if t.source is not None and t.tracking is None:
            if t.remote_absent:
                # Befund 2: the target's absence is measured (a null object id from git). The block stays; the
                # message is the reviewer's, verbatim. A proven evidence failure at a sent commit stays a deny.
                denial = _source_denial(repo, head_commit, sent, deadline, TARGET_ABSENT_TEXT[len("NOT MEASURED: "):])
                if denial is not None:
                    return denial
                return Verdict("ask", TARGET_ABSENT_TEXT, "target_ref_absent",
                               evidence=f"the commits this push would add by creating {t.dest}",
                               failed="the target ref does not exist, and the gate does not yet check the history "
                                      "and initial policy for creating it",
                               next_step="have a person review the creation of the ref, or push to a ref the remote "
                                         "already has", repo=repo, head=head_commit or t.source)
            why = (f"the push creates {t.dest}, which this repository does not track, so the gate cannot determine "
                   "which commits it adds (no comparison state)")
            denial = _source_denial(repo, head_commit, sent, deadline, why)
            return denial if denial is not None else _unresolved_verdict(repo, head_commit or t.source, why)

    # Every commit the push newly sends, across all targets, with the source tip always evaluated so a push
    # the remote already holds still has its evidence verified (its range is otherwise empty).
    order: list[str] = []
    for t in targets:
        if t.source is None:
            continue
        reachable = _newly_reachable(repo, t.source, t.tracking, deadline)
        if reachable is None:
            why = (f"the gate cannot list the commits this push adds to {t.dest} (a shallow clone, too long a "
                   "range, or git could not resolve it)")
            denial = _source_denial(repo, head_commit, sent, deadline, why)
            return denial if denial is not None else _unresolved_verdict(repo, head_commit, why)
        for commit in [t.source, *reachable]:
            if commit not in order:
                order.append(commit)

    verdicts = {commit: _evaluate_tree(repo, commit, deadline, where(commit), "") for commit in order}
    for commit in order:  # a deny at any sent commit denies the whole push (a valid tip cannot heal it, N3)
        if verdicts[commit].decision == "deny":
            return verdicts[commit]
    for commit in order:
        if verdicts[commit].decision == "ask":  # an empty declared list at a sent commit
            return verdicts[commit]

    # The evidence rules must be the same at the target's known state and at every commit the push adds.
    for t in targets:
        base = _rules_at(repo, t.tracking, deadline) if t.tracking else ("absent",)
        if base[0] == "unreadable":
            # R5-1: the target's known remote state is not available locally (a deletion against a ref a
            # different clone wrote, a partial clone). The gate cannot tell whether the rules change, so the
            # push is NOT MEASURED, never a silent 'absent' that reads as inactive.
            return _unresolved_verdict(repo, head_commit, f"the gate cannot read the target's known state for "
                                       f"{t.dest} in this repository, so it cannot tell whether the push "
                                       f"changes the evidence rules ({base[1]})")
        if t.source is None:  # a deletion removes the ref; its rules go to absent
            if base != ("absent",) and _rules_difference(base, ("absent",)):
                return _rules_verdict(repo, head_commit, f"the push removes the declaration (deletes {t.dest}, "
                                      f"against {t.tracking}, {known})")
            continue
        reachable = _newly_reachable(repo, t.source, t.tracking, deadline)
        for commit in dict.fromkeys([*reachable, t.source]):
            head_rules = _rules_at(repo, commit, deadline)
            if head_rules[0] == "unreadable":
                return _unresolved_verdict(repo, head_commit, f"the gate cannot read the evidence rules at "
                                           f"{commit[:12]} in this repository ({head_rules[1]})")
            if base != head_rules:
                digests = verdicts[t.source].digests if verdicts[t.source].decision == "pass" else ()
                against = t.tracking or "nothing, as this repository tracks no earlier state of the target"
                return _rules_verdict(repo, head_commit, f"{_rules_difference(base, head_rules)} "
                                      f"(at {commit[:12]}, against {against}, {known})", digests)

    declared = [verdicts[c] for c in order if verdicts[c].decision == "pass"]
    if not declared:  # every sent commit declares nothing
        nuance = _absence_nuance(repo, head_commit, deadline) if head_commit in order else None
        if nuance is not None:
            return nuance
        where_all = ", ".join(c[:12] for c in order) or head_commit[:12]
        compared = ("The comparison was against the remote's state of the target as git reported it to the "
                    "pre-push hook." if remote_state else
                    "Any comparison would be against this repository's last known state of the target, not a state "
                    "read from the remote (Ebene 2 makes the authoritative comparison).")
        return Verdict("inactive", f"NOT MEASURED: this push declares no evidence (at {where_all}, {DECLARATION} is "
                                   "absent). The gate is not active in this repository, because nothing is declared. "
                                   f"Nothing was verified. {compared}", "nothing_declared", repo=repo, head=head_commit)
    tip = (verdicts[targets[0].source] if targets[0].source and verdicts[targets[0].source].decision == "pass"
           else declared[0])
    tail = (f" The push sends {len(order)} commit(s) to {', '.join(dict.fromkeys(t.dest for t in targets))}; "
            + ("the evidence rules match the remote's state of the target as git reported it to the pre-push hook."
               if remote_state else
               "the evidence rules match the target's last known state in this repository, which was not read "
               "from the remote."))
    return Verdict("pass", tip.detail + tail, "verified", digests=tip.digests, repo=repo, head=head_commit)


#: All-zero object names git writes for a missing side of a pre-push ref line (SHA-1 and SHA-256 lengths).
_ZERO_OIDS = frozenset({"0" * 40, "0" * 64})


def pre_push_verdict(directory: str, lines: list[tuple], deadline: float) -> Verdict:
    """PROTOTYPE Ebene-2 pre-push verdict (DECISIONS.md, D24 — measured in test fixtures only, not installed
    or wired to core.hooksPath outside tests). git hands a pre-push hook, on stdin, one line
    `<local_ref> <local_sha> <remote_ref> <remote_sha>` per ref being pushed, in the repository the push
    runs in. The hook therefore knows the exact commits and the remote's own current state without parsing
    any shell command, so it reaches a verdict where Ebene 1 (the shell grammar) says NOT MEASURED. Each
    line becomes a target: source = the local sha (None when it is all-zero, a deletion), dest = the remote
    ref, tracking = the remote sha (None when the remote has no such ref yet). Then the shared core judges
    the evidence exactly as for a resolved shell push."""
    top = _git(directory, "rev-parse", "--show-toplevel", deadline=deadline)
    if top.returncode != 0:
        return Verdict("deny", f"proofbundle gate (pre-push): {directory} is not inside a git work tree.",
                       "not_a_work_tree", evidence=f"none, {directory} is not a work tree",
                       failed="the pre-push hook ran outside a repository", next_step="run the hook from the repository")
    repo = top.stdout.decode().strip()
    head = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", deadline=deadline)
    head_commit = head.stdout.decode().strip() if head.returncode == 0 and head.stdout.strip() else ""
    targets = []
    for local_ref, local_sha, remote_ref, remote_sha in lines:
        dest = remote_ref if remote_ref.startswith(_TRACKABLE) else None
        if dest is None:  # a ref the gate does not model (not a branch or tag): NOT MEASURED
            return _unresolved_verdict(repo, head_commit or local_sha,
                                       f"the pre-push ref {remote_ref} is not a branch or a tag")
        source = None if local_sha in _ZERO_OIDS else local_sha
        tracking = None if remote_sha in _ZERO_OIDS else remote_sha
        targets.append(PushTarget(source=source, dest=dest, tracking=tracking, remote_absent=tracking is None))
    if not targets:
        return Verdict("inactive", "NOT MEASURED: the pre-push hook received no ref to push.", "nothing_declared",
                       repo=repo, head=head_commit)
    return _evaluate_targets(repo, head_commit or targets[0].source, targets, deadline, remote_state=True)


# --- Nachtrag 24: approval by a human-written rule (no click path yet, owner choice A) ----------------
#
# A human may free one plain local git form in one repository by writing a rule, but only in "with-approvals"
# mode and never under Codex. The model can neither set the mode nor write a rule: the gate's own directory is a
# deny target for every file-writing tool, under both hosts (decide_write). push and gh are never freed, and a
# freed form stops being free the moment the repository's program-selecting state changes, because every rule
# carries the digest of that state at the time a human wrote it (DECISIONS.md D25). There is no click path: owner
# choice A of Nachtrag 31 measures the host's approval behaviour by running the host first, and until that is
# measured the stricter rule-file mechanism stands alone.

_GATE_MODES = ("strict", "with-approvals")
MAX_MODE_BYTES = 64
MAX_RULES_BYTES = 64 * 1024
MAX_RULES = 256
MAX_HOOK_BYTES = 4 * 1024 * 1024
_RULE_KEYS = frozenset({"repo", "form", "effect", "state_digest"})
_RULE_EFFECTS = ("free", "ask")
GATE_STATE_SCHEMA = "proofbundle-plugin/gate-state/v1"
#: Environment names, beside every GIT_* name, that select the programs or configuration a git call runs with.
_DIGEST_ENV_EXTRA = frozenset({"PATH", "HOME", "XDG_CONFIG_HOME", "PAGER", "EDITOR", "VISUAL", "SSH_ASKPASS"})


def _gate_dir(environ: dict) -> str | None:
    """The absolute directory that holds the approval mode, the human-written rules and the audit log, or None.
    `$PROOFBUNDLE_GATE_DIR` when it is an absolute path, else `$XDG_CONFIG_HOME/proofbundle` or ~/.config/
    proofbundle (owner card 3, stricter default: user-wide, never inside a repository). A relative override, or
    no home at all, yields None, and the gate stays strict: a file the model could reach through the repository
    it works in, or by a relative path, is not a human-only location."""
    override = environ.get("PROOFBUNDLE_GATE_DIR")
    if override:
        return override if os.path.isabs(override) else None
    base = environ.get("XDG_CONFIG_HOME")
    if base and os.path.isabs(base):
        return os.path.join(base, "proofbundle")
    home = environ.get("HOME")
    if home and os.path.isabs(home):
        return os.path.join(home, ".config", "proofbundle")
    return None


def _read_mode(environ: dict) -> str:
    """The approval mode a human set: "strict" (the default) or "with-approvals". Anything the gate cannot read
    as one of those two words — no directory, no file, an unreadable or oversized file, an unknown word — is
    strict. The mode is set only by a human at the gate directory; the model cannot write it, because
    decide_write denies every write to that directory (N24 Punkt 3)."""
    directory = _gate_dir(environ)
    if directory is None:
        return "strict"
    try:
        with open(os.path.join(directory, "mode"), "rb") as handle:
            raw = handle.read(MAX_MODE_BYTES + 1)
    except OSError:
        return "strict"
    if len(raw) > MAX_MODE_BYTES:
        return "strict"
    word = raw.decode("utf-8", "replace").strip()
    return word if word in _GATE_MODES else "strict"


def _read_rules(environ: dict) -> list[dict]:
    """The human-written rules, each a dict with exactly {repo, form, effect, state_digest}; [] on any problem
    (no directory, an unreadable or oversized file, JSON that is not a list, a repeated key at any depth, too
    many rules, a malformed entry, a non-absolute repo or an empty form). Fail-closed: a rule file the gate
    cannot read in full as a list of well-formed rules frees nothing. The gate only ever reads this file."""
    directory = _gate_dir(environ)
    if directory is None:
        return []
    try:
        with open(os.path.join(directory, "rules.json"), "rb") as handle:
            raw = handle.read(MAX_RULES_BYTES + 1)
    except OSError:
        return []
    if len(raw) > MAX_RULES_BYTES:
        return []
    try:
        data = strict_json(raw)   # a repeated key at any depth is AmbiguousJSON, a ValueError
    except (ValueError, UnicodeDecodeError):
        return []
    if not isinstance(data, list) or len(data) > MAX_RULES:
        return []
    rules: list[dict] = []
    for item in data:
        if not isinstance(item, dict) or set(item) != _RULE_KEYS:
            return []
        if not (isinstance(item["repo"], str) and os.path.isabs(item["repo"])
                and isinstance(item["form"], str) and item["form"].strip()
                and item["effect"] in _RULE_EFFECTS and isinstance(item["state_digest"], str)):
            return []
        rules.append(item)
    return rules


def _config_value(entries: list, key: str) -> str | None:
    """The effective value of a lower-cased config key from _config_entries (git's last value wins), or None."""
    value = None
    for _scope, _origin, name, raw in entries:
        if name.lower() == key:
            value = raw
    return value


def _bound_state_digest(directory: str, deadline: float, environ: dict | None = None) -> str | None:
    """The hex sha256 of the program-selecting state of the repository at directory, or None when any part
    cannot be read (so the gate asks). It binds a human rule to the state at the time the rule was written: the
    effective git configuration, the effective hook directory (each entry's name, permission bits and content
    hash, core.hooksPath included because git resolves it into this directory), the gitattributes git honours
    (info/attributes and core.attributesFile) and the GIT_* and program-selecting environment (PATH included).
    A change to any of these — a new hook, an edited config, a prepended PATH — changes the digest, so the rule
    stops acting and the gate asks again (N24 Punkt 4). Computed the same way by the `state-digest` CLI a human
    runs and by the gate on every call, so the two compare."""
    environ = os.environ if environ is None else environ
    paths, _why = _repo_paths(directory, deadline)
    if paths is None or paths["common"] is None:
        return None
    entries, _why = _config_entries(directory, deadline)
    if entries is None:
        return None
    common = os.path.realpath(paths["common"])
    hooks_dir = paths["hooks"]
    hooks: list = []
    if hooks_dir and os.path.isdir(hooks_dir):
        try:
            names = sorted(os.listdir(hooks_dir))
        except OSError:
            return None
        for name in names:
            full = os.path.join(hooks_dir, name)
            try:
                info = os.stat(full)   # follows a symlink to its target, so a redirected hook changes the hash
            except OSError:
                return None
            if not stat.S_ISREG(info.st_mode):
                hooks.append([name, oct(stat.S_IMODE(info.st_mode)), "nonfile"])
                continue
            try:
                with open(full, "rb") as handle:
                    content = handle.read(MAX_HOOK_BYTES + 1)
            except OSError:
                return None
            marker = "toolarge" if len(content) > MAX_HOOK_BYTES else hashlib.sha256(content).hexdigest()
            hooks.append([name, oct(stat.S_IMODE(info.st_mode)), marker])
    attrs: list = []
    attrs_file = _config_value(entries, "core.attributesfile")
    for label, path in (("info/attributes", os.path.join(common, "info", "attributes")),
                        ("core.attributesFile", os.path.expanduser(attrs_file) if attrs_file else None)):
        if path is None:
            attrs.append([label, "none"])
            continue
        try:
            with open(path, "rb") as handle:
                attrs.append([label, hashlib.sha256(handle.read()).hexdigest()])
        except FileNotFoundError:
            attrs.append([label, "absent"])
        except OSError:
            return None
    env = sorted((name, value) for name, value in environ.items()
                 if name.startswith("GIT_") or name in _DIGEST_ENV_EXTRA)
    document = {"schema": GATE_STATE_SCHEMA, "repo": common,
                "config": [[scope, origin, key, value] for scope, origin, key, value in entries],
                "hooks_dir": os.path.realpath(hooks_dir) if hooks_dir else None,
                "hooks": hooks, "attributes": attrs, "env": [[name, value] for name, value in env]}
    return hashlib.sha256(json.dumps(document, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def _rule_candidate(command: str, cwd: str, deadline: float) -> tuple[str, str] | None:
    """(repo, form) when command is exactly one plain local git form a human rule may free — a bare
    `git <local-subcommand> …` with no prefix assignment and no global option, acting on the repository at cwd —
    else None. repo is that repository's git-common-dir (realpath); form is the command's own text, stripped. A
    push, a gh call, an unknown or transfer-capable subcommand, a program-path invocation, a chain, a pipe, a
    wrapper, a substitution, a comment-bearing form, or any global option (`-C`, `-c`, …) yields None, so a rule
    can never free them: push and gh are never freeable, and the state digest binds only the plain form's
    repository (N24)."""
    calls = gated_calls(command)
    if len(calls) != 1 or _net_words(command) > 1:
        return None
    name, _directory, detail = calls[0]
    if detail != [_NOT_FREE] or not name.startswith("git ") or name in ("git", "git --version"):
        return None
    toks = _lex(_drop_comments(command))
    if toks is None or any(t[0] == "op" for t in toks) or _expansion_present(command):
        return None
    words = [t[1] for t in toks if t[0] == "word"]
    if len(words) < 2 or words[0] != "git" or words[1].startswith("-"):
        return None
    if words[1] not in _GIT_LOCAL_SUBCOMMANDS or f"git {words[1]}" != name:
        return None
    paths, _why = _repo_paths(cwd, deadline)
    if paths is None or paths["common"] is None:
        return None
    return os.path.realpath(paths["common"]), command.strip()


def _match_rule(command: str, cwd: str, deadline: float, environ: dict) -> tuple[str, dict] | None:
    """How a human rule bears on command under with-approvals mode and a non-codex host: ("free", rule) when a
    rule frees this exact form in this repository and the bound-state digest still matches; ("ask", rule) when a
    rule names this form with effect "ask" (a human forcing a question even in with-approvals mode, which wins
    over any freeing rule); None when no rule applies, when the digest no longer matches, or when it cannot be
    computed — the gate then asks as usual."""
    candidate = _rule_candidate(command, cwd, deadline)
    if candidate is None:
        return None
    repo, form = candidate
    matching = [rule for rule in _read_rules(environ)
                if rule["form"].strip() == form and os.path.realpath(rule["repo"]) == repo]
    if not matching:
        return None
    forced = next((rule for rule in matching if rule["effect"] == "ask"), None)
    if forced is not None:
        return ("ask", forced)
    # The digest is computed from the directory the command runs in, the same way the `state-digest` CLI computes
    # it from the repository a human points it at; computing it from the git-common-dir instead would read a
    # different configuration and never match.
    digest = _bound_state_digest(cwd, deadline, environ)
    if digest is None:
        return None
    freeing = next((rule for rule in matching
                    if rule["effect"] == "free" and rule["state_digest"] == digest), None)
    return ("free", freeing) if freeing is not None else None


def _approved_outcome(rule: dict) -> "Outcome":
    """The free outcome for a call a human rule frees: a `pass`, with an applied-rule note for the log."""
    detail = (f"proofbundle gate: a human rule frees this form in with-approvals mode. Approved form "
              f"{rule['form']!r} in {rule['repo']}; the gate recomputed the repository's program-selecting state "
              f"(configuration, hooks, gitattributes and the GIT_* environment) and it matches the digest the "
              f"rule carries. The gate asks again if that state changes; push and gh are never freed, and the "
              f"model can neither set the mode nor write a rule (N24; DECISIONS.md D25).")
    verdict = Verdict("pass", detail, "approved_by_rule", repo=rule["repo"])
    applied = {"origin": "rule", "repo": rule["repo"], "form": rule["form"], "effect": "free", "state_match": True}
    return Outcome("pass", verdict.text(), [verdict], applied_rule=applied)


def _within_gate_dir(path: str, cwd: str, gate_dir: str) -> str | None:
    """Why path is the gate directory itself or a file inside it — lexically and after resolving symlinks — or
    None. A relative path with no known cwd is None (the general write path handles an unresolvable target)."""
    if not os.path.isabs(path):
        if not (isinstance(cwd, str) and os.path.isabs(cwd)):
            return None
        path = os.path.join(cwd, path)
    roots = {os.path.normpath(gate_dir), os.path.realpath(gate_dir)}
    for candidate in {os.path.normpath(path), os.path.realpath(path)}:
        for root in roots:
            if candidate == root or candidate.startswith(root.rstrip(os.sep) + os.sep):
                return f"{candidate} is the gate directory {gate_dir} or a file inside it"
    return None


class Outcome:
    """The combined answer for one call: the decision, its text, the verdict of every repository, and, when a
    human rule freed the call, the applied-rule note for the log (N24)."""

    __slots__ = ("decision", "text", "verdicts", "applied_rule")

    def __init__(self, decision: str, text: str, verdicts: list, applied_rule: dict | None = None):
        self.decision, self.text, self.verdicts, self.applied_rule = decision, text, verdicts, applied_rule

    def __iter__(self):
        return iter((self.decision, self.text))


def decide(command: str, cwd: str, deadline: float, host: str = "claude",
           environ: dict | None = None) -> Outcome | None:
    """None for a call the gate does not gate, else the combined outcome. Under Codex the judge cannot bind
    a gated shell call to the directory it runs in, so it reports it NOT MEASURED (review Runde 5, R5-2).
    The former free list for local git commands has been removed. Those forms are NOT MEASURED, asked under
    Claude Code and denied under Codex. Only the exact bare command text `git --version` is exempt from
    judgment as a git form. The separate push path remains. Under Claude Code it may return `pass` or
    `inactive` after its checks; under Codex every push is denied because its execution context is unbound
    (review Runde 9, owner choice B; wording of review Runde 10, R10-3).

    After the structured scan, a safety net always runs (review Runde 12, R12-1 and R12-2): it builds a normal
    form of the whole command text — comments and substitutions included, quotes and backslashes removed, every
    ANSI-C quote $'…' evaluated to the bytes bash runs, only A to Z lower-cased in place — and counts the command
    words that name git or gh. Every such word must correspond to a call the scan resolved; a word it did not
    account for, whether the scan found nothing or found fewer calls than the net sees, is NOT MEASURED, never a
    pass or an inactive gate. The net also reports NOT MEASURED a form whose executed bytes it cannot build
    exactly like bash — a locale quote $"…", whose translation it cannot read (Nachtrag 33, K1) — even when no
    git/gh word is visible. An overmatch asks under Claude Code and denies under Codex. The one exemption stays
    the exact bare `git --version`.

    One repository-asking form can become free (Nachtrag 24): in "with-approvals" mode (a human set it at the
    gate directory) and never under Codex, a human rule may free exactly one plain local git form, bound by a
    digest to the repository's program-selecting state. push and gh never reach this path; a rule with effect
    "ask", a digest that no longer matches, strict mode, Codex, or no rule at all all fall through to the normal
    decision, which asks. The model can neither set the mode nor write a rule."""
    environ = os.environ if environ is None else environ
    calls = gated_calls(command)
    net_call = ("git or gh (a form the gate does not model)", UNKNOWN, [_NET])
    if _BARE_VERSION.fullmatch(command):
        return _judge(calls, cwd, deadline, host) if calls else None
    if host != "codex" and _read_mode(environ) == "with-approvals":
        applied = _match_rule(command, cwd, deadline, environ)
        if applied is not None and applied[0] == "free":
            return _approved_outcome(applied[1])
    nw = _net_words(command)
    unresolved = _net_unresolved(command)
    if not calls:
        return _judge([net_call], cwd, deadline, host) if (nw >= 1 or unresolved) else None
    if nw > len(calls) or unresolved:
        return _judge(list(calls) + [net_call], cwd, deadline, host)
    return _judge(calls, cwd, deadline, host)


def mcp_gated(tool: str) -> bool:
    return re.fullmatch(MCP_MATCHER, tool) is not None


def decide_mcp(tool: str, cwd: str, deadline: float, host: str = "claude") -> Outcome | None:
    """None for an MCP tool the gate does not gate; else NOT MEASURED, ask under Claude and deny under Codex
    (review Runde 6, R6-1). A gated MCP write acts on a remote target with bytes from its own arguments; the
    hook binds neither, so the local repository at cwd never decides the call — not pass, not inactive, not
    deny for a foreign target. Its HEAD is still checked, as a diagnosis named in the text only. Every gated
    MCP call therefore gets a permission decision; none ends without one."""
    if not mcp_gated(tool):
        return None
    unseen = _MCP_UNSEEN.get(tool.rsplit("__", 1)[-1], "it cannot see the branch the tool publishes")
    local = _judge([(f"MCP {tool}", ".", None)], cwd, deadline).verdicts
    diag = local[0] if local else None
    diagnosis = (f"'{diag.decision}' ({diag.reason_id}): {diag.detail}" if diag is not None
                 else "no verdict was reached")
    decision = "deny" if host == "codex" else "ask"
    verdict = Verdict(decision, f"NOT MEASURED: the MCP tool {tool} acts on a remote target with bytes from its own "
                                f"arguments, and the gate binds neither that target nor those bytes, so it checked "
                                f"nothing about what the tool publishes ({unseen}). Diagnosis only, not a verdict on "
                                f"this call: the local repository at {cwd}, at its HEAD, reads {diagnosis}",
                      "mcp_target_unbound", evidence=f"the remote target and the bytes {tool} writes",
                      failed="the hook binds neither the tool's actual target nor the bytes it writes",
                      next_step="have a person review the call, or publish through a `git push` the gate resolves")
    return Outcome(decision, verdict.text(), [verdict])


#: File-writing tools the gate judges (Nachtrag 19b, Punkt 6/7): Claude Code's Write, Edit, MultiEdit and
#: NotebookEdit, and Codex's apply_patch, whose PreToolUse input is {"command": <the raw patch>} (Codex at
#: 14a477ea, codex-rs/core/src/tools/handlers/apply_patch.rs, lines 289-295 and 414-419; its hook matcher
#: aliases are Write and Edit, codex-rs/core/src/tools/hook_names.rs, lines 34-39).
FILE_WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch"})
_PATCH_TARGETS = ("*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: ")
_PATCH_FRAME = ("*** Begin Patch", "*** End Patch", "*** End of File")


def _write_targets(tool: str, tool_input: object) -> list[str] | None:
    """The paths one file-tool call writes, or None when the gate cannot tell them for sure. A patch that
    names an environment (`*** Environment ID:`) writes into a filesystem the hook does not see (Codex
    parser.rs, line 8), and any `***` line the gate does not recognise could name a file, so both are None."""
    if not isinstance(tool_input, dict):
        return None
    if tool == "apply_patch":
        patch = tool_input.get("command")
        if not isinstance(patch, str):
            return None
        targets = []
        for line in patch.splitlines():
            text = line.strip()
            if not text.startswith("***"):
                continue
            marker = next((m for m in _PATCH_TARGETS if text.startswith(m.strip()) and
                           text[len(m.strip()):len(m.strip()) + 1] in (" ", "")), None)
            if marker is not None:
                path = text[len(marker.strip()):].strip()
                if not path:
                    return None
                targets.append(path)
            elif text not in _PATCH_FRAME:
                return None   # `*** Environment ID: …`, or a line the gate cannot read
        return targets
    path = tool_input.get("notebook_path" if tool == "NotebookEdit" else "file_path")
    return [path] if isinstance(path, str) and path else None


def _state_files(directory: str, deadline: float) -> tuple[set, set, str]:
    """(files, directories, problem): the configuration files and hook directory that select programs for
    the repository at directory, as git resolves them with the hook's environment — every file the effective
    configuration was read from, every file it includes from any origin (also one that is empty or does not
    exist yet: git skips a missing include, so a write would add configuration; an include from the command
    scope a host injects through GIT_CONFIG_COUNT counts as one from a file, review Runde 7, R7-5), the default
    global and system files, $GIT_DIR/config, config.worktree and commondir (also a missing one, review Runde 8,
    R8-4), a `.git` file that points to the repository, and the effective hook directory."""
    files, dirs = set(), set()
    entries, why = _config_entries(directory, deadline)
    if entries is None:
        return files, dirs, f"the effective configuration cannot be read ({why})"
    paths, why = _repo_paths(directory, deadline)
    if paths is None:
        return files, dirs, f"the repository layout cannot be read ({why})"
    base = paths["toplevel"] or directory
    for _scope, origin, key, value in entries:
        source = None
        if origin.startswith("file:"):
            source = os.path.join(base, os.path.expanduser(origin[5:]))
            files.add(source)
        k = key.lower()
        if value and (k == "include.path" or (k.startswith("includeif.") and k.endswith(".path"))):
            included = os.path.expanduser(value)
            if source is not None:
                files.add(os.path.join(os.path.dirname(source), included))
            elif os.path.isabs(included):
                files.add(included)   # an include from the command scope or standard input names its file
            else:   # git-config(1): a relative include must come from a file, so git itself refuses it
                return files, dirs, f"the include {value!r} from {origin or 'an unnamed origin'} names no file"
    home = os.path.expanduser("~")
    for name in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"):   # git-var(1): the files git itself would use
        named = _git(directory, "var", name, deadline=deadline)
        if named.returncode == 0:
            files.update(p for p in named.stdout.decode("utf-8", "replace").splitlines() if p and p != os.devnull)
    for name, default in (("GIT_CONFIG_GLOBAL", None), ("GIT_CONFIG_SYSTEM", "/etc/gitconfig")):
        value = os.environ.get(name)
        if value and value != os.devnull:
            files.add(value)
        elif value is None and default:
            files.add(default)
    if os.environ.get("GIT_CONFIG_GLOBAL") is None:
        files.add(os.path.join(home, ".gitconfig"))
        files.add(os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config"), "git", "config"))
    for root in {paths["common"], paths["gitdir"]} - {None}:
        # commondir (gitrepository-layout(5)) names the directory git takes the shared configuration and hooks
        # from, so a write to it, also one that creates it, redirects them (review Runde 8, R8-4)
        files.update({os.path.join(root, "config"), os.path.join(root, "config.worktree"),
                      os.path.join(root, "commondir")})
    if paths["toplevel"] and os.path.isfile(os.path.join(paths["toplevel"], ".git")):
        files.add(os.path.join(paths["toplevel"], ".git"))
    if paths["hooks"]:
        dirs.add(paths["hooks"])
    return files, dirs, ""


def _nearest_directory(path: str) -> str:
    while not os.path.isdir(path):
        path = os.path.dirname(path)
    return path


def _protected_write(path: str, cwd: str, deadline: float) -> str | None:
    """Why a write to path touches the configuration or hooks of the repository the path is in or the bound
    repository at cwd; None for an ordinary file. The path counts both as written (lexically: a hook path that
    is a symlink to a file outside is still a hook path) and resolved (symlinks followed), and a resolved target
    counts when it is, or is the same file as, a configuration file, an entry of the hook directory or the
    resolved target of such an entry (a hook symlinked to a file outside, or a hard link to a hook; review
    Runde 7, R7-5)."""
    if not os.path.isabs(path):
        if not (isinstance(cwd, str) and os.path.isabs(cwd)):
            return f"the relative path {path!r} cannot be resolved without a known directory"
        path = os.path.join(cwd, path)
    lexical, target = os.path.normpath(path), os.path.realpath(path)
    anchors = {_nearest_directory(target), _nearest_directory(lexical)}
    files, dirs = set(), set()
    for directory in anchors | ({os.path.realpath(cwd)} if isinstance(cwd, str) and os.path.isdir(cwd) else set()):
        more_files, more_dirs, problem = _state_files(directory, deadline)
        if problem:
            return f"{problem}, so the gate cannot tell whether {target} is part of it"
        files |= more_files
        dirs |= more_dirs
    def same(a: str, b: str) -> bool:
        return a == b or (os.path.exists(a) and os.path.exists(b) and os.path.samefile(a, b))

    for f in files:
        if lexical == os.path.normpath(f) or target == os.path.realpath(f):
            return f"{lexical} is the git configuration file {f}"
        if same(target, os.path.realpath(f)):
            return f"{target} is the same file as the git configuration file {f}"
    for d in dirs:
        for root in {os.path.normpath(d), os.path.realpath(d)}:
            # The lexical path is a second lock: a hook entry is also caught by the resolved target against both
            # roots and by the entry identity below (review Runde 8, R8-3).
            for candidate in (lexical, target):
                if candidate == root or candidate.startswith(root.rstrip(os.sep) + os.sep):
                    return f"{candidate} is in the hook directory {d}"
        try:
            entries = [os.path.join(d, name) for name in os.listdir(d)]
        except FileNotFoundError:
            continue
        except OSError as exc:
            return f"the hook directory {d} cannot be listed ({exc.strerror or exc}), so the gate cannot tell"
        for hook in entries:
            if same(target, os.path.realpath(hook)):
                return f"{target} is the file the hook entry {hook} resolves to"
    return None


def decide_write(tool: str, tool_input: object, cwd: str, deadline: float, host: str = "claude",
                 environ: dict | None = None) -> Outcome | None:
    """None for a file-tool write the gate does not gate; else NOT MEASURED, ask under Claude and deny under
    Codex (Nachtrag 19b, Punkt 6): a write to the configuration or the hooks of a repository changes which
    programs later git calls run, and a path the gate cannot map for sure is treated the same way.

    A write to the gate's own directory (the approval mode, the human-written rules, the audit log) is denied
    under both hosts (Nachtrag 24, Punkt 3): the model must never be able to set the mode, create or change an
    approval, or edit the log. This check runs before the host split, so Codex and Claude alike deny it.

    Under Codex every other file-tool write is NOT MEASURED and denied (review Runde 7, R7-6): an apply_patch
    without `*** Environment ID:` writes into the turn's primary environment (codex-rs/core/src/tools/handlers/
    mod.rs at 14a477ea, resolve_tool_environment, lines 160-178), which need not be the filesystem and directory
    of the hook's cwd, and the hook input carries nothing that binds the two. A missing environment line is no
    proof of binding, so the gate cannot tell for any path whether it is configuration or a hook."""
    environ = os.environ if environ is None else environ
    gate_dir = _gate_dir(environ)
    targets = _write_targets(tool, tool_input)
    if gate_dir is not None and targets is not None:
        for target in (targets or []):
            why = _within_gate_dir(target, cwd, gate_dir)
            if why:
                verdict = Verdict("deny", f"the gate's own directory holds the approval mode, the human-written "
                                          f"rules and the audit log, so {tool} must never write it: the model "
                                          f"cannot set the mode, create or change an approval, or edit the log. "
                                          f"{why}.",
                                  "write_to_gate_dir", evidence="the gate mode, rules and log",
                                  failed=f"{tool} would write {target} inside the gate directory {gate_dir}",
                                  next_step="a human edits the gate's mode and rules directly, outside the agent")
                return Outcome("deny", verdict.text(), [verdict])
    if host == "codex":
        why = (f"under Codex the hook does not bind {tool} to the filesystem and directory the write acts in: an "
               "apply_patch without `*** Environment ID:` writes into the turn's primary environment, which need "
               "not be the hook's directory, and a missing environment line is no proof of binding")
        verdict = Verdict("deny", f"NOT MEASURED: {why}, so the gate cannot tell whether the write touches the "
                                  "configuration or hooks of a git repository.",
                          "codex_write_unbound", evidence="the filesystem, directory and files the write acts on",
                          failed="the Codex hook does not carry the environment and directory of a file write",
                          next_step="make the change under a host whose hook binds the write's directory, or have "
                                    "a person make it")
        return Outcome("deny", verdict.text(), [verdict])
    reasons = [f"the gate cannot tell for sure which files this {tool} call writes"] if targets is None else []
    for target in targets or []:
        try:
            why = _protected_write(target, cwd, deadline)
        except GateError as exc:
            why = f"{exc}, so the gate cannot tell whether {target} is configuration or a hook"
        if why:
            reasons.append(why)
    if not reasons:
        return None
    decision = "deny" if host == "codex" else "ask"
    verdict = Verdict(decision, f"NOT MEASURED: {tool} would write the configuration or hooks of a git repository, "
                                f"which select the programs later git calls run: {'; '.join(reasons)}.",
                      "write_to_repo_state", evidence="the configuration files and hook directory the write touches",
                      failed="; ".join(reasons),
                      next_step="change git configuration and hooks yourself, or have a person review the write")
    return Outcome(decision, verdict.text(), [verdict])


def _evaluate_call(name: str, directory: str, detail: list[str] | None, deadline: float) -> Verdict:
    """The verdict for one gated call: a shell `git push` resolves its targets and the commits it sends; a
    `gh pr/release create` is judged as a push of the current branch to its upstream; an MCP tool, whose
    remote target the gate cannot read, is judged at HEAD with no range comparison."""
    if detail and detail[0] == _HOOKS_DISABLE:
        return Verdict("deny", f"the command would turn off the gate's check of the real push, so it is denied.",
                       "hooks_disabled",
                       evidence="none, the command would disable the pre-push verification",
                       failed=f"{name} would skip or redirect the hook that verifies the real push "
                              "(--no-verify, or a core.hooksPath override)",
                       next_step="push without --no-verify and without setting core.hooksPath, or obtain a human review")
    if name == "git push":
        return evaluate_push(directory, detail, deadline)
    if name.startswith("gh "):
        return evaluate_push(directory, detail, deadline)
    return evaluate_repository(directory, deadline)


def _judge(calls: list[tuple[str, str | None, list[str] | None]], cwd: str, deadline: float,
           host: str = "claude", extra: list | None = None) -> Outcome:
    verdicts = list(extra or [])
    seen = set()
    for name, directory, detail in calls:
        # realpath, not normpath: a `git -C` walks the filesystem physically through symlinks, so the gate
        # must too, or `git -C link/..` names a different repository than a string normalisation would (R4-2).
        resolved = directory if directory is UNKNOWN else os.path.realpath(os.path.join(cwd, directory))
        key = (name, resolved, tuple(detail) if detail is not None else None)
        if key in seen:
            continue
        seen.add(key)
        if detail and detail[0] == _HOOKS_DISABLE:
            # a hook-disabling form denies whatever the directory is, so a `--no-verify` or a core.hooksPath
            # override inside a chain (where the directory is NOT MEASURED) still denies, not merely asks.
            verdicts.append(_evaluate_call(name, resolved, detail, deadline))
            continue
        if host == "codex" and (name == "git push" or name.startswith("gh ")):
            # R5-2: under Codex the hook receives the session directory and the command text, not the
            # execution workdir or a remote environment, so a push Ebene 1 would otherwise resolve could be
            # judged against a different repository. Owner choice (02.10): such pushes are NOT MEASURED.
            verdicts.append(Verdict(
                "ask", f"NOT MEASURED: under Codex the gate cannot bind {name} to the directory and "
                       "environment it runs in. The hook receives the session directory and the command "
                       "text, not the execution workdir or a remote environment, so it could judge a "
                       "different repository than the push acts on.",
                "codex_context_unbound", evidence=f"the repository and target {name} acts on",
                failed="the Codex hook does not carry the command's working directory (workdir) or a "
                       "remote environment",
                next_step="run the push under a host that binds the execution directory to the gate, or have "
                          "a person review the push"))
            continue
        if detail == [_NET]:
            verdicts.append(Verdict(
                "ask", "NOT MEASURED: the safety net found a git or gh command word, or a quote whose executed "
                       "bytes it cannot build exactly like bash (a locale quote $\"…\" whose translation it cannot "
                       "read), that the gate's structured scan did not account for. A shell form Level 1 does not "
                       "model — an unsupported quote or substitution, a comment under a changed comment character, "
                       "a program name in a different letter case, or a word built by an expansion — is reported "
                       "NOT MEASURED rather than let it pass unchecked (review Runde 11, owner choice A; Nachtrag "
                       "33, K1).",
                "net_unmodeled_git", evidence="a git or gh command, or an unevaluable quote, the gate could not resolve",
                failed="the structured scan produced no gated call for a git/gh command word or an unevaluable "
                       "quote present in the text",
                next_step="run the call in a plain form the gate resolves (a single `git`/`gh` command, no "
                          "unusual quoting, substitution or letter case), or have a person review it"))
            continue
        if detail == [_NOT_FREE]:
            verdicts.append(Verdict(
                "ask", f"NOT MEASURED: the gate gives no free answer for {name}. A git form that acts on a repository "
                       "can start another program through its options, the repository's configuration and "
                       "configured values, its hooks or an indirect path such as automatic maintenance, and the gate "
                       "does not model them (owner choice B, review Runde 9; DECISIONS.md D3).",
                "git_form_not_free", evidence="none, the gate reads no repository state for a git form",
                failed=f"{name} may start a program the gate does not see",
                next_step="have a person review the call, or run it yourself outside the agent"))
            continue
        if detail == [_MAYBE_PUSH]:
            verdicts.append(Verdict(
                "ask", f"NOT MEASURED: {name} may transfer objects to a remote, or run another program that "
                       "does, through a form Ebene 1 does not model (an unrecognised git subcommand such as "
                       "send-pack, a per-command -c, a rebase --exec, an option or an environment or "
                       "configuration setting that selects a helper, filter, hook, editor or pager, or another "
                       "transport); the gate checked nothing.",
                "possible_unmodeled_push", evidence="the commits and refs this command might send",
                failed="the command is not one strict push form the gate resolves",
                next_step="use a plain `git push <remote> <refspec>` whose target this repository tracks, or "
                          "have a person review the command"))
            continue
        if resolved is UNKNOWN:
            verdicts.append(Verdict("ask", f"NOT MEASURED: the gate cannot tell which repository {name} acts on "
                                           "(a directory change or a git option it does not resolve).",
                                    "directory_unresolved", evidence=f"unknown, the repository {name} acts on",
                                    failed="the gate cannot resolve the directory",
                                    next_step="run the call in the repository's directory, with a literal path"))
            continue
        try:
            verdicts.append(_evaluate_call(name, resolved, detail, deadline))
        except GateError as exc:
            verdicts.append(Verdict("deny", f"proofbundle gate: {exc}. The call is denied because the gate reached "
                                            "no verdict.", "gate_error",
                                    evidence=f"the declaration {DECLARATION} and the evidence it names",
                                    failed=str(exc),
                                    next_step="fix the cause named here; the gate denies until it reaches a verdict",
                                    repo=resolved))
    for decision in ("deny", "ask"):
        chosen = [v for v in verdicts if v.decision == decision]
        if chosen:
            return Outcome(decision, " ".join(v.text() for v in chosen), verdicts)
    combined = "pass" if all(v.decision == "pass" for v in verdicts) else "inactive"
    return Outcome(combined, " ".join(v.text() for v in verdicts), verdicts)


# --- the host's hook protocol ------------------------------------------------------------------------

def _command_from_event(event: object) -> tuple[str, str]:
    if not isinstance(event, dict) or not isinstance(event.get("tool_input"), dict):
        raise GateError("the hook input is not a tool event")
    command = event["tool_input"].get("command")
    if isinstance(command, list) and all(isinstance(w, str) for w in command):
        command = shlex.join(command)
    if not isinstance(command, str):
        raise GateError("the hook input carries no shell command")
    cwd = event.get("cwd")
    return command, cwd if isinstance(cwd, str) and cwd else os.getcwd()


def answer(decision: str, reason: str, host: str = "claude") -> dict:
    """The PreToolUse answer. A pass and an inactive gate carry no permission decision, only the message.

    The reason goes to the user (systemMessage) and to the model (additionalContext) as well as into
    permissionDecisionReason, because a host shows the reason of an "ask" to the user only. Every field
    used here is one both hosts accept; Codex rejects an answer with any other field, and a
    permissionDecisionReason without a permissionDecision.
    """
    if decision == "ask" and host == "codex":
        decision, reason = "deny", reason + " Codex cannot ask, so the gate denies the call."
    specific = {"hookEventName": "PreToolUse", "additionalContext": reason}
    if decision not in ("pass", "inactive"):
        specific.update(permissionDecision=decision, permissionDecisionReason=reason)
    return {"systemMessage": reason, "hookSpecificOutput": specific}


def tree_digest_command(argv: list[str]) -> int:
    """`tree-digest [--repo DIR] [--rev REV] [--statement]`: the producer's side of the binding."""
    options, statement, i = {"--repo": ".", "--rev": "HEAD"}, False, 0
    while i < len(argv):
        if argv[i] == "--statement":
            statement, i = True, i + 1
        elif argv[i] in options and i + 1 < len(argv):
            options[argv[i]], i = argv[i + 1], i + 2
        else:
            print(f"usage: tree-digest [--repo DIR] [--rev REV] [--statement]; unknown {argv[i]!r}", file=sys.stderr)
            return 2
    try:
        digest = tree_digest(options["--repo"], options["--rev"])
    except GateError as exc:
        print(f"tree-digest: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write((subject_statement(digest).decode() if statement else digest) + "\n")
    return 0


def state_digest_command(argv: list[str]) -> int:
    """`state-digest [--repo DIR]`: print the bound-state digest a human puts in a rule, with the repository's
    canonical path and a ready rule skeleton. The gate recomputes this digest on every call and frees the form
    only while it matches, so a human runs this in the same environment the agent runs in (Nachtrag 24)."""
    options, i = {"--repo": "."}, 0
    while i < len(argv):
        if argv[i] in options and i + 1 < len(argv):
            options[argv[i]], i = argv[i + 1], i + 2
        else:
            print(f"usage: state-digest [--repo DIR]; unknown {argv[i]!r}", file=sys.stderr)
            return 2
    deadline = time.monotonic() + DEADLINE_SECONDS
    paths, why = _repo_paths(options["--repo"], deadline)
    if paths is None or paths["common"] is None:
        print(f"state-digest: not a git repository, or its layout cannot be read ({why or options['--repo']})",
              file=sys.stderr)
        return 1
    digest = _bound_state_digest(options["--repo"], deadline)
    if digest is None:
        print("state-digest: the program-selecting state cannot be read in full, so there is no digest; the gate "
              "will ask for every form in this repository", file=sys.stderr)
        return 1
    skeleton = {"repo": os.path.realpath(paths["common"]), "form": "git <the exact command to free>",
                "effect": "free", "state_digest": digest}
    sys.stdout.write(digest + "\n")
    sys.stdout.write(json.dumps(skeleton, indent=2, sort_keys=True) + "\n")
    return 0


def log_directory(host: str, environ: dict | None = None) -> str | None:
    """The first plugin data directory the host names that is, or can be made, a writable directory."""
    environ = os.environ if environ is None else environ
    for name in LOG_DIR_VARIABLES.get(host, ()):
        value = environ.get(name)
        if not value or not os.path.isabs(value):
            continue
        try:
            os.makedirs(value, exist_ok=True)
        except OSError:
            continue
        if os.path.isdir(value) and os.access(value, os.W_OK):
            return value
    return None


def log_entry(host: str, event: object, outcome: "Outcome | None", actions: list[str],
              environ: dict | None = None) -> dict:
    """What one call leaves in the log: no evidence content, no environment, no key. The approval mode is
    recorded on every entry, and the applied rule (origin, repo, form, effect, state_match) when a human rule
    freed the call, so the log shows each approval and a human can audit and revoke it (Nachtrag 24, Punkt 5)."""
    environ = os.environ if environ is None else environ
    session = event.get("session_id") if isinstance(event, dict) else None
    tool = event.get("tool_name") if isinstance(event, dict) else None
    verdict = outcome.decision if outcome is not None else "not_gated"
    sent = "none" if verdict in ("pass", "inactive", "not_gated") else ("deny" if host == "codex" else verdict)
    repos = [] if outcome is None else [
        {"path": v.repo, "head": v.head, "verdict": v.decision, "reason_id": v.reason_id, "digests": list(v.digests)}
        for v in outcome.verdicts]
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "host": host, "gate_version": GATE_VERSION,
             "session_id": session if isinstance(session, str) else None,
             "tool": tool if isinstance(tool, str) else None, "actions": actions, "decision": sent,
             "verdict": verdict, "mode": _read_mode(environ),
             "reason_ids": [r["reason_id"] for r in repos] or [verdict], "repos": repos}
    if outcome is not None and outcome.applied_rule is not None:
        entry["applied_rule"] = outcome.applied_rule
    return entry


def write_log(entry: dict, host: str) -> str | None:
    """Append the entry; never raises, never changes the answer. None when no directory was writable."""
    directory = log_directory(host)
    if directory is None:
        return None
    path = os.path.join(directory, LOG_NAME)
    try:
        if os.path.exists(path) and os.path.getsize(path) > MAX_LOG_BYTES:
            os.replace(path, path + ".1")
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError:
        return None
    return path


CI_USAGE = "usage: ci-check --repo DIR --require-declaration true|false"


def ci_check(repo: str, require_declaration: bool, deadline: float | None = None) -> tuple[int, dict]:
    """The CI mode (DECISIONS.md, D22): the gate's own evaluation of HEAD, stricter than at a push.

    Exit 0 only when every declared item verified and is bound to the tree of the commit, or when nothing
    is declared and the workflow says the repository need not declare (`not_required`, which is a waiver,
    not a verified result). CI fails every required check that is NOT MEASURED; with require-declaration
    false and no declaration it returns not_required, not verified. Every deny and a missing declaration
    where one is required exit 1. Whether a declaration is required comes from the workflow, not from the
    declaration, so deleting the declaration cannot switch the check off. The push range of D20 is not read:
    in CI the reviewed state of the evidence rules is CODEOWNERS' part.
    """
    deadline = time.monotonic() + DEADLINE_SECONDS if deadline is None else deadline
    try:
        verdict = evaluate_repository(repo, deadline, check_range=False)
    except GateError as exc:
        verdict = Verdict("deny", f"proofbundle gate: {exc}. The check fails because the gate reached no verdict.",
                          "gate_error", evidence=f"the declaration {DECLARATION} and the evidence it names",
                          failed=str(exc), next_step="fix the cause named here", repo=repo)
    if verdict.decision == "pass":
        code, outcome = 0, "verified"
    elif verdict.decision == "inactive" and not require_declaration:
        code, outcome = 0, "not_required"
    elif verdict.decision == "inactive":
        code, outcome = 1, "declaration_required"
        verdict = Verdict("deny", f"proofbundle gate: the workflow requires a declaration, and {DECLARATION} is absent "
                                  f"at HEAD {verdict.head[:12]}.", "declaration_required", evidence=f"the declaration {DECLARATION}",
                          failed="the repository must declare evidence, and it declares none",
                          next_step="restore the declaration and its evidence, or change the workflow input in a "
                                    "reviewed change", repo=verdict.repo, head=verdict.head)
    else:
        code, outcome = 1, "not_measured" if verdict.detail.startswith("NOT MEASURED") else "failed"
    report = {"outcome": outcome, "exit_code": code, "require_declaration": require_declaration,
              "repo": verdict.repo, "head": verdict.head, "verdict": verdict.decision, "reason_id": verdict.reason_id,
              "digests": list(verdict.digests), "message": verdict.text(), "gate_version": GATE_VERSION}
    return code, report


def ci_check_command(argv: list[str]) -> int:
    options, i = {"--repo": None, "--require-declaration": None}, 0
    while i < len(argv):
        if argv[i] in options and i + 1 < len(argv):
            options[argv[i]], i = argv[i + 1], i + 2
        else:
            print(f"{CI_USAGE}; unknown {argv[i]!r}", file=sys.stderr)
            return 2
    if None in options.values() or options["--require-declaration"] not in ("true", "false"):
        print(CI_USAGE, file=sys.stderr)
        return 2
    code, report = ci_check(options["--repo"], options["--require-declaration"] == "true")
    sys.stdout.write(json.dumps(report, indent=1) + "\n")
    print(("proofbundle evidence check passed: " if code == 0 else "proofbundle evidence check FAILED: ")
          + report["message"], file=sys.stderr)
    return code


# --- a test run as evidence (DECISIONS.md, D23) ------------------------------------------------------

RUN_SCHEMA = "proofbundle-plugin/test-run/v1"
RUN_KEYS = frozenset({"schema", "commit", "tree_before", "tree_after", "command", "program", "exit_code", "counts",
                      "report_sha256", "started_at", "finished_at", "platform", "gate_version"})
COUNT_KEYS = frozenset({"tests", "passed", "failed", "errors", "skipped"})
RUN_TIMEOUT_SECONDS = 600.0
MAX_REPORT_BYTES = 16 * 1024 * 1024
RUN_USAGE = "usage: run-evidence --repo DIR --out FILE [--timeout SECONDS] [--junit-out FILE] -- COMMAND..."


def _count(value) -> bool:
    return type(value) is int and value >= 0


def run_record_problem(run, digest) -> str | None:
    """What a run record shows that is not a green run on the tree digest, or None for a green one.

    Green: the record has the keys of RUN_SCHEMA, ran on the digest before and after, exited 0, and its
    counts add up with no failure, no error and at least one passed test. The gate asks this of every
    signed run record, whoever made it, so a signed record of a red run never binds.
    """
    if not isinstance(run, dict) or set(run) != RUN_KEYS or run["schema"] != RUN_SCHEMA:
        return f"the signed run record is not a {RUN_SCHEMA} record"
    if not isinstance(digest, str) or run["tree_before"] != digest or run["tree_after"] != digest:
        return "the signed run record ran on another tree than its subject names"
    if type(run["exit_code"]) is not int or run["exit_code"] != 0:
        return f"the signed run record shows exit code {run['exit_code']!r}"
    counts = run["counts"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS or not all(_count(v) for v in counts.values()):
        return "the signed run record has no readable counts"
    if (counts["failed"] or counts["errors"] or counts["passed"] < 1
            or counts["tests"] != counts["passed"] + counts["failed"] + counts["errors"] + counts["skipped"]):
        return (f"the signed run record shows {counts['passed']} passed, {counts['failed']} failed and "
                f"{counts['errors']} errors of {counts['tests']} tests")
    command = run["command"]
    if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
        return "the signed run record names no command"
    return None


def signed_run_problem(kind: str, content: bytes) -> str | None:
    """For a bundle whose signed payload carries a run record: what the record shows that is not a green
    run on the tree its subject names. None for every other evidence."""
    if kind != "bundle":
        return None
    try:
        document = strict_json(content)
        statement = strict_json(base64.b64decode(document["payload_b64"], validate=True))
    except AmbiguousJSON as exc:
        return f"the evidence {exc}, so its run record is ambiguous"
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, binascii.Error):
        return None
    if not isinstance(statement, dict) or "run" not in statement:
        return None
    subject = statement.get("subject")
    return run_record_problem(statement["run"], subject.get("digest") if isinstance(subject, dict) else None)


def signed_run_counts(kind: str, content: bytes):
    """The counts of a bundle's signed run record, or None when its payload carries none. Meaningful only
    once the item has verified and run_record_problem returned None, so the counts describe a green run."""
    if kind != "bundle":
        return None
    try:
        document = strict_json(content)
        statement = strict_json(base64.b64decode(document["payload_b64"], validate=True))
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, binascii.Error):   # AmbiguousJSON included
        return None
    if not isinstance(statement, dict) or not isinstance(statement.get("run"), dict):
        return None
    counts = statement["run"].get("counts")
    return counts if isinstance(counts, dict) and {"passed", "tests"} <= set(counts) else None


#: git's object id of a blob: the hash of `blob <size>` NUL and the bytes; SHA-1 for 40 hexadecimal digits, SHA-256
#: for 64 (the repository's object format, gitrepository-layout(5) extensions.objectFormat).
_BLOB_HASHES = {40: hashlib.sha1, 64: hashlib.sha256}


def _directory_problem(root: bytes, prefix: bytes) -> str | None:
    """None when root/prefix is a real directory (lstat, so a symbolic link is not followed), else why not."""
    shown = prefix.decode(errors="replace")
    try:
        st = os.lstat(os.path.join(root, prefix))
    except OSError:
        return f"{shown}, which is absent or cannot be read in the working tree"
    if stat.S_ISLNK(st.st_mode):
        return f"{shown}, which is a symbolic link in the working tree and a directory in the commit"
    if not stat.S_ISDIR(st.st_mode):
        return f"{shown}, which is not a directory in the working tree"
    return None


def _working_tree_problem(repo: str, commit: str, deadline: float) -> str | None:
    """None when the working tree holds exactly the files of the commit's tree, outside the top-level
    .proofbundle/ folder the tree digest leaves out, else the first difference (review Runde 8, R8-1).

    The comparison is of the bytes a test run reads and of the path types it sees, not of what `git add`
    would stage: every committed file must be a regular file (mode 100644, or 100755 with the owner's execute
    bit) or a symbolic link (120000) whose own bytes, or link text, hash to the committed blob id, and no
    other file that git does not ignore may exist. No configured clean or smudge filter, line-ending or
    encoding rule, fsmonitor or hook runs, because none is asked, and no checkout transformation is modelled:
    a working file whose bytes differ from its committed blob is refused before the run, including differences
    caused by checkout transformations, never staged into agreement with HEAD (review Runde 9, R9-7). The one git call
    that lists the other files reads the ignore rules only, with an index that does not exist (so nothing
    is refreshed or written), core.fsmonitor off and an empty hook directory. Measured by the reviewer: a
    clean filter that wrote the committed value back while staging let a run on another working file be
    recorded as a run on HEAD.

    Every intermediate component of a committed path must be a real directory in the working tree, checked
    with lstat before and after the run whatever the ignore rules say; a symbolic link, any other type, a
    component that cannot be read and an empty, `.` or `..` component are refused (review Runde 9, R9-1:
    a working directory replaced by a link to an outside directory with the same leaf bytes, ignored by a
    committed `.gitignore`, gave a green run for a tree on which the same test fails)."""
    # A second lock: run_evidence's tree_digest refuses first, and the ls-tree below goes through _git (R8-3).
    _refuse_partial_clone(repo, deadline)
    listing = _git(repo, "ls-tree", "-r", "-z", "--full-tree", commit, deadline=deadline)
    if listing.returncode != 0:
        raise GateError(f"git could not list the tree of {commit[:12]}")
    committed = {}
    for record in listing.stdout.split(b"\0"):
        if not record:
            continue
        meta, tab, path = record.partition(b"\t")
        fields = meta.split(b" ")
        if not tab or len(fields) != 3:
            raise GateError("git ls-tree gave a line the gate cannot read")
        mode, kind, oid = fields
        if path.startswith(EVIDENCE_DIR.encode()):
            continue
        if kind != b"blob" or mode not in TREE_MODES or len(oid) not in _BLOB_HASHES:
            raise GateError(f"the tree holds a {kind.decode(errors='replace')} at {path.decode(errors='replace')} "
                            "that the gate cannot compare with the working tree")
        committed[path] = (mode, oid.decode("ascii"))
    root = os.fsencode(repo)
    directories: dict[bytes, str | None] = {}
    for path, (mode, oid) in sorted(committed.items()):
        shown = path.decode(errors="replace")
        parts = path.split(b"/")
        if any(part in (b"", b".", b"..") for part in parts):
            return f"{shown} has a path component the gate cannot check safely"
        for depth in range(1, len(parts)):
            prefix = b"/".join(parts[:depth])
            if prefix not in directories:
                directories[prefix] = _directory_problem(root, prefix)
            if directories[prefix] is not None:
                return f"{shown} lies below {directories[prefix]}"
        full = os.path.join(root, path)
        try:
            st = os.lstat(full)
        except OSError:
            return f"{shown} is committed but absent from the working tree"
        if mode == b"120000":
            if not stat.S_ISLNK(st.st_mode):
                return f"{shown} is a symbolic link in the commit but not in the working tree"
            data = os.readlink(full)
        else:
            if not stat.S_ISREG(st.st_mode):
                return f"{shown} is a file in the commit but not a regular file in the working tree"
            if bool(st.st_mode & stat.S_IXUSR) != (mode == b"100755"):
                return f"{shown} has another execute bit in the working tree than in the commit"
            with open(full, "rb") as handle:
                data = handle.read()
        hasher = _BLOB_HASHES[len(oid)](b"blob %d\0" % len(data))
        hasher.update(data)
        if hasher.hexdigest() != oid:
            return (f"{shown} in the working tree differs from the committed bytes (a local change, or a "
                    "checkout filter, line-ending or encoding rule the gate does not model)")
    with tempfile.TemporaryDirectory(prefix="proofbundle-untracked-") as scratch:
        os.mkdir(os.path.join(scratch, "hooks"))
        env = dict(_read_env(), GIT_INDEX_FILE=os.path.join(scratch, "no-index"))
        left = deadline - time.monotonic()
        if left <= 0:
            raise GateError("the gate ran out of time")
        try:
            proc = subprocess.run(["git", *_READ_ONLY_GIT, "-c", "core.fsmonitor=false", "-c",
                                   f"core.hooksPath={os.path.join(scratch, 'hooks')}", "-c", "core.untrackedCache=false",
                                   "-C", repo, "ls-files", "-z", "--others", "--exclude-standard"],
                                  env=env, capture_output=True, timeout=left, check=False)
        except FileNotFoundError as exc:
            raise GateError("git is not on PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise GateError("git did not answer in time") from exc
    if proc.returncode != 0:
        raise GateError("git could not list the working tree's files")
    for path in proc.stdout.split(b"\0"):
        if path and not path.startswith(EVIDENCE_DIR.encode()) and path not in committed:
            return f"{path.decode(errors='replace')} is in the working tree but not in the commit"
    return None


_PYTHON_NAME = re.compile(r"python(?:3(?:\.\d+)*)?")


def _pytest_command(command: list[str]) -> bool:
    """Whether the command is a supported pytest form: an executable named pytest or py.test, or a Python
    interpreter with `-m pytest`. The run-evidence binding, stated verbatim (review F6, F7, N7, Befund 2):
    "The command must have a supported pytest form, and the report must carry this invocation's random suite
    name. This rejects unsupported command forms and an unchanged report from another invocation; it does
    not authenticate the executable or the reported test activity."
    """
    name = os.path.basename(command[0])
    if name in ("pytest", "py.test"):
        return True
    return _PYTHON_NAME.fullmatch(name) is not None and command[1:3] == ["-m", "pytest"]


class StaleReport(GateError):
    """The JUnit report does not carry the name this run set, so it is not the report this call wrote."""


def _junit_counts(path: str, suite_name: str) -> tuple[dict, str]:
    """Counts from the JUnit XML report the run wrote, and the report's sha256. Every testsuite must carry
    the name this call set, so a report left from another invocation is rejected (review F7, N7)."""
    import xml.etree.ElementTree as ElementTree  # only this subcommand reads XML

    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_REPORT_BYTES + 1)
    except OSError as exc:
        raise GateError("the command wrote no JUnit XML report") from exc
    if len(data) > MAX_REPORT_BYTES:
        raise GateError(f"the report is larger than {MAX_REPORT_BYTES} bytes")
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise GateError("the report declares a DOCTYPE or an entity")
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as exc:
        raise GateError(f"the report is not XML ({exc})") from exc
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite") if root.tag == "testsuites" else []
    if not suites:
        raise GateError("the report has no testsuite")
    if any(suite.get("name") != suite_name for suite in suites):
        raise StaleReport("the report was not written by this run (a testsuite does not carry the name this "
                          "call set); a replayed or stale report does not count")
    totals = dict.fromkeys(("tests", "failures", "errors", "skipped"), 0)
    for suite in suites:
        for name in totals:
            value = suite.get(name, "0")
            if not re.fullmatch(r"[0-9]{1,15}", value):
                raise GateError(f"the report's {name} is not a count: {value!r}")
            totals[name] += int(value)
    counts = {"tests": totals["tests"], "failed": totals["failures"], "errors": totals["errors"],
              "skipped": totals["skipped"]}
    counts["passed"] = counts["tests"] - counts["failed"] - counts["errors"] - counts["skipped"]
    if counts["passed"] < 0:
        raise GateError("the report's counts do not add up")
    return counts, hashlib.sha256(data).hexdigest()


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def run_evidence(directory: str, out: str, command: list[str],
                 timeout: float = RUN_TIMEOUT_SECONDS, junit_out: str | None = None) -> tuple[int, dict]:
    """Run a pytest command on the clean working tree of HEAD and, for a green run that left the tree as it
    was, write the statement a bundle signs: the subject and the run record (DECISIONS.md, D23).

    There is no evidence when the working tree differs from HEAD before the run, when the run moves HEAD or
    changes the working tree, when it times out or writes no readable report, or when it is not green. The
    record holds no environment value. Nothing is signed here.

    When junit_out is given, the exact JUnit report the record's report_sha256 is taken over is copied there,
    so a reader can hold the raw report beside the signed record and confirm the hash (review Runde 5,
    Befund 5; the report is otherwise discarded with the scratch directory).
    """
    report = {"outcome": "no_evidence", "reason_id": None, "message": "", "statement": None, "run": None,
              "gate_version": GATE_VERSION}

    def refuse(reason_id: str, message: str, run: dict | None = None) -> tuple[int, dict]:
        report.update(reason_id=reason_id, run=run,
                      message=f"NO EVIDENCE: {message}. Nothing was written, and nothing may be signed as this run.")
        return 1, report

    try:
        deadline = time.monotonic() + DEADLINE_SECONDS
        top = _git(directory, "rev-parse", "--show-toplevel", deadline=deadline)
        if top.returncode != 0:
            return refuse("not_a_work_tree", f"{directory} is not inside a git work tree")
        repo = top.stdout.decode().strip()
        head = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", deadline=deadline)
        if head.returncode != 0:
            return refuse("no_commit", f"{repo} has no commit at HEAD")
        commit = head.stdout.decode().strip()
        # The command is judged before the tree is read, so a call that cannot run is refused before any
        # comparison (review Runde 8, R8-1: the old staging ran fsmonitor and hooks before this refusal).
        program = shutil.which(command[0])
        if program is None:
            return refuse("no_program", f"{command[0]!r} is not an executable file on PATH")
        if not _pytest_command(command):
            return refuse("not_pytest", f"{command[0]!r} is not a pytest command; run-evidence runs only pytest "
                                        "(an executable named pytest, or a Python interpreter with -m pytest)")
        program = os.path.abspath(program)
        digest = tree_digest(repo, commit, deadline)
        problem = _working_tree_problem(repo, commit, deadline)
        if problem is not None:
            return refuse("tree_not_clean", f"the working tree of {repo} differs from HEAD {commit[:12]}: "
                                            f"{problem}; commit or remove the changes, then run again (files git "
                                            "ignores are not compared)")
        with tempfile.TemporaryDirectory(prefix="proofbundle-run-") as scratch:
            junit = os.path.join(scratch, "report.xml")
            suite_name = "proofbundle-run-" + secrets.token_hex(16)
            argv = [program, *command[1:], "-p", "no:cacheprovider", f"--junitxml={junit}",
                    "-o", f"junit_suite_name={suite_name}"]
            started = _now()
            try:
                proc = subprocess.Popen(argv, cwd=repo, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
                                        stdin=subprocess.DEVNULL, stdout=2, stderr=2, start_new_session=True)
            except OSError as exc:
                return refuse("not_started", f"the command could not start ({exc})")
            try:
                exit_code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
                return refuse("timeout", f"the command did not finish within {timeout:g} s")
            finished = _now()
            deadline = time.monotonic() + DEADLINE_SECONDS
            after = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", deadline=deadline)
            if after.returncode != 0 or after.stdout.decode().strip() != commit:
                return refuse("head_moved", f"the run moved HEAD away from {commit[:12]}")
            problem = _working_tree_problem(repo, commit, deadline)
            if problem is not None:
                return refuse("tree_changed", f"the run changed the working tree of {repo} ({problem}), so it did "
                                              "not run on the tree it would name")
            tree_after = digest   # the working tree still holds exactly the commit's files
            try:
                counts, report_sha256 = _junit_counts(junit, suite_name)
            except StaleReport as exc:
                return refuse("stale_report", str(exc))
            except GateError as exc:
                return refuse("no_report", str(exc))
            if junit_out is not None:
                try:
                    shutil.copyfile(junit, junit_out)  # the exact bytes report_sha256 is taken over (Befund 5)
                except OSError as exc:
                    return refuse("junit_not_written", f"the JUnit report could not be copied to {junit_out} ({exc})")
        import platform  # only this subcommand names the platform

        run = {"schema": RUN_SCHEMA, "commit": commit, "tree_before": digest, "tree_after": tree_after,
               "command": argv, "program": {"path": program, "sha256": _file_sha256(program)},
               "exit_code": exit_code, "counts": counts, "report_sha256": report_sha256, "started_at": started,
               "finished_at": finished, "gate_version": GATE_VERSION,
               "platform": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()}}
        problem = run_record_problem(run, digest)
        if problem is not None:
            return refuse("run_failed", problem.replace("the signed run record", "the run"), run)
        statement = json.dumps({"subject": {"algorithm": TREE_ALGORITHM, "digest": digest}, "run": run},
                               indent=1, sort_keys=True) + "\n"
        try:
            with open(out, "x", encoding="utf-8") as handle:
                handle.write(statement)
        except OSError as exc:
            return refuse("not_written", f"the statement could not be written to {out} ({exc})", run)
    except GateError as exc:
        return refuse("gate_error", str(exc))
    report.update(outcome="evidence", reason_id="green_run", run=run, statement=os.path.abspath(out),
                  message=f"proofbundle run: {counts['passed']} of {counts['tests']} tests passed, exit 0, on "
                          f"{TREE_ALGORITHM} {digest} at HEAD {commit[:12]}, and the run left the tree as it "
                          f"was. The statement is unsigned; sign it only if you mean to vouch for this run. "
                          "It records what the run reported, not that the tests test anything.")
    return 0, report


def run_evidence_command(argv: list[str]) -> int:
    if "--" not in argv:
        print(RUN_USAGE, file=sys.stderr)
        return 2
    split = argv.index("--")
    options, command, i = {"--repo": None, "--out": None, "--timeout": None, "--junit-out": None}, argv[split + 1:], 0
    head = argv[:split]
    while i < len(head):
        if head[i] in options and i + 1 < len(head):
            options[head[i]], i = head[i + 1], i + 2
        else:
            print(f"{RUN_USAGE}; unknown {head[i]!r}", file=sys.stderr)
            return 2
    timeout = RUN_TIMEOUT_SECONDS
    if options["--timeout"] is not None:
        if not re.fullmatch(r"[0-9]{1,5}", options["--timeout"]) or int(options["--timeout"]) == 0:
            print(f"{RUN_USAGE}; the timeout is a whole number of seconds from 1 to 99999", file=sys.stderr)
            return 2
        timeout = float(options["--timeout"])
    if options["--repo"] is None or options["--out"] is None or not command:
        print(RUN_USAGE, file=sys.stderr)
        return 2
    code, report = run_evidence(options["--repo"], options["--out"], command, timeout, options["--junit-out"])
    sys.stdout.write(json.dumps(report, indent=1) + "\n")
    print(report["message"], file=sys.stderr)
    return code


def _host(argv: list[str]) -> str:
    if not argv:
        return "claude"
    if len(argv) == 2 and argv[0] == "--host" and argv[1] in HOSTS:
        return argv[1]
    raise GateError(f"unknown arguments {argv!r}; the gate takes --host claude or --host codex")


def pre_push_command(argv: list[str]) -> int:
    """PROTOTYPE git pre-push hook entry (DECISIONS.md, D24 — not installed outside tests). git runs a
    pre-push hook as `hook <remote-name> <remote-url>` with one `<local_ref> <local_sha> <remote_ref>
    <remote_sha>` line per ref on stdin, in the repository being pushed. This reaches a verdict from those
    lines alone and denies the push (exit 1) when the evidence does not verify, whatever shell form launched
    the push. The two positional arguments (remote name and URL) are accepted and not needed here."""
    deadline = time.monotonic() + DEADLINE_SECONDS
    lines = []
    for raw in sys.stdin.read().splitlines():
        parts = raw.split()
        if not parts:
            continue  # a blank line carries no ref
        if len(parts) != 4:
            # R5-5: a non-empty line that is not git's four-field form is a controlled rejection, never an
            # empty ref list the gate would read as 'nothing to push' and let pass.
            sys.stderr.write("proofbundle pre-push (prototype): a ref line on stdin did not have the four "
                             "fields git writes (<local_ref> <local_sha> <remote_ref> <remote_sha>). "
                             "The push is denied.\n")
            return 1
        lines.append(tuple(parts))
    try:
        verdict = pre_push_verdict(os.getcwd(), lines, deadline)
    except GateError as exc:
        sys.stderr.write(f"proofbundle pre-push (prototype): {exc}. The push is denied.\n")
        return 1
    sys.stderr.write(verdict.text() + "\n")
    # Point 1 (review Runde 5): exit 0 only for pass and a measured inactive; ask, unknown states, measurement
    # errors and any exception all block (exit 1). A rule change stays blocked; there is no release switch in
    # an environment the model can write or run (D24).
    return 0 if verdict.decision in ("pass", "inactive") else 1


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["tree-digest"]:
        return tree_digest_command(argv[1:])
    if argv[:1] == ["state-digest"]:
        return state_digest_command(argv[1:])
    if argv[:1] == ["ci-check"]:
        return ci_check_command(argv[1:])
    if argv[:1] == ["run-evidence"]:
        return run_evidence_command(argv[1:])
    if argv[:1] == ["pre-push"]:
        return pre_push_command(argv[1:])
    deadline = time.monotonic() + DEADLINE_SECONDS
    host, event, actions = "claude", None, []
    try:
        host = _host(argv)
        try:
            event = strict_json(sys.stdin.read())
        except AmbiguousJSON as exc:
            raise GateError(f"the hook input {exc}, so the gate cannot tell which call it describes") from exc
        except ValueError as exc:
            raise GateError("the hook input is not JSON") from exc
        tool = event.get("tool_name") if isinstance(event, dict) else None
        if isinstance(tool, str) and tool.startswith("mcp__"):
            cwd = event.get("cwd")
            actions = [f"MCP {tool}"] if mcp_gated(tool) else []
            verdict = decide_mcp(tool, cwd if isinstance(cwd, str) and cwd else os.getcwd(), deadline, host=host)
        elif isinstance(tool, str) and tool in FILE_WRITE_TOOLS:
            cwd = event.get("cwd")
            verdict = decide_write(tool, event.get("tool_input"), cwd if isinstance(cwd, str) and cwd else os.getcwd(),
                                   deadline, host=host)
            actions = [f"file {tool}"] if verdict is not None else []
        else:
            command, cwd = _command_from_event(event)
            actions = sorted({name for name, _, _ in gated_calls(command)})
            verdict = decide(command, cwd, deadline, host=host)
    except GateError as exc:
        failure = Verdict("deny", f"proofbundle gate: {exc}. The call is denied because the gate reached no verdict.",
                          "hook_input", evidence="none, the gate could not read the call", failed=str(exc),
                          next_step="check the plugin's hook command and the host version")
        verdict = Outcome("deny", failure.text(), [failure])
    except Exception as exc:  # noqa: BLE001 - any failure inside the gate denies, it never allows
        failure = Verdict("deny", f"proofbundle gate: internal error {type(exc).__name__}: {exc}. "
                                  "The call is denied because the gate reached no verdict.", "internal_error",
                          evidence="none, the gate failed before a verdict", failed=f"{type(exc).__name__}: {exc}",
                          next_step="report this error; the gate denies until it is fixed")
        verdict = Outcome("deny", failure.text(), [failure])
    if host in HOSTS:
        try:
            write_log(log_entry(host, event, verdict, actions), host)
        except Exception:  # noqa: BLE001 - the log never changes the answer
            pass
    if verdict is not None:
        sys.stdout.write(json.dumps(answer(verdict.decision, verdict.text, host=host)) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
