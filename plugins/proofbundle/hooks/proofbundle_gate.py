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
#: Used only when the command cannot be tokenised: any mention of a gated call counts as one.
_FALLBACK = re.compile(r"\bgit-push\b|\bgit\b.*\bpush\b|\bgh\b.*\b(?:pr|release)\b.*\b(?:create|new)\b",
                       re.DOTALL)
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
    `$name`), or None if a `$(` or `${` is never closed."""
    n = len(s)
    if i + 1 >= n:
        return i + 1
    c = s[i + 1]
    if c == "(":
        depth, j = 0, i + 1
        while j < n:
            if s[j] == "(":
                depth += 1
            elif s[j] == ")":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        return None
    if c == "{":
        j = s.find("}", i + 2)
        return j + 1 if j >= 0 else None
    j = i + 1
    if s[j].isalpha() or s[j] == "_":
        j += 1
        while j < n and (s[j].isalnum() or s[j] == "_"):
            j += 1
        return j
    return i + 2


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
#: git global options (before the subcommand) that take their value as the next word.
_GIT_GLOBAL_VALUE = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path",
                               "--config-env", "--super-prefix"})

#: The allow-list of git subcommands Ebene 1 may leave free: built-ins that, per the git documentation,
#: neither transfer objects TO a remote nor run an arbitrary command, AND whose program-selecting
#: configuration keys and hooks are listed in _REPO_PROFILE (Nachtrag 19b). A subcommand NOT on this list is
#: NOT MEASURED as a possible transfer (DECISIONS.md, D3; review Runde 5, Punkt 4/6/8). Being on the list is
#: not enough to be free: the invocation must also be a checked form (_GIT_VETTED_OPTIONS), and decide()
#: reads the bound repository's effective configuration and hook directory and frees the call only when no
#: key or hook of its profile is present. The entries whose program list this round could not justify
#: completely left the list (review S1, fallback A): am, apply, archive, bugreport, checkout-index,
#: cherry-pick, clean, clone, column, commit-tree, fmt-merge-msg, fsck, gc, hash-object, maintenance, merge,
#: merge-file, mktag, mktree, notes, pack-objects, pack-refs, patch-id, prune, pull, range-diff, read-tree,
#: reflog, remote, repack, rerere, revert, sparse-checkout, stripspace, unpack-objects, update-index,
#: update-ref, verify-commit, verify-pack, verify-tag, worktree, write-tree, and the exec-capable rebase,
#: bisect and submodule; and `init`, which writes the repository's configuration and copies hooks from a
#: template directory chosen by --template, $GIT_TEMPLATE_DIR, init.templateDir or the compiled-in default
#: (git-init(1) TEMPLATE DIRECTORY; setup.c copy_templates, lines 1794-1844), so a later call runs them.
#: `fetch` and `ls-remote` left too (review Runde 7, R7-2): the transport they start is chosen by the URL
#: argument, the effective remote URL after rewriting and the protocol environment together — a `<scheme>://`
#: URL runs `git-remote-<scheme>` from PATH (gitremote-helpers(7)), and an inherited GIT_ALLOW_PROTOCOL=ext
#: lets `ext::` run a command — and the gate does not check the three together. `config` is here; a `config core.hooksPath` is denied earlier. The list closes no
#: indirect push it does not name, and is not offered as a complete boundary (review Runde 5, Punkt 5/8).
_GIT_LOCAL_SUBCOMMANDS = frozenset({
    "add", "annotate", "blame", "branch", "cat-file", "check-attr", "check-ignore", "check-mailmap",
    "check-ref-format", "checkout", "cherry", "commit", "config", "count-objects", "describe", "diff",
    "diff-files", "diff-index", "diff-tree", "for-each-ref", "grep", "log", "ls-files",
    "ls-tree", "merge-base", "mv", "name-rev", "reset", "restore", "rev-list", "rev-parse", "rm",
    "shortlog", "show", "show-branch", "show-ref", "stash", "status", "switch", "symbolic-ref", "tag", "var",
    "whatchanged",
})
#: Subcommands that run an arbitrary command through an argument (which could be a push the gate never
#: sees): `rebase -x/--exec`, `bisect run`, `submodule foreach` (review Runde 5, Punkt 6). Since Nachtrag 19b
#: none of the three is free in any form: their other forms check out commits, merge, or clone submodules,
#: and their program lists were not justified completely (S1, fallback A). The predicates stay as the record
#: of the forms that run a command directly.
_GIT_EXEC_WHEN = {
    # `-x`/`--exec` run an arbitrary command; the short option also takes an ATTACHED argument (`-x<cmd>`),
    # so any word beginning `-x` counts, not only the separated `-x` and `--exec`/`--exec=` forms (R6-2).
    "rebase": lambda args: any(a.startswith("-x") or a == "--exec" or a.startswith("--exec=") for a in args),
    "bisect": lambda args: bool(args) and args[0] == "run",
    "submodule": lambda args: "foreach" in args,
}

#: Per-subcommand options checked against the git documentation to take no value, or a value that is a
#: number, a format string, a ref, a pattern or a pathspec — never a program, a file to execute, an
#: editor, a pager, a filter, a transport helper or a configuration key. An allow-listed subcommand is
#: free (Ebene 1 returns None) only when every option word it carries is vetted here for that entry; any
#: other option, and any NOT MEASURED already established earlier in the parse (for example from a `-c`),
#: makes the whole invocation NOT MEASURED. A subcommand name alone does not establish that an invocation
#: cannot execute other programs; options and Git configuration can select helpers, filters, hooks or
#: editors (review Runde 6, R6-2; D3). Four single exceptions would not close that class, so each entry
#: is checked positively and the bare invocation is always a checked form. An entry absent here, or
#: present with an empty set, is free only in its bare form (options -> NOT MEASURED). Deliberately NOT
#: vetted anywhere: --open-files-in-pager / -O (grep), --upload-pack / --receive-pack / --exec (fetch,
#: pull, ls-remote, clone), --ext-diff / --output / -O<orderfile> (diff, log, show), -i / --edit /
#: --edit-description (editor), and every value-taking transport, pager, filter or config option.
_GIT_VETTED_OPTIONS = {
    "status": frozenset({"-s", "--short", "--porcelain", "--long", "-b", "--branch", "--show-stash",
                         "-v", "--verbose", "-z", "--ignored", "-u", "--untracked-files",
                         "--no-untracked-files", "--no-color", "--color"}),
    "log": frozenset({"--oneline", "--pretty", "--format", "--abbrev-commit", "--no-abbrev-commit",
                     "--graph", "--decorate", "--no-decorate", "-n", "--max-count", "--skip",
                     "--stat", "--numstat", "--shortstat", "--summary", "--name-only", "--name-status",
                     "--reverse", "--since", "--until", "--author", "--committer", "--grep",
                     "--date", "--all", "--branches", "--tags", "--remotes", "--no-color", "--color",
                     "--first-parent", "-p", "--patch", "--no-patch", "-m", "--merges", "--no-merges"}),
    "show": frozenset({"--oneline", "--pretty", "--format", "--abbrev-commit", "-s", "--stat",
                      "--numstat", "--name-only", "--name-status", "--no-color", "--color", "-p",
                      "--patch", "--no-patch"}),
    "diff": frozenset({"--stat", "--numstat", "--shortstat", "--summary", "--name-only", "--name-status",
                      "--cached", "--staged", "-p", "--patch", "--no-patch", "-U", "--unified",
                      "--no-color", "--color", "-w", "--ignore-all-space", "-b", "--ignore-space-change",
                      "--raw", "--check", "-M", "--find-renames", "-C", "--find-copies"}),
    "diff-tree": frozenset({"-r", "--stat", "--name-only", "--name-status", "--no-color", "-p",
                           "--root", "--abbrev"}),
    "diff-index": frozenset({"--cached", "--stat", "--name-only", "--name-status", "-p"}),
    "diff-files": frozenset({"--stat", "--name-only", "--name-status", "-p"}),
    "grep": frozenset({"-n", "--line-number", "-i", "--ignore-case", "-l", "--files-with-matches",
                      "-L", "--files-without-match", "-c", "--count", "-w", "--word-regexp",
                      "-e", "-E", "--extended-regexp", "-F", "--fixed-strings", "-P", "--perl-regexp",
                      "-G", "--basic-regexp", "--cached", "--no-index", "-h", "-H", "-v", "--invert-match",
                      "-A", "--after-context", "-B", "--before-context", "-C", "--context",
                      "--color", "--no-color", "--heading", "--break", "--line-number", "--untracked"}),
    "branch": frozenset({"-a", "--all", "-r", "--remotes", "-v", "-vv", "--verbose", "--list", "-l",
                        "--merged", "--no-merged", "--contains", "--no-contains", "--points-at",
                        "--format", "--show-current", "--no-color", "--color", "--sort"}),
    "tag": frozenset({"-l", "--list", "-n", "--contains", "--no-contains", "--points-at", "--merged",
                     "--no-merged", "--format", "--sort", "--color", "--no-color"}),
    "describe": frozenset({"--tags", "--all", "--long", "--abbrev", "--always", "--contains",
                          "--match", "--exclude", "--dirty"}),
    "rev-parse": frozenset({"--abbrev-ref", "--short", "--verify", "--quiet", "-q", "--symbolic",
                          "--symbolic-full-name", "--is-inside-work-tree", "--is-bare-repository",
                          "--show-toplevel", "--git-dir", "--git-common-dir", "--all", "--branches",
                          "--tags", "--remotes", "--default"}),
    "show-ref": frozenset({"--head", "--heads", "--tags", "-d", "--dereference", "--hash", "-s",
                         "--abbrev", "--verify", "-q", "--quiet"}),
    "for-each-ref": frozenset({"--format", "--sort", "--count", "--points-at", "--merged",
                             "--no-merged", "--contains", "--no-contains", "--color", "--no-color"}),
    "rev-list": frozenset({"--count", "--max-count", "-n", "--all", "--branches", "--tags", "--remotes",
                         "--reverse", "--first-parent", "--no-walk", "--oneline", "--left-right",
                         "--merges", "--no-merges"}),
    "ls-files": frozenset({"--cached", "-c", "--deleted", "-d", "--modified", "-m", "--others", "-o",
                         "--stage", "-s", "--unmerged", "-u", "-z", "--full-name", "--error-unmatch"}),
    "ls-tree": frozenset({"-r", "-d", "-t", "-l", "--long", "--name-only", "--name-status", "-z",
                        "--full-name", "--full-tree", "--abbrev"}),
    "cat-file": frozenset({"-t", "-s", "-p", "-e", "--batch-check", "--batch-all-objects"}),
    "shortlog": frozenset({"-n", "--numbered", "-s", "--summary", "-e", "--email", "--all", "--no-color"}),
    "blame": frozenset({"-l", "-s", "-e", "--show-email", "-w", "--line-porcelain", "--porcelain",
                      "-L", "--abbrev", "--date", "--no-color", "--color-lines"}),
    "name-rev": frozenset({"--tags", "--all", "--name-only", "--stdin", "--refs"}),
    "merge-base": frozenset({"--all", "--is-ancestor", "--independent", "--octopus", "--fork-point"}),
    "symbolic-ref": frozenset({"-q", "--quiet", "--short", "-d", "--delete"}),
    "count-objects": frozenset({"-v", "--verbose", "-H", "--human-readable"}),
}


#: `git config` (git-config(1)) is free only in a read form or as a write of a key checked to select no
#: program. A write of any other key may select a helper, filter, hook, editor or pager for a later call
#: (diff.external, core.editor, core.pager, filter.*, core.fsmonitor, core.sshCommand, credential.helper,
#: remote.*.uploadpack, include.path, …), so it is NOT MEASURED (review Runde 6, R6-2 class).
_CONFIG_READ_OPTIONS = frozenset({"--get", "--get-all", "--get-regexp", "--get-urlmatch", "-l", "--list"})
_CONFIG_READ_SUBCOMMANDS = frozenset({"get", "list"})          # git 2.46+ `git config get|list`
_CONFIG_WRITE_SUBCOMMANDS = frozenset({"set", "unset"})        # `edit` opens an editor and stays unvetted
_CONFIG_VETTED_OPTIONS = frozenset({"--get", "--get-all", "--get-regexp", "--get-urlmatch", "-l", "--list",
                                    "--show-origin", "--show-scope", "--name-only", "-z", "--null", "--local",
                                    "--global", "--worktree", "--bool", "--int", "--add", "--replace-all",
                                    "--unset", "--unset-all", "--all"})
#: push.default is here because it selects no program and the gate reads it itself when it judges a push.
_CONFIG_INERT_KEYS = frozenset({"user.name", "user.email", "init.defaultbranch", "color.ui", "core.autocrlf",
                                "core.quotepath", "pull.rebase", "pull.ff", "fetch.prune", "push.default",
                                "advice.detachedhead"})


def _config_inert(args: list[str]) -> bool:
    """Whether a `git config` invocation is a checked form: every option vetted for config, and either a read
    (an option or subcommand that only reads) or a write whose key is on _CONFIG_INERT_KEYS."""
    positionals, read = [], False
    for a in args:
        if a.startswith("-"):
            if a.split("=", 1)[0] not in _CONFIG_VETTED_OPTIONS:
                return False
            read = read or a.split("=", 1)[0] in _CONFIG_READ_OPTIONS
        else:
            positionals.append(a)
    if positionals and positionals[0] in _CONFIG_READ_SUBCOMMANDS:
        return True
    if positionals and positionals[0] in _CONFIG_WRITE_SUBCOMMANDS:
        positionals = positionals[1:]
    if read:
        return True
    return bool(positionals) and positionals[0].lower() in _CONFIG_INERT_KEYS


#: A format or sort value can make git verify signatures, which runs gpg.program (or gpg, or ssh-keygen):
#: the pretty-formats placeholders %G… (pretty.c, lines 1631-1633) and the ref-filter atom signature
#: (ref-filter.c, line 1749). The value may be attached (`--format=…`) or the next word (`--sort signature`),
#: so any word of these entries carrying the marker makes the invocation NOT MEASURED (Nachtrag 19b).
_SIGNATURE_WORDS = {"log": "%G", "show": "%G", "whatchanged": "%G",
                    "for-each-ref": "signature", "branch": "signature", "tag": "signature"}


def _options_inert(sub: str, args: list[str]) -> bool:
    """True iff every OPTION word in args is vetted inert for this subcommand (see _GIT_VETTED_OPTIONS).
    A word that does not begin with '-' is a positional (pathspec, ref, pattern) and never selects a
    program; a lone '--' ends option parsing. Any option whose bare name (before '=') is not vetted for
    this entry returns False, so the invocation is NOT MEASURED: an unchecked option can select a helper,
    filter, hook or editor (R6-2). Four fixed exceptions would not close that class, hence this positive
    per-entry check."""
    if sub == "config":
        return _config_inert(args)
    marker = _SIGNATURE_WORDS.get(sub)
    if marker is not None and any(marker in a for a in args):
        return False
    vetted = _GIT_VETTED_OPTIONS.get(sub, frozenset())
    seen_ddash = False
    for a in args:
        if seen_ddash or not a.startswith("-"):
            continue
        if a == "--":
            seen_ddash = True
            continue
        if a.split("=", 1)[0] not in vetted:
            return False
    return True


# --- Ebene 1: the repository state behind a free git form (Nachtrag 19b, review S1) -----------------------
#
# A subcommand name and its options do not decide alone whether a call runs another program: the repository's
# effective configuration (local, global, system, every included file and the environment-supplied scope) and
# its hooks can select helpers, filters, editors, pagers or hooks (S1, measured on c159b817). decide()
# therefore reads both, with the hook's own environment, in the bound repository before it leaves an
# allow-listed form free. Sources are the git v2.43.0 documentation (Documentation/*.txt at tag v2.43.0, the
# sources of git-config(1), githooks(5), gitattributes(5)), the git version of the measuring environment.

#: Every hook githooks(5) names (Documentation/githooks.txt). git starts a hook only by exactly this name in
#: the effective hook directory (core.hooksPath, else $GIT_DIR/hooks) and only when the file is executable; a
#: `*.sample` file is never one of them.
_GITHOOKS = frozenset({
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit",
    "prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase", "post-checkout", "post-merge", "pre-push",
    "pre-receive", "update", "proc-receive", "post-receive", "post-update", "reference-transaction",
    "push-to-checkout", "pre-auto-gc", "post-rewrite", "sendemail-validate", "fsmonitor-watchman",
    "p4-changelist", "p4-prepare-changelist", "p4-post-changelist", "p4-pre-submit", "post-index-change",
})
_BOOLEAN_WORDS = frozenset({"true", "false", "yes", "no", "on", "off", "1", "0", ""})


def _truthy(value: str | None) -> bool:
    """git's boolean truth: a key without a value is true (git-config(1), Values: boolean)."""
    return value is None or value.strip().lower() in ("true", "yes", "on", "1")


def _helper_url(value: str | None) -> bool:
    return value is not None and "::" in value   # <transport>::<address> runs git-remote-<transport>


#: Families of keys that select a program: (pattern over the key in lower case, value test or None, source).
#: Since review Runde 7 (R7-2) no allow-list entry carries transport, transport-helper-url, rewrite-to-helper or
#: protocol: fetch and ls-remote, the entries that talk to a remote, left the list. The families stay as the
#: record of what a joint check of the transport would have to read, and are named in D3.
_KEY_FAMILIES = {
    "fsmonitor": (r"core\.fsmonitor", lambda k, v: v is not None and v.strip().lower() not in _BOOLEAN_WORDS,
                  "git-config(1) core.fsmonitor: a pathname names a hook command (true is the built-in daemon)"),
    "filter": (r"filter\..+\.(clean|smudge|process)", None,
               "gitattributes(5) filter: filter.<driver>.clean, .smudge, .process are commands"),
    "diff-driver": (r"diff\.external|diff\..+\.(command|textconv)", None,
                    "git-config(1) diff.external, diff.<driver>.command, diff.<driver>.textconv"),
    "merge-driver": (r"merge\..+\.driver", None, "git-config(1) merge.<driver>.driver"),
    "editor": (r"core\.editor", None, "git-config(1) core.editor"),
    "transport": (r"core\.(sshcommand|gitproxy|askpass|alternaterefscommand)|credential\.helper"
                  r"|credential\..+\.helper|remote\..+\.(uploadpack|vcs)", None,
                  "git-config(1) core.sshCommand, core.gitProxy, core.askPass, core.alternateRefsCommand, "
                  "credential.helper, credential.<url>.helper, remote.<name>.uploadpack, remote.<name>.vcs"),
    "transport-helper-url": (r"remote\..+\.(url|pushurl)", lambda k, v: _helper_url(v),
                             "git-config(1) remote.<name>.url; gitremote-helpers(7) <transport>::<address>"),
    "rewrite-to-helper": (r"url\..+\.(insteadof|pushinsteadof)", lambda k, v: "::" in k.split(".", 1)[1],
                          "git-config(1) url.<base>.insteadOf with a <transport>:: base"),
    "protocol": (r"protocol\.allow|protocol\.(ext|fd)\.allow",
                 lambda k, v: (v or "").strip().lower() in ("always", "user") if k == "protocol.allow"
                 else (v or "").strip().lower() != "never",
                 "git-config(1) protocol.allow, protocol.<name>.allow (ext:: runs a command)"),
    "pager": (r"core\.pager", None, "git-config(1) core.pager"),
    "signature-format": (r"format\.pretty|pretty\..+", lambda k, v: "%G" in (v or ""),
                         "git-config(1) format.pretty, pretty.<name>; pretty-formats %G placeholders verify the "
                         "signature (pretty.c, lines 1631-1633, check_commit_signature runs gpg.program or gpg)"),
    "signature-sort": (r"(branch|tag)\.sort", lambda k, v: "signature" in (v or ""),
                       "git-config(1) branch.sort, tag.sort; the ref-filter atom signature verifies "
                       "(ref-filter.c, line 1749)"),
    "promisor": (r"extensions\.partialclone|remote\..+\.(promisor|partialclonefilter)", None,
                 "git-config(1) remote.<name>.promisor, remote.<name>.partialclonefilter; partial-clone "
                 "(extensions.partialClone): a missing object is fetched from the promisor remote with the "
                 "transport its configuration names, by any command that reads it (review Runde 7, R7-7)"),
}
#: gpg.program, gpg.<format>.program and gpg.ssh.defaultKeyCommand only choose WHICH program signs or verifies;
#: alone they start nothing, so they are no family here. What starts it counts instead: these trigger keys, a
#: %G value or a signature atom (_SIGNATURE_WORDS, format.pretty, pretty.*, branch.sort, tag.sort), and the
#: unvetted -S, --gpg-sign, --show-signature, -s, -u options. Measured in the source: log and show verify
#: only under show_signature (log-tree.c, lines 786-789), which log.showSignature sets (builtin/log.c, lines
#: 613-615); stash creates its commits without a signing key (builtin/stash.c, lines 1181, 1400, 1467).
#: Keys that make git run its default program for one subcommand (value true): signature display or signing.
_TRIGGER_SOURCES = {
    "log.showsignature": "git-config(1) log.showSignature (runs gpg.program or gpg)",
    "commit.gpgsign": "git-config(1) commit.gpgSign (runs gpg.program or gpg)",
    "tag.gpgsign": "git-config(1) tag.gpgSign (runs gpg.program or gpg, and the editor)",
}
#: The environment is configuration by another name (D3): a program-selecting variable in the hook's own
#: environment, which the command inherits from the same host, counts like its key, with the neutral values
#: D3 names for a command-level assignment (an editor of `true` or `:`, a pager of `cat` or empty). Sources:
#: git(1) ENVIRONMENT VARIABLES (GIT_EXTERNAL_DIFF, GIT_PAGER, GIT_EDITOR, GIT_SSH, GIT_SSH_COMMAND,
#: GIT_ASKPASS; GIT_EXEC_PATH under --exec-path), git-var(1) GIT_EDITOR and GIT_PAGER (then VISUAL, EDITOR,
#: PAGER), git-config(1) core.askPass (then SSH_ASKPASS) and core.gitProxy (GIT_PROXY_COMMAND). An
#: environment a session command exported later is not the hook's and is not seen (D3, named limit).
_ENV_FAMILIES = {
    "editor": (("GIT_EDITOR", "VISUAL", "EDITOR"), lambda v: v.strip() not in ("", "true", ":")),
    "pager": (("GIT_PAGER", "PAGER"), lambda v: v.strip() not in ("", "cat")),
    "diff-driver": (("GIT_EXTERNAL_DIFF",), lambda v: v.strip() != ""),
    "transport": (("GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS", "SSH_ASKPASS", "GIT_PROXY_COMMAND"),
                  lambda v: v.strip() != ""),
}
#: GIT_EXEC_PATH chooses where git finds every program it runs as git-<name> and is put first on PATH for
#: them (git(1) --exec-path), so it counts for every entry.
_ENV_EVERY_ENTRY = ("GIT_EXEC_PATH",)
_INDEX = frozenset({"post-index-change"})   # githooks(5): invoked when the index is written
_REFS = frozenset({"reference-transaction"})  # githooks(5): invoked by any command that updates references
_AUTO_GC = frozenset({"pre-auto-gc"})        # githooks(5): invoked by `git gc --auto`, which commit and fetch run
#: githooks(5): pre-commit, prepare-commit-msg, commit-msg and post-commit are invoked by git-commit(1);
#: post-rewrite only with --amend, an option that is not vetted; pre-merge-commit only by git-merge(1).
_COMMIT_HOOKS = frozenset({"pre-commit", "prepare-commit-msg", "commit-msg", "post-commit"})
_ALL = "all"


def _profile(keys=(), hooks=frozenset(), pages=False, triggers=(), submodules=False, sources=""):
    return {"keys": frozenset(keys), "hooks": hooks, "pages": pages, "triggers": frozenset(triggers),
            "submodules": submodules, "sources": sources}


_READ_ONLY = _profile(sources="reads objects, refs or attributes only; runs no driver, editor or hook")
#: core.fsmonitor counts for every entry, not only those that compare the worktree: any read of the index
#: queries the fsmonitor hook (read-cache.c post_read_index_from, line 1971, calls tweak_fsmonitor;
#: fsmonitor.c, lines 551-614, refresh_fsmonitor), and a revision of the form :<path> reads the index
#: (gitrevisions(7)), so a mapping per entry would not be sure (Nachtrag 19b, Punkt 3). A partial clone counts
#: for every entry too: any read of a missing object fetches it from the promisor remote and starts its
#: transport, and an index, a revision or a path can name such an object (review Runde 7, R7-7).
_EVERY_ENTRY = frozenset({"fsmonitor", "promisor"})
_WORKTREE = ("filter", "fsmonitor")
#: Per allow-listed subcommand: the key families and trigger keys that select a program for it, the hooks it
#: starts (githooks(5)), whether it pages by default (then core.pager counts; pager.<subcommand> counts for
#: every entry, git-config(1) pager.<cmd>), and whether it can run inside submodules, whose configuration the
#: gate does not read (then a .gitmodules file or a submodule.* key makes it NOT MEASURED; git-config(1)
#: submodule.recurse, status.submoduleSummary, fetch.recurseSubmodules). `_ALL` stands for every githooks(5)
#: name, for an entry whose hook list is not sure (stash: push and pop write commits, references, the index
#: and the worktree through internal paths githooks(5) does not name one by one). commit carries the hooks
#: githooks(5) names for it; it does not start pre-push, which git-push(1) alone runs (measured in Nachtrag
#: 19b: with the Ebene-2 pre-push hook installed, _ALL made every git fetch NOT MEASURED; fetch has left the
#: list since review Runde 7, R7-2).
_REPO_PROFILE = {
    **{sub: _READ_ONLY for sub in ("rev-parse", "show-ref", "for-each-ref", "cat-file", "ls-tree", "merge-base",
                                   "rev-list", "name-rev", "count-objects", "var", "check-ref-format",
                                   "check-attr", "check-ignore", "check-mailmap", "config")},
    "symbolic-ref": _profile(hooks=_REFS, sources="git-symbolic-ref(1); githooks(5) reference-transaction: git "
                                                  "2.43.0 does not start it for a symbolic reference (measured), git "
                                                  "2.51.1 does (review Runde 7, R7-3), so it counts for every form"),
    "cherry": _profile(sources="git-cherry(1): patch ids by the internal diff, no driver"),
    "log": _profile(("diff-driver", "signature-format"), pages=True, triggers=("log.showsignature",),
                    sources="git-log(1), git-config(1) diff.*, log.showSignature, format.pretty, pretty.*"),
    "show": _profile(("diff-driver", "signature-format"), pages=True, triggers=("log.showsignature",),
                     sources="git-show(1), as git log"),
    "whatchanged": _profile(("diff-driver", "signature-format"), pages=True,
                            triggers=("log.showsignature",), sources="git-whatchanged(1), as git log"),
    "shortlog": _profile(pages=True, sources="git-shortlog(1)"),
    "show-branch": _profile(pages=True, sources="git-show-branch(1)"),
    "blame": _profile(("diff-driver", "filter"), pages=True, sources="git-blame(1): textconv, the worktree file"),
    "annotate": _profile(("diff-driver", "filter"), pages=True, sources="git-annotate(1), as git blame"),
    "grep": _profile(pages=True, submodules=True, sources="git-grep(1), submodule.recurse"),
    "diff": _profile(("diff-driver",) + _WORKTREE, _INDEX, pages=True, submodules=True,
                     sources="git-diff(1): drivers, worktree filters, fsmonitor, submodules"),
    "diff-files": _profile(_WORKTREE, submodules=True, sources="git-diff-files(1): compares the worktree"),
    "diff-index": _profile(_WORKTREE, submodules=True, sources="git-diff-index(1): compares the worktree"),
    "diff-tree": _profile(sources="git-diff-tree(1): two trees, plumbing, no driver without --ext-diff"),
    "describe": _profile(_WORKTREE, _INDEX, submodules=True, sources="git-describe(1) --dirty refreshes the index"),
    "ls-files": _profile(_WORKTREE, sources="git-ls-files(1) -m/-d compare the worktree"),
    "status": _profile(_WORKTREE, _INDEX, submodules=True,
                       sources="git-status(1) BACKGROUND REFRESH writes the index; submodules"),
    "branch": _profile(("signature-sort",), _REFS, pages=True,
                       sources="git-branch(1): creating a branch updates a reference; branch.sort"),
    "tag": _profile(("editor", "signature-sort"), _REFS, pages=True, triggers=("tag.gpgsign",),
                    sources="git-tag(1), tag.gpgSign, tag.sort"),
    "add": _profile(_WORKTREE, _INDEX, submodules=True, sources="git-add(1): clean filters, writes the index"),
    "rm": _profile(_WORKTREE, _INDEX, submodules=True, sources="git-rm(1): compares the worktree, writes the index"),
    "mv": _profile(("fsmonitor",), _INDEX, submodules=True, sources="git-mv(1): writes the index"),
    "restore": _profile(_WORKTREE, _INDEX, submodules=True, sources="git-restore(1): smudge filters"),
    "switch": _profile(_WORKTREE, _INDEX | _REFS | {"post-checkout"}, submodules=True,
                       sources="git-switch(1), githooks(5) post-checkout"),
    "checkout": _profile(_WORKTREE, _INDEX | _REFS | {"post-checkout"}, submodules=True,
                         sources="git-checkout(1), githooks(5) post-checkout"),
    "reset": _profile(_WORKTREE, _INDEX | _REFS, submodules=True, sources="git-reset(1)"),
    "commit": _profile(("editor",) + _WORKTREE, _COMMIT_HOOKS | _REFS | _INDEX | _AUTO_GC,
                       triggers=("commit.gpgsign",), submodules=True,
                       sources="git-commit(1): editor, signing, githooks(5) pre-commit, prepare-commit-msg, "
                               "commit-msg, post-commit, reference-transaction, post-index-change, pre-auto-gc"),
    "stash": _profile(("diff-driver", "merge-driver") + _WORKTREE, _ALL, pages=True, submodules=True,
                      sources="git-stash(1): show diffs, apply/pop merge, writes refs/stash and the index"),
}
assert set(_REPO_PROFILE) == set(_GIT_LOCAL_SUBCOMMANDS), set(_REPO_PROFILE) ^ set(_GIT_LOCAL_SUBCOMMANDS)


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


def _repo_state(directory: str, sub: str, deadline: float) -> tuple[str, list[str]]:
    """('free', []) when no key or hook of sub's profile is present in the repository at directory;
    ('selects', [what…]) when one is; ('unreadable', [why]) when the state cannot be read for sure."""
    if not os.path.isdir(directory):
        return "unreadable", [f"{directory} is not a directory"]
    entries, why = _config_entries(directory, deadline)
    if entries is None:
        return "unreadable", [f"the effective configuration cannot be read ({why})"]
    paths, why = _repo_paths(directory, deadline)
    if paths is None:
        return "unreadable", [f"the repository layout cannot be read ({why})"]
    prof, hits = _REPO_PROFILE[sub], []
    for scope, origin, key, value in entries:
        k = key.lower()
        for family in prof["keys"] | _EVERY_ENTRY | ({"pager"} if prof["pages"] else set()):
            pattern, test, _source = _KEY_FAMILIES[family]
            if re.fullmatch(pattern, k) and (test is None or test(k, value)):
                hits.append(f"{key} ({scope} configuration, {family})")
        if k == f"pager.{sub}" and value is not None and value.strip().lower() not in ("false", "no", "off", "0"):
            hits.append(f"{key} ({scope} configuration, pager)")
        if k in prof["triggers"] and _truthy(value):
            hits.append(f"{key} ({scope} configuration, runs the signature program)")
        if prof["submodules"] and k.startswith("submodule."):
            hits.append(f"{key} ({scope} configuration, submodules whose configuration the gate does not read)")
    environment = _read_env()
    for family in sorted(prof["keys"] | ({"pager"} if prof["pages"] else set())):
        names, test = _ENV_FAMILIES.get(family, ((), None))
        for name in names:
            if name in environment and test(environment[name]):
                hits.append(f"${name} (the hook's environment, {family})")
    for name in _ENV_EVERY_ENTRY:
        if environment.get(name, "").strip():
            hits.append(f"${name} (the hook's environment, chooses the programs git runs)")
    if prof["submodules"] and paths["toplevel"] and os.path.isfile(os.path.join(paths["toplevel"], ".gitmodules")):
        hits.append(".gitmodules (submodules whose configuration the gate does not read)")
    if paths["hooks"] and prof["hooks"]:
        names = _GITHOOKS if prof["hooks"] == _ALL else prof["hooks"]
        for name in sorted(names):
            hook = os.path.join(paths["hooks"], name)
            if os.path.isfile(hook) and os.access(hook, os.X_OK):
                hits.append(f"the hook {name} in {paths['hooks']}")
    return ("selects", hits) if hits else ("free", [])


def _free_call_verdicts(free: list, cwd: str, deadline: float, host: str) -> list:
    """The NOT MEASURED verdicts for the free git forms of one command (Nachtrag 19b): none for a form whose
    repository state selects no program."""
    verdicts, seen = [], set()
    for sub, _args, directory in free:
        label = f"git {sub}"
        if host == "codex" or directory is UNKNOWN:
            why = ("under Codex a repository-dependent call has no bound execution context: the hook does not "
                   "receive the directory the command runs in, D12" if host == "codex"
                   else "the command changes the directory, runs git through a wrapper, a program path or a nested "
                        "shell, or after another command, in a pipeline, in the background or in a substitution")
            key = ("unbound", label, why)
            if key not in seen:
                seen.add(key)
                verdicts.append(Verdict(
                    "ask", f"NOT MEASURED: the gate cannot bind {label} to a repository ({why}), so it cannot read "
                           "the configuration and hooks that may select a program for it.",
                    "repo_state_unbound", evidence=f"the configuration and hooks of the repository {label} acts in",
                    failed="the gate cannot tell which repository the call acts in",
                    next_step="run the call as a plain command in the repository's directory, or have a person "
                              "review it"))
            continue
        resolved = os.path.realpath(os.path.join(cwd, directory))
        if (sub, resolved) in seen:
            continue
        seen.add((sub, resolved))
        try:
            state, what = _repo_state(resolved, sub, deadline)
        except GateError as exc:
            state, what = "unreadable", [str(exc)]
        if state == "free":
            continue
        if state == "unreadable":
            verdicts.append(Verdict(
                "ask", f"NOT MEASURED: {label} in {resolved}: {what[0]}. The gate frees an allow-listed form only "
                       "when it has read the effective configuration and hooks.",
                "repo_state_unreadable", evidence=f"the effective configuration and hook directory of {resolved}",
                failed=what[0], next_step="make the configuration readable, or have a person review the call",
                repo=resolved))
            continue
        verdicts.append(Verdict(
            "ask", f"NOT MEASURED: {label} in {resolved} may run another program: "
                   f"{'; '.join(what)} selects a program or is a hook git starts for this subcommand. Ebene 1 "
                   "leaves an allow-listed form free only when no such key or hook is present.",
            "repo_state_selects_program", evidence=f"the effective configuration and hook directory of {resolved}",
            failed=f"{len(what)} program-selecting key(s) or hook(s) for {label}",
            next_step="review the key or hook named here, or have a person review the call", repo=resolved))
    return verdicts


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


#: The free git forms Ebene 1 found in the command decide() is judging (Nachtrag 19b): (subcommand, args,
#: directory, -C values). decide() checks the repository state behind each. None outside decide().
_FREE_CALLS: list | None = None
#: The directory a free form in the first run of a chain acts in: "." (the event's directory) unless the command
#: text changes the directory anywhere, then UNKNOWN. A free form in any later run, in a substitution or in a
#: nested shell has no bound context (UNKNOWN; review Runde 7, R7-4).
_FREE_BASE: str | None = "."
#: The default of _strict_git's free_base: a free form acts in the directory the call resolved, with its -C
#: values. It is a value of its own and not UNKNOWN (None), which a caller passes for a context the gate cannot
#: bind: when UNKNOWN was also the default, the deliberately unknown context of a wrapper fell back to
#: _FREE_BASE, so `env --chdir=<other repository> git status` was judged by the configuration of the event's
#: directory (review Runde 7, R7-4).
_FROM_DIRECTORY = object()
_DIRECTORY_CHANGE = re.compile(r"(?<![\w./-])(cd|pushd|popd|source|eval)(?![\w./-])|(^|[\s;&|(])\.(\s|$)")


def _note_free(sub: str, args: list[str], base: str | None, c_values: list[str]) -> None:
    if _FREE_CALLS is None:
        return
    directory = base
    if directory is not UNKNOWN:
        for value in c_values:
            directory = os.path.join(directory, value)
    _FREE_CALLS.append((sub, tuple(args), directory))


def _strict_git(words: list[str], directory: str | None,
                free_base: object = _FROM_DIRECTORY) -> tuple[str, str | None, list[str] | None] | None:
    """Parse one strict `git …` simple command (the words after a bare `git`). Returns the gated call, or
    None when the subcommand is one git built-in that neither transfers objects to a remote nor runs an
    arbitrary command (the `_GIT_LOCAL_SUBCOMMANDS` allow-list). A `push` resolves its target as before:
    at most one literal `-C` is joined onto the directory (not normalised, so the judge resolves it
    physically through symlinks, R4-2); more than one `-C`, or any other global option (`-c`, `--git-dir`,
    `--work-tree`, `--namespace`, `--exec-path`, `--no-pager`, …), makes the push NOT MEASURED (R4-6).
    `--no-verify`, a `-c core.hooksPath` override, or a `git config core.hooksPath` denies (Punkt 5). A
    subcommand that is NOT on the allow-list — an unknown word, `send-pack`, `rebase --exec`, `bisect run`,
    `submodule foreach` — is NOT MEASURED as a possible transfer (`_MAYBE_PUSH`), and a per-command
    `-c alias.*` makes even an allow-listed subcommand NOT MEASURED, because the alias may name any command
    the gate does not see (review Runde 5, Punkt 6/7/8). Its arguments are never read with the push parser."""
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
        # A bare `git` or `git --version` runs nothing else; any other option-only form (`git --help` opens a
        # pager or a viewer, `git -c …`) is not a checked form (Nachtrag 19b).
        return None if not words or words == ["--version"] else ("git", UNKNOWN, [_MAYBE_PUSH])
    # An allow-listed subcommand is free only in a checked invocation form: a NOT MEASURED already
    # established in the global-option parse (e.g. a `-c`) is never lost, and every option word must be
    # vetted inert for this entry. Otherwise the invocation is NOT MEASURED, because an unchecked option
    # or configuration can select a helper, filter, hook or editor (review Runde 6, R6-2).
    if sub in _GIT_LOCAL_SUBCOMMANDS:
        if not_measured or not _options_inert(sub, args):
            return f"git {sub}", UNKNOWN, [_MAYBE_PUSH]
        # Free in the command text. decide() still reads the repository state behind the call (Nachtrag 19b),
        # in the directory the call resolved, or in none when the caller passes UNKNOWN (R7-4).
        _note_free(sub, args, start if free_base is _FROM_DIRECTORY else free_base, c_values)
        return None
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
            depth, j = 0, i + 1
            while j < n:
                if raw[j] == "(":
                    depth += 1
                elif raw[j] == ")":
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
    # A program path (`./git`, `/opt/x/git`) names a program the gate does not know, so a form it leaves free
    # has no bound context and is NOT MEASURED (review Runde 7, R7-4: the path check came after the free branch).
    call = (("git push", directory, rest) if base == "git-push"
            else _strict_git(rest, directory, free_base=_FROM_DIRECTORY if bare else UNKNOWN))
    if call is None:
        # A git invocation Ebene 1 would leave free is free only without an unvetted prefix assignment: the
        # environment selects helpers as configuration does (GIT_EXTERNAL_DIFF=… git diff is the -c
        # diff.external=… form, GIT_SSH_COMMAND=… git fetch the --upload-pack form), so it is NOT MEASURED
        # (review Runde 6, R6-2 class).
        return [] if neutral_only else [(_git_label(rest), UNKNOWN, [_MAYBE_PUSH])]
    name, cdir, detail = call
    if detail == [_HOOKS_DISABLE]:
        return [call]  # a push that would disable the real-push check denies, whatever the context
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


def _scan_run(words: list[tuple], emit, depth: int, env_set: bool = False, bound: bool = False) -> None:
    """Report every gated call a single run of words (between control operators) executes, each NOT
    MEASURED. A `git`/`git-push`/`gh` word anywhere in the run (so after a wrapper such as `env`, `sudo`,
    `command`, `nice`, `timeout`) counts; a shell executor word anywhere (`bash`/`sh`/`dash`/`zsh`/`ksh`,
    by basename, so a path form too) has its `-c` command string scanned in turn, and `eval`/`source`/`.`
    have their string arguments scanned. The scan is an over-approximation on purpose: it never misses a
    nested push, including through a wrapper or a `-lc`/`-cl` bundle (review R4-1, the bypass probes), at
    the cost of a rare harmless ask. A free git form here is bound to _FREE_BASE only when bound (the first run
    of a sequential chain), git is the bare command word and no wrapper precedes it (review Runde 7, R7-4)."""
    for k, (value, _has, _raw) in enumerate(words):
        base = os.path.basename(value)
        rest = [w[0] for w in words[k + 1:]]
        if base == "git":
            # A git word after a wrapper (sudo, env -i, nice, timeout, xargs, …) runs in an environment or
            # directory Ebene 1 does not know, so a free form there has no bound repository (Nachtrag 19b).
            wrapped = any(not (_ASSIGNMENT.match(w[0]) and _assignment_neutral(w[0])) for w in words[:k])
            found = _strict_git(rest, UNKNOWN, free_base=_FREE_BASE if bound and not wrapped and value == "git"
                                else UNKNOWN)
            if found is not None:
                emit([found])
            elif env_set:  # an unvetted assignment anywhere in the command may select a helper (R6-2 class)
                emit([(_git_label(rest), UNKNOWN, [_MAYBE_PUSH])])
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
            calls.append((name, UNKNOWN, detail if detail == [_HOOKS_DISABLE] else None))

    # Only the first run of a chain acts in the state the gate reads before the command: any earlier command,
    # a git form included, can change the configuration or the hooks before a later run starts (`printf … >>
    # .git/config; git status`); a pipeline or a background job runs beside the next run; a here-document
    # feeds input the gate does not read; a command substitution runs before the run it sits in. So a free form
    # is bound only in the first run, and only in a command without `|`, `&`, `<<` or a substitution (review
    # Runde 7, R7-4). No predecessor is modelled.
    bound = not _subst_bodies(command) and not any(t[0] == "op" and t[1] in ("|", "&", "<<") for t in toks)
    run: list = []
    for t in toks:
        if t[0] == "word":
            run.append(t[1:])
        else:  # a control operator ends the run
            if run:
                _scan_run(run, emit, depth, env_set, bound)
                bound = False
            run = []
    if run:
        _scan_run(run, emit, depth, env_set, bound)
    if depth < MAX_NESTING:
        for body in _subst_bodies(command):
            emit(gated_calls(body, UNKNOWN, depth + 1, inherited_env=env_set))
    return calls


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
    toks = _lex(command)
    if toks is None or depth > MAX_NESTING:
        return [("unparsed command", UNKNOWN, None)] if _FALLBACK.search(command) else []
    words = [t[1:] for t in toks if t[0] == "word"]
    h = 0
    while h < len(words) and _ASSIGNMENT.match(words[h][0]):
        h += 1
    single = not any(t[0] == "op" for t in toks) and not _expansion_present(command)
    head_gated = h < len(words) and os.path.basename(words[h][0]) in ("git", "git-push", "gh")
    if single and head_gated:
        return _resolve_single(words, directory, inherited_env)
    return _overmatch(command, toks, depth, inherited_env)


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
    _refuse_partial_clone, which does not depend on the version."""
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
#: repository.
_PARTIAL_CLONE_KEYS = r"^(extensions\.partialclone|remote\..+\.(promisor|partialclonefilter))$"


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


def signed_subjects(kind: str, content: bytes) -> list[str]:
    """The tree digests the signed part of the evidence names; empty when it names none.

    Read only after the evidence verified, from the same committed bytes the verifier read. A bundle
    names its subject as its whole payload, the JSON of subject_statement, or beside a run record that
    shows a green run on that tree (D23). A decision receipt names it as an inputSnapshot entry with uri
    TREE_SUBJECT_URI and its digest in sha256.
    """
    try:
        document = json.loads(content.decode("utf-8"))
        if kind == "bundle":
            statement = json.loads(base64.b64decode(document["payload_b64"], validate=True).decode("utf-8"))
            keys = set(statement) if isinstance(statement, dict) else set()
            subject = statement["subject"] if keys in ({"subject"}, {"subject", "run"}) else None
            if (isinstance(subject, dict) and set(subject) == SUBJECT_KEYS
                    and subject["algorithm"] == TREE_ALGORITHM and isinstance(subject["digest"], str)):
                if "run" in keys and run_record_problem(statement["run"], subject["digest"]) is not None:
                    return []
                return [subject["digest"]]
            return []
        statement = json.loads(base64.b64decode(document["payload"], validate=True).decode("utf-8"))
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
        policy = json.loads(raw.decode("utf-8"))
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
    replies = {}
    for line in proc.stdout.splitlines():
        try:
            reply = json.loads(line)
        except ValueError:
            continue
        if isinstance(reply, dict) and isinstance(reply.get("id"), int):
            replies[reply["id"]] = reply
    results = []
    for n in range(len(requests)):
        reply = replies.get(n + 1)
        if reply is None or "result" not in reply:
            tail = (proc.stderr or "").strip().splitlines()[-1:] or ["no output"]
            raise GateError(f"the verifier gave no answer for item {n} (exit {proc.returncode}: {tail[0]})")
        text = reply["result"]["content"][0]["text"]
        results.append({"is_error": bool(reply["result"].get("isError")), **json.loads(text)})
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
        if result["is_error"] or result.get("exit_code") != 0:
            why = result.get("error") or f"exit {result.get('exit_code')}: {result.get('meaning')}"
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


class Outcome:
    """The combined answer for one call: the decision, its text, and the verdict of every repository."""

    __slots__ = ("decision", "text", "verdicts")

    def __init__(self, decision: str, text: str, verdicts: list):
        self.decision, self.text, self.verdicts = decision, text, verdicts

    def __iter__(self):
        return iter((self.decision, self.text))


def decide(command: str, cwd: str, deadline: float, host: str = "claude") -> Outcome | None:
    """None for a call the gate does not gate, else the combined outcome. Under Codex the judge cannot bind
    a gated shell call to the directory it runs in, so it reports it NOT MEASURED (review Runde 5, R5-2).
    A git form the command text leaves free is free only when the bound repository's effective configuration
    and hooks select no program for it (Nachtrag 19b); otherwise it is NOT MEASURED too."""
    global _FREE_CALLS, _FREE_BASE
    free: list = []
    _FREE_CALLS, _FREE_BASE = free, (UNKNOWN if _DIRECTORY_CHANGE.search(command) else ".")
    try:
        calls = gated_calls(command)
    finally:
        _FREE_CALLS, _FREE_BASE = None, "."
    extra = _free_call_verdicts(free, cwd, deadline, host)
    if not calls and not extra:
        return None
    return _judge(calls, cwd, deadline, host, extra=extra)


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


def decide_write(tool: str, tool_input: object, cwd: str, deadline: float, host: str = "claude") -> Outcome | None:
    """None for a file-tool write the gate does not gate; else NOT MEASURED, ask under Claude and deny under
    Codex (Nachtrag 19b, Punkt 6): a write to the configuration or the hooks of a repository changes which
    programs later git calls run, and a path the gate cannot map for sure is treated the same way.

    Under Codex every file-tool write is NOT MEASURED and denied (review Runde 7, R7-6): an apply_patch without
    `*** Environment ID:` writes into the turn's primary environment (codex-rs/core/src/tools/handlers/mod.rs at
    14a477ea, resolve_tool_environment, lines 160-178), which need not be the filesystem and directory of the
    hook's cwd, and the hook input carries nothing that binds the two. A missing environment line is no proof of
    binding, so the gate cannot tell for any path whether it is configuration or a hook."""
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
    targets = _write_targets(tool, tool_input)
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


def log_entry(host: str, event: object, outcome: "Outcome | None", actions: list[str]) -> dict:
    """What one call leaves in the log: no evidence content, no environment, no key."""
    session = event.get("session_id") if isinstance(event, dict) else None
    tool = event.get("tool_name") if isinstance(event, dict) else None
    verdict = outcome.decision if outcome is not None else "not_gated"
    sent = "none" if verdict in ("pass", "inactive", "not_gated") else ("deny" if host == "codex" else verdict)
    repos = [] if outcome is None else [
        {"path": v.repo, "head": v.head, "verdict": v.decision, "reason_id": v.reason_id, "digests": list(v.digests)}
        for v in outcome.verdicts]
    return {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "host": host, "gate_version": GATE_VERSION,
            "session_id": session if isinstance(session, str) else None,
            "tool": tool if isinstance(tool, str) else None, "actions": actions, "decision": sent,
            "verdict": verdict, "reason_ids": [r["reason_id"] for r in repos] or [verdict], "repos": repos}


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
        document = json.loads(content.decode("utf-8"))
        statement = json.loads(base64.b64decode(document["payload_b64"], validate=True).decode("utf-8"))
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
        document = json.loads(content.decode("utf-8"))
        statement = json.loads(base64.b64decode(document["payload_b64"], validate=True).decode("utf-8"))
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, binascii.Error):
        return None
    if not isinstance(statement, dict) or not isinstance(statement.get("run"), dict):
        return None
    counts = statement["run"].get("counts")
    return counts if isinstance(counts, dict) and {"passed", "tests"} <= set(counts) else None


#: git's object id of a blob: the hash of `blob <size>` NUL and the bytes; SHA-1 for 40 hexadecimal digits, SHA-256
#: for 64 (the repository's object format, gitrepository-layout(5) extensions.objectFormat).
_BLOB_HASHES = {40: hashlib.sha1, 64: hashlib.sha256}


def _working_tree_problem(repo: str, commit: str, deadline: float) -> str | None:
    """None when the working tree holds exactly the files of the commit's tree, outside the top-level
    .proofbundle/ folder the tree digest leaves out, else the first difference (review Runde 8, R8-1).

    The comparison is of the bytes a test run reads and of the path types it sees, not of what `git add`
    would stage: every committed file must be a regular file (mode 100644, or 100755 with the owner's execute
    bit) or a symbolic link (120000) whose own bytes, or link text, hash to the committed blob id, and no
    other file that git does not ignore may exist. No configured clean or smudge filter, line-ending or
    encoding rule, fsmonitor or hook runs, because none is asked: a content transformation of any kind makes
    the bytes differ and is refused before the run, never staged into agreement with HEAD. The one git call
    that lists the other files reads the ignore rules only, with an index that does not exist (so nothing
    is refreshed or written), core.fsmonitor off and an empty hook directory. Measured by the reviewer: a
    clean filter that wrote the committed value back while staging let a run on another working file be
    recorded as a run on HEAD."""
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
    for path, (mode, oid) in sorted(committed.items()):
        shown = path.decode(errors="replace")
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
            event = json.loads(sys.stdin.read())
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
