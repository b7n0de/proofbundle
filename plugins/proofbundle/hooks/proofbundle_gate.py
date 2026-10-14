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
import concurrent.futures
import errno
import fnmatch
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import secrets
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

EVIDENCE_DIR = ".proofbundle/"
DECLARATION = EVIDENCE_DIR + "evidence.json"
DECLARATION_SCHEMA = "proofbundle-plugin/evidence/v0.2"
MAX_DECLARATION_BYTES = 64 * 1024
MAX_ITEMS = 32
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
#: Evidence kinds a declaration may name. An outcome receipt is not among them: it has no field that
#: can carry a tree subject (DECISIONS.md, D16).
KINDS = ("bundle", "decision")
#: The optional done check of the declaration (DECISIONS.md, D26): the receipt of the last test run, in the
#: working tree, and the trust policy at HEAD it must verify under.
DONE_KEYS = frozenset({"receipt", "policy"})
#: The order form of the done section (D28): the checks the task requires, and optionally the paths the work may
#: change and how many blocks without progress the Stop hook makes before it writes a blocker.
DONE_ORDER_KEYS = frozenset({"policy", "checks"})
DONE_ORDER_OPTIONAL = frozenset({"paths", "max_blocks"})
CHECK_KEYS = frozenset({"id", "args", "receipt"})
MAX_CHECKS = 8
MAX_CHECK_ARGS = 64
MAX_PATHS = 64
#: Blocks without progress before the blocker (N3): three by default, at most seven, under the eight continuations
#: after which Claude Code overrides a Stop hook.
DEFAULT_MAX_BLOCKS = 3
MAX_BLOCKS_LIMIT = 7
_CHECK_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
#: The done check's own files in the evidence folder, untracked and outside the working state (D28).
DONE_STATE = EVIDENCE_DIR + "done-state.json"
DONE_METRICS = EVIDENCE_DIR + "done-metrics.json"
DONE_BLOCKER = EVIDENCE_DIR + "done-blocker.json"
DONE_OWN_FILES = (DONE_STATE, DONE_METRICS, DONE_BLOCKER)
DONE_FILES_SCHEMA = "proofbundle-plugin/done-{}/v0.1"
METRIC_KEYS = ("blocked", "task_blocked", "missing_checks", "completed_after_block", "blockers", "done")
MAX_STATE_BYTES = 64 * 1024
DONE_RECEIPT = EVIDENCE_DIR + "proofbundle_pytest_receipt.json"
DONE_POLICY = EVIDENCE_DIR + "done-policy.json"
DONE_KEY_FILE = "done-test.key"
EVAL_CLAIM_SCHEMA = "proofbundle/eval-claim/v0.1"
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
#: measured to declare nothing, carries no decision under either host (D5, D12). A `git push` under Codex is the
#: other: since owner choice Karte 5 A (2026-10-08) it keeps its NOT MEASURED reason and only warns, and since owner
#: choice K5-1 C (2026-10-08) only in its plain form; every other push form is denied (D12).
HOSTS = ("claude", "codex")
#: The sentence a Codex push warning ends with (owner choice Karte 5 A, together with D, DECISIONS.md D12).
CODEX_PUSH_WARNING = ("Under Codex the gate warns about a git push and does not deny it (owner choice Karte 5 A, "
                      "DECISIONS.md D12): the boundary is the done check at the end of the session and the required "
                      "CI check, and git's pre-push hook (Level 2, D24), which git starts in the repository the push "
                      "acts on, checks the push only where it is installed (install-pre-push, D24B).")

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
    """The gate cannot reach a verdict. Answered as deny. Where it stopped while it read a tree's evidence, `head` names
    that commit, `digests` the evidence and policy files it had read there, and `reads` the record of every source
    commit read up to then, so the log keeps them (owner choice 3 A, review round 11 of 2026-10-12, R11-5)."""

    head: str | None = None
    digests: tuple = ()
    reads: tuple = ()


class VerifierCannotStart(GateError):
    """The verifier did not start, and the gate measured why (owner choice K02-A C, DECISIONS.md D24B): uv's own answer
    names a failed write or a failed name resolution, and a probe of the gate's own confirms it. `kind` is
    "no_writable_cache" or "no_network", `sign` says what was measured; the message stays the generic one, so every
    path that is not Level 2 answers as before."""

    def __init__(self, message: str, kind: str, sign: str):
        super().__init__(message)
        self.kind, self.sign = kind, sign


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
    double-quoted parameter or command substitution appeared in it, and <raw> is the original slice. The value of a
    word without a substitution is the text the shell forms from it, read by the one rule _shell_characters also
    gives every other reader (review round 3 of 2026-10-09, R3-1), so a predicate, the repository a `-C` names and a
    proposed spelling see the bytes git receives. A line continuation between words adds no word; a backslash at the
    very end of the command, which bash keeps and zsh drops, makes the command unparsable. A newline is a ';'. A redirection is ('redir', <operator>, <target>), its target the word that follows as a
    (<value>, <has_subst>, <raw>) tuple, or None when no word follows before an operator or the end; nothing is
    dropped, so every predicate sees the targets too (review round 2 of 2026-10-09, R2-1). A here-document or
    here-string is reported as '<<'. A bare `{` or `}` word is reported as that operator."""
    s = command
    i, n = 0, len(s)
    toks: list = []
    target_of: int | None = None  # the index of the redirection whose target the next word is
    while i < n:
        c = s[i]
        if c in " \t":
            i += 1
            continue
        if s.startswith("\\\n", i):  # a line continuation is removed before the shell reads a word (R3-1)
            i += 2
            continue
        if c == "\n":
            toks.append(("op", ";")); i += 1; target_of = None; continue
        if s.startswith("&&", i):
            toks.append(("op", "&&")); i += 2; target_of = None; continue
        if s.startswith("||", i):
            toks.append(("op", "||")); i += 2; target_of = None; continue
        if s.startswith(";;", i):
            toks.append(("op", ";")); i += 2; target_of = None; continue
        m = _REDIR.match(s, i)
        if m:
            i = m.end()
            if m.group().startswith("<<"):
                toks.append(("op", "<<"))  # here-document / here-string: unknown-forcing
                target_of = None
            else:
                toks.append(("redir", m.group(), None))
                target_of = len(toks) - 1
            continue
        if c in ";|&":
            toks.append(("op", c)); i += 1; target_of = None; continue
        if c in "()":
            toks.append(("op", c)); i += 1; target_of = None; continue
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
                    if d == "\\" and i + 1 < n and s[i + 1] in _DQ_ESCAPED:
                        if s[i + 1] != "\n":
                            buf.append(s[i + 1])
                        i += 2; continue
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
                if i + 1 >= n:
                    return None  # bash keeps a backslash at the very end, zsh drops it (R3-1): not one word
                if s[i + 1] != "\n":
                    buf.append(s[i + 1])
                i += 2
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
        value = "".join(buf) if has_subst else "".join(ch for ch, _literal in _shell_characters(raw))
        if target_of is not None:
            toks[target_of] = ("redir", toks[target_of][1], (value, has_subst, raw))
            target_of = None
        elif raw in ("{", "}"):
            toks.append(("op", raw))
        else:
            toks.append(("word", value, has_subst, raw))
    return toks


def _redirection_targets(toks: list) -> list[tuple]:
    """The targets of the redirections in toks, as word tuples (value, has_subst, raw), in their order."""
    return [t[2] for t in toks if t[0] == "redir" and t[2] is not None]


#: A redirection operator that duplicates or closes a descriptor (`2>&1`, `>&2`, `<&3`, `2>&-`): it opens no file when
#: its target is a descriptor number or `-`.
_FD_DUPLICATION = re.compile(r"\d*(?:>&|<&)")


def _redirections_open_no_file(toks: list) -> bool:
    """Whether every redirection in toks opens no file: a duplication or a close of a descriptor whose target is a
    number or `-` as written, or the null device written exactly `/dev/null`. Any other redirection may create,
    truncate or read a file before the command starts, the hook of a push among them (`> .git/hooks/pre-pus?` empties
    the pre-push hook in bash and zsh, measured), so a form with one gets no positive answer (review round 2 of
    2026-10-09, R2-2). A redirection without a target, or with a target the shell expands, is not one of these."""
    for t in toks:
        if t[0] != "redir":
            continue
        target = t[2]
        if target is None:
            return False
        value, has_subst, raw = target
        if has_subst or raw != value:
            return False
        if _FD_DUPLICATION.fullmatch(t[1]) and (raw == "-" or raw.isdigit() and raw.isascii()):
            continue
        if raw != "/dev/null":
            return False
    return True


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
#: Detail marker for exactly `git add` and `git commit -m` in the plain forms _plain_add_commit accepts, as the whole
#: command (owner choice K-NW-2 B of 2026-10-08). The judge frees such a call only after the state check of its
#: repository (_add_commit_state_problem) finds nothing that starts a program for it; otherwise it asks under Claude
#: Code and is denied under Codex, with the source it found (DECISIONS.md D3, "two forms after a state check").
_STATE_FREE = "\x00state-free"
#: The details that already carry their answer (deny, ask, a possible transfer, a state check), which a redirection
#: does not change into an unresolved push (R2-2).
_MARKER_DETAILS = ([_HOOKS_DISABLE], [_NOT_FREE], [_STATE_FREE], [_MAYBE_PUSH])
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
#: exempt, and, since owner choice K-NW-2 B of 2026-10-08, exactly two forms after a state check of their repository
#: (`git add` and `git commit -m`, _plain_add_commit and _add_commit_state_problem). The separate push path remains:
#: under Claude Code it denies an evidenced failure at the commits a push sends and otherwise asks, its destination NOT
#: MEASURED (D3, R9-1), except the local inactivity of owner choice 1 A for a repository that declares nothing
#: (_local_inactivity, D5); under Codex every push is NOT MEASURED because its execution context is unbound (review Runde
#: 11, R11-5), and a `git push` warns since Karte 5 A. The two
#: readers below remain for the write gate.


def _git_text(raw: bytes) -> str:
    """Bytes git printed for a name or a value, as Python names the same bytes (os.fsdecode, surrogateescape): every
    byte survives, so os.open and every later git argument get exactly what git printed back, and a byte that is not
    UTF-8 never becomes U+FFFD, the name of another file (review round 4 of 2026-10-09, R4-2). Messages may replace
    bytes; a name or value that enters a verdict is read only through this function."""
    return raw.decode("utf-8", "surrogateescape")


def _git_lines(raw: bytes) -> list[str] | None:
    """The newline-terminated lines git printed, each through _git_text; None when the output does not end in a
    newline. Split on the newline byte alone: str.splitlines also splits on U+0085, U+2028 and the separators
    \x1c-\x1e, which a path may carry, and a strip would drop the blanks a name may end in (R4-2)."""
    if not raw.endswith(b"\n"):
        return None
    return [_git_text(line) for line in raw[:-1].split(b"\n")]


def _git_value(raw: bytes) -> str | None:
    """One value git printed, as the bytes before its one closing newline (_git_text); None when the output does not
    end in a newline or holds nothing before it. Only that newline is removed: a name may itself end in a newline, a
    CR, a TAB, U+0085 or a blank, which decode().strip() cut and rstrip(b"\\n") cut in part (review round 5 of
    2026-10-09, R5-1)."""
    if not raw.endswith(b"\n") or raw == b"\n":
        return None
    return _git_text(raw[:-1])


#: git's own answer that a directory lies in no work tree: outside every repository (also at a filesystem
#: boundary, or where GIT_DIR or a .git file names no repository), or in a git directory without one. Matched on
#: the whole message, untranslated (LC_ALL=C): a message that only contains these words, such as a configuration
#: value quoted in another error, is not this answer (R5-1).
_NO_WORK_TREE = re.compile(rb"fatal: (?:not a git repository(?: \(or any of the parent directories\): [^\n]*"
                           rb"| \(or any parent up to mount point [^\n]*\)\nStopping at filesystem boundary "
                           rb"\(GIT_DISCOVERY_ACROSS_FILESYSTEM not set\)\.|: [^\n]*)"
                           rb"|this operation must be run in a work tree)\n")


def _work_tree(directory: str, deadline: float, *flags: str) -> tuple[str | None, str]:
    """The work tree git names for directory, with the bytes it printed (_git_value): (path, "") inside one, (None,
    "") where git answers that directory lies in none (_NO_WORK_TREE), (None, why) for any other answer, a failed read
    or output that is not one absolute path. Every path that reaches a verdict reads the work tree here, so the gate
    judges exactly the repository the call names, and a read that failed never counts as no repository (review round
    5 of 2026-10-09, R5-1: a repository whose name ends in LF, CR, TAB, U+0085 or a blank was judged as its
    neighbour or as none, and a configuration git refused to read made the done check inactive)."""
    top = _git(directory, "rev-parse", *flags, "--show-toplevel", deadline=deadline)
    if top.returncode != 0:
        if _NO_WORK_TREE.fullmatch(top.stderr):
            return None, ""
        why = top.stderr.decode("utf-8", "replace").strip().splitlines()
        return None, (f"git could not name the work tree of {directory}: "
                      + (why[0] if why else f"git rev-parse exited {top.returncode}"))
    path = _git_value(top.stdout)
    if path is None or not os.path.isabs(path):
        return None, "git rev-parse --show-toplevel gave output the gate cannot read as one path"
    pins, why = _pins(directory, path, deadline)
    if pins is None:
        return None, why
    pins = {**(getattr(directory, "pins", None) or {}), **pins}   # a work tree named again keeps what it carried
    return (_Tree(path, pins) if pins else path), ""


class _Tree(str):
    """A work tree as _work_tree names it, with the values git resolved for the call's directory (review round 7 of
    2026-10-10, R7-1). Every later read of the gate runs `git -C <work tree>`; _read_env sets these values for each git
    started on it, so the read means what git meant in the directory the call named."""
    pins: dict

    def __new__(cls, path: str, pins: dict) -> "_Tree":
        tree = super().__new__(cls, path)
        tree.pins = pins
        return tree


#: The path-valued names git reads once, against the directory it starts in (review round 7 of 2026-10-10, R7-1;
#: measured with git 2.43.0 and 2.51.1): GIT_WORK_TREE=repo started in P names P/repo, started in P/repo it names
#: P/repo/repo; GIT_DIR=../.git started in sub names the top's .git. git keeps that meaning for the whole command.
_PINNED_NAMES = ("GIT_DIR", "GIT_WORK_TREE")
#: The path-valued names git reads where it works after setting up the repository. Started at or below the top of the
#: work tree, git changes into the top first, so it reads them there, as the gate's `git -C <top>` does. Started
#: outside the work tree it does not change directory, and git's own commands then disagree (measured with git 2.43.0
#: and 2.51.1, started in P with the work tree P/repo): with GIT_INDEX_FILE=idx `ls-files --others` read P/idx and
#: `status` read P/repo/idx, with core.excludesFile=ex `ls-files` read P/ex and `check-ignore` read P/repo/ex. No one
#: value names what git reads, so the gate does not read them there (NOT MEASURED). HOME, XDG_CONFIG_HOME and the two
#: configuration files name where core.excludesFile comes from when it is not set elsewhere.
_PHASED_NAMES = ("GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                 "GIT_SHALLOW_FILE", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "HOME", "XDG_CONFIG_HOME")
#: The configuration keys whose relative path git reads in the same two places, and that a read of the gate uses:
#: the exclude file of `ls-files --exclude-standard` and the attributes file of the state digest.
_PHASED_KEYS = ("core.excludesFile", "core.attributesFile")


def _relative_value(name: str, value: str | None) -> bool:
    """Whether value names a path relative to a directory. An empty value names none, the same in every directory
    (git refuses an empty GIT_DIR or GIT_WORK_TREE, and opens no file for the others). The alternates are a list
    separated by colons, an entry in double quotes is unquoted by git and counted as relative here."""
    if not value:
        return False
    if name == "GIT_ALTERNATE_OBJECT_DIRECTORIES":
        return '"' in value or any(entry and not os.path.isabs(entry) for entry in value.split(":"))
    return not os.path.isabs(value)


def _pins(directory: str, top: str, deadline: float) -> tuple[dict | None, str]:
    """The values every later read on the work tree top needs so that it reads what git started in directory reads
    (R7-1): ({}, "") when none is needed, (pins, "") with absolute values git itself named in directory, (None, why)
    where no value names what git reads there (NOT MEASURED).

    Nothing is needed when directory is the top itself, or when the host gives no relative path and no GIT_WORK_TREE
    without GIT_DIR. Otherwise a relative GIT_DIR becomes the git directory git names in directory, a relative
    GIT_WORK_TREE becomes top. GIT_WORK_TREE without GIT_DIR makes git find the repository from directory, and a read
    started in top could find another one (a repository nested between them, or the one of top where directory lies in
    an outer repository): GIT_DIR becomes the one git found. Started outside the work tree, a relative value of a
    _PHASED_NAMES name or of a _PHASED_KEYS key is NOT MEASURED."""
    environ = dict(os.environ, **(getattr(directory, "pins", None) or {}))
    pinned = [n for n in _PINNED_NAMES if _relative_value(n, environ.get(n))]
    phased = [n for n in _PHASED_NAMES if _relative_value(n, environ.get(n))]
    found = environ.get("GIT_WORK_TREE") is not None and environ.get("GIT_DIR") is None
    try:
        if os.path.samefile(directory, top):
            return {}, ""
    except OSError:
        pass
    inside = _git(directory, "rev-parse", "--is-inside-work-tree", deadline=deadline)
    if inside.returncode != 0 or inside.stdout not in (b"true\n", b"false\n"):
        return None, f"git could not say whether {directory} lies inside its work tree"
    if inside.stdout == b"false\n":
        for key in _PHASED_KEYS:
            value = _git(directory, "config", "--type=path", "--get", key, deadline=deadline)
            if value.returncode == 1 and not value.stdout and not value.stderr:
                continue
            if value.returncode != 0 or not value.stdout.endswith(b"\n"):
                return None, f"git could not read {key} in {directory}"
            if _relative_value(key, _git_text(value.stdout[:-1])):
                phased.append(key)
        if phased:
            return None, (f"{', '.join(phased)} names a relative path, and {directory} lies outside the work tree "
                          f"{top}: git's own commands read it there and in the work tree (ls-files and status read "
                          "two different files), so no read of the gate means what git reads (NOT MEASURED); give "
                          "it as an absolute path, or run from inside the work tree")
    if not pinned and not found:
        return {}, ""
    out = _git(directory, "rev-parse", "--absolute-git-dir", deadline=deadline)
    gitdir = _git_value(out.stdout) if out.returncode == 0 else None
    if gitdir is None or not os.path.isabs(gitdir):
        return None, f"git could not name the git directory of {directory} as one absolute path"
    pins = {"GIT_DIR": gitdir} if ("GIT_DIR" in pinned or found) else {}
    if "GIT_WORK_TREE" in pinned:
        pins["GIT_WORK_TREE"] = top
    return pins, ""


def _config_entries(directory: str, deadline: float) -> tuple[list | None, str]:
    """The effective configuration as git itself reads it in directory, with the hook's environment:
    (scope, origin, key, value) per entry, value None for a key without '='. None when git cannot read it
    (an unreadable or malformed file, an include it cannot open: measured, `git config --list` exits 128).
    Origins and values keep their bytes (_git_text, R4-2)."""
    out = _git(directory, "config", "--list", "--null", "--show-origin", "--show-scope", deadline=deadline)
    if out.returncode != 0:
        why = out.stderr.decode("utf-8", "replace").strip().splitlines()
        return None, (why[-1] if why else f"git config exited {out.returncode}")
    parts = out.stdout.split(b"\0")
    if parts[-1] != b"" or (len(parts) - 1) % 3:
        return None, "git config --list --null --show-origin --show-scope gave output the gate cannot read"
    entries = []
    for i in range(0, len(parts) - 1, 3):
        scope, origin, kv = (_git_text(x) for x in parts[i:i + 3])
        key, nl, value = kv.partition("\n")
        entries.append((scope, origin, key, value if nl else None))
    return entries, ""


def _repo_paths(directory: str, deadline: float) -> tuple[dict | None, str]:
    """{'hooks', 'common', 'gitdir', 'toplevel'} of the repository at directory (all None outside one), each with the
    bytes git printed (_git_lines, R4-2); a path that is not absolute is output the gate cannot read."""
    out = _git(directory, "rev-parse", "--path-format=absolute", "--git-common-dir", "--git-dir",
               "--git-path", "hooks", deadline=deadline)
    if out.returncode != 0:
        if _NO_WORK_TREE.fullmatch(out.stderr):
            return {"hooks": None, "common": None, "gitdir": None, "toplevel": None}, ""
        return None, out.stderr.decode("utf-8", "replace").strip() or f"git rev-parse exited {out.returncode}"
    lines = _git_lines(out.stdout)
    if lines is None or len(lines) != 3 or not all(os.path.isabs(line) for line in lines):
        return None, "git rev-parse gave output the gate cannot read"
    common, gitdir, hooks = lines
    toplevel, why = _work_tree(directory, deadline, "--path-format=absolute")
    if why:
        return None, why
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


#: Characters with which a shell may rewrite an unquoted word into other words or other text before git sees it (review
#: 2026-10-09, F2): a glob (`*`, `?`, `[`, every POSIX shell), a brace expansion (`{`, bash, zsh and ksh) and zsh's
#: extended glob (`^`, `#`, under EXTENDED_GLOB). A `(` ends the word for the lexer, so an extglob or a glob qualifier
#: never reaches a free form. zsh's `~` inside a word excludes only together with another of these characters (measured
#: with zsh 5.9: `a.txt~b` stays as it is, `a.tx#t~b` becomes `a.txt`), so it needs no entry of its own.
_REWRITE_CHARS = frozenset("*?[{^#")
#: The tilde form the gate models as os.path.expanduser does: the plain `~`, then a slash or the end of the word. `~name`
#: is not modelled: zsh resolves it through its table of named directories (`hash -d`), state of the running shell the
#: gate cannot read, before the user names expanduser knows (review round 3 of 2026-10-09, R3-2). The shell's `~+`,
#: `~-` and `~N` name directories of the shell's own state as well.
_TILDE_MODELLED = re.compile(r"~(?:/|$)")


#: The characters a backslash escapes inside double quotes (POSIX 2.2.3, measured with bash 5.2 and zsh 5.9): before any
#: other character the backslash stays a character of the word.
_DQ_ESCAPED = '$`"\\\n'


def _shell_characters(raw: str) -> list[tuple[str, bool]]:
    """The characters a word as written contributes, each with whether it is literal (quoted or escaped): the one word
    formation of the gate, which the lexer's value, the hint of a narrower spelling and the repository a `-C` names all
    read (review round 3 of 2026-10-09, R3-1). A line continuation (backslash-newline, outside and inside double
    quotes) is removed before the shell reads the word, and an empty quote contributes nothing, so neither stands
    between a character and the start of the word or the character before it (review round 2 of 2026-10-09, R2-6).
    Inside double quotes a backslash escapes only what _DQ_ESCAPED names; before any other character it is a
    character of the word, as `"a\\b"` gives git `a\\b`."""
    chars: list[tuple[str, bool]] = []
    i, n = 0, len(raw)
    while i < n:
        c = raw[i]
        if c == "\\":
            if i + 1 < n and raw[i + 1] != "\n":
                chars.append((raw[i + 1], True))
            i += 2
        elif c == "'":
            j = raw.find("'", i + 1)
            j = n if j < 0 else j
            chars.extend((ch, True) for ch in raw[i + 1:j])
            i = j + 1
        elif c == '"':
            i += 1
            while i < n and raw[i] != '"':
                if raw[i] == "\\" and i + 1 < n and raw[i + 1] in _DQ_ESCAPED:
                    if raw[i + 1] != "\n":
                        chars.append((raw[i + 1], True))
                    i += 2
                else:
                    chars.append((raw[i], True))
                    i += 1
            i += 1
        else:
            chars.append((c, False))
            i += 1
    return chars


def _shell_rewrites(raw: str, tilde_modelled: bool = False) -> bool:
    """Whether the shell may rewrite the word as written (its raw text, quotes included) before the command sees it,
    read at the characters it contributes (_shell_characters): an unquoted, unescaped character of _REWRITE_CHARS; an
    unquoted `~` or `=` that comes first (a home or a directory of the shell's state; zsh's command path, `=git`) or
    right after an unquoted `=` or `:` (bash expands `a=~/x`; zsh under MAGIC_EQUAL_SUBST also `a=''~`, `a==git` and
    `a=b:=git`; measured with bash 5.2 and zsh 5.9). An empty quote and a line continuation count for nothing, so
    `''~` and a backslash-newline before `~` are a leading `~` (review round 2 of 2026-10-09, R2-6). With
    tilde_modelled, a leading `~` stays literal only in a form _TILDE_MODELLED names that the written word itself
    starts with, unquoted: there os.path.expanduser reads it like every shell. Inside '…' and "…" and after a
    backslash a character is literal. A word that may be rewritten is not the word the gate read: a file named
    `--edit` turns `*` into an option (review 2026-10-09, F2)."""
    chars = _shell_characters(raw)
    for k, (c, literal) in enumerate(chars):
        if literal:
            continue
        if c in _REWRITE_CHARS:
            return True
        if c in "~=":
            if k == 0:
                if c == "=" or not (tilde_modelled and raw.startswith("~") and _TILDE_MODELLED.match(raw)):
                    return True
            elif chars[k - 1] in (("=", False), (":", False)):
                return True
    return False


def _hooks_off(key: str) -> bool:
    """Whether a git config key is `core.hooksPath` (any case), which would redirect or disable the hook."""
    return key.strip().lower() == "core.hookspath"


#: The options of the two forms K-NW-2 B frees (DECISIONS.md D3). `git add` takes pathspecs and -A/--all/-u/--update;
#: `git commit` takes at least one message (-m, --message, a -m inside a cluster of a and q), -a/--all, -q/--quiet and
#: pathspecs. Every other option of either form (-p, -i, -e, -S, -v, --amend, -F, -C, --trailer, --no-verify, …)
#: leaves the form as it is today, not free: an editor, a signing program, a diff or a trailer command can start.
_ADD_OPTIONS = frozenset({"-A", "--all", "-u", "--update"})
_COMMIT_FLAGS = frozenset({"-a", "--all", "-q", "--quiet"})


def _plain_add_commit(sub: str, args: list[str], rewrites: list[bool] | None = None) -> bool:
    """Whether `git <sub> <args>` is one of the two plain forms K-NW-2 B frees after the state check: `git add` with
    pathspecs and only the options of _ADD_OPTIONS, or `git commit` with at least one message and only -a, -q and
    pathspecs. A `--` ends the options; a lone `-` is no pathspec here. `rewrites` says, word by word, whether the
    shell may rewrite it (_shell_rewrites): such a word before the `--` that ends the options, a message included,
    may become an option, so the form is not free (review 2026-10-09, F2); after that `--` it stays a pathspec."""
    after_dashdash = False
    rewritten = list(rewrites) if rewrites is not None else [False] * len(args)
    if sub == "add":
        for n, word in enumerate(args):
            if after_dashdash:
                continue
            if rewritten[n]:
                return False
            if word == "--":
                after_dashdash = True
            elif word.startswith("-") and word not in _ADD_OPTIONS:
                return False
        return True
    if sub != "commit":
        return False
    message, i = False, 0
    while i < len(args):
        word = args[i]
        if after_dashdash:
            i += 1
            continue
        if rewritten[i]:
            return False
        if word == "--":
            after_dashdash = True
        elif word in ("-m", "--message"):
            if i + 1 >= len(args) or rewritten[i + 1]:
                return False
            message, i = True, i + 1
        elif word.startswith("--message="):
            message = True
        elif word in _COMMIT_FLAGS:
            pass
        elif word.startswith("-") and not word.startswith("--") and len(word) > 1:
            for n, letter in enumerate(word[1:]):
                if letter in "aq":
                    continue
                if letter != "m":
                    return False
                if not word[n + 2:]:          # -am: the message is the next word
                    if i + 1 >= len(args) or rewritten[i + 1]:
                        return False
                    i += 1
                message = True                # -mMSG or -aqmMSG: the rest of the word is the message
                break
        elif word.startswith("-"):
            return False
        i += 1
    return message


def _redirection_present(command: str) -> bool:
    """Whether the command carries a redirection or a here-document outside quotes (`<`, `>`). The two forms K-NW-2 B
    frees are free only as the whole command without one, so a free call never writes a file the gate did not see."""
    i, n, quote = 0, len(command), None
    while i < n:
        c = command[i]
        if quote == "'":
            if c == "'":
                quote = None
        elif c == "\\":
            i += 1
        elif quote == '"':
            if c == '"':
                quote = None
        elif c in "'\"":
            quote = c
        elif c in "<>":
            return True
        i += 1
    return False


#: The configuration keys the state check positively understands as starting no program for `git add` and for
#: `git commit -m` (DECISIONS.md D3, K-NW-2 B). Any other key leaves the form not free, so the list frees only what it
#: names, in the spirit of Nachtrag 37. Each group is inert for these two forms: the repository format and the stat and
#: line-ending options git applies itself; the identity; the editor and pager, which neither form starts (no -e, no
#: pager for add or commit); signing settings that act only when signing is on, which commit.gpgSign and -S decide;
#: the settings of other commands (remotes, branches, push, pull, init, colours, advice, aliases, which git never
#: applies to a built-in); and the transport settings (http, credential, url rewrites, the ssh command and askpass),
#: inert because neither form talks to a remote: a partial clone's lazy fetch is excluded, since its promisor keys are
#: not on the list, and so is prefetch, since maintenance.* is refused; git's own default maintenance after a commit
#: runs only its gc task (git-maintenance(1)). include.path and includeIf.*.path are read through: git reads the
#: included files into the same list the check reads, and every entry they add is judged like any other.
_STATE_INERT_KEYS = frozenset({
    "core.repositoryformatversion", "core.filemode", "core.bare", "core.logallrefupdates", "core.ignorecase",
    "core.precomposeunicode", "core.symlinks", "core.autocrlf", "core.eol", "core.safecrlf", "core.checkstat",
    "core.trustctime", "core.quotepath", "core.excludesfile", "core.editor", "core.pager", "core.hookspath",
    "extensions.objectformat", "user.name", "user.email", "user.signingkey", "author.name", "author.email",
    "committer.name", "committer.email", "init.defaultbranch", "safe.directory", "gpg.format", "tag.gpgsign",
    "commit.gpgsign", "core.fsmonitor", "include.path", "core.sshcommand", "core.askpass",
})
_STATE_INERT_PATTERN = re.compile(r"(remote\.[^\n]*\.(url|pushurl|fetch)|branch\.[^\n]*\.(remote|merge)"
                                  r"|includeif\.[^\n]*\.path|push\.[a-z0-9]+|pull\.[a-z0-9]+|http\.[^\n]+"
                                  r"|color\.[^\n]+|advice\.[a-z0-9]+|alias\.[^\n]+|credential\.[^\n]+"
                                  r"|url\.[^\n]*\.(insteadof|pushinsteadof))")
#: The spellings of false that git reads as false and the state check accepts for commit.gpgSign and core.fsmonitor.
#: Every other value, a number included (review Runde 9: `2`, `1k`, `0x1` are true), counts as on.
#: Hook names githooks(5) of git 2.43 documents and neither `git add` nor `git commit -m` runs: the hooks of push,
#: receive, rebase, checkout, merge, am, send-email and p4, and fsmonitor-watchman, which only core.fsmonitor selects.
#: A hook of any other name, an unknown one included, leaves the form not free (pre-commit, prepare-commit-msg,
#: commit-msg, post-commit, post-index-change, reference-transaction and pre-auto-gc run on these forms).
_HOOKS_NOT_RUN_BY_ADD_COMMIT = frozenset({
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-merge-commit", "pre-rebase", "post-checkout",
    "post-merge", "pre-push", "pre-receive", "update", "proc-receive", "post-receive", "post-update",
    "push-to-checkout", "post-rewrite", "sendemail-validate", "p4-changelist", "p4-prepare-changelist",
    "p4-post-changelist", "p4-pre-submit", "fsmonitor-watchman",
})
#: GIT_* names in the hook's environment the state check accepts: the configuration files and entries git itself reads
#: into the list the check reads, the identity, the editor, sequence editor and pager neither form starts, and the
#: transport settings neither form uses (as above). Any other GIT_* name (GIT_EXEC_PATH, GIT_DIR, GIT_INDEX_FILE,
#: GIT_TRACE, …) leaves the form not free.
_STATE_INERT_ENV = re.compile(r"GIT_(CONFIG_(GLOBAL|SYSTEM|NOSYSTEM|PARAMETERS|COUNT|KEY_[0-9]+|VALUE_[0-9]+)"
                              r"|(AUTHOR|COMMITTER)_(NAME|EMAIL|DATE)|TERMINAL_PROMPT|EDITOR|SEQUENCE_EDITOR|PAGER"
                              r"|ASKPASS|SSH|SSH_COMMAND|SSH_VARIANT|SSL_[A-Z_]+|HTTP_[A-Z_]+)")


def _git_false(directory: str, value: str | None, deadline: float) -> bool:
    """Whether git reads value as the boolean false, asked of git itself with no configuration read (--type=bool on a
    default the null device cannot override, as _git_path does): `0`, ` 0`, `00`, `FALSE` and the empty value are
    false, ` no`, `no `, `false ` and `0 ` are no boolean at all, and core.fsmonitor then names a program git starts
    (measured with git 2.43.0; review round 5 of 2026-10-09, the class of R5-1: a strip made them `no` and `false`).
    A key without a value is true."""
    if value is None:
        return False
    out = _run_git(directory, ("config", "--file", os.devnull, "--type=bool", "--default", value, "--get",
                               "proofbundle-gate.boolean"), deadline)
    return out.returncode == 0 and out.stdout == b"false\n"


def _program_source(key: str, value: str | None, directory: str, deadline: float) -> str | None:
    """The program source a lower-cased configuration key names for `git add` or `git commit -m`, or None: a filter
    driver (any filter.* key, an empty driver name included), a hook (config hooks and gc.recentObjectsHook, which
    automatic maintenance runs after a commit), fsmonitor, a signature program (gpg.program, gpg.<format>.program,
    gpg.ssh.defaultKeyCommand, commit.gpgSign on), or automatic maintenance beyond git's own default (maintenance.*,
    gc.*). fsmonitor and commit.gpgSign are off only where git itself reads the value as false (_git_false)."""
    if key.startswith("filter."):
        return "filter"
    if key.startswith("hook.") or key == "gc.recentobjectshook":
        return "hook"
    if key == "core.fsmonitor" and not _git_false(directory, value, deadline):
        return "fsmonitor"
    if key == "gpg.program" or (key.startswith("gpg.") and key.endswith(".program")) \
            or key == "gpg.ssh.defaultkeycommand":
        return "signature program"
    if key == "commit.gpgsign" and not _git_false(directory, value, deadline):
        return "signature program"
    if key.startswith("maintenance.") or key.startswith("gc."):
        return "automatic maintenance"
    return None


def _standard_config_files(directory: str, deadline: float, paths: dict) -> set[str]:
    """The files git reads configuration from without an include: system, global, the repository's config and
    config.worktree, as git var and rev-parse name them. A file outside this set came in through an include."""
    files = set()
    for name in ("GIT_CONFIG_SYSTEM", "GIT_CONFIG_GLOBAL"):
        out = _git(directory, "var", name, deadline=deadline)
        if out.returncode == 0:
            files.update(os.path.realpath(line) for line in _git_lines(out.stdout) or () if line)
    for base, leaf in ((paths["common"], "config"), (paths["gitdir"], "config.worktree")):
        if base:
            files.add(os.path.realpath(os.path.join(base, leaf)))
    return files


def _add_commit_state_problem(directory: str, deadline: float, environ: dict | None = None) -> str | None:
    """None when the repository at directory holds nothing that starts a program for `git add` or `git commit -m`,
    else what it found (K-NW-2 B, DECISIONS.md D3). Read: the effective configuration with every include (git config
    --list in the hook's environment, so the same files the call reads), the effective hook directory (core.hooksPath
    resolved by git), and the hook's GIT_* environment. A source the owner named (filter, hook, fsmonitor, signature
    program, an include onto one) is named as such; any configuration key, hook or GIT_* name the check does not
    positively understand is named too, and either keeps the form not free. Not read: the program PATH selects (the
    D27 class, F15-3), and gitattributes, which select a driver only a filter.* or diff.* key defines."""
    environ = os.environ if environ is None else environ
    paths, why = _repo_paths(directory, deadline)
    if paths is None:
        return f"the gate cannot read the repository's layout ({why})"
    if paths["gitdir"] is None or paths["toplevel"] is None:
        return "the directory is not inside a git work tree"
    entries, why = _config_entries(directory, deadline)
    if entries is None:
        return f"the gate cannot read the effective configuration ({why})"

    def origin_of(scope: str, origin: str) -> str:
        # git names a file relative to the directory it ran in (`git -C directory`), e.g. file:.git/config
        where = origin.removeprefix("file:")
        if origin.startswith("file:") and os.path.realpath(os.path.join(directory, where)) not in \
                _standard_config_files(directory, deadline, paths):
            return f"through an include, in {where}"
        return f"in the {scope} configuration {where}"

    for scope, origin, key, value in entries:
        source = _program_source(key.lower(), value, directory, deadline)
        if source is not None:
            return f"a {source}: {key} {origin_of(scope, origin)}"
    for scope, origin, key, value in entries:
        lowered = key.lower()
        if lowered not in _STATE_INERT_KEYS and not _STATE_INERT_PATTERN.fullmatch(lowered):
            return f"a configuration key the check does not know to start no program: {key} {origin_of(scope, origin)}"
    hooks = paths["hooks"]
    if hooks and os.path.lexists(hooks):
        if not os.path.isdir(hooks):
            return f"a hook: the hook directory {hooks} is not a directory"
        try:
            names = sorted(os.listdir(hooks))
        except OSError as exc:
            return f"a hook: the hook directory {hooks} cannot be read ({exc})"
        for name in names:
            if not name.endswith(".sample") and name not in _HOOKS_NOT_RUN_BY_ADD_COMMIT:
                return f"a hook: {os.path.join(hooks, name)}"
    for name in sorted(environ):
        if name.startswith("GIT_") and not _STATE_INERT_ENV.fullmatch(name):
            return f"an environment setting the check does not know to start no program: {name}"
    return None


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


def _strict_git(words: list[str], directory: str | None, free_base: object = _FROM_DIRECTORY,
                rewrites: list[bool] | None = None,
                raws: list[str] | None = None) -> tuple[str, str | None, list[str] | None] | None:
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
    command the gate does not see (review Runde 5, Punkt 6/7/8). Its arguments are never read with the push parser.
    `raws` are the words as written: a `-C` value is expanded as a home directory only where the shell expands it, a
    `~` the written word starts with, unquoted and unescaped; a quoted or escaped `~` is the directory named `~`
    (review round 2 of 2026-10-09, R2-3). Without `raws` a value is read literally."""
    i, c_count, not_measured, deny, alias_config = 0, 0, False, False, False
    start, c_values = directory, []
    while i < len(words) and words[i].startswith("-"):
        option, eq, inline = words[i].partition("=")
        has_value = option in _GIT_GLOBAL_VALUE
        value = inline if eq else (words[i + 1] if has_value and i + 1 < len(words) else "")
        if option == "-C" and value and "$" not in value:
            c_count += 1
            shell_tilde = not eq and raws is not None and i + 1 < len(raws) and raws[i + 1].startswith("~")
            named = os.path.expanduser(value) if shell_tilde else value
            c_values.append(named)
            # A value the shell may rewrite (a glob, a `~name`, a tilde after an empty quote) names a directory the
            # gate cannot know, for every subcommand: no free form and no verdict about another repository (R3-2).
            rewritten_value = not eq and rewrites is not None and i + 1 < len(rewrites) and rewrites[i + 1]
            directory = (os.path.join(directory, named) if directory is not UNKNOWN and not rewritten_value
                         else UNKNOWN)
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
    if sub in ("add", "commit") and i == 0 and free_base is _FROM_DIRECTORY and start is not UNKNOWN \
            and _plain_add_commit(sub, args, None if rewrites is None else rewrites[i + 1:]):
        # K-NW-2 B (2026-10-08): the whole command is a plain `git add` or `git commit -m` with no global option;
        # the judge frees it only after the state check of its repository.
        return f"git {sub}", directory, [_STATE_FREE]
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
    # The value of a `-C` that starts with `~` as written is joined with os.path.expanduser (_strict_git), so a plain
    # `~` there is modelled; a quoted or escaped one stays the literal directory (R2-3).
    rewritten = [_shell_rewrites(w[2], tilde_modelled=k > i + 1 and words[k - 1][0] == "-C")
                 for k, w in enumerate(words) if k > i]
    if base not in ("git", "git-push", "gh"):
        return []
    bare = head == base
    if base == "gh":
        name = _gh_call(rest)
        if name is None:
            return []
        return [(name, directory if (bare and neutral_only and not any(rewritten)) else UNKNOWN, None)]
    # A program path (`./git`, `/opt/x/git`) names a program the gate does not know, so even `git --version` there
    # is NOT MEASURED (review Runde 7, R7-4; Runde 8, R8-5).
    call = (("git push", directory, rest) if base == "git-push"
            else _strict_git(rest, directory, free_base=_FROM_DIRECTORY if bare else UNKNOWN, rewrites=rewritten,
                             raws=[w[2] for w in words[i + 1:]]))
    if call is None:
        # The free `git --version` is free only without an unvetted prefix assignment: the environment selects
        # programs as configuration does (review Runde 6, R6-2 class), so it is NOT MEASURED.
        return [] if neutral_only else [("git --version", UNKNOWN, [_NOT_FREE])]
    name, cdir, detail = call
    if detail in ([_HOOKS_DISABLE], [_NOT_FREE]):
        return [call]  # a hook-disabling form denies and a repository form asks, whatever the context
    if detail == [_STATE_FREE] and not neutral_only:
        return [(name, UNKNOWN, [_NOT_FREE])]  # an unvetted assignment may select a program, as configuration does
    if not (bare and neutral_only):
        return [(name, UNKNOWN, None)]
    if cdir is not UNKNOWN and detail != [_STATE_FREE] and any(rewritten):
        # A word the shell may rewrite is not the word the resolver read: the target, a refspec or an option of the
        # push may differ (review 2026-10-09, F2). The plain forms decided that word by word above.
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
        elif t[0] == "redir":
            # A redirection does not end the simple command, and its target is read as one of its words: a shell
            # that reads the text another way (zsh's numeric glob `<1-2>`) gives git that word (R2-1). Reading
            # more words can only find more gated calls or a hook-disabling form, never free one.
            if t[2] is not None:
                run.append(t[2])
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
    was balanced. A `)` is suppressed inside a quote (review Runde 11, R11-1 case 3), after a backslash escape,
    and inside a `#` comment (Nachtrag 37, R14-3): a backslash-escaped paren, a quoted paren and a paren in a
    comment do not close the substitution, so the boundary is found under understood syntax. An unbalanced opener
    yields the rest of the text and ok=False, so the caller treats the context as NOT MEASURED."""
    depth, j, quote, n = 0, start, None, len(text)
    while j < n:
        ch = text[j]
        if quote is not None:
            if quote == '"' and ch == _BACKSLASH and j + 1 < n:
                j += 2
                continue
            if ch == quote:
                quote = None
            j += 1
            continue
        if ch == _BACKSLASH:            # a backslash escapes the next char, a `)` or `(` included (R14-3)
            j += 2
            continue
        if ch in "'\"":
            quote = ch
        elif ch == "#" and (j == start + 1 or text[j - 1] in " \t\n("):  # a comment runs to the line end (R14-3)
            nl = text.find(chr(10), j)
            j = n if nl < 0 else nl
            continue
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:j], j + 1, True
        j += 1
    return text[start + 1:], n, False


#: How the first words of a simple command bear on its program position (Nachtrag 37, R14-1). The net frees an
#: active expansion only as a data argument of a program word it has positively identified; these sets say when
#: that identification does NOT hold, so an expansion at or after the word is NOT MEASURED instead of free. They
#: only ADD strictness: a word in none of them is treated as an ordinary program, which for a genuinely unknown
#: program is a named recognition boundary (like an alias or a function), never the silent git/gh pass R14-1
#: shows. Extending them can only move more forms to NOT MEASURED, never free one — this is why the fix is the
#: positive-role rule and not a longer wrapper list ("keine weitere Namensliste als Schließung", review Runde 14).
#:
#: _NET_PREFIX_TRANSPARENT: reserved words after which a real command (a program position) follows immediately,
#: with no option in between — the next word is re-examined as the program word (so `if gi* …` tests `gi*`).
_NET_PREFIX_TRANSPARENT = frozenset({"if", "while", "until", "then", "elif", "else", "do", "!"})
#: Known command wrappers that run another program given as their argument, and reserved words (`time`, `coproc`)
#: that do the same. An option of the wrapper can shift the program further right (`env -- gi*`, `time -p gi*`),
#: and the net does not model each wrapper's options, so once a wrapper heads the command the program position is
#: unproven and any active expansion after it is NOT MEASURED (R14-1, R14-5).
_NET_EXPANSION_WRAPPERS = frozenset({"sudo", "env", "command", "builtin", "exec", "nice", "nohup", "ionice",
                                     "setsid", "stdbuf", "nocorrect", "xargs", "timeout", "time", "doas",
                                     "chroot", "runuser", "watch", "nix-shell", "coproc"})
#: Reserved words that open or close shell grammar the net does not model as a simple command (a `case`/`for`
#: head, a `[[ … ]]` test). An active expansion inside such grammar is not a proven data argument, so it is
#: NOT MEASURED rather than free.
_NET_STRUCTURAL_KEYWORDS = frozenset({"case", "esac", "for", "select", "function", "in", "fi", "done",
                                      "[[", "]]"})
#: The program position is unproven when the head word is one of these.
_NET_POSITION_UNSAFE = _NET_EXPANSION_WRAPPERS | _NET_STRUCTURAL_KEYWORDS
#: Operators (as _lex reports them) after which a new simple command, hence a new program position, begins.
_NET_CMD_START = frozenset({";", "&&", "||", "|", "&", "(", "{"})


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


def _net_position_unmodeled(toks: list) -> bool:
    """Whether any simple command in toks carries an active expansion whose data-argument role is NOT proven
    (Nachtrag 37, R14-1). The role is proven only inside a simple command whose program word is a plain literal
    command the net recognises in place — not an active expansion itself (`gi*`, `g{i..i}t`), not a substitution,
    not `--`, not a wrapper and not a reserved word that opens other grammar. Then, and only then, an active
    expansion in a following argument is data and stays free (`ls *.py`, `cp f.{txt,bak}`). A prefix assignment
    keeps the program position (its right side does not glob in bash). A reserved word after which a command
    follows (`if`, `while`, `then`, …) is transparent, so the next word is examined as the program. A wrapper, a
    structural reserved word, `--`, a substitution or an expansion in the program position leaves the real
    program unproven, and then any active expansion at or after it is NOT MEASURED — because it could be the
    program bash actually runs. Adding wrapper names would only move more forms here, never free one (R14-5)."""
    state = "prefix"   # prefix: before the program word | args: after a proven program word | blocked: unproven
    for t in toks:
        if t[0] == "op":
            if t[1] in _NET_CMD_START:
                state = "prefix"
            continue
        if t[0] == "redir":
            continue                       # a redirection names no program; its target is data
        value, raw = t[1], t[3]
        active = _unquoted_active_expansion(raw)
        if state == "args":
            continue                       # an argument of a proven program: an expansion here is data
        if state == "blocked":
            if active:
                return True                # the real program position is unknown; this expansion could be it
            continue
        if _ASSIGNMENT.match(value):
            continue                       # a leading prefix assignment; its right side is a literal value
        base = os.path.basename(value)
        if base in _NET_PREFIX_TRANSPARENT:
            continue                       # a reserved word after which a command follows: examine the next word
        if active:
            return True                    # the program word itself is an active expansion → NOT MEASURED
        if t[2] or value == "--" or base in _NET_POSITION_UNSAFE:
            state = "blocked"              # a substitution, `--`, a wrapper or structural grammar: unproven
            continue
        state = "args"                     # a plain literal program word: its later expansions are data
    return False


def _net_case_balanced(body: str) -> bool:
    """Whether a command-substitution body opens and closes its `case` statements in balance (Nachtrag 37,
    R14-3). An extracted body with more `case` than `esac` keywords means a `)` case-pattern terminator was taken
    for the substitution's end, so the boundary _balanced_paren found is not the one bash uses, and the whole call
    must be NOT MEASURED. An unparsable body is reported balanced here — the recursive _net_unmodeled on it already
    returns NOT MEASURED for the unparsable reason, so this axis does not need to."""
    toks = _lex(_drop_comments(body))
    if toks is None:
        return True
    opens = sum(1 for t in toks if t[0] == "word" and t[1] == "case")
    closes = sum(1 for t in toks if t[0] == "word" and t[1] == "esac")
    return opens <= closes


def _net_subcontexts(text: str) -> tuple[list, bool]:
    """The bodies of the executable contexts embedded at the top level of text — a command substitution `$(…)` or
    a backtick (inside double quotes too) and a process substitution `<(…)`/`>(…)` outside quotes — and whether
    every boundary was found under understood syntax (Nachtrag 37, R14-2/R14-3). A single quote suppresses them.
    boundary_ok is False when an opener never closes and when an extracted `$(…)`/backtick body does not balance
    its `case`/`esac`; the caller then treats the whole command as NOT MEASURED. Escaped parens, quoted parens and
    parens in a comment are already excluded by _balanced_paren, so they do not falsify a boundary here."""
    bodies: list = []
    ok = True
    i, n = 0, len(text)
    single = double = False
    while i < n:
        ch = text[i]
        if single:
            if ch == "'":
                single = False
            i += 1
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == "(" and not (i + 2 < n and text[i + 2] == "("):
            inner, j, closed = _balanced_paren(text, i + 1)
            bodies.append(inner)
            ok = ok and closed and _net_case_balanced(inner)
            i = j
            continue
        if ch == chr(96):
            j = text.find(chr(96), i + 1)
            if j < 0:
                ok = False
                break
            inner = text[i + 1:j]
            bodies.append(inner)
            ok = ok and _net_case_balanced(inner)
            i = j + 1
            continue
        if not double and ch in "<>" and i + 1 < n and text[i + 1] == "(":
            inner, j, closed = _balanced_paren(text, i + 1)
            bodies.append(inner)
            ok = ok and closed
            i = j
            continue
        if double:
            if ch == '"':
                double = False
            elif ch == _BACKSLASH and i + 1 < n and text[i + 1] in ('"', _BACKSLASH, "$", chr(96)):
                i += 2
                continue
            i += 1
            continue
        if ch == "'":
            single = True
        elif ch == '"':
            double = True
        elif ch == _BACKSLASH and i + 1 < n:
            i += 2
            continue
        i += 1
    return bodies, ok


def _net_unmodeled(text: str, depth: int = 0) -> bool:
    """THE single site that decides understood versus NOT MEASURED for the net (Nachtrag 37, Punkt 2). Every path
    on which the net reaches no git/gh answer passes through here, so decide() never frees a form it did not
    positively understand. It returns True — NOT MEASURED — for a closed set of reasons, each a class of the
    review:
      · the normal form itself cannot be built from understood bytes: a locale quote `$"…"`, a decoded NUL, an
        unbalanced or too-deep substitution (Nachtrag 35, R13-1..R13-3), measured once by _net_render;
      · a context the lexer cannot parse, so its program position is unknown (R14-2);
      · a simple command whose active expansion sits in an unproven program position (R14-1), via
        _net_position_unmodeled;
      · an embedded executable context whose boundary is not found under understood syntax (R14-3), or which is
        itself not understood — every subcontext runs this same site (R14-2).
    The recursion is bounded the same way _net_render bounds its own."""
    if depth > MAX_NESTING:
        return True
    if depth == 0 and _net_render(text)[1]:
        return True
    toks = _lex(_drop_comments(text))
    if toks is None:
        # The lexer cannot place the words (R14-2). A non-parseable context must not count as expansion-free: when
        # an active expansion is present its program position is unclear, so NOT MEASURED. A non-parseable context
        # with no active expansion — a benign ANSI-C quote in an everyday command (`IFS=$'\\n' read`,
        # `printf $'…'`, `echo $'a message'`) — keeps the silent pass the word test gives it; its decoded bytes
        # carry no git/gh word, and the lexer failure alone does not make it a git call.
        if _unquoted_active_expansion(text):
            return True
    elif _net_position_unmodeled(toks):
        return True
    bodies, boundary_ok = _net_subcontexts(text)
    if not boundary_ok:
        return True
    return any(_net_unmodeled(body, depth + 1) for body in bodies)


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
    """(normal form, unresolved) for the net's word test (review Runde 12/14/15). The normal form is the command
    text rendered by _net_render (ANSI-C quotes evaluated, quotes and backslashes removed, line continuations
    removed, substitutions read as their own commands, only A to Z lower-cased in place). `unresolved` is the one
    verdict of _net_unmodeled, the single site that decides understood versus NOT MEASURED (Nachtrag 37, Punkt 2):
    True when the command's executed bytes or its program positions are not positively understood — a locale
    quote, a decoded NUL byte, an unbalanced or too-deep substitution, an unparsable context, an active
    brace/glob in an unproven program position, or an embedded context whose boundary is not understood. Exact
    evaluation and a free verdict stay only where they are provably complete (DECISIONS.md D8). The scan is total:
    every command yields a normal form, and every free exit of the net goes through _net_unmodeled."""
    normal, _render_unresolved = _net_render(command)
    return normal, _net_unmodeled(command)


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
        targets = _redirection_targets(toks)
        if targets:
            # The hook check reads every redirection target as a word of the command as well: zsh reads
            # `<1-2> --no-verify` as a numeric glob and an option, bash as two redirections (review round 2 of
            # 2026-10-09, R2-1). A form that turns the hook off in either reading denies.
            disabling = [c for c in _resolve_single(words + targets, directory, inherited_env)
                         if c[2] == [_HOOKS_DISABLE]]
            if disabling:
                return disabling
        if _redirection_present(text):  # the two free forms are free only without a redirection (K-NW-2 B)
            calls = [(n, UNKNOWN, [_NOT_FREE]) if d == [_STATE_FREE] else (n, c, d) for n, c, d in calls]
        if not _redirections_open_no_file(toks):
            # A redirection that opens a file runs before git does, the pre-push hook may be its target (R2-2): the
            # repository and target of a push or gh call are not resolved, so it is NOT MEASURED, never inactive.
            calls = [(n, UNKNOWN, None) if c is not UNKNOWN and d not in _MARKER_DETAILS else (n, c, d)
                     for n, c, d in calls]
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


def _read_env(repo: str | None = None) -> dict:
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
    variable is a second lock with a function contract only (review Runde 8, R8-3). LC_ALL=C keeps git's messages
    untranslated: the gate reads one of them as git's answer that a directory lies in no work tree (_NO_WORK_TREE,
    review round 5 of 2026-10-09, R5-1), and a translation of it would be read as a failure.

    Two more names make the gate's reads mean something else than the reads of the git it judges (review round 6 of
    2026-10-10, the class of R6-1). GIT_CONFIG makes `git config`, and only that command, read one file instead of the
    repository's configuration (measured with git 2.43.0: `git config --get branch.main.pushRemote` found nothing while
    `git push` pushed to the configured remote and `git status` started core.fsmonitor), so it is dropped and the gate
    reads the configuration git push, add and commit read. GIT_LITERAL_PATHSPECS is set and the glob, noglob and icase
    variants dropped: every path the gate names to git is its own literal path (the declaration, a file at a commit);
    GIT_ICASE_PATHSPECS made `rev-list -- .proofbundle/evidence.json` list a commit of another file and `ls-tree` refuse
    the path (measured with git 2.43.0: "pathspec magic not supported by this command: 'icase'"). The trace variables
    (GIT_TRACE, GIT_TRACE_<x>, GIT_TRACE2, GIT_TRACE2_<x>) change what git prints, not what it reads, and are dropped:
    the gate reads a configuration key as absent only where git exits 1 and says nothing (R6-2), and a trace on stderr
    had made every absent key unreadable, so every push NOT MEASURED (measured at 5714030c, found in the class search
    of R6-2).

    A read on a work tree _work_tree named carries the values git resolved in the call's directory (_Tree, review round
    7 of 2026-10-10, R7-1): a relative GIT_WORK_TREE taken against the work tree instead of that directory had named
    an empty subdirectory, and the done check had passed without the untracked file the work tree held."""
    env = dict(os.environ)
    env.update(getattr(repo, "pins", None) or {})
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    env["GIT_GRAFT_FILE"] = os.devnull
    env["GIT_NO_LAZY_FETCH"] = "1"
    env["LC_ALL"] = "C"
    env.pop("LANGUAGE", None)
    env.pop("GIT_CONFIG", None)
    env["GIT_LITERAL_PATHSPECS"] = "1"
    for name in ("GIT_GLOB_PATHSPECS", "GIT_NOGLOB_PATHSPECS", "GIT_ICASE_PATHSPECS"):
        env.pop(name, None)
    for name in [name for name in env if name.startswith("GIT_TRACE")]:
        del env[name]
    return env


def _git_namespace() -> str | None:
    """The namespace GIT_NAMESPACE names, or None where it is unset or empty (git reads an empty value as no namespace
    and stops at any value it cannot expand, `/` included, so every read then fails). Measured with git 2.43.0: the
    variable leaves the local refs as they are, and a push to a local remote then created
    refs/namespaces/<ns>/refs/heads/main beside the main that refs/remotes/origin/main records (review round 6 of
    2026-10-10, the class of R6-1)."""
    return os.environ.get("GIT_NAMESPACE") or None


#: The configuration keys that make a repository a partial clone, as `git config --get-regexp` matches them
#: (review Runde 7, R7-7; the same pattern as the release funnel's refusal, Z309, commit 6e05e186). git fetches
#: an object a partial clone does not hold from the promisor remote the moment a command asks for it, and the
#: fetch starts the program that remote's configuration names (remote.<name>.uploadpack, an ssh command, a
#: remote helper). Measured by the reviewer and again here on git 2.43.0: `git cat-file -p <missing>` started a
#: marker uploadpack, and decide_mcp's diagnosis started it while it read a declaration this clone did not hold.
#: git makes a remote a promisor through remote.<name>.promisor and remote.<name>.partialclonefilter and through
#: the repository format's extensions.partialClone; whatever the value, the gate reads no object from such a
#: repository. The remote's subsection may be empty (remote..promisor, review Runde 8, R8-2), hence `.*`. The keys are
#: read by their presence, never by a last boolean value: measured by the reviewer in round 15 of 2026-10-13, true
#: followed by false still started the transport program at an object read, and a filter, extensions.partialClone and
#: another remote's key did as well (owner choice of 2026-10-13, 15:1x Berlin, on C-5).
_PARTIAL_CLONE_KEYS = r"^(extensions\.partialclone|remote\..*\.(promisor|partialclonefilter))$"
#: The refusal under those keys, in the owner's words (C-5): it says that the gate does not evaluate the configuration
#: and claims no partial clone, which a key set to false, say, does not make. GateError adds the closing full stop.
_PROMISOR_REFUSAL = ("This repository has promisor-related configuration that this gate does not evaluate. The gate "
                     "refuses object reads under this configuration. Use a full repository without that configuration "
                     "for this check")


def _run_git(repo: str, args: tuple, deadline: float) -> subprocess.CompletedProcess:
    left = deadline - time.monotonic()
    if left <= 0:
        raise GateError("the gate ran out of time")
    try:
        return subprocess.run(["git", *_READ_ONLY_GIT, "-C", repo, *args], capture_output=True,
                              timeout=left, check=False, env=_read_env(repo))
    except FileNotFoundError as exc:
        raise GateError("git is not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise GateError("git did not answer in time") from exc


def _refuse_partial_clone(repo: str, deadline: float) -> None:
    """GateError (_PROMISOR_REFUSAL) when repo has promisor-related configuration (_PARTIAL_CLONE_KEYS), asked before
    an object read, so no read of the gate can fetch. `git config --get-regexp` reads the configuration and no object;
    exit 1 with no output is "no such key", anything else refuses. A directory that does not exist is left to the call
    itself, which then fails as before without reading an object."""
    if not os.path.isdir(repo):
        return
    probe = _run_git(repo, ("config", "-z", "--get-regexp", _PARTIAL_CLONE_KEYS), deadline)
    if probe.returncode == 0 and probe.stdout:
        raise GateError(_PROMISOR_REFUSAL)
    if probe.returncode != 1 or probe.stdout:
        why = probe.stderr.decode("utf-8", "replace").strip().splitlines()
        raise GateError(f"git could not say whether {repo} has promisor-related configuration"
                        + (f": {why[0]}" if why else ""))


#: The gate's git calls that read the configuration or the repository layout and no object: the reads of the
#: state check (_config_entries, _repo_paths), of the write gate (_state_files) and of the directory a call names
#: (_pins, R7-1). Every other call is asked _refuse_partial_clone first, so a call not on this list is treated as an
#: object read.
_OBJECT_FREE_CALLS = frozenset({
    ("config", "--list", "--null", "--show-origin", "--show-scope"),
    ("rev-parse", "--path-format=absolute", "--git-common-dir", "--git-dir", "--git-path", "hooks"),
    ("rev-parse", "--path-format=absolute", "--show-toplevel"),
    ("rev-parse", "--is-inside-work-tree"), ("rev-parse", "--absolute-git-dir"),
    *(("config", "--type=path", "--get", key) for key in _PHASED_KEYS),
    ("var", "GIT_CONFIG_GLOBAL"), ("var", "GIT_CONFIG_SYSTEM"), ("var", "GIT_ATTR_SYSTEM"), ("var", "GIT_ATTR_GLOBAL"),
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
        if listing.returncode == 0:
            _whole_along(repo, head, path, deadline)
            if listing.stdout == b"":
                return None  # a measured absence: the tree is readable, whole and holds no such path
        raise GateError(f"the gate could not read {path} at {head[:12]}: the commit or its tree is not "
                        "available in this repository")
    _whole_along(repo, head, path, deadline)
    if kind.stdout.strip() != b"blob":
        raise GateError(f"{path} at HEAD is a {kind.stdout.strip().decode(errors='replace')}, not a file")
    size = _git(repo, "cat-file", "-s", f"{head}:{path}", deadline=deadline)
    if size.returncode != 0 or int(size.stdout.strip() or b"0") > limit:
        raise GateError(f"{path} at HEAD is larger than {limit} bytes")
    content = _git(repo, "cat-file", "blob", f"{head}:{path}", deadline=deadline)
    if content.returncode != 0:
        raise GateError(f"git could not read {path} at HEAD")
    return content.stdout


#: The entries of each tree _whole_along read whole, by (repository, tree id); a tree's bytes never change.
_WHOLE_TREES: dict[tuple[str, str], dict] = {}


def _whole_along(repo: str, commit: str, path: str, deadline: float) -> None:
    """GateError where a tree on the way to `path` at `commit`, the root tree included, names one entry twice or is not
    given whole. git's lookup of `<commit>:<path>` takes the first of two entries of one name and a checkout writes the
    last, so neither is a whole reading of the path, for its bytes, its object id or its absence (review round 11 of
    2026-10-12, the class of R11-4: with X's .proofbundle folder first and a second one after it, the pre-push hook
    passed the commit on X's declaration while its checkout declared an empty evidence list)."""
    root = _git(repo, "rev-parse", "--verify", "--quiet", f"{commit}^{{tree}}", deadline=deadline)
    oid = root.stdout.decode("ascii", "replace").strip()
    if root.returncode != 0 or not oid:
        raise GateError(f"the gate could not read {path} at {commit[:12]}: git does not name its tree")
    parts = path.split("/")
    for depth, part in enumerate(parts):
        entries = _WHOLE_TREES.get((repo, oid))
        if entries is None:
            read = _objects(repo, [oid], deadline).get(oid)
            entries = None if read is None or read[0] != b"tree" else _tree_entries(read[1], len(oid) // 2)
            if entries is None:
                raise GateError(f"git does not give the whole tree on the way to {path} at {commit[:12]}: a tree "
                                "there names one entry twice, or git does not give it")
            _WHOLE_TREES[(repo, oid)] = entries
        entry = entries.get(part.encode()) if depth < len(parts) - 1 else None
        if entry is None or entry[0] != b"40000":
            return   # the path ends here, or nothing further down is a folder: git's own lookup reads what stands
        oid = entry[1]


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
                                env=_read_env(repo))
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
    tree with one has no digest. Nor has a tree that names a path twice, a file or a folder at any depth, the
    .proofbundle folder included: git's lookup reads the first of the two entries and a checkout writes the last, so
    no one manifest stands for it (review round 12 of 2026-10-13, B-17: src/ naming app.py twice had given two records
    for one path, and evidence signed over them had passed the CI mode).
    """
    if deadline is None:
        deadline = time.monotonic() + DEADLINE_SECONDS
    if not rev or rev.startswith("-"):
        raise GateError(f"not a revision: {rev!r}")
    listing = _git(repo, "ls-tree", "-r", "-t", "-z", "--full-tree", rev, deadline=deadline)
    if listing.returncode != 0:
        raise GateError(f"git could not list the tree of {rev}")
    entries, seen = [], set()
    for record in listing.stdout.split(b"\0"):
        if not record:
            continue
        meta, tab, path = record.partition(b"\t")
        fields = meta.split(b" ")
        if not tab or len(fields) != 3:
            raise GateError("git ls-tree gave a line the gate cannot read")
        mode, kind, oid = fields
        if path in seen:
            raise GateError(f"the tree names {path.decode(errors='replace')} twice; {TREE_ALGORITHM} needs every path "
                            "once, so the tree has no digest")
        seen.add(path)
        if kind == b"tree":
            continue   # a folder: listed for the check above, covered through its files
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


def _no_constant(name: str) -> object:
    """The parse_constant of every JSON read of the gate: NaN, Infinity and -Infinity are not JSON (RFC 8259),
    and a reader that took them read a number nobody can write in JSON (review Runde 15, F15-4: a progress
    notification with progress NaN let a green verifier reply through)."""
    raise ValueError(f"the non-JSON constant {name}")


def strict_json(data: str | bytes) -> object:
    """json.loads that refuses a repeated key in every object, at any depth (AmbiguousJSON, a ValueError), and
    the non-JSON constants NaN, Infinity and -Infinity (a ValueError, review Runde 15, F15-4)."""
    return json.loads(data.decode("utf-8") if isinstance(data, bytes) else data, object_pairs_hook=_unique_pairs,
                      parse_constant=_no_constant)


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
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        raise GateError(f"{DECLARATION} is not JSON: {exc}") from exc
    if not isinstance(doc, dict) or set(doc) not in ({"schema", "evidence"}, {"schema", "evidence", "done"}):
        raise GateError(f"{DECLARATION} must be an object with exactly the keys schema and evidence, and "
                        "optionally done")
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
    if "done" in doc:
        _done_section(doc["done"])
    return items


def _done_section(value: object) -> dict:
    """The done check of the declaration (D26, D28), as {"policy", "checks", "paths", "max_blocks"}. Two forms:
    - {"receipt", "policy"}: one check, "tests", the pytest run its receipt names, with any selection;
    - {"policy", "checks"[, "paths"][, "max_blocks"]}: the order. Each check is {"id", "args", "receipt"}: the pytest
      arguments the run must have been given and the receipt it leaves. "paths" are the patterns the work must and may
      change (fnmatch, `*` also matches `/`), compared with the commit that declared the order; "max_blocks" is
      how many blocks without progress the Stop hook makes before it writes a blocker (1 to 7, default 3).
    Every file lies under .proofbundle/ and is a file of its own."""
    if isinstance(value, dict) and set(value) == DONE_KEYS:
        done = {"policy": _relative(value["policy"], "done.policy"), "paths": None, "max_blocks": DEFAULT_MAX_BLOCKS,
                "checks": [{"id": "tests", "args": None, "receipt": _relative(value["receipt"], "done.receipt")}]}
    elif isinstance(value, dict) and DONE_ORDER_KEYS <= set(value) <= DONE_ORDER_KEYS | DONE_ORDER_OPTIONAL:
        done = {"policy": _relative(value["policy"], "done.policy"), "checks": _done_checks(value["checks"]),
                "paths": _done_paths(value["paths"]) if "paths" in value else None,
                "max_blocks": _max_blocks(value.get("max_blocks", DEFAULT_MAX_BLOCKS))}
    else:
        raise GateError("done must be an object with exactly the keys policy and receipt, or with the keys policy "
                        "and checks and optionally paths and max_blocks")
    files = [done["policy"], *(check["receipt"] for check in done["checks"])]
    if len(set(files)) != len(files) or DECLARATION in files or any(f in DONE_OWN_FILES for f in files):
        raise GateError("done.policy and every receipt must name files of their own, other than the declaration and "
                        "the done check's own state files")
    return done


def _done_checks(value: object) -> list[dict]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_CHECKS:
        raise GateError(f"done.checks must be a list of 1 to {MAX_CHECKS} checks")
    checks, seen = [], set()
    for n, check in enumerate(value):
        where = f"done.checks[{n}]"
        if not isinstance(check, dict) or set(check) != CHECK_KEYS:
            raise GateError(f"{where} must be an object with exactly the keys args, id and receipt")
        ident, args = check["id"], check["args"]
        if not (isinstance(ident, str) and _CHECK_ID.fullmatch(ident)) or ident in seen:
            raise GateError(f"{where}.id must be a name of its own, of lowercase letters, digits, - and _ (at most 32)")
        if not (isinstance(args, list) and len(args) <= MAX_CHECK_ARGS
                and all(isinstance(a, str) and a and len(a) <= 1024 and "\0" not in a for a in args)):
            raise GateError(f"{where}.args must be a list of at most {MAX_CHECK_ARGS} non-empty strings, the arguments "
                            "pytest is given")
        seen.add(ident)
        checks.append({"id": ident, "args": list(args), "receipt": _relative(check["receipt"], f"{where}.receipt")})
    return checks


def _done_paths(value: object) -> list[str]:
    if not (isinstance(value, list) and 1 <= len(value) <= MAX_PATHS
            and all(isinstance(p, str) and p and len(p) <= 256 and "\0" not in p and not p.startswith("/")
                    for p in value)):
        raise GateError(f"done.paths must be a list of 1 to {MAX_PATHS} path patterns relative to the repository")
    return list(value)


def _max_blocks(value: object) -> int:
    if type(value) is not int or not 1 <= value <= MAX_BLOCKS_LIMIT:
        raise GateError(f"done.max_blocks must be a whole number from 1 to {MAX_BLOCKS_LIMIT}")
    return value


def parse_done(raw: bytes) -> dict | None:
    """The declaration's done check, or None when it declares none. The whole declaration must hold its form."""
    parse_declaration(raw)
    doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    return _done_section(doc["done"]) if "done" in doc else None


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


#: The MCP protocol versions the gate accepts in an initialize result (Nachtrag 37, R14-4). The gate sends
#: "2025-06-18" and the pinned proofbundle server answers the same (measured at 0.3.0); an initialize result that
#: names any other version is a handshake the gate did not agree to, so the whole verifier run is refused.
_MCP_PROTOCOL_VERSIONS = frozenset({"2025-06-18"})


def _mcp_init_result_ok(result: object) -> str | None:
    """Why an initialize result breaks the MCP 2025-06-18 contract the gate requires before it reads any answer
    (Nachtrag 37, R14-4), or None when it is well formed. A result that is merely present no longer suffices: it
    must be an object (not null, not false, not a bare value), name a protocolVersion the gate agreed to, and
    carry the mandatory capabilities object and a serverInfo object with a string name and version (the schema's
    InitializeResult). Without this a `result: null`, `result: false`, `result: {}`, an unsupported version or a
    `capabilities: null` / `serverInfo: false` passed the handshake and a later green answer read as pass."""
    if not isinstance(result, dict):
        return "an initialisation result that is not an object"
    version = result.get("protocolVersion")
    if not isinstance(version, str) or version not in _MCP_PROTOCOL_VERSIONS:
        return "an initialisation result without a protocol version the gate supports"
    if not isinstance(result.get("capabilities"), dict):
        return "an initialisation result without a capabilities object"
    info = result.get("serverInfo")
    if not (isinstance(info, dict) and isinstance(info.get("name"), str) and isinstance(info.get("version"), str)):
        return "an initialisation result without a serverInfo that names the server"
    return None


#: The logging levels of MCP 2025-06-18, the RFC 5424 severities; a message with any other level is one the gate
#: does not model, and the run is refused (review Runde 15, F15-4).
_MCP_LOG_LEVELS = frozenset({"debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"})


def _mcp_notification_contract(method: str, params: object) -> str | None:
    """Why a server notification breaks the contract of the notifications the gate permits (Nachtrag 37, R14-4),
    or None when it is well formed and may be set aside. The gate's pinned server sends no notification during a
    verify run (measured at 0.3.0), so only the two notifications whose contract the gate models are permitted,
    each checked against the MCP 2025-06-18 schema: a progress carries a progressToken that is a string or a
    non-boolean integer and a progress that is a non-boolean number; a logging message carries a string level. A
    malformed permitted notification (a progress with a null token or a `false` progress) is a contract break, not
    a message to skip, and any other method is a notification the gate does not model and refuses outright."""
    if method == "notifications/progress":
        if not isinstance(params, dict):
            return "a progress notification without an object params"
        token = params.get("progressToken")
        if not (isinstance(token, (str, int)) and not isinstance(token, bool)):
            return "a progress notification whose progressToken is not a string or an integer"
        progress = params.get("progress")
        if not (isinstance(progress, (int, float)) and not isinstance(progress, bool)):
            return "a progress notification whose progress is not a number"
        return None
    if method == "notifications/message":
        level = params.get("level") if isinstance(params, dict) else None
        if not (isinstance(level, str) and level in _MCP_LOG_LEVELS):
            return "a logging notification whose level is not one of the eight MCP logging levels"
        return None
    return f"a notification the gate does not model (method {method!r})"


#: How uv words the two failures measured in the Codex sandbox (KARTEN-02, Codex 0.161.0, workspace-write, network
#: off): a cache it cannot write and a package index it cannot resolve. A phrase alone decides nothing; a probe of the
#: gate's own must confirm it (_verifier_start_sign).
_UV_WRITE_FAILURE = ("read-only file system", "os error 30", "permission denied (os error 13)")
_UV_NAME_FAILURE = ("failed to lookup address information", "temporary failure in name resolution",
                    "name or service not known", "dns error")
_PROBE_SECONDS = 3.0


def _uv_cache_dir(uv: str, deadline: float) -> str | None:
    """The cache folder uv says it uses, with the verifier's environment; None where uv does not say."""
    left = min(deadline - time.monotonic(), 10.0)
    if left <= 0:
        return None
    try:
        proc = subprocess.run([uv, "cache", "dir"], env=_isolated_env(), capture_output=True, text=True,
                              timeout=left, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = proc.stdout.strip().splitlines()
    return lines[0] if proc.returncode == 0 and len(lines) == 1 and os.path.isabs(lines[0]) else None


def _write_probe(folder: str) -> str | None:
    """Why a file cannot be written in folder, or in the nearest folder above it that exists; None when it can (the
    probe file is removed at once, and no folder is created)."""
    here = folder
    while not os.path.isdir(here) and os.path.dirname(here) != here:
        here = os.path.dirname(here)
    try:
        fd, probe = tempfile.mkstemp(prefix=".proofbundle-write-probe-", dir=here)
    except OSError as exc:
        return f"{errno.errorcode.get(exc.errno, exc.errno)}, {exc.strerror}, in {here}"
    os.close(fd)
    os.unlink(probe)
    return None


def _probe_endpoints(environ) -> list[tuple[str, int]]:
    """Where uv would go for the package index: each proxy the environment names, and the default index host. The
    names only say where to probe; whether the network is there is what the probe measures."""
    endpoints = []
    for key in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        value = environ.get(key)
        if value:
            parts = urllib.parse.urlsplit(value if "//" in value else "//" + value)
            try:
                port = parts.port or 443
            except ValueError:
                continue
            if parts.hostname:
                endpoints.append((parts.hostname, port))
    endpoints.append(("pypi.org", 443))
    return list(dict.fromkeys(endpoints))


def _reach(host: str, port: int) -> str | None:
    """Why the endpoint is out of reach, or None: a name must resolve; an address literal must accept a connection."""
    outcome: list = []

    def attempt():
        try:
            ipaddress.ip_address(host)
        except ValueError:
            try:
                socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
                outcome.append(None)
            except OSError as exc:
                outcome.append(f"resolving {host} failed: {exc}")
            return
        try:
            socket.create_connection((host, port), timeout=_PROBE_SECONDS).close()
            outcome.append(None)
        except OSError as exc:
            outcome.append(f"connecting to {host}:{port} failed: {exc}")

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(_PROBE_SECONDS + 1)
    return outcome[0] if outcome else f"{host} gave no answer within {int(_PROBE_SECONDS)} s"


def _verifier_start_sign(uv: str, stderr: str, deadline: float) -> tuple[str, str] | None:
    """(kind, sign) when uv's answer and a probe of the gate's own both show that the verifier cannot start here for
    want of a writable cache or of the network (owner choice K02-A C); None otherwise, and then the start failure keeps
    its generic message. Never read from an environment name alone."""
    text = (stderr or "").lower()
    if any(phrase in text for phrase in _UV_WRITE_FAILURE):
        cache = _uv_cache_dir(uv, deadline)
        problem = _write_probe(cache) if cache is not None else None
        if problem is not None:
            return "no_writable_cache", (f"uv could not write its cache, and a write the gate tried there failed too "
                                         f"({problem})")
    if any(phrase in text for phrase in _UV_NAME_FAILURE):
        failures = [_reach(host, port) for host, port in _probe_endpoints(os.environ)]
        if failures and all(failures):
            return "no_network", (f"uv could not resolve its package index, and the gate reached none of the places "
                                  f"uv would go ({'; '.join(failures)})")
    return None


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
    sent_ids = set(range(len(requests) + 1))  # id 0 is initialize; ids 1..len are the tool calls the gate sent
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
            # A permitted notification is validated against its contract before it is set aside (Nachtrag 37,
            # R14-4): a malformed progress or logging notification, or a notification method the gate does not
            # model, refuses the whole run instead of being skipped.
            why = _mcp_notification_contract(reply["method"], reply.get("params"))
            if why is not None:
                raise GateError(f"the verifier sent {why}, which refuses the whole verifier run")
            continue  # a valid, modelled notification carries no answer; it is set aside
        rid = reply["id"]
        if not isinstance(rid, int) or isinstance(rid, bool):
            raise GateError("the verifier sent a reply whose id is not an integer, which refuses the whole "
                            "verifier run")
        # Every answer must belong to a request the gate sent (Nachtrag 37, R14-4): a reply whose id is none of
        # the initialize or tool-call ids is a message the gate cannot match to a request, so it refuses the whole
        # run rather than ignore it, closing the same contract class as the duplicate-reply refusal below.
        if rid not in sent_ids:
            raise GateError(f"the verifier sent a reply for request {rid}, which the gate did not send, which "
                            "refuses the whole verifier run")
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
        message = (f"the verifier did not initialise (exit {proc.returncode}: {tail[0]}), which refuses the whole "
                   "verifier run")
        sign = _verifier_start_sign(uv, proc.stderr, deadline)
        if sign is not None:
            raise VerifierCannotStart(message, *sign)
        raise GateError(message)
    # The initialisation result's own contract is checked before any answer is read (Nachtrag 37, R14-4): a result
    # that is present but null, false, empty, of an unsupported protocol version, or without the mandatory
    # capabilities and serverInfo objects is a broken handshake no later green answer can ride.
    why = _mcp_init_result_ok(init["result"])
    if why is not None:
        raise GateError(f"the verifier sent {why}, which refuses the whole verifier run")
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

    __slots__ = ("decision", "detail", "reason_id", "evidence", "failed", "next_step", "digests", "repo", "head",
                 "reads")

    def __init__(self, decision: str, detail: str, reason_id: str, evidence: str = "", failed: str = "",
                 next_step: str = "", digests: tuple = (), repo: str | None = None, head: str | None = None,
                 reads: tuple = ()):
        self.decision, self.detail, self.reason_id = decision, detail, reason_id
        self.evidence, self.failed, self.next_step = evidence, failed, next_step
        self.digests, self.repo, self.head = tuple(digests), repo, head
        self.reads = tuple(reads)   # owner choice 3 A: the evidence bytes a push's source check read (_source_reads)

    def text(self) -> str:
        if self.decision in ("pass", "inactive", "handover"):
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
    """True only when git lists nothing at DECLARATION in the commit's tree and says so with exit 0, and every tree on
    the way to it is whole (_whole_along, the class of R11-4)."""
    listing = _git(repo, "ls-tree", "-z", "--full-tree", commit, "--", DECLARATION, deadline=deadline)
    if listing.returncode != 0 or listing.stdout != b"":
        return False
    try:
        _whole_along(repo, commit, DECLARATION, deadline)
    except GateError:
        return False
    return True


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
    subject (kind, path, policy, public_key), the blob of each declared policy, and the done check (owner choice
    N2C-1 B, 2026-10-08): the whole done section and the blob of its done policy. Evidence files, receipts and any
    other file under .proofbundle/ are not rules."""
    try:
        raw = _blob(repo, commit, DECLARATION, deadline, MAX_DECLARATION_BYTES)
    except GateError as exc:
        return ("unreadable", str(exc))
    if raw is None:
        return ("absent",)
    try:
        items = parse_declaration(raw)
        done = parse_done(raw)
    except GateError:
        return ("malformed", hashlib.sha256(raw).hexdigest())
    rules = tuple(sorted((i["kind"], i["path"], i.get("policy", ""), i.get("public_key", "")) for i in items))
    policies = []
    try:
        for path in sorted({i["policy"] for i in items if "policy" in i}):
            policies.append((path, _blob_id(repo, commit, path, deadline)))
        done_rule = _done_rule(repo, commit, done, deadline)
    except GateError as exc:
        return ("unreadable", str(exc))
    return ("declared", rules, tuple(policies), done_rule)


def _blob_id(repo: str, commit: str, path: str, deadline: float) -> str:
    """The object id at `path` of the commit, "" where git names none; GateError where a tree on the way to it is not
    whole (_whole_along)."""
    _whole_along(repo, commit, path, deadline)
    blob = _git(repo, "rev-parse", "--verify", "--quiet", f"{commit}:{path}", deadline=deadline)
    return blob.stdout.decode().strip() if blob.returncode == 0 else ""


def _done_rule(repo: str, commit: str, done: dict | None, deadline: float) -> tuple:
    """The done check as an evidence rule (owner choice N2C-1 B, D20): the done section in one canonical form (its
    policy, each check's id, arguments and receipt, the paths and max_blocks) and the blob of the done policy at the
    commit; () when the declaration declares no done check. Who may change the policy or the order decides what a
    done check proves, so a push that changes either needs a review like a change to an evidence policy."""
    if done is None:
        return ()
    return (_done_canonical(done), _blob_id(repo, commit, done["policy"], deadline))


def _done_canonical(done: dict) -> tuple:
    """The done section in one comparable form: its policy, each check's id, arguments and receipt, the paths and
    max_blocks."""
    checks = tuple((c["id"], None if c["args"] is None else tuple(c["args"]), c["receipt"]) for c in done["checks"])
    return (done["policy"], checks, None if done["paths"] is None else tuple(done["paths"]), done["max_blocks"])


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
    if base[3] != head[3]:
        if not base[3] or not head[3]:
            parts.append("the push adds a done check" if head[3] else "the push removes the done check")
        elif base[3][0] != head[3][0]:
            parts.append("the done check changes (its policy, checks, receipts, paths or max_blocks)")
        else:
            parts.append(f"the done policy {head[3][0][0]} changes")
    return "; ".join(parts)


#: A push the gate resolves to more commits than this against one target is NOT MEASURED: the gate cannot
#: evaluate the whole range inside its deadline, and a tip alone does not vouch for what it hides (D3, N3).
MAX_RANGE_COMMITS = 64

#: One ref update a `git push` performs: the pushed commit (None for a deletion), the ref it writes on the
#: remote, and the remote's state of that ref as git hands it to the pre-push hook (None for a ref the remote does not
#: have). Level 1 builds no targets since R9-1 (resolve_push_targets returns None for every push). remote_absent is True only when the absence of the
#: target ref is MEASURED — a null object id for the remote side of a pre-push line — and False when merely
#: no local tracking ref is known (review Runde 6, Befund 2).
PushTarget = collections.namedtuple("PushTarget", "source dest tracking remote_absent", defaults=(False,))

_TRACKABLE = ("refs/heads/", "refs/tags/")


def _remote_names(repo: str, deadline: float) -> set | None:
    """The remotes git lists, one name per line with its bytes (_git_lines): a name may carry a blank, which a split
    on whitespace made two names, neither of them the one git pushes to (review round 5 of 2026-10-09, R5-1). None
    where git cannot list them: `git remote` reads the remote and branch configuration push reads and stops where push
    stops (measured with git 2.43.0: a branch.main.remote, pushRemote or merge, a remote.pushDefault or a remote's url,
    pushurl, push or fetch given with no value), so an unreadable list is not an empty one (review round 6 of
    2026-10-10, the class of R6-2)."""
    out = _git(repo, "remote", deadline=deadline)
    if out.returncode != 0:
        return None
    names = _git_lines(out.stdout) if out.stdout else []   # no remote: git prints nothing
    return None if names is None else set(names)


def _config_value(repo: str, key: str, deadline: float) -> str | None:
    """One value of a key as git reads it, with its bytes (_git_text; a strip made `origin ` the remote `origin`,
    R5-1): None only where the key is absent (git exits 1 and says nothing), a present value as it stands, the empty
    one included. git prints `key =` and a key with no `=` alike, and reads neither as absent: an empty
    branch.main.pushRemote made `git push` fail with "no path specified" instead of falling back to remote.pushDefault
    (measured with git 2.43.0; review round 6 of 2026-10-10, R6-2, where one reader returned None for both and an
    or-chain fell through to another remote). Any other answer of git raises GateError (NOT MEASURED)."""
    out = _git(repo, "config", "--get", key, deadline=deadline)
    if out.returncode == 1 and not out.stdout and not out.stderr:
        return None
    if out.returncode != 0 or not out.stdout.endswith(b"\n"):
        raise GateError(f"git could not read {key}")
    return _git_text(out.stdout[:-1])


def _config_bool(repo: str, key: str, deadline: float) -> bool:
    """A git boolean config value, normalised by git itself (so 1, yes and on read as true). False when the
    key is unset. A value git cannot read as a boolean, or a multi-valued key, raises GateError, which the
    caller turns into NOT MEASURED (review R3-3). Unset is exit 1 with nothing said: git also exits 1 for a key it
    cannot parse, and says so (review round 6 of 2026-10-10, the class of R6-2)."""
    out = _git(repo, "config", "--bool", "--get", key, deadline=deadline)
    if out.returncode == 1 and not out.stdout.strip() and not out.stderr:
        return False
    if out.returncode != 0:
        raise GateError(f"git could not read {key} as a boolean")
    return out.stdout.decode().strip() == "true"


def _config_present(repo: str, key: str, deadline: float) -> bool:
    """Whether a (possibly multi-valued) config key has any value, an empty one included. A git error other than
    'not set' (exit 1 with nothing said, _config_bool) raises GateError (NOT MEASURED)."""
    out = _git(repo, "config", "--get-all", key, deadline=deadline)
    if out.returncode == 0:
        return True
    if out.returncode == 1 and not out.stdout and not out.stderr:
        return False
    raise GateError(f"git could not read {key}")


def _push_adds_unnamed_refs(repo: str, remote: str, deadline: float) -> bool:
    """Whether the remote's configuration adds ref updates a plain push to it does not name: a configured
    remote.<name>.push, a mirror remote, or push.followTags. Each is a git boolean or a value list; a value
    the gate cannot read raises GateError (NOT MEASURED, review R3-3). A pushurl is covered by the endpoint
    check below."""
    return (_config_present(repo, f"remote.{remote}.push", deadline)
            or _config_bool(repo, f"remote.{remote}.mirror", deadline)
            or _config_bool(repo, "push.followTags", deadline))


def _legacy_remote(repo: str, remote: str, deadline: float) -> bool:
    """Whether git takes the remote from its older remote files, $GIT_COMMON_DIR/remotes/<name> or branches/<name>,
    which `git remote` does not list and the configuration does not hold: git reads them for a name without a `/` that
    the configuration gives no URL (remote.c of git 2.43.0, remote_get_1). Such a file names further URLs and the refs a
    push sends (`Push:`, or HEAD to the branch a branches file names), which the gate does not read (review round 13 of
    2026-10-13, the class of R13-1: with .git/remotes/legacy pushing refs/heads/other, `git push legacy` had been
    called locally inactive while git pushed another branch). A file the gate cannot rule out counts as present.

    Whether the configuration gives a URL is read from the list git uses, not from the key being there (review round 14
    of 2026-10-13, R14-3, measured by the reviewer with git 2.51.1: an empty remote.<name>.url starts the list anew,
    and with no URL after it git took the remote from .git/remotes/<name> while the gate, seeing the key, had named the
    current branch as the commit pushed). With no URL after the last empty value the files decide, as with no key; a
    URL after it is git's URL. git 2.43.0 refuses an empty URL and pushes nothing (_endpoint_consistent)."""
    if not remote or remote in (".", "..") or "/" in remote:
        return False
    urls = _config_all(repo, f"remote.{remote}.url", deadline)
    if "" in urls:
        urls = urls[len(urls) - urls[::-1].index(""):]   # the values after the last empty one
    if urls:
        return False
    paths, _why = _repo_paths(repo, deadline)
    if paths is None or not paths["common"]:
        return True
    for folder in ("remotes", "branches"):
        try:
            os.lstat(os.path.join(paths["common"], folder, remote))
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError:
            return True
        return True
    return False


#: The configuration only `git push` parses, read by git before it pushes anything, whatever the push needs (review
#: round 7 of 2026-10-10, R7-3; the push names compiled into git 2.43.0 and 2.51.1, each measured with both): a value
#: git cannot read stops the push with exit 128, an invalid value before a valid one too. The keys of remotes, branches
#: and URL rewrites stop `git remote get-url` as well, which every push the gate resolves reads (_endpoint_consistent),
#: and push.default, core.* and advice.* stop every read of the gate, so those need no check here.
_PUSH_BOOLEANS = ("push.autoSetupRemote", "push.followTags", "push.useForceIfIncludes", "push.negotiate",
                  "push.useBitmaps", "submodule.recurse")


def _push_config_problem(repo: str, deadline: float, command_options: list[str] | None = None) -> str | None:
    """What in the push configuration stops git push or makes it push more than the command names, or None. Every value
    of every key is read, before any resolution step, because git reads them all at the start of every push (R7-3: a
    bare push with an upstream had passed while push.autoSetupRemote held a value git refused, since only the case
    without an upstream read that key). Read through git's own parsers: --type=bool, --get-colorbool, --type=color, and
    the entries of --get-regexp, where a key written without `=` has no value. A present submodule.recurse true or
    push.recurseSubmodules on-demand or only is NOT MEASURED, whatever value follows it: with such a value in effect git
    pushes the submodules' commits to their own remotes, which no tracking ref here records, and git takes the last
    value, so a later false turns that off (measured by the reviewer with git 2.43.0 and 2.51.1). The gate does not
    decide which value is in effect (owner choice B: A, 2026-10-10), and its reason names the value present, not a
    submodule push (review round 8 of 2026-10-10, R8-5). `check` pushes nothing more, and any other word stops git.

    push.pushOption is the list git builds (builtin/push.c, git_push_config): each value appended, an empty value
    clearing what came before, a key without a value stopping every push. The options the command line gives
    (command_options, `-o`/`--push-option`) replace that list for the push; git refuses the push when an option of the
    list it uses holds a newline (review round 8 of 2026-10-10, R8-3; measured with git 2.43.0 and 2.51.1: `pushOption
    = "one\\ntwo"` stopped the push with exit 128 while the gate passed it, a later empty value made git accept it again,
    and `-o x` on the command line too). A NUL stands in neither a configuration value nor an argument."""
    def entries(pattern: str) -> list[tuple[str, str | None]] | None:
        out = _git(repo, "config", "--null", "--get-regexp", pattern, deadline=deadline)
        if out.returncode == 1 and not out.stdout and not out.stderr:
            return []
        if out.returncode != 0 or not out.stdout.endswith(b"\0"):
            return None
        found = []
        for entry in out.stdout[:-1].split(b"\0"):
            key, newline, value = entry.partition(b"\n")
            found.append((_git_text(key), _git_text(value) if newline else None))
        return found

    def is_false(value: str) -> bool | None:
        """git's own reading of value as a boolean: True for false, False for true, None where git refuses it."""
        out = _git(repo, "-c", f"proofbundle.probe={value}", "config", "--type=bool", "--get", "proofbundle.probe",
                   deadline=deadline)
        return None if out.returncode != 0 else out.stdout == b"false\n"

    for key in _PUSH_BOOLEANS:
        out = _git(repo, "config", "--type=bool", "--get-all", key, deadline=deadline)
        if out.returncode == 1 and not out.stdout and not out.stderr:
            continue
        if out.returncode != 0:
            return f"git cannot read every value of {key} as a boolean, and git push stops there"
        if key == "submodule.recurse" and b"true" in out.stdout.split(b"\n"):
            return "The configuration contains submodule.recurse=true; submodule push behavior is NOT MEASURED."
    for key, word_ok in (("push.recursesubmodules", ("check",)), ("push.gpgsign", ("if-asked",))):
        values = entries(f"^{key.replace('.', '[.]')}$")
        if values is None:
            return f"git cannot read {key}"
        for _name, value in values:
            if value is None and key == "push.gpgsign":
                continue   # a key without `=` is true: sign the push
            if value is not None and key == "push.recursesubmodules" and value in ("on-demand", "only"):
                return (f"The configuration contains push.recurseSubmodules={value}; submodule push behavior is NOT "
                        "MEASURED.")
            if value is not None and (value in word_ok if key == "push.recursesubmodules"
                                      else value.lower() in word_ok):
                continue
            false = None if value is None else is_false(value)
            if false is None or (key == "push.recursesubmodules" and not false):
                return f"git push stops at the value {value!r} of {key}"
    options = entries("^push[.]pushoption$")
    if options is None or any(value is None for _name, value in options):
        return "push.pushOption is set without a value, and git push stops there"
    listed: list[str] = []
    for _name, value in options:
        listed = [] if value == "" else [*listed, value]   # an empty value clears the list (R8-3)
    used = command_options if command_options else listed
    if any("\n" in option for option in used):
        where = "on the command line" if command_options else "in push.pushOption"
        return f"a push option {where} holds a newline, and git push stops there"
    color = _git(repo, "config", "--get-colorbool", "color.push", deadline=deadline)
    if color.returncode not in (0, 1):
        return "git cannot read color.push, and git push stops there"
    for slot in ("reset", "error"):
        out = _git(repo, "config", "--type=color", "--get-all", f"color.push.{slot}", deadline=deadline)
        if out.returncode not in (0, 1) or (out.returncode == 1 and (out.stdout or out.stderr)):
            return f"git cannot read color.push.{slot} as a color, and git push stops there"
    return None


def _config_all(repo: str, key: str, deadline: float) -> list[str]:
    """Every value of a (possibly multi-valued) config key, as git reads it; [] when unset. A git error
    other than 'not set' (exit 1 with nothing said, _config_bool) raises GateError (NOT MEASURED)."""
    out = _git(repo, "config", "--null", "--get-all", key, deadline=deadline)
    if out.returncode == 1 and not out.stdout and not out.stderr:
        return []
    values = _git_values(out.stdout) if out.returncode == 0 else None
    if values is None:
        raise GateError(f"git could not read {key}")
    return values


def _git_values(raw: bytes) -> list[str] | None:
    """The values `git config --null` printed, each ended by NUL, with their bytes; None for output that does not end
    in NUL. str.splitlines split a value at U+0085 or \x1c-\x1e and a value may hold a newline, so a URL or a refspec
    became two values git does not read (R5-1)."""
    if not raw.endswith(b"\0"):
        return None
    return [_git_text(value) for value in raw[:-1].split(b"\0")]


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
        name = _git_text(key)   # base and prefix keep their bytes: U+FFFD would match a URL git does not rewrite (R4-2)
        for suffix, kind in ((".pushinsteadof", "pushInsteadOf"), (".insteadof", "insteadOf")):
            if name.lower().endswith(suffix):
                rules.append((kind, name[len("url."):-len(suffix)], _git_text(value)))
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
    comparison it does apply to. A git error raises GateError (NOT MEASURED).

    remote.<name>.url is a list git reads with a reset rule and a fallback (review round 8 of 2026-10-10, the class of
    R8-3; measured with git 2.43.0 and 2.51.1): git 2.51.1 clears the list with an empty value, git 2.43.0 keeps the
    empty value as a URL and refuses the push, and where no URL is left both take the remote's own name for one
    (remote.c, add_url_alias) and push to that path below the top level. Only exactly one non-empty configured value
    reads the same under both, so any other list is NOT MEASURED; `get-url` alone had shown `origin` for both sides and
    passed a push to ./origin."""
    configured = _git(repo, "config", "--null", "--get-all", f"remote.{remote}.url", deadline=deadline)
    if configured.returncode == 1 and not configured.stdout and not configured.stderr:
        return False   # no URL: git pushes to the remote's name as a path
    if configured.returncode != 0 or not configured.stdout.endswith(b"\0"):
        raise GateError(f"git could not read the URLs of remote {remote}")
    values = configured.stdout[:-1].split(b"\0")
    if len(values) != 1 or not values[0]:
        return False   # an empty value: a URL git 2.43.0 refuses, a reset in newer git; or more than one URL
    if _applicable_rewrites(repo, remote, deadline):
        return False
    push = _git(repo, "remote", "get-url", "--push", "--all", remote, deadline=deadline)
    fetch = _git(repo, "remote", "get-url", "--all", remote, deadline=deadline)
    if push.returncode != 0 or fetch.returncode != 0:
        raise GateError(f"git could not read the URLs of remote {remote}")
    # Every line counts, a blank one too: git pushes to a pushurl of blanks as to any other (R5-1).
    push_urls, fetch_urls = _git_lines(push.stdout), _git_lines(fetch.stdout)
    return (push_urls is not None and fetch_urls is not None and len(push_urls) == 1 and len(fetch_urls) == 1
            and push_urls[0] == fetch_urls[0])


def _fetch_refspec(spec: str) -> tuple[bool, str, str | None, bool] | None:
    """One fetch refspec as git 2.43.0 parses it (refspec.c, parse_refspec): (negative, source, destination, pattern),
    destination None where the spec has no colon. One leading `+` is the force sign and one leading `^` makes the spec
    negative, never both (git reads `+^…` as an invalid ref, and `++…` as a source starting with `+`, R5-1 class); the
    last colon splits the sides; each side holds at most one `*`, a positive pattern needs it on both sides, and a
    negative spec has a source only. None for a spec git refuses (review round 6 of 2026-10-10, R6-3)."""
    negative = spec.startswith("^")
    rest = spec[1:] if spec[:1] in ("+", "^") else spec
    head, colon, tail = rest.rpartition(":")
    src, dst = (head, tail) if colon else (rest, None)
    if (negative and (dst is not None or not src)) or src.count("*") > 1 or (dst or "").count("*") > 1:
        return None
    pattern = "*" in src
    if pattern != ("*" in (dst or "")) and not (negative and dst is None):
        return None
    return negative, src, dst, pattern


def _refspec_map(key: str, value: str | None, pattern: bool, name: str) -> str | None:
    """What `name` maps to through one refspec side `key` onto the other side `value`, as git's
    match_name_with_pattern maps it (remote.c): a pattern side holds one `*` anywhere, which stands for any run of
    characters, an empty one too, and the same run fills the `*` of `value`; a plain side matches only itself. None
    where `name` does not match; with `value` None the matching name itself. A trailing `*` was all the gate read, so
    `refs/heads/o*her:refs/remotes/origin/ma*n` mapped nothing for it while git fetched oiher into main (R6-3)."""
    if not pattern:
        return None if name != key else (name if value is None else value)
    prefix, _, suffix = key.partition("*")
    if not (name.startswith(prefix) and name.endswith(suffix) and len(name) >= len(prefix) + len(suffix)):
        return None
    if value is None:
        return name
    head, _, tail = value.partition("*")
    return head + name[len(prefix):len(name) - len(suffix)] + tail


def _local_ref(dst: str, pattern: bool) -> str:
    """The local ref a fetch destination writes (remote.c, get_local_ref): a plain destination outside refs/ is
    completed, `heads/`, `tags/` and `remotes/` under refs/, anything else under refs/heads/; a pattern's expansion is
    taken as it stands."""
    if pattern or dst.startswith("refs/"):
        return dst
    return "refs/" + dst if dst.startswith(("heads/", "tags/", "remotes/")) else "refs/heads/" + dst


def _fetch_rules(repo: str, deadline: float) -> dict[str, list] | None:
    """Every remote's fetch refspecs as _fetch_refspec parses them, by remote name: {} where there is none, None where
    git cannot read them or a rule has no value or is one git refuses."""
    out = _git(repo, "config", "--null", "--get-regexp", r"^remote\..*\.fetch$", deadline=deadline)
    if out.returncode == 1 and not out.stdout and not out.stderr:
        return {}
    if out.returncode != 0 or not out.stdout.endswith(b"\0"):
        return None
    rules: dict[str, list] = {}
    for entry in out.stdout[:-1].split(b"\0"):
        key, newline, value = entry.partition(b"\n")
        parsed = _fetch_refspec(_git_text(value)) if newline else None
        if parsed is None:
            return None
        rules.setdefault(_git_text(key)[len("remote."):-len(".fetch")], []).append(parsed)
    return rules


def _fetch_excluded(specs: list, ref: str) -> bool:
    """Whether a negative refspec among specs excludes the remote ref `ref` from the fetch."""
    return any(_refspec_map(src, None, pattern, ref) is not None for negative, src, _dst, pattern in specs if negative)


def _fetch_maps_cleanly(repo: str, remote: str, dest: str, tracking: str, deadline: float) -> bool:
    """Whether the fetch rules in effect map the destination branch `dest` to exactly the tracking ref `tracking`,
    and nothing else onto it. Otherwise the tracking ref does not record the state of `dest` on the remote (a remapped
    or colliding refspec), the comparison would be against the wrong state, and the target is NOT MEASURED (review
    R3-2).

    The rules in effect are every remote's fetch refspecs, read as git 2.43.0 reads them (review round 6 of
    2026-10-10, R6-3, measured): a negative refspec of the remote excludes the remote refs it names, so an excluded
    `dest` is never fetched into its tracking ref (`git fetch` exits 0 and leaves it as it was), and an excluded source
    writes nothing; a `*` may stand anywhere in a side; a short name or an empty source (the remote's HEAD) writes the
    tracking ref like any other source (git then refuses the fetch, "Cannot fetch both"); and another remote whose
    fetch writes the tracking ref makes it record that remote. A rule git refuses is NOT MEASURED."""
    rules = _fetch_rules(repo, deadline)
    if not rules:
        return False   # no fetch rule at all, nothing maps dest; or a rule git refuses, or one the gate cannot read
    excluded = _fetch_excluded

    dest_maps_to, maps_to_tracking = set(), set()
    for name, specs in rules.items():
        for negative, src, dst, pattern in specs:
            if negative or not dst:
                continue   # no destination: the fetch writes FETCH_HEAD, not a tracking ref
            local = _local_ref(dst, pattern)
            if not pattern and (local == tracking or name == remote):
                # A plain source names whatever ref of the remote git resolves it to (remote.c get_remote_ref, the best
                # of refname_match's rules against the refs the remote advertises): `other` is refs/heads/other, and
                # refs/heads/gone is refs/heads/refs/heads/gone where the branch gone is missing (measured with git
                # 2.43.0 and 2.51.1). A negative refspec is compared with the ref git resolved, so `^other` excludes
                # nothing. Which remote ref that is, here or for dest, is not evidenced in this repository: NOT
                # MEASURED, never an exclusion read from the spelling (review round 7 of 2026-10-10, R7-4)
                return False
            if not pattern:
                continue   # another remote's plain source writes another ref than the tracking ref
            source = _refspec_map(local, src, pattern, tracking)
            # One decision site for an exclusion: git fetches no excluded source, so it writes nothing, and an
            # excluded dest leaves the tracking ref without its source (mutation M63a: a second check of dest alone
            # changed no verdict)
            if source is not None and not excluded(specs, source):
                if name != remote:
                    return False   # another remote's fetch writes the tracking ref
                maps_to_tracking.add(source)
            if name == remote:
                target = _refspec_map(src, local, pattern, dest)
                if target is not None:
                    dest_maps_to.add(target)
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


#: The rules by which git takes a name for a ref (refs.c, ref_rev_parse_rules), as prefix and suffix around the name.
#: git push applies them to the destination it looks up among the refs the remote advertises (remote.c, match_explicit
#: through count_refspec_match and refname_match), a full name such as refs/heads/main included.
_REV_PARSE_RULES = (("", ""), ("refs/", ""), ("refs/tags/", ""), ("refs/heads/", ""), ("refs/remotes/", ""),
                    ("refs/remotes/", "/HEAD"))


def _dest_candidates(value: str) -> list[tuple[str, bool]]:
    """Every remote ref git push matches the destination value against, with whether git counts that match as strong
    (remote.c, count_refspec_match): a match is weak where the ref lies outside refs/heads/ and refs/tags/ and the value
    is neither the whole name nor the whole name less its leading `refs/`. Where a strong match exists the weak ones do
    not count; two strong matches make git refuse the push ("dst refspec ... matches more than one"). Only names under
    refs/ can be refs a remote advertises for a push."""
    found: list[tuple[str, bool]] = []
    for prefix, suffix in _REV_PARSE_RULES:
        name = prefix + value + suffix
        if not name.startswith("refs/") or any(known == name for known, _strong in found):
            continue
        strong = (len(name) == len(value) or len(value) == len(name) - len("refs/")
                  or name.startswith(("refs/heads/", "refs/tags/")))
        found.append((name, strong))
    return found


def _shell_command(*words: str) -> str:
    """A command the answer suggests, every word quoted whole for a POSIX shell, so it parses and names each value as
    one word (review round 9 of 2026-10-11, R9-4: the remote o'brien had made `git fetch o'brien` an open quote)."""
    return " ".join(shlex.quote(word) for word in words)


#: The kinds of reason _dest_resolution gives (DECISIONS.md D33): the value does not name the destination, this
#: repository records a candidate, or the default case, a candidate whose presence on the remote is not known here.
#: Only the last may be handed over to Level 2; the other two stay asks.
DEST_NOT_NAMED = "not_named"
DEST_RECORDED_CANDIDATE = "recorded_candidate"
DEST_OPEN_AT_REMOTE = "open_at_remote"


def _dest_resolution_problem(repo: str, remote: str, value: str, dest: str,
                             deadline: float) -> tuple[str, str] | None:
    """The reason and next step of _dest_resolution, for the answer, without its kind."""
    found = _dest_resolution(repo, remote, value, dest, deadline)
    return None if found is None else (found[1], found[2])


def _dest_resolution(repo: str, remote: str, value: str, dest: str,
                     deadline: float) -> tuple[str, str, str] | None:
    """Why git push's resolution of the destination value `value` to exactly `dest` is not evidenced, as (kind, reason,
    next step), for the answer (NOT MEASURED; review round 8 of 2026-10-10, R8-2, and round 9 of 2026-10-11, R9-1);
    None only for a value git can match to no other ref. The kind is one of DEST_NOT_NAMED, DEST_RECORDED_CANDIDATE
    and DEST_OPEN_AT_REMOTE, decided here and nowhere else (D33: only the last may be handed over).

    git looks the value up among every ref the remote advertises to the push, by the rules of _REV_PARSE_RULES: for
    the value refs/heads/main it also matches refs/refs/heads/main, refs/tags/refs/heads/main and
    refs/heads/refs/heads/main, and with one of them beside refs/heads/main git refuses the push (measured with git
    2.43.0 and 2.51.1; where refs/heads/main is missing git writes the other ref). Every value has such other
    candidates. The gate does not read the remote (D3), and nothing this repository holds shows that a candidate is
    absent there: a configured fetch rule proves no fetch that ran under it, a fetch and a push see different sets of
    the remote's refs (uploadpack.hideRefs hides a ref from the one, not from the other), and a ref this repository
    does not record is no ref the remote lacks. Round 8 had counted a candidate as absent where a fetch rule recorded
    it and no local ref existed, and passed a push git refuses (R9-1). A recorded candidate is named as what this
    repository records, never as what the remote holds."""
    review = "have a person review the push"
    candidates = _dest_candidates(value)
    if (dest, True) not in candidates:
        return DEST_NOT_NAMED, f"git push looks up {value} on the remote, which does not name {dest}", review
    others = [name for name, _strong in candidates if name != dest]
    if not others:
        return None
    rules = _fetch_rules(repo, deadline)
    specs = [] if rules is None else rules.get(remote, [])
    strength = dict(candidates)
    for name in others:
        if _fetch_excluded(specs, name):
            continue
        for negative, src, dst, pattern in specs:
            local = None if negative or not pattern or not dst else _refspec_map(src, dst, True, name)
            if local is None:
                continue
            shown = _git(repo, "show-ref", "--verify", "--quiet", local, deadline=deadline)
            if shown.returncode == 0:
                # A weak match is no refusal: beside a strong one git ignores it, and it counts only where the remote
                # holds no strong match (review round 10 of 2026-10-11, R10-3: refs/remotes/refs/heads/main beside
                # main, git moved main with exit 0; git 2.43.0 and 2.51.1). Which ref git then writes depends on the
                # remote's refs now, so no write is named (review round 11 of 2026-10-12, R11-6, the review's
                # wording: with main gone and refs/heads/refs/heads/main on the remote, git moved the latter).
                match = (f"git push also matches {name} for {value} and refuses the push where the remote holds it "
                         f"beside {dest}" if strength.get(name) else
                         f"git push matches {name} for {value} only weakly: a weak match counts only when no strong "
                         "match exists on the remote, whose current refs the gate does not read")
                return (DEST_RECORDED_CANDIDATE,
                        f"this repository records {name} of {remote} as {local}, from a fetch at a time the gate does "
                        f"not know; {match}, and what the remote holds now is not known here", review)
    strong = [name for name, is_strong in candidates if is_strong and name != dest]
    return (DEST_OPEN_AT_REMOTE,
            f"git push also matches {', '.join(strong or others)} for {value}, and whether the remote holds one of "
            "them is not known here: the gate does not read the remote, and a ref this repository does not record "
            "is no evidence that the remote lacks it (D3)", review)


def _source_full_name(repo: str, src: str, deadline: float) -> str | None:
    """The full name of the local ref a refspec source names, as git push takes it for a refspec without `:`
    (remote.c, match_explicit: the destination is the source's own full name), or None where git names no single ref."""
    named = _git(repo, "-c", "core.warnAmbiguousRefs=true", "rev-parse", "--symbolic-full-name", src, deadline=deadline)
    if named.returncode != 0 or named.stderr:
        return None
    full = _git_value(named.stdout)
    return full if full and full.startswith("refs/") else None


def _push_source(repo: str, src: str, deadline: float) -> str | None:
    """The commit git push sends for the refspec source `src`, or None where git refuses it or the gate cannot read it.
    git push takes a name that answers to more than one ref (a branch and a tag of one name) as no source at all ("src
    refspec main matches more than one", measured with git 2.43.0 and 2.51.1), while `rev-parse --verify` silently
    takes the tag: the gate had judged the tag's commit (review round 7 of 2026-10-10, the class of R7-2). git's own
    count of the refs a name answers to decides, with the ambiguity warning on whatever the configuration says, since
    push counts them either way; a name that answers to none is an object name, which push and rev-parse read alike."""
    named = _git(repo, "-c", "core.warnAmbiguousRefs=true", "rev-parse", "--symbolic-full-name", src,
                 deadline=deadline)
    if named.returncode != 0 or named.stderr:
        return None   # git names more than one ref, or none it can read
    commit = _git(repo, "rev-parse", "--verify", "--quiet", src + "^{commit}", deadline=deadline)
    if commit.returncode != 0 or not commit.stdout.strip():
        return None
    return commit.stdout.decode().strip()


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


def _handover_drop(handover: dict | None) -> None:
    """The push is no hand-over (D33): a step other than the default destination case left it open."""
    if handover is not None:
        handover["targets"] = []
        handover["remote"] = None


def resolve_push_targets(repo: str, args: list[str] | None, deadline: float,
                         reasons: list | None = None, handover: dict | None = None) -> list[PushTarget] | None:
    """The ref updates a `git push` performs, each with its locally known target state, or None when the
    gate cannot resolve them completely (DECISIONS.md, D3 option B; N1, N2, N3).

    None (NOT MEASURED) for: an over-matched push with no literal arguments; a remote given as a URL or a
    path rather than a configured name; --all, --mirror, --tags, --prune, a delete flag, a wildcard or
    negative refspec, or any option the gate does not model; a configured remote.<name>.push, a pushurl, a
    mirror remote, or push.followTags, all of which add ref updates the command does not name; a bare push
    whose current branch has no tracking ref under the chosen remote; a destination that is not a literal
    branch or tag, or a branch with no uniquely mapped remote-tracking ref. There is no default-branch
    fallback: an unknown target state is NOT MEASURED, never 'unchanged' (N1). args is None for a
    `gh pr/release create`, read as a bare push of the current branch to its upstream. Where a check names why
    (a push configuration value, a destination git's resolution of which is not evidenced), `reasons` receives that
    reason and its next step for the answer: the reason the gate found, not a list of possible ones (review round 8 of
    2026-10-10; the reason of R8-5 had stayed inside the gate and the answer had named other causes).
    """
    if args is None:
        args = []
    if _git_namespace() is not None:
        return None  # the push writes under refs/namespaces/ on the remote, which no tracking ref records
    remote, refspecs, i, options_done, push_options = None, [], 0, False, []
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
                if opt == "--push-option":
                    push_options.append(word[len(opt) + 1:])
                i += 1
                continue
            if not eq and word in _PUSH_OPTS_NEUTRAL_VALUE:
                if i + 1 >= len(args):
                    return None  # git stops: the option needs a value
                push_options.append(args[i + 1])
                i += 2
                continue
            return None  # an abbreviation, a target option (--all/--mirror/--tags/--delete/--repo), unknown
        if remote is None:
            remote = word
        else:
            refspecs.append(word)
        i += 1
    try:
        problem = _push_config_problem(repo, deadline, push_options)
    except GateError:
        return None
    if problem is not None:  # git stops at a push value, or pushes more than the command names, whatever the case (R7-3)
        _note_reason(reasons, problem, "fix or remove that configuration value, or have a person review the push")
        return None
    remotes = _remote_names(repo, deadline)
    if remotes is None:
        return None  # git cannot read the remote configuration, and its push stops there as well
    if remote is None:  # a bare `git push`: the current branch to its chosen remote, same name
        return _default_targets(repo, deadline, remotes, reasons=reasons, handover=handover)
    if remote not in remotes:  # a URL or a filesystem path, not a configured remote name
        return None
    try:
        if _push_adds_unnamed_refs(repo, remote, deadline) or not _endpoint_consistent(repo, remote, deadline):
            return None
    except GateError:
        return None  # a malformed bool or an unreadable endpoint: NOT MEASURED (review R3-1, R3-3)
    if not refspecs:
        return _default_targets(repo, deadline, remotes, remote=remote, reasons=reasons, handover=handover)
    targets = []
    for spec in refspecs:
        forced = spec.startswith("+")
        spec = spec[1:] if forced else spec
        if "*" in spec or spec.startswith("^"):
            _handover_drop(handover)
            return None
        src, sep, dst = spec.partition(":")
        if not sep:  # `name` pushes the ref `name` to the same ref on the remote
            dst = src
        dest = _qualify_dest(dst)
        if dest is None:
            _handover_drop(handover)
            return None
        tracking = _tracking_ref(repo, remote, dest, deadline)
        if tracking is None:  # no uniquely mapped local target state: NOT MEASURED, no fallback (N1)
            _handover_drop(handover)
            return None
        # The value git looks up on the remote: the destination as written, or for a refspec without `:` the source's
        # own full name (R8-2); neither its spelling nor the fetch mapping of dest shows that git resolves it to dest
        value = dst if sep else _source_full_name(repo, src, deadline)
        try:
            found = None if value is None else _dest_resolution(repo, remote, value, dest, deadline)
        except GateError:
            _handover_drop(handover)
            return None
        if value is None or found is not None:
            if found is not None:
                _note_reason(reasons, found[1], found[2])
            # D33: the one reason Level 1 may hand over is the default case; it is collected and the next refspec read,
            # and the push stays unresolved for Level 1 whatever is collected. A deletion and a forced update are no
            # hand-over.
            commit = (_push_source(repo, src, deadline) if handover is not None and found is not None
                      and found[0] == DEST_OPEN_AT_REMOTE and src != "" and not forced else None)
            if commit is None:
                _handover_drop(handover)
                return None
            handover["targets"].append(PushTarget(source=commit, dest=dest, tracking=tracking))
            continue
        if src == "":  # `:dst` deletes the destination ref
            targets.append(PushTarget(source=None, dest=dest, tracking=tracking))
            continue
        commit = _push_source(repo, src, deadline)
        if commit is None:
            _handover_drop(handover)
            return None
        targets.append(PushTarget(source=commit, dest=dest, tracking=tracking))
    if handover is not None and handover["targets"]:
        if targets:
            _handover_drop(handover)   # a refspec git could resolve beside one handed over: not the modelled case
        else:
            handover["remote"] = remote
        return None
    return targets or None


#: The push.default values git 2.43.0 reads (builtin/push.c, git_default_push_config), case as written: `nothing`
#: and `matching` push no branch or more than one; any other value stops every git command.
_PUSH_DEFAULTS_CURRENT_BRANCH = ("simple", "current", "upstream", "tracking")


def _default_push(repo: str, deadline: float, remotes: set, remote: str | None) -> tuple[str, str] | None:
    """(remote, destination ref) of a push that names no refspec, set up as git 2.43.0 sets it up, or None where git
    pushes no single branch or stops (review round 6 of 2026-10-10, R6-2 and its class).

    The remote (remote.c, pushremote_for_branch and remote_for_branch): the one given, else the first of
    branch.<name>.pushRemote, remote.pushDefault and branch.<name>.remote that is present, whatever its value, else
    the one configured remote when there is exactly one, else origin. A present empty value is the remote git takes,
    and git cannot push to it ("no path specified"), so the push is None; it never falls through to the next key.
    The destination (builtin/push.c, setup_default_push_refspecs and get_upstream_ref): `current` pushes the branch
    under its own name; `simple` too, but to the branch's own remote only with exactly one upstream, written as the
    branch's own full ref, and a branch remote; `upstream` (and `tracking`) only to the branch's own remote, to its
    one upstream. push.autoSetupRemote stands in for an upstream that is not set at all. A configured
    remote.<name>.push, push.default nothing or matching, or a value git does not read is None. A read failure
    raises GateError (NOT MEASURED)."""
    head = _git(repo, "symbolic-ref", "--quiet", "HEAD", deadline=deadline)
    refname = _git_value(head.stdout) if head.returncode == 0 else None
    if refname is None or not refname.startswith("refs/heads/"):
        return None  # a detached HEAD names no branch to push; a branch name keeps its bytes, U+0085 too (R5-1)
    # The full refname, never the short form: with a tag of the same name `symbolic-ref --short` says heads/main, and
    # the gate had built refs/heads/heads/main and read branch.heads/main.* (review round 7 of 2026-10-10, R7-2)
    name = refname[len("refs/heads/"):]
    branch_remote = _config_value(repo, f"branch.{name}.remote", deadline)
    default_remote = next(iter(remotes)) if len(remotes) == 1 else "origin"
    fetch_remote = default_remote if branch_remote is None else branch_remote
    if remote is None:
        for key in (f"branch.{name}.pushRemote", "remote.pushDefault"):
            remote = _config_value(repo, key, deadline)
            if remote is not None:
                break
        else:
            remote = fetch_remote
    if remote == "":
        return None  # git takes the empty value as the remote and cannot push to it
    if _config_present(repo, f"remote.{remote}.push", deadline) or _legacy_remote(repo, remote, deadline):
        return None  # the remote's own push list decides what goes, not the current branch
    default = _config_value(repo, "push.default", deadline)
    default = "simple" if default is None else default
    if default not in _PUSH_DEFAULTS_CURRENT_BRANCH:
        return None  # nothing, matching, or a value git does not read
    if default == "current":
        return remote, refname
    same_remote = remote == fetch_remote
    if default == "simple" and not same_remote:
        return remote, refname
    if default != "simple" and not same_remote:
        return None  # upstream to another remote than the branch's own: git refuses
    merges = _config_all(repo, f"branch.{name}.merge", deadline)
    if not merges and _config_bool(repo, "push.autoSetupRemote", deadline):
        upstream = refname   # git pushes under the branch's own name and sets the upstream
    elif not merges or branch_remote is None or len(merges) != 1:
        return None  # no upstream, or two: git refuses
    else:
        upstream = merges[0]
    if default == "simple":
        return (remote, refname) if upstream == refname else None
    return (remote, upstream) if upstream.startswith("refs/heads/") else None


def _default_targets(repo: str, deadline: float, remotes: set, remote: str | None = None,
                     reasons: list | None = None, handover: dict | None = None) -> list[PushTarget] | None:
    """A push with no refspec: the branch git pushes (_default_push) to the remote git chooses, but only when that
    is faithful here. A configured remote.push, a pushurl, a mirror or push.followTags add updates the gate cannot
    name, so those are NOT MEASURED. Where the one reason left open is the default destination case, `handover`
    receives the target and the remote (D33)."""
    try:
        chosen = _default_push(repo, deadline, remotes, remote)
    except GateError:
        return None  # a value git cannot read: NOT MEASURED
    if chosen is None:
        return None
    remote, dest = chosen
    if remote not in remotes:
        return None  # a URL or a path, or a name no configured remote carries
    try:
        if _push_adds_unnamed_refs(repo, remote, deadline) or not _endpoint_consistent(repo, remote, deadline):
            return None
    except GateError:
        return None  # a malformed bool or an unreadable endpoint: NOT MEASURED (review R3-1, R3-3)
    tracking = _tracking_ref(repo, remote, dest, deadline)
    if tracking is None:
        return None
    try:   # git sets up `<branch>:<dest>` with dest in full, and looks that value up on the remote (R8-2)
        found = _dest_resolution(repo, remote, dest, dest, deadline)
    except GateError:
        return None
    head = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", deadline=deadline)
    source = head.stdout.decode().strip() if head.returncode == 0 and head.stdout.strip() else None
    if found is not None:
        _note_reason(reasons, found[1], found[2])
        if handover is not None and found[0] == DEST_OPEN_AT_REMOTE and source is not None:
            handover["targets"] = [PushTarget(source=source, dest=dest, tracking=tracking)]
            handover["remote"] = remote
        return None
    if source is None:
        return None
    return [PushTarget(source=source, dest=dest, tracking=tracking)]


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
                   "rules_changed", evidence=f"the evidence rules under {EVIDENCE_DIR} ({DECLARATION}, its policies "
                                             "and its done check)",
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
    names no commit, or a bare push whose current branch git would not push alone or not at all (_default_push: a
    detached HEAD, a configured remote.<name>.push, push.default matching or one git does not read, an empty remote
    value, an upstream git refuses). There is no
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
            commit = _push_source(repo, src, deadline)
            if commit is None:
                return None, remote
            sources.append(commit)
        return sources, remote
    remotes = _remote_names(repo, deadline)
    if remotes is None:
        raise GateError("git could not list the remotes")
    if _default_push(repo, deadline, remotes, remote) is None:  # the same choice as the target's (R6-2)
        return None, remote
    head = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", deadline=deadline)
    if head.returncode != 0 or not head.stdout.strip():
        return None, remote
    return [head.stdout.decode().strip()], remote


def _source_reads(commit: str, verdict: Verdict) -> list[dict]:
    """The evidence bytes the check of one source commit read, for the gate log (owner choice 3 A of 2026-10-11): each
    file _evaluate_tree read from the commit's tree, with the commit, its path, the sha256 of the bytes read and the
    outcome of that commit's check. A digest is no verification by itself: `passed` only where every declared item
    verified and named the tree; a check that failed or stopped part way carries its reason, and lists only what it
    read before it stopped. No file of the working tree is hashed here, and no commit the check did not read."""
    check = ("passed" if verdict.decision == "pass" else
             f"failed: {verdict.reason_id}" if verdict.decision == "deny" else f"not completed: {verdict.reason_id}")
    return _read_entries(commit, verdict.digests, check)


def _read_entries(commit: str, digests, check: str) -> list[dict]:
    """One log record per evidence or policy file read at `commit` ("<path> sha256:<hex>"), with `check`."""
    reads = []
    for digest in digests:
        path, _sep, value = digest.rpartition(" sha256:")
        reads.append({"commit": commit, "path": path, "sha256": value, "check": check})
    return reads


def _source_denial(repo: str, head_commit: str, sources: list[str], deadline: float, why: str,
                   reads: list | None = None, outcomes: dict | None = None) -> Verdict | None:
    """Befund 1 (review Runde 6): the evidence at uniquely determined source commits is checked even when the
    comparison with the target is NOT MEASURED. A proven evidence failure stays a deny, and the comparison
    that was not measured is named separately in it; anything else returns None, so the caller's NOT
    MEASURED stands — a pass at a source is never a verdict on a push whose comparison is unknown. `reads` receives
    the evidence bytes each checked commit read (_source_reads), up to and including a commit that denies; the deny
    carries them too (owner choice 3 A of 2026-10-11). Where a step fails, the caller hands the exception that record
    (evaluate_push, _keep_reads; owner choice of 2026-10-13 on R12-2 M2: one hand-over, not a second one here). Where
    `outcomes` is a dict, it receives the verdict of each source's evidence check under "evidence" and the set of
    source commits whose done check passed under "done", for the hand-over of D33."""
    reads = [] if reads is None else reads
    for commit in dict.fromkeys(sources):
        where = f"HEAD {commit[:12]}" if commit == head_commit else f"the pushed commit {commit[:12]}"
        verdict = _evaluate_tree(repo, commit, deadline, where, "")
        reads.extend(_source_reads(commit, verdict))
        if outcomes is not None:
            outcomes.setdefault("evidence", {})[commit] = verdict
        if verdict.decision == "deny":
            return Verdict("deny", verdict.detail.rstrip() + " Separately, the comparison with the target was NOT "
                                  f"MEASURED: {why.rstrip('.')}.", verdict.reason_id, evidence=verdict.evidence,
                           failed=verdict.failed, next_step=verdict.next_step, digests=verdict.digests,
                           repo=verdict.repo or repo, head=verdict.head or commit, reads=tuple(reads))
    denial, passes = _push_done(repo, sources, deadline)  # owner choice N2 C: a failed done check is proven too
    if outcomes is not None:
        outcomes["done"] = {v.head for v in passes}
    if denial is not None:
        return Verdict("deny", denial.detail.rstrip() + " Separately, the comparison with the target was NOT "
                              f"MEASURED: {why.rstrip('.')}.", denial.reason_id, evidence=denial.evidence,
                       failed=denial.failed, next_step=denial.next_step, repo=repo, head=denial.head,
                       reads=tuple(reads))
    return None


def _push_done(repo: str, sources: list[str], deadline: float) -> tuple[Verdict | None, list[Verdict]]:
    """Owner choice N2 C (2026-10-08): a push requires the done check at every commit it sends as a tip, the same
    check as at the end of a session (D26, D28), for the tree the push sends rather than the working state. Returns
    the first deny, worded for the push, and the passes; a tip whose declaration has no done check adds neither."""
    passes = []
    for commit in dict.fromkeys(sources):
        try:
            verdict = done_evaluation(repo, deadline, at_commit=commit)["verdict"]
        except Exception as exc:   # R12-2: the commit whose done check stopped; no digest of a file it did not read
            if getattr(exc, "head", None) is None:
                try:
                    exc.head = commit
                except AttributeError:
                    pass
            raise
        if verdict.decision == "deny":
            return Verdict("deny", f"proofbundle gate: the push needs the done check at the pushed commit "
                                   f"{commit[:12]} (owner choice N2 C, DECISIONS.md D26), and it does not pass: "
                                   f"{verdict.failed.rstrip('.')}.", verdict.reason_id, evidence=verdict.evidence,
                           failed=verdict.failed, next_step=verdict.next_step, repo=repo, head=commit), passes
        if verdict.decision == "pass":
            passes.append(verdict)
    return None, passes


def _then(why: str, more: str) -> str:
    """`more` after `why`: a new sentence after a reason that ends as one (the wording of R8-5 is kept whole)."""
    return f"{why} {more[0].upper()}{more[1:]}" if why.endswith(".") else f"{why}; {more}"


def _note_reason(reasons: list | None, why: str, next_step: str) -> None:
    """Keep the first reason a push resolution found, with its next step, for the answer."""
    if reasons is not None and not reasons:
        reasons.append((why, next_step))


def _sources_clean(sources: list[str]) -> str:
    """What an unresolved push's answer says where the evidence at the commits it sends showed no failure (R8-5)."""
    checked = ", ".join(c[:12] for c in dict.fromkeys(sources)) or "none (the push only deletes)"
    return f"the evidence at the sent source commit(s) {checked} showed no failure, which is not a verdict on the push"


def _unresolved_verdict(repo: str, head: str | None, why: str, next_step: str | None = None,
                        reads: tuple = ()) -> Verdict:
    """NOT MEASURED for a push whose targets or range the gate cannot resolve. `why` names the reason and what was
    checked; the text claims nothing beyond it (review round 9 of 2026-10-11, R9-3: "so it checked nothing" had stood
    beside a reason that named the evidence check at the sent commit)."""
    return Verdict("ask", f"NOT MEASURED: the gate cannot resolve what this push sends: "
                          f"{why.rstrip('.')}.", "push_not_measured",
                   evidence="the commits and refs this push would send",
                   failed=why, next_step=next_step or "have a person review the push",
                   repo=repo, head=head, reads=reads)


# --- a push from a repository that declares nothing (owner choice 1 A of 2026-10-11, DECISIONS.md D5) ------

#: The most commits owner choice 1 A reads for one push: the whole history every source of the push reaches. Without a
#: bound target state the commits a push newly sends are unknown, so no tracking ref is subtracted; a longer history is
#: not read, and the push is asked.
MAX_HISTORY_COMMITS = 20000
#: What the ask says of a local ref that holds a declaration and may record the ref a push writes (owner choice of
#: 2026-10-13): its relation to the actual destination is not established, and no equality of remotes is claimed.
_NOT_ESTABLISHED = ("it may record the ref this push writes, but whether it records the actual destination is not "
                    "established")
#: What owner choice 1 A says where it does not apply in a repository whose HEAD and working tree declare nothing.
_LOCAL_EXCEPTION = ("The gate's exception for a repository without a declaration (owner choice 1 A of 2026-10-11, "
                    "DECISIONS.md D5) does not apply: ")


def _push_words(args: list[str]) -> tuple[str | None, list[str], list[str], str | None]:
    """The remote word, the refspecs and the push options (-o, --push-option) of `git push` arguments, read like
    _push_sources reads them, and the first option the gate does not model (None where every option is modelled)."""
    remote, refspecs, options, i, options_done = None, [], [], 0, False
    while i < len(args):
        word = args[i]
        if not options_done and word == "--":
            options_done, i = True, i + 1
            continue
        if not options_done and word.startswith("-") and word != "-":
            opt, eq, _ = word.partition("=")
            if word in _PUSH_FLAGS_NEUTRAL or (eq and opt in _PUSH_OPTS_NEUTRAL_INLINE):
                if eq and opt == "--push-option":
                    options.append(word[len(opt) + 1:])
                i += 1
                continue
            if not eq and word in _PUSH_OPTS_NEUTRAL_VALUE and i + 1 < len(args):
                options.append(args[i + 1])
                i += 2
                continue
            return remote, refspecs, options, word
        if remote is None:
            remote = word
        else:
            refspecs.append(word)
        i += 1
    return remote, refspecs, options, None


def _objects(repo: str, oids: list[str], deadline: float) -> dict[str, tuple[bytes, bytes] | None]:
    """The type and bytes of each object through one `git cat-file --batch`; None for an object git does not give. A
    name git cannot resolve and an object it does not hold print the same `missing` line, so a tree entry is read from
    its tree here and never from a lookup of `<commit>:<path>` (measured with git 2.43.0 and 2.51.1)."""
    _refuse_partial_clone(repo, deadline)
    left = deadline - time.monotonic()
    if left <= 0:
        raise GateError("the gate ran out of time")
    try:
        proc = subprocess.Popen(["git", *_READ_ONLY_GIT, "-C", repo, "cat-file", "--batch"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=_read_env(repo))
    except FileNotFoundError as exc:
        raise GateError("git is not on PATH") from exc
    timer = threading.Timer(left, proc.kill)
    timer.start()
    writer = threading.Thread(target=_feed, args=(proc.stdin, "".join(o + "\n" for o in oids).encode()))
    writer.start()
    found: dict[str, tuple[bytes, bytes] | None] = {}
    try:
        for oid in oids:
            header = proc.stdout.readline().split()
            if len(header) == 2 and header[0] == oid.encode() and header[1] == b"missing":
                found[oid] = None
                continue
            if len(header) != 3 or header[0] != oid.encode():
                raise GateError(f"git gave no readable answer for the object {oid[:12]}")
            remaining, chunks = int(header[2]), []
            while remaining:
                chunk = proc.stdout.read(min(remaining, 1 << 20))
                if not chunk:
                    raise GateError("git stopped while the gate read an object")
                chunks.append(chunk)
                remaining -= len(chunk)
            if proc.stdout.read(1) != b"\n":
                raise GateError("git gave an object the gate cannot read")
            found[oid] = (header[1], b"".join(chunks))
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()
        writer.join()
        proc.stdout.close()
        proc.wait()
    if time.monotonic() >= deadline:
        raise GateError("the gate ran out of time while it read objects")
    return found


def _tree_entries(raw: bytes, oid_length: int) -> dict[bytes, tuple[bytes, str]] | None:
    """The entries of a raw tree object, name to (mode, object id), or None where the bytes are no tree or name one
    entry twice: neither the first nor the last of two entries of one name is a whole reading, and git itself reads
    such a tree as the first, its fsck as duplicateEntries (review round 11 of 2026-10-12, R11-4: a root tree with
    two `.proofbundle` entries, the declared folder first, had been read as the empty one and called an absence)."""
    entries, i = {}, 0
    while i < len(raw):
        space = raw.find(b" ", i)
        nul = raw.find(b"\0", space + 1) if space >= 0 else -1
        if space < 0 or nul < 0 or nul + 1 + oid_length > len(raw):
            return None
        if raw[space + 1:nul] in entries:
            return None
        entries[raw[space + 1:nul]] = (raw[i:space], raw[nul + 1:nul + 1 + oid_length].hex())
        i = nul + 1 + oid_length
    return entries


def _declaration_at(repo: str, commits: list[tuple[str, str]], deadline: float) -> tuple[str, str | None]:
    """Whether anything stands at DECLARATION, or in place of the EVIDENCE_DIR folder, in each (commit, root tree):
    ("absent", None) where every tree was read and holds neither, ("present", commit) for the first commit whose tree
    holds something there (an empty, broken or done-only declaration, a folder or a link at the path, a file or a link
    where the folder belongs), ("unread", commit) for the first commit whose tree git does not give whole."""
    folder, name = EVIDENCE_DIR.rstrip("/").encode(), DECLARATION[len(EVIDENCE_DIR):].encode()
    roots = _objects(repo, sorted({tree for _commit, tree in commits}), deadline)
    subtrees: dict[str, str] = {}
    for commit, tree in commits:
        read = roots.get(tree)
        entries = None if read is None or read[0] != b"tree" else _tree_entries(read[1], len(tree) // 2)
        if entries is None:
            return "unread", commit
        if folder in entries:
            mode, oid = entries[folder]
            if mode != b"40000":
                return "present", commit
            subtrees[commit] = oid
    inner = _objects(repo, sorted(set(subtrees.values())), deadline) if subtrees else {}
    for commit, oid in subtrees.items():
        read = inner.get(oid)
        entries = None if read is None or read[0] != b"tree" else _tree_entries(read[1], len(oid) // 2)
        if entries is None:
            return "unread", commit
        if name in entries:
            return "present", commit
    return "absent", None


def _commit_trees(repo: str, revs: list[str], deadline: float, walk: bool) -> list[tuple[str, str]] | None:
    """(commit, root tree) for each of `revs` (walk False) or for every commit they reach (walk True, at most
    MAX_HISTORY_COMMITS + 1), newest first; None where git cannot list them."""
    if not revs:
        return []
    listing = _git(repo, "rev-list", "--no-commit-header", "--format=%H %T",
                   *(("--max-count=%d" % (MAX_HISTORY_COMMITS + 1),) if walk else ("--no-walk",)), *revs, "--",
                   deadline=deadline)
    if listing.returncode != 0:   # stderr may carry git's hint on the emptied graft file (_read_env)
        return None
    pairs = [tuple(line.split()) for line in listing.stdout.decode("ascii", "replace").splitlines()]
    return pairs if all(len(pair) == 2 for pair in pairs) else None


def _working_tree_declares(repo: str) -> bool:
    """Whether the actual working tree holds anything at DECLARATION, or something other than a folder where
    EVIDENCE_DIR belongs; an answer git or the filesystem does not give counts as holding something."""
    try:
        if not stat.S_ISDIR(os.lstat(os.path.join(repo, EVIDENCE_DIR.rstrip("/"))).st_mode):
            return True   # a file or a link (also a dangling one) where the folder belongs
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return not _absent_in_working_tree(repo)


def _present_refs(repo: str, deadline: float,
                  head_binding: list | None = None) -> tuple[dict[str, str] | None, set[str] | str]:
    """Every present ref of the repository with the object it names, as this worktree reads them, and the refs git calls
    broken; (None, why) where git does not list them whole, where the ref store is not in the form the gate reads
    (_off_form), or where a symbolic ref lies outside the narrow contract (_outside). git resolves every ref: its
    listing names the object of each, and the gate follows no chain of its own (owner choice of 2026-10-13, 17:0x
    Berlin, A and A, the narrow contract, points 2, 4 and 6; the external design review of that day at 101bd167
    measured git's answer right in each worktree and the gate's own rebuild of chains, worktree contexts and depths
    wrong). The records git's listing leaves out are read from this worktree's git directory (_root_records); where
    `head_binding` is a list, the HEAD binding that reading read is appended to it (review round 18, R18-1)."""
    listing = _git(repo, "for-each-ref", "--format=%(refname)%00%(objectname)%00%(symref)", deadline=deadline)
    if listing.returncode != 0:
        return None, "git cannot list this repository's refs, so the local records of the destination are not known"
    broken = set()
    for line in listing.stderr.decode("utf-8", "replace").splitlines():
        if line in _GRAFT_HINT:
            continue   # git's known hint on the emptied graft file (_read_env), nothing about a ref
        if not line.startswith("warning: ignoring broken ref "):
            return None, ("git warns while it lists this repository's refs, so a record of the destination may be "
                          f"unread: {line}")
        broken.add(line[len("warning: ignoring broken ref "):])
    # Each line is the name, the object and the end of a symbolic ref's chain, with a NUL after each of the first two
    # and a line feed after all; any other line, or output that ends without a line feed, is no whole listing (narrow
    # contract, points 4 and 7). A name twice stops before any assignment (R16-1).
    present, symbolic = {}, {}
    if listing.stdout and not listing.stdout.endswith(b"\n"):
        return None, _UNREAD_LISTING
    for line in listing.stdout.split(b"\n")[:-1]:
        fields = line.split(b"\0")
        if len(fields) != 3 or not _OID.fullmatch(fields[1]):
            return None, _UNREAD_LISTING
        name = _git_text(fields[0])
        if name in present:   # R16-1: git lists a name of packed-refs twice, exit 0, no warning
            return None, _off_form("a name twice in git's listing", name)
        present[name] = fields[1].decode("ascii")
        if fields[2]:   # %(symref) marks a symbolic ref; it names the end of the chain, not the first step
            symbolic[name] = _git_text(fields[2])
    # git's listing leaves out a symbolic ref whose target does not exist, with exit 0 and no warning (review round 13
    # of 2026-10-13, R13-1): every ref the ref store holds must be one git lists or calls broken.
    paths, why = _repo_paths(repo, deadline)
    if paths is None or not paths["common"] or not paths["gitdir"]:
        return None, why or "git does not name the repository's directories, so its refs are not known"
    store, why = _stored_refs(repo, paths, deadline)
    if store is None:
        return None, why
    unlisted = sorted(set(store["names"]) - set(present) - broken)
    if unlisted:
        return None, _unresolved(unlisted[0])
    refused = sorted(name for name in present if not _ref_name_ok(name))
    if refused:
        return None, _off_form("a name git's ref rules refuse", refused[0])
    # The object git lists for a direct ref is the one the store holds, a valid loose file before its packed entry (review
    # round 17 of 2026-10-13, R17-1): the names alone matched while a ref moved between git's listing and the reading of
    # the store, and the map the final reading was compared with still held the earlier object. A difference leaves no
    # finished measurement, and the map returned holds only objects both readings gave.
    for name, oid in sorted(present.items()):
        if name in symbolic:
            continue   # its loose file names the end git lists, checked in _symbolic_outside
        held = store["loose"].get(name)
        stored = (held[1] if held[0] == "object" else None) if held is not None else store["packed"].get(name)
        if stored != oid:
            return None, _moved(name)
    why = _symbolic_outside(repo, store, present, symbolic, deadline)
    if why is not None:
        return None, why
    # Nor does git list FETCH_HEAD and the other root refs (the class of R13-1).
    beside, why = _root_records(paths, present, symbolic, head_binding)
    if beside is None:
        return None, why
    # Nor any further file of the git directory git resolves as a ref (owner choice of 2026-10-13, 20:0x, K16-1).
    further, why = _further_records(repo, paths, present, symbolic, deadline)
    if further is None:
        return None, why
    clash = sorted((set(beside) | set(further)) & set(present))
    if clash:
        return None, _off_form("a name twice in git's listing and beside it", clash[0])
    present.update(beside)
    present.update(further)
    return present, broken


def _off_form(reason: str, entry: str) -> str:
    """Why the exception does not apply where the ref store is not in the normal form the gate reads (owner choice of
    2026-10-13, 16:4x Berlin, A, on R16-1 to R16-4 of review round 16): the reason and the entry."""
    return f"the ref store is not in the form the gate reads ({reason}): {entry}"


def _outside(reason: str, entry: str) -> str:
    """Why the exception does not apply to a repository outside the range the narrow contract covers (owner choice of
    2026-10-13, 17:0x Berlin, A and A, points 1 and 2): the reason and the entry. It says what the gate does not
    measure here, never that nothing is declared, and asks no one to remove a worktree, a ref or a record."""
    return (f"the repository is outside the range the exception covers, one ordinary main worktree whose only symbolic "
            f"refs are HEAD and refs/remotes/<remote>/HEAD, each naming a ref git lists ({reason}): {entry}")


def _moved(ref: str) -> str:
    return (f"the local ref {ref} names another object in git's listing than in the ref store, so the refs changed while "
            "the gate read them and its reading is no finished measurement that nothing is declared")


def _unresolved(ref: str) -> str:
    return (f"the local ref {ref} is present, but git does not resolve it (a symbolic ref to a ref that does not "
            "exist, or a name git does not list), and it may record the ref this push writes")


#: Output of git's listing the gate cannot read as a whole listing (narrow contract, points 4 and 7).
_UNREAD_LISTING = "git lists a line the gate cannot read, so a record of the destination may be unread"
#: The hint git 2.43.0 prints, line by line, under GIT_GRAFT_FILE set to the empty device (_read_env), measured on
#: rev-list; the one known harmless output on stderr (narrow contract, point 7). Every other line is a warning.
_GRAFT_HINT = frozenset({
    "hint: Support for <GIT_DIR>/info/grafts is deprecated", "hint: and will be removed in a future Git version.",
    "hint: ", "hint: Please use \"git replace --convert-graft-file\"", "hint: to convert the grafts into replace refs.",
    "hint: Turn this message off by running", "hint: \"git config advice.graftFileDeprecated false\"",
})
#: The refs of one worktree; in a linked worktree those of the common directory belong to the main worktree.
_PER_WORKTREE = ("refs/bisect/", "refs/worktree/", "refs/rewritten/")
#: git lists the refs in a folder under refs/ that is a symbolic link and leaves out a symbolic ref there whose target
#: does not exist (measured with git 2.43.0); the gate does not follow such a link (the class of R13-1).
_LINKED_FOLDER = ("a folder of the repository's refs is a symbolic link, which git follows and the gate does not, so a "
                  "record of the destination may be unread")
#: An object name as git writes it into the ref store, in lower case, for SHA-1 or SHA-256.
_OID = re.compile(rb"[0-9a-f]{40}|[0-9a-f]{64}")
#: The characters git's ref rules refuse anywhere in a name (refs.c, check_refname_component, git 2.43.0): a space,
#: ~ ^ : ? * [ and a backslash, besides the control characters below 0x20 and DEL.
_REF_NAME_REFUSED = frozenset(" ~^:?*[\\\x7f")
#: The most bytes the gate reads of one file of the ref store, packed-refs, a loose ref or a root record; a larger one
#: leaves the exception unapplied (narrow contract, points 5 and 7).
MAX_RECORD_BYTES = 16 * 1024 * 1024


def _ref_name_ok(name: str) -> bool:
    """Whether git's ref rules (git check-ref-format, refs.c of git 2.43.0) take `name` as a full ref name: one under
    refs/ whose parts are not empty, do not start with `.` and do not end in .lock, with no `..`, no `@{`, no character
    of _REF_NAME_REFUSED or below 0x20, and no `/` or `.` at the end; or a root ref of the gate's list (HEAD, _ROOT_REF,
    _ROOT_REF_OTHERS). Bytes above 0x7f, which git takes, pass (owner choice of 2026-10-13, 16:4x Berlin, A, R16-3: a
    name the rules refuse is no name the gate models, and the exception does not apply)."""
    if "/" not in name:
        return name == "HEAD" or bool(_ROOT_REF.fullmatch(name)) or name in _ROOT_REF_OTHERS
    if not name.startswith("refs/") or name.endswith(("/", ".")) or ".." in name or "@{" in name:
        return False
    if any(not part or part.startswith(".") or part.endswith(".lock") for part in name.split("/")):
        return False
    return not any(char in _REF_NAME_REFUSED or ord(char) < 0x20 for char in name)


def _ref_file(raw: bytes) -> tuple[str, str]:
    """A loose ref file or a root record in the normal form, exactly `<oid>LF` or `ref: <name>LF` with a name
    _ref_name_ok takes: ("object", oid), ("symbolic", name), or ("off", reason). git reads more than this (a trailing
    space, a second line, no LF, CRLF, `ref:` with no space, measured with git 2.43.0) and less (a leading empty line,
    R16-4), so any other form is off the normal form."""
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        return "off", "a file not of the form <object>LF or ref: <name>LF"
    line = raw[:-1]
    if _OID.fullmatch(line):
        return "object", line.decode("ascii")
    if line.startswith(b"ref: "):
        target = _git_text(line[len(b"ref: "):])
        return ("symbolic", target) if _ref_name_ok(target) else ("off", "a target git's ref rules refuse")
    return "off", "a file not of the form <object>LF or ref: <name>LF"


def _no_link(path: str) -> bool:
    """Whether path is no symbolic link; an answer the filesystem does not give counts as one."""
    try:
        return not stat.S_ISLNK(os.lstat(path).st_mode)
    except FileNotFoundError:
        return True
    except OSError:
        return False


class _NotRegular(OSError):
    """An entry that is no regular file (a FIFO, a device, a socket, a folder), found at the opened descriptor."""


def _read_regular(path: str, limit: int, follow: bool = False) -> bytes:
    """Up to `limit` bytes of the regular file at `path` (review round 18 of 2026-10-14, R18-2). The file is opened
    without blocking and its type is checked at the opened descriptor before anything is read, so a FIFO with no writer,
    a device or a socket is never waited on: it raises _NotRegular, an OSError. A symbolic link is refused (the open
    fails) unless `follow`. OSError as open raises it."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    if not follow:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise _NotRegular(errno.EINVAL, "not a regular file", path)
        handle = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with handle:
        return handle.read(limit)


def _record_bytes(path: str) -> bytes | None:
    """The bytes of one file of the ref store, None where it holds more than MAX_RECORD_BYTES; OSError as open raises
    it, _NotRegular for an entry that is no regular file, checked at the descriptor before any read (R18-2)."""
    raw = _read_regular(path, MAX_RECORD_BYTES + 1)
    return None if len(raw) > MAX_RECORD_BYTES else raw


def _too_large(entry: str) -> str:
    return (f"the record {entry} holds more than {MAX_RECORD_BYTES} bytes, more than the gate reads, and it may record "
            "the ref this push writes")


def _stored_refs(repo: str, paths: dict, deadline: float) -> tuple[dict | None, str]:
    """The ref store of the files format, read whole and checked against its normal form: {"names": every ref name it
    holds, each file under refs/ of the common directory and of this worktree's git directory and each entry of
    packed-refs; "packed": each entry of packed-refs with its object; "loose": each loose file of the common directory
    with what it holds (_ref_file)}; (None, why) for a store the gate cannot read whole here, one in another format
    (extensions.refStorage, such as reftable), a folder or file it cannot read (review round 13 of 2026-10-13, R13-1),
    a file over MAX_RECORD_BYTES, or one off the normal form (owner choice of 2026-10-13, 16:4x Berlin, A, review
    round 16, kept as point 3 of the narrow contract of 17:0x): a symbolic link anywhere in it, a loose file not of
    the form _ref_file reads, a line of packed-refs not of the form `<oid> <name>` with a `^<oid>` line only after one
    and its header only at the top, a name there outside refs/ or twice (R16-1), or out of the order its `sorted` header
    promises, which git's lookup then misses (measured with git 2.43.0). A valid loose file beside its packed entry is
    git's ordinary precedence, and packed refs are no reason to ask."""
    storage = _git(repo, "config", "--get", "extensions.refstorage", deadline=deadline)
    if storage.returncode not in (0, 1) or (storage.returncode == 0 and storage.stdout.strip().lower() != b"files"):
        return None, ("the repository keeps its refs in a format other than files (extensions.refStorage), whose refs "
                      "the gate does not read whole here, so a record of the destination may be unread")
    names: set[str] = set()
    loose: dict[str, tuple[str, str]] = {}

    def stop(exc: OSError) -> None:
        raise exc

    try:
        for base in dict.fromkeys((paths["common"], paths["gitdir"])):
            top = os.path.join(base, "refs")
            if base != paths["common"] and not os.path.lexists(top):
                continue   # a linked worktree that holds no ref of its own
            if not _no_link(top):
                return None, _off_form("a symbolic link", os.path.relpath(top, paths["common"]))
            linked_common = base == paths["common"] and paths["gitdir"] != paths["common"]
            for root, dirs, files in os.walk(top, onerror=stop):
                if any(os.path.islink(os.path.join(root, name)) for name in dirs):
                    return None, _LINKED_FOLDER
                for name in files:
                    path = os.path.join(root, name)
                    ref = "refs/" + os.path.relpath(path, top).replace(os.sep, "/")
                    if linked_common and ref.startswith(_PER_WORKTREE):
                        continue
                    if not _no_link(path):
                        return None, _off_form("a symbolic link", ref)   # R16-2
                    names.add(ref)
                    if not _ref_name_ok(ref):
                        continue   # a name git does not list stays one the listing must name (_present_refs)
                    try:
                        raw = _record_bytes(path)
                    except _NotRegular:
                        return None, _off_form("an entry that is no regular file", ref)   # R18-2
                    if raw is None:
                        return None, _too_large(ref)
                    held = _ref_file(raw)
                    if held[0] == "off":
                        return None, _off_form(held[1], ref)
                    if base == paths["common"] or ref.startswith(_PER_WORKTREE):
                        loose[ref] = held
        packed_path = os.path.join(paths["common"], "packed-refs")
        if not _no_link(packed_path):
            return None, _off_form("a symbolic link", "packed-refs")
        try:
            packed = _record_bytes(packed_path)
        except _NotRegular:
            return None, _off_form("an entry that is no regular file", "packed-refs")   # R18-2
        if packed is None:
            return None, _too_large("packed-refs")
    except FileNotFoundError as exc:
        if exc.filename and os.path.basename(exc.filename) == "packed-refs":
            packed = b""
        else:
            return None, ("a folder of the repository's refs cannot be read, so a record of the destination may be "
                          "unread")
    except OSError:
        return None, "the repository's refs cannot be read whole, so a record of the destination may be unread"
    packed_refs: dict[str, str] = {}
    lines = packed.split(b"\n")
    if packed and lines[-1] != b"":
        return None, _off_form("a line of packed-refs not of the form <object> <name>", "packed-refs")
    lines = lines[:-1]
    sorted_ = False
    if lines and lines[0].startswith(b"# pack-refs with:"):
        sorted_ = b" sorted " in lines[0][len(b"# pack-refs with:"):] + b" "
        lines = lines[1:]
    previous, peelable = None, False
    for line in lines:
        if line.startswith(b"^") and peelable and _OID.fullmatch(line[1:]):
            peelable = False
            continue
        oid, space, raw_name = line.partition(b" ")
        if not space or not _OID.fullmatch(oid) or not raw_name:
            return None, _off_form("a line of packed-refs not of the form <object> <name>", "packed-refs")
        name = _git_text(raw_name)
        if not name.startswith("refs/"):
            return None, _off_form("a name outside refs/ in packed-refs", name)   # git lists it, rev-parse misses it
        if not _ref_name_ok(name):
            return None, _off_form("a name git's ref rules refuse", name)
        if name in packed_refs:
            return None, _off_form("a name twice in packed-refs", name)   # R16-1
        if sorted_ and previous is not None and raw_name <= previous:
            return None, _off_form("packed-refs out of the order its header promises", name)
        previous, peelable = raw_name, True
        names.add(name)
        packed_refs[name] = oid.decode("ascii")
    return {"names": names, "packed": packed_refs, "loose": loose}, ""


def _symbolic_outside(repo: str, store: dict, present: dict[str, str], symbolic: dict[str, str],
                      deadline: float) -> str | None:
    """Why a symbolic ref git lists lies outside the narrow contract (owner choice of 2026-10-13, 17:0x Berlin, point
    2), or None: the only one allowed under refs/ is refs/remotes/<remote>/HEAD of a remote git lists, whose loose file
    names exactly the ref git's listing ends its chain with, a ref git lists that is no symbolic ref itself. Any other
    symbolic ref, a chain, and a name that only ends in HEAD are asked; the gate follows no chain of its own."""
    if not symbolic:
        return None
    remotes = _remote_names(repo, deadline)
    if remotes is None:
        return "git cannot list the remotes, so whether a symbolic ref is one of a remote's HEAD is not known"
    for name, end in sorted(symbolic.items()):
        remote = (name[len("refs/remotes/"):-len("/HEAD")]
                  if name.startswith("refs/remotes/") and name.endswith("/HEAD") else None)
        if remote not in remotes:
            return _outside("a symbolic ref other than HEAD and refs/remotes/<remote>/HEAD", name)
        if store["loose"].get(name) != ("symbolic", end) or end not in present or end in symbolic:
            return _outside("a symbolic ref whose target is not a ref git lists, named directly", name)
    return None


#: The files of a git directory that hold refs beside refs/, git's root refs and pseudorefs: a name of capitals, `-` and
#: `_` that ends in _HEAD (refs.c, is_pseudoref_syntax of git 2.43.0), and the few others git writes.
_ROOT_REF = re.compile(r"[A-Z_-]+_HEAD")
_ROOT_REF_OTHERS = frozenset({"AUTO_MERGE", "BISECT_EXPECTED_REV", "MERGE_AUTOSTASH", "NOTES_MERGE_PARTIAL",
                              "NOTES_MERGE_REF"})
#: A line of FETCH_HEAD as git 2.43.0 writes it: the object, a tab, not-for-merge or nothing, a tab and what was fetched
#: from where (measured for a fetch of a remote, a branch, an object, a tag and --tags).
_FETCH_LINE = re.compile(rb"([0-9a-f]{40}|[0-9a-f]{64})\t(?:not-for-merge)?\t[^\n]*")


def _root_records(paths: dict, present: dict[str, str], symbolic: dict[str, str],
                  head_binding: list | None = None) -> tuple[dict[str, str] | None, str]:
    """The records git's ref listing leaves out (review round 13 of 2026-10-13, the class of R13-1), as {name: object},
    from this worktree's git directory: FETCH_HEAD line by line, not-for-merge lines included, MERGE_HEAD with one
    object per line, and the other root refs (ORIG_HEAD and its kin), each read whole up to MAX_RECORD_BYTES and in the
    normal form (narrow contract, points 3 and 5). HEAD is no record here, condition b reads it; it is an object or a
    direct symbolic ref to a ref git lists that is no symbolic ref itself (point 2). Any other symbolic root record, any
    other form and a symbolic link are asked. The HEAD this reading read is not dropped after its form check (review
    round 18 of 2026-10-14, R18-1): where `head_binding` is a list, (kind, value, object) is appended to it, the object
    of a symbolic HEAD being the one git lists for its target in the same inventory."""
    folder = paths["gitdir"]
    unread = ("the records beside the repository's refs cannot be read whole, so a record of the destination may be "
              "unread")
    found: dict[str, str] = {}
    try:
        names = sorted(name for name in os.listdir(folder) if _root_record_name(name))
        if os.path.lexists(os.path.join(folder, _INFO_REFS)):
            names.append(_INFO_REFS)
        for name in names:
            path = os.path.join(folder, name)
            if not _no_link(path):
                return None, _off_form("a symbolic link", name)   # R16-2
            try:
                raw = _record_bytes(path)
            except _NotRegular:
                return None, _off_form("an entry that is no regular file", name)   # R18-2: a FIFO is never waited on
            if raw is None:
                return None, _too_large(name)
            if name == "FETCH_HEAD":
                if raw and not raw.endswith(b"\n"):
                    return None, _off_form(_FETCH_FORM, name)
                for number, line in enumerate(raw.split(b"\n")[:-1], 1):
                    match = _FETCH_LINE.fullmatch(line)
                    if match is None:
                        return None, _off_form(_FETCH_FORM, name if number == 1 else f"{name} (line {number})")
                    found[name if number == 1 else f"{name} (line {number})"] = match.group(1).decode("ascii")
                continue
            if name == _INFO_REFS:
                if raw and not raw.endswith(b"\n"):
                    return None, _off_form(_INFO_REFS_FORM, name)
                for number, line in enumerate(raw.split(b"\n")[:-1], 1):
                    match = _INFO_REFS_LINE.fullmatch(line)
                    if match is None:
                        return None, _off_form(_INFO_REFS_FORM, name if number == 1 else f"{name} (line {number})")
                    found[name if number == 1 else f"{name} (line {number})"] = match.group(1).decode("ascii")
                continue
            if name == "MERGE_HEAD" and raw.endswith(b"\n") and raw.count(b"\n") > 1:
                for number, line in enumerate(raw[:-1].split(b"\n"), 1):
                    if not _OID.fullmatch(line):
                        return None, _off_form("a line of MERGE_HEAD not of the form <object>LF", name)
                    found[name if number == 1 else f"{name} (line {number})"] = line.decode("ascii")
                continue
            if not raw:
                return None, (f"the local ref {name} names nothing the gate can read, and it may record the ref this "
                              "push writes")
            kind, value = _ref_file(raw)
            if kind == "off":
                return None, _off_form(value, name)   # R16-4
            if name == "HEAD":
                if kind == "symbolic" and (value not in present or value in symbolic):
                    return None, _outside("a symbolic ref whose target is not a ref git lists, named directly", name)
                if head_binding is not None:
                    head_binding.append((kind, value, present[value] if kind == "symbolic" else value))
                continue
            if kind == "symbolic":
                return None, _outside("a symbolic ref other than HEAD and refs/remotes/<remote>/HEAD", name)
            found[name] = value
    except OSError:
        return None, unread
    return found, ""


def _root_record_name(name: str) -> bool:
    """Whether `name`, a path relative to the git directory, is one of the records _root_records reads in their strict
    form: HEAD, the root refs at the top of the git directory, and info/refs. The search for further records
    (_further_records) leaves them to that reading, so a broken form of theirs is never taken for an ordinary file."""
    return name == "HEAD" or bool(_ROOT_REF.fullmatch(name)) or name in _ROOT_REF_OTHERS or name == _INFO_REFS


#: The copy of the refs `git update-server-info` writes for the dumb transports; `git gc` writes it through `git repack`
#: (measured with git 2.43.0). git resolves the name info/refs to the object of its first line, so it is a record; every
#: line is read, each `<object>TAB<name>LF` as git writes it, a peeled tag as <name>^{} (FIX-17, the gc control).
_INFO_REFS = "info/refs"
_INFO_REFS_LINE = re.compile(rb"([0-9a-f]{40}|[0-9a-f]{64})\t[^\n]+")
_INFO_REFS_FORM = "a line of info/refs not of the form <object>TAB<name>LF"
#: The most further files the gate takes from the git directory beside the ref store and the root records (narrow
#: contract, point 7); more leave the exception unapplied.
MAX_FURTHER_FILES = 20000
#: How much of a further file the gate reads to know its form; a record in the direct normal form <oid>LF has 41 or 65.
_FURTHER_HEAD = 4096
#: A line of a reflog as git 2.43.0 writes it: the old and the new object, the identity, the time and its zone, and a tab
#: with the message where there is one.
_REFLOG_LINE = re.compile(rb"([0-9a-f]{40}|[0-9a-f]{64}) ([0-9a-f]{40}|[0-9a-f]{64}) [^<>\n]*<[^<>\n]*> [0-9]+ "
                          rb"[+-][0-9]{4}(?:\t[^\n]*)?")
#: The start of a file git can read as a ref (refs.c, parse_loose_ref_contents of git 2.43.0): `ref:`, or an object name,
#: whose hex digits git takes in either case. A file that starts so and that git does not resolve is no ordinary file.
_RECORD_LIKE = re.compile(rb"ref:|[0-9a-fA-F]{40}")
#: The supported form of BISECT_START that names a branch: its short name and a line feed, as `git bisect start` writes it
#: on a branch (measured with git 2.43.0); the branch is one git lists.
_BISECT_START = "BISECT_START"
#: How many of git's answers for further files the gate asks for side by side.
_FURTHER_WORKERS = 4
#: git's lists of a stopped rebase, with the number of objects on each of their lines (sequencer.c and builtin/am.c of
#: git 2.43.0): rewritten-list and rewritten hold `<old> <new>LF` for each commit rewritten so far, rewritten-pending
#: `<oid>LF` for each commit of a fixup chain not yet written. git resolves each name to the first object of its first
#: line (measured), so each is a record, and every object of every line is read as one, as for FETCH_HEAD (FIX-17: a
#: rebase stopped at a later pick had been asked).
_REWRITTEN = {"rebase-merge/rewritten-list": 2, "rebase-apply/rewritten": 2, "rebase-merge/rewritten-pending": 1}
_REWRITTEN_FORM = "a line of a rebase's rewritten list not of the form git writes"


def _further(reason: str, entry: str) -> str:
    """Why the exception does not apply to a further file of the git directory (owner choice of 2026-10-13, 20:0x,
    K16-1; review round 17): the reason and the entry."""
    return f"the git directory holds a file the gate does not read as a record whole ({reason}): {entry}"


def _further_name_ok(name: str) -> bool:
    """Whether git's ref rules take `name` as a ref name of one or more levels (git check-ref-format --allow-onelevel,
    refs.c of git 2.43.0): parts not empty, not starting with `.` and not ending in .lock, no `..`, no `@{`, not `@`,
    no character of _REF_NAME_REFUSED or below 0x20, and no `/` or `.` at the end. Only such a name is handed to git, so
    no revision expression ever is."""
    if name == "@" or name.endswith(("/", ".")) or ".." in name or "@{" in name:
        return False
    if any(not part or part.startswith(".") or part.endswith(".lock") for part in name.split("/")):
        return False
    return not any(char in _REF_NAME_REFUSED or ord(char) < 0x20 for char in name)


def _valid_reflog(raw: bytes) -> bool:
    """Whether `raw` is a reflog whole: one or more lines, each of the form _REFLOG_LINE, and a line feed at the end. A
    file of only <oid>LF is no reflog (owner choice of 2026-10-13, 21:4x)."""
    return (raw.endswith(b"\n") and
            all(_REFLOG_LINE.fullmatch(line) for line in raw[:-1].split(b"\n")))


def _rewritten(rel: str, path: str, head: bytes, oid: str) -> tuple[dict[str, str] | None, str]:
    """The records of one of git's rewritten lists (_REWRITTEN), as {name: object}: the first object of the first line
    under the file's own name, as git resolves it, every other one as `<name> (line N, object M)`. (None, why) where the
    file is larger than the gate reads, its bytes do not start as they did when the gate read its start, a line is not
    of the form git writes, or its first object is not the one git gave."""
    whole = _record_bytes(path)
    if whole is None:
        return None, _too_large(rel)
    if whole[:len(head)] != head:
        return None, _further("a file that changed while the gate read it", rel)
    if not whole.endswith(b"\n"):
        return None, _further(_REWRITTEN_FORM, rel)
    found: dict[str, str] = {}
    for number, line in enumerate(whole[:-1].split(b"\n"), 1):
        parts = line.split(b" ")
        if len(parts) != _REWRITTEN[rel] or not all(_OID.fullmatch(part) for part in parts):
            return None, _further(_REWRITTEN_FORM, rel)
        for place, part in enumerate(parts, 1):
            found[rel if (number, place) == (1, 1) else f"{rel} (line {number}, object {place})"] = part.decode("ascii")
    if found[rel] != oid:
        return None, _further("a record git resolves to another object than the file holds", rel)
    return found, ""


def _resolution(repo: str, name: str, deadline: float) -> tuple[str, str | None, str | None]:
    """git's two answers for a further file's name, with fixed, hardened calls and the name after `--end-of-options`:
    ("none", None, None) where both calls end in git's ordinary negative case, exit 1 with no output and no warning;
    ("broken", None, None) for the same where each call says only `warning: ignoring broken ref <name>`, which git 2.43.0
    prints for every file under a folder of the git directory whose bytes are no ref, a hook sample or an object file
    alike (measured; a file at the top prints nothing), so arbitrary text is not taken for a broken former ref by its
    path; ("found", object, full name) where both give exactly one line; ("warning", line, None) for any other line on
    stderr than the known graft hint; ("unknown", None, None) for anything else."""
    oid = _git(repo, "rev-parse", "--verify", "--quiet", "--end-of-options", name, deadline=deadline)
    full = _git(repo, "rev-parse", "--verify", "--quiet", "--symbolic-full-name", "--end-of-options", name,
                deadline=deadline)
    lines = [line for call in (oid, full) for line in call.stderr.decode("utf-8", "replace").splitlines()
             if line not in _GRAFT_HINT]
    negative = oid.returncode == 1 and full.returncode == 1 and not oid.stdout and not full.stdout
    if lines:
        if negative and len(lines) == 2 and set(lines) == {f"warning: ignoring broken ref {name}"}:
            return "broken", None, None
        return "warning", lines[0], None
    if negative:
        return "none", None, None
    if oid.returncode == 0 and full.returncode == 0:
        value, named = oid.stdout.split(b"\n"), full.stdout.split(b"\n")
        if len(value) == 2 and value[1] == b"" and _OID.fullmatch(value[0]) and len(named) == 2 and named[1] == b"" \
                and named[0]:
            return "found", value[0].decode("ascii"), _git_text(named[0])
    return "unknown", None, None


def _further_records(repo: str, paths: dict, present: dict[str, str], symbolic: dict[str, str],
                     deadline: float) -> tuple[dict[str, str] | None, str]:
    """Every further file of the git directory that git resolves as a ref, as {name: object} (owner choice of
    2026-10-13, 20:0x, K16-1, and the rule of review round 17): additional files outside the known ref stores and root
    records are included when git resolves their exact names. The git directory is read recursively, logs/, objects/,
    rebase-merge/ and any unknown folder included; refs/ and packed-refs are the store (_stored_refs) and HEAD, the root
    refs and info/refs are read in their strict form (_root_records), so a broken form of theirs never passes here.
    Only worktrees/ is left out: any entry there puts the repository outside the narrow contract (_narrow_range, point
    1). A valid reflog under logs/ is historical data and stays outside (owner choice of 2026-10-13, 21:4x); a file there
    of only <oid>LF is no reflog and is read here.

    Each other regular file whose name git's ref rules take goes to git twice, `rev-parse --verify --quiet` for the
    object and the same call with `--symbolic-full-name` for the full name. Only where the full name is exactly the
    file's name has git resolved this file: it must then hold <oid>LF, the object git gives, or be one of git's rewritten
    lists of a stopped rebase in the form git writes (_REWRITTEN), whose objects are all read. A full name of another ref
    already read, with its object, is git's substitution of a name, no record here. Where both calls end in git's
    ordinary negative case the file holds no record git can resolve now, which says nothing about whether it ever was
    one; a file that starts like a record and is not resolved is asked. A symbolic record, a record in another form, a
    record under a name the rules refuse, a warning, an answer the gate cannot read, a symbolic link, an entry that is
    no regular file or cannot be read, more than MAX_FURTHER_FILES files, and a file that changed while it was read are
    asked: (None, why)."""
    folder = paths["gitdir"]
    asked: list[tuple[str, str, bytes, str, str | None, bool]] = []   # (name, path, head, kind, value, record-like)
    count = 0

    def stop(exc: OSError) -> None:
        raise exc

    try:
        for root, dirs, files in os.walk(folder, onerror=stop):
            here = os.path.relpath(root, folder).replace(os.sep, "/")
            prefix = "" if here == "." else here + "/"
            if here == ".":
                dirs[:] = [d for d in dirs if d not in ("refs", "worktrees")]
            for name in sorted(dirs):
                if os.path.islink(os.path.join(root, name)):
                    return None, _off_form("a symbolic link", prefix + name)
            dirs.sort()
            for name in sorted(files):
                rel = prefix + name
                if here == "." and (name == "packed-refs" or _root_record_name(name)) or rel == _INFO_REFS:
                    continue
                count += 1
                if count > MAX_FURTHER_FILES:
                    return None, (f"the git directory holds more than {MAX_FURTHER_FILES} further files, more than the "
                                  "gate reads, and any of them may record the ref this push writes")
                path = os.path.join(root, name)
                mode = os.lstat(path).st_mode
                if stat.S_ISLNK(mode):
                    return None, _off_form("a symbolic link", rel)
                if not stat.S_ISREG(mode):
                    return None, _further("an entry that is no regular file", rel)
                if rel.startswith("logs/"):
                    whole = _record_bytes(path)
                    if whole is not None and _valid_reflog(whole):
                        continue   # historical reflog data (owner choice of 2026-10-13, 21:4x)
                try:
                    head = _read_regular(path, _FURTHER_HEAD + 1)   # R18-2: the type checked at the descriptor too
                except _NotRegular:
                    return None, _further("an entry that is no regular file", rel)
                kind, value = _ref_file(head) if len(head) <= _FURTHER_HEAD else ("off", None)
                like = bool(_RECORD_LIKE.match(head))
                if not _further_name_ok(rel):
                    if like:
                        return None, _further("a record under a name git's ref rules refuse", rel)
                    continue
                if head.startswith(b"ref:"):
                    return None, _further("a symbolic record", rel)
                asked.append((rel, path, head, kind, value, like))
        # git answers for each name; the calls run side by side, each with the gate's hardening and its deadline.
        with concurrent.futures.ThreadPoolExecutor(max_workers=_FURTHER_WORKERS) as pool:
            answers = list(pool.map(lambda item: _resolution(repo, item[0], deadline), asked))
        found: dict[str, str] = {}
        for (rel, path, head, kind, value, like), (answer, oid, full) in zip(asked, answers):
            if answer == "warning":
                return None, _further(f"git warns while it resolves the name: {oid}", rel)
            if answer == "unknown":
                return None, _further("an answer of git the gate cannot read", rel)
            if answer in ("none", "broken"):
                if rel == _BISECT_START and kind == "off" and not like:
                    branch = _git_text(head[:-1]) if head.endswith(b"\n") and head.count(b"\n") == 1 else ""
                    if not (branch and f"refs/heads/{branch}" in present and f"refs/heads/{branch}" not in symbolic):
                        return None, _further("BISECT_START in a form the gate does not read", rel)
                elif like:
                    return None, _further("a record form git does not resolve", rel)
            elif full == rel:
                if rel in _REWRITTEN:
                    listed, why = _rewritten(rel, path, head, oid)
                    if listed is None:
                        return None, why
                    found.update(listed)
                elif kind != "object":
                    return None, _further("a record not of the form <object>LF", rel)
                elif value != oid:
                    return None, _further("a record git resolves to another object than the file holds", rel)
                else:
                    found[rel] = oid
            elif full in present and present[full] == oid:
                if like:   # a file that reads as a record, and git resolved another ref by its name
                    return None, _further("a record form git does not resolve", rel)
            else:
                return None, _further("an answer of git the gate cannot read", rel)
            try:
                if _read_regular(path, _FURTHER_HEAD + 1) != head:
                    return None, _further("a file that changed while the gate read it", rel)
            except _NotRegular:
                return None, _further("an entry that is no regular file", rel)
    except OSError:
        return None, ("the git directory cannot be read whole, so a record of the destination may be unread")
    return found, ""


#: What a line of FETCH_HEAD in another form is called (narrow contract, point 5).
_FETCH_FORM = "a line of FETCH_HEAD not of the form <object>TAB[not-for-merge]TAB<note>LF"
#: The names in the environment that move git's view of the repository away from the work tree the call names
#: (external design review of 2026-10-13 at 101bd167); within one ordinary main worktree none is needed.
_CONTEXT_NAMES = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR")


def _narrow_range(repo: str, deadline: float) -> str | None:
    """None where the repository lies in the range the exception covers (owner choice of 2026-10-13, 17:0x Berlin, A
    and A, the narrow contract, point 1), else why not: exactly one ordinary main worktree, its .git a folder of its own
    that is git's directory for it, no linked worktree and no entry at all under <git directory>/worktrees, which is
    read itself and not counted from `git worktree list`, and no inherited GIT_DIR, GIT_WORK_TREE or GIT_COMMON_DIR,
    which move git's view of the repository. More worktrees lie outside on purpose; they are asked."""
    named = [name for name in _CONTEXT_NAMES if os.environ.get(name) is not None]
    if named:
        return _outside("the environment sets a name that moves git's view of the repository", named[0])
    paths, why = _repo_paths(repo, deadline)
    if paths is None or not paths["common"] or not paths["gitdir"]:
        return why or "git does not name the repository's directories, so its worktrees are not known"
    if os.path.realpath(paths["gitdir"]) != os.path.realpath(paths["common"]):
        return _outside("a linked worktree", str(repo))
    dot_git = os.path.join(str(repo), ".git")
    if (not _no_link(dot_git) or not os.path.isdir(dot_git)
            or os.path.realpath(dot_git) != os.path.realpath(paths["gitdir"])):
        return _outside("a .git that is not the worktree's own folder of the repository", dot_git)
    folder = os.path.join(paths["common"], "worktrees")
    if not _no_link(folder):
        return _outside("a symbolic link", "worktrees")
    try:
        entries = sorted(os.listdir(folder))
    except FileNotFoundError:
        entries = []
    except OSError:
        return _outside("an entry the gate cannot read", "worktrees")
    if entries:
        return _outside("a further worktree", f"worktrees/{entries[0]}")
    return None


#: The most tags the gate peels one after another to reach the object a ref names at last.
MAX_TAG_DEPTH = 16


def _ref_trees(repo: str, refs: dict[str, str],
               deadline: float) -> tuple[dict[str, tuple[str, str]], tuple[str, str] | None]:
    """The root tree each ref's object names once its tags are peeled, as {ref: (object, tree)}: a commit gives its tree,
    a tree is its own; a blob holds no path and gives none. The second value is (ref, "object") for the first ref whose
    object git does not give, (ref, "depth") for the first whose chain of tags is longer than MAX_TAG_DEPTH, else None.
    MAX_TAG_DEPTH is the gate's own limit; git peels a longer chain (measured with git 2.43.0: 17 tags), so the reason
    for that one names the gate's limit and not git (review round 15 of 2026-10-13, the class of R15-2)."""
    found: dict[str, tuple[str, str]] = {}
    pending = dict(refs)
    for _depth in range(MAX_TAG_DEPTH + 1):
        if not pending:
            return found, None
        objects = _objects(repo, sorted(set(pending.values())), deadline)
        later = {}
        for ref, oid in sorted(pending.items()):
            read = objects.get(oid)
            first = read[1].split(b"\n", 1)[0] if read is not None else b""
            if read is not None and read[0] == b"commit" and first.startswith(b"tree "):
                found[ref] = (oid, first[len(b"tree "):].decode("ascii", "replace"))
            elif read is not None and read[0] == b"tree":
                found[ref] = (oid, oid)
            elif read is not None and read[0] == b"tag" and first.startswith(b"object "):
                later[ref] = first[len(b"object "):].decode("ascii", "replace")
            elif read is None or read[0] != b"blob":
                return found, (ref, "object")
        pending = later
    return found, (min(pending), "depth") if pending else None


def _destination_records(repo: str, remote: str | None, values: list[str], deadline: float,
                         reading: dict | None = None) -> tuple[list[tuple[str, str, str]] | None, str | None]:
    """Every local ref that records a remote ref git push may write for one of `values`, as (local ref, remote ref,
    commit), or (None, why) where a record cannot be read. The remote refs are the candidates of each value
    (_dest_candidates), since the gate does not know which one git writes; the records are the local refs each
    remote's fetch rules map a candidate to, and refs/remotes/<remote>/<branch> for a branch candidate, for every
    configured remote. A dangling or broken ref is no missing one; a missing record says nothing about the remote.
    Where `reading` is a dict, this inventory's present refs, broken refs and HEAD binding are kept in it under
    "present", "broken" and "head", so the caller compares them with its own inventories instead of dropping what this
    one read after its form checks (review round 18 of 2026-10-14, the class of R18-1)."""
    remotes = _remote_names(repo, deadline)
    rules = _fetch_rules(repo, deadline)
    if remotes is None or rules is None:
        return None, ("git cannot read the remotes or their fetch rules, so the local records of the destination are "
                      "not known")
    # Every configured remote's records, for a named remote as for a URL or a path: git does not say which remotes name
    # the endpoint a push goes to, and a second remote of the same repository keeps its own records (review round 11 of
    # 2026-10-12, the class of R11-3: a remote naming `remote.git` as `remote`, which git completes, and one network
    # repository spelt as https and scp form had been told apart as written).
    chosen = sorted(remotes)
    wanted: dict[str, str] = {}
    for value in values:
        for name, _strong in _dest_candidates(value):
            for each in chosen:
                if name.startswith("refs/heads/"):
                    wanted.setdefault(f"refs/remotes/{each}/{name[len('refs/heads/'):]}", name)
                for negative, src, dst, pattern in rules.get(each, []):
                    if negative or not dst:
                        continue
                    if pattern:
                        local = _refspec_map(src, dst, True, name)
                    elif src in ("", "HEAD", name) or any(name == known for known, _s in _dest_candidates(src)):
                        local = _local_ref(dst, False)
                    else:
                        local = None
                    if local is not None:
                        wanted.setdefault(local, name)
    present, broken = _present_refs(repo, deadline, None if reading is None else reading.setdefault("head", []))
    if present is None:
        return None, broken
    if reading is not None:
        reading["present"], reading["broken"] = present, broken
    records = []
    for local, name in sorted(wanted.items()):
        if local in broken:
            return None, f"the local ref {local}, which may record the ref this push writes, is a broken ref"
        if local not in present:
            continue
        commit = _git(repo, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{present[local]}^{{commit}}",
                      deadline=deadline)
        if commit.returncode != 0 or not commit.stdout.strip():
            return None, (f"the local ref {local}, which may record the ref this push writes, names no commit this "
                          "repository holds")
        records.append((local, name, commit.stdout.decode().strip()))
    return records, None


def _head_binding(repo: str, head: str, deadline: float) -> tuple[tuple[str, str, str] | None, str]:
    """HEAD as the gate checked it (review round 18 of 2026-10-14, R18-1): ("symbolic", <ref>, <object>) where git names
    a ref for HEAD, ("object", <object>, <object>) for a detached HEAD, the object being `head`, the commit condition b
    read; (None, why) where git gives no answer the gate can read."""
    named = _git(repo, "symbolic-ref", "--quiet", "HEAD", deadline=deadline)
    if named.returncode == 0:
        lines = _git_lines(named.stdout)
        if lines is None or len(lines) != 1 or not lines[0]:
            return None, "git names HEAD's ref in a form the gate cannot read"
        return ("symbolic", lines[0], head), ""
    if named.returncode == 1 and not named.stdout:
        return ("object", head, head), ""
    return None, "git does not say whether HEAD names a ref"


def _head_read_problem(read: list, checked: tuple[str, str, str]) -> str | None:
    """Why HEAD as one inventory read it does not fit the HEAD the gate checked, or None (R18-1): a read value is never
    dropped after its form check, and a contradiction leaves no finished measurement of absence."""
    if len(read) != 1:
        return ("the gate did not read HEAD exactly once in its inventory, so its reading is no finished measurement "
                "that nothing is declared")
    kind, value, obj = read[0]
    if (kind, value, obj) == checked:
        return None
    shown = f"ref: {value} at {obj[:12]}" if kind == "symbolic" else obj[:12]
    known = f"ref: {checked[1]} at {checked[2][:12]}" if checked[0] == "symbolic" else checked[2][:12]
    return (f"HEAD named {shown} when the gate read the local refs, not {known}, the HEAD it checked, so HEAD changed "
            "while the gate read it and its reading is no finished measurement that nothing is declared")


def _local_inactivity(repo: str, head: str, push_args: list[str] | None, sources: list[str] | None,
                      deadline: float) -> tuple[Verdict | None, str | None]:
    """Owner choice 1 A of 2026-10-11 (D5 C of 2026-09-30): a repository that declares nothing stays outside Level 1.
    This is local inactivity, never a pass and never a check presumed at Level 2: the host's normal approval decides,
    and the push's destination stays NOT MEASURED. It holds only where (a) the repository, its work tree, the git
    environment (_work_tree) and every source of a `git push` are determined, no unresolved source is replaced by HEAD,
    and no configuration adds ref updates or a submodule push the command does not name; (b) nothing stands at
    DECLARATION, or in place of its folder, at HEAD, in the working tree and at every commit the push may send; (c)
    those commits are the whole history of every source, with no tracking ref subtracted, read whole and within
    MAX_HISTORY_COMMITS; (d) no local record of a remote ref the push may write holds anything there, every such record
    is readable, and a missing one is no evidence about the remote. Returns (the inactive verdict, None), or (None, why
    the exception does not apply), with why None where HEAD itself declares, so the repository is not one without a
    declaration. A ref git refuses or a hook-disabling form never reaches this (_evaluate_call, _judge)."""
    try:
        heads = _commit_trees(repo, [head], deadline, walk=False)
        if heads is None:
            return None, "git could not list the tree of HEAD"
        checked, why = _head_binding(repo, head, deadline)
        if checked is None:
            return None, why
        if _declaration_at(repo, heads, deadline)[0] != "absent":
            return None, None
        if _working_tree_declares(repo):
            return None, (f"the working tree holds something at {DECLARATION} or in place of its folder, or the gate "
                          "cannot tell that it does not")
        if push_args is None:
            return None, "a gh call sends through steps of its own, and the exception covers a `git push` only"
        if sources is None:
            return None, "the commits the push sends are not all determined"
        remote, refspecs, options, unmodeled = _push_words(push_args)
        if unmodeled is not None:
            return None, f"the option {unmodeled} is not one the gate models"
        remotes = _remote_names(repo, deadline)
        if remotes is None:
            return None, "git cannot list the remotes"
        values: list[str | None] = []
        if refspecs:
            for spec in refspecs:
                src, sep, dst = (spec[1:] if spec.startswith("+") else spec).partition(":")
                values.append((dst or None) if sep else _source_full_name(repo, src, deadline))
        else:
            chosen = _default_push(repo, deadline, remotes, remote)
            if chosen is None:
                return None, "git pushes no single branch for this push"
            remote, dest = chosen
            values.append(dest)
        problem = _push_config_problem(repo, deadline, options)
        if problem is not None:
            return None, problem.rstrip(".")
        if remote is None or _push_adds_unnamed_refs(repo, remote, deadline):
            return None, ("the configuration adds ref updates the command does not name (remote.<name>.push, "
                          "remote.<name>.mirror or push.followTags)")
        # Condition d reads the records of the ref the push writes. Under a namespace git writes another ref, and a
        # push URL other than the fetch URL writes to an endpoint whose records are not origin's: neither is modelled
        # here, so the exception does not apply (review round 11 of 2026-10-12, R11-3).
        if _git_namespace() is not None:
            return None, (f"GIT_NAMESPACE={_git_namespace()} makes git write the push under refs/namespaces/ on the "
                          "remote, and the local records of such a ref are not modelled here")
        if _legacy_remote(repo, remote, deadline):
            return None, (f"git takes the remote {remote} from its older remote files (.git/remotes/ or "
                          ".git/branches/), whose URLs and pushed refs the gate does not read")
        if remote in remotes and not _endpoint_consistent(repo, remote, deadline):
            return None, (f"the push of remote {remote} goes to another endpoint than the one its local records come "
                          "from (a pushurl, a further URL or a URL rewrite), and the records of that endpoint are not "
                          "modelled here")
        shallow = _git(repo, "rev-parse", "--is-shallow-repository", deadline=deadline)
        if shallow.returncode != 0 or shallow.stdout.decode().strip() != "false":
            return None, ("the repository is shallow, or git does not say that it is not, so the history the push may "
                          "send is not whole here")
        history = _commit_trees(repo, list(dict.fromkeys(sources)), deadline, walk=True)
        if history is None:
            return None, "git could not list the history the push may send"
        if len(history) > MAX_HISTORY_COMMITS:
            return None, (f"the history the push may send holds more than {MAX_HISTORY_COMMITS} commits, more than the "
                          "gate reads")
        state, at = _declaration_at(repo, history, deadline)
        if state == "present":
            return None, (f"something stands at {DECLARATION} or in place of its folder at {at[:12]}, a commit the "
                          "push may send")
        if state == "unread":
            return None, f"git does not give the whole tree of {at[:12]}, a commit the push may send"
        if any(value is None for value in values):
            return None, ("which ref the push writes on the remote cannot be named here, so its local records cannot "
                          "be read")
        # Condition d holds only within the narrow contract (owner choice of 2026-10-13, 17:0x Berlin, A and A).
        why = _narrow_range(repo, deadline)
        if why is not None:
            return None, why
        first: dict = {}
        records, why = _destination_records(repo, remote, [v for v in values if v is not None], deadline, first)
        if records is None:
            return None, why
        why = _head_read_problem(first["head"], checked)   # the class of R18-1: the first inventory read HEAD too
        if why is not None:
            return None, why
        record_trees =_commit_trees(repo, list(dict.fromkeys(c for _l, _n, c in records)), deadline, walk=False)
        if record_trees is None:
            return None, "git could not list the commits of the destination's local records"
        state, at = _declaration_at(repo, record_trees, deadline)
        if state != "absent":
            # The ask names the record and leaves its relation to the actual destination open: a record of another remote
            # may be relevant, it is not shown to be one of the destination (owner choice of 2026-10-13).
            local = next(local for local, _name, commit in records if commit == at)
            return None, (f"the local ref {local} holds something at {DECLARATION} or in place of its folder at "
                          f"{at[:12]}; {_NOT_ESTABLISHED}" if state == "present" else
                          f"git does not give the whole tree of {at[:12]}, the commit of the local ref {local}, which "
                          "may record the ref this push writes")
        # Every present ref, not only those today's fetch rules name: a tag git followed, the refs of a remote whose
        # configuration is gone, of an earlier fetch rule or of a one-time fetch into a branch record the destination
        # as well, and which present ref did is not determinable here (review round 12 of 2026-10-13, R12-1).
        read_head: list = []
        present, broken = _present_refs(repo, deadline, read_head)
        if present is None:
            return None, broken
        why = _head_read_problem(read_head, checked)
        if why is not None:
            return None, why
        if broken:
            return None, f"the local ref {min(broken)} is a broken ref, and it may record the ref this push writes"
        if len(present) > MAX_HISTORY_COMMITS:
            return None, (f"this repository holds more than {MAX_HISTORY_COMMITS} refs, more than the gate reads, and "
                          "any of them may record the ref this push writes")
        ref_trees, unread = _ref_trees(repo, present, deadline)
        if unread is not None and unread[1] == "depth":
            return None, (f"the local ref {unread[0]} names a chain of more than {MAX_TAG_DEPTH} tags, more than the "
                          "gate peels, and it may record the ref this push writes")
        if unread is not None:
            return None, (f"the local ref {unread[0]} names an object git does not give here, and it may record the "
                          "ref this push writes")
        state, at = _declaration_at(repo, list(dict.fromkeys(ref_trees.values())), deadline)
        if state != "absent":
            local = min(ref for ref, (oid, _tree) in ref_trees.items() if oid == at)
            return None, (f"the local ref {local} holds something at {DECLARATION} or in place of its folder at "
                          f"{at[:12]}; {_NOT_ESTABLISHED}" if state == "present" else
                          f"git does not give the whole tree of {at[:12]}, the object of the local ref {local}, which "
                          "may record the ref this push writes")
        # A change between the reading of the refs and the reading of their objects leaves no finished measurement of
        # absence (narrow contract, point 7).
        read_head = []
        again, why = _present_refs(repo, deadline, read_head)
        if again is None:
            return None, why
        head_why = _head_read_problem(read_head, checked)
        if head_why is not None:
            return None, head_why
        # The first inventory is one of these readings: what it read and kept only in part is compared, not dropped
        # (the class of R18-1, a ref or record that named a declared commit in it alone had been passed over).
        if again != present or why != broken or first["present"] != present or first["broken"] != broken:
            return None, ("the local refs changed while the gate read them, so its reading is no finished measurement "
                          "that nothing is declared")
    except GateError as exc:
        return None, f"the gate could not finish its reading ({exc})"
    tips = ", ".join(c[:12] for c in dict.fromkeys(sources)) or "none, the push only deletes"
    found = ("; of them, today's fetch rules map the destination to " + ", ".join(f"{local} at {commit[:12]}"
                                                                               for local, _name, commit in records)
             if records else "; today's fetch rules map the destination to no present ref, which says nothing about "
                             "the remote")
    text = (f"NOT MEASURED: the gate checks nothing here. {repo} declares no evidence: nothing stands at {DECLARATION} "
            f"at HEAD {head[:12]}, in the working tree, at the {len(history)} commit(s) the push may send (the whole "
            f"history of {tips}) or at any of the {len(present)} local refs of this repository (git's listing, "
            "FETCH_HEAD line by line, the other root refs of its one worktree, and every further file of its git "
            "directory whose exact name git resolves, valid reflogs left outside), each read since which "
            f"of them recorded the destination is not determinable here{found}. The gate is not active in this "
            "repository, because nothing is declared. This is local inactivity (owner choice 1 A of 2026-10-11, "
            "DECISIONS.md D5), not a check and not a pass, and the host's normal approval decides. The push's "
            "destination and its current state remain NOT MEASURED; a declaration that only the remote holds is not "
            "seen here.")
    return Verdict("inactive", text, "nothing_declared_locally", repo=repo, head=head), None


# --- one tree ----------------------------------------------------------------------------------------

def _evaluate_tree(repo: str, commit: str, deadline: float, where: str, pass_tail: str) -> Verdict:
    """The verdict of _evaluate_tree_reading. Where it raises, of any kind, the exception names the commit and the
    evidence and policy files read there before it stopped (R11-5, R12-2); a file whose reading failed is not among
    them."""
    digests: list[str] = []
    try:
        return _evaluate_tree_reading(repo, commit, deadline, where, pass_tail, digests)
    except Exception as exc:
        if getattr(exc, "head", None) is None:
            check = "not completed: gate_error" if isinstance(exc, GateError) else "not completed: internal_error"
            try:
                exc.head, exc.digests = commit, tuple(digests)
                exc.reads = (*getattr(exc, "reads", ()), *_read_entries(commit, digests, check))
            except AttributeError:   # an exception whose instances take no attributes keeps no record
                pass
        raise


def _keep_reads(exc: BaseException, reads: list, head: str | None = None) -> None:
    """Hand an exception of any kind, once, the record of the evidence a push's check read before it stopped: the
    earlier reads before those it carries, the commit where it stopped where it names none, and the digests read there
    where it names none (owner choice 3 A; review round 12 of 2026-10-13, R12-2: a failure after the source check, in
    the done check or outside the gate's own errors, had left the log with no record, no commit and no digest)."""
    if getattr(exc, "reads_whole", False):
        return
    try:
        exc.reads = (*reads, *getattr(exc, "reads", ()))
        exc.reads_whole = True
        if getattr(exc, "head", None) is None:
            exc.head = head
        if exc.head is not None and not getattr(exc, "digests", ()):
            exc.digests = tuple(f"{e['path']} sha256:{e['sha256']}" for e in exc.reads if e["commit"] == exc.head)
    except AttributeError:   # an exception whose instances take no attributes keeps no record
        pass


def _evaluate_tree_reading(repo: str, commit: str, deadline: float, where: str, pass_tail: str,
                           digests: list[str]) -> Verdict:
    """The verdict for the evidence a single commit's tree declares: pass, inactive, ask (empty list) or
    deny. No working-tree read and no range comparison; `where` names the commit in every message and
    `pass_tail` is appended to a pass. parse_declaration and the evidence-file _blob reads raise GateError,
    which the caller turns into a deny, so a tree whose evidence cannot be read is never silently treated as
    declaring nothing. The DECLARATION read is the one exception: a declaration the gate cannot read at the commit
    (over the read limit, in a tree git does not give whole, a commit this repository does not hold) is a NOT
    MEASURED ask that names the cause, never an absence and never an uncommitted declaration (review Runde 5, R5-1;
    review round 12 of 2026-10-13, B-12: a committed declaration over the limit had been answered as absent and not
    committed). Only a MEASURED absence (git lists the path empty with exit 0, in a tree read whole) returns
    'inactive' here, and the caller's absence nuance (D5) tells it from a declaration only in the working tree."""
    try:
        raw = _blob(repo, commit, DECLARATION, deadline, MAX_DECLARATION_BYTES)
    except GateError as exc:
        return Verdict("ask", f"NOT MEASURED: the gate could not read {DECLARATION} at {where}: {exc}. Nothing was "
                              "verified.", "declaration_unread",
                       evidence=f"the declaration {DECLARATION} at {where}", failed=f"the gate could not read it ({exc})",
                       next_step=f"make {DECLARATION} at the commit a file of at most {MAX_DECLARATION_BYTES} bytes in "
                                 "a tree git gives whole in this repository, or fetch the commit in full, then retry",
                       repo=repo, head=commit)
    if raw is None:
        return Verdict("inactive", f"NOT MEASURED: no evidence is declared at {where} ({DECLARATION} is absent).",
                       "nothing_declared", repo=repo, head=commit)
    items = parse_declaration(raw)
    if not items and parse_done(raw) is not None:
        return Verdict("inactive", f"NOT MEASURED: {DECLARATION} at {where} declares no evidence for this call, "
                                   "only a done check for the end of a session (DECISIONS.md, D26).",
                       "done_only", repo=repo, head=commit)
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
    requests, contents = [], []   # `digests` receives each evidence and policy file as it is read
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
    repo, unreadable = _work_tree(directory, deadline)
    if unreadable:
        return Verdict("ask", f"NOT MEASURED: {unreadable}, so no evidence was checked.", "not_a_work_tree",
                       evidence=f"none, {unreadable}", failed="the gate cannot name the repository to check",
                       next_step="run the call inside the repository it acts on, or confirm it yourself",
                       repo=directory)
    if repo is None:
        return Verdict("ask", f"NOT MEASURED: {directory} is not inside a git work tree, so no evidence was checked.",
                       "not_a_work_tree", evidence=f"none, {directory} is not inside a git work tree",
                       failed="there is no repository to check",
                       next_step="run the call inside the repository it acts on, or confirm it yourself",
                       repo=directory)
    head = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", deadline=deadline)
    if head.returncode != 0:
        return Verdict("ask", f"NOT MEASURED: {repo} has no commit at HEAD, so no evidence was checked.",
                       "no_commit", evidence=f"the declaration {DECLARATION}", failed="the repository has no commit",
                       next_step="commit first, then retry", repo=repo)
    commit = head.stdout.decode().strip()
    verdict = _evaluate_tree(repo, commit, deadline, f"HEAD {commit[:12]}",
                             " The evidence rules were not compared with any earlier state.")
    if verdict.decision == "inactive" and verdict.reason_id == "done_only":
        # The declaration is committed and declares only a done check (D26): no evidence, and nothing absent, so
        # the absence nuance of D5 does not apply (it would read the committed declaration as uncommitted).
        return Verdict("inactive", f"NOT MEASURED: {repo} declares no evidence at HEAD {commit[:12]}: {DECLARATION} "
                                   "declares only a done check for the end of a session (DECISIONS.md, D26). Nothing "
                                   "was verified.", "done_only", repo=repo, head=commit)
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

def evaluate_push(directory: str, push_args: list[str] | None, deadline: float,
                  environ: dict | None = None, plain_push: bool = False) -> Verdict:
    """The Level 1 verdict for a `git push` (push_args) or a `gh pr/release create` (push_args None, the current
    branch to its upstream). Since review round 9 of 2026-10-11 (R9-1) every push whose earlier steps resolve ends
    NOT MEASURED at the destination check, because git resolves the destination against refs of the remote the gate
    does not read, and no fetch rule changes that. The evidence at the commits the push sends (the uniquely
    determined source commits) is still checked: an evidenced failure there is a deny, and otherwise the answer is
    an ask that says what was checked. The comparison with the destination's state, and the range of newly sent
    commits, are Level 2's (pre_push_verdict), on git's own ref lines (review round 10, R10-5).

    The one place Level 1 hands a push over to Level 2 (owner adoption of review round 18, DECISIONS.md D33) is here,
    after every check above: only where the one reason left open is the default destination case, the source evidence
    is valid, the transport is approved, a bound Level 2 is installed and the command is the plain push form
    (`plain_push`, _codex_plain_push) (_handover_offer). Then the verdict is
    `handover`, which carries no permission decision; otherwise the answer is the ask it was, naming why."""
    repo, unreadable = _work_tree(directory, deadline)
    if unreadable:
        return Verdict("ask", f"NOT MEASURED: {unreadable}, so no evidence was checked.", "not_a_work_tree",
                       evidence=f"none, {unreadable}", failed="the gate cannot name the repository to check",
                       next_step="run the call inside the repository it acts on, or confirm it yourself",
                       repo=directory)
    if repo is None:
        return Verdict("ask", f"NOT MEASURED: {directory} is not inside a git work tree, so no evidence was checked.",
                       "not_a_work_tree", evidence=f"none, {directory} is not inside a git work tree",
                       failed="there is no repository to check",
                       next_step="run the call inside the repository it acts on, or confirm it yourself",
                       repo=directory)
    head = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", deadline=deadline)
    if head.returncode != 0:
        return Verdict("ask", f"NOT MEASURED: {repo} has no commit at HEAD, so no evidence was checked.",
                       "no_commit", evidence=f"the declaration {DECLARATION}", failed="the repository has no commit",
                       next_step="commit first, then retry", repo=repo)
    head_commit = head.stdout.decode().strip()
    reasons: list = []
    handover = {"targets": [], "remote": None} if push_args is not None else None
    targets = resolve_push_targets(repo, push_args, deadline, reasons, handover)
    if targets is None:
        found, next_step = reasons[0] if reasons else (None, None)
        try:
            sources, remote = _push_sources(repo, push_args, deadline)
            rewrites = (_applicable_rewrites(repo, remote, deadline)
                        if remote is not None and remote in (_remote_names(repo, deadline) or ()) else [])
        except GateError:
            sources, rewrites = None, []
        if found is None and sources is None:
            try:   # owner choice 2 A: the destination's reason is found apart from the source's
                found = _destination_reason(repo, push_args, deadline)
            except GateError:
                found = None
        why = found or ("the remote, a refspec, or the push configuration names updates the gate cannot map to a "
                        "locally tracked target (a URL or path remote, --all/--mirror/--tags, a wildcard refspec, a "
                        "configured remote push list, or a branch this repository does not track)")
        if _git_namespace() is not None:
            why = _then(why, f"GIT_NAMESPACE={_git_namespace()} makes git write the push under refs/namespaces/ on "
                             "the remote, a ref no tracking ref of this repository records")
        if rewrites:
            why = _then(why, "a URL rewrite applies to this remote (" + "; ".join(rewrites) + "), and equal "
                             "effective fetch and push URLs do not prove where the existing tracking ref came from")
        if sources is None:
            # Owner choice 2 A of 2026-10-11: both reasons, the source's first, each found on its own; no commit is
            # checked in place of the unresolved source.
            _none, note = _local_inactivity(repo, head_commit, push_args, None, deadline)
            try:
                source_why = _source_reason(repo, push_args, deadline)
            except GateError:
                source_why = "the gate cannot name the commits this push sends"
            told = _then(source_why, "the gate cannot tell which commits the push sends, so it checked no evidence, "
                                     "and no check of HEAD stands in for that")
            return _unresolved_verdict(repo, head_commit, _with_note(_then(told, f"for the destination, {why}"), note),
                                       next_step)
        reads: list = []
        outcomes: dict = {}
        try:   # R12-2: a failure of any kind after the source check keeps its record
            denial = _source_denial(repo, head_commit, sources, deadline, why, reads, outcomes)
            if denial is not None:
                return denial
            local, note = _local_inactivity(repo, head_commit, push_args, sources, deadline)
            if local is not None:
                return local   # owner choice 1 A: a repository that declares nothing, local inactivity and no check
            told = _with_note(_then(why, _sources_clean(sources)), note)
            try:
                hints = _rules_hints(repo, push_args, deadline) if note is None else []
            except GateError as exc:
                hints = [f"The evidence rules were not compared with a local record of the destination ({exc}); a "
                         "comparison that was not made is no equality."]
            if hints:
                told = f"{told.rstrip('.')}. " + " ".join(hints)
            # D33: the one place Level 1 hands a push over. Where it does not, the ask says why.
            offer, missing_level2 = _handover_offer(repo, head_commit, push_args, handover, sources, outcomes, hints,
                                                    note, reads, deadline, environ, plain_push)
            if isinstance(offer, Verdict):
                return offer
            if offer is not None:
                told = f"{told.rstrip('.')}. No hand-over to Level 2 (DECISIONS.md D33): {offer.rstrip('.')}."
            if missing_level2:   # answer 5 of review round 18: named as a voluntary step, never installed here
                next_step = (f"{(next_step or 'have a person review the push').rstrip('.')}; or, if you want such a push "
                             "to need no question, install Level 2 in this repository yourself with "
                             f"`{_shell_command('python3', os.path.realpath(__file__), 'install-pre-push', '--repo', repo)}`"
                             " (optional, D24B; the gate installs nothing)")
            return _unresolved_verdict(repo, head_commit, told, next_step, reads=tuple(reads))
        except Exception as exc:
            _keep_reads(exc, reads, head_commit)
            raise
    return _evaluate_targets(repo, head_commit, targets, deadline)


def _source_reason(repo: str, args: list[str] | None, deadline: float) -> str:
    """Why the commits a push sends are not determined (_push_sources named none), found apart from its destination
    (owner choice 2 A of 2026-10-11). A source that matches two strong refs here is named as one git push refuses
    (measured with git 2.43.0 and 2.51.1: a branch and a tag `main`, "src refspec main matches more than one"); a
    source that answers to a strong and a weak ref is named as not determined, never as a refusal (measured: beside
    refs/remotes/main/HEAD git pushed refs/heads/main with exit 0, while rev-parse warned that `main` is ambiguous)."""
    remote, refspecs, _options, unmodeled = _push_words(args or [])
    if unmodeled is not None:
        return f"the option {unmodeled} is not one the gate models as naming no further ref, commit or receiver"
    for spec in refspecs:
        bare = spec[1:] if spec.startswith("+") else spec
        if "*" in bare or bare.startswith("^"):
            return f"the refspec {spec} is a pattern or a negative refspec, which names no single source"
        src = bare.partition(":")[0]
        if src and _push_source(repo, src, deadline) is None:
            found = [(name, strong) for name, strong in _dest_candidates(src)
                     if _git(repo, "show-ref", "--verify", "--quiet", name, deadline=deadline).returncode == 0]
            strong = [name for name, is_strong in found if is_strong]
            if len(strong) > 1:
                return (f"the source {src} matches {', '.join(strong)} in this repository, and git push refuses a "
                        "source that matches more than one ref")
            if len(found) > 1:
                return (f"the source {src} answers to {', '.join(name for name, _s in found)} in this repository by "
                        "git's rules, and which of them git push takes is not determined here")
            return f"git names no single commit for the source {src} here"
    if not refspecs:
        if _git(repo, "symbolic-ref", "--quiet", "HEAD", deadline=deadline).returncode != 0:
            return "HEAD is detached, so a push that names no refspec names no branch"
        return ("git pushes no single branch from the current branch for this push (push.default, the remote's push "
                "list or the branch's upstream)")
    return "the gate cannot name the commits this push sends"


def _destination_reason(repo: str, args: list[str] | None, deadline: float) -> str | None:
    """Why git push's resolution of the destination is not evidenced, found apart from the source (owner choice 2 A
    of 2026-10-11), for the first refspec or the branch a push without one sends; None where no destination can be
    named. A destination whose value rests on an undetermined source is named as not known, and no reason claims that
    the remote holds a second match (_dest_resolution_problem)."""
    remote, refspecs, _options, unmodeled = _push_words(args or [])
    if unmodeled is not None or remote is None:
        return None
    if refspecs:
        bare = refspecs[0][1:] if refspecs[0].startswith("+") else refspecs[0]
        if "*" in bare or bare.startswith("^"):
            return None
        src, sep, dst = bare.partition(":")
        value = (dst or None) if sep else _source_full_name(repo, src, deadline)
        if value is None:
            return (f"which ref the push writes on the remote for {bare} is not known: a refspec without `:` writes "
                    "the full name of its source, which is not determined here, and the gate does not read the remote "
                    "(D3)") if not sep else None
    else:
        remotes = _remote_names(repo, deadline)
        chosen = None if remotes is None else _default_push(repo, deadline, remotes, remote)
        if chosen is None:
            return None
        remote, value = chosen
    dest = _qualify_dest(value)
    if dest is None:
        return f"the destination {value} is not a literal branch or tag the gate resolves"
    problem = _dest_resolution_problem(repo, remote, value, dest, deadline)
    return None if problem is None else problem[0]


def _rules_hint_difference(record: tuple, source: tuple) -> str:
    """What differs between the evidence rules at a local record and at a source commit, without saying that a push
    changes them (owner choice 4 A of 2026-10-11: "the push changes the evidence rules" is too strong for a hint)."""
    if record[0] != source[0]:
        return f"the declaration is {source[0]} at the source commit and {record[0]} at the local ref"
    if source[0] != "declared":
        return "the declaration differs"
    parts = []
    if record[1] != source[1]:
        parts.append("the declared items differ (kind, path, policy or public_key)")
    before, after = dict(record[2]), dict(source[2])
    parts += [f"the policy {path} differs" for path in sorted(set(before) | set(after))
              if before.get(path) != after.get(path)]
    if record[3] != source[3]:
        if not record[3] or not source[3]:
            parts.append(f"a done check is declared at the {'source commit' if source[3] else 'local ref'} only")
        elif record[3][0] != source[3][0]:
            parts.append("the done check differs (its policy, checks, receipts, paths or max_blocks)")
        else:
            parts.append(f"the done policy {source[3][0][0]} differs")
    return "; ".join(parts)


def _rules_hints(repo: str, args: list[str] | None, deadline: float) -> list[str]:
    """Owner choice 4 A of 2026-10-11: Level 1 names a difference of the evidence rules (_rules_at, the done check
    included; a subject or a receipt is no rule) between a source commit of the push and a local record of its
    destination, as a hint and never as a verdict. Each hint names the source commit, the record and its commit, and
    the two trees read; a record of another candidate than the destination itself, or one of several records, is named
    a locally recorded candidate ref. Only the two tips are compared, no commit between them. A comparison that could
    not be made, because a side is unreadable or no record exists, is named and is no equality. A refspec that only
    deletes, or whose source or destination cannot be named, gets no hint."""
    remote, refspecs, _options, unmodeled = _push_words(args or [])
    if unmodeled is not None or remote is None and refspecs:
        return []
    pairs: list[tuple[str, str]] = []
    if refspecs:
        for spec in refspecs:
            src, sep, dst = (spec[1:] if spec.startswith("+") else spec).partition(":")
            commit = _push_source(repo, src, deadline) if src else None
            value = (dst or None) if sep else _source_full_name(repo, src, deadline)
            if commit is not None and value is not None:
                pairs.append((commit, value))
    else:
        remotes = _remote_names(repo, deadline)
        chosen = None if remotes is None else _default_push(repo, deadline, remotes, remote)
        head = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", deadline=deadline)
        if chosen is None or head.returncode != 0:
            return []
        remote, value = chosen
        pairs.append((head.stdout.decode().strip(), value))
    hints = []
    for source, value in pairs:
        records, why = _destination_records(repo, remote, [value], deadline)
        if records is None:
            hints.append(f"The evidence rules at source commit {source[:12]} were not compared with a local record of "
                         f"{value}: {why}; a comparison that was not made is no equality.")
            continue
        if not records:
            # Today's fetch rules name these records; a present ref they do not map, such as a tag git followed, may
            # record the destination too, so no absence of records is claimed (the class of R12-1, 2026-10-13).
            hints.append(f"Today's fetch rules map {value} to no present ref, so the evidence rules at source commit "
                         f"{source[:12]} were compared with none; that is no equality.")
            continue
        dest = _qualify_dest(value)
        unclear = len(records) > 1 or any(name != dest for _local, name, _commit in records)
        trees = dict(_commit_trees(repo, list(dict.fromkeys([source, *(c for _l, _n, c in records)])), deadline,
                                   walk=False) or [])
        source_rules = _rules_at(repo, source, deadline)
        for local, _name, commit in records:
            label = "locally recorded candidate ref" if unclear else "local ref"
            record_rules = _rules_at(repo, commit, deadline)
            if "unreadable" in (source_rules[0], record_rules[0]):
                hints.append(f"The evidence rules at source commit {source[:12]} could not be compared with {label} "
                             f"{local} at {commit[:12]}: git does not give one side whole; a comparison that could not "
                             "be made is no equality.")
            elif source_rules != record_rules:
                hints.append(f"The evidence rules at source commit {source[:12]} differ from {label} {local} at "
                             f"{commit[:12]}. This is a local comparison. The actual push destination and its current "
                             f"state remain NOT MEASURED. (Trees read: {trees.get(source, '?')[:12]} at {source[:12]} "
                             f"and {trees.get(commit, '?')[:12]} at {commit[:12]}; "
                             f"{_rules_hint_difference(record_rules, source_rules)}; only these two tips were "
                             "compared, no commit between them.)")
    return hints


def _with_note(why: str, note: str | None) -> str:
    """`why`, then why owner choice 1 A does not apply where it was asked of a repository that declares nothing."""
    return why if note is None else f"{why.rstrip('.')}. {_LOCAL_EXCEPTION}{note}"


def _evaluate_targets(repo: str, head_commit: str, targets: list, deadline: float,
                      remote_state: bool = False) -> Verdict:
    """The verdict for a resolved set of push targets: the evidence at every commit the push newly sends to
    each target, and whether those commits change the evidence rules against the target's state. Level 1 resolves
    no target since R9-1 (resolve_push_targets returns None for every push), so this core runs for the pre-push hook
    (pre_push_verdict, targets from git's own stdin) with remote_state True, where the comparison state is the
    remote's as git reported it. The branch for remote_state False is not reached from Level 1 any more (review
    round 10 of 2026-10-11, R10-5)."""
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
            return denial if denial is not None else _unresolved_verdict(repo, head_commit or t.source,
                                                                         _then(why, _sources_clean(sent)))

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
            return denial if denial is not None else _unresolved_verdict(repo, head_commit,
                                                                         _then(why, _sources_clean(sent)))
        for commit in [t.source, *reachable]:
            if commit not in order:
                order.append(commit)

    verdicts = {commit: _evaluate_tree(repo, commit, deadline, where(commit), "") for commit in order}
    for commit in order:  # a deny at any sent commit denies the whole push (a valid tip cannot heal it, N3)
        if verdicts[commit].decision == "deny":
            return verdicts[commit]
    # Owner choice N2 C: the done check at each pushed tip. A failed one denies the push before any ask, as a
    # failed evidence check does; its passes are named in the push's pass below.
    done_denial, done_passes = _push_done(repo, [t.source for t in targets if t.source is not None], deadline)
    if done_denial is not None:
        return done_denial
    done_tail = "".join(f" The done check passed at the pushed commit {v.head[:12]}: "
                        f"{v.detail.removeprefix('proofbundle gate: ')}" for v in done_passes)
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
    if not declared:  # every sent commit declares nothing, or only a done check
        done_only = [c for c in order if verdicts[c].reason_id == "done_only"]
        # A sent commit whose committed declaration holds only a done check (D26) declares nothing absent, so the
        # absence nuance of D5 is not asked for it; it would read that declaration as an uncommitted one.
        nuance = (_absence_nuance(repo, head_commit, deadline)
                  if head_commit in order and verdicts[head_commit].reason_id != "done_only" else None)
        if nuance is not None:
            return nuance
        where_all = ", ".join(c[:12] for c in order) or head_commit[:12]
        compared = ("The comparison was against the remote's state of the target as git reported it to the "
                    "pre-push hook." if remote_state else
                    "Any comparison would be against this repository's last known state of the target, not a state "
                    "read from the remote (Ebene 2 makes the authoritative comparison).")
        if done_passes:
            return Verdict("pass", f"proofbundle gate: this push declares no evidence (at {where_all}), only a done "
                                   f"check.{done_tail} {compared}", "done", repo=repo, head=head_commit)
        if done_only:
            return Verdict("inactive", f"NOT MEASURED: this push declares no evidence (at {where_all}; {DECLARATION} "
                                       f"at {', '.join(c[:12] for c in done_only)} declares only a done check for the "
                                       "end of a session, DECISIONS.md D26). Nothing was verified. " + compared,
                           "done_only", repo=repo, head=head_commit)
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
    return Verdict("pass", tip.detail + tail + done_tail, "verified", digests=tip.digests, repo=repo, head=head_commit)


#: All-zero object names git writes for a missing side of a pre-push ref line (SHA-1 and SHA-256 lengths).
_ZERO_OIDS = frozenset({"0" * 40, "0" * 64})


def pre_push_verdict(directory: str, lines: list[tuple], deadline: float, remote: str | None = None,
                     url: str | None = None) -> Verdict:
    """PROTOTYPE Ebene-2 pre-push verdict (DECISIONS.md, D24 — measured in test fixtures only, not installed
    or wired to core.hooksPath outside tests). git hands a pre-push hook, on stdin, one line
    `<local_ref> <local_sha> <remote_ref> <remote_sha>` per ref being pushed, in the repository the push
    runs in. The hook therefore knows the exact commits and the remote's own current state without parsing
    any shell command, so it reaches a verdict where Ebene 1 (the shell grammar) says NOT MEASURED. Each
    line becomes a target: source = the local sha (None when it is all-zero, a deletion), dest = the remote
    ref, tracking = the remote sha (None when the remote has no such ref yet). Then the shared core judges
    the evidence exactly as for a resolved shell push.

    Two modes (D33, answer 6 of review round 18): where the worktree holds a hand-over pointer of Level 1, the
    hand-over is consumed and the push must be the push Level 1 handed over (_handover_mismatch: its age, its binding
    and its whole update set) before the core judges it; without one, Level 2 runs standalone as before and says so.
    `remote` and `url` are the two arguments git gives the hook."""
    repo, unreadable = _work_tree(directory, deadline)
    if repo is None:
        named = unreadable or f"{directory} is not inside a git work tree"
        return Verdict("deny", f"proofbundle gate (pre-push): {named}.", "not_a_work_tree", evidence=f"none, {named}",
                       failed="the pre-push hook cannot name the repository it runs in",
                       next_step="run the hook from the repository")
    head = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", deadline=deadline)
    head_commit = head.stdout.decode().strip() if head.returncode == 0 and head.stdout.strip() else ""
    # The pointer is looked up in the git directory git names as one value, which holds a path whose name carries a
    # line feed; _repo_paths reads three paths line by line and is asked only where a hand-over is present.
    named = _git(repo, "rev-parse", "--absolute-git-dir", deadline=deadline)
    gitdir = _git_value(named.stdout) if named.returncode == 0 else None
    if gitdir is None or not os.path.isabs(gitdir):
        return Verdict("deny", "proofbundle gate (pre-push): git does not name this repository's git directory as one "
                               "absolute path, so whether a hand-over pointer is present is not known. The push is "
                               "denied.", "git_directory_unread", evidence="the git directory of the repository",
                       failed="git does not name the git directory", next_step="have a person review the push",
                       repo=repo, head=head_commit)
    record, refusal, nonce = _take_handover(gitdir)
    if refusal is None and record is not None:
        paths, why = _repo_paths(repo, deadline)
        refusal = (_handover_mismatch(repo, paths, record, remote, url, lines, deadline)
                   if paths is not None and paths["gitdir"] and paths["common"] else
                   f"git does not name the repository's directories ({why or 'no answer'}), so the hand-over cannot be "
                   "compared")
    if refusal is not None:
        return _handover_refused(repo, head_commit or (lines[0][1] if lines else ""), nonce, refusal)
    targets = []
    for local_ref, local_sha, remote_ref, remote_sha in lines:
        dest = remote_ref if remote_ref.startswith(_TRACKABLE) else None
        if dest is None:  # a ref the gate does not model (not a branch or tag): NOT MEASURED
            return _unresolved_verdict(repo, head_commit or local_sha,
                                       f"the pre-push ref {remote_ref} is not a branch or a tag, so the gate checked "
                                       "no evidence")
        source = None if local_sha in _ZERO_OIDS else local_sha
        tracking = None if remote_sha in _ZERO_OIDS else remote_sha
        targets.append(PushTarget(source=source, dest=dest, tracking=tracking, remote_absent=tracking is None))
    if not targets:
        if record is not None:   # a no-op: git ran the hook with no ref line (measured with git 2.34.1)
            return Verdict("inactive", f"NOT MEASURED: the pre-push hook received no ref to push, so it checked nothing "
                                       f"and claims no update. The pointer names hand-over {record['nonce']}, which "
                                       f"names {len(record['updates'])} update(s); git gave a line for none of them. git "
                                       "does that for a no-op, a ref the remote reports at the commit it would send "
                                       "(measured with git 2.34.1); whether that is why was not checked. The hand-over "
                                       "is consumed.", "handover_no_update",
                           repo=repo, head=head_commit)
        return _with_mode(Verdict("inactive", "NOT MEASURED: the pre-push hook received no ref to push.",
                                  "nothing_declared", repo=repo, head=head_commit), None, lines)
    try:
        verdict = _evaluate_targets(repo, head_commit or targets[0].source, targets, deadline, remote_state=True)
    except VerifierCannotStart as exc:
        return _sandbox_verdict(repo, head_commit or targets[0].source, exc)
    return _with_mode(verdict, record, lines)


SANDBOX_REASON = "sandbox_verifier_unavailable"


def _sandbox_verdict(repo: str, commit: str, exc: VerifierCannotStart) -> Verdict:
    """Level 2 where the verifier cannot start for want of a writable cache or of the network (owner choice K02-A C,
    DECISIONS.md D24B): NOT MEASURED with its own reason, the push denied as before (exit 1)."""
    return Verdict("deny", f"NOT MEASURED: the verifier cannot start here, so this push was not checked: {exc.sign}. "
                           "These are the signs of a sandbox without network or without a writable cache. The push "
                           "belongs to a person outside the sandbox; the boundary is the required CI check "
                           f"(D22, D24B). Reason {SANDBOX_REASON}.", SANDBOX_REASON,
                   evidence="the start of the verifier: uv's answer and a probe of the gate's own",
                   failed=exc.sign, next_step="have a person push from outside the sandbox; the required CI check "
                                              "stays the boundary", repo=repo, head=commit)


# --- the hand-over of a push from Level 1 to Level 2 (owner adoption of review round 18, DECISIONS.md D33) ---------
#
# Level 1 does not read the remote (D3), so a push whose only open reason is the default destination case asks. Where a
# person approved the push's transport and a bound Level 2 is installed, Level 1 hands the push over instead: it writes
# the expected order into a one-time record and answers with no permission decision (D4 stays), and git's pre-push hook
# judges the actual update against that order. The record proves no origin and grants nothing Level 2 does not check
# again itself; it only narrows what Level 2 accepts (DESIGN_gegenstelle.md, section 7).

HANDOVER_SCHEMA = "proofbundle-plugin/handover/v1"
HANDOVER_POINTER_SCHEMA = "proofbundle-plugin/handover-pointer/v1"
#: The pointer in the per-worktree git directory that tells Level 2 a hand-over was given (the channel of D33). It is
#: found through git's own repository, not through the environment.
HANDOVER_POINTER = "proofbundle-handover"
#: How long a hand-over is valid after Level 1 wrote it.
HANDOVER_TTL_SECONDS = 300
MAX_HANDOVER_BYTES = 64 * 1024
_HANDOVER_KEYS = frozenset({"schema", "nonce", "created", "expires", "repo", "worktree", "gitdir", "remote", "url",
                            "push_words", "updates", "binding"})
_BINDING_KEYS = frozenset({"exec_path", "git_sha256", "hook", "hook_sha256", "gate", "gate_sha256", "plugin_version",
                           "interpreter", "environment", "configuration", "transport"})
#: The push options a hand-over allows. Every other option keeps the push an ask: a force or a lease (the remote's
#: history is replaced), a dry run, a signed push (a signing program starts), a push option and every option the gate
#: does not model.
_HANDOVER_FLAGS = frozenset({"-q", "--quiet", "-v", "--verbose", "--progress", "--no-progress", "--porcelain", "-u",
                             "--set-upstream", "--atomic", "--no-atomic", "--verify", "--thin", "--no-thin", "-4",
                             "--ipv4", "-6", "--ipv6"})
#: The names git sets for a hook it starts (measured with git 2.34.1: GIT_EXEC_PATH and GIT_PREFIX everywhere, and
#: GIT_DIR in a linked worktree and in a repository with a separate git directory, adversarial lens 2 of 2026-10-14,
#: F-B; a `-c` of the command reaches the hook as GIT_CONFIG_PARAMETERS, and a hand-over push never carries one). The
#: binding compares git's exec path on its own, and the repository, worktree and git directory git names in the hook
#: (which follow GIT_DIR) against the record, so it leaves these three out of the environment it compares.
_SET_BY_GIT_FOR_HOOKS = frozenset({"GIT_EXEC_PATH", "GIT_PREFIX", "GIT_DIR"})
#: Names the Bash tool of Claude Code sets in the shell a push runs in, with these values, and the host process does not
#: carry (measured in a session of 2026-10-14 by the adversarial lens and again by the builder: the host process held no
#: GIT_* name, the Bash tool's shell GIT_EDITOR=true and GIT_OPTIONAL_LOCKS=0). Bound, every hand-over of a real session
#: was refused. With these values they select no program and change nothing a push does: git push starts no editor, and
#: optional locks concern the index refresh of status. Any other value is bound. Whether a hook's own environment
#: carries them is NOT MEASURED; with these values it does not matter.
_HOST_SHELL_INERT = {"GIT_EDITOR": frozenset({"true", ":"}), "GIT_OPTIONAL_LOCKS": frozenset({"0", "1"})}
#: The names beside GIT_* the environment binding reads: where git reads its configuration, the gate directory, and
#: what selects ssh credentials and proxies. PATH is bound through the programs it selects (git, the interpreter).
_BINDING_ENV = frozenset({"HOME", "XDG_CONFIG_HOME", "PROOFBUNDLE_GATE_DIR", "SSH_AUTH_SOCK", "SSH_ASKPASS",
                          "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy",
                          "NO_PROXY", "no_proxy"})
#: What the transport digest reads besides the configuration (DESIGN_gegenstelle.md, 7.4).
_TRANSPORT_ENV = ("GIT_SSH", "GIT_SSH_COMMAND", "GIT_SSH_VARIANT", "GIT_ASKPASS", "SSH_ASKPASS", "SSH_AUTH_SOCK",
                  "GIT_PROXY_COMMAND", "GIT_ALLOW_PROTOCOL", "GIT_PROTOCOL_FROM_USER", "http_proxy", "https_proxy",
                  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy")
_TRANSPORT_SECTIONS = frozenset({"ssh", "credential", "http", "protocol"})
_TRANSPORT_CORE_KEYS = frozenset({"core.sshcommand", "core.askpass", "core.gitproxy"})
_TRANSPORT_PROGRAMS = ("git-receive-pack", "git-remote-http", "git-remote-https")
#: The configuration values and environment names that name a program the transport starts, one by one (the program
#: word of a plain command, a credential helper by git's own rules: _named_program). Their files are bound by sha256
#: (lens 1 of 2026-10-14, F2: the names alone were bound, so a program rewritten after the approval ran unasked).
_TRANSPORT_PROGRAM_KEYS = frozenset({"core.sshcommand", "core.askpass", "core.gitproxy"})
_TRANSPORT_PROGRAM_ENV = ("GIT_SSH", "GIT_SSH_COMMAND", "GIT_ASKPASS", "SSH_ASKPASS", "GIT_PROXY_COMMAND")
#: v2 (lens 1 of 2026-10-14): the files of the named programs, the ssh configuration for an ssh URL, the own
#: configuration of a path remote, and configuration origins as absolute paths. No v2 digest equals one of v1, so an
#: approval written before asks once.
TRANSPORT_DIGEST_SCHEMA = "proofbundle-plugin/transport/v2"
TRANSPORTS_FILE = "transports.json"
MAX_TRANSPORTS = 256
_TRANSPORT_ENTRY_KEYS = frozenset({"repo", "remote", "url", "transport_digest"})
_NONCE = re.compile(r"[0-9a-f]{32}")
#: The last second a record's times may name (9999-12-31T23:59:59Z): time.gmtime raises beyond it (lens 2, F-D).
_MAX_EPOCH = 253402300799


def _plain_path(value: object) -> bool:
    """Whether value is an absolute path os.path can take: a string with no NUL that the filesystem encoding encodes
    (a lone surrogate outside surrogateescape raises; adversarial lens 2 of 2026-10-14, F-D)."""
    if not isinstance(value, str) or "\0" in value or not os.path.isabs(value):
        return False
    try:
        os.fsencode(value)
    except UnicodeEncodeError:
        return False
    return True


def _canonical_digest(document: object) -> str:
    """sha256 of the canonical JSON of document; names and values keep the bytes git printed (R4-2)."""
    return hashlib.sha256(json.dumps(document, sort_keys=True, ensure_ascii=False)
                          .encode("utf-8", "surrogateescape")).hexdigest()


#: The largest file the binding hashes (adversarial lens 3 of 2026-10-14, F-O: a sparse file of several GiB named as a
#: program was read whole and raised MemoryError). A larger file binds as unreadable, which keeps the ask.
MAX_BOUND_FILE_BYTES = 512 * 1024 * 1024


def _sha256_or_none(path: str | None) -> str | None:
    """sha256 of the regular file at path, a link followed, hashed in blocks; None where there is none, it cannot be
    read, or it holds more than MAX_BOUND_FILE_BYTES. Opened as _read_regular opens: without blocking, its type checked
    at the descriptor before any read."""
    if not path:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BOUND_FILE_BYTES:
            return None
        digest, total = hashlib.sha256(), 0
        while block := os.read(fd, 1 << 20):
            total += len(block)
            if total > MAX_BOUND_FILE_BYTES:
                return None
            digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None
    finally:
        os.close(fd)


def _git_exec_path(deadline: float) -> str | None:
    """git's exec path as the git on PATH names it (`git --exec-path`), resolved; None where git does not say."""
    left = deadline - time.monotonic()
    if left <= 0:
        raise GateError("the gate ran out of time")
    try:
        out = subprocess.run(["git", "--exec-path"], capture_output=True, timeout=left, check=False, env=_read_env())
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired as exc:
        raise GateError("git did not answer in time") from exc
    value = _git_value(out.stdout) if out.returncode == 0 else None
    return os.path.realpath(value) if value and os.path.isabs(value) else None


def _interpreter_identity() -> list:
    """The interpreter that runs this gate: its file, its prefix and its version. The file alone does not tell a virtual
    environment from the system interpreter it was made from (both resolve to the same binary), and the prefix decides
    which site packages load."""
    return [os.path.realpath(sys.executable), sys.prefix, sys.version]


def _environment_digest(environ: dict) -> str:
    """The digest of the program-selecting environment the binding reads (every GIT_* name but those git sets for a
    hook and those the host's shell sets with an inert value, _HOST_SHELL_INERT; and _BINDING_ENV), name and value."""
    names = sorted(n for n in environ
                   if ((n.startswith("GIT_") and n not in _SET_BY_GIT_FOR_HOOKS
                        and environ[n] not in _HOST_SHELL_INERT.get(n, ())) or n in _BINDING_ENV))
    return _canonical_digest([[name, environ[name]] for name in names])


def _configuration_digest(repo: str, deadline: float) -> str | None:
    """The digest of the effective configuration git reads here, every entry with scope and origin; None where git
    cannot list it."""
    entries, _why = _config_entries(repo, deadline)
    return None if entries is None else _canonical_digest([list(entry) for entry in entries])


def _ssh_url(url: str) -> bool:
    """Whether git reaches url over ssh: an ssh scheme, or the scp form `[user@]host:path` with no slash before the
    colon (git's urlmatch rules, read; a local path or another scheme is none)."""
    if url.startswith(("ssh://", "git+ssh://", "ssh+git://")):
        return True
    if "://" in url or url.startswith(("/", ".", "~")):
        return False
    return ":" in url.split("/", 1)[0]


def _program_file(word: str | None, base: str, exec_path: str, environ: dict) -> list:
    """[the program word, the file it resolves to, its sha256] for the first word of a command: a word with a slash is a
    path (relative to base), any other is looked up in git's exec path and then on PATH, as git runs its dashed
    programs. [word, None, None] where it names no file, a shell builtin or a function for instance."""
    if not word:
        return [word, None, None]
    if "/" in word:
        found = os.path.join(base, os.path.expanduser(word))
    else:
        found = (os.path.join(exec_path, word) if os.path.isfile(os.path.join(exec_path, word))
                 else shutil.which(word, path=environ.get("PATH")))
    if not found:
        return [word, None, None]
    return [word, os.path.realpath(found), _sha256_or_none(found)]


#: A word of a program-naming value a hand-over relies on: no quote, expansion, glob, operator, redirection or space
#: inside (adversarial lens 3 of 2026-10-14, F-K). The program word alone may begin with `~/`, which the shell expands.
_PLAIN_WORD = re.compile(r"[A-Za-z0-9_./@%+=:,-]+")
#: Configuration keys and environment names whose value git runs as one program, with no shell (gitcredentials,
#: git-config; lens 3, F-L): the whole value is the program.
_UNSHELLED_PROGRAMS = frozenset({"core.askpass", "GIT_SSH", "GIT_ASKPASS", "SSH_ASKPASS"})
#: The URL forms a hand-over models (D33): a path, the scp form of ssh, and these schemes, which git carries itself or
#: with its own http helper. Every other form starts a remote helper (`<x>::<address>`, another scheme, an ext::
#: command, remote.<name>.vcs), which keeps the ask (lens 3, F-J, F-M). The comparison keeps git's letter case.
_HANDOVER_SCHEMES = ("file://", "ssh://", "git+ssh://", "ssh+git://", "git://", "http://", "https://")


def _named_program(key: str, value: str | None) -> tuple[str | None, str | None]:
    """(the program word git or the shell starts for a program-naming value, why a hand-over cannot rely on it). git
    runs the values of _UNSHELLED_PROGRAMS as one program path; every other value is a shell command, which must be
    plain words (_PLAIN_WORD) separated by single spaces, its program the first word after any leading `NAME=value`.
    A credential.helper names `git-credential-<word>` unless it is a `!command` or an absolute path. An empty
    credential.helper resets the list and names no program. Anything the gate does not model this way is the reason."""
    if value is None:
        return None, f"{key} has no value"
    name = key if key.startswith(("GIT_", "SSH_")) else key.lower()
    helper = name.startswith("credential.") and name.endswith(".helper")
    if helper and value == "":
        return None, None
    if name in _UNSHELLED_PROGRAMS:
        if not _PLAIN_WORD.fullmatch(value):
            return None, f"{key} names a program path the gate does not model ({value!r})"
        return value, None
    command = value[1:] if helper and value.startswith("!") else value
    words = command.split(" ")
    program_at = next((i for i, w in enumerate(words) if not _ASSIGNMENT.match(w)), None)
    if program_at is None:
        return None, f"{key} names no program ({value!r})"
    for i, word in enumerate(words):
        plain = word[2:] if i == program_at and word.startswith("~/") else word
        if not _PLAIN_WORD.fullmatch(plain):
            return None, (f"{key} is a shell command the gate does not model ({value!r}): a quote, an expansion, a "
                          "glob, an operator or a redirection decides there which program runs")
    program = words[program_at]
    if helper and not value.startswith("!") and not os.path.isabs(program):
        program = f"git-credential-{program}"
    return program, None


def _handover_url_problem(url: str, vcs: str | None) -> str | None:
    """Why a hand-over does not model the transport git chooses for `url` (_HANDOVER_SCHEMES), or None."""
    if vcs is not None:
        return f"remote.<name>.vcs ({vcs!r}) starts a remote helper"
    if "::" in url.split("/", 1)[0]:
        return f"the URL {url!r} names a remote helper (`<transport>::<address>`)"
    if url.startswith(_HANDOVER_SCHEMES) or "://" not in url:
        return None
    return f"the URL {url!r} has a scheme git hands to a remote helper"


def _ssh_config_files() -> list[str]:
    """The ssh client configuration files ssh reads (its user file under the home the password database names, not
    $HOME, and the system file). An Include inside them is not followed (D33, limits)."""
    files = ["/etc/ssh/ssh_config"]
    try:
        import pwd
        files.insert(0, os.path.join(pwd.getpwuid(os.getuid()).pw_dir, ".ssh", "config"))
    except (ImportError, KeyError):
        pass
    return files


def _path_remote(url: str, toplevel: str) -> str | None:
    """The local repository a path URL or a file:// URL names, absolute, or None for any other URL."""
    if url.startswith("file://"):
        return urllib.parse.unquote(urllib.parse.urlsplit(url).path) or None
    if "://" in url or _ssh_url(url):
        return None
    return os.path.realpath(os.path.join(toplevel, os.path.expanduser(url)))


def _transport_parts(repo: str, remote: str, url: str, deadline: float,
                     environ: dict) -> tuple[dict | None, list[str]]:
    """(the document whose digest binds the transport, the reasons a hand-over cannot rely on it; lens 3 of 2026-10-14)
    for what selects the programs, credentials and proxy of the transport to `remote` at `url` (D33,
    DESIGN_gegenstelle.md 7.4): the URL; every effective configuration entry of the remote, of a URL rewrite, of
    core.sshCommand, core.askPass and core.gitProxy and of the sections ssh, credential, http and protocol, with scope
    and origin (an origin file as an absolute path, so an approval does not depend on the worktree it was made in); the
    environment names of _TRANSPORT_ENV; git's exec path with the sha256 of its transport programs; the file and sha256
    of every program those entries and names start (one level: what that program reads or starts is not bound); the ssh
    on PATH and the ssh configuration files where the URL is an ssh URL; and the configuration file of a path remote,
    whose own settings (core.alternateRefsCommand) run before Level 2. A value the gate does not model as a plain
    command (_named_program), a program it resolves to no file and a transport that starts a remote helper
    (_handover_url_problem) are reasons. (None, []) where a part cannot be read."""
    entries, _why = _config_entries(repo, deadline)
    exec_path = _git_exec_path(deadline)
    toplevel, _unreadable = _work_tree(repo, deadline, "--path-format=absolute")
    if entries is None or exec_path is None or not toplevel:
        return None, []
    chosen, named, problems, vcs = [], [], [], None
    for scope, origin, key, value in entries:
        section, _dot, rest = key.partition(".")
        subsection, _dot, variable = rest.rpartition(".")
        section, variable = section.lower(), variable.lower()
        if ((section == "remote" and subsection == remote)
                or (section == "url" and variable in ("insteadof", "pushinsteadof"))
                or key.lower() in _TRANSPORT_CORE_KEYS or section in _TRANSPORT_SECTIONS):
            if origin.startswith("file:") and not os.path.isabs(origin[5:]):
                origin = "file:" + os.path.realpath(os.path.join(toplevel, origin[5:]))
            chosen.append([scope, origin, key, value])
            if section == "remote" and variable == "vcs":
                vcs = value
            if (key.lower() in _TRANSPORT_PROGRAM_KEYS or (section == "remote" and variable == "receivepack")
                    or (section == "credential" and variable == "helper")):
                named.append([key, value])
    named.extend([name, environ[name]] for name in _TRANSPORT_PROGRAM_ENV if name in environ)
    bound = []
    for key, value in named:
        program, why = _named_program(key, value)
        found = _program_file(program, toplevel, exec_path, environ)
        if why is None and program is not None and (found[1] is None or found[2] is None):
            why = f"{key} names the program {program!r}, which the gate resolves to no file it can hash"
        if why is not None:
            problems.append(why)
        bound.append([key, found])
    url_problem = _handover_url_problem(url, vcs)
    if url_problem is not None:
        problems.append(url_problem)
    programs: dict = {name: _sha256_or_none(os.path.join(exec_path, name)) for name in _TRANSPORT_PROGRAMS}
    files: dict = {}
    if _ssh_url(url):
        ssh = shutil.which("ssh", path=environ.get("PATH"))
        programs["ssh"] = [os.path.realpath(ssh), _sha256_or_none(ssh)] if ssh else None
        files = {path: _sha256_or_none(path) for path in _ssh_config_files()}
    local = _path_remote(url, toplevel)
    if local is not None:
        files = {path: _sha256_or_none(path) for path in (os.path.join(local, "config"),
                                                           os.path.join(local, ".git", "config"))}
    return {"schema": TRANSPORT_DIGEST_SCHEMA, "url": url, "configuration": chosen,
            "environment": [[n, environ[n]] for n in _TRANSPORT_ENV if n in environ],
            "exec_path": exec_path, "programs": programs, "named_programs": bound, "files": files}, problems


def _transport_digest(repo: str, remote: str, url: str, deadline: float, environ: dict) -> str | None:
    """The digest of _transport_parts, or None where a part cannot be read."""
    document, _problems = _transport_parts(repo, remote, url, deadline, environ)
    return None if document is None else _canonical_digest(document)


def _read_transports(environ: dict) -> list[dict]:
    """The transport approvals a person wrote, each exactly {repo, remote, url, transport_digest}; [] on any problem,
    as for the rules of D25: a file the gate cannot read whole approves nothing. The gate only ever reads it."""
    directory = _gate_dir(environ)
    if directory is None:
        return []
    try:
        raw = _read_regular(os.path.join(directory, TRANSPORTS_FILE), MAX_RULES_BYTES + 1, follow=True)
    except OSError:
        return []
    if len(raw) > MAX_RULES_BYTES:
        return []
    try:
        data = strict_json(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return []
    if not isinstance(data, list) or len(data) > MAX_TRANSPORTS:
        return []
    entries = []
    for item in data:
        if not isinstance(item, dict) or set(item) != _TRANSPORT_ENTRY_KEYS:
            return []
        if not (_plain_path(item["repo"]) and isinstance(item["remote"], str)
                and item["remote"] and isinstance(item["url"], str) and item["url"]
                and isinstance(item["transport_digest"], str) and _HEX64.fullmatch(item["transport_digest"])):
            return []
        entries.append(item)
    return entries


def _file_stamp(path: str) -> str:
    """Where a file a person writes lives, when it last changed and its sha256, for the answer that relies on it."""
    try:
        when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.lstat(path).st_mtime))
        digest = hashlib.sha256(_read_regular(path, MAX_RULES_BYTES + 1, follow=True)).hexdigest()[:16]
    except OSError:
        return f"{path} cannot be read"
    return f"{path} (last changed {when}, sha256 {digest}…)"


def _wrapper_root(raw: bytes) -> str | None:
    """The plugin folder a wrapper of install-pre-push names on its `root=` line, or None."""
    for line in raw.split(b"\n"):
        if line.startswith(b"root="):
            try:
                words = shlex.split(line[len(b"root="):].decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                return None
            return words[0] if len(words) == 1 else None
    return None


def _wrapper_gate(root: str, deadline: float) -> str | None:
    """The gate the wrapper finds at push time for `root`, by the wrapper's own resolver run here (_PRE_PUSH_RESOLVER);
    None where it finds none or does not answer."""
    left = min(deadline - time.monotonic(), 10.0)
    if left <= 0:
        raise GateError("the gate ran out of time")
    try:
        out = subprocess.run([sys.executable, "-I", "-c", _PRE_PUSH_RESOLVER, root], capture_output=True, text=True,
                             timeout=left, check=False, env=_isolated_env())
    except (OSError, subprocess.TimeoutExpired):
        return None
    found = out.stdout.strip()
    return found if out.returncode == 0 and found else None


def _bound_level2(hooks: str | None, deadline: float) -> tuple[dict | None, str]:
    """(the hook and gate binding, "") where the pre-push hook git uses here is a regular, executable file, byte for
    byte the wrapper install-pre-push writes, and the gate it finds at push time is this gate file; else (None, why).
    Installed hook bytes alone are no reason to hand over (answer 1 of review round 18): the hand-over also needs the
    approved transport, and Level 2 checks the binding again when it runs."""
    if not hooks:
        return None, "git names no hook folder for this repository"
    hook = os.path.join(hooks, "pre-push")
    try:
        st = os.lstat(hook)
    except FileNotFoundError:
        return None, f"no pre-push hook is installed at {hook}"
    except OSError as exc:
        return None, f"the pre-push hook at {hook} cannot be examined ({exc.strerror or exc})"
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return None, f"the pre-push hook at {hook} is no regular file"
    if not st.st_mode & stat.S_IXUSR:
        return None, f"the pre-push hook at {hook} is not executable, so git does not run it"
    try:
        raw = _read_regular(hook, MAX_HOOK_BYTES + 1)
    except OSError:
        return None, f"the pre-push hook at {hook} cannot be read"
    root = _wrapper_root(raw)
    if root is None or raw != pre_push_wrapper(root).encode("utf-8"):
        return None, f"the pre-push hook at {hook} is not the wrapper install-pre-push writes"
    own = os.path.realpath(__file__)
    found = _wrapper_gate(root, deadline)
    if found is None or os.path.realpath(found) != own:
        return None, (f"the pre-push hook at {hook} runs the gate {found or 'it finds nowhere'} at push time, not this "
                      f"gate {own} of plugin version {GATE_VERSION}")
    gate_sha256 = _sha256_or_none(own)
    if gate_sha256 is None:
        return None, f"this gate file {own} cannot be read"
    return {"hook": hook, "hook_sha256": hashlib.sha256(raw).hexdigest(), "gate": own, "gate_sha256": gate_sha256}, ""


def _handover_push_config_problem(repo: str, deadline: float) -> str | None:
    """Why the push configuration does what an option a hand-over excludes does, or None (adversarial lens of 2026-10-14,
    F3): push.gpgSign true or if-asked signs the push as --signed does and starts a signing program, and a non-empty
    push.pushOption list sends push options as -o does, which reach the server's hooks and which Level 2 never sees. git
    takes the last value of push.gpgSign (a key without a value is true), and an empty push.pushOption clears the list
    before it (_push_config_problem)."""
    def values(key: str) -> list[str | None] | None:
        out = _git(repo, "config", "--null", "--get-regexp", "^" + key.replace(".", "[.]") + "$", deadline=deadline)
        if out.returncode == 1 and not out.stdout and not out.stderr:
            return []
        if out.returncode != 0 or not out.stdout.endswith(b"\0"):
            return None
        return [_git_text(value) if newline else None
                for _key, newline, value in (entry.partition(b"\n") for entry in out.stdout[:-1].split(b"\0"))]
    signing, options = values("push.gpgsign"), values("push.pushoption")
    if signing is None or options is None:
        return "git cannot list push.gpgSign or push.pushOption, so the gate cannot tell what the push sends"
    if signing and (signing[-1] is None or signing[-1].lower() == "if-asked"
                    or not _git_false(repo, signing[-1], deadline)):
        return ("the configuration signs the push (push.gpgSign), as --signed does: a signing program starts, and a "
                "hand-over excludes a signed push")
    listed: list = []
    for value in options:
        listed = [] if value == "" else [*listed, value]
    if listed:
        return ("the configuration sends push options (push.pushOption), as -o does: they reach the server's hooks, Level "
                "2 never sees them, and a hand-over excludes a push option")
    return None


#: Where a path resolves differently in every process: the process's own directory, descriptors and standard streams
#: (adversarial lens 3 of 2026-10-14, F-H: /proc/self/cwd/bin is absolute, and the hook and the shell stand elsewhere).
_PROCESS_DEPENDENT = ("/proc/", "/dev/fd/", "/dev/stdin", "/dev/stdout", "/dev/stderr")


def _process_dependent(entry: str) -> bool:
    """Whether the PATH entry resolves through a process-dependent place (_PROCESS_DEPENDENT), directly or through a
    symbolic link on its way. os.path.realpath would follow /proc/self/cwd to this process's own directory and hide it,
    so the links are followed here one by one (at most 40)."""
    path = os.path.normpath(entry)
    for _hop in range(40):
        if (path + "/").startswith(_PROCESS_DEPENDENT):
            return True
        head = ""
        for part in path.split("/")[1:]:
            head = f"{head}/{part}"
            if os.path.islink(head):
                path = os.path.normpath(os.path.join(os.path.dirname(head), os.readlink(head)) + path[len(head):])
                break
        else:
            return False
    return True


def _git_identity_problem(deadline: float) -> str | None:
    """Why the git a plain `git push` starts is not shown to be git, or None (adversarial lens of 2026-10-14, F1): the
    program PATH names must be byte for byte the `git` in the exec path it reports. Only git starts the pre-push hook,
    and without Level 2 nothing judges a handed-over push. A wrapper or a script earlier on PATH, and a shim, differ.
    This proves no origin (D27): a program that reports a forged exec path holding a copy of itself is not caught.
    A PATH entry that is no absolute path (an empty one is the working directory) makes every lookup depend on the
    directory it runs in, and the shell's is not the gate's (adversarial lens 2 of 2026-10-14, F-A): no hand-over."""
    entries = os.environ.get("PATH", "").split(os.pathsep)
    if any(not os.path.isabs(entry) or _process_dependent(entry) for entry in entries):
        return ("PATH holds an entry that is no absolute path (an empty entry is the working directory) or resolves "
                "through /proc or /dev/fd, so the program a name selects depends on the process, and the shell's is "
                "not the gate's")
    git = shutil.which("git")
    exec_path = _git_exec_path(deadline)
    if git is None or exec_path is None:
        return "git names no program on PATH or no exec path, so the gate cannot tell which git the push starts"
    on_path, in_exec_path = os.path.realpath(git), os.path.join(exec_path, "git")
    measured = _sha256_or_none(on_path)
    if measured is None or measured != _sha256_or_none(in_exec_path):
        return (f"the git on PATH ({on_path}) is not byte for byte the git of its exec path ({in_exec_path}), so the "
                "gate cannot tell that the push starts git and its pre-push hook (a wrapper, a script or a shim)")
    # The pre-push wrapper starts `python3 -I <gate>` from PATH (D24B); a shim there can end the hook before Level 2
    # runs (lens 3, F-I). The host starts this gate the same way (hooks.json), so the two must be the same program.
    python, own = shutil.which("python3"), os.path.realpath(sys.executable)
    if python is None or _sha256_or_none(os.path.realpath(python)) != _sha256_or_none(own):
        return (f"the python3 on PATH ({os.path.realpath(python) if python else 'none'}), which the pre-push hook "
                f"starts, is not byte for byte the interpreter this gate runs under ({own}), so the gate cannot tell "
                "that the hook reaches Level 2 (a shim, a script or another interpreter)")
    return None


def _handover_binding(repo: str, remote: str, url: str, level2: dict, deadline: float, environ: dict) -> dict | None:
    """The binding Level 1 records and Level 2 recomputes (D33): git's exec path and the sha256 of the git program the
    gate runs, the hook and the gate, the plugin version, the interpreter, and the digests of the environment, the
    effective configuration and the transport. None where a part cannot be read."""
    exec_path = _git_exec_path(deadline)
    git = shutil.which("git")
    configuration = _configuration_digest(repo, deadline)
    transport = _transport_digest(repo, remote, url, deadline, environ)
    git_sha256 = _sha256_or_none(os.path.realpath(git)) if git else None
    if None in (exec_path, git_sha256, configuration, transport):
        return None
    return {"exec_path": exec_path, "git_sha256": git_sha256, "hook": level2["hook"],
            "hook_sha256": level2["hook_sha256"], "gate": level2["gate"], "gate_sha256": level2["gate_sha256"],
            "plugin_version": GATE_VERSION, "interpreter": _interpreter_identity(),
            "environment": _environment_digest(environ), "configuration": configuration, "transport": transport}


def _write_handover(gate_dir: str, gitdir: str, record: dict) -> str:
    """Write the record into <gate dir>/handover/<nonce>.json, created exclusively and never through a link, and then
    the pointer into the worktree's git directory, replacing an earlier one. Returns the record's path; OSError as the
    filesystem raises it."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    folder = os.path.join(gate_dir, "handover")
    os.makedirs(folder, mode=0o700, exist_ok=True)
    path = os.path.join(folder, record["nonce"] + ".json")
    with os.fdopen(os.open(path, flags, 0o600), "wb") as handle:
        handle.write(json.dumps(record, sort_keys=True, indent=1).encode("utf-8", "surrogateescape") + b"\n")
    temporary = os.path.join(gitdir, f".{HANDOVER_POINTER}.{secrets.token_hex(6)}.tmp")
    try:
        with os.fdopen(os.open(temporary, flags, 0o600), "wb") as handle:
            handle.write(json.dumps({"schema": HANDOVER_POINTER_SCHEMA, "nonce": record["nonce"]}).encode() + b"\n")
        os.replace(temporary, os.path.join(gitdir, HANDOVER_POINTER))
    except BaseException:
        if os.path.lexists(temporary):
            os.unlink(temporary)
        raise
    return path


def _handover_offer(repo: str, head_commit: str, push_args: list[str] | None, handover: dict | None,
                    sources: list[str], outcomes: dict, hints: list, note: str | None, reads: list, deadline: float,
                    environ: dict | None, plain_push: bool = False) -> tuple[Verdict | str | None, bool]:
    """The hand-over of D33, decided here and nowhere else: (the `handover` verdict, False) where every condition of
    DESIGN_gegenstelle.md 7.2 holds and the record is written; (why not, missing_level2) where the push is a candidate
    and one condition fails, missing_level2 True where only the bound Level 2 is missing; (None, False) where the push is
    no candidate at all (another open reason, a gh call, a repository that declares nothing)."""
    environ = os.environ if environ is None else environ
    if handover is None or push_args is None or not handover["targets"] or handover["remote"] is None or note is not None:
        return None, False
    targets, remote = handover["targets"], handover["remote"]
    if not plain_push:
        # The binding measures the git a plain `git push` starts in the hook's own environment. A prefix assignment,
        # an `env` carrier, a quoted or dashed command word (`git-push` is whatever program PATH names), a global
        # option or a chain runs another program or the same git in another environment than the one Level 1 read.
        return ("the command is not the plain form `git push …`: one simple command headed by a bare `git`, with no "
                "prefix assignment, chain, wrapper, global option, other git path, expansion, a redirection that opens "
                "a file, or an option word the shell may rewrite (the form _codex_plain_push names)"), False
    for word in push_args:
        if word == "--":
            break
        if word.startswith("-") and word != "-" and word not in _HANDOVER_FLAGS:
            return (f"the option {word} is not one a hand-over allows (a force, a lease, a dry run, a signed push and a "
                    "push option keep the push an ask)"), False
    why = _handover_push_config_problem(repo, deadline)
    if why is not None:
        return why, False
    if set(dict.fromkeys(sources)) != {t.source for t in targets}:
        return "the commits the push sends and the targets Level 1 resolved do not agree", False
    evidence, done = outcomes.get("evidence", {}), outcomes.get("done", set())
    for commit in dict.fromkeys(sources):
        verdict = evidence.get(commit)
        if verdict is not None and (verdict.decision == "pass" or (verdict.reason_id == "done_only" and commit in done)):
            continue
        return (f"the evidence at the sent commit {commit[:12]} did not verify as a pass "
                f"({verdict.reason_id if verdict is not None else 'not checked'}), and a hand-over needs valid source "
                "evidence"), False
    if hints:
        return ("the evidence rules differ from a local record of the destination, or were not compared with one "
                "(owner choice 4 A), which a person reviews"), False
    if _read_mode(environ) != "with-approvals":
        return ("the approval mode is strict; a hand-over needs with-approvals (D25), where a person's approval of the "
                "transport acts"), False
    gate_dir = _gate_dir(environ)
    paths, why = _repo_paths(repo, deadline)
    if gate_dir is None or paths is None or not paths["gitdir"] or not paths["common"]:
        return (why or "no gate directory is known, or git does not name the repository's directories"), False
    urls = _git(repo, "remote", "get-url", "--push", "--all", remote, deadline=deadline)
    url_lines = _git_lines(urls.stdout) if urls.returncode == 0 else None
    if not url_lines or len(url_lines) != 1 or not url_lines[0]:
        return f"git does not name one push URL of remote {remote}", False
    url = url_lines[0]
    document, problems = _transport_parts(repo, remote, url, deadline, environ)
    if document is None:
        return "the transport configuration cannot be read whole", False
    if problems:
        return ("the transport is not one a hand-over models, so the programs it starts before Level 2 are not known "
                "here: " + "; ".join(problems)), False
    transport = _canonical_digest(document)
    common = os.path.realpath(paths["common"])
    approvals = os.path.join(gate_dir, TRANSPORTS_FILE)
    approved = [entry for entry in _read_transports(environ)
                if os.path.realpath(entry["repo"]) == common and entry["remote"] == remote and entry["url"] == url
                and entry["transport_digest"] == transport]
    if not approved:
        command = _shell_command("python3", os.path.realpath(__file__), "transport-digest", "--repo", repo, "--remote",
                                 remote)
        return (f"the transport is not approved: {approvals} holds no entry for repository {common}, remote {remote} and "
                f"URL {url} with transport digest {transport}. The transport (its programs, credentials and proxy) "
                f"starts before Level 2 judges (G18-1), so only a person approves it; `{command}` prints the entry"), False
    level2, why = _bound_level2(paths["hooks"], deadline)
    if level2 is None:
        return f"no bound Level 2: {why}", True
    why = _git_identity_problem(deadline)
    if why is not None:
        return why, False
    binding = _handover_binding(repo, remote, url, level2, deadline, environ)
    if binding is None:
        return "the binding of the hand-over (git, configuration, transport) cannot be read whole", False
    created = int(time.time())
    record = {"schema": HANDOVER_SCHEMA, "nonce": secrets.token_hex(16), "created": created,
              "expires": created + HANDOVER_TTL_SECONDS, "repo": common, "worktree": os.path.realpath(repo),
              "gitdir": os.path.realpath(paths["gitdir"]), "remote": remote, "url": url, "push_words": list(push_args),
              "updates": [{"source": t.source, "dest": t.dest} for t in targets], "binding": binding}
    try:
        path = _write_handover(gate_dir, paths["gitdir"], record)
    except OSError as exc:
        return f"the hand-over could not be written ({exc.strerror or exc})", False
    updates = "; ".join(f"{t.dest} from {t.source[:12]}" for t in targets)
    until = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record["expires"]))
    text = (f"proofbundle gate: Level 1 hands this push over to Level 2 (DECISIONS.md D33) and makes no permission "
            "decision of its own: the gate never answers allow, and the host's own permission settings decide whether "
            f"it asks. Checked here: {_sources_clean(sources)}; the one reason left open is the destination, which "
            "git's pre-push hook reads from the remote's own answer to the push. The transport of remote "
            f"{remote} ({url}) is approved in {_file_stamp(approvals)}. The pre-push hook at {level2['hook']} is this "
            f"plugin's wrapper and runs this gate ({level2['gate']}, version {GATE_VERSION}). Level 2 checks the actual "
            f"update against hand-over {record['nonce']} ({updates}), consumes it, and blocks the push where anything "
            "differs; its verdict decides, not this message, and a Level 2 pass is no successful remote update. Valid "
            f"until {until}, recorded at {path}. A shell command can write the transport approval and the hand-over "
            "files, and the gate cannot tell who wrote them (D27).")
    return Verdict("handover", text, "handed_over", repo=repo, head=head_commit, reads=tuple(reads)), False


def _handover_form(record: object, nonce: str) -> str | None:
    """Why a hand-over record is not of the form Level 1 writes, or None."""
    if not isinstance(record, dict) or set(record) != _HANDOVER_KEYS or record.get("schema") != HANDOVER_SCHEMA:
        return "the record is not a hand-over of this plugin (its schema or fields differ)"
    if record["nonce"] != nonce:
        return "the record names another hand-over than the pointer"
    if not all(type(record[k]) is int and 0 <= record[k] <= _MAX_EPOCH for k in ("created", "expires")):
        return "the record's times are not whole numbers of seconds between 1970 and 9999"
    if not all(isinstance(record[k], str) and record[k] for k in ("repo", "worktree", "gitdir", "remote", "url")):
        return "the record does not name its repository, remote and URL"
    updates = record["updates"]
    if not (isinstance(updates, list) and updates and all(
            isinstance(u, dict) and set(u) == {"source", "dest"} and isinstance(u["source"], str)
            and u["source"].isascii() and _OID.fullmatch(u["source"].encode("ascii")) and isinstance(u["dest"], str)
            and u["dest"].startswith(_TRACKABLE)
            for u in updates)):
        return "the record's expected updates are not a list of sources and full destinations"
    binding = record["binding"]
    if not isinstance(binding, dict) or set(binding) != _BINDING_KEYS:
        return "the record's binding is not the one Level 1 writes"
    return None


def _take_handover(gitdir: str) -> tuple[dict | None, str | None, str]:
    """Consume the hand-over of this worktree, if there is one: (None, None, "") without a pointer, the standalone mode;
    (record, None, nonce) for a record of the form Level 1 writes; (None, why, nonce) where the pointer or the record
    is missing, unreadable, foreign or consumed already. Whoever moves the pointer first owns the hand-over, so it is
    used at most once, and the record is moved aside before it is read (D33, the channel)."""
    pointer = os.path.join(gitdir, HANDOVER_POINTER)
    if not os.path.lexists(pointer):
        return None, None, ""
    taken = pointer + ".consumed"
    try:
        os.replace(pointer, taken)
    except FileNotFoundError:
        return None, "the hand-over was consumed by another push at the same moment", ""
    except OSError as exc:
        return None, f"the hand-over pointer cannot be consumed ({exc.strerror or exc})", ""
    try:
        raw = _read_regular(taken, 4096)
        os.unlink(taken)
        pointed = strict_json(raw)
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):   # RecursionError: a nesting deeper than json reads
        return None, "the hand-over pointer is no regular file Level 2 can read", ""
    nonce = pointed.get("nonce") if isinstance(pointed, dict) else None
    if (not isinstance(pointed, dict) or set(pointed) != {"schema", "nonce"} or pointed["schema"] != HANDOVER_POINTER_SCHEMA
            or not isinstance(nonce, str) or not _NONCE.fullmatch(nonce)):
        return None, "the hand-over pointer is not of the form Level 1 writes", ""
    gate_dir = _gate_dir(os.environ)
    if gate_dir is None:
        return None, "no gate directory is known to Level 2, so the record the pointer names cannot be read", nonce
    record_path = os.path.join(gate_dir, "handover", nonce + ".json")
    consumed = record_path + ".consumed"
    try:
        os.replace(record_path, consumed)
    except FileNotFoundError:
        return None, (f"the record {record_path} is missing (consumed already, removed, or written under another gate "
                      "directory than Level 2's)"), nonce
    except OSError as exc:
        return None, f"the record {record_path} cannot be consumed ({exc.strerror or exc})", nonce
    try:
        raw = _read_regular(consumed, MAX_HANDOVER_BYTES + 1)
        record = strict_json(raw) if len(raw) <= MAX_HANDOVER_BYTES else None
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        return None, f"the record {record_path} is no regular file of strict JSON", nonce
    why = _handover_form(record, nonce)
    return (None, why, nonce) if why is not None else (record, None, nonce)


def _parent_git_sha256() -> tuple[bool, str | None]:
    """(measurable, sha256) of the program that started this process, git for a hook, read from /proc/<parent>/exe; (False,
    None) on a system without /proc, where the git program is bound through its exec path only (D33, not measured)."""
    if not os.path.isdir("/proc/self"):
        return False, None
    return True, _sha256_or_none(os.path.realpath(f"/proc/{os.getppid()}/exe"))


def _handover_mismatch(repo: str, paths: dict, record: dict, remote: str | None, url: str | None, lines: list,
                       deadline: float) -> str | None:
    """Why the push git runs is not the push Level 1 handed over (DESIGN_gegenstelle.md 7.5, steps 2 to 4), or None."""
    now = time.time()
    if now > record["expires"]:
        return (f"it expired at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(record['expires']))}, "
                f"{HANDOVER_TTL_SECONDS} s after the time it records as written")
    if record["created"] > now + 5:
        return "it was written in the future (the clock moved), so its age is not known"
    if (os.path.realpath(paths["common"]), os.path.realpath(repo), os.path.realpath(paths["gitdir"])) != \
            (record["repo"], record["worktree"], record["gitdir"]):
        return "it was written for another repository, worktree or git directory"
    if (remote, url) != (record["remote"], record["url"]):
        return (f"git pushes to remote {remote!r} at {url!r}, and the hand-over names remote {record['remote']!r} at "
                f"{record['url']!r}")
    binding = record["binding"]
    exec_path = os.environ.get("GIT_EXEC_PATH")
    if not exec_path or os.path.realpath(exec_path) != binding["exec_path"]:
        return (f"the git that runs this hook has the exec path {exec_path!r} (GIT_EXEC_PATH), and the hand-over "
                f"records {binding['exec_path']!r}")
    measurable, parent = _parent_git_sha256()
    if measurable and parent != binding["git_sha256"]:
        return "the git program that started this hook is not the git program the hand-over records (sha256 differs)"
    hook = os.path.join(paths["hooks"] or "", "pre-push")
    if hook != binding["hook"] or _sha256_or_none(hook) != binding["hook_sha256"]:
        return (f"the pre-push hook {hook} is not the hook the hand-over records ({binding['hook']}), or its bytes "
                "changed")
    own = os.path.realpath(__file__)
    if own != binding["gate"] or _sha256_or_none(own) != binding["gate_sha256"]:
        return f"this gate {own} is not the gate file the hand-over records ({binding['gate']}), or its bytes changed"
    if GATE_VERSION != binding["plugin_version"]:
        return f"this gate is plugin version {GATE_VERSION}, and the hand-over records {binding['plugin_version']}"
    if _interpreter_identity() != binding["interpreter"]:
        return (f"this gate runs under {_interpreter_identity()}, and the hand-over records the interpreter "
                f"{binding['interpreter']}")
    if _environment_digest(os.environ) != binding["environment"]:
        return ("the program-selecting environment of this push differs from the one the hand-over records (a GIT_* "
                "name, HOME, XDG_CONFIG_HOME, the gate directory, the ssh agent or a proxy)")
    if _configuration_digest(repo, deadline) != binding["configuration"]:
        return "the effective git configuration differs from the one the hand-over records"
    if _transport_digest(repo, record["remote"], record["url"], deadline, os.environ) != binding["transport"]:
        return "the transport configuration differs from the one the hand-over records"
    return _handover_update_problem(record["updates"], lines)


def _handover_update_problem(updates: list[dict], lines: list) -> str | None:
    """Why git's ref lines are not the update set of the hand-over (D33, 7.5 step 4), or None: every line must be one of
    the expected updates with its source. A line twice, a deletion, a line of another destination (the candidate,
    named with both names), another source or any other update refuses. An expected update without a line is a no-op
    git left out, which the caller names."""
    expected = {u["dest"]: u["source"] for u in updates}
    seen: set = set()
    for _local_ref, local_sha, remote_ref, _remote_sha in lines:
        if remote_ref in seen:
            return f"git hands the hook {remote_ref} twice"
        seen.add(remote_ref)
        if local_sha in _ZERO_OIDS:
            return f"git would delete {remote_ref}, which the hand-over does not name"
        if remote_ref not in expected:
            meant = [dest for dest in expected if any(remote_ref == name for name, _s in _dest_candidates(dest))]
            if meant:
                return (f"git would write {remote_ref} where the hand-over expects {meant[0]}: git resolved the "
                        f"destination to this other ref, as it does where the remote holds no {meant[0]} "
                        "(the candidate write)")
            return f"git would write {remote_ref}, which is none of the updates the hand-over names"
        if expected[remote_ref] != local_sha:
            return (f"git would send {local_sha[:12]} to {remote_ref}, and the hand-over names "
                    f"{expected[remote_ref][:12]}")
    return None


def _handover_refused(repo: str, head: str, nonce: str, why: str) -> Verdict:
    """Level 2 refuses a hand-over (D33): the push is denied (exit 1), and the next push asks Level 1 anew."""
    named = f"hand-over {nonce}" if nonce else "a hand-over"
    return Verdict("deny", f"proofbundle gate (pre-push): this worktree holds a hand-over pointer ({named}; who wrote it "
                           f"is not known, D27), and Level 2 refuses the hand-over: {why.rstrip('.')}. The push is not "
                           "the push that hand-over names, so it is denied, and the hand-over is consumed.",
                   "handover_refused",
                   evidence="the hand-over record the pointer names and git's ref lines", failed=why,
                   next_step="run the push again as one command of its own so that Level 1 decides anew, or have a "
                             "person review the push", repo=repo, head=head)


def _with_mode(verdict: Verdict, record: dict | None, lines: list) -> Verdict:
    """The verdict of Level 2 with the mode it ran in (answer 6 of review round 18), on a pass and an inactive verdict:
    standalone, or the hand-over it checked with the expected updates git left out as not checked."""
    if verdict.decision not in ("pass", "inactive"):
        return verdict
    if record is None:
        note = (" Level 2 ran without a hand-over from Level 1 (standalone mode): git's destination names were not "
                "compared with an expected target.")
    else:
        sent = {remote_ref for _l, _s, remote_ref, _r in lines}
        left_out = [u["dest"] for u in record["updates"] if u["dest"] not in sent]
        note = (f" Level 2 checked the update set of hand-over {record['nonce']} (the record the pointer names; who "
                "wrote it is not known, D27), and git's destinations are the ones it expects."
                + (f" git gave no line for {', '.join(left_out)}, as it does for a no-op (a ref the remote reports at "
                   "the commit it would send, measured with git 2.34.1); that update was not checked, and neither was "
                   "why git left it out." if left_out else "")
                + " A Level 2 pass is no successful remote update: git's own end result is separate.")
    return Verdict(verdict.decision, verdict.detail.rstrip() + note, verdict.reason_id, evidence=verdict.evidence,
                   failed=verdict.failed, next_step=verdict.next_step, digests=verdict.digests, repo=verdict.repo,
                   head=verdict.head, reads=verdict.reads)


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
#: v2 (review round 4 of 2026-10-09, R4-1): the attribute entries name the system and the global file git reads and
#: carry each file's path, so no digest of v1 equals one of v2 and a rule written before asks once.
GATE_STATE_SCHEMA = "proofbundle-plugin/gate-state/v2"
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
        raw = _read_regular(os.path.join(directory, "mode"), MAX_MODE_BYTES + 1, follow=True)   # R18-2 class
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
        raw = _read_regular(os.path.join(directory, "rules.json"), MAX_RULES_BYTES + 1, follow=True)   # R18-2 class
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


def _git_path(directory: str, value: str, deadline: float) -> str | None:
    """A pathname value of git's configuration as git interpolates it (git-config(1), "pathname": a leading `~/`,
    `~user/` and `%(prefix)/`), asked of git itself with no configuration read: the value is the default of a key the
    null device cannot hold, so the git that runs the command reads it with its own rules and its own runtime prefix
    (review round 3 of 2026-10-09, R3-3; os.path.expanduser knew `~` only). A relative result stays relative: its base
    is the caller's. None when git cannot say."""
    out = _run_git(directory, ("config", "--file", os.devnull, "--type=path", "--default", value, "--get",
                               "proofbundle-gate.interpolate"), deadline)
    if out.returncode != 0 or not out.stdout.endswith(b"\n"):
        return None
    return _git_text(out.stdout[:-1])


#: The attribute files git reads outside the work tree, as git var names them (git 2.42 and later): the system file,
#: $(prefix)/etc/gitattributes unless GIT_ATTR_NOSYSTEM is set, and the global file, core.attributesFile, else
#: $XDG_CONFIG_HOME/git/attributes, else $HOME/.config/git/attributes (gitattributes(5)). An unset key is not an absent
#: file: git reads the default then (review round 4 of 2026-10-09, R4-1).
_ATTRIBUTE_VARIABLES = (("system", "GIT_ATTR_SYSTEM"), ("global", "GIT_ATTR_GLOBAL"))


def _attribute_files(directory: str, toplevel: str | None, deadline: float) -> list | None:
    """[(label, path or None)] for each file of _ATTRIBUTE_VARIABLES, path None where git reads no such file; None
    when git cannot name one for sure. git var interpolates as the git that runs the command does (`~/`, `~user/`,
    `%(prefix)/`) and answers in the hook's environment; it exits 1 with no output where git reads no such file
    (measured with git 2.43: GIT_ATTR_NOSYSTEM, or neither HOME nor XDG_CONFIG_HOME set), 129 where the git is older
    than 2.42 and does not know the variable, and 128 where the configuration is broken. Anything but a known absence
    or one line is unknown, and so is a relative name without a work tree: git opens it against the work tree it has
    set up (measured for core.attributesFile from a subdirectory and with -C)."""
    found: list = []
    for label, name in _ATTRIBUTE_VARIABLES:
        out = _git(directory, "var", name, deadline=deadline)
        if out.returncode == 1 and out.stdout == b"":
            found.append((label, None))
            continue
        lines = _git_lines(out.stdout) if out.returncode == 0 else None
        if lines is None or len(lines) != 1 or not lines[0]:
            return None
        path = lines[0]
        if not os.path.isabs(path):
            if toplevel is None:
                return None
            path = os.path.join(toplevel, path)
        found.append((label, path))
    return found


def _bound_state_digest(directory: str, deadline: float, environ: dict | None = None) -> str | None:
    """The hex sha256 of the program-selecting state of the repository at directory, or None when any part
    cannot be read (so the gate asks). It binds a human rule to the state at the time the rule was written: the
    effective git configuration, the effective hook directory (each entry's name, permission bits and content
    hash, core.hooksPath included because git resolves it into this directory; a hook longer than MAX_HOOK_BYTES makes
    the state unknown, R5-2), the attribute files git reads outside
    the work tree (info/attributes, and the system and the global file as git var names them, R4-1: an unset
    core.attributesFile is the default file, not none) and the GIT_* and program-selecting environment (PATH included).
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
                # git cannot exec a directory, a FIFO or a device as a hook (measured with git 2.43.0: "cannot exec
                # ... Permission denied"), so there is no content to bind; a change to a regular file changes this
                hooks.append([name, oct(stat.S_IMODE(info.st_mode)), "nonfile"])
                continue
            try:
                content = _read_regular(full, MAX_HOOK_BYTES + 1, follow=True)   # checked again at the descriptor
            except OSError:
                return None
            if len(content) > MAX_HOOK_BYTES:
                # A hook the digest does not read in full is unknown: a fixed marker in place of its bytes let a
                # change behind the first MAX_HOOK_BYTES keep the digest (review round 5 of 2026-10-09, R5-2)
                return None
            hooks.append([name, oct(stat.S_IMODE(info.st_mode)), hashlib.sha256(content).hexdigest()])
    attribute_files = _attribute_files(directory, paths["toplevel"], deadline)
    if attribute_files is None:
        return None   # git cannot name an attribute file it reads, so the state is unknown rather than "absent"
    attrs: list = []
    for label, path in [("info/attributes", os.path.join(common, "info", "attributes")), *attribute_files]:
        if path is None:
            attrs.append([label, None, "none"])
            continue
        try:
            info = os.stat(path)   # follows a link, as git does; a FIFO or a directory is not read, it is unknown
        except FileNotFoundError:
            attrs.append([label, path, "absent"])
            continue
        except OSError:
            return None
        if not stat.S_ISREG(info.st_mode):
            return None
        try:
            attrs.append([label, path, hashlib.sha256(_read_regular(path, -1, follow=True)).hexdigest()])
        except OSError:
            return None
    env = sorted((name, value) for name, value in environ.items()
                 if name.startswith("GIT_") or name in _DIGEST_ENV_EXTRA)
    document = {"schema": GATE_STATE_SCHEMA, "repo": common,
                "config": [[scope, origin, key, value] for scope, origin, key, value in entries],
                "hooks_dir": os.path.realpath(hooks_dir) if hooks_dir else None,
                "hooks": hooks, "attributes": attrs, "env": [[name, value] for name, value in env]}
    # surrogateescape: a name or value carries the bytes git printed, and the serialisation carries them back as those
    # bytes, so FF and EF BF BD are two states, not one (R4-2); text that is UTF-8 serialises as before
    return hashlib.sha256(json.dumps(document, sort_keys=True, ensure_ascii=False)
                          .encode("utf-8", "surrogateescape")).hexdigest()


def _rule_candidate(command: str, cwd: str, deadline: float) -> tuple[str, str] | None:
    """(repo, form) when command is exactly one plain local git form a human rule may free — a bare
    `git <local-subcommand> …` with no prefix assignment and no global option, acting on the repository at cwd —
    else None. repo is that repository's git-common-dir (realpath); form is the command's own text, stripped. A
    push, a gh call, an unknown or transfer-capable subcommand, a program-path invocation, a chain, a pipe, a
    wrapper, a substitution, a comment-bearing form, or any global option (`-C`, `-c`, …) yields None, so a rule
    can never free them: push and gh are never freeable, and the state digest binds only the plain form's
    repository (N24).

    A form the net reports NOT MEASURED is never a candidate either, in with-approvals mode as in strict
    (Nachtrag 37): the net's single decision site (_net_unmodeled, via _net_unresolved) is consulted here, so a
    rule can free a form only when the net also positively understood it. Without this a rule could free a plain
    `git <local>` form the net could not build exactly like bash — a locale quote `$"…"`, a decoded NUL — which is
    the one way a human rule might otherwise free something NOT MEASURED."""
    calls = gated_calls(command)
    if len(calls) != 1 or _net_words(command) > 1 or _net_unresolved(command):
        return None
    name, _directory, detail = calls[0]
    if detail not in ([_NOT_FREE], [_STATE_FREE]) or not name.startswith("git ") or name in ("git", "git --version"):
        return None
    toks = _lex(_drop_comments(command))
    if toks is None or any(t[0] == "op" for t in toks) or _expansion_present(command):
        return None
    if any(_shell_rewrites(t[3]) for t in toks if t[0] == "word"):
        return None  # the approved text is not the command git gets when the shell rewrites a word (F2)
    if not _redirections_open_no_file(toks):
        return None  # a form a rule frees writes no file through the shell (R2-2)
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
    detail = (f"proofbundle gate: a rule frees this form in with-approvals mode. Approved form "
              f"{rule['form']!r} in {rule['repo']}; the gate recomputed the repository's program-selecting state "
              f"(configuration, hooks, gitattributes and the GIT_* environment) and it matches the digest the "
              f"rule carries. The gate asks again if that state changes; push and gh are never freed. "
              f"{_gate_files_stamp(os.environ)} A file tool cannot write these files; a shell command can, and "
              f"the gate cannot tell who wrote them, so check that you set this mode and rule yourself. The local "
              f"gate is an early warning; the boundary is the CI check (N24; DECISIONS.md D25).")
    verdict = Verdict("pass", detail, "approved_by_rule", repo=rule["repo"])
    applied = {"origin": "rule", "repo": rule["repo"], "form": rule["form"], "effect": "free", "state_match": True}
    return Outcome("pass", verdict.text(), [verdict], applied_rule=applied)


def _gate_files_stamp(environ: dict) -> str:
    """Where the mode and the rules a freed call relied on live, and when each last changed (review Runde 15,
    F15-2: a shell command switched the mode silently; the owner's rule for the user path is that making it
    visible is enough)."""
    directory = _gate_dir(environ)
    if directory is None:
        return "The gate directory is unknown."
    parts = []
    for name in ("mode", "rules.json"):
        path = os.path.join(directory, name)
        try:
            st = os.lstat(path)
            digest = hashlib.sha256(_read_regular(path, MAX_RULES_BYTES + 1, follow=True)).hexdigest()[:16]
            when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(st.st_mtime))
            parts.append(f"{path} last changed {when} (sha256 {digest}…)")
        except OSError:
            parts.append(f"{path} cannot be read")
    return "Mode and rules: " + "; ".join(parts) + "."


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


def _codex_plain_push(command: str) -> bool:
    """True when the whole command is the plain push form owner choice K5-1 C lets warn under Codex: one simple
    command, no chain, pipeline, background job, subshell, group, here-document or expansion anywhere, no prefix
    assignment of any kind, the command word exactly `git` as written (no path, no quotes, no wrapper) and `push`
    right after it (no global option such as -c or -C). A redirection keeps the form plain only when it opens no file
    (_redirections_open_no_file: `2>&1`, `>&2`, `2>&-`, `/dev/null`): any other target is opened before git starts and
    may be the pre-push hook itself (review round 2 of 2026-10-09, R2-2). Every other push form can step around that
    hook or the repository it runs in, so under Codex it is denied (DECISIONS.md D12)."""
    toks = _lex(_drop_comments(command))
    if toks is None or any(t[0] == "op" for t in toks) or _expansion_present(command):
        return False
    if not _redirections_open_no_file(toks):
        return False
    words = [t[1:] for t in toks if t[0] == "word"]
    if len(words) < 2 or _ASSIGNMENT.match(words[0][0]):
        return False
    (head, head_subst, head_raw), (sub_word, sub_subst, sub_raw) = words[0], words[1]
    if not (head == head_raw == "git" and sub_word == sub_raw == "push" and not (head_subst or sub_subst)):
        return False
    return not _push_options_rewritten(words[2:])


def _push_options_rewritten(words: list[tuple]) -> bool:
    """Whether a word among `git push`'s options, before the `--` that ends them, may be rewritten by the shell
    (_shell_rewrites): `--no-verif?` with a file named `--no-verify` turns the pre-push hook off (review 2026-10-09,
    F2). A `--` ends the options only after a word that takes no value: `push` itself, a word that is no option, a
    target-neutral flag or an inline `--opt=value`; after any other option it may be that option's value (`-o --`),
    so the options go on. After the `--` that ends them a word is a repository or a refspec, and the hook still runs."""
    takes_value = False
    for value, _subst, raw in words:
        if value == "--" and not takes_value:
            return False
        if _shell_rewrites(raw):
            return True
        takes_value = (value.startswith("-") and value != "-" and "=" not in value
                       and value not in _PUSH_FLAGS_NEUTRAL)
    return False


def decide(command: str, cwd: str, deadline: float, host: str = "claude",
           environ: dict | None = None) -> Outcome | None:
    """None for a call the gate does not gate, else the combined outcome. Under Codex the judge cannot bind
    a gated shell call to the directory it runs in, so it reports it NOT MEASURED (review Runde 5, R5-2).
    The former free list for local git commands has been removed. Those forms are NOT MEASURED, asked under
    Claude Code and denied under Codex. Only the exact bare command text `git --version` is exempt from
    judgment as a git form. The separate push path remains. Under Claude Code it denies an evidenced failure at the
    commits a push sends and otherwise asks, its destination NOT MEASURED (D3, R9-1), except the local inactivity of
    owner choice 1 A for a repository that declares nothing (_local_inactivity, D5); under Codex every push is NOT
    MEASURED because its execution context is unbound
    (review Runde 9, owner choice B; wording of review Runde 10, R10-3), and a `git push` warns (Karte 5 A, D12).

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
    outcome = _decide_outcome(command, cwd, deadline, host, environ)
    if outcome is not None:
        _name_narrower_spelling(outcome, command, cwd, deadline, host, environ)
    return outcome


def _narrower_spelling(command: str) -> str | None:
    """The narrower spelling of a refused `git add <paths>` or `git commit -m <message> [paths]` that the gate frees:
    the paths after a `--` that ends the options, and a message the shell may rewrite in single quotes (review round 2
    of 2026-10-09: `git add -- *.py`, `git add -- src/*`, `git commit -m 'fix#12'`). None when the command is not one
    plain simple form of the two, when it has no such spelling, or when the gate would not free the spelling itself
    (it is judged by gated_calls, so the hint never names a form the gate refuses)."""
    toks = _lex(_drop_comments(command))
    if toks is None or any(t[0] != "word" for t in toks) or _expansion_present(command):
        return None
    words = [t[1:] for t in toks]
    if len(words) < 3 or words[0][2] != "git" or words[1][2] not in ("add", "commit"):
        return None
    sub, rest = words[1][2], words[2:]
    if any(value == "--" for value, _subst, _raw in rest):
        return None
    if sub == "add":
        if any(value.startswith("-") for value, _subst, _raw in rest):
            return None
        spelled = ["git", "add", "--"] + [raw for _value, _subst, raw in rest]
    else:
        if len(rest) < 2 or rest[0][2] not in ("-m", "--message"):
            return None
        (message, message_subst, message_raw), paths = rest[1], rest[2:]
        if _shell_rewrites(message_raw):
            if "'" in message or message_subst:
                return None
            message_raw = f"'{message}'"
        if any(value.startswith("-") for value, _subst, _raw in paths):
            return None
        spelled = ["git", "commit", rest[0][2], message_raw] + (["--"] + [raw for _v, _s, raw in paths] if paths else [])
    proposal = " ".join(spelled)
    calls = gated_calls(proposal)
    if proposal == command.strip() or len(calls) != 1 or calls[0][2] != [_STATE_FREE]:
        return None
    return proposal


def _name_narrower_spelling(outcome: Outcome, command: str, cwd: str, deadline: float, host: str,
                            environ: dict | None) -> None:
    """Name the narrower spelling (_narrower_spelling) in the next step of a refused `git add` or `git commit` whose
    words the shell may rewrite, in place of the general hint, so an agent can run the form the gate frees. The
    spelling is named only when the whole gate passes it in the same context (host, directory, environment and the
    same deadline): gated_calls alone named `git add -- git-*`, which the net check still refuses, and a spelling a
    repository state check refuses (review round 3 of 2026-10-09, R3-5). Otherwise the general hint stays."""
    hinted = [v for v in outcome.verdicts if v.reason_id == "git_form_not_free" and v.next_step == _FREE_FORMS_HINT]
    if not hinted:
        return
    proposal = _narrower_spelling(command)
    if proposal is None:
        return
    try:
        checked = _decide_outcome(proposal, cwd, deadline, host, environ)
    except GateError:
        return
    if checked is None or checked.decision != "pass":
        return
    step = (f"run `{proposal}` instead: it leaves no word before the end of the options that the shell may turn into "
            "an option, and the gate frees it after a state check of the repository (DECISIONS.md D3); otherwise have "
            "a person review the call")
    for verdict in hinted:
        verdict.next_step = step
    outcome.text = outcome.text.replace(_FREE_FORMS_HINT.rstrip("."), step.rstrip("."))


def _decide_outcome(command: str, cwd: str, deadline: float, host: str, environ: dict | None) -> Outcome | None:
    """decide() without the hint of _name_narrower_spelling."""
    environ = os.environ if environ is None else environ
    calls = gated_calls(command)
    # The plain push form decides the Codex warning (D12) and is a condition of the hand-over under Claude Code (D33).
    plain = _codex_plain_push(command)
    net_call = ("git or gh (a form the gate does not model)", UNKNOWN, [_NET])
    if _BARE_VERSION.fullmatch(command):
        return _judge(calls, cwd, deadline, host, plain_push=plain, environ=environ) if calls else None
    if host != "codex" and _read_mode(environ) == "with-approvals":
        applied = _match_rule(command, cwd, deadline, environ)
        if applied is not None and applied[0] == "free":
            return _approved_outcome(applied[1])
    nw = _net_words(command)
    unresolved = _net_unresolved(command)
    if not calls:
        return (_judge([net_call], cwd, deadline, host, plain_push=plain, environ=environ)
                if (nw >= 1 or unresolved) else None)
    if nw > len(calls) or unresolved:
        return _judge(list(calls) + [net_call], cwd, deadline, host, plain_push=plain, environ=environ)
    return _judge(calls, cwd, deadline, host, plain_push=plain, environ=environ)


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
                      next_step=(f"have a person review the call, or publish through {_push_form_hint(host)}; its "
                                 "destination stays NOT MEASURED under Level 1 (D3)"))
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
    bases = {paths["toplevel"] or directory, directory}

    def anchored(name: str) -> set[str]:
        """A file name as git opens it. git takes a relative name (a relative GIT_CONFIG_GLOBAL, measured with git
        2.43) against its working directory, which is the work tree once git has set up the repository and the
        command's directory for a read before that (an alias): both are protected (R3-3). An absolute name is
        itself, never passed through os.path.expanduser: git names the file as it opened it, already interpolated,
        so a directory named `~` stays that directory."""
        return {name} if os.path.isabs(name) else {os.path.join(b, name) for b in bases}

    for _scope, origin, key, value in entries:
        sources: set[str] = set()
        if origin.startswith("file:"):
            sources = anchored(origin[5:])
            files |= sources
        k = key.lower()
        if value and (k == "include.path" or (k.startswith("includeif.") and k.endswith(".path"))):
            included = _git_path(directory, value, deadline)   # git's interpolation, `%(prefix)/` included (R3-3)
            if included is None:
                return files, dirs, f"git cannot resolve the include {value!r} from {origin or 'an unnamed origin'}"
            if os.path.isabs(included):
                files.add(included)   # an absolute include, also one from the command scope or standard input
            elif sources:
                files.update(os.path.join(os.path.dirname(s), included) for s in sources)   # beside the including file
            else:   # git-config(1): a relative include must come from a file, so git itself refuses it
                return files, dirs, f"the include {value!r} from {origin or 'an unnamed origin'} names no file"
    # git reads ~/.gitconfig and the XDG file at $HOME (git-config(1)) and neither when HOME is unset (measured with
    # git 2.43); os.path.expanduser reads HOME as well and falls back to the password database only when HOME is
    # unset, where it protects a file git does not read.
    home = os.path.expanduser("~")
    for name in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"):   # git-var(1): the files git itself would use
        named = _git(directory, "var", name, deadline=deadline)
        if named.returncode == 0:
            for p in _git_lines(named.stdout) or ():
                if p and p != os.devnull:
                    files |= anchored(p)
    for name, default in (("GIT_CONFIG_GLOBAL", None), ("GIT_CONFIG_SYSTEM", "/etc/gitconfig")):
        value = os.environ.get(name)
        if value and value != os.devnull:
            files |= anchored(value)
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


def _evaluate_call(name: str, directory: str, detail: list[str] | None, deadline: float,
                   environ: dict | None = None, plain_push: bool = False) -> Verdict:
    """The verdict for one gated call: a shell `git push` resolves its targets and the commits it sends; a
    `gh pr/release create` is judged as a push of the current branch to its upstream; an MCP tool, whose
    remote target the gate cannot read, is judged at HEAD with no range comparison. `environ` reaches the push path,
    which reads the approval mode and the gate directory from it (D33); `plain_push` says whether the whole command is
    the plain push form (_codex_plain_push), the only form Level 1 hands over."""
    if detail and detail[0] == _HOOKS_DISABLE:
        return Verdict("deny", f"the command would turn off the gate's check of the real push, so it is denied.",
                       "hooks_disabled",
                       evidence="none, the command would disable the pre-push verification",
                       failed=f"{name} would skip or redirect the hook that verifies the real push "
                              "(--no-verify, or a core.hooksPath override)",
                       next_step="push without --no-verify and without setting core.hooksPath, or obtain a human review")
    if name == "git push":
        return evaluate_push(directory, detail, deadline, environ, plain_push)
    if name.startswith("gh "):
        return evaluate_push(directory, detail, deadline)
    return evaluate_repository(directory, deadline)


#: The next step of a refused `git add` or `git commit` form (a chain, an option, a wrapper): the two forms K-NW-2 B
#: frees, so an agent without a person can still commit (measured in a Claude Code run on 2026-10-08: an agent that
#: chained the edit, `git add` and `git commit` was refused, read "have a person review the call" and stopped).
#: The push form Level 1 resolves from any working directory and checks, named wherever the gate tells the agent how
#: to push (FIX-17 Nachtrag 1, owner choice A of 2026-10-13, 23:3x Berlin, D32). Measured in the self-use of
#: 2026-10-13: Claude Code writes a push as `cd <repo> && git push <remote> <refspec>`, which Level 1 does not resolve
#: since review Runde 4 (directory_unresolved), so nearly every push asked. The resolution stays as it is; the answer
#: leads to the form it resolves: one command, one literal absolute `-C`, no `cd`, no chain.
SAFE_PUSH_FORM = "git -C <absolute path> push <remote> <refspec>"
SAFE_PUSH_EXAMPLE = "git -C /home/me/repo push origin HEAD:refs/heads/topic"


def _push_form_hint(host: str) -> str:
    """How to write a push the gate resolves and checks under `host`. Under Codex only the plain `git push …` in the
    session's directory warns (owner choice K5-1 C, D12): a global option such as `-C` is not that form there."""
    if host == "codex":
        return "the plain `git push <remote> <refspec>` on its own, in the session's directory"
    return (f"`{SAFE_PUSH_FORM}` as a command of its own, for example `{SAFE_PUSH_EXAMPLE}`: the gate resolves the "
            "repository from that path and checks the commits the push sends, while a `cd`, a `pushd` or any chain "
            "before the push stays unresolved and is asked")


_FREE_FORMS_HINT = ("run `git add <paths>` and then `git commit -m <message>`, each as a whole command of its own with no "
                    "chain, wrapper, redirection or other option: the gate frees exactly these two forms after a state "
                    "check of the repository (DECISIONS.md D3); otherwise have a person review the call")


def _state_free_verdict(name: str, directory: str | None, deadline: float, host: str) -> Verdict:
    """The verdict for one of the two forms K-NW-2 B frees: pass when the state check of its repository finds nothing
    that starts a program for it, else the not-free answer of D3 with the source it found. Under Codex the hook names
    the session directory, not the directory the command runs in (measured with Codex 0.161.0: a workdir the model
    sets reaches the command and not the hook), so the pass says which directory was checked."""
    try:
        problem = (_add_commit_state_problem(directory, deadline) if directory is not UNKNOWN
                   else "the gate cannot tell which repository the call acts on")
    except GateError as exc:
        problem = f"the state check reached no result ({exc})"
    if problem is None:
        where = (f"the session directory {directory}, which Codex names; Codex does not tell the gate where a command "
                 "runs (a workdir the model sets reaches the command, not the hook)" if host == "codex"
                 else f"the repository at {directory}")
        return Verdict("pass", f"proofbundle gate: {name} is free. The state check of {where} found no filter, hook, "
                               "fsmonitor, signature program or include onto one, and every configuration key, hook "
                               "and GIT_* setting it read is one it knows to start no program for this form (owner "
                               "choice K-NW-2 B; DECISIONS.md D3).", "free_after_state_check", repo=directory)
    return Verdict(
        "ask", f"NOT MEASURED: the gate gives no free answer for {name}: the state check found {problem}. Such a "
               "setting selects a program git may start for this form, which the gate does not see (owner choice "
               "K-NW-2 B; DECISIONS.md D3).",
        "git_form_not_free", evidence=f"the repository state {name} runs with",
        failed=f"{name} may start a program: {problem}",
        next_step="have a person review the call, or run it yourself outside the agent", repo=directory)


def _judge(calls: list[tuple[str, str | None, list[str] | None]], cwd: str, deadline: float,
           host: str = "claude", extra: list | None = None, plain_push: bool = False,
           environ: dict | None = None) -> Outcome:
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
            # Owner choice Karte 5 A with D (08.10): a `git push` keeps this reason and warns instead, because git
            # starts the pre-push hook (Level 2) in the push's own repository. Owner choice K5-1 C: only the plain
            # form warns (_codex_plain_push); any other push form may step around that hook, so it is denied. A gh
            # call starts no pre-push hook, so it stays an ask, denied under Codex; a hook-disabling push was
            # denied above, under both hosts.
            unbound = (f"NOT MEASURED: under Codex the gate cannot bind {name} to the directory and "
                       "environment it runs in. The hook receives the session directory and the command "
                       "text, not the execution workdir or a remote environment, so it could judge a "
                       "different repository than the push acts on.")
            if name == "git push" and not plain_push:
                verdicts.append(Verdict(
                    "ask", unbound + " Under Codex only the plain form `git push …` warns: one command headed by a "
                                     "bare `git`, with no prefix assignment, chain, wrapper, global option, other "
                                     "git path or expansion, and no option word the shell may rewrite, such as a "
                                     "glob (owner choice K5-1 C, DECISIONS.md D12; review 2026-10-09, F2). This form "
                                     "is not that form, so it may step around the pre-push hook.",
                    "codex_push_not_plain", evidence=f"the repository and target {name} acts on",
                    failed="the push is not the plain form `git push …` headed by a bare `git` with no prefix "
                           "assignment, chain, wrapper, global option, other git path, expansion or option word the "
                           "shell may rewrite",
                    next_step="run the push as the plain `git push <remote> <refspec>` on its own, or have a person "
                              "push"))
                continue
            verdicts.append(Verdict(
                "warn" if name == "git push" else "ask", unbound,
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
                next_step="run the call in a plain form the gate reads (a single `git`/`gh` command, no "
                          "unusual quoting, substitution or letter case), or have a person review it"))
            continue
        if detail == [_STATE_FREE]:
            verdicts.append(_state_free_verdict(name, resolved, deadline, host))
            continue
        if detail == [_NOT_FREE]:
            verdicts.append(Verdict(
                "ask", f"NOT MEASURED: the gate gives no free answer for {name}. A git form that acts on a repository "
                       "can start another program through its options, the repository's configuration and "
                       "configured values, its hooks or an indirect path such as automatic maintenance, and the gate "
                       "does not model them (owner choice B, review Runde 9; DECISIONS.md D3).",
                "git_form_not_free", evidence="none, the gate reads no repository state for a git form",
                failed=f"{name} may start a program the gate does not see",
                next_step=(_FREE_FORMS_HINT if name in ("git add", "git commit") else
                           "have a person review the call, or run it yourself outside the agent")))
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
                next_step=(f"have a person review the command, or run the push as {_push_form_hint(host)}; its "
                           "destination stays NOT MEASURED under Level 1 (D3)")))
            continue
        if resolved is UNKNOWN:
            verdicts.append(Verdict("ask", f"NOT MEASURED: the gate cannot tell which repository {name} acts on "
                                           "(a directory change, a git option it does not resolve, or a word the "
                                           "shell may rewrite, such as a glob).",
                                    "directory_unresolved", evidence=f"unknown, the repository {name} acts on",
                                    failed="the gate cannot resolve the directory",
                                    next_step=(f"run the push as {_push_form_hint(host)}, or have a person push"
                                               if name == "git push" else
                                               "run the call as one command of its own with literal words, for "
                                               "git with one literal absolute path as `git -C <absolute path> …`; "
                                               "a `cd`, a `pushd` or any chain before it stays unresolved")))
            continue
        try:
            verdicts.append(_evaluate_call(name, resolved, detail, deadline, environ, plain_push))
        except GateError as exc:
            verdicts.append(Verdict("deny", f"proofbundle gate: {exc}. The call is denied because the gate reached "
                                            "no verdict.", "gate_error",
                                    evidence=f"the declaration {DECLARATION} and the evidence it names",
                                    failed=str(exc),
                                    next_step="fix the cause named here; the gate denies until it reaches a verdict",
                                    digests=exc.digests, repo=resolved, head=exc.head, reads=exc.reads))
        except Exception as exc:  # noqa: BLE001 - any failure denies, with the record of what was read (R12-2)
            verdicts.append(Verdict("deny", f"proofbundle gate: internal error {type(exc).__name__}: {exc}. The call "
                                            "is denied because the gate reached no verdict.", "internal_error",
                                    evidence=f"the declaration {DECLARATION} and the evidence it names",
                                    failed=f"{type(exc).__name__}: {exc}",
                                    next_step="report this error; the gate denies until it is fixed",
                                    digests=getattr(exc, "digests", ()), repo=resolved,
                                    head=getattr(exc, "head", None), reads=getattr(exc, "reads", ())))
    for decision in ("deny", "ask", "warn"):
        chosen = [v for v in verdicts if v.decision == decision]
        if chosen:
            return Outcome(decision, " ".join(v.text() for v in chosen), verdicts)
    # A hand-over (D33) is no pass: Level 2 gives the verdict on the actual update, and the log says so.
    combined = ("handover" if any(v.decision == "handover" for v in verdicts) else
                "pass" if all(v.decision == "pass" for v in verdicts) else "inactive")
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
    permissionDecisionReason without a permissionDecision. A "warn" (a git push under Codex, Karte 5 A) carries no
    permission decision either: the reason, with the warning sentence, goes out as the message only.
    """
    if decision == "ask" and host == "codex":
        decision, reason = "deny", reason + " Codex cannot ask, so the gate denies the call."
    if decision == "warn":
        reason = f"{reason} {CODEX_PUSH_WARNING}"
    specific = {"hookEventName": "PreToolUse", "additionalContext": reason}
    if decision not in ("pass", "inactive", "warn", "handover"):   # D4: the gate never answers allow (D33 too)
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


TRANSPORT_USAGE = "usage: transport-digest [--repo DIR] [--remote NAME]"


def transport_digest_command(argv: list[str]) -> int:
    """`transport-digest [--repo DIR] [--remote NAME]` (default remote origin): print the transport digest of D33 and the
    entry a person copies into transports.json in the gate directory to approve that transport. The gate never writes
    that file; run this in the same environment the agent's pushes run in, since the digest binds it."""
    options, i = {"--repo": ".", "--remote": "origin"}, 0
    while i < len(argv):
        if argv[i] in options and i + 1 < len(argv):
            options[argv[i]], i = argv[i + 1], i + 2
        else:
            print(f"{TRANSPORT_USAGE}; unknown {argv[i]!r}", file=sys.stderr)
            return 2
    deadline = time.monotonic() + DEADLINE_SECONDS
    try:
        paths, why = _repo_paths(options["--repo"], deadline)
        if paths is None or paths["common"] is None:
            print(f"transport-digest: not a git repository, or its layout cannot be read ({why or options['--repo']})",
                  file=sys.stderr)
            return 1
        urls = _git(options["--repo"], "remote", "get-url", "--push", "--all", options["--remote"], deadline=deadline)
        lines = _git_lines(urls.stdout) if urls.returncode == 0 else None
        if not lines or len(lines) != 1 or not lines[0]:
            print(f"transport-digest: git names no single push URL of remote {options['--remote']!r}", file=sys.stderr)
            return 1
        document, problems = _transport_parts(options["--repo"], options["--remote"], lines[0], deadline, os.environ)
        digest = None if document is None else _canonical_digest(document)
    except GateError as exc:
        print(f"transport-digest: {exc}", file=sys.stderr)
        return 1
    for problem in problems:
        print(f"transport-digest: note: a hand-over does not rely on this transport: {problem}", file=sys.stderr)
    if digest is None:
        print("transport-digest: the transport configuration cannot be read whole, so there is no digest",
              file=sys.stderr)
        return 1
    entry = {"repo": os.path.realpath(paths["common"]), "remote": options["--remote"], "url": lines[0],
             "transport_digest": digest}
    sys.stdout.write(digest + "\n")
    sys.stdout.write(json.dumps(entry, indent=2, sort_keys=True) + "\n")
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
    sent = ("none" if verdict in ("pass", "inactive", "warn", "handover", "not_gated")
            else ("deny" if host == "codex" else verdict))
    repos = [] if outcome is None else [
        {"path": v.repo, "head": v.head, "verdict": v.decision, "reason_id": v.reason_id, "digests": list(v.digests),
         **({"evidence": list(v.reads)} if v.reads else {})}
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
        # A FIFO with no reader is never waited on (R18-2 class): the open does not block, and an entry that is no
        # regular file at the opened descriptor is not written to.
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NONBLOCK", 0)
                     | getattr(os, "O_CLOEXEC", 0), 0o644)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            os.write(fd, (json.dumps(entry, sort_keys=True) + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    except OSError:
        return None
    return path


# --- the done check: the end of a session only with a receipt for the current state (DECISIONS.md, D26) ---

def _tree_object_id(oid_length: int, files: dict) -> str:
    """The git tree id of {path: (mode, blob id)}, built as git builds a tree object: entries sorted by name, a
    directory compared as its name with a trailing slash. The same construction as the package's pytest plugin."""
    nested: dict = {}
    for path, entry in files.items():
        *dirs, leaf = path.split(b"/")
        node = nested
        for d in dirs:
            node = node.setdefault(d, {})
        node[leaf] = entry

    def build(node: dict) -> str:
        rows = []
        for name, value in node.items():
            if isinstance(value, dict):
                rows.append((name + b"/", b"40000 " + name, build(value)))
            else:
                rows.append((name, value[0] + b" " + name, value[1]))
        body = b"".join(head + b"\0" + bytes.fromhex(oid) for _key, head, oid in sorted(rows))
        hasher = _BLOB_HASHES[oid_length](b"tree %d\0" % len(body))
        hasher.update(body)
        return hasher.hexdigest()
    return build(nested)


def _state_excluded(path: bytes) -> bool:
    """An untracked path that is not part of the working state: the evidence folder and bytecode caches."""
    return path.startswith(EVIDENCE_DIR.encode()) or b"__pycache__" in path.split(b"/")


def working_state(repo: str, deadline: float) -> dict:
    """{"commit", "tree", "worktree", "problem", "files"} of the repository: HEAD's commit and tree id, and the tree id of
    the working state, the files of HEAD and every other file git does not ignore, read as raw bytes and modes
    (100755 when the owner may execute a file, else 100644), outside untracked files of the top-level
    .proofbundle/ folder and of __pycache__ folders. No clean or smudge filter, line-ending rule, fsmonitor, hook
    or index takes part (review Runde 8, R8-1). "worktree" is None and "problem" says why where the working
    state cannot be read as files: a submodule, a path component that is a link or not a directory, a file
    that is neither regular nor a link. The rules are the package's pytest plugin's, so both name the same tree
    for the same bytes."""
    _refuse_partial_clone(repo, deadline)
    ids = []
    for rev in ("HEAD^{commit}", "HEAD^{tree}"):
        proc = _git(repo, "rev-parse", "--verify", "-q", rev, deadline=deadline)
        value = proc.stdout.decode("ascii", "replace").strip()
        if proc.returncode != 0 or len(value) not in _BLOB_HASHES:
            raise GateError("the repository has no commit at HEAD")
        ids.append(value)
    commit, tree = ids
    state = {"commit": commit, "tree": tree, "worktree": None, "problem": None, "files": None}
    listing = _git(repo, "ls-tree", "-r", "-z", "--full-tree", commit, deadline=deadline)
    if listing.returncode != 0:
        raise GateError(f"git could not list the tree of {commit[:12]}")
    head = set()
    for record in listing.stdout.split(b"\0"):
        if not record:
            continue
        meta, tab, path = record.partition(b"\t")
        fields = meta.split(b" ")
        if not tab or len(fields) != 3:
            raise GateError("git ls-tree gave a line the gate cannot read")
        if fields[1] != b"blob":
            state["problem"] = f"the tree holds a {fields[1].decode(errors='replace')} at {path.decode(errors='replace')}"
            return state
        head.add(path)
    with tempfile.TemporaryDirectory(prefix="proofbundle-state-") as scratch:
        os.mkdir(os.path.join(scratch, "hooks"))
        env = dict(_read_env(repo), GIT_INDEX_FILE=os.path.join(scratch, "no-index"))
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
    paths = head | {p for p in proc.stdout.split(b"\0") if p and p not in head and not _state_excluded(p)}
    root = os.fsencode(repo)
    files = {}
    for path in sorted(paths):
        shown = path.decode(errors="replace")
        parts = path.split(b"/")
        if any(part in (b"", b".", b"..") for part in parts):
            state["problem"] = f"{shown} has a path component the gate cannot follow safely"
            return state
        deleted = False
        for depth in range(1, len(parts)):
            try:
                mode_bits = os.lstat(os.path.join(root, *parts[:depth])).st_mode
            except FileNotFoundError:
                deleted = True
                break
            except OSError:
                state["problem"] = f"{shown} lies below a directory the gate cannot read"
                return state
            if not stat.S_ISDIR(mode_bits):
                state["problem"] = f"{shown} lies below {b'/'.join(parts[:depth]).decode(errors='replace')}, which is " \
                                   "a link or not a directory in the working tree"
                return state
        if deleted:
            continue
        full = os.path.join(root, *parts)
        try:
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                mode, data = b"120000", os.readlink(full)
            elif stat.S_ISREG(st.st_mode):
                mode = b"100755" if st.st_mode & stat.S_IXUSR else b"100644"
                data = _read_regular(full, -1)   # checked again at the descriptor (R18-2 class)
            else:
                state["problem"] = f"{shown} is neither a regular file nor a link in the working tree"
                return state
        except FileNotFoundError:
            continue
        except OSError:
            state["problem"] = f"{shown} cannot be read in the working tree"
            return state
        hasher = _BLOB_HASHES[len(commit)](b"blob %d\0" % len(data))
        hasher.update(data)
        files[path] = (mode, hasher.hexdigest())
    state["worktree"] = _tree_object_id(len(commit), files)
    state["files"] = files
    return state


def commit_state(repo: str, commit: str, deadline: float) -> dict:
    """The state of a commit itself, in the shape of working_state: its commit and tree id, its tree as the state
    the receipts must name ("worktree"), and its files as git lists them (path: (mode, blob id)), not as the disk
    holds them. The done check at a pushed commit uses it (owner choice N2 C): the push sends that commit's tree,
    whatever the working tree holds. A submodule or another entry that is not a file leaves it unreadable as files,
    as in working_state."""
    _refuse_partial_clone(repo, deadline)
    proc = _git(repo, "rev-parse", "--verify", "-q", f"{commit}^{{tree}}", deadline=deadline)
    tree = proc.stdout.decode("ascii", "replace").strip()
    if proc.returncode != 0 or len(tree) not in _BLOB_HASHES:
        raise GateError(f"git could not name the tree of {commit[:12]}")
    state = {"commit": commit, "tree": tree, "worktree": None, "problem": None, "files": None}
    listing = _git(repo, "ls-tree", "-r", "-z", "--full-tree", commit, deadline=deadline)
    if listing.returncode != 0:
        raise GateError(f"git could not list the tree of {commit[:12]}")
    files = {}
    for record in listing.stdout.split(b"\0"):
        if not record:
            continue
        meta, tab, path = record.partition(b"\t")
        fields = meta.split(b" ")
        if not tab or len(fields) != 3:
            raise GateError("git ls-tree gave a line the gate cannot read")
        if fields[1] != b"blob":
            state["problem"] = f"the tree holds a {fields[1].decode(errors='replace')} at {path.decode(errors='replace')}"
            return state
        files[path] = (fields[0], fields[2].decode("ascii", "replace"))
    state["worktree"], state["files"] = tree, files
    return state


_THRESHOLD_ONE = re.compile(r"1(?:\.0+)?")


def done_claim_problem(claim: object) -> str | None:
    """Why a verified receipt's claim does not say that every test passed, or None. Done means a pytest pass
    rate of at least exactly 1 with passed true, at least one test and pytest's exit status 0: a lower
    threshold signs passed true for failing tests, and pytest's own receipt signs passed true for a run that
    exited 1 when the pass rate met the threshold (measured 2026-09-30, D23)."""
    if not isinstance(claim, dict) or claim.get("schema") != EVAL_CLAIM_SCHEMA:
        return "the receipt is not an eval receipt"
    if claim.get("suite") != "pytest" or claim.get("metric") != "pass_rate":
        return "the receipt is not a pytest receipt of the pass rate"
    if claim.get("comparator") != ">=" or not (isinstance(claim.get("threshold"), str)
                                               and _THRESHOLD_ONE.fullmatch(claim["threshold"])):
        return "the receipt does not require every test to pass (it needs comparator >= and threshold 1)"
    if claim.get("passed") is not True:
        return "the receipt says the tests did not pass"
    n, provenance = claim.get("n"), claim.get("provenance")
    if not (isinstance(n, int) and not isinstance(n, bool) and n >= 1):
        return "the receipt names no test that ran"
    status = provenance.get("exit_status") if isinstance(provenance, dict) else None
    if not (isinstance(status, int) and not isinstance(status, bool) and status == 0):
        return f"the receipt's pytest run did not exit 0 (exit status {status!r})"
    return None


def tested_tree(provenance: object) -> str | None:
    """The tree id the receipt's tests ran on: git_tree for a clean run, git_worktree_tree for a run on a
    working state that differed from HEAD, else None."""
    if not isinstance(provenance, dict):
        return None
    if provenance.get("git_clean") is True:
        value = provenance.get("git_tree")
    elif provenance.get("git_clean") is False:
        value = provenance.get("git_worktree_tree")
    else:
        return None
    return value if isinstance(value, str) and len(value) in _BLOB_HASHES and all(
        c in "0123456789abcdef" for c in value) else None


def _short(text: str, limit: int = 240) -> str:
    return text if len(text) <= limit else text[:limit - 3] + "..."


def check_command(check: dict, environ: dict) -> str:
    """The command that runs one check of the done section and leaves its receipt (D26, D28). A check of the
    order names its pytest arguments and clears PYTEST_ADDOPTS, so the receipt names exactly that selection."""
    key = environ.get("PROOFBUNDLE_KEY")
    if not (key and os.path.isabs(key)):
        directory = _gate_dir(environ)
        key = os.path.join(directory, DONE_KEY_FILE) if directory else "<your test key file>"
    selection = "" if check["args"] is None else "PYTEST_ADDOPTS= "
    args = "" if check["args"] is None else "".join(" " + shlex.quote(a) for a in check["args"])
    return (f"{selection}PROOFBUNDLE_EMIT=1 PROOFBUNDLE_THRESHOLD=1 PROOFBUNDLE_OUT={shlex.quote(check['receipt'])} "
            f"PROOFBUNDLE_KEY={shlex.quote(key)} python -m pytest{args}")


def selection_problem(check: dict, provenance: dict) -> str | None:
    """Why the receipt's run is not the run the check asks for, or None. A check of the order asks for exactly its
    pytest arguments, an empty PYTEST_ADDOPTS and no deselected test; the one-check form asks for no selection. Not
    seen here: plugins or conftest code that skip, select or rewrite tests in other ways (D28)."""
    if check["args"] is None:
        return None
    args, addopts, deselected = (provenance.get("pytest_args"), provenance.get("pytest_addopts"),
                                 provenance.get("n_deselected"))
    if not (isinstance(args, list) and all(isinstance(a, str) for a in args) and isinstance(addopts, str)
            and type(deselected) is int):
        return "the receipt does not name how pytest was asked to run (pytest_args, pytest_addopts, n_deselected)"
    if args != check["args"]:
        return _short(f"the receipt's run had the pytest arguments {json.dumps(args)}, the check asks for "
                      f"{json.dumps(check['args'])}")
    if addopts.strip():
        return _short(f"the receipt's run had PYTEST_ADDOPTS {addopts!r}, which the check does not allow")
    if deselected != 0:
        return f"the receipt's run deselected {deselected} tests"
    return None


def _receipt_bytes(path: str) -> bytes | None:
    """The receipt file's bytes; None when there is none. A link, another file type or an oversized file is
    refused, not followed."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise GateError(f"the receipt {path} cannot be read: {exc}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise GateError(f"the receipt {path} is not a regular file")
    if st.st_size > MAX_EVIDENCE_BYTES:
        raise GateError(f"the receipt {path} is larger than {MAX_EVIDENCE_BYTES} bytes")
    try:
        return _read_regular(path, MAX_EVIDENCE_BYTES + 1)   # checked again at the descriptor (R18-2 class)
    except _NotRegular as exc:
        raise GateError(f"the receipt {path} is not a regular file") from exc


def _signed_payload(content: bytes) -> bytes | None:
    """B of a proofbundle bundle: the payload bytes its signature covers, or None where there is none to read."""
    try:
        bundle = strict_json(content)
        return base64.b64decode(bundle["payload_b64"], validate=True) if isinstance(bundle, dict) else None
    except (KeyError, TypeError, ValueError, binascii.Error):
        return None


#: How many commits that changed the declaration the gate reads back to find the commit that declared the order; past
#: it the base is NOT MEASURED (owner choice Nordstern B).
MAX_ORDER_WALK = 256


def _parents(repo: str, commit: str, deadline: float) -> tuple[list[str], list[str]] | None:
    """(shown, recorded): the parents git shows for a commit and the parents its commit object names, or None where git
    cannot read either. They differ where git cuts the history at the commit (a shallow clone, or a shallow file named
    by GIT_SHALLOW_FILE), whatever source told git so; the gate reads no shallow file itself (review round 6 of
    2026-10-10, R6-1: it read the cut points from `--git-path shallow` while git followed GIT_SHALLOW_FILE). Replace refs
    and grafts are already off for every read of the gate (_read_env), so a difference is a cut."""
    shown = _git(repo, "rev-list", "--parents", "--max-count=1", commit, deadline=deadline)
    raw = _git(repo, "cat-file", "commit", commit, deadline=deadline)
    if shown.returncode != 0 or raw.returncode != 0:
        return None
    ids = shown.stdout.decode("ascii", "replace").split()
    if not ids or ids[0] != commit:
        return None
    header = raw.stdout.split(b"\n\n", 1)[0]
    recorded = [line[len(b"parent "):].decode("ascii", "replace") for line in header.split(b"\n")
                if line.startswith(b"parent ")]
    return ids[1:], recorded


def _order_at(repo: str, commit: str, deadline: float) -> tuple | None:
    """The canonical done section at a commit, None where it declares none; a declaration that does not parse is an
    order of its own (its bytes' digest), never the same as a valid one."""
    raw = _blob(repo, commit, DECLARATION, deadline, MAX_DECLARATION_BYTES)
    if raw is None:
        return None
    try:
        done = parse_done(raw)
    except GateError:
        return ("malformed", hashlib.sha256(raw).hexdigest())
    return None if done is None else _done_canonical(done)


def order_base(repo: str, commit: str, done: dict, deadline: float) -> tuple[str | None, str]:
    """The commit that declared the order as it stands at `commit` (owner choice Nordstern B, D28): on the first-parent
    line, the newest commit that changed the declaration and whose first parent declares another order or none. A
    change to the declaration that leaves the done section as it is (an evidence item, a subject) does not move it.
    (None, why) where it cannot be determined: the history is cut before it is found (git shows a commit without the
    parents its object names: a shallow clone or a shallow file git reads, R6-1), more than MAX_ORDER_WALK commits
    changed the declaration, or git cannot list them. `rev-list`, not `log`: no signature check, no pager, no program a
    configuration names."""
    section = _done_canonical(done)
    proc = _git(repo, "rev-list", "--first-parent", f"--max-count={MAX_ORDER_WALK + 1}", commit, "--", DECLARATION,
                deadline=deadline)
    if proc.returncode != 0:
        return None, "git could not list the commits that changed the declaration"
    candidates = proc.stdout.decode("ascii", "replace").split()
    for n, candidate in enumerate(candidates):
        if n == MAX_ORDER_WALK:
            return None, f"more than {MAX_ORDER_WALK} commits changed {DECLARATION} since the order was declared"
        parents = _parents(repo, candidate, deadline)
        if parents is None:
            return None, f"git could not read the parents of {candidate[:12]}"
        shown, recorded = parents
        if shown != recorded:
            return None, (f"the history is cut at {candidate[:12]}: git shows it without the parents its commit names "
                          "(a shallow clone, or a shallow file git reads), so the gate cannot tell which commit declared "
                          "the order")
        if not recorded:
            return candidate, ""   # a root commit of a full history declared it
        if _order_at(repo, recorded[0], deadline) != section:
            return candidate, ""
    return None, f"no commit on the first-parent line of {commit[:12]} declared the order it holds"


def changed_paths(repo: str, base: str, files: dict, deadline: float) -> list[str]:
    """The paths whose mode or bytes differ between the tree of `base`, the commit that declared the order
    (order_base), and the state `files` (D28)."""
    listing = _git(repo, "ls-tree", "-r", "-z", "--full-tree", base, deadline=deadline)
    if listing.returncode != 0:
        raise GateError(f"git could not list the tree of {base[:12]}, the commit that set the order")
    before = {}
    for record in listing.stdout.split(b"\0"):
        if not record:
            continue
        meta, tab, path = record.partition(b"\t")
        fields = meta.split(b" ")
        if not tab or len(fields) != 3 or fields[1] != b"blob":
            raise GateError(f"the tree of {base[:12]}, the commit that set the order, holds an entry the gate cannot "
                            "compare as a file")
        before[path] = (fields[0], fields[2].decode("ascii", "replace"))
    changed = sorted(p for p in set(before) | set(files) if before.get(p) != files.get(p))
    return [p.decode("utf-8", "surrogateescape") for p in changed]


#: Which reason id a deny of the done check carries for its first open point.
_OPEN_REASON = {"missing": "no_receipt", "unverified": "verification_failed", "red": "not_done",
                "other_selection": "other_selection", "no_state": "not_done", "stale": "stale_receipt",
                "outside_paths": "outside_paths", "no_change": "no_change"}


def done_evaluation(directory: str, deadline: float, receipt_path: str | None = None, environ: dict | None = None,
                    receipt_dir: str | None = None, at_commit: str | None = None, reviewed: bool = False) -> dict:
    """The done check (D26, D28) with what it found: {"verdict", "done", "repo", "commit", "state", "checks",
    "open", "policy", "base", "inside"}. Pass when every check of the done section has a receipt that verifies under
    the declared policy at HEAD, says that every test passed, was run with the check's selection, names HEAD's commit
    and tree and the tree of the working state now, and, for an order with paths, the working state changes at least
    one path the order names and none it does not allow, since the commit that declared the order; inactive (NOT
    MEASURED, no block) where no done check is declared; deny otherwise, naming the first open
    point and the command that closes it. `receipt_path` (one check) and `receipt_dir` (receipts named <id>.json)
    override the declared receipts, for the CI check, whose receipts lie outside the checkout. `at_commit` is the
    check at a pushed commit (owner choice N2 C): the declaration, the policy and the order come from that commit,
    and its tree, read from git, stands in for the working state; the receipts are still read from the working
    tree. A pushed commit without a declaration or a done check gets no done check (inactive). At a commit a receipt
    counts only for a clean run on that commit (git_clean true, review 2026-10-09 F1): a run on a working state that
    differed from it is not a run on the commit, whatever tree ids the receipt names. `reviewed` names the commit in
    the texts as the commit under review (the CI check) instead of a pushed commit."""
    result = {"verdict": None, "done": None, "repo": None, "commit": None, "state": None, "checks": [], "open": [],
              "policy": None, "base": None, "inside": []}
    try:
        return _evaluate_done(result, directory, deadline, receipt_path, environ, receipt_dir, at_commit, reviewed)
    except Exception as exc:
        # What the check had found before it failed, for the Stop hook's count (review 2026-10-09, F6).
        try:
            exc.partial = result  # type: ignore[attr-defined]
        except AttributeError:
            pass
        raise


def _refused(result: dict, verdict: Verdict, ident: str) -> dict:
    """A check that refuses before it reaches the open checks: the verdict, and the same refusal as the one open point,
    so the Stop hook counts it toward max_blocks and writes the blocker like any other (review 2026-10-09, F6)."""
    result["verdict"] = verdict
    result["open"] = [{"id": ident, "status": verdict.reason_id, "failed": verdict.failed,
                       "command": verdict.next_step}]
    return result


def _evaluate_done(result: dict, directory: str, deadline: float, receipt_path: str | None, environ: dict | None,
                   receipt_dir: str | None, at_commit: str | None, reviewed: bool) -> dict:
    environ = os.environ if environ is None else environ
    repo, unreadable = _work_tree(directory, deadline, "--path-format=absolute")
    if unreadable:
        raise GateError(unreadable)   # a read that failed is not "no repository": the end is not freed (R5-1)
    if repo is None:
        result["verdict"] = Verdict("inactive", "NOT MEASURED: not a git repository; no done check applies.",
                                    "no_repository")
        return result
    # The repository is known from here on: a failure after this point, the partial-clone refusal of the HEAD read
    # among them, is counted toward the repeat limit like any other refusal (review round 2 of 2026-10-09, R2-4).
    result["repo"] = repo
    head = _git(repo, "rev-parse", "--verify", "-q", "HEAD^{commit}", deadline=deadline)
    head_commit = head.stdout.decode("ascii", "replace").strip() if head.returncode == 0 else ""
    commit, where, now = head_commit, "HEAD", "the working state now"
    if at_commit is not None:
        pushed = _git(repo, "rev-parse", "--verify", "-q", f"{at_commit}^{{commit}}", deadline=deadline)
        commit = pushed.stdout.decode("ascii", "replace").strip()
        if pushed.returncode != 0 or len(commit) not in _BLOB_HASHES:
            raise GateError(f"git could not name the {'commit under review' if reviewed else 'pushed commit'} "
                            f"{at_commit[:12]}")
        where, now = ((f"the commit under review {commit[:12]}", "the tree of the commit under review") if reviewed
                      else (f"the pushed commit {commit[:12]}", "the tree the push sends"))
    result.update(repo=repo, commit=commit or None)
    raw = _blob(repo, commit, DECLARATION, deadline, MAX_DECLARATION_BYTES) if commit else None
    if raw is None and at_commit is not None:
        result["verdict"] = Verdict("inactive", f"NOT MEASURED: no declaration at {where} ({DECLARATION} is absent "
                                                "there); no done check applies to it.", "nothing_declared", repo=repo,
                                    head=commit)
        return result
    if raw is None:
        if _absent_in_working_tree(repo):
            result["verdict"] = Verdict("inactive", f"NOT MEASURED: no declaration ({DECLARATION} is absent at HEAD "
                                                    "and in the working tree); no done check applies.",
                                        "nothing_declared", repo=repo, head=commit or None)
            return result
        return _refused(result, Verdict("deny", f"NOT MEASURED: {DECLARATION} is in the working tree but not at HEAD.",
                                        "declaration_not_committed", evidence=f"the declaration {DECLARATION}",
                                        failed="the declaration is not committed, so the done check cannot read it "
                                               "from HEAD", next_step=f"commit {DECLARATION}", repo=repo,
                                        head=commit or None), "declaration")
    done = parse_done(raw)
    if done is None:
        result["verdict"] = Verdict("inactive", f"NOT MEASURED: {DECLARATION} at {where} declares no done check.",
                                    "no_done_check", repo=repo, head=commit)
        return result
    result["done"] = done
    checks = done["checks"]
    if receipt_path is not None and len(checks) != 1:
        raise GateError(f"the done check declares {len(checks)} checks; name a folder of receipts with --receipt-dir")
    policy = _blob(repo, commit, done["policy"], deadline, MAX_DECLARATION_BYTES)
    if policy is None:
        return _refused(result, Verdict("deny", f"proofbundle gate: the done policy {done['policy']} is missing at "
                                                f"{where}.", "missing_file", evidence=f"the done policy {done['policy']}",
                                        failed=f"the policy is missing at {where}",
                                        next_step=f"commit the policy {done['policy']} that pins your test key",
                                        repo=repo, head=commit), "policy")
    require_pinned_signer(policy, f"the done policy {done['policy']}")
    result["policy"] = policy
    rows = []
    for check in checks:
        if receipt_path is not None:
            location = receipt_path
        elif receipt_dir is not None:
            location = os.path.join(receipt_dir, check["id"] + ".json")
        else:
            location = os.path.join(repo, *check["receipt"].split("/"))
        command = check_command(check, environ)
        if at_commit is not None and commit != head_commit:  # the receipt must name the pushed commit's tree
            command = f"{_shell_command('git', 'checkout', commit[:12])} && {command}"
        row = {"id": check["id"], "receipt": check["receipt"], "location": location, "status": None, "failed": "",
               "command": command, "content": None, "payload": None}
        try:
            row["content"] = _receipt_bytes(location)
        except GateError as exc:
            row.update(status="unverified", failed=str(exc))
        if row["status"] is None and row["content"] is None:
            shown = check["receipt"] if receipt_path is None and receipt_dir is None else location
            row.update(status="missing", failed=f"no test run left a receipt at {shown}")
        rows.append(row)
    present = [row for row in rows if row["status"] is None]
    if present:
        with tempfile.TemporaryDirectory(prefix="proofbundle-done-") as scratch:
            policy_file = os.path.join(scratch, "policy.json")
            with open(policy_file, "wb") as handle:
                handle.write(policy)
            requests = []
            for n, row in enumerate(present):
                target = os.path.join(scratch, f"receipt-{n}.json")
                with open(target, "wb") as handle:
                    handle.write(row["content"])
                requests.append({"kind": "bundle", "path": target, "policy_path": policy_file})
            answers = verify_items(requests, deadline)
        for row, answer in zip(present, answers):
            exit_code = answer.get("exit_code")
            if answer["is_error"] or not (isinstance(exit_code, int) and not isinstance(exit_code, bool)
                                          and exit_code == 0):
                why = answer.get("error") or f"exit {exit_code!r}: {answer.get('meaning')}"
                row.update(status="unverified", failed=f"it does not verify under the done policy ({why})")
    state = None
    for row, check in zip(rows, checks):
        if row["status"] is not None:
            continue
        row["payload"] = _signed_payload(row["content"])
        try:
            claim = strict_json(row["payload"]) if row["payload"] is not None else None
        except ValueError:
            claim = None
        problem = done_claim_problem(claim)
        if problem is not None:
            row.update(status="red", failed=problem)
            continue
        provenance = claim["provenance"]
        problem = selection_problem(check, provenance)
        if problem is not None:
            row.update(status="other_selection", failed=problem)
            continue
        tested = tested_tree(provenance)
        if tested is None:
            row.update(status="no_state", failed="the receipt names no git state the tests ran on")
            continue
        if state is None:
            state = working_state(repo, deadline) if at_commit is None else commit_state(repo, commit, deadline)
            result["state"] = state
            if state["worktree"] is None:
                result["checks"] = rows
                return _refused(result, _state_not_measured(now, state, repo, commit), "state")
        named = (provenance.get("git_hash"), provenance.get("git_tree"))
        if named != (state["commit"], state["tree"]):
            row.update(status="stale", failed=f"the receipt names commit {str(named[0])[:12]} with tree "
                                              f"{str(named[1])[:12]}, and {where.removesuffix(' ' + commit[:12])} is "
                                              f"commit {state['commit'][:12]} with tree {state['tree'][:12]}")
            continue
        if tested != state["worktree"]:
            row.update(status="stale", failed=f"the tests ran on tree {tested[:12]}, and {now} is "
                                              f"tree {state['worktree'][:12]}")
            continue
        if at_commit is not None and provenance.get("git_clean") is not True:
            row.update(status="stale", failed=f"the receipt says git_clean false: its tests ran on a working state "
                                              f"that differed from commit {state['commit'][:12]}, and at "
                                              f"{where.removesuffix(' ' + commit[:12])} only a clean run on its own "
                                              "tree counts")
            continue
        row.update(status="green", tested=tested, tests=claim["n"])
    result["checks"] = rows
    opened = [{"id": row["id"], "status": row["status"], "failed": row["failed"], "command": row["command"],
               "receipt": row["receipt"]} for row in rows if row["status"] != "green"]
    if done["paths"] is not None:
        # Owner choice Nordstern B: an order that names paths is done only with a change in them since the commit that
        # declared it, for the state the receipts are for; and with none outside them (D28).
        if state is None:
            state = result["state"] = (working_state(repo, deadline) if at_commit is None
                                       else commit_state(repo, commit, deadline))
            if state["worktree"] is None:
                return _refused(result, _state_not_measured(now, state, repo, commit), "state")
        base, why = order_base(repo, commit, done, deadline)
        if base is None:
            return _refused(result, Verdict(
                "deny", f"NOT MEASURED: {why}, so the gate cannot tell whether the work changed the paths the order "
                        "names.", "order_base_not_measured", evidence=f"the history of {DECLARATION}", failed=why,
                next_step="fetch the full history (git fetch --unshallow) and run the checks again, or have a person "
                          "judge the work", repo=repo, head=commit), "paths")
        result["base"] = base
        changed = changed_paths(repo, base, state["files"], deadline)
        named = ", ".join(done["paths"])
        inside = [p for p in changed if any(fnmatch.fnmatchcase(p, pattern) for pattern in done["paths"])]
        outside = [p for p in changed if p not in inside]
        result["inside"] = inside
        if not inside:
            opened.insert(0, {"id": "paths", "status": "no_change",
                              "failed": _short(f"nothing in the paths the order names ({named}) changed in {now} since "
                                               f"{base[:12]}, the commit that declared the order, so the work the "
                                               "order asks for is missing", 400),
                              "command": f"do the work the order asks for in {named}, then run the checks again"})
        if outside:
            shown = ", ".join(outside[:5]) + (f" and {len(outside) - 5} more" if len(outside) > 5 else "")
            opened.append({"id": "paths", "status": "outside_paths",
                           "failed": _short(f"the work changes paths the order does not allow since {base[:12]}: "
                                            f"{shown}", 400),
                           "command": "undo the changes outside the allowed paths, or ask the owner to change the "
                                      "order", "outside": outside})
    result["open"] = opened
    if opened:
        first = opened[0]
        others = [f"{p['id']} ({p['status'].replace('_', ' ')})" for p in opened[1:]]
        failed = f"check {first['id']} is {first['status'].replace('_', ' ')}: {first['failed']}"
        if others:
            failed += "; also open: " + ", ".join(others)
        next_step = first["command"] if first["status"] in ("outside_paths", "no_change") else f"run {first['command']}"
        result["verdict"] = Verdict("deny", f"proofbundle gate: {failed}.", _OPEN_REASON[first["status"]],
                                    evidence=f"the receipt {first['receipt']}" if "receipt" in first
                                    else "the working state", failed=failed, next_step=next_step, repo=repo,
                                    head=commit)
        return result
    tested = rows[0]["tested"]
    names = ", ".join(row["id"] for row in rows)
    result["verdict"] = Verdict(
        "pass", f"proofbundle gate: done. {len(rows)} {'check' if len(rows) == 1 else 'checks'} ({names}): every "
                f"receipt verifies under {done['policy']}, says every one of its tests passed with exit status 0, was "
                f"run with the check's selection, and names commit {commit[:12]} and tree {tested}, {now}"
                + ("" if at_commit is not None else f" ({'clean' if tested == state['tree'] else 'with uncommitted changes'})")
                + (f"; no path outside the order changed since {result['base'][:12]}, the commit that declared it, "
                   f"and {len(result['inside'])} {'path' if len(result['inside']) == 1 else 'paths'} in it did"
                   if result["base"] else "")
                + ". This proves who signed the receipts and which tree they name, not that the tests test anything.",
        "done", repo=repo, head=commit)
    return result


def _state_not_measured(now: str, state: dict, repo: str, commit: str) -> Verdict:
    return Verdict("deny", f"NOT MEASURED: {now} cannot be read as files: {state['problem']}.", "state_not_measured",
                   evidence="the working tree", failed=state["problem"],
                   next_step="remove the cause named here, then run the tests with a receipt", repo=repo, head=commit)


def done_verdict(directory: str, deadline: float, receipt_path: str | None = None,
                 environ: dict | None = None) -> Verdict:
    """The verdict of done_evaluation alone."""
    return done_evaluation(directory, deadline, receipt_path, environ)["verdict"]


def _done_line(verdict: Verdict) -> str:
    """The one line a blocked end shows: the open point and the command that closes it."""
    return (f"proofbundle done check: {verdict.failed.rstrip('.')}. Next: {verdict.next_step.rstrip('.')}. "
            "Never weaken the declaration, the policy or the key to end the session.")


# --- the done check's own files in the evidence folder (D28) -------------------------------------------------------

def _evidence_folder(repo: str, create: bool = False) -> str | None:
    """The repository's .proofbundle folder when it is a real directory (not a link), else None. With create, a folder
    that is absent (nothing at all at its path) is made first, so the done check can count its blocks in a working tree
    from which the folder was removed (review round 3 of 2026-10-09, R3-4); a file or a link there is left as it is."""
    path = os.path.join(repo, EVIDENCE_DIR.rstrip("/"))
    if create:
        try:
            os.mkdir(path, 0o755)
        except OSError:
            pass   # it exists (a directory, a file or a link), or it cannot be made: the check below decides
    try:
        return path if stat.S_ISDIR(os.lstat(path).st_mode) else None
    except OSError:
        return None


def _read_done_file(repo: str, name: str, kind: str) -> dict | None:
    """One of the done check's own files, or None where it is absent, not a regular file, too large, not strict
    JSON or of another schema. Its content is counted, never trusted for a verdict."""
    if _evidence_folder(repo) is None:
        return None
    path = os.path.join(repo, *name.split("/"))
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_STATE_BYTES:
            return None
        doc = strict_json(_read_regular(path, MAX_STATE_BYTES + 1))   # checked again at the descriptor
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) and doc.get("schema") == DONE_FILES_SCHEMA.format(kind) else None


def _done_file_problem(repo: str, name: str, kind: str) -> str | None:
    """Why one of the done check's own files is present but cannot be read back (_read_done_file), None when it is
    absent or readable (review round 4 of 2026-10-09, R4-3: a record the next count cannot read is named, not taken
    for a first block in silence)."""
    path = os.path.join(repo, *name.split("/"))
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return f"{name} cannot be examined ({exc.strerror or exc})"
    if _read_done_file(repo, name, kind) is not None:
        return None
    if not stat.S_ISREG(st.st_mode):
        return f"{name} is not a regular file"
    if st.st_size > MAX_STATE_BYTES:
        return f"{name} is {st.st_size} bytes, more than the {MAX_STATE_BYTES} the hook reads back"
    return f"{name} is not the hook's own record (strict JSON of its schema)"


def _write_done_file(repo: str, name: str, doc: dict) -> str | None:
    """Write one of the done check's own files through a fresh temporary file that replaces it; never through a
    link. None on success, else why not. A document whose bytes exceed MAX_STATE_BYTES is not written: the hook would
    not read it back, so the next count would start again in silence (R4-3)."""
    data = (json.dumps(doc, indent=1, sort_keys=True) + "\n").encode("utf-8", "surrogatepass")
    if len(data) > MAX_STATE_BYTES:
        return f"{name} would be {len(data)} bytes, more than the {MAX_STATE_BYTES} the hook reads back"
    folder = _evidence_folder(repo, create=True)
    if folder is None:
        return f"{EVIDENCE_DIR} is not a directory of the repository"
    target = os.path.join(repo, *name.split("/"))
    temporary = os.path.join(folder, f".{os.path.basename(name)}.{secrets.token_hex(6)}.tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(temporary, target)
    except OSError as exc:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        return f"{name} could not be written: {exc}"
    return None


def _tally(repo: str, **increments) -> None:
    """Add to the local counters in DONE_METRICS (D28, N5): no network, nothing leaves the machine. A file that is
    not the counters' own form is started afresh."""
    metrics = _read_done_file(repo, DONE_METRICS, "metrics")
    if metrics is None or not all(type(metrics.get(k)) is int for k in METRIC_KEYS) \
            or not isinstance(metrics.get("open"), dict):
        metrics = {"schema": DONE_FILES_SCHEMA.format("metrics"), "first": _now(), "open": {},
                   **{k: 0 for k in METRIC_KEYS}}
    opened = increments.pop("open", ())
    for key, value in increments.items():
        metrics[key] += value
    for status in opened:
        metrics["open"][status] = (metrics["open"].get(status) if type(metrics["open"].get(status)) is int else 0) + 1
    metrics["last"] = _now()
    _write_done_file(repo, DONE_METRICS, metrics)


#: The longest session id a blocker names in full; a longer one is named by its sha256 alone (R4-3).
MAX_SESSION_TEXT = 256


def _session_key(event: dict | None) -> str:
    """The sha256 of the host's session id ("" when the event names none): the state file binds the session by this
    fixed-length key, so the record stays within MAX_STATE_BYTES whatever the host sends (review round 4 of
    2026-10-09, R4-3: a session id of 65536 characters made a record of 65684 bytes the next read discarded). Equal
    ids give equal keys and different ids different keys, so the count stays per session."""
    session = event.get("session_id") if isinstance(event, dict) and isinstance(event.get("session_id"), str) else ""
    return hashlib.sha256(session.encode("utf-8", "surrogatepass")).hexdigest()


def _session_text(event: dict | None) -> str | None:
    """The session id for a human reading the blocker, None when it is longer than MAX_SESSION_TEXT."""
    session = event.get("session_id") if isinstance(event, dict) and isinstance(event.get("session_id"), str) else ""
    return session if len(session) <= MAX_SESSION_TEXT else None


_STATE_FIELDS = frozenset({"schema", "session_sha256", "open", "blocks", "blocker"})
#: The form the gate wrote before R4-3, with the session id in clear (f0e25574 and earlier).
_STATE_FIELDS_CLEAR = frozenset({"schema", "session", "open", "blocks", "blocker"})
_SESSION_SHA256 = re.compile(r"[0-9a-f]{64}")


def _done_state(repo: str) -> tuple[dict | None, str | None]:
    """The count record (DONE_STATE) as (record, problem). record carries session_sha256, open, blocks and blocker
    when the file is a running count, problem is None then and where there is no file; (None, why) where a present
    file does not serve as a running count. The schema value alone does not make a record usable: every field is
    checked (review round 5 of 2026-10-09, R5-3: an older gate's record with the session in clear, and blocks "1" as a
    string, both restarted the count without a word). The form the gate wrote before R4-3, with the session id in
    clear, is taken over by the session's sha256, so an update of the plugin continues the count it finds."""
    doc = _read_done_file(repo, DONE_STATE, "state")
    if doc is None:
        return None, _done_file_problem(repo, DONE_STATE, "state")
    fields = frozenset(doc)
    if fields == _STATE_FIELDS_CLEAR and isinstance(doc["session"], str):
        session = hashlib.sha256(doc["session"].encode("utf-8", "surrogatepass")).hexdigest()
    elif fields == _STATE_FIELDS:
        session = doc["session_sha256"]
    else:
        return None, f"{DONE_STATE} carries the fields {', '.join(sorted(fields))}, not those of the hook's count"
    open_points = doc["open"]
    why = ("its session is not a sha256" if not (isinstance(session, str) and _SESSION_SHA256.fullmatch(session))
           else "its open points are not a list of [id, status] pairs"
           if not (isinstance(open_points, list) and all(isinstance(p, list) and len(p) == 2
                                                         and all(isinstance(x, str) for x in p) for p in open_points))
           else "its block count is not a whole number of at least 0"
           if not (type(doc["blocks"]) is int and doc["blocks"] >= 0)
           else "its blocker flag is not true or false" if type(doc["blocker"]) is not bool else None)
    if why is not None:
        return None, f"{DONE_STATE} is not a running count: {why}"
    return {"session_sha256": session, "open": open_points, "blocks": doc["blocks"], "blocker": doc["blocker"]}, None


def _blocker(result: dict, event: dict | None, blocks: int) -> dict:
    """The blocker file: every open point of the last verdict, in its order, with what it found and the command that
    closes it (review 2026-10-09, F5: a missing change in the order's paths was not named, and the paths outside them
    were lost when it came first); the paths the order names, the commit it was compared with, and each check."""
    state = result["state"] or {}
    # A check is "verified" only when it was judged green; one the check stopped before comparing with the state
    # (status None, e.g. a state that could not be measured) is not judged, never verified (R2-5).
    checks = [{"id": row["id"], "status": row["status"],
               "detail": row["failed"] or ("verified" if row["status"] == "green" else
                                           "not judged: the check stopped before it compared this receipt with the "
                                           "state"),
               "command": row["command"]}
              for row in result["checks"]]
    opened = [{"id": p["id"], "status": p["status"], "detail": p["failed"], "command": p["command"],
               **({"outside": p["outside"]} if "outside" in p else {})} for p in result["open"]]
    outside = next((p.get("outside", []) for p in result["open"] if p["status"] == "outside_paths"), [])
    done = result["done"] or {}
    return {"schema": DONE_FILES_SCHEMA.format("blocker"), "verdict": "NOT DONE", "written": _now(),
            "session": _session_text(event), "session_sha256": _session_key(event),
            "blocks_without_progress": blocks - 1, "head": result["commit"],
            "tree": state.get("tree"), "working_tree": state.get("worktree"),
            "clean": (state.get("worktree") == state.get("tree")) if state else None, "open": opened,
            "checks": checks, "paths": done.get("paths"), "order_base": result.get("base"), "outside_paths": outside,
            "text": "NOT DONE. The Stop hook stopped blocking after the same open points stayed open; this file names "
                    "them and the state the gate measured. It is not a receipt and proves nothing about the tests."}


def _account_block(result: dict, event: dict | None, limit: int) -> tuple[str | None, str | None, str | None]:
    """Count one blocked end (D28, N3 and N5) and decide whether to keep blocking. Returns (blocker, problem, unread):
    blocker
    None to block, else the path of the blocker file written instead: after `limit` blocks (the order's max_blocks)
    with the same open points (no progress) in the same session the hook writes the blocker and lets the session end
    without a done verdict. problem names why the count could not be recorded, None when it was: the bounded end then
    cannot take effect, and the block says so instead of depending silently on a file it could not write (review
    round 3 of 2026-10-09, R3-4). The record binds the session by its sha256 and never exceeds the bound it is read
    with; unread names a present record the hook could not read, in which case this block counted as the first and the
    record is written again (R4-3; a record of the right schema that is no running count included, R5-3), None
    otherwise."""
    repo = result["repo"]
    session = _session_key(event)
    signature = [[p["id"], p["status"]] for p in result["open"]]
    previous, unread = _done_state(repo)
    same = previous is not None and previous["session_sha256"] == session and previous["open"] == signature
    blocks = previous["blocks"] + 1 if same else 1
    statuses = [p["status"] for p in result["open"]]
    if blocks > limit:
        first = not (same and previous["blocker"] is True)
        # Every stop past the limit writes the blocker from the verdict it reached, so the file the message names
        # exists and shows the state last measured: the open points can keep their ids and statuses while the paths
        # and the tree change, and a deleted blocker is written again (review round 2 of 2026-10-09, R2-5). The
        # counter of blockers counts it once.
        problem = _write_done_file(repo, DONE_BLOCKER, _blocker(result, event, blocks))
        if problem is not None:
            _tally(repo, blocked=1, missing_checks=statuses.count("missing"), open=statuses)
            counted = _write_done_file(repo, DONE_STATE, {"schema": DONE_FILES_SCHEMA.format("state"),
                                                          "session_sha256": session, "open": signature,
                                                          "blocks": blocks, "blocker": False})
            return None, (f"the blocker could not be written ({problem})"
                          + ("" if counted is None else f", nor the block count ({counted})")), unread
        if first:
            _tally(repo, blockers=1)
        # The end stands once the blocker is written; a count the hook could not record is named in the end's message,
        # never dropped: the next stop reads the record from before this end (review round 7 of 2026-10-10, R7-5)
        counted = _write_done_file(repo, DONE_STATE, {"schema": DONE_FILES_SCHEMA.format("state"),
                                                      "session_sha256": session, "open": signature, "blocks": blocks,
                                                      "blocker": True})
        return DONE_BLOCKER, (None if counted is None else f"the end could not be recorded in the count ({counted})"), \
            unread
    _tally(repo, blocked=1, missing_checks=statuses.count("missing"), open=statuses)
    problem = _write_done_file(repo, DONE_STATE, {"schema": DONE_FILES_SCHEMA.format("state"), "session_sha256": session,
                                                  "open": signature, "blocks": blocks, "blocker": False})
    return None, (None if problem is None else f"the block count could not be recorded ({problem})"), unread


def _account_pass(result: dict, event: dict | None) -> tuple[str | None, str | None, str | None]:
    """Count a done verdict, and a completion after at least one block in the same session; the blocker of an
    earlier stop no longer stands and is removed. Returns (problem, removal, unread): problem names why the reset count
    could not be written, removal why the earlier blocker could not be removed, unread a present record the hook could
    not read (replaced only where problem is None), None where there is none. A done end names each like a refused one
    (review round 6 of 2026-10-10, R6-4: the record's problem was read here and dropped, so a record with blocks "1" was
    written over without a word, against R5-3). The three stay apart (review round 8 of 2026-10-10, R8-4: a removal that
    failed was reported as a count that could not be recorded, while the record held a valid count, and the note on the
    replaced unread record was dropped)."""
    repo = result["repo"]
    session = _session_key(event)
    previous, unread = _done_state(repo)
    after_block = previous is not None and previous["session_sha256"] == session and previous["blocks"] >= 1
    _tally(repo, done=1, completed_after_block=1 if after_block else 0)
    problem = _write_done_file(repo, DONE_STATE, {"schema": DONE_FILES_SCHEMA.format("state"), "session_sha256": session,
                                                  "open": [], "blocks": 0, "blocker": False})
    blocker = os.path.join(repo, *DONE_BLOCKER.split("/"))
    removed = None
    try:
        if stat.S_ISREG(os.lstat(blocker).st_mode):
            os.unlink(blocker)
    except FileNotFoundError:
        pass
    except OSError as exc:   # the earlier NOT DONE would stand beside this done end: named, not dropped (R7-5 class)
        removed = f"the earlier blocker {DONE_BLOCKER} could not be removed ({exc})"
    return (None if problem is None else f"the count could not be reset ({problem})"), removed, unread


def _hook_event(argv: list[str], name: str) -> tuple[str, dict]:
    host = _host(argv)
    try:
        event = strict_json(sys.stdin.read())
    except ValueError as exc:
        raise GateError(f"the hook input is not JSON ({exc})") from exc
    if not isinstance(event, dict) or event.get("hook_event_name") != name:
        raise GateError(f"the hook input is not a {name} event")
    return host, event


def _event_directory(event: dict) -> str:
    cwd = event.get("cwd")
    return cwd if isinstance(cwd, str) and os.path.isabs(cwd) else os.getcwd()


def stop_command(argv: list[str]) -> int:
    """The Stop hook (D26, D28), the same for Claude Code and Codex. Prints a block with one line, a message for a
    pass, nothing where no done check is declared; exits 0. It never sets continue: a block asks the host to go on
    working (Codex inserts the reason as a new turn), it never stops the host. Any failure inside the check blocks:
    the session does not end on a check that reached no verdict. After max_blocks blocks without progress it writes
    DONE_BLOCKER and stops blocking (N3). Claude Code overrides a Stop hook after eight continuations without a tool
    call in between (documented; nine blocks measured with Claude Code 2.1.294), which is why the hard boundary is
    the CI check (README)."""
    deadline = time.monotonic() + DEADLINE_SECONDS
    host, event, result = "claude", None, None
    try:
        host, event = _hook_event(argv, "Stop")
        result = done_evaluation(_event_directory(event), deadline)
        verdict = result["verdict"]
    except GateError as exc:
        verdict = Verdict("deny", f"proofbundle gate: {exc}.", "gate_error", evidence="the done check",
                          failed=f"the check reached no verdict ({exc})", next_step="fix the cause named here")
        result = _failed_check(exc, verdict)
    except Exception as exc:  # noqa: BLE001 - any failure inside the check blocks, it never lets the end through
        verdict = Verdict("deny", f"proofbundle gate: internal error {type(exc).__name__}: {exc}.", "internal_error",
                          evidence="the done check", failed=f"internal error {type(exc).__name__}: {exc}",
                          next_step="report this error")
        result = _failed_check(exc, verdict)
    blocker, counting, unread, removal = None, None, None, None
    # Every refusal counts toward the limit, a check that refused early or failed included (review 2026-10-09, F6);
    # where no order could be read, the default limit applies.
    limit = result["done"]["max_blocks"] if result is not None and result["done"] is not None else DEFAULT_MAX_BLOCKS
    try:
        if result is not None and result["repo"] and result["open"] and verdict.decision == "deny":
            blocker, counting, unread = _account_block(result, event, limit)
        elif result is not None and result["done"] is not None and verdict.decision == "pass":
            counting, removal, unread = _account_pass(result, event)
    except Exception as exc:  # noqa: BLE001 - counting never changes the answer, but a failed count is named (R3-4)
        blocker, counting = None, f"counting failed ({type(exc).__name__}: {exc})"
    try:
        write_log(log_entry(host, event, Outcome(verdict.decision, verdict.text(), [verdict]), ["Stop"]), host)
    except Exception:  # noqa: BLE001 - the log never changes the answer
        pass
    if verdict.decision == "pass":
        # Each failure of the hook's own files is named for what it is, and only one that happened (R8-4)
        message = verdict.detail
        if counting is not None:
            message += f" The hook could not record this end in its count: {counting}."
        if unread is not None:
            message += (f" The earlier count could not be read ({unread}); "
                        + ("the hook wrote its own record in its place." if counting is None
                           else "it stays in place, since the hook could not write its own record."))
        if removal is not None:
            message += f" {removal[0].upper()}{removal[1:]}; this done end stands, and the blocker file is out of date."
        sys.stdout.write(json.dumps({"systemMessage": message}) + "\n")
    elif blocker is not None:
        message = (f"proofbundle done check: NOT DONE. The same open points stayed open through {limit} "
                   f"blocks, so the hook stops blocking and the session ends without a done verdict. The open points "
                   f"and the state the gate measured are in {blocker}. Open: {verdict.failed.rstrip('.')}.")
        if counting is not None:   # an unread record never reaches here: it makes this block the first (R4-3)
            message += (f" The hook could not record this end in its count: {counting}; the next stop reads the record "
                        "from before it.")
        sys.stdout.write(json.dumps({"systemMessage": message}) + "\n")
    elif verdict.decision != "inactive":
        line = _done_line(verdict)
        if counting is not None and verdict.decision == "deny":
            line += (f" The hook could not count this block: {counting}, so the end after {limit} blocks without "
                     f"progress cannot take effect; make {EVIDENCE_DIR} a directory of the repository that the hook "
                     "can write.")
        elif unread is not None and verdict.decision == "deny":
            line += (f" The hook counted this block as the first: the earlier count could not be read ({unread}); "
                     f"its own record is written again, so the end after {limit} blocks without progress counts from "
                     "here.")
        sys.stdout.write(json.dumps({"decision": "block", "reason": line, "systemMessage": line}) + "\n")
    return 0


def _failed_check(exc: Exception, verdict: Verdict) -> dict | None:
    """The result the check had reached when it failed (done_evaluation attaches it), with the failure as its one open
    point, so a check that fails the same way at every stop is counted like any other refusal; None when the failure
    came before the repository was known."""
    partial = getattr(exc, "partial", None)
    if not isinstance(partial, dict) or not partial.get("repo"):
        return None
    partial["verdict"] = verdict
    partial["open"] = [{"id": "done-check", "status": verdict.reason_id, "failed": verdict.failed,
                        "command": verdict.next_step}]
    return partial


def task_completed_command(argv: list[str]) -> int:
    """The TaskCompleted hook of Claude Code (D28): the same check as the Stop hook. Prints the one line on stdout
    when the task must stay open, nothing when it may be marked completed, and exits 0 either way; the hook command
    in hooks.json turns a printed line into exit 2 with the line on stderr, and any other exit into exit 2 with its
    own line. Python itself exits 2 when it cannot open the gate (measured), so exit 2 cannot be the gate's own
    signal. Any failure inside the check keeps the task open. Codex has no such event."""
    deadline = time.monotonic() + DEADLINE_SECONDS
    result = None
    try:
        _host_name, event = _hook_event(argv, "TaskCompleted")
        result = done_evaluation(_event_directory(event), deadline)
        verdict = result["verdict"]
    except GateError as exc:
        verdict = Verdict("deny", f"proofbundle gate: {exc}.", "gate_error", evidence="the done check",
                          failed=f"the check reached no verdict ({exc})", next_step="fix the cause named here")
    except Exception as exc:  # noqa: BLE001 - any failure inside the check keeps the task open
        verdict = Verdict("deny", f"proofbundle gate: internal error {type(exc).__name__}: {exc}.", "internal_error",
                          evidence="the done check", failed=f"internal error {type(exc).__name__}: {exc}",
                          next_step="report this error")
    if verdict.decision != "deny":
        return 0
    try:
        if result is not None and result["done"] is not None:
            _tally(result["repo"], task_blocked=1)
    except Exception:  # noqa: BLE001 - counting never changes the answer
        pass
    sys.stdout.write(_done_line(verdict) + "\n")
    return 0


DONE_CHECK_USAGE = "usage: done-check --repo DIR [--receipt FILE | --receipt-dir DIR] [--at-commit REV]"


def done_check_command(argv: list[str]) -> int:
    """The done check in CI (D26, Teil 3): exit 0 only for a pass; every NOT MEASURED, every deny and a repository
    that declares no done check exit 1; a wrong call exits 2. `--at-commit REV` checks that commit as the commit under
    review: its declaration, policy and order, its tree in place of the working state, and only a clean run on it
    (review 2026-10-09 F1). The CI job names the commit it checked out, from the event, never HEAD, which the test
    command can move."""
    options, i = {"--repo": None, "--receipt": None, "--receipt-dir": None, "--at-commit": None}, 0
    while i < len(argv):
        if argv[i] in options and i + 1 < len(argv) and options[argv[i]] is None:
            options[argv[i]], i = argv[i + 1], i + 2
        else:
            print(f"{DONE_CHECK_USAGE}; unexpected {argv[i]!r}", file=sys.stderr)
            return 2
    if not options["--repo"] or options["--receipt"] == "" or options["--receipt-dir"] == "" or \
            options["--at-commit"] == "" or (options["--receipt"] is not None and options["--receipt-dir"] is not None):
        print(DONE_CHECK_USAGE, file=sys.stderr)
        return 2
    deadline = time.monotonic() + DEADLINE_SECONDS
    try:
        verdict = done_evaluation(options["--repo"], deadline, options["--receipt"],
                                  receipt_dir=options["--receipt-dir"], at_commit=options["--at-commit"],
                                  reviewed=options["--at-commit"] is not None)["verdict"]
    except GateError as exc:
        verdict = Verdict("deny", f"proofbundle gate: {exc}.", "gate_error", evidence="the done check",
                          failed=str(exc), next_step="fix the cause named here")
    code = 0 if verdict.decision == "pass" else 1
    report = {"exit_code": code, "verdict": verdict.decision, "reason_id": verdict.reason_id, "repo": verdict.repo,
              "head": verdict.head, "message": verdict.text(), "gate_version": GATE_VERSION}
    sys.stdout.write(json.dumps(report, indent=1) + "\n")
    print(("proofbundle done check passed: " if code == 0 else "proofbundle done check FAILED: ") + verdict.text(),
          file=sys.stderr)
    return code


# --- the done check as an in-toto Statement (D29) ------------------------------------------------------------------

INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
VSA_PREDICATE_TYPE = "https://slsa.dev/verification_summary/v1"
#: The verifier of the Verification Summary, a URI that names the plugin's done check; a consumer accepts only the
#: (signer, verifier) pairs it trusts (SLSA VSA v1.2, verifier).
VSA_VERIFIER_ID = "https://github.com/b7n0de/proofbundle/tree/main/plugins/proofbundle#done-check"
PINNED_PROOFBUNDLE = "6.1.0"
_RESOURCE_URI = re.compile(r"[a-z][a-z0-9+.-]*:[!-~]+")
_SIGN_TOOL = """# /// script
# requires-python = ">=3.10"
# dependencies = ["proofbundle==6.1.0"]
# ///
import hashlib, json, sys
from proofbundle.dsse import sign_envelope
from proofbundle.emit import load_signer
signer = load_signer(sys.argv[1])
with open(sys.argv[2], "rb") as handle:
    body = handle.read()
keyid = hashlib.sha256(signer.public_key().public_bytes_raw()).hexdigest()
print(json.dumps(sign_envelope(body, signer, payload_type="application/vnd.in-toto+json", keyid=keyid)))
"""


def verification_summary(result: dict, resource_uri: str, time_verified: str) -> dict:
    """The in-toto Statement v1 with the SLSA Verification Summary v1 predicate for a passing done check on a clean
    state, built as draft-gruszka-evaluation-receipt-mappings Section 4.3 cites a receipt: the subject is HEAD by
    gitCommit and gitTree, each receipt the check verified is an inputAttestation named by SHA-256 over its signed
    payload bytes B, in the order of the declared checks, and verificationResult is the done check's result, not a
    receipt's own passed. An inputAttestation carries the digest alone: the VSA v1 binding of in-toto-attestation
    0.9.3 reads only uri and digest there and refuses any other field (measured 2026-10-08), and a receipt has no
    URI to fetch it from."""
    done, state = result["done"], result["state"]
    policy = result["policy"]
    blob = _BLOB_HASHES[len(result["commit"])](b"blob %d\0" % len(policy) + policy).hexdigest()
    inputs = [{"digest": {"sha256": hashlib.sha256(row["payload"]).hexdigest()}} for row in result["checks"]]
    return {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [{"name": resource_uri, "digest": {"gitCommit": state["commit"], "gitTree": state["tree"]}}],
        "predicateType": VSA_PREDICATE_TYPE,
        "predicate": {
            "verifier": {"id": VSA_VERIFIER_ID, "version": {"proofbundle-plugin": GATE_VERSION,
                                                            "proofbundle": PINNED_PROOFBUNDLE}},
            "timeVerified": time_verified,
            "resourceUri": resource_uri,
            "policy": {"uri": f"{resource_uri}@{state['commit']}#{done['policy']}",
                       "digest": {"sha256": hashlib.sha256(policy).hexdigest(), "gitBlob": blob}},
            "inputAttestations": inputs,
            "verificationResult": "PASSED",
            "verifiedLevels": ["SLSA_SOURCE_LEVEL_UNEVALUATED"],
            "slsaVersion": "1.2",
        },
    }


def _resource_uri(value: str) -> str:
    if not _RESOURCE_URI.fullmatch(value) or len(value) > 2048:
        raise GateError("--resource-uri must be an absolute URI without spaces, for example "
                        "git+https://github.com/<owner>/<repo>")
    if "//" in value:
        authority = value.split("//", 1)[1].split("/", 1)[0]
        if "@" in authority:
            raise GateError("--resource-uri must not carry user information (a name or token before @)")
    return value


def done_statement(directory: str, key: str, out: str, resource_uri: str, deadline: float,
                   receipt_dir: str | None = None) -> str:
    """Write the done check's Verification Summary as a DSSE envelope (D29): only for a pass on a clean state, signed
    with the key file through the pinned package. Refuses an output that is a link or not a regular file."""
    resource_uri = _resource_uri(resource_uri)
    if not os.path.isabs(key):
        raise GateError("--key must be an absolute path to a key file outside the repository")
    result = done_evaluation(directory, deadline, receipt_dir=receipt_dir)
    verdict = result["verdict"]
    if verdict.decision != "pass":
        raise GateError(f"the done check does not pass, so there is no statement: {verdict.text()}")
    if result["state"]["worktree"] != result["state"]["tree"]:
        raise GateError("the working state differs from HEAD; the statement names a commit and its tree, so commit "
                        "the work and run the checks again")
    body = json.dumps(verification_summary(result, resource_uri, _now()), sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    try:
        st = os.lstat(out)
        if not stat.S_ISREG(st.st_mode):
            raise GateError(f"{out} exists and is not a regular file")
    except FileNotFoundError:
        pass
    uv = shutil.which("uv")
    if uv is None:
        raise GateError("uv is not on PATH, so the statement cannot be signed with the package")
    with tempfile.TemporaryDirectory(prefix="proofbundle-statement-") as scratch:
        tool, payload = os.path.join(scratch, "sign_tool.py"), os.path.join(scratch, "statement.json")
        with open(tool, "w", encoding="utf-8") as handle:
            handle.write(_SIGN_TOOL)
        with open(payload, "wb") as handle:
            handle.write(body)
        left = deadline - time.monotonic()
        proc = subprocess.run([uv, "run", "--quiet", "--no-config", "--script", tool, key, payload], cwd=scratch,
                              env=_isolated_env(), capture_output=True, text=True, timeout=max(left, 1), check=False)
    try:
        envelope = strict_json(proc.stdout) if proc.returncode == 0 else None
        ok = (isinstance(envelope, dict) and envelope.get("payloadType") == INTOTO_PAYLOAD_TYPE
              and base64.b64decode(envelope.get("payload", ""), validate=True) == body
              and isinstance(envelope.get("signatures"), list) and len(envelope["signatures"]) == 1)
    except (ValueError, binascii.Error, TypeError):
        ok = False
    if not ok:
        raise GateError(f"the package could not sign the statement with {key}: {proc.stderr.strip()[:300]}")
    with open(out, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(envelope, indent=1) + "\n")
    return (f"proofbundle done statement written to {out}: an in-toto Statement v1 with the SLSA Verification Summary "
            f"v1 predicate, subject {resource_uri} at commit {result['commit'][:12]}, {len(result['checks'])} "
            "receipts cited by the SHA-256 of their signed payload, signed with the key in DSSE. It states what the "
            "done check verified, not that the tests test anything.")


DONE_STATEMENT_USAGE = ("usage: done-statement --repo DIR --key FILE --out FILE --resource-uri URI "
                        "[--receipt-dir DIR]")


def done_statement_command(argv: list[str]) -> int:
    options, i = {"--repo": None, "--key": None, "--out": None, "--resource-uri": None, "--receipt-dir": None}, 0
    while i < len(argv):
        if argv[i] in options and i + 1 < len(argv) and options[argv[i]] is None:
            options[argv[i]], i = argv[i + 1], i + 2
        else:
            print(f"{DONE_STATEMENT_USAGE}; unexpected {argv[i]!r}", file=sys.stderr)
            return 2
    if not all(options[k] for k in ("--repo", "--key", "--out", "--resource-uri")) or options["--receipt-dir"] == "":
        print(DONE_STATEMENT_USAGE, file=sys.stderr)
        return 2
    try:
        print(done_statement(options["--repo"], options["--key"], options["--out"], options["--resource-uri"],
                             time.monotonic() + DEADLINE_SECONDS, options["--receipt-dir"]))
    except (GateError, OSError) as exc:
        print(f"proofbundle done-statement: {exc}", file=sys.stderr)
        return 1
    return 0


_KEY_TOOL = """# /// script
# requires-python = ">=3.10"
# dependencies = ["proofbundle==6.1.0"]
# ///
import base64, os, sys
from proofbundle.emit import generate_signer, load_signer, save_signer
path = sys.argv[1]
if not os.path.exists(path):
    save_signer(generate_signer(), path)
print(base64.b64encode(load_signer(path).public_key().public_bytes_raw()).decode("ascii"))
"""
DONE_INIT_USAGE = "usage: done-init --repo DIR [--key FILE]"


def done_init(directory: str, key_path: str | None, deadline: float, environ: dict | None = None) -> str:
    """Set up the done check in a repository (D26): a test key with the package's own key path (a 32-byte seed
    file, PROOFBUNDLE_KEY), a policy that pins it, the done section of the declaration and an ignore rule for the
    receipt, all staged. Writes nothing it has not named; refuses a repository that already declares a done
    check. The key is a local test key, never a release key."""
    environ = os.environ if environ is None else environ
    repo, unreadable = _work_tree(directory, deadline, "--path-format=absolute")
    if repo is None:
        raise GateError(unreadable or f"{directory} is not a git repository")
    if key_path is None:
        gate_dir = _gate_dir(environ)
        if gate_dir is None:
            raise GateError("no gate directory is known; name the key file with --key")
        os.makedirs(gate_dir, mode=0o700, exist_ok=True)
        key_path = os.path.join(gate_dir, DONE_KEY_FILE)
    if not os.path.isabs(key_path):
        raise GateError("--key must be an absolute path outside the repository")
    declaration = os.path.join(repo, *DECLARATION.split("/"))
    if os.path.lexists(declaration):
        try:
            raw = _read_regular(declaration, MAX_DECLARATION_BYTES + 1, follow=True)   # R18-2 class
        except _NotRegular as exc:
            raise GateError(f"{DECLARATION} is not a regular file") from exc
        parse_declaration(raw)
        doc = strict_json(raw)
        if "done" in doc:
            raise GateError(f"{DECLARATION} already declares a done check; change it in a reviewed commit")
    else:
        doc = {"schema": DECLARATION_SCHEMA, "evidence": []}
    doc["done"] = {"receipt": DONE_RECEIPT, "policy": DONE_POLICY}
    uv = shutil.which("uv")
    if uv is None:
        raise GateError("uv is not on PATH, so the key cannot be made with the package")
    with tempfile.TemporaryDirectory(prefix="proofbundle-key-") as scratch:
        tool = os.path.join(scratch, "key_tool.py")
        with open(tool, "w", encoding="utf-8") as handle:
            handle.write(_KEY_TOOL)
        left = deadline - time.monotonic()
        proc = subprocess.run([uv, "run", "--quiet", "--no-config", "--script", tool, key_path], cwd=scratch,
                              env=_isolated_env(), capture_output=True, text=True, timeout=max(left, 1), check=False)
    public = proc.stdout.strip()
    try:
        ok = proc.returncode == 0 and len(base64.b64decode(public, validate=True)) == 32
    except (binascii.Error, ValueError):
        ok = False
    if not ok:
        raise GateError(f"the package could not make or read the key {key_path}: {proc.stderr.strip()[:300]}")
    policy = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "local/done-check",
              "allowed_issuers": [{"public_key_b64": public}], "signature": {"require_expected_signer": True}}
    policy_file = os.path.join(repo, *DONE_POLICY.split("/"))
    if os.path.lexists(policy_file):
        raise GateError(f"{DONE_POLICY} exists already; remove it or set the done check up by hand")
    # Read before anything is written, and never waited on (the class of R18-2: a FIFO as .gitignore had blocked
    # done-init after it had written the policy and the declaration).
    ignore = os.path.join(repo, ".proofbundle", ".gitignore")
    try:
        existing = (_read_regular(ignore, -1, follow=True).decode("utf-8").splitlines()
                    if os.path.lexists(ignore) else [])
    except _NotRegular as exc:
        raise GateError(".proofbundle/.gitignore is not a regular file") from exc
    os.makedirs(os.path.dirname(declaration), exist_ok=True)
    with open(policy_file, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(policy, indent=2) + "\n")
    with open(declaration, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(doc, indent=2) + "\n")
    missing =[name.split("/", 1)[1] for name in (DONE_RECEIPT, *DONE_OWN_FILES) if name.split("/", 1)[1] not in existing]
    missing += [] if "receipts/" in existing else ["receipts/"]
    if missing:
        with open(ignore, "a", encoding="utf-8") as handle:
            handle.write("".join(line + "\n" for line in missing))
    staged = _git(repo, "add", "--", DECLARATION, DONE_POLICY, ".proofbundle/.gitignore", deadline=deadline)
    if staged.returncode != 0:
        raise GateError("git could not stage the done check")
    return (f"proofbundle done check set up in {repo}: test key {key_path} (a local test key, never a release key), "
            f"{DONE_POLICY} pins it, {DECLARATION} declares the done check, .proofbundle/.gitignore keeps the receipt "
            f"and the done check's own files out of the tree. Staged. Next: git commit -m \"declare the done check\"; then the tests run with a "
            f"receipt: {check_command(_done_section(doc['done'])['checks'][0], dict(environ, PROOFBUNDLE_KEY=key_path))}")


def done_init_command(argv: list[str]) -> int:
    options, i = {"--repo": None, "--key": None}, 0
    while i < len(argv):
        if argv[i] in options and i + 1 < len(argv) and options[argv[i]] is None:
            options[argv[i]], i = argv[i + 1], i + 2
        else:
            print(f"{DONE_INIT_USAGE}; unexpected {argv[i]!r}", file=sys.stderr)
            return 2
    if not options["--repo"]:
        print(DONE_INIT_USAGE, file=sys.stderr)
        return 2
    try:
        print(done_init(options["--repo"], options["--key"], time.monotonic() + DEADLINE_SECONDS))
    except (GateError, OSError) as exc:
        print(f"proofbundle done-init: {exc}", file=sys.stderr)
        return 1
    return 0


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
        found = ("declares only a done check, no evidence," if verdict.reason_id == "done_only" else "is absent")
        verdict = Verdict("deny", f"proofbundle gate: the workflow requires a declaration, and {DECLARATION} {found} "
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
            data = _read_regular(full, -1)   # checked again at the descriptor (R18-2 class)
        hasher = _BLOB_HASHES[len(oid)](b"blob %d\0" % len(data))
        hasher.update(data)
        if hasher.hexdigest() != oid:
            return (f"{shown} in the working tree differs from the committed bytes (a local change, or a "
                    "checkout filter, line-ending or encoding rule the gate does not model)")
    with tempfile.TemporaryDirectory(prefix="proofbundle-untracked-") as scratch:
        os.mkdir(os.path.join(scratch, "hooks"))
        env = dict(_read_env(repo), GIT_INDEX_FILE=os.path.join(scratch, "no-index"))
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
        data = _read_regular(path, MAX_REPORT_BYTES + 1, follow=True)   # R18-2 class: a FIFO is never waited on
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
    """The sha256 of the regular file at `path`, a link followed; _NotRegular for any other entry (R18-2 class)."""
    return hashlib.sha256(_read_regular(path, -1, follow=True)).hexdigest()


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
        repo, unreadable = _work_tree(directory, deadline)
        if repo is None:
            return refuse("not_a_work_tree", unreadable or f"{directory} is not inside a git work tree")
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
            # The check process starts in the work tree, and a relative GIT_DIR or GIT_WORK_TREE of the host would name
            # another repository or tree from there than the one compared above: it gets the values git resolved in the
            # call's directory (_pins), and none of the other settings of the gate's own reads (review round 8 of
            # 2026-10-10, R8-1; measured with git 2.43.0 and 2.51.1: GIT_WORK_TREE=repo given in P made the test read
            # P/repo/repo while the statement named P/repo).
            check_env = dict(os.environ, **(getattr(repo, "pins", None) or {}), PYTHONDONTWRITEBYTECODE="1")
            try:
                proc = subprocess.Popen(argv, cwd=repo, env=check_env,
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
    """PROTOTYPE git pre-push hook entry (DECISIONS.md, D24; installed only by install-pre-push, D24B). git runs a
    pre-push hook as `hook <remote-name> <remote-url>` with one `<local_ref> <local_sha> <remote_ref>
    <remote_sha>` line per ref on stdin, in the repository being pushed. This reaches a verdict from those
    lines alone and denies the push (exit 1) when the evidence does not verify, whatever shell form launched
    the push. The two positional arguments, the remote's name and the push URL (measured with git 2.34.1: a pushurl
    and an insteadOf rewrite applied), are compared with a hand-over of Level 1 where there is one (D33)."""
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
        verdict = pre_push_verdict(os.getcwd(), lines, deadline, argv[0] if argv else None,
                                   argv[1] if len(argv) > 1 else None)
    except GateError as exc:
        sys.stderr.write(f"proofbundle pre-push (prototype): {exc}. The push is denied.\n")
        return 1
    sys.stderr.write(verdict.text() + "\n")
    # Point 1 (review Runde 5): exit 0 only for pass and a measured inactive; ask, unknown states, measurement
    # errors and any exception all block (exit 1). A rule change stays blocked; there is no release switch in
    # an environment the model can write or run (D24).
    return 0 if verdict.decision in ("pass", "inactive") else 1


# --- install-pre-push: Level 2 into the repository where the user asks for it (owner choice K5-D C, D24B) -----------

INSTALL_USAGE = "usage: install-pre-push [--repo DIR]"
#: The line that marks a pre-push hook this command wrote; a hook without it is someone else's and is never replaced.
PRE_PUSH_MARK = "# proofbundle-pre-push-wrapper 1"
#: Environment names that move the repository away from the one the command is called in. A core.hooksPath given in
#: the environment (GIT_CONFIG_COUNT, GIT_CONFIG_PARAMETERS) shows up in the `command` scope and is refused there.
_INSTALL_MOVED_BY = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR")
#: Run by the wrapper at each push with the recorded plugin root: the gate of that root, or, when the root is a
#: version folder of an installed plugin (`…/proofbundle/<version>`), the gate of the newest version folder beside
#: it, so a plugin update needs no new install. Prints nothing when it finds none. No single quote may appear here.
_PRE_PUSH_RESOLVER = """import os, re, sys
root = sys.argv[1]
version = re.compile(r"[0-9]+([.][0-9]+)*")
def gate(folder):
    path = os.path.join(folder, "hooks", "proofbundle_gate.py")
    return path if os.path.isfile(path) and not os.path.islink(path) else None
family, name = os.path.split(root)
found = None
if version.fullmatch(name) and os.path.basename(family) == "proofbundle":
    best = None
    for entry in (os.listdir(family) if os.path.isdir(family) else []):
        if version.fullmatch(entry) and gate(os.path.join(family, entry)):
            key = tuple(int(part) for part in entry.split("."))
            best = max(best, (key, entry)) if best else (key, entry)
    found = gate(os.path.join(family, best[1])) if best else None
else:
    found = gate(root)
print(found or "")
"""


def _sh_quote(text: str) -> str:
    return "'" + text.replace("'", "'\\''") + "'"


def pre_push_wrapper(plugin_root: str) -> str:
    """The fixed pre-push hook install-pre-push writes: it records the plugin root it was installed from, finds the
    gate at each push (_PRE_PUSH_RESOLVER) and runs it as `pre-push` with git's arguments and ref lines. When it finds
    no gate it denies the push (exit 1); so does a failed python3."""
    assert "'" not in _PRE_PUSH_RESOLVER
    return (f"#!/bin/sh\n{PRE_PUSH_MARK} (install-pre-push, DECISIONS.md D24B)\n"
            "# Written on request by proofbundle_gate.py install-pre-push, which alone replaces it. It finds the\n"
            "# plugin's gate at each push and denies the push (exit 1) when it finds none.\n"
            f"root={_sh_quote(plugin_root)}\n"
            f"gate=$(python3 -I -c '{_PRE_PUSH_RESOLVER}' \"$root\") || gate=\"\"\n"
            'if [ -z "$gate" ]; then\n'
            '  echo "proofbundle pre-push: no proofbundle plugin gate found at $root or in a newer version beside'
            ' it, so the push is denied. Run install-pre-push again from the installed plugin, or remove $0." >&2\n'
            "  exit 1\n"
            "fi\n"
            'exec python3 -I "$gate" pre-push "$@"\n')


def _inside(path: str, folders: list[str]) -> bool:
    real = os.path.realpath(path)
    return any(os.path.commonpath([real, os.path.realpath(f)]) == os.path.realpath(f) for f in folders if f)


def install_pre_push(directory: str, deadline: float, environ: dict | None = None,
                     plugin_root: str | None = None) -> str:
    """Write the pre-push wrapper into the hook folder git uses for the repository at directory (owner choice K5-D C,
    D24B), and nowhere else: the repository's own `.git/hooks`, or a `core.hooksPath` set in its local or worktree
    configuration that points inside the repository. Sets no configuration, local or global. Refuses a hook folder
    set in any other scope, one outside the repository, an environment that moves the repository, and an existing
    pre-push hook it did not write, which it names and leaves as it is. Runs only when the user calls it."""
    environ = os.environ if environ is None else environ
    moved = [name for name in _INSTALL_MOVED_BY if environ.get(name)]
    if moved:
        raise GateError(f"{', '.join(moved)} is set, which moves the repository away from {directory}; run "
                        "install-pre-push without it")
    plugin_root = plugin_root or os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    if any(ord(c) < 32 for c in plugin_root):
        raise GateError("the plugin folder's path holds a control character, so no hook can name it safely")
    paths, why = _repo_paths(directory, deadline)
    if paths is None:
        raise GateError(f"git cannot tell the hook folder of {directory}: {why}")
    if paths["toplevel"] is None:
        raise GateError(f"{directory} is not the working tree of a git repository")
    entries, why = _config_entries(paths["toplevel"], deadline)
    if entries is None:
        raise GateError(f"git cannot read the configuration of {paths['toplevel']}: {why}")
    for scope, origin, key, _value in entries:
        if key == "core.hookspath" and scope not in ("local", "worktree"):
            raise GateError(f"core.hooksPath is set in the {scope} configuration ({origin}), so a hook there would act "
                            "beyond this repository; install-pre-push writes only into this repository's own hook "
                            "folder and never changes that setting")
    folder = paths["hooks"]
    if not _inside(folder, [paths["toplevel"], paths["common"]]):
        raise GateError(f"the local core.hooksPath of this repository points outside it ({folder}); install-pre-push "
                        "writes only inside the repository")
    hook = os.path.join(folder, "pre-push")
    if os.path.lexists(hook):
        ours = False
        if os.path.isfile(hook) and not os.path.islink(hook):
            try:
                lines = _read_regular(hook, 4096).splitlines()   # checked again at the descriptor (R18-2 class)
            except _NotRegular:
                lines = []
            ours = len(lines) > 1 and lines[1].startswith(PRE_PUSH_MARK.encode())
        if not ours:
            raise GateError(f"a pre-push hook that install-pre-push did not write exists at {hook}; it is left as it "
                            "is. Merge the proofbundle call into it by hand, or move it away and run "
                            "install-pre-push again")
    os.makedirs(folder, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".pre-push.", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(pre_push_wrapper(plugin_root))
        os.chmod(temp, 0o755)
        updated = os.path.lexists(hook)
        os.replace(temp, hook)
    except BaseException:
        if os.path.lexists(temp):
            os.unlink(temp)
        raise
    return (f"proofbundle install-pre-push: {'replaced the' if updated else 'wrote a'} pre-push hook at {hook}. At "
            f"each push it runs the gate of the plugin at {plugin_root}, or of the newest version installed beside "
            "it, and a push it cannot check is denied. Nothing else was changed: no configuration, local or global. "
            "`git push --no-verify` skips it; the boundary is the required CI check (D22).")


def install_pre_push_command(argv: list[str]) -> int:
    options, i = {"--repo": None}, 0
    while i < len(argv):
        if argv[i] in options and i + 1 < len(argv) and options[argv[i]] is None:
            options[argv[i]], i = argv[i + 1], i + 2
        else:
            print(f"{INSTALL_USAGE}; unexpected {argv[i]!r}", file=sys.stderr)
            return 2
    try:
        print(install_pre_push(options["--repo"] or os.getcwd(), time.monotonic() + DEADLINE_SECONDS))
    except (GateError, OSError) as exc:
        print(f"proofbundle install-pre-push: {exc}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["tree-digest"]:
        return tree_digest_command(argv[1:])
    if argv[:1] == ["state-digest"]:
        return state_digest_command(argv[1:])
    if argv[:1] == ["transport-digest"]:
        return transport_digest_command(argv[1:])
    if argv[:1] == ["ci-check"]:
        return ci_check_command(argv[1:])
    if argv[:1] == ["run-evidence"]:
        return run_evidence_command(argv[1:])
    if argv[:1] == ["pre-push"]:
        return pre_push_command(argv[1:])
    if argv[:1] == ["install-pre-push"]:
        return install_pre_push_command(argv[1:])
    if argv[:1] == ["stop"]:
        return stop_command(argv[1:])
    if argv[:1] == ["done-check"]:
        return done_check_command(argv[1:])
    if argv[:1] == ["done-init"]:
        return done_init_command(argv[1:])
    if argv[:1] == ["task-completed"]:
        return task_completed_command(argv[1:])
    if argv[:1] == ["done-statement"]:
        return done_statement_command(argv[1:])
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
                          next_step="report this error; the gate denies until it is fixed",
                          digests=getattr(exc, "digests", ()), head=getattr(exc, "head", None),
                          reads=getattr(exc, "reads", ()))   # R12-2: what an exception carries stays in the log
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
