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

_GIT_OPTIONS_WITH_VALUE = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace",
                                     "--config-env", "--super-prefix"})
_GH_OPTIONS_WITH_VALUE = frozenset({"-R", "--repo"})
_GH_GATED = frozenset({("pr", "create"), ("pr", "new"), ("release", "create"), ("release", "new")})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_OPERATOR = re.compile(r"^[;&|()<>]+$")
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
#: Target-neutral options taking a value as `--opt value` (or the short `-o value`).
_PUSH_OPTS_NEUTRAL_VALUE = frozenset({"-o", "--push-option", "--receive-pack", "--exec"})
#: Target-neutral options accepted in the inline `--opt=value` form.
_PUSH_OPTS_NEUTRAL_INLINE = frozenset({"--push-option", "--receive-pack", "--exec", "--force-with-lease",
                                       "--signed"})
#: Prepended to the resolved push arguments when a `git -c` or `--config-env` option set a configuration key
#: that can change the push target and that the gate's separate reads never see; resolve_push_targets then
#: reports NOT MEASURED (review R3-1). A GIT_CONFIG_* injection in the environment needs no sentinel: the
#: gate's reads inherit the same environment, so git applies it to them as it would to the push.
_GIT_CONFIG_SENTINEL = "\x00config-injected"
#: The last component of a config key, by section, for keys that can change a push's endpoint, target refs
#: or range. url.<base>.insteadof is included because, injected only into the push, it would rewrite the
#: endpoint the gate's reads cannot see (review R3-1, Befund 1).
_TARGET_CONFIG_EXACT = frozenset({"push.default", "push.followtags", "push.recursesubmodules",
                                  "remote.pushdefault"})
_TARGET_CONFIG_BY_SECTION = {"remote": frozenset({"url", "pushurl", "push", "mirror", "fetch"}),
                             "branch": frozenset({"remote", "pushremote", "merge"}),
                             "url": frozenset({"insteadof", "pushinsteadof"})}


def _key_affects_push_target(key: str) -> bool:
    """Whether a git config key can change which endpoint, refs or commits a push sends. Used for the keys a
    `git -c` or `--config-env` option injects, which the gate's separate reads never see (review R3-1)."""
    k = key.strip().lower()
    if k in _TARGET_CONFIG_EXACT:
        return True
    parts = k.split(".")
    return len(parts) >= 3 and parts[-1] in _TARGET_CONFIG_BY_SECTION.get(parts[0], frozenset())


class GateError(Exception):
    """The gate cannot reach a verdict. Answered as deny."""


# --- which calls are gated, and in which directory ---------------------------------------------------

def _tokens(command: str) -> list[str] | None:
    lexer = shlex.shlex(command.replace("`", " ; ").replace("\n", " ; "), posix=True,
                        punctuation_chars=";&|()<>")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:
        return None


def _join(directory: str | None, target: str) -> str | None:
    if directory is UNKNOWN or not target or "$" in target or target == "-":
        return UNKNOWN
    return os.path.normpath(os.path.join(directory, os.path.expanduser(target)))


def _git_call(words: list[str], directory: str | None) -> tuple[str, str | None, list[str] | None] | None:
    i, config_injected = 0, False
    while i < len(words) and words[i].startswith("-"):
        option, _, inline = words[i].partition("=")
        value = inline if inline else (words[i + 1] if option in _GIT_OPTIONS_WITH_VALUE
                                       and i + 1 < len(words) else "")
        if option == "-C":
            directory = _join(directory, value)
        elif option in ("--git-dir", "--work-tree"):
            directory = UNKNOWN
        elif option in ("-c", "--config-env"):
            # -c <key>=<value> / --config-env=<key>=<envvar>: the config key is the part before the first =.
            if not value or _key_affects_push_target(value.partition("=")[0]):
                config_injected = True  # per-command config the gate's separate reads never see (R3-1)
        i += 2 if (option in _GIT_OPTIONS_WITH_VALUE and not inline) else 1
    if i < len(words) and words[i] == "push":
        args = words[i + 1:]
        return "git push", directory, ([_GIT_CONFIG_SENTINEL] + args if config_injected else args)
    return None


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


def gated_calls(command: str, directory: str | None = ".", depth: int = 0) -> list[tuple[str, str | None, list[str] | None]]:
    """Every gated call in a shell command: its name, the directory it acts in (UNKNOWN when not literal),
    and for `git push` the words after `push` (its remote and refspecs), None for the other calls.

    Over-matching is deliberate: a word `git` followed by `push` anywhere in a simple command counts,
    and so does any quoted argument that itself contains one (as in `bash -c "git push"`). An over-matched
    push carries no literal arguments, so the gate resolves no target and the push is NOT MEASURED.
    """
    tokens = _tokens(command)
    if tokens is None or depth > MAX_NESTING:
        return [("unparsed command", UNKNOWN, None)] if _FALLBACK.search(command) else []
    calls: list[tuple[str, str | None, list[str] | None]] = []
    segments: list[list[str]] = [[]]
    for token in tokens:
        if _OPERATOR.match(token):
            segments.append([])
        else:
            segments[-1].append(token)
    for words in segments:
        head = [w for w in words if not _ASSIGNMENT.match(w)][:2]
        if head and head[0] in ("cd", "pushd"):
            directory = _join(directory, head[1]) if len(head) > 1 else _join(directory, "~")
        elif head and head[0] == "popd":
            directory = UNKNOWN
        for i, word in enumerate(words):
            name = os.path.basename(word)
            if name == "git":
                found = _git_call(words[i + 1:], directory)
                if found:
                    calls.append(found)
            elif name == "git-push":
                calls.append(("git push", directory, words[i + 1:]))
            elif name == "gh":
                found_gh = _gh_call(words[i + 1:])
                if found_gh:
                    calls.append((found_gh, directory, None))
            if any(c in word for c in " \t;&|"):
                calls.extend(gated_calls(word, directory, depth + 1))
    return calls


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
    what an object id resolves to, so they are not such a rewrite."""
    env = dict(os.environ)
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    env["GIT_GRAFT_FILE"] = os.devnull
    return env


def _git(repo: str, *args: str, deadline: float) -> subprocess.CompletedProcess:
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


def _blob(repo: str, head: str, path: str, deadline: float, limit: int) -> bytes | None:
    """The bytes of path at the commit, None when there is no such file there."""
    kind = _git(repo, "cat-file", "-t", f"{head}:{path}", deadline=deadline)
    if kind.returncode != 0:
        return None
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
#: none, which makes the whole push NOT MEASURED, N1).
PushTarget = collections.namedtuple("PushTarget", "source dest tracking")

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


def _endpoint_consistent(repo: str, remote: str, deadline: float) -> bool:
    """Whether the remote resolves to exactly one push endpoint equal to its one fetch endpoint. git's
    `remote get-url` applies pushurl and url.<base>.insteadOf / pushInsteadOf and lists every value, so this
    catches a pushInsteadOf rewrite, a pushurl, or a second URL that would send the push to a different or a
    further endpoint than the remote-tracking ref records (Befund 1). A git error raises GateError (NOT
    MEASURED). A symmetric insteadOf rewrites fetch and push alike, so the tracking ref still records the
    push endpoint and the two URLs stay equal."""
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
    if _GIT_CONFIG_SENTINEL in args:
        return None  # a `-c`/`--config-env` key that can change the target and the gate's reads cannot see
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
    `pass_tail` is appended to a pass. parse_declaration and _blob raise GateError, which the caller turns
    into a deny, so a tree whose declaration cannot be read is never silently treated as declaring nothing.
    """
    raw = _blob(repo, commit, DECLARATION, deadline, MAX_DECLARATION_BYTES)
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
    D22 for CI; decide_mcp for an MCP tool whose remote target the gate cannot read). A shell `git push`
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
        return _unresolved_verdict(repo, head_commit,
                                   "the remote, a refspec, or the push configuration names updates the gate cannot "
                                   "map to a locally tracked target (a URL or path remote, --all/--mirror/--tags, a "
                                   "wildcard refspec, a configured remote push list, or a branch this repository does "
                                   "not track)")

    def where(commit: str) -> str:
        return f"HEAD {commit[:12]}" if commit == head_commit else f"the pushed commit {commit[:12]}"

    # Every commit the push newly sends, across all targets, with the source tip always evaluated so a push
    # the remote already holds still has its evidence verified (its range is otherwise empty).
    order: list[str] = []
    for t in targets:
        if t.source is None:
            continue
        reachable = _newly_reachable(repo, t.source, t.tracking, deadline)
        if reachable is None:
            return _unresolved_verdict(repo, head_commit,
                                       f"the gate cannot list the commits this push adds to {t.dest} (a shallow "
                                       "clone, too long a range, or git could not resolve it)")
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
        if t.source is None:  # a deletion removes the ref; its rules go to absent
            if base != ("absent",) and _rules_difference(base, ("absent",)):
                return _rules_verdict(repo, head_commit, f"the push removes the declaration (deletes {t.dest}, "
                                      f"against {t.tracking})")
            continue
        reachable = _newly_reachable(repo, t.source, t.tracking, deadline)
        for commit in dict.fromkeys([*reachable, t.source]):
            head_rules = _rules_at(repo, commit, deadline)
            if base != head_rules:
                digests = verdicts[t.source].digests if verdicts[t.source].decision == "pass" else ()
                against = t.tracking or "nothing, as this repository tracks no earlier state of the target"
                return _rules_verdict(repo, head_commit, f"{_rules_difference(base, head_rules)} "
                                      f"(at {commit[:12]}, against {against})", digests)

    declared = [verdicts[c] for c in order if verdicts[c].decision == "pass"]
    if not declared:  # every sent commit declares nothing
        nuance = _absence_nuance(repo, head_commit, deadline) if head_commit in order else None
        if nuance is not None:
            return nuance
        where_all = ", ".join(c[:12] for c in order) or head_commit[:12]
        return Verdict("inactive", f"NOT MEASURED: this push declares no evidence (at {where_all}, {DECLARATION} is "
                                   "absent). The gate is not active in this repository, because nothing is declared. "
                                   "Nothing was verified.", "nothing_declared", repo=repo, head=head_commit)
    tip = (verdicts[targets[0].source] if targets[0].source and verdicts[targets[0].source].decision == "pass"
           else declared[0])
    tail = (f" The push sends {len(order)} commit(s) to {', '.join(dict.fromkeys(t.dest for t in targets))}; "
            "the evidence rules match the target's last known state in this repository, which was not read "
            "from the remote.")
    return Verdict("pass", tip.detail + tail, "verified", digests=tip.digests, repo=repo, head=head_commit)


class Outcome:
    """The combined answer for one call: the decision, its text, and the verdict of every repository."""

    __slots__ = ("decision", "text", "verdicts")

    def __init__(self, decision: str, text: str, verdicts: list):
        self.decision, self.text, self.verdicts = decision, text, verdicts

    def __iter__(self):
        return iter((self.decision, self.text))


def decide(command: str, cwd: str, deadline: float) -> Outcome | None:
    """None for a call the gate does not gate, else the combined outcome."""
    calls = gated_calls(command)
    if not calls:
        return None
    return _judge(calls, cwd, deadline)


def mcp_gated(tool: str) -> bool:
    return re.fullmatch(MCP_MATCHER, tool) is not None


def decide_mcp(tool: str, cwd: str, deadline: float) -> Outcome | None:
    """None for an MCP tool the gate does not know; else the verdict for the local repository at cwd.

    An MCP tool acts on a remote repository the gate cannot read. The gate judges the repository the
    session works in, at its HEAD, and says so in every answer.
    """
    if not mcp_gated(tool):
        return None
    outcome = _judge([(f"MCP {tool}", ".", None)], cwd, deadline)
    unseen = _MCP_UNSEEN.get(tool.rsplit("__", 1)[-1], "it cannot see the branch the tool publishes")
    outcome.text += (f" (MCP tool {tool}: the gate checked the local repository at {cwd}, at its HEAD; "
                     f"{unseen}.)")
    return outcome


def _evaluate_call(name: str, directory: str, detail: list[str] | None, deadline: float) -> Verdict:
    """The verdict for one gated call: a shell `git push` resolves its targets and the commits it sends; a
    `gh pr/release create` is judged as a push of the current branch to its upstream; an MCP tool, whose
    remote target the gate cannot read, is judged at HEAD with no range comparison."""
    if name == "git push":
        return evaluate_push(directory, detail, deadline)
    if name.startswith("gh "):
        return evaluate_push(directory, None, deadline)
    return evaluate_repository(directory, deadline)


def _judge(calls: list[tuple[str, str | None, list[str] | None]], cwd: str, deadline: float) -> Outcome:
    verdicts = []
    seen = set()
    for name, directory, detail in calls:
        resolved = directory if directory is UNKNOWN else os.path.normpath(os.path.join(cwd, directory))
        key = (name, resolved, tuple(detail) if detail is not None else None)
        if key in seen:
            continue
        seen.add(key)
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
RUN_USAGE = "usage: run-evidence --repo DIR --out FILE [--timeout SECONDS] -- COMMAND..."


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


def _working_tree_digest(repo: str, deadline: float) -> str:
    """The v1 digest of the working tree as `git add -A` would stage it on top of HEAD. It goes through a
    temporary index, so the repository's own index is left alone. Files git ignores are not in it."""
    with tempfile.TemporaryDirectory(prefix="proofbundle-index-") as scratch:
        env = dict(os.environ, GIT_INDEX_FILE=os.path.join(scratch, "index"))
        output = b""
        for args in (("read-tree", "HEAD"), ("add", "-A"), ("write-tree",)):
            left = deadline - time.monotonic()
            if left <= 0:
                raise GateError("the gate ran out of time")
            try:
                proc = subprocess.run(["git", "-C", repo, *args], env=env, capture_output=True, timeout=left,
                                      check=False)
            except FileNotFoundError as exc:
                raise GateError("git is not on PATH") from exc
            except subprocess.TimeoutExpired as exc:
                raise GateError("git did not answer in time") from exc
            if proc.returncode != 0:
                raise GateError(f"git {args[0]} failed on the working tree")
            output = proc.stdout
        return tree_digest(repo, output.decode().strip(), deadline)


_PYTHON_NAME = re.compile(r"python(?:3(?:\.\d+)*)?")


def _pytest_command(command: list[str]) -> bool:
    """Whether the command is a supported pytest form: an executable named pytest or py.test, or a Python
    interpreter with `-m pytest`. This keeps out a program that is not pytest; it does not authenticate the
    executable (review F7, N7)."""
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
                 timeout: float = RUN_TIMEOUT_SECONDS) -> tuple[int, dict]:
    """Run a pytest command on the clean working tree of HEAD and, for a green run that left the tree as it
    was, write the statement a bundle signs: the subject and the run record (DECISIONS.md, D23).

    There is no evidence when the working tree differs from HEAD before the run, when the run moves HEAD or
    changes the working tree, when it times out or writes no readable report, or when it is not green. The
    record holds no environment value. Nothing is signed here.
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
        digest = tree_digest(repo, commit, deadline)
        if _working_tree_digest(repo, deadline) != digest:
            return refuse("tree_not_clean", f"the working tree of {repo} differs from HEAD {commit[:12]}; commit "
                                            "or remove the changes, then run again (files git ignores are not "
                                            "compared)")
        program = shutil.which(command[0])
        if program is None:
            return refuse("no_program", f"{command[0]!r} is not an executable file on PATH")
        if not _pytest_command(command):
            return refuse("not_pytest", f"{command[0]!r} is not a pytest command; run-evidence runs only pytest "
                                        "(an executable named pytest, or a Python interpreter with -m pytest)")
        program = os.path.abspath(program)
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
            tree_after = _working_tree_digest(repo, deadline)
            if tree_after != digest:
                return refuse("tree_changed", f"the run changed the working tree of {repo}, so it did not run on "
                                              f"the tree it would name")
            try:
                counts, report_sha256 = _junit_counts(junit, suite_name)
            except StaleReport as exc:
                return refuse("stale_report", str(exc))
            except GateError as exc:
                return refuse("no_report", str(exc))
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
    options, command, i = {"--repo": None, "--out": None, "--timeout": None}, argv[split + 1:], 0
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
    code, report = run_evidence(options["--repo"], options["--out"], command, timeout)
    sys.stdout.write(json.dumps(report, indent=1) + "\n")
    print(report["message"], file=sys.stderr)
    return code


def _host(argv: list[str]) -> str:
    if not argv:
        return "claude"
    if len(argv) == 2 and argv[0] == "--host" and argv[1] in HOSTS:
        return argv[1]
    raise GateError(f"unknown arguments {argv!r}; the gate takes --host claude or --host codex")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["tree-digest"]:
        return tree_digest_command(argv[1:])
    if argv[:1] == ["ci-check"]:
        return ci_check_command(argv[1:])
    if argv[:1] == ["run-evidence"]:
        return run_evidence_command(argv[1:])
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
            verdict = decide_mcp(tool, cwd if isinstance(cwd, str) and cwd else os.getcwd(), deadline)
        else:
            command, cwd = _command_from_event(event)
            actions = sorted({name for name, _, _ in gated_calls(command)})
            verdict = decide(command, cwd, deadline)
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
