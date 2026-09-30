"""Pre-tool gate of the proofbundle plugin.

Before a shell call that pushes (`git push`), opens a pull request (`gh pr create`) or creates a
release (`gh release create`), and before an MCP tool that opens a pull request, a merge request or a
release, pushes files, writes a file or merges a pull request, the gate verifies the evidence the repository declares for its current head, with the plugin's
own MCP server, and answers the host in its hook format:

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
stdout: one JSON answer, or nothing for a call the gate does not gate.

Usage for a producer: proofbundle_gate.py tree-digest [--repo DIR] [--rev REV] [--statement] prints the
tree digest of REV (default HEAD), or with --statement the JSON a bundle signs to name it. The exit code is always 0; a failure inside the gate is answered as deny. Standard library
only, so the gate itself needs no package.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
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


def _git_call(words: list[str], directory: str | None) -> tuple[str, str | None] | None:
    i = 0
    while i < len(words) and words[i].startswith("-"):
        option, _, inline = words[i].partition("=")
        value = inline if inline else (words[i + 1] if option in _GIT_OPTIONS_WITH_VALUE
                                       and i + 1 < len(words) else "")
        if option == "-C":
            directory = _join(directory, value)
        elif option in ("--git-dir", "--work-tree"):
            directory = UNKNOWN
        i += 2 if (option in _GIT_OPTIONS_WITH_VALUE and not inline) else 1
    if i < len(words) and words[i] == "push":
        return "git push", directory
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


def gated_calls(command: str, directory: str | None = ".", depth: int = 0) -> list[tuple[str, str | None]]:
    """Every gated call in a shell command, with the directory it acts in (UNKNOWN when not literal).

    Over-matching is deliberate: a word `git` followed by `push` anywhere in a simple command counts,
    and so does any quoted argument that itself contains one (as in `bash -c "git push"`).
    """
    tokens = _tokens(command)
    if tokens is None or depth > MAX_NESTING:
        return [("unparsed command", UNKNOWN)] if _FALLBACK.search(command) else []
    calls: list[tuple[str, str | None]] = []
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
                calls.append(("git push", directory))
            elif name == "gh":
                found_gh = _gh_call(words[i + 1:])
                if found_gh:
                    calls.append((found_gh, directory))
            if any(c in word for c in " \t;&|"):
                calls.extend(gated_calls(word, directory, depth + 1))
    return calls


# --- the declaration and the evidence at HEAD --------------------------------------------------------

def _git(repo: str, *args: str, deadline: float) -> subprocess.CompletedProcess:
    left = deadline - time.monotonic()
    if left <= 0:
        raise GateError("the gate ran out of time")
    try:
        return subprocess.run(["git", "-C", repo, *args], capture_output=True, timeout=left, check=False)
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
        proc = subprocess.Popen(["git", "-C", repo, "cat-file", "--batch"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
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
    names its subject as its whole payload, the JSON of subject_statement. A decision receipt names it
    as an inputSnapshot entry with uri TREE_SUBJECT_URI and its digest in sha256.
    """
    try:
        document = json.loads(content.decode("utf-8"))
        if kind == "bundle":
            statement = json.loads(base64.b64decode(document["payload_b64"], validate=True).decode("utf-8"))
            subject = statement["subject"] if isinstance(statement, dict) and set(statement) == {"subject"} else None
            if (isinstance(subject, dict) and set(subject) == SUBJECT_KEYS
                    and subject["algorithm"] == TREE_ALGORITHM and isinstance(subject["digest"], str)):
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
        proc = subprocess.run([uv, "run", "--quiet", "--script", str(SERVER)],
                              input="".join(json.dumps(m) + "\n" for m in lines), capture_output=True,
                              text=True, timeout=left, check=False)
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


def rules_change(repo: str, commit: str, deadline: float) -> tuple[str, str]:
    """('unmeasured' | 'unchanged' | 'changed', what) for a push of commit, from local refs only.

    What the push adds is `git rev-list commit --not --remotes`: the commits no remote-tracking ref holds.
    Their boundary is what the remote is known to have, the predecessor. The rules at every boundary
    commit are compared with the rules at commit. Without any remote-tracking ref the gate cannot tell what
    the push adds, and says so. The gate never fetches.
    """
    remotes = _git(repo, "for-each-ref", "--format=%(objectname)", "refs/remotes", deadline=deadline)
    if remotes.returncode != 0 or not remotes.stdout.strip():
        return "unmeasured", "no remote-tracking ref is known locally, so the gate cannot tell what the push adds"
    listing = _git(repo, "rev-list", "--boundary", commit, "--not", "--remotes", deadline=deadline)
    if listing.returncode != 0:
        return "unmeasured", "git could not list the commits the push adds"
    lines = listing.stdout.decode().split()
    added = [line for line in lines if not line.startswith("-")]
    bases = [line[1:] for line in lines if line.startswith("-")]
    if not added:
        return "unchanged", ""
    head_rules = _rules_at(repo, commit, deadline)
    changes = []
    for base in bases or [None]:
        base_rules = ("absent",) if base is None else _rules_at(repo, base, deadline)
        if base_rules != head_rules:
            where = f"against {base[:12]}" if base else "against nothing, as the pushed history has no known base"
            changes.append(f"{_rules_difference(base_rules, head_rules)} ({where})")
    return ("changed", "; ".join(dict.fromkeys(changes))) if changes else ("unchanged", "")


_RULES_NEXT = ("have a person review the change to the evidence rules, then push; the gate reports every "
               "such change")


def _rules_verdict(repo: str, commit: str, what: str, digests: tuple = ()) -> Verdict:
    return Verdict("ask", f"proofbundle gate: the push changes the evidence rules under {EVIDENCE_DIR} at HEAD "
                          f"{commit[:12]}: {what}. Changes to the evidence rules need a review.",
                   "rules_changed", evidence=f"the evidence rules under {EVIDENCE_DIR} ({DECLARATION} and its policies)",
                   failed=what, next_step=_RULES_NEXT, digests=digests, repo=repo, head=commit)


# --- one repository ----------------------------------------------------------------------------------

def evaluate_repository(directory: str, deadline: float) -> Verdict:
    """The verdict for the repository that contains directory: pass, inactive, deny or ask.

    'inactive' is the one NOT MEASURED answer without a permission decision: the gate measured that the
    repository declares nothing, neither at HEAD nor in the working tree (DECISIONS.md, D5), and it cannot
    see a push that removes a declaration the remote holds (D20).
    """
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
    raw = _blob(repo, commit, DECLARATION, deadline, MAX_DECLARATION_BYTES)
    if raw is None:
        if _absent_at_head(repo, commit, deadline) and _absent_in_working_tree(repo):
            status, what = rules_change(repo, commit, deadline)
            if status == "changed":
                return _rules_verdict(repo, commit, what)
            return Verdict("inactive", f"NOT MEASURED: {repo} declares no evidence, neither at HEAD {commit[:12]} "
                                       f"nor in the working tree ({DECLARATION} is absent). The gate is not active in "
                                       "this repository, because nothing is declared. Nothing was verified.",
                           "nothing_declared", repo=repo, head=commit)
        in_tree = os.path.exists(os.path.join(repo, DECLARATION))
        hint = " A declaration exists in the working tree but is not committed; the gate reads HEAD." if in_tree else ""
        return Verdict("ask", f"NOT MEASURED: {repo} declares no evidence at HEAD {commit[:12]} "
                              f"({DECLARATION} is absent). Nothing was verified.{hint}",
                       "declaration_uncommitted" if in_tree else "absence_not_measured",
                       evidence=f"the declaration {DECLARATION}" + (" (working tree only)" if in_tree else ""),
                       failed=("the declaration is not committed, and the gate reads HEAD" if in_tree
                               else "the gate could not confirm that nothing is declared"),
                       next_step=("commit the declaration and the evidence it names, then retry" if in_tree
                                  else f"check what stands at {DECLARATION} in the working tree and at HEAD"),
                       repo=repo, head=commit)
    items = parse_declaration(raw)
    if not items:
        return Verdict("ask", f"NOT MEASURED: {DECLARATION} at HEAD {commit[:12]} declares an empty evidence "
                              "list. Nothing was verified.", "empty_declaration",
                       evidence=f"the declaration {DECLARATION}", failed="its evidence list is empty",
                       next_step="declare the evidence this tree needs and commit it", repo=repo, head=commit)
    tree = tree_digest(repo, commit, deadline)
    stale = [(n, item) for n, item in enumerate(items) if item["subject"]["digest"] != tree]
    if stale:
        return Verdict("deny", f"proofbundle gate: the declared subject does not match the tree at HEAD "
                               f"{commit[:12]}, which is {TREE_ALGORITHM} {tree}. "
                               + " | ".join(f"evidence[{n}] {i['path']} names {i['subject']['digest']}" for n, i in stale)
                               + ". The evidence speaks for another tree.", "stale_subject",
                       evidence=", ".join(_item(n, i) for n, i in stale),
                       failed=f"its subject is not the tree digest of HEAD ({TREE_ALGORITHM} {tree})",
                       next_step="build and sign the evidence for the tree at HEAD, then commit it under .proofbundle/",
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
                                           f"missing at HEAD {commit[:12]}. Nothing may be published without it.",
                                   "missing_file", evidence=f"{field} {item[field]} of {_item(n, item)}",
                                   failed="the file is missing at HEAD",
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
        return Verdict("deny", f"proofbundle gate: verification failed at HEAD {commit[:12]} (proofbundle {version}). "
                               + " | ".join(f"evidence[{n}] {i['kind']} {i['path']}: {why}" for n, i, why in failed),
                       "verification_failed", evidence=", ".join(_item(n, i) for n, i, _ in failed),
                       failed="; ".join(why for _, _, why in failed),
                       next_step="obtain evidence that verifies under the declared key or policy",
                       digests=digests, repo=repo, head=commit)
    unbound = []
    for n, (item, content) in enumerate(zip(items, contents)):
        named = signed_subjects(item["kind"], content)
        if not named:
            unbound.append((n, item, "the signed evidence names no tree subject"))
        elif item["subject"]["digest"] not in named:
            unbound.append((n, item, f"the signed evidence names {', '.join(named)}, not the declared subject "
                                     f"{item['subject']['digest']}"))
    if unbound:
        return Verdict("deny", f"proofbundle gate: the evidence verified but is not bound to the tree at HEAD "
                               f"{commit[:12]}. " + " | ".join(f"evidence[{n}] {i['path']}: {why}" for n, i, why in unbound),
                       "not_bound", evidence=", ".join(_item(n, i) for n, i, _ in unbound),
                       failed="; ".join(why for _, _, why in unbound),
                       next_step="sign a statement that names the tree digest of HEAD and commit it",
                       digests=digests, repo=repo, head=commit)
    status, what = rules_change(repo, commit, deadline)
    if status == "changed":
        return _rules_verdict(repo, commit, what, tuple(digests))
    if status == "unmeasured":
        return Verdict("ask", f"NOT MEASURED: the declared evidence verified at HEAD {commit[:12]}, but {what}. "
                              f"The gate cannot tell whether the push changes the evidence rules under {EVIDENCE_DIR}.",
                       "range_not_measured",
                       evidence=f"the evidence rules under {EVIDENCE_DIR} ({DECLARATION} and its policies)",
                       failed=what, next_step="fetch the remote, so its branches are known locally, then retry",
                       digests=tuple(digests), repo=repo, head=commit)
    return Verdict("pass", f"proofbundle gate: {len(items)} of {len(items)} declared items verified at HEAD "
                           f"{commit[:12]} for {TREE_ALGORITHM} {tree} with proofbundle {version}. This proves "
                           "who signed the recorded bytes and which tree they name, not that the recorded values "
                           "are true. The push leaves the evidence rules as the remote holds them.",
                   "verified", digests=tuple(digests), repo=repo, head=commit)


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
    outcome = _judge([(f"MCP {tool}", ".")], cwd, deadline)
    unseen = _MCP_UNSEEN.get(tool.rsplit("__", 1)[-1], "it cannot see the branch the tool publishes")
    outcome.text += (f" (MCP tool {tool}: the gate checked the local repository at {cwd}, at its HEAD; "
                     f"{unseen}.)")
    return outcome


def _judge(calls: list[tuple[str, str | None]], cwd: str, deadline: float) -> Outcome:
    verdicts = []
    for directory in dict.fromkeys(d if d is UNKNOWN else os.path.normpath(os.path.join(cwd, d))
                                   for _, d in calls):
        names = ", ".join(sorted({c for c, d in calls
                                  if (d if d is UNKNOWN else os.path.normpath(os.path.join(cwd, d))) == directory}))
        if directory is UNKNOWN:
            verdicts.append(Verdict("ask", f"NOT MEASURED: the gate cannot tell which repository {names} acts on "
                                           "(a directory change or a git option it does not resolve).",
                                    "directory_unresolved", evidence=f"unknown, the repository {names} acts on",
                                    failed="the gate cannot resolve the directory",
                                    next_step="run the call in the repository's directory, with a literal path"))
            continue
        try:
            verdicts.append(evaluate_repository(directory, deadline))
        except GateError as exc:
            verdicts.append(Verdict("deny", f"proofbundle gate: {exc}. The call is denied because the gate reached "
                                            "no verdict.", "gate_error",
                                    evidence=f"the declaration {DECLARATION} and the evidence it names at HEAD",
                                    failed=str(exc),
                                    next_step="fix the cause named here; the gate denies until it reaches a verdict",
                                    repo=directory))
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
    deadline = time.monotonic() + DEADLINE_SECONDS
    host = "claude"
    try:
        host = _host(argv)
        try:
            event = json.loads(sys.stdin.read())
        except ValueError as exc:
            raise GateError("the hook input is not JSON") from exc
        tool = event.get("tool_name") if isinstance(event, dict) else None
        if isinstance(tool, str) and tool.startswith("mcp__"):
            cwd = event.get("cwd")
            verdict = decide_mcp(tool, cwd if isinstance(cwd, str) and cwd else os.getcwd(), deadline)
        else:
            command, cwd = _command_from_event(event)
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
    if verdict is not None:
        sys.stdout.write(json.dumps(answer(verdict.decision, verdict.text, host=host)) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
