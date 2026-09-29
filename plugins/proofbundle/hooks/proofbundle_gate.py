"""Pre-tool gate of the proofbundle plugin.

Before a shell call that pushes (`git push`), opens a pull request (`gh pr create`) or creates a
release (`gh release create`), the gate verifies the evidence the repository declares for its current
head, with the plugin's own MCP server, and answers the host in its hook format:

- every declared item verifies: the gate makes no permission decision, so the host's normal
  permission flow applies, and a message names what was verified; the gate never grants a call;
- a declared item fails, is missing, or the declaration cannot be read: deny, with the reason;
- the repository declares nothing, or the gate cannot tell which repository the call acts on:
  NOT MEASURED, and the host asks the user; a host without an ask (Codex) gets deny instead.

The gate reads the declaration and the evidence from the commit at HEAD, not from the working tree, so
an uncommitted file can neither satisfy nor break it. The declaration lives at DECLARATION and is
described in DECISIONS.md next to this file's plugin.

Usage: proofbundle_gate.py [--host claude|codex]. stdin: the host's PreToolUse event (JSON). stdout:
one JSON answer, or nothing for a call the gate does not gate. The exit code is always 0; a failure inside the gate is answered as deny. Standard library
only, so the gate itself needs no package.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

DECLARATION = ".proofbundle/evidence.json"
DECLARATION_SCHEMA = "proofbundle-plugin/evidence/v0.1"
MAX_DECLARATION_BYTES = 64 * 1024
MAX_ITEMS = 32
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
KINDS = ("bundle", "decision", "outcome")
ITEM_KEYS = frozenset({"kind", "path", "public_key", "policy"})
#: Seconds for the whole gate. The hook timeout in the plugin manifests is 120 s; the gate answers deny
#: well before it, because a host that times a hook out may let the call run.
DEADLINE_SECONDS = 90.0
MAX_NESTING = 4
#: The hosts the gate answers. Claude Code has an "ask" decision; Codex has none. Codex's PreToolUse
#: parser marks an "ask" answer as a failed hook and lets the call run (openai/codex
#: codex-rs/hooks/src/engine/output_parser.rs and events/pre_tool_use.rs), so for Codex the gate turns
#: every NOT MEASURED ask into a deny.
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


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise GateError("the declaration repeats a key")
    return dict(pairs)


def _relative(value: object, where: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise GateError(f"{where} must be a non-empty path string")
    parts = value.split("/")
    if value.startswith("/") or "\\" in value or any(p in ("", ".", "..") for p in parts):
        raise GateError(f"{where} must be a normalised path inside the repository: {value!r}")
    return value


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


# --- one repository ----------------------------------------------------------------------------------

def evaluate_repository(directory: str, deadline: float) -> tuple[str, str]:
    """('pass' | 'deny' | 'ask', reason) for the repository that contains directory."""
    top = _git(directory, "rev-parse", "--show-toplevel", deadline=deadline)
    if top.returncode != 0:
        return "ask", f"NOT MEASURED: {directory} is not inside a git work tree, so no evidence was checked."
    repo = top.stdout.decode().strip()
    head = _git(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", deadline=deadline)
    if head.returncode != 0:
        return "ask", f"NOT MEASURED: {repo} has no commit at HEAD, so no evidence was checked."
    commit = head.stdout.decode().strip()
    raw = _blob(repo, commit, DECLARATION, deadline, MAX_DECLARATION_BYTES)
    if raw is None:
        hint = (" A declaration exists in the working tree but is not committed; the gate reads HEAD."
                if os.path.exists(os.path.join(repo, DECLARATION)) else "")
        return "ask", (f"NOT MEASURED: {repo} declares no evidence at HEAD {commit[:12]} "
                       f"({DECLARATION} is absent). Nothing was verified.{hint}")
    items = parse_declaration(raw)
    if not items:
        return "ask", (f"NOT MEASURED: {DECLARATION} at HEAD {commit[:12]} declares an empty evidence "
                       "list. Nothing was verified.")
    requests = []
    with tempfile.TemporaryDirectory(prefix="proofbundle-gate-") as scratch:
        for n, item in enumerate(items):
            arguments = {"kind": item["kind"]}
            for field in ("path", "policy"):
                if field not in item:
                    continue
                limit = MAX_EVIDENCE_BYTES if field == "path" else MAX_DECLARATION_BYTES
                content = _blob(repo, commit, item[field], deadline, limit)
                if content is None:
                    return "deny", (f"proofbundle gate: declared {field} {item[field]} of evidence[{n}] "
                                    f"is missing at HEAD {commit[:12]}. Nothing may be published without it.")
                if field == "policy" and item["kind"] == "bundle":
                    require_pinned_signer(content, f"the policy {item[field]} of evidence[{n}]")
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
            failed.append(f"evidence[{n}] {item['kind']} {item['path']}: {why}")
    if failed:
        return "deny", (f"proofbundle gate: verification failed at HEAD {commit[:12]} "
                        f"(proofbundle {version}). " + " | ".join(failed))
    return "pass", (f"proofbundle gate: {len(items)} of {len(items)} declared items verified at HEAD "
                    f"{commit[:12]} with proofbundle {version}. This proves who signed the recorded bytes, "
                    "not that the recorded values are true.")


def decide(command: str, cwd: str, deadline: float) -> tuple[str, str] | None:
    """None for a call the gate does not gate, else the combined (decision, reason)."""
    calls = gated_calls(command)
    if not calls:
        return None
    verdicts = []
    for directory in dict.fromkeys(d if d is UNKNOWN else os.path.normpath(os.path.join(cwd, d))
                                   for _, d in calls):
        names = ", ".join(sorted({c for c, d in calls
                                  if (d if d is UNKNOWN else os.path.normpath(os.path.join(cwd, d))) == directory}))
        if directory is UNKNOWN:
            verdicts.append(("ask", f"NOT MEASURED: the gate cannot tell which repository {names} acts on "
                                    "(a directory change or a git option it does not resolve)."))
        else:
            verdicts.append(evaluate_repository(directory, deadline))
    for decision in ("deny", "ask"):
        reasons = [r for d, r in verdicts if d == decision]
        if reasons:
            return decision, " ".join(reasons)
    return "pass", " ".join(r for _, r in verdicts)


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
    """The PreToolUse answer. A pass carries no permission decision, only the message.

    The reason goes to the user (systemMessage) and to the model (additionalContext) as well as into
    permissionDecisionReason, because a host shows the reason of an "ask" to the user only. Every field
    used here is one both hosts accept; Codex rejects an answer with any other field.
    """
    if decision == "ask" and host == "codex":
        decision, reason = "deny", reason + " Codex cannot ask, so the gate denies the call."
    specific = {"hookEventName": "PreToolUse", "additionalContext": reason}
    if decision != "pass":
        specific.update(permissionDecision=decision, permissionDecisionReason=reason)
    return {"systemMessage": reason, "hookSpecificOutput": specific}


def _host(argv: list[str]) -> str:
    if not argv:
        return "claude"
    if len(argv) == 2 and argv[0] == "--host" and argv[1] in HOSTS:
        return argv[1]
    raise GateError(f"unknown arguments {argv!r}; the gate takes --host claude or --host codex")


def main(argv: list[str] | None = None) -> int:
    deadline = time.monotonic() + DEADLINE_SECONDS
    host = "claude"
    try:
        host = _host(sys.argv[1:] if argv is None else argv)
        try:
            event = json.loads(sys.stdin.read())
        except ValueError as exc:
            raise GateError("the hook input is not JSON") from exc
        command, cwd = _command_from_event(event)
        verdict = decide(command, cwd, deadline)
    except GateError as exc:
        verdict = ("deny", f"proofbundle gate: {exc}. The call is denied because the gate reached no verdict.")
    except Exception as exc:  # noqa: BLE001 - any failure inside the gate denies, it never allows
        verdict = ("deny", f"proofbundle gate: internal error {type(exc).__name__}: {exc}. "
                           "The call is denied because the gate reached no verdict.")
    if verdict is not None:
        sys.stdout.write(json.dumps(answer(*verdict, host=host)) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
