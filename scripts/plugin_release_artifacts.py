#!/usr/bin/env python3
"""Build, check and verify the release artifacts of the proofbundle plugins at one commit.

It reads a local clone and writes nothing into it. `build` and `scan` use the standard library only. `verify` needs
the proofbundle package: it reads base64 with proofbundle._wire_b64.decode_b64, which takes only the canonical form,
and checks the signature with proofbundle.signature.verify_ed25519_pinned, which refuses a weak key before any
signature arithmetic. Reading script dependency metadata needs `tomllib` (Python 3.11 or later); on an older Python
the build ends as not measurable (exit 2) and writes nothing.

build
    python3 -I plugin_release_artifacts.py build --repo DIR --commit REV --out OUTDIR --version X.Y.Z
        --expect-pin X.Y.Z [--layout split|combined] [--tag-out FILE] [--inventory-out FILE]

    Reads git objects of REV only: no working tree, no filters, no attributes, no replace refs, no global or system
    git configuration. Before anything is written it checks, each on its own:
      - the required paths: LICENSE and every marketplace file of the layout as regular files, every plugin root of
        the layout as a nonempty tree;
      - every required version place and every required pin place of the layout's inventory (INVENTORIES below), with
        its exact count; script dependency metadata is read only from a block whose every line is a comment (PEP
        723), is parsed as TOML, and each block must list exactly one dependency, proofbundle pinned with == to the
        expected version; source constants are read with ast, never executed;
      - every marketplace of the layout: exactly the layout's entries, each source resolving from the folder that
        holds the marketplace to a root of the archive whose manifest carries the same name, no differing version
        field. In the split layout the public marketplace at the repository root lists proofbundle alone, and the
        Guard's own house marketplace in plugins/proofbundle-guard lists proofbundle-guard with the source "./";
      - in the split layout, the public verifier's profile: no hooks/ folder (and so no hooks/hooks.json), no
        "hooks" field in its two host manifests or its marketplace entry, no dependency on the Guard, exactly one MCP
        server, proofbundle, in .mcp.json and in the Codex manifest, and the tool set of that server;
      - in the split layout, the Guard's profile: hooks/hooks.json and the gate program present, every program a hook
        of either host starts present in the Guard's root, no skills/ folder, no MCP server registered, and its copy of
        the server byte-equal to the verifier's;
      - every archived entry: a regular file (0644 or 0755); a symbolic link or a gitlink stops the build.
    Then it writes into OUTDIR, which must be absent or empty, exactly three files:
      proofbundle-plugin-<V>.tar            A1, LICENSE, the marketplace file and the plugin roots under one prefix
      proofbundle-plugin-<V>.release.json   A2, the release statement, the exact bytes the owner signs
      SHA256SUMS                            A3, two lines derived from A2 and its own hash
    --tag-out writes the raw bytes of the annotated tag object T1, which `git mktag` accepts unchanged.
    --inventory-out writes one line per archived file: mode, size, sha256, path, and a review mark for names that
    look like key or credential material.
    The report on stdout names every place read, every check, each artifact with size and SHA-256, the bytes to sign,
    and T1 with its message hash and expected object id. Two runs on the same commit give the same bytes and report.

verify
    python3 -I plugin_release_artifacts.py verify --assets DIR --public-key BASE64 [--repo DIR]

    The third-party check of a downloaded release: S1 strictly decoded and verified with Ed25519 over the
    exact A2 bytes under the given raw public key; A2 canonical, with the expected members and values; A1 name, size
    and SHA-256 against A2; A3 rebuilt byte for byte; with --repo, the tag named in A2 is an annotated tag whose
    commit is the one in A2. The key itself must come from a channel the relying party already trusts.

scan
    python3 -I plugin_release_artifacts.py scan --repo DIR --commit REV [--commit REV ...]

    Lists lines that name a plugin version (0.3.0, 0.4.0) or the verifier pin. A list for reading, not a check.

Exit codes: 0 done, 1 a check failed (the report names it; build writes nothing), 2 not measurable (usage error,
missing commit or object, missing library).

Layouts. "split" is the release layout since pull request 472: plugins/proofbundle, the public verifier without
hooks, listed in the public marketplace, and plugins/proofbundle-guard, the house Guard, a root of its own with its own
house marketplace and no entry in the public one; the Guard root carries its own copy of the server because the gate
starts <root>/server/proofbundle_mcp.py. "combined" is the tree of main b55d736d with one root, kept only to reproduce
the historical probe there. A change of a place, a count, an entry or the tool set lands in this file together with
the change that makes it.

A1 is an uncompressed POSIX ustar archive written by Python's tarfile from the selected tree entries and their exact
blob bytes: paths in byte order, each directory before its content, directories 0755, files 0644 or 0755 as git
records them, owner 0/0 with empty names, every mtime the committer time of REV. It is not `git archive`: export-ignore
and other attributes do not apply.

A2 is the complete JSON object, serialized as json.dumps(obj, sort_keys=True, separators=(",", ":"),
ensure_ascii=True), ASCII, no trailing newline. These are the JSON settings of canonical_bytes in
scripts/pre_tag_receipt_lib.py, but that function is not used: it selects the pre-tag receipt's own fields and refuses
this object. The whole file is signed.

Assisted by little helpers.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tokenize
import unicodedata
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10, the package floor; the build then ends as not measurable
    tomllib = None

REPOSITORY_URL = "https://github.com/b7n0de/proofbundle"
STATEMENT_SCHEMA = "proofbundle-plugin-release/v0.1"
STATEMENT_PLUGIN = "proofbundle"
MARKETPLACE = ".claude-plugin/marketplace.json"
LICENSE = "LICENSE"
TAGGER = "b7n0de <45888075+b7n0de@users.noreply.github.com>"
SEMVER = re.compile(r"\d+\.\d+\.\d+")
HEX40 = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
HEX64 = re.compile(r"[0-9a-f]{64}")
PEP723 = re.compile(r"(?m)^# /// (?P<type>[a-zA-Z0-9-]+)$\s(?P<content>(^#(| .*)$\s)+)^# ///$")
REQUIREMENT = re.compile(r"^\s*(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?P<extras>\[[^\]]*\])?\s*"
                         r"(?P<rest>.*)$")
VERSION_CELL = re.compile(r"\d+\.\d+\.\d+")
CATALOG_HOST_NAMES = ("Claude Code", "Codex")
CATALOG_HOST_KEYS = {host.casefold() for host in CATALOG_HOST_NAMES}
REVIEW_NAME = re.compile(r"(?i)(\.pem|\.key|\.p12|\.pfx|\.pub|id_rsa|id_ed25519|secret|credential|token|password|"
                         r"\.env$|\.netrc$)")

V = "plugins/proofbundle"
G = "plugins/proofbundle-guard"
HOUSE_MARKETPLACE = G + "/.claude-plugin/marketplace.json"
#: The tools the public verifier's MCP server lists, the keys of its TOOLS table, read with ast. The Guard registers no
#: MCP server; its copy of the server, which only the gate starts, must be byte-equal to the verifier's.
#: The registrations of the verifier's MCP server, for each host its own, as main c9ab65b1 writes them.
MCP_REGISTRATIONS = {
    "/.mcp.json": {"proofbundle": {"command": "uv", "args": [
        "run", "--quiet", "--no-config", "--script", "${CLAUDE_PLUGIN_ROOT}/server/proofbundle_mcp.py"]}},
    "/.codex-plugin/plugin.json": {"proofbundle": {"command": "uv", "args": [
        "run", "--quiet", "--no-config", "--script", "server/proofbundle_mcp.py"], "cwd": ".",
        "env": {"PROOFBUNDLE_PLUGIN_HOST": "codex"}}},
}
VERIFIER_TOOLS = ("emit_receipt", "gate_selftest_check", "gate_selftest_prepare", "gate_status", "inspect_receipt",
                  "receipt_template", "verify_receipt")
#: The hook commands of the Guard, word for word as main c9ab65b1 writes them, for each host its own: @ROOT@ stands for
#: the host's root variable (Claude Code ${CLAUDE_PLUGIN_ROOT}, Codex ${PLUGIN_ROOT}) and @PROGRAM@ for the path of the
#: program inside the plugin; the bare start of a program is one form more. A hook command is held whole to one of
#: them (hook_programs). The readings of 2bcbf9f3 to ae0b16e4 found, one after the other, text joined to the quoted
#: path, an escaped blank, a leading command substitution, a rest the shell rejects and a failing input redirection,
#: each of which a reading of only the start let pass; a whole command can hide nothing else.
CLAUDE_ROOT, CODEX_ROOT = "CLAUDE_PLUGIN_ROOT", "PLUGIN_ROOT"
_BLOCKED = "{ echo 'proofbundle gate: the gate could not run, so the call is blocked' >&2; exit 2; }"
HOOK_TEMPLATES = {
    CLAUDE_ROOT: (
        'python3 -I "${@ROOT@}/@PROGRAM@"',
        'python3 -I "${@ROOT@}/@PROGRAM@" --autonomous || ' + _BLOCKED,
        'python3 -I "${@ROOT@}/@PROGRAM@" || true',
        'python3 -I "${@ROOT@}/@PROGRAM@" stop || { echo \'proofbundle done check: the check could not run, so the '
        "session does not end' >&2; exit 2; }",
        'out=$(python3 -I "${@ROOT@}/@PROGRAM@" task-completed) || { echo \'proofbundle done check: the check could '
        "not run, so the task stays open' >&2; exit 2; }; if [ -n \"$out\" ]; then printf '%s\\n' \"$out\" >&2; exit 2; fi",
        'python3 -I "${@ROOT@}/@PROGRAM@" session-start || printf \'%s\\n\' \'{"systemMessage": "proofbundle done check: '
        "the hand-over could not run, so an open blocker was not handed on; the done check at Stop is unchanged "
        "(D127).\"}'",
    ),
    CODEX_ROOT: (
        'python3 -I "${@ROOT@}/@PROGRAM@"',
        'python3 -I "${@ROOT@}/@PROGRAM@" --host codex || ' + _BLOCKED,
        'python3 -I "${@ROOT@}/@PROGRAM@" stop --host codex || { echo \'proofbundle done check: the check could not '
        "run, so the session goes on' >&2; exit 2; }",
    ),
}
_HOOK_PATH = r"([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)"
HOOK_START = {root: tuple(re.compile(re.escape(t).replace("@ROOT@", root).replace("@PROGRAM@", _HOOK_PATH))
                          for t in templates) for root, templates in HOOK_TEMPLATES.items()}

#: Every required version place ("version") and pin place ("pin"), by layout. Kinds:
#:   json_version   the "version" member of a JSON file
#:   py_constant    a top-level NAME = "string" assignment, read with ast, exactly one
#:   file_blocks    PEP 723 script blocks of the file, every line a comment, exactly COUNT of them
#:   const_block    the PEP 723 script block of the script in the top-level string constant NAME, exactly one
#:   catalog_rows   rows "| Claude Code |" and "| Codex |" of the plugin catalog with a version cell, exactly COUNT
#: "marketplaces" maps each marketplace file to the folder its sources are relative to, its name (None: not checked)
#: and its exact entries, plugin name -> source.
INVENTORIES: dict[str, dict] = {
    "split": {
        "roots": {"proofbundle": V, "proofbundle-guard": G},
        "public_root": V,
        "guard_root": G,
        "marketplaces": {
            MARKETPLACE: {"base": "", "name": "proofbundle", "entries": {"proofbundle": "./" + V}},
            HOUSE_MARKETPLACE: {"base": G, "name": "proofbundle-house", "entries": {"proofbundle-guard": "./"}},
        },
        "places": [
            ("version", "json_version", V + "/.claude-plugin/plugin.json", None, 1),
            ("version", "json_version", V + "/.codex-plugin/plugin.json", None, 1),
            ("version", "py_constant", V + "/server/proofbundle_mcp.py", "SERVER_VERSION", 1),
            ("pin", "file_blocks", V + "/server/proofbundle_mcp.py", None, 1),
            ("version", "json_version", G + "/.claude-plugin/plugin.json", None, 1),
            ("version", "json_version", G + "/.codex-plugin/plugin.json", None, 1),
            ("version", "py_constant", G + "/server/proofbundle_mcp.py", "SERVER_VERSION", 1),
            ("pin", "file_blocks", G + "/server/proofbundle_mcp.py", None, 1),
            ("version", "py_constant", G + "/hooks/proofbundle_gate.py", "GATE_VERSION", 1),
            ("pin", "py_constant", G + "/hooks/proofbundle_gate.py", "PINNED_PROOFBUNDLE", 1),
            ("pin", "const_block", G + "/hooks/proofbundle_gate.py", "_SIGN_TOOL", 1),
            ("pin", "const_block", G + "/hooks/proofbundle_gate.py", "_KEY_TOOL", 1),
            # the plugin catalog copies the version in its rows of both hosts (line 3 of the reading of dfef187a: the
            # scope file says it is checked, and only the combined layout read it)
            ("version", "catalog_rows", "plugins/README.md", None, 2),
        ],
    },
    "combined": {
        "roots": {"proofbundle": V},
        "public_root": None,
        "guard_root": None,
        "marketplaces": {
            MARKETPLACE: {"base": "", "name": None, "entries": {"proofbundle": "./" + V}},
        },
        "places": [
            ("version", "json_version", V + "/.claude-plugin/plugin.json", None, 1),
            ("version", "json_version", V + "/.codex-plugin/plugin.json", None, 1),
            ("version", "py_constant", V + "/server/proofbundle_mcp.py", "SERVER_VERSION", 1),
            ("pin", "file_blocks", V + "/server/proofbundle_mcp.py", None, 1),
            ("version", "py_constant", V + "/hooks/proofbundle_gate.py", "GATE_VERSION", 1),
            ("pin", "py_constant", V + "/hooks/proofbundle_gate.py", "PINNED_PROOFBUNDLE", 1),
            ("pin", "const_block", V + "/hooks/proofbundle_gate.py", "_SIGN_TOOL", 1),
            ("pin", "const_block", V + "/hooks/proofbundle_gate.py", "_KEY_TOOL", 1),
            ("version", "catalog_rows", "plugins/README.md", None, 2),
        ],
    },
}


class NotMeasurable(Exception):
    """The run could not measure: exit 2."""


class CheckFailed(Exception):
    """A check did not hold: exit 1."""


def _git_env() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }


def git(repo: Path, *args: str, stdin: bytes | None = None) -> bytes:
    proc = subprocess.run(["git", "-C", str(repo), *args], input=stdin, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=_git_env(), check=False)
    if proc.returncode != 0:
        raise NotMeasurable(f"git {' '.join(args[:3])} exited {proc.returncode}: "
                            f"{proc.stderr.decode('utf-8', 'replace').strip()}")
    return proc.stdout


def _resolve_commit(repo: Path, rev: str) -> str:
    out = git(repo, "rev-parse", "--verify", "--end-of-options", rev + "^{commit}").decode().strip()
    if not HEX40.fullmatch(out):
        raise NotMeasurable(f"rev-parse gave no object id for {rev!r}")
    return out


def tree_entry(repo: Path, commit: str, path: str) -> tuple[str, str, str] | None:
    """(mode, type, oid) of PATH at COMMIT, or None."""
    raw = git(repo, "ls-tree", "-z", "--full-tree", commit, "--", path)
    for record in raw.split(b"\0"):
        if not record:
            continue
        meta, _, name = record.partition(b"\t")
        if name.decode("utf-8", "replace") == path:
            mode, kind, oid = meta.decode().split(" ")
            return mode, kind, oid
    return None


def blob_text(repo: Path, commit: str, path: str) -> str:
    entry = tree_entry(repo, commit, path)
    if entry is None or entry[1] != "blob" or entry[0] not in ("100644", "100755"):
        raise CheckFailed(f"{path}: not a regular file at the commit")
    try:
        return git(repo, "cat-file", "blob", entry[2]).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CheckFailed(f"{path}: not UTF-8") from exc


class DuplicateMember(ValueError):
    """A JSON object that names one member twice."""


def _members(pairs: list[tuple[str, object]]) -> dict:
    """object_pairs_hook of every JSON reader here: json.loads keeps the last of two equal members, so a file could
    name "version" twice and read as one place; such a file is refused instead."""
    names = [name for name, _ in pairs]
    twice = sorted({name for name in names if names.count(name) > 1})
    if twice:
        raise DuplicateMember(f"duplicate member {', '.join(twice)}")
    return dict(pairs)


def _no_constant(name: str) -> object:
    """parse_constant of every JSON reader here: json.loads takes NaN, Infinity and -Infinity, which are no JSON (line
    3 of the reading of 11cf1963), so a file with one of them is refused as not JSON."""
    raise ValueError(f"{name} is no JSON value")


def json_text(text: str, path: str) -> object:
    try:
        return json.loads(text, object_pairs_hook=_members, parse_constant=_no_constant)
    except DuplicateMember as exc:
        raise CheckFailed(f"{path}: {exc}") from exc
    except ValueError as exc:
        raise CheckFailed(f"{path}: not JSON") from exc


def json_blob(repo: Path, commit: str, path: str) -> dict:
    data = json_text(blob_text(repo, commit, path), path)
    if not isinstance(data, dict):
        raise CheckFailed(f"{path}: not a JSON object")
    return data


def ls_tree(repo: Path, commit: str, paths: list[str]) -> list[tuple[str, str, str, str]]:
    raw = git(repo, "ls-tree", "-r", "-z", "--full-tree", commit, "--", *paths)
    entries = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        meta, _, path = record.partition(b"\t")
        mode, kind, oid = meta.decode().split(" ")
        try:
            name = path.decode("ascii")
        except UnicodeDecodeError as exc:
            raise CheckFailed(f"a path is not ASCII: {path!r}") from exc
        entries.append((mode, kind, oid, name))
    entries.sort(key=lambda e: e[3].encode())
    return entries


# --- reading places -----------------------------------------------------------------------------------------------

#: How a module may use a name the generator reads with ast (py_constant, server_tools), as every such name is used at
#: main c9ab65b1: every mention of the name as a Python token, in the NFKC form Python reads it in, is an ast.Name at
#: that place, exactly one of them is written, as the only target of the top-level assignment the generator reads, and
#: all others are read. A binding in any other form (a pattern, global, an import, a parameter, a def, a keyword, a
#: second target, another spelling of the same name) is a token without such a name or a second write, and stops the
#: build. The TOOLS table is a dict, so besides it may only be looked up
#: (TOOLS[key], key in TOOLS) or read by one of TABLE_READS. Code that changes a module's globals by name at run time
#: (globals(), setattr on the module) is not read; the generator reads what the source writes.
TABLE_READS = ("items", "keys", "values", "get")


def _parse(source: str, path: str) -> ast.Module:
    try:
        return ast.parse(source, filename=path)
    except SyntaxError as exc:
        raise CheckFailed(f"{path}: not parseable as Python ({exc.msg}, line {exc.lineno})") from exc


def _name_tokens(source: str, name: str, path: str) -> set[tuple[int, int]]:
    """The places of the tokens of name, as (line, UTF-8 byte offset in the line), the unit of ast's col_offset:
    tokenize counts columns in characters, and a non-ASCII character before a read on its line made the two differ
    (the Codex pre-run of the reading of 023a7d8b)."""
    lines = io.StringIO(source).readlines()
    try:
        # Python reads an identifier in NFKC (the Codex pre-run of the reading of 9830cdf1: a fullwidth spelling in an
        # import binds the same name), so the tokens are compared in that form.
        return {(t.start[0], len(lines[t.start[0] - 1][:t.start[1]].encode("utf-8")))
                for t in tokenize.generate_tokens(io.StringIO(source).readline)
                if t.type == tokenize.NAME and unicodedata.normalize("NFKC", t.string) == name}
    except (tokenize.TokenError, SyntaxError) as exc:
        raise CheckFailed(f"{path}: not readable as Python tokens ({exc})") from exc


def _only_read(source: str, name: str, path: str, table: bool = False) -> None:
    tree = _parse(source, path)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    names = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == name]
    stray = sorted(_name_tokens(source, name, path) - {(n.lineno, n.col_offset) for n in names})
    if stray:
        raise CheckFailed(f"{path}: {name} is used otherwise than read after its assignment (line {stray[0][0]})")
    written = [n for n in names if not isinstance(n.ctx, ast.Load)]
    top = len(written) == 1 and isinstance(parents.get(written[0]), (ast.Assign, ast.AnnAssign)) and \
        parents.get(parents[written[0]]) is tree and \
        (getattr(parents[written[0]], "targets", None) == [written[0]] or
         getattr(parents[written[0]], "target", None) is written[0])
    if not top:
        lines = sorted(n.lineno for n in written) or [0]
        raise CheckFailed(f"{path}: {name} is written {len(written)} times, used otherwise than read after its "
                          f"assignment (line {lines[-1]})")
    for node in names:
        if node is written[0] or not table:
            continue
        parent = parents.get(node)
        if not ((isinstance(parent, ast.Subscript) and parent.value is node and isinstance(parent.ctx, ast.Load))
                or (isinstance(parent, ast.Compare) and node in parent.comparators
                    and all(isinstance(op, (ast.In, ast.NotIn)) for op in parent.ops))
                or (isinstance(parent, ast.Attribute) and parent.attr in TABLE_READS
                    and isinstance(parents.get(parent), ast.Call) and parents[parent].func is parent)):
            raise CheckFailed(f"{path}: {name} is used otherwise than read after its assignment (line {node.lineno})")


def _assignments(source: str, path: str) -> dict[str, list[ast.expr]]:
    tree = _parse(source, path)
    found: dict[str, list[ast.expr]] = {}
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        for target in targets:
            if isinstance(target, ast.Name) and node.value is not None:
                found.setdefault(target.id, []).append(node.value)
    return found


def py_constant(source: str, path: str, name: str) -> str:
    values = _assignments(source, path).get(name, [])
    if len(values) != 1:
        raise CheckFailed(f"{path}: {len(values)} top-level assignments of {name}, expected 1")
    value = values[0]
    if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
        raise CheckFailed(f"{path}: {name} is not a plain string")
    _only_read(source, name, path)
    return value.value


def script_blocks(text: str, where: str) -> list[str]:
    """The script metadata blocks of a Python text. PEP 723 defines them as top-level comment blocks while its
    reference pattern reads the raw text, so a block written into a string literal matched as well and stood for the
    pin (line 3 of the reading of c3dd68eb). Every line of a block read here is a comment token at column 0, as the
    servers and the gate's constants write it at main c9ab65b1 and b55d736d; any other block stops the build."""
    try:
        comments = {token.start[0] for token in tokenize.generate_tokens(io.StringIO(text).readline)
                    if token.type == tokenize.COMMENT and token.start[1] == 0}
    except (tokenize.TokenError, SyntaxError) as exc:
        raise CheckFailed(f"{where}: not readable as Python tokens ({exc})") from exc
    blocks = []
    for match in PEP723.finditer(text):
        if match.group("type") != "script":
            continue
        first, last = text.count("\n", 0, match.start()) + 1, text.count("\n", 0, match.end()) + 1
        if any(line not in comments for line in range(first, last + 1)):
            raise CheckFailed(f"{where}: a script metadata block at lines {first}-{last} that is not a comment")
        content = "".join(line[2:] if line.startswith("# ") else line[1:]
                          for line in match.group("content").splitlines(keepends=True))
        blocks.append(content)
    return blocks


def block_pin(content: str, where: str) -> str:
    if tomllib is None:
        raise NotMeasurable("reading script dependency metadata needs tomllib, Python 3.11 or later")
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise CheckFailed(f"{where}: script metadata is not TOML ({exc})") from exc
    deps = data.get("dependencies", [])
    if not isinstance(deps, list) or not all(isinstance(d, str) for d in deps):
        raise CheckFailed(f"{where}: dependencies is not a list of strings")
    pins = []
    for dep in deps:
        match = REQUIREMENT.match(dep)
        if not match:
            raise CheckFailed(f"{where}: dependency {dep!r} is not readable")
        if re.sub(r"[-_.]+", "-", match.group("name")).lower() != "proofbundle":
            continue
        spec = match.group("rest").strip()
        exact = re.fullmatch(r"==\s*(\d+\.\d+\.\d+)", spec)
        if not exact:
            raise CheckFailed(f"{where}: proofbundle dependency {dep!r} is not an exact == pin")
        pins.append(exact.group(1))
    if len(pins) != 1:
        raise CheckFailed(f"{where}: {len(pins)} proofbundle dependencies, expected exactly 1")
    # the pin alone, as every script block the generator reads lists it at main c9ab65b1: another entry, a dependency
    # on proofbundle-guard among them, was passed over (line 3 of the reading of e05c0c9f)
    if len(deps) != 1:
        raise CheckFailed(f"{where}: {len(deps) - 1} dependencies besides the proofbundle pin, expected none")
    # the entry exactly as main c9ab65b1 writes it: the requirement pattern takes extras, markers and blanks that
    # the pin check passed over, so proofbundle[!!!]==6.4.0 read as the pin (the Codex pre-run of the reading of
    # f842b7b4)
    if not re.fullmatch(r"proofbundle==\d+\.\d+\.\d+", deps[0]):
        raise CheckFailed(f"{where}: dependency {deps[0]!r} is not in the form proofbundle==X.Y.Z")
    return pins[0]


#: The encoding declaration of PEP 263, in the form the PEP gives for the first two lines of a file.
PEP263 = re.compile(r"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")


def _cells(line: str) -> list[str]:
    """The cells of a table row, with exactly one outer pipe removed on each side, so an empty edge cell stays a cell
    (the Codex pre-run of the reading of 92b47349: stripping every outer pipe dropped them)."""
    row = line.strip()
    row = row[1:] if row.startswith("|") else row
    row = row[:-1] if row.endswith("|") else row
    return [cell.strip() for cell in row.split("|")]


def catalog_versions(text: str, path: str, count: int) -> list[str]:
    """The version cells of the catalog rows of both hosts, read as the table is written at main c9ab65b1. The table
    runs from its head row, the one line whose first cell is Host, to the first blank line, as GitHub Markdown ends a
    table. Every line of it has the house form, starting and ending with a pipe, the second line is the delimiter row,
    and every further line is a row of a host with as many cells as the head, the host written as in
    CATALOG_HOST_NAMES and a version X.Y.Z in the Version column; each host has exactly one row, and no line outside
    the table names a host in its first cell. The readings of 149788f8, c2ff7601, 950d341d and e6cfbd9c found a
    pattern counting matches, a row written with other blanks, a later number of a row with one cell more and a row
    without its outer pipes; the table is now held to its form as a whole."""
    lines = text.split("\n")
    # Markdown shows no table inside HTML, a fenced or an indented code block; the catalog at main c9ab65b1 has none
    # of them and a blank line before its head, so any of them stops the build rather than letting a table that is
    # not shown stand for the catalog
    # no HTML at all (the Codex pre-run of the reading of 58ac91a2: a <pre> block shows no table either; the catalog
    # at main c9ab65b1 holds no < at all)
    if "<" in text or any(line.lstrip().startswith(("```", "~~~")) or line.startswith(("    ", "\t"))
                          for line in lines):
        raise CheckFailed(f"{path}: HTML or a code block in the catalog; the house writes it without either")
    heads = [i for i, line in enumerate(lines) if "|" in line and _cells(line)[0].casefold() == "host"]
    if len(heads) != 1:
        raise CheckFailed(f"{path}: {len(heads)} catalog heads with a first cell Host, expected 1")
    start = heads[0]
    if start > 0 and lines[start - 1].strip():
        raise CheckFailed(f"{path}: the catalog head does not follow a blank line")
    end = next((i for i in range(start, len(lines)) if not lines[i].strip()), len(lines))
    table = lines[start:end]
    head = _cells(table[0])
    # the delimiter row as the house writes it, one --- per column of the head (the Codex pre-run of the reading of
    # b0828838: a narrower delimiter row makes no table, and the check took it)
    # no backslash in the table, as at main c9ab65b1: an escaped pipe is cell content to Markdown and a cell border to
    # the split here, so it moved the Version column (the Codex pre-run of the reading of 1bc66c8d)
    if any("\\" in line for line in table):
        raise CheckFailed(f"{path}: a backslash in the catalog table; the house writes the table without escapes")
    if any(not (line.startswith("|") and line.endswith("|")) for line in table) or len(table) < 2 \
            or table[1] != "|" + "---|" * len(head) or head.count("Version") != 1:
        raise CheckFailed(f"{path}: the catalog table is not in the house form (pipes at both ends of every line, a "
                          "delimiter row, one Version column)")
    width, column = len(head), head.index("Version")
    found = [_cells(line) for line in table[2:]]
    for cells in found:
        if len(cells) != width or cells[0] not in CATALOG_HOST_NAMES or not VERSION_CELL.fullmatch(cells[column]):
            raise CheckFailed(f"{path}: a catalog row not in the form of the head ({cells[0]!r}, {len(cells)} cells, "
                              f"expected a host and {width})")
    # one table in the file and no character reference, as at main c9ab65b1: a second table could name a host only
    # once Markdown renders it, by emphasis or a reference such as &#67; (the Codex pre-run of the reading of
    # cfbc30ca), so no line outside the catalog table holds a pipe and no line of the file an ampersand
    outside = [i + 1 for i, line in enumerate(lines) if not start <= i < end and "|" in line]
    if outside or "&" in text:
        raise CheckFailed(f"{path}: a pipe outside the catalog table or a character reference "
                          f"(line {outside[0] if outside else 0}); the house writes one table and no reference")
    names = sorted(cells[0] for cells in found)
    if len(found) != count or names != sorted(CATALOG_HOST_NAMES):
        raise CheckFailed(f"{path}: catalog rows of {names}, expected one each of {sorted(CATALOG_HOST_NAMES)}")
    return [cells[column] for cells in found]


def python_text(text: str, path: str) -> str:
    """A Python file the generator reads with ast, tokenize or the PEP 723 pattern, which it reads with LF line ends
    only, as every such file at main c9ab65b1 has: ast takes a lone CR for a line end while the token reader and the
    PEP 723 pattern do not, so a place could be read otherwise than Python reads it (the Codex pre-run of the reading
    of 7cf13c55). A CR in such a file stops the build."""
    if "\r" in text:
        raise CheckFailed(f"{path}: CR line ends; the generator reads Python files with LF line ends only")
    # Python decodes a file by its BOM or its coding cookie (PEP 263), the generator every file as UTF-8; no file it
    # reads this way carries either at main c9ab65b1, so either stops the build.
    if text.startswith("\ufeff") or any(PEP263.match(line) for line in text.split("\n")[:2]):
        raise CheckFailed(f"{path}: a BOM or an encoding declaration; the generator reads Python files as UTF-8 "
                          "without either")
    return text


def read_place(repo: Path, commit: str, kind: str, path: str, name: str | None, count: int) -> list[str]:
    text = blob_text(repo, commit, path)
    if kind in ("py_constant", "file_blocks", "const_block"):
        text = python_text(text, path)
    if kind == "json_version":
        data = json_text(text, path)
        if not isinstance(data, dict) or not isinstance(data.get("version"), str):
            raise CheckFailed(f"{path}: no string member version")
        return [data["version"]]
    if kind == "py_constant":
        return [py_constant(text, path, name)]
    if kind == "file_blocks":
        blocks = script_blocks(text, path)
        if len(blocks) != count:
            raise CheckFailed(f"{path}: {len(blocks)} script metadata blocks, expected {count}")
        return [block_pin(b, f"{path} block {i}") for i, b in enumerate(blocks, 1)]
    if kind == "const_block":
        # the constant is a script the gate writes out and runs, read like a file (python_text): LF line ends only, no
        # BOM and no encoding declaration, as both constants at main c9ab65b1 hold
        where = f"{path} {name}"
        blocks = script_blocks(python_text(py_constant(text, path, name), where), where)
        if len(blocks) != 1:
            raise CheckFailed(f"{path}: {len(blocks)} script metadata blocks in {name}, expected 1")
        return [block_pin(blocks[0], f"{path} {name}")]
    if kind == "catalog_rows":
        return catalog_versions(text, path, count)
    raise NotMeasurable(f"unknown place kind {kind}")


# --- checks -------------------------------------------------------------------------------------------------------

def check_required_paths(repo: Path, commit: str, layout: dict) -> None:
    for path in (LICENSE, *layout["marketplaces"]):
        entry = tree_entry(repo, commit, path)
        if entry is None or entry[1] != "blob" or entry[0] != "100644":
            raise CheckFailed(f"{path}: required as a regular file (100644), found {entry}")
    for root in layout["roots"].values():
        entry = tree_entry(repo, commit, root)
        if entry is None or entry[1] != "tree":
            raise CheckFailed(f"{root}: required as a tree, found {entry}")
        if not ls_tree(repo, commit, [root]):
            raise CheckFailed(f"{root}: an empty tree")


def _resolve(base: str, source: object) -> str | None:
    """The repository path a marketplace source names from the folder BASE, or None when it is no relative path that
    stays inside the repository."""
    if not isinstance(source, str) or not (source == "./" or source.startswith("./")):
        return None
    parts = [p for p in (base.split("/") if base else []) + source[2:].split("/") if p not in ("", ".")]
    if ".." in parts:
        return None
    return "/".join(parts)


def check_marketplaces(repo: Path, commit: str, layout: dict, version: str) -> list[str]:
    lines = []
    for path, spec in layout["marketplaces"].items():
        market = json_blob(repo, commit, path)
        if spec["name"] is not None and market.get("name") != spec["name"]:
            raise CheckFailed(f"{path}: marketplace name {market.get('name')!r}, expected {spec['name']!r}")
        entries = market.get("plugins")
        if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
            raise CheckFailed(f"{path}: no plugins list of objects")
        names = [e.get("name") for e in entries]
        if sorted(map(str, names)) != sorted(spec["entries"]) or len(set(names)) != len(names):
            raise CheckFailed(f"{path}: entries {names}, expected exactly {sorted(spec['entries'])}")
        for entry in entries:
            name = entry["name"]
            root = layout["roots"][name]
            if entry.get("source") != spec["entries"][name]:
                raise CheckFailed(f"{path}: entry {name} source {entry.get('source')!r}, "
                                  f"expected {spec['entries'][name]!r}")
            if _resolve(spec["base"], entry["source"]) != root:
                raise CheckFailed(f"{path}: entry {name} source {entry['source']!r} does not resolve to {root}")
            if "version" in entry and entry["version"] != version:
                raise CheckFailed(f"{path}: entry {name} version {entry['version']!r}, expected {version!r}")
            manifest = json_blob(repo, commit, root + "/.claude-plugin/plugin.json")
            if manifest.get("name") != name:
                raise CheckFailed(f"{root}/.claude-plugin/plugin.json: name {manifest.get('name')!r}, expected {name!r}")
            codex = tree_entry(repo, commit, root + "/.codex-plugin/plugin.json")
            if codex is not None and json_blob(repo, commit, root + "/.codex-plugin/plugin.json").get("name") != name:
                raise CheckFailed(f"{root}/.codex-plugin/plugin.json: name differs from {name!r}")
            lines.append(f"check marketplace {path} entry {name} -> {entry['source']} resolves to {root}, "
                         "manifest name equal")
    return lines


def hook_programs(command: object, root: str) -> list[str] | None:
    """The path of the program a hook command starts, as a list of one, or None where the command is no string, is
    not one of its host's HOOK_TEMPLATES as a whole, names a plugin root more than once, or names a path with a "."
    or ".." segment."""
    if not isinstance(command, str):
        return None
    m = next((m for m in (pattern.fullmatch(command) for pattern in HOOK_START[root]) if m), None)
    if m is None or command.count("PLUGIN_ROOT") != 1:
        return None
    path = m.group(1)
    if any(part in (".", "..") for part in path.split("/")):
        return None
    return [path]


def _hook_commands(value: object) -> list[object]:
    """The values of every "command" member of a hook structure, of any type, so a command that is no string is
    refused rather than passed over."""
    if isinstance(value, dict):
        return [v for k, v in value.items() if k == "command"] + \
            [c for k, v in value.items() if k != "command" for c in _hook_commands(v)]
    if isinstance(value, list):
        return [c for v in value for c in _hook_commands(v)]
    return []


def server_tools(repo: Path, commit: str, path: str) -> list[str]:
    """The keys of the top-level TOOLS table of an MCP server, read with ast, in the order written."""
    source = python_text(blob_text(repo, commit, path), path)
    tables = _assignments(source, path).get("TOOLS", [])
    if len(tables) != 1 or not isinstance(tables[0], ast.Dict):
        raise CheckFailed(f"{path}: {len(tables)} top-level TOOLS tables, expected one dict literal")
    _only_read(source, "TOOLS", path, table=True)
    keys = []
    for key in tables[0].keys:
        if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
            raise CheckFailed(f"{path}: a TOOLS key is not a plain string")
        keys.append(key.value)
    return keys


def mcp_servers(repo: Path, commit: str, path: str) -> list[str]:
    """The names of the MCP servers a manifest or an .mcp.json file declares."""
    if tree_entry(repo, commit, path) is None:
        return []
    servers = json_blob(repo, commit, path).get("mcpServers", {})
    if not isinstance(servers, dict):
        raise CheckFailed(f"{path}: mcpServers is not an object")
    return sorted(servers)


def check_public_profile(repo: Path, commit: str, layout: dict) -> list[str]:
    root = layout["public_root"]
    if root is None:
        return ["check public profile not applicable in this layout"]
    if tree_entry(repo, commit, root + "/hooks") is not None:
        raise CheckFailed(f"{root}/hooks: the public verifier holds a hooks folder (a Verify state holds none, "
                          "tests/test_plugin_verify_carries_no_guard.py)")
    for rel in ("/.claude-plugin/plugin.json", "/.codex-plugin/plugin.json"):
        if tree_entry(repo, commit, root + rel) is None:
            continue
        manifest = json_blob(repo, commit, root + rel)
        if "hooks" in manifest:
            raise CheckFailed(f"{root}{rel}: a hooks field in the public verifier")
        deps = manifest.get("dependencies", [])
        names = [d if isinstance(d, str) else d.get("name") if isinstance(d, dict) else None
                 for d in (deps if isinstance(deps, list) else [deps])]
        if any(isinstance(n, str) and n.split("@")[0] == "proofbundle-guard" for n in names):
            raise CheckFailed(f"{root}{rel}: the public verifier depends on proofbundle-guard")
    market = json_blob(repo, commit, MARKETPLACE)
    for entry in market["plugins"]:
        if entry.get("name") == "proofbundle":
            if "hooks" in entry:
                raise CheckFailed(f"{MARKETPLACE}: a hooks field in the public verifier's entry")
            deps = entry.get("dependencies", [])
            if any((d if isinstance(d, str) else d.get("name", "")).split("@")[0] == "proofbundle-guard"
                   for d in deps if isinstance(d, (str, dict))):
                raise CheckFailed(f"{MARKETPLACE}: the public verifier's entry depends on proofbundle-guard")
    # each host's registration of the verifier's server as main c9ab65b1 writes it, and none in the Claude Code
    # manifest (line 3 of the reading of 830dc0f9: the names alone let a registration named proofbundle start
    # another program than the server whose tools are read below)
    for rel, expected in MCP_REGISTRATIONS.items():
        servers = json_blob(repo, commit, root + rel).get("mcpServers") if tree_entry(repo, commit, root + rel) \
            else None
        if servers != expected:
            raise CheckFailed(f"{root}{rel}: MCP servers {servers!r}, expected exactly {expected!r}")
    if "mcpServers" in json_blob(repo, commit, root + "/.claude-plugin/plugin.json"):
        raise CheckFailed(f"{root}/.claude-plugin/plugin.json: an mcpServers field in the public verifier's Claude "
                          "Code manifest; its server is registered in .mcp.json")
    tools = server_tools(repo, commit, root + "/server/proofbundle_mcp.py")
    if sorted(tools) != sorted(VERIFIER_TOOLS) or len(set(tools)) != len(tools):
        raise CheckFailed(f"{root}/server/proofbundle_mcp.py: tools {sorted(tools)}, expected {sorted(VERIFIER_TOOLS)}")
    return [f"check public profile {root}: no hooks folder, no hooks field, no dependency on the Guard",
            f"check public profile {root}: one MCP server proofbundle in .mcp.json and the Codex manifest, "
            f"{len(tools)} tools " + " ".join(sorted(tools))]


def check_guard_profile(repo: Path, commit: str, layout: dict) -> list[str]:
    root = layout["guard_root"]
    if root is None:
        return ["check guard profile not applicable in this layout"]
    hooks_file, gate = root + "/hooks/hooks.json", root + "/hooks/proofbundle_gate.py"
    for path in (hooks_file, gate):
        entry = tree_entry(repo, commit, path)
        if entry is None or entry[1] != "blob" or entry[0] not in ("100644", "100755"):
            raise CheckFailed(f"{path}: required in the Guard as a regular file, found {entry}")
    # The Guard registers its Claude Code hooks in hooks/hooks.json alone, as at main c9ab65b1: a hooks field in its
    # Claude Code manifest or in its house marketplace entry would add hooks no check here reads, so it stops the build.
    if "hooks" in json_blob(repo, commit, root + "/.claude-plugin/plugin.json"):
        raise CheckFailed(f"{root}/.claude-plugin/plugin.json: a hooks field in the Guard's Claude Code manifest; the "
                          "Guard registers its Claude Code hooks in hooks/hooks.json")
    for market, spec in layout["marketplaces"].items():
        if layout["roots"].get("proofbundle-guard") == root and "proofbundle-guard" in spec["entries"]:
            for entry in json_blob(repo, commit, market).get("plugins", []):
                if isinstance(entry, dict) and entry.get("name") == "proofbundle-guard" and "hooks" in entry:
                    raise CheckFailed(f"{market}: a hooks field in the house marketplace entry of proofbundle-guard")
    registered = json_blob(repo, commit, hooks_file).get("hooks", {})
    if not isinstance(registered, dict):
        raise CheckFailed(f"{hooks_file}: hooks is not an object")
    commands = [(c, CLAUDE_ROOT) for c in _hook_commands(registered)]
    codex = root + "/.codex-plugin/plugin.json"
    if tree_entry(repo, commit, codex) is not None:
        codex_hooks = json_blob(repo, commit, codex).get("hooks", {})
        if not isinstance(codex_hooks, dict):
            raise CheckFailed(f"{codex}: hooks is not an object the generator reads")
        commands += [(c, CODEX_ROOT) for c in _hook_commands(codex_hooks)]
    started = set()
    for command, host_root in commands:
        found = hook_programs(command, host_root)
        if found is None:
            raise CheckFailed(f"{root}: the hook command {command!r} names no program of the Guard in a form the "
                              "generator reads")
        started.update(found)
    programs = sorted(started)
    if not programs:
        raise CheckFailed(f"{root}: no hook of either host starts a program of the Guard")
    for program in programs:
        entry = tree_entry(repo, commit, f"{root}/{program}")
        if entry is None or entry[1] != "blob" or entry[0] not in ("100644", "100755"):
            raise CheckFailed(f"{root}: a hook starts {program}, which the Guard does not hold")
    if tree_entry(repo, commit, root + "/skills") is not None:
        raise CheckFailed(f"{root}/skills: the Guard adds no skill")
    for rel in ("/.mcp.json", "/.claude-plugin/plugin.json", "/.codex-plugin/plugin.json"):
        servers = mcp_servers(repo, commit, root + rel)
        if servers:
            raise CheckFailed(f"{root}{rel}: the Guard registers the MCP servers {servers}")
    own = tree_entry(repo, commit, root + "/server/proofbundle_mcp.py")
    public = tree_entry(repo, commit, layout["public_root"] + "/server/proofbundle_mcp.py")
    if own is None or public is None or own[2] != public[2]:
        raise CheckFailed(f"{root}/server/proofbundle_mcp.py: not byte-equal to the verifier's server")
    return [f"check guard profile {root}: hooks/hooks.json and the gate present, every started program present "
            f"({len(programs)}: {' '.join(programs)}), no skills folder, no MCP server, server equal to the verifier's"]


def _build_tar(repo: Path, entries: list[tuple[str, str, str, str]], prefix: str, mtime: int) -> bytes:
    def info(name: str, kind: bytes, mode: int, size: int = 0) -> tarfile.TarInfo:
        item = tarfile.TarInfo(name)
        item.type, item.mode, item.mtime, item.size = kind, mode, mtime, size
        item.uid = item.gid = 0
        item.uname = item.gname = ""
        return item

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT, encoding="ascii") as tar:
        seen: set[str] = set()
        tar.addfile(info(prefix, tarfile.DIRTYPE, 0o755))
        for mode, kind, oid, path in entries:
            parts = path.split("/")[:-1]
            for i in range(1, len(parts) + 1):
                d = "/".join(parts[:i])
                if d not in seen:
                    seen.add(d)
                    tar.addfile(info(prefix + d + "/", tarfile.DIRTYPE, 0o755))
            data = git(repo, "cat-file", "blob", oid)
            item = info(prefix + path, tarfile.REGTYPE, 0o755 if mode == "100755" else 0o644, len(data))
            tar.addfile(item, io.BytesIO(data))
    return buf.getvalue()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def statement_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def sums_bytes(a2_name: str, a2_sha: str, a1_name: str, a1_sha: str) -> bytes:
    return "".join(f"{h}  {n}\n" for n, h in sorted(((a2_name, a2_sha), (a1_name, a1_sha)))).encode("ascii")


def tag_message(version: str, a2_sha: str) -> bytes:
    return (f"proofbundle plugin {version}\n"
            "\n"
            f"The first plugin-specific tag and GitHub release for proofbundle {version} for Claude Code\n"
            "and Codex, from the commit named by this tag. Release statement\n"
            f"proofbundle-plugin-{version}.release.json, SHA-256 {a2_sha}, signed by the owner;\n"
            "the signature is an asset of the GitHub release.\n").encode("utf-8")


def tag_object(commit: str, tag: str, epoch: int, message: bytes) -> bytes:
    head = f"object {commit}\ntype commit\ntag {tag}\ntagger {TAGGER} {epoch} +0000\n\n".encode("utf-8")
    return head + message


def git_object_id(kind: str, data: bytes, algo: str) -> str:
    h = hashlib.new(algo)
    h.update(f"{kind} {len(data)}\0".encode() + data)
    return h.hexdigest()


def cmd_build(args: argparse.Namespace) -> int:
    repo, out = Path(args.repo), Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise NotMeasurable(f"the output folder is not empty: {out.name}")
    if not SEMVER.fullmatch(args.version) or not SEMVER.fullmatch(args.expect_pin):
        raise NotMeasurable("--version and --expect-pin take X.Y.Z")
    layout = INVENTORIES[args.layout]
    commit = _resolve_commit(repo, args.commit)
    lines: list[str] = []
    say = lines.append
    say("proofbundle plugin release artifacts")
    say(f"layout {args.layout}")
    say(f"commit {commit}")
    commit_tree = git(repo, "rev-parse", "--verify", commit + "^{tree}").decode().strip()
    say(f"commit_tree {commit_tree}")
    epoch = int(git(repo, "show", "-s", "--format=%ct", commit).decode().strip())
    say(f"committer_time_unix {epoch}")
    try:
        check_required_paths(repo, commit, layout)
        say(f"check required paths {LICENSE}, " + ", ".join(layout["marketplaces"]) + ", "
            + ", ".join(layout["roots"].values()))
        trees = {name: git(repo, "rev-parse", "--verify", f"{commit}:{root}").decode().strip()
                 for name, root in layout["roots"].items()}
        for name in sorted(trees):
            say(f"tree {name} {trees[name]}")
        marketplace_blob = git(repo, "rev-parse", "--verify", f"{commit}:{MARKETPLACE}").decode().strip()
        say(f"marketplace_blob {marketplace_blob}")
        for path in layout["marketplaces"]:
            if path != MARKETPLACE:
                say(f"house_marketplace_blob {path} "
                    + git(repo, "rev-parse", "--verify", f"{commit}:{path}").decode().strip())
        problems = []
        for role, kind, path, name, count in layout["places"]:
            label = f"{path}" + (f" {name}" if name else "") + f" ({kind})"
            expected = args.version if role == "version" else args.expect_pin
            try:
                values = read_place(repo, commit, kind, path, name, count)
            except CheckFailed as exc:
                problems.append(f"{role} {exc}")
                continue
            for value in values:
                verdict = "ok" if value == expected else "WRONG"
                say(f"{role}_place {label} {value} expected {expected} {verdict}")
                if value != expected:
                    problems.append(f"{role} {label} says {value}, expected {expected}")
        if problems:
            raise CheckFailed("; ".join(problems))
        say(f"check every version place says {args.version}, every pin place proofbundle=={args.expect_pin}")
        lines.extend(check_marketplaces(repo, commit, layout, args.version))
        lines.extend(check_public_profile(repo, commit, layout))
        lines.extend(check_guard_profile(repo, commit, layout))
        selected = [LICENSE, MARKETPLACE, *layout["roots"].values()]
        entries = ls_tree(repo, commit, selected)
        for mode, kind, oid, path in entries:
            if kind != "blob" or mode not in ("100644", "100755"):
                raise CheckFailed(f"{path}: mode {mode} ({kind}) is no regular file; links and gitlinks need an "
                                  "explicit change of this generator")
        say(f"check archive entries are regular files: {len(entries)}")
    except CheckFailed as exc:
        say(f"check FAILED {exc}")
        say("result FAILED, no artifact written")
        sys.stdout.write("\n".join(lines) + "\n")
        return 1

    version = args.version
    stem = f"proofbundle-plugin-{version}"
    tag = f"proofbundle--v{version}"
    a1_name, a2_name = stem + ".tar", stem + ".release.json"
    a1 = _build_tar(repo, entries, stem + "/", epoch)
    statement = {
        "schema": STATEMENT_SCHEMA,
        "plugin": STATEMENT_PLUGIN,
        "version": version,
        "repository": REPOSITORY_URL,
        "commit": commit,
        "commit_tree": commit_tree,
        "plugin_tree": trees["proofbundle"],
        "marketplace_blob": marketplace_blob,
        "tag": tag,
        "verifier_pin": f"proofbundle=={args.expect_pin}",
        "archive": {"name": a1_name, "size": len(a1), "sha256": sha256(a1)},
    }
    a2 = statement_bytes(statement)
    a3 = sums_bytes(a2_name, sha256(a2), a1_name, sha256(a1))
    message = tag_message(version, sha256(a2))
    t1 = tag_object(commit, tag, epoch, message)
    algo = "sha1" if len(commit) == 40 else "sha256"

    out.mkdir(parents=True, exist_ok=True)
    artifacts = ((a1_name, a1), (a2_name, a2), ("SHA256SUMS", a3))
    for name, data in artifacts:
        (out / name).write_bytes(data)
    if args.tag_out:
        Path(args.tag_out).write_bytes(t1)
    if args.inventory_out:
        inv = []
        for mode, kind, oid, path in entries:
            data = git(repo, "cat-file", "blob", oid)
            mark = " REVIEW" if REVIEW_NAME.search(path) else ""
            inv.append(f"{mode} {len(data)} {sha256(data)} {path}{mark}\n")
        Path(args.inventory_out).write_text("".join(inv), encoding="ascii")
    review = [e[3] for e in entries if REVIEW_NAME.search(e[3])]
    say(f"review_names {len(review)}" + ("" if not review else " " + " ".join(review)))
    for name, data in artifacts:
        say(f"artifact {name} size {len(data)} sha256 {sha256(data)}")
    say(f"tag_name {tag}")
    say(f"to_sign_file {a2_name}")
    say(f"to_sign_size {len(a2)}")
    say(f"to_sign_sha256 {sha256(a2)}")
    say(f"to_sign_bytes {a2.decode('ascii')}")
    say(f"t1_tagger_epoch {epoch}")
    say(f"t1_message_sha256 {sha256(message)}")
    say(f"t1_object_sha256 {sha256(t1)}")
    say(f"t1_expected_object_id {git_object_id('tag', t1, algo)}")
    say("result OK")
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


# --- verify -------------------------------------------------------------------------------------------------------

def cmd_verify(args: argparse.Namespace) -> int:
    try:
        from proofbundle._wire_b64 import decode_b64  # noqa: PLC0415
        from proofbundle.signature import verify_ed25519_pinned  # noqa: PLC0415
    except ImportError as exc:
        raise NotMeasurable("verify needs the proofbundle package: its strict base64 reader and its Ed25519 check "
                            "for a pinned key") from exc
    assets = Path(args.assets)
    lines: list[str] = []
    say = lines.append

    def fail(why: str) -> int:
        say(f"check FAILED {why}")
        say("result FAILED")
        sys.stdout.write("\n".join(lines) + "\n")
        return 1

    try:
        raw_key = decode_b64(args.public_key)
    except ValueError:
        raise NotMeasurable("--public-key is not canonical standard base64") from None
    if len(raw_key) != 32:
        raise NotMeasurable("--public-key is not 32 raw bytes")
    say(f"public_key_raw_sha256 {sha256(raw_key)}")
    statements = sorted(assets.glob("proofbundle-plugin-*.release.json"))
    if len(statements) != 1:
        return fail(f"{len(statements)} release statements in the folder, expected 1")
    a2_path = statements[0]
    s1_path = a2_path.with_name(a2_path.name + ".sig")
    a2 = a2_path.read_bytes()
    say(f"a2 {a2_path.name} size {len(a2)} sha256 {sha256(a2)}")
    if not s1_path.is_file():
        return fail(f"{s1_path.name} is missing")
    s1 = s1_path.read_bytes()
    if len(s1) != 89 or not s1.endswith(b"\n") or b"\n" in s1[:-1]:
        return fail(f"{s1_path.name} is not 88 base64 characters and one LF ({len(s1)} bytes)")
    try:
        signature = decode_b64(s1[:-1])
    except ValueError:
        return fail(f"{s1_path.name} is not canonical standard base64")
    if len(signature) != 64:
        return fail(f"{s1_path.name} does not decode to exactly 64 bytes")
    if not verify_ed25519_pinned(raw_key, signature, a2):
        return fail("the signature does not verify over the exact A2 bytes under the given key, or the key is "
                    "no sound Ed25519 trust anchor")
    say("check S1 verifies over the exact A2 bytes")
    try:
        # the generator's strict reader (no NaN or Infinity, no member twice), as json.dumps would write NaN back
        obj = json.loads(a2, object_pairs_hook=_members, parse_constant=_no_constant)
    except ValueError:
        return fail("A2 is not JSON")
    if statement_bytes(obj) != a2:
        return fail("A2 is not in its canonical form")
    members = {"schema", "plugin", "version", "repository", "commit", "commit_tree", "plugin_tree",
               "marketplace_blob", "tag", "verifier_pin", "archive"}
    if set(obj) != members:
        return fail(f"A2 members {sorted(obj)}")
    version = obj["version"]
    expected = {"schema": STATEMENT_SCHEMA, "plugin": STATEMENT_PLUGIN, "repository": REPOSITORY_URL,
                "tag": f"proofbundle--v{version}"}
    for key, value in expected.items():
        if obj[key] != value:
            return fail(f"A2 {key} is {obj[key]!r}, expected {value!r}")
    if not SEMVER.fullmatch(version) or a2_path.name != f"proofbundle-plugin-{version}.release.json":
        return fail("A2 version and file name disagree")
    for key in ("commit", "commit_tree", "plugin_tree", "marketplace_blob"):
        if not isinstance(obj[key], str) or not HEX40.fullmatch(obj[key]):
            return fail(f"A2 {key} is not an object id")
    if not re.fullmatch(r"proofbundle==\d+\.\d+\.\d+", str(obj["verifier_pin"])):
        return fail("A2 verifier_pin malformed")
    archive = obj["archive"]
    if not (isinstance(archive, dict) and set(archive) == {"name", "size", "sha256"}
            and archive["name"] == f"proofbundle-plugin-{version}.tar" and isinstance(archive["size"], int)
            and isinstance(archive["sha256"], str) and HEX64.fullmatch(archive["sha256"])):
        return fail("A2 archive member malformed")
    say("check A2 canonical, members and values as expected")
    a1_path = assets / archive["name"]
    if not a1_path.is_file():
        return fail(f"{archive['name']} is missing")
    a1 = a1_path.read_bytes()
    if len(a1) != archive["size"] or sha256(a1) != archive["sha256"]:
        return fail(f"{archive['name']} size {len(a1)} sha256 {sha256(a1)} differ from A2")
    say(f"check A1 {archive['name']} size and SHA-256 equal A2")
    a3_path = assets / "SHA256SUMS"
    if not a3_path.is_file():
        return fail("SHA256SUMS is missing")
    if a3_path.read_bytes() != sums_bytes(a2_path.name, sha256(a2), archive["name"], archive["sha256"]):
        return fail("SHA256SUMS differs from its reconstruction")
    say("check A3 equals its reconstruction byte for byte")
    if args.repo:
        repo = Path(args.repo)
        ref = f"refs/tags/{obj['tag']}"
        try:
            kind = git(repo, "cat-file", "-t", ref).decode().strip()
            peeled = git(repo, "rev-parse", "--verify", ref + "^{commit}").decode().strip()
        except NotMeasurable:
            return fail(f"{ref} not found in the repository")
        if kind != "tag":
            return fail(f"{ref} is a {kind}, not an annotated tag")
        if peeled != obj["commit"]:
            return fail(f"{ref} names {peeled}, A2 names {obj['commit']}")
        say(f"check {ref} is annotated and names the A2 commit")
    say("result OK")
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


# --- scan ---------------------------------------------------------------------------------------------------------

PLUGIN_PATHS = (":(glob)plugins/**", ":(glob).claude-plugin/**", ":(glob)tests/*plugin*")
SCAN_PATTERNS = (
    ("version", r"(^|[^0-9.])0\.[34]\.0([^0-9]|$)", PLUGIN_PATHS + (":(glob)docs/release_scope/**",)),
    ("pin", r"proofbundle==[0-9]|PINNED_PROOFBUNDLE|(^|[^0-9.])6\.[34]\.0([^0-9]|$)", PLUGIN_PATHS),
)


def cmd_scan(args: argparse.Namespace) -> int:
    repo = Path(args.repo)
    lines: list[str] = []
    for rev in args.commit:
        commit = _resolve_commit(repo, rev)
        lines.append(f"commit {commit}")
        for label, pattern, paths in SCAN_PATTERNS:
            proc = subprocess.run(["git", "-C", str(repo), "grep", "-n", "-I", "-E", pattern, commit, "--", *paths],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  env=_git_env(), check=False)
            if proc.returncode not in (0, 1):
                raise NotMeasurable(f"git grep exited {proc.returncode}")
            hits = proc.stdout.decode("utf-8", "replace").splitlines()
            lines.append(f"{label} {len(hits)}")
            for hit in hits:
                rest = hit[len(commit) + 1:] if hit.startswith(commit + ":") else hit
                path, _, tail = rest.partition(":")
                number, _, content = tail.partition(":")
                content = content.strip()
                lines.append(f"  {label} {path}:{number} {content[:157] + '...' if len(content) > 160 else content}")
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--repo", required=True)
    b.add_argument("--commit", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--version", required=True)
    b.add_argument("--expect-pin", required=True)
    b.add_argument("--layout", choices=sorted(INVENTORIES), default="split")
    b.add_argument("--tag-out")
    b.add_argument("--inventory-out")
    v = sub.add_parser("verify")
    v.add_argument("--assets", required=True)
    v.add_argument("--public-key", required=True)
    v.add_argument("--repo")
    s = sub.add_parser("scan")
    s.add_argument("--repo", required=True)
    s.add_argument("--commit", required=True, action="append")
    args = parser.parse_args(argv)
    try:
        return {"build": cmd_build, "verify": cmd_verify, "scan": cmd_scan}[args.cmd](args)
    except CheckFailed as exc:
        sys.stdout.write(f"check FAILED {exc}\nresult FAILED\n")
        return 1
    except (NotMeasurable, OSError, ValueError, UnicodeDecodeError) as exc:
        sys.stderr.write(f"NOT MEASURABLE: {exc}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
