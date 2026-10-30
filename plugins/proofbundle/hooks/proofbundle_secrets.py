"""The key files and credential stores an agent must not read (DECISIONS.md D102, follow-up note 33, fallbook l01 and l02).

The PreToolUse hook of the file tools Read and Grep runs this script on its own, so a read costs the start of a small
program and not of the whole gate (measured with Python 3.13: 39 ms against 350 ms, most of which is the compilation of
the gate); for a key path it hands the call to the gate, which denies it, logs it and writes the short line. The gate
loads this file for the words of a Bash command. Both compare paths only: they never open, list or stat a file inside
a key folder or a key file, and they read no file's content.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys

#: Folders whose every file is a key or a credential, by their name anywhere in a path.
SECRET_FOLDERS = (".ssh", ".gnupg")
#: Files that hold a credential, by their last parts anywhere in a path.
SECRET_FILES = ((".netrc",), (".git-credentials",), (".aws", "credentials"), (".config", "gh", "hosts.yml"),
                (".docker", "config.json"), (".kube", "config"), (".pypirc",), (".npmrc",),
                (".claude", ".credentials.json"), (".codex", "auth.json"),
                (".config", "gcloud", "application_default_credentials.json"), (".config", "gcloud", "credentials.db"))
#: The names private keys of ssh have, anywhere.
SECRET_NAMES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk")
#: The endings of a key or a key store, unless the name says it is public (SECRET_PUBLIC).
SECRET_SUFFIXES = (".key", ".pem", ".p12", ".pfx", ".ppk", ".jks", ".keystore")
SECRET_PUBLIC = (".pub", "public", "cert", ".crt", "chain")
#: The programs that only name or test a path in the folder of keys, never read a file in it.
NAME_ONLY_PROGRAMS = ("ls", "test", "[")
#: The tools of Claude Code whose input names a path they read.
READ_TOOLS = {"Read": "file_path", "Grep": "path"}
#: The most links followed while resolving a path.
MAX_LINKS = 40


def _role(parts: list[str], final: bool) -> str | None:
    """The role that makes a path, given as its parts, a key path; None where it is none. A folder of SECRET_FOLDERS
    counts as any part; the names and endings of key files only as the last part of the whole path (final)."""
    if parts and parts[-1] in SECRET_FOLDERS and final:
        return "a folder of keys"
    if any(part in SECRET_FOLDERS for part in parts):
        return "a file in a folder of keys"
    if not final or not parts:
        return None
    if any(tuple(parts[-len(f):]) == f for f in SECRET_FILES):
        return "a store of credentials"
    name = parts[-1]
    if name in SECRET_NAMES:
        return "a private key"
    lowered = name.lower()
    if lowered.endswith(SECRET_SUFFIXES) and not any(m in lowered for m in SECRET_PUBLIC):
        return "a key file"
    return None


def named_path(path: str, cwd: str | None, home: str | None, *, normalise: bool = True) -> str | None:
    """The absolute path a word names: `~` and `~/x` from home, a relative one from cwd; None where it cannot be told.
    With normalise=False the `..` parts stay where they are written: the operating system applies them only after it has
    followed a link before them, and so must the walk in secret_problem (reading of G-2, part 10, P1)."""
    if path == "~" or path.startswith("~/"):
        if not home or not os.path.isabs(home):
            return None
        path = home + path[1:]
    if not os.path.isabs(path):
        if not cwd or not os.path.isabs(cwd):
            return None
        path = os.path.join(cwd, path)
    return os.path.normpath(path) if normalise else path


def relative_role(path: str) -> str | None:
    """The role of a relative path whose folder the gate cannot tell, by its own parts as written."""
    return _role([p for p in os.path.normpath(path).split(os.sep) if p not in ("", ".")], True)


def secret_problem(path: str, cwd: str | None, home: str | None) -> str | None:
    """The role that makes a path a key file, a credential store or a path in a folder of keys, as written or after the
    links it goes through, without the path, which HOME may decide; None for any other path. The walk stops before it
    touches a part that is a key path: it stats and reads links of the parts before such a part only, never the part
    itself or anything below it."""
    named = named_path(path, cwd, home)
    if named is None:
        return None
    role = _role([p for p in named.split(os.sep) if p], True)
    if role:
        return role
    # The walk takes the parts as written, `..` included: `<link>/../x` is the parent of the link's target, not of the
    # link, and a lexical normalisation before the walk would have looked at the wrong folder.
    links, done, todo = 0, [], [p for p in named_path(path, cwd, home, normalise=False).split(os.sep) if p]
    while todo:
        part = todo.pop(0)
        if part == "..":
            if done:
                done.pop()
            continue
        if part in ("", "."):
            continue
        here = done + [part]
        role = _role(here, not todo)
        if role:
            return f"{role}, through a link"
        current = os.sep + os.sep.join(here)
        try:
            mode = os.lstat(current).st_mode
        except (OSError, ValueError):   # a NUL byte names no file
            done = here
            continue
        if stat.S_ISLNK(mode):
            links += 1
            if links > MAX_LINKS:
                return None
            try:
                target = os.readlink(current)
            except (OSError, ValueError):
                done = here
                continue
            base = [] if os.path.isabs(target) else done
            todo = base + [p for p in target.split(os.sep) if p] + todo
            done = []
            continue
        done = here
    return None


def read_problem(tool: str, tool_input: object, cwd: str | None, home: str | None) -> str | None:
    """Why a call of a file tool of READ_TOOLS reads a key path; None for any other call."""
    key = READ_TOOLS.get(tool)
    if key is None or not isinstance(tool_input, dict):
        return None
    path = tool_input.get(key)
    if not isinstance(path, str) or not path:
        return None
    return secret_problem(path, cwd, home)


def main() -> int:
    """The hook: nothing for a read of any other path; for a key path the gate's answer, from the gate itself."""
    raw = sys.stdin.read()
    try:
        event = json.loads(raw)
    except ValueError:
        event = None
    if isinstance(event, dict):
        cwd = event.get("cwd") if isinstance(event.get("cwd"), str) else None
        if read_problem(event.get("tool_name"), event.get("tool_input"), cwd, os.environ.get("HOME")) is None:
            return 0
    gate = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proofbundle_gate.py")
    done = subprocess.run([sys.executable, "-I", gate, *sys.argv[1:]], input=raw, text=True, check=False)
    return done.returncode


if __name__ == "__main__":
    sys.exit(main())
