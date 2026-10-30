"""The key files and credential stores an agent must not read (DECISIONS.md D102, follow-up note 33, fallbook l01 and l02).

The PreToolUse hook of the file tools Read and Grep runs this script on its own, so a read costs the start of a small
program and not of the whole gate (measured with Python 3.13: 39 ms against 350 ms, most of which is the compilation of
the gate); for a key path it hands the call to the gate, which denies it, logs it and writes the short line. The gate
loads this file for the words of a Bash command. Both compare paths only: they never open, list or stat a file inside
a key folder or a key file, and they read no file's content.
"""
from __future__ import annotations

import itertools
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
#: The characters with which the shell makes a word into the names of files (pathname expansion, POSIX 2.13).
PATTERN_CHARS = "*?["
#: The most combinations of names a pattern is compared in; past it the pattern counts as a key path.
MAX_PATTERN_TRIES = 4096


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


def _pattern_tokens(part: str) -> list:
    """The tokens of a shell pattern (POSIX 2.13.1): ("lit", c), ("one",) for `?`, ("run",) for `*`, and ("set", S) for
    a bracket expression, where S is the set of characters it takes, or None where the comparison does not evaluate it
    and so lets it stand for any one character: a negated expression, a POSIX class (`[[:alpha:]]`), an equivalence
    class (`[[=h=]]`) and a collating symbol (`[[.h.]]`) (re-reading of the fixes at 21fead88, line 3, P1). A `[`
    without its `]` is itself, as the shell takes it."""
    tokens, i, n = [], 0, len(part)
    while i < n:
        c = part[i]
        if c == "*":
            tokens.append(("run",))
        elif c == "?":
            tokens.append(("one",))
        elif c == "\\" and i + 1 < n:
            i += 1
            tokens.append(("lit", part[i]))
        elif c == "[":
            j = i + 1
            negated = j < n and part[j] in "!^"
            j += 1 if negated else 0
            start = j
            if j < n and part[j] == "]":
                j += 1
            opaque = False
            while j < n and part[j] != "]":
                if part[j] == "[" and j + 1 < n and part[j + 1] in ":=.":
                    close = part.find(part[j + 1] + "]", j + 2)
                    if close == -1:
                        break
                    opaque, j = True, close + 2
                else:
                    j += 1
            if j >= n:
                tokens.append(("lit", "["))
            else:
                body, chars, k = part[start:j], set(), 0
                while k < len(body):
                    if k + 2 < len(body) and body[k + 1] == "-":
                        chars.update(chr(x) for x in range(ord(body[k]), ord(body[k + 2]) + 1))
                        k += 3
                    else:
                        chars.add(body[k])
                        k += 1
                tokens.append(("set", None if negated or opaque else frozenset(chars)))
                i = j
        else:
            tokens.append(("lit", c))
        i += 1
    return tokens


def _token_takes(token: tuple, char: str, fold: bool) -> bool:
    if token[0] in ("one", "run"):
        return True
    if token[0] == "lit":
        return token[1].lower() == char.lower() if fold else token[1] == char
    return token[1] is None or char in token[1] or (fold and (char.lower() in token[1] or char.upper() in token[1]))


def _may_match(tokens: list, name: str) -> bool:
    """Whether a pattern of _pattern_tokens may match the whole file name: a leading dot only by a literal leading dot
    (POSIX 2.13.3, bash without dotglob, zsh without GLOB_DOTS)."""
    if name.startswith(".") and not (tokens and tokens[0] == ("lit", ".")):
        return False
    reach = {0}
    for char in name:
        nxt = set()
        for t in sorted(reach):
            while t < len(tokens) and tokens[t] == ("run",):
                nxt.add(t)
                t += 1
            if t < len(tokens) and _token_takes(tokens[t], char, False):
                nxt.add(t + 1)
        reach = nxt
        if not reach:
            return False
    return any(all(tok == ("run",) for tok in tokens[t:]) for t in reach)


def may_match(pattern: str, name: str) -> bool:
    """Whether the shell's pattern may match the file name, by _pattern_tokens and _may_match; for the gate's root door
    (D119), which reads a program word with a pattern the same way D102 reads a path."""
    return _may_match(_pattern_tokens(pattern), name)


def _may_end_with(tokens: list, ending: str) -> bool:
    """Whether a pattern of _pattern_tokens may match a name that ends with `ending`, letters compared without case as
    _role compares the endings: read from the end of both, a `*` may take the rest of the ending and everything
    before it, every other token one character."""
    def walk(t: int, e: int) -> bool:
        if e < 0:
            return True
        if t < 0:
            return False
        if tokens[t] == ("run",):
            return True
        return _token_takes(tokens[t], ending[e], True) and walk(t - 1, e - 1)
    return walk(len(tokens) - 1, len(ending) - 1)


def _names_a_part_may_take(part: str) -> list[str]:
    """The names of a key path a part with a pattern may become: a folder of keys, a part of a credential store and the
    name of a private key. A part made of `*` and `?` alone is not compared with the names of single key files: it
    matches every file, and counting it would deny every `cat *`; it is compared with the folders and the stores."""
    tokens = _pattern_tokens(part)
    names = [*SECRET_FOLDERS, *(p for f in SECRET_FILES for p in f)]
    if not all(c in "*?" for c in part):
        names += list(SECRET_NAMES)
    return [n for n in dict.fromkeys(names) if _may_match(tokens, n)]


def _pattern_key_ending(part: str) -> bool:
    """Whether the last part of a pattern may name a file with the ending of a key (SECRET_SUFFIXES), unless its
    written text names a public file (SECRET_PUBLIC), it is made of `*` and `?` alone, or it ends with `*`: such a part
    writes no ending, and counting it would deny every `wc -l tests/test_*` as `*` alone would every `cat *`. The names
    of folders, stores and private keys still count for it (_names_a_part_may_take)."""
    tokens = _pattern_tokens(part)
    if all(c in "*?" for c in part) or (tokens and tokens[-1] == ("run",)) or \
            any(m in part.lower() for m in SECRET_PUBLIC):
        return False
    return any(_may_end_with(tokens, ending) for ending in SECRET_SUFFIXES)


def pattern_role(pattern: str, cwd: str | None, home: str | None) -> str | None:
    """The role of a key path that a word the shell expands as a pattern (PATTERN_CHARS) may name, compared by names
    only: each part with a pattern is tried as written and as every name of a key path it may match (_may_match); None
    where no combination is a key path. No folder is listed and no file is touched: what a folder holds now is not what
    it holds when the call runs (Codex on PR 441, P1). A relative pattern whose folder cannot be told is compared by its
    own parts."""
    named = named_path(pattern, cwd, home)
    parts = [p for p in (named if named is not None else os.path.normpath(pattern)).split(os.sep) if p not in ("", ".")]
    choices = [[p, *_names_a_part_may_take(p)] if any(c in p for c in PATTERN_CHARS) else [p] for p in parts]
    tries = 1
    for c in choices:
        tries *= len(c)
    if tries > MAX_PATTERN_TRIES:
        return "a pattern too wide to compare with the key paths"
    for combination in itertools.product(*choices):
        role = _role(list(combination), True)
        if role:
            return f"{role}, through a pattern"
    if parts and any(c in parts[-1] for c in PATTERN_CHARS) and _pattern_key_ending(parts[-1]):
        return "a key file, through a pattern"
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
