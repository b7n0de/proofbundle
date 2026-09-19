#!/usr/bin/env python3
"""Every cached bytecode file in the tree must be what its source compiles to. Fail closed.

WHY THIS EXISTS, measured 2026-09-19 on this checkout. A cached ``.pyc`` whose header still carries
the source's mtime and size is used by the interpreter WITHOUT looking at the source again. A file
planted that way runs instead of the code on disk, and ``__pycache__/`` is listed in ``.gitignore``,
so it never appears in ``git status``. Measured on this tree: seven cache files present, four under
``src`` and three under ``tests``, and ``git status`` reports none of them. The integrity story of
this repository rests on git-visible state, and this is a hole in exactly that surface.

THREE DEFENCES WERE MEASURED AND TWO OF THEM DO NOT DEFEND:

    default interpreter                   ran the planted body
    --check-hash-based-pycs always        ran the planted body
    -B / PYTHONDONTWRITEBYTECODE          ran the planted body

The flag only governs hash-based caches (PEP 552). A timestamp-based cache, which is what Python
writes by default, is untouched by it. ``dont_write_bytecode`` stops WRITING and says nothing about
reading one that is already there. The repository sets the latter in three scripts today; that is
useful for reproducibility and is not a defence against this.

WHAT THIS GATE DOES. For every cache file under the tree it recompiles the source and compares the
two CODE OBJECTS, not their serialisation. Compilation is deterministic for a given interpreter and
source, so a mismatch means the cache does not correspond to the source, whatever the header claims.

Comparing the marshalled bytes instead was tried first and is wrong: re-marshalling the very object
that came out of a cache file gives different bytes, because marshal shares interned objects by
back-reference. Measured on this tree, one of four untouched files differed that way. CPython
compares code objects structurally, and that is the property this gate is about.

FAIL CLOSED, in every direction that is not a proven match:

    MISMATCH        the cache does not match a fresh compile of its source
    ORPHAN          a cache file with no source next to it; nothing can be checked, and in the
                    legacy layout such a file is importable on its own
    UNREADABLE      the cache or the source could not be read or compiled

HONEST LIMIT, stated rather than implied. The comparison can only be made for cache files built by
the SAME interpreter version that runs this gate; a cache tagged for another version is reported as
SKIPPED_OTHER_INTERPRETER and is NOT a pass. Run the gate under each interpreter the project
supports to cover them all. The gate also cannot tell a malicious plant from an ordinary stale file
left behind by an edit; both are reported, because both mean the running bytes are not the bytes on
disk.

THE EMPTY RUN IS NAMED, not folded into the pass. A fresh checkout carries no cache files, so a
job that scans one reports success having examined nothing — the green-tick-over-an-empty-set shape
this project already carries on its list of false greens. The verdict for that run is EMPTY, and
``--fail-on-empty`` turns it into a failure for callers who know there should have been something.

Exit code: 0 when every checked cache matches, 1 on any finding (and on EMPTY with
``--fail-on-empty``), 2 on a usage error.
"""
from __future__ import annotations

import argparse
import json
import marshal
import sys
from pathlib import Path

SCHEMA = "proofbundle.pyc_integrity_gate.v1"

#: magic(4) + flags(4) + mtime-or-hash(8) = the header before the marshalled code object.
HEADER_LEN = 16

#: Directories that never belong to this project's own source.
SKIP_DIRS = frozenset({".git", ".venv", "venv", "node_modules", "build", "dist", ".mypy_cache",
                       ".pytest_cache", ".ruff_cache"})


def _tag() -> str:
    """The cache tag of the RUNNING interpreter, for example ``cpython-312``."""
    return sys.implementation.cache_tag or ""


def _sources_of(pyc: Path) -> Path | None:
    """The source a cache file belongs to, or None when there is none next to it."""
    if pyc.parent.name != "__pycache__":
        # Legacy sourceless layout: ``pkg/mod.pyc`` imports on its own.
        return pyc.with_suffix(".py")
    stem = pyc.name.split(".")[0]
    return pyc.parent.parent / f"{stem}.py"


def check_one(pyc: Path) -> dict:
    """One cache file. Returns a finding dict; ``state`` is OK only on a proven match."""
    rel = str(pyc)
    tag = _tag()
    if pyc.parent.name == "__pycache__":
        parts = pyc.name.split(".")
        if len(parts) >= 3 and parts[-2] != tag:
            return {"file": rel, "state": "SKIPPED_OTHER_INTERPRETER",
                    "reason": f"built for {parts[-2]}, this gate runs {tag}"}
    source = _sources_of(pyc)
    if source is None or not source.is_file():
        return {"file": rel, "state": "ORPHAN",
                "reason": ("no source next to this cache file; nothing can be compared, and in the "
                          "legacy layout such a file is importable on its own")}
    try:
        raw = pyc.read_bytes()
        text = source.read_bytes()
    except OSError as e:
        return {"file": rel, "state": "UNREADABLE", "reason": f"{type(e).__name__}: {e}"}
    if len(raw) <= HEADER_LEN:
        return {"file": rel, "state": "UNREADABLE", "reason": "shorter than a cache header"}
    # THE RECORDED FILENAME IS PART OF THE CODE OBJECT, so the source is recompiled under the
    # name the cache itself carries. Measured 2026-09-19: comparing against the current absolute
    # path reported five MISMATCH findings on an untouched tree, because the checkout had been
    # made at a different path than the one the cache was written at. A gate that is red on a
    # clean tree from its first run is the permanent red that teaches people to ignore a check.
    try:
        cached_code = marshal.loads(raw[HEADER_LEN:])
    except (ValueError, EOFError, TypeError) as e:
        return {"file": rel, "state": "UNREADABLE",
                "reason": f"the cached code object does not unmarshal: {type(e).__name__}: {e}"}
    name = getattr(cached_code, "co_filename", None)
    if not isinstance(name, str):
        return {"file": rel, "state": "UNREADABLE",
                "reason": "the cached object carries no filename, so nothing can be recompiled"}
    try:
        fresh_code = compile(text, name, "exec", dont_inherit=True)
    except (SyntaxError, ValueError) as e:
        return {"file": rel, "state": "UNREADABLE",
                "reason": f"the source does not compile: {type(e).__name__}: {e}"}
    # THE CODE OBJECTS ARE COMPARED, NOT THEIR SERIALISATION. Measured 2026-09-19: re-marshalling
    # the very object that was unmarshalled from a cache file gives different bytes, because
    # marshal shares interned objects by back-reference and the sharing pattern depends on the
    # object graph at dump time. One of four untouched files differed that way. A byte comparison
    # of the serialisation is therefore a proxy that answers a question about marshal rather than
    # about the bytecode. Code objects compare structurally in CPython, which is the property this
    # gate is actually about, and a planted body fails it.
    if cached_code == fresh_code:
        return {"file": rel, "state": "OK", "source": str(source)}
    return {"file": rel, "state": "MISMATCH", "source": str(source),
            "reason": ("the cached bytecode is not what this source compiles to, so the bytes that "
                      "would run are not the bytes on disk")}


def _candidates(root: Path) -> list[Path]:
    aus = []
    for p in root.rglob("*.pyc"):
        if any(t in SKIP_DIRS for t in p.parts):
            continue
        aus.append(p)
    return sorted(aus)


def survey(root: Path) -> dict:
    findings = [check_one(p) for p in _candidates(root)]
    bad = [b for b in findings if b["state"] in ("MISMATCH", "ORPHAN", "UNREADABLE")]
    skipped = [b for b in findings if b["state"] == "SKIPPED_OTHER_INTERPRETER"]
    return {
        "schema": SCHEMA,
        "root": str(root),
        "interpreter": _tag(),
        "checked": len(findings) - len(skipped),
        "skipped_other_interpreter": len(skipped),
        "findings": bad,
        "verdict": ("FINDINGS" if bad else ("EMPTY" if len(findings) - len(skipped) == 0
                                            else "CLEAN")),
        "honest_limit": (
            "A cache built for another interpreter version cannot be compared here and is counted "
            "as skipped, never as passed. Run this gate under each supported interpreter."),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=".", help="tree to scan")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-on-empty", action="store_true",
                    help=("treat a run that checked NOTHING as a failure. A fresh checkout holds "
                          "no cache files at all, so a job that scans one is green over an empty "
                          "set and proves nothing; in CI this gate belongs after the test step, "
                          "where imports have populated the caches, and with this flag set"))
    a = ap.parse_args(argv)
    root = Path(a.root).resolve()
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2
    e = survey(root)
    if a.json:
        print(json.dumps(e, ensure_ascii=False, indent=2))
    else:
        print(f"pyc-integrity: {e['verdict']} · {e['checked']} checked · "
              f"{e['skipped_other_interpreter']} skipped (other interpreter)")
        for b in e["findings"]:
            print(f"  {b['state']}: {b['file']} — {b.get('reason', '')}")
    if e["verdict"] == "FINDINGS":
        return 1
    if e["verdict"] == "EMPTY":
        # GREEN OVER AN EMPTY SET IS NOT GREEN. Without the flag this stays a pass, because an
        # empty tree is a legitimate state; with it, the caller has said that finding nothing is
        # itself the finding.
        return 1 if a.fail_on_empty else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
