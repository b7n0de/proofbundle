#!/usr/bin/env python3
"""Verify the pre-tag audit receipt of a checked-out commit -- the path for someone who holds a clone.

WHAT THIS ANSWERS. ``gh attestation verify`` proves that a wheel was built by this repository's
release workflow from a specific commit (RELEASE.md, "Verifying a published release"). This
script answers the question a reader has next: does THAT commit carry an audit receipt, signed by
the key this repository pins, bound to the tree of exactly that commit? It is the check the
release workflow runs on itself (``scripts/pre_tag_audit_gate.py``), turned towards a reader who
has nothing but a clone and the commit id from the provenance.

HOW TO RUN IT, from a clone, checked out at the commit the attestation names::

    git clone https://github.com/b7n0de/proofbundle && cd proofbundle
    git checkout <commit named by the attestation>
    python -I scripts/verify_pre_tag_receipt.py --commit <that commit> --version X.Y.Z

``-I`` (isolated mode) keeps ``PYTHONPATH``, the user's site directory and the script's own directory off the import
path. Three things are the reader's to establish BEFORE the start, because Python runs the startup files of its
installation (``.pth`` files, ``sitecustomize``) before the script's first line, ``-I`` included: ``python`` is
installed outside the clone, the clone does not lie inside that interpreter's installation, and no startup file of
that interpreter names a directory of the clone or a directory that contains it. The third is not implied by the
first two: a ``.pth`` path line in an outside virtual environment puts the clone on the search path at start, and a
``sitecustomize.py`` of the clone then runs before the first line (external review of 65d8f8cd, F5, measured there
with an outside venv under ``-I``); a line that names the PARENT of a clone called ``sitecustomize`` makes Python
import the clone itself as that package (Codex on PR 311 at 6d081424, thread 4173974268). No check inside a process
that has already started can replace that precondition; what this script refuses with exit 2 is what it can still
see: a virtual environment created inside the clone, a clone in the environment's own site directory, a clone under
the interpreter's installation (``lib-dynload`` and the rest), and, under ``-I``, a run whose search path at start
already named a directory of the clone or a directory that contains it. A clone whose own git configuration names a
program for git to run from the listed families (a ``filter``/``diff``/``merge`` driver, ``core.fsmonitor``,
``core.hooksPath``, an ssh, proxy, pager, editor or credential command, a remote's transport program, a difftool or
mergetool command, a shell alias; ``_GIT_PROGRAM_KEYS`` and ``_GIT_PROGRAM_EXACT``) is refused; that these families are
every program-selecting key is not shown. So is a partial clone, whose object reads would fetch through a transport its
configuration names, and a clone whose effective attributes (``.gitattributes`` of the checkout,
``.git/info/attributes``, macros, as ``git check-attr`` resolves them) name a ``filter``, ``diff`` or ``merge`` driver
git does not ship, a driver named ``set``, ``unset`` or ``unspecified`` included (told from the state of that name by
attribute pathspecs, over an index measured to list exactly the commit's files). An index that does not, and a warning
git prints while reading the attributes, refuse too. A directory under ``scripts/`` or ``src/`` that cannot be listed
refuses the measurement as well.
Without ``-I`` the script still takes every directory of the checkout off its
path before its first further import, and it refuses a run in which a module of the checkout was already loaded at
start (a ``sitecustomize.py`` reached through ``PYTHONPATH``); code that runs before the first line and hides itself is
beyond what any check inside the script can see. Run the script of the clone you verify: only the checkout ``--repo``
names is compared with the commit, so a script started from another checkout is refused.

THE EVIDENCE IS READ FROM THE COMMIT; THE CODE RUNS FROM THE CHECKOUT, SO THE CHECKOUT MUST BE
THE COMMIT. The receipt, the trust anchor and the gate source whose digest the receipt binds are
read from the commit's objects, and each object read (the commit, every tree below it, and those
blobs) is hashed and compared with the id it was read under, so neither a file placed into a dirty
checkout nor an object rewritten in the clone's store can stand in for a committed one. The
verifier code -- this script, ``pre_tag_receipt_lib.py``, the package under
``src/`` whose ed25519 primitive it calls -- is NOT read from the commit: Python runs what lies on
disk. An adversarial lens measured on 2026-09-18 what that means when nothing checks the two
against each other: one uncommitted edit to ``verify_receipt`` or to ``proofbundle.signature``,
HEAD untouched, and a commit with a garbage receipt reported VERIFIED. So two things are refused
with exit 2, never silently measured: a checkout at any head other than the named commit, and a
checkout that carries local modifications or untracked files under ``scripts/`` or ``src/``, or a
path there whose type is not the one the commit names (a directory replaced by a symbolic link). The
tree digest itself is taken by the same library function the release gate uses
(``pre_tag_receipt_lib.subject_tree_digest``), which reads ``HEAD``.

THREE CONTRACTS, each with a test that plants the defect and expects the refusal
(``tests/test_verify_pre_tag_receipt_third_party.py``):

  1. a commit without a valid receipt fails -- absent, unreadable, unsigned, or signed by a key
     the committed anchor does not list;
  2. a receipt produced for ANOTHER commit fails -- it binds that commit's tree, not this one;
  3. a receipt whose signature is correct but whose subject is wrong fails -- the signed bytes
     name a digest that is not the digest of this tree, and a valid signature over the wrong
     subject is not a receipt for this commit.

WHAT A PASS ESTABLISHES, AND WHAT IT DOES NOT. A pass means: the holder of the key that this
repository pins in ``audit_artifacts/pre_tag_trusted_pubkeys.txt`` signed a receipt over exactly
this tree and this version, and the receipt records an audit run that exited 0. It does NOT
establish the authority of that key from outside -- the key is published by the same party whose
release you are assessing -- and it does not say the audit was good; a signature makes a record
forgery-resistant, not true. Nor is this script independent of what it checks: it and the
library it calls are files of the very tree it verifies. The limit is printed with every verdict.
RELEASE.md, "What these commands establish, and what they do not", says the same in prose.

Exit codes: 0 VERIFIED · 1 NOT VERIFIED (absent, rejected, or bound to another tree) ·
2 not measurable (no git, malformed commit id, checkout not at the named commit, or an object of
the clone that is not the object its id names).
"""
# NO `from __future__ import` HERE, AND THE FIRST IMPORTS ARE THE TWO THE INTERPRETER HAS ALREADY LOADED.
# Deep gate run 7 at 1a3cd672 (L6-620v7-T6-VERIFIER-SELF-HIDDEN-SHADOW-01, three of three jurors P1): run as
# `python scripts/verify_pre_tag_receipt.py`, this script's own directory is the first entry of `sys.path`, ahead of
# the standard library, so an untracked `scripts/contextlib/` that hides itself with its own `.gitignore` ran at the
# first `import contextlib`, before any check, and a tampered receipt came back VERIFIED. `__future__` is not loaded
# at interpreter start either (measured on 3.10.12, system and venv), so its import would have been the first one
# to take a planted module. `os` and `sys` are loaded at start, so they are read before the judged tree's entries
# leave the path below.
import os
import sys

# THE WHOLE CHECKOUT, NOT ONLY `scripts/` AND `src/` (Codex on PR 311 at 3f598b5b, P1, re-measured at 1e189f89). The
# first fix took only those two directories off the path. Run with the top level on `sys.path` (`PYTHONPATH=.`, or
# `python -m`, which puts the working directory first), an untracked `contextlib.py`, `argparse.py` or `json.py` at the
# top level ran before any check, and so did `tests/contextlib.py` with `PYTHONPATH=tests`. Every directory of the
# checkout is judged code, with no exception.
#
# AND NO INTERPRETER FROM THE CHECKOUT (Codex on PR 311 at e61dc740, P1, reproduced). The fix of 653b5d67 kept the
# entries of an interpreter installed in the clone, a reader's `.venv/`. Such an installation is a directory of the
# checkout the commit does not hold, and Python runs its startup files before this script's first line, `-I`
# included: `-I` implies `-E` and `-s` (and `-P` from 3.11 on), and only `-S` would skip `site`, whose `.pth` files may
# import code. A `.pth` in `.venv/` that patched `importlib.util.spec_from_file_location` turned a receipt whose subject
# is not this tree into exit 0 VERIFIED, with and without `-I`. So the interpreter must be installed outside the clone;
# one whose installation lies in it refuses the measurement with exit 2.


def _checkout_root() -> str:
    """The top level of the checkout this script lies in: the parent of its own directory, resolved."""
    return os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def _judged_location(ort: str, wurzel: str) -> bool:
    """True iff the resolved path `ort` is the checkout `wurzel` or lies below it.

    A `wurzel` that already ends with the separator, the filesystem root above all, gets no second one. Codex on PR
    311 at 553989ae (thread 4175430079): `wurzel + os.sep` made the root `/` into the prefix `//`, which no resolved
    path carries, so a search path entry `/` was never found to contain the checkout, in the startup path check and
    in the path cleaning alike. Every caller asks through this one function, so the fix is here.

    IDENTITY, NOT SPELLING (Codex on PR 311 at 6cab813e, thread 4175660286). A resolved path keeps the spelling it
    was given on a volume that does not tell upper from lower case, so `/Users/X/Repo/child` and `/users/x/repo` name
    one directory and share no prefix. The spelling is therefore only the first test: when it does not match, `ort`
    and each of its ancestors are compared with `wurzel` by the identity of the directory (`os.path.samestat`), which
    covers every second spelling of the same directory at once, case, Unicode normal form or another alias. The chain
    starts at `ort` itself and ends at the root `os.path.dirname` reaches, which is checked before the walk stops.

    A FAILED STAT PROVES NO SEPARATION (external review of 6cab813e, question 4). A path that does not exist
    (`FileNotFoundError`, `NotADirectoryError`) leads nowhere and contains nothing, so the walk goes on to its
    ancestors, and a container that does not exist contains nothing. Any other failure of `stat` (a permission, a
    broken mount, a name the system refuses) leaves open whether the two are the same directory, and an open answer
    counts as containment: every caller then removes the entry, reports it or refuses with exit 2, before any further
    import. Only `os` is used, which is loaded at interpreter start."""
    if ort == wurzel:
        return True
    praefix = wurzel if wurzel.endswith(os.sep) else wurzel + os.sep
    if ort.startswith(praefix):
        return True
    try:
        ziel = os.stat(wurzel)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except (OSError, ValueError):
        return True
    pfad = ort
    while True:
        try:
            if os.path.samestat(os.stat(pfad), ziel):
                return True
        except (FileNotFoundError, NotADirectoryError):
            pass
        except (OSError, ValueError):
            return True
        oben = os.path.dirname(pfad)
        if not oben or oben == pfad:
            return False
        pfad = oben


def _interpreter_startaugen() -> list:
    """Every directory the interpreter reads startup code from, as `(label, resolved path)`.

    Called AFTER the judged tree has left `sys.path` (see the `__main__` block), so the imports below take the standard
    library, not a planted module. Two kinds. The four PREFIXES (`sys.prefix`, `sys.exec_prefix`, `sys.base_prefix`,
    `sys.base_exec_prefix`): the installation a virtual environment points at and the one it was built from. And the
    SITE DIRECTORIES that `site` processes at interpreter start, where a `.pth` file runs code:
    `site.getsitepackages()`, the user site, and the `purelib`/`platlib` of `sysconfig`. A `.pth` in any of them runs
    before this script's first line, `-I` included, because `-I` suppresses `PYTHONPATH` and the script directory but
    not `site` processing of the environment's own directories."""
    import contextlib as _c  # noqa: PLC0415
    import site  # noqa: PLC0415
    import sysconfig  # noqa: PLC0415
    augen = []
    for name in ("prefix", "exec_prefix", "base_prefix", "base_exec_prefix"):
        try:
            augen.append((f"sys.{name}", os.path.realpath(getattr(sys, name))))
        except (OSError, ValueError, TypeError, AttributeError):
            continue
    kandidaten: list = []
    with _c.suppress(Exception):
        kandidaten += list(site.getsitepackages())
    with _c.suppress(Exception):
        if site.ENABLE_USER_SITE:
            kandidaten.append(site.getusersitepackages())
    with _c.suppress(Exception):
        kandidaten += [sysconfig.get_paths().get("purelib"), sysconfig.get_paths().get("platlib")]
    for pfad in kandidaten:
        if isinstance(pfad, str) and pfad:
            with _c.suppress(OSError, ValueError, TypeError):
                augen.append(("site", os.path.realpath(pfad)))
    return augen


def _interpreter_overlaps_the_checkout() -> list:
    """Every directory of the interpreter that overlaps this checkout in either direction, as `name (path)`.

    Four findings of one class (Codex on PR 311): an interpreter installed IN the checkout (a `.venv/` in the clone);
    a clone placed in the venv's `purelib`; and a clone rooted at the interpreter's `lib-dynload`, where a
    `sitecustomize.py` runs under `-I`. Enumerating the particular startup directories lost that race -- `purelib`,
    then `lib-dynload`, then the next one a version adds. So the test is containment against the whole installation,
    in BOTH directions: the checkout must not lie in, equal, or contain any of the interpreter's four PREFIXES
    (`sys.prefix`, `sys.exec_prefix`, `sys.base_prefix`, `sys.base_exec_prefix`), which hold every directory the
    interpreter reads code from -- `lib-dynload`, the standard library, `purelib`, `platlib` all lie under one of them.
    The site directories are added as well for the user site, which lies under the user base rather than a prefix and
    which `-I` disables but a run without `-I` does not. A reader therefore runs the verifier from a clone that is
    disjoint from the Python that runs it; the documented command already is."""
    wurzel = _checkout_root()
    funde = []
    for name, pfad in _interpreter_startaugen():
        if _judged_location(pfad, wurzel) or _judged_location(wurzel, pfad):
            funde.append(f"{name} ({pfad})")
    return funde


def _remove_the_judged_tree_from_sys_path() -> None:
    """Drop every `sys.path` entry that lies in this checkout, its top level included, or that CONTAINS it, before any
    further import.

    The judged tree is code under judgement, not a library this script may import by name: the receipt library and
    the gate are loaded by path (`_lib`, `_gate`), and `src/` goes back on the path only after the checkout has been
    compared with the commit (`_measure`). An empty entry is the working directory. BOTH DIRECTIONS (Codex on PR 311
    at 6d081424, thread 4173974268): an entry that contains the checkout is a way into it as well, because a package
    lookup descends from the entry, so a clone named like a module is importable from its parent. AN ENTRY THAT CANNOT
    BE RESOLVED GOES as well (external review of 6cab813e, question 4): whether it names a directory of the checkout
    is open, and an open answer is removed rather than kept; the standard library this script imports next is never
    such an entry."""
    wurzel = _checkout_root()
    behalten = []
    for eintrag in sys.path:
        try:
            ort = os.path.realpath(eintrag or os.getcwd())
        except (OSError, ValueError, TypeError):
            continue
        if _judged_location(ort, wurzel) or _judged_location(wurzel, ort):
            continue
        behalten.append(eintrag)
    sys.path[:] = behalten


def _checkout_code_that_ran_before_this_script() -> list:
    """Every module loaded before this script's first line from a file of the checkout, as `name (path)`.

    Python imports `sitecustomize` (and, outside a virtual environment, `usercustomize`) at start from the first
    `sys.path` entry that holds one, and `PYTHONPATH` entries come before the standard library. Measured at 1e189f89:
    `PYTHONPATH=<clone>` and an untracked `sitecustomize.py` at the top level, and that file ran before this script.
    Nothing this script does afterwards can undo what such code did, so its presence refuses the measurement. This
    is a tripwire, not a boundary: a startup module that removes itself from `sys.modules` is not seen. The boundary is
    `python -I`, which reads no `PYTHONPATH` and does not put the script's directory on the path."""
    wurzel = _checkout_root()
    funde = []
    for name, modul in list(sys.modules.items()):
        if name == "__main__":
            continue
        # The file a module ran from: `__file__`, and the spec's origin only where the spec says it is a location. A
        # built-in or frozen module's origin is the word `built-in` or `frozen`, which resolved against a working
        # directory inside the checkout would name a path in it (measured: every run was refused through `sys`). A
        # namespace package has no file and runs no code.
        try:
            spec = getattr(modul, "__spec__", None)
            orte = [getattr(modul, "__file__", None)]
            if getattr(spec, "has_location", False) is True:
                orte.append(getattr(spec, "origin", None))
        except Exception:  # noqa: BLE001 - a module that cannot be read is no location
            continue
        for ort in orte:
            if not isinstance(ort, str) or not ort:
                continue
            try:
                aufgeloest = os.path.realpath(ort)
            except (OSError, ValueError, TypeError):
                continue
            if _judged_location(aufgeloest, wurzel):
                funde.append(f"{name} ({aufgeloest})")
                break
    return funde


def _startup_search_paths_into_the_checkout() -> list:
    """Under `-I`, every `sys.path` entry that names a directory of the checkout, or a directory that contains it, before
    this script changed the path.

    External review of 65d8f8cd, F5: a `.pth` path line in an OUTSIDE virtual environment put the clone on the search
    path at start, and under `python -I` a `sitecustomize.py` of the clone ran before this script's first line, although
    every prefix and site directory lay outside the clone. In isolated mode Python adds neither `PYTHONPATH` nor the
    script's directory, so an entry in the checkout at this point came from a startup file of the interpreter or from
    code one of them ran. Like `_checkout_code_that_ran_before_this_script` this is a tripwire, not a boundary: the
    startup code may already have run, and code that removes its own entry is not seen. The boundary is the
    precondition in the module docstring. Read before the path is cleaned, with `os` and `sys` only. Outside isolated
    mode the entries a reader puts there on purpose (`PYTHONPATH`, the script's directory) cannot be told apart from
    the others, so nothing is reported there; the empty entry is the working directory, which no `.pth` line adds.
    BOTH DIRECTIONS (Codex on PR 311 at 6d081424, thread 4173974268): a `.pth` line naming the PARENT of a clone called
    `sitecustomize` lets Python import the clone itself as that package at start, and an untracked `__init__.py` that
    hides its origin passes the tripwire for loaded modules; Codex measured exit 0 VERIFIED for a receipt that is not
    the tree. An entry that contains the checkout is therefore reported as well, and so is an entry that cannot be
    resolved (external review of 6cab813e, question 4): whether it names a directory of the checkout is open, and an
    open answer refuses with exit 2."""
    if not getattr(sys.flags, "isolated", 0):
        return []
    wurzel = _checkout_root()
    funde = []
    for eintrag in sys.path:
        if not isinstance(eintrag, str) or not eintrag:
            continue
        try:
            ort = os.path.realpath(eintrag)
        except (OSError, ValueError, TypeError):
            funde.append(eintrag)
            continue
        if _judged_location(ort, wurzel) or _judged_location(wurzel, ort):
            funde.append(eintrag)
    return funde


#: Filled only when this file runs as a script (see below); a caller that imports the module measures in its own
#: process, whose start this script did not see.
_INTERPRETER_OVERLAP: list = []
_STARTUP_PATH_INTO_CHECKOUT: list = []
_CODE_BEFORE_THIS_SCRIPT: list = []
#: The checkout this script runs from, when it runs as a script. Its code judges, so it must be the checkout `--repo`
#: names: that is the one compared with the commit. Measured on 2026-10-02 at 653b5d67: run from a checkout A whose
#: `pre_tag_receipt_lib.py` was edited, against a clean `--repo` B, the script compared B, loaded the library from A and
#: gave exit 0 VERIFIED for a receipt that does not bind the tree.
_SCRIPT_CHECKOUT: str | None = None

if __name__ == "__main__":
    _SCRIPT_CHECKOUT = _checkout_root()
    # THE PATH IS CLEANED FIRST, then everything else is measured. `_checkout_code_that_ran_before_this_script` reads
    # `sys.modules` (what already loaded, which cleaning does not unload) and `_interpreter_overlaps_the_checkout`
    # imports `site`/`sysconfig`/`contextlib` -- those imports must take the standard library, not a module planted on
    # the still-dirty path, so they run after the checkout's directories are gone. The one thing read BEFORE the
    # cleaning is the path itself, under -I (`_startup_search_paths_into_the_checkout`): the cleaning removes exactly
    # the entries it looks for.
    _STARTUP_PATH_INTO_CHECKOUT = _startup_search_paths_into_the_checkout()
    _remove_the_judged_tree_from_sys_path()
    _CODE_BEFORE_THIS_SCRIPT = _checkout_code_that_ran_before_this_script()
    _INTERPRETER_OVERLAP = _interpreter_overlaps_the_checkout()

import argparse  # noqa: E402 - after the path is cleaned, see above
import contextlib  # noqa: E402 - after the path is cleaned, see above
import hashlib  # noqa: E402 - after the path is cleaned, see above
import json  # noqa: E402 - after the path is cleaned, see above
import re  # noqa: E402 - after the path is cleaned, see above
from pathlib import Path  # noqa: E402 - after the path is cleaned, see above

_HEX40 = re.compile(r"\A[0-9a-f]{40}\Z")

#: The limit, in one place, printed with every verdict -- a reader who only sees the last line
#: must still see it. Keep it in sync with the section in RELEASE.md.
LIMIT = ("LIMIT: the trust anchor is a public key committed in this same repository. A pass shows "
         "that whoever controls that key signed a receipt over this tree; it does not establish the "
         "authority of that key from outside, and it does not say the audit was good. This script "
         "and the library it uses are part of the tree being verified, and they run from your "
         "checkout: the verdict is only as good as that checkout being exactly the named commit.")

#: The paths whose on-disk state must equal the commit for the verdict to mean anything: the code
#: that judges. Evidence outside them (the receipt folder, the anchor) is read from the commit.
_CODE_PFADE = ("scripts", "src")


#: Where Python keeps bytecode for THIS run: a fresh directory, never `__pycache__` next to the
#: sources. Created once, and set again on every measurement, because the process-wide import state
#: is restored when a measurement ends (see `_importzustand`).
_CACHE_DIR: str | None = None


def _bytecode_cache_elsewhere() -> None:
    """A `.pyc` next to the committed source is not the committed source, and Python would run it.

    Lens C, 2026-09-18, executed: a `signature.cpython-310.pyc` with `verify_ed25519 -> True`,
    header copied from the untouched `signature.py`, dropped under `src/proofbundle/__pycache__/`.
    `git status` never lists ignored paths, so the clean-checkout guard above saw nothing, and the
    tampered receipt came back VERIFIED. The guard was scoped to source files; the bytecode cache
    of an unmodified source file is the neighbour it did not cover.

    The fix is not a second guard over `__pycache__` (a cache that is present is not evidence of
    anything, and the first run of this script would create one). It is to make the cache next to
    the sources irrelevant: `sys.pycache_prefix` sends every cache lookup and write of this run to
    a fresh temporary directory, so nothing under the judged tree's `__pycache__` is ever read.
    What stays trusted, and is not measured here: the interpreter and its standard library.
    """
    global _CACHE_DIR
    if _CACHE_DIR is None:
        import tempfile  # noqa: PLC0415
        _CACHE_DIR = tempfile.mkdtemp(prefix="verify_pre_tag_receipt_pyc_")
    sys.pycache_prefix = _CACHE_DIR
    sys.dont_write_bytecode = True


def _modulorte(modul) -> list:
    """Every location a module names: `__file__`, `__path__`, and the same two from its spec. A value
    that cannot be read is skipped; the cleanup that calls this runs in a `finally` and must not raise
    (Codex on PR 274, round three: `__file__ = 1` made `Path(...)` raise there)."""
    orte: list = []
    spec = None
    with contextlib.suppress(Exception):
        spec = getattr(modul, "__spec__", None)
    for quelle, name in ((modul, "__file__"), (spec, "origin")):
        with contextlib.suppress(Exception):
            orte.append(getattr(quelle, name, None))
    for quelle, name in ((modul, "__path__"), (spec, "submodule_search_locations")):
        with contextlib.suppress(Exception):
            orte.extend(list(getattr(quelle, name, None) or []))
    return orte


def _liegt_unter(ort, pfade) -> bool:
    """True iff `ort` is a path below one of `pfade`; anything that is not a path is no location."""
    if not isinstance(ort, (str, os.PathLike)):
        return False
    try:
        return any(Path(ort).resolve().is_relative_to(p) for p in pfade)
    except (OSError, ValueError, RuntimeError, TypeError):
        return False


@contextlib.contextmanager
def _importzustand():
    """The process-wide import state as it was before this script touched it, restored on every exit.

    Same class and same fix as `pre_tag_audit_gate._importzustand` (2026-09-25): the judged tree's
    `src/` goes in front of `sys.path` for the measurement, and a caller in the same process -- the
    tests that import this module, `scripts/pre_tag_receipt.py` -- must not inherit it afterwards,
    nor the bytecode switches."""
    gesichert = (list(sys.path), sys.pycache_prefix, sys.dont_write_bytecode)
    module_vorher = set(sys.modules)
    pakete_vorher = _paketattribute()
    try:
        yield
    finally:
        neue_pfade = _neue_pfade(gesichert[0])
        # THE PATH AND THE SWITCHES FIRST, before anything that reads a module (Codex on PR 274, round
        # four: a module whose `__spec__` access raises made the cleanup raise, and the judged path
        # stayed installed because the restore below it was never reached).
        sys.path[:] = gesichert[0]
        sys.pycache_prefix, sys.dont_write_bytecode = gesichert[1], gesichert[2]
        _module_entfernen(module_vorher, pakete_vorher, neue_pfade)


def _neue_pfade(vorher: list) -> list:
    """The paths the call put on `sys.path`, resolved; one that cannot be resolved is skipped."""
    aus = []
    for p in sys.path:
        if isinstance(p, str) and p and p not in vorher:
            with contextlib.suppress(Exception):
                aus.append(Path(p).resolve())
    return aus


def _paketattribute() -> dict:
    """The attributes of every package present before the call, so that a child import that
    overwrites one can be undone (round four: a lasting package's `child` sentinel was deleted)."""
    aus = {}
    for name, modul in list(sys.modules.items()):
        with contextlib.suppress(Exception):
            if getattr(modul, "__path__", None) is not None:
                aus[name] = dict(vars(modul))
    return aus


def _module_entfernen(module_vorher: set, pakete_vorher: dict, neue_pfade: list) -> None:
    """Remove what the call loaded for the first time from a path it added; never raises."""
    # THE MODULES IT LOADED FROM THE JUDGED TREE LEAVE TOO (Codex on PR 274, measured): after the
    # restore of the path, `proofbundle` and `proofbundle._wire_b64` stayed in `sys.modules`, loaded
    # from the judged checkout, and a later import in the caller got that code. Removed is exactly
    # what this call loaded for the first time from a path this call put on `sys.path`; a module
    # first loaded from a path that was there before (the standard library, say) stays.
    for name in [n for n in list(sys.modules) if n not in module_vorher]:
        # One module that cannot be read must not keep the others (round four), so each is its own
        # attempt.
        with contextlib.suppress(Exception):
            modul = sys.modules.get(name)
            # A namespace package (PEP 420) has no `__file__`; its locations are its `__path__`
            # (round two). The spec is read too, because a module may overwrite its own `__file__`
            # (round three: `__file__ = 1`).
            orte = [o for o in _modulorte(modul) if isinstance(o, (str, os.PathLike))]
            # Round five (R4): a module may replace its own entry with an object that names no
            # location at all, a proxy without `__file__`, `__path__` and `__spec__`. Such an entry
            # is new to this call and cannot be shown to come from a path that stays, so when the
            # call added a path it leaves too. If it came from elsewhere, the cost is one import the
            # next caller runs again; the other error would keep the judged code installed.
            if not neue_pfade or (orte and not any(_liegt_unter(o, neue_pfade) for o in orte)):
                continue
            del sys.modules[name]
            # Round three: a child of a parent that stays is also an attribute of that parent, set by
            # the import system. Round four: if the parent had that attribute before, it gets its old
            # value back instead of losing it.
            eltern, _, kind = name.rpartition(".")
            elter = sys.modules.get(eltern) if eltern else None
            if elter is not None and getattr(elter, kind, None) is modul:
                alt = pakete_vorher.get(eltern)
                if alt is not None and kind in alt:
                    setattr(elter, kind, alt[kind])
                else:
                    delattr(elter, kind)


def _lib():
    """The receipt library, loaded BY PATH from this script's own directory.

    The gate does the same, and for the same measured reason: a plain ``from pre_tag_receipt_lib
    import ...`` takes whatever lies first on ``sys.path``, and the repository under judgement is
    put there so that ``proofbundle.signature`` is importable -- a repository carrying its own
    ``src/pre_tag_receipt_lib.py`` would then supply the verifier that judges it.
    """
    import importlib.util as ilu  # noqa: PLC0415
    _bytecode_cache_elsewhere()
    pfad = Path(__file__).resolve().parent / "pre_tag_receipt_lib.py"
    spec = ilu.spec_from_file_location("_verify_pre_tag_receipt_lib", pfad)
    if spec is None or spec.loader is None:
        raise ImportError(f"no loader for {pfad}")
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _gate():
    """The release gate, loaded by path for its two closed lists of what lies in the receipt
    folder without being a receipt. One source for that rule, not a copy of it here."""
    import importlib.util as ilu  # noqa: PLC0415
    _bytecode_cache_elsewhere()
    pfad = Path(__file__).resolve().parent / "pre_tag_audit_gate.py"
    spec = ilu.spec_from_file_location("_verify_pre_tag_receipt_gate", pfad)
    if spec is None or spec.loader is None:
        raise ImportError(f"no loader for {pfad}")
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── THIS SCRIPT'S OWN GIT FUNNEL ───────────────────────────────────────────────────────────────
#
# The receipt chain asks git through one funnel, `pre_tag_receipt_lib.git_run`, whose environment
# is built from an allowlist and whose configuration is pinned on git's command line. The verifier
# carries a copy of that funnel instead of calling it, and that is deliberate: its first job is to
# refuse a checkout whose `scripts/` or `src/` differ from the commit, and the library is one of
# the files that check exists to catch. Measured 2026-09-27 against a version that called the
# library: a library edited so that its funnel returned an empty `status` and its `verify_receipt`
# returned true hid itself, and a commit with an invalid receipt was `VERIFIED`. Every git call of
# this script therefore runs on this file's code alone. The two funnels must not drift:
# `tests/test_pre_tag_chain_asks_git_through_one_funnel.py` holds the allowlist, the pinned options
# and the built environment of both equal, and counts this function as the second place in the
# chain that may start git.

#: Environment names passed through to git unchanged (the library's `_GIT_INHERITED`).
_GIT_INHERITED = ("PATH", "SYSTEMROOT")

#: Configuration pinned for every call (the library's `GIT_PINNED_OPTIONS`; the reasons are there).
_GIT_PINNED_OPTIONS = (
    "--no-replace-objects",
    "-c", "core.useReplaceRefs=false",
    "-c", "core.quotePath=true",
    "-c", f"core.excludesFile={os.devnull}",
    "-c", f"core.attributesFile={os.devnull}",
    "-c", "core.fsmonitor=",
    "-c", "core.untrackedCache=false",
    "-c", "core.ignoreCase=false",
    "-c", "core.commitGraph=false",
    "-c", "core.checkStat=default",
    "-c", "core.trustctime=true",
    "-c", "color.ui=false",
)


#: Environment names that choose a PROGRAM for git to run, set empty so none is inherited (owner OA-4496f29e70). The
#: allowlist above already keeps them out -- only `PATH` and `SYSTEMROOT` pass through -- but they are emptied as well,
#: so a future name added to the allowlist cannot carry one, and `GIT_CONFIG_SYSTEM` is sent to the null device beside
#: the global so neither configuration file is read.
_GIT_PROGRAM_ENV = ("GIT_EXTERNAL_DIFF", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_PAGER", "GIT_EDITOR",
                    "GIT_SEQUENCE_EDITOR", "GIT_PROXY_COMMAND", "GIT_ASKPASS")


def _git_environment(root: Path) -> dict:
    """The complete environment of a git call about the repository whose top level is `root` (the
    library's `git_environment`): the allowlist, the pinned names, the work tree pinned to `root`
    and discovery stopped there, so a repository owned by another user still fails closed. No name
    that chooses a program is inherited (`_GIT_PROGRAM_ENV`), and both the global and the system
    configuration are sent to the null device."""
    umgebung = {k: os.environ[k] for k in _GIT_INHERITED if k in os.environ}
    umgebung.update({
        "LC_ALL": "C", "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_WORK_TREE": str(root),
        "GIT_CEILING_DIRECTORIES": str(root.parent),
    })
    umgebung.update({k: "" for k in _GIT_PROGRAM_ENV})
    return umgebung


#: The keys that make a repository a partial clone (the library's `_TEILKLON_SCHLUESSEL`; the reason is there). External
#: review of 65d8f8cd, F3: a missing object of such a clone ran the configured `remote.origin.uploadpack` from `_objekte`,
#: `_baum` and `_measure` before any refusal. `_git` asks nothing further of a repository that carries one of them. The
#: subsection may be empty (`remote..promisor`, external review of d97f6e7b, R2-2).
_TEILKLON_SCHLUESSEL = r"^(extensions\.partialclone|remote\..*\.(promisor|partialclonefilter))$"
#: How the funnel's refusal of a partial clone begins, so `_measure` can give it as the reason it is.
_TEILKLON_GRUND = "the clone is a partial clone"


#: Git configuration keys that name a PROGRAM git may run (owner OA-4496f29e70, the D3 program-selecting families).
#: A key is matched by its first and (where given) last dotted component, so the free middle name of a `filter.<n>.`,
#: `diff.<n>.` or `merge.<n>.` section is covered. `core.fsmonitor` and `core.hooksPath`/alternate-ref/ssh commands
#: name a program directly. Pagers and editors do not run in the verifier's non-interactive calls, but they choose a
#: program and are refused too, so the rule is the family, not the one call that happens to reach it.
_GIT_PROGRAM_KEYS = {
    ("filter", "clean"), ("filter", "smudge"), ("filter", "process"),
    ("diff", "command"), ("diff", "textconv"), ("merge", "driver"),
    ("credential", "helper"), ("gpg", "program"),
    # External review of d97f6e7b, question 2 (measured there: each of these came back `[]`): the transport programs of
    # a remote, and the external tool commands. `difftool`/`mergetool` `.path` are the same family as `.cmd`.
    ("remote", "uploadpack"), ("remote", "receivepack"), ("remote", "vcs"),
    ("difftool", "cmd"), ("difftool", "path"), ("mergetool", "cmd"), ("mergetool", "path"),
}
#: First components whose every subkey names a program (`pager.<cmd>`), unless the value is a plain boolean. This is
#: the ONLY family whose boolean value is exempted; see the reason at the matching below.
_GIT_PROGRAM_FIRST = {"pager"}
_GIT_PROGRAM_EXACT = {
    "core.fsmonitor", "core.hookspath", "core.sshcommand", "core.pager", "core.editor",
    "core.alternaterefscommand", "core.askpass", "diff.external", "sequence.editor",
    "credential.helper", "uploadpack.packobjectshook", "pack.packsizelimit.command",
    "interactive.difffilter", "gpg.ssh.defaultkeycommand", "gpg.ssh.allowedsignerscommand",
    "gpg.ssh.revocationfile",
    # External review of d97f6e7b, question 2: the proxy command of the git transport.
    "core.gitproxy",
}
#: Program keys for which git reads EXACTLY the empty value as "none": an empty `core.fsmonitor` switches the monitor
#: off (and the funnel itself pins `-c core.fsmonitor=`), an empty filter command applies no filter, an empty
#: credential helper resets the list. Every other program key is refused when present, even empty; white space is never
#: empty here, because the value is compared as git stores it, not stripped. `core.hooksPath` is deliberately NOT in this
#: set: its value is a DIRECTORY, an empty one is not an off switch (git resolves the hooks against the file system
#: root), and one of white space names a real relative directory (external review of d97f6e7b, R2-1, measured there
#: with one space), so it is refused whenever it is set.
_GIT_PROGRAM_EMPTY_IS_OFF = {"core.fsmonitor", "filter.*.clean", "filter.*.smudge", "filter.*.process",
                             "credential.helper", "credential.*.helper"}
#: A shell alias (`alias.<name>=!command`) runs a program when the alias is used; a plain alias names a git command.
_GIT_ALIAS_SHELL = "!"
_GIT_BOOLEAN = {"", "true", "false", "0", "1", "yes", "no", "on", "off"}


def _leer_heisst_aus(key_l: str) -> bool:
    """Whether git reads exactly the empty value of the program key `key_l` as "none" (`_GIT_PROGRAM_EMPTY_IS_OFF`)."""
    teile = key_l.split(".")
    form = key_l if len(teile) < 3 else f"{teile[0]}.*.{teile[-1]}"
    return key_l in _GIT_PROGRAM_EMPTY_IS_OFF or form in _GIT_PROGRAM_EMPTY_IS_OFF


def _git_configuration_selects_a_program(repo: Path) -> list:
    """Every configuration key of this clone that names a program git would run, as `key=value`.

    Read through this script's own funnel, with the global and system configuration already sent to the null device
    (`_git_environment`), so `git config --list --includes` returns the clone's own `.git/config` and the files it
    includes (`include`, `includeIf`) and nothing from outside. A key is reported when it names a program from the
    listed families: a `filter.<name>.clean`/`.smudge`/`.process`, a `diff.<name>.command`/`.textconv`, a
    `merge.<name>.driver`, a remote's `uploadpack`/`receivepack`/`vcs`, a `difftool`/`mergetool` command or path, a
    shell alias, or one of the exact program-naming keys (`core.fsmonitor`, `core.hooksPath`, `core.gitProxy`, an ssh
    or alternate-ref command, a configured pager or editor, a credential helper). The value is compared as git stores
    it; `core.hooksPath` is refused whenever it is set, and an empty value passes only for the keys where git reads it
    as "none". A boolean value is exempted for `pager.<cmd>` only, the one family git reads as a switch. An unparsable
    line is reported as a refusal of its own, never dropped. This is a refusal of the listed families, measured family
    by family, and not a proof that no clone-chosen program exists: the external review of d97f6e7b showed the earlier
    list incomplete, and that the present one is complete is not shown. The attributes that select drivers are judged
    separately (`_git_attributes_select_a_driver`)."""
    rc, aus, err = _git(repo, "config", "--list", "-z", "--includes")
    if rc != 0:
        # No configuration at all is rc 1 with empty output; a real failure carries a message.
        if aus == b"" and not err:
            return []
        return [f"the clone's git configuration could not be read: {err or 'git config failed'}"]
    funde = []
    # `--list -z` writes `key NL value NUL` for a key with a value, and `key NUL` for a value-less (boolean) key.
    for eintrag in aus.split(b"\0"):
        if not eintrag:
            continue
        schluessel, trenner, wert = eintrag.partition(b"\n")
        key = schluessel.decode("utf-8", "replace")
        value = wert.decode("utf-8", "replace") if trenner else ""
        key_l = key.lower()
        teile = key_l.split(".")
        gewaehlt = key_l in _GIT_PROGRAM_EXACT or (len(teile) >= 2 and (teile[0], teile[-1]) in _GIT_PROGRAM_KEYS)
        # A BOOLEAN IS A SWITCH ONLY WHERE GIT READS THE KEY AS ONE (external review of 65d8f8cd, F1, measured there:
        # that commit exempted a boolean value for every key, and `filter.demo.clean=true`, `core.sshCommand=false` and
        # `core.hooksPath=off` all came back as `[]`). Git reads `pager.<cmd>` as a switch when its value is a boolean
        # and as a pager command otherwise, so only that family keeps the exemption. For every other key the value IS
        # the program or the directory: `filter.<n>.clean=true` runs the command `true`, `core.sshCommand=false` runs
        # `false`, `core.hooksPath=off` names a directory `off`, and `core.fsmonitor` is a hook command on the git this
        # was measured with (2.34.1, whose `git help config` names no boolean form), so it is not exempted either.
        # THE VALUE IS COMPARED AS GIT STORES IT (external review of d97f6e7b, R2-1): stripping it made one space look
        # empty, and `core.hooksPath` of one space names a real directory. A program key is allowed empty only where git
        # reads the empty value as "none" (`_GIT_PROGRAM_EMPTY_IS_OFF`, the funnel's own `-c core.fsmonitor=` among
        # them); `core.hooksPath` is not among them, so it is refused whenever it is set.
        if len(teile) >= 2 and teile[0] in _GIT_PROGRAM_FIRST:
            gewaehlt = value.lower() not in _GIT_BOOLEAN
        if teile[0] == "alias" and value.lstrip().startswith(_GIT_ALIAS_SHELL):
            gewaehlt = True
        if gewaehlt and (value != "" or not _leer_heisst_aus(key_l)):
            funde.append(f"{key}={value[:60]!r}")
    return funde


#: The diff patterns git ships (git 2.34.1, `git help gitattributes`, "The following built in patterns are
#: available"). A built-in pattern sets a hunk header and word rule and names no program. A name git added later
#: (`kotlin`, say) is not in this list and is refused: fail closed, a refusal of a harmless name, never a pass of a
#: driver.
_DIFF_EINGEBAUT = frozenset((
    "ada", "bash", "bibtex", "cpp", "csharp", "css", "dts", "elixir", "fortran", "fountain", "golang", "html",
    "java", "markdown", "matlab", "objc", "pascal", "perl", "php", "python", "ruby", "rust", "scheme", "tex"))
#: The merge drivers git ships (`git help gitattributes`, "Built-in merge drivers").
_MERGE_EINGEBAUT = frozenset(("text", "binary", "union"))
#: The three states `git check-attr` reports for an attribute that carries no value. The SAME three words are also what it
#: prints for an attribute ASSIGNED that string (`filter=set`); git documents the ambiguity (external review of 12d5a7cb,
#: R3-1, which measured ten false passes through it). They are therefore never taken as a state on check-attr's word
#: alone: `_mehrdeutige_werte` asks git again with attribute pathspecs, which do tell a state from a string value.
_ATTR_OHNE_WERT = frozenset(("unspecified", "set", "unset"))
_ATTR_GEPRUEFT = ("filter", "diff", "merge")


def _index_ist_der_commit(repo: Path, eintraege: dict) -> str | None:
    """None when git's index lists exactly the non-directory entries of the commit (mode, id and path, all at stage 0);
    otherwise the reason. The attribute pathspecs below select paths from the INDEX, and a selection the checkout could
    change by editing its index (`git rm --cached`, a staged extra path) is not the set of committed files the attribute
    contract is about (external review of 12d5a7cb, R3-1: the follow-up query "must keep covering every checked commit
    path and must not leave their choice to a changeable index")."""
    rc, aus, err = _git(repo, "ls-files", "-s", "-z")
    if rc != 0 or err:
        return f"git ls-files could not list the index: {err or 'git ls-files failed'}"
    index = set()
    for eintrag in aus.split(b"\0"):
        if not eintrag:
            continue
        kopf, tab, pfad = eintrag.partition(b"\t")
        teile = kopf.split(b" ")
        if not tab or len(teile) != 3:
            return "git ls-files answered in a form that is not mode, id, stage and path"
        modus, oid, stufe = (t.decode("ascii", "replace") for t in teile)
        if stufe != "0":
            return f"the index holds {os.fsdecode(pfad)} at merge stage {stufe}"
        index.add((modus, oid, os.fsdecode(pfad)))
    commit = {(modus, oid, pfad) for pfad, (typ, oid, modus) in eintraege.items() if typ != "tree"}
    if index != commit:
        return (f"the index does not list exactly the files of the commit ({len(index - commit)} extra or changed, "
                f"{len(commit - index)} missing)")
    return None


def _mehrdeutige_werte(repo: Path) -> list:
    """Every path of the index whose `filter`, `diff` or `merge` attribute is the STRING `set`, `unset` or `unspecified`
    (a driver of that name), as `path: attribute=value`, asked through attribute pathspecs (`:(attr:filter=set)`), which
    match a string value and never a state (gitglossary, "attr"). An answer that is not a clean listing is a finding."""
    funde = []
    for attribut in _ATTR_GEPRUEFT:
        for wert in sorted(_ATTR_OHNE_WERT):
            rc, aus, err = _git(repo, "ls-files", "-z", "--", f":(top,attr:{attribut}={wert})")
            if rc != 0 or err:
                funde.append(f"git could not say which paths carry {attribut}={wert}: {err or 'git ls-files failed'}")
                continue
            funde += [f"{os.fsdecode(p)}: {attribut}={wert} (a driver of that name, not the state)"
                      for p in aus.split(b"\0") if p]
    return funde


def _git_attributes_select_a_driver(repo: Path, eintraege: dict) -> list:
    """Every committed FILE (a blob, a symbolic link included) whose EFFECTIVE `filter`, `diff` or `merge` attribute
    names a driver git does not ship, as `path: attribute=value` (owner decision OA-0a507fd998 A, after the external
    review of d97f6e7b did not confirm the configuration families as complete). A gitlink is not asked.

    The attributes are taken as git applies them, by git itself: `git check-attr --stdin` through this script's own
    funnel, for every committed file, reads the `.gitattributes` of the checkout in every directory on the path,
    `.git/info/attributes`, and the macros (`[attr]name ...`) they define, in git's order of precedence; the global
    attributes file is pinned to the null device (`core.attributesFile`). A search for driver names in one file would
    miss a directory rule, a macro and the precedence between them, which the review named. Refused: any named
    `filter` (git ships none), a `diff` that is not a built-in pattern (`_DIFF_EINGEBAUT`), a `merge` that is not a
    built-in driver (`_MERGE_EINGEBAUT`). An attribute that is set, unset or unspecified names no driver, but check-attr
    prints the same three words for a driver of that NAME (external review of 12d5a7cb, R3-1), so a second question
    tells them apart (`_mehrdeutige_werte`), after the index is measured to be exactly the commit's files
    (`_index_ist_der_commit`). Any warning git prints while reading the attributes refuses too (R3-5: a
    `.git/info/attributes` over git's size limit was ignored with a warning and the empty answer passed as complete).

    WHAT THIS IS AND IS NOT. The verifier's own git calls read objects and run no worktree filter, diff or merge, so a
    driver named here would not run in them (`cat-file --batch` uses neither `--filters` nor `--textconv`); the review
    measured a clone with unconfigured driver names still VERIFIED, a narrow separation it confirmed, not a complete
    execution boundary. This refusal is the owner's contract: a clone that names a driver git would run for its files
    is not measured, whatever the configuration says. Consequence for this repository: a commit that adds such an
    attribute would be refused by its own verifier."""
    pfade = [p for p, (typ, _oid, _modus) in sorted(eintraege.items()) if typ == "blob"]
    if not pfade:
        return []
    rc, aus, err = _git(repo, "check-attr", "-z", "--stdin", *_ATTR_GEPRUEFT,
                        eingabe=b"".join(os.fsencode(p) + b"\0" for p in pfade))
    if rc != 0:
        return [f"the attributes of the clone could not be read: {err or 'git check-attr failed'}"]
    if err:
        # A WARNING IS AN INCOMPLETE ANSWER (external review of 12d5a7cb, R3-5): git drops a rule it will not read (an
        # attributes file over its size limit, an overly long line) with a warning and exit 0, and the empty answer
        # looked like a clean tree. Read as complete only what git read without complaint.
        return [f"git warned while reading the attributes, so its answer is not the complete set: {err[:200]}"]
    teile = aus.split(b"\0")
    if teile and teile[-1] == b"":
        teile = teile[:-1]
    if len(teile) % 3:
        return ["git check-attr answered in a form that is not path, attribute and value"]
    funde = []
    for i in range(0, len(teile), 3):
        pfad, attribut, wert = (os.fsdecode(x) for x in teile[i:i + 3])
        if wert in _ATTR_OHNE_WERT:
            continue
        if (attribut == "filter" or (attribut == "diff" and wert not in _DIFF_EINGEBAUT)
                or (attribut == "merge" and wert not in _MERGE_EINGEBAUT)):
            funde.append(f"{pfad}: {attribut}={wert[:40]}")
    if funde:
        return funde
    # THE THREE WORDS, TOLD APART (R3-1). Only once the index is the commit's file list may an index-based selection
    # stand for "every committed file"; if it is not, nothing can be told apart, and that refuses. A gitlink (a
    # submodule entry, mode 160000) is not asked here (Codex on PR 311 at 6d081424, thread 4173974273);
    # RESTRISIKO_620.md R620-CODEX-6D08-2 names it, for 6.2.1.
    abweichung = _index_ist_der_commit(repo, eintraege)
    if abweichung is not None:
        return [f"{abweichung}, so a state set, unset or unspecified cannot be told from a driver of that name"]
    return _mehrdeutige_werte(repo)


def _nennt_die_wurzel(antwort: bytes, root: Path) -> bool:
    """Does git's `--show-toplevel` answer name `root` (already resolved)? The library's
    `_nennt_die_wurzel`, carried here for the reason `_git` is: compared as resolved paths, because
    git for Windows prints `C:/repo` where the resolved path reads `C:\\repo`, and an empty or
    relative answer names no directory (resolved, it would be this process's working directory)."""
    text = os.fsdecode(antwort)
    if not text or not Path(text).is_absolute():
        return False
    try:
        return Path(text).resolve() == root
    except (OSError, RuntimeError, ValueError):
        return False


def _git(repo: Path, *args: str, eingabe: bytes | None = None) -> tuple[int, bytes, str]:
    """One git call about `repo`, through this script's own funnel. -> (exit code, stdout, stderr)

    MEASURED 2026-09-27 (Codex on PR 249, and re-measured): this ran `git -C <repo>` with the
    caller's environment. With `GIT_WORK_TREE` pointing at a clean clone of the same commit, the
    cleanliness check below came back empty for a checkout that carried a modified
    `verify_receipt`, and a commit with an invalid receipt was `VERIFIED`, exit 0.

    Before the call, git must name `repo` as the top level with an empty prefix, as in the
    library's funnel, and the repository must not be a partial clone (`_TEILKLON_SCHLUESSEL`). A
    repository git will not answer for (not a repository, another owner, a subdirectory, no git, a
    partial clone) is returned as exit 128 with the reason, which every caller below reads as not
    measurable.
    """
    import subprocess  # noqa: PLC0415
    root = Path(os.fspath(repo)).resolve()
    umgebung = _git_environment(root)

    def starte(argumente: tuple, daten: bytes | None = None):
        extra = {"input": daten} if daten is not None else {"stdin": subprocess.DEVNULL}
        return subprocess.run(["git", *_GIT_PINNED_OPTIONS, "-C", str(root), *argumente],
                              capture_output=True, timeout=30, env=umgebung, **extra)

    try:
        ort = starte(("rev-parse", "--show-toplevel", "--show-prefix"))
        if ort.returncode != 0:
            return 128, b"", ("git does not answer for this directory as a repository: "
                              + ort.stderr.decode("utf-8", "replace").strip())
        zeilen = ort.stdout.split(b"\n")
        if len(zeilen) < 2 or not _nennt_die_wurzel(zeilen[0], root) or zeilen[1] != b"":
            return 128, b"", (f"git answers for {root} with the top level "
                              f"{os.fsdecode(zeilen[0])!r}; only the top level of a repository "
                              "is measured")
        # NO QUESTION TO A PARTIAL CLONE, before any object is read (see `_TEILKLON_SCHLUESSEL`).
        teilklon = starte(("config", "-z", "--get-regexp", _TEILKLON_SCHLUESSEL))
        if teilklon.returncode == 0 and teilklon.stdout:
            namen = sorted({e.split(b"\n", 1)[0].decode("utf-8", "replace")
                            for e in teilklon.stdout.split(b"\0") if e})
            return 128, b"", (f"{_TEILKLON_GRUND} ({', '.join(namen)[:160]}): git fetches an object it does not "
                              "hold from the promisor remote and starts the program that remote's configuration "
                              "names, so no object is read from it -- clone the repository in full")
        if teilklon.returncode != 1 or teilklon.stdout:
            return 128, b"", ("git could not say whether this clone is a partial clone: "
                              + (teilklon.stderr.decode("utf-8", "replace").strip() or "git config failed"))
        r = starte(args, eingabe)
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, b"", f"{type(exc).__name__}: {exc}"
    return r.returncode, r.stdout, r.stderr.decode("utf-8", "replace").strip()


# ── THIS SCRIPT'S OWN CHECK THAT AN OBJECT IS THE ONE ITS ID NAMES ─────────────────────────────
#
# Review finding on PR 249, 2026-09-27 (P0 at the release gate, measured): git returns whatever the
# object store holds under an id and does not hash it. The library now reads every object it uses
# through `pre_tag_receipt_lib.git_objects`, which does. This script reads the gate source and the
# receipts from the commit itself, and its cleanliness check compares the checkout with the commit's
# trees (it asked `git status` until 65d8f8cd and compares the bytes itself since); all of that happens
# here, before or beside the library, so the check is carried here as well, on this file's code alone,
# for the reason `_git` is: a library whose trees were rewritten to list its modified blob looked
# clean to `git status` and then judged itself (measured at 995cabdd with git 2.34.1 and 2.55.0:
# `VERIFIED` for a receipt nobody trusted signed).
# The library's copy and this one are held to one answer by
# `tests/test_pre_tag_receipt_git_answers_for_the_named_tree.py`.

#: The hash of an object id, by the number of hex digits (the library's `_ID_ALGORITHMUS`).
_ID_ALGORITHMUS = {40: "sha1", 64: "sha256"}
_IST_OBJEKT_ID = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


class _NichtDasObjekt(Exception):
    """An object of the clone is not the object its id names, or cannot be read as one."""


def _objekte(repo: Path, gesucht) -> dict:
    """{id: content} for `gesucht` [(id, type)], one `cat-file --batch`, each content hashed as git
    defines an id and compared with the id it was asked for (the library's `git_objects`)."""
    typen: dict = {}
    for oid, typ in gesucht:
        if not isinstance(oid, str) or not _IST_OBJEKT_ID.match(oid) or typen.setdefault(oid, typ) != typ:
            raise _NichtDasObjekt(f"{oid!r} is not a full object id asked for as one type")
    if not typen:
        return {}
    rc, aus, err = _git(repo, "cat-file", "--batch",
                        eingabe=b"".join(oid.encode("ascii") + b"\n" for oid in typen))
    if rc != 0:
        raise _NichtDasObjekt(f"git cat-file --batch failed: {err}")
    pos, raus = 0, {}
    for oid, typ in typen.items():
        ende = aus.find(b"\n", pos)
        kopf = aus[pos:ende].split(b" ") if ende >= 0 else []
        if len(kopf) != 3 or kopf[0] != oid.encode("ascii") or not kopf[2].isdigit():
            raise _NichtDasObjekt(f"the object {oid} is not in this clone's object store")
        gelesen, groesse = kopf[1].decode("ascii", "replace"), int(kopf[2])
        inhalt = aus[ende + 1:ende + 1 + groesse]
        if len(inhalt) != groesse or aus[ende + 1 + groesse:ende + 2 + groesse] != b"\n":
            raise _NichtDasObjekt(f"git's answer for the object {oid} is cut short")
        pos = ende + 2 + groesse
        h = hashlib.new(_ID_ALGORITHMUS[len(oid)])
        h.update(gelesen.encode("ascii") + b" " + str(len(inhalt)).encode("ascii") + b"\0" + inhalt)
        if gelesen != typ or h.hexdigest() != oid:
            raise _NichtDasObjekt(
                f"the {typ} under the id {oid} in this clone is not the object its id names (git "
                f"reads a {gelesen} whose bytes hash to {h.hexdigest()})")
        raus[oid] = inhalt
    if pos != len(aus):
        raise _NichtDasObjekt("git cat-file --batch answered more than it was asked")
    return raus


def _baum(repo: Path, commit: str) -> dict:
    """{path: (type, id)} for every entry below the tree of `commit`, read from the commit and from
    trees that each hash to their id; one `cat-file --batch` per level (the library's `git_tree`)."""
    return {pfad: (typ, oid) for pfad, (typ, oid, _modus) in _baum_eintraege(repo, commit).items()}


def _baum_eintraege(repo: Path, commit: str) -> dict:
    """{path: (type, id, mode)}: `_baum` with each entry's mode as `ls-tree` prints it (`100644`, `100755`,
    `120000`, `040000`, `160000`, the library's `_modus`). The mode tells a symbolic link from a file and a
    directory from both; `_code_on_disk_that_is_not_the_commit` holds the checkout to it (external review of
    65d8f8cd, F4)."""
    erste = _objekte(repo, [(commit, "commit")])[commit].split(b"\n", 1)[0]
    wurzel = erste[5:].decode("ascii", "replace")
    if not erste.startswith(b"tree ") or len(wurzel) != len(commit) or not _IST_OBJEKT_ID.match(wurzel):
        raise _NichtDasObjekt(f"the commit {commit} names no tree")
    breite, raus, ebene = len(commit) // 2, {}, [(wurzel, b"")]
    while ebene:
        gelesen = _objekte(repo, [(oid, "tree") for oid, _ in ebene])
        naechste = []
        for oid, praefix in ebene:
            inhalt, pos = gelesen[oid], 0
            while pos < len(inhalt):
                leer = inhalt.find(b" ", pos)
                nul = inhalt.find(b"\0", leer + 1) if leer >= 0 else -1
                modus = inhalt[pos:leer] if leer >= 0 else b""
                if (nul < 0 or nul + 1 + breite > len(inhalt) or nul == leer + 1 or not modus
                        or any(c < 0x30 or c > 0x37 for c in modus)):
                    raise _NichtDasObjekt(f"the tree {oid} is not in the form git writes")
                zahl = int(modus, 8)
                art = zahl & 0o170000
                typ = "tree" if art == 0o040000 else "blob" if art in (0o100000, 0o120000) else "commit"
                modus_text = ("040000" if art == 0o040000 else "120000" if art == 0o120000
                              else ("100755" if zahl & 0o100 else "100644") if art == 0o100000 else "160000")
                pfad, eid = praefix + inhalt[leer + 1:nul], inhalt[nul + 1:nul + 1 + breite].hex()
                raus[os.fsdecode(pfad)] = (typ, eid, modus_text)
                if typ == "tree":
                    naechste.append((eid, pfad + b"/"))
                pos = nul + 1 + breite
        ebene = naechste
    return raus


def _datei(repo: Path, baum: dict, rel: str) -> bytes | None:
    """The content of the blob at `rel` in `baum`, checked against its id; None if `rel` is no blob."""
    typ, oid = baum.get(rel, (None, None))
    return _objekte(repo, [(oid, "blob")])[oid] if typ == "blob" else None


def _kein_objekt_grund(exc: Exception) -> str:
    """The reason given when this clone's object store does not hold what the commit names."""
    return (f"this clone's object store does not hold the objects the commit names ({exc}); what "
            "git answers under those ids is not the commit, so nothing is measured -- clone "
            "afresh and run again")


def _code_on_disk_that_is_not_the_commit(repo: Path, baum: dict) -> list:
    """Every path under `scripts/` or `src/` at which the checkout is not the commit, by name and reason.

    `git status` answers through the index and the ignore rules, and both live outside the committed tree. Deep gate
    run 7 at 1a3cd672 (L6-620v7-T6-VERIFIER-SELF-HIDDEN-SHADOW-01, P1): an untracked package that carries its own
    `.gitignore` with `*` hides itself from `git status --porcelain --untracked-files=all`, and Python imports a
    package directory ahead of a module of the same name, so `src/proofbundle/signature/` ran as the judge and a
    tampered receipt came back VERIFIED. The neighbour of the same class is the index: a modified committed file whose
    `skip-worktree` or `assume-unchanged` bit is set is not listed either. So the property is computed from the bytes,
    as the producer does (`pre_tag_receipt._baumzustand_oder_stop`), on this file's code alone:

      a committed entry     its TYPE on disk first, read with `lstat` so a link is never followed: a committed
                            directory must be a directory, a committed file a regular file, a committed symbolic
                            link a link (`scripts` and `src` themselves included, so every directory on the way to
                            a compared file is one the commit names). Then a file's bytes, or a link's target,
                            hashed as a git blob and compared with the id the commit names; a committed path that
                            is missing refuses;
      an uncommitted path   a file Python could import (any suffix of `importlib.machinery.all_suffixes()`) or a
                            symbolic link refuses, whatever rule hides it. Other files (a `*.egg-info` of an
                            editable install, notes) cannot be imported and stay allowed.

    THE TYPE COMES BEFORE THE BYTES (external review of 65d8f8cd, F4, measured there): the committed directory
    `src/pkg` replaced by a symbolic link to an outside copy whose tracked files were byte-identical, with an extra
    `extra.py` behind the link, came back `[]` like the clean control. Reading a committed file follows a linked
    directory above it, and the walk below does not follow links and skips the linked directory's name because the
    commit has it, so an importable file nobody compared lay behind a structure judged clean. The `git status` this
    replaced refused that exchange; it is not brought back, because it is the call that ran a configured filter. The
    execute bit of a regular file is not compared: Python imports a module whatever that bit says, and on a file
    system without one (Windows) every committed `100755` would refuse. `__pycache__` is not read: this run keeps its
    bytecode in a fresh directory (`_bytecode_cache_elsewhere`), and no import names a package of that name."""
    import importlib.machinery  # noqa: PLC0415 - the standard library, after the path was cleaned
    import stat  # noqa: PLC0415 - the standard library, after the path was cleaned
    suffixe = tuple(importlib.machinery.all_suffixes())
    wurzel = repo.resolve()
    funde: list = []
    #: Committed directories found to be something else on disk; nothing below them is read through them.
    abgelehnt: list = []
    for rel, (typ, oid, modus) in sorted(baum.items()):
        if not (rel in _CODE_PFADE or any(rel.startswith(p + "/") for p in _CODE_PFADE)):
            continue
        if any(rel.startswith(a + "/") for a in abgelehnt):
            continue
        pfad = wurzel / rel
        try:
            st = os.lstat(pfad)
        except FileNotFoundError:
            if typ != "commit":                 # a submodule that was never initialised may be absent
                funde.append(f"{rel}: committed, but not in the checkout")
                if typ == "tree":
                    abgelehnt.append(rel)
            continue
        except OSError as exc:
            funde.append(f"{rel}: cannot be read ({type(exc).__name__})")
            if typ == "tree":
                abgelehnt.append(rel)
            continue
        ist = ("a symbolic link" if stat.S_ISLNK(st.st_mode) else "a directory" if stat.S_ISDIR(st.st_mode)
               else "a regular file" if stat.S_ISREG(st.st_mode) else "neither a file, a directory nor a link")
        soll = {"040000": "a directory", "120000": "a symbolic link", "100644": "a regular file",
                "100755": "a regular file"}.get(modus)
        if typ == "commit":
            # A submodule's directory is walked below like any other; it must not be a link to elsewhere.
            if stat.S_ISLNK(st.st_mode):
                funde.append(f"{rel}: committed as a submodule directory, but in the checkout it is a symbolic link")
            continue
        if ist != soll:
            funde.append(f"{rel}: committed as {soll}, but in the checkout it is {ist}")
            if typ == "tree":
                abgelehnt.append(rel)
            continue
        if typ == "tree":
            continue
        try:
            inhalt = os.fsencode(os.readlink(pfad)) if modus == "120000" else pfad.read_bytes()
        except OSError as exc:
            funde.append(f"{rel}: cannot be read ({type(exc).__name__})")
            continue
        h = hashlib.new(_ID_ALGORITHMUS[len(oid)])
        h.update(b"blob " + str(len(inhalt)).encode("ascii") + b"\0" + inhalt)
        if h.hexdigest() != oid:
            funde.append(f"{rel}: its bytes in the checkout are not the committed blob")
    # A DIRECTORY THAT CANNOT BE LISTED IS AN INCOMPLETE MEASUREMENT, NOT A CLEAN ONE (external review of d97f6e7b,
    # R2-5). `os.walk` without `onerror` drops every `scandir` error silently, so a directory the walk could not list
    # left no finding, and the library was loaded next. The comparison of committed paths above does not cover it,
    # because it is exactly the uncommitted files it does not know; and a directory that can be searched but not listed
    # still lets Python import a module from it by name. Every error of the walk is a finding now, and any finding
    # refuses with exit 2 before the library is loaded.
    nicht_gelistet: list = []
    for teil in _CODE_PFADE:
        if teil in abgelehnt:
            continue                            # already refused above; `os.walk` would follow a linked top
        # A top that is not on disk holds nothing to compare: if the commit names it, the comparison above already
        # reported it as missing; if not, there is no directory and no file in it. Walked anyway, `os.walk` reports
        # its absence through `onerror`, and the full suite at 0bfee205 measured exactly that: a tree without
        # `scripts/` was refused as "cannot be listed (FileNotFoundError)". Only a directory that exists and cannot
        # be listed is an incomplete measurement.
        if not os.path.lexists(wurzel / teil):
            continue
        for ordner, unterordner, dateien in os.walk(wurzel / teil, followlinks=False,
                                                    onerror=nicht_gelistet.append):
            unterordner[:] = [d for d in unterordner if d != "__pycache__"]
            rel_ordner = Path(ordner).relative_to(wurzel).as_posix()
            for name in sorted(unterordner) + sorted(dateien):
                rel = f"{rel_ordner}/{name}"
                if rel in baum:
                    continue
                if os.path.islink(os.path.join(ordner, name)) or (name in dateien and name.endswith(suffixe)):
                    funde.append(f"{rel}: not in the commit, and Python could import it or follow it")
    for fehler in nicht_gelistet:
        ort = getattr(fehler, "filename", None)
        try:
            rel = Path(os.fsdecode(ort)).relative_to(wurzel).as_posix() if ort is not None else "?"
        except (ValueError, TypeError):
            rel = os.fsdecode(ort) if isinstance(ort, (str, bytes)) else "?"
        funde.append(f"{rel}: cannot be listed ({type(fehler).__name__}), so the files in it were not compared; "
                     "Python may still import a module from it by name")
    return funde


def _version_token(version: str) -> str:
    return version.replace(".", "")


def measure(repo: Path, commit: str, version: str) -> dict:
    """See `_measure`; the import state of the process is the same afterwards."""
    with _importzustand():
        return _measure(repo, commit, version)


def _measure(repo: Path, commit: str, version: str) -> dict:
    """The whole measurement as one dict. ``verdict`` is VERIFIED, NOT_VERIFIED or NOT_MEASURABLE;
    every other field says what was read and from where. Never raises on a bad input -- a reader
    gets a verdict with a reason, not a traceback."""
    out: dict = {"schema": "b7n0de.verify_pre_tag_receipt.v1", "commit": commit, "version": version,
                 "checkout_head": None, "receipt_path": None, "receipt_read_from": None,
                 "subject_tree_digest": None, "gate_source_digest": None,
                 "trusted_pubkey_count": None, "signer_pubkey": None,
                 "verified": [], "rejected": [], "foreign_files": [],
                 "verdict": "NOT_MEASURABLE", "reason": None, "limit": LIMIT}
    commit = commit.strip().lower() if isinstance(commit, str) else commit
    out["commit"] = commit
    if not isinstance(commit, str) or not _HEX40.match(commit):
        out["reason"] = ("--commit must be the full 40-hex commit id named by the attestation; an "
                         "abbreviated id is a search query, not a subject")
        return out
    if _INTERPRETER_OVERLAP:
        # THE INTERPRETER AND THE CHECKOUT OVERLAP (see `_interpreter_overlaps_the_checkout`): either the interpreter is
        # installed in the checkout, or the checkout lies in a startup directory of the interpreter. Either way Python
        # runs that directory's startup code (`.pth` files, `sitecustomize`) before this script's first line, `-I`
        # included, and it is not the commit.
        out["reason"] = (f"the interpreter running this script shares a directory with the checkout "
                         f"({_INTERPRETER_OVERLAP[0][:160]}); Python runs the startup files of its installation (`.pth` "
                         "files, `sitecustomize`) from there before the verifier's first line, also under -I, and they "
                         "are not the commit -- run the verifier with a Python whose installation is outside the clone, "
                         "and from a clone that is not inside that installation")
        return out
    if _STARTUP_PATH_INTO_CHECKOUT:
        # A STARTUP FILE PUT THE CHECKOUT ON THE PATH, under -I (see `_startup_search_paths_into_the_checkout`). Code of
        # the checkout may have run before this line; the precondition in the module docstring was not met.
        out["reason"] = (f"under -I the search path at start already named a directory of this checkout or one that "
                         "contains it, or an entry whose place could not be established "
                         f"({_STARTUP_PATH_INTO_CHECKOUT[0][:160]}); -I adds neither PYTHONPATH nor the script's "
                         "directory, so a startup file of the interpreter (a `.pth` path line) put it there, and Python "
                         "may have run a `sitecustomize.py` of the checkout before the verifier's first line -- run the "
                         "verifier with a Python none of whose startup files names a directory of the clone or one "
                         "that contains it")
        return out
    if _SCRIPT_CHECKOUT is not None and os.path.realpath(repo) != _SCRIPT_CHECKOUT:
        # THE CODE THAT JUDGES IS NOT THE CODE THAT IS COMPARED (see `_SCRIPT_CHECKOUT`).
        out["reason"] = (f"the verifier runs from the checkout {_SCRIPT_CHECKOUT}, but --repo names "
                         f"{os.path.realpath(repo)}; only the checkout --repo names is compared with the commit, and the "
                         "code that judges must be that code -- run scripts/verify_pre_tag_receipt.py of the checkout "
                         "you verify")
        return out
    if _CODE_BEFORE_THIS_SCRIPT:
        # CODE OF THE CHECKOUT RAN BEFORE THIS SCRIPT (see `_checkout_code_that_ran_before_this_script`): whatever it
        # changed in this process is not measurable from here, so no verdict is given.
        out["reason"] = (f"code of this checkout ran before the verifier's first line "
                         f"({_CODE_BEFORE_THIS_SCRIPT[0][:160]}{' …' if len(_CODE_BEFORE_THIS_SCRIPT) > 1 else ''}); "
                         "Python loads such a module at start when PYTHONPATH names a directory of the checkout -- run "
                         "`python -I scripts/verify_pre_tag_receipt.py ...`, which reads no PYTHONPATH")
        return out
    rc, head, err = _git(repo, "rev-parse", "--verify", "HEAD")
    if rc != 0:
        # A partial clone is refused by the funnel itself, before this first question (see `_TEILKLON_SCHLUESSEL`).
        out["reason"] = (err if err.startswith(_TEILKLON_GRUND)
                         else f"not a git checkout, or no HEAD: {err or 'git rev-parse failed'}")
        return out
    # NO CONFIGURED PROGRAM, asked as early as a reason can still say what was refused (after git answered for the
    # directory as a repository) and before any object is read. The order is defence in depth: the object reads below
    # run no configured program, and the one way they could start one, the fetch of a partial clone, the funnel refuses
    # before every call (external review of 65d8f8cd, F3, where `_baum` still ran before this refusal). The cleanliness
    # check further down is `_code_on_disk_that_is_not_the_commit`, which hashes the bytes on disk itself and calls no
    # git worktree operation, so the `git status` that ran a `filter.*.clean` (measured on 2026-10-02 at 653b5d67) is
    # gone. As the owner's class decision (OA-4496f29e70), a clone whose own configuration names a program from the
    # families of `_git_configuration_selects_a_program` is refused, and that the families are complete is not shown;
    # the attributes are judged after the tree is read (`_git_attributes_select_a_driver`, owner OA-0a507fd998 A). The
    # global and system configuration are read from the null device and no program-selecting environment name is
    # inherited (`_git_environment`).
    programme = _git_configuration_selects_a_program(repo)
    if programme:
        out["reason"] = (f"keys of the clone's own git configuration select a program to run "
                         f"({programme[0][:160]}{' …' if len(programme) > 1 else ''}); a clone from the forge carries "
                         "no such setting, so clone afresh, then run again")
        return out
    head_s = head.decode().strip()
    out["checkout_head"] = head_s
    rc, obj, err = _git(repo, "rev-parse", "--verify", f"{commit}^{{commit}}")
    if rc != 0 or obj.decode().strip() != commit:
        out["reason"] = (f"commit {commit[:12]} is not an object of this clone "
                         f"({err or 'rev-parse failed'}) -- fetch it, or check the id")
        return out
    if head_s != commit:
        # REFUSED, NOT MEASURED. The tree digest is taken over HEAD by the library the release
        # gate uses; measuring a different head and reporting it under the requested commit
        # would be a verdict about the wrong tree.
        out["reason"] = (f"the checkout is at {head_s[:12]}, not at the named commit "
                         f"{commit[:12]} -- run `git checkout {commit}` first; this script measures "
                         "the tree that is checked out and refuses to guess about another")
        return out
    # THE COMMIT AND EVERY TREE BELOW IT ARE THE OBJECTS THEIR IDS NAME, checked before anything is
    # compared with them or read from them: the checkout is compared with these trees below, and the
    # gate source and the receipts are looked up in them.
    try:
        eintraege = _baum_eintraege(repo, commit)
    except _NichtDasObjekt as exc:
        out["reason"] = _kein_objekt_grund(exc)
        return out
    baum = {pfad: (typ, oid) for pfad, (typ, oid, _modus) in eintraege.items()}
    # NO ATTRIBUTE OF THE CLONE NAMES A DRIVER GIT WOULD RUN (owner decision OA-0a507fd998 A, after the external review of
    # d97f6e7b did not confirm the configuration families as complete). Judged for every committed file, with the
    # attributes as git itself resolves them (see `_git_attributes_select_a_driver`).
    treiber = _git_attributes_select_a_driver(repo, eintraege)
    if treiber:
        out["reason"] = (f"an attribute of the clone names a driver git would run for its files, or git's answer about "
                         f"the attributes is not complete ({treiber[0][:160]}{' …' if len(treiber) > 1 else ''}); the "
                         "attributes are read as git applies them (.gitattributes of the checkout, "
                         ".git/info/attributes, macros). "
                         "A fresh clone does not remove a driver selected by committed attributes.")
        return out
    # THE CODE THAT JUDGES MUST BE THE COMMITTED CODE (lens A, 2026-09-18, P0). HEAD equal to the commit says nothing
    # about the files on disk; an uncommitted edit to the receipt library or to the signature primitive flipped a
    # garbage receipt to VERIFIED with HEAD untouched. Every committed file under scripts/ and src/ is compared with
    # its blob here, and every untracked importable file or symlink there is refused -- from the bytes, not through
    # `git status`, which the ignore rules, the index bits and a configured filter all shape (deep gate run 7, P1, and
    # the owner's class decision). A modified or untracked file under scripts/ or src/ refuses the measurement with
    # exit 2: the honest answer is "your checkout is not that commit", not a verdict from code nobody pinned. The type
    # of every committed path there is compared first, so a directory replaced by a link to elsewhere refuses too
    # (external review of 65d8f8cd, F4).
    funde = _code_on_disk_that_is_not_the_commit(repo, eintraege)
    if funde:
        out["reason"] = (f"the checkout under {'/'.join(_CODE_PFADE)} is not the commit at {len(funde)} path(s) "
                         f"({funde[0][:120]}{' …' if len(funde) > 1 else ''}); the verifier and the library it calls "
                         "run from these files, so a modified or untracked checkout cannot judge the commit -- "
                         "`git stash` or clone afresh, then run again")
        return out

    lib = _lib()
    # The receipt binds `src/` through the tree digest, and `verify_receipt` imports
    # `proofbundle.signature` from it -- put THIS tree's src first, as the gate does.
    _bytecode_cache_elsewhere()
    src = str(repo.resolve() / "src")
    if src not in sys.path:
        sys.path.insert(0, src)

    # THE RECEIPT FOLDER, READ FROM THE COMMIT. The release gate judges every `*.json` under
    # `audit_artifacts/<token>/` (the file name is not fixed: the producer's default and the
    # owner-assembled receipts differ), and it sets aside the artefacts of this house that live
    # there without being receipts. Same rule here, with the same two lists, loaded from the gate
    # itself rather than typed a second time.
    ordner = f"audit_artifacts/{_version_token(version)}/"
    out["receipt_path"] = ordner
    out["receipt_read_from"] = f"git ls-tree/show {commit[:12]}:{ordner}"
    rc, listing, err = _git(repo, "ls-tree", "--full-tree", "-r", "--name-only", commit, "--",
                            f":(literal){ordner}")
    kandidaten = [ln for ln in listing.decode("utf-8", "replace").splitlines() if ln.endswith(".json")]
    if rc != 0 or not kandidaten:
        out["verdict"] = "NOT_VERIFIED"
        out["reason"] = (f"no receipt under {ordner} in commit {commit[:12]} -- this commit carries "
                         f"no pre-tag audit receipt for version {version} (a file in the working "
                         "tree does not count; only the committed tree is read)")
        return out

    # THE GATE SOURCE, THE ANCHOR AND THE RECEIPTS ARE THE BLOBS THEIR IDS NAME (review finding on
    # PR 249, 2026-09-27). They were read with `git show <commit>:<path>`, which returns whatever the
    # object store holds under the id; a rewritten gate object made the digest match a receipt that
    # binds another gate, and a rewritten receipt object stood in for the committed one. Each is read
    # here, on this file's code, and checked against its id; the anchor is checked here and parsed by
    # the library, whose own read checks it again.
    try:
        gate_blob = _datei(repo, baum, "scripts/pre_tag_audit_gate.py")
        _datei(repo, baum, "audit_artifacts/pre_tag_trusted_pubkeys.txt")
        blobs = {rel: _datei(repo, baum, rel) for rel in sorted(kandidaten)}
    except _NichtDasObjekt as exc:
        out["reason"] = _kein_objekt_grund(exc)
        return out
    if gate_blob is None:
        out["verdict"] = "NOT_VERIFIED"
        out["reason"] = ("commit carries no scripts/pre_tag_audit_gate.py -- the receipt binds the "
                         "digest of the gate that judged it, and there is none to compare against")
        return out
    out["gate_source_digest"] = hashlib.sha256(gate_blob).hexdigest()

    try:
        out["subject_tree_digest"] = lib.subject_tree_digest(repo)
    except Exception as exc:  # noqa: BLE001 -- the library raises a typed error; report, never crash
        out["reason"] = f"the tree digest could not be measured: {type(exc).__name__}: {exc}"
        return out

    trusted = lib.load_trusted_pubkeys(repo, ref=commit)
    out["trusted_pubkey_count"] = len(trusted)
    gate = _gate()
    verified: list[dict] = []
    rejected: list[dict] = []
    foreign: list[str] = []
    for rel, blob in blobs.items():
        if blob is None:
            rejected.append({"path": rel, "reason": "not readable from the commit: no blob at "
                                                    "that path in the commit's tree"})
            continue
        try:
            receipt = json.loads(blob.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            rejected.append({"path": rel, "reason": f"the committed receipt is not readable JSON "
                                                    f"({type(exc).__name__}: {exc})"})
            continue
        if not isinstance(receipt, dict):
            rejected.append({"path": rel, "reason": f"the committed receipt is not a JSON object "
                                                    f"(got {type(receipt).__name__})"})
            continue
        schema = receipt.get("schema")
        if (isinstance(schema, str) and schema in gate._FOREIGN_SCHEMAS
                and not any(f in receipt for f in gate._RECEIPT_SHAPED_FIELDS)):
            foreign.append(rel)                     # another artefact of this house, not a receipt
            continue
        try:
            ok, reason = lib.verify_receipt(receipt, trusted_pubkeys=trusted, expected_version=version,
                                            subject_tree_digest=out["subject_tree_digest"],
                                            gate_source_digest=out["gate_source_digest"])
        except Exception as exc:  # noqa: BLE001 -- fail closed with the reason, like the gate does
            ok, reason = False, f"verify_receipt raised {type(exc).__name__}: {exc} (fail-closed)"
        signer = receipt.get("signer_pubkey")
        eintrag = {"path": rel, "reason": reason,
                   "signer_pubkey": signer if isinstance(signer, str) else None}
        (verified if ok else rejected).append(eintrag)
    out["verified"] = verified
    out["rejected"] = rejected
    out["foreign_files"] = foreign
    if verified:
        out["verdict"] = "VERIFIED"
        out["receipt_path"] = verified[0]["path"]
        out["signer_pubkey"] = verified[0]["signer_pubkey"]
        out["reason"] = verified[0]["reason"]
        return out
    out["verdict"] = "NOT_VERIFIED"
    if rejected:
        out["receipt_path"] = rejected[0]["path"]
        out["signer_pubkey"] = rejected[0]["signer_pubkey"] if "signer_pubkey" in rejected[0] else None
        out["reason"] = "; ".join(f"{r['path']}: {r['reason']}" for r in rejected)
    else:
        out["reason"] = (f"no receipt under {ordner} in commit {commit[:12]} -- only "
                         f"{len(foreign)} foreign artefact(s) of this house lie there, none of them a "
                         "receipt (a file in the working tree does not count; only the committed "
                         "tree is read)")
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--repo", type=Path, default=Path("."), help="the clone (default: .)")
    p.add_argument("--commit", required=True, help="full 40-hex commit id named by the attestation")
    p.add_argument("--version", required=True, help="release version, e.g. 6.0.0")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    res = measure(a.repo.resolve(), a.commit, a.version)
    if a.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        print(f"[pre-tag-receipt] verdict={res['verdict']} commit={res['commit'][:12] if isinstance(res['commit'], str) else res['commit']} "
              f"version={res['version']} tree={(res['subject_tree_digest'] or '?')[:12]} "
              f"receipt={res['receipt_path'] or '-'} trusted_keys={res['trusted_pubkey_count']}")
        if res["reason"]:
            print(f"  {res['reason']}")
        print(f"  {LIMIT}")
    if res["verdict"] == "VERIFIED":
        return 0
    if res["verdict"] == "NOT_VERIFIED":
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
