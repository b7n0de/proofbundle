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
    python scripts/verify_pre_tag_receipt.py --commit <that commit> --version X.Y.Z

THE EVIDENCE IS READ FROM THE COMMIT; THE CODE RUNS FROM THE CHECKOUT, SO THE CHECKOUT MUST BE
THE COMMIT. The receipt, the trust anchor and the gate source whose digest the receipt binds are
read with ``git show <commit>:<path>``, so a file placed into a dirty checkout cannot stand in for
a committed one. The verifier code -- this script, ``pre_tag_receipt_lib.py``, the package under
``src/`` whose ed25519 primitive it calls -- is NOT read from the commit: Python runs what lies on
disk. An adversarial lens measured on 2026-09-18 what that means when nothing checks the two
against each other: one uncommitted edit to ``verify_receipt`` or to ``proofbundle.signature``,
HEAD untouched, and a commit with a garbage receipt reported VERIFIED. So two things are refused
with exit 2, never silently measured: a checkout at any head other than the named commit, and a
checkout that carries local modifications or untracked files under ``scripts/`` or ``src/``. The
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
2 not measurable (no git, malformed commit id, checkout not at the named commit).
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

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


def _git(repo: Path, *args: str) -> tuple[int, bytes, str]:
    try:
        r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, b"", f"{type(exc).__name__}: {exc}"
    return r.returncode, r.stdout, r.stderr.decode("utf-8", "replace").strip()


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
    rc, head, err = _git(repo, "rev-parse", "--verify", "HEAD")
    if rc != 0:
        out["reason"] = f"not a git checkout, or no HEAD: {err or 'git rev-parse failed'}"
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
    # THE CODE THAT JUDGES MUST BE THE COMMITTED CODE (lens A, 2026-09-18, P0). HEAD equal to the
    # commit says nothing about the files on disk; an uncommitted edit to the receipt library or
    # to the signature primitive flipped a garbage receipt to VERIFIED with HEAD untouched. A
    # modified or untracked file under scripts/ or src/ therefore refuses the measurement -- the
    # honest answer is "your checkout is not that commit", not a verdict from code nobody pinned.
    rc, schmutz, err = _git(repo, "status", "--porcelain", "--untracked-files=all", "--", *_CODE_PFADE)
    if rc != 0:
        out["reason"] = f"the working tree could not be inspected: {err or 'git status failed'}"
        return out
    zeilen = [ln for ln in schmutz.decode("utf-8", "replace").splitlines() if ln.strip()]
    if zeilen:
        out["reason"] = (f"the checkout carries {len(zeilen)} local modification(s) or untracked file(s) under "
                         f"{'/'.join(_CODE_PFADE)} ({zeilen[0].strip()[:80]}{' …' if len(zeilen) > 1 else ''}); "
                         "the verifier and the library it calls run from these files, so a modified "
                         "checkout cannot judge the commit -- `git stash` or clone afresh, then run again")
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
    # READ WITH -z (2026-09-26, measured in a throwaway repository). Without it git quotes a name
    # that holds a byte outside ASCII, the quoted line ends in `.json"` rather than `.json`, and a
    # receipt the release gate reads from disk was not a candidate here at all.
    rc, listing, err = _git(repo, "ls-tree", "-r", "--name-only", "-z", commit, "--", ordner)
    kandidaten = [n for n in (os.fsdecode(b) for b in listing.split(b"\0") if b) if n.endswith(".json")]
    if rc != 0 or not kandidaten:
        out["verdict"] = "NOT_VERIFIED"
        out["reason"] = (f"no receipt under {ordner} in commit {commit[:12]} -- this commit carries "
                         f"no pre-tag audit receipt for version {version} (a file in the working "
                         "tree does not count; only the committed tree is read)")
        return out

    rc, gate_blob, err = _git(repo, "show", f"{commit}:scripts/pre_tag_audit_gate.py")
    if rc != 0:
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
    for rel in sorted(kandidaten):
        rc, blob, err = _git(repo, "show", f"{commit}:{rel}")
        if rc != 0:
            rejected.append({"path": rel, "reason": f"not readable from the commit: {err}"})
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
    # A path is read as git names it (-z, os.fsdecode), so a name that is not UTF-8 carries
    # surrogates, and a strict stdout raised on one with exit 1, the exit code of a finding
    # (measured 2026-09-26 on all four path readers). Backslash escapes instead: in JSON they are
    # the escape of the same code point, so the name reads back as it was.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
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
