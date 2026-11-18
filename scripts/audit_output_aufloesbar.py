#!/usr/bin/env python3
"""Does a pre-tag receipt's SIGNED ``audit_output_digest`` resolve to a findable artifact?

═══ THE MEASURED OCCASION (2026-08-31, owner instruction) ═══

The v5.0.0 receipt (``audit_artifacts/500/pre_tag_receipt_v5.0.0.json``) is valid: it binds the
tag tree, it is signed by the pinned key, and ``pre_tag_audit_gate`` returns ok against that tree.
Its ``audit_output_digest`` is ``460fcdf3…`` — and **0 of 915 tracked files carry that digest**.
The ``audit_command`` even names a record, ``audit_artifacts/500/DEEP_RUN_RECORD_500_ITER8_
CEREMONY.md``; that file exists, is tracked, was committed 57 minutes BEFORE signing and has not
changed since — but its digest is ``4ca5d2a5…``. So the prose points at one artifact and the
signed digest covers another: the digest was taken over something transient that was never
committed.

C12.1 already records this as an HONEST LIMIT — *"the field is signed, which makes it
tamper-evident and attributable, not checkable"*. This module makes it checkable.

WHAT THIS DELIBERATELY DOES NOT DO: it does not move any gate verdict. Wiring resolvability into
``pre_tag_audit_gate.evaluate`` would retroactively fail v5.0.0, whose receipt is otherwise sound
and already published. A rule that changes the past is not a rule, it is a rewrite. This reports;
the release procedure consumes the report before the payload goes to the key holder.

THREE STATES, never two:
    AUFLOESBAR         a tracked file's digest equals the signed one — the file is named
    NICHT_AUFLOESBAR   every tracked file was hashed and none matched; the count is reported so
                       the negative is a measurement, not an impression
    NICHT_MESSBAR      the receipt is missing/unreadable, the field is absent, or git could not
                       list the tree. Explicitly NOT a pass and explicitly NOT a failure

HOW THE DIGEST IS COMPUTED, and it matters: the receipt builds it as
``sha256_text(file.read_text(encoding="utf-8", errors="ignore"))`` — over the DECODED TEXT, not
the raw bytes. For clean UTF-8 the two coincide; for a file with one invalid byte they do not,
because ``errors="ignore"`` drops it. A checker using ``sha256sum`` would report NICHT_AUFLOESBAR
for a file that legitimately matches. This module computes it exactly the way the receipt does.

    python3 scripts/audit_output_aufloesbar.py --receipt <pfad> [--repo .] [--json]

═══ THE RELEASE STEP (lesson 2 of 18 November 2026, from 6.6.1 on) ═══

An outside reader asked for the audit output of 6.6.0 and could not find it: the receipt was valid,
the digest pointed at no tracked file, and the output reached the tree only afterwards, through pull
request 538. Since 6.6.1 every digest of the signed receipt must resolve at the commit that is
tagged. Two of the three already do by construction, because `pre_tag_audit_gate.py --strict`
recomputes `subject_tree_digest` and `gate_source_digest` from the checked-out tree and refuses a
receipt that does not bind them. The third is this module's question, asked for the release:

    python3 scripts/audit_output_aufloesbar.py --version X.Y.Z [--repo .] [--json]

It asks the gate which receipts verify for this tree and version, and requires that the
`audit_output_digest` of each of them is the SHA-256 of the RAW BYTES of a regular file that the head
commit carries, read from the commit's objects and never from the working tree. Raw bytes,
not the decoded text: the producer hashes the bytes it captured (`pre_tag_receipt._audit_ausfuehren`,
"recomputable by anyone who holds the record, with sha256sum"), and a reader outside does the same.
The text reading above stays for `--receipt`, where older receipts were built over the decoded text.
A gate that verifies no receipt is NICHT_MESSBAR here: this step answers only for receipts the gate
accepted, and the gate's own step has already failed the release in that case.

Exit: 0 AUFLOESBAR · 1 NICHT_AUFLOESBAR · 2 NICHT_MESSBAR
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pre_tag_receipt_lib import (  # noqa: E402
    BaumNichtLesbar,
    git_file,
    git_objects,
    git_tree,
    sha256_text,
)

SCHEMA = "b7n0de.audit_output_aufloesbar.v1"

#: The modes of a regular file in a tree. A symbolic link (120000) carries its target's NAME as its
#: content, and a gitlink (160000) carries no content in this repository at all.
_REGULAER = ("100644", "100755")


def _verfolgte_blobs(repo: Path) -> list[tuple[str, bytes]] | None:
    """(path, content) of every regular file the HEAD COMMIT carries, sorted by path, or None if git
    cannot answer — None is the NICHT_MESSBAR signal, not [].

    The distinction is the whole point: an empty list would read as 'searched everything, found
    nothing', which is a verdict. A broken git has no verdict to give.

    READ FROM THE COMMIT, NOT FROM THE WORKING TREE (Codex on pull request 541, P2, 2026-11-18). The
    question is whether a digest resolves at the commit that is tagged. This listed the tracked paths
    and then read each from disk, and `Path.is_file()` follows a symbolic link: a committed link to an
    untracked record outside the tree passed as AUFLOESBAR, and deleting only that record changed the
    answer without changing the commit. A tracked file modified on disk and a file that is only staged
    are the same mismatch. Every blob is now read through `git_tree` and `git_objects` of the receipt
    library, each object checked against its id, and only regular files count.

    NAMES AS GIT STORES THEM (2026-09-26, measured in a throwaway repository). The path is the raw
    bytes of the tree entry, decoded the way Python decodes a file name (`os.fsdecode`); a quoted
    display form opens no file, and a record under such a name was once skipped without being
    counted."""
    try:
        _commit, eintraege = git_tree(repo, "HEAD")
        dateien = sorted((pfad, oid) for mode, typ, oid, pfad in eintraege
                         if typ == "blob" and mode in _REGULAER)
        inhalte = git_objects(repo, [(oid, "blob") for _pfad, oid in dateien])
    except (BaumNichtLesbar, OSError):
        return None
    return [(os.fsdecode(pfad), inhalte[oid]) for pfad, oid in dateien]


def _digest_wie_das_receipt(inhalt: bytes) -> str:
    """Exactly the older receipts' computation: the text as `Path.read_text(encoding="utf-8",
    errors="ignore")` returns it, which also turns `\\r\\n` and `\\r` into `\\n`."""
    return sha256_text(io.TextIOWrapper(io.BytesIO(inhalt), encoding="utf-8", errors="ignore").read())


def _digest_der_bytes(inhalt: bytes) -> str:
    """SHA-256 of the raw bytes, as the producer and `sha256sum` compute it."""
    return hashlib.sha256(inhalt).hexdigest()


def aufloesbar(receipt: dict, repo: Path, *, roh: bool = False) -> dict:
    """-> {zustand, digest, treffer, geprueft, grund}. Reports; never raises on a bad receipt.

    `roh=True` compares the SHA-256 of the raw bytes (the release step), otherwise the receipt's
    older reading over the decoded text."""
    rechne = _digest_der_bytes if roh else _digest_wie_das_receipt
    aus: dict = {"schema": SCHEMA, "repo": str(repo), "rechnung": "bytes" if roh else "text"}
    digest = (receipt or {}).get("audit_output_digest")
    if not isinstance(digest, str) or not digest.strip():
        aus.update(zustand="NICHT_MESSBAR", digest=None, treffer=[], geprueft=0,
                   grund="das Receipt fuehrt kein audit_output_digest")
        return aus
    digest = digest.strip().lower()
    aus["digest"] = digest
    dateien = _verfolgte_blobs(repo)
    if dateien is None:
        aus.update(zustand="NICHT_MESSBAR", treffer=[], geprueft=0,
                   grund=f"git could not read the tree of the head commit: {repo}")
        return aus
    treffer = [rel for rel, inhalt in dateien if rechne(inhalt) == digest]
    geprueft = len(dateien)
    aus["geprueft"] = geprueft
    aus["treffer"] = treffer
    if treffer:
        aus.update(zustand="AUFLOESBAR",
                   grund=f"der signierte Digest liegt als verfolgtes Artefakt vor: {', '.join(treffer)}")
    else:
        aus.update(zustand="NICHT_AUFLOESBAR",
                   grund=(f"{geprueft} verfolgte Datei(en) gehasht, keine traegt {digest[:12]}… — "
                          f"der signierte Digest ist attribuierbar, aber nicht nachrechenbar"))
    return aus


def _gate():
    """`pre_tag_audit_gate`, loaded BY PATH from this file's directory, as the gate loads its own
    library: a plain import would take whatever the judged tree puts first on `sys.path`."""
    import importlib.util as _ilu  # noqa: PLC0415
    pfad = Path(__file__).resolve().parent / "pre_tag_audit_gate.py"
    spec = _ilu.spec_from_file_location("_pre_tag_audit_gate_for_aufloesbar", pfad)
    if spec is None or spec.loader is None:
        raise ImportError(f"no loader for {pfad}")
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def fuer_version(repo: Path, version: str, *, gate=None) -> dict:
    """-> {zustand, version, gate_state, quittungen, grund}: the release step. Every receipt the gate
    verifies for `repo` and `version` must name, in `audit_output_digest`, the raw bytes of a tracked
    file. `gate` is the gate module (its `evaluate` and its `_lib`); tests hand in their own."""
    aus: dict = {"schema": SCHEMA, "repo": str(repo), "version": version, "rechnung": "bytes",
                 "gate_state": None, "quittungen": []}
    try:
        gate = gate or _gate()
        urteil = gate.evaluate(repo, version)
    except Exception as e:  # noqa: BLE001 — a gate that cannot rule gives no receipt to resolve
        aus.update(zustand="NICHT_MESSBAR",
                   grund=f"das Tor konnte nicht urteilen: {type(e).__name__}: {e}")
        return aus
    aus["gate_state"] = urteil.get("state") if isinstance(urteil, dict) else None
    verifiziert = urteil.get("verified_receipts") if isinstance(urteil, dict) else None
    if not (isinstance(urteil, dict) and urteil.get("ok") is True) or not verifiziert:
        aus.update(zustand="NICHT_MESSBAR",
                   grund=(f"das Tor verifiziert fuer {version} keine Quittung dieses Baums "
                          f"(state={aus['gate_state']!r}); ohne verifizierte Quittung gibt es keinen "
                          "signierten Digest, der auf ein Artefakt zeigen muesste"))
        return aus
    for eintrag in verifiziert:
        rel = eintrag.get("path") if isinstance(eintrag, dict) else None
        # THE RECEIPT TOO IS READ FROM THE COMMIT (the neighbour of the P2 above): the gate judged the
        # file on disk, and this step answers for the commit. A receipt that is not a regular file of
        # the commit, or whose bytes on disk are not the committed ones, leaves nothing to resolve.
        try:
            im_commit = git_file(repo, "HEAD", rel)
            if im_commit is None or im_commit[1] != "blob" or im_commit[0] not in _REGULAER:
                raise ValueError("the receipt is not a regular file of the head commit")
            if (repo / rel).read_bytes() != im_commit[3]:
                raise ValueError("the receipt the gate judged on disk is not the one the head commit carries")
            receipt = gate._lib().receipt_json(im_commit[3])
        except Exception as e:  # noqa: BLE001
            aus["quittungen"].append({"pfad": rel, "zustand": "NICHT_MESSBAR", "treffer": [],
                                      "grund": f"Quittung nicht lesbar: {type(e).__name__}: {e}"})
            continue
        r = aufloesbar(receipt, repo, roh=True)
        aus["quittungen"].append({"pfad": rel, "zustand": r["zustand"], "digest": r.get("digest"),
                                  "treffer": r.get("treffer", []), "geprueft": r.get("geprueft", 0),
                                  "grund": r.get("grund")})
    zustaende = [q["zustand"] for q in aus["quittungen"]]
    # A definite finding outranks an unmeasured one: one receipt whose digest names no tracked file
    # is a reason to stop, whatever else lies beside it.
    if "NICHT_AUFLOESBAR" in zustaende:
        aus["zustand"] = "NICHT_AUFLOESBAR"
    elif "NICHT_MESSBAR" in zustaende:
        aus["zustand"] = "NICHT_MESSBAR"
    else:
        aus["zustand"] = "AUFLOESBAR"
    aus["grund"] = "; ".join(f"{q['pfad']}: {q['zustand']} — {q['grund']}" for q in aus["quittungen"])
    return aus


def main(argv: list[str] | None = None) -> int:
    # A path is read as git names it (-z, os.fsdecode), so a name that is not UTF-8 carries
    # surrogates, and a strict stdout raised on one with exit 1, the exit code of a finding
    # (measured 2026-09-26 on all four path readers). Backslash escapes instead. The JSON form writes
    # every character outside ASCII as its JSON escape (`ensure_ascii`), because a backslash escape of
    # `ü` or of an emoji is no JSON escape, and under an output encoding that is not UTF-8 the output
    # was no JSON, with exit 0 (counter-reading of pull request 375, F5).
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    wahl = ap.add_mutually_exclusive_group(required=True)
    wahl.add_argument("--receipt", type=Path)
    wahl.add_argument("--version", help="the release step: every receipt the gate verifies for this version")
    ap.add_argument("--repo", type=Path, default=Path("."))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.version is not None:
        r = fuer_version(a.repo.resolve(), a.version)
        if a.json:
            print(json.dumps(r, indent=2, ensure_ascii=True))
        else:
            print(f"audit_output_digest {a.version}: {r['zustand']} — {r['grund']}")
        return {"AUFLOESBAR": 0, "NICHT_AUFLOESBAR": 1}.get(r["zustand"], 2)
    try:
        rc = json.loads(a.receipt.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        r = {"schema": SCHEMA, "zustand": "NICHT_MESSBAR", "digest": None, "treffer": [],
             "geprueft": 0, "grund": f"Receipt nicht lesbar: {type(e).__name__}: {e}"}
    else:
        r = aufloesbar(rc, a.repo.resolve())
    if a.json:
        print(json.dumps(r, indent=2, ensure_ascii=True))
    else:
        print(f"audit_output_digest: {r['zustand']} — {r['grund']}")
    return {"AUFLOESBAR": 0, "NICHT_AUFLOESBAR": 1}.get(r["zustand"], 2)


if __name__ == "__main__":
    sys.exit(main())
