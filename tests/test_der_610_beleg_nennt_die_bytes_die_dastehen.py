"""Every digest in the 610 evidence document is recomputed against the tree it sits in.

FOUND BY A REVIEW ROUND, 2026-09-20. The document named an exact carrier digest and, one line
below, the head that `git rev-parse` returned while the document was being WRITTEN. That head is
the one BEFORE the commit which introduces the bytes being described, so the line attributed an
exact integrity measurement to a revision that could not reproduce it: 16,562 bytes named against
a file that was 16,160 at that head.

THE CLASS, not the line: a provenance statement written by hand drifts from the bytes the moment
either side moves, and nothing notices, because a document is not executed. The repair is not a
corrected number, it is a case that recomputes every digest the document names. A number that is
checked on every run cannot go stale quietly.

HONEST LIMIT, stated rather than implied: this binds the digests to the files in the same tree. It
says nothing about whether those files are the right ones, and it cannot detect a document and a
tree that were changed together.
"""
from __future__ import annotations

import hashlib
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
BELEG = REPO / "audit_artifacts" / "610" / "README.md"

#: A line naming a path and its digest, in the two shapes the document uses.
_ANGABE = re.compile(r"^\s*(\S+\.(?:json|md))\s+sha256\s+([0-9a-f]{64})\b", re.M)


def _angaben() -> list[tuple[str, str]]:
    if not BELEG.is_file():
        pytest.skip(f"NOT MEASURABLE: {BELEG} is missing")
    return _ANGABE.findall(BELEG.read_text(encoding="utf-8"))


def test_der_beleg_nennt_ueberhaupt_digests():
    """[ZAEHLT] An empty match list would make every case below pass without measuring."""
    assert len(_angaben()) >= 4, (
        f"the document names {len(_angaben())} digests; the cases below would then be green "
        f"without having looked at anything")


def test_jeder_genannte_digest_stimmt_mit_der_datei_im_baum():
    """[ZAEHLT] The finding itself, recomputed rather than believed."""
    offen = []
    for pfad, genannt in _angaben():
        p = REPO / pfad
        if not p.is_file():
            offen.append(f"{pfad}: named in the document, absent from the tree")
            continue
        ist = hashlib.sha256(p.read_bytes()).hexdigest()
        if ist != genannt:
            offen.append(f"{pfad}: document says {genannt[:12]}…, the file is {ist[:12]}…")
    assert not offen, f"{len(offen)} digest(s) do not describe the file they name: {offen}"


def test_der_beleg_nennt_keinen_commit_als_messpunkt():
    """[ZAEHLT] The exact shape of the finding, held open so it cannot come back.

    A forty character hex string in this document would be a commit, and a commit named here is
    either the one that introduces the document, which it cannot know, or an earlier one, which
    cannot reproduce its bytes. Digests of forty characters do not exist, so the pattern is
    unambiguous.
    """
    if not BELEG.is_file():
        pytest.skip(f"NOT MEASURABLE: {BELEG} is missing")
    text = BELEG.read_text(encoding="utf-8")
    treffer = re.findall(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", text)
    assert not treffer, (
        f"the document names {len(treffer)} commit-shaped identifier(s): {treffer[:3]}. A head "
        f"named here is either unknowable or wrong about the bytes described")
