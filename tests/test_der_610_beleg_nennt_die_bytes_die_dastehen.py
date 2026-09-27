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
import subprocess

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


#: A run of lowercase hex that could be an abbreviated object name. The lookarounds keep a 64
#: character sha256 digest out, because that is ONE token rather than a prefix plus a tail.
_HEXWORT = re.compile(r"(?<![0-9a-zA-Z])[0-9a-f]{7,40}(?![0-9a-zA-Z])")


def _ist_bekanntes_objekt(token: str) -> bool | None:
    """Does git resolve this token here? None when the question cannot be asked at all."""
    try:
        r = subprocess.run(
            ["git", "-C", str(REPO), "rev-parse", "--verify", "--quiet", token + "^{commit}"],
            capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.returncode == 0


def test_KONTROLLE_die_erkennung_erkennt_den_eigenen_kopf():
    """[ZAEHLT] A detector that recognises nothing makes the case below green for free."""
    try:
        kopf = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("NOT MEASURABLE: git cannot be run here")
    if kopf.returncode != 0 or not kopf.stdout.strip():
        pytest.skip("NOT MEASURABLE: this tree has no readable head")
    assert _ist_bekanntes_objekt(kopf.stdout.strip()) is True, (
        "the detector does not recognise this tree's own head, so the case below measures nothing")


def test_der_beleg_nennt_keinen_kopf_als_messpunkt():
    """[ZAEHLT] Measured by ASKING GIT, not by counting characters.

    THE FIRST VERSION MATCHED A LENGTH, and a review round measured what that is worth: the
    abbreviations `050e477` and `050e4777a5ef` both slipped past a forty character pattern, so
    putting the old provenance line back into the document left all three cases passing while the
    document again named a revision that cannot reproduce its bytes. An exact length standing in
    for the property `git knows this object` is the same substitution this pull request is about,
    and it caught me a fourth time, here, inside the repair for the third.

    Every hex-shaped token is handed to git instead. A revision named in this document is either
    the one that introduces it, which it cannot know while being written, or an earlier one, which
    cannot reproduce its bytes. Both are wrong, so neither is allowed.
    """
    if not BELEG.is_file():
        pytest.skip(f"NOT MEASURABLE: {BELEG} is missing")
    text = BELEG.read_text(encoding="utf-8")
    treffer, unmessbar = [], 0
    for token in sorted(set(_HEXWORT.findall(text))):
        urteil = _ist_bekanntes_objekt(token)
        if urteil is None:
            unmessbar += 1
        elif urteil:
            treffer.append(token)
    if unmessbar:
        pytest.skip(f"NOT MEASURABLE: git could not be asked about {unmessbar} token(s)")
    assert not treffer, (
        f"the document names {len(treffer)} identifier(s) that git resolves here: {treffer[:3]}. "
        f"A revision named in this document is either unknowable while it is written or wrong "
        f"about the bytes it describes")
