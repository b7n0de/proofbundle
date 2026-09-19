"""PLANTED DEFECT CORPUS — never merged, never shipped. Branch pruefung/gepflanzte-defekte-20260919.

WHY THIS FILE EXISTS. The order QITEM-PROOFBUNDLE-PRUEFWEG-REVIEW-PROZEDERE-MESSEN-01, section B,
asks a question no inventory answers: not whether each review instance RUNS, but whether it CATCHES.
Six defects are planted below, each from a different class, each with the exact shape it had when it
was real. Three of them (D1, D2, D3) were genuine findings on 2026-09-13 and are therefore proven
classes, not invented ones.

HOW TO READ A RESULT. An instance that finds none of these is not a guard. An instance that reports
findings on the clean counter-probe is not a guard either — it is noise with a green badge. Both
failures cost the same and only one of them looks like failure.

NOTHING HERE IS IMPORTED BY PRODUCTION CODE.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# D1 — an unsigned carrier is written before the return (real finding 2026-09-13)
# ---------------------------------------------------------------------------


def schreibe_beleg(ziel: Path, nutzlast: dict, signierer=None) -> Path:
    """Write a receipt and sign it.

    DEFECT D1: the file is written and the path returned BEFORE signing. Every caller that trusts
    the returned path sees a carrier that exists and is unsigned. If signing raises, the unsigned
    file stays on disk and the exception hides that a carrier was already published.
    """
    ziel.write_text(json.dumps(nutzlast, sort_keys=True), encoding="utf-8")
    if signierer is not None:
        signierer(ziel)
    return ziel


# ---------------------------------------------------------------------------
# D2 — a source is not bound to the signed artifact (real finding 2026-09-13)
# ---------------------------------------------------------------------------


def pruefe_quelle(quelle: Path, manifest: dict) -> bool:
    """Check that a source belongs to the signed artifact.

    DEFECT D2: the binding is checked by NAME. Two different files with the same basename satisfy
    it, and the digest in the manifest is never compared against the bytes on disk. The signature
    covers the manifest, the manifest names the file, and nothing connects the file to either.
    """
    return quelle.name in manifest.get("sources", [])


# ---------------------------------------------------------------------------
# D3 — a test compares the working tree with itself (real finding 2026-09-13)
# ---------------------------------------------------------------------------


def baum_unveraendert(wurzel: Path) -> bool:
    """Assert the tree did not change during a run.

    DEFECT D3: both sides are read from the SAME tree at the SAME moment, so the comparison is
    `x == x` and cannot fail. It looks like a tamper check and is a tautology; a run that rewrote
    every file under `wurzel` still passes.
    """
    vorher = {p.name: p.stat().st_size for p in wurzel.rglob("*") if p.is_file()}
    nachher = {p.name: p.stat().st_size for p in wurzel.rglob("*") if p.is_file()}
    return vorher == nachher


# ---------------------------------------------------------------------------
# D4 — a regex without anchors
# ---------------------------------------------------------------------------

_KENNUNG = re.compile(r"[A-Z]-\d+")


def ist_kennung(s: str) -> bool:
    """Is this string an identifier of the form A-1?

    DEFECT D4: `search` without anchors. "NOT-A-KENNUNG-X-9-TRAILING" matches, and so does any
    sentence that happens to contain a capital letter, a hyphen and a digit. The function reports
    membership in a set far larger than the one it names.
    """
    return bool(_KENNUNG.search(s))


# ---------------------------------------------------------------------------
# D5 — a timezone assumption
# ---------------------------------------------------------------------------


def ist_abgelaufen(frist_iso: str) -> bool:
    """Has this deadline passed?

    DEFECT D5: `datetime.now()` is LOCAL time, the deadline is parsed as naive, and the comparison
    silently treats both as the same zone. On this machine (UTC+2 in summer) every deadline is
    judged two hours early, and the direction of the error flips with the season.
    """
    frist = datetime.fromisoformat(frist_iso.replace("Z", ""))
    return datetime.now() > frist


# ---------------------------------------------------------------------------
# D6 — a silent escape in an error path
# ---------------------------------------------------------------------------


def digest_oder_leer(pfad: Path) -> str:
    """Return the sha256 of a file.

    DEFECT D6: the error path returns "" instead of raising. A caller comparing digests sees two
    empty strings as equal, so an unreadable file and a second unreadable file "match". The escape
    is invisible in a green run because nothing distinguishes "" from a real answer.
    """
    try:
        return hashlib.sha256(pfad.read_bytes()).hexdigest()
    except Exception:
        return ""
