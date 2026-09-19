"""CLEAN COUNTER-PROBE — the same six jobs, done right. Never merged, never shipped.

WHY A CLEAN FILE IS PART OF THE MEASUREMENT. Section B of
QITEM-PROOFBUNDLE-PRUEFWEG-REVIEW-PROZEDERE-MESSEN-01 asks for both directions, and the second one
is the one that usually goes unasked: an instance that reports findings everywhere is as useless as
one that reports none, and it is harder to notice because its output looks like diligence. A review
instance that raises findings against THIS file is producing noise, not signal.

Same signatures and same names as the planted corpus, so the only difference between the two files
is whether the work is done correctly.

NOTHING HERE IS IMPORTED BY PRODUCTION CODE.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path


def schreibe_beleg(ziel: Path, nutzlast: dict, signierer) -> Path:
    """Write a receipt and sign it — and publish nothing that is not signed.

    The carrier is built beside the target and moved into place only after signing succeeded, so a
    failing signer leaves no unsigned file where a caller would look for one.

    THE SIGNER HAS NO DEFAULT, and that is the fix for the counter-probe's first finding: the first
    version kept `signierer=None` from the planted corpus, so a caller who simply omitted the
    argument published an unsigned artifact while the docstring promised the opposite. A promise
    that an optional argument can switch off is not an invariant.
    """
    if signierer is None:
        raise ValueError("kein Signierer — ein unsignierter Beleg wird nicht veroeffentlicht")
    entwurf = ziel.with_suffix(ziel.suffix + ".unsigniert")
    entwurf.write_text(json.dumps(nutzlast, sort_keys=True), encoding="utf-8")
    try:
        if signierer is not None:
            signierer(entwurf)
    except BaseException:
        entwurf.unlink(missing_ok=True)
        raise
    entwurf.replace(ziel)
    return ziel


def pruefe_quelle(quelle: Path, manifest: dict) -> bool:
    """Check that a source belongs to the signed artifact — by content, not by name.

    The manifest carries a digest per source; the bytes on disk are hashed and compared. A file
    that merely shares a basename does not satisfy it.
    """
    erwartet = (manifest.get("sources") or {}).get(quelle.name)
    if not erwartet:
        return False
    return hashlib.sha256(quelle.read_bytes()).hexdigest() == erwartet


def baumzustand(wurzel: Path) -> dict[str, str]:
    """The state a change would have to preserve: one digest per path, relative to the root."""
    return {
        str(p.relative_to(wurzel)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in wurzel.rglob("*")
        if p.is_file()
    }


def baum_unveraendert(wurzel: Path, vorzustand: dict[str, str]) -> bool:
    """Assert the tree did not change — against a state captured EARLIER, passed in by the caller.

    The earlier state is an argument, so the comparison has two independent sides and can fail.
    Paths are relative to the root, because two files in different directories may share a name.

    THE STATE IS A DIGEST PER PATH, NOT A SIZE, and that is the fix for the counter-probe's second
    finding: the first version compared `st_size`, which the planted corpus also did, so a change
    that keeps the length — "hello" to "world", or any same-length substitution — passed as
    unchanged. A tamper check whose quantity a tamperer can hold constant is not one.
    """
    return baumzustand(wurzel) == vorzustand


_KENNUNG = re.compile(r"\A[A-Z]-\d+\Z")


def ist_kennung(s: str) -> bool:
    """Is this string an identifier of the form A-1? Anchored, so the whole string must match."""
    return bool(_KENNUNG.match(s))


def ist_abgelaufen(frist_iso: str) -> bool:
    """Has this deadline passed? Both sides are aware of their zone.

    A deadline without an offset is read as UTC, which is what the house writes, and `now` is taken
    in UTC as well — so the answer does not change with the season or the machine.
    """
    roh = frist_iso.replace("Z", "+00:00")
    frist = datetime.fromisoformat(roh)
    if frist.tzinfo is None:
        frist = frist.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) > frist


def digest_oder_leer(pfad: Path) -> str:
    """Return the sha256 of a file, or raise.

    The name is kept for comparability with the planted corpus; the behaviour is not. An unreadable
    file is an error, not an empty answer, because two empty answers compare equal.
    """
    return hashlib.sha256(pfad.read_bytes()).hexdigest()
