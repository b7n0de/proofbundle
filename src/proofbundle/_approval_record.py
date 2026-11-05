"""The approval record of Case 1 of Section 3.3 of draft-gruszka-audit-decision-receipts-07 (finding B3).

The relying party supplies the approval record bytes A; the decision receipt binds them by the digest of its one
inputSnapshot entry named "approval record". A is read here strictly (one JSON value, no duplicate member name) and
taken only when the bytes are their own RFC 8785 serialization. A is no in-toto Statement, so it is not read through
the statement oracle (``_statement_payload.load_statement_strict``); decision.py, which verifies Statements and reads
them only through that oracle, takes the record from here.
"""
from __future__ import annotations

from typing import Any

from ._strict_json import loads_strict
from .errors import ProofBundleError


def read_approval_record(a_bytes: bytes) -> "tuple[Any, str | None]":
    """(the parsed record, None) when ``a_bytes`` are one JSON value in their own RFC 8785 form, else (None, the
    reason). Never raises: a value that is no bytes, bytes that do not parse, or that the canonicaliser refuses, are a
    reason, not an error. The bytes are read once, by what they store (`canonical._bytes_von`)."""
    from .canonical import _bytes_von  # noqa: PLC0415
    roh = _bytes_von(a_bytes)
    if roh is None:
        return None, "the approval record is not bytes"
    try:
        wert = loads_strict(roh)
    except (ProofBundleError, ValueError, UnicodeDecodeError, RecursionError):
        return None, "the approval record is not one JSON value"
    from . import canonical  # noqa: PLC0415 - the canonicaliser is a lazy import in every module
    # Two clauses, as decision._rfc8785_bytes has them: mypy 2.3.0 reads a starred tuple inside the except tuple as no
    # exception type (measured on this branch, "Exception type must be derived from BaseException").
    try:
        eigen = canonical.canonicalize_statement(wert) == roh
    except canonical.CanonicalizerUnavailable:
        eigen = False
    except canonical.NOT_CANONICALIZABLE:
        eigen = False
    if not eigen:
        return None, "the approval record is not its own RFC 8785 serialization"
    return wert, None


def approval_identity(record: Any) -> "tuple[str, str, str] | None":
    """The identity of an approval (Section 4 item 2): (approvalId, actionDigest.sha256, session), or None when the
    record does not carry them as non-empty strings and a digest object. Copies with other metadata share it."""
    if not isinstance(record, dict):
        return None
    aid, ses, dig = record.get("approvalId"), record.get("session"), record.get("actionDigest")
    sha = dig.get("sha256") if isinstance(dig, dict) and set(dig) == {"sha256"} else None
    if not (isinstance(aid, str) and aid and isinstance(ses, str) and ses and isinstance(sha, str) and sha):
        return None
    return aid, sha, ses


def read_consumption_state(state_bytes: bytes) -> "tuple[dict | None, str | None]":
    """The consumed identities by generation, or (None, the reason the state is no complete view, item 5). The state
    is a JSON array of identities (the generation "current") or an object of generations, each an array of
    identities. Every entry must be an identity; one that is not makes the whole state unreadable, never skipped."""
    try:
        wert = loads_strict(state_bytes)
    except (ProofBundleError, ValueError, UnicodeDecodeError, RecursionError):
        return None, "the consumption state does not parse, so it is not a complete view (Section 4 item 5)"
    generationen = {"current": wert} if isinstance(wert, list) else wert
    if not isinstance(generationen, dict):
        return None, "the consumption state is neither an array of identities nor an object of generations (item 5)"
    gelesen: dict = {}
    for name, eintraege in generationen.items():
        if not isinstance(eintraege, list):
            return None, f"generation {name!r} of the consumption state is not an array (item 5)"
        kennungen = set()
        for eintrag in eintraege:
            kennung = approval_identity(eintrag)
            if kennung is None:
                return None, f"generation {name!r} holds an entry that is no approval identity (item 5)"
            kennungen.add(kennung)
        gelesen[name] = kennungen
    return gelesen, None


def read_received_copies(copies_bytes: bytes) -> "tuple[list | None, str | None]":
    """The received approval record copies as a list of objects, or (None, the reason)."""
    try:
        wert = loads_strict(copies_bytes)
    except (ProofBundleError, ValueError, UnicodeDecodeError, RecursionError):
        return None, "the received copies do not parse (Section 4 item 2)"
    if not (isinstance(wert, list) and all(isinstance(x, dict) for x in wert)):
        return None, "the received copies are not an array of approval records (Section 4 item 2)"
    return wert, None
