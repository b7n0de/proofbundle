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
    reason). Never raises: bytes that do not parse, or that the canonicaliser refuses, are a reason, not an error."""
    try:
        wert = loads_strict(a_bytes)
    except (ProofBundleError, ValueError, UnicodeDecodeError, RecursionError):
        return None, "the approval record is not one JSON value"
    from . import canonical  # noqa: PLC0415 - the canonicaliser is a lazy import in every module
    try:
        eigen = canonical.canonicalize_statement(wert) == a_bytes
    except (canonical.CanonicalizerUnavailable, *canonical.NOT_CANONICALIZABLE):
        eigen = False
    if not eigen:
        return None, "the approval record is not its own RFC 8785 serialization"
    return wert, None
