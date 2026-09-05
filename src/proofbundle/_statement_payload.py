"""ONE oracle for "is this DSSE payload a well-formed in-toto Statement object" — shared by the standalone
verify paths AND the ``--with-related`` resolver (deep gate 2026-09-05, finding L4-01, P1).

THE CLASS: a parser-differential at the RESOLVER seam. ``cli._load_related`` verified an attached target's
signature, then parsed its payload leniently — a ``loads_strict`` failure (duplicate JSON key, NaN, BOM,
a non-object) was swallowed into ``relationships=None`` + ``subject_digest_state="absent"`` while the entry
kept ``verified=True``. The chain walk then saw a verified, edge-less ancestor and stopped honestly at the
horizon: a target whose payload carried an edge to a FAILING ancestor behind a duplicate ``predicate`` key
verified as ``lineage=VERIFIED`` / exit 0 — in Python AND in the Rust verifier — while the SAME bytes, verified
STANDALONE, were rejected as malformed (WP-C1 duplicate-key guard). The verdict of a chain depended on which
parser read a hop, and the hop's author chose the bytes.

INVARIANT: an attached target is VERIFIED only if it verifies standalone on every surface — crypto AND strict
structure. A payload that ``loads_strict`` refuses is an ``attached_target_malformed`` target and the chain
FAILs (``RELATION_TARGET_MALFORMED``), never a silent ``absent``. Loader and standalone verifier call THIS
function, so they cannot disagree about what "well-formed" means.
"""
from __future__ import annotations

from typing import Any

from ._strict_json import loads_strict
from .errors import BundleFormatError

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


def load_statement_strict(body: bytes, *, budget: Any = None, require_canonical: bool = False) -> dict:
    """Parse the EXACT signed payload bytes as a JSON object under the strict, budgeted parser.

    Raises :class:`BundleFormatError` (a ``ProofBundleError``) on anything that is not a well-formed JSON
    object: a duplicate key at any depth (WP-C1), a BOM or other non-UTF-8 prefix, a scalar or array at
    the top, or an over-budget body. The budget check (``input_bytes``) runs first so an oversized body is
    refused before it is parsed — the same order the standalone verifiers use.

    ``require_canonical=True`` additionally demands that the object re-serialises (RFC 8785 / JCS) to
    EXACTLY the signed bytes — the hash_binding rule every standalone verify path applies. NaN/Infinity
    (which ``json.loads`` accepts but JCS cannot represent) and any non-canonical spelling fail here.
    The canonicalizer is a core dependency; its absence is a broken install and fails closed too.
    """
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415 - local import avoids an import cycle
    b = budget if budget is not None else DEFAULT_BUDGET
    b.check("input_bytes", len(body))
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BundleFormatError(f"DSSE payload is not UTF-8 JSON: {exc}") from exc
    try:
        statement = loads_strict(text, budget=b)
    except ValueError as exc:  # json.JSONDecodeError (BOM, trailing garbage, ...)
        raise BundleFormatError(f"DSSE payload is not well-formed JSON: {exc}") from exc
    if not isinstance(statement, dict):
        raise BundleFormatError(
            f"DSSE payload is not a JSON object (got {type(statement).__name__}) — not an in-toto Statement")
    if require_canonical:
        from . import canonical  # noqa: PLC0415
        try:
            canonical_bytes = canonical.canonicalize_statement(statement)
        except Exception as exc:  # noqa: BLE001 — NaN, unavailable canonicalizer, ...: fail-closed, never raw
            raise BundleFormatError(f"DSSE payload is not RFC-8785 canonicalizable (hash_binding fail-closed): "
                                    f"{exc}") from exc
        if canonical_bytes != body:
            raise BundleFormatError("DSSE payload is not RFC-8785 canonical (hash_binding fail-closed)")
    return statement
