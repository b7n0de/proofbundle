"""ONE oracle for "is this DSSE payload a well-formed in-toto Statement object" — shared by the standalone
verify paths AND the ``--with-related`` resolver (deep gate 2026-09-05, finding L4-01, P1). Since deep gate
Z195 (L3-Z195-01) every verifier that reports ``structure_ok`` for a Statement parses through it, and it
reads ``_type``; since 2026-10-17 it reads the ``subject`` too (`statement_subject_problem`), the rule the
three in-toto verifiers of intoto.py apply as well.

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

import re
from typing import Any

from ._strict_json import loads_strict
from .canonical import _zeichen_von
from .errors import BundleFormatError

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

_LOWER_HEX_RE = re.compile(r"\A[0-9a-f]+\Z")
# ONE TABLE for the form of a digest and for its comparison with `content`: each hash function by the name hashlib
# knows it under, beside the length of its hex output. A digest under one of these names that has another length,
# or is not lowercase hex, names no content; with `content` present, intoto recomputes its digest over the decoded
# bytes. Every other algorithm name only needs a non-empty string, and its digest is not compared with the content
# (A9 in docs/IN_TOTO_PROFILE.md). It stands here, beside the Statement oracle, since the subject of every
# Statement is judged by it (2026-10-17); intoto reads it from here.
# Until K1 of the Codex defect search of the 6.3.0 candidate 98b168b9 these were two tables: the form named twelve
# functions, the comparison eight. Under md5, sha3_224, sha512_224 and sha512_256 a well-formed digest of other
# bytes verified ok=True at subject, model, dataset and evidence, and the v0.2 exporter wrote such a descriptor.
_HASH_FUNCTIONS = (("md5", 32), ("sha1", 40), ("sha224", 56), ("sha256", 64), ("sha384", 96),
                   ("sha512", 128), ("sha512_224", 56), ("sha512_256", 64), ("sha3_224", 56),
                   ("sha3_256", 64), ("sha3_384", 96), ("sha3_512", 128))


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _digest_set_problem(value: Any) -> str:
    """'' for a usable DigestSet, else what is wrong with it."""
    if not isinstance(value, dict):
        return f"digest must be a DigestSet object, got {type(value).__name__}"
    if not value:
        return "digest is empty"
    for alg, roh in value.items():
        if not _nonempty_str(alg):
            return "digest has an empty algorithm name"
        # The characters of the value (`_zeichen_von`), so a caller's `str` subclass that an emitter is
        # handed as `subject_sha256` is judged by what the serializer writes, not by its own `__len__`;
        # a parsed value is a plain `str` and reads the same.
        hexval = _zeichen_von(roh)
        if not hexval:
            return f"digest {alg[:40]!r} must be a non-empty string"
        for name, length in _HASH_FUNCTIONS:
            if alg == name and (len(hexval) != length or not _LOWER_HEX_RE.match(hexval)):
                return f"digest {alg!r} must be {length} lowercase hex characters"
    return ""


def statement_subject_problem(statement: dict) -> "str | None":
    """Why the ``subject`` of ``statement`` names no artifact an in-toto consumer could match, or None.

    in-toto Statement v1 (spec/v1/statement.md): ``subject`` is required, and each element MUST have
    ``digest`` set, because subject artifacts are matched purely by digest. A non-empty array whose every
    entry is an object with a usable digest (`_digest_set_problem`) passes; an absent subject and a
    present one of the wrong form are named apart.

    Owner decision of 2026-10-17 on the neighbour of finding L5-03. Measured on main 570dd164: decision,
    outcome, relation-statement, verification-summary, run-ledger and trust-pack verify reported ok=True and
    structure_ok=True for their own emitter's statement re-signed without a subject, with an empty subject,
    with subject null and with an entry without a digest; the Rust verifier exited 0 on the same bytes on
    both relation subcommands and on the trust-pack threshold. The three in-toto verifiers read this rule
    through `intoto._statement_layer_problem`, and the six emitters of those verifiers refuse to write a
    statement it refuses (`refuse_an_unwritable_subject`). agent_review and verifier_block read their
    subject with rules of their own, each stricter than this one."""
    if "subject" not in statement:
        return "subject is required: a non-empty array of ResourceDescriptors, each with a digest"
    subject = statement["subject"]
    if not isinstance(subject, list):
        return f"subject must be an array of ResourceDescriptors, got {type(subject).__name__}"
    if not subject:
        return "subject must name at least one artifact, got an empty array"
    for i, eintrag in enumerate(subject):
        if not isinstance(eintrag, dict):
            return f"subject[{i}] must be a ResourceDescriptor object, got {type(eintrag).__name__}"
        if "digest" not in eintrag:
            return f"subject[{i}] MUST carry digest (subject artifacts are matched by digest alone)"
        problem = _digest_set_problem(eintrag["digest"])
        if problem:
            return f"subject[{i}]: {problem}"
    return None


def refuse_an_unwritable_subject(statement: dict, error: type) -> dict:
    """``statement`` unchanged when its verifier would accept its subject; else ``error`` naming why.

    The emitter side of `statement_subject_problem`. The default subject of the six emitters is the
    sha256 of the canonical predicate and always passes; a caller's ``subject_sha256`` override is written
    verbatim and did not. Measured by the second reading of 2026-10-18 on this change: an override in
    capitals, of 63 characters, with a ``sha256:`` prefix or of one character emitted without complaint
    and its statement then failed its own verifier."""
    problem = statement_subject_problem(statement)
    if problem is not None:
        raise error(f"subject_sha256 cannot be written, since the verifier would refuse the statement: {problem}")
    return statement


def statement_type_problem(statement: dict) -> "str | None":
    """Why ``statement`` does not declare itself an in-toto Statement v1, or None when it does.

    Deep gate Z195, finding L3-Z195-01 (P2, jury 3 of 3): decision, outcome and relation-statement verify
    reported ``structure_ok=true`` and ``safeForAutomation=true`` for a signed statement whose ``_type`` was
    absent, JSON null or ``Statement/v0.1``. Each of them builds ``_type`` when it emits and none of them
    read it back. ``_type`` is what says which schema the other three keys follow, so a structure verdict
    that never read it did not judge the structure it named. The comparison is exact: no case folding, no
    trailing slash, no older version."""
    if "_type" not in statement:
        return f"_type is absent, expected {STATEMENT_TYPE!r}"
    value = statement["_type"]
    if value != STATEMENT_TYPE or not isinstance(value, str):
        from .budget import render_safe  # noqa: PLC0415 - local import avoids an import cycle
        return f"_type is {render_safe(value)}, expected {STATEMENT_TYPE!r}"
    return None


def load_statement_strict(body: bytes, *, budget: Any = None, require_canonical: bool = False) -> dict:
    """Parse the EXACT signed payload bytes as a JSON object under the strict, budgeted parser.

    Raises :class:`BundleFormatError` (a ``ProofBundleError``) on anything that is not a well-formed JSON
    object: a duplicate key at any depth (WP-C1), a BOM or other non-UTF-8 prefix, a scalar or array at
    the top, or an over-budget body; on an object whose ``_type`` is not exactly the in-toto
    Statement v1 type (:func:`statement_type_problem`); and on one whose ``subject`` names no artifact by
    digest (:func:`statement_subject_problem`, since 2026-10-17). The budget check (``input_bytes``) runs first
    so an oversized body is refused before it is parsed — the same order the standalone verifiers use.

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
    statement_type_error = statement_type_problem(statement)
    if statement_type_error is not None:
        raise BundleFormatError(f"DSSE payload is not an in-toto Statement v1: {statement_type_error}")
    subject_error = statement_subject_problem(statement)
    if subject_error is not None:
        raise BundleFormatError(f"DSSE payload is not an in-toto Statement v1: {subject_error}")
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
