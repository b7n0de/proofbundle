"""Canonical Statement primitive — the one home for the universal content root (ADR 0002).

The *content root* of an in-toto Statement is ``SHA-256`` over the RFC-8785 (JCS) canonical bytes of the
**full** Statement (``_type``, ``subject``, ``predicateType``, ``predicate`` — never a predicate-only or
field-subset canonicalization) taken BEFORE signing. The signature bytes are NEVER part of the preimage, so
the root survives counter-signing, key rotation and multi-signature envelopes (proofbundle#7 consensus,
2026-07-10). ``contentRootAlg`` for this definition is ``jcs-sha256-v1`` (see ``CONTENT_ROOT_ALG``).

Two-part rule (ADR 0002):

* a PRODUCER emits its Statement canonically (``canonicalize_statement``) and signs exactly those bytes;
* a VERIFIER hashes the EXACT transmitted payload bytes and NEVER re-canonicalizes — a payload that deviates
  from its own canonical form is a fail-closed error the caller must reject.

``statement_content_root`` serves both sides from one definition: given a JSON object it canonicalizes then
hashes (producer); given raw ``bytes`` it hashes exactly those bytes (verifier). Both yield the SAME 32-byte
root when the producer emitted canonically — which is the whole point of a content root: a verifier that
passes the exact signed payload bytes reproduces the producer's root without trusting a re-serialization.

The RFC-8785 canonicalizer ships in the ``[eval]`` extra (``rfc8785``); it is imported LAZILY so the base
install and the plain no-anchor verify path stay dependency-free. A missing extra is a clear fail-closed
``CanonicalizerUnavailable``, never a raw ``ImportError``.

This module is intentionally tiny and dependency-light: it is the shared primitive that the decision-receipt
predicate (``decision.py``) and, across the 2.1.0 migration (ADR 0002), the eval-result / svr in-toto export
paths converge on. Providing it here does NOT change any released wire format — the migration of the released
``intoto`` export paths off ``json.dumps(sort_keys=True)`` is a separate T3 / SemVer owner-gated step.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any, Union

from .errors import ProofBundleError

__all__ = ["CONTENT_ROOT_ALG", "STATEMENT_REQUIRED_KEYS", "CanonicalizerUnavailable",
           "canonicalize_statement", "statement_content_root"]

# The declared content-root algorithm this primitive computes (ADR 0002): SHA-256 over the RFC-8785 (JCS)
# canonical Statement bytes. A future algorithm MUST register its own distinct id — a verifier MUST NOT
# silently default a missing/unknown value, which is exactly where an algorithm-confusion attack would hide.
CONTENT_ROOT_ALG = "jcs-sha256-v1"

# The four keys of a full in-toto Statement v1. Passing a bare `predicate` where a full Statement is
# required would drop `subject` + `predicateType` and reopen the §2.1 context-confusion attack at the
# primitive level (ADR 0002 §2, full-Statement scope) — the opt-in `require_statement_shape` guard below
# fails closed on that. NOT enforced by default: some callers legitimately canonicalize a bare predicate
# for a subject-commitment digest (e.g. decision.build_decision_statement), which is a different operation.
STATEMENT_REQUIRED_KEYS = ("_type", "subject", "predicateType", "predicate")


class CanonicalizerUnavailable(ProofBundleError):
    """The RFC 8785 (JCS) canonicalizer extra is not installed, so a content root cannot be computed.

    Fail-closed: install ``proofbundle[eval]``. Callers that want a predicate-specific message (e.g.
    ``decision.py``'s ``DecisionReceiptError``) catch this and re-raise."""


def _require_statement_shape(obj: Any) -> None:
    """Fail closed unless ``obj`` is a full in-toto Statement OBJECT (the four ``STATEMENT_REQUIRED_KEYS``).

    Guards the §2.1 bug class at the primitive level: handing a bare ``predicate`` to a routine that expects
    a full Statement silently narrows the content-root scope (``subject`` + ``predicateType`` dropped). This
    is opt-in (``require_statement_shape=True``) precisely because a bare-predicate canonicalization is a
    legitimate, distinct operation elsewhere; enabling it by default would break those callers."""
    if not isinstance(obj, Mapping):
        raise ProofBundleError(
            "require_statement_shape: a full in-toto Statement (JSON object) is required, got "
            f"{type(obj).__name__}")
    # A dict is asked about its STORED keys (`dict.__contains__`), the keys `_plain_for_jcs` copies and
    # the serializer writes. `k in obj` asks the subclass's own `__contains__`: measured at 93b3c6f5
    # and on main 1e95b197, a dict subclass whose `__contains__` always answered True passed this
    # guard holding only a `predicate`, and a bare predicate was canonicalized.
    if issubclass(type(obj), dict):
        missing = [k for k in STATEMENT_REQUIRED_KEYS if not dict.__contains__(obj, k)]
    else:
        missing = [k for k in STATEMENT_REQUIRED_KEYS if k not in obj]
    if missing:
        raise ProofBundleError(
            f"require_statement_shape: object is missing in-toto Statement key(s) {missing} — this looks "
            "like a bare predicate, not a full Statement (subject + predicateType would be dropped; "
            "ADR 0002 §2 full-Statement scope)")


def _plain_for_jcs(value: Any, key_error: type) -> Any:
    """A copy of ``value`` in which every string and every object key is a plain ``str``.

    THE CLASS: a canonical serializer that reads a value through a method the caller's object can
    override. rfc8785 sorts object keys by ``key.encode("utf-16be")``, and a ``str`` subclass can
    override ``encode``. Measured at 6893586f with such a key in a claim's ``provenance``: an
    ``encode`` that raised LookupError or returned an int escaped ``emit_eval_receipt``, the eight
    producers and ``svr_properties`` as a raw exception, and one that returned other bytes for one
    key made the emitter sign a payload whose keys were not in canonical order. The same key in the
    ``harness`` argument of the two in-toto exporters did the same through
    ``canonicalize_statement``.

    Every other reader on the way reads the characters: the claim rule's regular expressions, the
    JSON encoders and the verify path's parser. ``str.__str__`` returns those characters as a plain
    ``str``, so the serializer reads what they read. That is why the copy is the fix and a wider
    ``except`` around the serializer is not: an except would turn the override into a refusal, and
    it would also swallow a real defect of the serializer.

    Containers are read once, by their STORED contents: through the base type's own methods
    (``dict.items``, ``list.__iter__``, ``tuple.__iter__``), never through a method a subclass can
    override (``items``, ``keys``, ``values``, ``__iter__``, ``__getitem__``). The two serializers
    do not share one reading of a subclass (measured on Python 3.10.12: ``json.dumps`` reads a dict
    subclass through ``items()``, ``rfc8785.dumps`` through ``dict()``, which calls ``keys()`` and
    ``__getitem__`` once ``__iter__`` is overridden, and both read a list subclass through
    ``__iter__``), so the copy reads the one thing no subclass can redirect, and both serializers
    then read the copy. Measured by lens run 5 at 5a21b199, where the copy read ``dict(value)``: a
    ``status`` holding a dict subclass whose ``__iter__`` is overridden and whose ``__getitem__``
    raises KeyError escaped ``issue_sd_jwt`` as a raw KeyError; c3ca546b signed its stored contents,
    and so does the copy now.

    The type that decides is the object's own (``type(value)``), not ``__class__``, which an object
    can set to anything; a value whose ``__class__`` claims str, dict, list, tuple, int or float
    and whose type is none of them raises ``key_error`` (at 5a21b199 such a dict in ``status`` was
    read through its ``keys()`` and ``__getitem__`` and signed, and such a string raised a raw
    TypeError).

    A container that contains itself, or a value nested deeper than the interpreter recurses, raises
    ``key_error`` too, never a RecursionError. Measured at 5a21b199: a circular ``status`` raised
    RecursionError, where c3ca546b gave json's ``ValueError: Circular reference detected``.

    Numbers, booleans, None and every other type pass unchanged, so the serializer judges them as
    before. A key that is not a string raises ``key_error``, the refusal rfc8785 gives such a key;
    it gave it only when the key had no ``encode`` method, and raised a raw TypeError when it had
    one. Two keys whose characters are equal raise ``key_error`` too, because JSON has one key for
    both.
    """
    try:
        return _plain_value(value, key_error, set())
    except RecursionError as exc:
        # Only this copy's own recursion can raise it here: every method called on the caller's
        # objects below is a base type's method, which runs no code of the caller.
        raise key_error("the value nests too deep to serialize") from exc


def _plain_value(value: Any, key_error: type, offen: set) -> Any:
    """One level of `_plain_for_jcs`. `offen` holds the ids of the containers being copied above
    this one, so a container met again on its own path is a circle, and one met again beside
    itself (the same list twice in one object) is copied twice, as a serializer writes it.

    Each type is asked with its own `issubclass` call and not with a tuple of types: a tuple costs
    one more level of recursion depth per call (measured on Python 3.10.12: from the same caller, a
    copy of nested lists written with a tuple of types reached one level less), and the copy would
    then refuse a level that rfc8785 writes from the same caller."""
    typ = type(value)
    if issubclass(typ, str):
        return str.__str__(value)
    if issubclass(typ, dict):
        if id(value) in offen:
            raise key_error("the value contains itself (a circular reference)")
        offen.add(id(value))
        kopie: dict = {}
        for schluessel, eintrag in list(dict.items(value)):
            if not issubclass(type(schluessel), str):
                raise key_error("object keys must be strings")
            schluessel = str.__str__(schluessel)
            if schluessel in kopie:
                raise key_error(f"object key {schluessel!r} appears twice")
            kopie[schluessel] = _plain_value(eintrag, key_error, offen)
        offen.discard(id(value))
        return kopie
    if issubclass(typ, list) or issubclass(typ, tuple):
        if id(value) in offen:
            raise key_error("the value contains itself (a circular reference)")
        offen.add(id(value))
        # A loop, not a list comprehension: on Python 3.10 a comprehension is a function of its own and
        # cost a second frame per nesting level, so the copy refused lists nested half as deep as the
        # serializer reads (lens run 4 at c3ca546b: 497 levels here against 994 in rfc8785).
        basis = list if issubclass(typ, list) else tuple
        liste: list = []
        for eintrag in list(basis.__iter__(value)):
            liste.append(_plain_value(eintrag, key_error, offen))
        offen.discard(id(value))
        return liste
    if issubclass(typ, int) or issubclass(typ, float):
        return value
    if isinstance(value, str) or isinstance(value, dict) or isinstance(value, list) \
            or isinstance(value, tuple) or isinstance(value, int) or isinstance(value, float):
        raise key_error(f"a value of type {typ.__name__} claims through __class__ to be a JSON "
                        "type it is not")
    return value


def canonicalize_statement(statement: Any, *, require_statement_shape: bool = False) -> bytes:
    """RFC-8785 (JCS) canonical bytes of a JSON in-toto Statement (or predicate) OBJECT.

    This is the producer-side canonicalization: the exact bytes to sign. It normalizes key order, number
    formatting and string escaping per RFC 8785, so two structurally-equal objects with different key
    insertion order produce byte-identical output. It does NOT hash and does NOT touch signatures.

    Uses the real ``rfc8785`` canonicalizer (the ``[eval]`` extra), lazily imported; a missing extra is a
    fail-closed ``CanonicalizerUnavailable``. Value errors from a non-JCS-able object (e.g. an unsafe float)
    propagate unchanged, exactly as calling ``rfc8785.dumps`` directly would.

    ``require_statement_shape=True`` (opt-in, default OFF) fails closed with ``ProofBundleError`` when
    ``statement`` is not a full in-toto Statement (the four ``STATEMENT_REQUIRED_KEYS``) — a guard against
    accidentally passing a bare ``predicate`` where the full-Statement scope is required (ADR 0002 §2). It is
    OFF by default because a bare-predicate canonicalization is a legitimate distinct operation (e.g. a
    subject-commitment digest); turning the check on by default would break those callers."""
    if require_statement_shape:
        _require_statement_shape(statement)
    # adversarial re-audit round 5: bound nesting/node count BEFORE rfc8785.dumps recurses — a relying party that
    # calls this documented primitive (or statement_content_root) directly on a deeply-nested received JSON
    # object would otherwise get a raw RecursionError. The DSSE verify_* surfaces already re-parse via
    # loads_strict (json_depth-bounded) so they were safe; this closes the direct-primitive path. A legitimate
    # emit-side statement is shallow and well under the budget, so this never changes producer behaviour.
    # The budget reads a container by its stored contents, which is what `_plain_for_jcs` copies below
    # and the serializer writes. Measured at 93b3c6f5 and on main 1e95b197, when it read a dict through
    # `items()`: a dict subclass whose `items`, `values` and `keys` show nothing hid 500 nested lists
    # from the depth bound of 64 and got 1036 bytes written, and 2000 raised a raw RecursionError.
    from ._strict_json import enforce_structural_budget  # noqa: PLC0415 - local import avoids an import cycle
    enforce_structural_budget(statement)
    try:
        import rfc8785  # noqa: PLC0415 — lazy: only the canonical/emit path pulls the JCS dependency
    except ImportError as exc:
        raise CanonicalizerUnavailable(
            "computing a Statement content root needs the RFC 8785 (JCS) canonicalizer — "
            "install proofbundle[eval]") from exc
    # A plain copy, so a key is sorted by its characters and not by its own `encode` (see
    # `_plain_for_jcs`). A plain statement, which is every parsed one, gives the same bytes as
    # before.
    return rfc8785.dumps(_plain_for_jcs(statement, rfc8785.CanonicalizationError))


def statement_content_root(statement: Union[Mapping, list, bytes, bytearray], *,
                           require_statement_shape: bool = False) -> bytes:
    """The content root of a Statement: 32 raw SHA-256 bytes over its canonical Statement bytes (ADR 0002).

    Accepts either side of the two-part rule:

    * a JSON OBJECT (``Mapping`` / ``list``) — the PRODUCER path: canonicalize (RFC 8785) then SHA-256;
    * raw ``bytes`` — the VERIFIER path: SHA-256 over the EXACT payload bytes, NEVER re-canonicalized.

    Both return the SAME root when the producer emitted canonically, so a verifier that passes the exact
    signed payload bytes reproduces the producer's root without trusting a re-serialization. The preimage is
    the STATEMENT (pre-signature); signature/envelope bytes are never included, so the root is stable across
    counter-signing, key rotation and multi-signature envelopes.

    ``.hex()`` on the return value gives the 64-char hex digest used in ``evidenceRefs[].digest.sha256`` and
    a ``statement`` anchor's ``canonicalRoot``.

    ``require_statement_shape=True`` (opt-in, default OFF) guards the OBJECT (producer) path against a bare
    predicate (see ``canonicalize_statement``). It does NOT apply to the ``bytes`` (verifier) path — opaque
    transmitted bytes cannot be introspected, and their shape was fixed at produce time."""
    if isinstance(statement, (bytes, bytearray)):
        # Verifier path: hash the exact transmitted payload bytes; do NOT re-canonicalize (DSSE rule). The
        # shape guard is not applicable to opaque bytes (documented) — the caller checked shape at produce.
        return hashlib.sha256(bytes(statement)).digest()
    if isinstance(statement, (Mapping, list)):
        # Producer path: canonicalize the object (optionally shape-guarded), then hash.
        return hashlib.sha256(
            canonicalize_statement(statement, require_statement_shape=require_statement_shape)).digest()
    raise ProofBundleError(
        "statement_content_root needs a JSON object (dict/list) to canonicalize or the exact payload "
        f"bytes; got {type(statement).__name__}")
