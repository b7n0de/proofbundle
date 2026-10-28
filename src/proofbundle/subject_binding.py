"""Decision Subject Binding + Nested Schema Closure — 3.2.0 O6 (EXPERIMENTAL).

Two cross-cutting hardening utilities for the receipt statements (eval/decision/outcome):

1. Subject binding mode. An in-toto Statement's ``subject`` is by default a DERIVED commitment to its
   predicate: ``subject[0].digest.sha256 == sha256(RFC-8785(predicate))``. ``build_*_statement`` allows a
   caller to OVERRIDE ``subject_sha256`` — that override is self-attested and NOT cross-checked at build or
   verify (documented in decision.py). This module lets a relying party CLASSIFY the binding: ``DERIVED``
   (the subject genuinely commits to the predicate — re-derived and matched) vs ``EXTERNAL_ATTESTED`` (the
   subject points elsewhere; a self-assertion that only a policy which pins the external attester may trust).
   ``require_derived_subject`` is the fail-closed gate for a relying party that requires a true commitment.

2. Nested schema closure. ``additionalProperties: false`` at the top level does not, by itself, close NESTED
   objects. ``nested_closure_violations`` walks a predicate against a declared ``{path: allowed_keys}`` map and
   reports any nested object carrying an undeclared key — so a versioned extensions container is the ONLY way
   to add fields, never a silent unknown nested key.

No-Overclaim: a DERIVED classification proves the subject commits to THESE predicate bytes, never that the
predicate's claim is true. ``EXTERNAL_ATTESTED`` is reported honestly, never silently treated as bound.
"""
from __future__ import annotations

import hashlib
from bisect import bisect_left, bisect_right
from typing import Any

from .canonical import _ein_stand, _pruefkopie
from .errors import ProofBundleError
# The schemas' own readings (ECMA-262, key-closed `sha256Digest`), one definition in _schema_shapes.
from ._schema_shapes import RFC3339_Z as _RFC3339_Z_TYPE, is_sha256_digest

# AMBIGUOUS (deep gate 2026-09-05, finding L4-02): a Statement with MORE THAN ONE subject never binds silently
# to subject[0]. Which object the statement speaks about is open, on the statement-under-verification side
# exactly as on the resolver side (cli._load_related already reported such a target as "ambiguous"); the
# verdict is order-invariant, so [derived, foreign] and [foreign, derived] classify identically.
SUBJECT_MODES = ("DERIVED", "EXTERNAL_ATTESTED", "AMBIGUOUS")


class SubjectBindingError(ProofBundleError):
    """A required DERIVED subject binding was not satisfied (fail-closed)."""


def _rfc8785_bytes(obj: Any) -> bytes:
    from . import canonical  # noqa: PLC0415
    try:
        return canonical.canonicalize_statement(obj)
    except canonical.CanonicalizerUnavailable as exc:
        raise SubjectBindingError(
            "subject binding needs the RFC 8785 (JCS) canonicalizer — install proofbundle[eval]") from exc
    except canonical.NOT_CANONICALIZABLE as exc:
        # Everything the shared path refuses leaves as this module's typed error: the canonicalizer's
        # own refusal (IntegerDomainError, FloatDomainError: a value the strict parser admits and RFC
        # 8785 cannot represent) and the structural budget's, which runs first. Measured on 8ecb6edf:
        # `classify_subject`, `require_derived_subject` and `derive_subject_digest` raised the bare
        # ValueError for a predicate holding `2**53` or NaN; on d5747000 they still raised a bare
        # BundleFormatError for a lone surrogate or a nesting past the budget's depth and a bare
        # BudgetExceeded for `2**8194`. The decision, outcome and relation verifiers catch every
        # exception here and report "could not classify the subject binding", as before.
        raise SubjectBindingError(
            f"the predicate is not RFC 8785 (JCS) canonicalizable: {exc}") from exc


@_ein_stand
def derive_subject_digest(predicate: Any) -> str:
    """The canonical DERIVED subject digest: sha256 over the RFC-8785 canonical predicate bytes (hex)."""
    return hashlib.sha256(_rfc8785_bytes(predicate)).hexdigest()


@_ein_stand
def subject_cardinality(statement: Any) -> int | None:
    """How many entries the Statement's ``subject`` array carries; ``None`` when there is no array at all.

    The ONE place the count is read (L4-02 sweep of every ``subject[0]`` site): a statement binds exactly
    one object or it binds none unambiguously — a second entry makes the binding AMBIGUOUS, and no caller
    may silently take the first."""
    if not isinstance(statement, dict):
        return None
    subj = statement.get("subject")
    if not isinstance(subj, list):
        return None
    return len(subj)


def _declared_subject_sha256(statement: Any) -> str | None:
    """The declared digest of the SINGLE subject — ``None`` for absent, empty, AMBIGUOUS (>1) or malformed."""
    if subject_cardinality(statement) != 1:
        return None
    subj = statement["subject"]
    if not isinstance(subj[0], dict):
        return None
    dig = subj[0].get("digest")
    sha = dig.get("sha256") if isinstance(dig, dict) else None
    return sha if isinstance(sha, str) else None


@_ein_stand
def classify_subject(statement: Any) -> dict:
    """Classify a Statement's subject binding.

    Returns ``{mode, matches, derived_sha256, declared_sha256}``:
      - ``mode`` is ``DERIVED`` when the declared subject digest equals the re-derived predicate digest,
        ``AMBIGUOUS`` when the subject array carries more than one entry (deep gate 2026-09-05, L4-02: the
        first entry is never silently taken, and the verdict does not depend on the order of the entries),
        else ``EXTERNAL_ATTESTED`` (the subject points at something other than these predicate bytes).
      - ``matches`` mirrors ``mode == 'DERIVED'`` for a quick boolean gate.
    A malformed statement (no predicate / no subject digest) is ``EXTERNAL_ATTESTED`` with ``matches`` False —
    fail-closed: we never call an unresolvable subject a genuine commitment.

    The statement is read once, into the plain copy of what it stores (round 12); one holding a value
    that is no JSON value is a malformed statement, EXTERNAL_ATTESTED.

    A predicate that RFC 8785 cannot represent (an integer outside +-(2**53 - 1), NaN, Infinity) or that the
    structural budget in front of the canonicalizer refuses (a lone surrogate, a nesting past its depth, an
    integer past its bit budget) has no derived digest at all and raises :class:`SubjectBindingError`: reporting
    it as EXTERNAL_ATTESTED would call a subject that may well be derived "a subject-rehang"."""
    try:
        statement = _pruefkopie(statement)
    except ValueError:
        return {"mode": "EXTERNAL_ATTESTED", "matches": False, "derived_sha256": None, "declared_sha256": None}
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    n = subject_cardinality(statement)
    if n is not None and n > 1:
        # Order-invariant by construction: the count decides before any entry is read.
        return {"mode": "AMBIGUOUS", "matches": False, "derived_sha256": None, "declared_sha256": None,
                "subject_count": n}
    declared = _declared_subject_sha256(statement)
    if predicate is None or declared is None:
        return {"mode": "EXTERNAL_ATTESTED", "matches": False,
                "derived_sha256": None, "declared_sha256": declared}
    derived = derive_subject_digest(predicate)
    is_derived = declared == derived
    return {"mode": "DERIVED" if is_derived else "EXTERNAL_ATTESTED", "matches": is_derived,
            "derived_sha256": derived, "declared_sha256": declared}


@_ein_stand
def require_derived_subject(statement: Any) -> None:
    """Fail-closed gate: raise :class:`SubjectBindingError` unless the subject is a genuine DERIVED commitment
    to the predicate. Use this when a relying party requires the subject to bind the predicate (an
    EXTERNAL_ATTESTED subject is only trustable via a policy that pins the external attester)."""
    c = classify_subject(statement)
    if c["mode"] == "AMBIGUOUS":
        raise SubjectBindingError(
            f"subject is AMBIGUOUS — the statement carries {c.get('subject_count')} subjects and never binds "
            "silently to the first one; a DERIVED commitment needs exactly one subject")
    if not c["matches"]:
        raise SubjectBindingError(
            "subject is not a DERIVED commitment to the predicate "
            f"(declared={c['declared_sha256']}, derived={c['derived_sha256']}) — EXTERNAL_ATTESTED, "
            "trust it only via a policy that pins the external attester")


def _declared_prefixes(paths: Any) -> "frozenset | tuple | None":
    """Every declared dotted path and every path that leads to one, cut at member and item boundaries.

    THE PATH TEXT IS KEPT ONLY WHERE IT CAN MATCH (deep gate 6.4.0, iteration 1, the neighbours of finding
    C1). Both walks below gave every child the text of its whole path. Measured at e29a2683 with 73190 bytes
    of input, fifty nested members with names of 1000 characters over 2000 members: about 100 MB of traced
    memory for each walk, 1375 times the input, against 5 times for a flat input of the same size. A path is
    looked up only to compare it with a declared one, and a path that is no prefix of a declared one cannot
    lead to one, so below it the walks carry a link instead of text.

    None for a map that is no dict: then nothing is cut, and the walk looks every path up as it did before,
    so such a map is refused where it was refused before, at its first lookup.

    A PLAIN DICT GETS NO PREFIX TEXT AT ALL (the counter-reading of C1, finding F1). The set above holds every
    prefix of every declared path as a string of its own, so a declared path of k names costs memory in
    proportion to k times its length, and the walk built the text of every node on a declared prefix. For a
    map whose type is exactly dict the walks read the sorted declared paths instead (`_declared_sorted`) and
    carry a position in them, three integers (`_position`). A dict subclass keeps the text: its own ``get``
    may answer for a prefix that is no key, and the walk looks every kept prefix up with it."""
    if not isinstance(paths, dict):
        return None
    if type(paths) is dict:
        return _declared_sorted(paths)
    out = {""}
    for p in paths:
        if not isinstance(p, str):
            continue
        p = str.__str__(p)
        out.add(p)
        for j, ch in enumerate(p):
            if ch == "." or p.startswith("[]", j):
                out.add(p[:j])
    return frozenset(out)


def _declared_sorted(paths: dict) -> tuple:
    """The declared str paths of a plain dict, each as plain text, sorted and without repeats."""
    return tuple(sorted({str.__str__(p) for p in paths if isinstance(p, str)}))


def _at_boundary(declared: tuple, lo: int, hi: int, off: int) -> bool:
    """Whether the common prefix of length ``off`` of ``declared[lo:hi]`` is in the set of `_declared_prefixes`:
    a declared path itself, or cut before a member (``.``) or an item (``[]``) of one."""
    if len(declared[lo]) == off:     # sorted, so a path equal to the prefix comes first
        return True
    for mark in (".", "[]"):
        end = off + len(mark)
        i = bisect_left(declared, mark, lo, hi, key=lambda p: p[off:end])
        if i < hi and declared[i][off:end] == mark:
            return True
    return False


def _position(declared: tuple, lo: int, hi: int, off: int, step: str) -> Any:
    """The position of ``step`` appended to the text at ``(lo, hi, off)``: the declared paths that start with the
    longer text, kept only at a boundary (`_at_boundary`), else None. No text is built for it."""
    end = off + len(step)
    if end == 0:
        # A member named "" below the root: its path is "" again, which the set always holds, declared or not.
        return (lo, hi, 0)
    lo = bisect_left(declared, step, lo, hi, key=lambda p: p[off:end])
    hi = bisect_right(declared, step, lo, hi, key=lambda p: p[off:end])
    if lo == hi or not _at_boundary(declared, lo, hi, end):
        return None
    return (lo, hi, end)


def _dotted_step(text: str, step: Any) -> str:
    """One step of a dotted path (``None`` = each item of an array), for `budget._chain_text`."""
    if step is None:
        return f"{text}[]"
    return f"{text}.{step}" if text else step


def _kept(declared: Any, text: Any) -> Any:
    """Where a walk stands while its path can still match a declared path (`_declared_prefixes`), else None:
    the text itself, or for a plain dict its position in the sorted declared paths."""
    if text is None:
        return None
    if type(declared) is tuple:
        if text == "":
            return (0, len(declared), 0)
        return _position(declared, 0, len(declared), 0, text) if declared else None
    if declared is not None and text not in declared:
        return None
    return text


def _child_text(declared: Any, parent: Any, name: str) -> Any:
    """Where a child stands while its path can still match a declared path, else None."""
    if parent is None:
        return None
    if type(declared) is tuple:
        lo, hi, off = parent
        return _position(declared, lo, hi, off, f".{name}" if off else name)
    return _kept(declared, f"{parent}.{name}" if parent else name)


def _item_text(declared: Any, parent: Any) -> Any:
    """Where each item of an array stands while its path can still match a declared path, else None."""
    if parent is None:
        return None
    if type(declared) is tuple:
        lo, hi, off = parent
        return _position(declared, lo, hi, off, "[]")
    return _kept(declared, f"{parent}[]")


def _lookup_text(declared: Any, cur: Any) -> Any:
    """The text a walk looks up in its map where it stands: for a plain dict only a declared path, since a plain
    dict has nothing else to answer; for any other map the kept text, as before."""
    if cur is None:
        return None
    if type(declared) is tuple:
        lo, hi, off = cur
        return declared[lo] if lo < hi and len(declared[lo]) == off else None
    return cur


@_ein_stand
def nested_closure_violations(obj: Any, allowed_map: dict[str, tuple[str, ...]], *, path: str = "") -> list[str]:
    """Walk ``obj`` and report nested objects with keys not in ``allowed_map`` for their dotted path.

    ``allowed_map`` maps a dotted path (``""`` = the root object, ``"decision"`` = the ``decision`` object,
    ``"evidenceRefs[]"`` = each item of the ``evidenceRefs`` array) to a tuple of allowed keys. A path that is
    NOT in ``allowed_map`` is not walked (its closure is not being asserted here) — only declared paths are
    checked, so this composes with a top-level ``additionalProperties:false`` rather than duplicating it.
    Fail-closed usage: declare every nested object whose closure matters; an undeclared key under a declared
    path is a violation (a versioned extensions container is the sanctioned way to extend)."""
    # adversarial re-audit round 8: ITERATIVE (explicit stack), not recursive — a relying party that calls this
    # public validator directly on a deeply-nested predicate obtained WITHOUT loads_strict (a REST body
    # json.loads'd by an integrator) would otherwise get a raw RecursionError, violating the
    # validate/require_valid contract. The CLI + DSSE paths are already loads_strict depth-bounded (64); this
    # closes the direct-primitive path. Bounded at the same json_depth / json_nodes budget so a hostile deep or
    # node-heavy structure is a FAIL-CLOSED violation (a returned error string), never a crash. DFS pre-order is
    # preserved (children pushed reversed) so the reported violation order is unchanged for legitimate inputs.
    from .budget import DEFAULT_BUDGET, _chain_text, render_safe, render_text  # noqa: PLC0415 - avoids an import cycle
    max_depth, max_nodes = DEFAULT_BUDGET.json_depth, DEFAULT_BUDGET.json_nodes
    out: list[str] = []
    # THE START PATH IS TEXT TOO, and it comes from the caller: `path=10**5000` raised ValueError
    # from the f-strings below (lens run 10 generator). A str path is itself, as a key is.
    start = render_text(path)
    declared = _declared_prefixes(allowed_map)
    # (value, where it stands or None below the declared prefixes, link for a message, depth): `_kept`.
    stack: list[tuple[Any, Any, Any, int]] = [(obj, _kept(declared, start), None, 0)]
    nodes = 0
    while stack:
        cur, cur_path, chain, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            out.append("<root>: structure exceeds the validation node budget (nested closure fail-closed)")
            break
        if depth > max_depth:
            # A MESSAGE NAMES THE PATH THROUGH `_chain_text` ON A DECLARED PATH TOO (F1): the kept text was
            # written whole, so a long declared path gave a message longer than the limit of the others.
            out.append(f"{_chain_text(start, chain, _dotted_step) or '<root>'}: nesting exceeds the validation "
                       "depth budget (nested closure fail-closed)")
            continue  # do not descend past the depth bound
        if isinstance(cur, dict):
            look = _lookup_text(declared, cur_path)
            allowed = allowed_map.get(look) if look is not None else None
            if allowed is not None:
                for k in cur:
                    if k not in allowed:
                        out.append(f"{_chain_text(start, chain, _dotted_step) or '<root>'}."
                                   f"{render_safe(k, quote=False)}: undeclared nested key (nested closure violated)")
            for k, v in reversed(list(cur.items())):
                # A PATH IS TEXT, built from a key rendered bounded: a key of `10**5000` (a direct-dict
                # caller) raised ValueError here and in the message above (the public-surface generator on
                # main 570dd164 and five carried commits: 36 of 189 calls). A str key is itself.
                name = k if isinstance(k, str) else render_safe(k, quote=False)
                stack.append((v, _child_text(declared, cur_path, name), (chain, name), depth + 1))
        elif isinstance(cur, list):
            item_path = _item_text(declared, cur_path)
            link = (chain, None)
            for v in reversed(cur):
                stack.append((v, item_path, link, depth + 1))
    return out



def _has_type(value: Any, kind: str) -> bool:
    """One JSON Schema type, as the schemas in schemas/ use it. `sha256` is the `sha256Digest` object and
    `rfc3339z` the `rfc3339z` string of their `$defs`; `boolean` is never an int, `string` never None."""
    if kind == "string":
        return isinstance(value, str)
    if kind == "object":
        return isinstance(value, dict)
    if kind == "array":
        return isinstance(value, list)
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "null":
        return value is None
    if kind == "rfc3339z":
        return isinstance(value, str) and bool(_RFC3339_Z_TYPE.match(value))
    if kind == "sha256":
        return is_sha256_digest(value)
    from .budget import render_safe  # noqa: PLC0415 - local import avoids an import cycle
    raise ValueError(f"unknown type kind {render_safe(kind)} in a type map")


@_ein_stand
def nested_type_violations(obj: Any, type_map: dict[str, "str | tuple[str, ...]"]) -> list[str]:
    """Walk ``obj`` and report every value at a declared dotted path whose JSON type is not the declared one.

    The sibling of :func:`nested_closure_violations`, with the same path convention (``"decision"``,
    ``"notChecked[]"`` for each item, ``"notChecked[].field"``). A path that is absent is not a violation
    (required-ness is the caller's job); a path that is PRESENT carries its type, and JSON null is a type
    like any other, so a present null is refused wherever the map does not name ``"null"``. Deep gate
    Z195, L3-Z195-03 and L3-Z195-05: the decision validator checked presence for required fields and
    skipped every None, and 311 type-confused predicates its own published schema refuses passed it.

    Iterative and bounded by the same budget as the closure walk, so a hostile structure is a returned
    violation, never a RecursionError."""
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415 - local import avoids an import cycle
    from .budget import _chain_text, render_safe  # noqa: PLC0415
    max_depth, max_nodes = DEFAULT_BUDGET.json_depth, DEFAULT_BUDGET.json_nodes
    out: list[str] = []
    declared = _declared_prefixes(type_map)
    # (value, where it stands or None below the declared prefixes, link for a message, depth): `_kept`.
    stack: list[tuple[Any, Any, Any, int]] = [(obj, _kept(declared, ""), None, 0)]
    nodes = 0
    while stack:
        cur, cur_path, chain, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            out.append("<root>: structure exceeds the validation node budget (type check fail-closed)")
            break
        if depth > max_depth:
            out.append(f"{_chain_text('', chain, _dotted_step) or '<root>'}: nesting exceeds the validation depth "
                       "budget (type check fail-closed)")
            continue
        look = _lookup_text(declared, cur_path)
        want = type_map.get(look) if look is not None else None
        if want is not None:
            kinds = (want,) if isinstance(want, str) else want
            if not any(_has_type(cur, k) for k in kinds):
                out.append(f"{_chain_text('', chain, _dotted_step)}: must be {' or '.join(kinds)}, "
                           f"got {render_safe(cur)}")
                continue   # a wrong container is not descended into; its own type is the finding
        if isinstance(cur, dict):
            for k, v in reversed(list(cur.items())):
                if isinstance(k, str):
                    stack.append((v, _child_text(declared, cur_path, k), (chain, k), depth + 1))
        elif isinstance(cur, list):
            item_path = _item_text(declared, cur_path)
            link = (chain, None)
            for v in reversed(cur):
                stack.append((v, item_path, link, depth + 1))
    return out
