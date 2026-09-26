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
import re
from typing import Any

from .errors import ProofBundleError

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


def derive_subject_digest(predicate: Any) -> str:
    """The canonical DERIVED subject digest: sha256 over the RFC-8785 canonical predicate bytes (hex)."""
    return hashlib.sha256(_rfc8785_bytes(predicate)).hexdigest()


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


def classify_subject(statement: Any) -> dict:
    """Classify a Statement's subject binding.

    Returns ``{mode, matches, derived_sha256, declared_sha256}``:
      - ``mode`` is ``DERIVED`` when the declared subject digest equals the re-derived predicate digest,
        ``AMBIGUOUS`` when the subject array carries more than one entry (deep gate 2026-09-05, L4-02: the
        first entry is never silently taken, and the verdict does not depend on the order of the entries),
        else ``EXTERNAL_ATTESTED`` (the subject points at something other than these predicate bytes).
      - ``matches`` mirrors ``mode == 'DERIVED'`` for a quick boolean gate.
    A malformed statement (no predicate / no subject digest) is ``EXTERNAL_ATTESTED`` with ``matches`` False —
    fail-closed: we never call an unresolvable subject a genuine commitment."""
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
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415 - local import avoids an import cycle
    max_depth, max_nodes = DEFAULT_BUDGET.json_depth, DEFAULT_BUDGET.json_nodes
    out: list[str] = []
    stack: list[tuple[Any, str, int]] = [(obj, path, 0)]
    nodes = 0
    while stack:
        cur, cur_path, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            out.append("<root>: structure exceeds the validation node budget (nested closure fail-closed)")
            break
        if depth > max_depth:
            out.append(f"{cur_path or '<root>'}: nesting exceeds the validation depth budget "
                       "(nested closure fail-closed)")
            continue  # do not descend past the depth bound
        if isinstance(cur, dict):
            allowed = allowed_map.get(cur_path)
            if allowed is not None:
                for k in cur:
                    if k not in allowed:
                        out.append(f"{cur_path or '<root>'}.{k}: undeclared nested key (nested closure violated)")
            for k, v in reversed(list(cur.items())):
                child = f"{cur_path}.{k}" if cur_path else k
                stack.append((v, child, depth + 1))
        elif isinstance(cur, list):
            item_path = f"{cur_path}[]"
            for v in reversed(cur):
                stack.append((v, item_path, depth + 1))
    return out


_SHA256_HEX_TYPE = re.compile(r"\A[0-9a-f]{64}\Z")
_RFC3339_Z_TYPE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z\Z")


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
        return (isinstance(value, dict) and set(value) == {"sha256"} and isinstance(value["sha256"], str)
                and bool(_SHA256_HEX_TYPE.match(value["sha256"])))
    raise ValueError(f"unknown type kind {kind!r} in a type map")


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
    from .budget import render_safe  # noqa: PLC0415
    max_depth, max_nodes = DEFAULT_BUDGET.json_depth, DEFAULT_BUDGET.json_nodes
    out: list[str] = []
    stack: list[tuple[Any, str, int]] = [(obj, "", 0)]
    nodes = 0
    while stack:
        cur, cur_path, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            out.append("<root>: structure exceeds the validation node budget (type check fail-closed)")
            break
        if depth > max_depth:
            out.append(f"{cur_path or '<root>'}: nesting exceeds the validation depth budget (type check fail-closed)")
            continue
        want = type_map.get(cur_path)
        if want is not None:
            kinds = (want,) if isinstance(want, str) else want
            if not any(_has_type(cur, k) for k in kinds):
                out.append(f"{cur_path}: must be {' or '.join(kinds)}, got {render_safe(cur)}")
                continue   # a wrong container is not descended into; its own type is the finding
        if isinstance(cur, dict):
            for k, v in reversed(list(cur.items())):
                if isinstance(k, str):
                    stack.append((v, f"{cur_path}.{k}" if cur_path else k, depth + 1))
        elif isinstance(cur, list):
            for v in reversed(cur):
                stack.append((v, f"{cur_path}[]", depth + 1))
    return out
