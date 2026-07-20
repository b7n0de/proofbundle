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
from typing import Any

from .errors import ProofBundleError

SUBJECT_MODES = ("DERIVED", "EXTERNAL_ATTESTED")


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


def _declared_subject_sha256(statement: Any) -> str | None:
    if not isinstance(statement, dict):
        return None
    subj = statement.get("subject")
    if not isinstance(subj, list) or not subj or not isinstance(subj[0], dict):
        return None
    dig = subj[0].get("digest")
    sha = dig.get("sha256") if isinstance(dig, dict) else None
    return sha if isinstance(sha, str) else None


def classify_subject(statement: Any) -> dict:
    """Classify a Statement's subject binding.

    Returns ``{mode, matches, derived_sha256, declared_sha256}``:
      - ``mode`` is ``DERIVED`` when the declared subject digest equals the re-derived predicate digest,
        else ``EXTERNAL_ATTESTED`` (the subject points at something other than these predicate bytes).
      - ``matches`` mirrors ``mode == 'DERIVED'`` for a quick boolean gate.
    A malformed statement (no predicate / no subject digest) is ``EXTERNAL_ATTESTED`` with ``matches`` False —
    fail-closed: we never call an unresolvable subject a genuine commitment."""
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
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
