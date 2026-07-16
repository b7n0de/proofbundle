"""Lineage/relationship profile `relation/v0.1` — EXPERIMENTAL (3.3.0 preview).

Change is never expressed by mutation: a new receipt carries a TYPED, SIGNED relationship
edge pointing at an earlier receipt's content root. The old receipt stays valid for its
bytes forever; the verifier reports the relationship as its own `lineage` state instead of
leaving replacement invisible (silent landing) or treating it as tampering.

Like decision.py/outcome.py this module is hand-rolled and fail-closed: unknown fields,
bad enums, malformed digests and non-RFC3339-Z timestamps are errors, never silently
accepted. Validators RETURN error lists (empty == valid) and never raise; see
`validate_relationships`. Verification is pure and offline: targets are supplied by the
caller (`--with-related` at the CLI), never fetched.

Honesty boundary (verbatim wording, enforced by claims-hygiene): a verified relationship
edge proves the ISSUER DECLARED the relation over exact bytes — "relationship declared by
issuer, not a statement of correctness." It never proves the successor is better, more
true, or methodologically sound, and `lineage` NEVER feeds `cryptoValid` or raises any
other assurance dimension (lattice monotonicity).

Interop mapping (see docs/predicates/relation.md; corrected against the draft-nobuo-scitt-protected-object-
binding-00 FULL TEXT, 2026-07-16 — that draft has NO `amends` relation):
  supersedes -> SCITT supersedes · revises/corrects -> SCITT supersedes (PROV wasRevisionOf)
  retracts -> SCITT revokes (PROV wasInvalidatedBy) · derivedFrom -> SCITT derivedFrom
  renews -> RFC 4998 line (no SCITT counterpart) · amends -> (no SCITT counterpart; own
  relation, justified in docs/predicates/relation.md).
"""
from __future__ import annotations

import re
from typing import Any

from .errors import ProofBundleError

RELATION_PROFILE = "proofbundle/relation/v0.1"

# Closed, versioned vocabulary. Extension only via a spec change — an unknown relation is
# a fail-closed error, never a silent pass-through (algorithm-confusion lesson, SPEC §5).
RELATIONS = ("supersedes", "revises", "corrects", "retracts", "renews", "derivedFrom", "amends")

# Successor-semantics subset: the PRESENT receipt declares itself the successor of the target.
SUCCESSOR_RELATIONS = frozenset({"supersedes", "revises", "corrects"})

REASON_CODES = ("correction", "rerun", "data-update", "methodology-update",
                "policy-change", "withdrawal", "other")

# The only registered content-root algorithm for relation/v0.1 edges. Explicit and
# REQUIRED — a missing digestAlgorithm is never defaulted (SPEC §5 hash-agility rule).
CONTENT_ROOT_ALGS = ("jcs-sha256-v1",)

# Hard chain limits (SPEC: cycles = FAIL, depth exceeded = FAIL with a stable code).
MAX_CHAIN_DEPTH = 32
MAX_EDGES_PER_RECEIPT = 64

# Per-edge / aggregate lineage states.
LINEAGE_VERIFIED = "VERIFIED"
LINEAGE_DECLARED_UNRESOLVED = "DECLARED_UNRESOLVED"
LINEAGE_FAIL = "FAIL"
LINEAGE_NOT_EVALUATED = "NOT_EVALUATED"

_RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
_SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")  # \Z (not $) — $ matches before a trailing newline

_EDGE_REQUIRED = ("relation", "targetReceiptDigest")
_EDGE_ALLOWED = ("relation", "targetReceiptDigest", "targetSubjectDigest",
                 "reason", "reasonCode", "declaredAt")
_DIGEST_ALLOWED = ("digestAlgorithm", "digest")


class RelationProfileError(ProofBundleError):
    """A relation/v0.1 relationships block is malformed (fail-closed)."""


def _validate_edge_digest(obj: Any, path: str, errors: list[str]) -> None:
    if not isinstance(obj, dict):
        errors.append(f"{path} must be an object {{digestAlgorithm, digest}}")
        return
    unknown = sorted(set(obj) - set(_DIGEST_ALLOWED))
    if unknown:
        errors.append(f"{path} unknown field(s) {unknown} (fail-closed)")
    alg = obj.get("digestAlgorithm")
    if alg is None:
        # Never silently default — exactly where an algorithm-confusion attack would hide.
        errors.append(f"{path}.digestAlgorithm is required (never defaulted)")
    elif alg not in CONTENT_ROOT_ALGS:
        errors.append(f"{path}.digestAlgorithm {alg!r} is not a registered relation/v0.1 "
                      f"content-root algorithm {list(CONTENT_ROOT_ALGS)}")
    digest = obj.get("digest")
    if not (isinstance(digest, str) and _SHA256_HEX.match(digest)):
        errors.append(f"{path}.digest must be 64 lowercase hex chars (sha-256)")


def validate_relationships(value: Any) -> list[str]:
    """Return a list of human-readable errors; **empty list == valid**. Fail-closed.

    This function RETURNS its findings, it does NOT raise — do NOT wrap it in
    ``try/except`` (a caller that treats "no exception" as "valid" reports a malformed
    block as valid). Use :func:`require_valid_relationships` for the raising form.
    """
    errors: list[str] = []
    if not isinstance(value, list):
        return ["relationships must be a JSON array of edge objects"]
    if not value:
        errors.append("relationships must not be an empty array (omit the field instead)")
    if len(value) > MAX_EDGES_PER_RECEIPT:
        errors.append(f"relationships carries {len(value)} edges > hard cap {MAX_EDGES_PER_RECEIPT}")
    for i, edge in enumerate(value):
        path = f"relationships[{i}]"
        if not isinstance(edge, dict):
            errors.append(f"{path} must be a JSON object")
            continue
        unknown = sorted(set(edge) - set(_EDGE_ALLOWED))
        if unknown:
            errors.append(f"{path} unknown field(s) {unknown} (fail-closed)")
        for req in _EDGE_REQUIRED:
            if req not in edge:
                errors.append(f"{path}.{req} is required")
        relation = edge.get("relation")
        if "relation" in edge and relation not in RELATIONS:
            errors.append(f"{path}.relation {relation!r} is not in the closed vocabulary "
                          f"{list(RELATIONS)} (extension only via spec change)")
        if "targetReceiptDigest" in edge:
            _validate_edge_digest(edge["targetReceiptDigest"], f"{path}.targetReceiptDigest", errors)
        if "targetSubjectDigest" in edge:
            _validate_edge_digest(edge["targetSubjectDigest"], f"{path}.targetSubjectDigest", errors)
        if "reasonCode" in edge and edge.get("reasonCode") not in REASON_CODES:
            errors.append(f"{path}.reasonCode {edge.get('reasonCode')!r} not in {list(REASON_CODES)}")
        if "reason" in edge and not isinstance(edge.get("reason"), str):
            errors.append(f"{path}.reason must be a string")
        if "declaredAt" in edge and not (isinstance(edge.get("declaredAt"), str)
                                         and _RFC3339_Z.match(edge["declaredAt"])):
            errors.append(f"{path}.declaredAt must be RFC3339 with a trailing Z")
    return errors


def require_valid_relationships(value: Any) -> None:
    """Raise :class:`RelationProfileError` on the first invalid relationships block."""
    errors = validate_relationships(value)
    if errors:
        raise RelationProfileError("; ".join(errors))


# ── Verification (pure, offline, fail-closed) ──────────────────────────────────
#
# The caller attaches candidate target receipts (`--with-related`) and pre-verifies each
# one STANDALONE with the existing machinery; this module never re-implements crypto. An
# attached target is described by an AttachedTarget mapping:
#     {"verified": bool,                     # target verified standalone (its own crypto)
#      "relationships": list | None}         # the target's OWN edges (for the chain walk)
# keyed by its content-root hex in `related`.

def _edge_target_hex(edge: dict) -> str | None:
    tgt = edge.get("targetReceiptDigest")
    if isinstance(tgt, dict) and isinstance(tgt.get("digest"), str):
        return tgt["digest"]
    return None


def verify_relationship_edges(
    relationships: Any,
    related: dict[str, dict] | None = None,
    *,
    subject_hex: str | None = None,
    max_depth: int = MAX_CHAIN_DEPTH,
) -> dict:
    """Evaluate the relation/v0.1 edges of ONE receipt against attached targets.

    Returns (never raises on malformed input — fail-closed result instead)::

        {"lineage": VERIFIED|DECLARED_UNRESOLVED|FAIL|NOT_EVALUATED,
         "edges": [{"relation", "targetDigest", "resolution", "errors": [...]}, ...],
         "errors": [...]}

    Per-edge resolution:
      VERIFIED             target attached AND verified standalone AND digest names it.
      DECLARED_UNRESOLVED  edge well-formed, target not attached — explicitly NOT an
                           error, but never more than "declared".
      FAIL                 structural error, unknown relation, cycle, depth exceeded,
                           or an attached target that does NOT verify.

    Aggregate `lineage`: FAIL if any edge FAILs; else DECLARED_UNRESOLVED if any edge is
    unresolved; else VERIFIED (>=1 edge verified); NOT_EVALUATED when no profile present.
    The aggregate NEVER upgrades any other verdict — wiring into cryptoValid is forbidden.
    """
    related = related if isinstance(related, dict) else {}
    if relationships is None:
        return {"lineage": LINEAGE_NOT_EVALUATED, "edges": [], "errors": []}

    structural = validate_relationships(relationships)
    if structural:
        return {"lineage": LINEAGE_FAIL, "edges": [],
                "errors": [f"relation:malformed:{e}" for e in structural]}

    edges_out: list[dict] = []
    errors: list[str] = []
    any_fail = False
    any_unresolved = False
    any_verified = False

    for i, edge in enumerate(relationships):
        target_hex = _edge_target_hex(edge)
        entry = {"relation": edge.get("relation"), "targetDigest": target_hex,
                 "resolution": LINEAGE_DECLARED_UNRESOLVED, "errors": []}
        # Self-reference is a degenerate cycle (a receipt can never be its own ancestor).
        if subject_hex is not None and target_hex == subject_hex:
            entry["resolution"] = LINEAGE_FAIL
            entry["errors"].append("relation:cycle: edge targets the receipt itself")
        elif target_hex in related:
            target = related[target_hex]
            if not isinstance(target, dict):
                entry["resolution"] = LINEAGE_FAIL
                entry["errors"].append("relation:attached_target_malformed")
            elif target.get("verified") is not True:
                # Fail-closed: an ATTACHED target that does not verify standalone is a
                # hard FAIL (present-and-wrong), unlike an absent one (declared-only).
                entry["resolution"] = LINEAGE_FAIL
                entry["errors"].append("relation:target_verification_failed")
            else:
                cycle_or_depth = _walk_chain(target_hex, related,
                                             seen=({subject_hex} if subject_hex else set()),
                                             max_depth=max_depth)
                if cycle_or_depth:
                    entry["resolution"] = LINEAGE_FAIL
                    entry["errors"].append(cycle_or_depth)
                else:
                    entry["resolution"] = LINEAGE_VERIFIED
        # else: stays DECLARED_UNRESOLVED — no error, no PASS upgrade.

        if entry["resolution"] == LINEAGE_FAIL:
            any_fail = True
        elif entry["resolution"] == LINEAGE_DECLARED_UNRESOLVED:
            any_unresolved = True
        elif entry["resolution"] == LINEAGE_VERIFIED:
            any_verified = True
        errors.extend(f"relationships[{i}]:{e}" for e in entry["errors"])
        edges_out.append(entry)

    if any_fail:
        lineage = LINEAGE_FAIL
    elif any_unresolved:
        lineage = LINEAGE_DECLARED_UNRESOLVED
    elif any_verified:
        lineage = LINEAGE_VERIFIED
    else:  # pragma: no cover — empty list is structurally rejected above
        lineage = LINEAGE_NOT_EVALUATED
    return {"lineage": lineage, "edges": edges_out, "errors": errors}


def _walk_chain(start_hex: str, related: dict[str, dict], *, seen: set,
                max_depth: int) -> str | None:
    """Walk the attached ancestry from `start_hex`; return a stable error code on a
    cycle or depth violation, else None. Absent targets terminate a path honestly
    (they are declared-only beyond the attached horizon).

    Cycle detection is PER PATH (DFS with backtracking): a diamond DAG
    (A->B, A->C, B->D, C->D) is legitimate lineage and MUST NOT report a cycle —
    only a path that revisits one of its OWN ancestors does. `proven_safe` memoizes
    subtrees so the walk stays linear in the attached set."""
    proven_safe: set[str] = set()

    def _dfs(node_hex: str, depth: int, path: set) -> str | None:
        if depth > max_depth:
            return f"relation:depth_exceeded: chain deeper than {max_depth}"
        if node_hex in path:
            return "relation:cycle: attached chain revisits a receipt on its own ancestry path"
        if node_hex in proven_safe:
            return None
        node = related.get(node_hex)
        if not isinstance(node, dict):
            proven_safe.add(node_hex)
            return None
        nested = node.get("relationships")
        if nested is None:
            proven_safe.add(node_hex)
            return None
        if validate_relationships(nested):
            return "relation:malformed_ancestor: attached target carries a malformed relationships block"
        path = path | {node_hex}
        for edge in nested:
            nxt = _edge_target_hex(edge)
            if nxt is None:
                continue
            # Traverse attached targets; an edge back onto the ancestry path (even to a
            # node that is not itself attached, e.g. the receipt under verification) is
            # a cycle and must be caught, so path members are always followed.
            if nxt in related or nxt in path:
                err = _dfs(nxt, depth + 1, path)
                if err:
                    return err
        proven_safe.add(node_hex)
        return None

    return _dfs(start_hex, 1, set(seen))


def successor_warning(_subject_relationships: Any = None, related: dict[str, dict] | None = None,
                      subject_hex: str | None = None) -> str | None:
    """Advisory (policy `reject_superseded` turns it into a blocker): if an ATTACHED,
    VERIFIED receipt declares a successor relation (supersedes/revises/corrects) OR a
    retraction (retracts) whose target is THIS receipt, the receipt under verification
    is superseded/retracted by attached material (retracts-then-use, prompt §7.6 —
    the retraction never breaks the target's crypto, it is a declared statement about it)."""
    related = related if isinstance(related, dict) else {}
    if subject_hex is None:
        return None
    for other_hex, other in related.items():
        if not isinstance(other, dict) or other.get("verified") is not True:
            continue
        nested = other.get("relationships")
        if not isinstance(nested, list) or validate_relationships(nested):
            continue
        for edge in nested:
            rel = edge.get("relation")
            if rel in SUCCESSOR_RELATIONS and _edge_target_hex(edge) == subject_hex:
                return (f"superseded_by_attached: attached receipt {other_hex[:12]}… declares "
                        f"{rel} over this receipt")
            if rel == "retracts" and _edge_target_hex(edge) == subject_hex:
                return (f"retracted_by_attached: attached receipt {other_hex[:12]}… declares "
                        f"retracts over this receipt")
    return None
