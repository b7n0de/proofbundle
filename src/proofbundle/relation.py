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

_RFC3339_Z = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z\Z")  # \A..\Z (not ^..$): $ matches before a trailing newline
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


def _edge_subject_hex(edge: dict) -> str | None:
    """The edge's OPTIONAL declared targetSubjectDigest (the successor's claim about the target's
    subject digest). Returns the 64-hex digest string or None when the field is absent/malformed.
    WP-A2/O2: when PRESENT it is gegengeprueft against the resolved target's real subject digest."""
    tgt = edge.get("targetSubjectDigest")
    if isinstance(tgt, dict) and isinstance(tgt.get("digest"), str):
        return tgt["digest"]
    return None


def _target_subject_pin_error(edge: dict, target: dict) -> str | None:
    """PB-2026-0717-01 fail-closed subject-pin gate.

    When the successor edge DECLARES a ``targetSubjectDigest`` (an optional pin), the resolved
    target MUST expose a PRESENT, UNAMBIGUOUS, well-formed actual subject digest that EQUALS the
    declared value; otherwise the edge FAILs with a stable, Python/Rust-identical wire code. Before
    3.6.1 a declared pin against an absent/null/malformed/ambiguous actual subject fell through to
    VERIFIED (False Accept — PB-2026-0717-01). An ABSENT declared pin returns None (optional field,
    no wire-break). The only unchanged accept path is ``present`` AND ``equal``.

    Robust by construction: the resolver (:func:`proofbundle.cli._load_related`) annotates
    ``subject_digest_state`` (``present``/``absent``/``ambiguous``/``malformed``); when that field
    is missing (target dict built by an older/foreign caller) the state is INFERRED fail-closed from
    the actual value (``None`` -> absent, non-64-hex -> malformed). Weakening evidence can therefore
    only move present -> absent/malformed = PASS -> FAIL, never FAIL -> PASS (metamorphic monotonicity)."""
    declared = _edge_subject_hex(edge)
    if declared is None:
        return None  # optional field absent — declared-only semantics unchanged
    actual = target.get("subject_digest")
    state = target.get("subject_digest_state")
    if state is None:  # fail-closed inference for un-annotated target dicts
        if actual is None:
            state = "absent"
        elif isinstance(actual, str) and _SHA256_HEX.match(actual):
            state = "present"
        else:
            state = "malformed"
    # An explicit resolver state wins over the None-inference; only a well-formed, present, EQUAL
    # actual subject verifies. The order matters: a "malformed" target carries subject_digest=None
    # too, so classify on the state first, never on the None-ness of the value.
    if state == "ambiguous":
        return (f"relation:target_subject_ambiguous ({CODE_RELATION_TARGET_SUBJECT_AMBIGUOUS}): "
                "resolved target exposes multiple subjects; a declared targetSubjectDigest cannot "
                "bind an ambiguous subject")
    if state == "absent":
        return (f"relation:target_subject_missing ({CODE_RELATION_TARGET_SUBJECT_MISSING}): "
                "declared targetSubjectDigest but the resolved target exposes no subject digest")
    if state == "malformed" or not (isinstance(actual, str) and _SHA256_HEX.match(actual)):
        return (f"relation:target_subject_malformed ({CODE_RELATION_TARGET_SUBJECT_MALFORMED}): "
                "resolved target subject digest is not a well-formed sha-256")
    if declared != actual:
        return (f"relation:target_subject_mismatch ({CODE_RELATION_TARGET_SUBJECT_MISMATCH}): "
                "declared targetSubjectDigest does not match the resolved target's subject")
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
                    # WP-A (per-target key plumbing): expose the key the target actually verified
                    # UNDER, so relation_signer checks against the TRUE verification, never a claim.
                    entry["verified_under"] = target.get("verified_under")
                    # WP-A2 / O2 (KERNFUND) + PB-2026-0717-01 fail-closed: the targetSubjectDigest
                    # pin is binding when DECLARED — the resolved target must expose a present,
                    # unambiguous, well-formed actual subject digest EQUAL to the declared value, else
                    # FAIL (absent/null/malformed/ambiguous/unequal). Before 3.6.1 only the unequal
                    # case FAILed and absent/malformed/ambiguous fell open to VERIFIED (False Accept).
                    _subject_pin_error = _target_subject_pin_error(edge, target)
                    if _subject_pin_error is not None:
                        entry["resolution"] = LINEAGE_FAIL
                        entry["errors"].append(_subject_pin_error)
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


# ── Trust-policy `relations` evaluation (WP-A signer · WP-A2 target-pin, pure/offline) ──────────
#
# Cut as its OWN function (SPEC §8.1 forward-compat): the decision AND outcome verify paths call it,
# and the 3.5.0 standalone relation-statement verifier will call it UNCHANGED — the signer/target
# rule evaluation is never inlined into a single verify path. It NEVER touches cryptoValid; every
# violation lands ONLY in the policy verdict (lattice monotonicity). It never raises.

# Stable policy-verdict violation codes (exit-3 class, mirrored as automation blockers).
CODE_LINEAGE_REQUIREMENT_FAILED = "LINEAGE_REQUIREMENT_FAILED"
CODE_RELATION_SIGNER_UNAUTHORIZED = "RELATION_SIGNER_UNAUTHORIZED"
CODE_RELATION_TARGET_MISMATCH = "RELATION_TARGET_MISMATCH"

# Stable targetSubjectDigest-pin fail-closed codes (PB-2026-0717-01). Identical strings in the Rust
# verifier so the Python/Rust parity vectors have a defined Sollwert. MISMATCH pre-dates 3.6.1 (a
# present-but-wrong actual subject); MISSING/AMBIGUOUS/MALFORMED are the 3.6.1 fail-closed additions.
CODE_RELATION_TARGET_SUBJECT_MISMATCH = "RELATION_TARGET_SUBJECT_MISMATCH"
CODE_RELATION_TARGET_SUBJECT_MISSING = "RELATION_TARGET_SUBJECT_MISSING"
CODE_RELATION_TARGET_SUBJECT_AMBIGUOUS = "RELATION_TARGET_SUBJECT_AMBIGUOUS"
CODE_RELATION_TARGET_SUBJECT_MALFORMED = "RELATION_TARGET_SUBJECT_MALFORMED"


def _keys_equal(a_b64: str | None, b_b64: str | None) -> bool:
    """Byte-equality of two base64 Ed25519 keys AFTER decode — never a string/keyId compare (the
    formal keyid-alias gegenmodell, 2026-07-15: two different b64 encodings, or a keyId alias, must
    never read as the same key). Fail-closed: an undecodable value is never equal to anything."""
    import base64  # noqa: PLC0415
    if not isinstance(a_b64, str) or not isinstance(b_b64, str):
        return False
    try:
        ra = base64.b64decode(a_b64, validate=True)
        rb = base64.b64decode(b_b64, validate=True)
    except (ValueError, TypeError):
        return False
    return len(ra) == 32 and ra == rb


def evaluate_relations_policy(relations_section: Any, lineage_result: dict, *,
                              successor_key_b64: str | None) -> list[dict]:
    """Apply the load_policy-validated trust-policy ``relations`` section over an already-computed
    ``lineage_result`` (from :func:`verify_relationship_edges`).

    ``successor_key_b64`` is the base64 verify key of the receipt UNDER verification — the issuer of
    the successor edge; relation_signer binds THIS key (never the target's, never a claim).

    Returns a list of ``{"code", "message"}`` violations — empty means the policy is satisfied. Codes:
    ``LINEAGE_REQUIREMENT_FAILED`` (require_relation_resolution / reject_superseded),
    ``RELATION_SIGNER_UNAUTHORIZED`` (relation_signer), ``RELATION_TARGET_MISMATCH``
    (require_relation_target). Pure, offline, never raises.

    ``reject_superseded`` DOUBLE MEANING (cross-reference): here it blocks a receipt over which an
    ATTACHED, verified successor is declared (the ``supersededByAttached`` warning — an EXTERNAL
    statement pointing AT this receipt). The standalone relation-statement path
    (:func:`relation_statement.verify_relation_statement`, SPEC §2.5) reuses the SAME flag for a
    SECOND, disjoint case: the statement's OWN verified supersedes/revises/corrects edge (a
    self-assertion) — same policy code, different subject. ``reject_retracted`` is the retracts sibling,
    standalone-only. Both extensions live in ``relation_statement`` and are NOT evaluated here."""
    out: list[dict] = []
    if not isinstance(relations_section, dict):
        return out
    edges = lineage_result.get("edges") if isinstance(lineage_result, dict) else None
    edges = edges if isinstance(edges, list) else []

    # (1) require_relation_resolution — a named relation that APPEARS as an edge must VERIFY.
    req = relations_section.get("require_relation_resolution") or []
    for e in edges:
        if e.get("relation") in req and e.get("resolution") != LINEAGE_VERIFIED:
            out.append({"code": CODE_LINEAGE_REQUIREMENT_FAILED,
                        "message": (f"relation {e.get('relation')!r} must resolve (target attached "
                                    f"and verified), got {e.get('resolution')}")})

    # (2) reject_superseded — an attached, verified successor/retractor over THIS receipt.
    if relations_section.get("reject_superseded") and lineage_result.get("supersededByAttached"):
        out.append({"code": CODE_LINEAGE_REQUIREMENT_FAILED,
                    "message": f"reject_superseded: {lineage_result['supersededByAttached']}"})

    # (3) relation_signer (WP-A) — the SUCCESSOR issuer key must satisfy the per-relation rule.
    signer = relations_section.get("relation_signer") or {}
    for e in edges:
        rule = signer.get(e.get("relation"))
        if not isinstance(rule, dict):
            continue
        mode = rule.get("mode")
        if mode == "pinned":
            keys = rule.get("keys") or []
            if not any(_keys_equal(successor_key_b64, k) for k in keys):
                out.append({"code": CODE_RELATION_SIGNER_UNAUTHORIZED,
                            "message": (f"relation {e.get('relation')!r}: successor issuer key is not "
                                        "a member of the pinned relation_signer set")})
        elif mode == "same-key":
            # same-key can only be confirmed against a RESOLVED target's real verify key; absence on a
            # DECLARED-ONLY edge is the resolution pin's job, not the signer's (no false unauthorized there).
            # PB-2026-0717-04 fail-closed: once an edge is VERIFIED (target resolved), same-key REQUIRES a
            # present verified_under that byte-matches the successor key. A VERIFIED edge with a missing/None
            # verified_under is a fail-open footgun in the direct related-API path (the CLI loader always sets
            # it) — treat it as unauthorized, never as satisfied.
            if e.get("resolution") == LINEAGE_VERIFIED:
                vu = e.get("verified_under")
                if vu is None or not _keys_equal(successor_key_b64, vu):
                    out.append({"code": CODE_RELATION_SIGNER_UNAUTHORIZED,
                                "message": (f"relation {e.get('relation')!r}: same-key requires a target "
                                            "verified_under that byte-matches the successor key; got "
                                            f"{'none' if vu is None else 'a differing key'}")})

    # (4) require_relation_target (WP-A2 / O1) — a named relation's edge must resolve to one of the
    #     RP-pinned parent roots. Fires on EVERY such edge, accept-path (T2) included — this is the
    #     decoy-parent fix: a valid-but-WRONG parent is rejected here, never in crypto.
    target_pin = relations_section.get("require_relation_target") or {}
    for e in edges:
        pinned = target_pin.get(e.get("relation"))
        if pinned is None:
            continue
        allowed = pinned if isinstance(pinned, list) else [pinned]
        if e.get("targetDigest") not in set(allowed):
            out.append({"code": CODE_RELATION_TARGET_MISMATCH,
                        "message": (f"relation {e.get('relation')!r}: edge resolves to parent "
                                    f"{str(e.get('targetDigest'))[:12]}… which is not in the pinned "
                                    "require_relation_target set (decoy/wrong parent)")})
    return out
