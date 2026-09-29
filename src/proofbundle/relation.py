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

from .budget import render_keys_safe
from .canonical import _pruefkopie, _zeichen_von
from .errors import ProofBundleError
from ._membership import is_member, stored_str_items, type_name
from ._wire_b64 import decode_b64

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

# \A..\Z (not ^..$): $ matches before a trailing newline. [0-9], not \d: in a str pattern \d is every Unicode
# decimal digit, so an Arabic-Indic year or Devanagari seconds passed here while the Rust verifier
# (tools/pb_verify_rs, is_rfc3339_z) takes ASCII digits only, and the same bytes got two verdicts.
_RFC3339_Z = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z\Z")
_SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")  # \Z (not $) — $ matches before a trailing newline

_EDGE_REQUIRED = ("relation", "targetReceiptDigest")
_EDGE_ALLOWED = ("relation", "targetReceiptDigest", "targetSubjectDigest",
                 "reason", "reasonCode", "declaredAt")
_DIGEST_ALLOWED = ("digestAlgorithm", "digest")


def _as_dict(v):
    """adversarial re-audit r5 class-fix: Config-Sub-Feld als dict, sonst {} (schliesst das ``_as_dict(x.get(k))``-Loch)."""
    return v if isinstance(v, dict) else {}


def _as_list(v):
    return v if isinstance(v, (list, tuple)) else []


class RelationProfileError(ProofBundleError):
    """A relation/v0.1 relationships block is malformed (fail-closed)."""


def _validate_edge_digest(obj: Any, path: str, errors: list[str]) -> None:
    if not isinstance(obj, dict):
        errors.append(f"{path} must be an object {{digestAlgorithm, digest}}")
        return
    unknown = render_keys_safe(set(obj) - set(_DIGEST_ALLOWED))
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
    try:
        value = _pruefkopie(value)   # one reading, by what it stores (round 12)
    except ValueError as exc:
        return [f"value is not a JSON value: {exc}"]
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
        unknown = render_keys_safe(set(edge) - set(_EDGE_ALLOWED))
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
#      "relationships": list | None,         # the target's OWN edges (for the chain walk)
#      "payload_malformed": str | None}      # L4-01: the strict parser's reason when the SIGNED payload
#                                            #   is not a well-formed statement (hard FAIL at any hop)
# keyed by its content-root hex in `related`.


def _read_attached_entries(related: Any) -> list[tuple[str, Any, str | None]]:
    """The entries of a ``related`` map, each read on its own: ``(label, target, reason)``.

    ``label`` is the characters of the entry's key (`_zeichen_von`) and ``target`` the plain copy of what
    the entry stores (`_pruefkopie`), with ``reason`` None. An entry that cannot be read so, because its
    value is no JSON value or its key is no string, is ``(label, _UNREADABLE, reason)``: it is kept and
    named, never dropped, and it changes nothing about the entries beside it. A key that is no string is
    labelled ``"(no str key)"``, which no content root can equal, so no edge can name it. A value that is
    no dict holds no entries. The map is read through ``dict.items`` of the base type, so no method of
    the caller's map, key or value runs.

    Codex review of PR 300 (thread 4121924153, P1), measured on the source of 3c5755c0: the map was
    read as ONE plain copy, and a map holding one value that is no JSON value was replaced by an empty
    map. One unreadable sibling such as ``{"irrelevant": object()}`` then hid a verified retraction from
    ``supersededByAttached``, so ``reject_superseded`` raised nothing, and turned a direct edge to an
    attached target that does not verify from FAIL into DECLARED_UNRESOLVED."""
    if not issubclass(type(related), dict):
        return []
    entries: list[tuple[str, Any, str | None]] = []
    for key, value in list(dict.items(related)):
        label = _zeichen_von(key)
        if label is None:
            entries.append(("(no str key)", _UNREADABLE,
                            f"its key is a value of type {type_name(key)}, not a string"))
            continue
        try:
            entries.append((label, _pruefkopie(value), None))
        except ValueError as exc:
            entries.append((label, _UNREADABLE, str(exc)))
    return entries


def _attached_targets(entries: list[tuple[str, Any, str | None]]) -> dict[str, Any]:
    """The targets an edge can name, by label, from `_read_attached_entries`. An unreadable entry stays
    `_UNREADABLE`, so an edge that names it FAILs as an attached target that is malformed. Two entries
    whose keys hold the same characters are one JSON key, and which of the two the caller meant is
    unknown, so that label holds `_UNREADABLE` as well: it never resolves an edge."""
    targets: dict[str, Any] = {}
    for label, target, _reason in entries:
        targets[label] = _UNREADABLE if label in targets else target
    return targets


def _related_abgelehnt(related: Any) -> str | None:
    """The refusal of a ``related`` that is neither None nor a dict, or None (deep gate at 7409b123, L4-620b-01).

    A ``related`` that is a Mapping but no dict (``collections.UserDict``, ``types.MappingProxyType``,
    ``collections.ChainMap``), a list of pairs or any other value was read as a map with no entries: the lineage
    block was skipped, an attached verified retraction was never seen, and ``reject_superseded`` passed. The
    three verifiers and this module's engine refuse it now, fail-closed, as a ``policy`` that is no dict is
    refused. The text is the lineage error and the ``supersededByAttached`` value, so ``reject_superseded`` names
    it too. Only the relying party's own object can be such a value (the ``--with-related`` resolver builds a
    dict), and nothing of it is read: only its type is named, by `_membership.type_name`."""
    if related is None or issubclass(type(related), dict):
        return None
    return (f"relation:related_malformed: related must be a JSON object mapping a content root to its attached "
            f"target, got a value of type {type_name(related)}; it is refused, never read as no attached "
            "targets (fail-closed)")


def _carries_attached_entries(related: Any) -> bool:
    """Whether ``related`` holds any attached entry, read from what the map stores (``dict.__len__`` of
    the base type), never through the caller's own ``__len__`` or ``__bool__``. A value that is neither None
    nor a dict counts as carrying entries, so the verifiers run the lineage step, which refuses it
    (`_related_abgelehnt`).

    The decision and outcome verifiers asked ``if "relationships" in predicate or related``: the
    caller's map answered through its own ``__bool__``. Measured 2026-09-28 on main 86671552 and on
    D4: a ``dict`` subclass whose ``__len__`` is 0, holding a verified retraction of the subject,
    skipped the lineage block, so ``reject_superseded`` never saw the retraction and both verifiers
    answered ``ok`` True, where the plain dict with the same entry answers ``ok`` False."""
    if related is None:
        return False
    return not issubclass(type(related), dict) or dict.__len__(related) > 0


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
    # One reading of the attached targets, by what they store (round 12): the plain copy, so the
    # targets judged below are not answered by a dict subclass's own `get` and `__contains__`. Each
    # entry is read on its own (`_read_attached_entries`, Codex review of PR 300, thread 4121924153):
    # an entry that cannot be read is kept as `_UNREADABLE`, an edge that names it FAILs, and
    # `successor_warning` names it, but it never clears the entries beside it. A `related` that is neither None
    # nor a dict is refused (`_related_abgelehnt`, deep gate at 7409b123, L4-620b-01): it was read as no
    # targets, and a verified retraction it held was never seen.
    abgelehnt = _related_abgelehnt(related)
    if abgelehnt is not None:
        return {"lineage": LINEAGE_FAIL, "edges": [], "errors": [abgelehnt], "supersededByAttached": abgelehnt}
    attached_entries = _read_attached_entries(related)
    related = _attached_targets(attached_entries)
    # R7-1 (3.6.3 never-raise residual): coerce a non-str subject_hex at entry. A truthy unhashable
    # value ([1]/{1:2}/{1,2}/bytearray) crashed the ``{subject_hex}`` seed in the resolved-edge branch
    # (TypeError: unhashable type). A non-str hex can never legitimately equal a str target_hex, so
    # None is the correct fail-closed coercion (self-reference check + cycle seed both stay honest).
    # A `str` subclass is read as its characters (round 12).
    subject_hex = _zeichen_von(subject_hex)
    # DER SCHLUESSEL WIRD HIER GESETZT, NICHT BEIM AUFRUFER (deep gate Lauf 7, Fund L4-600-02, P1).
    #
    # WAS WAR: `supersededByAttached` fuellten die AUFRUFER — decision.py:682 und outcome.py:673 taten
    # es, relation_statement.py nicht. Der Arm in evaluate_relations_policy (unten, (2)) liest genau
    # diesen Schluessel, und deshalb war `reject_superseded` auf der Statement-Flaeche fuer den
    # ANGEHAENGTEN Fall wirkungslos: die Flaeche nimmt die Flagge entgegen und konnte sie nie
    # behaupten. Der unabhaengige Zeuge war der Rust-Verifizierer, der den Schluessel in BEIDEN Modi
    # setzt (tools/pb_verify_rs/src/main.rs:1482) — Python endete mit 0, wo Rust mit 3 endet.
    #
    # DIE KLASSE, nicht die Instanz: drei Aufrufer, dreimal derselbe Dreizeiler, einer davon fehlte.
    # Eine Pflicht, die an der Disziplin des Aufrufers haengt, wird irgendwann vergessen — der vierte
    # Aufrufer haette sie genauso vergessen koennen. Diese Funktion bekommt `related` und
    # `subject_hex` ohnehin, also gehoert der Schluessel in IHRE Rueckgabe. Danach KANN ihn kein
    # Aufrufer mehr auslassen, weil er ihn nicht mehr selbst setzt.
    #
    # `successor_warning` haengt NICHT an den eigenen Kanten — sein erster Parameter heisst
    # `_subject_relationships` und wird nicht gelesen. Deshalb traegt auch der NOT_EVALUATED-Zweig den
    # Schluessel: ein angehaengter Nachbar kann eine Ruecknahme ueber dieses Objekt erklaeren, auch
    # wenn das Objekt selbst gar keine Kante hat. Die Richtung ist monoton: der Schluessel kann eine
    # Politik-Verletzung nur HINZUFUEGEN, nie eine entfernen.
    #
    # Die Aufrufer, die ihn heute selbst setzen, ueberschreiben ihn mit demselben Wert — ein
    # No-Op. Ihre Zeilen zu entfernen ist die Nacharbeit, nicht die Bedingung dieser Haertung.
    _sba = _successor_warning_over(attached_entries, subject_hex)
    if relationships is None:
        return {"lineage": LINEAGE_NOT_EVALUATED, "edges": [], "errors": [],
                "supersededByAttached": _sba}

    # Structural budget (deep gate wf_cfe249d0-ee8, finding L2-01, P1). A DIRECT-DICT surface — the caller
    # hands over an already-parsed structure, so loads_strict's input_bytes cap never runs here.
    #
    # This module looked bounded and is the clearest case of why "a bound" is not "the bounds":
    # MAX_EDGES_PER_RECEIPT caps the edge COUNT and _SHA256_HEX pins every digest to 64 chars — but the cap
    # is reported by validate_relationships only AFTER it has walked the entire list, and ``reason`` is an
    # unbounded free-text string on every edge. A ten-million-element list is therefore fully iterated
    # before its own cap is reported, and 64 edges each carrying a 100 MB reason pass the count cap
    # entirely. Size and count are different dimensions.
    #
    # The bound runs BEFORE validate_relationships for exactly that reason. It is reported as a fail-closed
    # RESULT, never raised: this function's contract is "never raises on malformed input — fail-closed
    # result instead", and a budget refusal is malformed input like any other.
    from ._strict_json import enforce_structural_budget  # noqa: PLC0415 - local import avoids an import cycle
    try:
        enforce_structural_budget(relationships)
    except ProofBundleError as exc:
        return {"lineage": LINEAGE_FAIL, "edges": [],
                "errors": [f"relation:over_budget: relationships exceed the verification budget "
                           f"(fail-closed): {exc}"],
                "supersededByAttached": _sba}

    # The edges are read once as well, into the plain copy of what they store (round 12); the
    # validator and the loop below read that copy.
    try:
        relationships = _pruefkopie(relationships)
    except ValueError as exc:
        return {"lineage": LINEAGE_FAIL, "edges": [],
                "errors": [f"relation:malformed:relationships are not a JSON value: {exc}"],
                "supersededByAttached": _sba}
    structural = validate_relationships(relationships)
    if structural:
        return {"lineage": LINEAGE_FAIL, "edges": [],
                "errors": [f"relation:malformed:{e}" for e in structural],
                "supersededByAttached": _sba}

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
        elif target_hex is not None and target_hex in related:
            target = related[target_hex]
            if not isinstance(target, dict):
                entry["resolution"] = LINEAGE_FAIL
                entry["errors"].append("relation:attached_target_malformed")
            elif _target_payload_malformed(target) is not None:
                # L4-01: the resolver could not parse the target's SIGNED payload strictly. That is a
                # finding about the target (its bytes fail standalone), never "no edges, subject absent".
                entry["resolution"] = LINEAGE_FAIL
                entry["errors"].append(_target_payload_malformed(target))
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
    return {"lineage": lineage, "edges": edges_out, "errors": errors,
            "supersededByAttached": _sba}


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
        # NOT attached -> the path ends honestly beyond the attached horizon (declared-only).
        # This must stay distinguishable from "attached but malformed": `related.get()` returns
        # None for both, so membership is the question, never the value's truthiness.
        if node_hex not in related:
            proven_safe.add(node_hex)
            return None
        node = related[node_hex]
        # ── DISTANCE INVARIANCE OF RELATION GATES (deep-gate finding L4-01, P1) ──────────────
        #
        # Every gate the direct-edge arm of verify_relationship_edges applies to the receipt's
        # OWN edge must also apply to every ancestor edge whose target is ATTACHED. Before this,
        # the walk adjudicated ancestor SYNTAX (malformed_ancestor below) and skipped ancestor
        # CRYPTO entirely: a cryptographically forged receipt placed at hop >= 2 yielded
        # lineage=VERIFIED and safeForAutomation=true. The gate was distance-scoped, and the
        # distance is attacker-chosen — the presenter simply inserts one self-signed hop.
        #
        # Measured by the gate on d3401a7 in Python AND in the Rust verifier. No existing chain
        # test caught it because every one of them hardcodes "verified": True on every ancestor,
        # so the property was untested in both languages.
        #
        # Three gates, mirroring lines 279-306 one to one:
        if not isinstance(node, dict):
            return ("relation:ancestor_attached_target_malformed: an ATTACHED ancestor is not a "
                    "well-formed target object (present-and-wrong is a hard FAIL at any hop)")
        # L4-01 (deep gate 2026-09-05): the SAME payload gate as on the receipt's own edge, at every hop.
        # A malformed payload used to arrive here as "verified, relationships=None" and end the path
        # honestly at the horizon — exactly the hop an attacker inserts to hide a failing ancestor.
        _payload_err = _target_payload_malformed(node)
        if _payload_err is not None:
            return f"relation:ancestor_edge: {_payload_err}"
        if node.get("verified") is not True:
            return ("relation:ancestor_verification_failed: an ATTACHED ancestor does not verify "
                    "standalone (present-and-wrong is a hard FAIL at any hop, exactly as for the "
                    "receipt's own edge)")
        nested = node.get("relationships")
        if nested is None:
            proven_safe.add(node_hex)
            return None
        if validate_relationships(nested):
            return "relation:malformed_ancestor: attached target carries a malformed relationships block"
        path = path | {node_hex}
        # A CYCLE IS ORDER-INDEPENDENT, so it is decided before any descent.
        #
        # The loop below returns on the FIRST error it meets while walking the sibling edges in
        # list order. Once the ancestor gates above exist, an unverified sibling listed BEFORE a
        # back-edge would mask the cycle — the run would still FAIL, but with a code that depends
        # on the order the issuer happened to write the edges in. That is the same
        # "verdict depends on position" shape as the finding this fix answers, one level down.
        # Detecting the back-edge first makes the cycle code independent of sibling order.
        for edge in nested:
            nxt = _edge_target_hex(edge)
            if nxt is not None and nxt in path:
                return "relation:cycle: attached chain revisits a receipt on its own ancestry path"
        for edge in nested:
            nxt = _edge_target_hex(edge)
            if nxt is None:
                continue
            # The subject pin binds at EVERY hop, not only on the receipt's own edge: a declared
            # targetSubjectDigest against an absent/ambiguous/malformed/unequal actual subject is
            # the same false-accept one hop further out. The wire code is preserved verbatim so
            # Python/Rust parity vectors keep their Sollwert; only the position is named.
            if nxt in related and isinstance(related[nxt], dict):
                _pin = _target_subject_pin_error(edge, related[nxt])
                if _pin is not None:
                    return f"relation:ancestor_edge: {_pin}"
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
    the retraction never breaks the target's crypto, it is a declared statement about it).

    Each entry of ``related`` is read on its own (`_read_attached_entries`): an entry that cannot be
    read is named with ``relation:malformed_successor`` unless a readable entry declares such a
    relation, and it never hides the entries beside it. A ``related`` that is neither None nor a dict is
    named with its refusal (`_related_abgelehnt`), never read as no attached receipts."""
    abgelehnt = _related_abgelehnt(related)
    if abgelehnt is not None:
        return abgelehnt
    return _successor_warning_over(_read_attached_entries(related), subject_hex)


def _successor_warning_over(entries: list[tuple[str, Any, str | None]], subject_hex: Any) -> str | None:
    """`successor_warning` over the entries `_read_attached_entries` read. `verify_relationship_edges`
    passes the entries it resolves its edges against, so the caller's map is read once there."""
    if subject_hex is None:
        return None
    # OWNER-ANORDNUNG 2026-09-08 (Karte OA-dccd141d78), deep gate Lauf 5 Fund L4-600-01 (P1).
    #
    # WAS HIER STAND: `if not isinstance(nested, list) or validate_relationships(nested): continue`
    # — ein STILLES Ueberspringen. Ein angehaengtes, kryptografisch verifiziertes Receipt, dessen
    # eigener relationships-Block einen Formfehler traegt, fiel damit aus der Betrachtung, UND MIT
    # IHM DIE RUECKNAHME, DIE ES DEKLARIERT. Der Angreifer haengt neben die `retracts`-Kante eine
    # zweite, absichtlich fehlerhafte Kante; `validate_relationships` meldet einen Fehler, die
    # Schleife geht weiter, `successor_warning` liefert None — und die ganze Kette dahinter
    # (supersededByAttached -> reject_superseded -> policy_ok -> safeForAutomation -> exit 3)
    # kippt lautlos in die freundliche Richtung: safeForAutomation false->true, exit 3->0.
    # In Python UND Rust identisch, weshalb das Differential zwischen beiden blind war: beide
    # Seiten machten denselben Fehler, und ein Vergleich zweier gleicher Fehler ist still.
    #
    # DIE UNTERSCHEIDUNG, auf die es ankommt: ein Receipt OHNE relationships-Feld hat schlicht
    # nichts erklaert — das ist kein Fund und wird weiter uebersprungen. Ein Receipt MIT einem
    # Feld, das nicht lesbar ist, hat etwas erklaert, das wir nicht auswerten koennen; das ist ein
    # eigener, benannter Zustand und niemals Schweigen. Fail-closed heisst hier: eine nicht
    # auswertbare Erklaerung wird wie eine Rueck nahme behandelt, nicht wie ihre Abwesenheit.
    #
    # ORDNUNG, damit das Verdikt nicht an der Reihenfolge haengt (dieselbe Regel, die _walk_chain
    # fuer Zyklen schon anwendet: "A CYCLE IS ORDER-INDEPENDENT, so it is decided before any
    # descent"): ZUERST werden alle Kandidaten auf eine ECHTE, lesbare Rueck nahme/Nachfolge
    # geprueft; erst wenn es keine gibt, meldet der unlesbare Block. Ein malformed Nachbar kann
    # eine echte Rueck nahme also nicht mehr maskieren, und `related` ist ein dict, dessen
    # Einfuegereihenfolge der Angreifer sonst mitbestimmen wuerde.
    # Der unlesbare Kandidat wird ORDNUNGSUNABHAENGIG gewaehlt (kleinster Hex), nicht "der erste".
    # Grund ist die Paritaet mit dem Rust-Verifizierer: der iteriert eine HashMap, deren Reihenfolge
    # in Rust bewusst randomisiert ist. "Der erste" haette dort bei mehreren unlesbaren Nachbarn je
    # Lauf einen anderen Text ergeben, waehrend Pythons dict die Einfuegereihenfolge behaelt — zwei
    # Sprachen, zwei Antworten, und der Unterschied haette nach einem Fund ausgesehen, der keiner ist.
    unlesbar: str | None = None
    unlesbar_hex: str | None = None
    for other_hex, other, reason in entries:
        if other is _UNREADABLE:
            # An entry that cannot be read (Codex review of PR 300, thread 4121924153): whether it
            # declares a retraction or supersession over this receipt is unknown, so it is named and
            # never skipped, and it is named only when no readable entry declares one. Only the relying
            # party's own object can hold such an entry (the `--with-related` resolver builds every entry
            # from a parsed file), so no third party can use it to mark a receipt. The smallest label,
            # then the smallest text, is chosen, so the answer does not depend on the order of the map.
            shown = other_hex if len(other_hex) <= 12 else other_hex[:12] + "…"
            text = (f"relation:malformed_successor ({CODE_RELATION_MALFORMED_SUCCESSOR}): attached "
                    f"entry {shown} is not a JSON value this verifier can read ({str(reason)[:80]}); a "
                    "retraction or supersession declared in it cannot be evaluated and is therefore NOT "
                    "ruled out (fail-closed — an unreadable statement about this receipt is never silence)")
            if unlesbar_hex is None or unlesbar is None or (other_hex, text) < (unlesbar_hex, unlesbar):
                unlesbar_hex = other_hex
                unlesbar = text
            continue
        if not isinstance(other, dict):
            continue
        # EIN UNLESBARER PAYLOAD IST NICHT DASSELBE WIE EINE UNGUELTIGE SIGNATUR (Lauf 8, beim
        # Schliessen von L4-800-01 am Nachbar-Arm gemessen). `verified` traegt seit dem L4-01-Fix
        # vom 05.09. ZWEI Bedeutungen: "Signatur haelt" UND "Payload lesbar" — der Aufloeser setzt
        # es fuer beides auf False. Diese Schleife las es fuer die erste, und damit fiel ein
        # Nachbar mit unlesbarem Payload STUMM aus der Betrachtung, mitsamt der Ruecknahme, die er
        # erklaert. GEMESSEN, 4 von 4 Zeilen wie angesagt: ein solcher Nachbar meldete NICHTS,
        # sogar dann, wenn er eine echte `retracts`-Kante ueber unser Subjekt trug. Die Verformung
        # maskierte die Ruecknahme — genau der Fehlermodus, den der Absatz oben ausschliesst.
        #
        # Ein Nachbar mit gebrochener SIGNATUR bleibt uebersprungen: eine unsignierte Behauptung
        # ist keine Aussage ueber uns. Ein Nachbar mit unlesbarem PAYLOAD dagegen hat etwas
        # erklaert, das wir nicht auswerten koennen, und faellt in denselben unlesbar-Zweig wie ein
        # unlesbarer relationships-Block.
        _payload_kaputt = other.get("payload_malformed")
        if other.get("verified") is not True and not _payload_kaputt:
            continue
        if _payload_kaputt:
            if unlesbar_hex is None or other_hex < unlesbar_hex:
                unlesbar_hex = other_hex
                unlesbar = (
                    f"relation:malformed_successor ({CODE_RELATION_MALFORMED_SUCCESSOR}): attached "
                    f"receipt {other_hex[:12]}… carries a signed payload this verifier cannot read "
                    f"({str(_payload_kaputt)[:80]}); a retraction or supersession declared in it "
                    "cannot be evaluated and is therefore NOT ruled out (fail-closed — an "
                    "unreadable statement about this receipt is never silence)")
            continue
        nested = other.get("relationships")
        if nested is None:
            continue  # kein Block deklariert — nichts erklaert, kein Fund
        if not isinstance(nested, list) or validate_relationships(nested):
            if unlesbar_hex is None or other_hex < unlesbar_hex:
                unlesbar_hex = other_hex
                unlesbar = (
                    f"relation:malformed_successor ({CODE_RELATION_MALFORMED_SUCCESSOR}): attached "
                    f"receipt {other_hex[:12]}… verifies standalone but carries a relationships "
                    "block this verifier cannot read; a retraction or supersession declared in it "
                    "cannot be evaluated and is therefore NOT ruled out (fail-closed — an "
                    "unreadable statement about this receipt is never silence)")
            continue
        for edge in nested:
            rel = edge.get("relation")
            if is_member(rel, SUCCESSOR_RELATIONS) and _edge_target_hex(edge) == subject_hex:
                return (f"superseded_by_attached: attached receipt {other_hex[:12]}… declares "
                        f"{rel} over this receipt")
            if rel == "retracts" and _edge_target_hex(edge) == subject_hex:
                return (f"retracted_by_attached: attached receipt {other_hex[:12]}… declares "
                        f"retracts over this receipt")
    return unlesbar


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

# Deep gate 2026-09-05, finding L4-01 (P1): an ATTACHED target whose signed payload the strict parser refuses
# (duplicate key, NaN, BOM, non-canonical, not an object) is `attached_target_malformed` — a hard FAIL at
# every hop, with the same stable wire code in Python and Rust. Before this the resolver swallowed the parse
# failure into "verified, no edges, subject absent", and a chain hidden behind a duplicate `predicate` key
# walked to VERIFIED while the same bytes failed standalone (parser-differential at the resolver seam).
CODE_RELATION_TARGET_MALFORMED = "RELATION_TARGET_MALFORMED"

# OWNER-ANORDNUNG 2026-09-08 (OA-dccd141d78), deep gate Lauf 5 Fund L4-600-01 (P1): ein ATTACHED,
# standalone verifiziertes Receipt, dessen EIGENER relationships-Block nicht lesbar ist, wurde in
# successor_warning still uebersprungen — samt der Rueck nahme, die es deklariert. Der Zustand hat
# jetzt einen Namen, identisch in Python und Rust, damit die Paritaets-Vektoren einen Sollwert haben.
CODE_RELATION_MALFORMED_SUCCESSOR = "RELATION_MALFORMED_SUCCESSOR"


def _target_payload_malformed(target: dict) -> str | None:
    """The resolver's typed verdict that an attached target's PAYLOAD is not a well-formed statement.

    ``payload_malformed`` is set by :func:`proofbundle.cli._load_related` (and any foreign resolver that
    follows the AttachedTarget contract) to the strict parser's reason. A ``subject_digest_state`` of
    ``"malformed"`` alone is NOT this condition (that state also names a single subject with a bad digest,
    which is the subject-pin's business); only the explicit payload verdict FAILs the whole target."""
    reason = target.get("payload_malformed")
    if reason is None or reason is False:
        return None
    return (f"relation:attached_target_malformed ({CODE_RELATION_TARGET_MALFORMED}): an ATTACHED target's "
            f"signed payload is not a well-formed statement — {reason if isinstance(reason, str) else 'rejected'}"
            " (present-and-malformed is a hard FAIL at any hop; the same bytes fail standalone)")


def _keys_equal(a_b64: str | None, b_b64: str | None) -> bool:
    """Byte-equality of two base64 Ed25519 keys AFTER decode — never a string/keyId compare (the
    formal keyid-alias gegenmodell, 2026-07-15: two different b64 encodings, or a keyId alias, must
    never read as the same key). Fail-closed: an undecodable value is never equal to anything."""
    if not isinstance(a_b64, str) or not isinstance(b_b64, str):
        return False
    try:
        ra = decode_b64(a_b64)
        rb = decode_b64(b_b64)
    except (ValueError, TypeError):
        return False
    return len(ra) == 32 and ra == rb


class _Unreadable:
    """What a lineage result stores where it holds no JSON scalar. It is neither text nor None, so every
    rule, which reads a field by its exact type, finds it meets nothing and grants nothing, and asking
    its type runs only this class's code. `_read_attached_entries` keeps it for an attached entry that
    cannot be read: it is no dict, so an edge that names it FAILs, and `successor_warning` names it."""

    __slots__ = ()


_UNREADABLE = _Unreadable()


def _stored_scalar(value: Any) -> Any:
    """A field of a lineage result by what it stores: an exact JSON scalar as it is, a ``str`` subclass
    as the text it holds (as the plain copy reads it), anything else `_UNREADABLE`."""
    typ = type(value)
    if value is None or typ is str or typ is bool or typ is int or typ is float:
        return value
    if issubclass(typ, str):
        return str.__str__(value)
    return _UNREADABLE


def _lineage_as_stored(value: Any) -> dict:
    """A lineage result that has no plain copy, read from what it stores and running no code of the
    caller: its items under keys of type ``str`` itself (`_membership.stored_str_items`), each field by
    `_stored_scalar`, and its ``edges``, when they are a list, through ``list.copy`` of the base type,
    each edge that is a dict read the same way. A value that is not a dict is ``{}``, as the rules have
    always read it.

    Found in review of the 6.2.0 chain (PR 300 carrying PR 291): the fallback that judges such a
    result as it stands handed on the caller's object, and the rules then read it through its own
    ``get``, so a dict subclass holding one value that is no JSON value chose the edges the rules
    judged, and a stored field that is no JSON value reached `_keys_equal`, whose ``isinstance`` reads
    the value's own ``__class__``."""
    gespeichert = stored_str_items(value)
    oben = {k: _stored_scalar(v) for k, v in gespeichert.items() if k != "edges"}
    kanten: Any = gespeichert.get("edges")
    if issubclass(type(kanten), list):
        oben["edges"] = [{k: _stored_scalar(v) for k, v in stored_str_items(e).items()}
                         for e in list.copy(kanten) if issubclass(type(e), dict)]
    return oben


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
    # The three inputs are read once, by what they hold (round 12): the section and the lineage result
    # as the plain copies of what they store (a `str` subclass `resolution` answered "VERIFIED" through
    # its own `__ne__`), the successor key as its characters. A section that is no dict reads as absent;
    # a dict section holding a value that is no JSON value is refused (below). A lineage result holding
    # a value that is no JSON value is judged as it stands (PR 291,
    # which lands before this change): every rule below reads an edge's fields by their exact type, so
    # such a value fails a rule that is set and grants nothing, where reading the whole result as
    # absent let the rule pass over it. "As it stands" is what it stores (`_lineage_as_stored`), never
    # the caller's object: its own `get` would decide which edges the rules see.
    try:
        relations_section = _pruefkopie(relations_section)
    except ValueError as exc:
        # A dict section holding one value that is no JSON value is refused, as `evaluate_policy` and
        # `evaluate_decision_policy` refuse such a policy (Codex review of PR 300, thread 4121924153, the
        # neighbour on this verdict path). It was read as absent, so one unreadable entry dropped every
        # rule the section sets, `reject_superseded` among them: measured on the source of 3c5755c0,
        # `verify_outcome_receipt` reported `policy_ok` True over an attached retraction and
        # `verify_relation_statement` over an attached supersession. A boolean flag that is no bool
        # gets the loader's message, read from what the section stores.
        if issubclass(type(relations_section), dict):
            stored = stored_str_items(relations_section)
            reason = next((f"relations.{flag} must be a boolean (true/false)"
                           for flag in ("reject_superseded", "reject_retracted")
                           if flag in stored and type(stored[flag]) is not bool),
                          f"the relations section is not a JSON value: {exc}")
            return [{"code": CODE_LINEAGE_REQUIREMENT_FAILED,
                     "message": f"relations policy section rejected before evaluation (fail-closed): {reason}"}]
        relations_section = _UNREADABLE
    try:
        lineage_result = _pruefkopie(lineage_result)
    except ValueError:
        lineage_result = _lineage_as_stored(lineage_result)
    successor_key_b64 = _zeichen_von(successor_key_b64)
    if relations_section is None:
        return out
    if not isinstance(relations_section, dict):
        # A section that is present and no JSON object was read as absent, and every rule it meant was dropped:
        # the outcome and relation statement verifiers judged an attached retraction under `{"relations": [...]}`
        # with no rule and gave ok True (deep gate at 7409b123, the sweep of L4-620b-01). The loader refuses it
        # with this message; so does this evaluator now. None stays "no relations section".
        return [{"code": CODE_LINEAGE_REQUIREMENT_FAILED,
                 "message": "relations policy section rejected before evaluation (fail-closed): relations must be "
                            "a JSON object"}]
    # LAUF 14 L4 F1 (11.09.2026): `{"reject_superseeded": true}` (ein e zu viel) liess eine attached
    # Supersession unbeanstandet — die beabsichtigte Sperre war lautlos abgeschaltet. Dieselbe
    # Huellenregel wie in load_policy, aus derselben Quelle (policy._huelle_relations); ein
    # unbekannter Schluessel ist hier eine Verletzung, kein Wurf (diese Funktion wirft nie).
    from .policy import (  # noqa: PLC0415 - lokal, wie die Nachbarn
        PolicyError,
        _huelle_relations,
        _relations_felder_pruefen,
        _require_bool,
    )
    try:
        _huelle_relations(relations_section)
        # The loader's boolean rule and message for the two flags of this section (the two other
        # evaluators apply it since round 2): "false" read by its truth switched reject_superseded ON,
        # and 0 switched it off, where load_policy refuses both.
        for _flag in ("reject_superseded", "reject_retracted"):
            _require_bool(relations_section, _flag, "relations")
        # Every other field of the section by the loader's rule too (deep gate at 7409b123): a
        # require_relation_resolution that is no list, a relation_signer or require_relation_target that is
        # no dict, and a relation name out of the registry were each read as no rule here.
        _relations_felder_pruefen(relations_section)
    except PolicyError as exc:
        return [{"code": CODE_LINEAGE_REQUIREMENT_FAILED,
                 "message": f"relations policy section rejected before evaluation (fail-closed): {exc}"}]
    # R7-2b (3.6.3 adversarial re-audit sibling): coerce lineage_result at entry — a non-dict 2nd arg
    # crashed the reject_superseded branch (lineage_result.get('supersededByAttached')) which sits
    # outside the isinstance guard on the edges read below (fail-closed to {}, no violation from a
    # malformed lineage_result — a real supersededByAttached only rides on a well-formed dict).
    lineage_result = lineage_result if isinstance(lineage_result, dict) else {}
    edges = lineage_result.get("edges")
    edges = edges if isinstance(edges, list) else []
    # R7-2 (3.6.3 never-raise residual): the container is already list-coerced, but a non-dict ELEMENT
    # (5 / 'x' / None / [1]; mixed [{...},5]) crashed all three sinks below — the relation/resolution
    # loop (e.get('relation')), the signer loop (signer.get(e.get('relation'))) and the target loop
    # (target_pin.get(e.get('relation'))). Filter to dict elements once, protecting every sink.
    edges = [e for e in edges if isinstance(e, dict)]

    # (1) require_relation_resolution — a named relation that APPEARS as an edge must VERIFY.
    _req = relations_section.get("require_relation_resolution")  # adversarial re-audit round 4: non-list guard ('in')
    req = _req if isinstance(_req, (list, tuple)) else []
    # An edge's relation and resolution count only as plain strs. `lineage_result` may be the caller's, and
    # `in req` / `!=` ran the value's own __eq__/__ne__: a resolution answering "equal" met the requirement
    # without resolving (measured). A relation that is not a plain str cannot be matched against a rule, so
    # it fails any rule that is set; a required relation resolves only as the plain str VERIFIED. Values
    # that are not plain strs are never rendered.
    _not_plain = ("an edge's relation is not a plain str, so the relations policy cannot be judged on it "
                  "(fail-closed)")
    for e in edges:
        _rel, _res = e.get("relation"), e.get("resolution")
        if type(_rel) is not str:
            if req:
                out.append({"code": CODE_LINEAGE_REQUIREMENT_FAILED, "message": _not_plain})
            continue
        if _rel in req and not (type(_res) is str and _res == LINEAGE_VERIFIED):
            out.append({"code": CODE_LINEAGE_REQUIREMENT_FAILED,
                        "message": (f"relation {_rel!r} must resolve (target attached "
                                    f"and verified), got {_res if type(_res) is str else '(not a str)'}")})

    # (2) reject_superseded — an attached, verified successor/retractor over THIS receipt.
    # supersededByAttached is None or a str message. It was read by its truth, which ran the caller's own
    # __bool__ (an object saying False hid a supersession); now only None and "" are "not superseded", and
    # a value that is not a str is superseded and not rendered.
    _sba = lineage_result.get("supersededByAttached")
    if relations_section.get("reject_superseded") and _sba is not None and not (type(_sba) is str
                                                                                and _sba == ""):
        out.append({"code": CODE_LINEAGE_REQUIREMENT_FAILED,
                    "message": ("reject_superseded: " + _sba if type(_sba) is str else
                                "reject_superseded: the lineage result's supersededByAttached is not a "
                                "str (fail-closed)")})

    # (3) relation_signer (WP-A) — the SUCCESSOR issuer key must satisfy the per-relation rule.
    _signer = relations_section.get("relation_signer")  # adversarial re-audit round 4: non-dict guard (.get below)
    signer = _signer if isinstance(_signer, dict) else {}
    for e in edges:
        # R7-2b: a non-str edge['relation'] is unhashable (list/dict/set/bytearray) and crashed the
        # dict-key lookup; relations are always strings, so a non-str never names a rule (fail-closed None).
        _rel = e.get("relation")
        if signer and type(_rel) is not str:
            out.append({"code": CODE_RELATION_SIGNER_UNAUTHORIZED, "message": _not_plain})
            continue
        rule = signer.get(_rel) if type(_rel) is str else None
        if not isinstance(rule, dict):
            continue
        mode = rule.get("mode")
        if mode == "pinned":
            keys = _as_list(rule.get("keys"))
            if not any(_keys_equal(successor_key_b64, k) for k in keys):
                out.append({"code": CODE_RELATION_SIGNER_UNAUTHORIZED,
                            "message": (f"relation {_rel!r}: successor issuer key is not "
                                        "a member of the pinned relation_signer set")})
        elif mode == "same-key":
            # same-key can only be confirmed against a RESOLVED target's real verify key; absence on a
            # DECLARED-ONLY edge is the resolution pin's job, not the signer's (no false unauthorized there).
            # PB-2026-0717-04 fail-closed: once an edge is VERIFIED (target resolved), same-key REQUIRES a
            # present verified_under that byte-matches the successor key. A VERIFIED edge with a missing/None
            # verified_under is a fail-open footgun in the direct related-API path (the CLI loader always sets
            # it) — treat it as unauthorized, never as satisfied.
            # Checked unless the resolution is a plain str other than VERIFIED: `== LINEAGE_VERIFIED`
            # ran the caller's __eq__, and an object answering False skipped the key check (measured).
            _res = e.get("resolution")
            if not (type(_res) is str and _res != LINEAGE_VERIFIED):
                vu = e.get("verified_under")
                if vu is None or not _keys_equal(successor_key_b64, vu):
                    out.append({"code": CODE_RELATION_SIGNER_UNAUTHORIZED,
                                "message": (f"relation {_rel!r}: same-key requires a target "
                                            "verified_under that byte-matches the successor key; got "
                                            f"{'none' if vu is None else 'a differing key'}")})

    # (4) require_relation_target (WP-A2 / O1) — a named relation's edge must resolve to one of the
    #     RP-pinned parent roots. Fires on EVERY such edge, accept-path (T2) included — this is the
    #     decoy-parent fix: a valid-but-WRONG parent is rejected here, never in crypto.
    target_pin = _as_dict(relations_section.get("require_relation_target"))
    for e in edges:
        # R7-2b: a non-str relation is unhashable → guard the dict-key lookup (a non-str never names a pin).
        _rel = e.get("relation")
        if target_pin and type(_rel) is not str:
            out.append({"code": CODE_RELATION_TARGET_MISMATCH, "message": _not_plain})
            continue
        pinned = target_pin.get(_rel) if type(_rel) is str else None
        if pinned is None:
            continue
        # adversarial re-audit r5: nur hashbare str-Digests in die Menge; ein dict/list-Wert crasht sonst set() (unhashable).
        _cand = pinned if isinstance(pinned, list) else [pinned]
        allowed = [a for a in _cand if isinstance(a, str)]
        # R7-2b: a non-str/unhashable targetDigest crashed ``x not in set(...)`` — a non-str can never be a
        # pinned 64-hex root, so treat it as a mismatch (fail-closed decoy/wrong-parent), never a raw crash.
        _td = e.get("targetDigest")
        # type(), not isinstance(): the set membership hashed and compared the caller's own object.
        if not (type(_td) is str and _td in set(allowed)):
            out.append({"code": CODE_RELATION_TARGET_MISMATCH,
                        "message": (f"relation {_rel!r}: edge resolves to parent "
                                    f"{_td[:12] if type(_td) is str else '(not a str)'}… which is not in "
                                    "the pinned require_relation_target set (decoy/wrong parent)")})
    return out
