"""CAP-1 (draft-hillier-coverage-attestation-00) — the eight normative rules as a package function.

WHAT THIS IS. A Coverage Attestation Document states what an examination examined, what it did not,
and why — per stratum a denominator with a basis, and a unit-by-unit account with a reason drawn
from a closed set. Without that, an absence claim ("not found") is unfalsifiable: it does not
distinguish whether anyone looked.

WRITTEN FROM THE DRAFT TEXT, sections 4, 4.1, 4.2, 4.3, 5 and 6 of revision -00 (Datatracker,
retrieved 2026-09-04), plus the field names from CAP-1.schema.json (author's repository, commit
0980d32), which section 4 declares to be the normative form. The rule names are those of the
author's conformance manifest (R1-no-silent-remainder, …), so that the fifteen vectors run as tests
unchanged. The author's reference verifier was NOT read; the second independent reading in this
house is `tools/cap1_unabhaengige_umsetzung/` and stays there untouched (order, part C).

THREE PROPERTIES this module carries:
  * never-raise: `check_cap1_document` returns an error list for EVERY input, never an exception.
    A verifier that crashes on a broken document does not judge it.
  * Refusal is the only conformant answer to a violating document (draft §5); nothing is corrected,
    nothing guessed, nothing filled in.
  * Every rule stands SEPARATELY in `RULES`, so the draft's meta-test (§7.2: "eight rules, eight
    mutants, eight kills") can silence them one at a time and watch the class fall.

DUPLICATES (the clause that -01 will carry, and which originates here): JSON objects with duplicate
names are rejected at READ time, not here — this module receives an already parsed object.
`load_cap1_document` reads strictly and refuses duplicates.
"""
from __future__ import annotations

from typing import Any, TypeGuard

from ._membership import is_member

__all__ = [
    "CAP1_PROFILE", "DISPOSITIONS", "BASIS_KINDS", "HARD_DISPOSITIONS", "RULE_IDS", "RULES",
    "check_cap1_document", "is_conformant", "load_cap1_document",
]

CAP1_PROFILE = "cap/1"

#: Draft §6, the closed vocabulary. Eight values, verbatim.
DISPOSITIONS = frozenset({
    "not_applicable", "disabled_by_policy", "unsupported_input", "resource_exhausted",
    "failed", "unavailable", "out_of_scope", "withheld",
})

#: Draft §4.2, the three kinds of denominator.
BASIS_KINDS = frozenset({"catalogue", "enumeration", "declared"})

#: Draft R7: these three dispositions are incompatible with `integrity.complete = true`.
HARD_DISPOSITIONS = frozenset({"failed", "resource_exhausted", "unavailable"})

_HEX = frozenset("0123456789abcdef")


def _is_int(x: object) -> TypeGuard[int]:
    """A genuine integer. `bool` is an int subclass in Python and is not a number here.

    WHY TypeGuard AND NOT bool, measured 2026-09-15: `mypy src` reported six errors in this module,
    all of one class — a value read from parsed JSON is `Any | None`, and the checker did not see
    that `_is_int(el)` had already narrowed it to `int`. At RUNTIME every one of those places was
    correctly guarded; the only thing wrong was that the guarantee did not stand in the return type.
    With `TypeGuard[int]` the checker narrows through EVERY call site, including the ones that do
    not exist yet — six `# type: ignore` would instead have silenced exactly six places and let the
    seventh go red again."""
    return isinstance(x, int) and not isinstance(x, bool)


def _is_digest(x: object) -> bool:
    """Schema: `^[0-9a-f]{32,128}$` — the draft mandates no algorithm (§9), only the shape."""
    return isinstance(x, str) and 32 <= len(x) <= 128 and set(x) <= _HEX


def _strata(doc: dict) -> list[dict]:
    s = doc.get("strata")
    return [x for x in s if isinstance(x, dict)] if isinstance(s, list) else []


def _unexamined(s: dict) -> list[dict]:
    u = s.get("unexamined")
    return [x for x in u if isinstance(x, dict)] if isinstance(u, list) else []


def _sid(s: dict) -> str:
    sid = s.get("id")
    return sid if isinstance(sid, str) and sid else "?"


# ── the eight rules, draft §5, one function each ──────────────────────────────────────────────

def _r0_shape(doc: dict, f) -> None:
    """R0: object, profile cap/1, subject, at least one stratum, integrity with a boolean complete,
    stratum identifiers present and unique."""
    if doc.get("profile") != CAP1_PROFILE:
        f("R0-shape", "profile ist nicht die Zeichenkette cap/1")
    subject = doc.get("subject")
    if not isinstance(subject, dict) or not isinstance(subject.get("ref"), str) or not subject.get("ref"):
        f("R0-shape", "kein Subjekt benannt (subject.ref)")
    strata = doc.get("strata")
    if not isinstance(strata, list) or not strata:
        f("R0-shape", "kein Stratum vorhanden")
    else:
        for i, s in enumerate(strata):
            if not isinstance(s, dict):
                f("R0-shape", f"strata[{i}] ist kein Objekt")
    integrity = doc.get("integrity")
    if not isinstance(integrity, dict) or not isinstance(integrity.get("complete"), bool):
        f("R0-shape", "integrity fehlt oder integrity.complete ist kein Wahrheitswert")
    ids = []
    for s in _strata(doc):
        sid = s.get("id")
        if not isinstance(sid, str) or not sid:
            f("R0-shape", "Stratum ohne id")
        else:
            ids.append(sid)
    if len(ids) != len(set(ids)):
        f("R0-shape", "Stratum-Kennungen sind nicht eindeutig")


def _r1_no_silent_remainder(doc: dict, f) -> None:
    """R1: eligible == examined + the number of individually listed unexamined entries; a remainder
    that only works out by subtraction is refused."""
    for s in _strata(doc):
        el, ex, un = s.get("eligible"), s.get("examined"), s.get("unexamined")
        if not isinstance(un, list):
            f("R1-no-silent-remainder", f"{_sid(s)}: unexamined ist keine Liste")
            continue
        # DISTINCT UNITS, NOT LIST ENTRIES. Codex (P1, review of 2026-09-23 on a8b93ca), reproduced
        # before the fix: with both entries of the PV-01 stratum set to `unit: "pdf.ts"`,
        # `eligible: 6` and `examined: 4` produced NO error, although only ONE unit is accounted
        # for. The arithmetic worked out because two rows were counted, and a second eligible unit
        # could therefore disappear while the rule's own property, "individually listed unexamined
        # units", still read as satisfied. Counting rows measures the length of a list; the rule is
        # about how many units the account covers.
        einheiten = [u.get("unit") for u in un if isinstance(u, dict)]
        benannt = [x for x in einheiten if isinstance(x, str) and x]
        verschieden = len(set(benannt))
        # A REPEATED UNIT IS SAID OUT LOUD. Without this line the count above would silently be one
        # lower and the reader would see an arithmetic complaint whose cause is a duplicate row.
        # Naming the duplicate is what makes the refusal actionable.
        if len(benannt) != verschieden:
            mehrfach = sorted({x for x in benannt if benannt.count(x) > 1})
            f("R1-no-silent-remainder",
              f"{_sid(s)}: dieselbe Einheit ist mehrfach als unexamined gefuehrt ({', '.join(mehrfach)}) "
              f"— zwei Zeilen ueber eine Einheit sind eine Einheit")
        if _is_int(el) and _is_int(ex) and el != ex + verschieden:
            f("R1-no-silent-remainder",
              f"{_sid(s)}: eligible {el} ist nicht examined {ex} plus {verschieden} einzeln gefuehrte "
              f"unexamined Einheit(en)")


def _r2_closed_disposition(doc: dict, f) -> None:
    """R2: every unexamined entry names a unit and carries a disposition from §6; free text is not
    accepted here, because free text does not aggregate."""
    for s in _strata(doc):
        for i, u in enumerate(s.get("unexamined") or []):
            if not isinstance(u, dict):
                f("R2-closed-disposition", f"{_sid(s)}[{i}]: Eintrag ist kein Objekt")
                continue
            if not isinstance(u.get("unit"), str) or not u.get("unit"):
                f("R2-closed-disposition", f"{_sid(s)}[{i}]: keine Einheit benannt (unit)")
            if not is_member(u.get("disposition"), DISPOSITIONS):
                f("R2-closed-disposition",
                  f"{_sid(s)}[{i}]: disposition {u.get('disposition')!r} steht nicht im geschlossenen Vokabular")


def _r3_withholding_digest_bound(doc: dict, f) -> None:
    """R3: a unit listed as withheld carries a digest of the withheld material — otherwise it is
    indistinguishable from a gap."""
    for s in _strata(doc):
        for i, u in enumerate(_unexamined(s)):
            if u.get("disposition") == "withheld" and not _is_digest(u.get("withheld_digest")):
                f("R3-withholding-digest-bound", f"{_sid(s)}[{i}]: withheld ohne withheld_digest")


def _r4_denominator_basis(doc: dict, f) -> None:
    """R4: every stratum names a basis.kind from §4.2; catalogue needs catalogue_digest,
    enumeration needs enumeration_method."""
    for s in _strata(doc):
        basis = s.get("basis")
        if not isinstance(basis, dict):
            f("R4-denominator-basis", f"{_sid(s)}: kein basis-Objekt")
            continue
        kind = basis.get("kind")
        if not is_member(kind, BASIS_KINDS):
            f("R4-denominator-basis", f"{_sid(s)}: basis.kind {kind!r} ist nicht aus der geschlossenen Menge")
            continue
        if kind == "catalogue" and not _is_digest(basis.get("catalogue_digest")):
            f("R4-denominator-basis", f"{_sid(s)}: catalogue-Basis ohne catalogue_digest")
        if kind == "enumeration" and not (isinstance(basis.get("enumeration_method"), str)
                                          and basis.get("enumeration_method")):
            f("R4-denominator-basis", f"{_sid(s)}: enumeration-Basis ohne enumeration_method")


def _r5_counts_well_formed(doc: dict, f) -> None:
    """R5: counts are non-negative integers, and examined does not exceed eligible."""
    for s in _strata(doc):
        el, ex = s.get("eligible"), s.get("examined")
        if not _is_int(el) or el < 0:
            f("R5-counts-well-formed", f"{_sid(s)}: eligible ist keine nicht-negative Ganzzahl")
        if not _is_int(ex) or ex < 0:
            f("R5-counts-well-formed", f"{_sid(s)}: examined ist keine nicht-negative Ganzzahl")
        if _is_int(el) and _is_int(ex) and ex > el:
            f("R5-counts-well-formed", f"{_sid(s)}: examined ({ex}) uebersteigt eligible ({el})")


def _r6_absence_is_scoped(doc: dict, f) -> None:
    """R6: every absence claim names an existing stratum that bounds it."""
    vorhandene = {_sid(s) for s in _strata(doc)}
    aa = doc.get("absence_assertions")
    if aa is None:
        return
    if not isinstance(aa, list):
        f("R6-absence-is-scoped", "absence_assertions ist keine Liste")
        return
    for i, a in enumerate(aa):
        if not isinstance(a, dict):
            f("R6-absence-is-scoped", f"absence_assertions[{i}]: Eintrag ist kein Objekt")
            continue
        st = a.get("stratum")
        if not isinstance(st, str) or not st:
            f("R6-absence-is-scoped", f"absence_assertions[{i}]: kein Stratum benannt")
        elif st not in vorhandene:
            f("R6-absence-is-scoped", f"absence_assertions[{i}]: Stratum {st!r} existiert nicht")


def _r7_incomplete_not_clean(doc: dict, f) -> None:
    """R7: a unit with failed / resource_exhausted / unavailable rules out complete=true; when
    complete=false, capped_to names the verdict a reader may rely on."""
    _integrity = doc.get("integrity")
    integrity: dict = _integrity if isinstance(_integrity, dict) else {}
    hart = any(is_member(u.get("disposition"), HARD_DISPOSITIONS)
               for s in _strata(doc) for u in _unexamined(s))
    complete = integrity.get("complete")
    if hart and complete is True:
        f("R7-incomplete-not-clean",
          "eine Einheit ist failed/resource_exhausted/unavailable, integrity.complete ist trotzdem true")
    if complete is False:
        ct = integrity.get("capped_to")
        if not isinstance(ct, str) or not ct:
            f("R7-incomplete-not-clean", "integrity.complete ist false, aber capped_to nennt keinen Verdikt")


def _r8_supports_bounds_citation(doc: dict, f) -> None:
    """R8: a stratum cited by an absence claim names which classes of claim it supports."""
    aa = doc.get("absence_assertions")
    # THE FOURTH SITE OF THE SAME CLASS, and it sits one level earlier than the three that 7bdfb31
    # closed. There the hashing happened at the TEST (`x in CONSTANT`); here it happens while the
    # set is BUILT: a set comprehension hashes every element, and `a.get("stratum")` arrives
    # unchecked from the document. An attacker sending `{"stratum": []}` raised a bare TypeError
    # here, which `check_cap1_document` turned into "rule could not be evaluated" — exactly the
    # verdict degradation the other three fixes stand against.
    #
    # `is_member` does NOT help at this site: it protects the left operand of a membership test,
    # not the construction of the container. So this filters instead of redirecting.
    #
    # WHY `isinstance(..., str)` AND NOT `Hashable`: `_sid` always returns a string, so a non-string
    # can never equal a stratum identifier. What gets filtered is therefore exactly the set that
    # could never have matched anyway — behaviour for every WELL-FORMED document is unchanged, and
    # an `("a", [])` tuple, which `Hashable` would wrongly let through, does not arise here at all.
    #
    # HONEST LIMIT: after this fix an absence claim with a non-textual `stratum` cites NO stratum,
    # rather than making the rule crash. That its shape is wrong is R0's business; R8 judges
    # `supports`, not the shape of the citation.
    zitiert = ({a.get("stratum") for a in aa
                if isinstance(a, dict) and isinstance(a.get("stratum"), str)}
               if isinstance(aa, list) else set())
    for s in _strata(doc):
        if _sid(s) in zitiert:
            sup = s.get("supports")
            if not isinstance(sup, list) or not sup:
                f("R8-supports-bounds-citation",
                  f"{_sid(s)}: von einer Abwesenheitsaussage zitiert, nennt aber keine supports")
                continue
            # THE CONTAINER WAS CHECKED, ITS ELEMENTS WERE NOT. Codex (P1, review of 2026-09-23 on
            # a8b93ca), reproduced before the fix: `supports: [null]` produced NO error, although
            # R8 requires the stratum to NAME the classes of claim it supports and `null` names
            # none. A non-empty list of nothing is a list, not a naming.
            #
            # THE CLASS IS WIDER THAN THE REPORTED VALUE, measured in the same run before the fix:
            # `[""]`, `[7]`, `[[]]`, `[{}]` and `["absence-of-secret", null]` all passed as well.
            # Fixing only `null` would have left five neighbours of one class open, so what is
            # demanded here is the property every element must have.
            leer = [i for i, c in enumerate(sup) if not (isinstance(c, str) and c.strip())]
            if leer:
                f("R8-supports-bounds-citation",
                  f"{_sid(s)}: supports[{', '.join(str(i) for i in leer)}] nennt keine Klasse "
                  f"(kein nicht-leerer Text) — eine Liste aus Nichts ist keine Benennung")


#: Rule register in the draft's order. R5 runs BEFORE R1, because R1 computes on the same numbers
#: and a non-integer eligible would otherwise give a type error instead of a refusal.
RULES: dict[str, Any] = {
    "R0-shape": _r0_shape,
    "R5-counts-well-formed": _r5_counts_well_formed,
    "R1-no-silent-remainder": _r1_no_silent_remainder,
    "R2-closed-disposition": _r2_closed_disposition,
    "R3-withholding-digest-bound": _r3_withholding_digest_bound,
    "R4-denominator-basis": _r4_denominator_basis,
    "R6-absence-is-scoped": _r6_absence_is_scoped,
    "R7-incomplete-not-clean": _r7_incomplete_not_clean,
    "R8-supports-bounds-citation": _r8_supports_bounds_citation,
}
RULE_IDS: tuple[str, ...] = tuple(RULES)


def check_cap1_document(doc: object) -> list[dict]:
    """All rules against the document; returns a list of {rule, reason}. NEVER an exception.

    An empty list means: conformant in the draft's sense — internal consistency, not truth (§9).
    """
    out: list[dict] = []

    def f(rule: str, reason: str) -> None:
        out.append({"rule": rule, "reason": reason})

    if not isinstance(doc, dict):
        f("R0-shape", f"das Dokument ist kein Objekt, sondern {type(doc).__name__}")
        return out
    for rule_id, rule in RULES.items():
        try:
            rule(doc, f)
        except Exception as exc:  # noqa: BLE001 — never-raise is this surface's promise
            f(rule_id, f"Regel konnte nicht ausgewertet werden ({type(exc).__name__}: {exc})")
    return out


def is_conformant(doc: object) -> bool:
    return not check_cap1_document(doc)


def load_cap1_document(raw: object) -> Any:
    """Read strictly: UTF-8, JSON, no duplicate names — with the package's ONE strict reader.

    The first version brought its own `object_pairs_hook`. Since WP-C1 the package has exactly one
    reader for this property (`_strict_json.loads_strict`, in every verify path); a second would be
    a second truth about the same boundary, and those drift. Duplicate names come back as
    `BundleFormatError` (ProofBundleError family) — RFC 8259 §4 otherwise calls the behaviour
    'unpredictable', and three equally conformant readers judge the same bytes differently
    (measured in tools/cap1_unabhaengige_umsetzung).

    Raises ONLY typed errors (ProofBundleError, the ValueError family including UnicodeDecodeError)
    — never a bare TypeError. The package's never-raise family fuzzes every public surface with
    eight wrong types; a reader that crashes on `None` with TypeError does not judge, it falls over
    (measured on this file's first run, 2026-09-05).
    """
    from ._strict_json import loads_strict  # noqa: PLC0415
    if isinstance(raw, (bytes, bytearray, memoryview)):
        text = bytes(raw).decode("utf-8")
    elif isinstance(raw, str):
        text = raw
    else:
        raise ValueError(f"CAP-1 document must be str or bytes, not {type(raw).__name__}")
    return loads_strict(text)
