#!/usr/bin/env python3
"""
CAP-1 Verifier, unabhaengige Umsetzung.

GESCHRIEBEN AUS DEM ENTWURFSTEXT draft-hillier-coverage-attestation-00, Abschnitte 4, 4.1,
4.2, 4.3, 5 und 6, plus den Feldnamen aus CAP-1.schema.json — den Abschnitt 4 ausdruecklich
zur normativen Form erklaert ("The normative shape is given by the accompanying JSON Schema").

NICHT gelesen und NICHT uebersetzt: verify.mjs, verify.py, verify.html, run.mjs, mutate.mjs,
crosscheck.py aus dem Baum des Autors. Diese Umsetzung soll seine Lesart PRUEFEN, nicht
wiederholen; wer sie abschreibt, misst dieselbe Lesart zweimal.

Keine Abhaengigkeiten, kein Netzwerk, keine Uhr. Standardbibliothek.
"""
import json
import sys

# Abschnitt 6, das geschlossene Vokabular. Acht Eintraege, woertlich aus dem Text.
VOKABULAR = {
    "not_applicable",
    "disabled_by_policy",
    "unsupported_input",
    "resource_exhausted",
    "failed",
    "unavailable",
    "out_of_scope",
    "withheld",
}

# Abschnitt 4.2, die drei Basis-Arten.
BASIS_ARTEN = {"catalogue", "enumeration", "declared"}

# R7 nennt genau diese drei als unvereinbar mit complete=true.
UNVEREINBAR_MIT_COMPLETE = {"failed", "resource_exhausted", "unavailable"}


def _ganzzahl(x):
    """Eine echte Ganzzahl. bool ist in Python eine int-Unterklasse und hier keine Zahl."""
    return isinstance(x, int) and not isinstance(x, bool)


def verify(doc):
    """Gibt (ok, failures) zurueck. failures ist eine Liste aus (regel, begruendung)."""
    f = []

    def fehler(regel, grund):
        f.append((regel, grund))

    # ── R0, shape ────────────────────────────────────────────────────────────
    # "The document MUST be an object, MUST declare profile as cap/1, MUST name a subject,
    #  MUST carry at least one stratum, and MUST carry an integrity object with a boolean
    #  complete. Stratum identifiers MUST be present and unique."
    if not isinstance(doc, dict):
        fehler("R0-shape", "das Dokument ist kein Objekt")
        return False, f

    if doc.get("profile") != "cap/1":
        fehler("R0-shape", "profile ist nicht die Zeichenkette cap/1")

    subject = doc.get("subject")
    if not isinstance(subject, dict) or not subject.get("ref"):
        fehler("R0-shape", "kein Subjekt benannt")

    strata = doc.get("strata")
    if not isinstance(strata, list) or len(strata) < 1:
        fehler("R0-shape", "kein Stratum vorhanden")
        strata = []

    integrity = doc.get("integrity")
    if not isinstance(integrity, dict) or not isinstance(integrity.get("complete"), bool):
        fehler("R0-shape", "integrity fehlt oder complete ist kein Wahrheitswert")
        integrity = {}

    ids = []
    for s in strata:
        if not isinstance(s, dict):
            fehler("R0-shape", "ein Stratum ist kein Objekt")
            continue
        sid = s.get("id")
        if not isinstance(sid, str) or not sid:
            fehler("R0-shape", "Stratum ohne id")
        else:
            ids.append(sid)
    if len(ids) != len(set(ids)):
        fehler("R0-shape", "Stratum-Kennungen sind nicht eindeutig")

    # Ab hier nur noch ueber wohlgeformte Strata weiterarbeiten.
    strata = [s for s in strata if isinstance(s, dict)]

    # ── R5, counts well formed ───────────────────────────────────────────────
    # "Counts MUST be non-negative integers and examined MUST NOT exceed eligible."
    # ZUERST, weil R1 auf denselben Zahlen rechnet: eine nicht-ganzzahlige eligible
    # wuerde dort einen Typfehler statt einer Verweigerung ergeben.
    for s in strata:
        sid = s.get("id", "?")
        el, ex = s.get("eligible"), s.get("examined")
        if not _ganzzahl(el) or el < 0:
            fehler("R5-counts-well-formed", f"{sid}: eligible ist keine nicht-negative Ganzzahl")
        if not _ganzzahl(ex) or ex < 0:
            fehler("R5-counts-well-formed", f"{sid}: examined ist keine nicht-negative Ganzzahl")
        if _ganzzahl(el) and _ganzzahl(ex) and ex > el:
            fehler("R5-counts-well-formed", f"{sid}: examined ({ex}) uebersteigt eligible ({el})")

    # ── R1, no silent remainder ──────────────────────────────────────────────
    # "For every stratum, eligible MUST equal examined plus the number of individually
    #  accounted unexamined units. A remainder that reconciles only by subtraction MUST
    #  be refused."
    for s in strata:
        sid = s.get("id", "?")
        el, ex = s.get("eligible"), s.get("examined")
        un = s.get("unexamined")
        if not isinstance(un, list):
            fehler("R1-no-silent-remainder", f"{sid}: unexamined ist keine Liste")
            continue
        if _ganzzahl(el) and _ganzzahl(ex) and el != ex + len(un):
            fehler(
                "R1-no-silent-remainder",
                f"{sid}: eligible {el} ist nicht examined {ex} plus {len(un)} einzeln "
                f"aufgefuehrte unexamined",
            )

    # ── R2, closed disposition ───────────────────────────────────────────────
    # "Every unexamined entry MUST name a unit and MUST carry a disposition drawn from
    #  the closed vocabulary in Section 6."
    for s in strata:
        sid = s.get("id", "?")
        for i, u in enumerate(s.get("unexamined") or []):
            if not isinstance(u, dict):
                fehler("R2-closed-disposition", f"{sid}[{i}]: Eintrag ist kein Objekt")
                continue
            if not isinstance(u.get("unit"), str) or not u.get("unit"):
                fehler("R2-closed-disposition", f"{sid}[{i}]: kein unit benannt")
            d = u.get("disposition")
            if d not in VOKABULAR:
                fehler(
                    "R2-closed-disposition",
                    f"{sid}[{i}]: disposition {d!r} steht nicht im geschlossenen Vokabular",
                )

    # ── R3, withholding is digest-bound ──────────────────────────────────────
    # "A unit disposed as withheld MUST carry a digest binding the withheld material."
    for s in strata:
        sid = s.get("id", "?")
        for i, u in enumerate(s.get("unexamined") or []):
            if isinstance(u, dict) and u.get("disposition") == "withheld":
                wd = u.get("withheld_digest")
                if not isinstance(wd, str) or not wd:
                    fehler(
                        "R3-withholding-digest-bound",
                        f"{sid}[{i}]: withheld ohne withheld_digest",
                    )

    # ── R4, denominator basis ────────────────────────────────────────────────
    # "Every stratum MUST declare basis.kind from the closed set in Section 4.2. A
    #  catalogue basis MUST carry a catalogue digest. An enumeration basis MUST state
    #  its method."
    for s in strata:
        sid = s.get("id", "?")
        basis = s.get("basis")
        if not isinstance(basis, dict):
            fehler("R4-denominator-basis", f"{sid}: kein basis-Objekt")
            continue
        kind = basis.get("kind")
        if kind not in BASIS_ARTEN:
            fehler("R4-denominator-basis", f"{sid}: basis.kind {kind!r} ist nicht aus der Menge")
            continue
        if kind == "catalogue":
            cd = basis.get("catalogue_digest")
            if not isinstance(cd, str) or not cd:
                fehler("R4-denominator-basis", f"{sid}: catalogue-Basis ohne catalogue_digest")
        if kind == "enumeration":
            em = basis.get("enumeration_method")
            if not isinstance(em, str) or not em:
                fehler("R4-denominator-basis", f"{sid}: enumeration-Basis ohne enumeration_method")

    # ── R6, absence is scoped ────────────────────────────────────────────────
    # "Every absence assertion MUST name an existing stratum that bounds it. An absence
    #  claim that names no population MUST be refused."
    vorhandene = {s.get("id") for s in strata}
    aa = doc.get("absence_assertions")
    if aa is not None and not isinstance(aa, list):
        fehler("R6-absence-is-scoped", "absence_assertions ist keine Liste")
        aa = []
    for i, a in enumerate(aa or []):
        if not isinstance(a, dict):
            fehler("R6-absence-is-scoped", f"absence[{i}]: Eintrag ist kein Objekt")
            continue
        st = a.get("stratum")
        if not isinstance(st, str) or not st:
            fehler("R6-absence-is-scoped", f"absence[{i}]: kein Stratum benannt")
        elif st not in vorhandene:
            fehler("R6-absence-is-scoped", f"absence[{i}]: Stratum {st!r} existiert nicht")

    # ── R7, incomplete is not clean ──────────────────────────────────────────
    # "Where any unit is disposed as failed, resource_exhausted or unavailable,
    #  integrity.complete MUST NOT be true. Where integrity.complete is false, capped_to
    #  MUST state the verdict a reader may rely on."
    hat_harte = False
    for s in strata:
        for u in s.get("unexamined") or []:
            if isinstance(u, dict) and u.get("disposition") in UNVEREINBAR_MIT_COMPLETE:
                hat_harte = True
    complete = integrity.get("complete")
    if hat_harte and complete is True:
        fehler(
            "R7-incomplete-not-clean",
            "eine Einheit ist failed/resource_exhausted/unavailable, complete ist trotzdem true",
        )
    if complete is False:
        ct = integrity.get("capped_to")
        if not isinstance(ct, str) or not ct:
            fehler("R7-incomplete-not-clean", "complete ist false, aber capped_to nennt kein Verdikt")

    # ── R8, supports bounds citation ─────────────────────────────────────────
    # "A stratum cited by an absence assertion MUST state which classes of claim it
    #  supports."
    zitiert = set()
    for a in aa or []:
        if isinstance(a, dict) and isinstance(a.get("stratum"), str):
            zitiert.add(a["stratum"])
    for s in strata:
        sid = s.get("id")
        if sid in zitiert:
            sup = s.get("supports")
            if not isinstance(sup, list) or len(sup) == 0:
                fehler(
                    "R8-supports-bounds-citation",
                    f"{sid}: von einer absence assertion zitiert, nennt aber keine supports",
                )

    return len(f) == 0, f


def main(argv):
    if len(argv) != 2:
        print("usage: cap1_verify.py <attestation.json>", file=sys.stderr)
        return 2
    with open(argv[1], "rb") as fh:
        doc = json.loads(fh.read().decode("utf-8"))
    ok, failures = verify(doc)
    if ok:
        print("CONFORMS")
        return 0
    print("REFUSED")
    for regel, grund in failures:
        print(f"  {regel}: {grund}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
