"""CAP-1 (draft-hillier-coverage-attestation-00) — die acht normativen Regeln als Paketfunktion.

WAS DAS IST. Ein Coverage Attestation Document sagt, was eine Untersuchung untersucht hat, was nicht,
und warum — je Stratum ein Nenner mit Basis und eine Buchfuehrung Einheit fuer Einheit mit einem
Grund aus einer geschlossenen Menge. Ohne das ist eine Abwesenheitsaussage ("nicht gefunden")
unfalsifizierbar: sie unterscheidet nicht, ob nachgesehen wurde.

GESCHRIEBEN AUS DEM ENTWURFSTEXT, Abschnitte 4, 4.1, 4.2, 4.3, 5 und 6 der Fassung -00 (Datatracker,
abgerufen 2026-09-04), plus die Feldnamen aus CAP-1.schema.json (Autor-Repo, Commit 0980d32), die
Abschnitt 4 zur normativen Form erklaert. Die Regelnamen sind die des Konformitaets-Manifests des
Autors (R1-no-silent-remainder, …), damit die fuenfzehn Vektoren unveraendert als Test laufen.
Der Referenzverifier des Autors wurde NICHT gelesen; die zweite unabhaengige Lesart im Haus ist
`tools/cap1_unabhaengige_umsetzung/` und bleibt dort unveraendert (Auftrag Teil C).

DREI EIGENSCHAFTEN, die dieses Modul traegt:
  * never-raise: `check_cap1_document` gibt fuer JEDE Eingabe eine Fehlerliste zurueck, nie eine
    Ausnahme. Ein Verifizierer, der bei einem kaputten Dokument abstuerzt, urteilt nicht.
  * Refusal ist die einzige konforme Antwort auf ein verletzendes Dokument (Entwurf §5); es wird
    nichts korrigiert, nichts erraten, nichts aufgefuellt.
  * Jede Regel steht EINZELN in `RULES`, damit der Meta-Test des Entwurfs (§7.2: "acht Regeln, acht
    Mutanten, acht Kills") sie einzeln stumm schalten und die Klasse fallen sehen kann.

DUPLIKATE (die Klausel, die -01 tragen wird und von uns stammt): JSON-Objekte mit doppelten Namen
werden beim LESEN abgewiesen, nicht hier — dieses Modul bekommt ein bereits geparstes Objekt.
`load_cap1_document` liest strikt und lehnt Doppelungen ab.
"""
from __future__ import annotations

from typing import Any, TypeGuard

from ._membership import is_member

__all__ = [
    "CAP1_PROFILE", "DISPOSITIONS", "BASIS_KINDS", "HARD_DISPOSITIONS", "RULE_IDS", "RULES",
    "check_cap1_document", "is_conformant", "load_cap1_document",
]

CAP1_PROFILE = "cap/1"

#: Entwurf §6, das geschlossene Vokabular. Acht Werte, woertlich.
DISPOSITIONS = frozenset({
    "not_applicable", "disabled_by_policy", "unsupported_input", "resource_exhausted",
    "failed", "unavailable", "out_of_scope", "withheld",
})

#: Entwurf §4.2, die drei Arten des Nenners.
BASIS_KINDS = frozenset({"catalogue", "enumeration", "declared"})

#: Entwurf R7: diese drei Dispositionen sind mit `integrity.complete = true` unvereinbar.
HARD_DISPOSITIONS = frozenset({"failed", "resource_exhausted", "unavailable"})

_HEX = frozenset("0123456789abcdef")


def _is_int(x: object) -> TypeGuard[int]:
    """Eine echte Ganzzahl. `bool` ist in Python eine int-Unterklasse und hier keine Zahl.

    WARUM TypeGuard UND NICHT bool, gemessen 2026-09-15: `mypy src` meldete sechs Fehler in diesem
    Modul, alle derselben Klasse — ein aus geparstem JSON gelesener Wert ist `Any | None`, und der
    Pruefer sah nicht, dass `_is_int(el)` ihn bereits auf `int` einengt. Zur LAUFZEIT war jede
    dieser Stellen korrekt bewacht; falsch war nur, dass die Zusicherung im Rueckgabetyp nicht
    stand. Mit `TypeGuard[int]` verengt der Pruefer durch JEDE Aufrufstelle, auch durch die, die es
    noch nicht gibt — sechs `# type: ignore` haetten dagegen genau sechs Stellen stumm gestellt und
    die siebte wieder rot werden lassen."""
    return isinstance(x, int) and not isinstance(x, bool)


def _is_digest(x: object) -> bool:
    """Schema: `^[0-9a-f]{32,128}$` — der Entwurf schreibt keinen Algorithmus vor (§9), nur die Form."""
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


# ── die acht Regeln, Entwurf §5, je eine Funktion ─────────────────────────────────────────────

def _r0_shape(doc: dict, f) -> None:
    """R0: Objekt, profile cap/1, subject, mindestens ein Stratum, integrity mit boolean complete,
    Stratum-Kennungen vorhanden und eindeutig."""
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
    """R1: eligible == examined + Anzahl der einzeln gefuehrten unexamined; ein Rest, der nur durch
    Subtraktion aufgeht, wird abgewiesen."""
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
    """R2: jeder unexamined-Eintrag nennt eine Einheit und traegt eine Disposition aus §6; Freitext
    an dieser Stelle wird nicht angenommen, weil Freitext nicht aggregiert."""
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
    """R3: eine als withheld gefuehrte Einheit traegt einen Digest des zurueckgehaltenen Materials —
    sonst ist sie von einer Luecke nicht zu unterscheiden."""
    for s in _strata(doc):
        for i, u in enumerate(_unexamined(s)):
            if u.get("disposition") == "withheld" and not _is_digest(u.get("withheld_digest")):
                f("R3-withholding-digest-bound", f"{_sid(s)}[{i}]: withheld ohne withheld_digest")


def _r4_denominator_basis(doc: dict, f) -> None:
    """R4: jedes Stratum nennt basis.kind aus §4.2; catalogue braucht catalogue_digest, enumeration
    braucht enumeration_method."""
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
    """R5: Zaehler sind nicht-negative Ganzzahlen, examined uebersteigt eligible nicht."""
    for s in _strata(doc):
        el, ex = s.get("eligible"), s.get("examined")
        if not _is_int(el) or el < 0:
            f("R5-counts-well-formed", f"{_sid(s)}: eligible ist keine nicht-negative Ganzzahl")
        if not _is_int(ex) or ex < 0:
            f("R5-counts-well-formed", f"{_sid(s)}: examined ist keine nicht-negative Ganzzahl")
        if _is_int(el) and _is_int(ex) and ex > el:
            f("R5-counts-well-formed", f"{_sid(s)}: examined ({ex}) uebersteigt eligible ({el})")


def _r6_absence_is_scoped(doc: dict, f) -> None:
    """R6: jede Abwesenheitsaussage nennt ein existierendes Stratum, das sie begrenzt."""
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
    """R7: eine Einheit mit failed / resource_exhausted / unavailable schliesst complete=true aus;
    bei complete=false nennt capped_to den Verdikt, auf den ein Leser sich stuetzen darf."""
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
    """R8: ein von einer Abwesenheitsaussage zitiertes Stratum nennt, welche Klassen von Aussagen es
    stuetzt."""
    aa = doc.get("absence_assertions")
    # DIE VIERTE STELLE DERSELBEN KLASSE, und sie sitzt eine Ebene frueher als die drei, die
    # 7bdfb31 geschlossen hat. Dort wurde beim TEST gehasht (`x in KONSTANTE`), hier schon beim
    # AUFBAU der Menge: eine Set-Comprehension hasht jedes Element, und `a.get("stratum")` kommt
    # ungeprueft aus dem Dokument. Ein Angreifer, der `{"stratum": []}` schickt, loeste hier ein
    # rohes TypeError aus, das `check_cap1_document` in "Regel konnte nicht ausgewertet werden"
    # verwandelte — genau die Verdikt-Degradation, gegen die die drei anderen Fixes stehen.
    #
    # `is_member` hilft an dieser Stelle NICHT: es schuetzt den linken Operanden eines
    # Mitgliedschaftstests, nicht den Aufbau des Behaelters. Deshalb wird hier gefiltert statt
    # umgeleitet.
    #
    # WARUM `isinstance(..., str)` UND NICHT `Hashable`: `_sid` gibt immer eine Zeichenkette
    # zurueck, ein Nicht-String kann also niemals gleich einer Stratum-Kennung sein. Gefiltert
    # wird damit genau die Menge, die ohnehin nie treffen koennte — das Verhalten fuer jedes
    # WOHLGEFORMTE Dokument bleibt unveraendert, und ein `("a", [])`-Tupel, das `Hashable` faelsch-
    # lich durchliesse, kommt hier gar nicht erst in Frage.
    #
    # EHRLICHE GRENZE: eine Abwesenheitsaussage mit nicht-textlichem `stratum` zitiert nach diesem
    # Fix KEIN Stratum mehr, statt die Regel abstuerzen zu lassen. Dass ihre Form falsch ist, ist
    # Sache von R0; R8 urteilt ueber `supports`, nicht ueber die Form der Zitierung.
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


#: Regelregister in der Reihenfolge des Entwurfs. R5 laeuft VOR R1, weil R1 auf denselben Zahlen
#: rechnet und eine nicht-ganzzahlige eligible sonst einen Typfehler statt einer Verweigerung gaebe.
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
    """Alle Regeln gegen das Dokument; Rueckgabe eine Liste von {rule, reason}. NIE eine Ausnahme.

    Eine leere Liste heisst: konform im Sinn des Entwurfs — innere Konsistenz, nicht Wahrheit (§9).
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
        except Exception as exc:  # noqa: BLE001 — never-raise ist die Zusage dieser Flaeche
            f(rule_id, f"Regel konnte nicht ausgewertet werden ({type(exc).__name__}: {exc})")
    return out


def is_conformant(doc: object) -> bool:
    return not check_cap1_document(doc)


def load_cap1_document(raw: object) -> Any:
    """Strikt lesen: UTF-8, JSON, keine doppelten Namen — mit dem EINEN strikten Leser des Pakets.

    Die erste Fassung brachte einen eigenen `object_pairs_hook` mit. Das Paket hat seit WP-C1
    genau einen Leser fuer diese Eigenschaft (`_strict_json.loads_strict`, in jedem Verify-Pfad);
    ein zweiter waere eine zweite Wahrheit ueber dieselbe Grenze, und die driftet. Doppelte Namen
    kommen als `BundleFormatError` (ProofBundleError-Familie) zurueck — RFC 8259 §4 nennt das
    Verhalten sonst 'unpredictable', drei gleichermassen konforme Leser urteilen ueber dieselben
    Bytes verschieden (gemessen in tools/cap1_unabhaengige_umsetzung).

    Wirft NUR typisierte Fehler (ProofBundleError, ValueError-Familie inkl. UnicodeDecodeError) —
    nie einen rohen TypeError. Die never-raise-Familie des Pakets fuzzt jede oeffentliche Flaeche
    mit acht falschen Typen; ein Leser, der bei `None` mit TypeError abstuerzt, urteilt nicht, er
    faellt um (gemessen beim ersten Lauf dieser Datei, 2026-09-05).
    """
    from ._strict_json import loads_strict  # noqa: PLC0415
    if isinstance(raw, (bytes, bytearray, memoryview)):
        text = bytes(raw).decode("utf-8")
    elif isinstance(raw, str):
        text = raw
    else:
        raise ValueError(f"CAP-1 document must be str or bytes, not {type(raw).__name__}")
    return loads_strict(text)
