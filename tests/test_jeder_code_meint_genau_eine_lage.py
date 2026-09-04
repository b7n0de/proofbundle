"""Die Code-Tafel: fuer JEDEN Reason Code eine ausloesende Eingabe und die Lage, die er meint.

WOGEGEN DIESE DATEI STEHT. Ein Tiefen-Gate hat am 02.09.2026 dieselbe Klasse an EINEM Tag viermal
gefunden: ein Code deckt zwei oder mehr LAGEN, und seine Meldung beschreibt nur eine davon.
`SUBJECT_DIGEST_ALGORITHMS` gab fuer `digest={}` woertlich aus „got [] (an extra algorithm …)",
und es gab keinen extra algorithm. `SUBJECT_CARDINALITY` gab fuer `got 0` aus „more than one leaves
it open which object the receipt speaks about"; null ist nicht mehr als eins.

WARUM DIE VORGAENGER-RIEGEL DAS NICHT FANGEN. Sie messen ein frei waehlbares MERKMAL:
`_ist_gecodet` fuehrt eine Liste von FUNKTIONSNAMEN, die Ratsche in
`test_jede_formpruefung_nennt_ihren_grund` pinnt die Menge der Meldungen mit RICHTUNGS-Sprache.
Beides ist umgehbar, ohne etwas Boeses zu tun: eine neue Sammelbedingung mit neutral formulierter
Meldung passiert die ganze Ratschendatei unbemerkt (adversarial gemessen: 45 passed).

DIE EIGENSCHAFT STATT DES MERKMALS. Diese Tafel bindet jeden Code an die LAGEN, die ihn ausloesen.
Zwei verschiedene Lagen unter demselben Code sind erlaubt — aber nur MIT ausgeschriebener
Begruendung im Eintrag. Wer morgen eine Sammelbedingung anlegt, muss entweder trennen oder
hinschreiben, warum die Lagen dieselbe Antwort verdienen. Das ist der Punkt, an dem man es merkt.

EHRLICHE GRENZE. Gemessen wird, WELCHER Code bei welcher Eingabe entsteht und ob die Lagen
getrennt sind. Ob der Satz neben dem Code gut FORMULIERT ist, misst diese Datei nicht — das bleibt
Lesearbeit.
"""
from __future__ import annotations

import ast
import functools
import inspect
import unittest

import pytest

from proofbundle import agent_review as ar

KOERPER = "Ein Rumpf."


def _pred() -> dict:
    return {
        "schemaVersion": "0.1.0", "reviewId": "tafel",
        "subjectContext": {"kind": "githubPullRequest", "forge": "github.com",
                           "repositoryId": "R_kg", "pullRequestNodeId": "PR_kw1",
                           "headSha": "a" * 40, "baseSha": "b" * 40,
                           "reviewedDiffDigest": "c" * 64,
                           "bodyCoreDigest": ar.body_core_digest(KOERPER)},
        "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "agent"}],
                        "reviewRuns": [], "findings": [], "findingsTotal": 0,
                        "findingsRoot": ar.findings_root([]), "nonClaims": ["x"]},
        "coverage": {"status": "PARTIAL", "knownGaps": ["y"]},
        "times": {"declaredAt": "2026-09-01T09:00:00Z"},
        "limitations": ["Tier 1"],
    }


def _stmt(pred: dict | None = None, **ueber) -> dict:
    p = _pred() if pred is None else pred
    s = {"_type": ar.STATEMENT_TYPE,
         "subject": [{"name": ar._subject_name(p) if isinstance(p, dict) else "x",
                      "digest": {"sha256": ar._subject_digest(p) if isinstance(p, dict) else "a" * 64}}],
         "predicateType": ar.AGENT_REVIEW_PREDICATE_TYPE, "predicate": p}
    s.update(ueber)
    return s


def _ohne(d: dict, schluessel: str) -> dict:
    k = dict(d)
    k.pop(schluessel, None)
    return k


#: (Lage, Bauer -> (statement, predicate), erwarteter Code, geteilt_weil)
#:
#: `geteilt_weil` ist NUR gesetzt, wenn dieser Code MEHR ALS EINE Lage deckt. Ein leerer Wert bei
#: einem geteilten Code laesst `test_geteilte_codes_tragen_eine_begruendung` fallen — das ist der
#: Ort, an dem eine neue Konfundierung auffliegt.
TAFEL: list[tuple[str, object, str, str]] = [
    ("statement ist kein Objekt", lambda: ("kein Objekt", _pred()),
     "STATEMENT_NOT_OBJECT", ""),
    ("_type fehlt", lambda: (_ohne(_stmt(), "_type"), _pred()),
     "STATEMENT_TYPE_ABSENT", ""),
    ("_type ist null", lambda: (_stmt(_type=None), _pred()),
     "STATEMENT_TYPE_MISMATCH", "null und ein falscher Wert teilen sich den Code: beide TRAGEN einen _type, er ist nur nicht der erwartete. Das FEHLEN hat seit dem 02.09.2026 einen eigenen Code"),
    ("_type falsch", lambda: (_stmt(_type="https://example/Statement/v9"), _pred()),
     "STATEMENT_TYPE_MISMATCH", "null und ein falscher Wert teilen sich den Code: beide TRAGEN einen _type, er ist nur nicht der erwartete. Das FEHLEN hat seit dem 02.09.2026 einen eigenen Code"),
    ("subject fehlt", lambda: (_ohne(_stmt(), "subject"), _pred()),
     "SUBJECT_ABSENT_FIELD", ""),
    ("subject ist null", lambda: (_stmt(subject=None), _pred()),
     "SUBJECT_NOT_ARRAY", "null und Nicht-Liste teilen sich den Code: beide TRAGEN ein subject-Feld. Das FEHLEN hat einen eigenen Code"),
    ("subject ist kein Array", lambda: (_stmt(subject="kein Array"), _pred()),
     "SUBJECT_NOT_ARRAY", "null und Nicht-Liste teilen sich den Code: beide TRAGEN ein subject-Feld. Das FEHLEN hat einen eigenen Code"),
    ("subject ist leer", lambda: (_stmt(subject=[]), _pred()), "SUBJECT_ABSENT", ""),
    ("zwei subjects", lambda: (_stmt(subject=[{"name": "x", "digest": {"sha256": "a" * 64}}] * 2),
                               _pred()), "SUBJECT_CARDINALITY", ""),
    ("subject[0] ist kein Objekt", lambda: (_stmt(subject=["nur Text"]), _pred()),
     "SUBJECT_ENTRY_NOT_OBJECT", ""),
    ("digest fehlt", lambda: (_stmt(subject=[{"name": "x"}]), _pred()),
     "SUBJECT_DIGEST_ABSENT", ""),
    ("digest ist null", lambda: (_stmt(subject=[{"name": "x", "digest": None}]), _pred()),
     "SUBJECT_DIGEST_NOT_OBJECT", "null und Nicht-Objekt teilen sich den Code: beide TRAGEN ein digest-Feld. Das FEHLEN hat einen eigenen Code"),
    ("digest ist kein Objekt", lambda: (_stmt(subject=[{"name": "x", "digest": "kein Objekt"}]),
                                        _pred()), "SUBJECT_DIGEST_NOT_OBJECT", "null und Nicht-Objekt teilen sich den Code: beide TRAGEN ein digest-Feld. Das FEHLEN hat einen eigenen Code"),
    ("digest ist leer", lambda: (_stmt(subject=[{"name": "x", "digest": {}}]), _pred()),
     "SUBJECT_DIGEST_EMPTY", ""),
    ("digest ohne sha256", lambda: (_stmt(subject=[{"name": "x", "digest": {"sha512": "b" * 64}}]),
                                    _pred()), "SUBJECT_DIGEST_SHA256_ABSENT", ""),
    ("digest mit Zusatz", lambda: (_stmt(subject=[{"name": "x", "digest": {
        "sha256": "a" * 64, "sha512": "b" * 64}}]), _pred()),
     "SUBJECT_DIGEST_EXTRA_ALGORITHMS", ""),
    ("sha256 zu kurz", lambda: (_stmt(subject=[{"name": "x", "digest": {"sha256": "kurz"}}]),
                                _pred()), "SUBJECT_DIGEST_FORM", "Nicht-String/Grossbuchstaben/Laenge teilen sich den Code; der Satz ist eine ANFORDERUNG ('must be 64 lowercase hex'), keine Lagenbeschreibung — jede der drei Lagen verletzt ihn wahrheitsgemaess"),
    ("sha256 in Grossbuchstaben",
     lambda: (_stmt(subject=[{"name": "x", "digest": {"sha256": "A" * 64}}]), _pred()),
     "SUBJECT_DIGEST_FORM", "Nicht-String/Grossbuchstaben/Laenge teilen sich den Code; der Satz ist eine ANFORDERUNG ('must be 64 lowercase hex'), keine Lagenbeschreibung — jede der drei Lagen verletzt ihn wahrheitsgemaess"),
    ("sha256 ist kein String",
     lambda: (_stmt(subject=[{"name": "x", "digest": {"sha256": 42}}]), _pred()),
     "SUBJECT_DIGEST_FORM", "Nicht-String/Grossbuchstaben/Laenge teilen sich den Code; der Satz ist eine ANFORDERUNG ('must be 64 lowercase hex'), keine Lagenbeschreibung — jede der drei Lagen verletzt ihn wahrheitsgemaess"),
    ("name fehlt", lambda: (_stmt(subject=[{"digest": {"sha256": "a" * 64}}]), _pred()),
     "SUBJECT_NAME_ABSENT", ""),
    ("name ist null", lambda: (_stmt(subject=[{"name": None, "digest": {"sha256": "a" * 64}}]),
                               _pred()), "SUBJECT_NAME_NULL", ""),
    ("name ist die leere Zeichenkette",
     lambda: (_stmt(subject=[{"name": "", "digest": {"sha256": "a" * 64}}]), _pred()),
     "SUBJECT_NAME_EMPTY", ""),
    ("name ist eine Zahl", lambda: (_stmt(subject=[{"name": 42, "digest": {"sha256": "a" * 64}}]),
                                    _pred()), "SUBJECT_NAME_NOT_STRING", ""),
    ("name zeigt auf ein fremdes Objekt",
     lambda: (_stmt(subject=[{"name": "github-pr:FREMD:PR_999",
                              "digest": {"sha256": ar._subject_digest(_pred())}}]), _pred()),
     "SUBJECT_NAME_DISAGREES", ""),
    # KEIN `_subject_digest` hier: es liest `predicate["subjectContext"]` direkt und wirft ohne
    # ihn KeyError. Der Digest ist fuer DIESE Lage gleichgueltig — geprueft wird der NAME.
    ("subjectContext fehlt ganz",
     lambda: (_stmt(subject=[{"name": ar._subject_name(_pred()),
                              "digest": {"sha256": "a" * 64}}],
                    predicate=_ohne(_pred(), "subjectContext")),
              _ohne(_pred(), "subjectContext")),
     "SUBJECT_NAME_UNDERIVABLE", ""),
    ("unbekanntes Statement-Feld", lambda: (_stmt(zusatz=1), _pred()),
     "UNKNOWN_STATEMENT_FIELD", ""),
]


def _codes(statement, predicate) -> set[str]:
    return {getattr(e, "code", None) for e in ar.validate_statement_shape(statement, predicate)}


def _code_literale(knoten: ast.AST) -> set[str]:
    """Alle Code-Zeichenketten, die dieser Ausdruck liefern KANN.

    NICHT nur `ast.Constant`. Die erste Fassung las ausschliesslich ein String-Literal als erstes
    Argument — und uebersah damit prompt zwei frisch angelegte Codes, weil sie als
    Bedingungsausdruck geschrieben sind:

        _shape_err("SUBJECT_ABSENT_FIELD" if lage == "absent" else "SUBJECT_NOT_ARRAY", …)

    Beide Zweige sind Codes des Moduls, und keiner war fuer den Sammler sichtbar. Das ist dieselbe
    Klasse, gegen die diese ganze Datei steht: der Sammler mass eine FORM (steht dort ein Literal)
    statt die Eigenschaft (welche Codes kann der Aufruf vergeben). Gefunden nicht durch Lesen,
    sondern weil die Ratsche fuenf Codes meldete und zwei fehlten.
    """
    if isinstance(knoten, ast.Constant) and isinstance(knoten.value, str) and knoten.value:
        return {knoten.value}
    if isinstance(knoten, ast.IfExp):
        return _code_literale(knoten.body) | _code_literale(knoten.orelse)
    if isinstance(knoten, ast.BoolOp):
        out: set[str] = set()
        for w in knoten.values:
            out |= _code_literale(w)
        return out
    return set()


def _codes_im_modul() -> set[str]:
    gefunden: set[str] = set()
    for k in ast.walk(ast.parse(inspect.getsource(ar))):
        if (isinstance(k, ast.Call) and isinstance(k.func, ast.Name)
                and k.func.id == "_shape_err" and k.args):
            gefunden |= _code_literale(k.args[0])
    return gefunden


#: `SECTION_NOT_OBJECT` wird von `_mit_abschnitt` zur Laufzeit in sieben abschnittsbezogene Codes
#: qualifiziert (`SUBJECTCONTEXT_…`, `DECLARATION_…`, …) und erscheint deshalb NIE unqualifiziert.
#: Er steht hier statt in der Tafel, weil eine Tafelzeile eine ausloesende Eingabe braucht und es
#: fuer den unqualifizierten Code keine gibt.
NUR_ALS_BAUSTEIN = {"SECTION_NOT_OBJECT"}

#: Codes des Moduls, die diese Tafel (noch) nicht fuehrt — mit Grund. Waechst die Menge, faellt
#: `test_jeder_code_des_moduls_steht_in_der_tafel`: ein neuer Code ohne Eintrag ist genau der Fall,
#: den die Vorgaenger-Riegel durchgelassen haben.
OHNE_TAFELZEILE = {
    "FINDINGS_ROOT_MISSING": "wird von _validate_declaration vergeben, nicht von "
                             "validate_statement_shape — eigene Testdatei",
    "FINDINGS_ROOT_MALFORMED": "wird von _validate_declaration vergeben, nicht von "
                               "validate_statement_shape — eigene Testdatei",
    # 04.09.2026, Teil A des v0.2-Vorgabewechsels. BEIDE haben eine eigene Testdatei; der Grund
    # fuer die Ausnahme ist dieselbe wie oben — sie werden nicht von `validate_statement_shape`
    # vergeben, und eine Tafelzeile braucht eine ausloesende Eingabe FUER DIESEN Pfad.
    "FIXCOMMIT_NOT_FULL_SHA": "wird von validate_agent_review_v02_predicate vergeben, nicht von "
                              "validate_statement_shape — tests/test_a4_fixcommit_volle_sha.py "
                              "(13 Faelle plus Gegenrichtung)",
    "POLICY_NOT_EVALUABLE": "wird von _verify_v02_inner vergeben, wenn eine UEBERGEBENE Policy "
                            "beim Auswerten wirft — tests/test_policy_nicht_auswertbar_hat_einen_"
                            "code.py. Dieser Code hatte beim ersten vollen Lauf KEINEN Test; "
                            "gefunden hat das genau diese Tafel, nicht ein roter Test",
}


#: WIE VIELE AUFRUFSTELLEN vergibt jeder Code? Gepinnt, weil die Code-INVENTUR allein zu wenig ist.
#:
#: GM-3, gemessen von einer adversarialen Linse am 02.09.2026: eine NEUE LAGE unter einem
#: BESTEHENDEN Code passierte die ganze Tafel unbemerkt. Gepflanzt wurde eine Pruefung, die
#: `sha256 == "0"*64` unter `SUBJECT_DIGEST_FORM` ablehnt — mit der Meldung „must be 64 lowercase
#: hex characters" fuer einen Digest, der genau das IST. Ergebnis: 55 passed. Dieselbe Lage mit
#: EIGENEM Code faellt sofort („Code(s) ohne Tafelzeile").
#:
#: Damit war die Kopfaussage dieser Datei falsch: „Wer morgen eine Sammelbedingung anlegt, muss
#: entweder trennen oder hinschreiben … Das ist der Punkt, an dem man es merkt." Man merkte es
#: nicht — und der Anreiz zeigte in die falsche Richtung: einen vorhandenen Code
#: wiederzuverwenden war der STILLE Weg.
#:
#: Die Zahl der AUFRUFSTELLEN je Code schliesst EINEN der beiden Wege: eine neue STELLE unter
#: einem alten Code aendert sie.
#:
#: SIE SCHLIESST DEN ANDEREN NICHT, und der Satz, der hier zuerst stand ("Die Zahl der
#: Aufrufstellen je Code schliesst das"), war schlicht falsch. Eine adversariale Linse hat am
#: 02.09.2026 GENAU den Defekt gepflanzt, den der Absatz darueber als gefangen fuehrt — aber als
#: BEDINGUNGSERWEITERUNG (`if X:` -> `if X or Y:`) statt als neue Aufrufstelle:
#:
#:     2983 passed, 0 FAILED
#:
#: Eine `if`-Bedingung ist kein `ast.Call`. Keine Zaehlung von Vergabestellen kann sie sehen —
#: nicht diese und keine kuenftige. Der Weg, der beide Faelle deckt, ist nicht struktureller,
#: sondern verhaltensbezogener Art: die NEGATIVSEITE je Code (siehe unten
#: `test_kein_gueltiger_digest_loest_die_formmeldung_aus`). Sie toetet den Defekt, den 3001 Tests
#: nicht toeten. `SECTION_NOT_OBJECT` hat sieben, weil `_mit_abschnitt` sie zur Laufzeit in sieben
#: abschnittsbezogene Codes qualifiziert.
AUFRUFSTELLEN_JE_CODE = {
    "FINDINGS_ROOT_MALFORMED": 1, "FINDINGS_ROOT_MISSING": 1, "SECTION_NOT_OBJECT": 7,
    "STATEMENT_NOT_OBJECT": 1, "STATEMENT_TYPE_ABSENT": 1, "STATEMENT_TYPE_MISMATCH": 1,
    "SUBJECT_ABSENT": 1, "SUBJECT_ABSENT_FIELD": 1, "SUBJECT_CARDINALITY": 1,
    "SUBJECT_DIGEST_ABSENT": 1, "SUBJECT_DIGEST_EMPTY": 1, "SUBJECT_DIGEST_EXTRA_ALGORITHMS": 1,
    "SUBJECT_DIGEST_FORM": 1, "SUBJECT_DIGEST_NOT_OBJECT": 1, "SUBJECT_DIGEST_SHA256_ABSENT": 1,
    "SUBJECT_ENTRY_NOT_OBJECT": 1, "SUBJECT_NAME_ABSENT": 1, "SUBJECT_NAME_DISAGREES": 1,
    "SUBJECT_NAME_EMPTY": 1, "SUBJECT_NAME_NOT_STRING": 1, "SUBJECT_NAME_NULL": 1,
    "SUBJECT_NAME_UNDERIVABLE": 1, "SUBJECT_NOT_ARRAY": 1, "UNKNOWN_STATEMENT_FIELD": 1,
}


@functools.lru_cache(maxsize=1)
def _erzeuger_namen() -> frozenset[str]:
    """WELCHE AUFRUFE ERZEUGEN EIN FEHLEROBJEKT MIT CODE — abgeleitet, nicht getippt.

    DER FUND, der diese Funktion noetig machte (Dissenter-Linse, 02.09.2026): `_shape_err` ist
    woertlich `return ShapeError(code, message)`. Alle vier Riegel dieser Runde banden an den
    BEZEICHNER `_shape_err`; die Schwester-Ratsche fuehrt `ShapeError` ausdruecklich als legitimen
    Code-Traeger. Eine neue Lage, direkt ueber `ShapeError(...)` eingepflanzt, lief mit

        2983 passed, 18 skipped, 0 failed

    durch — VIER Riegel auf einmal blind. Die beiden Riegel-Familien waren sich uneinig, was ein
    codeerzeugender Aufruf ist, und die grosszuegigere war der Fluchtweg aus der strengeren.

    `ShapeError` hier in eine Liste einzutragen waere der naechste Bezeichner gewesen. Stattdessen
    wird die Menge ABGELEITET: jeder Typ des Moduls, der ein `code`-Merkmal traegt, und jede
    Funktion, deren ganzer Rumpf ein `return <dieser Typ>(...)` ist. Kommt morgen ein zweiter
    Fehlertyp oder ein zweiter Einzeiler dazu, ist er von selbst dabei.

    Gemessen heute: {'_shape_err', 'ShapeError'} — und NULL direkte `ShapeError()`-Aufrufe. Das
    Loch war latent, nicht offen; genau deshalb faellt es sonst erst auf, wenn es benutzt wird.
    """
    quelltext = inspect.getsource(ar)
    baum = ast.parse(quelltext)
    typen = set()
    for k in baum.body:
        if isinstance(k, ast.ClassDef):
            quelle = ast.get_source_segment(quelltext, k) or ""
            if "code" in quelle:
                typen.add(k.name)
    namen = set(typen)
    for k in baum.body:
        if isinstance(k, (ast.FunctionDef, ast.AsyncFunctionDef)):
            rumpf = [z for z in k.body if not (isinstance(z, ast.Expr)
                                               and isinstance(z.value, ast.Constant))]
            if (len(rumpf) == 1 and isinstance(rumpf[0], ast.Return)
                    and isinstance(rumpf[0].value, ast.Call)
                    and isinstance(rumpf[0].value.func, ast.Name)
                    and rumpf[0].value.func.id in typen):
                namen.add(k.name)
    return frozenset(namen)


def _ist_erzeuger(knoten: ast.AST, namen: frozenset[str]) -> bool:
    return (isinstance(knoten, ast.Call) and isinstance(knoten.func, ast.Name)
            and knoten.func.id in namen)


def test_die_erzeugermenge_wird_abgeleitet_und_umfasst_beide_wege():
    """Die Menge darf nicht auf einen Namen zusammenschrumpfen — das war der Fluchtweg."""
    namen = _erzeuger_namen()
    assert "ShapeError" in namen, (
        f"der Fehlertyp selbst fehlt in der Erzeugermenge {sorted(namen)} — dann ist ein direkter "
        f"`ShapeError(...)`-Aufruf wieder unsichtbar, und genau das war der Fund")
    assert "_shape_err" in namen, (
        f"der Einzeiler um den Typ fehlt in {sorted(namen)}")
    assert len(namen) >= 2


def _aufrufstellen_je_code() -> dict[str, int]:
    """Wie oft wird jeder Code vergeben? Am Syntaxbaum, ueber alle Schreibweisen."""
    from collections import Counter  # noqa: PLC0415
    zaehler: Counter = Counter()
    namen = _erzeuger_namen()
    for k in ast.walk(ast.parse(inspect.getsource(ar))):
        if _ist_erzeuger(k, namen) and k.args:
            for code in _code_literale(k.args[0]):
                zaehler[code] += 1
    return dict(zaehler)


def _urteile_aufrufstellen(lage: dict[str, int]) -> None:
    """DAS URTEIL, EINMAL — beide Aufrufer FUEHREN es aus, statt es nachzubauen."""
    gewachsen = {c: (AUFRUFSTELLEN_JE_CODE[c], n) for c, n in lage.items()
                 if c in AUFRUFSTELLEN_JE_CODE and n > AUFRUFSTELLEN_JE_CODE[c]}
    assert not gewachsen, (
        f"Code(s) werden an MEHR Stellen vergeben als gepinnt (soll, ist): {gewachsen}. "
        f"Eine neue Aufrufstelle unter einem bestehenden Code ist eine neue LAGE — sie braucht "
        f"eine Tafelzeile, sonst deckt ein Code zwei Dinge, ohne dass es jemand merkt.")
    gesunken = {c: (n_soll, lage.get(c, 0)) for c, n_soll in AUFRUFSTELLEN_JE_CODE.items()
                if lage.get(c, 0) < n_soll}
    assert not gesunken, (
        f"Code(s) werden an WENIGER Stellen vergeben (soll, ist): {gesunken} — gute Nachricht, "
        f"aber die Zahl gehoert nachgezogen, sonst deckt sie beim naechsten Mal zu viel.")


class CodeTafel(unittest.TestCase):

    def test_jede_lage_loest_ihren_code_aus(self):
        """Die Tafel ist keine Behauptung: jede Zeile wird gefahren."""
        for lage, bauer, code, _ in TAFEL:
            with self.subTest(lage=lage):
                st, pred = bauer()
                self.assertIn(code, _codes(st, pred),
                              f"{lage!r} liefert {_codes(st, pred)}, erwartet {code}")

    def test_jeder_code_des_moduls_steht_in_der_tafel(self):
        """DIE RATSCHE, und sie misst die EIGENSCHAFT statt der Wortwahl.

        Ein neuer Code ohne Tafelzeile faellt hier — unabhaengig davon, wie seine Meldung
        formuliert ist. Genau das konnte die Wortwahl-Ratsche nicht.
        """
        gefuehrt = {c for _, _, c, _ in TAFEL} | NUR_ALS_BAUSTEIN | set(OHNE_TAFELZEILE)
        fehlend = sorted(_codes_im_modul() - gefuehrt)
        self.assertFalse(fehlend, (
            f"Code(s) ohne Tafelzeile: {fehlend}. Jeder Reason Code braucht eine ausloesende "
            f"Eingabe und die Lage, die er meint — sonst weiss niemand, ob er eine oder fuenf "
            f"Lagen deckt."))

    def test_die_tafel_verrottet_nicht(self):
        """GEGENRICHTUNG. Eine Tafel, die Codes fuehrt, die es nicht mehr gibt, deckt nichts."""
        im_modul = _codes_im_modul()
        verwaist = sorted({c for _, _, c, _ in TAFEL} - im_modul)
        self.assertFalse(verwaist, f"Tafelzeilen fuer Codes, die das Modul nicht mehr vergibt: "
                                   f"{verwaist}")
        tot = sorted(set(OHNE_TAFELZEILE) - im_modul)
        self.assertFalse(tot, f"OHNE_TAFELZEILE nennt Codes, die es nicht mehr gibt: {tot}")

    def test_geteilte_codes_tragen_eine_begruendung(self):
        """DER KERN. Zwei Lagen unter einem Code sind erlaubt — aber nur ausgeschrieben.

        Wer morgen eine Sammelbedingung anlegt, muss trennen oder hinschreiben, warum die Lagen
        dieselbe Antwort verdienen. Das ist der Punkt, an dem man es merkt.
        """
        nach_code: dict[str, list[tuple[str, str]]] = {}
        for lage, _, code, grund in TAFEL:
            nach_code.setdefault(code, []).append((lage, grund))
        ohne_grund = {c: [lage for lage, g in eintraege if not g]
                      for c, eintraege in nach_code.items() if len(eintraege) > 1}
        ohne_grund = {c: lagen for c, lagen in ohne_grund.items() if lagen}
        self.assertFalse(ohne_grund, (
            f"Code(s) decken mehrere Lagen OHNE Begruendung: {ohne_grund}. Entweder trennen oder "
            f"im Tafeleintrag hinschreiben, warum dieselbe Antwort richtig ist."))

    def test_ungeteilte_codes_tragen_keine_ueberfluessige_begruendung(self):
        """Die andere Richtung: eine Begruendung bei einem Code, der nur EINE Lage deckt, ist
        Rauschen und laesst die naechste echte Teilung uebersehen."""
        nach_code: dict[str, list[str]] = {}
        for _, _, code, grund in TAFEL:
            nach_code.setdefault(code, []).append(grund)
        ueberfluessig = [c for c, g in nach_code.items() if len(g) == 1 and g[0]]
        self.assertFalse(ueberfluessig,
                         f"Begruendung bei Code(s), die nur eine Lage decken: {ueberfluessig}")

    def test_meta_ein_neuer_code_ohne_tafelzeile_wird_gefangen(self):
        """META. Beweist, dass die Ratsche fallen KANN — mit einer NEUTRAL formulierten Meldung,
        also genau der Form, die die Wortwahl-Ratsche durchliess."""
        gefuehrt = {c for _, _, c, _ in TAFEL} | NUR_ALS_BAUSTEIN | set(OHNE_TAFELZEILE)
        erfunden = _codes_im_modul() | {"EIN_GANZ_NEUER_CODE_NEUTRAL_FORMULIERT"}
        self.assertTrue(sorted(erfunden - gefuehrt),
                        "ein neuer Code bliebe unbemerkt — die Ratsche misst nichts")

    def test_meta_eine_stille_konfundierung_wird_gefangen(self):
        """META. Zwei Lagen unter einem Code OHNE Begruendung muessen auffallen."""
        tafel = list(TAFEL) + [("erfundene zweite Lage", lambda: (_stmt(subject=[]), _pred()),
                                "SUBJECT_ABSENT", "")]
        nach_code: dict[str, list[str]] = {}
        for _, _, code, grund in tafel:
            nach_code.setdefault(code, []).append(grund)
        ohne = {c: g for c, g in nach_code.items() if len(g) > 1 and any(not x for x in g)}
        self.assertIn("SUBJECT_ABSENT", ohne,
                      "eine unbegruendete Doppelbelegung bleibt unbemerkt")


if __name__ == "__main__":
    unittest.main()


# ── Die Vorpruefung muss dieselben Felder kennen wie die Ableitung ─────────────────────────────

def _sc_felder(quelle: str) -> set[str]:
    """Welche Schluessel werden AUS DEM BEHAELTER `sc` gelesen? Am Syntaxbaum.

    AUF `sc` EINGESCHRAENKT, und das ist der Punkt. Die erste Fassung sammelte JEDEN
    `.get("…")`-Aufruf — und zog damit `subjectContext` mit ein, das der BEHAELTER ist und kein
    Schluessel darin (`predicate.get("subjectContext")`). Richtiger Gegenstand, falsche Einheit:
    die Vorpruefung „fehlte" ein Feld, das es dort gar nicht geben kann.
    """
    felder: set[str] = set()
    for k in ast.walk(ast.parse(quelle)):
        if (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute)
                and k.func.attr == "get" and isinstance(k.func.value, ast.Name)
                and k.func.value.id == "sc" and k.args
                and isinstance(k.args[0], ast.Constant) and isinstance(k.args[0].value, str)):
            felder.add(k.args[0].value)
        elif (isinstance(k, ast.Subscript) and isinstance(k.value, ast.Name)
                and k.value.id == "sc" and isinstance(k.slice, ast.Constant)
                and isinstance(k.slice.value, str)):
            felder.add(k.slice.value)
    return felder


def test_die_vorpruefung_kennt_jedes_feld_aus_dem_abgeleitet_wird():
    """DAS MECHANISCHE KRITERIUM, und es ersetzt eine Aufzaehlung.

    `SUBJECT_NAME_UNDERIVABLE` soll sagen „aus diesem subjectContext laesst sich kein Name
    ableiten". Das kann die Vorpruefung nur, wenn sie JEDES Feld kennt, aus dem `_subject_name`
    ableitet. Die erste Fassung kannte VIER von FUENF: `repositoryId` fehlte. Gemessen von einer
    adversarialen Linse am 02.09.2026 — ohne `repositoryId` meldete der Vergleich weiterhin
    „derives 'github-pr::PR_kw1'", byte-genau die Signatur des Defekts, gegen den die Aenderung
    gebaut wurde, nur ein Feld weiter. Bei `repositoryId: null` stand ein Python-`None` im Namen.

    Wer `_subject_name` morgen um ein Feld erweitert, faellt hier — nicht erst beim naechsten Gate.
    """
    aus_ableitung = _sc_felder(inspect.getsource(ar._subject_name))
    aus_vorpruefung = _sc_felder(inspect.getsource(ar.validate_statement_shape))
    fehlend = sorted(aus_ableitung - aus_vorpruefung)
    assert not fehlend, (
        f"`_subject_name` leitet aus {sorted(aus_ableitung)} ab, die Vorpruefung kennt "
        f"{sorted(aus_vorpruefung)} — es fehlt {fehlend}. Fuer ein fehlendes Feld erfindet die "
        f"Meldung dann wieder einen Vergleichswert, statt zu sagen, dass sich nichts vergleichen "
        f"laesst.")
    assert aus_ableitung, "keine Felder erhoben — die Messung ist leer und belegt nichts"


def test_meta_ein_ungeprueftes_ableitungsfeld_wird_gefangen():
    """META. Beweist, dass das Kriterium fallen KANN."""
    aus_ableitung = _sc_felder(inspect.getsource(ar._subject_name)) | {"einNeuesFeld"}
    aus_vorpruefung = _sc_felder(inspect.getsource(ar.validate_statement_shape))
    assert sorted(aus_ableitung - aus_vorpruefung) == ["einNeuesFeld"], (
        "ein ungeprueftes Ableitungsfeld bliebe unbemerkt — das Kriterium misst nichts")


@pytest.mark.parametrize("weg,erwartet", [
    ("repositoryId fehlt", "SUBJECT_NAME_UNDERIVABLE"),
    ("repositoryId null", "SUBJECT_NAME_UNDERIVABLE"),
    ("repositoryId leer", "SUBJECT_NAME_UNDERIVABLE"),
])
def test_ohne_repositoryId_wird_kein_vergleichswert_erfunden(weg, erwartet):
    """Die drei Lagen aus dem Befund, je gefahren."""
    p = _pred()
    if weg == "repositoryId fehlt":
        p["subjectContext"].pop("repositoryId")
    elif weg == "repositoryId null":
        p["subjectContext"]["repositoryId"] = None
    else:
        p["subjectContext"]["repositoryId"] = ""
    st = {"_type": ar.STATEMENT_TYPE,
          "subject": [{"name": "github-pr:R_echt:PR_kw1", "digest": {"sha256": "a" * 64}}],
          "predicateType": ar.AGENT_REVIEW_PREDICATE_TYPE, "predicate": p}
    codes = [getattr(e, "code", None) for e in ar.validate_statement_shape(st, p)]
    assert erwartet in codes, f"{weg}: {codes}"
    assert "SUBJECT_NAME_DISAGREES" not in codes, (
        f"{weg}: der Vergleich lief trotzdem und erfindet einen Wert — {codes}")


def test_kein_code_bekommt_still_eine_zweite_lage():
    """GM-3 GESCHLOSSEN: eine neue Aufrufstelle unter einem alten Code faellt hier."""
    _urteile_aufrufstellen(_aufrufstellen_je_code())


def test_meta_eine_zweite_lage_unter_altem_code_wird_gefangen():
    """META, und es FUEHRT das Urteil aus statt es nachzubauen."""
    lage = dict(_aufrufstellen_je_code())
    lage["SUBJECT_DIGEST_FORM"] = lage.get("SUBJECT_DIGEST_FORM", 1) + 1
    with pytest.raises(AssertionError, match="MEHR Stellen"):
        _urteile_aufrufstellen(lage)
    # GEGENRICHTUNG: die gesunde Lage darf nicht werfen, sonst faengt das Urteil alles
    _urteile_aufrufstellen(_aufrufstellen_je_code())


#: DIE EINE STELLE, DIE EINEN CODE DYNAMISCH BAUEN DARF — benannt, nicht geduldet.
#:
#: `_mit_abschnitt` qualifiziert `SECTION_NOT_OBJECT` zur Laufzeit in abschnittsbezogene Codes
#: (`f"{_code_segment(...)}_{code}"`). Das ist Absicht und der Grund, warum diese eine Kennung
#: sieben Aufrufstellen hat. Jede ANDERE dynamische Form waere ein blinder Fleck.
DYNAMISCHER_QUALIFIZIERER = "_mit_abschnitt"


def _stellen_die_der_sammler_nicht_lesen_kann() -> list[tuple[int, str, str]]:
    """Welche `_shape_err`-Aufrufe liefern dem Sammler KEINEN Code? (Zeile, Form, umgebende Funktion)"""
    baum = ast.parse(inspect.getsource(ar))
    funktion_von: dict[int, str] = {}
    for f in ast.walk(baum):
        if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for k in ast.walk(f):
                if hasattr(k, "lineno"):
                    funktion_von.setdefault(k.lineno, f.name)
    blind = []
    namen = _erzeuger_namen()
    for k in ast.walk(baum):
        if not (_ist_erzeuger(k, namen) and k.args):
            continue
        # DER WEITERREICHER IST KEINE VERGABESTELLE. `_shape_err` ist woertlich
        # `return ShapeError(code, message)` und gibt sein EIGENES Parameter durch — dort steht
        # naturgemaess ein Name und kein Literal. Ausgenommen wird das als EIGENSCHAFT (der Aufruf
        # steht in einer Funktion, die selbst zur Erzeugermenge gehoert), nicht als Name: kommt
        # morgen ein zweiter Einzeiler dazu, ist er von selbst mit ausgenommen.
        if funktion_von.get(k.lineno) in namen:
            continue
        arg = k.args[0]
        if _code_literale(arg):
            continue
        # DIE AUSNAHME IST EINE ZEILE, KEINE FUNKTION — und das ist die zweite Fassung.
        #
        # Die erste liess JEDE unlesbare Stelle in `_mit_abschnitt` durch ("der Qualifizierer darf
        # dynamisch bauen"). Eine adversariale Linse nannte das am 02.09.2026 eine UNBEGRENZTE
        # AMNESTIE: befreit war nicht die qualifizierende Zeile, sondern die ganze Funktion — wer
        # dort eine zweite Vergabestelle anlegt, ist frei. Und ihr eigener erster Fangversuch war
        # selbst merkmalsgebunden (er haftete an einem Fixture-Literal `"coverage"`); ein
        # getauschter String, und derselbe Angriff war wieder gruen.
        #
        # Die Eigenschaft, die den Qualifizierer wirklich auszeichnet: sein Code wird AUS DEM
        # EINGEHENDEN CODE abgeleitet. Das ist ein f-String, der den Namen `code` einsetzt — und
        # nichts anderes darf hier durch, auch nicht in derselben Funktion.
        if funktion_von.get(k.lineno) == DYNAMISCHER_QUALIFIZIERER and _leitet_aus_code_ab(arg):
            continue
        blind.append((arg.lineno, type(arg).__name__,
                      funktion_von.get(arg.lineno, "<modulebene>")))
    return blind


def _leitet_aus_code_ab(knoten: ast.AST) -> bool:
    """Baut dieser Ausdruck seinen Code aus einem EINGEHENDEN Code — statt frei zu erfinden?"""
    if not isinstance(knoten, ast.JoinedStr):
        return False
    return any(isinstance(t, ast.Name) and t.id == "code"
               for w in knoten.values if isinstance(w, ast.FormattedValue)
               for t in ast.walk(w.value))


def _urteile_lesbarkeit(blind: list[tuple[int, str, str]]) -> None:
    """DAS URTEIL, EINMAL — beide Aufrufer FUEHREN es aus."""
    # KEIN ZWEITER FILTER HIER. Diese Zeile lautete `[b for b in blind if b[2] !=
    # DYNAMISCHER_QUALIFIZIERER]` — und liess damit ALLES durch, was in der qualifizierenden
    # Funktion steht. Das war die unbegrenzte Amnestie: der Sammler oben meldete die gepflanzte
    # zweite Vergabestelle korrekt (`[(307, 'JoinedStr', '_mit_abschnitt')]`), und das Urteil warf
    # sie danach weg. Gemessen am 02.09.2026: `21 passed` mit dem Exploit im Baum.
    #
    # Die Ausnahme gehoert an GENAU EINE Stelle, und das ist der Sammler, wo sie an die
    # Eigenschaft gebunden ist (`_leitet_aus_code_ab`). Zwei Traeger derselben Regel sind die
    # naechste Drift — und hier waren sie sogar sofort uneinig.
    fremd = list(blind)
    assert not fremd, (
        f"`_shape_err` bekommt an diesen Stellen einen Code, den der Sammler NICHT lesen kann: "
        f"{fremd}. Damit ist die Stelle fuer die Code-Tafel UND fuer die Aufrufstellen-Zaehlung "
        f"unsichtbar — eine neue Lage koennte sich dort verstecken. Entweder ein lesbares Literal "
        f"schreiben, oder den Bau in `{DYNAMISCHER_QUALIFIZIERER}` legen, dessen Ausgaben die "
        f"Tafel gesondert fuehrt.")


def test_jede_vergabestelle_ist_fuer_den_sammler_lesbar():
    """PRE-SWEEP-FUND (02.09.2026): der Zaehler war ueber die FORM des Arguments blind.

    Gemessen mit eingepflanzten Defekten: eine Kennung aus einer Schleifenvariablen
    (`for _c in (...)`) und eine zusammengesetzte (`"SUBJECT_DIGEST" + "_FORM"`) liefen BEIDE mit
    `14 passed` durch — der Sammler las `ast.Constant`/`IfExp`/`BoolOp` und gab fuer alles andere
    die leere Menge zurueck. Eine leere Menge sah aus wie "keine Codes hier", nicht wie "ich kann
    das nicht lesen". Genau die Klasse, gegen die diese Datei steht, in ihrem eigenen Sammler.

    Der Fix zaehlt nicht mehr Formen auf (das waere die naechste Aufzaehlung, die die zehnte Form
    verpasst), sondern verlangt, dass JEDE Stelle AUFLOESBAR ist. Was der Sammler nicht lesen kann,
    faellt hier laut — statt still zu fehlen.
    """
    _urteile_lesbarkeit(_stellen_die_der_sammler_nicht_lesen_kann())


def test_meta_eine_unlesbare_vergabestelle_wird_gefangen():
    """META: fuehrt das Urteil aus, statt es nachzubauen."""
    with pytest.raises(AssertionError, match="NICHT lesen kann"):
        _urteile_lesbarkeit([(1, "BinOp", "_validate_subject")])
    # GEGENRICHTUNG — und sie wird jetzt AM SAMMLER geprueft, nicht am Urteil.
    #
    # Diese Zeile rief frueher `_urteile_lesbarkeit([(309, "JoinedStr", <Qualifizierer>)])` und
    # verliess sich darauf, dass DAS URTEIL die Funktion ausnimmt. Genau diese zweite Ausnahme war
    # die unbegrenzte Amnestie (siehe `_urteile_lesbarkeit`). Sie ist entfernt; die Ausnahme haengt
    # jetzt an der EIGENSCHAFT im Sammler. Der Meta-Test muss dorthin folgen, sonst prueft er eine
    # Mechanik, die es nicht mehr gibt.
    baum = ast.parse(inspect.getsource(ar))
    qualifizierend = [k.args[0] for k in ast.walk(baum)
                      if isinstance(k, ast.Call) and isinstance(k.func, ast.Name)
                      and k.func.id == "_shape_err" and k.args
                      and isinstance(k.args[0], ast.JoinedStr)]
    assert qualifizierend, "der dynamische Qualifizierer ist verschwunden"
    assert any(_leitet_aus_code_ab(a) for a in qualifizierend), (
        "keine der dynamischen Vergabestellen leitet ihren Code aus dem eingehenden ab — dann "
        "greift die Ausnahme fuer nichts mehr und der Riegel ist entweder blind oder zu streng")
    # und der heutige Stand ist sauber
    _urteile_lesbarkeit(_stellen_die_der_sammler_nicht_lesen_kann())


def _fremde_fehlererzeuger() -> list[int]:
    """Dict-Literale mit Schluessel `code` AUSSERHALB von `_shape_err` — ein zweiter Erzeuger."""
    baum = ast.parse(inspect.getsource(ar))
    innerhalb = set()
    namen = _erzeuger_namen()          # EINMAL, nicht je Knoten — das parste sonst das ganze
    for k in ast.walk(baum):           # Modul pro Syntaxknoten und liess die Suite haengen
        if _ist_erzeuger(k, namen):
            innerhalb.update(id(n) for n in ast.walk(k))
    treffer = []
    for k in ast.walk(baum):
        if isinstance(k, ast.Dict) and id(k) not in innerhalb:
            if any(isinstance(s, ast.Constant) and s.value == "code" for s in k.keys):
                treffer.append(k.lineno)
    return treffer


def _urteile_ein_erzeuger(treffer: list[int]) -> None:
    assert not treffer, (
        f"Fehlerobjekte mit `code` werden auch AUSSERHALB von `_shape_err` gebaut (Zeilen "
        f"{treffer}). Dann zaehlt die Aufrufstellen-Ratsche an diesen Stellen nichts, und die "
        f"Code-Tafel sieht sie nicht. Ein Erzeuger, oder die Ratsche misst die Haelfte.")


def test_es_gibt_genau_einen_erzeuger_von_fehlerobjekten():
    """PRE-SWEEP-FUND: ein handgebautes `{"code": ..., "message": ...}` umging die ganze Tafel.

    Gemessen: `14 passed`. Die Ratsche zaehlt `_shape_err`-Aufrufe; wer den Umschlag selbst baut,
    kommt in keiner Zaehlung vor. Heute ist die Zahl solcher Stellen NULL — das wird hier gepinnt,
    damit sie es bleibt.
    """
    _urteile_ein_erzeuger(_fremde_fehlererzeuger())


def test_meta_ein_zweiter_erzeuger_wird_gefangen():
    """META: fuehrt das Urteil aus."""
    with pytest.raises(AssertionError, match="AUSSERHALB von"):
        _urteile_ein_erzeuger([42])
    _urteile_ein_erzeuger(_fremde_fehlererzeuger())


def test_kein_gueltiger_digest_loest_die_formmeldung_aus():
    """DIE NEGATIVSEITE — und sie ist der einzige Weg, der die KLASSE trifft.

    Die drei strukturellen Riegel oben pruefen, WIE ein Code vergeben wird (an welcher Stelle, in
    welcher Form, von welchem Erzeuger). Keiner von ihnen kann sehen, dass eine BESTEHENDE Stelle
    unter einer ERWEITERTEN Bedingung feuert — dort aendert sich keine Struktur, nur Verhalten.

    Diese Pruefung fragt stattdessen: was darf `SUBJECT_DIGEST_FORM` NICHT ausloesen? Ein Digest,
    der die dokumentierte Form erfuellt (64 Zeichen, Kleinbuchstaben-Hex), darf die Formmeldung
    NIE ausloesen — egal welche Bedingung morgen dazukommt.

    GEMESSEN von einer adversarialen Linse und danach hier verankert: sauber gruen; mit dem
    gepflanzten Defekt (`sha256 == "0"*64` wird abgelehnt, als Bedingungserweiterung eingebaut)
    ROT — waehrend die volle Suite mit `2983 passed, 0 FAILED` durchlief.

    EHRLICHE GRENZE, und sie ist gross: das ist die Negativseite fuer EINEN Code von 24. Die
    uebrigen 23 haben sie nicht. Diese Pruefung schliesst die Klasse nicht, sie zeigt den Weg und
    deckt den einen Fall, an dem er gemessen wurde. Wer sie fuer die Klasse haelt, macht denselben
    Fehler wie der Satz, den sie korrigiert.

    KEIN SKIP. Eine erste Fassung rief `_validate_subject(sc, errs)` mit zwei Argumenten, fing den
    `TypeError` und uebersprang — ein uebersprungener Test misst nichts und sieht aus wie ein
    bestandener. Die Aufrufform ist jetzt am Quelltext abgelesen statt geraten.
    """
    gueltige = ["0" * 64, "a" * 64, "0123456789abcdef" * 4,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    for d in gueltige:
        statement = {"_type": "https://in-toto.io/Statement/v1",
                     "predicateType": ar.PREDICATE_TYPE if hasattr(ar, "PREDICATE_TYPE") else "x",
                     "subject": [{"name": "x", "digest": {"sha256": d}}]}
        errs = ar.validate_statement_shape(statement, {})
        codes = [getattr(e, "code", None) for e in errs]
        assert "SUBJECT_DIGEST_FORM" not in codes, (
            f"ein GUELTIGER sha256 ({d[:12]}…) loest die Formmeldung aus. Die Meldung sagt "
            f"'must be 64 lowercase hex characters' ueber einen Digest, der genau das IST — also "
            f"traegt der Code jetzt zwei Lagen. Gefunden hat das keine Strukturpruefung, sondern "
            f"diese Negativseite: die Struktur aendert sich bei einer Bedingungserweiterung nicht. "
            f"Alle Codes dieses Laufs: {codes}")


def test_meta_die_negativseite_faengt_was_die_struktur_nicht_sieht():
    """DER BEWEIS, gemessen — und er zeigt die ARBEITSTEILUNG der beiden Riegel-Arten.

    Am 02.09.2026 eingepflanzt: Linse 50s Bedingungserweiterung an einer BESTEHENDEN Vergabestelle
    (`elif not _HEX64.match(...)` -> `elif not _HEX64.match(...) or dig["sha256"] == "0"*64`).
    Keine neue Aufrufstelle, kein neuer Code, keine neue Erzeugerform — strukturell aendert sich
    NICHTS. Ergebnis:

        mit dem Defekt          1 failed, 20 passed   (nur die Negativseite faellt)
        nach dem Zurueckstellen 21 passed             (`cmp -s` OK)

    Die zwanzig strukturellen Zusicherungen bleiben gruen, und sie haben recht damit: sie messen
    die Form, und die Form ist unveraendert. Eine Zaehlung von Vergabestellen KANN eine
    `if`-Bedingung nicht sehen, weil eine Bedingung kein `ast.Call` ist — das ist keine Luecke im
    Riegel, sondern eine Grenze seiner Messgroesse.

    Dieser Test kann die Mutation nicht wiederholen, ohne den Pruefling im Arbeitsbaum zu aendern.
    Er haelt die Messung fest und prueft, was ohne Mutation pruefbar ist: dass die Bedingung, an
    der gemessen wurde, ueberhaupt noch im Pruefling steht.
    """
    quelle = inspect.getsource(ar)
    assert '_HEX64.match(dig["sha256"])' in quelle, (
        "die Bedingung, an der die Negativseite gemessen wurde, steht nicht mehr im Pruefling — "
        "die Messung im Docstring deckt den heutigen Stand dann nicht mehr")
