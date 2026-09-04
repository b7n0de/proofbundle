"""Jede Formpruefung des Verifiers nennt einen STABILEN Grund — als Familie, nicht als Fallliste.

DIE ABNAHME (Gegenlese Runde 2, P0.1, 31.08.2026): *"Falsches `_type`, String Subject, String
Declaration, leere oder mehrfache Subjects und falsche Digestformen ergeben stabile Reason
Codes."*

Vorher gab `verify_agent_review` fuer alle sechs ein korrektes `ok=False` mit einem guten Satz —
und `reason_codes` blieb LEER. Ein Verbraucher sah DASS es fiel, hatte aber nichts Stabiles, worauf
er verzweigen konnte; wer auf den Text matchte, brach beim naechsten Umformulieren still.

WARUM DIESER TEST DIE FAMILIE MISST UND NICHT DIE SECHS.
Eine Stunde vor diesem Test hat das Re-Gate an seinem eigenen praeregistrierten Ziel FZ-07
gefunden, dass ein Schwestertest ueber eine handgepflegte Liste lief und der Dateikopf einen
Vollstaendigkeits-Test zusagte, den es nicht gab. Denselben Fehler hier zu wiederholen waere
teurer als der urspruengliche Defekt: die sechs benannten Faelle sind ABNAHME, nicht Umfang.

Der Umfang wird deshalb am SYNTAXBAUM gemessen: keine Fehlerstelle der Formpruefung darf ohne
Code entstehen. Eine neue Pruefung ohne Code faellt hier, bevor sie ausgeliefert wird.
"""
from __future__ import annotations

import ast
import base64
import copy
import inspect
import json
import textwrap

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as ar

SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PK = SK.public_key().public_bytes_raw()
KOERPER = "Ein PR-Rumpf, wie er sichtbar veroeffentlicht wird."


def _doc():
    return {
        "schemaVersion": "0.1.0", "reviewId": "grund",
        "subjectContext": {"kind": "githubPullRequest", "forge": "github.com",
                           "repositoryId": "R_kg", "pullRequestNodeId": "PR_kw1",
                           "headSha": "a" * 40, "baseSha": "b" * 40,
                           "reviewedDiffDigest": "c" * 64,
                           "bodyCoreDigest": ar.body_core_digest(KOERPER)},
        "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "agent"}],
                        "reviewRuns": [], "findings": [], "findingsTotal": 0,
                        "findingsRoot": ar.findings_root([]),
                        "nonClaims": ["keine Aussage ueber Qualitaet"]},
        "coverage": {"status": "PARTIAL", "knownGaps": ["nur eine Runde"]},
        "times": {"declaredAt": "2026-09-01T09:00:00Z"},
        "limitations": ["Tier 1"],
    }


def _neu_signiert(mutation):
    """Ein GUELTIG signierter Umschlag mit veraendertem Inhalt — der Angriff, den die Gegenlese fuhr."""
    env = copy.deepcopy(ar.emit_agent_review(_doc(), SK, legacy_v01=True))
    st = json.loads(base64.b64decode(env["payload"]))
    mutation(st)
    env["payload"] = base64.b64encode(json.dumps(st).encode()).decode()
    roh = base64.b64decode(env["payload"])
    pae = (b"DSSEv1 " + str(len(env["payloadType"])).encode() + b" " + env["payloadType"].encode()
           + b" " + str(len(roh)).encode() + b" " + roh)
    env["signatures"] = [{"sig": base64.b64encode(SK.sign(pae)).decode()}]
    return env


#: Die sechs Faelle, die die Abnahme WOERTLICH nennt. Sie sind die untere Schranke, nicht der Umfang.
ABNAHME = {
    "falsches _type": lambda s: s.__setitem__("_type", "https://example/Wrong/v1"),
    "String Subject": lambda s: s.__setitem__("subject", "keine-liste"),
    "String Declaration": lambda s: s["predicate"].__setitem__("declaration", "kein-objekt"),
    "leeres Subject": lambda s: s.__setitem__("subject", []),
    "mehrfache Subjects": lambda s: s["subject"].append({"name": "x", "digest": {"sha256": "d" * 64}}),
    "falsche Digestform": lambda s: s["subject"][0].__setitem__("digest", {"sha256": "KEIN-HEX"}),
}


@pytest.mark.parametrize("name", sorted(ABNAHME))
def test_die_abnahme_faelle_nennen_einen_grund(name):
    """Jeder der sechs woertlich genannten Faelle faellt UND nennt einen stabilen Code."""
    r = ar.verify_agent_review(_neu_signiert(ABNAHME[name]), PK, strict=True)
    assert r["ok"] is False, f"{name}: kam als gueltig durch"
    assert r["reason_code"], f"{name}: faellt, nennt aber keinen Grund — reason_codes={r['reason_codes']}"
    assert r["reason_code"] in r["reason_codes"]


def test_der_gueltige_fall_nennt_keinen_grund():
    """GEGENPROBE. Ein Riegel, der immer einen Grund nennt, nennt keinen."""
    doc = _doc()
    r = ar.verify_agent_review(ar.emit_agent_review(doc, SK, legacy_v01=True), PK, strict=True,
                               expected_subject_digest=ar._subject_digest(doc),
                               observed_body=KOERPER)
    assert r["ok"] is True
    assert r["reason_code"] is None, f"ein gueltiges Receipt traegt einen Fehlgrund: {r['reason_code']}"


def _formpruefung_quelle() -> str:
    return textwrap.dedent(inspect.getsource(ar.validate_statement_shape))


#: Traeger, die IMMER einen Code erzeugen. `_mit_abschnitt` steht hier ABSICHTLICH NICHT.
_IMMER_GECODET = ("_shape_err", "ShapeError")


def _ist_gecodet(w: ast.AST) -> bool:
    """Entsteht dieser Wert durch die Code-Vergabe?

    `_mit_abschnitt` IST EIN BEDINGTER TRAEGER, und die Vorgaengerfassung fuehrte ihn in einer
    Reihe mit `_shape_err`. Gemessen von einer adversarialen Linse am 02.09.2026: es gibt den Code
    nur weiter, WENN der uebergebene Fehler schon einen hat — sonst liefert es ein nacktes `str`
    (`_mit_abschnitt('coverage','irgendwas').code is None`). Und es ist die IDIOMATISCHE
    Schreibweise dieses Moduls, fuenf Aufrufstellen allein im oeffentlichen Haupteingang. Dieselbe
    codelose Pruefung IN DER BEWACHTEN Funktion kam mit Huelle als die Suite blieb gruen durch und ohne Huelle
    als 5 failed.

    Deshalb wird die Bedingung jetzt GEPRUEFT statt angenommen: `_mit_abschnitt(x, y)` gilt nur
    als gecodet, wenn `y` selbst gecodet ist. Das ist die Eigenschaft; die Namensliste war das
    frei waehlbare Merkmal.
    """
    if isinstance(w, ast.Call) and isinstance(w.func, ast.Name):
        if w.func.id in _IMMER_GECODET:
            return True
        if w.func.id == "_mit_abschnitt":
            # zweites Positionsargument ist der eingepackte Fehler; ohne ihn nichts zu tragen
            return bool(len(w.args) >= 2 and _ist_gecodet(w.args[1]))
        return False
    if isinstance(w, ast.Call) and isinstance(w.func, ast.Attribute):
        if w.func.attr in _IMMER_GECODET:
            return True
        if w.func.attr == "_mit_abschnitt":
            return bool(len(w.args) >= 2 and _ist_gecodet(w.args[1]))
        return False
    # Ein NAME als eingepackter Fehler (`for e in …: _mit_abschnitt("x", e)`) ist statisch nicht
    # entscheidbar — konservativ NICHT gecodet. Ueberfangen ist hier richtig: die Alternative
    # waere, eine unbelegte Annahme als Deckung zu zaehlen.
    if isinstance(w, ast.Name):
        return False
    # `f"..." for e in ...` — eine Comprehension traegt ihr Element im `elt`
    if isinstance(w, ast.GeneratorExp | ast.ListComp):
        return _ist_gecodet(w.elt)
    return False


def _fehlerlisten_namen(baum: ast.AST) -> set[str]:
    """Die Namen, die eine Funktion als IHR ERGEBNIS zurueckgibt — bar oder als `name + [...]`.

    DAS IST DIE EIGENSCHAFT, NICHT DIE GEWOHNHEIT. Die Vorgaengerfassung suchte den BEZEICHNER
    `errs`, und eine adversariale Gegenlesung hat am 02.09.2026 gemessen, was das kostet: der
    oeffentliche Haupteingang `validate_agent_review_predicate` fuellt eine Liste namens `errors`
    und hatte 13 codelose Stellen, von denen der Sweep genau EINE sah. Dieselbe Datei war zuvor
    schon einmal ueber die SCHREIBWEISEN verbreitert worden — aber nie ueber den VARIABLENNAMEN,
    und der eigene Hauptvalidator benutzt den anderen. Das ist woertlich die Klasse, die der
    Docstring von `_fehlerstellen_ohne_code` selbst benennt.

    DIE ERSTE FASSUNG DIESER REGEL KANNTE VIER RUECKGABEFORMEN, und eine adversariale Linse hat am
    02.09.2026 gemessen, was das kostet: `return errors[:]` — eine voellig harmlose Schutzkopie mit
    nachweislich unveraendertem Verhalten — loeschte den Namen und damit ALLE Fundstellen der
    Funktion, 14 auf 1. Dasselbe fuer `errors or []`, `tuple(errors)`, `errors.copy()`. Die
    Ratsche meldete daraufhin "GESUNKEN — gute Nachricht, Grundlinie nachziehen"; dem Rat gefolgt
    und fuenf codelose Pruefungen ergaenzt, blieben die Suite blieb gruen. Der Riegel baute sich beim normalen
    Refactoring selbst ab. Deshalb kennt die Regel jetzt ZEHN Formen (gemessen mit zehn Sonden; hier stand 'acht',
    waehrend dieselbe Datei weiter unten korrekt 'Zehn' schrieb — dieselbe Groesse, zwei Zahlen) — UND die erkannte
    Namensmenge wird selbst gepinnt (`GRUNDLINIE_TRAEGER`), denn eine Liste von Formen kann die
    neunte nicht kennen.

    GEMESSEN, warum genau diese Regel und nicht "jeder Name" — KORRIGIERT am 02.09.2026, weil die
    urspruengliche Zahl zu KEINEM Zeitpunkt reproduzierte. Hier stand "88 Stellen, davon 6 zu
    Unrecht"; eine adversariale Linse hat nachgerechnet:

    ZWEITE KORREKTUR am 02.09.2026, und sie betrifft meine EIGENE erste Korrektur: die schrieb
    "127 Stellen / 21 Funktionen" und mischte damit ZWEI Zaehlregeln, ohne eine davon zu nennen.
    Genau die Klasse, gegen die diese Datei steht. Beide Zahlen sind richtig — fuer verschiedene
    Fragen. Deshalb steht die Regel ab jetzt bei der Zahl:

        REGEL A · die Ratsche DIESER Datei (`GRUNDLINIE_CODELOS`)
                  17 Traegerfunktionen · 127 codelose Stellen (= die Summe der Ratsche)

        REGEL B · ueber ALLE Modulebene-Funktionen, die eine Fehlerliste tragen
                  20 Funktionen · davon 7 NICHT in der Ratsche: _finalize_failclosed,
                  _mit_abschnitt, _subject_name, apply_time_evidence, derive_limitation_codes,
                  replace_disclosure_block, validate_statement_shape

    Die Fehltreffer der urspruenglichen Ueberlegung sind Merkle-Blaetter in `findings_root`,
    Textteile in `render_disclosure_line` und die Ergebnislisten von `resolve_receipt_chain` —
    keine Fehlerlisten. Eine Zahl ohne ihre Zaehlregel ist keine Messung, sondern eine Behauptung
    mit Ziffern; die erste Korrektur ersetzte eine falsche Zahl durch eine mehrdeutige.

    Die RICHTUNG der Aussage haelt und ist nachgemessen: die Regel "was die Funktion zurueckgibt"
    trifft die 11 Validatoren und KEINE der vier Fehltreffer-Funktionen.
    """
    namen: set[str] = set()
    for k in ast.walk(baum):
        if isinstance(k, ast.Return) and k.value is not None:
            w = k.value
            if isinstance(w, ast.Name):
                namen.add(w.id)                                    # return errs
            elif isinstance(w, ast.BinOp) and isinstance(w.left, ast.Name):
                namen.add(w.left.id)                               # return errs + [...]
            elif isinstance(w, ast.BoolOp) and isinstance(w.values[0], ast.Name):
                namen.add(w.values[0].id)                          # return errs or []
            elif isinstance(w, ast.Subscript) and isinstance(w.value, ast.Name) and isinstance(
                    w.slice, ast.Slice):
                namen.add(w.value.id)                              # return errs[:]
            elif isinstance(w, ast.Call) and isinstance(w.func, ast.Attribute) and isinstance(
                    w.func.value, ast.Name) and w.func.attr in ("copy",):
                namen.add(w.func.value.id)                         # return errs.copy()
            elif isinstance(w, ast.Call) and isinstance(w.func, ast.Name) and w.func.id in (
                    "list", "sorted", "tuple", "frozenset", "set"):
                for a in w.args:                                   # return list(errs)
                    if isinstance(a, ast.Name):
                        namen.add(a.id)
    # EIN SPRUNG DATENFLUSS: `errors.extend(hilf)` macht `hilf` zu einer Fehlerliste, auch wenn
    # sie selbst nie zurueckgegeben wird. Gemessen am 02.09.2026: ohne diesen Sprung blieb die
    # Ratsche gruen, waehrend eine eingepflanzte codelose Stelle ueber eine Hilfsliste in die
    # Ergebnisliste floss. EHRLICHE GRENZE: genau EIN Sprung. Eine Kette ueber zwei Hilfslisten
    # entkommt weiterhin — das ist eine Reichweiten-Analyse und waere hier ueberbaut.
    for _ in range(1):
        zuwachs: set[str] = set()
        for k in ast.walk(baum):
            if (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute)
                    and k.func.attr in ("extend", "append")
                    and isinstance(k.func.value, ast.Name) and k.func.value.id in namen):
                for a in k.args:
                    if isinstance(a, ast.Name):
                        zuwachs.add(a.id)
            elif isinstance(k, ast.Assign) and isinstance(k.value, ast.Name):
                for z in k.targets:
                    if isinstance(z, ast.Name) and z.id in namen:
                        zuwachs.add(k.value.id)
        namen |= zuwachs
    return namen


def _fehlerstellen_ohne_code(quelle: str) -> list[int]:
    """Jede Stelle, die einen Formfehler erzeugt, OHNE ihm einen Code zu geben. Am Syntaxbaum.

    DIE ERSTE FASSUNG FING GENAU EINE FORM (`errs.append`), und eine adversariale Gegenlesung
    hat am 01.09.2026 gemessen, dass acht von elf realistischen Schreibweisen entkommen —
    darunter `errs.extend(...)`, das dieses Modul selbst benutzt (gemessen DREI
    Stellen — hier stand einmal 'sieben', was zu keinem Zeitpunkt zutraf). Ein Riegel,
    der die haeufigste Alternative nicht kennt, prueft die Gewohnheit des Autors und nicht die
    Eigenschaft.

    Gefangen werden jetzt alle Formen, mit denen man eine Liste fuellt: append · extend · insert ·
    `+=` · `errs = errs + [...]` · `errs[i:] = [...]` · `return [...]` · `return errs + [...]`.
    """
    ohne: list[int] = []
    baum = ast.parse(quelle)
    # Welche Listen sind Fehlerlisten? Die, die die Funktion zurueckgibt. `errs` bleibt immer
    # dabei, damit Bruchstuecke ohne eigenes `return` (Meta-Proben, Teilquellen) weiter messen.
    nur = _fehlerlisten_namen(baum) | {"errs"}

    def pruefe(werte, zeile):
        for w in werte:
            if isinstance(w, ast.GeneratorExp | ast.ListComp):
                if not _ist_gecodet(w):
                    ohne.append(getattr(w.elt, "lineno", zeile))
                continue
            if isinstance(w, ast.List):
                pruefe(w.elts, zeile)
                continue
            if not _ist_gecodet(w):
                ohne.append(getattr(w, "lineno", zeile))

    for k in ast.walk(baum):
        zeile = getattr(k, "lineno", -1)
        if isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute):
            ziel = k.func.value
            # ZWEI TRAEGER, nicht einer. Eine lokale Liste `errs.append(...)` UND das Ergebnisfeld
            # `r["errors"].append(...)`, das die beiden Verifier benutzen. Die Fassung davor kannte
            # nur den ersten — und genau im zweiten liegen die neun Ablehnungswege, die eine
            # adversariale Gegenlesung am 02.09.2026 als codelos gemessen hat (Signatur ungueltig,
            # fremdes Ziel, Rumpf abweichend, findingsRoot deckt nicht, ...). Ein Sweep, der den
            # Traeger der schwersten Faelle nicht kennt, misst den bequemen Teil.
            ist_ergebnisfeld = (isinstance(ziel, ast.Subscript)
                                and isinstance(ziel.slice, ast.Constant)
                                and ziel.slice.value in ("errors", "warnings"))
            if ((isinstance(ziel, ast.Name) and ziel.id in nur) or ist_ergebnisfeld) and (
                    k.func.attr in ("append", "extend", "insert")):
                # insert(0, x) -> das Element ist das ZWEITE Argument
                pruefe(k.args[1:] if k.func.attr == "insert" else k.args, zeile)
        elif isinstance(k, ast.AugAssign) and isinstance(k.target, ast.Name) and k.target.id in nur:
            pruefe([k.value], zeile)
        elif isinstance(k, ast.Assign):
            for z in k.targets:
                # errs = errs + [...]  und  errs[len(errs):] = [...]
                # NUR die zwei FUELL-Formen, nie eine schlichte Neuzuweisung.
                #
                # Die Vorgaengerfassung zaehlte `else: pruefe([w])`, also JEDES `name = <irgendwas>`.
                # Solange die Namensmenge nur `errs` war und die Ratsche nur fuenf handverlesene
                # Funktionen kannte, fiel das nicht auf. Mit der Eigenschafts-Regel schlug es sofort
                # durch: `errs = pruefer(...)` in `emit_agent_review`, `ref = sc.get("humanRef")` in
                # `_subject_name`, `codes = {...}` in `derive_limitation_codes` — neun Fehltreffer,
                # alle vom selben Zweig. Eine Zuweisung ERSETZT die Liste, sie fuellt sie nicht.
                if isinstance(z, ast.Name) and z.id in nur:
                    w = k.value
                    # NUR `errs = errs + [...]`: rechts eine LISTE, links dieselbe Liste. Ohne die
                    # Listen-Bedingung zaehlte `neu = body[:start] + block + body[ende:]` in
                    # `replace_disclosure_block` als Fehlerstelle — das ist Textverkettung.
                    # ZWEI FUELL-FORMEN, NICHT EINE. Die erste Fassung verlangte `ast.BinOp` —
                    # also die Schreibweise `errs = errs + [...]`. Eine adversariale Linse hat am
                    # 02.09.2026 die BEDEUTUNGSGLEICHE Form `errs = [*errs, "…"]` in die bewachte
                    # Funktion `validate_statement_shape` gepflanzt: eine codelose Pruefung, die
                    # zur Laufzeit feuert, und die GANZE Suite blieb gruen —
                    #
                    #     2986 passed, 15 skipped, exit 0
                    #
                    # Fuenf Netze schwiegen, jedes aus gemessenem Grund. Die Eigenschaft ist
                    # "die Zuweisung baut die Liste AUS SICH SELBST neu auf"; `+` und `[*x, …]`
                    # sind zwei Schreibweisen derselben Eigenschaft. Wer nur eine kennt, misst
                    # wieder die Form statt der Sache.
                    if (isinstance(w, ast.BinOp) and isinstance(w.right, ast.List)
                            and isinstance(w.left, ast.Name) and w.left.id in nur):
                        pruefe(w.right.elts, zeile)
                    elif isinstance(w, (ast.List, ast.Tuple)) and any(
                            isinstance(e, ast.Starred) and isinstance(e.value, ast.Name)
                            and e.value.id in nur for e in w.elts):
                        # `errs = [*errs, x]` — die entpackte Liste ist der alte Inhalt, die
                        # uebrigen Elemente sind das Neue. Nur die pruefen, nie das Sternchen.
                        pruefe([e for e in w.elts if not isinstance(e, ast.Starred)], zeile)
                elif (isinstance(z, ast.Subscript) and isinstance(z.value, ast.Name)
                        and z.value.id in nur and isinstance(z.slice, ast.Slice)):
                    # NUR ein SCHNITT `errs[len(errs):] = [...]`. Ein Schluessel ist keine Fuellung:
                    # `aus["signature_time_status"] = "PLATFORM_ATTESTED"` in `apply_time_evidence`
                    # setzt ein Feld, es haengt keinen Fehler an.
                    pruefe([k.value], zeile)
        elif isinstance(k, ast.Return) and k.value is not None:
            w = k.value
            if isinstance(w, ast.List):
                pruefe(w.elts, zeile)
            elif isinstance(w, ast.BinOp) and isinstance(w.right, ast.List):
                pruefe(w.right.elts, zeile)
            elif isinstance(w, ast.Call) and isinstance(w.func, ast.Name) and w.func.id == "list":
                for a in w.args:
                    if isinstance(a, ast.List):
                        pruefe(a.elts, zeile)
    return ohne


def test_keine_formpruefung_ohne_code():
    """DIE FAMILIE. Keine Fehlerstelle der Formpruefung entsteht ohne Code — auch keine kuenftige.

    Gemessen am Syntaxbaum statt an einer Fallliste: wer morgen eine Pruefung ergaenzt und den
    Code vergisst, faellt hier, und nicht erst beim Verbraucher, der auf einen Text gematcht hat.
    """
    ohne = _fehlerstellen_ohne_code(_formpruefung_quelle())
    assert not ohne, (
        f"{len(ohne)} Fehlerstelle(n) in validate_statement_shape ohne Reason Code "
        f"(Zeilen relativ zur Funktion: {ohne}) — `_shape_err(\"CODE\", ...)` benutzen.")


def test_meta_eine_stelle_ohne_code_wird_gefangen():
    """META. Beweist, dass die Familienpruefung ueberhaupt fallen KANN."""
    quelle = _formpruefung_quelle() + '\ndef _spaeter(errs):\n    errs.append("neue Pruefung ohne Code")\n'
    ohne = _fehlerstellen_ohne_code(quelle)
    assert len(ohne) == 1, f"eine codelose Stelle wird NICHT gefangen: {ohne}"


def test_meta_eine_codierte_stelle_gilt_nicht_als_verstoss():
    """META, Gegenrichtung. Sonst waere der Test immer rot und damit wertlos."""
    quelle = _formpruefung_quelle() + '\ndef _spaeter(errs):\n    errs.append(_shape_err("NEU", "mit Code"))\n'
    assert _fehlerstellen_ohne_code(quelle) == []


def test_der_code_ueberlebt_das_praefixen():
    """Der Abschnittsname wird vorangestellt, OHNE den Code zu verlieren.

    Genau dort ging er verloren: `f"declaration: {e}"` auf einer ShapeError erzeugt ein nacktes
    `str`. Der Fall `String Declaration` der Abnahme lief durch diese Zeile.
    """
    e = ar._shape_err("SECTION_NOT_OBJECT", "must be an object")
    mit = ar._mit_abschnitt("declaration", e)
    assert str(mit) == "declaration: must be an object"
    assert getattr(mit, "code", None) == "DECLARATION_SECTION_NOT_OBJECT"
    # Ein Fehler OHNE Code bleibt ein schlichter Text — kein erfundener Code.
    assert getattr(ar._mit_abschnitt("coverage", "irgendwas"), "code", None) is None


def test_der_code_ist_json_serialisierbar():
    """Das Ergebnis geht als JSON nach draussen. Eine str-Unterklasse darf das nicht brechen."""
    r = ar.verify_agent_review(_neu_signiert(ABNAHME["String Subject"]), PK, strict=True)
    wieder = json.loads(json.dumps(r))
    assert wieder["reason_code"] == "SUBJECT_NOT_ARRAY"
    assert isinstance(wieder["errors"][0], str)


def test_ein_hinweis_wird_nie_zum_fehlgrund():
    """DER VERTRAG ZWISCHEN reason_code UND reason_codes, gepinnt.

    Gefunden von einer adversarialen Gegenlesung am 01.09.2026: der Kommentar im Modul behauptete,
    `reason_code` sei die schlichte Ableitung aus `reason_codes`. Waere er das, truege ein
    BESTANDENES Receipt einen Fehlgrund — und jeder Verbraucher, der auf `reason_code is not None`
    verzweigt, lehnte es ab.

    Die Gegenprobe darunter ist der Punkt: der Test der Gegenrichtung (`der gueltige Fall nennt
    keinen Grund`) bestand vorher nur, weil seine Fixture `observedAt` weglaesst. Mit dem Feld
    waere er rot gewesen, ohne dass etwas kaputt ist.
    """
    doc = _doc()
    doc["times"]["observedAt"] = "2026-09-01T09:00:00Z"   # in v0.1 zulaessig, aber selbstdeklariert
    r = ar.verify_agent_review(ar.emit_agent_review(doc, SK, legacy_v01=True), PK, strict=True,
                               expected_subject_digest=ar._subject_digest(doc),
                               observed_body=KOERPER)
    assert r["ok"] is True, f"die Fixture ist nicht gueltig: {r['errors'][:2]}"
    assert r["errors"] == []
    assert "LEGACY_SELF_DECLARED_OBSERVED_AT" in r["advisory_codes"], (
        "die Vorbedingung traegt nicht — ohne den Hinweis prueft dieser Test nichts")
    assert r["reason_code"] is None, (
        f"ein HINWEIS ist zum Fehlgrund geworden: {r['reason_code']!r}")
    assert r["reason_codes"] == [], (
        f"ein HINWEIS steht unter den Fehlgruenden: {r['reason_codes']!r}")


#: Die elf Schreibweisen, mit denen ein Autor eine Fehlerliste fuellen kann. Acht davon entkamen
#: der ersten Fassung des Sweeps — gemessen von einer adversarialen Gegenlesung, nicht vermutet.

def test_eine_ablehnung_ohne_code_traegt_keinen_hinweis_als_grund():
    """DIE ANDERE HAELFTE — gemessen von einer adversarialen Gegenlesung am 02.09.2026.

    `reason_code` (Skalar) war gegen diese Falle geschuetzt, `reason_codes` (Liste) nicht. Eine
    fehlgeschlagene SIGNATURPRUEFUNG traegt keinen Code (neun von elf Ablehnungswegen tun das
    nicht). Trug das Receipt zusaetzlich ein `times.observedAt`, kam die Ablehnung mit einer
    NICHT-LEEREN Liste zurueck, deren einziger Eintrag der Zeit-Hinweis war:

        ok = False
        errors = ['DSSE signature verification failed — payload is unauthenticated']
        reason_codes = ['LEGACY_SELF_DECLARED_OBSERVED_AT']

    Eine leere Liste sagt ehrlich "kein maschineller Grund". Eine Liste mit genau einem Hinweis
    laedt dazu ein, `reason_codes[0]` als Grund zu lesen — und der Grund war die Signatur.
    """
    doc = _doc()
    doc["times"]["observedAt"] = "2026-09-01T09:00:00Z"
    umschlag = ar.emit_agent_review(doc, SK, legacy_v01=True)
    fremd = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key().public_bytes_raw()
    r = ar.verify_agent_review(umschlag, fremd, strict=True,
                               expected_subject_digest=ar._subject_digest(doc),
                               observed_body=KOERPER)
    assert r["ok"] is False, "die Vorbedingung traegt nicht — das Receipt haette fallen muessen"
    assert r["crypto_ok"] is False, "abgelehnt, aber nicht wegen der Signatur — Test prueft nichts"
    assert "LEGACY_SELF_DECLARED_OBSERVED_AT" in r["advisory_codes"], (
        "der Hinweis fehlt ganz — dann misst dieser Test die Falle nicht")
    assert r["reason_codes"] == [], (
        f"eine Ablehnung wegen der SIGNATUR fuehrt {r['reason_codes']!r} als Fehlgrund — ein "
        f"Verbraucher, der reason_codes[0] liest, bekommt einen Hinweis ueber ein Zeitfeld")



@pytest.mark.parametrize("digest,erwartet", [
    ({}, "SUBJECT_DIGEST_EMPTY"),
    ({"sha512": "b" * 64}, "SUBJECT_DIGEST_SHA256_ABSENT"),
    ({"md5": "c" * 32, "sha512": "b" * 64}, "SUBJECT_DIGEST_SHA256_ABSENT"),
    ({"sha256": "a" * 64, "sha512": "b" * 64}, "SUBJECT_DIGEST_EXTRA_ALGORITHMS"),
])
def test_drei_digest_lagen_drei_codes(digest, erwartet):
    """EIN CODE DARF NICHT ZWEI ENTGEGENGESETZTE LAGEN DECKEN.

    Zweimal an einem Tag dieselbe Klasse. Zuerst deckte `SUBJECT_DIGEST_ALGORITHMS` "gar kein
    Digest" UND "zu viele" ab, mit einem Satz, der nur den zweiten Fall erklaerte — fuer
    `digest={}` lautete die Ausgabe woertlich "got [] (an extra algorithm ...)", und es gab
    keinen extra algorithm. Der Fix dagegen teilte in fehlend/ueberzaehlig und liess dabei WIEDER
    einen Code ueber zwei Lagen stehen: `{}` und `{sha512}` bekamen beide "carries no sha256".

    Die zweite Lage ist die gefaehrlichere. Bei `{}` ist das Subjekt an nichts gebunden; bei
    `{sha512}` ist es SEHR WOHL gebunden, nur an etwas, das dieser Verifier nicht liest — ein
    Produzent kann die beiden auf verschiedene Objekte zeigen lassen. Wer beides gleich meldet,
    laesst einen Verbraucher den zweiten Fall fuer den ersten halten.
    """
    st = {"_type": ar.STATEMENT_TYPE, "subject": [{"name": "x", "digest": digest}],
          "predicateType": ar.AGENT_REVIEW_PREDICATE_TYPE, "predicate": {}}
    codes = [getattr(e, "code", None) for e in ar.validate_statement_shape(st, {})
             if "digest" in str(e)]
    assert erwartet in codes, f"digest={sorted(digest)} liefert {codes}, erwartet {erwartet}"


@pytest.mark.parametrize("anzahl,erwartet", [
    (0, "SUBJECT_ABSENT"),
    (2, "SUBJECT_CARDINALITY"),
    (5, "SUBJECT_CARDINALITY"),
])
def test_kein_subjekt_und_zu_viele_subjekte_sind_verschiedene_lagen(anzahl, erwartet):
    """DIESELBE KLASSE eine Ebene hoeher, gefunden beim Nachbar-Sweep derselben Runde.

    `len(subj) != 1` deckte BEIDE Lagen mit einem Code — und der Satz war fuer die eine aktiv
    falsch: fuer `got 0` lautete die Ausgabe "more than one leaves it open which object the
    receipt speaks about". Null ist nicht mehr als eins. Ein Receipt OHNE Subjekt spricht ueber
    nichts; eines mit MEHREREN laesst offen, ueber welches. Kaputtes Statement gegen
    Verwechslungsangriff — verschiedene Ursachen, verschiedene Reaktionen.

    Gemessen ueber die drei Codes mit Richtungs-Sprache im Modul: zwei waren konfundiert und sind
    getrennt, `UNKNOWN_STATEMENT_FIELD` beschreibt genau einen Zustand und bleibt.
    """
    gut = {"name": "x", "digest": {"sha256": "a" * 64}}
    st = {"_type": ar.STATEMENT_TYPE, "subject": [gut] * anzahl,
          "predicateType": ar.AGENT_REVIEW_PREDICATE_TYPE, "predicate": {}}
    codes = [getattr(e, "code", None) for e in ar.validate_statement_shape(st, {})]
    assert erwartet in codes, f"n={anzahl} liefert {codes}, erwartet {erwartet}"
    andere = "SUBJECT_CARDINALITY" if erwartet == "SUBJECT_ABSENT" else "SUBJECT_ABSENT"
    assert andere not in codes, f"n={anzahl} traegt AUCH {andere} — die Lagen sind nicht getrennt"


def test_keine_meldung_beschreibt_eine_andere_lage_als_ihre_bedingung():
    """DIE FAMILIE, am Syntaxbaum. Jede Meldung mit Richtungs-Sprache ("more than", "extra",
    "exactly one") muss zu einer Bedingung gehoeren, die NUR diese Richtung trifft.

    Als Ratsche gefuehrt: waechst die Zahl, hat jemand eine neue Sammelbedingung mit einer
    einseitigen Meldung angelegt — genau die Klasse, die diese Runde zweimal bezahlt hat.
    """
    import re  # noqa: PLC0415
    richtung = re.compile(r"more than|extra|too many|at least|exactly one|additional", re.I)
    quelle = inspect.getsource(ar)
    gefunden = set()
    for k in ast.walk(ast.parse(quelle)):
        if not (isinstance(k, ast.Call) and isinstance(k.func, ast.Name)
                and k.func.id == "_shape_err" and k.args
                and isinstance(k.args[0], ast.Constant)):
            continue
        teile = []
        for a in k.args[1:]:
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                teile.append(a.value)
            elif isinstance(a, ast.JoinedStr):
                teile += [v.value for v in a.values
                          if isinstance(v, ast.Constant) and isinstance(v.value, str)]
        if richtung.search(" ".join(teile)):
            gefunden.add(k.args[0].value)
    erlaubt = {"SUBJECT_CARDINALITY", "SUBJECT_DIGEST_EXTRA_ALGORITHMS", "UNKNOWN_STATEMENT_FIELD"}
    assert gefunden == erlaubt, (
        f"Meldungen mit Richtungs-Sprache haben sich geaendert: {sorted(gefunden)} "
        f"statt {sorted(erlaubt)} — jede neue muss belegen, dass ihre Bedingung nur diese "
        f"Richtung trifft, sonst beschreibt sie die falsche Lage.")


def test_die_drei_digest_codes_sind_wirklich_verschieden():
    """GEGENRICHTUNG. Ohne sie bestuende der Test oben auch, wenn alle drei denselben Code
    traegen — dann waere die Trennung nur behauptet."""
    def code_fuer(digest):
        st = {"_type": ar.STATEMENT_TYPE, "subject": [{"name": "x", "digest": digest}],
              "predicateType": ar.AGENT_REVIEW_PREDICATE_TYPE, "predicate": {}}
        return {getattr(e, "code", None) for e in ar.validate_statement_shape(st, {})
                if "digest" in str(e)}
    leer = code_fuer({})
    falsch = code_fuer({"sha512": "b" * 64})
    zuviel = code_fuer({"sha256": "a" * 64, "sha512": "b" * 64})
    assert leer != falsch != zuviel != leer, (
        f"die drei Lagen teilen sich Codes: leer={leer} falsch={falsch} zuviel={zuviel}")

_FORMEN_OHNE_CODE = (
    # ÜBERFANGEN, ABSICHTLICH. `_mit_abschnitt("x", e)` mit einer SCHLEIFENVARIABLEN ist
    # statisch nicht als gecodet nachweisbar — `e` kann alles sein. Die Vorgaengerfassung
    # fuehrte diese Form als korrekt, und genau darueber lief eine codelose Pruefung in der
    # BEWACHTEN Funktion durch. Laufzeitgemessen am 02.09.2026 liefert der oeffentliche
    # Haupteingang an genau diesen Stellen 14 von 14 Fehlern OHNE Code — das Ueberfangen
    # trifft hier also die Wahrheit, es ist keine blosse Vorsicht.
    'errs.extend(_mit_abschnitt("x", e) for e in ys)',
    'errs.append("codelos")',
    'errs.extend(["codelos"])',
    'errs.insert(0, "codelos")',
    'errs += ["codelos"]',
    'errs = errs + ["codelos"]',
    'errs[len(errs):] = ["codelos"]',
    'return ["codelos"]',
    'return errs + ["codelos"]',
    'return list(["codelos"])',
    'errs.extend(f"feld {x}" for x in xs)',
    'errs.append(_helfer())',
)

_FORMEN_MIT_CODE = (
    'errs.append(_shape_err("A", "mit"))',
    'errs.extend([_shape_err("A", "mit")])',
    'errs += [_shape_err("A", "mit")]',
    'return [_shape_err("A", "mit")]',
    'errs.extend(_mit_abschnitt("x", _shape_err("A", "m")) for e in ys)',
)


@pytest.mark.parametrize("form", _FORMEN_OHNE_CODE)
def test_jede_schreibweise_ohne_code_wird_gefangen(form):
    """DIE FAMILIE DER SCHREIBWEISEN, nicht die eine, die mir eingefallen ist."""
    quelle = f"def f(errs, xs, x, e, ys):\n    {form}\n"
    assert _fehlerstellen_ohne_code(quelle), f"entkommt dem Sweep: {form}"


@pytest.mark.parametrize("form", _FORMEN_MIT_CODE)
def test_jede_korrekte_schreibweise_gilt_nicht_als_verstoss(form):
    """GEGENRICHTUNG. Ein Riegel, der alles fasst, ordnet nichts."""
    quelle = f"def f(errs, xs, x, e, ys):\n    {form}\n"
    assert _fehlerstellen_ohne_code(quelle) == [], f"faelschlich gefangen: {form}"


def test_der_code_traegt_keinen_array_index():
    """DIE EIGENSCHAFT, die `_code_segment` schuetzen soll — an der Wirkung gemessen.

    Der Zeichen-Filter allein reicht NICHT: `_code_segment("findings[7]")` ergibt `FINDINGS7`,
    die Ziffer ueberlebt. Geschuetzt ist die Eigenschaft dadurch, dass die Aufrufer einen
    indexfreien `code_teil` uebergeben — und genau das wird hier gemessen, nicht die Filterform.
    """
    def code_bei(index: int):
        gute = [{"id": f"F{i}", "severity": "low", "title": "t",
                 "disposition": "open", "reason": "r"} for i in range(index)]
        doc = _doc()
        doc["declaration"]["findings"] = [*gute, "kein-objekt"]
        doc["declaration"]["findingsTotal"] = index + 1
        for e in ar.validate_agent_review_predicate(doc, strict=True):
            if "must be an object" in str(e):
                return getattr(e, "code", None)
        return None

    assert code_bei(0) is not None, "die Vorbedingung traegt nicht"
    assert code_bei(0) == code_bei(7), (
        f"der Array-Index reist in den Code: {code_bei(0)} vs {code_bei(7)}")


#: DIE RATSCHE. Wie viele Fehlerstellen ausserhalb von `validate_statement_shape` noch keinen
#: Reason Code tragen — je Funktion, GEMESSEN, nicht getippt.
#:
#: Das ist eine UMFANGSGRENZE, kein Defekt. Aber ein Titel wie "jede Formpruefung nennt ihren
#: Grund" liest sich weiter, als er misst, und genau diese Klasse hat dieser Lauf schon dreimal
#: bezahlt.
#:
#: DIE ZAHLEN SIND AM 02.09.2026 UM DEN FAKTOR DREI GEWACHSEN — 37 Stellen in 5 Funktionen wurden
#: zu 120 in 17. Nichts am Verifier hat sich geaendert; der SWEEP hat aufgehoert, die Gewohnheit
#: des Autors zu messen. Drei Erweiterungen, jede aus einem gemessenen Fehltreffer:
#:   1. Der Bezeichner `errs` wurde durch die Eigenschaft ersetzt (die Liste, die die Funktion
#:      zurueckgibt). `validate_agent_review_predicate` fuellt `errors` und hatte 13 ungesehene.
#:   2. Das Ergebnisfeld `r["errors"]` kam dazu. Dort liegen die neun Ablehnungswege, die eine
#:      Gegenlesung als codelos gemessen hat — Signatur ungueltig, fremdes Ziel, Rumpf abweichend.
#:   3. Zwei zu weite Zweige wurden verengt (jede Neuzuweisung, jeder Dict-Schluessel zaehlte),
#:      was neun Fehltreffer entfernte, die die alte handverlesene Funktionsliste verdeckt hatte.
#:
#: ZWEITES WACHSTUM AM 02.09.2026, +7 Stellen (120 -> 127). Wieder hat sich am Verifier nichts
#: geaendert: `_ist_gecodet` fuehrte `_mit_abschnitt` als Code-Traeger, obwohl es einen Code nur
#: WEITERGIBT, wenn der eingepackte Fehler schon einen hat. Fuenf `_mit_abschnitt`-Zeilen im
#: oeffentlichen Haupteingang galten deshalb als gruen, waehrend dieselbe Funktion zur Laufzeit
#: 14 von 14 Fehlern OHNE Code liefert. Die Bedingung wird jetzt geprueft statt angenommen, und
#: die sieben Stellen stehen hier, wo sie hingehoeren.
#:
#: DIE MENGE DER FUNKTIONEN WIRD MITGEMESSEN. Eine neue Funktion mit codelosen Stellen faellt
#: hier, auch wenn niemand sie hier eintraegt — die Vorgaengerfassung listete fuenf Namen von Hand
#: und war fuer alles andere blind.
GRUNDLINIE_CODELOS = {
    "_pruefe_sichtbaren_block": 2,
    "_validate_assured": 7,
    "_validate_coverage": 12,
    "_validate_declaration": 10,
    "_validate_finding": 9,
    "_validate_limitation_codes": 4,
    "_validate_subject": 8,
    "_validate_supersession": 5,
    "_validate_times": 4,
    "_verify_agent_review_inner": 14,
    "_verify_v02_inner": 13,
    "_zielbindung": 4,
    "validate_agent_review_predicate": 19,
    "validate_agent_review_v02_predicate": 5,
    "validate_time_claim": 9,
    "verify_agent_review": 1,
    "verify_agent_review_v02": 1,
}


#: DIE VORAUSSETZUNG DER MESSUNG, selbst gepinnt.
#:
#: Eine Ratsche ueber eine ERHOBENE Zahl ist nur so gut wie die Erhebung. Gemessen am 02.09.2026:
#: `return errors` -> `return errors[:]` — Verhalten nachweislich unveraendert — liess die Zahl
#: des oeffentlichen Haupteingangs von 14 auf 1 fallen, weil der Sweep den Traeger nicht mehr
#: erkannte. Die Ratsche meldete „GESUNKEN — gute Nachricht, Grundlinie nachziehen". Dem Rat
#: gefolgt und fuenf codelose Pruefungen ergaenzt: die Suite blieb gruen. Der Riegel hatte sich beim normalen
#: Refactoring selbst abgebaut, und seine eigene Empfehlung war der Weg dorthin.
#:
#: Zehn Rueckgabeformen sind jetzt bekannt — aber eine Liste von Formen kann die ELFTE nicht
#: kennen. Deshalb steht hier, WELCHE Traeger je Funktion erkannt werden. Verschwindet einer, ist
#: das ein BEFUND und keine gute Nachricht: die Zahl faellt dann, weil das Instrument blind wurde.
GRUNDLINIE_TRAEGER = {
    "_pruefe_sichtbaren_block": [],
    "_validate_assured": ["errs"],
    "_validate_coverage": ["errs"],
    "_validate_declaration": ["errs"],
    "_validate_finding": ["errs"],
    "_validate_limitation_codes": ["errs"],
    "_validate_subject": ["errs"],
    "_validate_supersession": ["errs"],
    "_validate_times": ["errs"],
    "_verify_agent_review_inner": ["r"],
    "_verify_v02_inner": ["r"],
    "_zielbindung": [],
    "validate_agent_review_predicate": ["errors"],
    "validate_agent_review_v02_predicate": ["errs"],
    "validate_time_claim": ["errs"],
    "verify_agent_review": [],
    "verify_agent_review_v02": [],
}


def _traeger_aller_funktionen() -> dict[str, list[str]]:
    """Welche Fehlerlisten erkennt der Sweep heute je Funktion?"""
    lage: dict[str, list[str]] = {}
    # ES WIRD UEBER DEN PIN ITERIERT, UND DAS IST GEPRUEFT — nicht angenommen.
    #
    # Eine adversariale Linse meldete am 02.09.2026, die Schleife sei EINSEITIG: sie laufe ueber
    # `GRUNDLINIE_TRAEGER`, also koenne eine ENTFERNTE Funktion nie auffallen, und die vier
    # Eintraege mit leerer Liste koennten ohnehin nichts melden. Der Befund klingt richtig. Er ist
    # es nicht, und das ist mit eingepflanztem Defekt in BEIDEN Spielarten gemessen:
    #
    #   `_validate_times` entfernt (Pin `["errs"]`) -> `verloren` faellt, weil `lage.get(k, [])`
    #       fuer die fehlende Funktion `[]` liefert und die Sollmenge uebrig bleibt
    #   `_zielbindung`    entfernt (Pin `[]`)       -> faellt ebenfalls, ueber `fehlend`
    #
    # Beide Male rot, danach byte-genau zurueckgestellt. Der Kommentar steht hier, damit die
    # naechste Gegenlesung nicht denselben plausiblen Fehlschluss ein zweites Mal zieht: die
    # leere Liste traegt nichts ueber `verloren`, aber `fehlend` deckt sie ab.
    for name in GRUNDLINIE_TRAEGER:
        fn = getattr(ar, name, None)
        if fn is None:
            continue
        try:
            quelle = textwrap.dedent(inspect.getsource(fn))
        except (OSError, TypeError):
            continue
        lage[name] = sorted(_fehlerlisten_namen(ast.parse(quelle)) - {"errs"}
                            | ({"errs"} if "errs" in _fehlerlisten_namen(ast.parse(quelle)) else set()))
    return lage


def _urteile_traeger(lage: dict[str, list[str]]) -> None:
    """DAS URTEIL, EINMAL — und beide Aufrufer FUEHREN es aus, statt es nachzubauen.

    Die erste Fassung hatte den Test und seinen Meta-Test getrennt gerechnet: der Meta-Test baute
    die Verlust-Menge selbst nach, statt das Urteil zu rufen. Ein deterministischer Pre-Sweep hat
    das am 02.09.2026 gemessen — `assert not verloren` durch `assert True or not verloren`
    ersetzt, und BEIDE Tests blieben gruen. Ein Meta-Test, der den Prueflig nachbaut, beweist nur,
    dass sein eigener Nachbau funktioniert.
    """
    verloren = {k: (v, lage.get(k, [])) for k, v in GRUNDLINIE_TRAEGER.items()
                if set(v) - set(lage.get(k, []))}
    assert not verloren, (
        f"der Sweep erkennt Fehlerlisten NICHT mehr, die er kannte (soll, ist): {verloren}. "
        f"Das ist kein Fortschritt, sondern eine blind gewordene Messung — pruefe, ob die "
        f"Rueckgabeform geaendert wurde (`return errs[:]`, `errs or []`, `tuple(errs)`, …).")
    # Die Eintraege mit leerer Liste (`[]`) koennen ueber `verloren` NIE etwas melden — eine leere
    # Sollmenge ist immer erfuellt. Ihr Wert liegt ALLEIN hier: verschwindet die Funktion, faellt es.
    fehlend = sorted(set(GRUNDLINIE_TRAEGER) - set(lage))
    assert not fehlend, f"Funktion(en) aus der Traeger-Grundlinie gibt es nicht mehr: {fehlend}"


def test_der_sweep_verliert_keinen_traeger():
    """DIE VORAUSSETZUNG DER MESSUNG. Ein verlorener Traeger ist ein BEFUND, keine gute Nachricht."""
    _urteile_traeger(_traeger_aller_funktionen())


def test_meta_ein_verlorener_traeger_wird_gefangen():
    """META, und es FUEHRT das Urteil aus statt es nachzubauen.

    Wird `_urteile_traeger` stumm geschaltet, faellt dieser Test — genau das konnte die erste
    Fassung nicht.
    """
    lage = dict(_traeger_aller_funktionen())
    lage["validate_agent_review_predicate"] = []          # der blendende Umbau, simuliert
    with pytest.raises(AssertionError, match="NICHT mehr"):
        _urteile_traeger(lage)


def test_meta_das_urteil_ist_bei_gesunder_lage_still():
    """GEGENRICHTUNG. Ein Urteil, das immer wirft, faengt alles und misst nichts."""
    _urteile_traeger(_traeger_aller_funktionen())


def _lage_aller_funktionen() -> dict[str, int]:
    """Misst JEDE Funktion des Moduls, nicht eine Auswahl."""
    lage: dict[str, int] = {}
    for name in dir(ar):
        fn = getattr(ar, name, None)
        if not callable(fn) or getattr(fn, "__module__", "") != ar.__name__:
            continue
        try:
            quelle = textwrap.dedent(inspect.getsource(fn))
        except (OSError, TypeError):
            continue
        anzahl = len(_fehlerstellen_ohne_code(quelle))
        if anzahl:
            lage[name] = anzahl
    return lage


def test_die_ungedeckte_flaeche_waechst_nicht():
    """RATSCHE ueber das, was AUSSERHALB der bewachten Funktion liegt.

    Ohne diese Zahlen liesse sich der Rest des Verifiers beliebig um codelose Pruefungen
    erweitern, waehrend der Test darueber gruen bleibt und einen Umfang suggeriert, den er nicht
    hat. Sinkt eine Zahl, gehoert sie hier gesenkt — das ist der Zweck einer Ratsche.
    """
    lage = _lage_aller_funktionen()
    gewachsen = {k: (GRUNDLINIE_CODELOS[k], v) for k, v in lage.items()
                 if k in GRUNDLINIE_CODELOS and v > GRUNDLINIE_CODELOS[k]}
    assert not gewachsen, f"codelose Fehlerstellen sind gewachsen (soll, ist): {gewachsen}"
    neu_dazu = {k: v for k, v in lage.items() if k not in GRUNDLINIE_CODELOS}
    assert not neu_dazu, (
        f"NEUE Funktion(en) mit codelosen Fehlerstellen: {neu_dazu} — entweder Codes vergeben "
        f"oder hier bewusst eintragen. Genau diese Blindheit hatte die handverlesene Vorfassung.")
    gesunken = {k: (GRUNDLINIE_CODELOS[k], lage.get(k, 0)) for k in GRUNDLINIE_CODELOS
                if lage.get(k, 0) < GRUNDLINIE_CODELOS[k]}
    # ZWEI URSACHEN, ZWEI MELDUNGEN. Die Vorgaengerfassung sagte bei jedem Sinken „gute Nachricht,
    # Grundlinie nachziehen" — auch dann, wenn der Sweep blind geworden war. Wer dem Rat folgt,
    # baut den Riegel ab. `test_der_sweep_verliert_keinen_traeger` trennt die beiden Faelle; hier
    # steht die Trennung nur noch im Satz.
    traeger = _traeger_aller_funktionen()
    blind = {k for k in gesunken if set(GRUNDLINIE_TRAEGER.get(k, [])) - set(traeger.get(k, []))}
    assert not gesunken, (
        f"codelose Stellen sind GESUNKEN: {gesunken}. "
        + (f"ACHTUNG, fuer {sorted(blind)} ist das KEINE gute Nachricht — der Sweep erkennt dort "
           f"die Fehlerliste nicht mehr, die Zahl faellt wegen Blindheit. Erst die Rueckgabeform "
           f"pruefen." if blind else
           "Fuer alle genannten Funktionen werden die Fehlerlisten weiterhin erkannt, es ist also "
           "wirklich besser geworden — Grundlinie nachziehen."))


def test_meta_der_sweep_haengt_nicht_am_bezeichner_errs():
    """META fuer die Klasse, die am 02.09.2026 gemessen wurde.

    Eine codelose Fehlerstelle in einer Funktion, die den Namen `errs` GAR NICHT benutzt, muss
    gefangen werden. Die Vorgaengerfassung sah hier nichts — und genau so entkam der oeffentliche
    Haupteingang mit 13 Stellen.
    """
    quelle = 'def f(problems, x):\n    problems.append("codelos")\n    return problems\n'
    assert len(_fehlerstellen_ohne_code(quelle)) == 1, (
        "eine codelose Stelle in einer Liste, die NICHT `errs` heisst, entkommt dem Sweep")
    gut = 'def f(problems, x):\n    problems.append(_shape_err("A", "mit"))\n    return problems\n'
    assert _fehlerstellen_ohne_code(gut) == [], "die Gegenrichtung ist rot, der Test waere wertlos"


def test_meta_das_ergebnisfeld_wird_mitgemessen():
    """META. `r["errors"].append(...)` ist der Traeger der schwersten Ablehnungswege."""
    quelle = 'def f(r):\n    r["errors"].append("codelos")\n'
    assert len(_fehlerstellen_ohne_code(quelle)) == 1, (
        'eine codelose Stelle an r["errors"] entkommt dem Sweep')


def test_meta_eine_zuweisung_ist_keine_fuellung():
    """META, Gegenrichtung. Ohne diese Verengung zaehlten neun harmlose Stellen als Verstoss."""
    for harmlos in ('errs = pruefer(x)', 'neu = a[:1] + b[2:]', 'aus["feld"] = "wert"'):
        quelle = f'def f(errs, neu, aus, a, b, pruefer, x):\n    {harmlos}\n    return errs\n'
        assert _fehlerstellen_ohne_code(quelle) == [], f"Fehltreffer bei {harmlos!r}"


def test_die_bewachte_funktion_ist_wirklich_leer():
    """Die Gegenrichtung zur Ratsche: im bewachten Bereich steht die Zahl auf null."""
    import textwrap
    assert _fehlerstellen_ohne_code(
        textwrap.dedent(inspect.getsource(ar.validate_statement_shape))) == []
