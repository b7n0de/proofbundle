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
    env = copy.deepcopy(ar.emit_agent_review(_doc(), SK))
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
    r = ar.verify_agent_review(ar.emit_agent_review(doc, SK), PK, strict=True,
                               expected_subject_digest=ar._subject_digest(doc),
                               observed_body=KOERPER)
    assert r["ok"] is True
    assert r["reason_code"] is None, f"ein gueltiges Receipt traegt einen Fehlgrund: {r['reason_code']}"


def _formpruefung_quelle() -> str:
    return textwrap.dedent(inspect.getsource(ar.validate_statement_shape))


def _ist_gecodet(w: ast.AST) -> bool:
    """Entsteht dieser Wert durch die Code-Vergabe?"""
    if isinstance(w, ast.Call) and isinstance(w.func, ast.Name):
        return w.func.id in ("_shape_err", "ShapeError", "_mit_abschnitt")
    if isinstance(w, ast.Call) and isinstance(w.func, ast.Attribute):
        return w.func.attr in ("_shape_err", "_mit_abschnitt")
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
    schon einmal ueber elf SCHREIBWEISEN verbreitert worden — aber nie ueber den VARIABLENNAMEN,
    und der eigene Hauptvalidator benutzt den anderen. Das ist woertlich die Klasse, die der
    Docstring von `_fehlerstellen_ohne_code` selbst benennt.

    GEMESSEN, warum genau diese Regel und nicht "jeder Name": ueber alle Namen zaehlt der Sweep
    88 Stellen, davon 6 zu Unrecht — Merkle-Blaetter in `findings_root`, Textteile in
    `render_disclosure_line` und die drei Ergebnislisten von `resolve_receipt_chain` sind keine
    Fehlerlisten. Die Regel "was die Funktion zurueckgibt" trifft die 11 Validatoren und keinen
    der sechs Fehltreffer.
    """
    namen: set[str] = set()
    for k in ast.walk(baum):
        if isinstance(k, ast.Return) and k.value is not None:
            w = k.value
            if isinstance(w, ast.Name):
                namen.add(w.id)
            elif isinstance(w, ast.BinOp) and isinstance(w.left, ast.Name):
                namen.add(w.left.id)
            elif isinstance(w, ast.Call) and isinstance(w.func, ast.Name) and w.func.id in (
                    "list", "sorted"):
                for a in w.args:
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
    darunter `errs.extend(...)`, das dieses Modul an sieben Stellen SELBST benutzt. Ein Riegel,
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
                    if (isinstance(w, ast.BinOp) and isinstance(w.right, ast.List)
                            and isinstance(w.left, ast.Name) and w.left.id in nur):
                        pruefe(w.right.elts, zeile)
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
    r = ar.verify_agent_review(ar.emit_agent_review(doc, SK), PK, strict=True,
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
    umschlag = ar.emit_agent_review(doc, SK)
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
    'errs.extend(_mit_abschnitt("x", e) for e in ys)',
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
#: DIE MENGE DER FUNKTIONEN WIRD MITGEMESSEN. Eine neue Funktion mit codelosen Stellen faellt
#: hier, auch wenn niemand sie hier eintraegt — die Vorgaengerfassung listete fuenf Namen von Hand
#: und war fuer alles andere blind.
GRUNDLINIE_CODELOS = {
    "_pruefe_sichtbaren_block": 2,
    "_validate_assured": 7,
    "_validate_coverage": 12,
    "_validate_declaration": 8,
    "_validate_finding": 9,
    "_validate_limitation_codes": 4,
    "_validate_subject": 8,
    "_validate_supersession": 5,
    "_validate_times": 4,
    "_verify_agent_review_inner": 14,
    "_verify_v02_inner": 13,
    "_zielbindung": 4,
    "validate_agent_review_predicate": 14,
    "validate_agent_review_v02_predicate": 5,
    "validate_time_claim": 9,
    "verify_agent_review": 1,
    "verify_agent_review_v02": 1,
}


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
    assert not gesunken, (
        f"codelose Stellen sind GESUNKEN — gute Nachricht, Grundlinie nachziehen: {gesunken}")


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
