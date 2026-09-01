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
            if isinstance(ziel, ast.Name) and ziel.id == "errs" and k.func.attr in (
                    "append", "extend", "insert"):
                # insert(0, x) -> das Element ist das ZWEITE Argument
                pruefe(k.args[1:] if k.func.attr == "insert" else k.args, zeile)
        elif isinstance(k, ast.AugAssign) and isinstance(k.target, ast.Name) and k.target.id == "errs":
            pruefe([k.value], zeile)
        elif isinstance(k, ast.Assign):
            for z in k.targets:
                # errs = errs + [...]  und  errs[len(errs):] = [...]
                if (isinstance(z, ast.Name) and z.id == "errs") or (
                        isinstance(z, ast.Subscript) and isinstance(z.value, ast.Name)
                        and z.value.id == "errs"):
                    w = k.value
                    if isinstance(w, ast.BinOp):
                        pruefe([w.right], zeile)
                    else:
                        pruefe([w], zeile)
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
    assert "LEGACY_SELF_DECLARED_OBSERVED_AT" in r["reason_codes"], (
        "die Vorbedingung traegt nicht — ohne den Hinweis prueft dieser Test nichts")
    assert r["reason_code"] is None, (
        f"ein HINWEIS ist zum Fehlgrund geworden: {r['reason_code']!r}")


#: Die elf Schreibweisen, mit denen ein Autor eine Fehlerliste fuellen kann. Acht davon entkamen
#: der ersten Fassung des Sweeps — gemessen von einer adversarialen Gegenlesung, nicht vermutet.
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


#: WAS DIESER TEST NICHT DECKT — gemessen und benannt, statt implizit offengelassen.
#:
#: `test_keine_formpruefung_ohne_code` bewacht `validate_statement_shape`. Der uebrige
#: Validator-Stapel traegt weiterhin codelose Fehlerstellen; eine adversariale Gegenlesung hat am
#: 01.09.2026 gezaehlt und darauf hingewiesen, dass die Abnahme nur die Statement-Form nennt.
#: Das ist eine UMFANGSGRENZE, kein Defekt — aber ein Titel wie "jede Formpruefung nennt ihren
#: Grund" liest sich weiter, als er misst, und genau diese Klasse hat dieser Lauf schon zweimal
#: bezahlt. Die Zahlen stehen deshalb hier, als Ratsche: sie duerfen nicht wachsen.
GRUNDLINIE_CODELOS = {
    "validate_agent_review_predicate": 1,
    "_validate_assured": 7,
    "_validate_finding": 9,
    "_validate_subject": 8,
    "_validate_coverage": 12,
}


def test_die_ungedeckte_flaeche_waechst_nicht():
    """RATSCHE ueber das, was AUSSERHALB der bewachten Funktion liegt.

    Ohne diese Zahlen liesse sich der Rest des Verifiers beliebig um codelose Pruefungen
    erweitern, waehrend der Test darueber gruen bleibt und einen Umfang suggeriert, den er nicht
    hat. Sinkt eine Zahl, gehoert sie hier gesenkt — das ist der Zweck einer Ratsche.
    """
    import textwrap
    lage = {}
    for name, erwartet in GRUNDLINIE_CODELOS.items():
        fn = getattr(ar, name)
        lage[name] = len(_fehlerstellen_ohne_code(textwrap.dedent(inspect.getsource(fn))))
    gewachsen = {k: (GRUNDLINIE_CODELOS[k], v) for k, v in lage.items() if v > GRUNDLINIE_CODELOS[k]}
    assert not gewachsen, f"codelose Fehlerstellen sind gewachsen (soll, ist): {gewachsen}"
    gesunken = {k: (GRUNDLINIE_CODELOS[k], v) for k, v in lage.items() if v < GRUNDLINIE_CODELOS[k]}
    assert not gesunken, (
        f"codelose Stellen sind GESUNKEN — gute Nachricht, Grundlinie nachziehen: {gesunken}")


def test_die_bewachte_funktion_ist_wirklich_leer():
    """Die Gegenrichtung zur Ratsche: im bewachten Bereich steht die Zahl auf null."""
    import textwrap
    assert _fehlerstellen_ohne_code(
        textwrap.dedent(inspect.getsource(ar.validate_statement_shape))) == []
