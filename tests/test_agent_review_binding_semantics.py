"""`ok` heisst nicht "gueltig", sondern "brauchbar als Beleg FUER DAS OBJEKT VOR DIR".

DER ANGRIFF, DER DIESE TRENNUNG ERZWANG (externe Gegenlesung, zweite Runde, 31.08.2026). Ein
Angreifer nimmt ein gueltiges Receipt fuer Vorgang A und legt es bei Vorgang B vor. Am Envelope
aendert er nichts — er luegt daneben. Ein Pruefpfad, der nur `ok` liest (etwa eine Pipeline mit der
Frage "gibt es hier ein gueltiges Receipt"), bekam gruen.

Die naheliegende Abwehr waere eine Warnung gewesen. Sie traegt nicht: neben einem gruenen Ergebnis
wird sie ueberlesen. Also zwei Felder, zwei Aussagen — und `ok` ist die staerkere.
"""
import base64
import copy
import json
import sys
import unittest
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from proofbundle import agent_review as AR  # noqa: E402

BODY = "# T\n\nText.\n"
FINDINGS = [{"id": "F1", "severity": "low", "title": "t", "disposition": "dismissed", "reason": "r"}]


def _pred(**patch):
    p = {
        "schemaVersion": "0.1.0", "reviewId": "r",
        "subjectContext": {"kind": "githubPullRequest", "forge": "github.com",
                           "repositoryId": "R", "pullRequestNodeId": "PR",
                           "headSha": "a" * 40, "baseSha": "b" * 40,
                           "reviewedDiffDigest": "c" * 64,
                           "bodyCoreDigest": AR.body_core_digest(BODY),
                           # v0.2 verlangt sie, und der Emitter stellt ab 6.0.0 v0.2 aus.
                           # Derselbe Wert wie bodyCoreDigest: dieser Test variiert den
                           # sichtbaren Block nicht, er prueft die BINDUNG an den
                           # Gegenstand, nicht die Offenlegung.
                           "disclosureCoreDigest": AR.body_core_digest(BODY)},
        "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "x"}],
                        "reviewRuns": [], "findings": FINDINGS, "findingsTotal": 1,
                        "findingsRoot": AR.findings_root(FINDINGS), "nonClaims": ["n"]},
        "coverage": {"status": "UNKNOWN"},
        "times": {"declaredAt": "2026-08-31T17:00:00Z"},
        "limitations": ["l"],
    }
    p.update(patch)
    # limitationCodes sind in v0.2 Pflicht und werden ABGELEITET, nie getippt — ein
    # handgesetzter Code driftet vom Inhalt weg, ohne dass ein Digest sich bewegt. Nach
    # `patch`, damit ein veraendertes Praedikat die dazu passenden Codes bekommt; und nur
    # wenn der Test sie nicht selbst gesetzt hat, denn dann prueft er genau sie.
    p.setdefault("limitationCodes", AR.derive_limitation_codes(p))
    return p


def _pruefe(env, pk, **kw):
    """Der Verifier fuer die Version, die dieses Haus AUSSTELLT — plus eine Sperre.

    ZWEI DINGE IN EINER STELLE, und beide sind gemessen (02.09.2026).

    ERSTENS die Version. Der Emitter stellt ab 6.0.0 v0.2 aus. Wuerden diese Tests weiter mit dem
    v0.1-Verifier pruefen, pruefte nach dem Release niemand mehr die Bindungssemantik auf der
    Fassung, die wir wirklich ausliefern — ein Waechter fuer eine Version, die es nicht mehr gibt.

    ZWEITENS die Sperre. Fuehrt man ein v0.2-Receipt durch den v0.1-Verifier, meldet er korrekt
    `ok=False` mit `UNKNOWN_PREDICATE_VERSION` — aber `assurance_ok`, `crypto_ok` und
    `internal_subject_consistency_ok` behalten `True`, weil sie VOR der Versionspruefung gerechnet
    werden. Von dreizehn Aufrufstellen fielen nach der Umstellung nur fuenf Tests; die uebrigen
    waeren teils vakuos gruen geblieben. Ein gruener Test auf einem abgelehnten Receipt meldet
    Deckung, die es nicht gibt.

    Deshalb EINE Stelle statt dreizehn Einzelfixes: eine Versionsablehnung wird hier zum
    Testfehler mit Namen, egal welche Achse der Aufrufer danach liest.
    """
    r = AR.verify_agent_review_v02(env, pk, **kw)
    if r.get("reason_code") == "UNKNOWN_PREDICATE_VERSION":
        raise AssertionError(
            "der Verifier hat dieses Receipt wegen der predicateType-Version ABGELEHNT — jede "
            "Achse, die hier noch True traegt, wurde vor der Ablehnung gerechnet und sagt nichts "
            f"ueber den geprueften Gegenstand aus (reason_codes={r.get('reason_codes')})")
    return r


@pytest.fixture
def paar():
    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    return sk, sk.public_key().public_bytes_raw()


def test_ohne_erwartung_ist_ok_falsch_und_die_konsistenz_wahr(paar):
    """DER KERN. Das Receipt ist in sich stimmig — aber nichts hier sagt, dass es hierher gehoert."""
    sk, pk = paar
    r = _pruefe(AR.emit_agent_review(_pred(), sk), pk)
    assert r["internal_consistency_ok"] is True
    assert r["ok"] is False
    assert r["subject_expectation"] == "not_supplied"
    # AN DIE EIGENSCHAFT GEBUNDEN, NICHT AN DEN WORTLAUT (nachgezogen 02.09.2026). Vorher stand
    # hier ein Substring-Vergleich auf „belongs to the object". v0.2 sagt dasselbe mit anderen
    # Worten („no expected subject digest was supplied"), und der Test waere rot geworden, obwohl
    # die gepruefte Eigenschaft unveraendert haelt. Ein Test, der an einer Formulierung haengt,
    # misst die Formulierung. Gemessen wird jetzt, dass der Grund die FEHLENDE ERWARTUNG benennt.
    assert r["errors"], "ohne Erwartung muss ein Grund genannt werden, nicht bloss ok=False"
    assert any("expected subject" in e for e in r["errors"]), r["errors"]


def test_mit_richtiger_erwartung_ist_ok_wahr(paar):
    sk, pk = paar
    p = _pred()
    r = _pruefe(AR.emit_agent_review(p, sk), pk,
                               expected_subject_digest=AR._subject_digest(p))
    assert r["ok"] is True and r["subject_expectation"] == "checked"


def test_fremdes_receipt_faellt_gegen_die_erwartung_durch(paar):
    """Der Angriff selbst: gueltiges Receipt fuer A, vorgelegt bei B."""
    sk, pk = paar
    a = _pred()
    b = copy.deepcopy(a)
    b["subjectContext"]["pullRequestNodeId"] = "PR_ANDERER"
    r = _pruefe(AR.emit_agent_review(b, sk), pk,
                               expected_subject_digest=AR._subject_digest(a))
    assert r["ok"] is False and r["subject_binding_ok"] is False


def test_eine_warnung_allein_haette_nicht_getragen(paar):
    """Festgehalten, weil es die verworfene Alternative ist: die Warnung STEHT weiterhin da, aber
    sie ist nicht mehr das Einzige. Wer nur `ok` liest, ist jetzt sicher."""
    sk, pk = paar
    r = _pruefe(AR.emit_agent_review(_pred(), sk), pk)
    assert any("expected_subject_digest" in w for w in r["warnings"])
    assert r["ok"] is False, "die Warnung ersetzt das Urteil nicht, sie begleitet es"


def test_kaputte_signatur_macht_auch_die_konsistenz_falsch(paar):
    """Die Gegenrichtung: `internal_consistency_ok` ist kein Trostpreis, den es immer gibt."""
    sk, pk = paar
    env = AR.emit_agent_review(_pred(), sk)
    env["signatures"][0]["sig"] = base64.b64encode(b"\x00" * 64).decode()
    r = _pruefe(env, pk, expected_subject_digest="0" * 64)
    assert r["internal_consistency_ok"] is False and r["ok"] is False


def test_das_statement_traegt_die_erwartete_form(paar):
    sk, _ = paar
    env = AR.emit_agent_review(_pred(), sk)
    stmt = json.loads(base64.b64decode(env["payload"]))
    # DIESER TEST IST DER WAECHTER UEBER DIE EMITTER-VORGABE (Owner-Festlegung 2, 02.09.2026).
    # Ab 6.0.0 stellt der Emitter v0.2 aus; wer die Vorgabe still zurueckdreht, faellt hier auf.
    # Die Gegenrichtung steht daneben: v0.1 bleibt AUSSTELLBAR, nur nicht mehr als Vorgabe.
    assert stmt["predicateType"] == AR.AGENT_REVIEW_PREDICATE_TYPE_V02
    alt = json.loads(base64.b64decode(AR.emit_agent_review(_pred(), sk, v02=False)["payload"]))
    assert alt["predicateType"] == AR.AGENT_REVIEW_PREDICATE_TYPE
    assert stmt["subject"][0]["digest"]["sha256"] == AR._subject_digest(_pred())


# ── never-raise: der Verify-Pfad liefert IMMER ein typisiertes Ergebnis ────────────────────────

def _handgebaut(assurance_wert):
    """Ein Statement, das der Emitter ABLEHNEN wuerde — genau deshalb von Hand gebaut. Ein
    Angreifer benutzt den Emitter nicht."""
    from proofbundle import canonical, dsse
    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    praedikat = {
            "schemaVersion": "0.1.0", "reviewId": "r",
            "subjectContext": {"kind": "githubPullRequest", "forge": "g", "repositoryId": "R",
                               "pullRequestNodeId": "P", "headSha": "a" * 40, "baseSha": "b" * 40,
                               "reviewedDiffDigest": "c" * 64, "bodyCoreDigest": "d" * 64},
            "declaration": {"authoring": [{"assurance": assurance_wert, "assertedBy": "x"}],
                            "reviewRuns": [], "findings": [], "findingsTotal": 0,
                            "nonClaims": ["n"]},
            "coverage": {"status": "UNKNOWN"},
            "times": {"declaredAt": "2026-08-31T17:00:00Z"},
            "limitations": ["l"]}
    # DER NAME WIRD ABGELEITET, NICHT GETIPPT (nachgezogen 31.08.2026). Vorher stand hier `"x"`.
    # Seit der Statement-Typisierung (P0.1/P0.3) faellt ein Name, der nicht aus dem signierten
    # subjectContext folgt, schon in der Formpruefung — und dann liefe die Assurance-Pruefung, die
    # dieser Test eigentlich meint, gar nicht mehr. Der Schutz bestuende weiter, der Test bewiese
    # ihn nicht: genau die Klasse "der Fix wurde zwei Stellen weiter verworfen".
    stmt = {
        "_type": AR.STATEMENT_TYPE,
        "subject": [{"name": AR._subject_name(praedikat),
                     "digest": {"sha256": AR._subject_digest(praedikat)}}],
        # DER TYP FOLGT DEM VERIFIER, GEGEN DEN GEPRUEFT WIRD (nachgezogen 02.09.2026). Der
        # Emitter stellt ab 6.0.0 v0.2 aus, also prueft dieser Test mit dem v0.2-Verifier — und
        # ein handgebautes Statement mit v0.1-Typ wuerde von ihm wegen der VERSION abgelehnt.
        # Dann liefe die Assurance-Pruefung, die dieser Test eigentlich meint, gar nicht mehr.
        # Genau dieselbe Klasse, die der Kommentar zum Namen oben beschreibt, nur eine Ebene
        # hoeher: der Schutz bestuende weiter, der Test bewiese ihn nicht.
        "predicateType": AR.AGENT_REVIEW_PREDICATE_TYPE_V02,
        "predicate": praedikat,
    }
    env = dsse.sign_envelope(canonical.canonicalize_statement(stmt), sk,
                             payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)
    return env, sk.public_key().public_bytes_raw()


@pytest.mark.parametrize("wert,beschreibung", [
    (["unhashbar"], "eine Liste"),
    ({"a": 1}, "ein Dict"),
    (42, "eine Zahl"),
])
def test_ein_unhashbarer_assurance_wert_wirft_nicht(wert, beschreibung):
    """DER DEFEKT, DEN CI GEFUNDEN HAT — und der schwerere lag eine Zeile ueber dem gemeldeten.

    Der Linter monierte einen ungeschuetzten `in`-Test auf einer hashenden Menge. Die eigentliche
    Gefahr war die MENGE selbst: `rungs` war eine set-Comprehension ueber produzentenbestimmte
    Werte, und ein unhashbarer Wert liess dort eine ROHE TypeError aus einem Verify-Pfad fallen,
    der vertraglich immer ein typisiertes Ergebnis liefert. Ausgefuehrt gemessen, bevor der Fix
    kam: `unhashable type: 'list'`.

    Haette ich nur den gemeldeten Punkt gefixt, waere der schwerere geblieben und die Suite
    gruen geworden."""
    env, pk = _handgebaut(wert)
    r = _pruefe(env, pk)          # darf NICHT werfen
    assert r["ok"] is False and r["assurance_ok"] is False, beschreibung


def test_ein_zulaessiger_wert_bleibt_zulaessig():
    """Die Gegenrichtung: die Haertung darf den Normalfall nicht miterschlagen."""
    env, pk = _handgebaut("selfDeclared")
    assert _pruefe(env, pk)["assurance_ok"] is True


# ── der Erwartungsvergleich wird EXAKT gefuehrt ────────────────────────────────────────────────

class ErwartungsvergleichIstExakt(unittest.TestCase):
    """`expected_subject_digest` wird exakt verglichen — nicht per startswith, casefold oder strip.

    WARUM DAS EIN EIGENER TEST IST. Der Vergleich ist die einzige Stelle, an der ein Leser sagen
    kann "dieses Receipt gehoert zu DEM Vorgang vor mir". Waere er lockerbar, koennte ein Receipt
    mit einem Digest durchgehen, der dem erwarteten nur AEHNELT — und Aehnlichkeit ist bei einem
    Hash keine Naehe, sondern ein anderer Gegenstand. Ein Riegel des Hauses meldete diesen
    Vergleich als einzigen ohne Beinahe-Treffer-Korpus; er hatte recht.

    Korpus aus `tests/_beinahe_treffer.py` — dieselbe Quelle wie kbjwt, statuslist und intoto.
    """

    def test_expected_subject_digest_wird_EXAKT_verglichen(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from _beinahe_treffer import pruefe_exakt

        sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        pk = sk.public_key().public_bytes_raw()
        p = _pred()
        env = AR.emit_agent_review(p, sk)
        erwartet = AR._subject_digest(p)

        # Gegenprobe des Aufbaus: mit dem RICHTIGEN Digest ist es gueltig. Ohne diese Zeile misst
        # der Korpus unten nichts — jede Abwandlung waere schon deshalb falsch, weil alles falsch ist.
        self.assertTrue(
            _pruefe(env, pk, expected_subject_digest=erwartet)["ok"],
            "der selbstgebaute Beleg verifiziert nicht — die Pruefung unten misst dann nichts")

        pruefe_exakt(
            lambda v: _pruefe(env, pk, expected_subject_digest=v)["ok"],
            erwartet, self)


# ═══ P0.3 · ZWEI ACHSEN STATT EINER (Gegenlese Runde 2, N04) ═══════════════════════════════════
#
# DIE LUECKE, DIE DIESE TESTS SCHLIESSEN, und sie ist selbst gemessen: als die Achse am 01.09.2026
# von `True` auf `None` umgestellt wurde, blieben 84 bestehende Tests gruen. KEINER pinnte, was
# `subject_binding_ok` ohne Zielkontext bedeutet — genau die Stelle, an der die Gegenlese ein
# gruenes Bindungs-Signal fuer eine ungepruefte Bindung fand. Ein Feld, dessen Bedeutung kein Test
# haelt, kann sich in beide Richtungen bewegen, ohne dass es auffaellt.


def test_ohne_zielkontext_ist_die_bindungsachse_NIE_wahr(paar):
    """DER WORTLAUT DER ABNAHME: „Ohne Zielkontext lautet der Zustand NOT_EVALUATED, niemals
    subject_binding_ok=True." Vorher stand die Achse hier auf `True`."""
    sk, pk = paar
    r = _pruefe(AR.emit_agent_review(_pred(), sk), pk)
    assert r["internal_subject_consistency_ok"] is True, "die interne Konsistenz IST gegeben"
    assert r["expected_subject_match"] == "NOT_EVALUATED"
    assert r["subject_binding_ok"] is not True, (
        "ohne unabhaengig erfasste Zielbytes darf die Bindungsachse nie gruen sein — "
        f"war {r['subject_binding_ok']!r}")
    assert r["subject_binding_ok"] is None, "und auch nicht False: niemand hat gefragt"


def test_mit_passendem_zielkontext_wird_die_achse_wahr(paar):
    """DIE GEGENRICHTUNG. Ohne sie waere die Haertung keine Praezisierung, sondern eine
    Abschaffung — die Achse duerfte einfach nie mehr gruen werden und niemand saehe es."""
    sk, pk = paar
    pred = _pred()
    r = _pruefe(AR.emit_agent_review(pred, sk), pk,
                               expected_subject_digest=AR._subject_digest(pred))
    assert r["internal_subject_consistency_ok"] is True
    assert r["expected_subject_match"] == "MATCH"
    assert r["subject_binding_ok"] is True
    assert r["ok"] is True, r["errors"]


def test_fremder_zielkontext_macht_beide_achsen_eindeutig(paar):
    """DASSELBE RECEIPT AUF FREMDEM PR — die Abnahme aus dem Auftrag. Intern konsistent bleibt es,
    die Zielachse faellt, und die zusammengefuehrte Achse faellt mit."""
    sk, pk = paar
    r = _pruefe(AR.emit_agent_review(_pred(), sk), pk,
                               expected_subject_digest="f" * 64)
    assert r["internal_subject_consistency_ok"] is True
    assert r["expected_subject_match"] == "MISMATCH"
    assert r["subject_binding_ok"] is False
    assert r["ok"] is False


def test_die_zwei_achsen_gelten_in_v02_GENAUSO(paar):
    """DER NACHBAR. Die Bindungslogik stand zweimal im Modul; ein Fix, der nur v0.1 erreicht, ist
    der Fehlermodus, gegen den dieser Auftrag gebaut ist.

    DIE ERSTE FASSUNG DIESES TESTS WAR TAUTOLOGISCH, und sie ist genau deshalb hier
    dokumentiert: sie schickte ein v0.1-Envelope in `verify_agent_review_v02`. Dort ist
    `predicate_type_ok` dann `False`, der Bindungsblock wird NIE BETRETEN, und die Zusicherungen
    hielten gegen die Vorbelegung aus `_empty_result` statt gegen eine Messung — gemessen: der
    eingepflanzte v0.2-Defekt liess den Test gruen. Der Test baut jetzt ein echtes
    v0.2-Statement, und die Zusicherung unten prueft ZUERST, dass der Pfad ueberhaupt lief."""
    from proofbundle import canonical, dsse                       # noqa: PLC0415
    sk, pk = paar
    pred = _pred()
    st = {"_type": AR.STATEMENT_TYPE,
          "subject": [{"name": AR._subject_name(pred),
                       "digest": {"sha256": AR._subject_digest(pred)}}],
          "predicateType": AR.AGENT_REVIEW_PREDICATE_TYPE_V02, "predicate": pred}
    env = dsse.sign_envelope(canonical.canonicalize_statement(st), sk,
                             payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)

    ohne = AR.verify_agent_review_v02(env, pk)
    assert ohne["predicate_type_ok"] is True, (
        "der v0.2-Pfad wurde nicht betreten — dann misst dieser Test nichts")
    assert ohne["internal_subject_consistency_ok"] is True, ohne["errors"]
    assert ohne["expected_subject_match"] == "NOT_EVALUATED"
    assert ohne["subject_binding_ok"] is not True, (
        f"auch in v0.2 nie gruen ohne Zielkontext — war {ohne['subject_binding_ok']!r}")

    mit = AR.verify_agent_review_v02(env, pk,
                                     expected_subject_digest=AR._subject_digest(pred))
    assert mit["expected_subject_match"] == "MATCH"
    assert mit["subject_binding_ok"] is True, mit["errors"]


def test_die_bindungslogik_steht_nur_EINMAL_im_modul():
    """DER KLASSEN-FIX, strukturell festgehalten. Zwei Kopien sind zwei Wahrheiten, die
    auseinanderlaufen — und die zweite ist die, die niemand mitfixt."""
    quelle = (Path(__file__).resolve().parents[1] / "src" / "proofbundle"
              / "agent_review.py").read_text(encoding="utf-8")
    assert quelle.count("def _zielbindung(") == 1, "der Helfer existiert nicht genau einmal"
    assert quelle.count("_zielbindung(r, predicate, statement") == 2, (
        "beide Verify-Pfade muessen denselben Helfer rufen")
    assert 'r["subject_binding_ok"] = derived == claimed' not in quelle, (
        "eine der alten Kopien der Bindungsrechnung steht noch im Modul")


def test_ein_MISMATCH_blockt_das_automations_urteil(paar):
    """DER DEFEKT, DEN ICH SELBST EINGEBAUT HABE (01.09.2026), festgenagelt.

    Die erste Fassung von P0.3 setzte `expected_subject_match` in die `references`-Liste von
    `automation_summary`. Deren Vertrag lautet woertlich: Feldnamen, deren Wert AUSDRUECKLICH
    `False` ist, bedeuten eine nicht aufgeloeste Referenz — gefiltert wird mit `is False`. Eine
    Zeichenkette ist nie `is False`. `"MISMATCH"` waere also durchgerutscht, und schlimmer: die
    Aenderung ERSETZTE die funktionierende Boolean-Achse durch die wirkungslose. Ein Riegel, der
    die eigene Verschaerfung blind macht, ist schlechter als keiner.

    Gefunden, weil die volle Suite ein `F` warf — nicht, weil ich es beim Schreiben gesehen haette."""
    sk, pk = paar
    r = _pruefe(AR.emit_agent_review(_pred(), sk), pk,
                               expected_subject_digest="f" * 64)
    assert r["expected_subject_match"] == "MISMATCH"
    assert r["subject_binding_ok"] is False
    a = r["automation"]
    assert a["safeForAutomation"] is False, a
    assert "REFERENCES_NOT_RESOLVED" in a["automationBlockers"], a


def test_keine_stringwertige_achse_in_IRGENDEINER_references_liste():
    """DIE KLASSE, nicht die Instanz. `automation_summary` filtert seine `references` mit
    `is False` — ein stringwertiges Feld dort ist per Bauart wirkungslos und sieht trotzdem aus wie
    eine Pruefung.

    ERST NUR `agent_review` GEPRUEFT, DANN GEMESSEN, dass fuenf weitere Module denselben Vertrag
    tragen: decision, outcome, run_ledger, trust_pack, verification_summary. Ein Test, der nur den
    Traeger prueft, an dem der Fehler auffiel, ist ein Instanz-Test fuer eine Klasse mit sechs
    Traegern — genau der Fehlermodus, den dieses Haus als „fix the instance, not the class" fuehrt.

    GEMESSEN wird am LAUFZEITWERT aus dem Ergebnis-Geruest des jeweiligen Moduls, nicht am
    Quelltext: eine Textsuche nach Grossbuchstaben-Zuweisungen fand in allen sechs Modulen nichts
    und haette den echten Fall in `agent_review` ebenfalls nicht gefunden."""
    import importlib
    import re

    TRAEGER = ("decision", "outcome", "run_ledger", "trust_pack", "verification_summary",
               "agent_review")
    src = Path(__file__).resolve().parents[1] / "src" / "proofbundle"
    geprueft = 0
    for name in TRAEGER:
        datei = src / f"{name}.py"
        if not datei.is_file():
            continue
        quelle = datei.read_text(encoding="utf-8")
        listen = re.findall(r'"references": \[([^\]]+)\]', quelle, re.S)
        felder = sorted({x.strip().strip('"')
                         for roh in listen
                         for x in roh.replace("\n", " ").split(",") if x.strip().strip('"')})
        if not felder:
            continue
        modul = importlib.import_module(f"proofbundle.{name}")
        leer = None
        for kandidat in ("_empty_result", "_leeres_ergebnis", "_result_skeleton"):
            if hasattr(modul, kandidat):
                leer = getattr(modul, kandidat)()
                break
        if leer is None:
            continue                      # nicht messbar — ausdruecklich keine Freigabe, kein Alarm
        for feld in felder:
            assert feld in leer, f"{name}: {feld} steht in references, aber nicht im Ergebnis"
            assert not isinstance(leer[feld], str), (
                f"{name}: {feld} ist stringwertig — `is False` trifft es nie, die Achse ist "
                "wirkungslos und verdraengt womoeglich eine, die wirkt")
        geprueft += 1

    assert geprueft >= 4, (
        f"nur {geprueft} Traeger geprueft — bei weniger als vier misst dieser Test wieder nur "
        "eine Instanz")
