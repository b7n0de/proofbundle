"""Der Konformitaets-Korpus wird AUSGEFUEHRT — P0.5 der Gegenlesung Runde 2.

DER BEFUND, der diesen Ausfuehrer noetig machte, gemessen am 01.09.2026: der Korpus unter
`conformance/agent_review/` traegt DREIZEHN Faelle in 26 Dateien — und KEIN Test fuehrte sie aus.
Es gab einen Generator, der sie schreibt, und niemanden, der sie liest. Ein Korpus ohne Ausfuehrer
ist eine Sammlung, kein Gate; er sieht aus wie Absicherung und ist keine.

DREI EIGENSCHAFTEN, die dieser Ausfuehrer zusammen halten muss — einzeln ist jede wertlos:

1. VOLLSTAENDIGKEIT. Jeder Fall wird gefahren. Ein Fall, dessen Erwartungsform der Ausfuehrer
   nicht kennt, laesst ihn FALLEN — er wird nicht uebersprungen. Stilles Ueberspringen ist die
   Form, in der ein Gate gruen aussieht und nichts prueft (skip-fake-green, eigener Klassen-Ledger).
2. RICHTIGKEIT. Die Erwartung des Falls muss eintreten, am ECHTEN Eintrittspunkt: die
   oeffentlichen Funktionen des Moduls, nicht nachgebaute Logik.
3. WIRKSAMKEIT (P0.5.6, "die Mutationstests selbst mutieren"). Zu jedem Gegenbeweis-Fall wird
   geprueft, dass sein Urteil KIPPT, wenn man den Defekt herausnimmt. Ohne diese dritte
   Eigenschaft koennte der ganze Korpus aus Faellen bestehen, die auch ein kaputter Validator
   besteht.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from proofbundle import agent_review as AR

KORPUS = Path(__file__).resolve().parents[1] / "conformance" / "agent_review"


def _laeufer():
    """Der Konformitaets-Laeufer als Modul. Er liegt nicht im Paket, sondern im Repo-Baum — in
    der ausgelieferten sdist ebenso, das ist gemessen (`conformance/` faehrt im Paket mit)."""
    import importlib.util  # noqa: PLC0415
    import sys as _sys  # noqa: PLC0415
    if "_rc_fuer_test" in _sys.modules:
        return _sys.modules["_rc_fuer_test"]
    # DER VOLLE WURZEL-RELATIVE PFAD ALS EIN LITERAL, nicht zusammengesetzt. Die
    # Skip-Ableitung in `tests/conftest.py::modul_ist_repo_kontext` liest Pfad-Literale und
    # fragt, ob sie im Baum existieren; ein blosses "run_conformance.py" las sie als Datei IM
    # WURZELVERZEICHNIS, fand sie dort nicht und stufte dieses ganze Modul als repo-kontext-
    # abhaengig ein — es waere in der sdist stillschweigend UEBERSPRUNGEN worden. Genau die
    # skip-fake-green-Klasse, vor der conftest.py selbst warnt, und gefangen hat sie
    # `test_im_echten_checkout_ist_die_ableitung_ein_no_op`, nicht meine Durchsicht.
    # Nicht die Heuristik wurde aufgeweicht, sondern das Literal richtig geschrieben.
    pfad = KORPUS.parents[1] / "conformance/run_conformance.py"
    spec = importlib.util.spec_from_file_location("_rc_fuer_test", pfad)
    mod = importlib.util.module_from_spec(spec)
    _sys.modules["_rc_fuer_test"] = mod
    spec.loader.exec_module(mod)
    return mod


def _faelle() -> list[Path]:
    return sorted(d for d in KORPUS.iterdir() if (d / "case.json").is_file())


def _fall(d: Path) -> dict:
    return json.loads((d / "case.json").read_text(encoding="utf-8"))


def _eingabe(d: Path, fall: dict):
    return json.loads((d / fall["input"]).read_text(encoding="utf-8"))


ALLE = _faelle()
IDS = [d.name.replace("agent-review-", "") for d in ALLE]


def test_der_korpus_ist_nicht_leer_und_die_zahl_steht_fest():
    """Ein Ausfuehrer, der null Faelle findet, besteht sonst mit gruener Anzeige."""
    assert len(ALLE) >= 13, f"nur {len(ALLE)} Faelle gefunden — der Korpus ist geschrumpft"


def test_jedes_fall_verzeichnis_traegt_auch_eine_case_json():
    """Ein Verzeichnis mit Eingaben, aber ohne Fallbeschreibung, wuerde still nicht gefahren."""
    ohne = [d.name for d in KORPUS.iterdir()
            if d.is_dir() and not d.name.startswith("_") and not (d / "case.json").is_file()]
    assert ohne == [], f"Fallverzeichnisse ohne case.json: {ohne}"


# ── der Ausfuehrer ────────────────────────────────────────────────────────────────────────────

def _urteil(d: Path, fall: dict) -> dict:
    """Das gemessene Urteil zu einem Fall, am echten Eintrittspunkt. Kennt der Ausfuehrer die
    Erwartungsform nicht, wirft er — Ueberspringen waere hier die falsche Antwort."""
    erw = fall["expected"]
    eingabe = _eingabe(d, fall)

    # ═══ EINE WEICHE, NICHT ZWEI ═══════════════════════════════════════════════════════════
    #
    # GEMESSEN am 01.09.2026, im hermetic-cleanroom UND im Repo: der Positiv-Kontroll-Fall
    # `emit-verify-roundtrip` fiel mit "DSSE envelope.payload must be a base64 string". Die
    # Meldung war richtig, der PFAD falsch — der Fall traegt ein rohes agent-review DOKUMENT,
    # keinen fertigen Umschlag, und dieser Ausfuehrer warf ihn in den Verifier.
    #
    # DIE URSACHE WAR NICHT DER FALL, sondern dass es die Weiche ZWEIMAL gab: einmal in
    # `run_conformance` und einmal hier daneben nachgebaut. Als die Strecke in derselben Runde
    # auf den Erzeuger umgestellt wurde (N06/P0.5), wanderte nur die dortige Fassung mit. Zwei
    # Fassungen derselben Entscheidung sind zwei Wahrheiten, und die ungerufene altert still.
    #
    # Der Laeufer gibt die KLASSIFIKATION zurueck, nicht sein eigenes Urteil — die Erwartung
    # wird weiterhin HIER geprueft. Ein erster Versuch delegierte das Urteil mit und drehte bei
    # `invalid`-Faellen das Vorzeichen: acht rote Tests, gemessen, zurueckgenommen.
    # ENG VERENGT auf den ERZEUGER-Pfad. Beim Zusammenfuehren fiel eine ZWEITE Abweichung
    # zwischen den beiden Fassungen auf, und dort ist die hiesige die sorgfaeltigere: fuer
    # fertige UMSCHLAEGE misst der Laeufer immer `ok`, dieser Ausfuehrer dagegen
    # `internal_consistency_ok`, wenn der Fall keine Erwartung mitbringt — gemessen liefert der
    # Laeufer fuer den Zielbindungs-Fall `invalid` AUCH ohne Erwartung, kann die Zielbindung also
    # nicht mehr von "irgendetwas davor" trennen. Heute faellt das nicht auf, weil kein
    # Umschlag-Fall `valid` ohne Erwartung erwartet; ein kuenftiger wuerde es. Die Delegation
    # nimmt deshalb nur den Pfad, um den es ging.
    if (fall.get("kind") == "agent_review_predicate"
            and fall.get("input") == "predicate.json" and "classification" in erw):
        got = _laeufer().klassifiziere_agent_review(fall, d)
        return {"ok": got == "valid", "refused": got == "refused",
                "result": {"errors": [f"klassifiziert als {got}"]},
                "gemessen_an": "run_conformance.klassifiziere_agent_review"}

    if "classification" in erw:
        art = erw["classification"]
        if art == "refused":
            # "refused" heisst: der ERZEUGER nimmt das nicht an.
            if isinstance(eingabe, dict) and "body" in eingabe:
                try:
                    AR.body_core_digest(eingabe["body"])
                except AR.AgentReviewError:
                    return {"refused": True}
                return {"refused": False}
            errs = AR.validate_agent_review_predicate(eingabe, strict=True)
            return {"refused": bool(errs), "errors": errs}
        if art in ("invalid", "valid"):
            # "invalid"/"valid" heisst: der PRUEFER urteilt so ueber einen fertigen Umschlag.
            #
            # GEMESSEN wird `internal_consistency_ok`, NICHT `ok` — und das ist keine Abschwaechung,
            # sondern die einzig mit dem Korpus beantwortbare Frage. Seit der P0.3-Haertung sind es
            # zwei getrennte Aussagen: `internal_consistency_ok` heisst "dieses Receipt ist in sich
            # stimmig und unveraendert", `ok` heisst zusaetzlich "du darfst es als Beleg FUER DAS
            # OBJEKT VOR DIR benutzen". Die zweite braucht eine von AUSSEN gesetzte Erwartung, und
            # genau die kann ein Korpusfall nicht mitbringen — er hat kein Objekt vor sich. Wer
            # hier `ok` misst, misst das Fehlen einer Erwartung und nennt es Ungueltigkeit.
            #
            # DIE AUSNAHME STEHT IM FALL SELBST, nicht in meiner Annahme: traegt er
            # `params.expectedSubjectDigest`, dann prueft er GERADE die Zielbindung — ein Receipt,
            # das kryptografisch einwandfrei ist und zu einem ANDEREN Objekt gehoert. Dort ist `ok`
            # die richtige Groesse, und die Erwartung kommt aus dem Korpus statt aus mir. Mein
            # erster Entwurf hat pauschal `internal_consistency_ok` gemessen und genau diesen Fall
            # gruen gemacht, obwohl er der wichtigste des ganzen Korpus ist.
            pk = bytes.fromhex((KORPUS / "publickey.hex").read_text().strip())
            erwartet = (fall.get("params") or {}).get("expectedSubjectDigest")
            r = AR.verify_agent_review(eingabe, pk, strict=True,
                                       expected_subject_digest=erwartet)
            massgeblich = r["ok"] if erwartet else r["internal_consistency_ok"]
            return {"ok": bool(massgeblich), "result": r,
                    "gemessen_an": "ok" if erwartet else "internal_consistency_ok"}
        raise AssertionError(f"unbekannte classification {art!r} in {d.name}")

    if "bodyCoreStable" in erw:
        vor = AR.body_core_digest(eingabe["bodyBefore"])
        nach = AR.body_core_digest(eingabe["bodyAfter"])
        return {"stable": vor == nach}

    if "subjectExpectation" in erw:
        pk = bytes.fromhex((KORPUS / "publickey.hex").read_text().strip())
        r = AR.verify_agent_review(eingabe, pk, strict=True)
        return {"subject_expectation": r["subject_expectation"]}

    raise AssertionError(
        f"{d.name}: unbekannte Erwartungsform {sorted(erw)} — der Ausfuehrer kennt sie nicht und "
        f"UEBERSPRINGT sie ausdruecklich NICHT, weil ein uebersprungener Fall gruen aussieht")


@pytest.mark.parametrize("d", ALLE, ids=IDS)
def test_der_fall_verhaelt_sich_wie_beschrieben(d):
    fall = _fall(d)
    erw, u = fall["expected"], _urteil(d, _fall(d))
    if "classification" in erw:
        art = erw["classification"]
        if art == "refused":
            assert u["refused"] is True, f"{d.name}: wurde ANGENOMMEN, erwartet war Verweigerung"
        elif art == "invalid":
            assert u["ok"] is False, f"{d.name}: der Pruefer sagte ok=True"
        else:
            assert u["ok"] is True, f"{d.name}: der Pruefer sagte ok=False — {u['result']['errors']}"
    elif "bodyCoreStable" in erw:
        assert u["stable"] is erw["bodyCoreStable"], d.name
    else:
        assert u["subject_expectation"] == erw["subjectExpectation"], d.name


# ── P0.5.6: die Mutationstests selbst mutieren ────────────────────────────────────────────────

#: Je Gegenbeweis-Fall der Eingriff, der seinen Defekt WEGNIMMT. Faellt danach das Urteil nicht
#: um, prueft der Fall nichts — dann ist er ein Fall, den auch ein kaputter Validator besteht.
_ENTSCHAERFUNG = {
    "agent-review-counter-proof-partial-must-name-its-gap":
        lambda p: p["coverage"].update({"knownGaps": ["eine benannte Luecke"]}),
    "agent-review-counter-proof-complete-needs-an-expectation":
        lambda p: p["coverage"].update({"observedRuns": 3, "expectedRuns": 3, "sources": ["s"],
                                        "window": "w", "collectionMethod": "m"}),
    # MEINE ERSTE ENTSCHAERFUNG WAR HIER FALSCH und der Meta-Test hat es gefangen: ich hatte
    # `coverage.status` umgestellt, obwohl der Fall gar nicht die Abdeckung prueft, sondern das
    # WEGLASSEN von `findingsTotal` ("eine Pflicht, die sich durch Weglassen eines Feldes
    # abschalten laesst, ist keine"). Der Test wurde rot und hatte recht — beinahe haette ich
    # daraus einen Korpus-Defekt gemeldet, den es nicht gibt.
    "agent-review-counter-proof-gap-duty-cannot-be-switched-off":
        lambda p: p["declaration"].update(
            {"findingsTotal": len(p["declaration"].get("findings") or [])}),
    "agent-review-counter-proof-assurance-cannot-be-self-raised":
        lambda p: [i.update({"assurance": "selfDeclared"})
                   for i in (p["declaration"].get("authoring") or [])
                   + (p["declaration"].get("reviewRuns") or [])],
    "agent-review-counter-proof-anchored-time-needs-evidence":
        lambda p: p["times"].pop("anchoredAt", None),
}


@pytest.mark.parametrize("name", sorted(_ENTSCHAERFUNG), ids=lambda s: s[-40:])
def test_der_gegenbeweis_kippt_wenn_man_seinen_defekt_wegnimmt(name):
    """Ohne diesen Test koennte der Korpus aus Faellen bestehen, die JEDER Validator besteht."""
    d = KORPUS / name
    fall = _fall(d)
    assert fall["expected"]["classification"] == "refused", f"{name} ist kein refused-Fall mehr"
    p = _eingabe(d, fall)
    assert AR.validate_agent_review_predicate(p, strict=True), (
        f"{name} wird gar nicht mehr verweigert — der Fall prueft nichts")
    _ENTSCHAERFUNG[name](p)
    errs = AR.validate_agent_review_predicate(p, strict=True)
    assert errs == [], (
        f"{name}: nach dem Wegnehmen des Defekts wird immer noch verweigert ({errs[:2]}) — der "
        f"Fall unterscheidet nicht zwischen seinem Defekt und irgendetwas anderem")


def test_jeder_gegenbeweis_fall_ist_entweder_entschaerfbar_oder_benannt():
    """Ein Fall ohne Entschaerfung ist nicht verboten — aber er muss BENANNT sein.

    Die fuenf oben sind praedikat-basiert und lassen sich punktgenau entschaerfen. Die uebrigen
    Gegenbeweise arbeiten auf Umschlaegen oder Ruempfen, wo 'den Defekt wegnehmen' das Artefakt
    neu bauen hiesse. Das ist eine ehrliche Grenze und keine Luecke — solange sie hier steht und
    nicht dadurch entsteht, dass jemand die Liste vergisst.
    """
    ohne = {"agent-review-counter-proof-duplicate-disclosure-block-fails-closed",
            "agent-review-counter-proof-findings-root-covers-the-list",
            "agent-review-counter-proof-receipt-does-not-travel-between-subjects",
            "agent-review-counter-proof-introducing-the-first-block-moves-the-digest"}
    alle_gegen = {d.name for d in ALLE if _fall(d)["role"] == "counter_proof"}
    assert alle_gegen == set(_ENTSCHAERFUNG) | ohne, (
        f"neue oder entfallene Gegenbeweis-Faelle: {alle_gegen ^ (set(_ENTSCHAERFUNG) | ohne)}")


def test_die_positiven_kontrollen_sind_wirklich_positiv():
    """Ein Korpus aus lauter Gegenbeweisen bestuende auch mit einem Validator, der alles ablehnt."""
    positiv = [d for d in ALLE if _fall(d)["role"] == "positive_control"]
    assert len(positiv) >= 4, f"nur {len(positiv)} positive Kontrollen"


def test_der_zielbindungs_fall_faellt_NUR_weil_die_erwartung_uebergeben_wird():
    """Die Eigenschaft, auf die es ankommt — und mein erster Pin hat sie NICHT gehalten.

    Der erste Entwurf pruefte, an WELCHEM Feld gemessen wird (`ok` statt
    `internal_consistency_ok`). Ein Mutationslauf zeigte, dass das folgenlos ist: sobald die
    Erwartung uebergeben wird, sind BEIDE Felder falsch, weil `subject_binding_ok` in beide
    eingeht. Der Pin mass also eine Unterscheidung, die am Urteil nichts aendert — er sah aus wie
    eine Absicherung und war keine.

    Was WIRKLICH traegt: dieser Fall faellt ausschliesslich deshalb, weil der Ausfuehrer den
    `expectedSubjectDigest` aus dem Korpus uebergibt. Laesst er ihn weg, ist dasselbe Receipt in
    sich stimmig — kryptografisch einwandfrei und an ein ANDERES Objekt gebunden. Genau das ist
    der Fehlermodus, fuer den die Bindung existiert.
    """
    d = KORPUS / "agent-review-counter-proof-receipt-does-not-travel-between-subjects"
    fall = _fall(d)
    erwartet = (fall.get("params") or {}).get("expectedSubjectDigest")
    assert erwartet, "der Fall bringt seinen erwarteten Subject-Digest nicht mehr mit"

    pk = bytes.fromhex((KORPUS / "publickey.hex").read_text().strip())
    env = _eingabe(d, fall)
    mit = AR.verify_agent_review(env, pk, strict=True, expected_subject_digest=erwartet)
    ohne = AR.verify_agent_review(env, pk, strict=True)
    assert mit["ok"] is False and mit["subject_binding_ok"] is False
    assert ohne["internal_consistency_ok"] is True, (
        "ohne Erwartung faellt das Receipt schon aus einem anderen Grund — dann belegt der Fall "
        "nicht mehr die Zielbindung, sondern irgendetwas davor")
    # Der Fall traegt einen fertigen UMSCHLAEG und geht damit NICHT ueber die delegierte
    # Erzeuger-Weiche, sondern weiter ueber die Messung hier. `gemessen_an` ist deshalb
    # unveraendert `ok` — und genau das ist die Eigenschaft, die der Test haelt: bei einem Fall
    # MIT Erwartung wird `ok` gemessen und nicht `internal_consistency_ok`.
    assert _urteil(d, fall)["gemessen_an"] == "ok"


def test_eine_unbekannte_erwartungsform_laesst_den_ausfuehrer_FALLEN(tmp_path):
    """Der Zweig war bis hierher UNGETESTET, und ein Mutationslauf hat genau das gezeigt: ihn durch
    ein stilles Ueberspringen zu ersetzen liess alle 23 Tests gruen, weil kein Fall im Korpus eine
    unbekannte Form hat. Ein Waechter, den kein Fall erreicht, ist eine Absichtserklaerung.
    """
    d = tmp_path / "agent-review-erfundene-form"
    d.mkdir()
    (d / "predicate.json").write_text("{}", encoding="utf-8")
    fall = {"caseId": "agent-review-erfundene-form", "kind": "agent_review_predicate",
            "input": "predicate.json", "role": "counter_proof", "rule": "X",
            "expected": {"etwasVoelligNeues": True}}
    (d / "case.json").write_text(json.dumps(fall), encoding="utf-8")
    with pytest.raises(AssertionError, match="unbekannte Erwartungsform"):
        _urteil(d, fall)


# ── P0.5.4: der ECHTE Emitter, und ein Mutant, der ihn umgeht, muss rot werden ────────────────

def test_die_positive_kontrolle_laeuft_durch_den_ECHTEN_emitter():
    """Der Befund lautete woertlich: fuer predicate.json ruft der Laeufer
    `require_valid_agent_review_predicate`, NICHT `emit_agent_review`. Ein Konformitaetslauf, der
    den Erzeuger nie anfasst, prueft den Weg nicht, auf dem echte Belege entstehen.

    Hier laeuft mindestens eine positive Kontrolle den vollen Weg: Predicate -> emit_agent_review
    mit deterministischem Testschluessel -> verify des ERZEUGTEN Umschlags.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    pk = sk.public_key().public_bytes_raw()

    d = KORPUS / "agent-review-positive-control-valid-self-declared"
    env_fix = _eingabe(d, _fall(d))
    import base64
    p = json.loads(base64.b64decode(env_fix["payload"]))["predicate"]

    env = AR.emit_agent_review(p, sk, strict=True)          # <- der echte Erzeuger
    r = AR.verify_agent_review(env, pk, strict=True,
                               expected_subject_digest=AR._subject_digest(p))
    assert r["crypto_ok"] is True, r["errors"]
    assert r["ok"] is True, r["errors"]


def test_ein_ungueltiges_praedikat_kommt_durch_den_emitter_NICHT_durch():
    """Die Gegenprobe: sonst waere der Roundtrip mit einem Emitter zu bestehen, der alles signiert.

    Der Befund verlangt woertlich "ein Mutant, der nur den Emitter umgeht, muss rot werden". Der
    Weg dahin ist dieser: der Emitter MUSS selbst ablehnen, sonst ist es gleichgueltig, ob man ihn
    aufruft oder umgeht.

    GEMESSEN am 01.09.2026, und es gehoert hierher, weil es die Aussagekraft dieses Tests
    beschreibt: die Ablehnung traegt durch ZWEI unabhaengige Pruefungen — die in `emit_agent_review`
    und die in `build_agent_review_statement`. Klemmt man nur EINE ab, bleibt dieser Test gruen; erst
    mit beiden wird er rot. Der Test belegt also die EIGENSCHAFT ("kommt nicht durch"), nicht eine
    einzelne Codestelle. Das ist Absicht (Defense in Depth) und keine Luecke — aber wer hier eine
    einzelne Zeile aendert und diesen Test gruen sieht, hat nichts bewiesen.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    d = KORPUS / "agent-review-counter-proof-partial-must-name-its-gap"
    p = _eingabe(d, _fall(d))
    with pytest.raises(AR.AgentReviewError):
        AR.emit_agent_review(p, sk, strict=True)
