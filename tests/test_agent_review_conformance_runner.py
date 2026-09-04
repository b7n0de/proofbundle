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

import base64
import json
from pathlib import Path

import pytest

from proofbundle import agent_review as AR

#: DIE FASSUNG STEHT HIER AUSDRUECKLICH, seit v0.2 die Vorgabe ist (6.0.0). Diese Datei
#: prueft die v0.1-Semantik — sie ruft den v0.1-Verifizierer und sichert den v0.1-Typ zu.
#: Sie verliess sich bisher auf den Vorgabewert; `legacy_v01=True` erhaelt genau das, was
#: sie prueft, statt sie an einen Vorgabewert zu haengen, den eine andere Entscheidung
#: bewegt. KEINE Zusicherung wurde dabei geaendert — nur die Fassung benannt.


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


#: Verzeichnisse im Korpus, die KEINE Faelle sind. Der fuehrende Unterstrich war bisher die
#: einzige Kennzeichnung (`_generator`); `policies/` kam mit Teil A3 dazu und traegt keinen, weil
#: der Auftrag seinen Pfad woertlich nennt. Die Liste steht hier ausdruecklich, statt die
#: Unterstrich-Regel zu dehnen: wer sie liest, sieht WELCHE Verzeichnisse gemeint sind, und ein
#: neues faellt auf, statt von einer Namensregel stillschweigend mitgenommen zu werden.
KEINE_FAELLE = {"policies"}


def test_jedes_fall_verzeichnis_traegt_auch_eine_case_json():
    """Ein Verzeichnis mit Eingaben, aber ohne Fallbeschreibung, wuerde still nicht gefahren.

    Die Zusicherung ist UNVERAENDERT — jeder FALL traegt seine Beschreibung. Praezisiert ist nur,
    was ein Fall ist: `policies/` haelt die benannte Standard-Policy und ist keiner.
    """
    ohne = [d.name for d in KORPUS.iterdir()
            if d.is_dir() and not d.name.startswith("_") and d.name not in KEINE_FAELLE
            and not (d / "case.json").is_file()]
    assert ohne == [], f"Fallverzeichnisse ohne case.json: {ohne}"


def test_die_ausnahmeliste_nimmt_keinen_echten_fall_heraus():
    """GEGENPROBE. Eine Ausnahmeliste ist ein Loch im Riegel, solange niemand prueft, dass sie nur
    das enthaelt, was wirklich kein Fall ist. Ein Verzeichnis MIT case.json darf nie darin stehen."""
    falsch = [n for n in KEINE_FAELLE if (KORPUS / n / "case.json").is_file()]
    assert falsch == [], f"als Nicht-Fall gefuehrt, traegt aber eine case.json: {falsch}"


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
    # KETTEN-ACHSEN (Test 19, Supersession). Die MESSUNG wird delegiert, die Erwartung bleibt
    # hier — dieselbe Trennung wie beim Erzeuger-Pfad darunter, und aus demselben Grund: einen
    # Ausfuehrer zweimal zu schreiben heisst, ihn einmal altern zu lassen.
    _KETTEN_ACHSEN = ("currentReceipt", "chainIntegrity", "unverifiedSupersessionClaim")
    if any(a in erw for a in _KETTEN_ACHSEN):
        _, _geprueft, kette = _laeufer().loese_kette(fall, d)
        if "currentReceipt" in erw:
            passt = kette["current"] == erw["currentReceipt"]
            grund = f"current={kette['current']!r}"
        elif "chainIntegrity" in erw:
            passt = kette["integrity_ok"] is bool(erw["chainIntegrity"])
            grund = (f"integrity_ok={kette['integrity_ok']}, "
                     f"missing={kette['missing_predecessors']}")
        else:
            passt = (erw["unverifiedSupersessionClaim"]
                     in kette["unverified_supersession_claims"]) and not kette["corrected"]
            grund = (f"claims={kette['unverified_supersession_claims']}, "
                     f"corrected={kette['corrected']}")
        return {"ok": passt, "refused": False, "kette": True,
                "result": {"errors": [grund]},
                "gemessen_an": "run_conformance.loese_kette"}

    # A5, ERSTE HAELFTE: die zwei neuen Achsen (Weiche, Policy). Die MESSUNG kommt aus dem
    # Laeufer, die Erwartung bleibt hier — dieselbe Trennung wie bei den Kettenachsen, und aus
    # demselben Grund: einen Ausfuehrer zweimal zu schreiben heisst, ihn einmal altern zu lassen.
    if "versionStatus" in erw:
        m = _laeufer().miss_versionsstatus(fall, d)
        return {"ok": m["status"] == erw["versionStatus"], "achse": "versionStatus",
                "result": {"errors": [f"status={m['status']!r} codes={m['codes']}"]},
                "gemessen_an": "run_conformance.miss_versionsstatus"}
    if "policyDecision" in erw:
        m = _laeufer().miss_policy_entscheidung(fall, d)
        return {"ok": m["decision"] == erw["policyDecision"], "achse": "policyDecision",
                "result": {"errors": [f"decision={m['decision']!r} codes={m['codes']}"]},
                "gemessen_an": "run_conformance.miss_policy_entscheidung"}

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
    elif u.get("kette"):
        # Die Kettenachsen sind in `_urteil` schon gegen die Erwartung gemessen; hier zaehlt nur
        # noch das Ergebnis. Der Grund faehrt in der Meldung mit, sonst stuende bei einem roten
        # Fall nichts als der Dateiname.
        assert u["ok"], f"{d.name}: {u['result']['errors']}"
    elif u.get("achse") in ("versionStatus", "policyDecision"):
        # A5: schon in `_urteil` gegen die Erwartung gemessen, der Grund faehrt mit.
        assert u["ok"], f"{d.name}: {u['result']['errors']}"
    elif "subjectExpectation" in erw:
        assert u["subject_expectation"] == erw["subjectExpectation"], d.name
    else:
        # KEIN stiller Vorgabewert. Die vorige Fassung las jede unbekannte Achse als
        # `subjectExpectation` und fiel dann mit einem KeyError statt mit einer Aussage — ein
        # `else`, das eine Annahme traegt, ist der haeufigste Ort fuer eine falsche.
        raise AssertionError(f"{d.name}: unbekannte Erwartungsachse {sorted(erw)} — der Pruefer "
                             f"muss sie kennen, sonst misst er etwas anderes als der Laeufer")


# ── P0.5.6: die Mutationstests selbst mutieren ────────────────────────────────────────────────

#: Je Gegenbeweis-Fall der Eingriff, der seinen Defekt WEGNIMMT. Faellt danach das Urteil nicht
#: um, prueft der Fall nichts — dann ist er ein Fall, den auch ein kaputter Validator besteht.
_ENTSCHAERFUNG = {
    # ── die v0.2-Gegenbeweise aus Teil A5 ─────────────────────────────────────────────────────
    #
    # Die Entschaerfung nimmt GENAU DEN Defekt weg, den der Fall prueft, und sonst nichts. Ein
    # Flip, der nebenbei etwas anderes repariert, belegt nicht, dass der Fall an seinem eigenen
    # Grund faellt — dieselbe Falle, in die ich weiter unten schon einmal gelaufen bin.
    "agent-review-v02-counter-proof-coverage-partial-must-name-its-gap":
        lambda p: p["coverage"].update({"knownGaps": ["eine benannte Luecke"]}),
    "agent-review-v02-counter-proof-limitation-codes-are-required":
        lambda p: p.update({"limitationCodes": ["COVERAGE_PARTIAL", "CURRENTNESS_UNKNOWN",
                                                "IDENTITY_UNBOUND", "NOT_QUALITY_ATTESTATION",
                                                "TIME_SELF_DECLARED"]}),
    "agent-review-v02-counter-proof-fixcommit-must-be-the-full-sha":
        lambda p: p["declaration"]["findings"][0].update({"fixCommit": "f" * 40}),
    "agent-review-v02-counter-proof-disclosure-core-digest-is-required":
        lambda p: p["subjectContext"].update({"disclosureCoreDigest": "e" * 64}),
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
    # DER PRUEFER FOLGT DER FASSUNG DES FALLS (A5). Fest verdrahtet auf v0.1 wuerde er einen
    # v0.2-Fall an den falschen Regeln messen: der v0.1-Validator kennt weder die
    # fixCommit-Pflicht noch disclosureCoreDigest noch limitationCodes, meldete also fuer einen
    # entschaerften v0.2-Fall Fehler, die es nicht gibt — oder schlimmer, fuer den unentschaerften
    # KEINE. Dieselbe Kopplung, die beim Konformitaets-Laeufer selbst schon aufgefallen ist.
    _pruefer = (AR.validate_agent_review_v02_predicate
                if fall.get("predicateVersion") == "v0.2"
                else AR.validate_agent_review_predicate)
    assert _pruefer(p, strict=True), (
        f"{name} wird gar nicht mehr verweigert — der Fall prueft nichts")
    _ENTSCHAERFUNG[name](p)
    errs = _pruefer(p, strict=True)
    assert errs == [], (
        f"{name}: nach dem Wegnehmen des Defekts wird immer noch verweigert ({errs[:2]}) — der "
        f"Fall unterscheidet nicht zwischen seinem Defekt und irgendetwas anderem")


# ── Entschaerfung auf KETTENEBENE ───────────────────────────────────────────────────────────────
# Die zwei Supersessions-Gegenbeweise arbeiten auf Umschlaegen, lassen sich aber sehr wohl
# punktgenau entschaerfen — nur nicht am Praedikat, sondern an der Kette. Sie deshalb in die
# "ohne Entschaerfung"-Liste zu schieben waere bequem und schwaecher als noetig.
def _entschaerfe_fremden_schluessel(d):
    """Denselben Umschlag mit UNSEREM Schluessel signieren — dann ist der Anspruch geprueft."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415
    kette = json.loads((d / "chain.json").read_text())["envelopes"]
    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    heil = []
    for env in kette:
        st = json.loads(base64.b64decode(env["payload"], validate=True))
        heil.append(AR.emit_agent_review(st["predicate"], sk, legacy_v01=True))
    return heil


def _entschaerfe_fehlenden_vorgaenger(d):
    """Den ueberholten Beleg wieder dazulegen — er liegt in der Positivkontrolle derselben Runde."""
    quelle = KORPUS / "agent-review-positive-control-supersession-names-the-current-receipt"
    voll = json.loads((quelle / "chain.json").read_text())["envelopes"]
    return voll


_KETTEN_ENTSCHAERFUNG = {
    "agent-review-counter-proof-a-foreign-key-cannot-supersede-our-receipt":
        (_entschaerfe_fremden_schluessel,
         lambda k: not k["unverified_supersession_claims"] and bool(k["corrected"])),
    "agent-review-counter-proof-a-superseded-predecessor-must-still-be-present":
        (_entschaerfe_fehlenden_vorgaenger,
         lambda k: k["integrity_ok"] is True),
}


@pytest.mark.parametrize("name", sorted(_KETTEN_ENTSCHAERFUNG), ids=lambda s: s[-40:])
def test_der_ketten_gegenbeweis_kippt_wenn_man_seinen_defekt_wegnimmt(name):
    """Ohne das koennte ein Kettenfall gruen sein, ohne je etwas zu unterscheiden."""
    d = KORPUS / name
    entschaerfe, ist_heil = _KETTEN_ENTSCHAERFUNG[name]
    laeufer = _laeufer()

    _, _, vorher = laeufer.loese_kette(_fall(d), d)
    assert not ist_heil(vorher), f"{name}: der Fall ist schon heil — er prueft nichts"

    heile_umschlaege = entschaerfe(d)
    geprueft = set()
    schluessel = bytes.fromhex((KORPUS / "publickey.hex").read_text().strip())
    for env in heile_umschlaege:
        if AR.verify_agent_review(env, schluessel).get("crypto_ok") is True:
            geprueft.add(AR.receipt_digest(env))
    nachher = AR.resolve_receipt_chain(heile_umschlaege, verified=geprueft)
    assert ist_heil(nachher), (
        f"{name}: nach dem Wegnehmen des Defekts stimmt es immer noch nicht — der Fall "
        f"unterscheidet nicht zwischen seinem Defekt und irgendetwas anderem ({nachher})")


# ── A5, erste Haelfte: Entschaerfung der Weichen- und Policy-Gegenbeweise ────────────────────
# Jeder Gegenbeweis nimmt GENAU seinen Defekt weg und wird danach am selben Eintrittspunkt
# gemessen wie im Laeufer. Ein Flip, der nebenbei etwas anderes repariert, belegt nichts.

def _v02_predicate_des_falls(d: Path) -> dict:
    fall = _fall(d)
    eingabe = _eingabe(d, fall)
    if fall.get("input") == "envelope.json":
        return json.loads(base64.b64decode(eingabe["payload"], validate=True))["predicate"]
    return eingabe


def _miss_policy(pred: dict, policy):
    """Dieselbe Messung wie `run_conformance.miss_policy_entscheidung`, auf einem entschaerften
    Predicate — den Umweg ueber eine Datei braucht sie nicht."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415
    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    env = AR.emit_agent_review(pred, sk)
    return AR.verify_agent_review_v02(env, sk.public_key().public_bytes_raw(),
                                      expected_subject_digest=AR._subject_digest(pred),
                                      policy=policy)


def _entschaerfe_fremde_fassung(d: Path):
    # Dasselbe Predicate als v0.2 neu ausgestellt: die Weiche muss es als `current` lesen.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415
    pred = _v02_predicate_des_falls(d)
    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    env = AR.emit_agent_review(pred, sk)
    r = AR.verify_agent_review_any(env, sk.public_key().public_bytes_raw(),
                                   expected_subject_digest=AR._subject_digest(pred))
    return r.get("predicateVersionStatus"), r


def _entschaerfe_ohne_policy(d: Path):
    return _miss_policy(_v02_predicate_des_falls(d), AR.load_policy())


def _entschaerfe_unbekannte_abdeckung(d: Path):
    pred = dict(_v02_predicate_des_falls(d))
    pred["coverage"] = {"status": "PARTIAL", "knownGaps": ["eine benannte Luecke"]}
    return _miss_policy(pred, AR.load_policy())


def _entschaerfe_sperrende_policy(d: Path):
    return _miss_policy(_v02_predicate_des_falls(d), AR.load_policy())


_A5_ENTSCHAERFUNG = {
    "agent-review-v02-counter-proof-unknown-predicate-type-is-refused":
        (lambda d: _laeufer().miss_versionsstatus(_fall(d), d)["status"] == "unknown",
         lambda d: _entschaerfe_fremde_fassung(d)[0] == "current"),
    "agent-review-v02-counter-proof-without-policy-nothing-is-decided":
        (lambda d: _laeufer().miss_policy_entscheidung(_fall(d), d)["decision"] is None,
         lambda d: _entschaerfe_ohne_policy(d).get("policy_decision") == "accept"),
    "agent-review-v02-counter-proof-unknown-coverage-is-insufficient-evidence":
        (lambda d: _laeufer().miss_policy_entscheidung(_fall(d), d)["decision"]
         == "insufficient_evidence",
         lambda d: _entschaerfe_unbekannte_abdeckung(d).get("policy_decision") == "accept"),
    "agent-review-v02-counter-proof-blocking-policy-rejects":
        (lambda d: _laeufer().miss_policy_entscheidung(_fall(d), d)["decision"] == "reject",
         lambda d: _entschaerfe_sperrende_policy(d).get("policy_decision") == "accept"),
}


@pytest.mark.parametrize("name", sorted(_A5_ENTSCHAERFUNG), ids=lambda s: s[-40:])
def test_der_a5_gegenbeweis_kippt_wenn_man_seinen_defekt_wegnimmt(name):
    """Ohne diesen Test koennte ein Weichen- oder Policy-Fall gruen sein, ohne je zu unterscheiden."""
    d = KORPUS / name
    ist_defekt, ist_heil = _A5_ENTSCHAERFUNG[name]
    assert ist_defekt(d), f"{name}: der Fall ist schon heil — er prueft nichts"
    assert ist_heil(d), (f"{name}: nach dem Wegnehmen des Defekts stimmt es immer noch nicht — der "
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
    bekannt = set(_ENTSCHAERFUNG) | set(_KETTEN_ENTSCHAERFUNG) | set(_A5_ENTSCHAERFUNG) | ohne
    assert alle_gegen == bekannt, (
        f"neue oder entfallene Gegenbeweis-Faelle: {alle_gegen ^ bekannt}")


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

    env = AR.emit_agent_review(p, sk, strict=True, legacy_v01=True)          # <- der echte Erzeuger
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
        AR.emit_agent_review(p, sk, strict=True, legacy_v01=True)
