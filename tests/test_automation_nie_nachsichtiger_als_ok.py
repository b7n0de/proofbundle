"""Die Automations-Flaeche darf nie nachsichtiger urteilen als das Urteil, das sie zusammenfasst.

DER BEFUND, der diesen Test noetig machte (Tiefen-Gate 5.1.0, 01.09.2026, von ZWEI unabhaengigen
Linsen gefunden und danach von Hand reproduziert): `safeForAutomation` blieb `True`, waehrend `ok`
auf `False` stand — auf zwei Wegen. Ohne `expected_subject_digest` steht `subject_binding_ok` auf
`None`, und die Referenz-Auswertung blockt nur bei einem EXPLIZITEN `False`. Und bei
`body_core_digest_match == "MISMATCH"` — der sichtbare Text ist nachweislich nicht der signierte —
blockte gar nichts, weil die Achse stringwertig ist und korrekt nicht in `references` steht.

WARUM DIESER TEST UEBER DIE VOLLE MENGE LAEUFT UND NICHT UEBER DIE ZWEI BEKANNTEN FAELLE.
Ein Test, der die zwei gemeldeten Achsen aufzaehlt, ist beim naechsten Lauf wieder blind — dann
gegen die dritte. Die Eigenschaft ist EINE Invariante, und sie wird hier als solche geprueft:
ueber jede Kombination, die ein `ok=False` erzeugen kann.

Das ist die Generator-Haertung, die das Runbook fuer jeden Fund verlangt: Property statt
Punktfixture.
"""
from __future__ import annotations

import itertools

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as ar

SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PK = SK.public_key().public_bytes_raw()
#: Der sichtbare Rumpf TRAEGT einen Offenlegungsblock. v0.2 verlangt `disclosureCoreDigest`, und
#: `disclosure_core_digest` verweigert ausdruecklich eine Antwort auf einen Rumpf ohne Block —
#: "answering with the digest of an empty string would look like a fact". Fuer v0.1 aendert das
#: nichts an der Substanz: `body_core_digest` rechnet ohnehin ohne den Block.
KOERPER = ("Ein PR-Rumpf, wie er sichtbar veroeffentlicht wird.\n\n"
           + ar.DISCLOSURE_BEGIN + "\n"
           + "**Agent review receipt** \u00b7 Tier 1, selfDeclared\n"
           + "<sub><code>sha256:" + "a" * 64 + "</code></sub>\n"
           + ar.DISCLOSURE_END + "\n")


def _doc(**ueber):
    d = {
        "schemaVersion": "0.1.0", "reviewId": "invariante",
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
    d.update(ueber)
    return d


#: Jede Achse, die ein `ok=False` erzeugen kann — als AUFRUF-Variation, nicht als Feldliste.
#: Wer hier eine Zeile ergaenzt, erweitert die gepruefte Menge; wer eine Achse im Modul ergaenzt,
#: ohne sie hier zu nennen, wird vom Vollstaendigkeits-Test darunter erwischt.
VARIANTEN = {
    "pfad": ["v0.1", "v0.2"],
    "ziel_erwartung": [None, "gesetzt", "falsch"],
    "sichtbarer_text": [None, "passend", "abweichend"],
    # VIERTE ACHSE seit 04.09.2026. Vorher bewegte KEINE Variante die Policy — `policy_ok` blieb
    # ueber die ganze Matrix auf einem Wert und war damit kein Kriterium, sondern ein konstanter
    # Summand. Der Vollstaendigkeits-Test hat das gefangen, als die Achse ueberhaupt entstand;
    # sie in UNBEWEGT_BEGRUENDET zu schieben waere die bequeme und falsche Antwort gewesen.
    "policy": [None, "standard"],
}


def _v02_predicate(doc):
    """Ein GUELTIGES v0.2-Predicate.

    DREI DINGE, die mein erster Entwurf falsch hatte — und der Kontrollfall stand deshalb auf
    `ok=False`, womit die halbe Matrix ein kaputtes Dokument prueft und trivial gruen ist:
      * `schemaVersion` bleibt `0.1.x`. Die Fassung steht im `predicateType`, nicht in der
        Schemaversion — der gemeinsame Validator verlangt ausdruecklich `0.1.x`.
      * `subjectContext.disclosureCoreDigest` ist in v0.2 PFLICHT.
      * `limitationCodes` ist in v0.2 PFLICHT.
    """
    pred = dict(doc)
    pred["subjectContext"] = dict(doc["subjectContext"],
                                  disclosureCoreDigest=ar.disclosure_core_digest(KOERPER))
    pred["limitationCodes"] = ar.derive_limitation_codes(pred)
    return pred


def _v02_umschlag(doc):
    """Baut einen v0.2-Umschlag von Hand. HISTORISCH: bis 6.0.0 konnte `emit_agent_review` nur
    v0.1; seit dem Vorgabewechsel kann es beides, und dieser Handbau bleibt trotzdem stehen — er
    prueft die Form UNABHAENGIG vom Aussteller, und genau das ist sein Wert."""
    import base64  # noqa: PLC0415
    import json  # noqa: PLC0415

    from proofbundle import dsse  # noqa: PLC0415
    pred = _v02_predicate(doc)
    stmt = {"_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": ar._subject_name(pred),
                         "digest": {"sha256": ar._subject_digest(pred)}}],
            "predicateType": ar.AGENT_REVIEW_PREDICATE_TYPE_V02,
            "predicate": pred}
    payload = json.dumps(stmt, separators=(",", ":"), sort_keys=True).encode()
    sig = SK.sign(dsse.pae("application/vnd.in-toto+json", payload))
    return {"payload": base64.b64encode(payload).decode(),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": base64.b64encode(sig).decode()}]}


def _fahre(pfad, ziel, text, policy=None):
    """DIE INVARIANTE GILT FUER BEIDE VERIFIER.

    Bis zum 02.09.2026 lief diese Menge nur ueber v0.1. Eine adversariale Gegenlesung hat dann
    gemessen, was das kostet: neutralisiert man die Nachkorrektur im v0.2-Pfad, meldet
    `safeForAutomation=True` bei `ok=False` — und die volle Suite bleibt Zeichen fuer Zeichen
    gruen, 2920 bestanden. Der einzige Waechter der v0.2-Haelfte war ein Quelltext-Zaehler
    (`quelle.count(...) >= 2`), also genau die Bauform, gegen die dieser Lauf angetreten ist.
    """
    doc = _doc()
    if pfad == "v0.2":
        env, pruefer = _v02_umschlag(doc), ar.verify_agent_review_v02
        digest = ar._subject_digest(_v02_predicate(doc))
    else:
        env, pruefer = ar.emit_agent_review(doc, SK, legacy_v01=True), ar.verify_agent_review
        digest = ar._subject_digest(doc)
    kw = {}
    if policy == "standard" and pfad == "v0.2":
        # v0.1 hat konzeptionell KEINE Policy-Achse (ihr Verifizierer kennt das Wort nicht) —
        # ihr eine unterzuschieben pruefte eine Eigenschaft, die es dort nicht gibt.
        kw["policy"] = ar.load_policy()
    if ziel == "gesetzt":
        kw["expected_subject_digest"] = digest
    elif ziel == "falsch":
        kw["expected_subject_digest"] = "f" * 64
    if text == "passend":
        kw["observed_body"] = KOERPER
    elif text == "abweichend":
        kw["observed_body"] = "Ein GANZ ANDERER Rumpf, den niemand signiert hat."
    return pruefer(env, PK, strict=True, **kw)


@pytest.mark.parametrize("pfad,ziel,text,policy", list(itertools.product(*VARIANTEN.values())))
def test_safe_impliziert_ok(pfad, ziel, text, policy):
    """DIE INVARIANTE: safeForAutomation=True setzt ok=True voraus. Ueber die volle Kombination."""
    r = _fahre(pfad, ziel, text, policy)
    a = r.get("automation") or {}
    if a.get("safeForAutomation") is True:
        assert r.get("ok") is True, (
            f"pfad={pfad!r} ziel={ziel!r} text={text!r}: die Automations-Flaeche meldet sicher, waehrend das "
            f"Receipt-Urteil ok={r.get('ok')!r} lautet — blockers={a.get('automationBlockers')}")


def test_die_menge_enthaelt_ueberhaupt_einen_nicht_ok_fall():
    """GEGENPROBE. Ohne sie waere der Test oben gruen, weil er nie einen ok=False sieht — genau
    die Tautologie, die im Konformitaets-Korpus dieses Releases gefunden wurde."""
    nicht_ok = [(p, z, t, pol) for p in VARIANTEN["pfad"] for z in VARIANTEN["ziel_erwartung"]
                for t in VARIANTEN["sichtbarer_text"] for pol in VARIANTEN["policy"]
                if _fahre(p, z, t, pol).get("ok") is not True]
    assert len(nicht_ok) >= 3, (
        f"nur {len(nicht_ok)} Kombinationen liefern ok!=True — die Menge prueft die Invariante "
        f"kaum: {nicht_ok}")


def _alle_verifier():
    """Jede oeffentliche `verify_*`-Funktion des Pakets — GEMESSEN, nicht aufgezaehlt."""
    import importlib  # noqa: PLC0415
    import pkgutil  # noqa: PLC0415

    import proofbundle  # noqa: PLC0415
    gefunden = []
    for m in pkgutil.iter_modules(proofbundle.__path__):
        if m.ispkg:
            continue
        try:
            mod = importlib.import_module(f"proofbundle.{m.name}")
        except Exception:                                        # noqa: BLE001
            continue
        for n in dir(mod):
            if n.startswith("verify_") and callable(getattr(mod, n, None)):
                gefunden.append((m.name, n, getattr(mod, n)))
    return gefunden


#: Eingaben, die JEDER Verifier ablehnen muss. Bewusst grob: es geht um die Invariante, nicht um
#: die Diagnose.
_MUELL = [
    "nicht-ein-dict",
    {"payload": "!!!keine base64!!!", "payloadType": "application/vnd.in-toto+json",
     "signatures": [{"sig": "AA=="}]},
    {"payload": "a2VpbiBqc29u", "payloadType": "application/vnd.in-toto+json",
     "signatures": [{"sig": "AA=="}]},
    {"payload": "e30=", "payloadType": "application/vnd.in-toto+json"},
]


def test_kein_verifier_meldet_sicher_bei_nicht_ok():
    """DIE INVARIANTE, jetzt ueber das GANZE Paket und als VERHALTEN gemessen.

    Bis zum 02.09.2026 stand hier ein Waechter, der am Syntaxbaum zaehlte, ob jede Funktion mit
    einer `automation`-Flaeche auch die Nachkorrektur RUFT. Ein Tiefen-Gate hat gemessen, was das
    kostet: eine vierte Flaeche mit `automation_verdict.automation_summary(...)` statt
    `automation_summary(...)` — dieselbe Funktion, andere Schreibweise — lieferte `ok=False,
    safe=True, blockers=[]` bei 89 gruenen Tests.

    Der Waechter pruefte die SCHREIBWEISE. Die Invariante ist jetzt IN `automation_summary`
    gefaltet, wo man sie nicht vergessen kann, und dieser Test misst sie am VERHALTEN — ueber jede
    `verify_*`-Funktion, die das Paket fuehrt, nicht ueber eine Liste.
    """
    verifier = _alle_verifier()
    assert verifier, "keine Verifier gefunden — die Erhebung misst nichts"
    verstoesse, gefahren = [], 0
    for modul, name, fn in verifier:
        for env in _MUELL:
            try:
                r = fn(env, bytes(range(32)))
            except TypeError:
                continue                       # andere Signatur, nicht dieser Vertrag
            except Exception:                  # noqa: BLE001 — hier zaehlt nur die Invariante
                continue
            if not isinstance(r, dict):
                continue
            gefahren += 1
            a = r.get("automation") or {}
            if r.get("ok") is not True and a.get("safeForAutomation") is True:
                verstoesse.append(f"{modul}.{name}: blockers={a.get('automationBlockers')}")
    assert gefahren >= 8, (
        f"nur {gefahren} Faelle gefahren — die Vorrichtung misst zu wenig, um etwas zu belegen")
    assert not verstoesse, (
        f"Verifier melden sicher bei nicht-ok: {verstoesse}")


def test_meta_die_invariante_faellt_wenn_man_sie_herausnimmt():
    """META, und es FUEHRT die Invariante aus statt sie nachzubauen.

    Ohne `RECEIPT_NOT_OK` in `automation_summary` waere die Flaeche bei `ok=False` wieder sicher.
    """
    from proofbundle.automation_verdict import automation_summary  # noqa: PLC0415
    mit_ok_false = automation_summary(
        {"ok": False, "crypto_ok": True, "structure_ok": True},
        required_checks={"crypto": "crypto_ok", "structure": "structure_ok",
                         "policy": None, "references": []})
    assert mit_ok_false["safeForAutomation"] is False, (
        "die Zusammenfassung meldet sicher, obwohl ok=False — die Invariante ist nicht gefaltet")
    assert "RECEIPT_NOT_OK" in mit_ok_false["automationBlockers"], (
        f"der Grund fehlt: {mit_ok_false['automationBlockers']}")
    # GEGENRICHTUNG, sonst faengt der Test alles: ohne `ok` darf nichts blocken.
    ohne_ok = automation_summary(
        {"crypto_ok": True, "structure_ok": True},
        required_checks={"crypto": "crypto_ok", "structure": "structure_ok",
                         "policy": None, "references": []})
    assert ohne_ok["safeForAutomation"] is True, (
        "ein FEHLENDES ok blockt — das ist 'nicht anwendbar', nicht 'nicht bestanden'")



@pytest.mark.parametrize("pfad", VARIANTEN["pfad"])
def test_der_kontrollfall_bleibt_gruen(pfad):
    """Ein Riegel, der alles blockt, ist kein Riegel — UND eine Fixture, die nie gueltig wird,
    macht die halbe Matrix trivial.

    GEMESSEN am 02.09.2026: mein erster v0.2-Umschlag war ungueltig (schemaVersion auf 0.2.0
    statt 0.1.x, `disclosureCoreDigest` und `limitationCodes` fehlten). Alle neun v0.2-Faelle
    standen damit auf ok=False, `safeForAutomation` trivial auf False, und
    `test_safe_impliziert_ok` war auf dieser Haelfte gruen, ohne etwas zu pruefen. Ohne diesen
    Kontrollfall JE PFAD bliebe das unsichtbar.
    """
    r = _fahre(pfad, "gesetzt", "passend")
    assert r.get("ok") is True, f"die {pfad}-Fixture ist ungueltig: {r.get('errors')[:3]}"
    a = r.get("automation") or {}
    if pfad == "v0.1":
        assert a.get("safeForAutomation") is True, (
            f"v0.1 ohne Policy-Achse muss sicher sein: {a.get('automationBlockers')}")
    else:
        # v0.2 FUEHRT eine Policy-Achse. Ohne uebergebene Policy ist sie NICHT ausgewertet, und ein
        # Receipt, dessen Policy nie ausgewertet wurde, ist nicht automatisierbar-sicher. Bis zum
        # 02.09.2026 meldete v0.2 hier `True` — weil der Aufruf `policy=None` uebergab, was laut
        # Vertrag "dieser Predicate-Typ hat gar keine Policy-Schicht" heisst. Das war fuer v0.1
        # richtig und fuer v0.2 falsch, und weil BEIDE Pfade dieselbe Zeile trugen, konnte kein
        # Pfadvergleich es sehen.
        assert a.get("safeForAutomation") is False, (
            "v0.2 fuehrt eine Policy-Achse; ohne Auswertung darf die Flaeche nicht sicher melden")
        assert "POLICY_NOT_EVALUATED" in (a.get("automationBlockers") or []), (
            f"der Grund fehlt: {a.get('automationBlockers')}")


#: Achsen, die diese Aufruf-Matrix NICHT bewegt — je mit dem Grund, warum das in Ordnung ist.
#: Diese Liste ist der EINZIGE erlaubte Rest. Waechst das Modul um eine Achse, die hier nicht
#: steht und die die Matrix nicht bewegt, faellt `test_die_menge_ist_vollstaendig` — genau das,
#: was der Kopf dieser Datei zusagt.
UNBEWEGT_BEGRUENDET = {
    "assurance_ok": "haengt an der Sprossen-Erklaerung im Dokument, nicht am Aufruf",
    "crypto_ok": "haengt am Schluessel, nicht am Aufruf — eine falsche Signatur ist eine andere Klasse",
    "findings_root_ok": "haengt an der Befundliste im Dokument, nicht am Aufruf",
    "internal_subject_consistency_ok": "haengt am subjectContext im Dokument",
    "predicate_type_ok": "haengt am Umschlag, nicht am Aufruf",
    "statement_shape_ok": "haengt am Umschlag, nicht am Aufruf",
    "structure_ok": "haengt am Dokument, nicht am Aufruf",
    "currentness": "braucht eine Kette; dieser Aufruf uebergibt keine",
    # ── seit dem 02.09.2026, als die Pfad-Achse (v0.1 | v0.2) dazukam ──────────────────────────
    # Die vier Zeit-Achsen plus `policy_decision` fuehrt NUR der v0.2-Pfad — fuenf v0.2-exklusive
    # Schluessel, aber nur VIER davon sind Zeit-Achsen. Hier stand 'fuenf Zeit-Achsen'; die Datei
    # selbst begruendet den fuenften zwei Zeilen spaeter anders ('braucht eine uebergebene Policy'). Sie bewegen sich nicht an `ziel` oder `text`,
    # sondern an Zeitbelegen, die `apply_time_evidence` beisteuert — das ist eine andere Klasse und
    # hat ihre eigene Testdatei. Zwei Achsen sind aus dieser Liste GEFALLEN, weil die Pfad-Achse sie
    # wirklich bewegt: `internal_consistency_ok` und `disclosure_core_digest_match`. Eine
    # Begruendung, die nicht mehr stimmt, deckt sonst etwas, das niemand mehr prueft.
    "event_time_status": "v0.2-Zeitachse; bewegt sich an Zeitbelegen, nicht an Ziel oder Text",
    "external_time_status": "v0.2-Zeitachse; braucht einen externen Anker, den dieser Aufruf nicht gibt",
    "observation_time_status": "v0.2-Zeitachse; braucht eine beobachtete Zeit",
    "signature_time_status": "v0.2-Zeitachse; braucht eine bezeugte Signaturzeit",
    # `policy_decision` ist am 04.09.2026 aus dieser Liste GEFALLEN: die neue Policy-Achse bewegt
    # sie wirklich, und der Riegel `test_die_begruendete_liste_verrottet_nicht` hat das im selben
    # Lauf gemeldet. Genau dafuer ist er da — eine Begruendung, die nicht mehr stimmt, deckt sonst
    # etwas, das niemand mehr prueft.
    #
    # ZWEI NEUE EINTRAEGE, und sie sind KEINE Urteilsachsen: `policy_name` und `policy_digest`
    # sagen, GEGEN WAS entschieden wurde, nicht WIE. Sie nehmen genau einen Wert an, weil die
    # Matrix genau eine benannte Policy fuehrt. Eine zweite, erfundene Policy nur dafuer zu bauen
    # bewegte die Achse, ohne eine Eigenschaft zu pruefen — das waere ein Test ueber die Matrix
    # statt ueber den Code.
    "policy_name": "Identitaet der Policy, kein Urteil; die Matrix fuehrt genau eine benannte",
    "policy_digest": "Fassung der Policy, kein Urteil; bewegt sich erst mit einer zweiten Policy",
}

#: Werte, die NICHT als Urteil zaehlen: Sammelbehaelter und das Urteil selbst.
_KEINE_ACHSE = ("ok", "errors", "warnings", "reason_code", "reason_codes", "advisory_codes",
                "automation")


def _achsen_und_werte():
    """Welche Achse nahm ueber die volle Matrix welche Werte an? GEMESSEN, nicht aufgezaehlt."""
    gesehen: dict[str, set] = {}
    for pfad, ziel, text, policy in itertools.product(*VARIANTEN.values()):
        r = _fahre(pfad, ziel, text, policy)
        for k, v in r.items():
            if k in _KEINE_ACHSE or isinstance(v, (list, dict)):
                continue
            gesehen.setdefault(k, set()).add(v)
    return gesehen


def test_die_menge_ist_vollstaendig():
    """DIE ZUSAGE AUS DEM DATEIKOPF, eingeloest.

    Bis zum 01.09.2026 versprach der Kopf dieser Datei einen 'Vollstaendigkeits-Test darunter' —
    und es gab keinen. Das Deep-Gate hat es an seinem eigenen praeregistrierten Ziel FZ-07
    gefunden: der Test zaehlte ueber eine handgepflegte Liste, und die Zusage darueber machte
    das unsichtbar. Eine Zusage, die keine Mechanik traegt, ist schlimmer als keine — sie laesst
    den Leser glauben, die Familie sei gedeckt.

    DIE EIGENSCHAFT: jede Achse des Ergebnisses ist entweder von dieser Matrix BEWEGT (nimmt
    ueber die Kombinationen mehr als einen Wert an) oder ausdruecklich als unbewegt BEGRUENDET.
    Ein drittes gibt es nicht. Waechst das Modul um eine Achse, faellt dieser Test.
    """
    gesehen = _achsen_und_werte()
    bewegt = {k for k, v in gesehen.items() if len(v) > 1}
    unerklaert = sorted(set(gesehen) - bewegt - set(UNBEWEGT_BEGRUENDET))
    assert not unerklaert, (
        f"neue Achse(n) ohne Deckung: {unerklaert}. Entweder eine Variante ergaenzen, die sie "
        f"bewegt, oder sie in UNBEWEGT_BEGRUENDET mit Grund eintragen — stillschweigend "
        f"durchlaufen darf sie nicht.")


def test_die_begruendete_liste_verrottet_nicht():
    """GEGENRICHTUNG, und sie war bis zum 02.09.2026 EINSEITIG.

    Sie fand nur Namen, die es GAR NICHT MEHR gibt. Eine Achse, die es gibt und die sich BEWEGT,
    fiel in `bewegt` und verschwand aus `unerklaert` — ihre stehengebliebene Begruendung deckte
    also weiter etwas ab, das niemand mehr prueft. Gemessen von einer adversarialen Linse: zwei
    Achsen (`observed_time_assurance`, `time_semantics`) trugen Begruendungen, die nachweislich
    falsch waren, und der Kommentar daneben behauptete, genau dieser Sweep sei gemacht worden.

    Zwei Richtungen, weil es zwei Arten von Verrottung gibt: ein Name ohne Achse und eine
    Begruendung ohne Wahrheit.
    """
    gesehen = _achsen_und_werte()
    verwaist = sorted(set(UNBEWEGT_BEGRUENDET) - set(gesehen))
    assert not verwaist, (
        f"UNBEWEGT_BEGRUENDET nennt Achsen, die das Ergebnis nicht mehr fuehrt: {verwaist}")
    bewegt = {k for k, v in gesehen.items() if len(v) > 1}
    falsch = sorted(bewegt & set(UNBEWEGT_BEGRUENDET))
    assert not falsch, (
        f"Achse(n) BEWEGEN sich, stehen aber als unbewegt begruendet: {falsch}. Die Begruendung "
        f"stimmt nicht mehr — streichen, damit sie nicht die naechste echte Unbewegtheit deckt. "
        f"Werte: { {k: sorted(map(str, gesehen[k])) for k in falsch} }")


def test_meta_eine_falsch_gewordene_begruendung_wird_gefangen():
    """META. Beweist, dass die zweite Richtung fallen KANN."""
    gesehen = _achsen_und_werte()
    bewegt = {k for k, v in gesehen.items() if len(v) > 1}
    assert bewegt, "keine Achse bewegt sich — die Vorrichtung misst nichts"
    liste = set(UNBEWEGT_BEGRUENDET) | {next(iter(sorted(bewegt)))}
    assert sorted(bewegt & liste), "eine falsch gewordene Begruendung bliebe unbemerkt"


def test_meta_eine_neue_achse_wird_gefangen():
    """META. Beweist, dass der Vollstaendigkeits-Test ueberhaupt fallen KANN — sonst misst er
    nichts. Eine kuenstliche Achse wird eingeschleust; der Test muss sie melden."""
    gesehen = _achsen_und_werte()
    gesehen["eine_neue_achse_die_niemand_erklaert_hat"] = {"NUR_EIN_WERT"}
    bewegt = {k for k, v in gesehen.items() if len(v) > 1}
    unerklaert = sorted(set(gesehen) - bewegt - set(UNBEWEGT_BEGRUENDET))
    assert unerklaert == ["eine_neue_achse_die_niemand_erklaert_hat"], (
        f"der Vollstaendigkeits-Test faengt eine neue Achse NICHT — er misst nichts: {unerklaert}")


# ── Die Nachkorrektur in _finalize_failclosed ist dort ein No-op ───────────────────────────────

@pytest.mark.parametrize("name,umschlag", [
    ("Umschlag kein Objekt", "nicht-ein-dict"),
    ("payload keine base64", {"payload": "!!!keine base64!!!",
                              "payloadType": "application/vnd.in-toto+json",
                              "signatures": [{"sig": "AA=="}]}),
    ("payload kein JSON", {"payload": "a2VpbiBqc29u",
                           "payloadType": "application/vnd.in-toto+json",
                           "signatures": [{"sig": "AA=="}]}),
    ("signatures fehlen", {"payload": "e30=",
                           "payloadType": "application/vnd.in-toto+json"}),
])
@pytest.mark.parametrize("pruefer", ["v0.1", "v0.2"])
def test_die_nachkorrektur_im_failclosed_pfad_bricht_nichts(name, umschlag, pruefer):
    """EINE ABGEWIESENE GEGENLESUNG, ALS TEST STATT ALS SATZ.

    Eine Pflicht-Gegenlesung meldete am 02.09.2026 als kritischen Fund: `_finalize_failclosed`
    setze `ok = False` und rufe DANACH die Nachkorrektur — die sei dort „moeglicherweise nicht
    mehr anwendbar oder fuehrt zu einem Fehler". Das war eine Vermutung, keine Messung.

    Am Quelltext geprueft: die Nachkorrektur greift NUR bei `ok is not True` UND
    `safeForAutomation is True`; sie ist idempotent und wirft nicht. Im fail-closed-Pfad steht
    `safe` bereits auf False, sie ist dort also ein No-op.

    Dieser Test haelt die Abweisung fest. Die Hausregel dazu: eine Gegenlesung ANZUNEHMEN und sie
    ABZUWEISEN sind dieselbe Art Aussage ueber den Quelltext — fuer die Annahme galt „am Code
    pruefen" laengst, fuer die Abweisung nicht, dabei ist sie die riskantere. Ein abgewiesener
    echter Befund bleibt im Baum.
    """
    fn = ar.verify_agent_review if pruefer == "v0.1" else ar.verify_agent_review_v02
    r = fn(umschlag, bytes(range(32)), strict=True)          # darf NICHT werfen
    a = r.get("automation") or {}
    assert r.get("ok") is False, f"{name}/{pruefer}: fail-closed liefert ok={r.get('ok')!r}"
    assert a.get("safeForAutomation") is False, (
        f"{name}/{pruefer}: die Automations-Flaeche meldet sicher auf einem fail-closed-Pfad")
    assert "RECEIPT_NOT_OK" in (a.get("automationBlockers") or []), (
        f"{name}/{pruefer}: der Grund fehlt. Blockers: {a.get('automationBlockers')}")


# NACHTRAG 02.09.2026: die urspruengliche Fassung dieses Tests nagelte fest, `RECEIPT_NOT_OK` werde
# hier NICHT angehaengt — damals stimmte das, weil die Nachkorrektur ein separater Aufruf war und
# auf dem fail-closed-Pfad nichts zu tun fand (`safe` stand schon auf False). Seit die Invariante
# IN `automation_summary` gefaltet ist, wird der Grund immer genannt, und das ist die bessere
# Antwort: ein Verbraucher sieht jetzt, DASS das Receipt nicht ok ist, statt es aus der Abwesenheit
# eines Blockers schliessen zu muessen.
#
# Die ABWEISUNG der Gegenlesung bleibt davon unberuehrt und ist weiterhin das, was dieser Test
# haelt: der Aufruf wirft nicht, und die Flaeche meldet nicht sicher.
