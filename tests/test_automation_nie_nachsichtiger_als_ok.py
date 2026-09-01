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
    """Baut einen v0.2-Umschlag von Hand — `emit_agent_review` kennt nur den v0.1-Typ."""
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


def _fahre(pfad, ziel, text):
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
        env, pruefer = ar.emit_agent_review(doc, SK), ar.verify_agent_review
        digest = ar._subject_digest(doc)
    kw = {}
    if ziel == "gesetzt":
        kw["expected_subject_digest"] = digest
    elif ziel == "falsch":
        kw["expected_subject_digest"] = "f" * 64
    if text == "passend":
        kw["observed_body"] = KOERPER
    elif text == "abweichend":
        kw["observed_body"] = "Ein GANZ ANDERER Rumpf, den niemand signiert hat."
    return pruefer(env, PK, strict=True, **kw)


@pytest.mark.parametrize("pfad,ziel,text", list(itertools.product(*VARIANTEN.values())))
def test_safe_impliziert_ok(pfad, ziel, text):
    """DIE INVARIANTE: safeForAutomation=True setzt ok=True voraus. Ueber die volle Kombination."""
    r = _fahre(pfad, ziel, text)
    a = r.get("automation") or {}
    if a.get("safeForAutomation") is True:
        assert r.get("ok") is True, (
            f"pfad={pfad!r} ziel={ziel!r} text={text!r}: die Automations-Flaeche meldet sicher, waehrend das "
            f"Receipt-Urteil ok={r.get('ok')!r} lautet — blockers={a.get('automationBlockers')}")


def test_die_menge_enthaelt_ueberhaupt_einen_nicht_ok_fall():
    """GEGENPROBE. Ohne sie waere der Test oben gruen, weil er nie einen ok=False sieht — genau
    die Tautologie, die im Konformitaets-Korpus dieses Releases gefunden wurde."""
    nicht_ok = [(p, z, t) for p in VARIANTEN["pfad"] for z in VARIANTEN["ziel_erwartung"]
                for t in VARIANTEN["sichtbarer_text"] if _fahre(p, z, t).get("ok") is not True]
    assert len(nicht_ok) >= 3, (
        f"nur {len(nicht_ok)} Kombinationen liefern ok!=True — die Menge prueft die Invariante "
        f"kaum: {nicht_ok}")


def test_beide_verifier_pfade_tragen_die_nachkorrektur():
    """STRUKTURELL, gegen die Klasse 'ein Fix erreichte nur eine Kopie'. Der urspruengliche Defekt
    entstand genau so: der v0.1-Pfad wurde gehaertet, der v0.2-Pfad nicht."""
    import inspect
    quelle = inspect.getsource(ar)
    n = quelle.count("_automation_darf_nicht_nachsichtiger_sein_als_ok(r)")
    assert n >= 2, (
        f"die Nachkorrektur wird nur {n}x gerufen — v0.1 UND v0.2 muessen sie tragen")


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
    assert (r.get("automation") or {}).get("safeForAutomation") is True


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
    "observed_time_assurance": "braucht eine beobachtete Zeit; v0.1 verbietet anchoredAt",
    "time_semantics": "v0.1-Konstante, kann in diesem Pfad nur einen Wert annehmen",
    # ── seit dem 02.09.2026, als die Pfad-Achse (v0.1 | v0.2) dazukam ──────────────────────────
    # Die fuenf Zeit-Achsen fuehrt NUR der v0.2-Pfad. Sie bewegen sich nicht an `ziel` oder `text`,
    # sondern an Zeitbelegen, die `apply_time_evidence` beisteuert — das ist eine andere Klasse und
    # hat ihre eigene Testdatei. Zwei Achsen sind aus dieser Liste GEFALLEN, weil die Pfad-Achse sie
    # wirklich bewegt: `internal_consistency_ok` und `disclosure_core_digest_match`. Eine
    # Begruendung, die nicht mehr stimmt, deckt sonst etwas, das niemand mehr prueft.
    "event_time_status": "v0.2-Zeitachse; bewegt sich an Zeitbelegen, nicht an Ziel oder Text",
    "external_time_status": "v0.2-Zeitachse; braucht einen externen Anker, den dieser Aufruf nicht gibt",
    "observation_time_status": "v0.2-Zeitachse; braucht eine beobachtete Zeit",
    "signature_time_status": "v0.2-Zeitachse; braucht eine bezeugte Signaturzeit",
    "policy_decision": "braucht eine uebergebene Policy; dieser Aufruf uebergibt keine",
}

#: Werte, die NICHT als Urteil zaehlen: Sammelbehaelter und das Urteil selbst.
_KEINE_ACHSE = ("ok", "errors", "warnings", "reason_code", "reason_codes", "advisory_codes",
                "automation")


def _achsen_und_werte():
    """Welche Achse nahm ueber die volle Matrix welche Werte an? GEMESSEN, nicht aufgezaehlt."""
    gesehen: dict[str, set] = {}
    for pfad, ziel, text in itertools.product(*VARIANTEN.values()):
        r = _fahre(pfad, ziel, text)
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
    """GEGENRICHTUNG. Eine Ausnahmeliste, die Namen fuehrt, die es nicht mehr gibt, waechst
    stumm zu und deckt irgendwann etwas, das niemand mehr prueft."""
    gesehen = _achsen_und_werte()
    verwaist = sorted(set(UNBEWEGT_BEGRUENDET) - set(gesehen))
    assert not verwaist, (
        f"UNBEWEGT_BEGRUENDET nennt Achsen, die das Ergebnis nicht mehr fuehrt: {verwaist}")


def test_meta_eine_neue_achse_wird_gefangen():
    """META. Beweist, dass der Vollstaendigkeits-Test ueberhaupt fallen KANN — sonst misst er
    nichts. Eine kuenstliche Achse wird eingeschleust; der Test muss sie melden."""
    gesehen = _achsen_und_werte()
    gesehen["eine_neue_achse_die_niemand_erklaert_hat"] = {"NUR_EIN_WERT"}
    bewegt = {k for k, v in gesehen.items() if len(v) > 1}
    unerklaert = sorted(set(gesehen) - bewegt - set(UNBEWEGT_BEGRUENDET))
    assert unerklaert == ["eine_neue_achse_die_niemand_erklaert_hat"], (
        f"der Vollstaendigkeits-Test faengt eine neue Achse NICHT — er misst nichts: {unerklaert}")
