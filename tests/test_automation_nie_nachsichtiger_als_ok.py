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
KOERPER = "Ein PR-Rumpf, wie er sichtbar veroeffentlicht wird."


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
    "ziel_erwartung": [None, "gesetzt", "falsch"],
    "sichtbarer_text": [None, "passend", "abweichend"],
}


def _fahre(ziel, text):
    doc = _doc()
    env = ar.emit_agent_review(doc, SK)
    kw = {}
    if ziel == "gesetzt":
        kw["expected_subject_digest"] = ar._subject_digest(doc)
    elif ziel == "falsch":
        kw["expected_subject_digest"] = "f" * 64
    if text == "passend":
        kw["observed_body"] = KOERPER
    elif text == "abweichend":
        kw["observed_body"] = "Ein GANZ ANDERER Rumpf, den niemand signiert hat."
    return ar.verify_agent_review(env, PK, strict=True, **kw)


@pytest.mark.parametrize("ziel,text", list(itertools.product(*VARIANTEN.values())))
def test_safe_impliziert_ok(ziel, text):
    """DIE INVARIANTE: safeForAutomation=True setzt ok=True voraus. Ueber die volle Kombination."""
    r = _fahre(ziel, text)
    a = r.get("automation") or {}
    if a.get("safeForAutomation") is True:
        assert r.get("ok") is True, (
            f"ziel={ziel!r} text={text!r}: die Automations-Flaeche meldet sicher, waehrend das "
            f"Receipt-Urteil ok={r.get('ok')!r} lautet — blockers={a.get('automationBlockers')}")


def test_die_menge_enthaelt_ueberhaupt_einen_nicht_ok_fall():
    """GEGENPROBE. Ohne sie waere der Test oben gruen, weil er nie einen ok=False sieht — genau
    die Tautologie, die im Konformitaets-Korpus dieses Releases gefunden wurde."""
    nicht_ok = [(z, t) for z in VARIANTEN["ziel_erwartung"] for t in VARIANTEN["sichtbarer_text"]
                if _fahre(z, t).get("ok") is not True]
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


def test_der_kontrollfall_bleibt_gruen():
    """Ein Riegel, der alles blockt, ist kein Riegel."""
    r = _fahre("gesetzt", "passend")
    assert r.get("ok") is True
    assert (r.get("automation") or {}).get("safeForAutomation") is True


#: Achsen, die diese Aufruf-Matrix NICHT bewegt — je mit dem Grund, warum das in Ordnung ist.
#: Diese Liste ist der EINZIGE erlaubte Rest. Waechst das Modul um eine Achse, die hier nicht
#: steht und die die Matrix nicht bewegt, faellt `test_die_menge_ist_vollstaendig` — genau das,
#: was der Kopf dieser Datei zusagt.
UNBEWEGT_BEGRUENDET = {
    "assurance_ok": "haengt an der Sprossen-Erklaerung im Dokument, nicht am Aufruf",
    "crypto_ok": "haengt am Schluessel, nicht am Aufruf — eine falsche Signatur ist eine andere Klasse",
    "findings_root_ok": "haengt an der Befundliste im Dokument, nicht am Aufruf",
    "internal_consistency_ok": "Sammelachse ueber die Dokumentpruefung, vom Aufruf unabhaengig",
    "internal_subject_consistency_ok": "haengt am subjectContext im Dokument",
    "predicate_type_ok": "haengt am Umschlag, nicht am Aufruf",
    "statement_shape_ok": "haengt am Umschlag, nicht am Aufruf",
    "structure_ok": "haengt am Dokument, nicht am Aufruf",
    "disclosure_core_digest_match": "braucht einen Offenlegungsblock; dieses Dokument fuehrt keinen",
    "currentness": "braucht eine Kette; dieser Aufruf uebergibt keine",
    "observed_time_assurance": "braucht eine beobachtete Zeit; v0.1 verbietet anchoredAt",
    "time_semantics": "v0.1-Konstante, kann in diesem Pfad nur einen Wert annehmen",
}

#: Werte, die NICHT als Urteil zaehlen: Sammelbehaelter und das Urteil selbst.
_KEINE_ACHSE = ("ok", "errors", "warnings", "reason_code", "reason_codes", "automation")


def _achsen_und_werte():
    """Welche Achse nahm ueber die volle Matrix welche Werte an? GEMESSEN, nicht aufgezaehlt."""
    gesehen: dict[str, set] = {}
    for ziel, text in itertools.product(*VARIANTEN.values()):
        r = _fahre(ziel, text)
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
