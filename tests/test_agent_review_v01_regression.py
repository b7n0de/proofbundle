"""A5, zweite Haelfte: die sechs v0.1-Receipts urteilen unter v0.2 wie unter 5.1.0.

Der Auftrag (Thema 5, A5) woertlich: "Die sechs bestehenden v0.1-Receipts unter
receipts/agent_review laufen als Regressionsfaelle, jedes muss `legacy` und denselben `ok`-Wert
wie unter 5.1.0 tragen, die Werte werden vorher unter 5.1.0 gemessen und als Erwartung
eingefroren."

DIE ERWARTUNG IST GEMESSEN, NICHT GESCHRIEBEN. Sie liegt in
conformance/agent_review/_regression/v01_unter_510.json und stammt aus einem Lauf gegen den Tag
v5.1.0 (06ee9ef), nicht aus diesem Zweig. Wer sie aus dem heutigen Code ableitete, bekaeme eine
Tautologie: jede Fassung bestuende.

ZWEI EINGABEN JE RECEIPT, und die zweite ist die, die traegt. Ohne erwarteten Subject-Digest
steht `subject_expectation` auf "not_supplied" und `ok` ist bei ALLEN sechs false — eine
Erwartung, in der alles false ist, unterscheidet nichts und faengt keine Regression. Mit dem
Digest aus der eigenen Nutzlast gehen fuenf auf true und eines bleibt false. Erst dieser
Unterschied macht den Fall zu einem Test.

EIN BEFUND STEHT IN DER ERWARTUNG, unveraendert eingefroren: `inspect_ai_5141.receipt.json`
hat unter 5.1.0 `crypto_ok=false` — es verifiziert nicht gegen den veroeffentlichten Schluessel,
waehrend seine Nachfolger r2 und r3 es tun. Das wird hier NICHT geheilt und nicht weggelassen:
eine Regression friert den Zustand ein, den es gab, nicht den, den man sich wuenscht.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ERWARTUNG = REPO / "conformance" / "agent_review" / "_regression" / "v01_unter_510.json"
RECEIPTS = REPO / "receipts" / "agent_review"


def _erwartung() -> dict:
    assert ERWARTUNG.is_file(), (
        f"{ERWARTUNG} fehlt — ohne die unter 5.1.0 gemessene Erwartung ist dieser Test "
        "wertlos und darf NICHT still gruen werden")
    return json.loads(ERWARTUNG.read_text(encoding="utf-8"))


def _schluessel() -> bytes:
    # HEX MIT ZEILENUMBRUCH. Als rohe Bytes gelesen ergaebe die Datei einen falschen Pubkey,
    # und die Fehlmessung saehe aus wie ein Sicherheitsbefund.
    roh = (RECEIPTS / "inspect_ai_5141.publickey.hex").read_text(encoding="utf-8").strip()
    k = bytes.fromhex(roh)
    assert len(k) == 32, f"kein ed25519-Pubkey: {len(k)} Bytes"
    return k


def _namen() -> list[str]:
    return sorted(_erwartung()["receipts"])


def test_die_erwartung_stammt_aus_5_1_0_und_nicht_aus_diesem_zweig():
    """Sonst waere der ganze Test eine Tautologie."""
    e = _erwartung()
    assert e["gemessen_unter"] == "proofbundle 5.1.0"
    assert e["tag"] == "v5.1.0"
    assert e["commit"] == "06ee9ef"
    assert len(e["receipts"]) == 6, "der Auftrag nennt SECHS Bestands-Receipts"


def test_die_erwartung_trennt_ueberhaupt():
    """Eine Erwartung, in der alles denselben Wert traegt, faengt keine Regression.

    Genau das war die erste Fassung: ohne erwarteten Digest stand `ok` bei allen sechs auf
    false. Der Fall haette JEDE Verifier-Aenderung bestanden.
    """
    werte = {n: d["mit_eigenem_digest"].get("ok")
             for n, d in _erwartung()["receipts"].items()}
    assert len(set(werte.values())) > 1, (
        f"die eingefrorene Erwartung unterscheidet nichts: {werte}")


@pytest.mark.parametrize("name", _namen())
def test_v01_receipt_urteilt_wie_unter_510(name):
    """Derselbe `ok`-Wert wie unter 5.1.0 — mit derselben Eingabe."""
    from proofbundle import agent_review as ar

    e = _erwartung()["receipts"][name]
    umschlag = json.loads((RECEIPTS / name).read_text(encoding="utf-8"))
    dig = e["subject_digest_aus_nutzlast"]
    r = ar.verify_agent_review_any(umschlag, _schluessel(), expected_subject_digest=dig)
    soll = e["mit_eigenem_digest"]
    assert r.get("ok") == soll.get("ok"), (
        f"{name}: ok wanderte von {soll.get('ok')} (5.1.0) auf {r.get('ok')} (v0.2-Zweig)")
    for feld in ("crypto_ok", "structure_ok", "internal_consistency_ok", "subject_expectation"):
        if feld in soll:
            assert r.get(feld) == soll[feld], (
                f"{name}: {feld} wanderte von {soll[feld]} auf {r.get(feld)}")


@pytest.mark.parametrize("name", _namen())
def test_v01_receipt_wird_als_legacy_ausgewiesen(name):
    """Der Auftrag verlangt den sichtbaren Altfassungs-Ausweis (A2).

    Ein v0.1-Receipt muss unter v0.2 sagen, dass es eine Altfassung ist — sonst weiss ein
    Leser des Ergebnisses nicht, nach welcher Regel geurteilt wurde.
    """
    from proofbundle import agent_review as ar

    e = _erwartung()["receipts"][name]
    umschlag = json.loads((RECEIPTS / name).read_text(encoding="utf-8"))
    r = ar.verify_agent_review_any(umschlag, _schluessel(),
                                   expected_subject_digest=e["subject_digest_aus_nutzlast"])
    status = r.get("predicateVersionStatus") or r.get("predicate_version_status")
    codes = r.get("reason_codes") or r.get("reasonCodes") or []
    assert status == "legacy" or "AGENT_REVIEW_LEGACY_V01" in codes, (
        f"{name}: weder predicateVersionStatus=legacy noch AGENT_REVIEW_LEGACY_V01 — "
        f"Status {status!r}, Codes {codes!r}")


@pytest.mark.parametrize("name", _namen())
def test_alle_sechs_sind_wirklich_v01(name):
    """Die Gegenprobe zur Menge: waere ein v0.2-Receipt darunter, prueften wir das Falsche."""
    umschlag = json.loads((RECEIPTS / name).read_text(encoding="utf-8"))
    nutz = json.loads(base64.b64decode(umschlag["payload"]))
    assert str(nutz.get("predicateType", "")).endswith("/agent-review/v0.1"), (
        f"{name} ist kein v0.1-Receipt: {nutz.get('predicateType')}")
