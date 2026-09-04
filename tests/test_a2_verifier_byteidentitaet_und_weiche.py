"""Teil A2: der v0.1-Verifizierer bleibt byte-identisch, und eine Weiche liest beide Fassungen.

WARUM BYTE-IDENTITAET UND NICHT "VERHAELT SICH GLEICH". Ein Verhaltenstest prueft die Faelle, die
jemand aufgeschrieben hat. Sechs Receipts stehen draussen und wurden unter dem 5.1.0-Verifizierer
ausgestellt; fuer sie zaehlt nicht, ob wir an dieselben Faelle gedacht haben, sondern ob der Code
derselbe ist. Der Pin ist deshalb der sha256 des FUNKTIONSQUELLTEXTS, aufgeloest per `ast` — nicht
der der ganzen Datei, die sich aus hundert unbeteiligten Gruenden aendert.

DER SCHEINBARE WIDERSPRUCH IN A2, und wie er aufgeloest ist. A2 verlangt die Byte-Identitaet UND
dass ein v0.1-Ergebnis die Altfassung ausweist. Beides zugleich geht nur, wenn die Kennzeichnung
AUSSERHALB der gepinnten Funktion entsteht: sie gehoert der Weiche `verify_agent_review_any`.
Ehrlich benannt: wer `verify_agent_review` direkt ruft, bekommt sie nicht.

DER PIN IST GEGEN DEN TAG GENOMMEN, nicht gegen den aktuellen Baum. Ein Pin gegen den Baum, in dem
man gerade arbeitet, ist eine Tautologie — er bestaetigt, dass nichts sich geaendert hat, seit man
zuletzt hingesehen hat.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from proofbundle import agent_review as AR

REPO = Path(__file__).resolve().parents[1]
QUELLE = REPO / "src" / "proofbundle" / "agent_review.py"

#: Gemessen am 04.09.2026 gegen `git show v5.1.0:src/proofbundle/agent_review.py`.
PIN_5_1_0 = {
    "verify_agent_review": "1fe2c866cc8f072d",
    "_empty_result": "33afb78339e43cf5",
}


def _funktionsquelle(text: str, name: str) -> str:
    for knoten in ast.walk(ast.parse(text)):
        if isinstance(knoten, ast.FunctionDef) and knoten.name == name:
            return ast.get_source_segment(text, knoten)
    raise AssertionError(f"{name} ist nicht mehr auffindbar")


def _kurz_sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


@pytest.mark.parametrize("name", sorted(PIN_5_1_0))
def test_der_v01_pfad_ist_byteidentisch_zum_stand_5_1_0(name):
    jetzt = _kurz_sha(_funktionsquelle(QUELLE.read_text(encoding="utf-8"), name))
    assert jetzt == PIN_5_1_0[name], (
        f"{name} hat sich gegenueber 5.1.0 geaendert ({jetzt} statt {PIN_5_1_0[name]}). "
        "Sechs Receipts stehen draussen und wurden unter diesem Code ausgestellt — eine Aenderung "
        "hier ist eine Entscheidung ueber sie, keine Aufraeumarbeit.")


def test_der_pin_stimmt_mit_dem_tag_ueberein_nicht_nur_mit_sich_selbst():
    """GEGENPROBE: der Pin oben ist eine abgetippte Zahl. Sie muss gegen die WIRKLICHE Fassung im
    Tag stehen, sonst pinnt sie sich selbst fest."""
    r = subprocess.run(["git", "show", "v5.1.0:src/proofbundle/agent_review.py"],
                       capture_output=True, text=True, cwd=str(REPO), timeout=60)
    if r.returncode != 0:
        pytest.skip("Tag v5.1.0 in diesem Checkout nicht aufloesbar — der Pin bleibt ungeprueft")
    for name, erwartet in PIN_5_1_0.items():
        assert _kurz_sha(_funktionsquelle(r.stdout, name)) == erwartet, (
            f"der eingetragene Pin fuer {name} entspricht nicht dem Tag v5.1.0")


# ── die Weiche ────────────────────────────────────────────────────────────────────────────────

def _umschlag(predicate_type: str) -> dict:
    payload = base64.b64encode(json.dumps(
        {"_type": AR.STATEMENT_TYPE, "predicateType": predicate_type,
         "subject": [{"name": "x", "digest": {"sha256": "0" * 64}}],
         "predicate": {}}).encode()).decode()
    return {"payload": payload, "payloadType": "application/vnd.in-toto+json", "signatures": []}


def test_ein_fremder_predicate_type_wird_abgewiesen_nicht_geraten():
    r = AR.verify_agent_review_any(_umschlag("https://example.org/etwas/v9"), b"\0" * 32)
    assert r["ok"] is False
    assert r["reason_code"] == "AGENT_REVIEW_PREDICATE_TYPE_UNKNOWN"
    assert r["predicateVersionStatus"] == "unknown"


def test_ein_unlesbarer_umschlag_wirft_nicht_sondern_urteilt():
    """Die Zusage dieser Flaeche ist never-raise. Ein Aufrufer, der einen Traceback bekommt, hat
    kein Urteil — und ein fehlendes Urteil liest sich in jeder Automatisierung wie ein Fehler des
    Aufrufers statt wie einer der Eingabe."""
    for kaputt in ({}, {"payload": "kein base64!"}, {"payload": base64.b64encode(b"{").decode()}):
        r = AR.verify_agent_review_any(kaputt, b"\0" * 32)
        assert r["ok"] is False
        assert r["predicateVersionStatus"] == "unknown"


def test_die_weiche_kennzeichnet_die_altfassung():
    r = AR.verify_agent_review_any(_umschlag(AR.AGENT_REVIEW_PREDICATE_TYPE), b"\0" * 32)
    assert r["predicateVersionStatus"] == "legacy"
    assert AR.AGENT_REVIEW_LEGACY_V01 in r["reason_codes"]


def test_die_weiche_kennzeichnet_die_aktuelle_fassung():
    r = AR.verify_agent_review_any(_umschlag(AR.AGENT_REVIEW_PREDICATE_TYPE_V02), b"\0" * 32)
    assert r["predicateVersionStatus"] == "current"
    assert AR.AGENT_REVIEW_LEGACY_V01 not in (r.get("reason_codes") or [])


def test_die_weiche_bessert_das_urteil_ihrer_fassung_nicht_nach():
    """`ok` bleibt, was der jeweilige Verifizierer sagt. Ein Dispatcher, der nachbessert, waere ein
    zweiter Verifizierer mit demselben Namen."""
    env = _umschlag(AR.AGENT_REVIEW_PREDICATE_TYPE)
    direkt = AR.verify_agent_review(env, b"\0" * 32)
    ueber_weiche = AR.verify_agent_review_any(env, b"\0" * 32)
    assert direkt["ok"] == ueber_weiche["ok"]
    assert direkt["reason_code"] == ueber_weiche["reason_code"]
