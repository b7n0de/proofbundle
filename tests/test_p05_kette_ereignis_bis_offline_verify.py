"""P0.5.5 — GitHub-Ereignis, Body-Render, Zeuge und Offline-Verify als EINE Kette.

DER FUND, den das Fahren dieser Kette am 01.09.2026 zutage foerderte, und er betrifft jeden, der
unsere Belege nachprueft:

    gh api ... --jq '.body'   -> 3976 B, Digest a35cb91602e48178, MISMATCH
    derselbe Rumpf ohne den
    letzten Zeilenumbruch     -> 3975 B, Digest 40bdf04bc72bd820, MATCH

`--jq` haengt GENAU EINEN Zeilenumbruch an. Der veroeffentlichte Beleg ist in Ordnung; das
MESSWERKZEUG hat den Gegenstand veraendert. `rstrip("\\n")` ist ebenfalls falsch — es entfernt zu
viel und ergibt einen dritten Digest. Ich war eine Messung davon entfernt, eine Drift am eigenen
veroeffentlichten Receipt zu melden, die es nicht gibt.

DESHALB LAEUFT DIESER TEST OFFLINE ueber eine aufgezeichnete Fixture: der Rumpf, wie er am Ziel
steht, byte-genau. Die Kette wird damit in CI wiederholbar, und die Falle bleibt gepinnt.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from proofbundle import agent_review as AR

FIX = Path(__file__).resolve().parent / "fixtures" / "kette_147"
BODY = (FIX / "body_wie_am_ziel.md").read_text(encoding="utf-8")
ENV = json.loads((FIX / "receipt.json").read_text(encoding="utf-8"))
PRED = json.loads(base64.b64decode(ENV["payload"]))["predicate"]

#: Der Pubkey des Ausstellers. Er steht HIER, weil er sonst nirgends veroeffentlicht ist — genau
#: das ist der offene Punkt P1.3, und ein Test, der ihn braucht, macht ihn wenigstens auffindbar.
PUBKEY_HEX = "dfb2f4d05ceda23253fa26927b86e2408eead905fcaad8ba057947d4afde9d2e"


# ── Glied 1 und 2: das Ereignis und der gerenderte Block ──────────────────────────────────────

def test_der_rumpf_traegt_genau_einen_gerenderten_offenlegungsblock():
    assert BODY.count(AR.DISCLOSURE_BEGIN) == 1
    assert BODY.count(AR.DISCLOSURE_END) == 1


def test_der_block_ist_die_kanonische_drei_zeilen_form():
    innen = BODY[BODY.index(AR.DISCLOSURE_BEGIN) + len(AR.DISCLOSURE_BEGIN):
                 BODY.index(AR.DISCLOSURE_END)].strip("\n")
    zeilen = innen.splitlines()
    assert len(zeilen) == 3, f"{len(zeilen)} Zeilen statt drei"
    assert "" not in zeilen, "eine Leerzeile im Block — das Eingabefeld rendert sie als Absatz"
    assert zeilen[2].startswith("<sub><code>sha256:")


# ── Glied 3: Offline-Verify gegen genau diesen Rumpf ──────────────────────────────────────────

def test_die_kette_haelt_offline_gegen_den_rumpf_am_ziel():
    r = AR.verify_agent_review(ENV, bytes.fromhex(PUBKEY_HEX), strict=True,
                               expected_subject_digest=AR._subject_digest(PRED),
                               observed_body=BODY)
    assert r["crypto_ok"] is True, r["errors"]
    assert r["subject_binding_ok"] is True
    assert r["body_core_digest_match"] == "MATCH", r["errors"]
    assert r["ok"] is True, r["errors"]


# ── die Falle, gepinnt in BEIDE Richtungen ────────────────────────────────────────────────────

def test_ein_zusaetzlicher_zeilenumbruch_erzeugt_einen_falschen_MISMATCH():
    """Der Fehlalarm, in den jeder externe Pruefer mit `gh api --jq` laeuft."""
    r = AR.verify_agent_review(ENV, bytes.fromhex(PUBKEY_HEX), strict=True,
                               expected_subject_digest=AR._subject_digest(PRED),
                               observed_body=BODY + "\n")
    assert r["body_core_digest_match"] == "MISMATCH"
    assert r["ok"] is False


def test_und_rstrip_entfernt_zu_viel_und_erzeugt_einen_DRITTEN_digest():
    """Die naheliegende Reparatur ist ebenfalls falsch — deshalb steht sie hier als Gegenprobe."""
    zu_viel = (BODY + "\n").rstrip("\n")
    assert AR.body_core_digest(zu_viel) != AR.body_core_digest(BODY), (
        "rstrip trifft hier zufaellig das Richtige — dann ist dieser Test veraltet")
    r = AR.verify_agent_review(ENV, bytes.fromhex(PUBKEY_HEX), strict=True,
                               expected_subject_digest=AR._subject_digest(PRED),
                               observed_body=zu_viel)
    assert r["body_core_digest_match"] == "MISMATCH"


def test_der_receipt_digest_der_fixture_ist_der_veroeffentlichte():
    """Damit auffaellt, wenn jemand die Fixture gegen ein anderes Receipt tauscht."""
    assert AR.receipt_digest(ENV) == (
        "5f5755dcef03bf30488894cc08c83fb8e1fd2f8b392bd2edeb2a90af0ac19f4b")


# ── Glied 4: der Zeuge, mit ehrlicher Grenze ──────────────────────────────────────────────────

def test_das_receipt_behauptet_KEINEN_zeugen_und_das_ist_die_ehrliche_lage():
    """Der Zeuge ist das vierte Glied der Kette — und dieses Receipt traegt ihn NICHT.

    Bezeugt und verankert sind zwei verschiedene Tatsachen, und beide sind verschieden von
    "signiert". Das Predicate sagt das selbst in seinen `limitations`; der Test haelt fest, dass
    es das weiterhin tut, statt dass jemand die Zeile spaeter still entfernt.
    """
    assert AR._zeitachsen(PRED)["external_time_status"] == "NOT_EVALUATED"
    assert any("transparency-log" in x or "timestamp anchor" in x
               for x in PRED["limitations"]), PRED["limitations"]
