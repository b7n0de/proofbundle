"""Die Statement-Form wird getypt, BEVOR Semantik gerechnet wird (P0.1/P0.3 der Gegenlese Runde 2).

WAS HIER GEMESSEN WURDE, bevor der Fix kam, am echten r2-Receipt und mit gueltiger Signatur UND
korrektem Ziel-Digest: falsches `_type`, ZWEI Subjects und ein Subject-Name, der auf ein fremdes
Repository zeigt — jeweils `ok=True`. Und `subject`/`declaration` als String verliessen die
oeffentliche Flaeche mit einer rohen AttributeError.

DIE FALLE, DIE FAST ZUGESCHNAPPT WAERE, steht hier, weil sie die wiederverwendbare Lehre ist:
OHNE Ziel-Digest waren dieselben drei Mutationen rot, und das sah aus, als gaebe es die Pruefungen
schon. Das Rot kam von einer voellig anderen Achse — dem fehlenden Zielvergleich. Ein Verdikt ist
kein Grund; erst der Fehlertext trennte die beiden.
"""
from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as AR
from proofbundle import canonical, dsse

SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PK = SK.public_key().public_bytes_raw()


def _pred() -> dict:
    return {
        "schemaVersion": "0.1.0", "reviewId": "r",
        "subjectContext": {"kind": "githubPullRequest", "forge": "g", "repositoryId": "R",
                           "pullRequestNodeId": "P", "headSha": "a" * 40, "baseSha": "b" * 40,
                           "reviewedDiffDigest": "c" * 64, "bodyCoreDigest": "d" * 64},
        "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "x"}],
                        "reviewRuns": [], "findings": [], "findingsTotal": 0, "nonClaims": ["n"]},
        "coverage": {"status": "UNKNOWN"},
        "times": {"declaredAt": "2026-08-31T17:00:00Z"},
        "limitations": ["l"],
    }


def _stmt(**ueberschreiben) -> dict:
    p = _pred()
    st = {"_type": AR.STATEMENT_TYPE,
          "subject": [{"name": AR._subject_name(p), "digest": {"sha256": AR._subject_digest(p)}}],
          "predicateType": AR.AGENT_REVIEW_PREDICATE_TYPE,
          "predicate": p}
    st.update(ueberschreiben)
    return st


def _sig(st: dict) -> dict:
    return dsse.sign_envelope(canonical.canonicalize_statement(st), SK,
                              payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)


def _ziel() -> str:
    return AR._subject_digest(_pred())


# ── die Kontrolle zuerst: ohne sie belegt jedes Rot unten nichts ───────────────────────────────

def test_die_kontrolle_ist_gruen():
    r = AR.verify_agent_review(_sig(_stmt()), PK, strict=True, expected_subject_digest=_ziel())
    assert r["ok"] is True and r["statement_shape_ok"] is True, r["errors"]


# ── P0.3: die Statement-Ebene wird wirklich geprueft ───────────────────────────────────────────

@pytest.mark.parametrize("name,mutation", [
    ("_type falsch", {"_type": "https://example.org/Falsch/v9"}),
    ("_type fehlt", {"_type": None}),
    ("zwei Subjects", None),
    ("leeres Subject-Array", {"subject": []}),
    ("subject als String", {"subject": "nicht-liste"}),
    ("subject[0] als String", {"subject": ["text"]}),
    ("Extra-Feld im Statement", {"schmuggel": 1}),
])
def test_fehlgeformte_statements_fallen_TROTZ_gueltiger_signatur(name, mutation):
    st = _stmt()
    if name == "zwei Subjects":
        st["subject"] = st["subject"] * 2
    elif mutation.get("_type", "x") is None:
        del st["_type"]
    else:
        st.update(mutation)
    r = AR.verify_agent_review(_sig(st), PK, strict=True, expected_subject_digest=_ziel())
    assert r["ok"] is False, f"{name}: durchgelassen"
    assert r["statement_shape_ok"] is False, f"{name}: Form nicht als Grund gemeldet"


def test_subject_name_muss_aus_dem_signierten_kontext_folgen():
    """Der Kern von N03: ein Name, der auf ein fremdes Repo zeigt, waehrend die Signatur ueber
    einen anderen Kontext geht. Vorher: ok=True."""
    st = _stmt()
    st["subject"][0]["name"] = "github-pr:fremd/repo#1"
    r = AR.verify_agent_review(_sig(st), PK, strict=True, expected_subject_digest=_ziel())
    assert r["ok"] is False and r["statement_shape_ok"] is False
    assert any("disagree" in e for e in r["errors"]), r["errors"]


@pytest.mark.parametrize("digest", [
    {"sha1": "a" * 40},                       # falscher Algorithmus
    {"sha256": "a" * 64, "sha1": "b" * 40},   # zwei Algorithmen zur Auswahl
    {"sha256": "A" * 64},                     # Grossbuchstaben
    {"sha256": "a" * 63},                     # zu kurz
    "nicht-objekt",
])
def test_digestform_wird_eng_gefuehrt(digest):
    st = _stmt()
    st["subject"][0]["digest"] = digest
    r = AR.verify_agent_review(_sig(st), PK, strict=True, expected_subject_digest=_ziel())
    assert r["statement_shape_ok"] is False and r["ok"] is False


# ── P0.1: never raise, und der Notausgang ist NICHT die Antwort ────────────────────────────────

@pytest.mark.parametrize("wert", ["text", ["a"], 7, None])
def test_declaration_falsch_getypt_faellt_GETYPT_nicht_ueber_die_huelle(wert):
    """Die Huelle faengt alles — genau deshalb darf sie hier nicht greifen. `internal_error` meldet
    einen VERIFIER-Defekt; eine bekannte Eingabeklasse muss ein normales Urteil ergeben."""
    st = _stmt()
    st["predicate"]["declaration"] = wert
    r = AR.verify_agent_review(_sig(st), PK, strict=True, expected_subject_digest=_ziel())
    assert r["ok"] is False
    assert r.get("reason_code") != "internal_error", "als Verifier-Defekt gemeldet statt getypt"
    assert r["findings_root_ok"] is False and r["assurance_ok"] is False, (
        "beide Achsen muessen fail-closed sein — nicht unbekannt bleiben")


def test_die_huelle_existiert_und_liefert_einen_stabilen_code():
    """Die Gegenrichtung zum Test darueber: fuer WIRKLICH Unmodelliertes muss die Huelle greifen
    und ein typisiertes Ergebnis liefern, keine Ausnahme."""
    r = AR.verify_agent_review({"payload": "nicht-base64!!", "payloadType": "x",
                                "signatures": [{"sig": "x"}]}, PK)
    assert r["ok"] is False and r["structure_ok"] is False


def test_kein_verify_pfad_wirft_bei_beliebigem_muell():
    """Breit statt tief: keine dieser Eingaben darf eine Ausnahme aus der oeffentlichen Flaeche
    lassen. Ein Verifier, der abstuerzt, ist dort blind, wo ein Angreifer ansetzt."""
    for muell in [{}, {"payload": None}, {"payload": [], "signatures": None},
                  {"payload": base64.b64encode(b"{}").decode(), "payloadType": "x",
                   "signatures": [{"sig": base64.b64encode(b"\x00" * 64).decode()}]},
                  {"payload": base64.b64encode(json.dumps({"_type": 1}).encode()).decode(),
                   "payloadType": AR.INTOTO_STATEMENT_PAYLOAD_TYPE,
                   "signatures": [{"sig": base64.b64encode(b"\x00" * 64).decode()}]}]:
        r = AR.verify_agent_review(muell, PK)      # darf NICHT werfen
        assert r["ok"] is not True


# ── die Reihenfolge selbst: Semantik erst NACH der Typisierung ─────────────────────────────────

def test_semantik_laeuft_nicht_auf_ungetypter_form():
    """Wenn die Form faellt, darf keine semantische Achse ein Urteil behaupten — sonst rechnete
    sie auf Sand, und genau dort fielen die rohen Ausnahmen."""
    st = _stmt()
    st["subject"] = "nicht-liste"
    r = AR.verify_agent_review(_sig(st), PK, strict=True, expected_subject_digest=_ziel())
    assert r["statement_shape_ok"] is False
    assert r["subject_binding_ok"] is None, "Bindung wurde trotz kaputter Form gerechnet"


# ── die Huelle selbst: sie wird erst durch einen eingepflanzten Fehler pruefbar ────────────────

def test_die_huelle_wandelt_eine_unerwartete_ausnahme_in_ein_urteil(monkeypatch):
    """DIESER TEST EXISTIERT WEGEN EINES MUTANTEN, DEN DIE SUITE NICHT FING.

    Der Gate-Meta-Lauf am 31.08.2026 entfernte die Never-Raise-Huelle (`except Exception` zu
    `except ZeroDivisionError`) und ALLE 32 Tests blieben gruen. Der Grund ist gerade der Erfolg
    der Typisierung davor: seit `_type`, Subject-Form und `declaration` getypt werden, erreicht
    keine der geprueften Eingaben die Huelle mehr. Eine Verteidigung in der Tiefe, die kein Test
    ausloest, ist nicht bewiesen — sie ist nur vorhanden.

    Ein Angreifer sucht sich nicht die Eingaben aus, die wir modelliert haben. Deshalb wird der
    unmodellierte Fall hier ERZWUNGEN: ein interner Aufruf wirft, und die oeffentliche Flaeche
    muss daraus ein typisiertes Ergebnis mit stabilem Code machen statt die Ausnahme
    durchzulassen."""
    def platzt(*_a, **_k):
        raise RuntimeError("etwas, das niemand modelliert hat")

    monkeypatch.setattr(AR, "validate_statement_shape", platzt)
    r = AR.verify_agent_review(_sig(_stmt()), PK, strict=True, expected_subject_digest=_ziel())
    assert r["ok"] is False
    assert r["reason_code"] == "internal_error", "die Huelle liefert keinen stabilen Code"
    assert r["structure_ok"] is False
    assert any("RuntimeError" in e for e in r["errors"]), r["errors"]
    assert any("defect in the verifier" in e for e in r["errors"]), (
        "der Code muss als VERIFIER-Defekt kenntlich sein, nicht als Urteil ueber das Receipt")


def test_ohne_die_huelle_kaeme_die_ausnahme_durch(monkeypatch):
    """Die Gegenrichtung, damit der Test darueber nicht selbst tautologisch wird: derselbe
    eingepflanzte Fehler MUSS auf dem inneren Pfad als Ausnahme sichtbar sein. Waere er das
    nicht, bewiese der Test oben nur, dass irgendetwas ok=False liefert."""
    def platzt(*_a, **_k):
        raise RuntimeError("etwas, das niemand modelliert hat")

    monkeypatch.setattr(AR, "validate_statement_shape", platzt)
    with pytest.raises(RuntimeError):
        AR._verify_agent_review_inner(_sig(_stmt()), PK, strict=True,
                                      expected_subject_digest=_ziel())
