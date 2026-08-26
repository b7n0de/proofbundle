"""The two TOTAL boundaries never let a raw exception out — measured, not asserted.

WHERE THIS COMES FROM. An external review of 2026-08-23 rejected both sides of a long-running
argument ("must raise" vs "must return") and settled it as TWO named layers with exactly one
normalisation boundary between them:

    strict internal parse/validate layer -> may raise documented, typed errors
    total verify/plugin boundary         -> ALWAYS returns a normalised structured verdict

The house already had the pattern in `parse_tlog_proof` (strict) and `verify_tlog_proof`
(total). What it did not have was the boundary actually holding. Two gaps, both REPRODUCED on
main c669d39 before the fix:

  Gap 1 -- `verify_rfc3161(..., frozen=None)`
      The type floor reads `if frozen is not None and not isinstance(frozen, Mapping)`, so
      `None` passes it and reaches `frozen.get(...)`:
          AttributeError: 'NoneType' object has no attribute 'get'
      out of a function whose docstring promises "Returns {ok, detail}".

  Gap 2 -- a registered verifier that RETURNS the wrong shape
      `verify_anchor` wraps the verifier CALL in `except Exception`, but every `res.get(...)`
      sits OUTSIDE that try. Measured with a verifier returning each shape:
          None -> AttributeError | [1,2] -> AttributeError | 42 -> AttributeError | "x" -> AttributeError
      The comment in the source claimed the opposite ("nothing leaked over the public path").
      A raising third party was contained; a returning one was not.

WHY THAT ASYMMETRY IS THE INTERESTING PART. `register_anchor_type` tells third-party authors
their verifier "MUST be fail-closed … never raise for an ordinary bad proof". A boundary that
contains the authors who obey and crashes on the authors who do not has the guarantee exactly
backwards: the well-behaved plugin is protected, the misbehaving one takes the host down.

These tests bind the CONTRACT, not the implementation: for every hostile input shape the
boundary returns a verdict, and the verdict of a misbehaving verifier is indistinguishable from
that of a raising one.
"""
from __future__ import annotations

import base64

import pytest

from proofbundle import anchors
from proofbundle.anchors_rfc3161 import verify_rfc3161

WURZEL = b"\x07" * 32
FREMDE_FORMEN = (None, [1, 2], 42, "text", 3.5, True, b"bytes", set())


def _anker(atype: str = "vertragstest") -> dict:
    return {"type": atype, "target": "receipt",
            "canonicalRoot": base64.b64encode(WURZEL).decode(), "proof": "AA=="}


@pytest.fixture()
def registriert():
    """Registriert einen Testverifier und raeumt ihn wieder ab."""
    schluessel = "vertragstest"
    vorher = anchors._VERIFIERS.get(schluessel)
    yield schluessel
    if vorher is None:
        anchors._VERIFIERS.pop(schluessel, None)
    else:
        anchors._VERIFIERS[schluessel] = vorher


# ── Gap 1: die strikte Schicht laesst None nicht mehr durchfallen ──────────────────────────

def test_frozen_none_ergibt_ein_verdikt_statt_einer_rohen_exception():
    """GAP 1. `None` passierte den Mapping-Guard und traf danach `.get(...)`.

    Normalisiert statt abgelehnt: `verify_anchor` bildet jedes Nicht-dict-`frozen` ohnehin auf
    `{}` ab, "kein frozen-Block" ist hier also eine etablierte, fail-closed Bedeutung — sie
    ergibt `frozenEvidence: False` und `needs_rp_trust`, die sichere Richtung.
    """
    r = verify_rfc3161(b"x", b"y", frozen=None)
    assert isinstance(r, dict), f"kein Verdikt, sondern {type(r).__name__}"
    assert r.get("ok") is False, "ein leerer frozen-Block darf nie zu ok=True fuehren"
    assert r.get("frozenEvidence") is False


def test_die_strikte_schicht_darf_weiter_typisiert_werfen():
    """I2 des Reviews, ausdruecklich: strikte Grenzen bleiben ERLAUBT. Der Fix macht die
    Funktion nicht wahllos total — ein echter Typfehler wirft weiterhin typisiert, und genau
    diese Unterscheidung ist der ganze Entwurf. Wer das aufweicht, verliert die Diagnose."""
    from proofbundle.errors import BundleFormatError
    for schlecht in (123, "string", [1], object()):
        with pytest.raises(BundleFormatError):
            verify_rfc3161(b"", b"", frozen=schlecht)
        with pytest.raises(BundleFormatError):
            verify_rfc3161(b"", b"", frozen={}, rp_trust=schlecht)


def test_mapping_statt_dict_wird_weiter_akzeptiert():
    """I3 des Reviews. Nur `.get(...)` wird benutzt, also sind MappingProxyType und OrderedDict
    gueltige Eingaben. Ein Floor, der gueltige Eingabe ablehnt, ist ein eigener Defekt."""
    from collections import OrderedDict
    from types import MappingProxyType
    for form in (MappingProxyType({}), OrderedDict()):
        r = verify_rfc3161(b"x", b"y", frozen=form)
        assert isinstance(r, dict) and r.get("ok") is False


# ── Gap 2: die totale Grenze haelt auch gegen einen Verifier, der falsch ZURUECKGIBT ───────

@pytest.mark.parametrize("rueckgabe", FREMDE_FORMEN)
def test_verify_anchor_gibt_immer_ein_verdikt_egal_was_der_verifier_liefert(registriert, rueckgabe):
    """GAP 2, die eigentliche Zusage dieser Grenze.

    Fuer JEDE dieser Formen kam vorher eine rohe AttributeError heraus. `True` und `b"bytes"`
    stehen bewusst mit in der Liste: sie sind wahrheitswertig bzw. sequenzartig und wuerden von
    einer Pruefung, die nur auf `None` oder nur auf `isinstance(res, (list, int))` schaut,
    durchgelassen.
    """
    anchors._VERIFIERS[registriert] = lambda *a, **k: rueckgabe
    r = anchors.verify_anchor(_anker(), target_roots={"receipt": WURZEL})
    assert isinstance(r, dict), f"kein Verdikt, sondern {type(r).__name__}"
    assert r["ok"] is False and r["status"] == "fail"
    assert "fail-closed" in r["detail"]


def test_ein_falsch_zurueckgebender_verifier_ist_nicht_vom_werfenden_zu_unterscheiden(registriert):
    """DIE EIGENTLICHE VERTRAGSEIGENSCHAFT. Beide sind derselbe Fehlerfall — "der Verifier hat
    sich nicht an die Zusage gehalten" — und eine totale Grenze schuldet ihren Konsumenten, dass
    sie gleich aussehen. Ohne diesen Test koennte ein spaeterer Umbau die eine Form zu einem
    Sonderzustand machen und die Unterscheidung waere zurueck."""
    anchors._VERIFIERS[registriert] = lambda *a, **k: None
    zurueck = anchors.verify_anchor(_anker(), target_roots={"receipt": WURZEL})

    def wirft(*a, **k):
        raise RuntimeError("boom")

    anchors._VERIFIERS[registriert] = wirft
    geworfen = anchors.verify_anchor(_anker(), target_roots={"receipt": WURZEL})

    assert zurueck["ok"] == geworfen["ok"] is False
    assert zurueck["status"] == geworfen["status"] == "fail"
    assert set(zurueck) == set(geworfen), "die beiden Verdikte tragen verschiedene Felder"


def test_ein_gueltiges_mapping_laeuft_unveraendert_durch(registriert):
    """ANTI-TAUTOLOGIE, und sie ist hier unverzichtbar: eine Grenze, die ALLES auf fail
    abbildet, wuerde jeden Test darueber bestehen und waere trotzdem kaputt. Ein gueltiger
    Verifier muss weiterhin durchkommen, mit seinem eigenen detail."""
    anchors._VERIFIERS[registriert] = lambda *a, **k: {"ok": True}
    gut = anchors.verify_anchor(_anker(), target_roots={"receipt": WURZEL})
    assert gut["ok"] is True and gut["status"] == "pass"

    anchors._VERIFIERS[registriert] = lambda *a, **k: {"ok": False, "detail": "schlechter Beweis"}
    schlecht = anchors.verify_anchor(_anker(), target_roots={"receipt": WURZEL})
    assert schlecht["ok"] is False and schlecht["detail"] == "schlechter Beweis", (
        "das detail des Verifiers wurde ueberschrieben — dann geht die Diagnose verloren")


def test_ein_mappingproxy_als_rueckgabe_wird_akzeptiert(registriert):
    """Dieselbe Mapping-statt-dict-Regel auf der RUECKGABE-Seite. Ein Verifier, der ein
    unveraenderliches Mapping liefert, verhaelt sich vorbildlich und darf dafuer nicht als
    fehlerhaft gelten."""
    from types import MappingProxyType
    anchors._VERIFIERS[registriert] = lambda *a, **k: MappingProxyType({"ok": True})
    r = anchors.verify_anchor(_anker(), target_roots={"receipt": WURZEL})
    assert r["ok"] is True, r
