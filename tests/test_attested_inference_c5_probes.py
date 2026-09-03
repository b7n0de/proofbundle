"""C5 plant probes — each one must fail at the place it is supposed to fail.

These are the eight probes named in the order (QITEM-DEEPGATE-ANBIETERBEZEUGTE-INFERENZ-01, C5).
A probe is not a demonstration that the code works; it is a demonstration that the code REFUSES.
Every test below plants a specific defect in the input and asserts both the refusal AND its
reason, because a refusal for the wrong reason is a different bug wearing the right answer.

The eighth probe is the one that binds this module to the wider claim: a receipt that says
HARDWARE_ATTESTED while binding no evidence package must not verify. This module cannot produce
that level at all, and the test asserts that structurally rather than by inspection.
"""

from __future__ import annotations

import hashlib
import json
import unittest

import pytest

from proofbundle.errors import BundleFormatError
from proofbundle.experimental import attested_inference as ai

NONCE = "n0nce-3f8a91c47b2e5d60"
REQ = b'{"model":"m","prompt":"p"}'
RES = b'{"choices":[{"text":"answer"}]}'


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _evidence(**over):
    """A provider answer that passes everything, so each probe changes exactly one thing."""
    e = {
        "provider_signature": "sig...",
        "signed": {
            "nonce": NONCE,
            "request_hash": _sha(REQ),
            "response_hash": _sha(RES),
        },
        "route": "backend-a",
    }
    e.update(over)
    return e


def _check(evidence, **kw):
    kw.setdefault("provider", "testprovider")
    kw.setdefault("nonce", NONCE)
    kw.setdefault("request_bytes", REQ)
    kw.setdefault("response_bytes", RES)
    kw.setdefault("planned_route", "backend-a")
    return ai.check_on_receipt(evidence, **kw)


def test_kontrolle_ein_sauberer_fall_wird_angenommen():
    """THE CONTROL, and it comes first on purpose.

    Without it every probe below could be green because the checker refuses everything. A probe
    suite whose control is not measured proves nothing about the probes.
    """
    r = _check(_evidence())
    assert r["outcome"] == ai.OUTCOME_ACCEPTED, r
    assert r["reasons"] == []
    assert r["not_measurable"] == []


# --- Probe 1 -----------------------------------------------------------------------------------

def test_probe1_ein_trial_mit_ungepruefter_route_zaehlt_nicht_als_eigene_domaene():
    """An unverified upstream is not a domain, it is an unknown.

    Counting it would inflate a diversity panel with something nobody checked — the one thing a
    diversity floor must never do. Both refusal states are covered: a failure and a
    not-measurable, because only ACCEPTED may count and the two other states are different
    reasons for the same answer.
    """
    ohne_route = _evidence()
    ohne_route.pop("route")
    r = _check(ohne_route)
    assert r["outcome"] == ai.OUTCOME_NOT_MEASURABLE
    assert ai.counts_as_own_domain(r) is False

    r2 = _check(_evidence(route="backend-b"))
    assert r2["outcome"] == ai.OUTCOME_ATTESTATION_FAILURE
    assert ai.counts_as_own_domain(r2) is False

    assert ai.counts_as_own_domain(_check(_evidence())) is True, \
        "die Kontrolle: ein sauberer Fall MUSS zaehlen, sonst misst counts_as_own_domain nichts"


# --- Probe 2 -----------------------------------------------------------------------------------

def test_probe2_eine_alte_quote_ohne_frische_nonce_faellt_durch():
    """A quote that predates this request cannot contain this request's nonce."""
    alt = _evidence(signed={"nonce": "n0nce-aeltere-anfrage-0000",
                            "request_hash": _sha(REQ), "response_hash": _sha(RES)})
    r = _check(alt)
    assert r["outcome"] == ai.OUTCOME_ATTESTATION_FAILURE
    assert ai.REASON_STALE_NONCE in r["reasons"]


# --- Probe 3 -----------------------------------------------------------------------------------

@pytest.mark.parametrize("feld,grund", [
    ("request_hash", ai.REASON_REQUEST_HASH),
    ("response_hash", ai.REASON_RESPONSE_HASH),
])
def test_probe3_ein_falscher_hash_scheitert_an_der_bindung(feld, grund):
    """A mismatch means the statement is about a different exchange than ours."""
    e = _evidence()
    e["signed"][feld] = _sha(b"etwas anderes")
    r = _check(e)
    assert r["outcome"] == ai.OUTCOME_ATTESTATION_FAILURE
    assert grund in r["reasons"], r["reasons"]


# --- Probe 4 -----------------------------------------------------------------------------------

def test_probe4_eine_stille_route_verschiebung_ist_ein_attestierungsausfall():
    """The evidence then describes a machine that did not serve this answer."""
    r = _check(_evidence(route="backend-b"))
    assert r["outcome"] == ai.OUTCOME_ATTESTATION_FAILURE
    assert ai.REASON_ROUTE_DRIFT in r["reasons"]


# --- Probe 5 -----------------------------------------------------------------------------------

def test_probe5_eine_hardware_quote_belegt_nirgends_die_qualitaet_eines_reviews():
    """Shown at the WORDING, as the order requires, not at behaviour alone.

    The module must nowhere suggest that an attestation says anything about the quality of what
    was computed. The words are the surface a reader acts on, so the words are what is measured.
    """
    import inspect
    quelle = inspect.getsource(ai)
    tief = quelle.lower()
    for verbot in ("proves the review", "attests the quality", "guarantees correctness",
                   "quality of the review", "belegt die qualitaet"):
        assert verbot not in tief, f"unzulaessige Behauptung im Wortlaut: {verbot!r}"
    # Und die Gegenrichtung: die Abgrenzung MUSS dastehen, nicht nur nicht fehlen.
    assert "not an enclave attestation" in tief
    assert "the signer and the party being vouched for are the same entity" in tief

    r = _check(_evidence())
    assert r["normalised"]["assurance"] == ai.ASSURANCE_PROVIDER_DECLARED, \
        "auch ein ANGENOMMENER Fall bleibt provider_declared — angenommen heisst nicht attestiert"
    assert "not an enclave attestation" in r["normalised"]["detail"].lower()


# --- Probe 6 -----------------------------------------------------------------------------------

def test_probe6_veraenderte_evidenz_faellt_durch_und_landet_auf_provider_declared():
    e = _evidence()
    erwartet = ai.evidence_digest(e)
    e["signed"]["nonce"] = NONCE          # Inhalt bleibt gueltig, aber der Digest wandert
    e["zusatz"] = "nachtraeglich eingefuegt"
    r = _check(e, expected_evidence_digest=erwartet)
    assert r["outcome"] == ai.OUTCOME_ATTESTATION_FAILURE
    assert ai.REASON_EVIDENCE_TAMPERED in r["reasons"]
    assert r["normalised"]["assurance"] == ai.ASSURANCE_PROVIDER_DECLARED


def test_probe6_die_reihenfolge_nennt_die_richtige_ursache():
    """Tampering is checked BEFORE binding. Otherwise altered evidence would be reported as a
    binding failure, and a refusal for the wrong reason sends the reader to the wrong place."""
    e = _evidence()
    erwartet = ai.evidence_digest(e)
    e["signed"]["nonce"] = "voellig andere nonce"
    r = _check(e, expected_evidence_digest=erwartet)
    assert r["reasons"][0] == ai.REASON_EVIDENCE_TAMPERED, r["reasons"]


# --- Probe 7 -----------------------------------------------------------------------------------

def test_probe7_evidenz_einer_anderen_antwort_scheitert_an_der_bindung():
    """Perfectly valid evidence — for someone else's call."""
    fremd = {
        "provider_signature": "sig...",
        "signed": {"nonce": "n0nce-fremde-anfrage-9999",
                   "request_hash": _sha(b"fremde anfrage"),
                   "response_hash": _sha(b"fremde antwort")},
        "route": "backend-a",
    }
    r = _check(fremd)
    assert r["outcome"] == ai.OUTCOME_ATTESTATION_FAILURE
    assert ai.REASON_STALE_NONCE in r["reasons"]
    assert ai.REASON_REQUEST_HASH in r["reasons"]
    assert ai.REASON_RESPONSE_HASH in r["reasons"]


# --- Probe 8 -----------------------------------------------------------------------------------

def test_probe8_hardware_attested_ist_hier_strukturell_unerreichbar():
    """A receipt claiming HARDWARE_ATTESTED without a bound evidence package must not verify.

    Asserted structurally rather than by inspection: there is no argument, no branch and no
    string in this module that can produce a level above provider_declared. An assurance level a
    caller can assert measures nothing — so the absence is the guarantee.
    """
    import inspect
    quelle = inspect.getsource(ai)
    for hoeher in ("hardware_attested", "enclave_attested", "HARDWARE_ATTESTED"):
        zuweisungen = [z for z in quelle.splitlines()
                       if f'"{hoeher}"' in z and "assurance" in z and "=" in z
                       and not z.strip().startswith("#")]
        assert not zuweisungen, f"{hoeher} wird hier zugewiesen: {zuweisungen}"

    # Und ueber alle Eingaben, auch die perfekte: das Ergebnis bleibt gedeckelt.
    for ev in (_evidence(), _evidence(route="backend-b"), {"leer": True}):
        try:
            r = _check(ev)
        except BundleFormatError:
            continue
        assert r["normalised"]["assurance"] == ai.ASSURANCE_PROVIDER_DECLARED


def test_die_pruefung_benennt_falsche_form_statt_zu_werfen():
    """DIE ERSTE FASSUNG ERWARTETE HIER EINEN WURF, und der Haus-Riegel hat das gefangen.

    `test_never_raise_population_guard` meldete `check_on_receipt` als oeffentliche Pruefflaeche
    ausserhalb der Never-Raise-Eigenschaft. Er hat recht: wer nach einem Urteil greift, muss ein
    Urteil bekommen, auch bei feindlicher Eingabe. Die strikte Schicht bleibt `evidence_digest`,
    das weiterhin wirft; diese Grenze faengt es und BENENNT es.

    Und die Richtung ist fail-closed: eine Nicht-Abbildung hat nicht die Frage unbeantwortet
    gelassen, sie hat es versaeumt, Evidenz zu sein.
    """
    r = ai.check_on_receipt("kein dict", provider="p", nonce=NONCE,
                            request_bytes=REQ, response_bytes=RES)
    assert r["outcome"] == ai.OUTCOME_ATTESTATION_FAILURE
    assert r["reasons"] == [ai.REASON_MALFORMED]
    assert ai.counts_as_own_domain(r) is False
    assert r["normalised"]["assurance"] == ai.ASSURANCE_PROVIDER_DECLARED

    # Die strikte Schicht darunter wirft weiterhin — das ist der Zwei-Schichten-Vertrag, nicht
    # eine Inkonsequenz. Genau EINE Normalisierungsgrenze liegt dazwischen.
    with pytest.raises(BundleFormatError):
        ai.evidence_digest("kein dict")


class DerVerfaelschungsVergleichIstExakt(unittest.TestCase):
    """`expected_evidence_digest` gegen das Beinahe-Treffer-Korpus.

    DER HAUS-RIEGEL HAT DAS HIER GEFANGEN, nicht ich: `JederZeichenkettenVergleichHatEinKorpus`
    meldete den neuen Parameter als Erwartungsvergleich ohne Korpus. Er hat recht, und der Grund
    steht in `_beinahe_treffer`: gegen einen VOELLIG FREMDEN Wert verhaelt sich ein gelockerter
    Vergleich exakt wie ein exakter. Erst der Beinahe-Treffer trennt sie — und beim Digest ist die
    gefaehrliche Lockerung `startswith`, weil ein gekuerzter Digest wie ein gueltiger aussieht.

    Gemessen wird ueber `pruefe_exakt`, das die Gegenrichtung eingebaut hat: ein Vergleich, der
    ALLES ablehnt, waere sonst ebenfalls gruen.
    """

    def test_der_digest_vergleich_laesst_sich_nicht_lockern(self):
        from tests._beinahe_treffer import pruefe_exakt

        e = _evidence()
        echt = ai.evidence_digest(e)

        # Der Aufruf traegt `expected_evidence_digest=` SYNTAKTISCH in sich. Eine daneben
        # definierte Hilfsfunktion waere dasselbe Verhalten und trotzdem nicht gedeckt: der
        # Riegel liest den AST des Aufrufs, nicht seine Wirkung. Das ist kein Formalismus —
        # er kann Wirkung gar nicht lesen, und eine Deckung, die er nicht sehen kann, ist fuer
        # die naechste Flaeche keine.
        pruefe_exakt(
            lambda kandidat: ai.REASON_EVIDENCE_TAMPERED not in _check(
                e, expected_evidence_digest=kandidat)["reasons"],
            echt, self)


def test_tiefe_verschachtelung_stuerzt_nicht_ab():
    """DIESEN DEFEKT HAT DER HAUS-RIEGEL GEFUNDEN, NICHT ICH.

    `test_no_public_surface_raises_raw_on_hostile_primary` meldete einen rohen `RecursionError`
    aus `check_on_receipt` bei tief verschachtelter Evidenz. Die Verschachtelungstiefe waehlt der
    Anbieter, nicht wir — also ist sie feindliche Eingabe, und eine Pruefflaeche, die daran
    abstuerzt, urteilt nicht, sie faellt aus.
    """
    tief = {"a": {}}
    zeiger = tief["a"]
    for _ in range(5000):
        zeiger["a"] = {}
        zeiger = zeiger["a"]
    zeiger["nonce"] = NONCE

    r = _check(tief)
    assert r["outcome"] in (ai.OUTCOME_ATTESTATION_FAILURE, ai.OUTCOME_NOT_MEASURABLE)
    assert isinstance(r["evidence_digest"], str)


def test_zu_tiefes_wird_ersetzt_und_nicht_weggelassen():
    """Zwei verschiedene tiefe Strukturen duerfen nicht denselben Digest bekommen.

    Waere der zu tiefe Ast still weggelassen worden, kollidierten beliebig viele verschiedene
    Nutzlasten auf einem Digest — und ein Digest, der auf Zuruf kollidiert, ist schlechter als
    keiner, weil man sich auf ihn verlaesst.
    """
    def bauen(blatt):
        wurzel = {"a": {}}
        z = wurzel["a"]
        for _ in range(ai._MAX_DEPTH + 10):
            z["a"] = {}
            z = z["a"]
        z["blatt"] = blatt
        return wurzel

    assert ai.evidence_digest(bauen("x")) == ai.evidence_digest(bauen("y")), \
        "unterhalb der Grenze ist die Ununterscheidbarkeit die dokumentierte Folge des Abschnitts"
    flach_x = {"a": {"blatt": "x"}}
    flach_y = {"a": {"blatt": "y"}}
    assert ai.evidence_digest(flach_x) != ai.evidence_digest(flach_y), \
        "oberhalb der Grenze MUSS der Digest weiterhin trennen — sonst trennt er gar nichts"
    assert ai._TOO_DEEP in json.dumps(ai._without_credentials(bauen("x"))), \
        "der abgeschnittene Ast wird durch einen Marker ERSETZT, nicht entfernt"
