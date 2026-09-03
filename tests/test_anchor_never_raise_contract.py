"""Die totale Grenze `verify_anchor` laesst keine rohe Ausnahme aus fremdem Verifier-Ergebnis.

ANLASS (2026-09-03, Phase 2 des Zweischicht-Vertrags, Schritte 2 und 6). Am Stand 621b049 stand der
Verifier-Aufruf im `try`, aber `res.get(...)` DAHINTER. Ausfuehrbar belegt: ein registrierter
Verifier mit `return None` liess `AttributeError: 'NoneType' object has no attribute 'get'` aus
`verify_anchor` austreten.

Invariante I1 des Reviews verbietet das: kein roher Fehler aus einer totalen Verify-Grenze. Der
Plugin-Vertrag in docs/ANCHORS.md verlangt vom Fremdverifier ein Mapping mit {"ok", "detail"} —
wer das nicht liefert, ist selbst der Defekt, aber ein Plugin-Defekt darf die Grenze nicht
durchbrechen.

DAZU I3: `MappingProxyType` MUSS als `frozen` akzeptiert werden. Der vorherige
`isinstance(_frozen, dict)` verwarf ihn STILL auf `{}` — gemessen ist MappingProxyType nicht
isinstance(dict), aber sehr wohl isinstance(Mapping). Ein read-only frozen-Block waere also nie
beim Verifier angekommen, und zwar ohne jede Meldung.
"""
from __future__ import annotations

import base64
import hashlib
from collections import OrderedDict
from types import MappingProxyType

import pytest

from proofbundle import anchors

ROOT = hashlib.sha256(b"never-raise-contract").digest()


def _anker(typ: str, **extra) -> dict:
    a = {"type": typ, "target": "receipt",
         "canonicalRoot": base64.b64encode(ROOT).decode(),
         "proof": base64.b64encode(b"proof").decode()}
    a.update(extra)
    return a


def _verify(a: dict) -> dict:
    return anchors.verify_anchor(a, target_roots={"receipt": ROOT}, now=None, rp_trust=None)


@pytest.mark.parametrize("rueckgabe,name", [
    (None, "None"), ([], "list"), (42, "int"), ("ok", "str"), (object(), "object"),
])
def test_ein_verifier_mit_falscher_rueckgabeform_bricht_die_grenze_nicht(rueckgabe, name, request):
    """Kein roher Fehler, sondern ein strukturiertes FAIL, dessen Grund die FORM benennt."""
    typ = f"formtest-{request.node.callspec.id}"
    anchors.register_anchor_type(typ, lambda p, c, *, frozen, now, _r=rueckgabe: _r)
    r = _verify(_anker(typ))
    assert r["ok"] is False, r
    assert "non-mapping" in r["detail"], (
        f"der Grund muss die FORM benennen, nicht schlechte Evidenz suggerieren: {r['detail']!r}"
    )
    assert name.lower() in r["detail"].lower() or type(rueckgabe).__name__ in r["detail"], r["detail"]


def test_ein_werfender_verifier_bleibt_gefangen():
    """Die bestehende Zusage darf durch den neuen Zweig nicht verloren gehen."""
    def wirft(p, c, *, frozen, now):
        raise RuntimeError("kaputt")
    anchors.register_anchor_type("werfer-testtyp", wirft)
    r = _verify(_anker("werfer-testtyp"))
    assert r["ok"] is False and "fail-closed" in r["detail"], r


def test_ein_gueltiges_mapping_geht_weiterhin_durch():
    """Gegenrichtung: die Formpruefung darf gueltige Ergebnisse nicht abweisen."""
    anchors.register_anchor_type("gut-testtyp", lambda p, c, *, frozen, now: {"ok": True, "detail": "verifiziert"})
    r = _verify(_anker("gut-testtyp"))
    assert r["ok"] is True and r["detail"] == "verifiziert", r


@pytest.mark.parametrize("bauer,name", [
    (lambda: {"quelle": "tsa"}, "dict"),
    (lambda: OrderedDict(quelle="tsa"), "OrderedDict"),
    (lambda: MappingProxyType({"quelle": "tsa"}), "MappingProxyType"),
])
def test_I3_jeder_Mapping_typ_erreicht_den_verifier(bauer, name):
    """I3 woertlich: Mapping statt konkretem dict, MappingProxyType und OrderedDict werden
    akzeptiert. Vorher fiel genau MappingProxyType still auf {}."""
    gesehen: dict = {}

    def merkt(p, c, *, frozen, now):
        gesehen["frozen"] = dict(frozen)
        return {"ok": True, "detail": "x"}

    typ = f"frozentest-{name}"
    anchors.register_anchor_type(typ, merkt)
    _verify(_anker(typ, frozen=bauer()))
    assert gesehen.get("frozen") == {"quelle": "tsa"}, (
        f"{name}: der frozen-Block kam beim Verifier nicht an — er wurde still verworfen"
    )


@pytest.mark.parametrize("wert", [None, "text", ["a"], 7])
def test_ein_NICHT_mapping_frozen_wird_weiterhin_auf_leer_normalisiert(wert):
    """Gegenrichtung zu I3: die Oeffnung auf Mapping darf keinen falschen Typ durchlassen. Ein
    Verifier soll nie ein str oder eine Liste als frozen sehen."""
    gesehen: dict = {}

    def merkt(p, c, *, frozen, now):
        gesehen["frozen"] = frozen
        return {"ok": True, "detail": "x"}

    typ = f"frozenbad-{type(wert).__name__}"
    anchors.register_anchor_type(typ, merkt)
    _verify(_anker(typ, frozen=wert))
    assert gesehen.get("frozen") == {}, f"{wert!r} haette auf {{}} normalisiert werden muessen"


# ---------------------------------------------------------------------------
# Schritt 7 der zwoelf: outcome_class und reason_code additiv, nach Abschnitt 8 des Reviews.
#
# Die Fallzuordnung dort ist bindend und unterscheidet ausdruecklich zwei Dinge, die sich leicht
# verwechseln lassen: ein `BundleFormatError` aus dem Verifier ist eine Aussage ueber die EVIDENZ
# (sie hat die falsche Form), ein unerwarteter RuntimeError ist ein DEFEKT. Wer beides gleich
# fuehrt, gibt entweder einen Evidenzmangel als Hausfehler aus oder verdeckt einen echten Defekt.
# ---------------------------------------------------------------------------
from proofbundle.errors import BundleFormatError  # noqa: E402


@pytest.mark.parametrize("rueckgabe", [None, [], 42])
def test_falsche_rueckgabeform_ist_internal_error(rueckgabe):
    """Abschnitt 8: Verifier gibt None / Liste zurueck -> ok=false, internal_error."""
    typ = f"klasse-form-{type(rueckgabe).__name__}"
    anchors.register_anchor_type(typ, lambda p, c, *, frozen, now, _r=rueckgabe: _r)
    r = _verify(_anker(typ))
    assert r["ok"] is False and r.get("outcome_class") == "internal_error", r
    assert str(r.get("reason_code", "")).startswith("anchor.verifier."), r


def test_mapping_ohne_ok_feld_ist_internal_error():
    """Abschnitt 8: 'Verifier Mapping ohne ok' -> internal_error. Ein Mapping ohne das eine
    Pflichtfeld ist kein schlechtes Ergebnis, sondern ein Plugin, das den Vertrag nicht haelt."""
    anchors.register_anchor_type("klasse-ohne-ok", lambda p, c, *, frozen, now: {"detail": "x"})
    r = _verify(_anker("klasse-ohne-ok"))
    assert r["ok"] is False and r.get("outcome_class") == "internal_error", r
    assert r.get("reason_code") == "anchor.verifier.result_missing_ok", r


def test_ein_BundleFormatError_ist_malformed_evidence_und_NICHT_internal_error():
    """Die Unterscheidung, auf der Abschnitt 8 besteht. Waeren beide gleich, waere der Riegel
    wirkungslos — deshalb steht hier BEIDES: die Klasse muss malformed_evidence sein UND darf
    nicht internal_error sein."""
    def wirft(p, c, *, frozen, now):
        raise BundleFormatError("frozen block has the wrong shape")
    anchors.register_anchor_type("klasse-malformed", wirft)
    r = _verify(_anker("klasse-malformed"))
    assert r["ok"] is False, r
    assert r.get("outcome_class") == "malformed_evidence", r
    assert r.get("outcome_class") != "internal_error", r


def test_ein_unerwarteter_fehler_ist_internal_error_und_leakt_keinen_bibliothekstext():
    """Abschnitt 7.5: kein ungefilterter Exception-Text im aeusseren Verdict. Bibliotheksfehler
    koennen Pfade und Zertifikatsdetails tragen."""
    geheim = "/home/geheim/pfad/zertifikat.pem"

    def wirft(p, c, *, frozen, now):
        raise RuntimeError(f"kaputt bei {geheim}")

    anchors.register_anchor_type("klasse-intern", wirft)
    r = _verify(_anker("klasse-intern"))
    assert r["ok"] is False and r.get("outcome_class") == "internal_error", r
    assert geheim not in r["detail"], f"der Bibliothekstext steht im Verdict: {r['detail']!r}"
    assert "RuntimeError" in r["detail"], "der Typ darf und soll drinstehen"


def test_ein_gueltiges_ergebnis_bekommt_KEINE_fehlerklasse():
    """Gegenrichtung: die additiven Felder duerfen einen Erfolg nicht markieren."""
    anchors.register_anchor_type("klasse-gut", lambda p, c, *, frozen, now: {"ok": True, "detail": "ok"})
    r = _verify(_anker("klasse-gut"))
    assert r["ok"] is True, r
    assert r.get("outcome_class") in (None, "verified"), r


def test_ein_registriertes_pseudo_mapping_ohne_get_wird_abgewiesen():
    """`Mapping.register(cls)` macht isinstance wahr, ohne die Mixin-Methoden zu liefern. Ein reiner
    isinstance-Guard laesst so ein Objekt durch, und erst der Verifier stuerzt beim .get(...).

    Die Klasse war in anchors_rfc3161 und anchors_ots bereits gefixt (Deep-Gate iter9) und stand
    hier noch offen — gefunden beim Lesen der Nachbardatei, nicht durch einen Fehlschlag."""
    from collections.abc import Mapping as _M

    class PseudoMapping:
        pass

    _M.register(PseudoMapping)
    assert isinstance(PseudoMapping(), _M), "die Falle setzt voraus, dass isinstance hier True ist"

    gesehen: dict = {}

    def merkt(p, c, *, frozen, now):
        gesehen["frozen"] = frozen
        return {"ok": True, "detail": "x"}

    anchors.register_anchor_type("pseudo-mapping-testtyp", merkt)
    _verify(_anker("pseudo-mapping-testtyp", frozen=PseudoMapping()))
    assert gesehen.get("frozen") == {}, (
        "ein Mapping ohne aufrufbares .get muss auf {} normalisiert werden, sonst stuerzt der Verifier"
    )


# ---------------------------------------------------------------------------
# Schritte 3-5: der RFC-3161-Kern meldete JEDEN Fehler als `chain_fail` mit dem Text "did not
# verify against the relying-party TSA root". Fuer ein fehlendes Extra und fuer ein malformed
# Policy-OID ist dieser Satz FALSCH und schickt den Leser in die Evidenz, wo nichts zu finden ist.
#
# WARUM DIESE TESTS EIN SKIP-TOR HABEN, und warum das kein Feigenblatt ist: ohne das Extra
# `[anchors]` kehrt verify_rfc3161 an der Import-Wache um und erreicht den geaenderten Block NIE.
# Die erste Fassung dieser Tests lief deshalb GRUEN, ohne irgendetwas zu pruefen — ein Gate-Meta-Lauf
# zeigte es: beide eingepflanzten Defekte ueberlebten mit 24 passed. Die Datei selbst warnt woertlich
# davor ("the probe is green for a reason that has nothing to do with the defence it names").
#
# Ein SKIP sagt ehrlich "hier nicht gemessen". Ein stilles Bestehen behauptet das Gegenteil.
# ---------------------------------------------------------------------------
def _anchors_extra_da() -> bool:
    try:
        import rfc3161_client  # noqa: F401, PLC0415
    except ImportError:
        return False
    return True


_OHNE_EXTRA = pytest.mark.skipif(
    not _anchors_extra_da(),
    reason="proofbundle[anchors] (rfc3161-client) fehlt — verify_rfc3161 kehrt an der Import-Wache "
           "um und erreicht den geprueften Block nicht. NICHT GEMESSEN, nicht bestanden.")


def test_die_import_wache_wird_als_solche_erkannt():
    """Gegenprobe zum Skip-Tor: wenn das Extra fehlt, MUSS die Antwort die Import-Wache sein und
    nicht etwa ein Verdict, das wie eine Messung aussieht. Ohne diesen Test koennte das Tor
    stillschweigend am falschen Grund haengen."""
    from proofbundle import anchors_rfc3161 as a3

    r = a3.verify_rfc3161(b"x", hashlib.sha256(b"x").digest(),
                          frozen={"rootCertsDerB64": ["x"]}, rp_trust={"trusted_tsa_roots": ["x"]})
    if _anchors_extra_da():
        assert "needs proofbundle[anchors]" not in r["detail"], (
            "das Extra ist da, aber die Antwort ist trotzdem die Import-Wache")
    else:
        assert "needs proofbundle[anchors]" in r["detail"], (
            f"ohne Extra muss die Import-Wache antworten, bekommen: {r['detail']!r}")


@_OHNE_EXTRA
def test_rfc3161_ein_kaputtes_zertifikat_ist_invalid_evidence_und_KEIN_oid_problem():
    """Der Fall, den mein eigener Test gefunden hat, und er ging gegen meine eigene Aenderung.

    Die erste Fassung fing `ValueError` um den GANZEN Kryptoblock und meldete ihn als "die
    gepinnte TSA policy OID ist ungueltig". Gemessen kommt der ValueError hier aber aus dem
    ZERTIFIKATSLADEN — eine Ursache, die der Text erfindet. Genau die Klasse, die dieser Auftrag
    schliessen soll: ein Sammelzweig, dessen Begruendung eine bestimmte Ursache BEHAUPTET.

    Der OID-Parse hat jetzt seinen eigenen, engen Schutz."""
    from proofbundle import anchors_rfc3161 as a3

    r = a3.verify_rfc3161(b"kaputt", hashlib.sha256(b"cert-test").digest(),
                          frozen={"rootCertsDerB64": ["kein-zertifikat"]},
                          rp_trust={"trusted_tsa_roots": ["kein-zertifikat"]})
    assert r["ok"] is False, r
    assert r.get("outcome_class") == "invalid_evidence", r
    assert "policy OID" not in r["detail"], (
        f"ein Zertifikatsfehler darf nicht als OID-Problem erscheinen: {r['detail']!r}")


@_OHNE_EXTRA
def test_rfc3161_verdicts_tragen_keinen_rohen_bibliothekstext():
    """7.5: Bibliotheks-Exceptions koennen Pfade und Zertifikatsdetails tragen. Geprueft wird die
    EIGENSCHAFT (nur der Exception-TYP steht im Verdict), nicht die Abwesenheit eines zufaellig
    gewaehlten Musters — die erste Fassung suchte nach "/home/" und haette jeden anderen Leak
    durchgelassen."""
    from proofbundle import anchors_rfc3161 as a3

    r = a3.verify_rfc3161(b"kaputt", hashlib.sha256(b"leak-test").digest(),
                          frozen={"rootCertsDerB64": ["x"]}, rp_trust={"trusted_tsa_roots": ["x"]})
    assert r["ok"] is False and r.get("outcome_class") == "invalid_evidence", r
    schwanz = r["detail"].rsplit("(", 1)[-1].rstrip(")")
    assert schwanz.isidentifier(), (
        f"im Verdict steht mehr als der Exception-Typ: {r['detail']!r}")


# NICHT GEMESSEN, und das gehoert hierher statt in eine Fussnote: der enge OID-Zweig
# (rfc3161.rp_policy_oid_malformed / rfc3161.frozen_policy_oid_malformed) wird von KEINEM Test
# dieser Datei erreicht. Grund, gemessen: das Zertifikatsladen scheitert vorher, und ein Testfall,
# der bis zum OID-Parse kommt, braucht ein ECHT ladbares DER-Wurzelzertifikat. Das zu bauen ist
# moeglich, war aber nicht Teil dieser Runde. Der Zweig ist also GESCHRIEBEN und BEGRUENDET, aber
# NICHT durch einen Muss-Fehlschlag belegt — wer ihn aendert, merkt es hier nicht.


def test_die_klasse_folgt_der_HERKUNFT_nicht_dem_ausnahmetyp():
    """Beide Faelle werfen denselben BundleFormatError — die Klasse muss trotzdem verschieden sein.

    Ein Gate-Meta-Lauf deckte auf, dass mein erster Test das nicht band: er prueste nur `frozen`,
    und eine Mutation, die BEIDE Faelle auf malformed_evidence legt, ueberlebte. `frozen` ist
    Material des PRODUZENTEN (Evidenz), `rp_trust` kommt von der verlassenden Seite
    (Konfiguration). Sie gleichzusetzen gaebe einen Konfigurationsfehler der lesenden Seite als
    Evidenzmangel des Produzenten aus — und umgekehrt."""
    from proofbundle import anchors_rfc3161 as a3

    r_frozen = a3.verify_rfc3161(b"p", b"\x00" * 32, frozen=None, rp_trust={})
    r_rp = a3.verify_rfc3161(b"p", b"\x00" * 32, frozen={}, rp_trust=123)
    assert r_frozen.get("outcome_class") == "malformed_evidence", r_frozen
    assert r_rp.get("outcome_class") == "invalid_configuration", r_rp
    assert r_frozen["outcome_class"] != r_rp["outcome_class"], (
        "die beiden Herkuenfte duerfen nie dieselbe Klasse ergeben — sonst ordnet die Klasse nichts"
    )
    assert r_frozen.get("reason_code") != r_rp.get("reason_code"), (r_frozen, r_rp)
