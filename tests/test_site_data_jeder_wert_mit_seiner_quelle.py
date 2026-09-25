#!/usr/bin/env python3
"""site-data.json: every value with its source, every gap with its reason.

The three required cases: a missing source yields not_measurable, a tampered receipt yields failed,
and the file is byte-stable while its sources do not change.

THE FOURTH CASE IS HERE BECAUSE IT WAS MISSING. While building the generator the call was
`verify_ed25519(pubkey, message, signature)` instead of `(pubkey, signature, message)`. The call
succeeded, returned a bool, and the bool was wrong: ALL FOUR genuine release receipts reported that
their ed25519 signature does not hold, and that would have gone onto a public page as an accusation.
It showed only because four independently produced receipts failed identically; one alone might have
looked like a real finding.

`test_eine_echte_quittung_gilt_als_passed` is the case that would have shown it at once. It stands
BEFORE the tampering case, because a check that refuses everything passes the tampering case as well
- and then the tampering case proves nothing.

THREE STATES, NEVER TWO, and that is this file's load-bearing promise: `passed`, `failed`,
`nicht_pruefbar`. `failed` means checked and failed. Writing it for an artefact kind touched with
the wrong tool is an accusation without a measurement.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _erzeuger():
    s = importlib.util.spec_from_file_location("_rsd", REPO / "scripts" / "render_site_data.py")
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


RSD = _erzeuger()

ECHTE_QUITTUNG = REPO / "audit_artifacts" / "610" / "pre_tag_receipt_v6.1.0.json"


def _quittung() -> dict:
    return json.loads(ECHTE_QUITTUNG.read_text(encoding="utf-8"))


class TestDieQuittungWirdMitIHREMPrueferGeprueft:

    @pytest.mark.skipif(not ECHTE_QUITTUNG.is_file(), reason="keine echte Quittung im Baum")
    def test_eine_echte_quittung_gilt_als_passed(self):
        # THE CASE THAT WOULD HAVE SHOWN THE SWAPPED ARGUMENT AT ONCE. Without it the tampering
        # case passes even when the check refuses EVERYTHING, and then it proves nothing.
        e = RSD._check_receipt(_quittung())
        assert e["state"] == "passed", (
            "a genuine signed release receipt does not count as passed. First suspicion: the "
            "argument order of verify_ed25519 is (pubkey, signature, message). "
            f"Result: {e}")
        assert "signatur_durch_vertrauten_schluessel" in e["checked"]
        assert "audit_exit_code_0" in e["checked"]

    @pytest.mark.skipif(not ECHTE_QUITTUNG.is_file(), reason="keine echte Quittung im Baum")
    def test_eine_manipulierte_quittung_ergibt_failed(self):
        d = _quittung()
        # ONE character in a SIGNED field. This is the required case: a tampered receipt yields
        # failed.
        d["subject_tree_digest"] = "0" * len(str(d.get("subject_tree_digest") or "0"))
        e = RSD._check_receipt(d)
        assert e["state"] == "failed", f"a tampered receipt passed: {e}"
        assert "Signatur" in e["reason"], e

    @pytest.mark.skipif(not ECHTE_QUITTUNG.is_file(), reason="keine echte Quittung im Baum")
    def test_ein_fehlgeschlagener_audit_ergibt_failed_auch_mit_gueltiger_signatur(self):
        # A validly signed receipt about a FAILED run is not evidence. The signature says that
        # someone attested it, not that it went well.
        d = _quittung()
        d["audit_exit_code"] = 1
        e = RSD._check_receipt(d)
        assert e["state"] == "failed", f"a failed audit passed: {e}"
        # The reason names either the exit code or the signature broken by changing it; both are
        # an honest failed, but it must not be passed.
        assert "audit_exit_code" in e["reason"] or "Signatur" in e["reason"], e

    def test_eine_fremde_artefaktart_ist_NICHT_PRUEFBAR_und_nicht_failed(self):
        # THE DIFFERENCE THAT MADE THE FIRST DRAFT WRONG: the bundle verifier on a pre-tag
        # receipt produced no check names and the code wrote `failed`. `failed` is an accusation;
        # for a kind with no declared checker, `nicht_pruefbar` belongs there.
        for fremd in ({"schema": "b7n0de.etwas_anderes.v1"}, {}, {"schema": None}):
            e = RSD._check_receipt(fremd)
            assert e["state"] == "not_checkable", f"{fremd} yielded {e['state']!r}"
            assert e["state"] != "failed"
            assert "reason" in e and e["reason"]

    @pytest.mark.skipif(not ECHTE_QUITTUNG.is_file(), reason="keine echte Quittung im Baum")
    def test_die_baumbindung_wird_als_nicht_gepruefbar_benannt_und_nicht_behauptet(self):
        # An honest limit: verify_receipt requires the EXPECTED tree digest, and holding a
        # historical receipt against TODAY's tree would have to fail. It therefore stands as not
        # checkable instead of missing or counting as checked.
        e = RSD._check_receipt(_quittung())
        assert e.get("tree_binding") == "nicht_gepruefbar_ohne_auscheckung_am_tag", e
        assert "baumbindung" not in (e.get("checked") or [])


class TestEineFehlendeQuelleErgibtNichtMessbar:

    def test_interop_ohne_datei_ist_nicht_messbar_mit_grund(self):
        # `docs/interop_status.json` is not in this tree. The field must NOT appear as an empty
        # list: 0, an empty list and a last-known value are all forbidden, and all three share one
        # property, they read like a measurement.
        d = RSD.interop()
        if (REPO / "docs" / "interop_status.json").is_file():
            pytest.skip("the curated list now exists - this case tests its absence")
        assert d.get("not_measurable") is True, d
        assert d.get("reason"), "a gap without a reason is a gap that looks like a value"
        assert "value" not in d, "a gap must not carry a value"

    def test_die_luecke_traegt_nie_null_oder_eine_leere_liste(self):
        luecke = RSD._gap(source="x", reason="y")
        assert luecke.get("value", "FEHLT") == "FEHLT"
        assert luecke["not_measurable"] is True and luecke["reason"] == "y"

    def test_scorecard_ohne_netz_ist_nicht_messbar_mit_genau_diesem_grund(self):
        d = RSD.scorecard(network=False)
        assert d.get("not_measurable") is True
        assert "not asked" in d["reason"], d
        assert d.get("stable") is False, "a network field is never marked stable"


class TestByteStabilUeberDieBaumFelder:
    """The promise holds for the fields from the TREE and explicitly not for those from the network.

    Asserting it over everything would give a test that is red on every second run and therefore
    gets switched off. A network field has no source time in the tree; its measurement time IS the
    run time.
    """

    def test_zwei_laeufe_ohne_quellenaenderung_geben_dieselben_baum_felder(self):
        a = RSD.tree_fields(RSD.build(network=False, check=False))
        b = RSD.tree_fields(RSD.build(network=False, check=False))
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True), (
            "two runs without a source change gave different tree fields - somewhere a run time "
            "stands where a source time should")

    def test_ein_netzfeld_ist_ausdruecklich_nicht_teil_der_zusage(self):
        d = RSD.build(network=False, check=False)
        assert d["scorecard"].get("stable") is False
        assert "scorecard" not in RSD.tree_fields(d), (
            "the network field is inside the stability promise, which makes it unkeepable")

    def test_eine_geaenderte_quelle_aendert_das_feld(self, tmp_path, monkeypatch):
        # COUNTER-CONTROL: without it a generator that ALWAYS writes the same would pass the
        # stability test. Measured on the counting rule that stands as data next to the number: if
        # it changes, the field has to change.
        vorher = RSD.test_surface()["tests_functions"]
        monkeypatch.setattr(RSD, "_TEST_COUNTING_RULE", "a different rule")
        nachher = RSD.test_surface()["tests_functions"]
        assert vorher != nachher, "a changed counting rule left the field unchanged"


class TestJederWertNenntSeineQuelleUndSeineMesszeit:

    def test_jedes_feld_traegt_quelle_und_gemessen_am(self):
        d = RSD.build(network=False, check=False)
        felder = {k: v for k, v in d.items() if isinstance(v, dict) and "stable" in v}
        assert felder, "the generator produced not a single field"
        for k, v in felder.items():
            assert v.get("source"), f"{k} names no source"
            if v.get("not_measurable"):
                assert v.get("measured_at") is None, f"{k} is not measurable and carries a time"
                assert v.get("reason"), f"{k} is not measurable without a reason"
            else:
                assert "value" in v, f"{k} carries no value"

    def test_der_erklaerungsblock_zaehlt_NICHT_als_gemessenes_feld(self):
        # MEASURED ON THE FIRST RUN: the block used the same keys as the data fields
        # (`messzeit`, `stabil`, `nicht_messbar`), and the gap loop took it for a field without a
        # reason - KeyError. Fixed at the COLLISION, not with a special case.
        d = RSD.build(network=False, check=False)
        lesart = d["how_to_read"]
        assert "stable" not in lesart and "not_measurable" not in lesart, (
            "the explanation block carries data-field names again and is counted as a field: "
            f"{sorted(lesart)}")
        assert all(k.endswith("_means") for k in lesart), sorted(lesart)
        assert "lesart" not in RSD.tree_fields(d)

    def test_checks_nennt_das_buendel_an_dem_gemessen_wurde(self):
        # A number without its object is the very constant this avoids, only by a detour.
        # Measured on an envelope bundle it is TWO and not three.
        d = RSD.verifier_checks()
        if d.get("not_measurable"):
            assert d.get("reason")
            return
        assert "bundle.json" in d["source"], d["source"]
        assert d.get("checks_measured"), "the number stands without the list it came from"
        assert d["value"] == len(d["checks_measured"])

    def test_die_testzahl_traegt_ihre_zaehlregel(self):
        d = RSD.test_surface()
        for k in ("tests_files", "tests_functions"):
            if d[k].get("not_measurable"):
                continue
            assert d[k].get("counting_rule"), f"{k} names no counting rule, so the number is bare"
            assert "def test_" in d[k]["counting_rule"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
