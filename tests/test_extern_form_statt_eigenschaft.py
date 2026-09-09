"""Erwartung am Kopf 8626618: GRUEN.

Die Tests binden an geschlossene Eigenschaften: Jede nicht zulaessige Form wird
fail-closed behandelt, jede budgetierte Strukturachse gilt fuer Schluessel und
Werte, und eine akzeptierte Drahtform hat kein ueberzaehliges C2SP-Padding.
Sie nennen die historischen Fundstellen nicht als Testoracle.
"""
from __future__ import annotations

import pytest

from proofbundle._strict_json import enforce_structural_budget
from proofbundle._wire_b64 import decode_b64_c2sp
from proofbundle.budget import BudgetExceeded, VerificationBudget
from proofbundle.errors import BundleFormatError
from proofbundle.relation import LINEAGE_FAIL, verify_relationship_edges
from proofbundle.relation_statement import validate_relation_statement_predicate


@pytest.mark.parametrize("not_an_array", [None, {}, "edge", 7, True])
def test_required_edge_collection_rejects_every_non_array_form(not_an_array):
    predicate = {
        "schemaVersion": "0.1.0",
        "statementId": "external-property-test",
        "relationships": not_an_array,
    }
    assert validate_relation_statement_predicate(predicate)


@pytest.mark.parametrize(
    ("key", "achse"),
    [(b"xxx", "string_len"), (("x", "y", "z"), "json_nodes"),
     (frozenset({"x", "y", "z"}), "json_nodes")],
    ids=["bytes", "tuple", "frozenset"],
)
def test_structural_budget_applies_to_mapping_keys_as_well_as_values(key, achse):
    """Die Latte greift am SCHLUESSEL, und zwar auf der GENANNTEN Achse.

    NACHGESCHAERFT VON DER JURY (un_echoXX, 09.09.2026). Die eingereichte Fassung prueft nur,
    DASS `BudgetExceeded` fliegt, nicht WORAN. Damit bliebe sie gruen, wenn ein Schluessel aus
    einem unbeteiligten Grund abgewiesen wuerde — eine Bindung, die weniger anfasst als der
    Satz behauptet, den sie belegt.

    Gegenprobe zur Trennschaerfe, gemessen am Kopf 7621f69: ein gewoehnlicher `str`-Schluessel
    derselben Laenge (`{"ab": None}`) wirft unter genau dieser Latte NICHTS. Der Wurf kommt also
    von der Beschaffenheit des Schluessels, nicht von der Knotenzahl des Behaelters — sonst
    haette die leere Abbildung schon geworfen.
    """
    budget = VerificationBudget(json_nodes=2, string_len=2)
    with pytest.raises(BudgetExceeded) as gefangen:
        enforce_structural_budget({key: None}, budget=budget)
    assert gefangen.value.dimension == achse
    # Die Trennschaerfe selbst, im Test und nicht nur im Kommentar: ein str-Schluessel derselben
    # Laenge passiert. Ohne diese Zeile belegt der Fall nicht, dass der SCHLUESSEL die Ursache ist.
    enforce_structural_budget({"ab": None}, budget=budget)


def test_structural_walk_rejects_an_unclassified_value_instead_of_skipping_it():
    with pytest.raises(BundleFormatError, match="not a JSON value"):
        enforce_structural_budget({"value": object()})


def test_malformed_attached_neighbor_cannot_resolve_an_edge():
    digest = "a" * 64
    edge = {"relation": "derivedFrom", "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": digest}}
    related = {digest: {"verified": True, "relationships": {"not": "an array"}}}
    result = verify_relationship_edges([edge], related)
    assert result["lineage"] == LINEAGE_FAIL
    assert result["edges"][0]["resolution"] == LINEAGE_FAIL


@pytest.mark.parametrize("wire", ["QUI==", "QUJD=", "QUJD=="])
def test_c2sp_decoder_rejects_all_surplus_padding(wire):
    with pytest.raises(ValueError):
        decode_b64_c2sp(wire)
