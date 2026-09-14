"""L4-600-02 (deep gate Lauf 7, P1): `reject_superseded` war auf der relation-statement-Flaeche
fuer den ANGEHAENGTEN Fall wirkungslos — Python endete mit 0, wo der unabhaengige Rust-Verifizierer
mit 3 endet.

DIE KLASSE, nicht die Instanz. `supersededByAttached` fuellten die AUFRUFER: decision.py und
outcome.py taten es, relation_statement.py nicht. Der Arm in `evaluate_relations_policy` liest
genau diesen Schluessel. Eine Pflicht, die an der Disziplin des Aufrufers haengt, wird irgendwann
vergessen — hier war es der dritte von drei. Der Fix setzt den Schluessel in
`verify_relationship_edges`, also in der EINEN Funktion, die jeder Aufrufer ohnehin benutzt;
danach KANN ihn keiner mehr auslassen.

Die Faelle unten pruefen beide Ebenen: die Eigenschaft der gemeinsamen Funktion (jeder
Rueckgabepfad traegt den Schluessel) UND die Wirkung auf der Flaeche, auf der sie fehlte.
"""
from __future__ import annotations

import base64
import json
import pathlib
import unittest

from proofbundle import anchors, dsse
from proofbundle.decision import emit_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.relation import verify_relationship_edges
from proofbundle.relation_statement import emit_relation_statement, verify_relation_statement

EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"
BASE = json.loads((EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))

_A, _B = "a" * 64, "b" * 64


def _edge(hexd: str, relation: str) -> dict:
    return {"relation": relation,
            "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": hexd}}


class TestSchluesselAufJedemRueckgabepfad(unittest.TestCase):
    """Die EIGENSCHAFT: jeder Rueckgabepfad von verify_relationship_edges traegt den Schluessel.

    Vorher war das die Pflicht des Aufrufers, und genau daran ist sie gescheitert. Ein vierter
    Aufrufer haette denselben Fehler gemacht.
    """

    def setUp(self):
        # Ein angehaengter, verifizierter Nachbar erklaert eine Nachfolge ueber UNS (subject_hex=_B).
        self.related = {_A: {"verified": True, "relationships": [_edge(_B, "supersedes")],
                             "subject_digest": None}}

    def test_mit_eigener_kante(self):
        r = verify_relationship_edges([_edge(_A, "derivedFrom")], self.related, subject_hex=_B)
        self.assertIn("supersededByAttached", r)
        self.assertIn("declares supersedes over this receipt", r["supersededByAttached"])

    def test_ohne_eigene_kante_traegt_der_not_evaluated_zweig_ihn_auch(self):
        """successor_warning haengt NICHT an den eigenen Kanten (sein erster Parameter wird nicht
        gelesen). Ein Nachbar kann also eine Ruecknahme ueber ein Objekt erklaeren, das selbst gar
        keine Kante traegt — dieser Zweig darf den Schluessel deshalb nicht auslassen."""
        r = verify_relationship_edges(None, self.related, subject_hex=_B)
        self.assertEqual(r["lineage"], "NOT_EVALUATED")
        self.assertIn("declares supersedes over this receipt", r["supersededByAttached"])

    def test_der_fail_zweig_traegt_ihn_auch(self):
        r = verify_relationship_edges([{"relation": "gibt-es-nicht"}], self.related, subject_hex=_B)
        self.assertEqual(r["lineage"], "FAIL")
        self.assertIn("supersededByAttached", r)

    def test_ohne_nachbarn_ist_der_schluessel_da_und_None(self):
        """Anwesend mit None, nicht abwesend: ein Leser, der `.get()` benutzt, sieht keinen
        Unterschied — einer, der `in` prueft, sehr wohl. Der Schluessel ist Teil des Vertrags."""
        r = verify_relationship_edges([_edge(_A, "derivedFrom")], {}, subject_hex=_B)
        self.assertIn("supersededByAttached", r)
        self.assertIsNone(r["supersededByAttached"])


class TestWirkungAufDerStatementFlaeche(unittest.TestCase):
    """Die WIRKUNG auf genau der Flaeche, auf der der Schluessel fehlte."""

    def test_reject_superseded_greift_auf_der_statement_flaeche(self):
        sk = generate_signer()
        pub = sk.public_key().public_bytes_raw()
        tgt = emit_decision_receipt({**BASE, "decisionId": "d-target"}, sk, strict=True)
        root = anchors.statement_content_root(dsse.load_payload(tgt)).hex()
        env = emit_relation_statement(
            {"schemaVersion": "0.1.0", "statementId": "urn:uuid:s-1",
             "relationships": [_edge(root, "retracts")]}, sk)
        stmt_hex = anchors.statement_content_root(dsse.load_payload(env)).hex()
        # Der angehaengte Nachbar erklaert eine NACHFOLGE ueber das Statement selbst. Der EIGENE
        # Selbstauskunfts-Arm greift hier NICHT (die eigene Kante ist `retracts`, keine Nachfolge),
        # also haengt alles am angehaengten Arm — genau der, der wirkungslos war.
        related = {root: {"verified": True, "relationships": [_edge(stmt_hex, "supersedes")],
                          "verified_under": base64.b64encode(pub).decode(), "subject_digest": None}}
        r = verify_relation_statement(env, pub, related=related,
                                      policy={"relations": {"reject_superseded": True}})
        self.assertIsNotNone(r["lineage"]["supersededByAttached"])
        self.assertIs(r["policy_ok"], False)
        self.assertIn("LINEAGE_REQUIREMENT_FAILED", r["relations_policy_codes"] or [])

    def test_ohne_die_flagge_bleibt_es_eine_warnung(self):
        """Gegenrichtung: ohne `reject_superseded` ist der angehaengte Nachfolger eine WARNUNG und
        kein Blocker. Ein Fix, der immer blockt, waere so falsch wie einer, der nie blockt."""
        sk = generate_signer()
        pub = sk.public_key().public_bytes_raw()
        tgt = emit_decision_receipt({**BASE, "decisionId": "d-target"}, sk, strict=True)
        root = anchors.statement_content_root(dsse.load_payload(tgt)).hex()
        env = emit_relation_statement(
            {"schemaVersion": "0.1.0", "statementId": "urn:uuid:s-2",
             "relationships": [_edge(root, "retracts")]}, sk)
        stmt_hex = anchors.statement_content_root(dsse.load_payload(env)).hex()
        related = {root: {"verified": True, "relationships": [_edge(stmt_hex, "supersedes")],
                          "verified_under": base64.b64encode(pub).decode(), "subject_digest": None}}
        r = verify_relation_statement(env, pub, related=related,
                                      policy={"relations": {"reject_superseded": False}})
        self.assertIsNotNone(r["lineage"]["supersededByAttached"])
        self.assertIsNot(r["policy_ok"], False)
        self.assertTrue(any("superseded_by_attached" in w for w in r["warnings"]))


if __name__ == "__main__":
    unittest.main()
