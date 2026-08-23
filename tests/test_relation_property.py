"""Property-based chain walker (hypothesis): random attachment graphs — the relation
verifier must TERMINATE, NEVER RAISE, respect the depth bound, honor lattice dominance
(FAIL > DECLARED_UNRESOLVED > VERIFIED), and flag every injected cycle while never
flagging a legitimate DAG."""
import unittest

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except ImportError:  # PB-2026-0718-L6-01: hypothesis is a dev-only dep — from a bare `[eval]`+pytest sdist
    import pytest    # install it is absent; a clean module-level skip beats a collection error.
    pytest.skip("hypothesis not installed (dev-only dependency)", allow_module_level=True)

from proofbundle.relation import (
    LINEAGE_DECLARED_UNRESOLVED,
    LINEAGE_FAIL,
    LINEAGE_NOT_EVALUATED,
    LINEAGE_VERIFIED,
    RELATIONS,
    verify_relationship_edges,
)


def hexid(i: int) -> str:
    return format(i, "064x")


def edge(target_hex, relation="supersedes"):
    return {"relation": relation,
            "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": target_hex}}


# Ein zufaelliger DAG: Knoten 1..n, Kanten nur von hoeherem zu niedrigerem Index (zyklenfrei).
@st.composite
def dag(draw):
    n = draw(st.integers(min_value=1, max_value=12))
    related = {}
    for i in range(1, n + 1):
        targets = draw(st.lists(st.integers(min_value=1, max_value=max(1, i - 1)),
                                max_size=3, unique=True)) if i > 1 else []
        rels = [edge(hexid(t), draw(st.sampled_from(RELATIONS))) for t in targets]
        related[hexid(i)] = {"verified": draw(st.booleans()),
                             "relationships": rels or None}
    roots = draw(st.lists(st.integers(min_value=1, max_value=n), min_size=1, max_size=4,
                          unique=True))
    edges = [edge(hexid(r), draw(st.sampled_from(RELATIONS))) for r in roots]
    return edges, related


class TestChainWalkerProperties(unittest.TestCase):
    @settings(max_examples=120, deadline=None)
    @given(dag())
    def test_never_raises_and_states_are_lawful(self, case):
        edges, related = case
        res = verify_relationship_edges(edges, related, subject_hex=hexid(999))
        self.assertIn(res["lineage"], (LINEAGE_VERIFIED, LINEAGE_DECLARED_UNRESOLVED,
                                       LINEAGE_FAIL, LINEAGE_NOT_EVALUATED))
        # Lattice-Dominanz: FAIL > UNRESOLVED > VERIFIED (aggregiert aus den Kanten).
        states = [e["resolution"] for e in res["edges"]]
        if LINEAGE_FAIL in states:
            self.assertEqual(res["lineage"], LINEAGE_FAIL)
        elif LINEAGE_DECLARED_UNRESOLVED in states:
            self.assertEqual(res["lineage"], LINEAGE_DECLARED_UNRESOLVED)
        elif states:
            self.assertEqual(res["lineage"], LINEAGE_VERIFIED)
        # Ein DAG (Kanten nur abwaerts) darf NIE einen Zyklus melden.
        self.assertFalse(any("relation:cycle" in err for err in res["errors"]))

    @settings(max_examples=60, deadline=None)
    @given(dag(), st.integers(min_value=1, max_value=12))
    def test_injected_back_edge_onto_path_is_caught_or_unreachable(self, case, victim):
        # Injektion: ein Knoten erhaelt eine Kante ZURUECK auf das Pruefobjekt (subject) —
        # jeder Pfad, der diesen Knoten erreicht, MUSS als Zyklus enden; unerreichbare
        # Knoten duerfen still bleiben (kein Over-Fire).
        edges, related = case
        subject = hexid(999)
        v = hexid(min(victim, len(related)))
        node = related[v]
        node["relationships"] = (node.get("relationships") or []) + [edge(subject, "derivedFrom")]
        node["verified"] = True
        res = verify_relationship_edges(edges, related, subject_hex=subject)
        # Nie eine Exception (implizit), und WENN der Praeparat-Knoten von einer verifizierten
        # Wurzel erreichbar ist, muss FAIL mit Zyklus-Code kommen.
        reachable = self._reachable_via_verified(edges, related, v)
        if reachable:
            # FAIL bleibt PFLICHT — das ist die Sicherheitseigenschaft und sie wird nicht weicher.
            self.assertEqual(res["lineage"], LINEAGE_FAIL)
            # DER CODE darf seit dem L4-01-Fix ein staerkerer sein. Der Walker meldet den ERSTEN
            # Fehler in DFS-Reihenfolge; seit Vorfahren auch kryptographisch geprueft werden, kann
            # ein unverifizierter Geschwister-Zweig den Pfad beenden, BEVOR die eingespritzte
            # Rueck-Kante ueberhaupt erreicht wird. Der Lauf faellt dann aus einem staerkeren Grund.
            #
            # Verlangt wird deshalb ein BENANNTER Grund aus der geschlossenen Menge — nie "FAIL
            # ohne Code", denn das waere die Luecke, die dieser Test bewacht.
            codes = " ".join(res["errors"])
            self.assertTrue(
                any(c in codes for c in ("relation:cycle",
                                         "relation:ancestor_verification_failed",
                                         "relation:ancestor_attached_target_malformed")),
                f"FAIL ohne benannten Grund — weder Zyklus noch Vorfahren-Gate: {res['errors']}")

    def _reachable_via_verified(self, edges, related, target_hex):
        # Erreichbarkeit entlang VERIFIZIERTER beigelegter Knoten.
        #
        # KORRIGIERT 2026-08-08 (deep-gate L4-01): die Vorfassung stieg in die Wurzel nur bei
        # VERIFIED ein und folgte "danach allen beigelegten Kanten" — ohne `verified` der
        # DURCHLAUFENEN Knoten zu pruefen. Damit modellierte dieses Hilfsmittel exakt den Defekt,
        # den das Gate gefunden hat: der Walker adjudizierte Vorfahren-Syntax und ueberging
        # Vorfahren-Krypto, sodass ein gefaelschter Beleg ab Hop 2 als VERIFIED durchging.
        #
        # Der Walker bricht jetzt an einem unverifizierten Vorfahren ab (hard FAIL, wie am eigenen
        # Rand). Ein Opferknoten HINTER einem solchen Vorfahren ist damit nicht mehr erreichbar,
        # und das Verdikt bleibt FAIL — nur mit dem staerkeren Code statt mit dem Zyklus. Das
        # Modell zieht hier nach; die Zusicherung des Tests bleibt unveraendert scharf.
        seen = set()
        stack = []
        for e in edges:
            t = e["targetReceiptDigest"]["digest"]
            if t in related and related[t].get("verified") is True:
                stack.append(t)
        while stack:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            if n == target_hex:
                return True
            for e2 in (related.get(n, {}).get("relationships") or []):
                t2 = e2["targetReceiptDigest"]["digest"]
                # Der Walker steigt in einen ATTACHED Knoten nur ein, wenn er selbst verifiziert
                # ist; ein unverifizierter beendet den Pfad mit FAIL, bevor ein dahinterliegender
                # Zyklus ueberhaupt sichtbar wird.
                if t2 in related and isinstance(related[t2], dict) and related[t2].get("verified") is True:
                    stack.append(t2)
        return target_hex in seen


if __name__ == "__main__":
    unittest.main()
