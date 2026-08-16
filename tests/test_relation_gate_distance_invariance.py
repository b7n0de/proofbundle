"""Ein Relations-Gate darf nicht davon abhaengen, WIE WEIT weg der Defekt sitzt.

DIE KLASSE (deep gate wf_1c023644-953, Fund L4-01, P1, jury-bestaetigt): `verify_relationship_edges`
prueft am EIGENEN Rand des Belegs, ob das Ziel standalone verifiziert und ob der erklaerte
`targetSubjectDigest` bindet. `_walk_chain` tat davon nichts — es adjudizierte Vorfahren-SYNTAX
(`malformed_ancestor`) und uebersprang Vorfahren-KRYPTO vollstaendig.

Folge, gemessen: ein kryptographisch GEFAELSCHTER Beleg im angehaengten Evidenz-Satz ergab
`lineage=VERIFIED` und `safeForAutomation=true`, sobald der Vorlegende einen selbst-signierten
Zwischenschritt einfuegte. Der Riegel war distanz-abhaengig, und die Distanz waehlt der Angreifer.

WARUM KEIN BESTEHENDER TEST DAS FING: jeder Ketten-Test setzt `"verified": True` auf JEDEM
Vorfahren. Die Eigenschaft war in beiden Sprachen ungetestet — die Regression der Klasse blieb
gruen, weil sie den Fall nie erzeugte.

Diese Datei prueft die Eigenschaft, nicht den Einzelfall: fuer jede Defektklasse und jede Hop-Tiefe
muss dasselbe Verdikt herauskommen. Der Generator variiert die Tiefe, nichts wird gepinnt.
"""
from __future__ import annotations

import unittest

from proofbundle.relation import (
    LINEAGE_FAIL,
    LINEAGE_VERIFIED,
    verify_relationship_edges,
)

MAX_HOP = 5
SUBJECT = f"{0xABC:064x}"


def _hex(i: int) -> str:
    return f"{i:064x}"


def _edge(target_hex: str, subject_pin: str | None = None) -> dict:
    e = {"relation": "supersedes",
         "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": target_hex}}
    if subject_pin is not None:
        e["targetSubjectDigest"] = {"digestAlgorithm": "jcs-sha256-v1", "digest": subject_pin}
    return e


def _kette(tiefe: int, defekt_bei: int | None, defekt: str | None) -> dict:
    """Generator G(defect D, depth n): eine gerade Kette SUBJECT -> h(0) -> … -> h(tiefe-1).

    Alles ist byte-identisch bis auf den einen Knoten, an dem der Defekt sitzt — genau das macht
    den Vergleich ueber die Hop-Distanz zu einer Aussage und nicht zu einem Zufall.
    """
    related: dict[str, object] = {}
    for i in range(tiefe):
        weiter = _edge(_hex(i + 1)) if i + 1 < tiefe else None
        node: object = {"verified": True,
                        "subject_digest": _hex(1000 + i),
                        "subject_digest_state": "present",
                        "relationships": [weiter] if weiter else None}
        if i == defekt_bei:
            if defekt == "forged_sig":
                node["verified"] = False                      # type: ignore[index]
            elif defekt == "attached_malformed":
                node = "kein Zielobjekt"
            elif defekt == "subject_absent":
                node["subject_digest"] = None                 # type: ignore[index]
                node["subject_digest_state"] = "absent"       # type: ignore[index]
            elif defekt == "subject_ambiguous":
                node["subject_digest_state"] = "ambiguous"    # type: ignore[index]
            elif defekt == "subject_malformed":
                node["subject_digest"] = "kein-hex"           # type: ignore[index]
                node["subject_digest_state"] = "malformed"    # type: ignore[index]
        related[_hex(i)] = node
    # Der Subject-Pin wird auf der KANTE erklaert, die auf den defekten Knoten zeigt.
    if defekt in ("subject_absent", "subject_ambiguous", "subject_malformed") and defekt_bei is not None:
        if defekt_bei == 0:
            pass  # die Wurzelkante traegt den Pin, siehe _wurzelkante
        else:
            vor = related[_hex(defekt_bei - 1)]
            if isinstance(vor, dict) and vor.get("relationships"):
                vor["relationships"][0] = _edge(_hex(defekt_bei), subject_pin=_hex(1000 + defekt_bei))
    return related


def _wurzelkante(defekt: str | None, defekt_bei: int | None) -> dict:
    pin = _hex(1000) if (defekt_bei == 0 and defekt and defekt.startswith("subject_")) else None
    return _edge(_hex(0), subject_pin=pin)


DEFEKTE = ("forged_sig", "attached_malformed", "subject_absent",
           "subject_ambiguous", "subject_malformed")


class DistanzInvarianz(unittest.TestCase):

    def test_jeder_defekt_ergibt_dasselbe_verdikt_an_jeder_hop_distanz(self):
        """verdict(D at hop 1) == verdict(D at hop n) fuer alle n, ueber sonst gleiche Evidenz."""
        for defekt in DEFEKTE:
            with self.subTest(defekt=defekt):
                verdikte = {}
                for hop in range(MAX_HOP):
                    related = _kette(MAX_HOP, hop, defekt)
                    res = verify_relationship_edges([_wurzelkante(defekt, hop)], related,
                                                    subject_hex=SUBJECT)
                    verdikte[hop] = res["lineage"]
                self.assertEqual(
                    set(verdikte.values()), {LINEAGE_FAIL},
                    f"Defekt {defekt!r} ergibt je nach Hop-Distanz ein anderes Verdikt: {verdikte}. "
                    "Genau das war L4-01 — die Distanz waehlt der Angreifer.")

    def test_ein_gefaelschter_vorfahre_wird_nie_VERIFIED(self):
        """Die schaerfste Einzelaussage, in eigener Zeile: kein Hop macht eine Faelschung gueltig."""
        for hop in range(MAX_HOP):
            with self.subTest(hop=hop + 1):
                res = verify_relationship_edges([_wurzelkante(None, None)],
                                                _kette(MAX_HOP, hop, "forged_sig"),
                                                subject_hex=SUBJECT)
                self.assertNotEqual(
                    res["lineage"], LINEAGE_VERIFIED,
                    f"ein gefaelschter Beleg an Hop {hop + 1} wurde VERIFIED — "
                    "safeForAutomation haenge daran")

    def test_negativkontrolle_eine_saubere_kette_bleibt_VERIFIED(self):
        """Die Gegenrichtung, ohne die die Property wertlos waere: kein Ueberblocken.

        Ein Riegel, der alles ablehnt, haelt jede Invarianz — und taugt nichts.
        """
        for tiefe in range(1, MAX_HOP + 1):
            with self.subTest(tiefe=tiefe):
                res = verify_relationship_edges([_wurzelkante(None, None)],
                                                _kette(tiefe, None, None), subject_hex=SUBJECT)
                self.assertEqual(res["lineage"], LINEAGE_VERIFIED,
                                 f"saubere Kette der Tiefe {tiefe} wurde blockiert: {res['errors']}")

    def test_jeder_fehlschlag_traegt_einen_benannten_grund(self):
        """FAIL ohne Code waere die naechste Luecke: niemand koennte sagen, WORAN es lag."""
        for defekt in DEFEKTE:
            for hop in range(MAX_HOP):
                with self.subTest(defekt=defekt, hop=hop + 1):
                    res = verify_relationship_edges([_wurzelkante(defekt, hop)],
                                                    _kette(MAX_HOP, hop, defekt),
                                                    subject_hex=SUBJECT)
                    self.assertTrue(res["errors"],
                                    f"{defekt!r} an Hop {hop + 1}: FAIL ohne jeden Grund")
                    self.assertTrue(
                        any(e.startswith("relationships[") for e in res["errors"]),
                        f"{defekt!r} an Hop {hop + 1}: Grund ohne Kanten-Zuordnung: {res['errors']}")

    def test_ein_unerreichbarer_defekt_blockiert_nicht(self):
        """Ein nicht angehaengter Vorfahr beendet den Pfad ehrlich — declared-only, kein FAIL.

        Diese Zeile trennt 'streng' von 'kaputt': die Eigenschaft gilt fuer ANGEHAENGTE Vorfahren,
        nicht fuer alles jenseits des Horizonts.
        """
        related = {_hex(0): {"verified": True, "subject_digest": _hex(1000),
                             "subject_digest_state": "present",
                             "relationships": [_edge(_hex(77))]}}   # h(77) ist NICHT beigelegt
        res = verify_relationship_edges([_edge(_hex(0))], related, subject_hex=SUBJECT)
        self.assertEqual(res["lineage"], LINEAGE_VERIFIED,
                         f"ein Vorfahr jenseits des angehaengten Horizonts wurde als Fehler "
                         f"gewertet: {res['errors']}")


if __name__ == "__main__":
    unittest.main()
