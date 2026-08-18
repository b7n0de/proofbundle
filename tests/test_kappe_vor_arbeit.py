"""Die Kappe läuft VOR der Arbeit, die sie begrenzt — an allen drei Stellen, nicht nur an einer.

OWNER-ENTSCHEID 2026-08-18 zu `PB-GLEICHE-KLASSE-BLEIBT-UMGEKEHRT-ENTSCHIEDEN-01`: „vereinheitlichen
auf Kappe-vor-Arbeit wie 2c52596, das ist der dokumentierte Hausstandard des Budget-Moduls. Einzige
Ausnahme, wenn die Kappe an der Gegenstelle ohne die begrenzte Arbeit nicht berechenbar ist."
Die Ausnahme greift an keiner der drei Stellen: die Kappe zählt Elemente, und `len(proof_list)` ist
ohne das Dekodieren berechenbar.

WARUM DIESER TEST DIE AUFRUFZAHL MISST UND NICHT DIE ZEIT. Der Befund wurde ursprünglich über
Laufzeiten geführt, und genau daran ist die erste Nachmessung gescheitert: ein Eingang, der vorher
abbrach, lieferte 60 ms und las sich wie „wird nicht dekodiert" — dabei war er nur nie am
Prüfgegenstand angekommen. Eine Zeitmessung ist von Last, Cache und Maschinenzustand abhängig; die
Zahl der `_b64d`-Aufrufe ist es nicht. Sie ist die Größe, um die es wirklich geht: **wurde die
Arbeit geleistet, bevor abgelehnt wurde?**

Gemessen vor dem Fix: `recompute_merkle_root_b64` 195002 Aufrufe, `verify_bundle` 195004.
Danach: 2 und 4 (der Root und die Signaturfelder, die vor der Liste liegen).
"""
from __future__ import annotations

import base64
import unittest

import proofbundle.bundle as bundle_modul
from proofbundle import bundle as B
from proofbundle import persample as P
from proofbundle.budget import DEFAULT_BUDGET

_UEBER_DER_KAPPE = DEFAULT_BUDGET.merkle_path + 44   # deutlich darüber, aber schnell zu bauen
_ROOT_B64 = base64.b64encode(b"r" * 32).decode()


class _Zaehler:
    """Zählt die `_b64d`-Aufrufe des Moduls, ohne sein Verhalten zu ändern."""

    def __init__(self):
        self.n = 0
        self._orig = bundle_modul._b64d

    def __enter__(self):
        def zaehl(*a, **k):
            self.n += 1
            return self._orig(*a, **k)
        bundle_modul._b64d = zaehl
        return self

    def __exit__(self, *_):
        bundle_modul._b64d = self._orig


def _bundle(n: int, elementbreite: int = 32) -> dict:
    return {
        "schema": "proofbundle/v0.1",
        "payload_b64": base64.b64encode(b"nutzlast").decode(),
        "signature": {"alg": "ed25519",
                      "public_key_b64": base64.b64encode(b"p" * 32).decode(),
                      "sig_b64": base64.b64encode(b"s" * 64).decode()},
        "merkle": {"hash_alg": "sha256-rfc6962", "leaf_index": 0, "tree_size": n,
                   "inclusion_proof_b64": [base64.b64encode(b"x" * elementbreite).decode()] * n,
                   "root_b64": _ROOT_B64},
    }


class DieKappeLaeuftVorDerArbeit(unittest.TestCase):

    def test_recompute_dekodiert_die_ueberlange_liste_nicht(self):
        with _Zaehler() as z:
            res = B.recompute_merkle_root_b64(_bundle(_UEBER_DER_KAPPE))
        self.assertIsNone(res["recomputed_b64"])
        self.assertLess(
            z.n, 10,
            f"{z.n} Dekodier-Aufrufe für eine Liste mit {_UEBER_DER_KAPPE} Elementen — die Kappe "
            f"läuft wieder NACH der Arbeit, die sie begrenzt")

    def test_verify_bundle_dekodiert_die_ueberlange_liste_nicht(self):
        with _Zaehler() as z:
            res = B.verify_bundle(_bundle(_UEBER_DER_KAPPE))
        self.assertFalse(res.ok)
        self.assertLess(
            z.n, 10,
            f"{z.n} Dekodier-Aufrufe auf dem zentralen Entrypoint — Kappe wieder nach der Arbeit")

    def test_persample_lehnt_vor_dem_dekodieren_ab(self):
        """Der Beleg ist das ungültige base64: es wird nie berührt, sonst gäbe es einen Wurf."""
        res = P.verify_sample_opening(
            {"index": 0, "disclosure": "x", "proof_b64": ["!!kein-base64!!"] * _UEBER_DER_KAPPE},
            _ROOT_B64, 1000)
        self.assertFalse(res["ok"])
        self.assertIn("refused before decoding", res["detail"])

    def test_die_kappe_ist_ohne_die_arbeit_berechenbar(self):
        """Die Owner-Ausnahme prüfen statt annehmen: `len(proof_list) == len(proof)`.

        Nur wenn das gilt, ist die Umstellung überhaupt zulässig — sonst müsste nach Option 3
        entschieden und im Code begründet werden.
        """
        b = _bundle(8)
        liste = b["merkle"]["inclusion_proof_b64"]
        dekodiert = [base64.b64decode(p, validate=True) for p in liste]
        self.assertEqual(len(liste), len(dekodiert),
                         "die Kappe wäre ohne das Dekodieren nicht berechenbar — dann greift die "
                         "Owner-Ausnahme und dieser Fix ist der falsche")


class DieVerdikteAendernSichNicht(unittest.TestCase):
    """ANTI-TAUTOLOGIE: eine Kappe, die auch gültige Beweise abschneidet, wäre keine Härtung.

    Ohne diese Richtung bliebe der Test oben auch dann grün, wenn die Kappe auf 0 stünde und alles
    abwiese — die Aufrufzahl wäre dann erst recht klein.
    """

    def test_ein_beweis_unter_der_kappe_wird_normal_verarbeitet(self):
        """Die erwartete Zahl ist FEST, nicht aus der geprüften Kappe abgeleitet.

        Der erste Entwurf baute `_bundle(DEFAULT_BUDGET.merkle_path - 1)` und verglich gegen
        `merkle_path - 10`. Beides skalierte mit der Größe, die geprüft werden soll: bei einer Kappe
        von 0 wurde daraus eine leere Liste gegen eine negative Schranke, und der Test blieb grün,
        obwohl die Kappe alles abschnitt. Die Sensitivitätsprobe hat das gezeigt, nicht der Lauf.
        Eine feste Zahl bindet den Test an die SACHE (64 Elemente werden verarbeitet) statt an den
        Wert, den er bewachen soll.
        """
        FEST = 64
        self.assertLess(FEST, DEFAULT_BUDGET.merkle_path,
                        "Vorbedingung: 64 Elemente müssen unter der ausgelieferten Kappe liegen")
        with _Zaehler() as z:
            B.recompute_merkle_root_b64(_bundle(FEST))
        self.assertGreaterEqual(
            z.n, FEST,
            f"nur {z.n} Dekodier-Aufrufe für {FEST} Elemente UNTER der Kappe — die Kappe schneidet "
            f"zu früh, gültige Beweise werden nicht mehr verarbeitet")

    def test_der_leere_beweis_bleibt_der_gute_fall(self):
        b = _bundle(1)
        b["merkle"]["inclusion_proof_b64"] = []
        res = B.recompute_merkle_root_b64(b)
        self.assertNotIn("merkle_path budget", res["detail"],
                         "der Ein-Blatt-Fall wird von der Kappe erfasst — sie steht falsch")


if __name__ == "__main__":
    unittest.main()
