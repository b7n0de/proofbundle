"""Die Frist `not_after` des Vertrauensankers muss AUCH auf dem Registerpfad wirken (C12.2).

DER FUND (adversariale Linse, 2026-09-06). Der ausgelieferte Vertrauensanker
`audit_artifacts/readiness_trusted_pubkeys.txt` sagt ueber das Zeilenformat woertlich:

    not_after   last day this key may produce evidence, compared against the artifact's
                `produced_at` (the moment of MEASUREMENT), not against "now".

Die Rolle `readiness_und_register_signierer_600` deckt laut Rollentabelle C6.2, C6.3, C8.2 UND
C12.2. Fuer die ersten drei wirkt die Frist — `_artifact_signature_ok` vergleicht sie gegen
`produced_at` und verwirft. Fuer C12.2 wirkt sie NICHT: `_autorisierte_schluessel` bildet die
erlaubte Menge ausschliesslich ueber `role`; `not_after` wird geparst und nie konsultiert.

DIE EIGENSCHAFT (nicht: "dieser eine Anker ist gut"): FUER JEDEN Schluessel des Ankers und FUER
JEDEN Check, den seine Rolle abdeckt, gilt — liegt `not_after` VOR dem Messzeitpunkt der Evidenz,
ist der Schluessel fuer diesen Check NICHT autorisiert. Messzeitpunkt ist `produced_at` bei den
Bereitschaftsartefakten und `generated_at` beim Registerkoerper (das Registerschema traegt kein
`produced_at`; gegen "jetzt" zu pruefen waere falsch, weil Evidenz von gestern nicht unzulaessig
wird, weil die Matrix heute laeuft).

ZWEI RICHTUNGEN, damit der Test nicht bloss immer rot ist:
  * abgelaufen -> NICHT autorisiert (die Zusicherung)
  * gueltig    -> autorisiert       (Anti-Paritaet: ein immer-verwerfender Filter erfuellt die
                                     erste Haelfte und ist wertlos)

STAND 2026-09-06: der erste Test SCHLAEGT FEHL. Das ist Absicht — er ist der ausfuehrbare Beleg des
Fundes, bevor er der Fangnachweis eines Fixes wird.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
for _sub in ("src", "scripts"):
    _p = str(REPO / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class NotAfterGiltAufJedemPfad(unittest.TestCase):
    def setUp(self):
        self.acm = _load("acm_notafter", "scripts/audit_candidate_matrix.py")
        self.addCleanup(lambda: sys.modules.pop("acm_notafter", None))

    def _anker_mit_frist(self, frist: str) -> dict:
        zuordnung, zustand = self.acm._trust_anchor(REPO)
        self.assertEqual(zustand, "ok", "der Anker ist hier nicht lesbar; ohne ihn misst nichts")
        return {pub: dict(feld, not_after=frist) for pub, feld in zuordnung.items()}

    def _anker_setzen(self, anker: dict) -> None:
        original = self.acm._trust_anchor
        self.acm._trust_anchor = lambda repo: (anker, "ok")
        self.addCleanup(lambda: setattr(self.acm, "_trust_anchor", original))

    #: Der Messzeitpunkt, den der freigabeentscheidende Aufrufer uebergibt — das `generated_at` des
    #: Registerkoerpers. Gegen DIESE Zeit wird die Frist geprueft, nicht gegen "jetzt".
    MESSZEITPUNKT = "2026-09-06T10:27:05Z"

    def test_abgelaufener_schluessel_ist_fuer_C12_2_nicht_autorisiert(self):
        """DIE ZUSICHERUNG: eine abgelaufene Frist entzieht die Autorisierung."""
        self._anker_setzen(self._anker_mit_frist("2000-01-01"))
        erlaubt, grund = self.acm._autorisierte_schluessel(
            REPO, "C12.2", gemessen_am=self.MESSZEITPUNKT)
        self.assertEqual(
            erlaubt, set(),
            "ein Schluessel, dessen not_after 26 Jahre vor dem Messzeitpunkt liegt, gilt fuer C12.2 "
            f"weiter als autorisiert — die Frist waere auf diesem Pfad Dekoration ({grund})")

    def test_ANTI_PARITAET_gueltiger_schluessel_bleibt_autorisiert(self):
        """Ohne diese Haelfte erfuellte ein Filter, der IMMER verwirft, den Test oben."""
        self._anker_setzen(self._anker_mit_frist("2099-12-31"))
        erlaubt, grund = self.acm._autorisierte_schluessel(
            REPO, "C12.2", gemessen_am=self.MESSZEITPUNKT)
        self.assertTrue(erlaubt, f"ein gueltiger Schluessel muss autorisiert bleiben ({grund})")

    def test_ohne_messzeitpunkt_wird_die_frist_nicht_geprueft_und_sagt_es(self):
        """DIE BENANNTE GRENZE, damit sie nicht zur stillen Luecke wird.

        Ein Aufrufer ohne Messzeitpunkt kann die Frist nicht anwenden — eine erfundene Zeit waere
        schlimmer als eine benannte Luecke. Der Rueckgabegrund MUSS das dann aussprechen, sonst
        saehe der Zustand aus wie eine bestandene Pruefung. Genau diese Verwechslung war der Fund."""
        self._anker_setzen(self._anker_mit_frist("2000-01-01"))
        erlaubt, grund = self.acm._autorisierte_schluessel(REPO, "C12.2")
        self.assertTrue(erlaubt, "ohne Messzeitpunkt wird nicht gefiltert — das ist die Absicht")
        self.assertIn("not_after NICHT geprueft", grund,
                      "der Grund verschweigt, dass die Frist nicht angewandt wurde — dann ist die "
                      "Grenze still statt benannt")

    def test_die_frist_wirkt_auf_dem_artefaktpfad_bereits(self):
        """KONTRASTBELEG im selben Modul: dort ist dieselbe Klasse schon geschlossen."""
        quelle = (REPO / "scripts" / "audit_candidate_matrix.py").read_text(encoding="utf-8")
        artefakt = quelle.split("def _artifact_signature_ok", 1)[-1].split("\ndef ", 1)[0]
        register = quelle.split("def _autorisierte_schluessel", 1)[-1].split("\ndef ", 1)[0]
        self.assertIn("not_after", artefakt,
                      "der Artefaktpfad wertet not_after nicht aus — dann ist der Kontrast weg")
        self.assertIn("produced_at", artefakt)
        # KORREKTUR meiner eigenen ersten Fassung (2026-09-06): hier stand
        # `assertIn("not_after", register)` als Veraltungs-Waechter — mit der Annahme, der
        # Registerpfad erwaehne die Frist wenigstens. Er erwaehnt sie NIE, und genau das IST der
        # Fund; die Behauptung war also falsch und haette den Test aus dem falschen Grund rot
        # gehalten. Der Waechter prueft jetzt das, was er meinte: solange die Frist im
        # Registerpfad fehlt, steht der Fund; taucht sie dort auf, ist der Fix da und dieser
        # Kontrasttest hat seinen Zweck erfuellt.
        if "not_after" in register:
            self.skipTest("der Registerpfad wertet not_after inzwischen aus — Fix ist gelandet, "
                          "der Kontrasttest hat seinen Zweck erfuellt")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
