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
JEDEN Check, den seine Rolle abdeckt, gilt — liegt `not_after` VOR dem Messzeitpunkt der Evidenz
ODER VOR HEUTE, ist der Schluessel fuer diesen Check NICHT autorisiert. Messzeitpunkt ist
`produced_at` bei den Bereitschaftsartefakten und `generated_at` beim Registerkoerper.

WARUM ZWEI FRISTEN, und warum hier einmal das Gegenteil stand. Diese Datei trug an dieser Stelle
den Satz, gegen "jetzt" zu pruefen waere falsch, weil Evidenz von gestern nicht unzulaessig werde,
nur weil die Matrix heute laeuft. Der erste Halbsatz stimmt — der Schluss daraus nicht. Beide
Messzeitpunkte, `produced_at` und `generated_at`, werden VOM SIGNIERER SELBST geschrieben und sind
von seiner Signatur gedeckt; er waehlt sie also frei. Wer die private Haelfte eines abgelaufenen
Schluessels haelt, datiert in das Fenster zurueck und ist wieder autorisiert. GEMESSEN 2026-09-06
auf BEIDEN Pfaden mit Wegwerf-Schluesselpaaren:

    Registerpfad  (`_autorisierte_schluessel`)  ehrlich -> 0 Schluessel, rueckdatiert -> 1
    Artefaktpfad  (`_artifact_signature_ok`)    ehrlich -> untrusted,    rueckdatiert -> verified

Ein selbstbehaupteter Zeitpunkt kann nicht belegen, WANN signiert wurde; genau dafuer gibt es
vertrauenswuerdige Zeitstempel (RFC 3161). Ohne einen solchen ist die einzige tragfaehige Lesart,
dass das Fenster auch JETZT offen sein muss. Der Preis ist benannt: nach Ablauf wird auch
rechtmaessig entstandene Evidenz hier unzulaessig — bezahlbar, weil `_freshness_error` Evidenz
ohnehin auf 180 Tage begrenzt und diese Matrix einen KANDIDATEN mit frischer Messung beurteilt,
nicht ein Archiv. Klasse `gueltigkeitsfenster_gegen_selbstbehaupteten_zeitpunkt` im
Berkeley-Klassenledger.

ZWEI RICHTUNGEN, damit der Test nicht bloss immer rot ist:
  * abgelaufen -> NICHT autorisiert (die Zusicherung)
  * gueltig    -> autorisiert       (Anti-Paritaet: ein immer-verwerfender Filter erfuellt die
                                     erste Haelfte und ist wertlos)

STAND: der Fund ist auf beiden Pfaden geschlossen; die Tests sind seine Fangnachweise.
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

    def test_ohne_messzeitpunkt_autorisiert_niemand(self):
        """FAIL-CLOSED — und die erste Fassung dieses Tests forderte das GEGENTEIL.

        Sie hiess `test_ohne_messzeitpunkt_wird_die_frist_nicht_geprueft_und_sagt_es` und verlangte,
        dass ohne Messzeitpunkt NICHT gefiltert wird, solange der Rueckgabegrund es ausspricht — eine
        „benannte Grenze". Die Pflicht-Gegenlesung hat das als fail-open zurueckgewiesen und hat
        recht: ein Aufrufer, der den Parameter vergisst oder aus einer aelteren Fassung stammt,
        bekaeme abgelaufene Schluessel, und ein Satz im Rueckgabewert haelt ihn davon nicht ab.
        Eine Grenze zu benennen ersetzt nicht, sie zu schliessen."""
        self._anker_setzen(self._anker_mit_frist("2000-01-01"))
        erlaubt, grund = self.acm._autorisierte_schluessel(REPO, "C12.2")
        self.assertEqual(erlaubt, set(),
                         f"ohne Messzeitpunkt wurde jemand autorisiert — fail-open ({grund})")
        self.assertIn("fail-closed", grund)

    def test_RUECKDATIERUNG_aktiviert_keinen_abgelaufenen_schluessel(self):
        """DER FUND DER GEGENLESUNG, ausfuehrbar festgehalten.

        Die Signatur deckt `generated_at` mit ab, ein Halter eines widerrufenen Schluessels waehlt
        es also frei. Wird die Frist NUR gegen diesen Wert geprueft, genuegt eine Rueckdatierung vor
        die Frist, und der abgelaufene Schluessel ist wieder autorisiert. Gemessen an der ersten
        Fassung: beim ehrlichen Zeitpunkt null Schluessel, auf 1999 zurueckdatiert wieder einer.

        Der Autor hatte dazu geschrieben, das Lesen dieses Feldes koenne die erlaubte Menge „nur
        VERKLEINERN". Das stimmt gegenueber KEINER Pruefung und ist falsch gegenueber dem ehrlichen
        Messzeitpunkt — und das ist der Vergleich, auf den es ankommt. Daher zwei Fristen: gegen den
        Messzeitpunkt UND gegen heute."""
        self._anker_setzen(self._anker_mit_frist("2000-01-01"))
        for zeit in ("1999-01-01T00:00:00Z", "2000-01-01T00:00:00Z", "1900-01-01T00:00:00Z"):
            with self.subTest(gemessen_am=zeit):
                erlaubt, grund = self.acm._autorisierte_schluessel(REPO, "C12.2", gemessen_am=zeit)
                self.assertEqual(erlaubt, set(),
                                 f"Rueckdatierung auf {zeit[:10]} hat einen abgelaufenen Schluessel "
                                 f"reaktiviert ({grund})")

    def test_ANTI_PARITAET_2_die_zweite_frist_sperrt_nicht_den_gueltigen_fall(self):
        """Zwei Fristen koennten zusammen ALLES verwerfen — dann waere der Filter wertlos.

        Diese Haelfte misst, dass ein gueltiger Schluessel bei ehrlichem Messzeitpunkt UND heutigem
        Datum durchkommt. Ohne sie waere `test_RUECKDATIERUNG_...` auch dann gruen, wenn die
        Funktion konstant die leere Menge zurueckgaebe."""
        self._anker_setzen(self._anker_mit_frist("2099-12-31"))
        for zeit in (self.MESSZEITPUNKT, "2020-01-01T00:00:00Z"):
            with self.subTest(gemessen_am=zeit):
                erlaubt, grund = self.acm._autorisierte_schluessel(REPO, "C12.2", gemessen_am=zeit)
                self.assertTrue(erlaubt, f"gueltiger Schluessel wurde gesperrt ({grund})")

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


class NotAfterAufDemArtefaktpfad(unittest.TestCase):
    """DERSELBE FUND, ZWEITE INSTANZ — der Nachbar-Sweep der Klasse (Fix-the-class, Schritt b).

    Der Registerpfad war der Fund; der Artefaktpfad trug dieselbe verletzte Invariante und
    zusaetzlich ihre Begruendung als Kommentar im Code UND als Erklaerung im ausgelieferten
    Vertrauensanker. Eine Klasse, die nur an der Fundstelle geschlossen wird, kehrt am Nachbarn
    zurueck — hier gemessen, nicht vermutet.

    Gebaut wird ein WEGWERF-Schluesselpaar in einem temporaeren Baum. Der echte Release-Schluessel
    ist an keiner Stelle beteiligt; seine private Haelfte liegt in Owner-Verwahrung am Mac.
    """

    ROLLE = "readiness_und_register_signierer_600"

    def setUp(self):
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
        except ImportError as exc:                      # pragma: no cover — Umgebung
            self.skipTest(f"ed25519 nicht verfuegbar ({exc})")
        self.ed25519 = ed25519
        self.acm = _load("acm_artefakt", "scripts/audit_candidate_matrix.py")
        self.addCleanup(lambda: sys.modules.pop("acm_artefakt", None))

    def _baum_mit_frist(self, frist: str):
        """(repo, signierfunktion, trusted, ankerzustand) — ein Baum, dessen Anker genau EINEN
        Wegwerf-Schluessel mit dieser Frist committet."""
        import base64
        import subprocess
        import tempfile

        sk = self.ed25519.Ed25519PrivateKey.generate()
        pub = base64.b64encode(sk.public_key().public_bytes_raw()).decode()
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        repo = pathlib.Path(td.name)
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        ziel = repo / self.acm.READINESS_TRUST_ANCHOR_REL
        ziel.parent.mkdir(parents=True, exist_ok=True)
        ziel.write_text(f"{pub} role={self.ROLLE} not_after={frist}\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@x", "-c", "user.name=t",
                        "commit", "-qm", "anker"], check=True)

        import sign_readiness_artifact as sra
        from proofbundle import canonical

        def signiere(produced_at: str) -> dict:
            koerper = {"produced_at": produced_at, "signer_role": self.ROLLE,
                       "input_digest": "0" * 64, "ok": True,
                       "producer": {"tool": "test", "tool_version": "1"},
                       "trust_anchor_digest": sra.trust_anchor_digest(repo)}
            sig = sk.sign(canonical.canonicalize_statement(koerper))
            return dict(koerper, signature={"alg": "ed25519", "public_key_b64": pub,
                                            "sig_b64": base64.b64encode(sig).decode()})

        trusted, zustand = self.acm._trust_anchor(repo)
        self.assertEqual(zustand, "ok", "der Wegwerf-Anker ist nicht lesbar")
        return repo, signiere, trusted, zustand

    def _heute(self, tage: int) -> str:
        from datetime import datetime, timedelta, timezone
        return (datetime.now(timezone.utc) + timedelta(days=tage)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def test_RUECKDATIERUNG_auf_dem_artefaktpfad_reaktiviert_nichts(self):
        """Der Exploit, ausfuehrbar. Frist in der VERGANGENHEIT, `produced_at` in ihr Fenster
        zurueckdatiert und zugleich innerhalb des 180-Tage-Frischefensters — genau der Korridor,
        in dem die alte Fassung `verified` sagte."""
        frist = self._heute(-97)[:10]
        repo, signiere, trusted, zustand = self._baum_mit_frist(frist)
        for versatz in (-128, -120, -100):
            with self.subTest(produced_at_vor_tagen=-versatz):
                art = signiere(self._heute(versatz))
                z, grund = self.acm._artifact_signature_ok(art, trusted, zustand, repo=repo)
                self.assertNotEqual(
                    z, self.acm.ART_VERIFIED,
                    f"ein um {-versatz} Tage zurueckdatiertes produced_at hat einen seit {frist} "
                    f"abgelaufenen Schluessel reaktiviert ({grund})")

    def test_ANTI_PARITAET_3_gueltige_frist_laesst_das_artefakt_durch(self):
        """Ohne diese Haelfte waere der Test oben auch dann gruen, wenn der Pfad ALLES verwuerfe."""
        repo, signiere, trusted, zustand = self._baum_mit_frist(self._heute(365)[:10])
        for versatz in (0, -30):
            with self.subTest(produced_at_vor_tagen=-versatz):
                art = signiere(self._heute(versatz))
                z, grund = self.acm._artifact_signature_ok(art, trusted, zustand, repo=repo)
                self.assertEqual(z, self.acm.ART_VERIFIED,
                                 f"ein gueltiges Artefakt wurde verworfen ({z}: {grund})")

    def test_die_frist_wirkt_ueberhaupt_noch_gegen_zu_spaete_evidenz(self):
        """Die ERSTE Frist darf durch die zweite nicht ersetzt worden sein: Evidenz, die NACH dem
        Ablauf entstand, bleibt unzulaessig — auch solange das Fenster heute noch offen ist."""
        repo, signiere, trusted, zustand = self._baum_mit_frist(self._heute(10)[:10])
        art = signiere(self._heute(9))
        z, _ = self.acm._artifact_signature_ok(art, trusted, zustand, repo=repo)
        self.assertEqual(z, self.acm.ART_VERIFIED, "innerhalb des Fensters muss es durchgehen")
        spaet = signiere(self._heute(30))
        z2, grund2 = self.acm._artifact_signature_ok(spaet, trusted, zustand, repo=repo)
        self.assertNotEqual(z2, self.acm.ART_VERIFIED,
                            f"Evidenz von NACH dem Ablauf wurde zugelassen ({grund2})")
