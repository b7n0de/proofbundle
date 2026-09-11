"""Ein Inhaltsfehler wird als Inhaltsfehler gemeldet — `DATA_BLOCKED` meint die UMGEBUNG, sonst nichts.

WAS HIER GESCHLOSSEN WIRD. Deep Gate Lauf 11, Fund `LAUF11-L5` (P0): in
`scripts/audit_candidate_matrix.py` lief `canonical.canonicalize_statement(body)` INNERHALB
desselben `try`, dessen `except Exception` als „fehlender Kanonisierer = Umgebung" kommentiert war.
Damit wurde jeder Fehler BEIM Kanonisieren zu `ART_UNMEASURABLE_HERE` und damit zu `DATA_BLOCKED`
— auch `BudgetExceeded` und `FloatDomainError`, die Eigenschaften des ARTEFAKTS sind, nicht der
Maschine.

DER AUSGEFÜHRTE FALL, ungestubbt gemessen am Kandidatenkopf `e95e72f`: zwei Artefakte mit
DERSELBEN gefälschten Signatur (32 Nullbytes Schlüssel, 64 Nullbytes Signatur):

    ohne Zusatzfeld       -> untrusted         -> _artifact_verdict = FAIL
    mit 1.000.001 Zeichen -> unmeasurable_here -> _artifact_verdict = DATA_BLOCKED

Dieselbe Fälschung, zwei Urteile — und das zweite sagt „hier nicht messbar" über ein Artefakt,
dessen Signatur schlicht falsch ist. Ein Leser des Berichts sieht einen Umgebungsmangel, wo eine
Fälschung liegt.

WARUM DIE BEREITSCHAFT TROTZDEM NICHT KIPPTE, und warum das den Fund nicht entschärft: `ready`
verlangt `verdict == PASS` für jede entscheidende Zeile, und weder FAIL noch DATA_BLOCKED ist
PASS. Das Tor wurde also nicht grün. Dass die Verwechslung folgenlos blieb, ist Glück der Bauart
— die Eigenschaft, die diese Datei über hunderte Zeilen begründet, war trotzdem verletzt.

DIE REIHENFOLGE IST DER FIX. Die Abwesenheit des Verifiers ist eine Aussage über die Umgebung und
wird VOR der Kanonisierung geprüft; alles, was danach beim Kanonisieren schiefgeht, ist eine
Aussage über das Artefakt.
"""
from __future__ import annotations

import base64
import importlib.util
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _matrix():
    if str(REPO / "scripts") not in sys.path:
        sys.path.insert(0, str(REPO / "scripts"))
    spec = importlib.util.spec_from_file_location(
        "_acm_l5", REPO / "scripts" / "audit_candidate_matrix.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_acm_l5"] = mod
    spec.loader.exec_module(mod)
    return mod


NULL_PUB = base64.b64encode(b"\x00" * 32).decode()
NULL_SIG = base64.b64encode(b"\x00" * 64).decode()


def _gefaelschtes_artefakt(zusatzfeld: str | None = None) -> dict:
    """Ein Artefakt mit einer SIGNATUR, die nicht verifiziert — 32/64 Nullbytes. Der Unterschied
    zwischen den beiden Fällen ist AUSSCHLIESSLICH ein Zusatzfeld, dessen Länge die Budgetgrenze
    des Kanonisierers überschreitet. Die Fälschung ist in beiden Fällen dieselbe."""
    art = {
        "schema": "b7n0de.readiness_artifact.v1",
        "version": "6.0.0",
        "produced_at": "2026-09-11T09:00:00Z",
        "signature": {"alg": "ed25519", "public_key_b64": NULL_PUB, "sig_b64": NULL_SIG},
    }
    if zusatzfeld is not None:
        art["zusatz"] = zusatzfeld
    return art


class TestDieselbeFaelschungDasselbeUrteil(unittest.TestCase):

    def setUp(self):
        self.m = _matrix()
        self.trusted = {NULL_PUB: {"role": "readiness_und_register_signierer_600"}}

    def _zustand(self, art):
        return self.m._artifact_signature_ok(art, self.trusted, "ok", repo=REPO)

    def test_die_gefaelschte_signatur_ohne_zusatzfeld_ist_untrusted(self):
        """ANTI-PARITÄT und Vorbedingung: ohne diese Zeile wäre die Probe darunter leer-wahr,
        weil ein Prüfer, der ALLES als untrusted meldet, sie bestünde."""
        zustand, grund = self._zustand(_gefaelschtes_artefakt())
        self.assertEqual(zustand, self.m.ART_UNTRUSTED,
                         f"Kontrolle gefallen: die Fälschung wird nicht als untrusted erkannt ({grund})")

    def test_dasselbe_artefakt_mit_grossem_feld_bleibt_ein_inhaltsfehler(self):
        """DER FUND. Ein Feld über der Budgetgrenze macht aus derselben Fälschung keinen
        Umgebungsmangel."""
        gross = "x" * 1_000_001
        zustand, grund = self._zustand(_gefaelschtes_artefakt(gross))
        self.assertNotEqual(
            zustand, self.m.ART_UNMEASURABLE_HERE,
            "eine gefälschte Signatur wird als 'hier nicht messbar' gemeldet, sobald das Artefakt "
            f"ein Feld über der Budgetgrenze trägt — das ist eine Aussage über die Umgebung, und "
            f"die Umgebung ist in Ordnung ({grund})")

    def test_beide_faelle_liefern_DASSELBE_verdikt(self):
        """Die Eigenschaft in einem Satz: der Unterschied ist ein Zusatzfeld, das Urteil darf sich
        dadurch nicht ändern."""
        def verdikt(art):
            zustand, grund = self._zustand(art)
            return self.m._artifact_verdict({"state": zustand, "detail": grund})

        ohne = verdikt(_gefaelschtes_artefakt())
        mit = verdikt(_gefaelschtes_artefakt("x" * 1_000_001))
        self.assertEqual(ohne[0], mit[0],
                         f"dieselbe Fälschung, zwei Verdikte: ohne Zusatzfeld {ohne[0]}, mit {mit[0]}")

    def test_ein_fehlender_kanonisierer_bleibt_ein_umgebungsmangel(self):
        """DIE GEGENRICHTUNG, und sie ist die Hälfte, die den Fix von einer Verschärfung
        unterscheidet: ist der Kanonisierer WIRKLICH nicht da, ist `DATA_BLOCKED` richtig. Ein Fix,
        der auch das zu FAIL macht, hätte die Ehrlichkeit über Nicht-Gemessenes zerstört."""
        import proofbundle
        import proofbundle.canonical as echtes  # explizit: der Test darf nicht davon leben, dass ein frueherer Test das Modul schon geladen hat (LAUF12-L6 P2)
        try:
            del sys.modules["proofbundle.canonical"]
            proofbundle.canonical = None  # der Import gelingt, das Modul ist unbrauchbar
            m = _matrix()
            zustand, grund = m._artifact_signature_ok(
                _gefaelschtes_artefakt(), self.trusted, "ok", repo=REPO)
        finally:
            proofbundle.canonical = echtes
            sys.modules["proofbundle.canonical"] = echtes
        self.assertEqual(zustand, m.ART_UNMEASURABLE_HERE,
                         f"ohne brauchbaren Kanonisierer muss das Urteil UMGEBUNG bleiben ({grund})")


class TestDieEineUebersetzungZustandVerdikt(unittest.TestCase):
    """LAUF12-L5 F4 (P1, Gate-Blindheit ausgefuehrt): `_artifact_verdict` ist die EINE Stelle, an
    der ein Zustand zu einem Verdikt wird, und kein Test im Repo hielt sie fest. Die Mutation
    `DATA_BLOCKED -> PASS` an genau dieser Zeile ueberlebte vier Riegel, weil alle nur FAIL-Faelle
    verglichen. DATA_BLOCKED ist von den echten Maengeln ausgenommen — ein Zustand, der dorthin
    faellt, entscheidet den Exit-Code. Diese Klasse fragt die Uebersetzung direkt."""

    def setUp(self):
        self.m = _matrix()

    def _alle_zustaende(self):
        return sorted({getattr(self.m, n) for n in dir(self.m) if n.startswith("ART_")})

    def test_nur_unmeasurable_here_ist_data_blocked(self):
        m = self.m
        self.assertEqual(m._ART_DATA_BLOCKED_STATES, {m.ART_UNMEASURABLE_HERE},
                         "die Menge der Umgebungs-Zustaende ist nicht mehr genau {unmeasurable_here}")
        self.assertEqual(m._artifact_verdict({"state": m.ART_UNMEASURABLE_HERE, "detail": "x"})[0],
                         m.DATA_BLOCKED)

    def test_kein_zustand_wird_je_zu_pass(self):
        """Die Zeile, die die Mutation traf: aus KEINEM Zustand — auch nicht aus `verified` — macht
        die Uebersetzung ein PASS. Ein Bestehen bildet nur die aufrufende Pruefung, und nur aus
        `signed_body`."""
        m = self.m
        for zustand in self._alle_zustaende():
            for absent in (m.FAIL, m.DATA_BLOCKED):
                with self.subTest(zustand=zustand, absent=absent):
                    verdikt, _ = m._artifact_verdict({"state": zustand, "detail": "x"}, absent=absent)
                    self.assertNotEqual(verdikt, m.PASS, f"{zustand!r} wird zu PASS uebersetzt")

    def test_jeder_artefakt_zustand_ist_fail_und_absent_folgt_der_pflicht(self):
        m = self.m
        for zustand in self._alle_zustaende():
            if zustand in (m.ART_UNMEASURABLE_HERE, m.ART_ABSENT):
                continue
            with self.subTest(zustand=zustand):
                self.assertEqual(m._artifact_verdict({"state": zustand, "detail": "x"})[0], m.FAIL,
                                 f"{zustand!r} ist eine Eigenschaft des Artefakts und muss FAIL sein")
        self.assertEqual(m._artifact_verdict({"state": m.ART_ABSENT, "detail": "x"}, absent=m.FAIL)[0], m.FAIL)
        self.assertEqual(m._artifact_verdict({"state": m.ART_ABSENT, "detail": "x"},
                                             absent=m.DATA_BLOCKED)[0], m.DATA_BLOCKED)


class TestUmgebungUndArtefaktInBeideRichtungen(unittest.TestCase):
    """Die drei Lauf-12-Funde an derselben Invariante, je in ihrer Richtung:
    F1 Umgebung->Artefakt (fehlendes rfc8785 beim AUFRUF war FAIL), F2 Artefakt->Umgebung (ein
    ungekappter Leser liess ein Artefakt den Kanonisierer in MemoryError treiben), F3
    Artefakt->Umgebung (eine korrupte Registry IM Baum wurde als kaputtes Gate gelesen)."""

    def setUp(self):
        self.m = _matrix()
        self.trusted = {NULL_PUB: {"role": "readiness_und_register_signierer_600"}}

    def test_f1_ein_kanonisierer_der_beim_aufruf_fehlt_ist_umgebung(self):
        """`rfc8785` wird in canonical.py LAZY importiert — beim Aufruf, nicht beim Attributzugriff.
        Fehlt das Extra, muss das Urteil UMGEBUNG sein, nicht 'Fälschung'."""
        import proofbundle.canonical as can
        echt = can.canonicalize_statement

        def fehlt(_body):
            raise can.CanonicalizerUnavailable("rfc8785 is not installed (extra proofbundle[eval])")
        can.canonicalize_statement = fehlt
        try:
            zustand, grund = self.m._artifact_signature_ok(_gefaelschtes_artefakt(), self.trusted, "ok",
                                                           repo=REPO)
        finally:
            can.canonicalize_statement = echt
        self.assertEqual(zustand, self.m.ART_UNMEASURABLE_HERE,
                         f"ein fehlender Kanonisierer beim Aufruf wurde als Artefakt-Mangel gelesen ({grund})")

    def test_f1_gegenrichtung_ein_anderer_fehler_beim_kanonisieren_bleibt_artefakt(self):
        import proofbundle.canonical as can
        echt = can.canonicalize_statement

        def kaputt(_body):
            raise ValueError("float out of JCS domain")
        can.canonicalize_statement = kaputt
        try:
            zustand, _ = self.m._artifact_signature_ok(_gefaelschtes_artefakt(), self.trusted, "ok",
                                                       repo=REPO)
        finally:
            can.canonicalize_statement = echt
        self.assertNotEqual(zustand, self.m.ART_UNMEASURABLE_HERE,
                            "ein Inhaltsfehler beim Kanonisieren wurde zur Umgebung — der Fix von "
                            "Lauf 11 ist zurueckgedreht")

    def test_f2_der_artefakt_leser_kappt_vor_dem_lesen(self):
        """Ein Artefakt ueber dem input_bytes-Budget wird abgewiesen, BEVOR es gelesen wird —
        MALFORMED, eine Eigenschaft des Artefakts."""
        import tempfile
        from proofbundle.budget import DEFAULT_BUDGET
        sys.path.insert(0, str(REPO / "tests"))
        from _lastdeckel import gedeckelt  # noqa: PLC0415 — eigene Testlast gedeckelt (LAUF11-L3)
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "gross.json").write_bytes(b"x" * (gedeckelt(DEFAULT_BUDGET.input_bytes, bytes_je_element=1) + 1))
            res = self.m._signed_versioned_artifact("gross.json", "6.0.0", repo=Path(d))
        self.assertEqual(res["state"], self.m.ART_MALFORMED, res["detail"])
        self.assertIn("before reading", res["detail"])

    def test_f2_der_artefakt_leser_parst_strikt(self):
        """Der Leser nimmt keinen JSON-Text an, den der strikte Parser ablehnt — ein doppelter
        Schluessel ist ein Parser-Differential und war unter `json.loads` unsichtbar."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "doppelt.json").write_text('{"version": "6.0.0", "version": "6.0.1"}')
            res = self.m._signed_versioned_artifact("doppelt.json", "6.0.0", repo=Path(d))
        self.assertEqual(res["state"], self.m.ART_MALFORMED, res["detail"])
        self.assertIn("strict", res["detail"])

    def test_f2_der_leser_wirft_nie_speichermangel_beim_parsen_ist_umgebung(self):
        """Gegenlesung un_turbov1 (Lauf 13, Stelle 5b): der Vertrag sagt 'wirft nie'. Ein MemoryError
        aus dem strikten Parser eines Dokuments UNTER der Kappe ist die Maschine, nicht das Artefakt."""
        import tempfile
        import proofbundle._strict_json as sj
        echt = sj.loads_strict

        def kein_speicher(_roh, **_kw):
            raise MemoryError("simulated")
        sj.loads_strict = kein_speicher
        try:
            with tempfile.TemporaryDirectory() as d:
                (Path(d) / "k.json").write_text('{"version": "6.0.0"}')
                res = self.m._signed_versioned_artifact("k.json", "6.0.0", repo=Path(d))
        finally:
            sj.loads_strict = echt
        self.assertEqual(res["state"], self.m.ART_UNMEASURABLE_HERE, res["detail"])

    def test_f3_eine_korrupte_registry_im_baum_ist_ein_mangel_des_baums(self):
        """`scripts/rust_parity_registry.json` liegt IM begutachteten Baum. Wirft das Gate daran,
        ist die fehlende Matrix FAIL, nicht DATA_BLOCKED; fehlt das Gate-MODUL, ist es Umgebung."""
        m = self.m
        abwesend = {"state": m.ART_ABSENT, "detail": "matrix is absent", "signed_body": None,
                    "unverified": None, "source_digest": None}
        echt_art, echt_par = m._signed_versioned_artifact, m._rust_parity
        m._signed_versioned_artifact = lambda *a, **k: abwesend

        def wirft(exc):
            def _f():
                raise exc
            return _f
        try:
            m._rust_parity = wirft(ValueError("registry is not valid JSON"))
            self.assertEqual(m.c8_2_differential_agrees()[0], m.FAIL,
                             "eine korrupte Registry im Baum wurde zur Umgebung (DATA_BLOCKED)")
            m._rust_parity = wirft(ImportError("no module named rust_parity_gate"))
            self.assertEqual(m.c8_2_differential_agrees()[0], m.DATA_BLOCKED,
                             "ein fehlendes Gate-Modul ist Umgebung und muss DATA_BLOCKED bleiben")
            m._rust_parity = lambda: {"binary_available": False}
            self.assertEqual(m.c8_2_differential_agrees()[0], m.DATA_BLOCKED)
            m._rust_parity = lambda: {"binary_available": True}
            self.assertEqual(m.c8_2_differential_agrees()[0], m.FAIL)
        finally:
            m._signed_versioned_artifact, m._rust_parity = echt_art, echt_par


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
