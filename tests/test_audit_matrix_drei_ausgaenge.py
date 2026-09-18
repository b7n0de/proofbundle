"""Drei Ausgaenge je Zelle, und rot nur fuer ein FAIL (Owner-Auftrag 2026-09-17,
QITEM-PROOFBUNDLE-AUDIT-MATRIX-SOAK-KLEIN-01, Schritte 1, 3, 4, 5).

GEMESSEN AN PR 218: der beratende Job war rot, und zwar auf JEDEM Pull Request -- DATA_BLOCKED 0,
FAIL 4, alle vier Zellen kandidatengebundene Freigabe-Evidenz, die kein Pull Request je erfuellen
kann. Ein Rot, das immer kommt, wird uebersehen, und dann auch das Rot, das etwas sagt.

Jeder Fall hier kann fallen: die Ausgangsabbildung ist eine reine Funktion (alle Kombinationen
stehen da), der Ausgangscode wird mit gepflanzten Verdikten gemessen, und die Kontrolle
(PASS + NOT_MEASURED ist gruen) steht neben den zwei roten Faellen.
"""
from __future__ import annotations

import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _sub in ("src", "scripts"):
    _p = str(REPO / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _deutsche_prosa as _dp  # noqa: E402


def _matrix():
    spec = importlib.util.spec_from_file_location("acm_drei", REPO / "scripts" / "audit_candidate_matrix.py")
    m = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(m)
    return m


class TestDieAbbildungIstVollstaendig(unittest.TestCase):
    """`outcome_for` ist rein: jede Kombination aus Verdikt, Ereignis und Evidenzzustand steht hier."""

    def setUp(self):
        self.m = _matrix()

    def _zeile(self, verdict, detail="d"):
        return {"id": "X.1", "verdict": verdict, "detail": detail}

    def test_pass_und_fail_sind_gemessen(self):
        m = self.m
        for auf_pr in (True, False):
            self.assertEqual(m.outcome_for(self._zeile(m.PASS), auf_pr=auf_pr, zustand=None)[0], m.PASS)
            self.assertEqual(m.outcome_for(self._zeile(m.FAIL), auf_pr=auf_pr, zustand=None)[0], m.FAIL)

    def test_die_vier_nicht_gemessenen_verdikte(self):
        m = self.m
        for v in (m.DATA_BLOCKED, m.NOT_APPLICABLE, m.EXTERNAL, m.PENDING):
            for auf_pr in (True, False):
                o, grund = m.outcome_for(self._zeile(v), auf_pr=auf_pr, zustand=None)
                self.assertEqual(o, m.NOT_MEASURED, v)
                self.assertTrue(grund.strip())

    def test_ein_unbekanntes_verdikt_ist_fail(self):
        m = self.m
        self.assertEqual(m.outcome_for(self._zeile("WEIRD"), auf_pr=True, zustand=None)[0], m.FAIL)

    def test_ungebundene_evidenz_ist_auf_einem_pr_nicht_gemessen_und_sonst_fail(self):
        """DER KERN: die vier Zellen von PR 218. Ein Artefakt, das nicht an diesen Kopf gebunden ist,
        ist auf einem Pull Request NOT_MEASURED -- und ausserhalb weiterhin FAIL."""
        m = self.m
        for zustand in sorted(m._ART_UNBOUND_ON_PR):
            with self.subTest(zustand=zustand):
                o, grund = m.outcome_for(self._zeile(m.FAIL), auf_pr=True, zustand=zustand)
                self.assertEqual(o, m.NOT_MEASURED)
                self.assertIn(zustand, grund)
                self.assertEqual(m.outcome_for(self._zeile(m.FAIL), auf_pr=False, zustand=zustand)[0],
                                 m.FAIL, "ausserhalb eines Pull Requests bleibt ungebundene Evidenz FAIL")

    def test_die_menge_der_ungebundenen_zustaende_ist_genau_benannt(self):
        """KEIN SELBSTBEZUEGLICHES ORAKEL (Linse A, 2026-09-17): der Fall darueber iteriert die
        Menge selbst und kann darum nie sagen, ob ein Mitglied hineingehoert. Hier steht die
        Menge ausgeschrieben, aus der Reihenfolge der Zulassung begruendet: Schema, Version und
        Kandidatenbindung werden ZUERST geprueft; wer die Gate-Zeile, die Provenienz, die
        Signatur oder den Anker erreicht, bindet diesen Kopf schon -- und ist dann dort kaputt."""
        m = self.m
        self.assertEqual(set(m._ART_UNBOUND_ON_PR),
                         {m.ART_ABSENT, m.ART_VERSION_UNBOUND, m.ART_CANDIDATE_UNBOUND,
                          m.ART_UNMEASURABLE_HERE})

    def test_gebrochene_evidenz_bleibt_auch_auf_einem_pr_fail(self):
        """Die Gegenrichtung: ein gefaelschtes oder in sich widerspruechliches Artefakt ist ein
        Defekt des Baums, egal welcher Kopf ihn traegt. DAZU SEIT LINSE A: ein Artefakt, das
        diesen Kopf bindet und unsigniert ist, keine Provenienz nennt, ein negatives Gate-Verdikt
        traegt oder unter keinem Anker signiert wurde -- gemessen von der Linse mit einem
        kryptografiefreien Artefakt am eigenen PR-Kopf, das vorher als 'measured at the release,
        not here' durchging."""
        m = self.m
        for zustand in (m.ART_MALFORMED, m.ART_SCHEMA_MISMATCH, m.ART_VACUOUS,
                        m.ART_SELF_REPORTED_FAILURE, m.ART_STALE, m.ART_UNTRUSTED,
                        m.ART_UNSIGNED, m.ART_PROVENANCE_INCOMPLETE, m.ART_GATE_LINE_UNBOUND,
                        m.ART_NO_TRUST_ANCHOR):
            with self.subTest(zustand=zustand):
                self.assertNotIn(zustand, m._ART_UNBOUND_ON_PR)
                self.assertEqual(m.outcome_for(self._zeile(m.FAIL), auf_pr=True, zustand=zustand)[0],
                                 m.FAIL)


def _lauf(m, checks, monkeypatch_env: dict, *, pin="bound", zustaende=None, strict=False):
    """Faehrt `main()` mit gepflanzten Zellen und liefert (rc, stdout)."""
    m.CHECKS = [(cid, 1, cid, (lambda v=v, d=d: (v, d))) for cid, v, d in checks]
    m.version_pin_binding = lambda _v: {"state": pin, "detail": "test"}
    if zustaende:
        echte = m.evaluate

        def mit_zustand():
            r = echte()
            return r
        # Der Zustand wird von den Zellen registriert; hier pflanzen wir ihn ueber eine Zelle, die
        # ihn selbst eintraegt -- so wie die echten Zellen es tun.
        m.CHECKS = [(cid, 1, cid, (lambda cid=cid, v=v, d=d: (m._EVIDENZ_ZUSTAND.__setitem__(cid, zustaende[cid])
                                                             if cid in zustaende else None) or (v, d)))
                    for cid, v, d in checks]
    alt_env = {k: os.environ.get(k) for k in monkeypatch_env}
    os.environ.update({k: v for k, v in monkeypatch_env.items() if v is not None})
    for k, v in monkeypatch_env.items():
        if v is None:
            os.environ.pop(k, None)
    alt = sys.stdout
    sys.stdout = puffer = io.StringIO()
    try:
        rc = m.main(["--strict"] if strict else [])
    finally:
        sys.stdout = alt
        for k, v in alt_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return rc, puffer.getvalue()


class TestDerAusgangscodeFolgtDenAusgaengen(unittest.TestCase):
    def setUp(self):
        self.m = _matrix()
        self.env = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_STEP_SUMMARY": None,
                    "GITHUB_ACTIONS": None}

    def test_kontrolle_pass_und_nicht_gemessen_ist_gruen(self):
        m = self.m
        rc, aus = _lauf(m, [("C2.1", m.PASS, "ok"), ("C6.3", m.DATA_BLOCKED, "no soak box"),
                            ("C12.1", m.NOT_APPLICABLE, "before the tag"), ("EXT.1", m.EXTERNAL, "human")],
                        self.env)
        self.assertEqual(rc, 0, aus)
        self.assertIn("1 of 4 measured", aus)
        self.assertIn("3 NOT_MEASURED", aus)

    def test_eine_gepflanzte_fail_zelle_macht_den_lauf_rot(self):
        """FANGNACHWEIS 1 der Fertig-Bedingung: eine FAIL-Zelle, Exit 1."""
        m = self.m
        rc, aus = _lauf(m, [("C2.1", m.PASS, "ok"), ("C4.1", m.FAIL, "planted"), ("EXT.1", m.EXTERNAL, "h")],
                        self.env)
        self.assertEqual(rc, 1, aus)

    def test_null_gemessene_zellen_sind_rot_mit_dem_wort_nothing_measured(self):
        """FANGNACHWEIS 2: null gemessene Zellen sind nie gruen."""
        m = self.m
        rc, aus = _lauf(m, [("C6.3", m.DATA_BLOCKED, "x"), ("C12.1", m.NOT_APPLICABLE, "y"),
                            ("EXT.1", m.EXTERNAL, "z")], self.env)
        self.assertEqual(rc, 1)
        self.assertIn("NOTHING_MEASURED", aus)

    def test_ungebundene_evidenz_auf_einem_pr_faerbt_nicht_rot_ausserhalb_schon(self):
        """Die Form von PR 218, gepflanzt: vier FAIL-Zellen mit ungebundener Evidenz."""
        m = self.m
        zellen = [("C6.2", m.FAIL, "no version field"), ("C6.3", m.FAIL, "no version field"),
                  ("C8.2", m.FAIL, "no version field"), ("C2.1", m.PASS, "ok"), ("EXT.1", m.EXTERNAL, "h")]
        zust = {"C6.2": m.ART_VERSION_UNBOUND, "C6.3": m.ART_VERSION_UNBOUND, "C8.2": m.ART_VERSION_UNBOUND}
        rc, aus = _lauf(m, zellen, self.env, zustaende=zust)
        self.assertEqual(rc, 0, aus)
        self.assertIn("NOT_MEASURED on this pull request", aus)
        rc, aus = _lauf(m, zellen, dict(self.env, GITHUB_EVENT_NAME=None), zustaende=zust)
        self.assertEqual(rc, 1, "ausserhalb eines Pull Requests bleibt ungebundene Evidenz rot")

    def test_ein_entscheidendes_pending_ist_nicht_gemessen_und_nicht_rot(self):
        """DIE ENTSCHEIDUNG ALS VERTRAG (Linse A nannte sie als Abweichung vom Vorzustand):
        vor dem 2026-09-17 machte ein PENDING_JUSTIFIED auf einer entscheidenden Zelle den Lauf
        rot. Der Owner-Auftrag sagt: rot nur fuer FAIL. PENDING ist 'ehrlich erklaert, offen,
        kein Blocker' -- also NOT_MEASURED mit Grund, Notiz auf dem PR, und weiterhin KEINE
        Bereitschaft auf dem Release-Pfad."""
        m = self.m
        rc, aus = _lauf(m, [("C2.1", m.PASS, "ok"), ("C8.3", m.PENDING, "one PENDING Rust surface undocumented"),
                            ("EXT.1", m.EXTERNAL, "h")], dict(self.env, GITHUB_ACTIONS="true"))
        self.assertEqual(rc, 0, aus)
        self.assertIn("::notice title=NOT_MEASURED C8.3::", aus)
        self.assertIn("audit_candidate_ready=False", aus)
        rc, _ = _lauf(m, [("C2.1", m.PASS, "ok"), ("C8.3", m.PENDING, "x"), ("EXT.1", m.EXTERNAL, "h")],
                      dict(self.env, GITHUB_EVENT_NAME=None))
        self.assertEqual(rc, 0, "auch ausserhalb eines Pull Requests: PENDING ist kein FAIL")

    def test_ein_detail_mit_zeilenumbruch_bleibt_eine_zeile_im_bericht(self):
        """Der Bericht traegt jetzt auch Workflow-Kommandos; ein Feld darf keine Zeile werden."""
        m = self.m
        _rc, aus = _lauf(m, [("C2.1", m.PASS, "ok\n::error title=INJECTED::x"), ("EXT.1", m.EXTERNAL, "h")],
                         self.env)
        self.assertNotIn("\n::error title=INJECTED", aus)
        self.assertEqual(len([z for z in aus.splitlines() if z.startswith("::error")]), 0)

    def test_eine_werfende_zelle_wird_nicht_ueber_ihren_alten_zustand_gewaschen(self):
        """un-Gegenlesung und Linse A (2026-09-17): eine Zelle registriert `version_unbound` und
        wirft danach; ohne Bereinigung laese der Ausgang den Absturz als 'nicht an diesen Kopf
        gebunden' und machte ihn auf einem PR zu NOT_MEASURED."""
        m = self.m

        def registriert_und_wirft():
            m._EVIDENZ_ZUSTAND["C6.2"] = m.ART_VERSION_UNBOUND
            raise RuntimeError("boom after registering")
        m.CHECKS = [("C2.1", 1, "C2.1", lambda: (m.PASS, "ok")), ("C6.2", 6, "C6.2", registriert_und_wirft),
                    ("EXT.1", 0, "EXT.1", lambda: (m.EXTERNAL, "h"))]
        m.version_pin_binding = lambda _v: {"state": "bound", "detail": "test"}
        alt_env = os.environ.get("GITHUB_EVENT_NAME")
        os.environ["GITHUB_EVENT_NAME"] = "pull_request"
        try:
            r = m.evaluate()
        finally:
            if alt_env is None:
                os.environ.pop("GITHUB_EVENT_NAME", None)
            else:
                os.environ["GITHUB_EVENT_NAME"] = alt_env
        zeile = [x for x in r["checks"] if x["id"] == "C6.2"][0]
        self.assertEqual(zeile["verdict"], m.FAIL)
        self.assertEqual(zeile["outcome"], m.FAIL, zeile)
        self.assertIn("RuntimeError", zeile["detail"])
        self.assertIn("C6.2", r["failed_deciding"])

    def test_eine_informative_fail_zelle_entscheidet_nicht(self):
        m = self.m
        info = sorted(m._INFORMATIVE_CHECKS)[0]
        rc, _ = _lauf(m, [("C2.1", m.PASS, "ok"), (info, m.FAIL, "presence proxy"), ("EXT.1", m.EXTERNAL, "h")],
                      self.env)
        self.assertEqual(rc, 0)

    def test_ein_ungebundener_pin_bleibt_rot(self):
        m = self.m
        rc, _ = _lauf(m, [("C2.1", m.PASS, "ok"), ("EXT.1", m.EXTERNAL, "h")], self.env, pin="drift")
        self.assertEqual(rc, 1)

    def test_die_zusammenfassung_wird_geschrieben_und_die_annotationen_gedruckt(self):
        m = self.m
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        summary = Path(tmp.name) / "summary.md"
        rc, aus = _lauf(m, [("C2.1", m.PASS, "ok"), ("C6.3", m.DATA_BLOCKED, "no box"),
                            ("C4.1", m.FAIL, "planted"), ("EXT.1", m.EXTERNAL, "h")],
                        dict(self.env, GITHUB_STEP_SUMMARY=str(summary), GITHUB_ACTIONS="true"))
        self.assertEqual(rc, 1)
        text = summary.read_text(encoding="utf-8")
        self.assertIn("| id | cell | outcome |", text)
        self.assertIn("2 of 4 measured", text)
        self.assertIn("::notice title=NOT_MEASURED C6.3::", aus)
        self.assertIn("::error title=FAIL C4.1::", aus)
        self.assertNotIn("::error title=FAIL C6.3", aus)

    def test_der_bericht_ist_englisch(self):
        m = self.m
        _rc, aus = _lauf(m, [("C2.1", m.PASS, "ok"), ("C6.3", m.DATA_BLOCKED, "no box"),
                             ("C4.1", m.FAIL, "planted"), ("C12.1", m.NOT_APPLICABLE, "before the tag"),
                             ("C7.3", m.PENDING, "declared"), ("EXT.1", m.EXTERNAL, "h")],
                         dict(self.env, GITHUB_ACTIONS="true"))
        neu = [z for z in aus.splitlines() if z.startswith("  outcomes") or z.startswith("::")
               or "NOT_MEASURED on this" in z or "NOTHING_MEASURED" in z]
        self.assertTrue(neu)
        self.assertFalse(_dp.treffer("\n".join(neu)), neu)
        summary = m._step_summary(m.evaluate())
        self.assertFalse(_dp.treffer(summary), summary[:400])


class TestDerLebendeSoak(unittest.TestCase):
    """C6.4 misst, statt Evidenz zuzulassen: ein Fake-Harness in beiden Richtungen."""

    def setUp(self):
        self.m = _matrix()

    def _mit_harness(self, ergebnis):
        import types
        fake = types.ModuleType("fuzz_soak")
        fake.soak = lambda dauer, seed=0, max_iters=None: dict(ergebnis, requested=dauer, seed=seed)
        alt = sys.modules.get("fuzz_soak")
        sys.modules["fuzz_soak"] = fake
        self.addCleanup(lambda: sys.modules.__setitem__("fuzz_soak", alt) if alt else sys.modules.pop("fuzz_soak", None))

    def _env(self, **kw):
        alt = {k: os.environ.get(k) for k in kw}
        for k, v in kw.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.addCleanup(lambda: [os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None)
                                 for k, v in alt.items()])

    def test_sauberer_lauf_ist_pass(self):
        self._mit_harness({"ok": True, "iterations": 1234, "parsers_soaked": 7, "elapsed_seconds": 2.0,
                           "untriaged_crashes": [], "untriaged_crash_count": 0, "false_accepts": [],
                           "false_accept_count": 0})
        self._env(AUDIT_MATRIX_SMALL_SOAK_SECONDS="2")
        v, d = self.m.c6_4_small_soak_live()
        self.assertEqual(v, self.m.PASS, d)
        self.assertIn("1234 iterations", d)

    def test_ein_absturz_ist_fail(self):
        self._mit_harness({"ok": False, "iterations": 50, "parsers_soaked": 7, "elapsed_seconds": 2.0,
                           "untriaged_crashes": [{"parser": "p.verify_x", "exc": "KeyError", "count": 1}],
                           "untriaged_crash_count": 1, "false_accepts": [], "false_accept_count": 0})
        self._env(AUDIT_MATRIX_SMALL_SOAK_SECONDS="2")
        v, d = self.m.c6_4_small_soak_live()
        self.assertEqual(v, self.m.FAIL, d)
        self.assertIn("KeyError", d)

    def test_null_iterationen_sind_fail_nicht_pass(self):
        """P-A5 fuer die lebende Zelle: ein Soak ueber nichts beweist nichts."""
        self._mit_harness({"ok": True, "iterations": 0, "parsers_soaked": 0, "elapsed_seconds": 0.0,
                           "untriaged_crashes": [], "untriaged_crash_count": 0, "false_accepts": [],
                           "false_accept_count": 0})
        self._env(AUDIT_MATRIX_SMALL_SOAK_SECONDS="2")
        self.assertEqual(self.m.c6_4_small_soak_live()[0], self.m.FAIL)

    def test_abgeschaltet_ist_nicht_gemessen_nie_gruen(self):
        self._mit_harness({"ok": True, "iterations": 1, "parsers_soaked": 1, "elapsed_seconds": 1.0,
                           "untriaged_crashes": [], "untriaged_crash_count": 0, "false_accepts": [],
                           "false_accept_count": 0})
        for wert in ("0", "-5", "abc"):
            with self.subTest(wert=wert):
                self._env(AUDIT_MATRIX_SMALL_SOAK_SECONDS=wert)
                self.assertEqual(self.m.c6_4_small_soak_live()[0], self.m.DATA_BLOCKED)

    def test_ohne_harness_nicht_messbar(self):
        import types
        kaputt = types.ModuleType("fuzz_soak")   # ohne `soak`
        alt = sys.modules.get("fuzz_soak")
        sys.modules["fuzz_soak"] = kaputt
        self.addCleanup(lambda: sys.modules.__setitem__("fuzz_soak", alt) if alt else sys.modules.pop("fuzz_soak", None))
        self._env(AUDIT_MATRIX_SMALL_SOAK_SECONDS="1")
        v, _d = self.m.c6_4_small_soak_live()
        self.assertIn(v, (self.m.DATA_BLOCKED, self.m.FAIL))
        self.assertNotEqual(v, self.m.PASS)

    def test_c6_4_steht_in_den_zellen_und_nicht_im_inventar(self):
        ids = [cid for cid, *_ in self.m.CHECKS]
        self.assertIn("C6.4", ids)
        self.assertNotIn("C6.4", {e["id"] for e in self.m.EVIDENCE_ADMISSION_INVENTORY})
        self.assertNotIn("C6.4", self.m._INFORMATIVE_CHECKS)

    def test_der_nachtlauf_hinweis_ist_ohne_token_ehrlich(self):
        self._env(GH_TOKEN=None, GITHUB_TOKEN=None, GITHUB_REPOSITORY="o/r")
        self.assertIn("not running with a GitHub token", self.m._nightly_soak_hinweis())


if __name__ == "__main__":
    unittest.main()
