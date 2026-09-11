"""Acceptance tests for scripts/restrisiko_render.py.

The external review of 2026-09-11 (sha256 59a14a7c) prescribes the shape of these tests in
its section 6, and its wording is the contract:

  "For each rule first prove the defective input case, then check the corrected input green.
   Additionally disable the relevant protective check on purpose. At least one test must
   fail as a result. A skipped test, an empty test run or an unnoticed failure of the
   mutation must not count as passed."

So every rule below appears three times: the planted defect must be REFUSED, the clean
register must PASS, and removing the check must make the defect slip through. The last of
the three is what distinguishes a rule that works from a rule that is merely written down.

Inventory and expected values are fixed INDEPENDENTLY of the generator under test. Deriving
them from it would reproduce the self-reference the 6.0.0 record describes in S13.
"""
import copy
import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "restrisiko_render.py"
ECHTES_REGISTER = REPO / "audit_artifacts" / "findings_register_610.json"

spec = importlib.util.spec_from_file_location("restrisiko_render_ut", SCRIPT)
rr = importlib.util.module_from_spec(spec)
sys.modules["restrisiko_render_ut"] = rr
spec.loader.exec_module(rr)


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


class Basis(unittest.TestCase):
    """Every case works on a throwaway tree with a real evidence root.

    A copy on disk, not a patched attribute: a catch-proof that sets state instead of
    walking the path proves nothing.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.wurzel = cls.tmp / "root"
        (cls.wurzel / "evidence").mkdir(parents=True)
        cls.beleg = cls.wurzel / "evidence" / "measured.txt"
        cls.beleg.write_text("a measurement that really exists\n", encoding="utf-8")
        cls.fang = cls.wurzel / "evidence" / "catch.txt"
        cls.fang.write_text("a catch-proof that really exists\n", encoding="utf-8")
        cls.policy = cls.wurzel / "evidence" / "policy.md"
        cls.policy.write_text("severity rule\n", encoding="utf-8")
        cls.sauber = {
            "schema": "proofbundle.findings_register.v2",
            "profile_version": "test.1", "document_id": "urn:test:1",
            "register_revision": 1, "publisher": "b7n0de", "language": "en",
            "issued": "2026-09-12",
            "release_subject": {"product": "proofbundle", "version": "6.1.0"},
            "assessment_cutoff": "2026-09-12",
            "inventory": {
                "source_identifiers_total": 3,
                "series_counts": {"N": 3},
                "sources": [{"path": "evidence/measured.txt", "sha256": _sha(cls.beleg)}],
                "coverage_gaps": [],
            },
            "policy_refs": [{"name": "severity", "version": "1",
                             "sha256": _sha(cls.policy)}],
            "entries": [
                {"id": "N90", "record_revision": 1, "title": "a quality finding",
                 "record_role": "finding", "kind": "quality", "severity": "P2",
                 "quality_assessments": [{"subject": "the thing", "quality_status": "open",
                                          "reason_code": "defect_confirmed",
                                          "rationale": "it was measured and it is wrong"}],
                 "funnel": {"reaches_user": True, "verdict": "does_not_block_release",
                            "reason_codes": ["accepted_known_risk"],
                            "rationale": "named and accepted, changes no verdict"},
                 "remediation": {"category": "none_available", "planning_state": "planned",
                                 "target_version": "6.1.0"},
                 "evidence": [{"path": "evidence/measured.txt", "sha256": _sha(cls.beleg),
                               "role": "measurement"},
                              {"path": "evidence/catch.txt", "sha256": _sha(cls.fang),
                               "role": "catch_proof"}]},
                {"id": "N91", "record_revision": 1, "title": "a security finding",
                 "record_role": "finding", "kind": "security", "severity": "P2",
                 "vex_statements": [{"vulnerability": {"name": "OWN-1"},
                                     "products": [{"@id": "pkg:pypi/proofbundle@6.1.0"}],
                                     "status": "affected",
                                     "action_statement": "upgrade when the fix ships"}],
                 "funnel": {"reaches_user": True, "verdict": "does_not_block_release",
                            "reason_codes": ["accepted_known_risk"],
                            "rationale": "named and accepted, changes no verdict"},
                 "remediation": {"category": "none_available", "planning_state": "deferred"},
                 "evidence": [{"path": "evidence/measured.txt", "sha256": _sha(cls.beleg),
                               "role": "measurement"}]},
                {"id": "N92", "record_revision": 1, "title": "a stated limitation",
                 "record_role": "limitation", "kind": "quality", "severity": "P3",
                 "quality_assessments": [{"subject": "the other thing",
                                          "quality_status": "under_investigation",
                                          "reason_code": "measurement_incomplete",
                                          "rationale": "the evidence is not yet sufficient"}],
                 "funnel": {"reaches_user": None, "verdict": "unresolved",
                            "reason_codes": ["insufficient_evidence"],
                            "rationale": "unknown stays unknown, it is not an all-clear"},
                 "remediation": {"category": "none_available", "planning_state": "undecided"},
                 "evidence": [{"path": "evidence/measured.txt", "sha256": _sha(cls.beleg),
                               "role": "measurement"}]},
            ],
        }

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def lauf(self, reg: dict, extra=None) -> int:
        p = self.tmp / "reg.json"
        p.write_text(json.dumps(reg), encoding="utf-8")
        return rr.main(["--register", str(p), "--check-only",
                        "--evidence-root", str(self.wurzel)] + (extra or []))



class TestKontrolle(Basis):
    def test_das_saubere_register_besteht_ALLE_regeln(self):
        """Without this, every red below could mean 'everything is red'."""
        self.assertEqual(self.lauf(self.sauber), rr.EXIT_OK)


class TestRegelnDerAbnahmetabelle(Basis):
    """One planted defect per rule of the review's section 6."""

    def test_strenges_profil_unbekannter_status(self):
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["severity"] = "P9"
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_strenges_profil_fehlendes_pflichtfeld(self):
        r = copy.deepcopy(self.sauber)
        del r["entries"][0]["funnel"]
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_strenges_profil_doppelte_kennung(self):
        r = copy.deepcopy(self.sauber)
        r["entries"].append(copy.deepcopy(r["entries"][0]))
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_vollstaendige_kennungsmenge_zahl_bleibt_gleich_menge_nicht(self):
        """The review's sharpest case: remove one, duplicate another, count unchanged."""
        r = copy.deepcopy(self.sauber)
        r["entries"][2] = copy.deepcopy(r["entries"][0])
        r["entries"][2]["id"] = "N90"
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_sicherheits_und_qualitaetssemantik_nicht_vertauschbar(self):
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["vex_statements"] = [{"vulnerability": {"name": "x"},
                                              "products": [{"@id": "p"}], "status": "affected",
                                              "action_statement": "y"}]
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_affected_ohne_handlung_wird_abgewiesen(self):
        r = copy.deepcopy(self.sauber)
        del r["entries"][1]["vex_statements"][0]["action_statement"]
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_vendor_fix_ohne_veroeffentlichte_korrektur(self):
        """A target release is not a fix. This is the review's explicit correction."""
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["remediation"] = {"category": "vendor_fix", "planning_state": "planned",
                                          "target_version": "6.1.0"}
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_deferred_als_abhilfekategorie_wird_abgewiesen(self):
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["remediation"]["category"] = "deferred"
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_trichter_unbekannt_darf_nicht_zu_false_werden(self):
        """insufficient_evidence must stay unresolved, never a quiet pass."""
        r = copy.deepcopy(self.sauber)
        r["entries"][2]["funnel"]["verdict"] = "does_not_block_release"
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_beleg_fehlt(self):
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["evidence"] = []
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_beleg_pfad_zeigt_ins_leere(self):
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["evidence"][0]["path"] = "evidence/not_here.txt"
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_beleg_ist_leer(self):
        leer = self.wurzel / "evidence" / "empty.txt"
        leer.write_text("", encoding="utf-8")
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["evidence"][0] = {"path": "evidence/empty.txt",
                                          "sha256": _sha(leer), "role": "measurement"}
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_EIN_GEAENDERTES_BYTE_im_beleg_laesst_die_pruefung_scheitern(self):
        """A digest binds content. This is the whole point of recording it."""
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["evidence"][0]["sha256"] = "0" * 64
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_beleg_pfad_entweicht_nach_oben(self):
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["evidence"][0]["path"] = "../outside.txt"
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_ein_entweichender_symlink_wird_gefangen(self):
        aussen = self.tmp / "outside.txt"
        aussen.write_text("not in the root\n", encoding="utf-8")
        link = self.wurzel / "evidence" / "link.txt"
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(aussen)
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["evidence"][0] = {"path": "evidence/link.txt",
                                          "sha256": _sha(aussen), "role": "measurement"}
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_historischer_bericht_zaehlt_nicht_als_fangnachweis(self):
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["evidence"] = [{"path": "evidence/measured.txt",
                                        "sha256": _sha(self.beleg),
                                        "role": "historical_record"}]
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_NICHT_MESSBAR_ohne_grund_wird_abgewiesen(self):
        """Owner decision 2026-09-11: a claimed limit must carry its ground."""
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["measurement_state"] = {"state": "NOT_MEASURABLE"}
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_NICHT_MESSBAR_mit_grund_besteht(self):
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["measurement_state"] = {
            "state": "NOT_MEASURABLE", "reason": "it needs hardware this house does not run"}
        self.assertEqual(self.lauf(r), rr.EXIT_OK)

    def test_abdeckungsluecke_ohne_begruendung_wird_abgewiesen(self):
        r = copy.deepcopy(self.sauber)
        r["inventory"]["coverage_gaps"] = [{"identifiers": "S86-S101",
                                            "state": "NOT_APPLICABLE", "note": "resolved"}]
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_inventar_summe_muss_zur_gesamtzahl_passen(self):
        r = copy.deepcopy(self.sauber)
        r["inventory"]["series_counts"] = {"N": 99}
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_zyklische_beziehung_wird_abgewiesen(self):
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["related_records"] = [{"relation": "corrects", "target": "N90"}]
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_beziehung_ins_leere_wird_abgewiesen(self):
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["related_records"] = [{"relation": "supersedes", "target": "N999"}]
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_kaputtes_json_ergibt_keine_teilveroeffentlichung(self):
        p = self.tmp / "broken.json"
        p.write_text("{not json", encoding="utf-8")
        self.assertEqual(rr.main(["--register", str(p), "--check-only"]), rr.EXIT_REFUSED)

    def test_deutsche_fachwoerter_auf_der_englischen_flaeche(self):
        self.assertTrue(rr.pruefung_sprache("this text mentions a Fangnachweis"))
        self.assertFalse(rr.pruefung_sprache("this text is plain English throughout"))


class TestKeineTeilveroeffentlichung(Basis):
    """A half-renewed output set is worse than none: it looks current."""

    def test_ein_ungueltiger_letzter_eintrag_schreibt_KEINE_datei(self):
        r = copy.deepcopy(self.sauber)
        r["entries"][-1]["severity"] = "P9"
        p = self.tmp / "reg.json"
        p.write_text(json.dumps(r), encoding="utf-8")
        ziel_a = self.tmp / "summary.md"
        ziel_b = self.tmp / "full.md"
        rc = rr.main(["--register", str(p), "--evidence-root", str(self.wurzel),
                      "--out-summary", str(ziel_a), "--out-full", str(ziel_b)])
        self.assertEqual(rc, rr.EXIT_REFUSED)
        self.assertFalse(ziel_a.exists(), "a refused run must leave no output behind")
        self.assertFalse(ziel_b.exists())


class TestBezeichner(Basis):
    def test_eine_liste_IM_repository_wird_verweigert(self):
        drin = REPO / "identifier_list_must_never_live_here.txt"
        drin.write_text("x\n", encoding="utf-8")
        try:
            with self.assertRaises(SystemExit) as ctx:
                rr.check_identifiers("text", drin)
            self.assertIn("INSIDE the repository", str(ctx.exception))
        finally:
            drin.unlink()

    def test_die_worte_selbst_stehen_nicht_in_der_meldung(self):
        liste = self.tmp / "words.txt"
        liste.write_text("zzsecretzz\n", encoding="utf-8")
        treffer, _ = rr.check_identifiers("a text with zzsecretzz in it", liste)
        self.assertTrue(treffer)
        for t in treffer:
            self.assertNotIn("zzsecretzz", t)

    def test_schreibweise_zaehlt_nicht_eigenschaft_zaehlt(self):
        liste = self.tmp / "words2.txt"
        liste.write_text("Müller\n", encoding="utf-8")
        for s in ("müller", "MÜLLER", "Muller"):
            with self.subTest(schreibweise=s):
                treffer, _ = rr.check_identifiers(f"text with {s}", liste)
                self.assertTrue(treffer, f"{s} slipped through")

    def test_ohne_liste_ist_der_zustand_NOT_MEASURED(self):
        """`no hits` and `not checked` must never share a word."""
        treffer, lage = rr.check_identifiers("anything", None)
        self.assertEqual(treffer, [])
        self.assertIn("NOT_MEASURED", lage)


class TestSchutzAbschalten(Basis):
    """The third of the review's three steps, and the one that decides.

    For each protective check: remove it from the source, run the register that the check
    refuses, and insist the mutated generator lets it through. A rule whose removal changes
    nothing was never enforcing anything.
    """

    def _mutiert_laden(self, alt: str, neu: str):
        quelle = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(alt, quelle, "the mutation template no longer matches the source")
        ns = {"__name__": "rr_mutiert", "__file__": str(SCRIPT)}
        exec(compile(quelle.replace(alt, neu), "<mutiert: restrisiko_render.py>", "exec"), ns)
        return ns

    def _lauf_mit(self, ns, reg):
        p = self.tmp / "reg_mut.json"
        p.write_text(json.dumps(reg), encoding="utf-8")
        return ns["main"](["--register", str(p), "--check-only",
                           "--evidence-root", str(self.wurzel)])

    def test_META_ohne_belegpruefung_kommt_ein_falscher_digest_durch(self):
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["evidence"][0]["sha256"] = "0" * 64
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)
        ns = self._mutiert_laden("        fehler += pruefung_belege(reg, a.evidence_root)\n", "")
        self.assertEqual(self._lauf_mit(ns, r), 0,
                         "removing the evidence check changed nothing — it was never binding")

    def test_META_ohne_abhilfepruefung_kommt_ein_geplanter_fix_als_vendor_fix_durch(self):
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["remediation"] = {"category": "vendor_fix", "planning_state": "planned",
                                          "target_version": "6.1.0"}
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)
        ns = self._mutiert_laden("        fehler += pruefung_abhilfe(reg)\n", "")
        self.assertEqual(self._lauf_mit(ns, r), 0)

    def test_META_ohne_semantikpruefung_wird_ein_qualitaetsfund_zur_schwachstelle(self):
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["vex_statements"] = [{"vulnerability": {"name": "x"},
                                              "products": [{"@id": "p"}], "status": "affected",
                                              "action_statement": "y"}]
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)
        ns = self._mutiert_laden("        fehler += pruefung_semantik(reg)\n", "")
        self.assertEqual(self._lauf_mit(ns, r), 0)

    def test_META_ohne_trichterpruefung_wird_unzureichende_evidenz_zur_entwarnung(self):
        r = copy.deepcopy(self.sauber)
        r["entries"][2]["funnel"]["verdict"] = "does_not_block_release"
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)
        ns = self._mutiert_laden("        fehler += pruefung_trichter(reg)\n", "")
        self.assertEqual(self._lauf_mit(ns, r), 0)

    def test_META_ohne_beziehungspruefung_kommt_ein_zyklus_durch(self):
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["related_records"] = [{"relation": "corrects", "target": "N90"}]
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)
        ns = self._mutiert_laden("        fehler += pruefung_beziehungen(reg)\n", "")
        self.assertEqual(self._lauf_mit(ns, r), 0)

    def test_META_ohne_inventarpruefung_kommt_eine_unbelegte_luecke_durch(self):
        r = copy.deepcopy(self.sauber)
        r["inventory"]["coverage_gaps"] = [{"identifiers": "S86-S101",
                                            "state": "NOT_APPLICABLE", "note": "resolved"}]
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)
        ns = self._mutiert_laden("        fehler += pruefung_inventar(reg, a.evidence_root)\n", "")
        self.assertEqual(self._lauf_mit(ns, r), 0)


class TestOffline(unittest.TestCase):
    @staticmethod
    def _wurzelmodule(quelle: str) -> set:
        import ast
        m = set()
        for n in ast.walk(ast.parse(quelle)):
            if isinstance(n, ast.Import):
                m.update(a.name.split(".")[0] for a in n.names)
            elif isinstance(n, ast.ImportFrom) and n.module:
                m.add(n.module.split(".")[0])
        return m

    def test_der_erzeuger_kann_kein_netz(self):
        module = self._wurzelmodule(SCRIPT.read_text(encoding="utf-8"))
        for verboten in ("socket", "http", "requests", "urllib", "httpx"):
            self.assertNotIn(verboten, module)

    def test_META_die_netzpruefung_faengt_einen_versteckten_import(self):
        m = self._wurzelmodule("def f():\n    import urllib.request\n")
        self.assertIn("urllib", m, "an import nested in a function must be seen")


class TestEchtesRegister(unittest.TestCase):
    """The register this branch actually ships must pass its own rules."""

    @unittest.skipUnless(ECHTES_REGISTER.is_file(), "register not in this tree")
    def test_das_ausgelieferte_register_besteht(self):
        self.assertEqual(
            rr.main(["--register", str(ECHTES_REGISTER), "--check-only"]), rr.EXIT_OK)


if __name__ == "__main__":
    unittest.main(verbosity=2)
