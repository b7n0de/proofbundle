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
                "series_counts_source": "evidence/measured.txt",
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


class TestFundeDerFremdfamilie(Basis):
    """Four holes a foreign-family lens (qwen3.8:27b) found in this generator on 2026-09-12.

    All four were reproduced with a real input before being fixed, and all four are the same
    shape: a case distinction without an else. The lens is recorded because the cases exist
    BECAUSE of it — none of them came from my own review.
    """

    def test_EIN_ZYKLUS_DER_LAENGE_ZWEI_wird_gefangen(self):
        """The sharpest of the four: the first version checked only self-loops.

        A -> B -> A passes both `ziel == i` and `ziel not in ids`. "A cycle of length 1" is
        the FORM of the rule; "the graph has a cycle" is its property.
        """
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["related_records"] = [{"relation": "corrects", "target": "N91"}]
        r["entries"][1]["related_records"] = [{"relation": "corrects", "target": "N90"}]
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_EIN_ZYKLUS_DER_LAENGE_DREI_wird_ebenfalls_gefangen(self):
        """Length 2 fixed as an instance would leave length 3 open. The walk has no length."""
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["related_records"] = [{"relation": "corrects", "target": "N91"}]
        r["entries"][1]["related_records"] = [{"relation": "corrects", "target": "N92"}]
        r["entries"][2]["related_records"] = [{"relation": "corrects", "target": "N90"}]
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_eine_KETTE_ohne_zyklus_bleibt_erlaubt(self):
        """The counter-direction: a walk that refuses every graph would also be green here."""
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["related_records"] = [{"relation": "corrects", "target": "N91"}]
        r["entries"][1]["related_records"] = [{"relation": "corrects", "target": "N92"}]
        self.assertEqual(self.lauf(r), rr.EXIT_OK)

    def test_ein_UNBEKANNTER_vex_status_wird_abgewiesen(self):
        """Before the fix only `affected` and `not_affected` were examined at all."""
        r = copy.deepcopy(self.sauber)
        r["entries"][1]["vex_statements"][0]["status"] = "maybe_affected"
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_eine_UNBEKANNTE_vex_begruendung_wird_abgewiesen(self):
        r = copy.deepcopy(self.sauber)
        r["entries"][1]["vex_statements"][0]["justification"] = "we_thought_about_it"
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_EIN_FALSCHER_FELDTYP_ergibt_ein_URTEIL_keinen_absturz(self):
        """A validator that crashes has not judged. The gate checked presence, not type."""
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["evidence"] = "see attached report"
        try:
            rc = self.lauf(r)
        except AttributeError as exc:
            self.fail(f"crashed instead of judging: {exc}")
        self.assertEqual(rc, rr.EXIT_REFUSED)

    def test_record_revision_als_boolean_wird_abgewiesen(self):
        """`True` is an int in Python. A type check that forgets this accepts a flag."""
        r = copy.deepcopy(self.sauber)
        r["entries"][0]["record_revision"] = True
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_ein_ZU_GROSSER_beleg_wird_abgewiesen_statt_eingelesen(self):
        """No timeout, no chunking, no bound was the state before. A bound nobody sees is none."""
        gross = self.wurzel / "evidence" / "huge.bin"
        gross.write_bytes(b"\0" * 16)
        echte_grenze = rr.MAX_BELEG_BYTES
        try:
            rr.MAX_BELEG_BYTES = 8          # smaller than the file we just wrote
            with self.assertRaises(ValueError) as ctx:
                rr.sha256_of(gross)
            self.assertIn("larger than", str(ctx.exception))
        finally:
            rr.MAX_BELEG_BYTES = echte_grenze

    def test_eine_NICHT_REGULAERE_datei_wird_abgewiesen_statt_gelesen(self):
        """read_bytes() on a FIFO blocks until a writer appears — forever, in a validator."""
        import os
        fifo = self.wurzel / "evidence" / "pipe"
        if not fifo.exists():
            os.mkfifo(fifo)
        with self.assertRaises((ValueError, OSError)):
            rr.sha256_of(fifo)


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


class TestDeckungBindetDenBaum(Basis):
    """A coverage figure belongs to the tree it was measured in.

    Measured 12.09.2026 on the shipped register: the inventory declares RESTRISIKO_600.md at two
    states, the tag (R7 S107 N21 A4) and the work branch (S104). `series_counts` totals the TAG
    state; the coverage run reads the working tree, which is the BRANCH state. Both figures are
    correct and they are about different files. Nothing said which — and the sum rule that does
    exist compares the series against the declared total, which is arithmetic, not a measurement
    of the source.
    """

    def _prosa(self, name: str, text: str) -> Path:
        d = self.wurzel / name
        d.write_text(text, encoding="utf-8")
        return d

    def test_eine_UNGENANNTE_quellfassung_wird_abgewiesen(self):
        datei = self._prosa("prose_unknown_state.md", "## N90 covered\n")
        f = rr.pruefung_deckung(self.sauber, [datei])
        self.assertTrue(any("does not name" in x for x in f),
                        "coverage against an unnamed tree passed silently")

    def test_die_GENANNTE_quellfassung_besteht(self):
        """The counter-direction: a rule that refuses every file would also be red above."""
        datei = self._prosa("prose_known_state.md", "## N90 covered\n")
        r = copy.deepcopy(self.sauber)
        r["inventory"]["sources"] = [{"path": "prose_known_state.md@someref",
                                      "sha256": _sha(datei)}]
        self.assertEqual(rr.pruefung_deckung(r, [datei]), [])

    def test_eine_prosa_only_kennung_wird_weiterhin_gemeldet(self):
        """The older rule must survive the new one — both findings, not one instead of the other."""
        datei = self._prosa("prose_with_orphan.md", "## S77 only in the prose\n")
        r = copy.deepcopy(self.sauber)
        r["inventory"]["sources"] = [{"path": "prose_with_orphan.md@someref",
                                      "sha256": _sha(datei)}]
        f = rr.pruefung_deckung(r, [datei])
        self.assertTrue(any("S77" in x and "no carrier entry" in x for x in f))

    def test_META_ohne_den_digest_vergleich_kommt_eine_fremde_fassung_durch(self):
        quelle = SCRIPT.read_text(encoding="utf-8")
        alt = "        if bekannt and ist not in bekannt:"
        self.assertIn(alt, quelle, "the mutation template no longer matches the source")
        ns = {"__name__": "rr_mut_deckung", "__file__": str(SCRIPT)}
        exec(compile(quelle.replace(alt, "        if False:"),
                     "<mutiert: deckung>", "exec"), ns)
        datei = self._prosa("prose_unknown_state2.md", "## N90 covered\n")
        self.assertEqual(ns["pruefung_deckung"](self.sauber, [datei]), [],
                         "removing the digest comparison changed nothing — it never bound a tree")


class TestReihenzaehlungNenntIhrenBaum(Basis):
    """`series_counts` without a named source is a number about an unknown file."""

    def test_eine_reihenzaehlung_OHNE_quelle_wird_abgewiesen(self):
        r = copy.deepcopy(self.sauber)
        del r["inventory"]["series_counts_source"]
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_eine_quelle_die_NICHT_DEKLARIERT_ist_wird_abgewiesen(self):
        r = copy.deepcopy(self.sauber)
        r["inventory"]["series_counts_source"] = "some/other/file.md@v9"
        self.assertEqual(self.lauf(r), rr.EXIT_REFUSED)

    def test_META_die_summenregel_faengt_das_NICHT(self):
        """Why the new rule is not redundant, measured instead of asserted.

        The sum rule compares two declared numbers with each other. It is green for any pair that
        adds up, whatever tree either number came from — so it cannot be the check that binds the
        source, and a reader who takes it for one is reassured by arithmetic.
        """
        r = copy.deepcopy(self.sauber)
        del r["inventory"]["series_counts_source"]
        self.assertEqual(sum(r["inventory"]["series_counts"].values()),
                         r["inventory"]["source_identifiers_total"],
                         "the fixture must be arithmetically consistent for this case to mean anything")
        quelle = SCRIPT.read_text(encoding="utf-8")
        alt = '        quelle = (inv.get("series_counts_source") or "").strip()'
        self.assertIn(alt, quelle, "the mutation template no longer matches the source")
        ns = {"__name__": "rr_mut_reihen", "__file__": str(SCRIPT)}
        exec(compile(quelle.replace(alt, '        quelle = "evidence/measured.txt"'),
                     "<mutiert: reihen>", "exec"), ns)
        self.assertEqual(ns["pruefung_inventar"](r, self.wurzel), [],
                         "without the new rule the missing source passes — the sum rule never saw it")


class TestAusgenommeneBereiche(Basis):
    """Owner order 20260911T2233Z, decision one, item three, and its prohibition.

    "The identifier check and the language check run over the generated surfaces and over new
    texts, not over the archive, and they know the archive path as an exempt area, explicitly and
    with a ground, not as a silent exception." Prohibition: "no silent exception in the identifier
    check, every exempt path stands with its reason in the configuration."

    The state before these cases is worth recording, because it was the more flattering one: two
    outward texts already CLAIMED this configuration existed. It did not. The archive went
    unjudged because the checks only ever saw the generated string and never walked a tree — which
    is a silent exception wearing the words of the opposite. What follows measures the difference:
    an exemption that takes effect and is named, against one that nothing consults.
    """

    def _archiv(self) -> Path:
        d = self.wurzel / "audit_artifacts" / "600" / "restrisiko"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _liste(self, wort: str) -> Path:
        liste = self.tmp / "identifiers_outside.txt"
        liste.write_text(wort + "\n", encoding="utf-8")
        return liste

    def _lauf_mit_texten(self, *texte: Path, wort: str = "zzkennungzz"):
        import contextlib
        import io
        reg = self.tmp / "reg_ausnahme.json"
        reg.write_text(json.dumps(self.sauber), encoding="utf-8")
        puffer = io.StringIO()
        with contextlib.redirect_stdout(puffer):
            rc = rr.main(["--register", str(reg), "--check-only",
                          "--evidence-root", str(self.wurzel),
                          "--identifier-list", str(self._liste(wort)),
                          "--also-check", *[str(t) for t in texte]])
        return rc, puffer.getvalue()

    # ---- the two halves of the catch-proof named in the finding -------------------------------

    def test_ein_bezeichner_IM_ARCHIV_wird_nicht_gemeldet(self):
        datei = self._archiv() / "S13_excerpt.md"
        datei.write_text("historical excerpt mentioning zzkennungzz\n", encoding="utf-8")
        rc, aus = self._lauf_mit_texten(datei)
        self.assertEqual(rc, rr.EXIT_OK, "the archive must not be judged")
        self.assertIn("EXEMPT AREA", aus, "the exception was silent — the order forbids exactly that")
        self.assertIn("owner order 20260911T2233Z", aus, "the granting decision is not named")
        self.assertIn("byte-identical excerpts", aus, "the ground is not named")

    def test_DERSELBE_bezeichner_AUSSERHALB_wird_gemeldet(self):
        """The other half. Without it, a checker that reports nothing at all would pass above."""
        datei = self.wurzel / "a_new_outward_text.md"
        datei.write_text("a new outward text mentioning zzkennungzz\n", encoding="utf-8")
        rc, _ = self._lauf_mit_texten(datei)
        self.assertEqual(rc, rr.EXIT_IDENTIFIER)

    def test_ein_praefix_erbt_die_ausnahme_NICHT(self):
        """`…/restrisiko_other` is not `…/restrisiko`. A string prefix would say it is."""
        d = self.wurzel / "audit_artifacts" / "600" / "restrisiko_other"
        d.mkdir(parents=True, exist_ok=True)
        datei = d / "not_the_archive.md"
        datei.write_text("mentions zzkennungzz\n", encoding="utf-8")
        rc, _ = self._lauf_mit_texten(datei)
        self.assertEqual(rc, rr.EXIT_IDENTIFIER)

    def test_der_sprachpruefer_laeuft_auch_ueber_neue_texte(self):
        datei = self.wurzel / "another_new_text.md"
        datei.write_text("this new text mentions a Fangnachweis\n", encoding="utf-8")
        rc, _ = self._lauf_mit_texten(datei)
        self.assertEqual(rc, rr.EXIT_REFUSED)

    def test_der_sprachpruefer_laesst_das_archiv_in_ruhe(self):
        """The archive carries the older vocabulary ON PURPOSE and is bound byte-for-byte."""
        datei = self._archiv() / "S22_excerpt.md"
        datei.write_text("historischer Ausschnitt mit Fangnachweis und gemessen\n",
                         encoding="utf-8")
        rc, aus = self._lauf_mit_texten(datei)
        self.assertEqual(rc, rr.EXIT_OK)
        self.assertIn("EXEMPT AREA", aus)

    # ---- the exemption list judged by its own standard ----------------------------------------

    def test_eine_ausnahme_OHNE_GRUND_wird_abgewiesen(self):
        f = rr.pruefung_ausnahmen(({"path": "some/where", "decision": "someone said so"},))
        self.assertTrue(any("without a reason" in x for x in f))

    def test_eine_ausnahme_OHNE_ENTSCHEID_wird_abgewiesen(self):
        f = rr.pruefung_ausnahmen(({"path": "some/where", "reason": "a real ground, stated"},))
        self.assertTrue(any("names no decision" in x for x in f))

    def test_eine_ausnahme_DIE_DEN_GANZEN_BAUM_DECKT_wird_abgewiesen(self):
        f = rr.pruefung_ausnahmen(({"path": ".", "reason": "r", "decision": "d"},))
        self.assertTrue(f, "an area covering everything is an end, not an exception")

    def test_eine_ausnahme_DIE_NACH_OBEN_ENTWEICHT_wird_abgewiesen(self):
        f = rr.pruefung_ausnahmen(({"path": "../../etc", "reason": "r", "decision": "d"},))
        self.assertTrue(any("escapes upwards" in x for x in f))

    def test_die_AUSGELIEFERTE_liste_besteht_ihre_eigene_pruefung(self):
        """The configuration this branch ships, not only a fixture of one."""
        self.assertEqual(rr.pruefung_ausnahmen(), [])
        self.assertTrue(rr.AUSGENOMMENE_BEREICHE, "the declared list is empty")


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

    def _lauf_mit_texten_mutiert(self, ns, *texte, wort="zzkennungzz"):
        import contextlib
        import io
        reg = self.tmp / "reg_mut_ausnahme.json"
        reg.write_text(json.dumps(self.sauber), encoding="utf-8")
        liste = self.tmp / "identifiers_outside_mut.txt"
        liste.write_text(wort + "\n", encoding="utf-8")
        puffer = io.StringIO()
        with contextlib.redirect_stdout(puffer):
            rc = ns["main"](["--register", str(reg), "--check-only",
                             "--evidence-root", str(self.wurzel),
                             "--identifier-list", str(liste),
                             "--also-check", *[str(t) for t in texte]])
        return rc, puffer.getvalue()

    def test_META_ohne_die_ausnahme_wird_das_archiv_gemeldet(self):
        """The exemption must TAKE EFFECT, not merely be declared.

        This is the case the finding asked for by name: the same planted identifier, once inside
        the archive and once outside. Above it must stay silent; here, with the consultation cut
        out, it must be reported — otherwise the exemption was never load-bearing and the
        configuration entry would be one more sentence about a mechanism nobody consults.
        """
        d = self.wurzel / "audit_artifacts" / "600" / "restrisiko"
        d.mkdir(parents=True, exist_ok=True)
        datei = d / "S31_excerpt.md"
        datei.write_text("historical excerpt mentioning zzkennungzz\n", encoding="utf-8")
        ns = self._mutiert_laden(
            "            (ausgenommen.append((k, b)) if b else geprueft.append(k))",
            "            geprueft.append(k)")
        rc, _ = self._lauf_mit_texten_mutiert(ns, datei)
        self.assertEqual(rc, rr.EXIT_IDENTIFIER,
                         "cutting out the exemption changed nothing — it never exempted anything")

    def test_META_ohne_den_neuen_text_kommt_ein_bezeichner_durch(self):
        """The other direction: the new-text scan must reach the identifier check."""
        datei = self.wurzel / "a_third_new_text.md"
        datei.write_text("a new outward text mentioning zzkennungzz\n", encoding="utf-8")
        ns = self._mutiert_laden(
            '    zusammen = "\\n".join(t for _, t in flaechen) + (openvex_text or "") + neuer_text',
            '    zusammen = "\\n".join(t for _, t in flaechen) + (openvex_text or "")')
        rc, _ = self._lauf_mit_texten_mutiert(ns, datei)
        self.assertEqual(rc, rr.EXIT_OK,
                         "the scan was not what carried the new text into the check")

    def test_META_ohne_die_meldung_ist_die_ausnahme_wieder_still(self):
        """"Not a silent exception" is a property of the OUTPUT, so it is measured there.

        Silencing the report leaves the verdict untouched — which is precisely why the verdict
        cannot be the measurement for it. Before this branch the archive was skipped and nothing
        said so; that state is reproduced here on purpose and must be distinguishable.
        """
        d = self.wurzel / "audit_artifacts" / "600" / "restrisiko"
        d.mkdir(parents=True, exist_ok=True)
        datei = d / "S44_excerpt.md"
        datei.write_text("historical excerpt mentioning zzkennungzz\n", encoding="utf-8")
        ns = self._mutiert_laden("    for datei, bereich in uebergangen:",
                                 "    for datei, bereich in []:")
        rc, aus = self._lauf_mit_texten_mutiert(ns, datei)
        self.assertEqual(rc, rr.EXIT_OK, "the verdict is unchanged — that is the point")
        self.assertNotIn("EXEMPT AREA", aus,
                         "the mutation did not actually silence the report; the case proves nothing")

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
