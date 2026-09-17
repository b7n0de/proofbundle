"""WP-W2 — the offline conformance corpus runs green, and its anchor checks are real.

The harness lives in `conformance/run_conformance.py`. In the base test job (no
`[anchors]` extra) the canonicalization / content-root / validator checks run for every
case and the anchor sub-checks skip. The `_HAS_OTS` test runs the full anchor-required
pass — it executes in the dedicated `anchors` CI job, mirroring tests/test_anchors_ots.py.
"""
import importlib.util
import pathlib
import unittest

import pytest

# L6-02 follow-up: the conformance harness validates the corpus against JSON Schema, so it needs jsonschema
# (a [test]-extra dep). From a bare `[eval]` sdist install it is absent -> skip cleanly rather than error.
pytest.importorskip("jsonschema")

_CONF = pathlib.Path(__file__).resolve().parents[1] / "conformance"

_spec = importlib.util.spec_from_file_location("run_conformance", _CONF / "run_conformance.py")
_rc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rc)


class TestConformanceCorpus(unittest.TestCase):
    def test_corpus_passes_offline(self):
        # Non-anchor checks (canonicalization, content roots, evidenceRef binding, validator
        # finding counts) run for every case regardless of the [anchors] extra.
        self.assertEqual(_rc.run(require_anchors=False), 0)

    @unittest.skipUnless(_rc._HAS_OTS, "needs [anchors]/opentimestamps for the anchor sub-checks")
    def test_corpus_passes_with_anchors_required(self):
        # The full run: a confirmed anchor must verify offline against its frozen block header,
        # a pending anchor must report pending. Runs in the anchors CI job.
        self.assertEqual(_rc.run(require_anchors=True), 0)

    def test_manifest_and_cases_are_wellformed(self):
        import json
        manifest = json.loads((_CONF / "manifest.json").read_text())
        self.assertTrue(manifest.get("cases"))
        for rel in manifest["cases"]:
            case = json.loads((_CONF / rel / "case.json").read_text())
            for key in ("caseId", "kind", "expected", "specRefs", "rationale", "attribution"):
                self.assertIn(key, case, f"{rel} case.json missing {key}")
            # every shipped decision_crossimpl case must fully declare its bindings (the floor):
            if case["kind"] == "decision_crossimpl":
                exp = case["expected"]
                for k in ("jcs_byte_identical", "content_roots_match_manifest", "decision_content_root",
                          "evidence_content_root", "evidence_ref_binds_content_root",
                          "decision_predicate_findings", "schema_conformant"):
                    self.assertIn(k, exp, f"{rel} expected under-declares {k}")
                if (_CONF / rel / "decision_receipt.jcs.ots").is_file():
                    self.assertIn("anchor", exp, f"{rel} ships a .ots but declares no anchor")


class TestHarnessFailsClosed(unittest.TestCase):
    """WP-W2 review (harness-soundness lens): a case that UNDER-DECLARES its expectations must FAIL,
    not pass green asserting nothing (fake-PASS-by-omission), and a missing fixture must be a per-case
    FAIL, not a run-aborting crash."""

    def _copy_corpus(self):
        import shutil
        import tempfile
        dst = pathlib.Path(tempfile.mkdtemp()) / "conformance"
        shutil.copytree(_CONF, dst)
        return dst

    def _run_on(self, root, **kw):
        import importlib.util
        spec = importlib.util.spec_from_file_location("rc_tmp", root / "run_conformance.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        m.ROOT = root
        return m.run(**kw)

    def test_empty_expected_fails(self):
        import json
        root = self._copy_corpus()
        case_path = next(root.glob("decision/crossimpl/*/case.json"))
        case = json.loads(case_path.read_text())
        case["expected"] = {}
        case_path.write_text(json.dumps(case))
        self.assertEqual(self._run_on(root), 1, "a case declaring no expectations must FAIL")

    def test_dropping_a_binding_key_fails(self):
        import json
        root = self._copy_corpus()
        case_path = next(root.glob("decision/crossimpl/*/case.json"))
        case = json.loads(case_path.read_text())
        del case["expected"]["content_roots_match_manifest"]
        case_path.write_text(json.dumps(case))
        self.assertEqual(self._run_on(root), 1, "dropping a mandatory binding key must FAIL")

    def test_dropping_anchor_on_anchored_case_fails(self):
        import json
        root = self._copy_corpus()
        # the confirmed-anchor case ships a .ots — dropping its anchor expectation must fail
        cdir = root / "decision/crossimpl/confirmed-anchor-lifecycle"
        case = json.loads((cdir / "case.json").read_text())
        case["expected"].pop("anchor", None)
        (cdir / "case.json").write_text(json.dumps(case))
        self.assertEqual(self._run_on(root, require_anchors=_rc._HAS_OTS), 1,
                         "an anchored case that drops its anchor expectation must FAIL")

    def test_missing_fixture_is_per_case_fail_not_crash(self):
        root = self._copy_corpus()
        (next(root.glob("decision/crossimpl/*/evidence_eval_result.json"))).unlink()
        # must return 1 (a FAIL), not raise
        self.assertEqual(self._run_on(root), 1)

    def test_missing_case_dir_is_per_case_fail_not_crash(self):
        # WP-S1 review (harness lens): a manifest entry pointing at a deleted case dir must be a
        # per-case FAIL, not an uncaught FileNotFoundError that aborts the whole run and masks other cases.
        import shutil
        root = self._copy_corpus()
        shutil.rmtree(next(root.glob("bundle/*")))
        self.assertEqual(self._run_on(root), 1)  # returns 1, does not raise

    def test_malformed_case_json_is_per_case_fail_not_crash(self):
        root = self._copy_corpus()
        next(root.glob("bundle/*/case.json")).write_text("{ this is not json")
        self.assertEqual(self._run_on(root), 1)

    def test_case_json_without_kind_is_per_case_fail(self):
        import json
        root = self._copy_corpus()
        cp = next(root.glob("bundle/*/case.json"))
        case = json.loads(cp.read_text())
        case.pop("kind", None)
        cp.write_text(json.dumps(case))
        self.assertEqual(self._run_on(root), 1)

    def test_native_bundle_input_path_escape_is_rejected(self):
        import json
        root = self._copy_corpus()
        cp = root / "bundle/valid-minimal/case.json"
        case = json.loads(cp.read_text())
        case["input"] = "/etc/hostname"
        cp.write_text(json.dumps(case))
        self.assertEqual(self._run_on(root), 1, "an input escaping the case dir must FAIL")

    def test_native_bundle_wrong_expected_exitcode_fails(self):
        import json
        root = self._copy_corpus()
        # the valid bundle verifies with exit 0; asserting it must exit 2 must FAIL
        cp = root / "bundle/valid-minimal/case.json"
        case = json.loads(cp.read_text())
        case["expected"]["exitCode"] = 2
        cp.write_text(json.dumps(case))
        self.assertEqual(self._run_on(root), 1)

    def test_native_bundle_missing_exitcode_fails(self):
        import json
        root = self._copy_corpus()
        cp = root / "bundle/valid-minimal/case.json"
        case = json.loads(cp.read_text())
        case["expected"] = {}
        cp.write_text(json.dumps(case))
        self.assertEqual(self._run_on(root), 1, "a native_bundle case without exitCode must FAIL (floor)")

    def test_duplicate_key_bundle_is_rejected(self):
        # the C1 defense as a conformance property: the dup-key fixture MUST verify to exit 2
        from proofbundle.cli import main as cli_main
        import contextlib
        import io
        p = _CONF / "bundle/duplicate-json-key/bundle.json"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = cli_main(["verify", str(p)])
        self.assertEqual(rc, 2, "a bundle with a duplicate JSON key must be rejected as malformed")


def zahl_der_faelle(ausgabe: str) -> int:
    """Die Fallzahl aus der Kopfzeile — der Nenner kommt aus DERSELBEN Ausgabe wie der Zaehler."""
    import re
    return int(re.search(r"\] (\d+) cases", ausgabe).group(1))


class TestExecutedScopeIsDisclosed(unittest.TestCase):
    """R4-04 — a check that did NOT RUN must never be counted as one that passed.

    An external review ran the corpus on the documented `pip install -e '.[test]'` setup, which does
    NOT carry `opentimestamps`. The harness reported `122/122 cases pass` and printed four SKIPPED
    lines below it: one case that never ran, three that ran without their anchor sub-check. Both
    statements were true; together they let the honest number be quoted as a dishonest one.

    `_HAS_OTS` is forced here rather than probed, so these contracts assert the same thing in the
    base job and in the [anchors] job — the property is the disclosure, not the environment.
    """

    def _lauf(self, *, has_ots, require_anchors=False, defekt=None):  # noqa: D401
        import contextlib
        import importlib.util
        import io
        spec = importlib.util.spec_from_file_location("rc_scope", _CONF / "run_conformance.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        m._HAS_OTS = has_ots
        if defekt is not None:
            defekt(m)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = m.run(require_anchors=require_anchors)
        return rc, buf.getvalue(), m

    def _zahlen(self, ausgabe):
        import re
        kopf = ausgabe.splitlines()[0]
        # NICHT ueber ein {zahl: wort}-Woerterbuch: sobald zwei Posten dieselbe Zahl tragen
        # (drei Nullen sind der Normalfall), faellt einer davon still weg.
        paare = re.findall(r"(\d+) (cases|fully checked|partially checked|not run|failed)",
                           kopf.replace("·", " "))
        zahlen = {wort: int(zahl) for zahl, wort in paare}
        self.assertEqual(len(zahlen), 5, f"die Kopfzeile nennt nicht alle fuenf Posten: {kopf}")
        return zahlen, kopf

    def test_headline_names_the_skipped_checks_instead_of_a_pass_ratio(self):
        rc, ausgabe, _ = self._lauf(has_ots=False)
        zahlen, kopf = self._zahlen(ausgabe)
        self.assertEqual(rc, 0, "without --require-anchors a skip is still exit 0 (documented contract)")
        # the three states are named, and they add up to the whole corpus
        self.assertEqual(zahlen["fully checked"] + zahlen["partially checked"]
                         + zahlen["not run"] + zahlen["failed"], zahlen["cases"], kopf)
        self.assertGreater(zahlen["partially checked"], 0, kopf)
        self.assertGreater(zahlen["not run"], 0, kopf)
        # the quotable half-truth is gone: no bare "N/N cases pass" anywhere in the summary
        self.assertNotIn("cases pass", ausgabe)
        # and every skipped check is named with its case id
        self.assertIn("did NOT run in this environment", ausgabe)
        genannt = sum(1 for z in ausgabe.splitlines() if z.strip().startswith("- "))
        self.assertEqual(genannt, zahlen["partially checked"] + zahlen["not run"],
                         "every partially-checked and not-run case must be named individually")

    def test_a_case_that_did_not_run_is_not_labelled_pass(self):
        _, ausgabe, _ = self._lauf(has_ots=False)
        import re
        fuer_fall = dict((fall, marke) for marke, fall in re.findall(
            r"^  (PASS|PARTIAL|NOT RUN|FAIL)\s+(\S+?):", ausgabe, re.M))
        self.assertEqual(len(fuer_fall), zahl_der_faelle(ausgabe),
                         "jede Fallzeile muss genau eine der vier Marken tragen")
        self.assertEqual(fuer_fall.get("native-bundle-forged-anchor-own-frozen"), "NOT RUN",
                         "the wholly skipped case must not carry a PASS label")
        self.assertEqual(fuer_fall.get("decision-crossimpl-schema-conformant"), "PARTIAL",
                         "a case whose anchor sub-check skipped must not carry a PASS label")

    def test_with_anchors_present_nothing_is_partial_or_unrun(self):
        """Mit den Ankern nichts Teilweises und nichts Ungelaufenes.

        DAS FLAG IST NICHT DIE FAEHIGKEIT, und daran ist dieser Fall am 16.09.2026 gefallen. Er
        erzwang `_HAS_OTS = True` und schloss daraus, die Bibliothek stehe zur Verfuegung. Der
        Laeufer liest das Flag, die Ankerpruefung ruft aber die ECHTE Bibliothek — und im
        hermetischen Reinraum, der aus der sdist baut, ist sie nicht installiert. Drei
        `decision-crossimpl`-Faelle meldeten dort `anchor status 'no_lib'`, der Kopf sagte
        107 von 110 vollstaendig geprueft und 3 gefallen, und dieser Vertrag fiel.

        Gefallen ist er zu RECHT: das Verhalten des Laeufers war richtig, die ANNAHME des Falls
        war falsch. Wer `--require-anchors` sagt und die Anker nicht hat, bekommt einen
        Fehlschlag, und genau das ist der Zweck des Schalters. Der Fall misst deshalb jetzt die
        Faehigkeit statt den Stellvertreter und behauptet in jeder Umgebung das Richtige.
        """
        import importlib.util
        anker_da = importlib.util.find_spec("opentimestamps") is not None
        rc, ausgabe, _ = self._lauf(has_ots=True, require_anchors=True)
        zahlen, kopf = self._zahlen(ausgabe)
        if anker_da:
            self.assertEqual(rc, 0, ausgabe)
            self.assertEqual(zahlen["fully checked"], zahlen["cases"], kopf)
            self.assertNotIn("did NOT run in this environment", ausgabe)
        else:
            # Ohne die Bibliothek MUSS es fallen, und der Grund muss die Bibliothek nennen.
            self.assertEqual(rc, 1, kopf)
            self.assertGreater(zahlen["failed"], 0, kopf)
            self.assertIn("opentimestamps", ausgabe,
                          "ein Fehlschlag wegen fehlender Anker muss die Bibliothek benennen")
        # In BEIDEN Umgebungen gilt: unter --require-anchors gibt es kein Teilweise und kein
        # Ungelaufenes mehr. Ein uebersprungener Anker ist dann ein Fehlschlag, kein stiller Rest.
        self.assertEqual(zahlen["partially checked"], 0, kopf)
        self.assertEqual(zahlen["not run"], 0, kopf)

    def test_require_anchors_turns_every_skip_into_a_failure(self):
        rc, ausgabe, _ = self._lauf(has_ots=False, require_anchors=True)
        zahlen, kopf = self._zahlen(ausgabe)
        self.assertEqual(rc, 1, kopf)
        self.assertEqual(zahlen["partially checked"], 0, kopf)
        self.assertEqual(zahlen["not run"], 0, kopf)
        self.assertGreater(zahlen["failed"], 0, kopf)

    # --- die beiden Boeden, je mit eingepflanztem Defekt ---------------------------------------

    def test_a_check_that_hides_its_skip_is_caught(self):
        """Der Pruefer ueberspringt die Ankerpruefung und meldet trotzdem FULL ohne Skip.

        Das ist der Defekt, den die Kopfzeile allein nicht sehen kann. Gefangen wird er vom ZWEITEN
        Leser: `skips_forced_by_environment` leitet aus dem Fall ab, was hier gar nicht laufen kann.
        """
        def defekt(m):
            echt = m._DISPATCH["decision_crossimpl"]

            def luegner(case, case_dir, **kw):
                r = echt(case, case_dir, **kw)
                r["scope"], r["skipped"] = m.FULL, []      # den Skip verschweigen
                return r
            m._DISPATCH = dict(m._DISPATCH, decision_crossimpl=luegner)
        rc, ausgabe, _ = self._lauf(has_ots=False, defekt=defekt)
        self.assertEqual(rc, 1, "a check hiding its skip must FAIL the run")
        self.assertIn("must never be counted as one that did", ausgabe)

    def test_a_check_that_declares_no_scope_at_all_is_caught(self):
        """Fail-closed floor: ohne ausgewiesenen Umfang zaehlt ein Ergebnis NICHT als voll geprueft."""
        def defekt(m):
            echt = m._DISPATCH["native_bundle"]

            def stumm(case, case_dir, **kw):
                r = echt(case, case_dir, **kw)
                r.pop("scope", None)
                return r
            m._DISPATCH = dict(m._DISPATCH, native_bundle=stumm)
        rc, ausgabe, _ = self._lauf(has_ots=True, defekt=defekt)
        self.assertEqual(rc, 1, "an ok result without a declared scope must FAIL the run")
        self.assertIn("without declaring its executed scope", ausgabe)


    # --- was die Gegenlese der FREMDEN Modellfamilie am 16.09.2026 fand ------------------------

    def test_a_reported_skip_with_full_scope_is_caught_for_any_dependency(self):
        """P1 der fremden Familie: die unabhaengige Ableitung kennt NUR opentimestamps.

        Ihr Befund, woertlich: "Die 'unabhaengige Ableitung' schuetzt nur vor Luegen ueber OTS."
        Ein Pruefer, der wegen IRGENDEINER anderen fehlenden Bibliothek etwas ueberspringt und das
        auch meldet, wurde trotzdem als voll geprueft gezaehlt — `forced - reported` ist leer, also
        griff nichts. Der Widerspruch im Ergebnis selbst faengt das OHNE Kenntnis der Bibliothek.
        """
        def defekt(m):
            echt = m._DISPATCH["native_bundle"]

            def fremde_luecke(case, case_dir, **kw):
                r = echt(case, case_dir, **kw)
                # ein Skip, den `skips_forced_by_environment` NIE kennen kann
                r["skipped"] = ["libfoo-missing"]
                r["scope"] = m.FULL
                return r
            m._DISPATCH = dict(m._DISPATCH, native_bundle=fremde_luecke)
        rc, ausgabe, _ = self._lauf(has_ots=True, defekt=defekt)
        self.assertEqual(rc, 1, "ein gemeldeter Skip neben scope=FULL muss den Lauf faellen")
        self.assertIn("only 'full' means nothing was skipped", ausgabe)
        self.assertIn("libfoo-missing", ausgabe,
                      "der Grund muss im Klartext dastehen — sonst weiss der Leser nur DASS, nicht WAS")

    def test_the_headline_accounts_for_every_case(self):
        """P2 der fremden Familie: ein Fall, der in keinen Eimer faellt, verschwand aus der Summe
        und stand in der Detailzeile als '?'. Zwei Ansichten, ein Lauf, zwei Wahrheiten."""
        rc, ausgabe, _ = self._lauf(has_ots=True)
        zahlen, kopf = self._zahlen(ausgabe)
        self.assertEqual(zahlen["fully checked"] + zahlen["partially checked"]
                         + zahlen["not run"] + zahlen["failed"], zahlen["cases"], kopf)
        self.assertNotIn("UNACCOUNTED", ausgabe)
        self.assertNotIn("  ?  ", ausgabe, "keine Fallzeile ohne Marke")

    def test_partial_without_a_named_skip_is_caught(self):
        """Die GEGENRICHTUNG der Bindung. Ein Fall, der Teilausfuehrung behauptet, ohne zu sagen was
        fehlte, liefert eine Zahl, die niemand nachrechnen kann."""
        def defekt(m):
            echt = m._DISPATCH["native_bundle"]

            def leere_behauptung(case, case_dir, **kw):
                r = echt(case, case_dir, **kw)
                r["scope"], r["skipped"] = m.PARTIAL, []
                return r
            m._DISPATCH = dict(m._DISPATCH, native_bundle=leere_behauptung)
        rc, ausgabe, _ = self._lauf(has_ots=True, defekt=defekt)
        self.assertEqual(rc, 1, "PARTIAL ohne benannten Skip muss fallen")
        self.assertIn("must name what was", ausgabe)

    def test_a_case_that_did_not_run_must_name_what_it_would_have_checked(self):
        def defekt(m):
            echt = m._DISPATCH["native_bundle"]

            def stumme_null(case, case_dir, **kw):
                r = echt(case, case_dir, **kw)
                r["scope"], r["skipped"] = m.NONE, []
                return r
            m._DISPATCH = dict(m._DISPATCH, native_bundle=stumme_null)
        rc, ausgabe, _ = self._lauf(has_ots=True, defekt=defekt)
        self.assertEqual(rc, 1, "NONE ohne benannten Skip muss fallen")
        self.assertIn("must name what was", ausgabe)

    def test_a_case_with_two_skips_is_listed_once_not_twice(self):
        """Aggregat und Detail muessen dieselbe MENGE beschreiben.

        Die erste Fassung druckte eine Zeile je SKIP-EINTRAG: ein Fall mit zwei uebersprungenen
        Teilpruefungen stand zweimal da, waehrend die Kopfzeile ihn einmal zaehlte. Zwei Ansichten,
        ein Lauf, zwei Zahlen.
        """
        def defekt(m):
            echt = m._DISPATCH["decision_crossimpl"]

            def doppelt(case, case_dir, **kw):
                r = echt(case, case_dir, **kw)
                if r.get("skipped"):
                    r["skipped"] = list(r["skipped"]) + ["zweiter-grund"]
                return r
            m._DISPATCH = dict(m._DISPATCH, decision_crossimpl=doppelt)
        rc, ausgabe, _ = self._lauf(has_ots=False, defekt=defekt)
        self.assertEqual(rc, 0, ausgabe)
        zahlen, kopf = self._zahlen(ausgabe)
        zeilen = [z for z in ausgabe.splitlines() if z.strip().startswith("- ")]
        self.assertEqual(len(zeilen), zahlen["partially checked"] + zahlen["not run"],
                         f"eine Zeile je FALL, nicht je Eintrag: {kopf}")
        self.assertIn("zweiter-grund", ausgabe, "der zweite Grund darf nicht verschwinden")

    def test_a_broken_jsonschema_falls_back_and_says_why(self):
        """P1 der cross_format-Linse: das Hochziehen des Imports machte aus einer stillen
        Herabstufung einen Absturz. Jetzt faengt eine ENGE Klammer den Laufzeitfehler, faellt auf den
        Strukturboden zurueck UND nennt den Grund — Abwesenheit und Defekt sind nicht dasselbe."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("cf_broken", _CONF / "cross_format.py")
        cf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cf)
        faelle = cf.load_cases()

        class KaputterValidator:
            def __init__(self, schema): pass
            def iter_errors(self, case):
                raise ImportError("simulated: partially installed jsonschema")
        import jsonschema  # noqa: PLC0415
        echt = jsonschema.Draft202012Validator
        try:
            jsonschema.Draft202012Validator = KaputterValidator
            probleme = cf.validate_schema(faelle)          # darf NICHT werfen
        finally:
            jsonschema.Draft202012Validator = echt
        self.assertIsInstance(probleme, list)
        self.assertFalse(cf.has_full_schema_check(),
                         "nach einem Laufzeitfehler darf der Lauf nicht als voll geprueft gelten")
        name = cf.schema_check_name()
        self.assertIn("FAILED at runtime", name)
        self.assertIn("simulated", name, "der Grund gehoert in die Meldung, nicht nur 'floor'")

    def test_require_full_schema_turns_a_reduced_precondition_into_a_failure(self):
        """P2 der Umgehungs-Linse: die Korpus-Vorpruefung hatte keinen eigenen Schalter.

        Gemessen von ihr: ein `caseId` von "" verletzt `minLength: 1` und faellt MIT jsonschema
        (rc 1), wird OHNE jsonschema durchgewunken (rc 0, "94 fully checked"). Derselbe Korpus, zwei
        Urteile, je nach Umgebung — und die annehmende Seite zaehlte jeden Fall als voll geprueft.
        `--require-anchors` schliesst diese Form eine Ebene tiefer; das hier ist ihr Gegenstueck.
        """
        import contextlib
        import importlib.util
        import io
        spec = importlib.util.spec_from_file_location("rc_fs", _CONF / "run_conformance.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        echt = m.cross_format.has_full_schema_check
        try:
            m.cross_format.has_full_schema_check = lambda: False
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc_ohne = m.run(require_full_schema=True)
            ausgabe = buf.getvalue()
            buf2 = io.StringIO()
            with contextlib.redirect_stdout(buf2):
                rc_frei = m.run(require_full_schema=False)
        finally:
            m.cross_format.has_full_schema_check = echt
        self.assertEqual(rc_ohne, 1, "mit dem Schalter muss die reduzierte Vorpruefung fallen")
        self.assertIn("NOT FULLY CHECKED", ausgabe)
        self.assertEqual(rc_frei, 0, "ohne den Schalter bleibt es beim dokumentierten Verhalten")
        self.assertIs(m.cross_format.has_full_schema_check, echt)

    def test_the_headline_accounts_for_every_case_even_when_the_floor_fires(self):
        """Gegenprobe: auch wenn der Boden einen Fall zu FAIL macht, muss die Summe aufgehen.

        Ohne diese Gegenprobe pruefte die vorige Zusicherung nur den gruenen Lauf — und ein Zaehler,
        der nur im gruenen Lauf stimmt, ist kein Zaehler.
        """
        def defekt(m):
            echt = m._DISPATCH["native_bundle"]

            def neuer_umfang(case, case_dir, **kw):
                r = echt(case, case_dir, **kw)
                r["scope"] = "degraded"      # ein Wert, den niemand registriert hat
                return r
            m._DISPATCH = dict(m._DISPATCH, native_bundle=neuer_umfang)
        rc, ausgabe, _ = self._lauf(has_ots=True, defekt=defekt)
        self.assertEqual(rc, 1, "ein unbekannter Umfangswert muss fallen")
        self.assertIn("without declaring its executed scope", ausgabe)
        zahlen, kopf = self._zahlen(ausgabe)
        self.assertEqual(zahlen["fully checked"] + zahlen["partially checked"]
                         + zahlen["not run"] + zahlen["failed"], zahlen["cases"],
                         f"auch im Fehlerfall muss die Kopfzeile jeden Fall verbuchen: {kopf}")
        self.assertNotIn("UNACCOUNTED", ausgabe)

    def test_corpus_integrity_failure_still_names_the_schema_checker(self):
        """P3 der fremden Familie: auf dem Abbruchpfad fehlte die Angabe, WER geprueft hat.

        `cross_format` ist ein GETEILTES Modul (dieselbe Instanz in sys.modules fuer jeden frisch
        geladenen Laeufer). Eine Ersetzung ohne Ruecknahme vergiftet jeden Nachbartest — beim ersten
        Schreiben dieses Falls genau so passiert, drei Nachbarn fielen.
        """
        import contextlib
        import importlib.util
        import io
        spec = importlib.util.spec_from_file_location("rc_cf", _CONF / "run_conformance.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        echt = m.cross_format.run
        try:
            m.cross_format.run = lambda *a, **k: (False, ["geplanter Integritaetsfehler"])
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = m.run()
        finally:
            m.cross_format.run = echt
        ausgabe = buf.getvalue()
        self.assertEqual(rc, 1)
        self.assertIn("corpus integrity FAIL", ausgabe)
        self.assertIn("schema checked by:", ausgabe,
                      "auch wenn der Lauf hier abbricht, muss dastehen WER den Korpus geprueft hat")
        # und die Ruecknahme muss wirken, sonst faellt der naechste Test aus DIESEM Grund
        self.assertIs(m.cross_format.run, echt)


if __name__ == "__main__":
    unittest.main()
