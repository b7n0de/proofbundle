"""PB-2026-0718-11 — the cross-format comparator is non-vacuous.

A ``crossFormatId`` claims the SAME logical scenario is represented in >= 2 encodings/levels whose declared
verdicts must agree. A SINGLETON group (one member) verifies nothing — the agreement check is vacuously
true and the comparator reports ok=true for a scenario present in only one format (the Teil-4 finding: all
6 xfmt groups were singletons yet the comparator passed). This guard pins the fix on both sides:

* the LIVE corpus has no singleton cross-format group (every id links a decision AND an outcome encoding),
  and cross_format.run() passes;
* a synthetic singleton group is a fail-closed PROBLEM, and a synthetic contradictory pair is a PROBLEM —
  the comparator cannot pass either.
"""
import importlib.util
import pathlib
import unittest

_CONF = pathlib.Path(__file__).resolve().parents[1] / "conformance"
_spec = importlib.util.spec_from_file_location("cross_format", _CONF / "cross_format.py")
_cf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_cf)


class LiveCorpusNonVacuous(unittest.TestCase):
    def test_no_singleton_cross_format_groups(self):
        groups: dict[str, int] = {}
        for _rel, case in _cf.load_cases():
            xid = case.get("crossFormatId")
            if isinstance(xid, str) and xid:
                groups[xid] = groups.get(xid, 0) + 1
        self.assertTrue(groups, "expected the corpus to declare cross-format groups")
        singletons = {x: n for x, n in groups.items() if n < 2}
        self.assertEqual(singletons, {}, f"singleton cross-format groups are vacuous: {singletons}")

    def test_corpus_cross_format_passes(self):
        ok, problems = _cf.run()
        self.assertTrue(ok, f"cross-format integrity problems: {problems}")


class SingletonAndContradictionFailClosed(unittest.TestCase):
    def _case(self, xid, expected):
        return ("synthetic/" + str(expected), {"caseId": "c", "kind": "decision_relation",
                                                "expected": expected, "crossFormatId": xid})

    def test_singleton_group_is_failclosed(self):
        # one member under an id -> vacuous -> must be a reported problem, not a silent pass
        problems = _cf.check_cross_format([self._case("xfmt-solo", {"exitCode": 0, "lineage": "VERIFIED"})])
        self.assertTrue(any("only 1 member" in p or "vacuous" in p for p in problems), problems)

    def test_contradictory_pair_is_failclosed(self):
        # two members that disagree on an axis -> the comparator must flag the contradiction
        problems = _cf.check_cross_format([
            self._case("xfmt-x", {"exitCode": 0, "lineage": "VERIFIED"}),
            self._case("xfmt-x", {"exitCode": 3, "lineage": "DECLARED_UNRESOLVED"}),
        ])
        self.assertTrue(any("disagrees" in p for p in problems), problems)

    def test_agreeing_pair_passes(self):
        problems = _cf.check_cross_format([
            self._case("xfmt-ok", {"exitCode": 0, "lineage": "VERIFIED"}),
            self._case("xfmt-ok", {"exitCode": 0, "lineage": "VERIFIED"}),
        ])
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
