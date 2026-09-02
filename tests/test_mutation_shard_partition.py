"""The shard partition and the CLI contract of mutation_check.

Both defects these tests cover were found by CI, not by me, and both are the same class: a new
parameter that quietly changed an existing contract.

1. ``main()`` called with no arguments passed ``None`` to ``parse_args``, and argparse reads
   ``sys.argv`` for ``None`` -- under pytest, that is pytest's own flags, and the run died with
   ``SystemExit(2)``. ``parse_args(None)`` is not ``parse_args([])``.
2. The sharded call passed ``shard=`` unconditionally, which broke the test stubs that replace
   ``_run_operators`` with a function that has no such parameter.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("_mc", ROOT / "scripts" / "mutation_check.py")
mc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mc)


class ThePartitionIsGaplessAndDeterministic(unittest.TestCase):
    def test_every_operator_lands_in_exactly_one_shard(self):
        n = len(mc.MUTATIONS)
        for k in (1, 2, 3, 8, 10, 16, n):
            parts = [set(mc.partition(n, i, k)) for i in range(1, k + 1)]
            union = set().union(*parts)
            self.assertEqual(union, set(range(n)), f"K={k}: the union has a gap")
            self.assertEqual(sum(len(p) for p in parts), n, f"K={k}: shards overlap")

    def test_the_same_arguments_give_the_same_shard(self):
        self.assertEqual(mc.partition(88, 3, 10), mc.partition(88, 3, 10))

    def test_shards_are_balanced_within_one(self):
        sizes = [len(mc.partition(88, i, 10)) for i in range(1, 11)]
        self.assertLessEqual(max(sizes) - min(sizes), 1, f"unbalanced: {sizes}")

    def test_round_robin_not_blockwise(self):
        """Operators are grouped by file; a block would hand one shard every expensive one."""
        first = mc.partition(88, 1, 10)
        self.assertNotEqual(first, list(range(len(first))), "this looks blockwise, not round-robin")

    def test_an_index_outside_the_range_is_refused(self):
        for i, k in ((0, 10), (11, 10), (-1, 10)):
            with self.assertRaises(ValueError):
                mc.partition(88, i, k)

    def test_k_equal_to_n_gives_one_operator_each(self):
        n = len(mc.MUTATIONS)
        self.assertTrue(all(len(mc.partition(n, i, n)) == 1 for i in range(1, n + 1)))


class TheCliContractHolds(unittest.TestCase):
    def test_main_with_no_arguments_does_not_read_sys_argv(self):
        """The defect CI found: parse_args(None) reads sys.argv, which under pytest is its flags."""
        gerufen = {}

        def stub(work):
            gerufen["shard"] = "not passed"
            return 0

        echt_run, echt_prep, echt_status = mc._run_operators, mc._prepare_workdir, mc._worktree_status
        mc._run_operators = stub
        mc._prepare_workdir = lambda root, work: None
        mc._worktree_status = lambda root: ""
        alt_argv = sys.argv
        sys.argv = ["pytest", "-q", "--tb=short", "tests/"]
        try:
            rc = mc.main()
        finally:
            sys.argv = alt_argv
            mc._run_operators, mc._prepare_workdir, mc._worktree_status = echt_run, echt_prep, echt_status
        self.assertEqual(rc, 0)
        self.assertEqual(gerufen["shard"], "not passed")

    def test_the_unsharded_call_keeps_the_old_signature(self):
        """A stub without a shard parameter must still work; that is the existing contract."""
        echt_run, echt_prep, echt_status = mc._run_operators, mc._prepare_workdir, mc._worktree_status
        mc._run_operators = lambda work: 0
        mc._prepare_workdir = lambda root, work: None
        mc._worktree_status = lambda root: ""
        try:
            self.assertEqual(mc.main([]), 0)
        finally:
            mc._run_operators, mc._prepare_workdir, mc._worktree_status = echt_run, echt_prep, echt_status

    def test_a_malformed_shard_argument_is_refused(self):
        for bad in ("1", "1/", "/10", "a/b", "0/10", "11/10"):
            with self.assertRaises(SystemExit, msg=f"--shard {bad} should be refused"):
                mc.main(["--shard", bad])


if __name__ == "__main__":
    unittest.main()
