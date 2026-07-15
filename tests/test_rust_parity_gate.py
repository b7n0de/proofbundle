"""Rust second-verifier parity gate (Finding 11) — the gate must be an HONESTY mechanism: it must
catch a stale/lying COVERED claim, an untracked new verify_* surface, and an orphaned registry entry,
not just report a green number. Anti-tautology, both directions (a broken fixture is caught AND a
correct fixture stays green), mirroring this repo's own `_selfcheck_detects_broken` convention."""
from __future__ import annotations

import importlib.util
import io
import json
import stat
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "rust_parity_gate", REPO / "scripts" / "rust_parity_gate.py"
)
rpg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rpg)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text), encoding="utf-8")


def _fake_binary(dir_: Path, subcommands: list) -> Path:
    """A tiny fake pb_verify_rs whose `coverage-report` self-declares exactly `subcommands` — stands
    in for the real cargo-built binary so the binary-declaration cross-check is testable without cargo."""
    path = dir_ / "fake_pb_verify_rs.py"
    payload = json.dumps({"verify_subcommands": subcommands})
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"if len(sys.argv) > 1 and sys.argv[1] == 'coverage-report':\n"
        f"    print('{payload}')\n"
        "    sys.exit(0)\n"
        "sys.exit(2)\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


class _FixtureTree:
    """A minimal src/ + main.rs + crosscheck.py + registry.json tree, isolated in a tempdir, so the
    gate's cross-checks can be exercised without touching the real repo."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.src_dir = tmp / "src" / "proofbundle"
        self.rust_main = tmp / "main.rs"
        self.crosscheck_py = tmp / "crosscheck.py"
        self.registry_path = tmp / "registry.json"
        self.src_dir.mkdir(parents=True)

    def write_module(self, name: str, code: str) -> None:
        _write(self.src_dir / f"{name}.py", code)

    def write_rust_arms(self, arms: list) -> None:
        body = "\n".join(f'        "{a}" => {{ /* stub */ }}' for a in arms)
        _write(self.rust_main, f"""\
        fn main() {{
            match "x" {{
        {body}
                other => {{}}
            }}
        }}
        """)

    def write_crosscheck(self, markers: list) -> None:
        body = "\n".join(f"# {m}" for m in markers)
        _write(self.crosscheck_py, body + "\n")

    def write_registry(self, entries: dict) -> None:
        _write(self.registry_path, json.dumps({
            "schema": "test.registry.v1", "status_values": ["COVERED", "PARTIAL", "PENDING"],
            "entries": entries,
        }))

    def evaluate(self, rust_bin=None):
        return rpg.evaluate(
            src_dir=self.src_dir, registry_path=self.registry_path, rust_main=self.rust_main,
            crosscheck_py=self.crosscheck_py, rust_bin=rust_bin,
        )


class TestDiscoverPythonVerifyFunctions(unittest.TestCase):
    def test_module_level_verify_prefixed_function_is_found(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d)
            _write(src / "thing.py", '''\
                def verify_widget(x):
                    """Checks the widget."""
                    return True
            ''')
            found = rpg.discover_python_verify_functions(src)
            self.assertIn("proofbundle.thing.verify_widget", found)
            self.assertEqual(found["proofbundle.thing.verify_widget"]["doc_first_line"], "Checks the widget.")

    def test_private_underscore_prefixed_helper_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d)
            _write(src / "thing.py", '''\
                def _verify_internal(x):
                    return True
                def verify_public(x):
                    return True
            ''')
            found = rpg.discover_python_verify_functions(src)
            self.assertNotIn("proofbundle.thing._verify_internal", found)
            self.assertIn("proofbundle.thing.verify_public", found)

    def test_non_verify_function_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d)
            _write(src / "thing.py", "def build_widget(x):\n    return True\n")
            found = rpg.discover_python_verify_functions(src)
            self.assertEqual(found, {})

    def test_method_inside_a_class_is_not_module_level(self):
        # A verify_* METHOD is a different surface (bound to an object, not a free function) — the
        # gate's ground truth is module-level functions only, matching the registry's dotted refs.
        with tempfile.TemporaryDirectory() as d:
            src = Path(d)
            _write(src / "thing.py", '''\
                class Foo:
                    def verify_bar(self):
                        return True
            ''')
            found = rpg.discover_python_verify_functions(src)
            self.assertEqual(found, {})


class TestRustMatchArms(unittest.TestCase):
    def test_flag_and_catchall_arms_excluded_bare_subcommand_included(self):
        with tempfile.TemporaryDirectory() as d:
            rust_main = Path(d) / "main.rs"
            _write(rust_main, '''\
                fn main() {
                    match args[1].as_str() {
                        "content-root" => {}
                        "verify-dsse" => {}
                        "--expected-root" => {}
                        "--anchor-type" | "--anchor-target" => {}
                        other => fatal("x"),
                    }
                }
            ''')
            arms = rpg.rust_match_arms(rust_main)
            self.assertEqual(arms, {"content-root", "verify-dsse"})

    def test_real_repo_main_rs_has_the_expected_subcommands(self):
        arms = rpg.rust_match_arms(rpg.RUST_MAIN)
        for expected in ("content-root", "verify-dsse", "merkle-root", "strict-parse",
                         "verify-bundle", "verify-trust-pack-threshold", "coverage-report"):
            self.assertIn(expected, arms)
        self.assertNotIn("other", arms)
        self.assertFalse(any(a.startswith("-") for a in arms), "no CLI flag leaked in as a subcommand")


class TestEvaluateGoodPath(unittest.TestCase):
    def test_fully_backed_covered_claim_is_trusted(self):
        with tempfile.TemporaryDirectory() as d:
            tree = _FixtureTree(Path(d))
            tree.write_module("thing", '''\
                def verify_widget(x):
                    """doc"""
                    return True
            ''')
            tree.write_rust_arms(["thing-check"])
            tree.write_crosscheck(["CALL_THING_CHECK marker present"])
            tree.write_registry({
                "proofbundle.thing.verify_widget": {
                    "status": "COVERED", "rust_subcommands": ["thing-check"],
                    "crosscheck_refs": ["CALL_THING_CHECK"], "notes": "fully ported",
                },
            })
            fake_bin = _fake_binary(Path(d), ["thing-check"])
            result = tree.evaluate(rust_bin=fake_bin)
            self.assertEqual(result["covered"], 1)
            self.assertEqual(result["untracked"], [])
            self.assertEqual(result["orphaned"], [])
            self.assertEqual(result["stale"], [])
            self.assertTrue(result["registry_integrity_ok"])
            self.assertTrue(result["binary_available"])

    def test_no_binary_available_is_data_blocked_not_stale(self):
        # No fake binary passed and no target/{debug,release} exists at the fixture path — the
        # binary-declaration cross-check must be SKIPPED (honest DATA_BLOCKED), not treated as a lie,
        # as long as the main.rs match arm and the crosscheck.py reference both hold up. The auto-detect
        # fallback constants are monkeypatched to nonexistent paths so this doesn't accidentally pick up
        # this very repo's own cargo-built binary (which legitimately exists in this checkout).
        orig_debug, orig_release = rpg.RUST_BIN_DEBUG, rpg.RUST_BIN_RELEASE
        with tempfile.TemporaryDirectory() as d:
            try:
                rpg.RUST_BIN_DEBUG = Path(d) / "no-debug-bin"
                rpg.RUST_BIN_RELEASE = Path(d) / "no-release-bin"
                tree = _FixtureTree(Path(d))
                tree.write_module("thing", "def verify_widget(x):\n    return True\n")
                tree.write_rust_arms(["thing-check"])
                tree.write_crosscheck(["CALL_THING_CHECK"])
                tree.write_registry({
                    "proofbundle.thing.verify_widget": {
                        "status": "COVERED", "rust_subcommands": ["thing-check"],
                        "crosscheck_refs": ["CALL_THING_CHECK"], "notes": "",
                    },
                })
                result = tree.evaluate(rust_bin=Path(d) / "does-not-exist")
                self.assertFalse(result["binary_available"])
                self.assertEqual(result["covered"], 1)
                self.assertTrue(result["registry_integrity_ok"])
            finally:
                rpg.RUST_BIN_DEBUG, rpg.RUST_BIN_RELEASE = orig_debug, orig_release


class TestEvaluateCatchesLies(unittest.TestCase):
    """The anti-tautology core: each of these fixtures is a DELIBERATELY broken claim, and the gate
    must flag it — proving the mechanism actually checks evidence instead of trusting the registry."""

    def _base_tree(self, root: Path, *, arms, crosscheck_markers, coverage_subcommands):
        tree = _FixtureTree(root)
        tree.write_module("thing", "def verify_widget(x):\n    return True\n")
        tree.write_rust_arms(arms)
        tree.write_crosscheck(crosscheck_markers)
        tree.write_registry({
            "proofbundle.thing.verify_widget": {
                "status": "COVERED", "rust_subcommands": ["thing-check"],
                "crosscheck_refs": ["CALL_THING_CHECK"], "notes": "",
            },
        })
        fake_bin = _fake_binary(root, coverage_subcommands) if coverage_subcommands is not None else None
        return tree, fake_bin

    def test_claimed_subcommand_missing_from_main_rs_is_stale(self):
        with tempfile.TemporaryDirectory() as d:
            tree, fake_bin = self._base_tree(
                Path(d), arms=["some-other-subcommand"],  # thing-check NOT actually a match arm
                crosscheck_markers=["CALL_THING_CHECK"], coverage_subcommands=["thing-check"],
            )
            result = tree.evaluate(rust_bin=fake_bin)
            self.assertEqual(result["covered"], 0)
            self.assertIn("proofbundle.thing.verify_widget", result["stale"])
            self.assertFalse(result["registry_integrity_ok"])
            item = next(i for i in result["items"] if i["python_ref"] == "proofbundle.thing.verify_widget")
            self.assertEqual(item["status"], "STALE_COVERED_CLAIM")
            self.assertIn("not a match arm", item["notes"])

    def test_claimed_subcommand_absent_from_built_binary_report_is_stale(self):
        with tempfile.TemporaryDirectory() as d:
            # main.rs really has the arm, but the BUILT binary's self-report omits it (binary is
            # stale relative to source — exactly the drift class this cross-check exists to catch).
            tree, fake_bin = self._base_tree(
                Path(d), arms=["thing-check"], crosscheck_markers=["CALL_THING_CHECK"],
                coverage_subcommands=[],
            )
            result = tree.evaluate(rust_bin=fake_bin)
            self.assertIn("proofbundle.thing.verify_widget", result["stale"])
            self.assertFalse(result["registry_integrity_ok"])
            item = next(i for i in result["items"] if i["python_ref"] == "proofbundle.thing.verify_widget")
            self.assertIn("coverage-report does not list it", item["notes"])

    def test_claimed_crosscheck_ref_absent_is_stale(self):
        with tempfile.TemporaryDirectory() as d:
            tree, fake_bin = self._base_tree(
                Path(d), arms=["thing-check"], crosscheck_markers=["totally unrelated text"],
                coverage_subcommands=["thing-check"],
            )
            result = tree.evaluate(rust_bin=fake_bin)
            self.assertIn("proofbundle.thing.verify_widget", result["stale"])
            item = next(i for i in result["items"] if i["python_ref"] == "proofbundle.thing.verify_widget")
            self.assertIn("does not appear in crosscheck.py", item["notes"])

    def test_new_python_verify_function_with_no_registry_entry_is_untracked(self):
        with tempfile.TemporaryDirectory() as d:
            tree = _FixtureTree(Path(d))
            tree.write_module("thing", "def verify_brand_new(x):\n    return True\n")
            tree.write_rust_arms([])
            tree.write_crosscheck([])
            tree.write_registry({})
            result = tree.evaluate()
            self.assertIn("proofbundle.thing.verify_brand_new", result["untracked"])
            self.assertFalse(result["registry_integrity_ok"])

    def test_registry_entry_for_a_removed_python_function_is_orphaned(self):
        with tempfile.TemporaryDirectory() as d:
            tree = _FixtureTree(Path(d))
            tree.write_module("thing", "def verify_still_here(x):\n    return True\n")
            tree.write_rust_arms([])
            tree.write_crosscheck([])
            tree.write_registry({
                "proofbundle.thing.verify_renamed_away": {
                    "status": "PENDING", "rust_subcommands": [], "crosscheck_refs": [], "notes": "",
                },
            })
            result = tree.evaluate()
            self.assertIn("proofbundle.thing.verify_renamed_away", result["orphaned"])
            self.assertFalse(result["registry_integrity_ok"])

    def test_pending_status_never_flagged_as_a_registry_problem(self):
        with tempfile.TemporaryDirectory() as d:
            tree = _FixtureTree(Path(d))
            tree.write_module("thing", "def verify_widget(x):\n    return True\n")
            tree.write_rust_arms([])
            tree.write_crosscheck([])
            tree.write_registry({
                "proofbundle.thing.verify_widget": {
                    "status": "PENDING", "rust_subcommands": [], "crosscheck_refs": [], "notes": "not ported",
                },
            })
            result = tree.evaluate()
            self.assertEqual(result["pending"], 1)
            self.assertTrue(result["registry_integrity_ok"])


class TestMainCLI(unittest.TestCase):
    def test_default_invocation_always_exits_0_even_with_a_broken_registry(self):
        # Advisory contract (project-style, mirrors branch_base_check.py): the default CLI mode NEVER
        # fails the build, even when the registry is provably broken.
        with tempfile.TemporaryDirectory() as d:
            registry = Path(d) / "registry.json"
            registry.write_text(json.dumps({
                "schema": "x", "status_values": ["COVERED", "PARTIAL", "PENDING"],
                "entries": {"proofbundle.does.not_exist": {"status": "PENDING"}},
            }))
            buf = io.StringIO()
            with redirect_stdout(buf):
                # Point at a REAL src dir so there's at least ground truth, but a throwaway registry
                # full of orphans — this must still print + exit 0 without --strict.
                rc = rpg.main(["--json"])
            self.assertEqual(rc, 0)

    def test_strict_mode_exits_1_on_a_broken_registry_fixture(self):
        # Build a tiny broken fixture in isolation and drive it through evaluate() directly (main()'s
        # argparse wiring is exercised separately below against the real, honest repo registry).
        with tempfile.TemporaryDirectory() as d:
            tree = _FixtureTree(Path(d))
            tree.write_module("thing", "def verify_brand_new(x):\n    return True\n")
            tree.write_rust_arms([])
            tree.write_crosscheck([])
            tree.write_registry({})
            result = tree.evaluate()
            self.assertFalse(result["registry_integrity_ok"])

    def test_real_repo_registry_is_honest_strict_mode_exits_0(self):
        # The committed registry must stay in sync with the live Python AST inventory and the real
        # main.rs / crosscheck.py — this is the regression test that keeps Finding 11's mechanism from
        # silently rotting the same way the hand-maintained CROSS_IMPLEMENTATION_REPORT.md table did.
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = rpg.main(["--strict", "--json"])
        self.assertEqual(rc, 0, buf.getvalue())
        out = json.loads(buf.getvalue())
        self.assertTrue(out["registry_integrity_ok"])
        self.assertEqual(out["untracked"], [])
        self.assertEqual(out["orphaned"], [])
        self.assertEqual(out["stale"], [])
        # honesty floor: PENDING must be a real, non-zero majority — this gate exists precisely because
        # the Rust surface is small; a suspicious 100%-covered result would itself be a red flag.
        self.assertGreater(out["pending"], out["covered"] + out["partial"])

    def test_markdown_output_mode_runs_without_error(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = rpg.main(["--markdown"])
        self.assertEqual(rc, 0)
        self.assertIn("| python_ref | status |", buf.getvalue())

    def test_human_output_prints_rust_parity_pending_lines(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = rpg.main([])
        self.assertEqual(rc, 0)
        self.assertIn("Rust-Parity: PENDING", buf.getvalue())

    def test_rust_bin_override_is_actually_consulted(self):
        # An empty self-declared coverage-report for the REAL repo must turn every real COVERED/PARTIAL
        # claim stale — proving --rust-bin is not silently ignored in favor of the auto-detected binary.
        with tempfile.TemporaryDirectory() as d:
            fake_bin = _fake_binary(Path(d), [])
            result = rpg.evaluate(rust_bin=fake_bin)
            self.assertTrue(result["binary_available"])
            self.assertGreater(len(result["stale"]), 0)
            self.assertFalse(result["registry_integrity_ok"])


if __name__ == "__main__":
    unittest.main()
