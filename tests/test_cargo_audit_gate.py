"""The Rust dependency audit fails on every advisory or warning that audit.toml does not list.

Lens finding F1 on PR 296 (foxtrot, measured with cargo-audit 0.22.2): `cargo audit --deny warnings`
refuses unmaintained, unsound and yanked, and exits 0 on an informational "notice" advisory
(personnummer 0.1.0, RUSTSEC-2020-0166); `--deny notice` and `--deny all` are refused by the tool. The
rule of the step is "never exit 0 on a lock file that carries a RustSec advisory or warning it does not
list", so `scripts/cargo_audit_gate.py` judges `cargo audit --json` as well. These cases pin its
judgement on canned reports (no cargo-audit needed) and its exit codes through a stand-in for cargo; the
last case runs the script's own two-direction self-test where cargo-audit 0.22.2 and a fetched advisory
database are present, and skips elsewhere. The rust-parity job runs that self-test on every run.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("_cargo_audit_gate", REPO / "scripts" / "cargo_audit_gate.py")
g = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(g)

_NOTICE = {"kind": "notice", "package": {"name": "personnummer", "version": "0.1.0"},
           "advisory": {"id": "RUSTSEC-2020-0166"}}
_RSA = {"advisory": {"id": "RUSTSEC-2023-0071"}, "package": {"name": "rsa", "version": "0.9.10"}}


_SETTINGS = {"target_arch": [], "target_os": [], "severity": None, "ignore": [],
             "informational_warnings": ["unmaintained", "unsound", "notice"]}


def _report(vulns=(), settings=None, **warnings) -> dict:
    return {"vulnerabilities": {"found": bool(vulns), "count": len(vulns), "list": list(vulns)},
            "warnings": warnings, "settings": dict(_SETTINGS, **(settings or {}))}


class TheJudgement(unittest.TestCase):
    def test_a_clean_report_passes(self) -> None:
        self.assertEqual(g.judge(_report()), [])

    def test_a_notice_fails_unless_listed(self) -> None:
        gruende = g.judge(_report(notice=[_NOTICE]))
        self.assertEqual(len(gruende), 1)
        self.assertIn("notice RUSTSEC-2020-0166", gruende[0])
        self.assertEqual(g.judge(_report(settings={"ignore": ["RUSTSEC-2020-0166"]}, notice=[_NOTICE])), [])

    def test_every_warning_kind_fails_a_later_one_included(self) -> None:
        for art in ("unmaintained", "unsound", "notice", "informational", "a-kind-not-yet-named"):
            with self.subTest(kind=art):
                entry = dict(_NOTICE, kind=art, advisory={"id": "RUSTSEC-2099-0001"})
                bericht = _report(settings={"ignore": ["RUSTSEC-2020-0166"]}, **{art: [entry]})
                self.assertEqual(len(g.judge(bericht)), 1)

    def test_a_warning_without_an_advisory_id_cannot_be_listed(self) -> None:
        yanked = {"kind": "yanked", "package": {"name": "x", "version": "1.0.0"}, "advisory": None}
        self.assertEqual(len(g.judge(_report(settings={"ignore": ["RUSTSEC-2023-0071"]}, yanked=[yanked]))), 1)

    def test_a_vulnerability_fails_unless_listed(self) -> None:
        self.assertEqual(len(g.judge(_report([_RSA]))), 1)
        self.assertEqual(g.judge(_report([_RSA], settings={"ignore": ["RUSTSEC-2023-0071"]})), [])

    def test_an_audit_toml_that_narrows_the_report_fails(self) -> None:
        # Measured with 0.22.2: each setting hid an advisory from --json, and cargo-audit exited 0.
        for settings in ({"severity": "critical"}, {"informational_warnings": ["unmaintained"]},
                         {"informational_warnings": ["unmaintained", "unsound"]}, {"severity": "low"}):
            with self.subTest(settings=settings):
                self.assertNotEqual(g.judge(_report(settings=settings)), [])
        self.assertEqual(g.judge(_report(settings={"informational_warnings": [
            "notice", "unsound", "unmaintained", "a-later-kind"]})), [])

    def test_a_report_of_another_shape_is_an_error_never_a_pass(self) -> None:
        schlecht = [
            [], {}, {"vulnerabilities": {"count": 0, "list": []}},
            {"vulnerabilities": {"count": 1, "list": []}, "warnings": {}},
            {"vulnerabilities": {"count": True, "list": [_RSA]}, "warnings": {}},
            _report(notice=_NOTICE), _report(notice=["RUSTSEC-2020-0166"]),
            _report(notice=[dict(_NOTICE, advisory={"id": 7})]),
            {k: v for k, v in _report().items() if k != "settings"},
            _report(settings={"informational_warnings": "notice"}),
            _report(settings={"ignore": "RUSTSEC-2023-0071"}), _report(settings={"ignore": [7]}),
            {k: v for k, v in _report().items() if k != "settings"} | {"settings": {"severity": None}},
        ]
        for bericht in schlecht:
            with self.subTest(report=bericht):
                with self.assertRaises(g.GateError):
                    g.judge(bericht)


class TheListedIds(unittest.TestCase):
    """The listed IDs are the ones cargo-audit applied, `settings.ignore` of its report."""

    def test_the_listed_ids_are_the_reports_ignore_list(self) -> None:
        self.assertEqual(g.listed_ids(_report(settings={"ignore": ["RUSTSEC-2023-0071"]})),
                         {"RUSTSEC-2023-0071"})
        self.assertEqual(g.listed_ids(_report()), set())

    def test_an_ignore_list_of_another_shape_is_an_error(self) -> None:
        for ignore in ("RUSTSEC-2023-0071", [7], None, {"RUSTSEC-2023-0071": True}):
            with self.subTest(ignore=ignore):
                with self.assertRaises(g.GateError):
                    g.listed_ids(_report(settings={"ignore": ignore}))

    def test_the_checked_in_audit_toml_lists_the_one_exception(self) -> None:
        # The step's cargo-audit reads this file; its text names the one exception the report must carry.
        text = (REPO / "tools" / "pb_verify_rs" / ".cargo" / "audit.toml").read_text(encoding="utf-8")
        self.assertIn('ignore = ["RUSTSEC-2023-0071"]', text)


@unittest.skipIf(sys.platform == "win32", "the stand-in for cargo is a POSIX script")
class TheExitCodes(unittest.TestCase):
    """The gate's exit code against a stand-in for cargo that writes a chosen report and exit code."""

    def _gate(self, stdout: str, rc: int) -> tuple:
        with tempfile.TemporaryDirectory() as tmp:
            ort = Path(tmp)
            (ort / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
            cargo = ort / "cargo"
            cargo.write_text(textwrap.dedent(f"""\
                #!{sys.executable}
                import sys
                sys.stdout.write({stdout!r})
                sys.exit({rc})
                """), encoding="utf-8")
            cargo.chmod(0o755)
            lauf = subprocess.run([sys.executable, str(REPO / "scripts" / "cargo_audit_gate.py"),
                                   "--dir", str(ort), "--cargo", str(cargo)],
                                  capture_output=True, text=True, timeout=60)
            return lauf.returncode, lauf.stdout

    def test_exit_codes(self) -> None:
        faelle = [
            ("clean", json.dumps(_report()), 0, 0),
            ("notice, cargo-audit exit 0", json.dumps(_report(notice=[_NOTICE])), 0, 1),
            ("unlisted vulnerability", json.dumps(_report([_RSA])), 1, 1),
            ("cargo-audit error with a clean report", json.dumps(_report()), 2, 2),
            ("cargo-audit error without output", "", 2, 2),
            ("no JSON", "not json", 0, 2),
            ("exit 1 without a vulnerability", json.dumps(_report()), 1, 2),
        ]
        for name, ausgabe, rc, erwartet in faelle:
            with self.subTest(case=name):
                self.assertEqual(self._gate(ausgabe, rc)[0], erwartet)


def _cargo_audit_ready() -> bool:
    if shutil.which("cargo") is None or not (Path.home() / ".cargo" / "advisory-db").is_dir():
        return False
    lauf = subprocess.run(["cargo", "audit", "--version"], capture_output=True, text=True)
    return lauf.returncode == 0 and "0.22.2" in lauf.stdout


@unittest.skipUnless(_cargo_audit_ready(),
                     "needs cargo-audit 0.22.2 and a fetched advisory database (the rust-parity job has both)")
class TheSelfTestAgainstTheRealTool(unittest.TestCase):
    def test_both_directions(self) -> None:
        self.assertEqual(g.main(["--self-test", "--no-fetch"]), 0)


if __name__ == "__main__":
    unittest.main()
