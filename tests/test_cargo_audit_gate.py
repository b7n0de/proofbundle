"""The Rust dependency audit fails on every advisory or warning that audit.toml does not list.

Lens finding F1 on PR 296 (measured with cargo-audit 0.22.2): `cargo audit --deny warnings`
refuses unmaintained, unsound and yanked, and exits 0 on an informational "notice" advisory
(personnummer 0.1.0, RUSTSEC-2020-0166); `--deny notice` and `--deny all` are refused by the tool. The
rule of the step is "never exit 0 on a lock file that carries a RustSec advisory or warning it does not
list", so `scripts/cargo_audit_gate.py` judges `cargo audit --json` as well. These cases pin its
judgement on canned reports (no cargo-audit needed) and its exit codes through a stand-in for cargo; the
last case runs the script's own two-direction self-test where cargo-audit 0.22.2 and a fetched advisory
database are present, and skips elsewhere. The rust-parity job runs that self-test on every run.

The lens run on PR 296 at 5138b4d2 found three more ways the whole step exited 0 (F1 to F3 below): a
crates.io package in the sparse source spelling was never checked, an audit.toml key other than the
ignore list hid advisories, and a yanked lookup that failed read as a clean report. Their cases run the
gate against a stand-in for cargo that models what cargo-audit 0.22.2 was measured to do.
"""
from __future__ import annotations

import importlib.util
import json
import os
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


#: A stand-in for cargo that models what cargo-audit 0.22.2 was measured to do (rustsec 0.33.0):
#: an advisory matches a package only when the lock names it with the crates.io source in the
#: spelling rustsec knows, the git index; `--json` writes nothing to stderr, even when the yanked
#: lookup fails; the terminal run writes its progress, a failed lookup and a summary to stderr.
#: The test chooses the rest through the JSON in GATE_STAND_IN.
_STAND_IN = r"""
import json, os, sys
spec = json.loads(os.environ["GATE_STAND_IN"])
args = sys.argv[1:]
with open(args[args.index("--file") + 1], encoding="utf-8") as fh:
    lock = fh.read()
vulns = []
for name, version, advisory in spec.get("vulnerable", []):
    block = ('name = "%s"\nversion = "%s"\n'
             'source = "registry+https://github.com/rust-lang/crates.io-index"\n' % (name, version))
    if block in lock:
        vulns.append({"advisory": {"id": advisory}, "package": {"name": name, "version": version}})
warnings = spec.get("warnings", {})
settings = {"target_arch": [], "target_os": [], "severity": None, "ignore": [],
            "informational_warnings": ["unmaintained", "unsound", "notice"]}
settings.update(spec.get("settings", {}))
if "--json" in args:
    sys.stderr.write("".join(z + "\n" for z in spec.get("json_stderr", [])))
    sys.stdout.write(json.dumps({"vulnerabilities": {"found": bool(vulns), "count": len(vulns), "list": vulns},
                                 "warnings": warnings, "settings": settings}))
else:
    zeilen = ["      Loaded 1271 security advisories (from /stand-in/advisory-db)"]
    zeilen += spec.get("terminal_stderr", [])
    zeilen.append("    Scanning Cargo.lock for vulnerabilities (1 crate dependencies)")
    if vulns:
        zeilen.append("error: %d vulnerabilit%s found!" % (len(vulns), "y" if len(vulns) == 1 else "ies"))
    n = spec.get("terminal_warnings", sum(len(v) for v in warnings.values()))
    if n:
        zeilen.append("warning: %d allowed warning%s found" % (n, "" if n == 1 else "s"))
    sys.stderr.write("".join(z + "\n" for z in zeilen))
sys.exit(1 if vulns else 0)
"""

_CRATES_IO_GIT = "registry+https://github.com/rust-lang/crates.io-index"


def _lock(*pakete) -> str:
    text = "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n"
    for name, version, source in pakete:
        text += f'\n[[package]]\nname = "{name}"\nversion = "{version}"\nsource = "{source}"\n'
    return text


def _run_gate(lock: str, spec: dict, audit_toml: str | None = None, config_toml: str | None = None) -> tuple:
    """(exit code, stdout) of the gate on `lock` against the stand-in; CARGO_HOME is an empty directory."""
    with tempfile.TemporaryDirectory() as tmp:
        ort = Path(tmp) / "work"
        (ort / ".cargo").mkdir(parents=True)
        (ort / "Cargo.lock").write_text(lock, encoding="utf-8")
        if audit_toml is not None:
            (ort / ".cargo" / "audit.toml").write_text(audit_toml, encoding="utf-8")
        if config_toml is not None:
            (ort / ".cargo" / "config.toml").write_text(config_toml, encoding="utf-8")
        cargo = Path(tmp) / "cargo"
        cargo.write_text(f"#!{sys.executable}\n" + _STAND_IN, encoding="utf-8")
        cargo.chmod(0o755)
        (Path(tmp) / "cargo-home").mkdir()
        env = dict(os.environ, GATE_STAND_IN=json.dumps(spec), CARGO_HOME=str(Path(tmp) / "cargo-home"))
        lauf = subprocess.run([sys.executable, str(REPO / "scripts" / "cargo_audit_gate.py"),
                               "--dir", str(ort), "--cargo", str(cargo)],
                              capture_output=True, text=True, timeout=60, env=env)
        return lauf.returncode, lauf.stdout + lauf.stderr


_COMMITTED_TOML = (REPO / "tools" / "pb_verify_rs" / ".cargo" / "audit.toml").read_text(encoding="utf-8")
_LISTED = {"settings": {"ignore": ["RUSTSEC-2023-0071"]}}


@unittest.skipIf(sys.platform == "win32", "the stand-in for cargo is a POSIX script")
class F1EveryLockSourceIsAudited(unittest.TestCase):
    """PROPERTY (lens run on PR 296 at 5138b4d2, F1, P1): the gate never passes a lock whose packages
    the audit did not check. rustsec 0.33.0 matches an advisory to a crates.io package only in the
    source spelling of the git index, so smallvec 1.6.0 (RUSTSEC-2021-0003) under
    `sparse+https://index.crates.io/` was never checked and the whole step exited 0. A crates.io
    package in either spelling cargo writes is audited; a package from any other source fails the gate."""

    def test_f1_control_the_git_spelling_is_caught(self) -> None:
        spec = {"vulnerable": [["smallvec", "1.6.0", "RUSTSEC-2021-0003"]]}
        rc, ausgabe = _run_gate(_lock(("smallvec", "1.6.0", _CRATES_IO_GIT)), spec)
        self.assertEqual(rc, 1, ausgabe)
        self.assertIn("RUSTSEC-2021-0003", ausgabe)

    def test_f1_the_sparse_spelling_is_audited_as_crates_io(self) -> None:
        spec = {"vulnerable": [["smallvec", "1.6.0", "RUSTSEC-2021-0003"]]}
        rc, ausgabe = _run_gate(_lock(("smallvec", "1.6.0", "sparse+https://index.crates.io/")), spec)
        self.assertEqual(rc, 1, ausgabe)
        self.assertIn("RUSTSEC-2021-0003", ausgabe)

    def test_f1_a_source_other_than_crates_io_fails_the_gate(self) -> None:
        for source in ("git+https://github.com/servo/rust-smallvec?tag=v1.6.0#0123456789abcdef0123456789abcdef01234567",
                       "registry+https://example.com/index", "sparse+https://example.com/index/",
                       "sparse+https://index.crates.io", "registry+https://github.com/rust-lang/crates.io-index.git"):
            with self.subTest(source=source):
                rc, ausgabe = _run_gate(_lock(("smallvec", "1.6.0", source)), {})
                self.assertEqual(rc, 1, ausgabe)
                self.assertIn(source, ausgabe)


@unittest.skipIf(sys.platform == "win32", "the stand-in for cargo is a POSIX script")
class F2AuditTomlCarriesOnlyTheIgnoreList(unittest.TestCase):
    """PROPERTY (lens run on PR 296 at 5138b4d2, F2, P1): audit.toml can only list exceptions. Keys
    such as `[target] os`, `[database] url`, `path` or `stale` and `[yanked] enabled = false` hide
    advisories without naming one (grep-cli 0.1.5 beside audit.toml plus `[target] os = ["linux"]`:
    cargo-audit exit 0, vulnerabilities 0). audit.toml may carry `[advisories] ignore` and nothing
    else; any other table or key is refused with its name."""

    def test_f2_control_the_committed_file_passes(self) -> None:
        rc, ausgabe = _run_gate(_lock(), _LISTED, audit_toml=_COMMITTED_TOML)
        self.assertEqual(rc, 0, ausgabe)

    def test_f2_any_other_table_or_key_is_refused(self) -> None:
        for zusatz, name in (('[target]\nos = ["linux"]\n', "target"), ('[target]\narch = ["x86_64"]\n', "target"),
                             ('[database]\nurl = "https://example.com/advisory-db.git"\n', "database"),
                             ('[database]\npath = "/tmp/advisory-db"\n', "database"),
                             ("[database]\nstale = true\n", "database"), ("[yanked]\nenabled = false\n", "yanked"),
                             ("[output]\nquiet = true\n", "output"),
                             ('severity_threshold = "critical"\n', "severity_threshold"),
                             ('informational_warnings = ["unmaintained"]\n', "informational_warnings"),
                             ('target.os = ["linux"]\n', "target.os")):
            with self.subTest(extra=zusatz):
                rc, ausgabe = _run_gate(_lock(), _LISTED, audit_toml=_COMMITTED_TOML + zusatz)
                self.assertEqual(rc, 1, ausgabe)
                self.assertIn(name, ausgabe)


class TheAuditTomlReader(unittest.TestCase):
    """`audit_toml_ignore` reads the list and refuses everything else, line by line."""

    def test_the_committed_file(self) -> None:
        self.assertEqual(g.audit_toml_ignore(_COMMITTED_TOML), (["RUSTSEC-2023-0071"], []))

    def test_a_list_over_several_lines_with_comments(self) -> None:
        text = ('# head\n[advisories]\nignore = [\n  "RUSTSEC-2023-0071", # rsa\n  "RUSTSEC-2020-0166",\n]\n'
                "# tail\n")
        self.assertEqual(g.audit_toml_ignore(text), (["RUSTSEC-2023-0071", "RUSTSEC-2020-0166"], []))
        self.assertEqual(g.audit_toml_ignore(""), ([], []))

    def test_an_id_that_is_no_advisory_id_is_refused(self) -> None:
        ids, gruende = g.audit_toml_ignore('[advisories]\nignore = ["GHSA-xxxx-xxxx-xxxx"]\n')
        self.assertEqual(len(gruende), 1)
        self.assertIn("GHSA-xxxx-xxxx-xxxx", gruende[0])

    def test_a_list_of_another_shape_is_an_error(self) -> None:
        for text in ('[advisories]\nignore = [\n"RUSTSEC-2023-0071",\n', '[advisories]\nignore = [RUSTSEC-2023-0071]\n'):
            with self.subTest(text=text):
                with self.assertRaises(g.GateError):
                    g.audit_toml_ignore(text)

    @unittest.skipIf(sys.platform == "win32", "the stand-in for cargo is a POSIX script")
    def test_the_applied_list_must_be_the_files_list(self) -> None:
        # cargo-audit reports an ignore list the file does not state: some other configuration applied.
        rc, ausgabe = _run_gate(_lock(), {"settings": {"ignore": []}}, audit_toml=_COMMITTED_TOML)
        self.assertEqual(rc, 2, ausgabe)


@unittest.skipIf(sys.platform == "win32", "the stand-in for cargo is a POSIX script")
class F3ALookupErrorIsNeverAPass(unittest.TestCase):
    """PROPERTY (lens run on PR 296 at 5138b4d2, F3, P1): a lookup cargo-audit could not make is an
    error of the audit, exit 2, never 0. With `protocol = "git"` in .cargo/config.toml the yanked
    libc 0.2.165 was reported clean: measured with 0.22.2, `--json` writes nothing to stderr and no
    yanked warning, and the terminal run writes `warning: couldn't open crates.io index: ...` to stderr.
    The gate read only the JSON run's stdout."""

    _LIBC = _lock(("libc", "0.2.165", _CRATES_IO_GIT))

    def test_f3_control_a_clean_run_passes(self) -> None:
        rc, ausgabe = _run_gate(self._LIBC, {"terminal_stderr": ["    Updating crates.io index"]})
        self.assertEqual(rc, 0, ausgabe)

    def test_f3_a_failed_lookup_ends_the_gate_with_2(self) -> None:
        for zeile in ("warning: couldn't open crates.io index: registry: the url "
                      "'https://github.com/rust-lang/crates.io-index' is invalid",
                      "error: couldn't check if the package is yanked: not found: No such crate in crates.io "
                      "index: libc"):
            for wo in ("terminal_stderr", "json_stderr"):
                with self.subTest(line=zeile[:40], stream=wo):
                    rc, ausgabe = _run_gate(self._LIBC, {wo: [zeile]}, config_toml='[registries.crates-io]\nprotocol = "git"\n')
                    self.assertEqual(rc, 2, ausgabe)

    def test_f3_the_json_run_and_the_terminal_run_agree(self) -> None:
        # The terminal run found a warning the JSON run does not carry: the two runs did not see the same
        # lookups, and the JSON run is the one judged.
        rc, ausgabe = _run_gate(self._LIBC, {"terminal_warnings": 1})
        self.assertEqual(rc, 2, ausgabe)


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
