"""The Rust dependency audit fails on every advisory or warning that audit.toml does not list.

Lens finding F1 on PR 296 (measured with cargo-audit 0.22.2): `cargo audit --deny warnings`
refuses unmaintained, unsound and yanked, and exits 0 on an informational "notice" advisory
(personnummer 0.1.0, RUSTSEC-2020-0166); `--deny notice` and `--deny all` are refused by the tool. The
rule of the step is "never exit 0 on a lock file that carries a RustSec advisory or warning it does not
list", so `scripts/cargo_audit_gate.py` judges `cargo audit --json` as well. These cases pin its
judgement on canned reports (no cargo-audit needed) and its exit codes through a stand-in for cargo; the
last case runs the script's own self-test (every case, F1 to F3 included) where cargo-audit 0.22.2 and a fetched advisory
database are present, and skips elsewhere. The rust-parity job runs that self-test on every run.

The lens run on PR 296 at 5138b4d2 found three more ways the whole step exited 0 (F1 to F3 below): a
crates.io package in the sparse source spelling was never checked, an audit.toml key other than the
ignore list hid advisories, and a yanked lookup that failed read as a clean report. Their cases run the
gate against a stand-in for cargo that models what cargo-audit 0.22.2 was measured to do.

The lens verdict on PR 296 at d30f236e found C3: the gate alone, called with --no-fetch against an
advisory database with no advisories in it, printed OK and exited 0 on a lock holding
curve25519-dalek 4.1.2, which the fetched database fails with RUSTSEC-2024-0344. The step fetches
right before the gate, so the whole step did not reach that state; the gate did. Its cases give the
stand-in and the real tool a database the test builds: a git work tree with a fetch marker, in the
form cargo-audit 0.22.2 leaves one after a fetch.
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
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("_cargo_audit_gate", REPO / "scripts" / "cargo_audit_gate.py")
g = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(g)

_NOTICE = {"kind": "notice", "package": {"name": "personnummer", "version": "0.1.0"},
           "advisory": {"id": "RUSTSEC-2020-0166"}}
_RSA = {"advisory": {"id": "RUSTSEC-2023-0071"}, "package": {"name": "rsa", "version": "0.9.10"}}


_SETTINGS = {"target_arch": [], "target_os": [], "severity": None, "ignore": [],
             "informational_warnings": ["unmaintained", "unsound", "notice"]}


#: The `database` object of `cargo audit --json`, as 0.22.2 writes it under --no-fetch (measured against
#: advisory-db e2111519: the count of the advisories it loaded, and null for the commit and the time,
#: which rustsec 0.33.0 fills only on a fetch).
_DATABASE = {"advisory-count": 1271, "last-commit": None, "last-updated": None}


def _report(vulns=(), settings=None, **warnings) -> dict:
    return {"database": dict(_DATABASE),
            "vulnerabilities": {"found": bool(vulns), "count": len(vulns), "list": list(vulns)},
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


_GIT = shutil.which("git")
_NO_STAND_IN = sys.platform == "win32" or _GIT is None
_WHY_NO_STAND_IN = ("the stand-in for cargo is a POSIX script, and the advisory database the gate reads is a git "
                    "repository")
_ADVISORY_DB_URL = "https://github.com/RustSec/advisory-db.git"


def _git(db: Path, *args: str, when: float | None = None) -> str:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_AUTHOR_NAME="advisory database", GIT_AUTHOR_EMAIL="db@example.invalid",
               GIT_COMMITTER_NAME="advisory database", GIT_COMMITTER_EMAIL="db@example.invalid")
    if when is not None:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = f"@{int(when)} +0000"
    lauf = subprocess.run(["git", "-c", "commit.gpgsign=false", "-C", str(db), *args], capture_output=True,
                          text=True, env=env, timeout=60, check=True)
    return lauf.stdout.strip()


def _database(home: Path, fetched_ago: float = 0.0, commit_ago: float = 0.0, marker: str | None = "head") -> Path:
    """An advisory database in the form cargo-audit 0.22.2 leaves one after a fetch, under `home`.

    Measured on ~/.cargo/advisory-db at e2111519 and read in rustsec 0.33.0 (src/repository/git/
    repository.rs): a git work tree with the advisories under crates/ (left empty here), HEAD at the
    remote HEAD it fetched, and .git/FETCH_HEAD, written on every clone and every fetch (a fetch that
    brought no new commit rewrote it: mtime 16:21:50Z after the run at 16:21:48Z), its first line the
    commit, two tabs and the URL. `fetched_ago` sets the marker's mtime into the past, `commit_ago` the committer
    time of HEAD; `marker` "head" names HEAD, "behind" names HEAD and then a commit moves HEAD past it,
    None writes no marker, and any other text is the marker's content, `{head}` standing for HEAD."""
    db = home / "advisory-db"
    (db / "crates").mkdir(parents=True)
    jetzt = time.time()
    _git(db, "init", "-q")
    _git(db, "commit", "-q", "--allow-empty", "-m", "advisory database for a test", when=jetzt - commit_ago)
    if marker is not None:
        kopf = _git(db, "rev-parse", "HEAD")
        datei = db / ".git" / "FETCH_HEAD"
        text = f"{kopf}\t\t{_ADVISORY_DB_URL}\n{kopf}\t\tbranch 'main' of {_ADVISORY_DB_URL}\n"
        datei.write_text(text if marker in ("head", "behind") else marker.format(head=kopf), encoding="utf-8")
        os.utime(datei, (jetzt - fetched_ago, jetzt - fetched_ago))
        if marker == "behind":
            _git(db, "commit", "-q", "--allow-empty", "-m", "a commit after the fetch", when=jetzt - commit_ago)
    return db


@unittest.skipIf(_NO_STAND_IN, _WHY_NO_STAND_IN)
class TheExitCodes(unittest.TestCase):
    """The gate's exit code against a stand-in for cargo that writes a chosen report and exit code."""

    def _gate(self, stdout: str, rc: int) -> tuple:
        with tempfile.TemporaryDirectory() as tmp:
            ort = Path(tmp)
            (ort / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
            cargo = ort / "cargo"
            # The --json run writes the chosen report; the terminal run writes the summary cargo-audit
            # writes for it to stderr (the gate requires the two to agree).
            cargo.write_text(textwrap.dedent(f"""\
                #!{sys.executable}
                import json, os, sys
                ausgabe = {stdout!r}
                if "--json" in sys.argv:
                    sys.stdout.write(ausgabe)
                else:
                    try:
                        bericht = json.loads(ausgabe)
                        v = len(bericht["vulnerabilities"]["list"])
                        w = sum(len(e) for e in bericht["warnings"].values())
                        n = bericht["database"]["advisory-count"]
                    except Exception:
                        v = w = 0
                        n = 1271
                    db = (sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv
                          else os.path.join(os.environ["CARGO_HOME"], "advisory-db"))
                    sys.stderr.write("      Loaded %d security advisories (from %s)\\n" % (n, db))
                    if v:
                        sys.stderr.write("error: %d vulnerabilit%s found!\\n" % (v, "y" if v == 1 else "ies"))
                    if w:
                        sys.stderr.write("warning: %d allowed warning%s found\\n" % (w, "" if w == 1 else "s"))
                sys.exit({rc})
                """), encoding="utf-8")
            cargo.chmod(0o755)
            _database(ort / "cargo-home")
            env = dict(os.environ, CARGO_HOME=str(ort / "cargo-home"))
            lauf = subprocess.run([sys.executable, str(REPO / "scripts" / "cargo_audit_gate.py"),
                                   "--dir", str(ort), "--cargo", str(cargo)],
                                  capture_output=True, text=True, timeout=60, env=env)
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
#: It loads no database: it reports `advisory_count` (1271 unless chosen) in the JSON, and a Loaded line
#: with `loaded` advisories from `loaded_from` (by default the count, and the database cargo-audit
#: reads: `--db`, else $CARGO_HOME/advisory-db, else $HOME/.cargo/advisory-db). With `argv_log` it
#: appends its arguments to that file. The test chooses the rest through the JSON in GATE_STAND_IN.
_STAND_IN = r"""
import json, os, sys
spec = json.loads(os.environ["GATE_STAND_IN"])
args = sys.argv[1:]
if spec.get("argv_log"):
    with open(spec["argv_log"], "a", encoding="utf-8") as fh:
        fh.write(json.dumps(args) + "\n")
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
count = spec.get("advisory_count", 1271)
if "--db" in args:
    db = args[args.index("--db") + 1]
else:
    db = os.path.join(os.environ.get("CARGO_HOME") or os.path.join(os.environ["HOME"], ".cargo"), "advisory-db")
if "--json" in args:
    sys.stderr.write("".join(z + "\n" for z in spec.get("json_stderr", [])))
    sys.stdout.write(json.dumps({"database": {"advisory-count": count, "last-commit": None, "last-updated": None},
                                 "lockfile": {"dependency-count": lock.count("[[package]]")},
                                 "vulnerabilities": {"found": bool(vulns), "count": len(vulns), "list": vulns},
                                 "warnings": warnings, "settings": settings}))
else:
    zeilen = ["      Loaded %d security advisories (from %s)" % (spec.get("loaded", count),
                                                                 spec.get("loaded_from", db))]
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


def _run_gate(lock: str, spec: dict, audit_toml: str | None = None, config_toml: str | None = None, *,
              no_fetch: bool = False, cargo_home: bool = True, databases: tuple = ("cargo-home",),
              database: dict | None = None) -> tuple:
    """(exit code, stdout) of the gate on `lock` against the stand-in.

    HOME is a directory of the test, so the machine's own ~/.cargo never takes part. CARGO_HOME is
    <tmp>/cargo-home, or unset when `cargo_home` is false. `databases` names where a database is built
    ("cargo-home" for <tmp>/cargo-home/advisory-db, "home" for <tmp>/home/.cargo/advisory-db), each with
    the arguments `database` gives `_database`; a fresh one unless chosen."""
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
        orte = {"cargo-home": Path(tmp) / "cargo-home", "home": Path(tmp) / "home" / ".cargo"}
        for ort_ in orte.values():
            ort_.mkdir(parents=True)
        for name in databases:
            _database(orte[name], **(database or {}))
        env = dict(os.environ, GATE_STAND_IN=json.dumps(spec), HOME=str(Path(tmp) / "home"))
        if cargo_home:
            env["CARGO_HOME"] = str(orte["cargo-home"])
        else:
            env.pop("CARGO_HOME", None)
        lauf = subprocess.run([sys.executable, str(REPO / "scripts" / "cargo_audit_gate.py"),
                               "--dir", str(ort), "--cargo", str(cargo)] + (["--no-fetch"] if no_fetch else []),
                              capture_output=True, text=True, timeout=60, env=env)
        return lauf.returncode, lauf.stdout + lauf.stderr


_COMMITTED_TOML = (REPO / "tools" / "pb_verify_rs" / ".cargo" / "audit.toml").read_text(encoding="utf-8")
_LISTED = {"settings": {"ignore": ["RUSTSEC-2023-0071"]}}


@unittest.skipIf(_NO_STAND_IN, _WHY_NO_STAND_IN)
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


@unittest.skipIf(_NO_STAND_IN, _WHY_NO_STAND_IN)
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

    @unittest.skipIf(_NO_STAND_IN, _WHY_NO_STAND_IN)
    def test_the_applied_list_must_be_the_files_list(self) -> None:
        # cargo-audit reports an ignore list the file does not state: some other configuration applied.
        rc, ausgabe = _run_gate(_lock(), {"settings": {"ignore": []}}, audit_toml=_COMMITTED_TOML)
        self.assertEqual(rc, 2, ausgabe)


@unittest.skipIf(_NO_STAND_IN, _WHY_NO_STAND_IN)
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


#: The bound on the age of the last fetch, stated here apart from the gate: one hour, twice the
#: rust-parity job's timeout of 30 minutes, inside which the step fetches right before the gate.
_FETCH_BOUND = 3600
#: rustsec 0.33.0's own bound on the age of the database's last commit (STALE_AFTER, 90 days, in
#: src/repository/git/commit.rs), which cargo-audit 0.22.2 applies on a fetch and skips under --no-fetch.
_COMMIT_BOUND = 90 * 86400


@unittest.skipIf(_NO_STAND_IN, _WHY_NO_STAND_IN)
class C3TheGateVouchesOnlyForADatabaseItEstablished(unittest.TestCase):
    """PROPERTY (lens verdict on PR 296 at d30f236e, C3, P1): the gate never reports OK on a database it has not
    established as present, filled and fresh. Measured at d30f236e with cargo-audit 0.22.2: --no-fetch against
    a database whose crates/ directory is empty wrote `Loaded 0 security advisories` and
    `database.advisory-count` 0 and exited 0, and the gate printed OK and exited 0 on a lock holding
    curve25519-dalek 4.1.2 (the fetched database fails it with RUSTSEC-2024-0344, exit 1). --no-fetch also skips
    rustsec's own rule against a database whose last commit is older than 90 days, which a fetch applies. The
    stand-in reports whatever database the case chooses; the gate has to establish the database itself."""

    _CURVE = _lock(("curve25519-dalek", "4.1.2", _CRATES_IO_GIT))
    _FULL = {"vulnerable": [["curve25519-dalek", "4.1.2", "RUSTSEC-2024-0344"]]}

    def test_c3_control_a_fresh_filled_database_judges_the_verdict_lock(self) -> None:
        for no_fetch in (True, False):
            with self.subTest(no_fetch=no_fetch):
                rc, ausgabe = _run_gate(self._CURVE, self._FULL, no_fetch=no_fetch)
                self.assertEqual(rc, 1, ausgabe)
                self.assertIn("RUSTSEC-2024-0344", ausgabe)
                rc, ausgabe = _run_gate(_lock(), {}, no_fetch=no_fetch)
                self.assertEqual(rc, 0, ausgabe)

    def test_c3_an_empty_database_ends_the_gate_with_2(self) -> None:
        for spec, namen in (({"advisory_count": 0}, ("advisory-count 0", "Loaded 0")),
                            ({"advisory_count": 0, "loaded": 1271}, ("advisory-count 0",)),
                            ({"loaded": 0}, ("Loaded 0",))):
            for no_fetch in (True, False):
                with self.subTest(spec=spec, no_fetch=no_fetch):
                    rc, ausgabe = _run_gate(self._CURVE, spec, no_fetch=no_fetch)
                    self.assertEqual(rc, 2, ausgabe)
                    self.assertTrue(any(name in ausgabe for name in namen), ausgabe)

    def test_c3_a_missing_database_ends_the_gate_with_2(self) -> None:
        for no_fetch in (True, False):
            with self.subTest(no_fetch=no_fetch):
                rc, ausgabe = _run_gate(self._CURVE, {}, no_fetch=no_fetch, databases=())
                self.assertEqual(rc, 2, ausgabe)
                self.assertIn("does not exist", ausgabe)

    def test_c3_a_database_fetched_longer_ago_than_the_bound_ends_the_gate_with_2(self) -> None:
        for no_fetch in (True, False):
            with self.subTest(no_fetch=no_fetch):
                rc, ausgabe = _run_gate(self._CURVE, {}, no_fetch=no_fetch,
                                        database={"fetched_ago": _FETCH_BOUND + 600})
                self.assertEqual(rc, 2, ausgabe)
                self.assertIn("last fetched", ausgabe)
        rc, ausgabe = _run_gate(_lock(), {}, no_fetch=True, database={"fetched_ago": _FETCH_BOUND - 600})
        self.assertEqual(rc, 0, ausgabe)

    def test_c3_a_database_without_a_fetch_marker_ends_the_gate_with_2(self) -> None:
        rc, ausgabe = _run_gate(self._CURVE, {}, no_fetch=True, database={"marker": None})
        self.assertEqual(rc, 2, ausgabe)
        self.assertIn("no fetch marker", ausgabe)

    def test_c3_a_fetch_marker_not_in_the_form_cargo_audit_writes_ends_the_gate_with_2(self) -> None:
        # rustsec 0.33.0 writes the remote HEAD commit, two tabs and the URL first; a marker that does not
        # name a commit that way cannot say which commit was fetched.
        for text in ("not a commit\n", "", "{head}\tnot-for-merge\tbranch 'main' of " + _ADVISORY_DB_URL + "\n"):
            with self.subTest(marker=text):
                rc, ausgabe = _run_gate(self._CURVE, {}, no_fetch=True, database={"marker": text})
                self.assertEqual(rc, 2, ausgabe)
                self.assertIn("does not begin with a commit", ausgabe)

    def test_c3_a_head_other_than_the_fetched_commit_ends_the_gate_with_2(self) -> None:
        rc, ausgabe = _run_gate(self._CURVE, {}, no_fetch=True, database={"marker": "behind"})
        self.assertEqual(rc, 2, ausgabe)
        self.assertIn("not the commit the last fetch", ausgabe)

    def test_c3_a_last_commit_older_than_rustsecs_bound_ends_the_gate_with_2(self) -> None:
        rc, ausgabe = _run_gate(self._CURVE, {}, no_fetch=True, database={"commit_ago": _COMMIT_BOUND + 86400})
        self.assertEqual(rc, 2, ausgabe)
        self.assertIn("90 days", ausgabe)
        rc, ausgabe = _run_gate(_lock(), {}, no_fetch=True, database={"commit_ago": _COMMIT_BOUND - 86400})
        self.assertEqual(rc, 0, ausgabe)

    def test_c3_a_fetch_marker_in_the_future_ends_the_gate_with_2(self) -> None:
        rc, ausgabe = _run_gate(self._CURVE, {}, no_fetch=True, database={"fetched_ago": -600})
        self.assertEqual(rc, 2, ausgabe)
        self.assertIn("in the future", ausgabe)

    def test_c3_the_database_is_the_one_under_cargo_home_else_under_home(self) -> None:
        # rustsec 0.33.0 reads $CARGO_HOME/advisory-db, and $HOME/.cargo/advisory-db when CARGO_HOME is unset.
        faelle = ((True, ("home",), 2), (True, ("cargo-home",), 0), (False, ("cargo-home",), 2), (False, ("home",), 0))
        for cargo_home, databases, erwartet in faelle:
            with self.subTest(cargo_home=cargo_home, databases=databases):
                rc, ausgabe = _run_gate(_lock(), {}, no_fetch=True, cargo_home=cargo_home, databases=databases)
                self.assertEqual(rc, erwartet, ausgabe)

    def test_c3_cargo_audit_reads_the_database_the_gate_established(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "argv"
            rc, ausgabe = _run_gate(_lock(), {"argv_log": str(log)}, no_fetch=True)
            self.assertEqual(rc, 0, ausgabe)
            laeufe = [json.loads(z) for z in log.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(laeufe), 2)
        for args in laeufe:
            self.assertIn("--db", args)
            self.assertTrue(args[args.index("--db") + 1].endswith("/cargo-home/advisory-db"), args)
        rc, ausgabe = _run_gate(_lock(), {"loaded_from": "/elsewhere/advisory-db"}, no_fetch=True)
        self.assertEqual(rc, 2, ausgabe)
        self.assertIn("loaded its advisories from", ausgabe)
        # Both runs loaded advisories, but not the same number: they did not read the same database.
        rc, ausgabe = _run_gate(_lock(), {"loaded": 1200}, no_fetch=True)
        self.assertEqual(rc, 2, ausgabe)
        self.assertIn("did not read the same database", ausgabe)


def _fetched_database_age() -> float | None:
    """Seconds since cargo-audit last fetched this machine's advisory database (the mtime of its
    .git/FETCH_HEAD), or None when it has none."""
    marker = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo") / "advisory-db" / ".git" / "FETCH_HEAD"
    try:
        return time.time() - marker.stat().st_mtime
    except OSError:
        return None


def _cargo_audit_ready() -> bool:
    alter = _fetched_database_age()
    if shutil.which("cargo") is None or _GIT is None or alter is None or alter > _FETCH_BOUND:
        return False
    lauf = subprocess.run(["cargo", "audit", "--version"], capture_output=True, text=True)
    return lauf.returncode == 0 and "0.22.2" in lauf.stdout


_WHY_NOT_READY = ("needs cargo-audit 0.22.2, git and an advisory database cargo-audit fetched within the hour (the "
                  "rust-parity job fetches it right before its gate)")


def _database_with_an_advisory(home: Path) -> Path:
    """`_database`, with one advisory and a README committed, HEAD at that commit and the fetch marker naming
    it: the smallest database whose worktree cargo-audit would read advisories from."""
    db = _database(home)
    (db / "crates" / "curve25519-dalek").mkdir(parents=True)
    (db / "crates" / "curve25519-dalek" / "RUSTSEC-2024-0344.md").write_text(
        "```toml\n[advisory]\nid = \"RUSTSEC-2024-0344\"\npackage = \"curve25519-dalek\"\n```\n", encoding="utf-8")
    (db / "README.md").write_text("advisory database for a test\n", encoding="utf-8")
    _git(db, "add", "-A")
    _git(db, "commit", "-q", "-m", "one advisory")
    kopf = _git(db, "rev-parse", "HEAD")
    (db / ".git" / "FETCH_HEAD").write_text(f"{kopf}\t\t{_ADVISORY_DB_URL}\n", encoding="utf-8")
    return db


@unittest.skipIf(_NO_STAND_IN, _WHY_NO_STAND_IN)
class C3TheWorktreeIsTheFetchedCommit(unittest.TestCase):
    """PROPERTY (review of PR 296 at f97cb257, P1): the gate vouches for the bytes cargo-audit reads, and
    rustsec reads the advisories from the database's worktree, not from its commit. Measured at f97cb257 with
    cargo-audit 0.22.2 on a copy of the fetched database (e2111519, 1271 advisories) whose worktree lost
    crates/curve25519-dalek/RUSTSEC-2024-0344.md, HEAD and .git/FETCH_HEAD untouched: `database_state`
    succeeded, cargo-audit loaded 1270 advisories, and the gate printed OK and exited 0 on curve25519-dalek
    4.1.2, which the fetched database fails with exit 1. The worktree must hold exactly HEAD's files, with
    HEAD's bytes, and nothing else; compared by content, since a stat cache can be kept while bytes change."""

    def _state(self, db: Path) -> str:
        return g.database_state(db)

    def test_c3_control_a_clean_worktree_is_established(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = _database_with_an_advisory(Path(tmp))
            self.assertIn("fetched 0 s ago", self._state(db))

    def _refused(self, change, wort: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = _database_with_an_advisory(Path(tmp))
            change(db)
            with self.assertRaises(g.GateError) as fall:
                self._state(db)
            self.assertIn(wort, str(fall.exception))

    def test_c3_a_deleted_advisory_ends_the_gate_with_2(self) -> None:
        self._refused(lambda db: (db / "crates" / "curve25519-dalek" / "RUSTSEC-2024-0344.md").unlink(),
                      "lacks 1 file")

    def test_c3_a_changed_advisory_ends_the_gate_with_2(self) -> None:
        def aendern(db: Path) -> None:
            datei = db / "crates" / "curve25519-dalek" / "RUSTSEC-2024-0344.md"
            datei.write_text(datei.read_text(encoding="utf-8").replace("curve25519-dalek", "curve25519-dalex"),
                             encoding="utf-8")
        self._refused(aendern, "worktree")

    def test_c3_a_change_that_keeps_size_and_mtime_ends_the_gate_with_2(self) -> None:
        # Same length, modification time put back, and the database's own config telling git not to trust
        # ctime: git's stat cache then says clean (asserted below), and only the content says otherwise.
        def aendern(db: Path) -> None:
            datei = db / "crates" / "curve25519-dalek" / "RUSTSEC-2024-0344.md"
            _git(db, "config", "core.trustctime", "false")
            alt = time.time() - 3600
            os.utime(datei, (alt, alt))
            _git(db, "update-index", "--refresh")     # the index caches the old mtime, not racily clean
            datei.write_bytes(datei.read_bytes().replace(b"0344", b"0345"))
            os.utime(datei, (alt, alt))
            self.assertEqual(_git(db, "status", "--porcelain"), "", "git's stat cache must not see the change")
        self._refused(aendern, "differ from commit")

    def test_c3_an_untracked_advisory_ends_the_gate_with_2(self) -> None:
        def zufuegen(db: Path) -> None:
            (db / "crates" / "other").mkdir()
            (db / "crates" / "other" / "RUSTSEC-2099-0001.md").write_text("x\n", encoding="utf-8")
        self._refused(zufuegen, "worktree")

    def test_c3_an_ignored_file_ends_the_gate_with_2(self) -> None:
        def zufuegen(db: Path) -> None:
            (db / ".git" / "info" / "exclude").write_text("*.md\n", encoding="utf-8")
            (db / "crates" / "curve25519-dalek" / "RUSTSEC-2099-0002.md").write_text("x\n", encoding="utf-8")
        self._refused(zufuegen, "worktree")

    def test_c3_a_file_turned_into_a_symlink_ends_the_gate_with_2(self) -> None:
        def ersetzen(db: Path) -> None:
            datei = db / "crates" / "curve25519-dalek" / "RUSTSEC-2024-0344.md"
            ziel = db.parent / "elsewhere.md"
            ziel.write_bytes(datei.read_bytes())
            datei.unlink()
            datei.symlink_to(ziel)
        self._refused(ersetzen, "worktree")

    # The maintainer's rule of 28 September 2026: git status --porcelain --untracked-files=all is empty.

    def test_c3_a_mode_change_git_status_reports_ends_the_gate_with_2(self) -> None:
        # The bytes stay, so the content comparison passes; git status reports the mode.
        self._refused(lambda db: (db / "README.md").chmod(0o755), "git status")

    def test_c3_an_edit_an_index_flag_hides_from_git_status_ends_the_gate_with_2(self) -> None:
        # skip-worktree tells git status to trust the index; the content comparison does not.
        def verbergen(db: Path) -> None:
            datei = db / "crates" / "curve25519-dalek" / "RUSTSEC-2024-0344.md"
            _git(db, "update-index", "--skip-worktree", "crates/curve25519-dalek/RUSTSEC-2024-0344.md")
            datei.write_text("x\n", encoding="utf-8")
            self.assertEqual(_git(db, "status", "--porcelain", "--untracked-files=all"), "",
                             "the flag must hide the edit from git status")
        self._refused(verbergen, "differ from commit")

    def _a_command_in_the_config_is_refused_and_not_run(self, setzen) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = _database_with_an_advisory(Path(tmp))
            spur = Path(tmp) / "ran"
            setzen(db, f"touch {spur}")
            # The stat data changes, so a git status would hash the file again, through a clean filter.
            datei = db / "README.md"
            os.utime(datei, (time.time() - 7200,) * 2)
            with self.assertRaises(g.GateError) as fall:
                self._state(db)
            self.assertIn("would run a command", str(fall.exception))
            self.assertFalse(spur.exists(), "the gate ran a command the database's config names")

    def test_c3_a_clean_filter_in_the_databases_config_is_refused_and_not_run(self) -> None:
        def setzen(db: Path, befehl: str) -> None:
            _git(db, "config", "filter.pb.clean", f"{befehl}; cat")
            (db / ".git" / "info").mkdir(exist_ok=True)
            (db / ".git" / "info" / "attributes").write_text("* filter=pb\n", encoding="utf-8")
        self._a_command_in_the_config_is_refused_and_not_run(setzen)

    def test_c3_a_file_system_monitor_in_the_databases_config_is_refused_and_not_run(self) -> None:
        self._a_command_in_the_config_is_refused_and_not_run(
            lambda db, befehl: _git(db, "config", "core.fsmonitor", befehl))


@unittest.skipUnless(_cargo_audit_ready(), _WHY_NOT_READY)
class C3AgainstTheRealTool(unittest.TestCase):
    """The verdict's case with cargo-audit 0.22.2 itself: curve25519-dalek 4.1.2 fails against the fetched
    database (RUSTSEC-2024-0344) and, against a database with no advisories, ends the gate with 2."""

    def _gate(self, cargo_home: Path | None) -> tuple:
        with tempfile.TemporaryDirectory() as tmp:
            ort = Path(tmp)
            (ort / ".cargo").mkdir()
            (ort / ".cargo" / "audit.toml").write_text(_COMMITTED_TOML, encoding="utf-8")
            (ort / "Cargo.lock").write_text(_lock(("curve25519-dalek", "4.1.2", _CRATES_IO_GIT)), encoding="utf-8")
            with mock.patch.dict(os.environ, {"CARGO_HOME": str(cargo_home)} if cargo_home else {}):
                return g._gate_quietly(ort, "cargo", True, False)

    def test_c3_control_the_fetched_database_fails_the_verdict_lock(self) -> None:
        rc, ausgabe = self._gate(None)
        self.assertEqual(rc, 1, ausgabe)
        self.assertIn("RUSTSEC-2024-0344", ausgabe)

    def test_c3_the_verdict_lock_against_an_empty_database_ends_the_gate_with_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _database(Path(tmp))
            rc, ausgabe = self._gate(Path(tmp))
        self.assertEqual(rc, 2, ausgabe)
        self.assertTrue("advisory-count 0" in ausgabe or "Loaded 0" in ausgabe, ausgabe)


@unittest.skipUnless(_cargo_audit_ready(), _WHY_NOT_READY)
class TheSelfTestAgainstTheRealTool(unittest.TestCase):
    def test_both_directions(self) -> None:
        self.assertEqual(g.main(["--self-test", "--no-fetch"]), 0)


if __name__ == "__main__":
    unittest.main()
