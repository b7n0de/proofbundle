#!/usr/bin/env python3
"""Fail the Rust dependency audit on every RustSec advisory or warning that audit.toml does not list.

WHY THIS EXISTS BESIDE `cargo audit --deny warnings`. The rule of the rust-parity job's audit step is:
never exit 0 on a lock file that carries a RustSec advisory or warning the checked-in
`tools/pb_verify_rs/.cargo/audit.toml` does not list. `--deny warnings` holds it for three warning kinds
only. Measured with cargo-audit 0.22.2 (lens run on PR 296, and again here against advisory-db
e2111519): a lock holding personnummer 0.1.0 carries RUSTSEC-2020-0166, `informational = "notice"`;
`cargo audit --deny warnings` prints `Warning: notice` and exits 0, `--json` reports it under
`warnings.notice`, and `--deny notice` and `--deny all` are refused by the tool itself (exit 2). So the
step also reads `cargo audit --json` and judges it here.

THE JUDGEMENT. Every entry of `vulnerabilities.list` and every entry of every kind under `warnings`
(unmaintained, unsound, yanked, notice, and any kind a later cargo-audit adds) fails the gate unless
its advisory ID is listed under `[advisories] ignore` in `<dir>/.cargo/audit.toml`, read as the list
cargo-audit reports it applied (`settings.ignore`). An entry without an advisory ID (a yanked crate) cannot be listed and always fails. Output that is not the JSON shape
cargo-audit 0.22.2 writes, a cargo-audit exit code other than 0 or 1, or a count that disagrees with its
list, is an error: exit 2, never a pass. An audit.toml that narrows what cargo-audit reports
(`severity_threshold`, or `informational_warnings` without one of unmaintained, unsound, notice), read
from the report's own `settings`, fails the gate too (1): it would hide an advisory without listing
its ID.

The step runs cargo-audit in the directory that holds the checked-in audit.toml, because cargo-audit
reads `.cargo/audit.toml` from its working directory and an audit.toml under CARGO_HOME only when none
lies there (lens finding F2 on PR 296); the listed IDs are the ones cargo-audit read from that file.

WHAT cargo-audit ALONE LETS THROUGH, and the gate does not (second lens run on PR 296, at 5138b4d2;
each measured with cargo-audit 0.22.2, each with the whole step at exit 0 before):
- F1, lock sources. rustsec matches an advisory to a crates.io package only in the git-index source
  spelling; smallvec 1.6.0 under `sparse+https://index.crates.io/` was reported clean. The gate reads the
  lock in the form cargo writes, fails every package from a source other than crates.io, and audits the
  crates.io packages in the git spelling.
- F2, audit.toml. `[target]`, `[database]`, `[yanked]` and the other keys hide advisories without naming
  one. The gate refuses every table and key but `[advisories] ignore`, and requires the list cargo-audit
  applied to be the file's list.
- F3, lookups. A yanked lookup that failed read as a clean report: the `--json` run wrote nothing to
  stderr for it, the terminal run named it there. The gate reads stderr of both runs; a line that is not
  progress or a summary is exit 2, and the two runs must agree.

`--self-test` proves each of these with lock files it writes into temporary directories (so the
repository carries no fixture), through the gate itself: a lock holding personnummer 0.1.0 fails the
gate although `--deny warnings` exits 0; a lock holding rsa 0.9.10 (RUSTSEC-2023-0071, the one listed
exception, which PR 290 brings into Cargo.lock) passes next to the checked-in audit.toml with
vulnerabilities.count 0 and no warning, and fails without it; smallvec 1.6.0 in the sparse spelling
fails naming RUSTSEC-2021-0003; a git source fails; an audit.toml with a `[target]` table is refused; a
yanked lookup that fails (a crate the index does not carry) is exit 2. `--lock` judges any other lock
file in the same way, which is how the full Cargo.lock of PR 290 was measured.

Exit codes: 0 pass, 1 an unlisted advisory or warning (or a failed self-test case), 2 an error.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_DIR = REPO / "tools" / "pb_verify_rs"


class GateError(Exception):
    """The audit could not be judged; the gate answers 2, never 0."""


def _advisory_id(entry, wo: str):
    if not isinstance(entry, dict):
        raise GateError(f"{wo}: an entry is not an object")
    advisory = entry.get("advisory")
    if advisory is None:
        return None
    if not (isinstance(advisory, dict) and isinstance(advisory.get("id"), str)):
        raise GateError(f"{wo}: an advisory without a string id")
    return advisory["id"]


#: The two spellings cargo writes in a lock file for a package from the crates.io registry: the git
#: index, and the sparse index when the registry is configured with the sparse protocol under its own
#: name. rustsec 0.33.0 (inside cargo-audit 0.22.2) matches an advisory to a crates.io package only in
#: the first spelling: smallvec 1.6.0 under the second was reported clean, measured with
#: RUSTSEC-2021-0003 (lens finding F1 at 5138b4d2).
CRATES_IO_GIT = "registry+https://github.com/rust-lang/crates.io-index"
CRATES_IO_SPARSE = "sparse+https://index.crates.io/"

_LOCK_KEY = re.compile(r'(name|version|source|checksum) = "([^"\\]*)"')
_LOCK_DEPENDENCY = re.compile(r' "[^"\\]*",')


def lock_packages(text: str) -> list:
    """The packages of a Cargo.lock, each a dict with `line`, `name`, `version` and, when the lock names
    one, `source`. Read in the form cargo writes (comment lines, `version = N`, `[[package]]` blocks with
    name, version, source, checksum and a `dependencies = [` list, one quoted entry per line); any other
    line is an error, because a lock this gate cannot read is a lock whose sources it cannot vouch for.
    Parsed by hand: tomllib is not in the standard library of Python 3.10, the floor of this repository."""
    pakete: list = []
    aktuell = None
    in_liste = False
    kopf = False
    for nr, zeile in enumerate(text.split("\n"), 1):
        if in_liste:
            if zeile == "]":
                in_liste = False
            elif not _LOCK_DEPENDENCY.fullmatch(zeile):
                raise GateError(f"Cargo.lock line {nr} is not in the form cargo writes: {zeile[:80]!r}")
            continue
        if zeile == "" or zeile.startswith("#"):
            continue
        if zeile == "[[package]]":
            aktuell = {"line": nr}
            pakete.append(aktuell)
            continue
        if aktuell is None and not kopf and re.fullmatch(r"version = [0-9]+", zeile):
            kopf = True
            continue
        if aktuell is not None:
            if zeile == "dependencies = [" and "dependencies" not in aktuell:
                aktuell["dependencies"] = True
                in_liste = True
                continue
            treffer = _LOCK_KEY.fullmatch(zeile)
            if treffer and treffer.group(1) not in aktuell:
                aktuell[treffer.group(1)] = treffer.group(2)
                continue
        raise GateError(f"Cargo.lock line {nr} is not in the form cargo writes: {zeile[:80]!r}")
    if in_liste:
        raise GateError("Cargo.lock ends inside a dependencies list")
    for paket in pakete:
        if "name" not in paket or "version" not in paket:
            raise GateError(f"Cargo.lock: the package at line {paket['line']} lacks a name or a version")
    return pakete


def foreign_sources(pakete: list) -> list:
    """Reasons for every package whose source is not the crates.io registry in a spelling cargo writes.
    A package without a source is a path or workspace member, code of this repository; any other source
    (a git repository, another registry, another spelling of crates.io) lies outside what the advisory
    database is matched against, so it fails the gate instead of passing unchecked."""
    return [f"package {p['name']} {p['version']} (Cargo.lock line {p['line']}) comes from source "
            f"{p['source']}, which is not the crates.io registry: the audit does not cover it"
            for p in pakete if "source" in p and p["source"] not in (CRATES_IO_GIT, CRATES_IO_SPARSE)]


def crates_io_in_git_spelling(text: str) -> str:
    """The lock with every crates.io package written in the git-index spelling, the one rustsec matches:
    the same registry, so the same packages, now checked."""
    return (text.replace(f'"{CRATES_IO_SPARSE}"', f'"{CRATES_IO_GIT}"')
            .replace(f"({CRATES_IO_SPARSE})", f"({CRATES_IO_GIT})"))


_ADVISORY_ID = re.compile(r"RUSTSEC-[0-9]{4}-[0-9]{4}")
_TABLE = re.compile(r"\[\[?\s*(.*?)\s*\]\]?")
_KEY = re.compile(r"([^=]+?)\s*=\s*(.*)")
_LIST_ITEMS = re.compile(r'((?:"[^"\\]*"\s*,\s*)*(?:"[^"\\]*"\s*,?)?)\s*(\])?')


def audit_toml_path(directory: Path):
    """The audit.toml cargo-audit applies when it runs in `directory`: `.cargo/audit.toml` there, else
    `audit.toml` under CARGO_HOME (lens finding F2 on PR 296: the second applies only when the first is
    absent). None when neither exists."""
    lokal = directory / ".cargo" / "audit.toml"
    if lokal.is_file():
        return lokal
    heim = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo") / "audit.toml"
    return heim if heim.is_file() else None


def audit_toml_ignore(text: str) -> tuple:
    """(the advisory IDs under `[advisories] ignore`, the reasons the file carries anything else).

    audit.toml may list exceptions and nothing more. Every other table or key can hide an advisory
    without naming it: measured with cargo-audit 0.22.2, `[target] os = ["linux"]` beside grep-cli 0.1.5
    gave exit 0 and no vulnerability, `[yanked] enabled = false` dropped the yanked libc 0.2.165, and
    `[database]` points the audit at another or a stale database (lens finding F2 at 5138b4d2). So any
    table other than `[advisories]`, any key other than `ignore` in it, any key before it, and any ID
    that is not a RUSTSEC advisory ID is refused by name. Read by hand, line by line (tomllib is not in
    Python 3.10); a line this reader does not know is refused too, never skipped."""
    ids: list = []
    gruende: list = []
    tabelle = None
    advisories_gesehen = ignore_gesehen = False
    in_ignore = in_fremder_liste = False
    for nr, roh in enumerate(text.splitlines(), 1):
        zeile = roh.split("#", 1)[0].strip()
        if not zeile:
            continue
        if in_fremder_liste:
            in_fremder_liste = "]" not in zeile
            continue
        if not in_ignore:
            kopf = _TABLE.fullmatch(zeile)
            if kopf:
                if zeile == "[advisories]" and not advisories_gesehen:
                    tabelle, advisories_gesehen = "advisories", True
                else:
                    tabelle = kopf.group(1)
                    gruende.append(f"audit.toml line {nr} opens the table {zeile}: only [advisories] ignore "
                                   "may stand in audit.toml")
                continue
            paar = _KEY.fullmatch(zeile)
            if tabelle == "advisories" and paar and paar.group(1) == "ignore" and not ignore_gesehen:
                if not paar.group(2).startswith("["):
                    gruende.append(f"audit.toml line {nr}: advisories.ignore is not a list")
                    continue
                ignore_gesehen = in_ignore = True
                zeile = paar.group(2)[1:].strip()
            else:
                name = paar.group(1).strip() if paar else zeile[:60]
                if tabelle in (None, "advisories"):
                    gruende.append(f"audit.toml line {nr} sets {tabelle + '.' if tabelle else ''}{name}: "
                                   "only [advisories] ignore may stand in audit.toml")
                if paar and paar.group(2).startswith("[") and "]" not in paar.group(2):
                    in_fremder_liste = True
                continue
        eintraege = _LIST_ITEMS.fullmatch(zeile)
        if not eintraege:
            raise GateError(f"audit.toml line {nr}: advisories.ignore is not a list of quoted advisory IDs")
        for kennung in re.findall(r'"([^"\\]*)"', eintraege.group(1)):
            if not _ADVISORY_ID.fullmatch(kennung):
                gruende.append(f"audit.toml ignores {kennung!r}, which is not a RUSTSEC advisory ID")
            ids.append(kennung)
        if eintraege.group(2):
            in_ignore = False
    if in_ignore or in_fremder_liste:
        raise GateError("audit.toml ends inside a list")
    return ids, gruende


#: The informational kinds cargo-audit 0.22.2 reports by default (`settings.informational_warnings`).
_ALL_INFORMATIONAL = ("unmaintained", "unsound", "notice")


def listed_ids(report) -> set:
    """The advisory IDs cargo-audit applied from `[advisories] ignore` of the audit.toml it read, as its
    report states them in `settings.ignore`. The step runs next to the checked-in
    tools/pb_verify_rs/.cargo/audit.toml, so that is the file read (an audit.toml under CARGO_HOME
    applies only when none lies there, lens finding F2). `gate` also reads the file itself
    (`audit_toml_ignore`) and requires both lists to agree."""
    settings = report.get("settings") if isinstance(report, dict) else None
    ignore = settings.get("ignore") if isinstance(settings, dict) else None
    if not (isinstance(ignore, list) and all(isinstance(i, str) for i in ignore)):
        raise GateError("cargo audit --json lacks settings.ignore as a list of advisory IDs")
    return set(ignore)


def _narrowed(settings) -> list:
    """Reasons the report cannot be complete: audit.toml can hide advisories without naming one.

    Measured with cargo-audit 0.22.2 against advisory-db e2111519: `informational_warnings =
    ["unmaintained"]` under `[advisories]` removed the personnummer notice from `warnings` (exit 0), and
    `severity_threshold = "critical"` removed RUSTSEC-2023-0071 (a medium one) from `vulnerabilities`
    (exit 0). Either would pass an advisory audit.toml does not list, so either fails the gate."""
    if not isinstance(settings, dict):
        raise GateError("cargo audit --json lacks settings")
    gruende = []
    if settings.get("severity") is not None:
        gruende.append(f"audit.toml sets severity_threshold {settings.get('severity')!r}: advisories "
                       "below it are not reported")
    for feld in ("target_arch", "target_os"):
        filter_ = settings.get(feld)
        if not isinstance(filter_, list):
            raise GateError(f"cargo audit --json lacks settings.{feld}")
        if filter_:
            gruende.append(f"the audit filters by {feld} {filter_}: advisories for other targets are not "
                           "reported")
    arten = settings.get("informational_warnings")
    if not isinstance(arten, list):
        raise GateError("cargo audit --json lacks settings.informational_warnings")
    for art in _ALL_INFORMATIONAL:
        if art not in arten:
            gruende.append(f"audit.toml leaves {art!r} out of informational_warnings: such a warning "
                           "is not reported")
    return gruende


def judge(report) -> list:
    """The reasons `report` (parsed `cargo audit --json`) fails the gate; empty when it passes."""
    if not isinstance(report, dict):
        raise GateError("cargo audit --json did not write an object")
    vulns, warnings = report.get("vulnerabilities"), report.get("warnings")
    if not (isinstance(vulns, dict) and isinstance(vulns.get("list"), list)
            and type(vulns.get("count")) is int and isinstance(warnings, dict)):
        raise GateError("cargo audit --json lacks vulnerabilities.list, vulnerabilities.count or warnings")
    if vulns["count"] != len(vulns["list"]):
        raise GateError(f"vulnerabilities.count {vulns['count']} disagrees with its list of "
                        f"{len(vulns['list'])}")
    gruende = _narrowed(report.get("settings"))
    listed = listed_ids(report)
    for entry in vulns["list"]:
        kennung = _advisory_id(entry, "vulnerabilities.list")
        if kennung not in listed:
            gruende.append(f"vulnerability {kennung or '(no advisory id)'} is not listed in audit.toml")
    for art, entries in sorted(warnings.items()):
        if not isinstance(entries, list):
            raise GateError(f"warnings.{art} is not a list")
        for entry in entries:
            kennung = _advisory_id(entry, f"warnings.{art}")
            if kennung is None or kennung not in listed:
                paket = entry.get("package") if isinstance(entry.get("package"), dict) else {}
                gruende.append(f"warning {art} {kennung or '(no advisory id)'} "
                               f"({paket.get('name', '?')} {paket.get('version', '?')}) is not listed "
                               "in audit.toml")
    return gruende


#: What cargo-audit 0.22.2 writes to stderr on a run it completed, read from the rust-parity job's log
#: and measured locally: its progress, and the two summary lines of the terminal run.
_STDERR_PROGRESS = (
    re.compile(r"\s*Fetching advisory database from `[^`]+`"),
    re.compile(r"\s*Loaded [0-9]+ security advisories \(from .+\)"),
    re.compile(r"\s*Updating crates\.io index"),
    re.compile(r"\s*Scanning .+ for vulnerabilities \([0-9]+ crate dependencies\)"),
)
_STDERR_VULNERABILITIES = re.compile(r"error: ([0-9]+) vulnerabilit(?:y|ies) found!")
_STDERR_WARNINGS = re.compile(r"warning: ([0-9]+) allowed warnings? found")


def stderr_counts(stderr: str, run: str) -> tuple:
    """(vulnerabilities, warnings) that a run's stderr summary states; any other line is an error.

    A lookup cargo-audit could not make is no finding: with `protocol = "git"` in .cargo/config.toml the
    yanked check of libc 0.2.165 failed, the terminal run wrote `warning: couldn't open crates.io index:
    ...` to stderr, the `--json` run wrote nothing there and no yanked warning, and both exited 0
    (measured with 0.22.2; lens finding F3 at 5138b4d2). So stderr is read, and a line that is not
    progress or a summary ends the gate with 2."""
    schwachstellen = warnungen = 0
    for zeile in stderr.splitlines():
        if not zeile.strip() or any(m.fullmatch(zeile) for m in _STDERR_PROGRESS):
            continue
        treffer = _STDERR_VULNERABILITIES.fullmatch(zeile)
        if treffer:
            schwachstellen = int(treffer.group(1))
            continue
        treffer = _STDERR_WARNINGS.fullmatch(zeile)
        if treffer:
            warnungen = int(treffer.group(1))
            continue
        raise GateError(f"cargo audit ({run}) wrote {zeile.strip()[:300]!r} to stderr: a lookup it could not "
                        "make is not a clean report")
    return schwachstellen, warnungen


def _cargo_audit(directory: Path, befehl: list):
    try:
        lauf = subprocess.run(befehl, cwd=directory, capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateError(f"{' '.join(befehl)} could not run ({exc})") from exc
    if lauf.returncode not in (0, 1):
        raise GateError(f"cargo audit exited {lauf.returncode}: {lauf.stderr.strip()[:400]}")
    return lauf


def _flags(no_fetch: bool, check_yanked: bool) -> list:
    return (["--no-fetch"] if no_fetch else []) + ([] if check_yanked else ["--no-yanked"])


def run_audit(directory: Path, lock: str, cargo: str, no_fetch: bool, check_yanked: bool = True):
    """(exit code, parsed report) of `cargo audit --json --file <lock>` run in `directory`.
    `check_yanked=False` is for the self-test's cases that are not about a yanked crate; the gate
    itself never skips the yanked check."""
    lauf = _cargo_audit(directory, [cargo, "audit", "--json", "--file", lock] + _flags(no_fetch, check_yanked))
    stderr_counts(lauf.stderr, "--json")
    try:
        return lauf.returncode, json.loads(lauf.stdout)
    except json.JSONDecodeError as exc:
        raise GateError(f"cargo audit --json wrote no JSON ({exc})") from exc


def run_terminal(directory: Path, lock: str, cargo: str, no_fetch: bool, check_yanked: bool = True) -> tuple:
    """(exit code, vulnerabilities, warnings) of the same audit in cargo-audit's terminal form, the one
    that names a failed lookup on stderr."""
    lauf = _cargo_audit(directory, [cargo, "audit", "--file", lock, "--color", "never"]
                        + _flags(no_fetch, check_yanked))
    return (lauf.returncode, *stderr_counts(lauf.stderr, "terminal"))


def gate(directory: Path, lock: str, cargo: str, no_fetch: bool, check_yanked: bool = True) -> int:
    toml = audit_toml_path(directory)
    try:
        ids, verweigert = audit_toml_ignore(toml.read_text(encoding="utf-8")) if toml else ([], [])
    except (OSError, UnicodeDecodeError) as exc:
        raise GateError(f"{toml} could not be read ({exc})") from exc
    if verweigert:
        for grund in verweigert:
            print(f"FAIL {grund}")
        print(f"FAIL {toml}: audit.toml carries more than [advisories] ignore; the audit was not run")
        return 1
    try:
        text = (directory / lock).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise GateError(f"{lock} in {directory} could not be read ({exc})") from exc
    fremd = foreign_sources(lock_packages(text))
    geprueft = crates_io_in_git_spelling(text)
    with tempfile.TemporaryDirectory() as tmp:
        datei = lock
        if geprueft != text:
            datei = str(Path(tmp) / "Cargo.lock")
            Path(datei).write_text(geprueft, encoding="utf-8")
        rc, report = run_audit(directory, datei, cargo, no_fetch, check_yanked)
        terminal = run_terminal(directory, datei, cargo, no_fetch, check_yanked)
    gruende = fremd + judge(report)
    json_zahlen = (rc, report["vulnerabilities"]["count"], sum(len(v) for v in report["warnings"].values()))
    if terminal != json_zahlen:
        raise GateError(f"the terminal run (exit, vulnerabilities, warnings) {terminal} and the --json run "
                        f"{json_zahlen} disagree: the two did not see the same lookups")
    listed = listed_ids(report)
    if listed != set(ids):
        raise GateError(f"cargo-audit applied the ignore list {sorted(listed)}, the audit.toml it runs next "
                        f"to ({toml or 'none'}) states {sorted(set(ids))}")
    if rc == 1 and not report["vulnerabilities"]["list"]:
        raise GateError("cargo audit exited 1 but reports no vulnerability")
    for grund in gruende:
        print(f"FAIL {grund}")
    print(f"{'FAIL' if gruende else 'OK  '} cargo audit --json on {lock} in {directory}: "
          f"vulnerabilities.count {report['vulnerabilities']['count']}, warnings "
          f"{ {k: len(v) for k, v in sorted(report['warnings'].items())} }, listed {sorted(listed)}")
    return 1 if gruende else 0


_KOPF = ("# This file is automatically @generated by Cargo.\n"
         "# It is not intended for manual editing.\nversion = 3\n")


def _lock_with(name: str, version: str, source: str = CRATES_IO_GIT) -> str:
    return _KOPF + f'\n[[package]]\nname = "{name}"\nversion = "{version}"\nsource = "{source}"\n'


def _gate_quietly(directory: Path, cargo: str, no_fetch: bool, check_yanked: bool) -> tuple:
    """(exit code, output) of `gate` on `directory`/Cargo.lock, a GateError being exit 2."""
    puffer = io.StringIO()
    with contextlib.redirect_stdout(puffer):
        try:
            code = gate(directory, "Cargo.lock", cargo, no_fetch, check_yanked)
        except GateError as exc:
            print(f"ERROR {exc}")
            code = 2
    return code, puffer.getvalue()


def self_test(directory: Path, cargo: str, no_fetch: bool, listed_lock: str | None) -> int:
    """Each case in a fresh temporary directory, through the gate itself. Returns 0 only when every case
    holds. The cases that are not about the yanked check skip it (`--no-yanked`), because a failed yanked
    lookup is exit 2 (F3) and the index does not carry personnummer; the gate never skips it."""
    toml = directory / ".cargo" / "audit.toml"
    geliehen = Path(listed_lock).read_text(encoding="utf-8") if listed_lock else _lock_with("rsa", "0.9.10")
    faelle = [
        # (name, lock, audit.toml text or None, .cargo/config.toml text or None, yanked check,
        #  exit codes that hold, texts the output must name)
        ("a notice-class advisory fails the gate", _lock_with("personnummer", "0.1.0"), "", None, False,
         {1}, ["notice RUSTSEC-2020-0166"]),
        ("the listed exception passes next to audit.toml", geliehen, "", None, False,
         {0}, ["vulnerabilities.count 0, warnings {}"]),
        ("the same lock without audit.toml fails the gate", geliehen, None, None, False,
         {1}, ["vulnerability RUSTSEC-2023-0071"]),
        ("F1: a crates.io package in the sparse spelling is audited",
         _lock_with("smallvec", "1.6.0", CRATES_IO_SPARSE), "", None, False, {1}, ["RUSTSEC-2021-0003"]),
        ("F1: a package from a git source fails the gate",
         _lock_with("smallvec", "1.6.0", "git+https://github.com/servo/rust-smallvec?tag=v1.6.0"
                    "#0123456789abcdef0123456789abcdef01234567"), "", None, False, {1}, ["git+https://"]),
        ("F2: audit.toml with a [target] table is refused", _lock_with("grep-cli", "0.1.5"),
         '\n[target]\nos = ["linux"]\n', None, False, {1}, ["[target]"]),
        ("F3: a yanked lookup that fails ends the gate with 2",
         _lock_with("pb-verify-rs-self-test-no-such-crate", "0.0.1"), "", None, True, {2},
         ["couldn't check if the package is yanked"]),
    ]
    fehler = 0
    for name, inhalt, toml_zusatz, config, yanked, erlaubt, muss_nennen in faelle:
        with tempfile.TemporaryDirectory() as tmp:
            ort = Path(tmp)
            (ort / "Cargo.lock").write_text(inhalt, encoding="utf-8")
            if toml_zusatz is not None:
                (ort / ".cargo").mkdir()
                (ort / ".cargo" / "audit.toml").write_text(toml.read_text(encoding="utf-8") + toml_zusatz,
                                                           encoding="utf-8")
            if config is not None:
                (ort / ".cargo").mkdir(exist_ok=True)
                (ort / ".cargo" / "config.toml").write_text(config, encoding="utf-8")
            deny = subprocess.run([cargo, "audit", "--file", "Cargo.lock", "--deny", "warnings"]
                                  + _flags(no_fetch, yanked),
                                  cwd=ort, capture_output=True, text=True, timeout=600)
            code, ausgabe = _gate_quietly(ort, cargo, no_fetch, yanked)
            ok = code in erlaubt and all(text in ausgabe for text in muss_nennen)
            fehler += not ok
            gruende = "; ".join(z for z in ausgabe.splitlines() if z.startswith(("FAIL", "ERROR")))
            print(f"{'OK  ' if ok else 'FAIL'} self-test: {name}: gate {code} (expected {sorted(erlaubt)}), "
                  f"--deny warnings exit {deny.returncode}" + (f": {gruende}" if gruende else ""))
    return 1 if fehler else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", type=Path, default=DEFAULT_DIR,
                        help="the directory that holds Cargo.lock and .cargo/audit.toml")
    parser.add_argument("--lock", default="Cargo.lock", help="the lock file, relative to --dir")
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--no-fetch", action="store_true",
                        help="use the advisory database cargo-audit already fetched")
    parser.add_argument("--self-test", action="store_true",
                        help="prove every case on temporary lock files instead of judging --lock")
    parser.add_argument("--listed-lock", default=None,
                        help="with --self-test: the lock to use for the listed-exception cases")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            return self_test(args.dir.resolve(), args.cargo, args.no_fetch, args.listed_lock)
        return gate(args.dir.resolve(), args.lock, args.cargo, args.no_fetch)
    except GateError as exc:
        print(f"ERROR {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
