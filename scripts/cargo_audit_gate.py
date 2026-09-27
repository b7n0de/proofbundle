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

`--self-test` proves both directions with two lock files it writes into a temporary directory (so the
repository carries no fixture): a lock holding personnummer 0.1.0 fails the gate although
`--deny warnings` exits 0, and a lock holding rsa 0.9.10 (RUSTSEC-2023-0071, the one listed exception,
which PR 290 brings into Cargo.lock) passes next to the checked-in audit.toml with vulnerabilities.count
0 and no warning, and fails without it. `--lock` judges any other lock file in the same way, which is
how the full Cargo.lock of PR 290 was measured.

Exit codes: 0 pass, 1 an unlisted advisory or warning (or a failed self-test case), 2 an error.
"""
from __future__ import annotations

import argparse
import json
import shutil
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


#: The informational kinds cargo-audit 0.22.2 reports by default (`settings.informational_warnings`).
_ALL_INFORMATIONAL = ("unmaintained", "unsound", "notice")


def listed_ids(report) -> set:
    """The advisory IDs cargo-audit applied from `[advisories] ignore` of the audit.toml it read, as its
    report states them in `settings.ignore`. The step runs next to the checked-in
    tools/pb_verify_rs/.cargo/audit.toml, so that is the file read (an audit.toml under CARGO_HOME
    applies only when none lies there, lens finding F2). Read from the report and not by parsing the
    file: that needs tomllib, which Python 3.10, the floor of this repository, does not have."""
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


def run_audit(directory: Path, lock: str, cargo: str, no_fetch: bool):
    """(exit code, parsed report) of `cargo audit --json --file <lock>` run in `directory`."""
    befehl = [cargo, "audit", "--json", "--file", lock] + (["--no-fetch"] if no_fetch else [])
    try:
        lauf = subprocess.run(befehl, cwd=directory, capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateError(f"{' '.join(befehl)} could not run ({exc})") from exc
    if lauf.returncode not in (0, 1):
        raise GateError(f"cargo audit exited {lauf.returncode}: {lauf.stderr.strip()[:400]}")
    try:
        return lauf.returncode, json.loads(lauf.stdout)
    except json.JSONDecodeError as exc:
        raise GateError(f"cargo audit --json wrote no JSON ({exc})") from exc


def gate(directory: Path, lock: str, cargo: str, no_fetch: bool) -> int:
    rc, report = run_audit(directory, lock, cargo, no_fetch)
    gruende = judge(report)
    listed = listed_ids(report)
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


def _lock_with(name: str, version: str) -> str:
    return (_KOPF + f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n')


def self_test(directory: Path, cargo: str, no_fetch: bool, listed_lock: str | None) -> int:
    """Both directions, each in a fresh temporary directory. Returns 0 only when every case holds."""
    toml = directory / ".cargo" / "audit.toml"
    faelle = [
        ("a notice-class advisory fails the gate", _lock_with("personnummer", "0.1.0"), True, 1,
         {"notice": "RUSTSEC-2020-0166"}),
        ("the listed exception passes next to audit.toml",
         Path(listed_lock).read_text(encoding="utf-8") if listed_lock else _lock_with("rsa", "0.9.10"),
         True, 0, {}),
        ("the same lock without audit.toml fails the gate",
         Path(listed_lock).read_text(encoding="utf-8") if listed_lock else _lock_with("rsa", "0.9.10"),
         False, 1, {"vulnerability": "RUSTSEC-2023-0071"}),
    ]
    fehler = 0
    for name, inhalt, mit_toml, erwartet, muss_nennen in faelle:
        with tempfile.TemporaryDirectory() as tmp:
            ort = Path(tmp)
            (ort / "Cargo.lock").write_text(inhalt, encoding="utf-8")
            if mit_toml:
                (ort / ".cargo").mkdir()
                shutil.copyfile(toml, ort / ".cargo" / "audit.toml")
            deny = subprocess.run([cargo, "audit", "--file", "Cargo.lock", "--deny", "warnings"]
                                  + (["--no-fetch"] if no_fetch else []),
                                  cwd=ort, capture_output=True, text=True, timeout=600)
            _rc, report = run_audit(ort, "Cargo.lock", cargo, no_fetch)
            gruende = judge(report)
            ergebnis = 1 if gruende else 0
            genannt = all(any(art in g and kennung in g for g in gruende) for art, kennung in muss_nennen.items())
            sauber = erwartet == 1 or (report["vulnerabilities"]["count"] == 0 and not report["warnings"])
            ok = ergebnis == erwartet and genannt and sauber
            fehler += not ok
            print(f"{'OK  ' if ok else 'FAIL'} self-test: {name}: gate {ergebnis} (expected {erwartet}), "
                  f"--deny warnings exit {deny.returncode}, vulnerabilities.count "
                  f"{report['vulnerabilities']['count']}, warnings "
                  f"{ {k: len(v) for k, v in sorted(report['warnings'].items())} }"
                  + (f", reasons: {'; '.join(gruende)}" if gruende else ""))
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
                        help="prove both directions on temporary lock files instead of judging --lock")
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
