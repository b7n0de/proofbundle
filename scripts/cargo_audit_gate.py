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

WHAT THE GATE ALONE LET THROUGH (lens verdict on PR 296 at d30f236e, C3): called with --no-fetch against
an advisory database with no advisories in it, cargo-audit 0.22.2 loads 0 (`Loaded 0 security
advisories`, `database.advisory-count` 0) and exits 0, and the gate said OK on a lock holding
curve25519-dalek 4.1.2, which the fetched database fails with RUSTSEC-2024-0344. The step fetches right
before the gate, so the whole step did not reach this; the gate did. Now the gate establishes the
database itself before it vouches for a report: $CARGO_HOME/advisory-db (~/.cargo/advisory-db when
CARGO_HOME is unset), handed to every cargo-audit run as --db, must exist, carry the fetch marker
cargo-audit writes on every fetch (.git/FETCH_HEAD) no older than one hour and naming HEAD, and have a
last commit younger than rustsec's own 90 days; and both runs must have loaded more than 0 advisories,
the same number, from that path. Each is exit 2 with its reason, never 0.

`--self-test` proves each of these with lock files it writes into temporary directories (so the
repository carries no fixture), through the gate itself: a lock holding personnummer 0.1.0 fails the
gate although `--deny warnings` exits 0; a lock holding rsa 0.9.10 (RUSTSEC-2023-0071, the one listed
exception, which PR 290 brings into Cargo.lock) passes next to the checked-in audit.toml with
vulnerabilities.count 0 and no warning, and fails without it; smallvec 1.6.0 in the sparse spelling
fails naming RUSTSEC-2021-0003; a git source fails; an audit.toml with a `[target]` table is refused; a
yanked lookup that fails (a crate the index does not carry) is exit 2; curve25519-dalek 4.1.2 fails
against the fetched database and ends the gate with 2 against a database with no advisories, a
database fetched longer ago than the bound and a missing database end it with 2. `--lock` judges any other lock
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
import shutil
import subprocess
import sys
import tempfile
import time
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


ADVISORY_DB_URL = "https://github.com/RustSec/advisory-db.git"

#: How long ago the advisory database may have been fetched when the gate reads it: one hour. The
#: rust-parity step fetches it right before the gate (cargo audit without --no-fetch, the step's third
#: line); measured on CI run 36343366980, the fetch began at 19:14:05.34Z and the self-test's last line
#: came at 19:14:10.15Z, under five seconds, and the job's timeout is 30 minutes, so no run of that
#: job can reach the bound. Any fetch resets it: rustsec 0.33.0 rewrites .git/FETCH_HEAD on every clone
#: and fetch (src/repository/git/repository.rs), measured twice on ~/.cargo/advisory-db with fetches
#: that brought no new commit (16:21:48Z run, marker 16:21:50Z; 21:17:12.16Z run, marker 21:17:12.84Z).
#: The fetch marker, not the last commit, carries the tight bound: the longest gap between two commits
#: on the database's main branch in the last five years is 24.06 days (measured at e2111519), so a
#: tight bound on the commit would fail a database fetched a second ago.
FETCH_AGE_BOUND = 3600
#: rustsec 0.33.0's own bound on the age of the database's last commit (STALE_AFTER, 90 days,
#: src/repository/git/commit.rs, the committer time of HEAD): a fetch refuses an older database, but
#: rustsec writes the fetch marker before that check, and --no-fetch skips it (cargo-audit 0.22.2,
#: src/auditor.rs). The gate applies it itself. 90 days is 3.7 times the longest measured gap.
COMMIT_AGE_BOUND = 90 * 86400
#: How far the fetch marker may lie ahead of this clock: the fetch and the gate run on one machine,
#: so only a clock adjustment between them puts it ahead, and a minute covers one.
_CLOCK_LEAD = 60
_FETCH_HEAD_LINE = re.compile(r"([0-9a-f]{40})\t\t(\S.*)")


def advisory_db_path() -> Path:
    """The advisory database cargo-audit reads when no --db is given: $CARGO_HOME/advisory-db, and
    ~/.cargo/advisory-db when CARGO_HOME is unset or empty; a relative CARGO_HOME is taken from the
    working directory (rustsec 0.33.0 Repository::default_path through home 0.5.12 cargo_home). The gate
    hands this path to every cargo-audit run as --db, so the database it establishes is the one they read."""
    return (Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo") / "advisory-db").absolute()


def _git(db: Path, *args: str) -> str:
    """stdout of a git plumbing command on the database's repository. GIT_* variables are dropped so
    that none of them points git at another repository or object store."""
    umgebung = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    try:
        lauf = subprocess.run(["git", "--no-replace-objects", f"--git-dir={db / '.git'}", *args], env=umgebung,
                              capture_output=True, encoding="utf-8", errors="replace", timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateError(f"git could not read the advisory database {db} ({exc})") from exc
    if lauf.returncode != 0:
        raise GateError(f"git could not read the advisory database {db}: {lauf.stderr.strip()[:300]}")
    return lauf.stdout


def _hashes(db: Path, pfade: list) -> list:
    """The git object ids of the files `pfade` (relative to `db`) as they stand, raw bytes, no filters: what
    git would store for exactly the bytes rustsec reads."""
    umgebung = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    eingabe = "".join(str(db / pfad) + "\n" for pfad in pfade)
    try:
        lauf = subprocess.run(["git", "--no-replace-objects", f"--git-dir={db / '.git'}", "hash-object",
                               "--no-filters", "--stdin-paths"], input=eingabe, env=umgebung, capture_output=True,
                              encoding="utf-8", errors="replace", timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateError(f"git could not hash the worktree of the advisory database {db} ({exc})") from exc
    if lauf.returncode != 0:
        raise GateError(f"git could not hash the worktree of the advisory database {db}: {lauf.stderr.strip()[:300]}")
    ids = lauf.stdout.split()
    if len(ids) != len(pfade):
        raise GateError(f"git hashed {len(ids)} of {len(pfade)} worktree files of the advisory database {db}")
    return ids


def worktree_problem(db: Path, kopf: str) -> str:
    """'' when the worktree of `db` holds exactly the files of commit `kopf`, as regular files with its bytes,
    and nothing else; otherwise what differs. rustsec loads the advisories from the worktree, so this is what
    makes a statement about the commit a statement about what cargo-audit reads. Compared by content, not by
    git's stat cache, which an edit can keep."""
    baum = {}
    for eintrag in _git(db, "ls-tree", "-r", "-z", "--full-tree", kopf).split("\0"):
        if not eintrag:
            continue
        kopfteil, pfad = eintrag.split("\t", 1)
        modus, art, objekt = kopfteil.split(" ")
        if art != "blob" or modus not in ("100644", "100755"):
            return f"commit {kopf[:12]} carries {pfad} as {art} {modus}; the gate vouches only for regular files"
        baum[pfad] = objekt
    vorhanden, keine_datei = set(), []
    for wurzel, ordner, dateien in os.walk(db):
        rel = Path(wurzel).relative_to(db)
        if rel == Path("."):
            ordner[:] = [o for o in ordner if o != ".git"]
        for name in list(ordner):
            if (Path(wurzel) / name).is_symlink():
                ordner.remove(name)
                keine_datei.append((rel / name).as_posix())
        for name in dateien:
            pfad = (rel / name).as_posix()
            vorhanden.add(pfad)
            if (Path(wurzel) / name).is_symlink() or not (Path(wurzel) / name).is_file():
                keine_datei.append(pfad)
    fremd = sorted(vorhanden - set(baum))
    fehlend = sorted(set(baum) - vorhanden)
    if fremd:
        return f"the worktree holds {len(fremd)} file(s) that commit {kopf[:12]} does not, first {fremd[0]}"
    if fehlend:
        return f"the worktree lacks {len(fehlend)} file(s) of commit {kopf[:12]}, first {fehlend[0]}"
    if keine_datei:
        return f"the worktree holds {sorted(keine_datei)[0]} as a link or special file, not as the commit's file"
    pfade = sorted(baum)
    anders = [pfad for pfad, objekt in zip(pfade, _hashes(db, pfade)) if objekt != baum[pfad]]
    if anders:
        return f"{len(anders)} worktree file(s) differ from commit {kopf[:12]}, first {anders[0]}"
    return ""


def database_state(db: Path) -> str:
    """What the gate established about the advisory database `db`; a GateError when it cannot vouch for it.

    The database must exist; carry .git/FETCH_HEAD, which rustsec 0.33.0 writes on every clone and fetch
    (its first line the remote HEAD commit, two tabs and the URL), last written no longer ago than
    FETCH_AGE_BOUND and not ahead of this clock by more than _CLOCK_LEAD; have HEAD at the commit that
    fetch brought, so the marker speaks of this content; have a worktree that is exactly that commit, since
    rustsec reads the advisories from the worktree (`worktree_problem`); and have that commit younger than
    COMMIT_AGE_BOUND by its committer time, the time rustsec judges."""
    if not db.is_dir():
        raise GateError(f"the advisory database {db} does not exist (the gate reads $CARGO_HOME/advisory-db, "
                        "~/.cargo/advisory-db when CARGO_HOME is unset): the audit would check the lock against "
                        "nothing")
    marker = db / ".git" / "FETCH_HEAD"
    try:
        geschrieben = marker.stat().st_mtime
        erste = marker.read_text(encoding="utf-8").split("\n", 1)[0]
    except (OSError, UnicodeDecodeError) as exc:
        raise GateError(f"the advisory database {db} has no fetch marker (.git/FETCH_HEAD, which cargo-audit "
                        f"writes on every fetch; {exc}): the gate cannot tell when it was fetched") from exc
    alter = time.time() - geschrieben
    if alter > FETCH_AGE_BOUND:
        raise GateError(f"the advisory database {db} was last fetched {alter / 60:.0f} minutes ago "
                        f"(.git/FETCH_HEAD), longer than the bound of {FETCH_AGE_BOUND // 60} minutes: fetch it "
                        "(cargo audit without --no-fetch) and run the gate again")
    if alter < -_CLOCK_LEAD:
        raise GateError(f"the fetch marker of the advisory database {db} lies in the future, {-alter:.0f} s "
                        "ahead of this clock: the gate cannot tell when it was fetched")
    zeile = _FETCH_HEAD_LINE.fullmatch(erste)
    if not zeile:
        raise GateError(f"the fetch marker of the advisory database {db} does not begin with a commit, two tabs "
                        f"and a URL, the form cargo-audit writes: {erste[:120]!r}")
    kopf = _git(db, "rev-parse", "--verify", "--quiet", "HEAD^{commit}").strip()
    if kopf != zeile.group(1):
        raise GateError(f"HEAD of the advisory database {db} ({kopf or 'none'}) is not the commit the last fetch "
                        f"brought ({zeile.group(1)}): the database changed after that fetch, or the fetch did "
                        "not complete")
    abweichung = worktree_problem(db, kopf)
    if abweichung:
        raise GateError(f"the worktree of the advisory database {db} is not the commit the last fetch brought: "
                        f"{abweichung}; cargo-audit would read those bytes, not the fetched ones")
    kopfzeilen = _git(db, "cat-file", "commit", kopf).split("\n\n", 1)[0].split("\n")
    committer = [z for z in kopfzeilen if z.startswith("committer ")]
    teile = committer[0].rsplit(" ", 2) if len(committer) == 1 else []
    if len(teile) != 3 or not re.fullmatch(r"[0-9]+", teile[1]) or not re.fullmatch(r"[+-][0-9]{4}", teile[2]):
        raise GateError(f"the last commit of the advisory database {db} ({kopf}) has no committer time git "
                        "writes")
    tage = (time.time() - int(teile[1])) / 86400
    if tage * 86400 >= COMMIT_AGE_BOUND:
        raise GateError(f"the last commit of the advisory database {db} ({kopf[:12]}) is {tage:.0f} days old, "
                        f"at or past rustsec's own bound of {COMMIT_AGE_BOUND // 86400} days: cargo-audit refuses "
                        "such a database on a fetch, and --no-fetch skips that rule")
    return f"database {db} at {kopf[:12]}, fetched {max(alter, 0):.0f} s ago, last commit {tage:.1f} days old"


def database_count(report) -> int:
    """`database.advisory-count` of `cargo audit --json`: how many advisories the run loaded."""
    database = report.get("database") if isinstance(report, dict) else None
    anzahl = database.get("advisory-count") if isinstance(database, dict) else None
    if type(anzahl) is not int or anzahl < 0:
        raise GateError("cargo audit --json lacks database.advisory-count as a count")
    return anzahl


_LOADED = re.compile(r"\s*Loaded ([0-9]+) security advisories \(from (.+)\)")


def loaded_advisories(stderr: str) -> tuple:
    """(count, database path) of the one `Loaded` line cargo-audit's terminal run writes to stderr."""
    geladen = [m for m in map(_LOADED.fullmatch, stderr.splitlines()) if m]
    if len(geladen) != 1:
        raise GateError(f"cargo audit (terminal) wrote {len(geladen)} Loaded lines, not one: it did not state "
                        "which database it read")
    return int(geladen[0].group(1)), geladen[0].group(2)


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


def _flags(no_fetch: bool, check_yanked: bool, database: Path) -> list:
    return ["--db", str(database)] + (["--no-fetch"] if no_fetch else []) + ([] if check_yanked else ["--no-yanked"])


def run_audit(directory: Path, lock: str, cargo: str, no_fetch: bool, check_yanked: bool = True,
              database: Path | None = None):
    """(exit code, parsed report) of `cargo audit --json --file <lock>` run in `directory` against
    `database` (advisory_db_path() unless given). `check_yanked=False` is for the self-test's cases that
    are not about a yanked crate; the gate itself never skips the yanked check."""
    lauf = _cargo_audit(directory, [cargo, "audit", "--json", "--file", lock]
                        + _flags(no_fetch, check_yanked, database or advisory_db_path()))
    stderr_counts(lauf.stderr, "--json")
    try:
        return lauf.returncode, json.loads(lauf.stdout)
    except json.JSONDecodeError as exc:
        raise GateError(f"cargo audit --json wrote no JSON ({exc})") from exc


def run_terminal(directory: Path, lock: str, cargo: str, no_fetch: bool, check_yanked: bool = True,
                 database: Path | None = None) -> tuple:
    """(exit code, vulnerabilities, warnings, (advisories loaded, from where)) of the same audit in
    cargo-audit's terminal form, the one that names a failed lookup and the database it read on stderr."""
    lauf = _cargo_audit(directory, [cargo, "audit", "--file", lock, "--color", "never"]
                        + _flags(no_fetch, check_yanked, database or advisory_db_path()))
    return (lauf.returncode, *stderr_counts(lauf.stderr, "terminal"), loaded_advisories(lauf.stderr))


def gate(directory: Path, lock: str, cargo: str, no_fetch: bool, check_yanked: bool = True,
         database: Path | None = None) -> int:
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
    db = database or advisory_db_path()
    # Under --no-fetch the runs read the database as it stands, so it is established before them; a
    # run that fetches brings it up to date, so it is established after them.
    zustand = database_state(db) if no_fetch else None
    with tempfile.TemporaryDirectory() as tmp:
        datei = lock
        if geprueft != text:
            datei = str(Path(tmp) / "Cargo.lock")
            Path(datei).write_text(geprueft, encoding="utf-8")
        rc, report = run_audit(directory, datei, cargo, no_fetch, check_yanked, db)
        terminal = run_terminal(directory, datei, cargo, no_fetch, check_yanked, db)
    zustand = zustand or database_state(db)
    anzahl = database_count(report)
    geladen, quelle = terminal[3]
    if anzahl == 0:
        raise GateError(f"cargo audit --json reports database.advisory-count 0: {db} holds no advisory, so the "
                        "audit checked the lock against nothing")
    if geladen == 0:
        raise GateError(f"cargo audit (terminal) wrote Loaded 0 security advisories (from {quelle}): the audit "
                        "checked the lock against nothing")
    if quelle != str(db):
        raise GateError(f"cargo-audit loaded its advisories from {quelle}, not from the database the gate "
                        f"established ({db})")
    if geladen != anzahl:
        raise GateError(f"the terminal run loaded {geladen} advisories and the --json run reports {anzahl}: the "
                        "two did not read the same database")
    gruende = fremd + judge(report)
    json_zahlen = (rc, report["vulnerabilities"]["count"], sum(len(v) for v in report["warnings"].values()))
    if terminal[:3] != json_zahlen:
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
          f"{ {k: len(v) for k, v in sorted(report['warnings'].items())} }, listed {sorted(listed)}; "
          f"{zustand}, {anzahl} advisories loaded")
    return 1 if gruende else 0


_KOPF = ("# This file is automatically @generated by Cargo.\n"
         "# It is not intended for manual editing.\nversion = 3\n")


def _lock_with(name: str, version: str, source: str = CRATES_IO_GIT) -> str:
    return _KOPF + f'\n[[package]]\nname = "{name}"\nversion = "{version}"\nsource = "{source}"\n'


def _gate_quietly(directory: Path, cargo: str, no_fetch: bool, check_yanked: bool,
                  database: Path | None = None) -> tuple:
    """(exit code, output) of `gate` on `directory`/Cargo.lock, a GateError being exit 2."""
    puffer = io.StringIO()
    with contextlib.redirect_stdout(puffer):
        try:
            code = gate(directory, "Cargo.lock", cargo, no_fetch, check_yanked, database)
        except GateError as exc:
            print(f"ERROR {exc}")
            code = 2
    return code, puffer.getvalue()


def _database_without_advisories(ort: Path, fetched_ago: float) -> Path:
    """A database in the form cargo-audit leaves one after a fetch, with no advisory in it: a git work tree
    with an empty crates/, HEAD at one commit made now, and .git/FETCH_HEAD naming that commit, written
    `fetched_ago` seconds back."""
    db = ort / "advisory-db"
    (db / "crates").mkdir(parents=True)
    umgebung = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    umgebung.update(GIT_AUTHOR_NAME="self-test", GIT_AUTHOR_EMAIL="self-test@example.invalid",
                    GIT_COMMITTER_NAME="self-test", GIT_COMMITTER_EMAIL="self-test@example.invalid")
    try:
        for befehl in (["init", "-q"], ["-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m",
                                        "a database with no advisories"]):
            subprocess.run(["git", "-C", str(db), *befehl], env=umgebung, capture_output=True, timeout=60,
                           check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateError(f"the self-test could not build a database with git ({exc})") from exc
    kopf = _git(db, "rev-parse", "--verify", "HEAD^{commit}").strip()
    marker = db / ".git" / "FETCH_HEAD"
    marker.write_text(f"{kopf}\t\t{ADVISORY_DB_URL}\n", encoding="utf-8")
    os.utime(marker, (time.time() - fetched_ago,) * 2)
    return db


def self_test(directory: Path, cargo: str, no_fetch: bool, listed_lock: str | None) -> int:
    """Each case in a fresh temporary directory, through the gate itself. Returns 0 only when every case
    holds. The cases that are not about the yanked check skip it (`--no-yanked`), because a failed yanked
    lookup is exit 2 (F3) and the index does not carry personnummer; the gate never skips it."""
    toml = directory / ".cargo" / "audit.toml"
    geliehen = Path(listed_lock).read_text(encoding="utf-8") if listed_lock else _lock_with("rsa", "0.9.10")
    curve = _lock_with("curve25519-dalek", "4.1.2")
    faelle = [
        # (name, lock, audit.toml text or None, .cargo/config.toml text or None, yanked check,
        #  exit codes that hold, texts the output must name, database: None for the fetched one,
        #  "empty", "stale", "edited" or "missing" for one the case builds, or leaves out, in its directory)
        ("a notice-class advisory fails the gate", _lock_with("personnummer", "0.1.0"), "", None, False,
         {1}, ["notice RUSTSEC-2020-0166"], None),
        ("the listed exception passes next to audit.toml", geliehen, "", None, False,
         {0}, ["vulnerabilities.count 0, warnings {}"], None),
        ("the same lock without audit.toml fails the gate", geliehen, None, None, False,
         {1}, ["vulnerability RUSTSEC-2023-0071"], None),
        ("F1: a crates.io package in the sparse spelling is audited",
         _lock_with("smallvec", "1.6.0", CRATES_IO_SPARSE), "", None, False, {1}, ["RUSTSEC-2021-0003"], None),
        ("F1: a package from a git source fails the gate",
         _lock_with("smallvec", "1.6.0", "git+https://github.com/servo/rust-smallvec?tag=v1.6.0"
                    "#0123456789abcdef0123456789abcdef01234567"), "", None, False, {1}, ["git+https://"], None),
        ("F2: audit.toml with a [target] table is refused", _lock_with("grep-cli", "0.1.5"),
         '\n[target]\nos = ["linux"]\n', None, False, {1}, ["[target]"], None),
        ("F3: a yanked lookup that fails ends the gate with 2",
         _lock_with("pb-verify-rs-self-test-no-such-crate", "0.0.1"), "", None, True, {2},
         ["couldn't check if the package is yanked"], None),
        ("C3: curve25519-dalek 4.1.2 fails against the fetched database", curve, "", None, False, {1},
         ["vulnerability RUSTSEC-2024-0344"], None),
        ("C3: the same lock against a database with no advisories ends the gate with 2", curve, "", None, False,
         {2}, ["advisory-count 0"], "empty"),
        ("C3: a database fetched longer ago than the bound ends the gate with 2", curve, "", None, False, {2},
         ["last fetched"], "stale"),
        ("C3: a missing database ends the gate with 2", curve, "", None, False, {2}, ["does not exist"],
         "missing"),
        ("C3: the fetched database with RUSTSEC-2024-0344 deleted from its worktree ends the gate with 2", curve,
         "", None, False, {2}, ["worktree"], "edited"),
    ]
    fehler = 0
    for name, inhalt, toml_zusatz, config, yanked, erlaubt, muss_nennen, datenbank in faelle:
        with tempfile.TemporaryDirectory() as tmp:
            ort = Path(tmp)
            # A database the case builds has no remote to fetch from, so it is read as it stands.
            db, holen_nicht = advisory_db_path(), no_fetch
            if datenbank is not None:
                db, holen_nicht = ort / "advisory-db", True
                if datenbank == "edited":
                    # The review's case: the fetched database, refs and fetch marker kept, one advisory gone
                    # from the worktree cargo-audit reads.
                    shutil.copytree(advisory_db_path(), db, symlinks=True)
                    (db / "crates" / "curve25519-dalek" / "RUSTSEC-2024-0344.md").unlink()
                elif datenbank != "missing":
                    _database_without_advisories(ort, FETCH_AGE_BOUND + 600 if datenbank == "stale" else 0)
            (ort / "Cargo.lock").write_text(inhalt, encoding="utf-8")
            if toml_zusatz is not None:
                (ort / ".cargo").mkdir()
                (ort / ".cargo" / "audit.toml").write_text(toml.read_text(encoding="utf-8") + toml_zusatz,
                                                           encoding="utf-8")
            if config is not None:
                (ort / ".cargo").mkdir(exist_ok=True)
                (ort / ".cargo" / "config.toml").write_text(config, encoding="utf-8")
            deny = subprocess.run([cargo, "audit", "--file", "Cargo.lock", "--deny", "warnings"]
                                  + _flags(holen_nicht, yanked, db),
                                  cwd=ort, capture_output=True, text=True, timeout=600)
            code, ausgabe = _gate_quietly(ort, cargo, holen_nicht, yanked, db)
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
