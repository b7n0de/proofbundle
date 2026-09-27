#!/usr/bin/env python3
"""Does a pre-tag receipt's SIGNED ``audit_output_digest`` resolve to a findable artifact?

═══ THE MEASURED OCCASION (2026-08-31, owner instruction) ═══

The v5.0.0 receipt (``audit_artifacts/500/pre_tag_receipt_v5.0.0.json``) is valid: it binds the
tag tree, it is signed by the pinned key, and ``pre_tag_audit_gate`` returns ok against that tree.
Its ``audit_output_digest`` is ``460fcdf3…`` — and **0 of 915 tracked files carry that digest**.
The ``audit_command`` even names a record, ``audit_artifacts/500/DEEP_RUN_RECORD_500_ITER8_
CEREMONY.md``; that file exists, is tracked, was committed 57 minutes BEFORE signing and has not
changed since — but its digest is ``4ca5d2a5…``. So the prose points at one artifact and the
signed digest covers another: the digest was taken over something transient that was never
committed.

C12.1 already records this as an HONEST LIMIT — *"the field is signed, which makes it
tamper-evident and attributable, not checkable"*. This module makes it checkable.

WHAT THIS DELIBERATELY DOES NOT DO: it does not move any gate verdict. Wiring resolvability into
``pre_tag_audit_gate.evaluate`` would retroactively fail v5.0.0, whose receipt is otherwise sound
and already published. A rule that changes the past is not a rule, it is a rewrite. This reports;
the release procedure consumes the report before the payload goes to the key holder.

THREE STATES, never two:
    AUFLOESBAR         a tracked file's digest equals the signed one — the file is named
    NICHT_AUFLOESBAR   every tracked file was hashed and none matched; the count is reported so
                       the negative is a measurement, not an impression
    NICHT_MESSBAR      the receipt is missing/unreadable, no JSON object, nested too deep to parse
                       or larger than a receipt is; the field is absent; git could not list the
                       tree; or no tracked file matched while some tracked path could not be
                       hashed; or the run stopped on an exception the resolver does not name.
                       Explicitly NOT a pass and explicitly NOT a failure

WHAT IS READ WHOLE IS CAPPED (a review of the stack at 1ecc2aca, on main as well, measured
2026-09-26). A receipt `[1]` or `"x"` ended the run with an AttributeError and exit 1, the code of
NICHT_AUFLOESBAR; one nested 100000 deep ended it with a RecursionError; and a 12 GB sparse file
at a tracked path, under an 8 GB address-space limit, with a MemoryError. The receipt is read up to
`RECEIPT_CAP` bytes, a tracked file is hashed up to `FILE_CAP` bytes, and a path that is no
regular file within that cap, missing and FIFO included, or one the file system refuses to show, is
counted as not hashed instead of being read or skipped.

HOW THE DIGEST IS COMPUTED, and it matters: the receipt builds it as
``sha256_text(file.read_text(encoding="utf-8", errors="ignore"))`` — over the DECODED TEXT, not
the raw bytes. For clean UTF-8 the two coincide; for a file with one invalid byte they do not,
because ``errors="ignore"`` drops it. A checker using ``sha256sum`` would report NICHT_AUFLOESBAR
for a file that legitimately matches. This module computes it exactly the way the receipt does.

    python3 scripts/audit_output_aufloesbar.py --receipt <pfad> [--repo .] [--json]

Exit: 0 AUFLOESBAR · 1 NICHT_AUFLOESBAR · 2 NICHT_MESSBAR
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pre_tag_receipt_lib import sha256_text  # noqa: E402

SCHEMA = "b7n0de.audit_output_aufloesbar.v1"

#: The largest receipt this repository holds is 6667 bytes (`audit_artifacts/600/
#: pre_tag_receipt_v6.0.0.json`), and the largest JSON file in any receipt folder 326135 bytes
#: (`audit_artifacts/600/findings_register_v2.json`), measured 2026-09-26. 4 MiB is twelve times the
#: second; a file larger than that is no receipt.
RECEIPT_CAP = 4 * 1024 * 1024
#: The largest tracked file is 1603370 bytes (`assets/b7n0de-hase.png`, measured 2026-09-26); 64 MiB
#: is forty times that. An audit output larger than the cap cannot be matched and is counted instead.
FILE_CAP = 64 * 1024 * 1024


def _pfad(rel: str) -> str:
    """A name as a line-oriented report prints it: on one line, and with one reading.

    Printed raw, a name with a line break in it starts a line of its own, so a file name can write a
    line that reads like a verdict: a tracked file named `docs/z<LF>  - README.md:1: fake finding.md`
    split one problem of the version gate into two printed items, one blaming README.md (7056ebf6),
    and the four other release tools printed such a name raw as well (a review lens, run 10, measured
    2026-09-26 at 50f3ef33). A name that holds a character that does not print, a double quote or a
    backslash is written in double quotes with backslash escapes; every other name as it is. The same
    function stands in each of the five release tools, held identical by a test.
    """
    if all(c.isprintable() and c not in '"\\' for c in rel):
        return rel
    return '"' + "".join(
        "\\" + c if c in '"\\' else c if c.isprintable() else c.encode("unicode_escape").decode("ascii")
        for c in rel) + '"'


def _unerwartet(exc: BaseException) -> str:
    """An exception no branch of this tool names, as one report line: where it was raised, and its
    type and message. `traceback` makes the message text and says so when it cannot: `str()` of an int
    past Python's limit for writing it in decimal raises in turn. The same function stands in each of
    the five release tools, held identical by a test, so that each ends such a run in its own verdict
    for what it could not judge, and never in the exit code of a finding (a review lens, measured
    2026-09-27 at 53676296)."""
    ort = traceback.extract_tb(exc.__traceback__)[-1:]
    wo = f" at {Path(ort[0].filename).name}:{ort[0].lineno}" if ort else ""
    text = traceback.format_exception_only(type(exc), exc)[-1].strip()
    return f"an unexpected exception{wo}: {_pfad(text[:300])}"


def _tracked_files(repo: Path) -> list[str] | None:
    """Tracked paths, or None if git cannot answer — None is the NICHT_MESSBAR signal, not [].

    The distinction is the whole point: an empty list would read as 'searched everything, found
    nothing', which is a verdict. A broken git has no verdict to give.

    READ WITH -z AND AS BYTES (2026-09-26, measured in a throwaway repository). Without -z git
    quotes a path that holds a byte outside ASCII (`"audit_artifacts/pr\\303\\274fung.md"`), that
    name opens no file, and the file was skipped without being counted: its digest was never
    compared, and a record under such a name read as NICHT_AUFLOESBAR."""
    try:
        r = subprocess.run(["git", "-C", str(repo), "ls-files", "-z"],
                           capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return [os.fsdecode(z) for z in r.stdout.split(b"\0") if z]


def _bytes_bis(p: Path, cap: int) -> bytes | None:
    """The bytes of a regular file of at most `cap` bytes; None for anything else, never a read of
    more than `cap + 1` bytes (a FIFO is not opened, a file that grows past the cap is refused)."""
    try:
        if not stat.S_ISREG(p.stat().st_mode) or p.stat().st_size > cap:
            return None
        with p.open("rb") as fh:
            raw = fh.read(cap + 1)
    except OSError:
        return None
    return raw if len(raw) <= cap else None


def _digest_wie_das_receipt(p: Path) -> str | None:
    """Exactly the receipt's computation. Returns None for a path that cannot be read as a file of at
    most `FILE_CAP` bytes."""
    raw = _bytes_bis(p, FILE_CAP)
    if raw is None:
        return None
    # As `read_text` reads: universal newlines, so a CRLF file hashes as the receipt hashed it.
    return sha256_text(io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8", errors="ignore").read())


def aufloesbar(receipt: dict, repo: Path) -> dict:
    """-> {zustand, digest, treffer, geprueft, grund}. Reports; never raises on a bad receipt.

    An exception no branch of `_aufloesbar` names is NICHT_MESSBAR with its reason, and `main` exits 2
    on it. Uncaught, such an exception would end the run with exit 1, the code of NICHT_AUFLOESBAR, a
    negative this run did not measure; the sweep of the class a review lens found in the mutant guard
    (measured 2026-09-27 at 53676296) gave each of the five release tools its own verdict for it."""
    try:
        return _aufloesbar(receipt, repo)
    except Exception as exc:  # noqa: BLE001 -- every other exception is no verdict of this resolver
        return {"schema": SCHEMA, "repo": str(repo), "zustand": "NICHT_MESSBAR", "digest": None,
                "treffer": [], "geprueft": 0,
                "grund": f"the run stopped on {_unerwartet(exc)}, so nothing was resolved"}


def _aufloesbar(receipt: dict, repo: Path) -> dict:
    aus: dict = {"schema": SCHEMA, "repo": str(repo)}
    if not isinstance(receipt, dict):
        aus.update(zustand="NICHT_MESSBAR", digest=None, treffer=[], geprueft=0,
                   grund=f"the receipt is no JSON object (got {type(receipt).__name__})")
        return aus
    digest = receipt.get("audit_output_digest")
    if not isinstance(digest, str) or not digest.strip():
        aus.update(zustand="NICHT_MESSBAR", digest=None, treffer=[], geprueft=0,
                   grund="das Receipt fuehrt kein audit_output_digest")
        return aus
    digest = digest.strip().lower()
    aus["digest"] = digest
    # THE RECEIPT'S VALUE IS PRINTED AS A NAME IS (`_pfad`). Printed raw, a digest `a<LF>AUFLOESBAR`
    # split the one report line in two, and so did a U+2028 in it (a review lens, measured 2026-09-27
    # at 6614ac32); b17c141c had quoted the verifier's `signer_pubkey` and not swept this reader.
    gezeigt = _pfad(digest[:12])
    dateien = _tracked_files(repo)
    if dateien is None:
        aus.update(zustand="NICHT_MESSBAR", treffer=[], geprueft=0,
                   grund=f"git konnte den Baum nicht auflisten: {_pfad(str(repo))}")
        return aus
    treffer, geprueft, nicht_gehasht = [], 0, []
    for rel in dateien:
        p = repo / rel
        # `is_dir` re-raises what the file system refuses (EACCES under a directory without search
        # permission), which ended the run with a traceback and exit 1, the code of NICHT_AUFLOESBAR (a
        # review lens, run 10, measured 2026-09-26). Such a path is not hashed, below.
        try:
            ist_verzeichnis = p.is_dir()
        except OSError:
            ist_verzeichnis = False
        if ist_verzeichnis:
            continue                      # a gitlink or a directory is no file a digest could name
        berechnet = _digest_wie_das_receipt(p)
        if berechnet is None:
            nicht_gehasht.append(rel)
            continue
        geprueft += 1
        if berechnet == digest:
            treffer.append(rel)
    aus["geprueft"] = geprueft
    aus["treffer"] = treffer
    aus["nicht_gehasht"] = nicht_gehasht
    if treffer:
        aus.update(zustand="AUFLOESBAR",
                   grund=("der signierte Digest liegt als verfolgtes Artefakt vor: "
                          + ", ".join(_pfad(t) for t in treffer)))
    elif nicht_gehasht:
        # A negative over a set with holes is not a negative: the file not hashed may be the one. The
        # first form skipped such a path without counting it, a file missing from the working tree or
        # a FIFO at a tracked path as much as one too large to read.
        aus.update(zustand="NICHT_MESSBAR",
                   grund=(f"{len(nicht_gehasht)} tracked path(s) could not be read as a regular file of at "
                          f"most {FILE_CAP} bytes (first {_pfad(nicht_gehasht[0])}), and none of the "
                          f"{geprueft} hashed carries {gezeigt}…"))
    else:
        aus.update(zustand="NICHT_AUFLOESBAR",
                   grund=(f"{geprueft} verfolgte Datei(en) gehasht, keine traegt {gezeigt}… — "
                          f"der signierte Digest ist attribuierbar, aber nicht nachrechenbar"))
    return aus


def main(argv: list[str] | None = None) -> int:
    """The resolver as a command. EVERY LINE OF IT ENDS IN ONE OF THE THREE STATES.

    `aufloesbar` held an exception no branch names to NICHT_MESSBAR, and the lines around that call did
    not: a `--repo` that is a symlink to itself raised a RuntimeError in `Path.resolve()`, and the run
    ended with a traceback and exit 1, the code of NICHT_AUFLOESBAR (a review lens, measured 2026-09-27
    at 6614ac32 and on main at 10f3466b). From the stream set-up to the printed verdict, such an
    exception is NICHT_MESSBAR with its reason, exit 2, and a stdout that refuses the verdict leaves it
    on stderr."""
    als_json = False
    try:
        # A path is read as git names it (-z, os.fsdecode), so a name that is not UTF-8 carries
        # surrogates, and a strict stdout raised on one with exit 1, the exit code of a finding
        # (measured 2026-09-26 on all four path readers). Backslash escapes instead: in JSON they are
        # the escape of the same code point, so the name reads back as it was.
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(errors="backslashreplace")
        ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
        ap.add_argument("--receipt", required=True, type=Path)
        ap.add_argument("--repo", type=Path, default=Path("."))
        ap.add_argument("--json", action="store_true")
        a = ap.parse_args(argv)
        als_json = a.json
        roh = _bytes_bis(a.receipt, RECEIPT_CAP)
        try:
            if roh is None:
                raise OSError(f"no regular file of at most {RECEIPT_CAP} bytes: {_pfad(str(a.receipt))}")
            # RecursionError: a receipt nested deeper than the parser's stack, measured at 100000.
            rc = json.loads(roh.decode("utf-8"))
        except (OSError, ValueError, RecursionError) as e:
            r = {"schema": SCHEMA, "zustand": "NICHT_MESSBAR", "digest": None, "treffer": [],
                 "geprueft": 0, "grund": f"Receipt nicht lesbar: {type(e).__name__}: {e}"}
        else:
            r = aufloesbar(rc, a.repo.resolve())
        _melde(r, als_json)
        return {"AUFLOESBAR": 0, "NICHT_AUFLOESBAR": 1}.get(r["zustand"], 2)
    except Exception as exc:  # noqa: BLE001 -- every other exception is no verdict of this resolver
        r = {"schema": SCHEMA, "zustand": "NICHT_MESSBAR", "digest": None, "treffer": [], "geprueft": 0,
             "grund": f"the run stopped on {_unerwartet(exc)}, so nothing was resolved"}
        try:
            _melde(r, als_json)
        except Exception:  # noqa: BLE001 -- stdout refused the verdict, so stderr carries it
            with contextlib.suppress(Exception):
                print(f"audit_output_digest: NICHT_MESSBAR — {r['grund']}", file=sys.stderr)
        return 2


def _melde(r: dict, als_json: bool) -> None:
    """The verdict on stdout: the whole result as JSON, or one line."""
    if als_json:
        print(json.dumps(r, indent=2, ensure_ascii=False))
    else:
        print(f"audit_output_digest: {r['zustand']} — {r['grund']}")


if __name__ == "__main__":
    sys.exit(main())
