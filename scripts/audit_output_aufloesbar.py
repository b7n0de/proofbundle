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
    NICHT_MESSBAR      the receipt is missing/unreadable, the field is absent, or git could not
                       list the tree. Explicitly NOT a pass and explicitly NOT a failure

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
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pre_tag_receipt_lib import sha256_text  # noqa: E402

SCHEMA = "b7n0de.audit_output_aufloesbar.v1"


def _tracked_files(repo: Path) -> list[str] | None:
    """Tracked paths, or None if git cannot answer — None is the NICHT_MESSBAR signal, not [].

    The distinction is the whole point: an empty list would read as 'searched everything, found
    nothing', which is a verdict. A broken git has no verdict to give."""
    try:
        r = subprocess.run(["git", "-C", str(repo), "ls-files"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return [z for z in r.stdout.splitlines() if z.strip()]


def _digest_wie_das_receipt(p: Path) -> str | None:
    """Exactly the receipt's computation. Returns None for a path that cannot be read as a file."""
    try:
        return sha256_text(p.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, ValueError):
        return None


def aufloesbar(receipt: dict, repo: Path) -> dict:
    """-> {zustand, digest, treffer, geprueft, grund}. Reports; never raises on a bad receipt."""
    aus: dict = {"schema": SCHEMA, "repo": str(repo)}
    digest = (receipt or {}).get("audit_output_digest")
    if not isinstance(digest, str) or not digest.strip():
        aus.update(zustand="NICHT_MESSBAR", digest=None, treffer=[], geprueft=0,
                   grund="das Receipt fuehrt kein audit_output_digest")
        return aus
    digest = digest.strip().lower()
    aus["digest"] = digest
    dateien = _tracked_files(repo)
    if dateien is None:
        aus.update(zustand="NICHT_MESSBAR", treffer=[], geprueft=0,
                   grund=f"git konnte den Baum nicht auflisten: {repo}")
        return aus
    treffer, geprueft = [], 0
    for rel in dateien:
        p = repo / rel
        if not p.is_file():
            continue
        geprueft += 1
        if _digest_wie_das_receipt(p) == digest:
            treffer.append(rel)
    aus["geprueft"] = geprueft
    aus["treffer"] = treffer
    if treffer:
        aus.update(zustand="AUFLOESBAR",
                   grund=f"der signierte Digest liegt als verfolgtes Artefakt vor: {', '.join(treffer)}")
    else:
        aus.update(zustand="NICHT_AUFLOESBAR",
                   grund=(f"{geprueft} verfolgte Datei(en) gehasht, keine traegt {digest[:12]}… — "
                          f"der signierte Digest ist attribuierbar, aber nicht nachrechenbar"))
    return aus


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--receipt", required=True, type=Path)
    ap.add_argument("--repo", type=Path, default=Path("."))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    try:
        rc = json.loads(a.receipt.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        r = {"schema": SCHEMA, "zustand": "NICHT_MESSBAR", "digest": None, "treffer": [],
             "geprueft": 0, "grund": f"Receipt nicht lesbar: {type(e).__name__}: {e}"}
    else:
        r = aufloesbar(rc, a.repo.resolve())
    if a.json:
        print(json.dumps(r, indent=2, ensure_ascii=False))
    else:
        print(f"audit_output_digest: {r['zustand']} — {r['grund']}")
    return {"AUFLOESBAR": 0, "NICHT_AUFLOESBAR": 1}.get(r["zustand"], 2)


if __name__ == "__main__":
    sys.exit(main())
