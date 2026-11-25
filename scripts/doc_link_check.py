#!/usr/bin/env python3
"""Doc-link checker — fail CI if a Markdown link points at a local file that does not exist.

A tool that sells reviewability cannot ship docs whose internal links 404 — a broken link or a
missing image reads as abandonment (six-lens review §5, RELEASE.md). This checks every
`[text](target)` link in the repo's Markdown: local relative targets (not http/mailto/#anchor) must
resolve to a file on disk. External URLs are out of scope here (a separate online link-checker /
lychee job can cover those without gating every offline CI run).

Read-only, stdlib only. Exit 0 clean, exit 1 on any broken local link.
CLI: [--json]
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
_SKIP = (".git", "node_modules", ".venv", "archive", "upstream")   # docs/archive/ is frozen history;
# docs/upstream/ is ready-to-submit in-toto material whose relative links resolve in the in-toto repo tree, not ours

#: A RECORD THAT MOVED WITH ITS BYTES. The residual-risk records moved from the root to
#: docs/residual_risk/ unchanged, byte for byte, while RESTRISIKO_600.md stayed at the root. One moved
#: record links it by a bare relative name, which no longer resolves beside the record. Each entry
#: names the moved file, the link target as the file writes it, the sha256 of the file's bytes, and
#: the path from the root where the target stands. The entry holds only while the file has exactly
#: these bytes and the target exists at that path; an edit of the file, or a missing target, makes the
#: link broken again, so the fix is then to write the link anew.
_VERSCHOBEN_MIT_BYTES = {
    ("docs/residual_risk/RESTRISIKO_640.md", "RESTRISIKO_600.md"):
        ("28433f230d26cc3c735afcd2495af720ad210ddea6f2029c650eac53e906687f", "RESTRISIKO_600.md"),
}


def _haelt_als_verschoben(rel: str, target: str, roh: bytes) -> bool:
    eintrag = _VERSCHOBEN_MIT_BYTES.get((rel, target))
    if eintrag is None:
        return False
    sha, ziel = eintrag
    return hashlib.sha256(roh).hexdigest() == sha and (REPO / ziel).is_file()


def _iter_md():
    for md in sorted(REPO.rglob("*.md")):
        if any(part in _SKIP for part in md.relative_to(REPO).parts):
            continue
        yield md


def check() -> dict:
    broken = []
    checked = 0
    for md in _iter_md():
        try:
            roh = md.read_bytes()
        except OSError:
            continue
        text = roh.decode("utf-8", errors="replace")
        rel = md.relative_to(REPO).as_posix()
        # blank fenced code so a `[x](y)` inside a code sample is not treated as a live link
        text = re.sub(r"```.*?```", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.DOTALL)
        for m in _LINK.finditer(text):
            target = m.group(1).strip()
            if target.startswith(("http://", "https://", "mailto:", "#", "tel:")):
                continue
            path_part = target.split("#", 1)[0].split("?", 1)[0].strip()
            if not path_part:
                continue   # pure in-page anchor
            checked += 1
            if not (md.parent / path_part).resolve().exists():
                if _haelt_als_verschoben(rel, target, roh):
                    continue
                broken.append({"file": str(md.relative_to(REPO)), "target": target})
    return {
        "schema": "proofbundle.doc_link_check.v1",
        "verdict": "FAIL" if broken else "PASS",
        "checked": checked,
        "broken": broken,
    }


def main(argv=None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    out = check()
    if "--json" in args:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(f"[doc-link-check] {out['verdict']} · {out['checked']} local links · {len(out['broken'])} broken")
        for b in out["broken"]:
            print(f"  {b['file']} -> {b['target']}")
    return 1 if out["broken"] else 0


if __name__ == "__main__":
    sys.exit(main())
