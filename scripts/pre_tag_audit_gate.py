#!/usr/bin/env python3
"""Fundament F7 discipline — the adversarial internal audit is a gate BEFORE every release tag.

Front-Loading §7 (the Loek lesson, 16.07): the decoy-parent structural finding (F1) was found by
EXTERNAL eyes AFTER 3.3.0 shipped. The cheap fix is to run the six-lens / master-prompt-v2 adversarial
audit before EVERY tag (3.4.0, 3.5.0, 3.6.0, ...), not only before the audit-candidate — so structural
problems surface at 3.4.0 where they are cheap, not just before the external audit.

This gate mechanises "the audit was actually run for THIS release": the CHANGELOG section for the
version being released MUST record an adversarial / N-lens audit (the discipline the project has
followed since v1.3.0 — see docs/AUDIT_READINESS.md), OR an ``audit_artifacts/`` file must name the
version. A release whose CHANGELOG section records no adversarial pass is one where the pre-tag audit
was skipped — the exact regression §7 forbids.

It enforces an EXISTING convention (every released section already carries a lens/adversarial note),
so it passes for real releases and only fires when the discipline was genuinely skipped.

CLI:
  python scripts/pre_tag_audit_gate.py [--repo .] [--version X.Y.Z] [--json] [--strict]

Exit code: 0 unless ``--strict`` and no audit record for the release version is found. Wired
``--strict`` into release.yml (a pre-build step) so a tag cannot ship without the audit note.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# The discipline markers the CHANGELOG section / audit artifact must carry.
_AUDIT_MARKERS = re.compile(r"\b\d+\s*-?\s*lens(es)?\b|\badversarial\b|\bmaster[- ]prompt\b|\blinsen\b",
                            re.IGNORECASE)


def pyproject_version(repo: Path) -> str | None:
    text = (repo / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'(?m)^\s*version\s*=\s*["\']([0-9]+\.[0-9]+\.[0-9]+[^"\']*)["\']', text)
    return m.group(1) if m else None


def changelog_section(repo: Path, version: str) -> str | None:
    """Return the text of the ``## [<version>]`` section (up to the next ``## [`` heading), or None."""
    text = (repo / "CHANGELOG.md").read_text(encoding="utf-8")
    # match "## [3.3.0]" possibly followed by a date; stop at the next "## [" heading.
    pat = re.compile(r"^##\s*\[" + re.escape(version) + r"\].*?$(.*?)(?=^##\s*\[|\Z)",
                     re.MULTILINE | re.DOTALL)
    m = pat.search(text)
    return m.group(1) if m else None


def audit_artifact_for(repo: Path, version: str) -> str | None:
    """An audit_artifacts/ file whose NAME or CONTENT names the version and carries an audit marker."""
    art_dir = repo / "audit_artifacts"
    if not art_dir.is_dir():
        return None
    ver_token = version.replace(".", "")
    # recursive: the disciplined record lives in a version-scoped subfolder (audit_artifacts/360/...),
    # which a flat glob("*.md") would miss — a version-scoped subdir is exactly the discipline we locate.
    for f in sorted(art_dir.rglob("*.md")):
        name = f.name.replace(".", "").replace("_", "")
        body = f.read_text(encoding="utf-8", errors="ignore")
        if (ver_token in name or version in body) and _AUDIT_MARKERS.search(body):
            return str(f.relative_to(repo))
    return None


def evaluate(repo: Path, version: str | None = None) -> dict:
    version = version or pyproject_version(repo)
    if not version:
        return {"ok": False, "version": None,
                "reason": "could not read the release version from pyproject.toml"}
    section = changelog_section(repo, version)
    changelog_ok = bool(section and _AUDIT_MARKERS.search(section))
    artifact = audit_artifact_for(repo, version)
    ok = changelog_ok or bool(artifact)
    return {
        "ok": ok,
        "version": version,
        "changelog_section_found": section is not None,
        "changelog_records_audit": changelog_ok,
        "audit_artifact": artifact,
        "reason": None if ok else (
            f"no adversarial/N-lens audit recorded for {version}: the CHANGELOG [{version}] section "
            "carries no lens/adversarial note and no audit_artifacts file names it — run the pre-tag "
            "adversarial audit (master-prompt-v2) and record it before tagging (Front-Load §7)"),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--repo", type=Path, default=Path("."))
    p.add_argument("--version", default=None, help="override the release version (default: pyproject)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--strict", action="store_true",
                   help="exit non-zero if no pre-tag adversarial audit is recorded for the version")
    args = p.parse_args(argv)
    result = evaluate(args.repo.resolve(), args.version)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        status = "OK" if result["ok"] else "MISSING"
        print(f"[pre-tag-audit] version={result['version']} audit-recorded={result['ok']} ({status})")
        if result.get("audit_artifact"):
            print(f"  artifact: {result['audit_artifact']}")
        if not result["ok"]:
            print(f"  {result['reason']}")
    if args.strict and not result["ok"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
