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

# RT10-PRETAG-02: a bare marker SUBSTRING is not proof the audit ran — a line like "the adversarial audit
# did NOT run" / "adversarial review pending" matches the marker but NEGATES it. A marker only counts as a
# POSITIVE attestation when its own line is not negated by one of these (line-scoped, so a negation elsewhere
# in the file does not suppress a genuine positive line).
_AUDIT_NEGATION = re.compile(
    r"\bnot\b|\bnicht\b|\bno\b|\bnever\b|\bnie\b|\bwithout\b|\bohne\b|\bskip(?:ped|ping)?\b|\bpending\b"
    r"|\bdeferred?\b|\bpostponed?\b|\bvertagt\b|\bverschoben\b|\bnoch\s+nicht\b|\bnot\s+yet\b|\btbd\b|\btodo\b"
    r"|\bt\.?b\.?d\.?\b|did\s*n[o']t|has\s*n[o']t|have\s*n[o']t|was\s*n[o']t|were\s*n[o']t|is\s*n[o']t"
    r"|\bunrun\b|\bnot\s+run\b|\bfailed\s+to\b|\bausstehend\b|\bnicht\s+durchgef|\bplanned\b|\bgeplant\b"
    r"|\bcancell?ed\b|\baborted\b|\bwaived\b|\bincomplete\b|\bunfinished\b|\babgebrochen\b|\bstorniert\b",
    re.IGNORECASE)


def _positive_audit_marker(text: str) -> bool:
    """True iff some PARAGRAPH asserts an adversarial/N-lens audit was run — a discipline marker in a
    paragraph that carries no negation.

    RT10-PRETAG-03 (2026-08-16, found by triggering it): the scope used to be the physical LINE, and a
    wrapped sentence walked straight through the RT10-PRETAG-02 negation guard. Measured live on a real
    release candidate, where an honest retraction being written INTO the CHANGELOG flipped the gate to
    ``ok: true, changelog_records_audit: true`` for roughly two minutes:

        …never shipped a user-facing CLI flag in a patch release. That claim was falsified during the pre-tag
        adversarial audit and is retracted here rather than quietly deleted: four patch releases have shipped

    The second line opens with ``adversarial`` and carries no negation token of its own — the words that
    take it back (``never``, and the fact that the audit was still running) sit on the line above. Nothing
    was crafted to defeat the guard; ordinary prose wrapping at 110 columns did it, and it will do it again
    to anyone who writes a careful sentence about an audit that has not finished. The guard was therefore
    most easily defeated by exactly the kind of honest text this project requires of itself.

    Paragraph scope is strictly STRICTER than line scope — a paragraph contains its lines, so it can only
    ever bring MORE negation tokens into view, never fewer. No text that the old rule rejected can be
    accepted by the new one.

    Sentence scope was measured first and REJECTED: it still returns True on the block above, because
    "falsified" is not a negation token and the sentence carrying ``adversarial`` genuinely contains none.
    A finer scope does not help when the negation lives in the surrounding argument rather than in a word.

    The counter-direction is measured too, because a stricter gate that rejects genuine records would just
    be a different defect: the real ``audit_artifacts/370/pre_tag_adversarial_audit_370.md`` still returns
    True. Its opening paragraph pairs the claim with a "NOT a substitute for the external audit"
    disclaimer, so that paragraph is correctly not counted — and the later "Six diverse falsification-first
    lenses …" paragraph carries the marker with no negation, which is the attestation. House style survives.

    HONEST LIMIT, unchanged by this fix: this infers a fact from free prose, and prose inference stays
    defeatable in principle. The durable answer is an explicit attestation token that means one thing
    ("pre-tag-adversarial-audit: RUN | version=X.Y.Z"), which is what the version-consistency-gate branch
    moves to. This narrows a live hole in the mechanism that guards releases today; it does not claim to
    have made prose inference sound.
    """
    for absatz in re.split(r"\n\s*\n", text):
        if _AUDIT_MARKERS.search(absatz) and not _AUDIT_NEGATION.search(absatz):
            return True
    return False


def pyproject_version(repo: Path) -> str | None:
    text = (repo / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'(?m)^\s*version\s*=\s*["\']([0-9]+\.[0-9]+\.[0-9]+[^"\']*)["\']', text)
    return m.group(1) if m else None


def changelog_section(repo: Path, version: str) -> str | None:
    """Return the text of the ``## [<version>]`` section (up to the next ``## [`` heading), or None.

    Returns None (not a crash) when CHANGELOG.md is absent, so the gate can be evaluated against a
    partial/temporary repo tree (e.g. a discrimination fixture that only carries audit_artifacts/)."""
    p = repo / "CHANGELOG.md"
    if not p.is_file():
        return None
    text = p.read_text(encoding="utf-8")
    # match "## [3.3.0]" possibly followed by a date; stop at the next "## [" heading.
    pat = re.compile(r"^##\s*\[" + re.escape(version) + r"\].*?$(.*?)(?=^##\s*\[|\Z)",
                     re.MULTILINE | re.DOTALL)
    m = pat.search(text)
    return m.group(1) if m else None


def _version_token(version: str) -> str:
    """The compact directory token for a version, e.g. ``3.6.0`` -> ``360``."""
    return version.replace(".", "")


def audit_records_for(repo: Path, version: str) -> list[str]:
    """Every ``*.md`` inside the version-scoped subfolder ``audit_artifacts/<token>/`` that carries a
    discipline marker (N-lens / adversarial / master-prompt / Linsen), deterministically ordered.

    The version-scoped SUBFOLDER is the anchor — a directory named EXACTLY after the compact version
    token (``360`` for 3.6.0). This is why:
      * a note anywhere else in the ``audit_artifacts/`` tree (a pre-sorting foreign file) is not a
        3.6.0 record — only the exact ``audit_artifacts/360/`` subfolder is scanned, never the whole
        tree, so sort order across the tree can no longer let a foreign file win;
      * a sibling ``audit_artifacts/1360/`` folder or a ``review_1360_notes.md`` whose name merely
        embeds the digits is NOT selected — the anchor is the exact directory ``360``, never a raw
        substring, so ``360`` cannot match ``1360``.

    This returns the FULL candidate list (not just the first): a caller that needs an additional
    predicate (C12.2 needs the '0 open P0/P1' line) scans all candidates, so a decoy record that
    carries the marker but omits the line cannot mask a genuine record that has it.

    Known limitation (No-Fake, honestly declared — see docs/readiness_pack/AUDITOR_OPEN_POINTS.md):
    the scan is ``rglob`` rooted at the exact subfolder, so it never walks the wider tree, but it DOES
    follow a symlink placed inside ``audit_artifacts/<token>/`` — a symlink pointing outside the repo
    would be traversed. The committed tree carries no such symlink; this is a declared boundary."""
    scoped = repo / "audit_artifacts" / _version_token(version)
    if not scoped.is_dir():
        return []
    out: list[str] = []
    for f in sorted(scoped.rglob("*.md")):
        if not f.is_file():
            continue
        body = f.read_text(encoding="utf-8", errors="ignore")
        if _positive_audit_marker(body):   # RT10-PRETAG-02: a negated marker line does not count
            out.append(str(f.relative_to(repo)))
    return out


def audit_artifact_for(repo: Path, version: str) -> str | None:
    """The version-scoped adversarial audit record locator (existence, for C12.1): the first ``*.md``
    under ``audit_artifacts/<token>/`` carrying a discipline marker, or None.

    Anchored to the exact ``audit_artifacts/<token>/`` subfolder (see ``audit_records_for``): a file
    elsewhere in the tree, a sibling ``1360/`` folder, or a ``review_1360_notes.md`` is never a
    3.6.0 record."""
    recs = audit_records_for(repo, version)
    return recs[0] if recs else None


def evaluate(repo: Path, version: str | None = None) -> dict:
    version = version or pyproject_version(repo)
    if not version:
        return {"ok": False, "version": None,
                "reason": "could not read the release version from pyproject.toml"}
    section = changelog_section(repo, version)
    changelog_ok = bool(section and _positive_audit_marker(section))  # RT10-PRETAG-02 negation guard
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
