#!/usr/bin/env python3
"""Render a release body from the versioned content source, deterministically.

WHY A SOURCE AND NOT A TITLE PREFIX. The grouping of a release comes from
``release_notes/release-source.json``, a file that is reviewed and versioned like any other, not
from the conventional-commit prefix of a pull request title. Owner word of 2026-09-23: prefixes
such as ``feat``, ``docs`` and ``fix`` "are not on their own a reliable statement about whether an
entry concerns the verifier, the CI, or an internal review process". Measured over all 48 entries of this
release: five prefixes span more than one group, and ``fix`` alone spans three — the prefix
separates none of them.

WHAT THE SOURCE KEEPS. Every entry carries the editorial short form AND the original title, author
and URL. A short form that replaces its original loses the only thing a reader can check it
against, and the set of pull requests stops being traceable the moment nobody can say where it came
from.

WHY IT IS BOUND TO ONE VERSION. This renderer refuses to run unless the source declares the version
it was asked for. It is not a general generator: the 6.1.0 source carries 6.1.0 statements, and
copying them into a later tag would restate an audit status that was measured for a different tree.
Owner word of 2026-09-23, in translation: for future releases the example script must not be
wired in unchanged as a general generator; it binds deliberately to one version and carries an
explicit version check for that reason.

DETERMINISM IS A PROPERTY, NOT A HOPE. Two runs over the same source produce byte-identical output:
no timestamps, no set iteration, no locale-dependent sorting. The entry order is the order in the
source, because the source is the reviewed artefact.

No network. No packages beyond the standard library. Python 3.10 or newer.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO = Path(__file__).resolve().parents[1]
QUELLE = REPO / "release_notes" / "release-source.json"

#: The five groups a complete source carries.
#:
#: THIS IS A DELIBERATE SECOND STATEMENT, and an adversarial counter-reading was right to call it
#: duplication before accepting the reason. The names also live in the source, so adding a group
#: there means changing this tuple too. That friction is the point: without it, `pruefe` would read
#: the group set FROM the source and a source that had silently lost four of five groups would pass
#: every check, because it would be measured against itself. A release note listing one group
#: instead of five is exactly the failure nobody notices.
#:
#: The rendered ORDER comes from the source, not from here. This tuple decides membership only.
ERWARTETE_GRUPPEN = (
    "Verifier and receipt formats",
    "Build, CI and test infrastructure",
    "Audit and evidence",
    "Documentation and interoperability",
    "Dependencies",
)


class QuellenFehler(ValueError):
    """The source cannot carry this release. Refused rather than rendered around."""


def lade(pfad: Path, version: str) -> Dict[str, Any]:
    """Read the source and REFUSE unless it declares the version that was asked for.

    The version check is the whole reason this refuses instead of adapting: a source that says
    6.1.0 carries an audit status measured on the 6.1.0 tree, and rendering it under another tag
    would publish a statement about a tree nobody examined.
    """
    if not pfad.is_file():
        raise QuellenFehler(f"no content source at {pfad}")
    try:
        daten = json.loads(pfad.read_text(encoding="utf-8"))
    except json.JSONDecodeError as fehler:
        raise QuellenFehler(f"{pfad} is not readable JSON: {fehler}") from None
    if not isinstance(daten, dict):
        raise QuellenFehler(f"{pfad} holds {type(daten).__name__}, expected an object")
    erklaert = daten.get("version")
    if erklaert != version:
        raise QuellenFehler(
            f"the source declares version {erklaert!r}, the render was asked for {version!r} — "
            f"refusing, because a source carries statements measured for ONE tree and reusing them "
            f"under another tag would publish a claim about a tree nobody examined")
    return daten


def kopf_des_baums(repo: Path) -> str | None:
    """The commit this tree is checked out at, or None when that is not measurable.

    None is NOT the same as "matches". The caller treats it as a finding, because a note that
    cannot say which tree it describes is the defect this function exists for.
    """
    import subprocess  # noqa: PLC0415 — only the CLI path needs it
    try:
        r = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    kopf = r.stdout.strip()
    return kopf if r.returncode == 0 and len(kopf) == 40 else None


def pruefe(daten: Dict[str, Any], kopf: str | None = None) -> List[str]:
    """Structural findings, all of them, rather than the first one.

    A renderer that stops at the first problem makes a caller fix them one run at a time.

    `kopf` is the commit of the tree being rendered IN. Pass it and the source's own
    `release_commit` is checked against it. See the block at that check for why.
    """
    befunde: List[str] = []
    gruppen = daten.get("gruppen")
    if not isinstance(gruppen, list) or not gruppen:
        return ["the source carries no groups"]

    namen = [g.get("name") for g in gruppen if isinstance(g, dict)]
    fehlend = [n for n in ERWARTETE_GRUPPEN if n not in namen]
    if fehlend:
        befunde.append(f"group(s) missing from the source: {', '.join(fehlend)}")
    fremd = [n for n in namen if n not in ERWARTETE_GRUPPEN]
    if fremd:
        befunde.append(f"group(s) the renderer does not know: {', '.join(str(x) for x in fremd)}")
    # A MEMBERSHIP CHECK DOES NOT COUNT, and the two above are membership checks. Codex, review of
    # 2026-09-23 on PR 256: appending a second empty group with an ALREADY KNOWN name passes both —
    # nothing is missing and nothing is unknown — so `pruefe` reported no findings, the CLI exited 0,
    # and the rendered note carried that section TWICE. Reproduced before this line went in.
    #
    # The shape was already right one level down, where `nr in gesehen` counts pull requests instead
    # of testing membership. This is the same rule at the group level, and it is the one that matters
    # more: the five groups ARE the declared boundary of the release, so a sixth section widens what
    # the note claims to cover without anything refusing it.
    doppelt = sorted({str(n) for n in namen if namen.count(n) > 1})
    if doppelt:
        befunde.append(f"group name(s) declared more than once: {', '.join(doppelt)}")

    # THE SOURCE NAMED THE TREE AND NOTHING COMPARED IT. Codex, review of 2026-09-23 on PR 256:
    # `release_commit` has always carried the commit the 48 entries describe, and the render bound
    # the VERSION and never the TREE. Measured on this branch at the time of the finding: HEAD sat
    # 12 commits beyond `dcac5aee`, including the first-parent merges #245, #247 and #253, the source
    # names none of the three, and the render exited 0 all the same. The workflow triggers on a tag
    # push, so a tag pushed from such a tree would ship those descendants while publishing "All
    # changes" and detail links for the older one.
    #
    # It is the same class as the digest this pull request already fixed one layer up: a value was
    # recorded and nothing checked it. A recorded commit nobody compares is not a binding.
    erklaert = daten.get("release_commit")
    if kopf is not None:
        if not isinstance(erklaert, str) or len(erklaert) != 40:
            befunde.append("the source declares no 40-character release_commit, so the notes cannot "
                           "say which tree they describe")
        elif erklaert != kopf:
            befunde.append(
                f"the source describes tree {erklaert[:12]} but the render is running in {kopf[:12]}"
                " — the notes would describe a different tree than the artefacts")

    gesehen: Dict[int, str] = {}
    for g in gruppen:
        if not isinstance(g, dict):
            befunde.append("a group is not an object")
            continue
        for e in g.get("eintraege") or []:
            nr = e.get("nr") if isinstance(e, dict) else None
            if not isinstance(nr, int):
                befunde.append(f"an entry in {g.get('name')!r} carries no pull request number")
                continue
            if nr in gesehen:
                # EVERY PULL REQUEST EXACTLY ONCE. A number in two groups makes the total larger
                # than the set, and the total is what a reader takes for the size of the release.
                befunde.append(
                    f"#{nr} appears in {gesehen[nr]!r} and again in {g.get('name')!r}")
            gesehen[nr] = g.get("name")
            for feld in ("kurz", "originaltitel", "autor", "url"):
                if not e.get(feld):
                    befunde.append(f"#{nr} lacks {feld}")
    return befunde


def _zeile(e: Dict[str, Any]) -> str:
    return f"- {e['kurz']}. [#{e['nr']}]({e['url']})."


def rendere(daten: Dict[str, Any]) -> str:
    """The body. Order comes from the source; nothing here sorts or dedupes behind the reader."""
    q = daten
    commit = q["release_commit"]
    basis = f"https://github.com/b7n0de/proofbundle/blob/{commit}"
    teile: List[str] = [q["kopfsatz"], ""]

    teile.append(
        f"[Changelog]({basis}/CHANGELOG.md) · "
        f"[Known limitations]({basis}/RESTRISIKO_610.md) · "
        f"[Release scope]({basis}/docs/release_scope/{q['version']}.md)")
    teile += ["", "## What changed", "", "| Area | Change | Evidence |", "|---|---|---|"]
    for z in q["was_sich_aenderte"]:
        teile.append(f"| **{z['bereich']}** | {z['aenderung']} | {z['beleg']} |")

    teile += ["", "## Before upgrading", ""]
    for v in q["vor_dem_upgrade"]:
        teile.append(f"- **{v['titel']}** {v['text']}")

    teile += ["", "<details>", "<summary>Audit status and known limitations</summary>", "",
              q["auditstatus"], "", "</details>", "", "## All changes", ""]
    gesamt = sum(len(g["eintraege"]) for g in q["gruppen"])
    teile += [f"{gesamt} pull requests, grouped by area. Shortened descriptions link to the "
              f"original discussions.", ""]
    for g in q["gruppen"]:
        n = len(g["eintraege"])
        teile += ["<details>",
                  f"<summary>{g['name']} · {n} pull request{'s' if n != 1 else ''}</summary>", ""]
        teile += [_zeile(e) for e in g["eintraege"]]
        teile += ["", "</details>", ""]

    danke = " and ".join(
        f"[@{a}](https://github.com/{'apps/' if a == 'dependabot' else ''}{a})" for a in q["danke"])
    teile += ["## Contributors", "", f"Thanks to {danke}.", "",
              f"[Full comparison {q['vorheriger_tag']}...{q['tag']}]"
              f"(https://github.com/b7n0de/proofbundle/compare/{q['vorheriger_tag']}...{q['tag']})"]
    return "\n".join(teile) + "\n"


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--version", required=True, help="the version the source must declare")
    p.add_argument("--quelle", type=Path, default=QUELLE)
    p.add_argument("--aus", type=Path, help="write here instead of stdout")
    p.add_argument("--baum", type=Path, default=Path(__file__).resolve().parents[1],
                   help="the tree whose HEAD the source's release_commit is checked against")
    p.add_argument("--kopf", help="state that HEAD instead of measuring it; for cases that must "
                                  "exercise both directions from one checkout")
    a = p.parse_args(argv)

    try:
        daten = lade(a.quelle, a.version)
    except QuellenFehler as fehler:
        print(f"  REFUSED: {fehler}", file=sys.stderr)
        return 2
    befunde = pruefe(daten, kopf=a.kopf or kopf_des_baums(a.baum))
    if befunde:
        print(f"  REFUSED: the source is not renderable ({len(befunde)} finding(s)):",
              file=sys.stderr)
        for b in befunde:
            print(f"    - {b}", file=sys.stderr)
        return 2

    text = rendere(daten)
    if a.aus:
        a.aus.write_text(text, encoding="utf-8")
        print(f"  {a.aus} · {len(text)} characters · "
              f"{sum(len(g['eintraege']) for g in daten['gruppen'])} pull requests")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
