#!/usr/bin/env python3
"""Can the workflows produce every status check the branch ruleset requires?

WHY THIS EXISTS. A required status check has two failure modes, red and ABSENT, and only the
first is visible. A red check shows a red line. An absent one shows nothing at all: the pull
request stays BLOCKED with no check red on it, and GitHub offers no field that separates "still
running" from "will never be reported" -- `mergeStateStatus` is BLOCKED for both. Whoever looks
at the red lines therefore repairs exactly the checks that do not block.

Measured in this repository on 2026-09-16: pull requests 209, 210, 211 and 212 all stood at
BLOCKED with mergeable=MERGEABLE, no required check red, and four of the seven required contexts
absent -- not failing, not skipped, simply never created, because the test matrix produces five
Python versions only under a condition. Pull request 211 is the fix FOR the one red advisory
check, that check was green on it, and it was blocked all the same.

This is the third instance of one class here. The first was a missing `labeled` trigger, closed
2026-09-14 in commit 89301253. The second was a missing `merge_group` trigger in
fork-pr-isolation.yml, the second of two files that carry required contexts. Each was found by a
person reading, never by a mechanism. Hence this gate.

WHAT IT DOES NOT DO. It does not evaluate GitHub expressions. Anything it cannot read literally
it reports as NOT_MEASURABLE with the reason, and NOT_MEASURABLE is a failure, never a pass --
an unknown must not read as fine. In particular it understands exactly one conditional matrix
shape, `fromJSON( <condition> && '<json>' || '<json>' )`, because that is the shape this
repository uses; it takes the second literal as the ordinary case and names the condition.

KNOWN TRAPS, from the survey of prior art on 2026-09-16, each guarded below:
  * A job skipped by `if:` reports Success, so a required check on a conditional job never blocks.
    An ABSENT context is stricter than a skipped one: it does not report at all.
  * A reusable workflow reports as `<caller job id> / <called job name>`, not as the called job's
    own name. Reading only the called file yields the wrong context name.
  * A job `name:` may interpolate matrix values, so the context name exists only after expansion.
  * `cond && A || B` falls through to B whenever A is falsy, regardless of cond. Empty or `[]` in
    the true arm silently disables the whole condition.

Exit 0 when every declared context is produced, either unconditionally or under a named
condition. Exit 1 when one is unreachable or not measurable.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:                                    # pragma: no cover - guarded, see below
    yaml = None

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"
DECLARATION = REPO / ".github" / "required_status_checks.json"

ALWAYS = "produced"
GATED = "produced-only-if"
ABSENT = "never-produced"
UNKNOWN = "not-measurable"

#: `fromJSON( <condition> && '<true arm>' || '<false arm>' )`. The false arm is the ordinary case.
_TERNARY = re.compile(
    r"fromJSON\(\s*(?P<cond>.*?)&&\s*'(?P<wahr>\[[^']*\])'\s*\|\|\s*'(?P<sonst>\[[^']*\])'\s*\)",
    re.S,
)
_MATRIX_REF = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")


def _lade(pfad: Path) -> dict:
    """Read one workflow. A file that does not parse is NOT an empty file."""
    if yaml is None:
        raise RuntimeError(
            "PyYAML is missing, so no workflow can be read. That is not an empty result: without "
            "the parser this gate cannot tell a reachable context from an absent one, and it must "
            "not pretend otherwise. PyYAML is declared in the [test] extra of pyproject.toml.")
    d = yaml.safe_load(pfad.read_text(encoding="utf-8"))
    if not isinstance(d, dict):
        raise ValueError(f"{pfad.name}: top level is {type(d).__name__}, expected a mapping")
    return d


def matrix_werte(job: dict, roh: str) -> tuple[dict[str, list], dict[str, list], str | None, str | None]:
    """Return (ordinary values, gated values, condition, note) per matrix key.

    The NOTE carries a defect the value sets alone cannot express. An empty true arm makes the
    whole condition dead: `cond && '[]' || B` yields B for every value of cond. The resulting
    context set is the same as if the condition had been deleted, so counting values would never
    reveal it -- the reader has to be told in words, or the dead condition sits there looking
    live. Measured as a surviving mutant against this gate's own contracts on 2026-09-16.

    Three shapes are understood. A literal list is both ordinary and gated. The one conditional
    shape this repository uses splits into the two arms. Anything else yields an empty ordinary
    set, which the caller turns into NOT_MEASURABLE rather than into a pass.
    """
    m = ((job.get("strategy") or {}).get("matrix")) or {}
    if not isinstance(m, dict):
        return {}, {}, None, None
    gewoehnlich: dict[str, list] = {}
    gegated: dict[str, list] = {}
    bedingung: str | None = None
    hinweis: str | None = None
    for schluessel, wert in m.items():
        if schluessel in ("include", "exclude"):
            continue
        if isinstance(wert, list):
            gewoehnlich[schluessel] = list(wert)
            gegated[schluessel] = list(wert)
            continue
        if isinstance(wert, str) and "fromJSON" in wert:
            t = _TERNARY.search(wert)
            if not t:
                gewoehnlich[schluessel] = []
                gegated[schluessel] = []
                continue
            try:
                wahr = json.loads(t.group("wahr"))
                sonst = json.loads(t.group("sonst"))
            except json.JSONDecodeError:
                gewoehnlich[schluessel] = []
                gegated[schluessel] = []
                continue
            # cond && A || B falls through to B whenever A is falsy, condition or not.
            if not wahr:
                # `cond && '[]' || B` is B for every cond. The condition is dead, and the value
                # sets look exactly as they would without it -- only this note says so.
                gewoehnlich[schluessel] = list(sonst)
                gegated[schluessel] = list(sonst)
                hinweis = (f"matrix key {schluessel!r}: the true arm of the condition is empty, so "
                           f"`cond && '[]' || ...` falls through for every value of the condition. "
                           f"The condition is dead code and produces nothing.")
                continue
            gewoehnlich[schluessel] = list(sonst)
            gegated[schluessel] = list(wahr)
            bedingung = " ".join(t.group("cond").split())
            continue
        gewoehnlich[schluessel] = []
        gegated[schluessel] = []
    return gewoehnlich, gegated, bedingung, hinweis


def kontextnamen(job_id: str, job: dict, werte: dict[str, list]) -> list[str]:
    """The context names this job reports, after matrix expansion.

    Without a matrix the context is the job's `name:` or, lacking one, its id. With a matrix and
    no custom name GitHub appends the values in parentheses. A custom name that interpolates
    matrix values is expanded here, because the context name only exists after substitution.
    """
    roh_name = job.get("name")
    if not werte:
        return [str(roh_name) if roh_name else job_id]
    schluessel = sorted(werte)
    if roh_name and _MATRIX_REF.search(str(roh_name)):
        namen = []
        for k in schluessel:
            for v in werte[k]:
                namen.append(_MATRIX_REF.sub(
                    lambda m, _v=v, _k=k: str(_v) if m.group(1) == _k else m.group(0),
                    str(roh_name)))
        return namen
    basis = str(roh_name) if roh_name else job_id
    namen = []
    for k in schluessel:
        for v in werte[k]:
            namen.append(f"{basis} ({v})")
    return namen


def erhebe(verzeichnis: Path | None = None) -> dict:
    """Every context the workflows can report, with how it arises."""
    wf = verzeichnis or WORKFLOWS
    gewoehnlich: dict[str, str] = {}
    gegated: dict[str, tuple[str, str]] = {}
    unlesbar: list[str] = []
    hinweise: list[str] = []
    for pfad in sorted(wf.glob("*.yml")) + sorted(wf.glob("*.yaml")):
        try:
            doc = _lade(pfad)
        except Exception as e:                          # noqa: BLE001
            unlesbar.append(f"{pfad.name}: {type(e).__name__}: {e}")
            continue
        for job_id, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            if job.get("uses"):
                # A reusable workflow reports as "<caller job id> / <called job name>". Reading the
                # called file would give the wrong name on its own, so the caller id is carried.
                unlesbar.append(
                    f"{pfad.name}:{job_id}: calls a reusable workflow; its context is "
                    f"'{job_id} / <job name inside the called file>' and is not derived here")
                continue
            gew, geg, bedingung, hinweis = matrix_werte(job, pfad.read_text(encoding="utf-8"))
            if hinweis:
                hinweise.append(f"{pfad.name}:{job_id}: {hinweis}")
            # DIE `if:`-BEDINGUNG DES JOBS, und sie war bis 2026-09-16 ein blinder Fleck. Ein Job
            # hinter einem `if:` laeuft nicht immer, seine Kontexte sind also nicht unbedingt
            # erzeugt. Gefunden von einer fremden Modellfamilie in der Gegenlesung: ein
            # Pflicht-Job mit `if: false` wurde als `produced` gemeldet — ein STILLES
            # Falschurteil, nicht ein `not-measurable`. Dazu die Haerte dahinter: ein durch `if:`
            # uebersprungener Job meldet GitHub ein Success, ein Pflichtkontext auf ihm blockiert
            # also nie und beweist auch nichts.
            job_if = job.get("if")
            if job_if is not None:
                als_text = " ".join(str(job_if).split())
                if als_text.lower() in ("false", "${{ false }}"):
                    hinweise.append(
                        f"{pfad.name}:{job_id}: `if: {als_text}` — dieser Job laeuft NIE, seine "
                        f"Kontexte entstehen unter keiner Bedingung")
                    continue
                for name in kontextnamen(job_id, job, gew or geg):
                    if name not in gewoehnlich:
                        gegated.setdefault(name, (pfad.name, f"job `if: {als_text}`"))
                continue
            hat_matrix = bool((job.get("strategy") or {}).get("matrix"))
            if hat_matrix and not any(gew.values()) and not any(geg.values()):
                unlesbar.append(f"{pfad.name}:{job_id}: matrix values not readable literally")
                continue
            for name in kontextnamen(job_id, job, gew):
                gewoehnlich.setdefault(name, pfad.name)
            if bedingung:
                for name in kontextnamen(job_id, job, geg):
                    if name not in gewoehnlich:
                        gegated.setdefault(name, (pfad.name, bedingung))
    return {"gewoehnlich": gewoehnlich, "gegated": gegated, "unlesbar": unlesbar,
            "hinweise": hinweise}


def pruefe(declaration: Path | None = None, verzeichnis: Path | None = None) -> dict:
    d = declaration or DECLARATION
    if not d.is_file():
        return {"verdict": UNKNOWN, "reason": f"{d} is missing; nothing declares what is required"}
    erklaert = json.loads(d.read_text(encoding="utf-8"))
    verlangt = list(erklaert.get("required_contexts") or [])
    if not verlangt:
        return {"verdict": UNKNOWN, "reason": f"{d.name} declares no required context"}
    erhoben = erhebe(verzeichnis)
    je: list[dict] = []
    for k in verlangt:
        if k in erhoben["gewoehnlich"]:
            je.append({"context": k, "state": ALWAYS, "from": erhoben["gewoehnlich"][k]})
        elif k in erhoben["gegated"]:
            datei, bed = erhoben["gegated"][k]
            je.append({"context": k, "state": GATED, "from": datei, "condition": bed})
        else:
            je.append({"context": k, "state": ABSENT, "from": None})
    zahl = {ALWAYS: 0, GATED: 0, ABSENT: 0}
    for e in je:
        zahl[e["state"]] += 1
    verdict = ABSENT if zahl[ABSENT] else (GATED if zahl[GATED] else ALWAYS)
    return {"verdict": verdict, "per_context": je, "counts": zahl,
            "unreadable": erhoben["unlesbar"], "dead_conditions": erhoben["hinweise"],
            "produced_contexts": sorted(erhoben["gewoehnlich"]),
            "ruleset": erklaert.get("ruleset"), "branch": erklaert.get("branch")}


def erklaerung_gegen_regelsatz(declaration: Path | None = None, repo: str | None = None) -> dict:
    """Stimmt die ERKLAERUNG mit dem Regelsatz ueberein, den GitHub wirklich fuehrt?

    Die Erklaerung in `.github/required_status_checks.json` ist eine Kopie, und eine Kopie driftet.
    Wer den Regelsatz aendert und die Datei vergisst, bekommt vom Offline-Tor weiter ein Urteil, das
    sich auf gestrige Pflichten bezieht: alles gruen, gemessen an der falschen Menge. Diese Funktion
    holt die Wahrheit und vergleicht.

    SIE BRAUCHT DAS NETZ und ist deshalb ausdruecklich KEIN Teil des Offline-Tors. Ein Aufruf ohne
    Netz gibt `not-measurable` mit Grund zurueck, nie ein stilles Bestehen: ein Vergleich, der nicht
    stattfand, ist kein Vergleich.
    """
    d = declaration or DECLARATION
    if not d.is_file():
        return {"verdict": UNKNOWN, "reason": f"{d} is missing; there is nothing to compare"}
    erklaert = json.loads(d.read_text(encoding="utf-8"))
    rs_id = erklaert.get("ruleset_id")
    ziel = repo or erklaert.get("repo") or "b7n0de/proofbundle"
    if not rs_id:
        return {"verdict": UNKNOWN, "reason": f"{d.name} names no ruleset_id to compare against"}
    import subprocess  # noqa: PLC0415 - nur auf diesem, netzabhaengigen Pfad
    try:
        r = subprocess.run(["gh", "api", f"repos/{ziel}/rulesets/{rs_id}"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return {"verdict": UNKNOWN, "reason": f"gh could not be run ({type(e).__name__})"}
    if r.returncode != 0:
        return {"verdict": UNKNOWN,
                "reason": f"gh api exited {r.returncode}: {r.stderr.strip()[:200]}"}
    try:
        doc = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        return {"verdict": UNKNOWN, "reason": f"the ruleset did not parse as JSON ({e})"}
    echt: list[str] = []
    for regel in doc.get("rules") or []:
        if regel.get("type") == "required_status_checks":
            echt = [c.get("context") for c
                    in (regel.get("parameters") or {}).get("required_status_checks") or []]
    erklaert_menge = set(erklaert.get("required_contexts") or [])
    echt_menge = set(echt)
    return {
        "verdict": ALWAYS if erklaert_menge == echt_menge else ABSENT,
        "ruleset": doc.get("name"), "ruleset_id": rs_id, "repo": ziel,
        "declared_only": sorted(erklaert_menge - echt_menge),
        "ruleset_only": sorted(echt_menge - erklaert_menge),
        "in_both": sorted(erklaert_menge & echt_menge),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--declaration", type=Path, default=None)
    ap.add_argument("--workflows", type=Path, default=None)
    ap.add_argument("--verify-declaration", action="store_true",
                    help="NETZ: die Erklaerung gegen den echten Regelsatz halten und Drift melden. "
                         "Nicht Teil des Offline-Tors; ohne Netz lautet das Urteil not-measurable.")
    ap.add_argument("--repo", default=None, help="owner/name fuer --verify-declaration")
    ap.add_argument("--allow-gated", action="store_true",
                    help="treat a context that is only produced under a NAMED condition as a pass. "
                         "Off by default: a condition nobody sets is a pull request nobody can merge.")
    a = ap.parse_args(argv)
    if a.verify_declaration:
        d = erklaerung_gegen_regelsatz(a.declaration, a.repo)
        if a.json:
            print(json.dumps(d, ensure_ascii=False, indent=2))
        else:
            print(f"[declaration] {d.get('repo')} ruleset {d.get('ruleset')}: {d['verdict']}")
            if d.get("reason"):
                print(f"  reason: {d['reason']}")
            for k, wort in (("declared_only", "declared but NOT required"),
                            ("ruleset_only", "required but NOT declared")):
                for c in d.get(k) or []:
                    print(f"  {wort}: {c}")
        return 0 if d["verdict"] == ALWAYS else 1
    r = pruefe(a.declaration, a.workflows)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print(f"[required-checks] ruleset {r.get('ruleset')} on {r.get('branch')}: {r['verdict']}")
        for e in r.get("per_context", []):
            zeile = f"  {e['state']:18} {e['context']}"
            if e.get("condition"):
                zeile += f"   only if: {e['condition']}"
            elif e.get("from"):
                zeile += f"   from {e['from']}"
            print(zeile)
        for h in r.get("dead_conditions", []):
            print(f"  dead-condition     {h}")
        for u in r.get("unreadable", []):
            print(f"  not-measurable     {u}")
    if r.get("dead_conditions"):
        # A condition that can never take effect is a silent lie in the workflow, even when the
        # produced contexts happen to be right today.
        return 1
    if r["verdict"] == ALWAYS:
        return 0
    if r["verdict"] == GATED and a.allow_gated:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
