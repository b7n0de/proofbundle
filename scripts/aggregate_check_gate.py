#!/usr/bin/env python3
"""The one required status check, and the wiring that keeps it honest.

WHY THIS EXISTS. A required status check has two failure modes, red and ABSENT, and only the
first is visible. An absent context produces no line, no colour and no message; the pull request
simply stays BLOCKED with nothing red on it. Three times in this repository a required context
could not be produced, and a person reading found it every time, never a mechanism.

WHAT GITHUB ACTUALLY SAYS, quoted rather than summarised, because the difference matters. The
documentation does NOT recommend an aggregate job. It recommends the rule underneath: "Avoid
requiring workflows that can be skipped", and it states that a job skipped by a conditional
"reports 'Success'" without blocking a merge. The aggregate job is one way to obey that rule --
community practice, not a documented recommendation -- and this file does not call it more than
that.

WHAT THE AGGREGATE JOB CAN AND CANNOT DO, measured, not assumed:

  IT CAN remove the conditional contexts from the required set. `test (3.10)` .. `test (3.14)`
  are produced only under the landing condition, so four of them are absent on an ordinary pull
  request. One always-running job replaces all six ci.yml contexts.

  IT CANNOT cover `guard`. That job lives in fork-pr-isolation.yml, and `needs` never reaches
  across workflow files. The required set therefore goes from seven to TWO, not to one. `guard`
  is unconditional, carries no matrix and has the merge_group trigger, so it is not exposed to
  this class -- but saying "one required context" would be false, and this gate refuses to.

  IT CANNOT save a run that never starts. If a trigger is missing, the workflow does not run,
  the aggregate context is absent, and we are back at the same class one level up. That is why
  the advisory reachability gate stays wired even after this job becomes the required check:
  remove the aggregate job and the class is invisible again, with nothing to say so.

THE PROMISE THIS GATE HAD TO RESCUE. The ruleset carries no merge-queue rule (measured
2026-09-16 on ruleset 18386496). Without one, required checks are judged on the pull request
head. Reducing the required set to the aggregate job alone would therefore have let a pull
request merge with the test suite run on ONE Python version, because the five-version matrix
only fires under the landing condition -- the five required contexts were the thing enforcing it.
So this gate measures the matrix instead of trusting it: every `test` leg records the version it
ran, and the aggregate job fails unless the set of recorded versions equals the declared one. The
remedy is named in the failure message, which is the whole improvement over today: the pull
request is still held back before landing, but now it says why instead of standing BLOCKED with
nothing red on it.

WHY THE VERSIONS ARE MEASURED AND NOT DERIVED. The landing condition already exists twice in
ci.yml (the matrix expression and the mutation gate), kept identical by a contract. A third copy
here would be a third promise about one invariant, and three promises hold exactly until somebody
edits one of them. The legs report what they ran; this file counts. Same shape as the mutation
shards in the file next door, which report their own operator counts rather than being trusted.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CI = REPO / ".github" / "workflows" / "ci.yml"
DECLARATION = REPO / ".github" / "required_status_checks.json"

#: The job id of the aggregate check. It is also the status-check context name, because the job
#: carries no `name:` -- and that coupling is deliberate: a `name:` would let the context drift
#: away from the id without a single line changing here.
SAMMEL_JOB = "all-checks-passed"

#: The one job the aggregate never waits on: itself.
NIE_IN_NEEDS = frozenset({SAMMEL_JOB})

#: Jobs whose SKIP is accepted, each with the reason. A skip that is not on this list is red --
#: that is the whole point, since GitHub reports a skipped job as success. The list is pinned
#: against ci.yml in both directions by the contracts: every entry must really carry an `if:`,
#: and every job carrying an `if:` must be named here. Neither half alone is enough. Without the
#: first, the list collects names that no longer skip and quietly widens; without the second, a
#: new `if:` on `test` would make a skipped test suite an accepted outcome.
ERLAUBT_UEBERSPRUNGEN: dict[str, str] = {
    "branch-base": "advisory, runs on pull_request only",
    "required-check-reachability": "advisory, runs on pull_request only",
    "mutation": "the heavy layer runs at the landing candidate only (B3)",
    "mutation-summary": "carries the same predicate as its producer, by contract",
}

#: Job results that are red no matter which job produced them.
ROT = frozenset({"failure", "cancelled", "timed_out"})


def _einzeilig(text: object, grenze: int = 200) -> str:
    """Fold any value that enters a report line onto one line.

    A value read out of someone else's file -- a job result, an artifact name -- is an INPUT, not
    a promise. A newline in it forges whole report lines that look like this tool's own output.
    """
    roh = "".join(ch if ch.isprintable() or ch.isspace() else " " for ch in str(text))
    eins = " ".join(roh.split())
    return eins if len(eins) <= grenze else eins[: grenze - 1] + "…"


def _deklaration(pfad: Path | None = None) -> dict:
    p = pfad or DECLARATION
    return json.loads(p.read_text(encoding="utf-8"))


def _ci_text(pfad: Path | None = None) -> str:
    return (pfad or CI).read_text(encoding="utf-8")


def _jobs(ci_text: str) -> dict:
    import yaml  # imported here so --judge works without PyYAML on the runner

    d = yaml.safe_load(ci_text)
    return dict(d.get("jobs") or {})


# ---------------------------------------------------------------- judging a run


def beurteile(needs: dict, gelaufene_versionen: set[str], erwartete_versionen: list[str]) -> tuple[int, list[str]]:
    """The verdict of the aggregate job. Returns (exit code, report lines).

    `needs` is the `needs` context of the workflow run: {job_id: {"result": ..., ...}}.
    """
    zeilen: list[str] = []
    fehler: list[str] = []

    if not isinstance(needs, dict) or not needs:
        return 1, ["ERROR: the needs context is empty or not an object -- nothing was measured, "
                   "and an unmeasured run is not a passing one"]

    for jid in sorted(needs):
        eintrag = needs[jid]
        ergebnis = ""
        if isinstance(eintrag, dict):
            ergebnis = str(eintrag.get("result") or "")
        ergebnis_k = _einzeilig(ergebnis, 40)
        if not ergebnis:
            fehler.append(f"{_einzeilig(jid, 60)}: no result reported -- that is not a pass")
            zeilen.append(f"  {jid:30s} (no result)")
            continue
        if ergebnis in ROT:
            fehler.append(f"{_einzeilig(jid, 60)}: {ergebnis_k}")
            zeilen.append(f"  {jid:30s} {ergebnis_k}  <-- red")
        elif ergebnis == "skipped":
            if jid in ERLAUBT_UEBERSPRUNGEN:
                zeilen.append(f"  {jid:30s} skipped (accepted: {ERLAUBT_UEBERSPRUNGEN[jid]})")
            else:
                fehler.append(
                    f"{_einzeilig(jid, 60)}: skipped, and this job is not on the accepted list. "
                    "GitHub reports a skipped job as success, so an unaccounted skip is exactly "
                    "the hole this check exists to close"
                )
                zeilen.append(f"  {jid:30s} skipped  <-- not accepted")
        elif ergebnis == "success":
            zeilen.append(f"  {jid:30s} success")
        else:
            fehler.append(f"{_einzeilig(jid, 60)}: unknown result {ergebnis_k!r} -- "
                          "an unknown state is not a pass")
            zeilen.append(f"  {jid:30s} {ergebnis_k}  <-- unknown")

    erwartet = sorted(set(erwartete_versionen))
    gelaufen = sorted({_einzeilig(v, 20) for v in gelaufene_versionen})
    zeilen.append(f"  python versions run: {', '.join(gelaufen) or '(none)'}")
    zeilen.append(f"  python versions declared: {', '.join(erwartet)}")
    if set(gelaufen) != set(erwartet):
        fehlend = sorted(set(erwartet) - set(gelaufen))
        zusatz = sorted(set(gelaufen) - set(erwartet))
        teil = []
        if fehlend:
            teil.append(f"missing {', '.join(fehlend)}")
        if zusatz:
            teil.append(f"unexpected {', '.join(zusatz)}")
        fehler.append(
            "the test matrix did not run the declared Python versions (" + "; ".join(teil) + "). "
            "The heavy layer runs at the landing candidate only: add the label 'landung' to this "
            "pull request, or push the branch as release/*. This check is held back on purpose, "
            "and it says so rather than leaving the pull request BLOCKED with nothing red on it"
        )

    if fehler:
        return 1, zeilen + [""] + [f"ERROR: {f}" for f in fehler]
    return 0, zeilen + ["", f"{SAMMEL_JOB}: every needed job reported, none red, "
                            f"matrix complete over {len(erwartet)} declared versions"]


def _versionen_aus_artefakten(ordner: Path) -> set[str]:
    """Read the version each `test` leg recorded for itself.

    The legs report what they RAN. Deriving it from the matrix expression instead would be a
    third copy of the landing condition, and an invariant in three places is three promises.
    """
    gefunden: set[str] = set()
    if not ordner.is_dir():
        return gefunden
    for p in sorted(ordner.rglob("test-leg-*.txt")):
        try:
            roh = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = re.search(r"^python-version=([0-9][0-9.a-zA-Z\-]*)\s*$", roh, re.M)
        if m:
            gefunden.add(m.group(1))
    return gefunden


# ---------------------------------------------------------------- checking the wiring


def pruefe_verdrahtung(ci_text: str | None = None, deklaration: dict | None = None) -> list[str]:
    """Is the aggregate job wired so that it can actually carry the promise? Returns findings."""
    text = ci_text if ci_text is not None else _ci_text()
    decl = deklaration if deklaration is not None else _deklaration()
    jobs = _jobs(text)
    funde: list[str] = []

    if SAMMEL_JOB not in jobs:
        return [f"{SAMMEL_JOB} is not a job in ci.yml -- the required context cannot be produced "
                f"by anything, which is the failure mode this whole gate exists against"]

    sammel = jobs[SAMMEL_JOB] or {}

    kontexte = [str(c) for c in (decl.get("required_contexts") or [])]
    if SAMMEL_JOB not in kontexte:
        funde.append(f"{SAMMEL_JOB} is not in required_contexts -- the job runs but nothing "
                     f"requires it, so it gates nothing")

    bedingung = str(sammel.get("if") or "")
    if "always()" not in bedingung:
        funde.append(f"{SAMMEL_JOB} has if={bedingung!r} and does not call always() -- a job that "
                     f"can be skipped reports success and blocks nothing")
    if sammel.get("continue-on-error"):
        funde.append(f"{SAMMEL_JOB} carries continue-on-error, so its red would not be red")
    if sammel.get("name"):
        funde.append(f"{SAMMEL_JOB} carries a name:, which becomes the context instead of the job "
                     f"id -- the required context would then drift without this file changing")

    needs = sammel.get("needs") or []
    if isinstance(needs, str):
        needs = [needs]
    needs = [str(n) for n in needs]
    soll = set(jobs) - NIE_IN_NEEDS
    fehlend = sorted(soll - set(needs))
    fremd = sorted(set(needs) - soll)
    if fehlend:
        funde.append(f"{SAMMEL_JOB} does not wait on: {', '.join(fehlend)} -- a job outside the "
                     f"needs list cannot turn this check red, whatever it does")
    if fremd:
        funde.append(f"{SAMMEL_JOB} waits on jobs that ci.yml does not define: {', '.join(fremd)}")

    mit_if = {j for j, v in jobs.items() if (v or {}).get("if") and j not in NIE_IN_NEEDS}
    ohne_eintrag = sorted(mit_if - set(ERLAUBT_UEBERSPRUNGEN))
    ohne_if = sorted(set(ERLAUBT_UEBERSPRUNGEN) - mit_if)
    if ohne_eintrag:
        funde.append(f"these jobs carry an if: and can therefore be skipped, but the accepted-skip "
                     f"list does not name them: {', '.join(ohne_eintrag)}")
    if ohne_if:
        funde.append(f"the accepted-skip list names jobs that carry no if: and cannot skip: "
                     f"{', '.join(ohne_if)} -- the list widens without anyone deciding to")

    versionen = [str(v) for v in (decl.get("required_python_versions") or [])]
    if not versionen:
        funde.append("required_python_versions is missing from the declaration -- without it the "
                     "aggregate job cannot tell a full matrix from a single leg")

    return funde


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--judge", action="store_true",
                    help="judge one run: needs results plus the versions the legs recorded")
    ap.add_argument("--needs-json", type=Path,
                    help="file holding toJSON(needs) from the workflow run")
    ap.add_argument("--legs-dir", type=Path,
                    help="directory holding the downloaded test-leg-*.txt artifacts")
    ap.add_argument("--verify-wiring", action="store_true",
                    help="check ci.yml and the declaration against each other")
    a = ap.parse_args(argv)

    if a.verify_wiring:
        funde = pruefe_verdrahtung()
        if funde:
            print(f"{SAMMEL_JOB} wiring: {len(funde)} finding(s)")
            for f in funde:
                print(f"  ERROR: {_einzeilig(f, 400)}")
            return 1
        print(f"{SAMMEL_JOB} wiring: ok")
        return 0

    if a.judge:
        if not a.needs_json:
            print("ERROR: --judge needs --needs-json", file=sys.stderr)
            return 2
        try:
            needs = json.loads(a.needs_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: the needs context is not readable ({type(e).__name__}) -- "
                  "not measurable is not a pass")
            return 1
        decl = _deklaration()
        gelaufen = _versionen_aus_artefakten(a.legs_dir) if a.legs_dir else set()
        rc, zeilen = beurteile(needs, gelaufen, [str(v) for v in (decl.get("required_python_versions") or [])])
        for z in zeilen:
            print(z)
        return rc

    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
