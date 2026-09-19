#!/usr/bin/env python3
"""Does every required status check EXIST on this head -- not: could a workflow produce it.

THE GAP THIS CLOSES, measured on 2026-09-19. `required_check_reachability_gate.py` answers a
STRUCTURAL question: can some workflow produce each required context, unconditionally or under a
named condition. That is the right question when a workflow changes. It is the wrong question when
a pull request will not merge, and the difference is not academic:

    pull request 228, head fb2bab4d5d65   guard: success   all-checks-passed: ABSENT   -> BLOCKED
    pull request 226, head ee6d565be4d6   guard: success   all-checks-passed: success  -> CLEAN
    required_check_reachability_gate --drift-marker ""  ->  produced, produced, rc=0

The structural gate said `produced` for both. It was not wrong; it answered its own question. But
a context that CAN be produced and a context that WAS produced are two different facts, and only
the second decides whether this pull request moves. The same pairing stood on 2026-09-17 at pull
request 218: the guard green, the pull request blocked, and nothing between them said why.

WHY AN ABSENT CONTEXT IS THE DANGEROUS ONE. A red check writes a red line. An absent one writes
nothing: no colour, no row, no message. The pull request simply stays BLOCKED, and whoever reads
the checks page repairs the checks that are visible -- which are exactly the ones that are not the
problem. `.github/required_status_checks.json` names this class in its own header: "A required
status check has TWO failure modes, red and ABSENT, and only the first is visible."

FAIL-CLOSED, AND NOT MEASURABLE IS NOT A PASS. Without network, without a token, or with an
unreadable ruleset the verdict is NOT_MEASURABLE with its reason and a non-zero exit. An unknown
must never read as fine -- that is the whole point of a gate that exists because something was
invisible.

Exit: 0 every required context present, 1 at least one absent, 2 not measurable.
"""
from __future__ import annotations

import argparse
import json
import subprocess

SCHEMA = "b7n0de.required_context_presence.v1"


def _gh(*args: str, timeout: int = 60) -> tuple[int, str, str]:
    try:
        p = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, "", f"{type(e).__name__}: {e}"
    return p.returncode, p.stdout, p.stderr


def pflichtkontexte(repo: str) -> tuple[set[str], str]:
    """The contexts the active rulesets require on the default branch.

    READ FROM THE LIVE RULESET, not from the declaration beside it. The declaration exists so an
    offline check can run; here the question is what actually blocks this pull request, and only
    the ruleset answers that.
    """
    rc, out, err = _gh("api", f"repos/{repo}/rulesets", "--jq", ".[].id")
    if rc != 0:
        return set(), f"NICHT MESSBAR: rulesets nicht lesbar ({err.strip()[:120]})"
    aus: set[str] = set()
    for rid in [z for z in out.split() if z.strip()]:
        rc2, out2, err2 = _gh(
            "api", f"repos/{repo}/rulesets/{rid}", "--jq",
            '.rules[] | select(.type=="required_status_checks")'
            ' | .parameters.required_status_checks[].context')
        if rc2 != 0:
            return set(), f"NICHT MESSBAR: ruleset {rid} nicht lesbar ({err2.strip()[:120]})"
        aus.update(z.strip() for z in out2.splitlines() if z.strip())
    if not aus:
        # NO REQUIRED CONTEXT IS A STATEMENT, NOT AN EMPTY RESULT. Either protection is off or the
        # read is wrong; both deserve a look, and neither is a green light.
        return set(), "NICHT MESSBAR: kein Ruleset nennt einen Pflichtkontext"
    return aus, "gemessen"


def vorhandene_kontexte(repo: str, sha: str) -> tuple[set[str], str]:
    """Every check-run name that EXISTS on this head, whatever its conclusion."""
    rc, out, err = _gh("api", f"repos/{repo}/commits/{sha}/check-runs?per_page=100",
                       "--jq", ".check_runs[].name")
    if rc != 0:
        return set(), f"NICHT MESSBAR: check-runs nicht lesbar ({err.strip()[:120]})"
    return {z.strip() for z in out.splitlines() if z.strip()}, "gemessen"


def basisstand(repo: str, sha: str, basis: str = "main") -> tuple[int | None, bool, str]:
    """How far this head lags the base branch, and whether the ruleset makes that fatal.

    UNDER `strict_required_status_checks_policy` A PRESENT CONTEXT ON A STALE HEAD IS WORTH
    NOTHING. Measured 2026-09-19 on pull request 228: both required contexts existed on the head
    and both were green, this gate said `gruen`, and the merge was refused with "2 of 2 required
    status checks are expected". The cause was not absence but staleness — pull request 226 had
    landed one minute earlier, so the head was one commit behind main and GitHub wanted the checks
    re-run on an up-to-date head. Presence answers a question the ruleset does not ask when it is
    strict; this reader supplies the half that was missing.
    """
    rc, out, err = _gh("api", f"repos/{repo}/rulesets", "--jq", ".[].id")
    if rc != 0:
        return None, False, f"NICHT MESSBAR: rulesets nicht lesbar ({err.strip()[:120]})"
    streng = False
    for rid in [z for z in out.split() if z.strip()]:
        rc2, out2, err2 = _gh(
            "api", f"repos/{repo}/rulesets/{rid}", "--jq",
            '.rules[] | select(.type=="required_status_checks")'
            ' | .parameters.strict_required_status_checks_policy')
        if rc2 != 0:
            return None, False, f"NICHT MESSBAR: ruleset {rid} nicht lesbar ({err2.strip()[:120]})"
        if "true" in out2:
            streng = True
    rc3, out3, err3 = _gh("api", f"repos/{repo}/compare/{basis}...{sha}", "--jq", ".behind_by")
    if rc3 != 0:
        return None, streng, f"NICHT MESSBAR: Vergleich zur Basis nicht lesbar ({err3.strip()[:120]})"
    try:
        zurueck = int(out3.strip())
    except ValueError:
        return None, streng, f"NICHT MESSBAR: behind_by unlesbar ({out3.strip()[:60]!r})"
    return zurueck, streng, "gemessen"


def pruefe(repo: str, sha: str, basis: str = "main") -> dict:
    verlangt, z1 = pflichtkontexte(repo)
    if z1 != "gemessen":
        return {"schema": SCHEMA, "urteil": "NICHT_MESSBAR", "grund": z1, "sha": sha}
    vorhanden, z2 = vorhandene_kontexte(repo, sha)
    if z2 != "gemessen":
        return {"schema": SCHEMA, "urteil": "NICHT_MESSBAR", "grund": z2, "sha": sha}
    fehlend = sorted(verlangt - vorhanden)
    zurueck, streng, z3 = basisstand(repo, sha, basis)
    if z3 != "gemessen":
        return {"schema": SCHEMA, "urteil": "NICHT_MESSBAR", "grund": z3, "sha": sha}
    # DIE DRITTE LAGE: alles da, alles gruen, und trotzdem blockiert. Sie zaehlt nur, wenn die
    # Regelmenge streng ist — sonst ist ein Rueckstand zur Basis kein Hindernis.
    veraltet = bool(streng and zurueck and zurueck > 0)
    return {
        "schema": SCHEMA,
        "urteil": "ROT" if (fehlend or veraltet) else "gruen",
        "sha": sha,
        "verlangt": sorted(verlangt),
        "fehlend": fehlend,
        "streng": streng,
        "hinter_basis": zurueck,
        "veraltet_unter_streng": veraltet,
        # DIE ABWESENHEIT WIRD ZUERST GENANNT, auch wenn beides zutrifft: sie ist die Lage, an der
        # ein Mensch zuerst etwas tun kann, und ein Grund, der "alle Pflichtkontexte existieren"
        # sagt, waehrend `fehlend` nicht leer ist, widerspricht der eigenen Ausgabe.
        "grund": (f"{len(fehlend)} Pflichtkontext(e) existieren auf diesem Kopf NICHT: {fehlend}. "
                  "Ein abwesender Kontext hat keine Farbe und keine Zeile — der Pull Request "
                  "bleibt BLOCKED, ohne dass etwas rot ist"
                  + (f" (zusaetzlich liegt der Kopf {zurueck} Commit(s) hinter {basis}, "
                     "und die Regelmenge ist streng)" if veraltet else "")
                  if fehlend else
                  (f"Alle Pflichtkontexte existieren, aber der Kopf liegt {zurueck} Commit(s) "
                   f"hinter {basis}, und die Regelmenge ist streng. GitHub verlangt sie dann "
                   "erneut auf einem aktuellen Kopf und meldet sie als expected — nichts ist rot, "
                   "und der Pull Request laesst sich trotzdem nicht landen") if veraltet else
                  ""),
        "geprueft_wird": ("die EXISTENZ am Kopf und, bei strenger Regelmenge, ob der Kopf aktuell zur Basis ist — NICHT der Ausgang und NICHT die Erzeugbarkeit"),
        "nicht_geprueft": ("ob ein vorhandener Kontext bestanden hat — das sagt `gh pr checks`; "
                           "und ob ein Workflow ihn erzeugen KOENNTE — das sagt "
                           "required_check_reachability_gate.py"),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--repo", required=True, help="owner/name")
    p.add_argument("--sha", help="der Kopf; ohne ihn wird --pr gelesen")
    p.add_argument("--pr", help="Pull-Request-Nummer, deren Kopf geprueft wird")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    sha = a.sha
    if not sha:
        if not a.pr:
            p.error("entweder --sha oder --pr")
        rc, out, err = _gh("pr", "view", a.pr, "--repo", a.repo, "--json", "headRefOid",
                           "--jq", ".headRefOid")
        if rc != 0 or not out.strip():
            print(json.dumps({"schema": SCHEMA, "urteil": "NICHT_MESSBAR",
                              "grund": f"Kopf von PR {a.pr} nicht lesbar ({err.strip()[:120]})"}))
            return 2
        sha = out.strip()
    d = pruefe(a.repo, sha)
    if a.json:
        print(json.dumps(d, ensure_ascii=False, indent=2))
    else:
        print(f"required-context-presence: {d['urteil']} · {d['sha'][:12]}")
        if d.get("fehlend"):
            print(f"  ! {d['grund']}")
        if d.get("urteil") == "NICHT_MESSBAR":
            print(f"  ! {d['grund']}")
    return {"gruen": 0, "ROT": 1}.get(d["urteil"], 2)


if __name__ == "__main__":
    raise SystemExit(main())
