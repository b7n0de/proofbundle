"""A label starts no run of ci.yml, and `landung` still starts the mutation layer (owner word
2026-09-28, EIN-LABEL-STARTET-KEINE-CI-MEHR-01).

WHY. ci.yml ran on `labeled` and `unlabeled` for the label `landung`, and its concurrency group cancels a
running pull_request run. Measured 2026-09-28 09:28Z and 09:40Z: every label set on a pull request of the
6.2.0 chain cancelled its running CI and started a full one, about 55 minutes each. The mutation layer, the
one thing that has to start when `landung` is set, moved to landung.yml; ci.yml keeps its other ways in.

WHAT THIS HOLDS, each with a counter-example it fails on:
  1. ci.yml subscribes exactly opened, synchronize and reopened on pull_request.
  2. landung.yml runs on pull_request `labeled` and `unlabeled` only, and its layer starts only when
     `landung` is set.
  3. The steps of `mutation` and `mutation-summary` are the same in both files, apart from `needs` and
     `if`, so a fix to one copy cannot miss the other.
  4. landung.yml produces no required context. Its jobs carry a condition, and GitHub reports a job
     skipped by a condition as success; on a required context that could stand beside a red one. That is
     why ci.yml got no condition, and why this file must never carry a required context.
  5. Another label leaves a running layer alone: the concurrency group carries the label's name.
"""
from __future__ import annotations

import json
import pathlib

import pytest

yaml = pytest.importorskip("yaml")

REPO = pathlib.Path(__file__).resolve().parents[1]
WF = REPO / ".github" / "workflows"
DECLARATION = REPO / ".github" / "required_status_checks.json"

#: The jobs whose steps exist twice. `needs` and `if` differ by design and are left out of the comparison.
KOPIERTE_JOBS = ("mutation", "mutation-summary")
EIGENE_SCHLUESSEL = {"needs", "if"}
LABEL_BEDINGUNG = "github.event.action == 'labeled' && github.event.label.name == 'landung'"


def _lade(name: str) -> dict:
    return yaml.safe_load((WF / name).read_text(encoding="utf-8"))


def _on(d: dict) -> dict:
    on = d.get(True) or d.get("on") or {}
    return on if isinstance(on, dict) else {}


def _pull_request_typen(d: dict) -> "list | None":
    pr = _on(d).get("pull_request")
    return (pr or {}).get("types") if isinstance(pr, dict) else None


def _kopien_weichen_ab(a: dict, b: dict) -> list[str]:
    """The copied jobs whose content differs between the two workflows, `needs` and `if` aside."""
    schlecht = []
    for job in KOPIERTE_JOBS:
        x = {k: v for k, v in ((a.get("jobs") or {}).get(job) or {}).items() if k not in EIGENE_SCHLUESSEL}
        y = {k: v for k, v in ((b.get("jobs") or {}).get(job) or {}).items() if k not in EIGENE_SCHLUESSEL}
        if not x or not y:
            schlecht.append(f"{job}: missing in one of the two files")
        elif x != y:
            schlecht.append(f"{job}: differs in {sorted(k for k in set(x) | set(y) if x.get(k) != y.get(k))}")
    return schlecht


def _pflichtkontexte(d: dict, verlangt: set[str]) -> list[str]:
    """Jobs of a workflow that would report a required context: by job id, by display name, or by the
    name a matrix job reports (`<name> (<value>)`), read against the declared set and the job ids the
    ruleset's contexts come from."""
    getroffen = []
    for job, v in ((d.get("jobs") or {}).items()):
        name = str((v or {}).get("name") or job)
        kandidaten = {job, name}
        if any(k in verlangt for k in kandidaten) or any(c.startswith(f"{name} (") for c in verlangt):
            getroffen.append(job)
    return sorted(getroffen)


def _verlangte_kontexte() -> set[str]:
    d = json.loads(DECLARATION.read_text(encoding="utf-8"))
    # the declared required contexts, and the legs the collector all-checks-passed judges
    return set(d["required_contexts"]) | {"test", "coverage"} | {e["context"] for e in d.get("accepted_gated", [])}


def _gruppe_traegt_label(d: dict) -> bool:
    g = str(((d.get("concurrency") or {}).get("group")) or "")
    return "github.event.label.name" in g and "github.event_name" in g


def _kern(s: str) -> str:
    s = " ".join(str(s).split())
    if s.startswith("always()"):
        s = s[len("always()"):].lstrip()
        if s.startswith("&&"):
            s = s[2:].lstrip()
    if s.startswith("(") and s.endswith(")"):
        s = s[1:-1].strip()
    return " ".join(s.split())


# ── the repository as it stands ───────────────────────────────────────────────────────────────────


def test_ci_yml_laeuft_bei_keinem_label_ereignis():
    assert _pull_request_typen(_lade("ci.yml")) == ["opened", "synchronize", "reopened"]


def test_landung_yml_laeuft_nur_bei_label_ereignissen():
    d = _lade("landung.yml")
    assert set(_on(d)) == {"pull_request"}, f"landung.yml has other triggers: {sorted(_on(d))}"
    assert _pull_request_typen(d) == ["labeled", "unlabeled"]


def test_die_schicht_startet_nur_wenn_landung_gesetzt_wird():
    jobs = _lade("landung.yml")["jobs"]
    assert _kern(jobs["mutation"]["if"]) == LABEL_BEDINGUNG
    assert _kern(jobs["mutation-summary"]["if"]) == LABEL_BEDINGUNG, (
        "producer and collector carry different predicates -- the collector is then red when the layer "
        "stays away on purpose, or silent when it is red")
    assert jobs["mutation-summary"]["needs"] == ["mutation"]


def test_die_schritte_beider_kopien_sind_gleich():
    assert _kopien_weichen_ab(_lade("ci.yml"), _lade("landung.yml")) == []


def test_landung_yml_traegt_keinen_pflichtkontext():
    assert _pflichtkontexte(_lade("landung.yml"), _verlangte_kontexte()) == []


def test_ein_anderes_label_bricht_die_schicht_nicht_ab():
    assert _gruppe_traegt_label(_lade("landung.yml"))


def test_ci_yml_behaelt_seine_pflichtkontexte():
    """No required context removed or renamed: the jobs the ruleset's contexts come from are still in
    ci.yml under the same ids, and all-checks-passed still needs exactly test and coverage."""
    jobs = _lade("ci.yml")["jobs"]
    assert {"test", "coverage", "all-checks-passed"} <= set(jobs)
    assert jobs["all-checks-passed"]["needs"] == ["test", "coverage"]
    assert "name" not in jobs["all-checks-passed"] and "name" not in jobs["test"]
    assert json.loads(DECLARATION.read_text(encoding="utf-8"))["required_contexts"] == ["all-checks-passed", "guard"]


# ── counter-examples: each assertion above must be able to fail ────────────────────────────────────


def test_fangnachweis_eine_abweichende_kopie_wird_gefunden():
    schritt = {"runs-on": "u", "timeout-minutes": 5, "steps": [{"run": "a"}]}
    a = {"jobs": {"mutation": dict(schritt, needs=["test"]), "mutation-summary": dict(schritt)}}
    b = {"jobs": {"mutation": dict(schritt, **{"if": "x"}), "mutation-summary": dict(schritt)}}
    assert _kopien_weichen_ab(a, b) == [], "needs and if are the copies' own and must not count"
    anders = {"jobs": {"mutation": dict(schritt, steps=[{"run": "b"}]), "mutation-summary": dict(schritt)}}
    assert _kopien_weichen_ab(a, anders) == ["mutation: differs in ['steps']"]
    assert _kopien_weichen_ab(a, {"jobs": {"mutation": dict(schritt)}}) == [
        "mutation-summary: missing in one of the two files"]


def test_fangnachweis_ein_pflichtkontext_in_landung_yml_wird_gefunden():
    verlangt = {"all-checks-passed", "guard", "test (3.10)", "test", "coverage"}
    assert _pflichtkontexte({"jobs": {"mutation": {}, "mutation-summary": {}}}, verlangt) == []
    assert _pflichtkontexte({"jobs": {"all-checks-passed": {}}}, verlangt) == ["all-checks-passed"]
    assert _pflichtkontexte({"jobs": {"x": {"name": "guard"}}}, verlangt) == ["x"]
    assert _pflichtkontexte({"jobs": {"t": {"name": "test"}}}, verlangt) == ["t"], "a matrix name counts too"


def test_fangnachweis_eine_gruppe_ohne_labelnamen_wird_gefunden():
    assert not _gruppe_traegt_label({"concurrency": {"group": "${{ github.workflow }}-${{ github.event_name }}-${{ github.ref }}"}})
    assert _gruppe_traegt_label({"concurrency": {"group": "${{ github.event_name }}-${{ github.event.label.name }}"}})


def test_fangnachweis_ci_yml_mit_label_typen_wird_gefunden():
    alt = {"on": {"pull_request": {"types": ["opened", "synchronize", "reopened", "labeled", "unlabeled"]}}}
    assert _pull_request_typen(alt) != ["opened", "synchronize", "reopened"]
