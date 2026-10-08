"""A label starts no run of ci.yml, and `landung` still starts the mutation layer (owner word
2026-09-28, EIN-LABEL-STARTET-KEINE-CI-MEHR-01).

WHY. ci.yml ran on `labeled` and `unlabeled` for the label `landung`, and its concurrency group cancels a
running pull_request run. Measured 2026-09-28 09:28Z and 09:40Z: every label set on a pull request of the
6.2.0 chain cancelled its running CI and started a full one, about 55 minutes each. The mutation layer, the
one thing that has to start when `landung` is set, moved to landung.yml; ci.yml keeps its other ways in.

WHAT THIS HOLDS, each with a counter-example it fails on:
  1. ci.yml subscribes exactly opened, synchronize and reopened on pull_request.
  2. landung.yml runs on pull_request `labeled`, `unlabeled`, `synchronize` and `reopened`, and its layer
     starts when `landung` is set and on every new head of a pull request that carries it (Codex on pull
     request 310, round one, P1: a push to a labelled candidate sends only `synchronize`).
  3. The steps of `mutation` and `mutation-summary` are the same in both files, apart from `needs` and
     `if`, so a fix to one copy cannot miss the other.
  4. landung.yml produces no required context. Its jobs carry a condition, and GitHub reports a job
     skipped by a condition as success; on a required context that could stand beside a red one. That is
     why ci.yml got no condition, and why this file must never carry a required context.
  5. Another label leaves a running layer alone: the concurrency group carries the label's name.
  6. The layer waits for test and coverage of the same head, as it does in ci.yml (Codex on pull
     request 310, round two, P1): `mutation` needs `ci-prerequisites`, which runs
     scripts/landung_waits_for_ci.py with the layer's own predicate, and the jobs that script waits
     for are the `needs` of ci.yml's mutation job and the collector `all-checks-passed`, which judges
     the full matrix (round three, P1: a fork's one-leg run is not the release matrix). The script's
     verdict is measured as a program.
"""
from __future__ import annotations

import importlib.util
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
LABEL_BEDINGUNG = ("( github.event.action == 'labeled' && github.event.label.name == 'landung' ) "
                   "|| ( ( github.event.action == 'synchronize' || github.event.action == 'reopened' ) "
                   "&& contains(github.event.pull_request.labels.*.name, 'landung') )")
#: The events on which a labelled candidate gets a new head while the label stays.
NEUER_KOPF = ("synchronize", "reopened")
#: The job that holds the layer back until test and coverage of ci.yml succeeded on the same head.
VORBEDINGUNG = "ci-prerequisites"
SKRIPT = REPO / "scripts" / "landung_waits_for_ci.py"


def _skript():
    spec = importlib.util.spec_from_file_location("landung_waits_for_ci", SKRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _wartet_nicht(d: dict) -> list[str]:
    """How the layer of a landung.yml could start without test and coverage of its head."""
    jobs = d.get("jobs") or {}
    schlecht = []
    if VORBEDINGUNG not in jobs:
        return [f"no job {VORBEDINGUNG}"]
    if (jobs.get("mutation") or {}).get("needs") != [VORBEDINGUNG]:
        schlecht.append(f"mutation does not need {VORBEDINGUNG}")
    schritte = jobs[VORBEDINGUNG].get("steps") or []
    laeufe = [s for s in schritte if "scripts/landung_waits_for_ci.py" in str(s.get("run", ""))]
    if len(laeufe) != 1:
        schlecht.append(f"{VORBEDINGUNG} does not run scripts/landung_waits_for_ci.py exactly once")
    elif (laeufe[0].get("env") or {}).get("HEAD_SHA") != "${{ github.event.pull_request.head.sha }}":
        schlecht.append(f"{VORBEDINGUNG} does not name the head of the event")
    elif ((laeufe[0].get("env") or {}).get("BASE_SHA"), (laeufe[0].get("env") or {}).get("EVENT_ACTION")) != (
            "${{ github.event.pull_request.base.sha }}", "${{ github.event.action }}"):
        schlecht.append(f"{VORBEDINGUNG} does not name the base and the action of the event")
    if (jobs[VORBEDINGUNG].get("permissions") or {}).get("actions") != "read":
        schlecht.append(f"{VORBEDINGUNG} cannot read the runs of ci.yml")
    return schlecht


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


def _umschliesst(s: str) -> bool:
    """Whether the parenthesis that opens `s` is the one that closes it. `( a ) || ( b )` starts and ends
    with a parenthesis without being one group, and stripping them would change the predicate."""
    if not (s.startswith("(") and s.endswith(")")):
        return False
    tiefe = 0
    for i, c in enumerate(s):
        tiefe += {"(": 1, ")": -1}.get(c, 0)
        if tiefe == 0:
            return i == len(s) - 1
    return False


def _kern(s: str) -> str:
    s = " ".join(str(s).split())
    if s.startswith("always()"):
        s = s[len("always()"):].lstrip()
        if s.startswith("&&"):
            s = s[2:].lstrip()
    if _umschliesst(s):
        s = s[1:-1].strip()
    return " ".join(s.split())


def _neuer_kopf_verpasst(d: dict) -> list[str]:
    """How a labelled candidate's new head could miss the layer: an event not subscribed, or a job
    condition that does not run on it with the label present."""
    schlecht = [f"type {e} not subscribed" for e in NEUER_KOPF if e not in (_pull_request_typen(d) or [])]
    for job in KOPIERTE_JOBS:
        bed = _kern(((d.get("jobs") or {}).get(job) or {}).get("if") or "")
        for e in NEUER_KOPF:
            if f"github.event.action == '{e}'" not in bed:
                schlecht.append(f"{job} does not run on {e}")
        if "contains(github.event.pull_request.labels.*.name, 'landung')" not in bed:
            schlecht.append(f"{job} does not ask whether the pull request carries the label")
    g = " ".join(str(((d.get("concurrency") or {}).get("group")) or "").split())
    if not all(f"github.event.action == '{e}'" in g for e in NEUER_KOPF):
        schlecht.append("a new head does not join the group of the layer, so it cannot replace the old head's run")
    return schlecht


# ── the repository as it stands ───────────────────────────────────────────────────────────────────


def test_ci_yml_laeuft_bei_keinem_label_ereignis():
    assert _pull_request_typen(_lade("ci.yml")) == ["opened", "synchronize", "reopened"]


def test_landung_yml_laeuft_bei_label_und_neuem_kopf():
    d = _lade("landung.yml")
    assert set(_on(d)) == {"pull_request"}, f"landung.yml has other triggers: {sorted(_on(d))}"
    assert _pull_request_typen(d) == ["labeled", "unlabeled", "synchronize", "reopened"]


def test_ein_neuer_kopf_eines_kandidaten_bekommt_die_schicht():
    """Codex on pull request 310, round one (P1): the label is a state, and a push to a labelled
    candidate sends only `synchronize`; ci.yml no longer runs the layer for the label, so the new head
    had no mutation verdict."""
    assert _neuer_kopf_verpasst(_lade("landung.yml")) == []


def test_die_schicht_startet_nur_wenn_landung_gesetzt_wird():
    jobs = _lade("landung.yml")["jobs"]
    assert _kern(jobs["mutation"]["if"]) == LABEL_BEDINGUNG
    assert _kern(jobs["mutation-summary"]["if"]) == LABEL_BEDINGUNG, (
        "producer and collector carry different predicates -- the collector is then red when the layer "
        "stays away on purpose, or silent when it is red")
    assert _kern(jobs[VORBEDINGUNG]["if"]) == LABEL_BEDINGUNG, (
        "the prerequisite and the layer carry different predicates -- then the layer either never "
        "starts or starts without its prerequisite having run")
    assert jobs["mutation-summary"]["needs"] == ["mutation"]


def test_die_schicht_wartet_auf_test_und_coverage_desselben_kopfes():
    """Codex on pull request 310, round two (P1): a push to a labelled candidate started 36 shards beside
    CI. In ci.yml the layer needs test and coverage; the script waits for exactly those jobs."""
    assert _wartet_nicht(_lade("landung.yml")) == []
    s = _skript()
    ci = _lade("ci.yml")["jobs"]
    assert s.CI_NEEDS == tuple(ci["mutation"]["needs"]), (
        "the script waits for other jobs than the ones ci.yml's mutation job needs")
    assert ci[s.COLLECTOR]["needs"] == list(s.CI_NEEDS), (
        "the collector the script waits for does not judge the same jobs")
    assert s.WAITED == s.CI_NEEDS + (s.COLLECTOR,)
    assert (WF / s.CI_WORKFLOW).is_file()


# ── the script's verdict, measured as a program ─────────────────────────────────────────────────────


def _job(name: str, status: str = "completed", conclusion: "str | None" = "success") -> dict:
    return {"name": name, "status": status, "conclusion": conclusion}


GRUEN = [_job("test (3.10)"), _job("test (3.14)"), _job("coverage"), _job("all-checks-passed"),
         _job("guard"), _job("mutation", conclusion="skipped")]


@pytest.mark.parametrize("jobs,lauf,erwartet", [
    (GRUEN, "completed", "green"),
    # a red leg is red at once, while coverage is still running
    ([_job("test (3.10)", conclusion="failure"), _job("coverage", "in_progress", None)], "in_progress", "red"),
    ([_job("test (3.10)"), _job("coverage", conclusion="cancelled")], "completed", "red"),
    ([_job("test (3.10)", conclusion="skipped"), _job("coverage")], "completed", "red"),
    ([_job("test (3.10)"), _job("coverage", "in_progress", None)], "in_progress", "wait"),
    ([_job("test (3.10)", "queued", None)], "in_progress", "wait"),
    ([], "queued", "wait"),
    # a finished run without one of the jobs never turns green
    ([_job("test (3.10)")], "completed", "red"),
    ([_job("coverage")], "completed", "red"),
    # another job's red is not the layer's business, and a name that only starts like `test` is not a leg
    ([_job("test (3.10)"), _job("coverage"), _job("all-checks-passed"), _job("anchors", conclusion="failure")],
     "completed", "green"),
    ([_job("tests-extra", conclusion="failure"), _job("test (3.10)"), _job("coverage"), _job("all-checks-passed")],
     "completed", "green"),
    # Codex on pull request 310, round three (P1): a fork's one-leg run has test and coverage green and the
    # collector red, because one leg is not the full matrix; the layer must not start on it
    ([_job("test (3.12)"), _job("coverage"), _job("all-checks-passed", conclusion="failure")], "completed", "red"),
    # the collector is created only after test and coverage finished
    ([_job("test (3.10)"), _job("coverage")], "in_progress", "wait"),
    ([_job("test (3.10)"), _job("coverage")], "completed", "red"),
])
def test_das_urteil_des_skripts(jobs, lauf, erwartet):
    assert _skript().judge(jobs, lauf)[0] == erwartet


class _FalscheApi:
    """The GitHub answers the script reads, the runs served from a list of states, one per poll; the base's
    landing time and this landung run's creation time are fixed per case."""

    def __init__(self, laeufe_je_ruf, jobs, basis="2025-12-31T00:00:00Z", eigener="2026-01-01T00:00:00Z"):
        self.laeufe_je_ruf, self.jobs, self.schlaf, self.uhr = list(laeufe_je_ruf), jobs, 0, 0.0
        self.basis, self.eigener = basis, eigener

    def fetch(self, path, token):
        if "/jobs?" in path:
            return {"total_count": len(self.jobs), "jobs": self.jobs}
        if "/commits/" in path:
            return {"commit": {"committer": {"date": self.basis}}}
        if "/workflows/" not in path:
            return {"created_at": self.eigener}
        return {"workflow_runs": self.laeufe_je_ruf.pop(0) if self.laeufe_je_ruf else []}

    def sleep(self, s):
        self.schlaf += 1
        self.uhr += s


# Fixture values, not measurements: a head, and the creation stamps of two runs in a fixed order.
ENV = {"GITHUB_REPOSITORY": "o/r", "HEAD_SHA": "a" * 40, "BASE_SHA": "c" * 40, "EVENT_ACTION": "labeled",
       "GITHUB_RUN_ID": "99"}
LAUF = {"id": 7, "head_sha": "a" * 40, "created_at": "2026-01-01T00:00:00Z", "status": "completed"}


def test_das_skript_wartet_bis_der_lauf_erscheint_und_urteilt_dann():
    api = _FalscheApi([[], [], [LAUF]], GRUEN)
    assert _skript().main(fetch=api.fetch, sleep=api.sleep, clock=lambda: api.uhr, env=ENV) == 0
    assert api.schlaf == 2


def test_das_skript_wird_rot_wenn_kein_lauf_erscheint():
    api = _FalscheApi([], GRUEN)
    s = _skript()
    assert s.main(fetch=api.fetch, sleep=api.sleep, clock=lambda: api.uhr, env=ENV) == 1
    assert api.uhr > s.APPEAR_S


def test_das_skript_liest_nur_den_lauf_dieses_kopfes():
    fremd = dict(LAUF, head_sha="b" * 40, created_at="2026-01-02T00:00:00Z")
    api = _FalscheApi([[fremd], [fremd, LAUF]], GRUEN)
    assert _skript().main(fetch=api.fetch, sleep=api.sleep, clock=lambda: api.uhr, env=ENV) == 0
    assert api.schlaf == 1, "the run of another head was read as this head's"


def test_das_skript_wird_rot_wenn_die_api_nicht_lesbar_ist():
    s = _skript()
    api = _FalscheApi([], GRUEN)

    def kaputt(path, token):
        raise s.ReadError("HTTP 502")
    assert s.main(fetch=kaputt, sleep=api.sleep, clock=lambda: api.uhr, env=ENV) == 1
    assert api.schlaf == s.MAX_READ_ERRORS - 1


def test_ein_lauf_vor_der_landung_der_basis_zaehlt_nicht():
    """Codex on pull request 310, round four (P1): CI finished green, main moved, the head did not, and the label
    was set. The run tested an older merge candidate; it must not start the layer, and the reason says why."""
    s = _skript()
    api = _FalscheApi([[LAUF]] * 100, GRUEN, basis="2026-01-02T00:00:00Z")
    assert s.main(fetch=api.fetch, sleep=api.sleep, clock=lambda: api.uhr, env=ENV) == 1
    assert api.uhr > s.APPEAR_S
    # the control: with the base landed before the run, the same run counts
    api = _FalscheApi([[LAUF]], GRUEN, basis="2025-12-31T00:00:00Z")
    assert s.main(fetch=api.fetch, sleep=api.sleep, clock=lambda: api.uhr, env=ENV) == 0


@pytest.mark.parametrize("aktion", ["synchronize", "reopened"])
def test_auf_einem_neuen_lauf_wird_der_vorige_lauf_nicht_gelesen(aktion):
    """Round four, the sibling: on synchronize and reopened ci.yml starts a new run, and the previous run of the
    same head was read before the new one appeared."""
    neu = dict(LAUF, id=8, created_at="2026-01-03T00:00:30Z")
    api = _FalscheApi([[LAUF], [LAUF], [LAUF, neu]], GRUEN, eigener="2026-01-03T00:00:00Z")
    assert _skript().main(fetch=api.fetch, sleep=api.sleep, clock=lambda: api.uhr, env=dict(ENV, EVENT_ACTION=aktion)) == 0
    assert api.schlaf == 2, "the run from before this landung run was read as the evidence"


def test_ohne_basis_und_aktion_wird_es_rot():
    api = _FalscheApi([[LAUF]], GRUEN)
    for fehlt in ("BASE_SHA", "EVENT_ACTION", "GITHUB_RUN_ID"):
        env = {k: v for k, v in ENV.items() if k != fehlt}
        assert _skript().main(fetch=api.fetch, sleep=api.sleep, clock=lambda: api.uhr, env=env) == 1, fehlt


def _warter_zu_kurz(landung: dict, ci: dict, warte: tuple) -> list[str]:
    """The jobs the waiter may outlast too little: its limit must stand 30 minutes above each, and within the
    360 minutes a hosted job may take."""
    eigen = int(landung["jobs"][VORBEDINGUNG].get("timeout-minutes") or 0)
    schlecht = [f"{j} may take {ci['jobs'][j].get('timeout-minutes')} minutes" for j in warte
                if eigen < int(ci["jobs"][j].get("timeout-minutes") or 360) + 30]
    return schlecht + ([f"{VORBEDINGUNG} exceeds 360 minutes"] if eigen > 360 else [])


def test_der_warter_lebt_laenger_als_was_er_erwartet():
    """Codex on pull request 310, round four (P1): the waiter was capped at 120 minutes while coverage may take
    300, so it timed out, the layer was skipped and the candidate had no mutation verdict."""
    s = _skript()
    assert _warter_zu_kurz(_lade("landung.yml"), _lade("ci.yml"), s.WAITED) == []


def test_fangnachweis_ein_zu_kurzer_warter_wird_gefunden():
    landung = {"jobs": {VORBEDINGUNG: {"timeout-minutes": 120}}}
    ci = {"jobs": {"test": {"timeout-minutes": 180}, "coverage": {"timeout-minutes": 300}}}
    assert _warter_zu_kurz(landung, ci, ("test", "coverage")) == ["test may take 180 minutes",
                                                                  "coverage may take 300 minutes"]


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


def test_fangnachweis_ein_verpasster_neuer_kopf_wird_gefunden():
    nur_label = {"on": {"pull_request": {"types": ["labeled", "unlabeled"]}},
                 "concurrency": {"group": "${{ github.event.label.name }}"},
                 "jobs": {j: {"if": "github.event.action == 'labeled' && github.event.label.name == 'landung'"}
                          for j in KOPIERTE_JOBS}}
    befund = _neuer_kopf_verpasst(nur_label)
    assert "type synchronize not subscribed" in befund and "mutation does not run on synchronize" in befund
    assert any(b.startswith("a new head does not join") for b in befund)
    assert _neuer_kopf_verpasst(_lade("landung.yml")) == []


def test_fangnachweis_eine_schicht_ohne_vorbedingung_wird_gefunden():
    d = _lade("landung.yml")
    ohne_needs = json.loads(json.dumps(d, default=str))
    del ohne_needs["jobs"]["mutation"]["needs"]
    assert _wartet_nicht(ohne_needs) == [f"mutation does not need {VORBEDINGUNG}"]
    ohne_job = json.loads(json.dumps(d, default=str))
    del ohne_job["jobs"][VORBEDINGUNG]
    assert _wartet_nicht(ohne_job) == [f"no job {VORBEDINGUNG}"]
    fremder_kopf = json.loads(json.dumps(d, default=str))
    for schritt in fremder_kopf["jobs"][VORBEDINGUNG]["steps"]:
        if "env" in schritt:
            schritt["env"]["HEAD_SHA"] = "${{ github.sha }}"
    assert _wartet_nicht(fremder_kopf) == [f"{VORBEDINGUNG} does not name the head of the event"]
    ohne_basis = json.loads(json.dumps(d, default=str))
    for schritt in ohne_basis["jobs"][VORBEDINGUNG]["steps"]:
        if "env" in schritt:
            schritt["env"].pop("BASE_SHA", None)
    assert _wartet_nicht(ohne_basis) == [f"{VORBEDINGUNG} does not name the base and the action of the event"]
    ohne_recht = json.loads(json.dumps(d, default=str))
    ohne_recht["jobs"][VORBEDINGUNG]["permissions"] = {"contents": "read"}
    assert _wartet_nicht(ohne_recht) == [f"{VORBEDINGUNG} cannot read the runs of ci.yml"]


def test_fangnachweis_kern_streift_nur_ein_echtes_paar_ab():
    assert _kern("( a ) || ( b )") == "( a ) || ( b )"
    assert _kern("always() && ( ( a ) || ( b ) )") == "( a ) || ( b )"
    assert _kern("( a && b )") == "a && b"


def test_fangnachweis_ci_yml_mit_label_typen_wird_gefunden():
    alt = {"on": {"pull_request": {"types": ["opened", "synchronize", "reopened", "labeled", "unlabeled"]}}}
    assert _pull_request_typen(alt) != ["opened", "synchronize", "reopened"]
