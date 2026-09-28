"""Der CI-Schnitt als Vertrag — Nachtrag 1 zu 20260913T2012Z, Punkt B7.

WARUM ES DIESE DATEI GIBT, gemessen und nicht vermutet. Am 13.09.2026 um 20:22Z standen 119 Laeufe
in der Warteschlange, vier CI-Laeufe liefen 65 bis 255 Minuten mit 28 Mutations-Shards, und in allen
vier waren `test` und `coverage` laengst rot. Fuenf Pushes auf EINEN Zweig zwischen 17:55Z und
18:07Z hatten 30 Laeufe eingereiht. Ursache war Saettigung durch eigene Last.

Der Schnitt behebt das an vier Stellen (concurrency, timeout, needs, Landekandidat). Diese Datei
haelt ihn fest, damit er nicht beim naechsten Umbau still zurueckgedreht wird.

JEDE ZUSICHERUNG HIER HAT EINEN FANGNACHWEIS: ein gebautes Gegenbeispiel, an dem die Pruefung
NACHWEISLICH faellt. Eine Zusicherung ohne Gegenbeispiel kann gruen sein, weil sie nichts prueft.
"""
from __future__ import annotations

import pathlib

import pytest

yaml = pytest.importorskip("yaml")

REPO = pathlib.Path(__file__).resolve().parents[1]
WF = REPO / ".github" / "workflows"

#: Die sieben Pflichtkontexte des Regelsatzes protect-main (id 18386496), gemessen 13.09.2026.
#: Ein Workflow, der einen davon traegt, darf NIEMALS durch paths-ignore uebersprungen werden:
#: eine uebersprungene Pflichtpruefung meldet nie und blockiert den Merge dauerhaft.
PFLICHT_JOBS = {"guard", "coverage", "test"}


def _workflows() -> dict[str, dict]:
    aus = {}
    for f in sorted(WF.glob("*.y*ml")):
        aus[f.name] = yaml.safe_load(f.read_text(encoding="utf-8"))
    return aus


def _trigger(d: dict) -> set[str]:
    on = d.get(True) or d.get("on") or {}
    if isinstance(on, str):
        return {on}
    return set(on) if isinstance(on, (dict, list)) else set()


def _bedingung_ist_geklammert(ausdruck: str) -> bool:
    """Steht die Oder-Kette VOR dem `&&` in einer eigenen Klammer?

    WARUM DAS NICHT MIT EINER TEXTSUCHE GEHT, an der ersten Fassung dieser Datei gemessen: die
    naheliegende Probe `"( github.event_name" in s` ist GRUEN AUCH OHNE die schuetzende Klammer,
    denn `fromJSON(` liefert selbst ein `(` vor dem Namen. Der Fangnachweis hat das gefangen; die
    Zusicherung haette sonst nichts geprueft und gruen gemeldet.

    Gemessen wird deshalb die STRUKTUR: ab dem Inneren von `fromJSON(` bis zu dem `&&`, das auf der
    aeussersten Ebene steht, muss genau eine abgeschlossene Klammergruppe liegen — und sonst nichts.
    """
    i = ausdruck.find("fromJSON(")
    if i < 0:
        return False
    i += len("fromJSON(")
    tiefe, pos_und = 0, -1
    j = i
    while j < len(ausdruck) - 1:
        c = ausdruck[j]
        if c == "(":
            tiefe += 1
        elif c == ")":
            if tiefe == 0:
                break
            tiefe -= 1
        elif c == "&" and ausdruck[j + 1] == "&" and tiefe == 0:
            pos_und = j
            break
        j += 1
    if pos_und < 0:
        return False
    vorne = ausdruck[i:pos_und].strip()
    if not (vorne.startswith("(") and vorne.endswith(")")):
        return False
    # und die erste Klammer muss die letzte auch wirklich schliessen
    tiefe = 0
    for k, c in enumerate(vorne):
        if c == "(":
            tiefe += 1
        elif c == ")":
            tiefe -= 1
            if tiefe == 0:
                return k == len(vorne) - 1
    return False


def _nur_gerufen(d: dict) -> bool:
    """Ein Workflow, den es nur als GERUFENEN gibt: `workflow_call` und sonst nichts."""
    return _trigger(d) == {"workflow_call"}


def test_jeder_workflow_hat_eine_concurrency_gruppe():
    """Mit EINER Ausnahme, und die ist keine Nachlaessigkeit, sondern eine Messung.

    In einem AUFGERUFENEN Workflow ist `github.workflow` der Name des AUFRUFERS. Eine Gruppe
    `${{ github.workflow }}-${{ github.ref }}` loest dort also auf denselben Wert auf wie beim
    Aufrufer, und mit `cancel-in-progress` bricht der Gerufene seinen eigenen Aufrufer ab. Gemessen
    an `reusable-build-attest.yml` (nur `workflow_call`) und `published-artifact-gate.yml`, das ihn
    ruft: beide trugen bis zur Codex-Runde eins an PR 202 exakt denselben Gruppenausdruck.

    Die Regel kehrt sich fuer diese Klasse also UM: ein nur gerufener Workflow darf KEINE eigene
    Gruppe tragen. Seine Nebenlaeufigkeit regelt der Aufrufer.
    """
    wfs = _workflows()
    fehlend = [n for n, d in wfs.items() if not _nur_gerufen(d or {}) and not (d or {}).get("concurrency")]
    assert not fehlend, f"ohne concurrency-Gruppe: {fehlend}"
    zuviel = [n for n, d in wfs.items() if _nur_gerufen(d or {}) and (d or {}).get("concurrency")]
    assert not zuviel, (
        "ein nur ueber workflow_call erreichbarer Workflow traegt eine EIGENE concurrency-Gruppe: "
        f"{zuviel} — dort ist github.workflow der Name des AUFRUFERS, die Gruppen fallen zusammen, "
        "und der Gerufene bricht seinen Aufrufer ab")


def _ohne_fremd_schutz(wfs: dict) -> list[str]:
    """Stellen, die `github.head_ref` fuer die SCHWERE Schicht lesen, ohne auf dasselbe Repository
    einzuschraenken. Auf einem Fork-PR bestimmt der Beitragende diesen Wert; ein Zweig namens
    `release/x` schaltete damit zehn Mutations-Shards und die Fuenferversionen-Matrix frei."""
    schutz = "head.repo.full_name == github.repository"
    schlecht = []
    for n, d in sorted(wfs.items()):
        for job, v in ((d or {}).get("jobs") or {}).items():
            if not isinstance(v, dict):
                continue
            stellen = [("if", str(v.get("if") or ""))]
            m = ((v.get("strategy") or {}).get("matrix") or {})
            if isinstance(m, dict):
                stellen.append(("matrix", str(m.get("python-version") or "")))
            for wo, s in stellen:
                if "github.head_ref" in s and schutz not in s:
                    schlecht.append(f"{n}::{job}::{wo}")
    return schlecht


def test_die_schwere_schicht_haengt_nicht_an_einem_fremdbestimmten_zweignamen():
    assert _ohne_fremd_schutz(_workflows()) == []


def test_der_sammler_traegt_dasselbe_praedikat_wie_der_erzeuger():
    """`mutation-summary` ist fail-closed und faellt bei allem, was nicht `success` ist. Seit die
    schwere Schicht bedingt ist, waere `skipped` — der Normalfall auf main — genau das gewesen."""
    jobs = _workflows()["ci.yml"]["jobs"]
    def kern(s: str) -> str:
        """Das Praedikat ohne seine Verpackung. NICHT `replace("&&", " ", 1)`: das erste `&&` steht
        seit dem Fork-Schutz INNERHALB der Bedingung, nicht am `always()`-Gelenk — die erste Fassung
        dieser Normalisierung schnitt damit das falsche Zeichen heraus und meldete einen Unterschied,
        den es nicht gab."""
        s = " ".join(str(s).split())
        if s.startswith("always()"):
            s = s[len("always()"):].lstrip()
            if s.startswith("&&"):
                s = s[2:].lstrip()
        if s.startswith("(") and s.endswith(")"):
            s = s[1:-1].strip()
        return " ".join(s.split())
    assert kern(jobs["mutation-summary"]["if"]) == kern(jobs["mutation"]["if"]), (
        "Erzeuger und Sammler tragen VERSCHIEDENE Landebedingungen — dann ist der Sammler entweder "
        "rot, wenn die Schicht absichtlich ausbleibt, oder still, wenn sie rot ist")


#: The jobs of ci.yml that may still read the label `landung`: the fork pull request's full matrix and
#: its collector. Since the owner word of 2026-09-28 (EIN-LABEL-STARTET-KEINE-CI-MEHR-01) ci.yml runs
#: on no label event, so there the label takes effect at the fork's next push; everything that has to
#: start when the label is SET lives in landung.yml, which subscribes the label events.
CI_LABEL_NUR_FUER_FORKS = {"test", "all-checks-passed"}


def _label_verstoesse(wfs: dict) -> list[str]:
    """Where a workflow decides on `landung` without the events that make the decision happen.

    Pure, so a built counter-example can make it fail. ci.yml is the one file that must NOT subscribe
    the label events, and there the label may be read only in CI_LABEL_NUR_FUER_FORKS."""
    schlecht = []
    for n, d in sorted(wfs.items()):
        jobs = (d or {}).get("jobs") or {}
        mit_label = sorted(j for j, v in jobs.items() if "'landung'" in str(v))
        if not mit_label:
            continue
        on = ((d or {}).get(True) or (d or {}).get("on") or {})
        typen = (on.get("pull_request") or {}).get("types") if isinstance(on, dict) else None
        if n == "ci.yml":
            if typen is None or {"labeled", "unlabeled"} & set(typen):
                schlecht.append(f"{n} subscribes a label event (types={typen}); a label must start no run of it")
            fremd = [j for j in mit_label if j not in CI_LABEL_NUR_FUER_FORKS]
            if fremd:
                schlecht.append(f"{n} reads `landung` in {fremd}, outside the fork matrix; that work starts "
                                "at the label and belongs in landung.yml")
            continue
        if not typen or not {"labeled", "unlabeled"} <= set(typen):
            schlecht.append(f"{n} decides on `landung` but subscribes types={typen}; setting or removing "
                            "the label would start nothing there")
    return schlecht


def test_ein_label_praedikat_verlangt_das_label_ereignis():
    """Without `types` GitHub sends only opened, synchronize and reopened, so a predicate on `landung`
    without `labeled` is a condition nobody sets. Since 2026-09-28 with one owned exception, ci.yml,
    which subscribes no label event at all (see `_label_verstoesse`)."""
    assert _label_verstoesse(_workflows()) == []


def test_fangnachweis_ein_label_praedikat_ohne_ereignis_wird_gefunden():
    auf_label = {"pull_request": {"types": ["labeled", "unlabeled"]}}
    bedingung = {"if": "github.event.action == 'labeled' && github.event.label.name == 'landung'"}
    assert _label_verstoesse({"l.yml": {"on": auf_label, "jobs": {"m": bedingung}}}) == []
    assert _label_verstoesse({"l.yml": {"on": {"pull_request": {"types": ["labeled"]}},
                                        "jobs": {"m": bedingung}}})[0].startswith("l.yml decides on")
    ci_label = {"pull_request": {"types": ["opened", "synchronize", "reopened", "labeled"]}}
    assert _label_verstoesse({"ci.yml": {"on": ci_label, "jobs": {"test": bedingung}}})[0].startswith(
        "ci.yml subscribes a label event")
    ci_heil = {"pull_request": {"types": ["opened", "synchronize", "reopened"]}}
    assert _label_verstoesse({"ci.yml": {"on": ci_heil, "jobs": {"test": bedingung}}}) == []
    assert _label_verstoesse({"ci.yml": {"on": ci_heil, "jobs": {"mutation": bedingung}}})[0].startswith(
        "ci.yml reads `landung` in ['mutation']")


def test_fangnachweis_eine_eigene_gruppe_im_gerufenen_workflow_wird_gefunden():
    gebaut = {"r.yml": {"on": {"workflow_call": None}, "concurrency": {"group": "x"}, "jobs": {}}}
    zuviel = [n for n, d in gebaut.items() if _nur_gerufen(d) and d.get("concurrency")]
    assert zuviel == ["r.yml"]
    ohne = {"r.yml": {"on": {"workflow_call": None}, "jobs": {}}}
    assert [n for n, d in ohne.items() if _nur_gerufen(d) and d.get("concurrency")] == []


def test_fangnachweis_ein_ungeschuetztes_head_ref_wird_gefunden():
    gebaut = {"x.yml": {"jobs": {"m": {"if": "startsWith(github.head_ref, 'release/')"}}}}
    assert _ohne_fremd_schutz(gebaut) == ["x.yml::m::if"]
    heil = {"x.yml": {"jobs": {"m": {"if": "github.event.pull_request.head.repo.full_name == "
                                           "github.repository && startsWith(github.head_ref, 'release/')"}}}}
    assert _ohne_fremd_schutz(heil) == []


def test_cancel_in_progress_ist_bedingt_und_nicht_pauschal():
    """Ein Nightly darf NICHT abgebrochen werden, ein ueberholter Push schon.

    Deshalb steht dort ein Ausdruck ueber `github.event_name`, kein festes true.
    """
    hart = []
    for n, d in _workflows().items():
        c = (d or {}).get("concurrency") or {}
        if not isinstance(c, dict):
            continue
        wert = c.get("cancel-in-progress")
        trig = _trigger(d)
        if wert is True and ({"schedule", "workflow_dispatch"} & trig):
            hart.append((n, sorted(trig)))
    assert not hart, (
        "cancel-in-progress: true fest verdrahtet, obwohl der Workflow auch per schedule oder "
        f"workflow_dispatch laeuft — ein Nightly soll durchlaufen: {hart}")


def test_jeder_laufende_job_traegt_ein_zeitbudget():
    ohne = []
    for n, d in _workflows().items():
        for job, v in ((d or {}).get("jobs") or {}).items():
            if not isinstance(v, dict) or "runs-on" not in v:
                continue          # `uses:`-Jobs koennen kein timeout-minutes tragen
            if "timeout-minutes" not in v:
                ohne.append(f"{n}::{job}")
    assert not ohne, f"Jobs ohne timeout-minutes: {ohne}"


#: GitHub's limit for a job on a hosted runner, in minutes. A budget above it is not a budget: GitHub
#: stops the job at 360 minutes whatever the workflow says.
GITHUB_JOB_GRENZE_MIN = 360


def _mutationsdeckel_verletzt(d: dict) -> list[str]:
    """Where the mutation job breaks its cap. Pure, so a built counter-example can make it fail."""
    job = d["jobs"]["mutation"]
    t = job.get("timeout-minutes")
    if not isinstance(t, int):
        return [f"the job carries no numeric timeout-minutes ({t!r})"]
    schlecht = []
    if t > GITHUB_JOB_GRENZE_MIN:
        schlecht.append(f"job budget {t} minutes, above GitHub's limit of {GITHUB_JOB_GRENZE_MIN}")
    schritte = [s for s in job.get("steps") or [] if s.get("name") == "Mutation check"]
    if len(schritte) != 1:
        return schlecht + [f"{len(schritte)} steps named 'Mutation check', expected one"]
    s = schritte[0].get("timeout-minutes")
    if not isinstance(s, int) or s >= t:
        schlecht.append(f"the step 'Mutation check' has {s!r} minutes and must stop below the job's "
                        f"{t}, or the steps after it never record how far the shard got")
    return schlecht


def test_ein_mutationsshard_bleibt_in_seinem_deckel():
    """TWO ORDERS, AND THE YOUNGER ONE HOLDS. The first, from 13.09.2026, in translation: "mutation
    not above 60 minutes per shard, otherwise the shard is cut wrong." Measured then, shards ran 151
    to 288 minutes. The second is the owner word on Z230 of 26.09.2026, in translation: "job cap and
    shard count provisionally such that a shard safely finishes within the upper limit of a GitHub
    job of 6 hours; you set the final values after the first measured CI run time."

    Since Z230 each mutant runs over a baseline of its own selection, and a selection costs about
    2000 to 2200 s in CI, so one mutant alone comes close to the old 60 minutes. The contract holds
    the younger order: the job stays within GitHub's limit, and the gate step stops before the job,
    so the shard still records how far it got. PROVISIONAL like the values it checks: when the first
    measured CI run sets the final cap and shard count, this contract follows them.
    """
    assert _mutationsdeckel_verletzt(_workflows()["ci.yml"]) == []


def test_fangnachweis_ein_deckel_ueber_der_github_grenze_wird_gefunden():
    def wf(job, schritt):
        return {"jobs": {"mutation": {"timeout-minutes": job,
                                      "steps": [{"name": "Mutation check",
                                                 "timeout-minutes": schritt}]}}}
    assert _mutationsdeckel_verletzt(wf(361, 345)) == [
        "job budget 361 minutes, above GitHub's limit of 360"]
    assert _mutationsdeckel_verletzt(wf(360, 360)) == [
        "the step 'Mutation check' has 360 minutes and must stop below the job's 360, or the steps "
        "after it never record how far the shard got"]
    assert _mutationsdeckel_verletzt(wf(360, None))[0].startswith("the step 'Mutation check' has None")
    assert _mutationsdeckel_verletzt({"jobs": {"mutation": {"timeout-minutes": 360, "steps": []}}}) == [
        "0 steps named 'Mutation check', expected one"]
    assert _mutationsdeckel_verletzt(wf(360, 345)) == [], "the provisional values are reported"


def test_mutation_startet_erst_nach_test_und_coverage():
    """Der teuerste Job haengt an den billigen. Ohne das rechnen Shards weiter, waehrend das
    Urteil laengst rot ist — am 13.09. in allen vier laufenden Laeufen gemessen."""
    m = _workflows()["ci.yml"]["jobs"]["mutation"]
    assert set(m.get("needs") or []) >= {"test", "coverage"}, (
        f"mutation.needs ist {m.get('needs')} — test und coverage fehlen")


def test_die_schwere_schicht_haengt_am_landekandidaten():
    """Three ways in, since 2026-09-28 in two files: by hand and on a release/ branch in ci.yml, on the
    label `landung` in landung.yml, where the label event arrives (EIN-LABEL-STARTET-KEINE-CI-MEHR-01)."""
    wfs = _workflows()
    bed = str(wfs["ci.yml"]["jobs"]["mutation"].get("if") or "")
    for merkmal in ("workflow_dispatch", "release/"):
        assert merkmal in bed, f"Landekandidaten-Bedingung nennt '{merkmal}' nicht: {bed[:120]}"
    label = str(wfs["landung.yml"]["jobs"]["mutation"].get("if") or "")
    assert "github.event.label.name == 'landung'" in label, f"landung.yml nennt das Label nicht: {label}"


def test_die_versionsmatrix_traegt_ihre_klammer():
    """RUECKFALLSPERRE gegen einen Fehler, der beim Schreiben gefangen wurde.

    In GitHub-Ausdruecken bindet `&&` staerker als `||`. Ohne Klammer liest sich
    `A || B || C || D && voll || eine` als `A || B || C || (D && voll) || eine`, und bei wahrem A
    kommt `true` statt einer JSON-Liste heraus — die Matrix waere leer und der Job liefe nie.
    """
    s = str(_workflows()["ci.yml"]["jobs"]["test"]["strategy"]["matrix"]["python-version"])
    assert "fromJSON" in s, "die Versionsmatrix ist keine Ausdrucksmatrix mehr"
    assert _bedingung_ist_geklammert(s), (
        "die Klammer um die Oder-Kette fehlt — && bindet staerker als ||, der Ausdruck liefert dann "
        f"`true` statt einer Liste: {s[:160]}")


def test_die_pflichtkontexte_werden_nie_uebersprungen():
    """DIE AUSNAHME, die der Auftrag NICHT vorsah, und ihr Grund.

    B5 verlangt paths-ignore fuer Prosa und Register. Fuer die zwei Workflows, die die sieben
    Pflichtpruefungen des Regelsatzes protect-main tragen, ist das NICHT ausfuehrbar: eine
    uebersprungene Pflichtpruefung meldet nie einen Zustand, und der Merge bleibt dauerhaft
    blockiert. Dieselbe Falle steht im Kopf von b7-governance-analytics-gate im Nachbarrepo.
    """
    verletzt = []
    for n, d in _workflows().items():
        jobs = set(((d or {}).get("jobs") or {}).keys())
        if not (jobs & PFLICHT_JOBS):
            continue
        on = (d.get(True) or d.get("on") or {})
        for trig in ("push", "pull_request"):
            block = on.get(trig) if isinstance(on, dict) else None
            if isinstance(block, dict) and "paths-ignore" in block:
                verletzt.append(f"{n}::{trig}")
    assert not verletzt, (
        "ein Workflow mit Pflichtkontext traegt paths-ignore — eine uebersprungene Pflichtpruefung "
        f"blockiert den Merge dauerhaft: {verletzt}")


# ── Fangnachweise: jede Zusicherung oben muss an einem Gegenbeispiel FALLEN koennen ──────────────

def _pruefe_zeitbudget(wfs: dict) -> list[str]:
    ohne = []
    for n, d in wfs.items():
        for job, v in ((d or {}).get("jobs") or {}).items():
            if isinstance(v, dict) and "runs-on" in v and "timeout-minutes" not in v:
                ohne.append(f"{n}::{job}")
    return ohne


def test_fangnachweis_ein_job_ohne_zeitbudget_wird_gefunden():
    gebaut = {"x.yml": {"jobs": {"a": {"runs-on": "ubuntu-latest"}}}}
    assert _pruefe_zeitbudget(gebaut) == ["x.yml::a"]
    heil = {"x.yml": {"jobs": {"a": {"runs-on": "ubuntu-latest", "timeout-minutes": 5}}}}
    assert _pruefe_zeitbudget(heil) == [], "die Pruefung meldet auch einen heilen Job — sie irrt"


def test_fangnachweis_ein_uses_job_wird_NICHT_faelschlich_gemeldet():
    """Die Gegenrichtung: ein Job, der einen wiederverwendbaren Workflow ruft, KANN kein
    timeout-minutes tragen. Ihn zu melden waere ein Fehlalarm, den niemand beheben kann."""
    gebaut = {"x.yml": {"jobs": {"a": {"uses": "./.github/workflows/y.yml"}}}}
    assert _pruefe_zeitbudget(gebaut) == []


def test_fangnachweis_die_klammerpruefung_faellt_ohne_klammer():
    ohne = "${{ fromJSON( github.event_name == 'x' || startsWith(a,'b') && 'voll' || 'eine' ) }}"
    mit = "${{ fromJSON( ( github.event_name == 'x' || startsWith(a,'b') ) && 'voll' || 'eine' ) }}"
    assert not _bedingung_ist_geklammert(ohne), (
        "die Pruefung haelt die KLAMMERLOSE Form fuer geklammert — genau der Fehler der ersten "
        "Fassung, wo `fromJSON(` selbst als Klammer durchging")
    assert _bedingung_ist_geklammert(mit), "die Pruefung erkennt die richtige Form nicht"
    # Und die dritte Richtung: ohne fromJSON ist es keine Ausdrucksmatrix
    assert not _bedingung_ist_geklammert("[\"3.12\"]")

def test_die_versionsmatrix_ist_ein_REINER_ausdruck():
    """DER FUND VOM 13.09.2026, an PR 202 gemessen, und die Luecke im Vertrag darueber.

    Die erste Fassung trug die begruendenden Kommentare INNERHALB des gefalteten Skalars `>-`.
    Dort ist `#` kein Kommentar, sondern Text. Der Wert der Matrix war damit eine ZEICHENKETTE,
    die mit Prosa beginnt und den Ausdruck nur enthaelt — GitHub bekam keine Liste, die Matrix war
    leer, und der Job `test` ENTSTAND GAR NICHT. Gemessen: neun Jobs statt zwoelf im Lauf zu
    PR 202, kein einziger test-Kontext, und die fuenf Pflichtpruefungen des Regelsatzes
    protect-main haetten NIE gemeldet. Ein PR waere dauerhaft unmergebar gewesen.

    DIE ALTE ZUSICHERUNG WAR GRUEN DABEI. Sie prueft, ob `fromJSON` VORKOMMT und ob die Klammer
    sitzt — beides stimmte auch mit dem Prosa-Vorspann. Sie mass den INHALT, nicht die FORM.
    Diese hier misst die Form: der Wert muss der Ausdruck sein, nicht ihn enthalten.
    """
    v = str(_workflows()["ci.yml"]["jobs"]["test"]["strategy"]["matrix"]["python-version"]).strip()
    assert v.startswith("${{"), (
        f"die Matrix ist kein reiner Ausdruck, sie beginnt mit {v[:60]!r} — steht ein Kommentar im "
        "gefalteten Skalar, wird er Teil des Wertes und die Matrix bleibt leer")
    assert v.endswith("}}"), f"die Matrix endet nicht mit }}}}: {v[-60:]!r}"


def test_fangnachweis_ein_prosa_vorspann_wird_gefunden():
    """Die Gegenrichtung: genau die kaputte Form von PR 202 muss auffallen."""
    kaputt = "# ein Kommentar im Skalar ${{ fromJSON( ( a || b ) && 'x' || 'y' ) }}"
    heil = "${{ fromJSON( ( a || b ) && 'x' || 'y' ) }}"
    def ist_rein(s: str) -> bool:
        s = s.strip()
        return s.startswith("${{") and s.endswith("}}")
    assert not ist_rein(kaputt), "der Fangnachweis erkennt den Prosa-Vorspann nicht"
    assert ist_rein(heil)
    # und die alte, unzureichende Pruefung waere bei BEIDEN gruen gewesen:
    assert "fromJSON" in kaputt and "fromJSON" in heil


# ── Nachtrag 14.09.2026: ein Zeitbudget UNTER der gemessenen Dauer ist ein Abbruch mit Ansage ─────

#: Die laengste je GEMESSENE Laufzeit je Job, in Minuten, aus der GitHub-Actions-API ueber die
#: juengsten 40 Laeufe des Repositoriums (Zustand success oder failure, also wirklich beendet;
#: abgebrochene Laeufe sagen ueber die Dauer nichts). Erhoben 14.09.2026 00:0xZ.
#:
#: WARUM ES DIESE ZAHLEN GIBT. Der Schnitt setzte `timeout-minutes` nach Augenmass statt nach
#: Messung, und Nachtrag 1 hatte ausdruecklich "Wert aus den gemessenen Dauern plus Reserve"
#: verlangt. GEMESSEN am eigenen Landekandidaten: `coverage` lief von 21:31:18Z bis 22:01:33Z,
#: exakt 30 Minuten, und GitHub meldete den Zeitueberlauf als `cancelled` — nicht als `failure`.
#: Eine abgebrochene Pflichtpruefung ist unter dem stehenden GO weder gruen noch messbar, der
#: Landekandidat des Schnitts blockierte sich also an seiner eigenen Zeile. Die drei beendeten
#: coverage-Laeufe davor brauchten 34, 40 und 41 Minuten: das Limit lag UNTER dem Minimum.
#:
#: NACHTRAG 14.09.2026 00:19Z, AM LANDELAUF DES SCHNITTS SELBST GEMESSEN — und zwei eigene Fehler
#: darin. Die Landung von PR 202 lief mit den NEUEN Budgets durch, und ihre Endzahlen waren:
#:
#:     coverage      40.0 min      test (3.10)   32.3 min      test (3.11)   29.1 min
#:     test (3.12)   27.4 min      test (3.13)   26.9 min      test (3.14)   21.2 min
#:
#: Erstens: `test` stand hier auf 30, die Hoechstdauer ist gemessen 32.3. Der Schnitt hat also nicht
#: EINEN Job gerettet, sondern ZWEI — unter dem alten 30-Minuten-Budget waeren `coverage` (40.0) und
#: `test (3.10)` (32.3) beide abgeschnitten worden, und dieser PR haette nie landen koennen.
#: Zweitens, und das ist der peinlichere: der Absatz darueber nennt selbst 41 Minuten als gemessene
#: coverage-Dauer, waehrend die Konstante 40 sagte. Eine Zahl, die ihrem eigenen Beleg zwei Zeilen
#: weiter oben widerspricht, ist keine Messung, sondern eine Erinnerung an eine.
#:
#: Beide Budgets tragen die korrigierten Werte weiterhin: coverage braucht ceil(41*1.25)=52 bei 60,
#: `test` braucht ceil(33*1.25)=42 bei 50. Die Workflows aendern sich dadurch NICHT — korrigiert wird
#: die Behauptung, nicht die Verdrahtung.
GEMESSENE_MAXIMA_MIN = {"test": 33, "coverage": 41}

#: Reserve auf die gemessene Hoechstdauer. Ein Limit GLEICH dem Maximum ist kein Budget, sondern
#: eine Wette darauf, dass kein Lauf je langsamer wird — `test` stand genau dort.
RESERVE = 1.25


def _zu_knappe_budgets(wfs: dict, maxima: dict[str, int]) -> list[str]:
    """Jobs, deren Budget die gemessene Hoechstdauer plus Reserve nicht traegt. Rein, damit ein
    gebautes Gegenbeispiel sie fallen lassen kann."""
    import math
    zu_knapp = []
    for name, d in sorted(wfs.items()):
        for job, v in ((d or {}).get("jobs") or {}).items():
            if job not in maxima or not isinstance(v, dict):
                continue
            noetig = math.ceil(maxima[job] * RESERVE)
            hat = v.get("timeout-minutes")
            if hat is None or hat < noetig:
                zu_knapp.append(f"{name}::{job} hat {hat}, braucht mindestens {noetig}")
    return zu_knapp


def test_kein_zeitbudget_liegt_unter_der_gemessenen_dauer():
    assert _zu_knappe_budgets(_workflows(), GEMESSENE_MAXIMA_MIN) == []


def test_fangnachweis_ein_budget_gleich_dem_maximum_wird_gefunden():
    """Die Richtung, an der die erste Fassung scheiterte: 30 Minuten Limit bei 30 Minuten
    gemessener Dauer sah aus wie ein Budget und war keins."""
    gebaut = {"x.yml": {"jobs": {"test": {"runs-on": "u", "timeout-minutes": 30}}}}
    assert _zu_knappe_budgets(gebaut, {"test": 30}) == ["x.yml::test hat 30, braucht mindestens 38"]


def test_fangnachweis_ein_fehlendes_budget_wird_gefunden():
    gebaut = {"x.yml": {"jobs": {"coverage": {"runs-on": "u"}}}}
    assert _zu_knappe_budgets(gebaut, {"coverage": 40}) == [
        "x.yml::coverage hat None, braucht mindestens 50"]


def test_fangnachweis_ein_ausreichendes_budget_wird_NICHT_gemeldet():
    gebaut = {"x.yml": {"jobs": {"test": {"runs-on": "u", "timeout-minutes": 50}}}}
    assert _zu_knappe_budgets(gebaut, {"test": 30}) == []


# ── Runde zwei, 14.09.2026: cancel-in-progress prueft den ANKOMMENDEN, die Gruppe bestimmt das OPFER ──

def _gruppe_ohne_ereignis(wfs: dict) -> list[str]:
    """Gruppen, die das Ereignis NICHT enthalten.

    DIE KLASSE, in einem Satz: `cancel-in-progress` wird am ANKOMMENDEN Lauf ausgewertet, die Gruppe
    bestimmt aber, WER stirbt. Ein Ausdruck, der nur auf `push` und `pull_request` wahr wird, schuetzt
    deshalb nicht den geplanten oder von Hand ausgeloesten Lauf — er raeumt ihn ab, sobald jemand auf
    denselben Ref pusht. GEMESSEN am 14.09.2026: ci.yml traegt `workflow_dispatch` neben `push`, und
    codeql, demo-reproducible, published-artifact-gate und scorecard tragen `schedule` daneben; alle
    fuenf teilten sich mit dem Push eine Gruppe. Das Ereignis IN der Gruppe trennt sie.
    """
    ohne = []
    for n, d in sorted(wfs.items()):
        c = (d or {}).get("concurrency") or {}
        g = str(c.get("group") or "")
        if g and "github.event_name" not in g:
            ohne.append(n)
    return ohne


def _kann_eine_veroeffentlichung_abbrechen(wfs: dict) -> list[str]:
    """Workflows, die auf TAG-Pushes laufen und trotzdem abbrechen duerfen."""
    schlecht = []
    for n, d in sorted(wfs.items()):
        on = ((d or {}).get(True) or (d or {}).get("on") or {})
        push = on.get("push") if isinstance(on, dict) else None
        if not (isinstance(push, dict) and push.get("tags")):
            continue
        c = (d or {}).get("concurrency") or {}
        if c.get("cancel-in-progress") is not False:
            schlecht.append(f"{n} (cancel-in-progress={c.get('cancel-in-progress')!r})")
    return schlecht


def test_keine_gruppe_vermischt_zwei_ereignisarten():
    assert _gruppe_ohne_ereignis(_workflows()) == []


def test_ein_lauf_auf_einem_tag_wird_nie_abgebrochen():
    """Die Auflage stand im eigenen Restrisiko-Blatt, bevor der Schnitt sie verletzte:
    `RESTRISIKO_600.md`, Abschnitt "Die Ausnahme: release.yml darf NICHT abgebrochen werden", sagt
    woertlich "release.yml bekommt cancel-in-progress: false". Der bedingte Ausdruck ist dort IMMER
    wahr, weil der einzige Trigger ein Push ist — ein zweimal gepushter Tag haette den laufenden
    Release zwischen Entwurf, Upload und Veroeffentlichung abgebrochen."""
    assert _kann_eine_veroeffentlichung_abbrechen(_workflows()) == []


def test_ein_label_praedikat_verlangt_auch_das_entfernen():
    """A predicate on `landung` needs both directions. Without `unlabeled` the heavy layer keeps
    running after the label is taken off: the event snapshot of the running run does not know about
    the removal, and no new run enters the group to replace it. `_label_verstoesse` asks for both
    events outside ci.yml; this case names the direction."""
    for n, d in _workflows().items():
        if n == "ci.yml" or "'landung'" not in str((d or {}).get("jobs") or {}):
            continue
        on = (d.get(True) or d.get("on") or {})
        typen = (on.get("pull_request") or {}).get("types") if isinstance(on, dict) else None
        assert typen and "unlabeled" in typen, f"{n} abonniert kein `unlabeled` (types={typen})"


def test_fangnachweis_eine_gruppe_ohne_ereignis_wird_gefunden():
    gebaut = {"x.yml": {"concurrency": {"group": "${{ github.workflow }}-${{ github.ref }}"}}}
    assert _gruppe_ohne_ereignis(gebaut) == ["x.yml"]
    heil = {"x.yml": {"concurrency": {
        "group": "${{ github.workflow }}-${{ github.event_name }}-${{ github.ref }}"}}}
    assert _gruppe_ohne_ereignis(heil) == []


def test_fangnachweis_ein_abbrechbarer_tag_lauf_wird_gefunden():
    gebaut = {"r.yml": {"on": {"push": {"tags": ["v*"]}},
                        "concurrency": {"group": "g", "cancel-in-progress": True}}}
    assert _kann_eine_veroeffentlichung_abbrechen(gebaut) == ["r.yml (cancel-in-progress=True)"]
    bedingt = {"r.yml": {"on": {"push": {"tags": ["v*"]}},
                         "concurrency": {"group": "g",
                                         "cancel-in-progress": "${{ github.event_name == 'push' }}"}}}
    assert _kann_eine_veroeffentlichung_abbrechen(bedingt) == [
        "r.yml (cancel-in-progress=\"${{ github.event_name == 'push' }}\")"], (
        "ein BEDINGTER Ausdruck ist hier keine Entwarnung: auf einem Workflow, dessen einziger "
        "Trigger ein Push ist, ist er immer wahr")
    heil = {"r.yml": {"on": {"push": {"tags": ["v*"]}},
                      "concurrency": {"group": "g", "cancel-in-progress": False}}}
    assert _kann_eine_veroeffentlichung_abbrechen(heil) == []
