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


def test_ein_label_praedikat_verlangt_das_label_ereignis():
    """Ohne `types` sendet GitHub nur opened, synchronize, reopened. Ein Praedikat auf `landung`
    ohne `labeled` ist eine Bedingung, die niemand stellt."""
    for n, d in _workflows().items():
        s = str((d or {}).get("jobs") or {})
        if "labels.*.name, 'landung'" not in s:
            continue
        on = (d.get(True) or d.get("on") or {})
        typen = (on.get("pull_request") or {}).get("types") if isinstance(on, dict) else None
        assert typen and "labeled" in typen, (
            f"{n} entscheidet am Label `landung`, abonniert aber kein `labeled` — das Anbringen des "
            f"Labels loest dort keinen Lauf aus (types={typen})")


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


def test_ein_mutationsshard_bleibt_unter_einer_stunde():
    """Der Auftrag woertlich: 'Mutation nicht ueber 60 Minuten je Shard, sonst ist der Shard falsch
    geschnitten.' Gemessen liefen Shards 151 bis 288 Minuten."""
    d = _workflows()["ci.yml"]
    t = d["jobs"]["mutation"]["timeout-minutes"]
    assert t <= 60, f"Mutations-Shard mit {t} Minuten Budget — ueber der angeordneten Grenze von 60"


def test_mutation_startet_erst_nach_test_und_coverage():
    """Der teuerste Job haengt an den billigen. Ohne das rechnen Shards weiter, waehrend das
    Urteil laengst rot ist — am 13.09. in allen vier laufenden Laeufen gemessen."""
    m = _workflows()["ci.yml"]["jobs"]["mutation"]
    assert set(m.get("needs") or []) >= {"test", "coverage"}, (
        f"mutation.needs ist {m.get('needs')} — test und coverage fehlen")


def test_die_schwere_schicht_haengt_am_landekandidaten():
    m = _workflows()["ci.yml"]["jobs"]["mutation"]
    bed = str(m.get("if") or "")
    for merkmal in ("workflow_dispatch", "release/", "landung"):
        assert merkmal in bed, f"Landekandidaten-Bedingung nennt '{merkmal}' nicht: {bed[:120]}"


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
GEMESSENE_MAXIMA_MIN = {"test": 30, "coverage": 40}

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
