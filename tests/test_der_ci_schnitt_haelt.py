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


def test_jeder_workflow_hat_eine_concurrency_gruppe():
    fehlend = [n for n, d in _workflows().items() if not (d or {}).get("concurrency")]
    assert not fehlend, f"ohne concurrency-Gruppe: {fehlend}"


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
