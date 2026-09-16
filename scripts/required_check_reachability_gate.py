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
import hashlib
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


#: `if:`-Ausdruecke, die NICHT einschraenken. Sie sehen aus wie eine Bedingung und sind keine.
#:
#: WARUM DAS EINE EIGENE MENGE IST. Die erste Fassung las jedes `if:` als Einschraenkung und
#: meldete den Job als `produced-only-if`. Fuer `if: false` war das schon gesondert behandelt --
#: die andere Richtung fehlte. Gemessen 2026-09-16 beim Bau des Sammel-Jobs: `if: always()` ist
#: die STAERKSTE Zusage, die ein Job geben kann (er laeuft auch, wenn seine Vorgaenger fallen oder
#: der Lauf abgebrochen wird), und genau dieser Job wurde als bedingt gefuehrt. Der Kontext, der
#: die Klasse heilen soll, waere damit selbst als Instanz der Klasse gemeldet worden.
#:
#: DIE MENGE BLEIBT KLEIN UND WOERTLICH. `always() && X` schraenkt sehr wohl ein und steht
#: deshalb NICHT hier; `mutation-summary` in ci.yml ist genau dieser Fall und muss bedingt
#: bleiben. Geprueft wird der normalisierte Text, nicht ein Teilstring -- ein Vergleich auf
#: "enthaelt always()" wuerde `always() && <Landebedingung>` mitnehmen und die Landebedingung
#: unsichtbar machen.
_IMMER_WAHR = frozenset({"always()", "${{ always() }}", "true", "${{ true }}"})


def _schraenkt_ein(bedingung: object) -> bool:
    """Schraenkt dieses `if:` die Erzeugung des Kontexts wirklich ein?"""
    return " ".join(str(bedingung).split()).lower() not in _IMMER_WAHR


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
            if job_if is not None and _schraenkt_ein(job_if):
                als_text = " ".join(str(job_if).split())
                if als_text.lower() in ("false", "${{ false }}"):
                    hinweise.append(
                        f"{pfad.name}:{job_id}: `if: {als_text}` — this job never runs, so "
                        f"its contexts arise under no condition")
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


_HEX64 = re.compile(r"[0-9a-f]{64}")


def bedingungs_digest(text: str) -> str:
    """Der Digest EINER Bedingung, ueber genau der Form, die auch im Bericht steht.

    Normalisiert wird nur der Weissraum -- dieselbe Faltung, mit der die Bedingung gelesen und
    gedruckt wird. Waere hier eine zweite Normalisierung, haetten Bericht und Zusage zwei
    verschiedene Gegenstaende, und die Zusage bezoege sich auf etwas, das niemand sieht.
    """
    return hashlib.sha256(" ".join((text or "").split()).encode("utf-8")).hexdigest()


def _zusagen(roh, feld: str = "condition_sha256") -> tuple[dict[str, str], list[str]]:
    """Liest eine Zusagenliste. Gibt die BINDENDEN Zusagen und die unverbindlichen Eintraege.

    Bindend ist nur ein Eintrag der Form {"context": ..., <feld>: <64 hex>}. Eine nackte
    Zeichenkette ist die alte, namensgebundene Form; sie wird NICHT als Zusage gezaehlt, sondern
    beim Namen genannt, damit ihr Weiterleben auffaellt statt zu wirken.

    DAS FELD IST EIN PARAMETER, WEIL ES ZWEI ZUSAGEARTEN GIBT, und genau das war der naechste
    Fund. `accepted_gated` wurde am 2026-09-16 von der Namensbindung auf `condition_sha256`
    umgestellt -- und `accepted_unreadable` blieb eine nackte Praefixliste. Eine dritte Linse
    baute den Fall am selben Tag und mass ihn: derselbe Job wechselte von "ruft einen
    wiederverwendbaren Workflow" auf "Matrix nicht woertlich lesbar", zwei verschiedene
    Unmessbarkeiten mit demselben Praefix, und das Tor blieb still gruen. Ein Instanz-Fix, der
    den Nachbarn stehen laesst, verschiebt die Luecke nur.
    """
    bindend: dict[str, str] = {}
    lose: list[str] = []
    for eintrag in roh or []:
        if isinstance(eintrag, str):
            lose.append(eintrag)
            continue
        if not isinstance(eintrag, dict):
            lose.append(repr(eintrag))
            continue
        name, digest = eintrag.get("context"), eintrag.get(feld)
        if not name or not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            lose.append(str(name or eintrag))
            continue
        bindend[name] = digest
    return bindend, lose


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
    # DIE ZUSAGE HAENGT AN DER BEDINGUNG, NICHT AM NAMEN. Die erste Fassung fuehrte
    # `accepted_gated` als blosse Namensliste, und zwei unabhaengige Gegenleser fanden am
    # 2026-09-16 dieselbe Luecke: ein Name, der einmal dort steht, ist dauerhaft immun. Ein
    # Kontext, der heute UNBEDINGT laeuft und morgen hinter einem `if:` verschwindet, rutschte
    # durch, solange sein Name schon gelistet war; und eine Bedingung durfte beliebig ENGER
    # werden -- von "Label landung" auf "Label landung UND ein nie gesetztes zweites Label" --
    # ohne dass sich etwas am Urteil aenderte. Beides ist genau die Verschlechterung, die diese
    # Sohle fangen soll, also bindet die Zusage jetzt an den Digest der normalisierten Bedingung.
    # Ein Eintrag ohne diesen Digest zaehlt NICHT als Zusage: fail closed, damit eine veraltete
    # Erklaerungsform nicht als Freibrief weiterlebt.
    hingenommen, unverbindlich = _zusagen(erklaert.get("accepted_gated"))
    hingenommen_unlesbar, unverbindlich_unlesbar = _zusagen(
        erklaert.get("accepted_unreadable"), "reason_sha256")
    neu_gegated, geaenderte_bedingung = [], []
    for e in je:
        if e["state"] != GATED:
            continue
        ist = bedingungs_digest(e.get("condition") or "")
        e["condition_sha256"] = ist
        soll = hingenommen.get(e["context"])
        if soll == ist:
            continue
        neu_gegated.append(e["context"])
        if soll is not None:
            geaenderte_bedingung.append({"context": e["context"], "declared": soll, "measured": ist})
    neu_gegated.sort()
    # DER GRUND, NICHT DER PRAEFIX. Wer eine Unmessbarkeit hinnimmt, nimmt EINE hin -- die, die
    # er gelesen hat. Derselbe Job kann morgen aus einem anderen Grund unlesbar sein, und dieser
    # Grund ist dann NICHT zugesagt. Gemessen (Linse 3, 2026-09-16): Wechsel von "calls a
    # reusable workflow" auf "matrix values not readable literally" -- gleicher Praefix, exit 0,
    # `newly_unreadable` leer.
    neu_unlesbar, geaenderter_grund = [], []
    for u in erhoben["unlesbar"]:
        soll, grund = None, None
        for name, dig in hingenommen_unlesbar.items():
            if u == name or u.startswith(f"{name}:"):
                soll, grund = dig, u[len(name):].lstrip(": ")
                break
        ist = bedingungs_digest(grund or "")
        if soll is not None and soll == ist:
            continue
        neu_unlesbar.append(u)
        if soll is not None:
            geaenderter_grund.append({"context": name, "declared": soll, "measured": ist})
    return {"verdict": verdict, "per_context": je, "counts": zahl,
            "accepted_gated": sorted(hingenommen), "newly_gated": neu_gegated,
            "changed_conditions": geaenderte_bedingung,
            "unbound_acceptances": sorted(unverbindlich),
            "newly_unreadable": neu_unlesbar, "changed_reasons": geaenderter_grund,
            "unbound_unreadable_acceptances": sorted(unverbindlich_unlesbar),
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


def _erklaerungs_digest(pfad: Path | None) -> str:
    """Der Digest der Erklaerungsdatei, an die ein Markerurteil gebunden wird.

    Ein Marker sagt sonst nur, DASS einmal geprueft wurde, nie WORAN. Drei Angriffe gelangen am
    2026-09-16 gegen die erste Fassung: ein Marker von 2020 meldete "checked"; einer ohne
    Zeitpunkt ebenso; einer mit fremdem Regelsatz wurde unbesehen zitiert. Alle drei fielen unter
    dieselbe Luecke - gebunden war die EXISTENZ der Datei, nicht der gepruefte ZUSTAND. Dieselbe
    Klasse wie die Namensbindung in `accepted_gated`, nur eine Ebene hoeher.
    """
    p = pfad or (Path(__file__).resolve().parents[1] / ".github" / "required_status_checks.json")
    try:
        return hashlib.sha256(Path(p).read_bytes()).hexdigest()
    except OSError:
        return ""


def _jetzt() -> str:
    from datetime import datetime, timezone  # noqa: PLC0415
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def drift_lage(marker: str | None, erklaerung: Path | None = None) -> dict:
    """Was der Netz-Lauf hinterlassen hat — oder dass er nichts hinterlassen hat.

    VIER ZUSTAENDE, und nur der erste ist eine bestandene Pruefung: `ran` (ein Urteil, das an
    GENAU DIESE Erklaerung gebunden ist), `stale` (ein Urteil ueber eine andere oder ungenannte
    Erklaerung), `unreadable` (Datei da, aber ohne Urteil oder ohne Zeitpunkt) und `absent`
    (nichts da). `absent` heisst NICHT `in Ordnung`: es heisst, dass dieser Lauf nichts darueber
    weiss, ob die Erklaerung noch zum Regelsatz passt.

    `stale` kam dazu, weil die erste Fassung an die EXISTENZ des Markers band statt an den
    geprueften ZUSTAND. Drei Angriffe gingen dagegen durch; sie stehen als Faelle in
    `TestTheOfflineRunSaysWhetherTheDriftCheckRan`.
    """
    if not marker:
        return {"state": "absent", "why": "no marker requested"}
    p = Path(marker)
    if not p.is_file():
        return {"state": "absent", "why": f"{marker} does not exist"}
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"state": "unreadable", "why": f"{marker}: {exc}"}
    # FORM VOR INHALT. Der Marker ist eine Datei, die jemand anders geschrieben hat; seine Felder
    # sind Eingabewerte, keine Zusicherungen. Gemessen 2026-09-16 (Linse 1): ein Marker mit
    # `"declaration_sha256": 123456` liess `war[:12]` mit `TypeError` abstuerzen -- MITTEN im
    # Bericht, nach den richtigen Zeilen, ohne Urteil fuer den Rest. Ein Werkzeug, das an seiner
    # Eingabe abstuerzt, urteilt nicht.
    if not isinstance(d, dict) or not isinstance(d.get("verdict"), str) or not d["verdict"].strip():
        return {"state": "unreadable", "why": f"{marker}: no verdict in the marker"}
    if not isinstance(d.get("at"), str) or not d["at"].strip():
        return {"state": "unreadable", "why": f"{marker}: no timestamp in the marker — without "
                                              "one, a run that happened cannot be told from one "
                                              "that never did"}
    ist = _erklaerungs_digest(erklaerung)
    war = d.get("declaration_sha256")
    if war is not None and not isinstance(war, str):
        return {"state": "unreadable",
                "why": f"{marker}: declaration_sha256 is {type(war).__name__}, not text"}
    if not war:
        return {"state": "stale", "verdict": d["verdict"], "at": d.get("at"),
                "why": "the marker does not say WHICH declaration was checked"}
    if not ist:
        # NICHT LESBAR IST NICHT GEBUNDEN. Waere hier ein Durchlass, koennte die Bindung
        # abgeschaltet werden, indem man die Erklaerung unlesbar macht - die unmessbare Seite
        # wuerde still zur bestandenen. Genau die Verwechslung, gegen die dieses Tor gebaut ist.
        return {"state": "stale", "verdict": d["verdict"], "at": d.get("at"),
                "why": "the declaration is not readable here, so the binding cannot be checked"}
    if war != ist:
        return {"state": "stale", "verdict": d["verdict"], "at": d.get("at"),
                "why": f"checked was {_kurz(war, 12)}\u2026, present here is {_kurz(ist, 12)}\u2026 — the "
                       "declaration changed after the check"}
    return {"state": "ran", "verdict": d["verdict"], "at": d.get("at"),
            "ruleset": d.get("ruleset"), "reason": d.get("reason")}


def _einzeilig(text: object, grenze: int = 160) -> str:
    """Ein Grund, der ueber Zeilen laeuft, zerschneidet den einzeiligen Bericht.

    GEMESSEN 2026-09-16 am eigenen Marker: die Fehlermeldung von `gh` traegt einen Zeilenumbruch,
    und die Berichtszeile brach mitten im Satz ab — der Leser sah die halbe Begruendung und hielt
    sie fuer die ganze. Gefaltet und gekappt, mit sichtbarer Kappmarke.

    ZWEITE RUNDE, und sie ist der eigentliche Punkt: die erste Fassung faltete NUR den Grund. Eine
    adversariale Linse legte am selben Tag einen Marker vor, dessen `ruleset` einen Zeilenumbruch
    trug — und erzeugte damit im Bericht zwei zusaetzliche Zeilen, die exakt wie echte Ausgabe des
    Werkzeugs aussahen, inklusive einer zweiten, erfundenen Kopfzeile mit dem Urteil `produced`.
    Ein Feld aus einer fremden Datei ist ein EINGABEWERT, kein Text. Seitdem laeuft JEDER Wert,
    der in eine Berichtszeile geht, hier durch; `str.split()` faengt Zeilenumbruch, Tabulator und
    Wagenruecklauf, aber KEIN NUL und keine anderen Steuerzeichen, darum die zweite Faltung.
    """
    roh = "".join(ch if ch.isprintable() or ch.isspace() else " " for ch in str(text))
    eins = " ".join(roh.split())
    return eins if len(eins) <= grenze else eins[: grenze - 1] + "\u2026"


def _kurz(wert: object, n: int) -> str:
    """Die ersten n Zeichen eines Feldes — als TEXT, nicht als Scheibe eines unbekannten Typs.

    `war[:12]` auf einer Zahl wirft `TypeError: 'int' object is not subscriptable`, und zwar
    mitten im Bericht: die Zeilen davor stehen da, alles danach fehlt, und der Ausgang ist ein
    Traceback statt eines Urteils. Gemessen 2026-09-16 an einem Marker mit
    `"declaration_sha256": 123456`. Ein Werkzeug, das an seiner Eingabe abstuerzt, urteilt nicht.

    ES IST EIN SCHNITT, KEINE KAPPUNG: `_einzeilig(x, n)` setzt eine Kappmarke INNERHALB der n
    Zeichen und liefert damit elf Zeichen plus `\u2026`, wo zwoelf erwartet werden. Der erste
    Anlauf tat genau das und machte aus `190648ee09c0` ein `190648ee09c\u2026`; der Vertrag, der
    den gemessenen Digest in der Zeile sucht, fiel zu Recht.
    """
    return _einzeilig(wert, 10 ** 9)[:n]


def _drift_zeile(marker: str | None, erklaerung: Path | None = None) -> str:
    """DIE ZEILE SAGT NICHT MEHR, ALS SIE WEISS.

    'ran' war die erste Fassung fuer JEDEN abgelegten Marker — auch fuer einen, dessen Lauf gar
    nichts messen konnte. Gemessen 2026-09-16 ohne Token: der Marker trug `not-measurable`, die
    Zeile begann trotzdem mit 'ran at ...', und wer nur den Zeilenanfang liest, haelt die
    Drift-Pruefung fuer erledigt. Das ist dieselbe Verwechslung, gegen die dieses ganze Tor steht:
    GELAUFEN ist nicht GEMESSEN. Ein Lauf ohne Messung wird darum als NOT MEASURABLE gefuehrt und
    nennt die Zeit trotzdem, damit sichtbar bleibt, dass es einen Versuch gab.
    """
    lage = drift_lage(marker, erklaerung)
    # KEIN ROHER WERT IN DIE ZEILE. Jedes Feld kommt aus einer Datei, die jemand anders geschrieben
    # hat; roh gedruckt faelscht ein Zeilenumbruch darin ganze Berichtszeilen (siehe _einzeilig).
    zeit = _einzeilig(lage.get("at"), 64)
    satz = _einzeilig(lage.get("ruleset"), 64)
    if lage["state"] == "ran":
        v = _einzeilig(lage["verdict"], 48)
        grund = f" ({_einzeilig(lage['reason'])})" if lage.get("reason") else ""
        if v == ALWAYS:
            return (f"drift-check        checked at {zeit}: declaration matches the live "
                    f"ruleset {satz}{grund}")
        if v == UNKNOWN:
            return (f"drift-check        NOT MEASURABLE — a run at {zeit} could not "
                    f"reach the live ruleset{grund}")
        return (f"drift-check        DRIFT — checked at {zeit} against ruleset "
                f"{satz}: {v}{grund}")
    if lage["state"] == "stale":
        return (f"drift-check        STALE — a run at {zeit} said "
                f"{_einzeilig(lage.get('verdict'), 48)}, but {_einzeilig(lage['why'])}")
    if lage["state"] == "unreadable":
        return f"drift-check        NOT MEASURABLE — {_einzeilig(lage['why'])}"
    return ("drift-check        NOT RUN — this verdict rests on a declaration that may have "
            f"drifted from the live ruleset ({_einzeilig(lage['why'])})")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--declaration", type=Path, default=None)
    ap.add_argument("--workflows", type=Path, default=None)
    ap.add_argument("--verify-declaration", action="store_true",
                    help="NETWORK: hold the declaration against the live ruleset and report "
                         "drift. Not part of the offline gate; with no network the verdict is "
                         "not-measurable, never a pass.")
    ap.add_argument("--repo", default=None, help="owner/name for --verify-declaration")
    ap.add_argument("--drift-marker", default=".required-checks-drift.json",
                    help="where --verify-declaration puts its verdict and where the offline "
                         "run reads it. Empty means: no marker.")
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
        # DER MARKER. Eine Gegenlesung des gelandeten Standes hielt fest, dass das Offline-Tor
        # gruen melden kann, ohne zu wissen, OB die Drift-Pruefung ueberhaupt lief — und ein Urteil,
        # das nicht weiss, worauf es ruht, sagt mehr als es prueft. Der Netz-Lauf legt darum sein
        # Ergebnis ab, der Offline-Lauf liest es und NENNT es. Er blockt NICHT darauf: ein
        # fehlender Token oder ein totes Netz wuerden den beratenden Job sonst aus Umweltgruenden
        # rot faerben, also genau das Dauerrot herstellen, gegen das die Sohle gebaut ist. Gesagt
        # wird es trotzdem, weil eine Pruefung, die nicht lief, keine bestandene ist.
        if a.drift_marker:
            try:
                Path(a.drift_marker).write_text(json.dumps(
                    {"verdict": d["verdict"], "repo": d.get("repo"), "ruleset": d.get("ruleset"),
                     "reason": d.get("reason"), "at": _jetzt(),
                     # WORAUF SICH DAS URTEIL BEZIEHT. Ohne diesen Digest sagt der Marker nur, DASS
                     # einmal etwas geprueft wurde, nie WORAN — und ein Marker von gestern behauptet
                     # dann etwas ueber eine Erklaerung von heute. Gemessen 2026-09-16: ein Marker
                     # mit `at: 2020-01-01` meldete unveraendert "checked".
                     "declaration_sha256": _erklaerungs_digest(a.declaration)},
                    ensure_ascii=False), encoding="utf-8")
            except OSError as exc:
                print(f"  marker not written ({exc}) — the offline run will report it as NOT RUN")
        return 0 if d["verdict"] == ALWAYS else 1
    r = pruefe(a.declaration, a.workflows)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print(f"[required-checks] ruleset {_einzeilig(r.get('ruleset'), 64)} on "
              f"{_einzeilig(r.get('branch'), 64)}: {_einzeilig(r['verdict'], 32)}")
        for e in r.get("per_context", []):
            zeile = f"  {_einzeilig(e['state'], 18):18} {_einzeilig(e['context'], 80)}"
            if e.get("condition"):
                # Der Digest steht IM BERICHT, weil die Zusage genau ihn nennen muss. Es gibt
                # bewusst kein `--accept-current`: ein Ein-Befehl-Freibrief waere keine Sohle,
                # sondern eine Selbstsegnung. Wer zusagt, kopiert den Wert und traegt ihn ein.
                zeile += (f"   [{_kurz(e.get('condition_sha256', '?'), 16)}…] "
                          f"only if: {_einzeilig(e['condition'], 220)}")
            elif e.get("from"):
                zeile += f"   from {_einzeilig(e['from'], 80)}"
            print(zeile)
        print("  " + _drift_zeile(a.drift_marker, a.declaration))
        for g in r.get("changed_conditions", []):
            print(f"  condition-changed   {_einzeilig(g['context'], 80)}: "
                  f"declared {_kurz(g['declared'], 16)}…, measured {_kurz(g['measured'], 16)}… — "
                  f"the acceptance was made for a DIFFERENT condition, so it does not carry")
        for u in r.get("unbound_acceptances", []):
            print(f"  unbound-acceptance  {_einzeilig(u, 80)}: listed by name only, without "
                  f"condition_sha256 — a name alone cannot say WHICH state was accepted, so it "
                  f"does not carry")
        for g in r.get("changed_reasons", []):
            print(f"  reason-changed      {_einzeilig(g['context'], 80)}: "
                  f"declared {_kurz(g['declared'], 16)}…, measured {_kurz(g['measured'], 16)}… — "
                  f"the acceptance was made for a DIFFERENT limit, so it does not carry")
        for u in r.get("unbound_unreadable_acceptances", []):
            print(f"  unbound-limit       {_einzeilig(u, 80)}: listed by name only, without "
                  f"reason_sha256 — a prefix alone cannot say WHICH limit was accepted, so it "
                  f"does not carry")
        for h in r.get("dead_conditions", []):
            print(f"  dead-condition     {_einzeilig(h, 160)}")
        neu_u = set(r.get("newly_unreadable") or [])
        for u in r.get("unreadable", []):
            marke = "not-measurable" if u in neu_u else "known-limit   "
            # DER DIGEST DES GRUNDES STEHT IM BERICHT, genau wie der der Bedingung: wer eine
            # Unmessbarkeit hinnehmen will, muss SAGEN KOENNEN, welche. Ohne den Wert im Bericht
            # bliebe nur die Namensform, und die ist die Luecke, die hier gerade geschlossen wird.
            print(f"  {marke}     {_einzeilig(u, 200)}")
    if r.get("dead_conditions"):
        # A condition that can never take effect is a silent lie in the workflow, even when the
        # produced contexts happen to be right today.
        return 1
    # EINE VERSCHLECHTERUNG IST EINE VERSCHLECHTERUNG, AUCH WENN SONST ALLES LAEUFT. Diese drei
    # Zeilen standen frueher UNTER der Abkuerzung `verdict == ALWAYS`, und damit wirkten sie nur,
    # wenn ohnehin schon etwas bedingt war. Gemessen 2026-09-16 beim Schreiben des Falls fuer die
    # gebundene Grenz-Zusage: alle Pflichtkontexte unbedingt erzeugt, eine NEUE unmessbare Stelle
    # im Bericht, `reason-changed` gedruckt -- und exit 0. Die Erklaerung behauptete im selben
    # Atemzug "A NEW unmeasurable case still fails". Sie tat es nicht. Eine unmessbare Stelle kann
    # einen Pflichtkontext verdecken; das ist unabhaengig davon, wie die uebrigen dastehen.
    if (r.get("newly_unreadable") or r.get("unbound_acceptances")
            or r.get("unbound_unreadable_acceptances")):
        return 1
    if r["verdict"] == ALWAYS:
        return 0
    if r["verdict"] == GATED and a.allow_gated:
        return 0
    # THE RATCHET. An advisory job that is red from its first run teaches people to look away, and
    # a gate that is habitually stepped over checks nothing any more. The REPORT above still names
    # every conditional context together with its condition; only the exit code follows what the
    # declaration accepts today. It turns red as soon as things get WORSE: a context nobody
    # produces, something not measurable, or a NEWLY conditional one that is not declared.
    # `accepted_gated` is deliberately NOT tested again here. The first draft did test it, and it
    # was a dead condition: verdict GATED means at least one conditional context exists, so if
    # `newly_gated` is empty that context is in the list and the list cannot be empty. A condition
    # that can never decide anything makes mutants unkillable -- which is exactly what this tool
    # reports as `dead-condition` in other people's workflows. A mutant that pinned `newly_gated`
    # to empty survived the first contract because of it.
    # `unbound_unreadable_acceptances` steht hier aus demselben Grund wie `unbound_acceptances`:
    # eine Zusage in der alten Namensform ist keine Zusage, und wenn sie den Ausgang nicht
    # beruehrt, lebt die alte Form als stiller Freibrief weiter.
    if (r["verdict"] == GATED and not r.get("newly_gated")
            and not r.get("newly_unreadable") and not r.get("unbound_acceptances")
            and not r.get("unbound_unreadable_acceptances")):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
