#!/usr/bin/env python3
"""A pull request that carries a release-scope line names that line's identifier in its title.

WHY THIS GATE EXISTS. `docs/release_scope/<version>.md` maps each scope item to its own branch:
one identifier, one branch, one pull request. Without a gate that mapping is a promise in a
document — readable, and unenforced. The landing card counts what landed by reading identifiers
out of the pull-request titles on main, so a title without its identifier is not a cosmetic
omission: it makes the item invisible to the count that is supposed to track it.

Owner decision 2026-09-14: the title form is English, `[<version> <ID>] type(scope): subject`,
exactly one identifier per pull request.

WHAT THIS GATE DOES NOT DO, said plainly. It judges the BRANCH, not the diff. A pull request whose
head branch is named in the scope file must carry that line's identifier; a branch the scope file
does not name is not judged here at all, and is reported as such rather than as a pass. Deciding
"does this diff touch scope content" from the changed files would be a second, weaker oracle over
the same question, and a guess dressed as a measurement is worse than a stated limit.

THE RIDERS ARE AN EXCEPTION BY CONSTRUCTION, not by a hand-kept list. Scope lines whose branch
column says "mit X", "= X" or names no branch at all ride along with another item. They have no
branch of their own, so no pull request can ever match them, so they can never trigger this gate.
That is the same exception the order names, derived from the file instead of copied out of it —
a copied list is a second truth that ages the moment the file moves.

Exit: 0 green · 1 RED, with the reason. Never a third outcome: a gate that cannot measure and
says so quietly reads, in a pull-request check list, exactly like one that passed.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[1]

#: Ein Bezeichner der Umfangsdatei: Buchstabe, optionaler Punkt oder Strich, Ziffern, optional ein
#: Unterteil. Deckt A1, A5.1, B-3, N1-1a, N2-3a, S65-5, Z.278.
_KENNUNG = r"[A-Z]\.?-?\d+(?:[.\-][0-9a-z]+)*"

#: THE WHOLE TITLE FORM, anchored at both ends. The contract in the module docstring above reads
#: `[<version> <ID>] type(scope): subject`, exactly one identifier, at the start.
#:
#: UNTIL 2026-09-16 THIS WAS AN UNANCHORED `findall`, which asks a different question altogether,
#: namely whether a bracket of this version appears anywhere in the title. Measured at head
#: 1077c3d, three titles passed green: `WRONG PREFIX [6.1.0 N3-1] nonsense`, then
#: `irgendwas [6.1.0 N3-1]` with no subject form at all, and
#: `[6.1.0 N3-1] [6.0.1 R1] feat(scope): subject` carrying a second identifier of a FOREIGN
#: version, which went uncounted because only matches of the current version were counted. Three
#: titles, all green, none conforming. Codex round one raised it; it was re-measured here, and it
#: reaches further than reported, because the third form was not in the report.
#: THE SEPARATORS ARE PLAIN SPACES, not `\s`, and the title is ONE line. Both were measured on
#: the first version of this expression, by running it rather than by reading it.
#:
#: `\s` in Python matches U+00A0 and U+2009 as well, so `[6.1.0<narrow space>A1] feat(x): y`
#: passed. The landing card reads identifiers out of titles with its own reader, and two readers
#: that disagree about what a space is will disagree about which line landed. A separator that
#: looks like a space and is not one is exactly the kind of difference this gate exists to catch.
#:
#: And `\s` matches a newline, so `[6.1.0 A1] feat(x): y\nanything at all` passed as well:
#: the form bound the first line and said nothing about the rest. A pull-request title is one
#: line; whatever follows a line break was never judged, and a rule that stops at the first
#: newline judges a prefix while claiming to judge a title.
_TITELFORM = re.compile(
    rf"^\[ *(?P<version>[0-9]+(?:\.[0-9]+)*) +(?P<kennung>{_KENNUNG}) *\]"
    r" +(?P<typ>[a-z][a-z0-9]*)(?:\([^()]+\))?: +\S[^\r\n]*\Z")

#: EVERY identifier bracket in the title, whatever its version. The old expression counted only
#: the current one, so a second bracket of a foreign version stayed invisible, which is exactly the
#: ambiguity that "exactly one identifier" was written against.
_JEDE_KLAMMER = re.compile(rf"\[ *[0-9]+(?:\.[0-9]+)* +{_KENNUNG} *\]")

#: Wo der Umfang endet. Alles danach (Out, Begruendungen, Owner-Tueren) ist NICHT die Menge, gegen
#: die ein Pull Request geprueft wird — dort stehen Zeilen, die ausdruecklich nicht gebaut werden.
_ENDE_DES_UMFANGS = re.compile(r"^##\s+Out\b", re.M)


def lies_umfang(pfad: pathlib.Path) -> tuple[dict[str, list[str]], list[str], str]:
    """(Zweig -> LISTE der Kennungen, Mitlaeufer, Zustand). Nur der In-Abschnitt zaehlt.

    EINE LISTE, WEIL EINE ABBILDUNG IN BEIDE RICHTUNGEN VERLIEREN KANN. Die erste Fassung bildete
    Kennung -> Zweig ab und ueberschrieb still, sobald zwei Zeilen dieselbe Kennung anfuehren —
    und genau das tut der 6.1.0-Umfang dreimal (A1, A2, A3). Die zweite Fassung drehte die
    Richtung und verlor spiegelverkehrt, sobald zwei Zeilen denselben Zweig nennen. Beide Male
    war der Verlust STILL. Eine Liste verliert nichts, und die Mehrdeutigkeit wird zum Befund
    statt zur Abwesenheit. Beide Fassungen fand der eigene Vertrag, nicht das Lesen.

    ACHTUNG, EINE KENNUNG IDENTIFIZIERT KEINE ZEILE. Gemessen am 6.1.0-Umfang: A1, A2 und A3
    fuehren je ZWEI verschiedene Zeilen an, eine aus dem Sammelauftrag und eine aus RESTRISIKO_600,
    mit verschiedenem Gegenstand und verschiedenem Zweig. Die Rueckgabe hier bildet deshalb nur
    Zweig -> Kennung verlaesslich ab (Zweige sind eindeutig); die Gegenrichtung ist mehrdeutig und
    wird von `pruefe_umfangsdatei` als Befund ueber die DATEI gemeldet, nicht still ueberschrieben.

    Gibt drei Dinge zurueck, weil drei verschiedene Fragen daran haengen: welcher Zweig zu welchem
    Bezeichner gehoert, welche Zeilen gar keinen eigenen Zweig haben (und deshalb nie ein Pull
    Request sein koennen), und ob die Datei ueberhaupt lesbar war. Die dritte ist die wichtigste:
    eine leere Abbildung aus einer fehlenden Datei sieht aus wie eine leere Abbildung aus einem
    leeren Umfang, und die beiden bedeuten das Gegenteil voneinander.
    """
    try:
        text = pfad.read_text(encoding="utf-8")
    except OSError as e:
        return {}, [], f"NICHT MESSBAR: {type(e).__name__}: {e}"
    schnitt = _ENDE_DES_UMFANGS.search(text)
    if schnitt is None:
        # FAIL-CLOSED, und auch das fand die fremde Familie. Ohne die Marke galt vorher die GANZE
        # Datei als Umfang — samt der Zeilen unter "Out", die ausdruecklich NICHT gebaut werden.
        # Ein Riegel, der bei fehlender Struktur die Pruefmenge VERGROESSERT, urteilt danach ueber
        # Zeilen, die niemand bauen wollte, und nennt das eine Messung.
        return {}, [], ("NICHT MESSBAR: kein Abschnitt '## Out' gefunden — ohne ihn ist die Grenze "
                        "des Umfangs nicht bestimmbar, und die ganze Datei als Umfang zu lesen "
                        "waere eine Vergroesserung der Pruefmenge, keine Messung")
    im_umfang = text[: schnitt.start()]
    zu_zweig: dict[str, list[str]] = {}
    mitlaeufer: list[str] = []
    for zeile in im_umfang.splitlines():
        if not zeile.startswith("|") or zeile.count("|") < 3:
            continue
        spalten = [s.strip() for s in zeile.strip("|").split("|")]
        if len(spalten) < 2:
            continue
        punkt, zweig = spalten[0], spalten[-1]
        if set(zweig) <= set("-: ") or not punkt:
            continue
        m = re.match(rf"^\**({_KENNUNG})", punkt)
        if not m:
            continue
        kennung = m.group(1)
        if zweig.startswith("`") and zweig.endswith("`"):
            # ZWEIG -> KENNUNG, nicht umgekehrt. Die Gegenrichtung UEBERSCHREIBT still, sobald zwei
            # Zeilen dieselbe Kennung anfuehren, und genau das tut der 6.1.0-Umfang dreimal (A1, A2,
            # A3). Der erste Zweig verlor dabei seine Zuordnung und galt danach als "ausserhalb des
            # Umfangs" — ein Pull Request auf einer echten Umfangszeile waere ungeprueft
            # durchgelaufen. Gefunden vom eigenen Vertrag, nicht am Text.
            zu_zweig.setdefault(zweig.strip("`"), []).append(kennung)
        else:
            mitlaeufer.append(kennung)
    if not zu_zweig:
        return {}, mitlaeufer, "NICHT MESSBAR: kein einziger Zweig im In-Abschnitt gefunden"
    return zu_zweig, mitlaeufer, "gemessen"


def fuehrende_kennungen(pfad: pathlib.Path) -> tuple[list[tuple[str, str, str]], str]:
    """Jede In-Zeile als (Kennung, Punkt, Zweigspalte) — ZEILENWEISE, ohne Zusammenfassen.

    Die Zaehleinheit ist die ZEILE, nicht die Kennung und nicht der Zweig. Gemessen am 6.1.0-Umfang:
    55 Zeilen, 52 verschiedene fuehrende Kennungen, 44 eigene Zweige, 9 Mitlaeufer. Wer ueber
    Kennungen zaehlt, zaehlt drei Zeilen zu wenig; wer ueber Zweige zaehlt, elf.
    """
    try:
        text = pfad.read_text(encoding="utf-8")
    except OSError as e:
        return [], f"NICHT MESSBAR: {type(e).__name__}: {e}"
    schnitt = _ENDE_DES_UMFANGS.search(text)
    if schnitt is None:
        return [], ("NICHT MESSBAR: kein Abschnitt '## Out' gefunden — die Grenze des Umfangs ist "
                    "nicht bestimmbar")
    im_umfang = text[: schnitt.start()]
    aus: list[tuple[str, str, str]] = []
    for zeile in im_umfang.splitlines():
        if not zeile.startswith("|") or zeile.count("|") < 3:
            continue
        spalten = [s.strip() for s in zeile.strip("|").split("|")]
        if len(spalten) < 2 or set(spalten[-1]) <= set("-: ") or not spalten[0]:
            continue
        m = re.match(rf"^\**({_KENNUNG})", spalten[0])
        if m:
            aus.append((m.group(1), spalten[0], spalten[-1]))
    return aus, ("gemessen" if aus else "NICHT MESSBAR: keine Zeile im In-Abschnitt gefunden")


def pruefe_umfangsdatei(pfad: pathlib.Path) -> dict:
    """Die Datei selbst: fuehrt jede Kennung GENAU EINE Zeile an?

    Das ist eine Aussage ueber die DATEI, nicht ueber einen Pull Request, und sie gehoert getrennt:
    eine doppelt vergebene Kennung ist kein Fehler des Autors, der sie brav in seinen Titel
    schreibt — sie macht nur seinen Titel mehrdeutig. Die Landekarte zaehlt gelandete Zeilen aus
    Titeln; zwei Zeilen unter einer Kennung werden dort zu einer, und die andere verschwindet aus
    der Zahl, die ihr Landen belegen soll.
    """
    zeilen, zustand = fuehrende_kennungen(pfad)
    if zustand != "gemessen":
        return {"schema": "b7n0de.release_scope_datei.v1", "urteil": "ROT",
                "gruende": [f"Umfangsdatei {pfad} {zustand}"], "zeilen": 0,
                "kennungen": 0, "kollisionen": {}}
    von_kennung: dict[str, list[str]] = {}
    for k, punkt, _z in zeilen:
        von_kennung.setdefault(k, []).append(punkt[:60])
    kollisionen = {k: v for k, v in von_kennung.items() if len(v) > 1}
    gruende = [f"Kennung {k!r} fuehrt {len(v)} Zeilen an {v} — ein Titel [{'<version>'} {k}] "
               "zeigt damit auf mehr als eine Zeile, und die Landekarte zaehlt sie als eine"
               for k, v in sorted(kollisionen.items())]
    return {
        "schema": "b7n0de.release_scope_datei.v1",
        "urteil": "gruen" if not gruende else "ROT",
        "gruende": gruende,
        "zeilen": len(zeilen),
        "kennungen": len(von_kennung),
        "kollisionen": {k: v for k, v in sorted(kollisionen.items())},
    }


def pruefe(*, branch: str, title: str, version: str,
           scope_pfad: pathlib.Path | None = None) -> dict:
    """Das Urteil. Zweiwertig, und jedes ROT traegt seinen Grund."""
    pfad = scope_pfad or (REPO / "docs" / "release_scope" / f"{version}.md")
    zu_zweig, mitlaeufer, zustand = lies_umfang(pfad)
    gruende: list[str] = []
    if zustand != "gemessen":
        gruende.append(f"Umfangsdatei {pfad} {zustand} — ohne sie ist nicht messbar, ob dieser "
                       "Pull Request eine Umfangszeile traegt; Unkenntnis sperrt")
        return _urteil(branch, title, version, gruende, None, zu_zweig, mitlaeufer, zustand)

    passend = sorted(zu_zweig.get(branch) or [])
    if not passend:
        # KEIN PASS, SONDERN EINE ANGABE UEBER DIE REICHWEITE. Der Aufrufer soll sehen, dass hier
        # nichts geprueft wurde, statt ein gruenes Haekchen als Aussage ueber den Inhalt zu lesen.
        return _urteil(branch, title, version, [], None, zu_zweig, mitlaeufer, zustand,
                       ausserhalb=True)
    if len(passend) > 1:
        gruende.append(f"der Zweig {branch!r} steht bei MEHREREN Umfangszeilen {passend} — "
                       "ein Zweig je Zeile, sonst zaehlt die Landekarte ihn doppelt oder gar nicht")
        return _urteil(branch, title, version, gruende, None, zu_zweig, mitlaeufer, zustand)

    kennung = passend[0]
    # Eine Kollision ist ein Befund ueber die DATEI. Sie steht im Ergebnis, faellt dem Autor des
    # Pull Requests aber nicht zur Last: er kann nur die eine Kennung schreiben, die es gibt.
    datei_urteil = pruefe_umfangsdatei(pfad)
    kollision = kennung in (datei_urteil.get("kollisionen") or {})
    # THE WHOLE FORM, AT THE START, EXACTLY ONE IDENTIFIER, in that order, because each step is
    # what makes the next one meaningful. First, how many identifier brackets does the title carry
    # at all, whatever their version. Then, does the title as a WHOLE match the contract form. Only
    # then, does it name the right identifier.
    alle_klammern = _JEDE_KLAMMER.findall(title)
    if len(alle_klammern) > 1:
        gruende.append(f"der Titel nennt {len(alle_klammern)} Kennungen {alle_klammern} — genau "
                       "eine je Pull Request, sonst ist die Zuordnung zur Umfangszeile mehrdeutig. "
                       "Gezaehlt werden ALLE Versionen, nicht nur die eigene: eine zweite Klammer "
                       "fremder Version macht den Titel genauso mehrdeutig")
    form = _TITELFORM.match(title)
    if not form and not alle_klammern:
        # THE MOST COMMON CASE DESERVES ITS OWN SENTENCE. A title with no bracket at all and a
        # title with a bracket in the wrong place are two different jobs for whoever has to fix
        # them, and one shared shape message for both leaves the author guessing which one they
        # have. An existing case asserted exactly this wording and fell when the two were folded
        # together, and it was right to.
        gruende.append(f"der Titel nennt keine Umfangskennung: erwartet [{version} {kennung}] "
                       f"am Anfang, gelesen {title!r}")
    elif not form:
        gruende.append(
            f"der Titel haelt die Form nicht ein: erwartet [{version} {kennung}] "
            f"type(scope): subject AM ANFANG, gelesen {title!r}. Geprueft wird der ganze Titel, "
            "nicht ob die Klammer irgendwo vorkommt")
    else:
        if form.group("version") != version:
            gruende.append(f"der Titel nennt die Version {form.group('version')!r}, geprueft wird "
                           f"gegen {version!r} — Titel und Umfangsdatei zeigen auf verschiedene "
                           "Releases")
        elif form.group("kennung") != kennung:
            gruende.append(f"der Titel nennt [{version} {form.group('kennung')}], der Zweig "
                           f"{branch!r} gehoert aber zu {kennung} — Titel und Zweig zeigen auf "
                           "verschiedene Zeilen")
    if kollision:
        # ROT, und die fremde Modellfamilie hat mich hier umgestimmt (16.09.2026). Meine erste
        # Fassung liess so einen Pull Request gruen durch, mit einem Vermerk: der Autor koenne ja
        # nur die eine Kennung schreiben, die es gibt. Ihr Einwand traegt: der ZWECK dieses Riegels
        # ist die eindeutige Zaehlbarkeit, und ein Titel, den die Landekarte nicht zuordnen kann,
        # verfehlt ihn — gleich wem die Schuld gehoert. Gruen hiesse hier: der Pull Request ist in
        # Ordnung, obwohl sein Landen nicht zaehlbar ist. Und die Reparatur steht offen, sie ist
        # nur nicht im Titel: die Kennung in der Umfangsdatei aufteilen.
        zeilen = (pruefe_umfangsdatei(pfad).get("kollisionen") or {}).get(kennung, [])
        gruende.append(
            f"die Kennung {kennung!r} fuehrt {len(zeilen)} Zeilen der Umfangsdatei an {zeilen} — "
            "ein Titel mit ihr ist nicht zuordenbar, und die Landekarte zaehlt zwei Zeilen als "
            "eine. Zu tun ist es in der Umfangsdatei, nicht im Titel: die Kennung aufteilen")
    d = _urteil(branch, title, version, gruende, kennung, zu_zweig, mitlaeufer, zustand)
    d["kennung_mehrdeutig"] = kollision
    return d


def _urteil(branch, title, version, gruende, kennung, zu_zweig, mitlaeufer, zustand,
            *, ausserhalb: bool = False) -> dict:
    gruen = not gruende
    return {
        "schema": "b7n0de.release_scope_title_gate.v1",
        "version": version, "branch": branch, "title": title,
        "urteil": "gruen" if gruen else "ROT",
        "gruende": gruende,
        "kennung_des_zweigs": kennung,
        "ausserhalb_des_umfangs": ausserhalb,
        "umfang_zustand": zustand,
        "umfangszeilen_mit_zweig": len(zu_zweig),
        "mitlaeufer_ohne_zweig": sorted(mitlaeufer),
        # AUSDRUECKLICH OFFEN, damit niemand mehr hineinliest als dasteht.
        "geprueft_wird": "der head-Zweig gegen die Umfangsdatei, NICHT der Diff",
        "nicht_geprueft": ("ob ein Pull Request auf einem nicht genannten Zweig inhaltlich eine "
                           "Umfangszeile beruehrt — das entscheidet dieser Riegel nicht"),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--branch", required=True, help="der head-Zweig des Pull Requests")
    p.add_argument("--title", required=True, help="der Titel des Pull Requests")
    p.add_argument("--version", default="6.1.0")
    p.add_argument("--scope", default=None, help="Pfad der Umfangsdatei (sonst aus --version)")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    d = pruefe(branch=a.branch, title=a.title, version=a.version,
               scope_pfad=pathlib.Path(a.scope) if a.scope else None)
    if a.json:
        print(json.dumps(d, ensure_ascii=False, indent=2))
    else:
        marke = "ausserhalb des Umfangs" if d["ausserhalb_des_umfangs"] else (
            d["kennung_des_zweigs"] or "—")
        print(f"release-scope-title: {d['urteil']} · {d['branch']} · {marke}")
        for g in d["gruende"]:
            print(f"  ! {g}")
        print(f"  geprueft: {d['geprueft_wird']}")
    return 0 if d["urteil"] == "gruen" else 1


if __name__ == "__main__":
    raise SystemExit(main())
