"""Vertrag: die Reifegrad-Marken der obersten CLI-Ebene bleiben ABLEITBAR und gezaehlt.

WARUM ES DIESEN VERTRAG GIBT, und die Begruendung ist eine Messung an mir selbst.
Am 15.09.2026 wurde die Hilfeausgabe der obersten Ebene vermessen, um eine GRUPPIERTE
Hilfe vorzubereiten (Auftrag Z43). Der erste Zaehler suchte die Marke am ANFANG der
Beschreibung, in eckigen Klammern, und meldete *zwei* markierte Kommandos. Nach der
EIGENSCHAFT gemessen — "nennt sich experimentell", egal an welcher Stelle und in welcher
Klammer — sind es **vier**. Ein Vierfaches uebersehen, weil nach der Schreibweise gesucht
wurde statt nach der Eigenschaft.

Die Marke steht heute in DREI Schreibweisen: ``[EXPERIMENTAL v2.0]`` fuehrend,
``(EXPERIMENTAL)`` mitten im Satz, ``[PROPOSED]`` fuehrend. Sie ist Prosa, kein Feld.
Solange das so ist, ist jede Gruppierung eine Regex-Uebung mit genau dieser Fehlerklasse.

WAS DIESER VERTRAG LEISTET und was nicht. Er macht die Marke NICHT zu einem Feld — das
ist eine Aenderung an ``cli.py`` und gehoert in einen eigenen Zug. Er haelt die gemessene
Verteilung fest, damit eine Verschiebung AUFFAELLT statt still zu passieren: ein neues
Kommando ohne Marke, eine Marke in einer VIERTEN Schreibweise, ein experimentelles
Kommando, das stillschweigend stabil wird. Das ist die billige Haelfte des Klassenfixes,
und sie ist sofort zu haben.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

WURZEL = Path(__file__).resolve().parents[1]

#: Gemessen 15.09.2026 an origin/main 4aeebe38. Eine Abweichung ist kein Fehler dieses
#: Tests, sondern eine Aenderung an der CLI, die jemand bewusst mitziehen muss.
ERWARTET = {"EXPERIMENTAL": 4, "PROPOSED": 2, "unmarked": 13}
ERWARTETE_KOMMANDOS = 19


def _hilfe() -> str:
    r = subprocess.run(
        [sys.executable, "-m", "proofbundle.cli", "--help"],
        capture_output=True, text=True, cwd=WURZEL,
        env={"PYTHONPATH": str(WURZEL / "src"), "PATH": "/usr/bin:/bin", "HOME": "/tmp"},
    )
    assert r.returncode == 0, f"--help endete mit {r.returncode}: {r.stderr[:400]}"
    return r.stdout


def _kommandos(hilfe: str) -> dict[str, str]:
    """Name -> vollstaendige Beschreibung, Fortsetzungszeilen angehaengt.

    DIE FORTSETZUNGSZEILEN SIND DER PUNKT: argparse bricht lange Beschreibungen um, und
    eine Marke kann in der ZWEITEN Zeile stehen. Wer nur die erste liest, misst die
    Schreibweise des Umbruchs.
    """
    aus: dict[str, str] = {}
    akt: str | None = None
    for z in hilfe.split("\n"):
        m = re.match(r"^ {4}([a-z][a-z0-9-]*)\s{2,}(\S.*)$", z)
        if m:
            akt = m.group(1)
            aus[akt] = m.group(2)
        elif akt is not None and re.match(r"^ {20,}\S", z):
            aus[akt] += " " + z.strip()
        elif not z.strip() or z.startswith("options:"):
            akt = None
    return aus


def _reifegrad(beschreibung: str) -> str:
    """Nach der EIGENSCHAFT, nicht nach der Schreibweise — das ist der ganze Punkt."""
    if "EXPERIMENTAL" in beschreibung:
        return "EXPERIMENTAL"
    if "PROPOSED" in beschreibung:
        return "PROPOSED"
    return "unmarked"


def test_die_oberste_ebene_fuehrt_die_gemessene_zahl_an_kommandos() -> None:
    cmds = _kommandos(_hilfe())
    assert len(cmds) == ERWARTETE_KOMMANDOS, (
        f"{len(cmds)} Unterkommandos statt {ERWARTETE_KOMMANDOS}. Wer eines hinzufuegt oder "
        f"entfernt, zieht diese Zahl mit — sie steht in einem Messblatt und in einem Auftrag. "
        f"Gefunden: {sorted(cmds)}"
    )


def test_die_reifegrad_verteilung_bleibt_wie_gemessen() -> None:
    cmds = _kommandos(_hilfe())
    ist: dict[str, int] = {"EXPERIMENTAL": 0, "PROPOSED": 0, "unmarked": 0}
    wer: dict[str, list[str]] = {k: [] for k in ist}
    for name, b in cmds.items():
        g = _reifegrad(b)
        ist[g] += 1
        wer[g].append(name)
    assert ist == ERWARTET, (
        f"Die Reifegrad-Verteilung hat sich verschoben: {ist} statt {ERWARTET}.\n"
        f"EXPERIMENTAL: {sorted(wer['EXPERIMENTAL'])}\n"
        f"PROPOSED:     {sorted(wer['PROPOSED'])}\n"
        f"ohne Marke:   {sorted(wer['unmarked'])}\n"
        "Das ist kein Fehler dieses Tests. Entweder ist ein Kommando reifer geworden — dann "
        "gehoert die Zahl hier nachgezogen —, oder eine Marke ist in einer Schreibweise "
        "dazugekommen, die `_reifegrad` nicht als solche liest. Der zweite Fall ist der "
        "gefaehrliche: er sieht aus wie ein stabiles Kommando."
    )


def test_eine_marke_wird_auch_in_einer_fortsetzungszeile_gefunden() -> None:
    """Anti-Fall gegen den Fehler, der diesen Vertrag ausgeloest hat.

    Die Marke von `outcome` steht NICHT am Anfang, sondern in Klammern mitten im Satz —
    und bei `verify-enclave` fuehrend in eckigen Klammern. Ein Zaehler, der nur den Anfang
    liest, findet einen von beiden. Dieser Fall stellt sicher, dass `_reifegrad` beide
    sieht, und er faellt, wenn jemand die Erkennung auf ein Praefix verengt.
    """
    cmds = _kommandos(_hilfe())
    fuehrend = [n for n, b in cmds.items() if b.lstrip().startswith("[EXPERIMENTAL")]
    innen = [n for n, b in cmds.items()
             if "EXPERIMENTAL" in b and not b.lstrip().startswith("[EXPERIMENTAL")]
    assert fuehrend, "kein Kommando mit fuehrender EXPERIMENTAL-Marke — Vorzustand war 1"
    assert innen, (
        "kein Kommando mit EXPERIMENTAL-Marke INNERHALB der Beschreibung. Gemessen waren es "
        "drei (outcome, relation-statement, anchor). Faellt dieser Fall weg, verliert der "
        "Vertrag genau die Eigenschaft, fuer die er gebaut wurde."
    )


# ── ab hier: das Feld, und seine Bindung an die Prosa (15.09.2026, zweite Haelfte des Klassenfixes) ──
#
# Die Tests darueber messen die PROSA. Seit dem Umbau traegt ``cli.py`` den Reifegrad zusaetzlich als
# FELD (``MATURITY``). Zwei Aussagen ueber dieselbe Sache koennen auseinanderlaufen, und ein Feld,
# das niemand gegen die Wirklichkeit haelt, ist genau die Attrappe, gegen die dieser Vertrag
# ueberhaupt gebaut wurde. Die folgenden Faelle sind deshalb ZWEI LESER DERSELBEN QUELLE: der eine
# liest den gerenderten Hilfetext, der andere die Deklaration — und sie muessen sich einig sein.


def test_das_feld_kennt_genau_die_kommandos_die_die_hilfe_zeigt() -> None:
    from proofbundle.cli import MATURITY

    aus_hilfe = set(_kommandos(_hilfe()))
    aus_feld = set(MATURITY)
    assert aus_hilfe == aus_feld, (
        f"Hilfe und Feld nennen verschiedene Kommandos.\n"
        f"nur in der Hilfe: {sorted(aus_hilfe - aus_feld)}\n"
        f"nur im Feld:      {sorted(aus_feld - aus_hilfe)}\n"
        "Ein Kommando, das nur im Feld steht, ist eine Leiche; eines, das nur in der Hilfe "
        "steht, kommt an `_oberbefehl` vorbei und ist unklassifiziert."
    )


def test_das_feld_sagt_dasselbe_wie_die_prosa() -> None:
    """Die eigentliche Bindung: Deklaration gegen den TATSAECHLICH gerenderten Text.

    Nicht gegen eine zweite Kopie der Deklaration — das waere eine Zusicherung am
    Stellvertreter, und die faellt nie.
    """
    from proofbundle.cli import MATURITY

    abweichungen = []
    for name, beschreibung in _kommandos(_hilfe()).items():
        aus_prosa = _reifegrad(beschreibung)
        aus_feld = MATURITY.get(name)
        if aus_prosa != aus_feld:
            abweichungen.append(f"  {name}: Prosa sagt {aus_prosa!r}, Feld sagt {aus_feld!r}")
    assert not abweichungen, (
        "Feld und Hilfetext widersprechen sich:\n" + "\n".join(abweichungen) + "\n"
        "Entweder wurde ein Kommando reifer und nur an EINER der beiden Stellen nachgezogen, "
        "oder eine Marke steht in einer Schreibweise, die `_reifegrad` nicht liest. Beide Faelle "
        "sind der Grund, warum diese Bindung existiert."
    )


def test_die_verteilung_aus_dem_feld_ist_dieselbe_zahl_wie_aus_der_prosa() -> None:
    from collections import Counter

    from proofbundle.cli import MATURITY

    aus_feld = Counter(MATURITY.values())
    assert dict(aus_feld) == ERWARTET, (
        f"Die Verteilung AUS DEM FELD ist {dict(aus_feld)} statt {ERWARTET}. Die Prosa-Messung "
        "steht in einem eigenen Fall darueber; weichen die beiden verschieden ab, ist das die "
        "interessantere Meldung."
    )


def test_ein_kommando_ohne_erklaerten_reifegrad_wird_abgewiesen() -> None:
    """Fangnachweis fuer den Riegel selbst — er muss fallen KOENNEN.

    ``_oberbefehl`` soll ein unklassifiziertes Kommando LAUT abweisen. Ohne diesen Fall waere die
    Pflicht eine Behauptung im Docstring: niemand haette je gemessen, dass sie greift.
    """
    import argparse

    import pytest

    from proofbundle.cli import MaturityNotDeclaredError, _oberbefehl

    sub = argparse.ArgumentParser().add_subparsers()
    # EIGENER TYP, nicht KeyError. Die erste Fassung warf KeyError und wurde dafuer im grossen
    # never-raise-Boden gefangen — was zwei Gegenlesungen am 15.09.2026 durch Ausfuehren widerlegt
    # haben (siehe den Docstring der Ausnahme). Ein Entwicklerfehler bekommt seinen eigenen Namen
    # und seinen eigenen, engen Ausgang.
    with pytest.raises(MaturityNotDeclaredError) as exc:
        _oberbefehl(sub, "ein-kommando-das-niemand-erklaert-hat", help="x")
    assert "Reifegrad" in str(exc.value)

    # Gegenprobe, damit der Fall nicht aus dem falschen Grund gruen ist: ein ERKLAERTES
    # Kommando geht durch. Ohne diese Haelfte wuerde der Fall auch bestehen, wenn `_oberbefehl`
    # ausnahmslos jeden Namen abwiese.
    durch = _oberbefehl(sub, "demo", help="x")
    assert durch is not None


def test_die_reifegrad_pflicht_bricht_die_never_raise_regel_nicht(capsys) -> None:
    """Der Riegel darf die Bauart der Datei nicht verletzen, gegen die er gesetzt ist.

    ``cli.py`` ist durchgaengig darauf gebaut, NIE einen rohen Traceback zu zeigen — ``KeyError``
    steht sogar namentlich in ``_CLI_BACKSTOP_FAMILY``. Beim Einbau der Reifegrad-Pflicht wurde
    gemessen, dass ihr ``KeyError`` genau daran vorbeilief, weil ``build_parser()`` VOR dem ``try``
    stand. Dieser Fall haelt beides fest: die Pflicht greift, UND sie greift innerhalb des Bodens.

    Er faellt in beide Richtungen: ohne die Pflicht beendet ``verify --help`` den Lauf mit
    ``SystemExit(0)``, und wandert ``build_parser()`` wieder aus dem ``try``, entkommt der
    ``KeyError`` roh. Die Meldung wird mitgeprueft, damit die 2 nicht aus einem anderen Grund
    entsteht — eine nackte Zahl waere hier eine Zusicherung am Stellvertreter.
    """
    from proofbundle import cli

    echt = dict(cli.MATURITY)
    try:
        del cli.MATURITY["demo"]
        rc = cli.main(["verify", "--help"])
    finally:
        cli.MATURITY.clear()
        cli.MATURITY.update(echt)
    fehler = capsys.readouterr().err
    assert rc == 2, f"erwartet der dokumentierte Ausgang 2 fuer malformed input, bekam {rc}"
    assert "Reifegrad" in fehler, (
        f"der Ausgang 2 nennt den Grund nicht — er koennte aus einer ganz anderen Ecke kommen. "
        f"stderr war: {fehler[:300]!r}")


# ══ Nach der Gegenlesung (Linse 2, 15.09.2026): drei P1, alle durch Ausfuehren gemessen ══
#
# WAS DIE LINSE FAND, und sie hat in allen drei Punkten recht:
#
# B2 — die Faelle darueber binden nicht „jedes oberste Kommando", sondern „jedes Kommando, das die
#      80-Spalten-Hilfe ausdruckt". Zwei Ausgaenge daran vorbei wurden GEMESSEN gruen: ein
#      `sub.add_parser("x")` OHNE `help=` erscheint in der Hilfe nie (argparse legt gar keine
#      Pseudo-Aktion an), und ein Name ab 19 Zeichen sprengt die Spaltenbreite, worauf argparse die
#      Beschreibung auf die Folgezeile setzt und die Fortsetzungsregel sie an das VORHERIGE
#      Kommando klebt. Beide Male: 8 passed, Kommando aufrufbar, unklassifiziert.
# B3 — `_reifegrad` ist ein Substring-Test OHNE Verneinung. `"(no longer EXPERIMENTAL as of 3.9)"`
#      klassifiziert als EXPERIMENTAL. Gemessen 8 passed — und der Modul-Docstring oben nennt genau
#      diesen Fall („ein experimentelles Kommando, das stillschweigend stabil wird") als den, den
#      dieser Vertrag abfangen soll.
# B1 — wird die Prosa eines Tages AUS dem Feld gerendert (der naheliegendste Folgeumbau), ist die
#      Bindung eine Tautologie: ein Schreiber und sein Echo. Gemessen 8 passed, waehrend das Feld
#      log.
#
# DIE WURZEL IST EINE: der Vertrag las das BILD des Parsers. Die drei Faelle hier lesen statt dessen
# den PARSER und den QUELLTEXT — zwei Quellen, die keine Darstellung dazwischen haben.


def _oberste_choices() -> dict:
    """Die Kommandomenge aus dem PARSER, nicht aus seinem Bild.

    Unabhaengig von Terminalbreite, argparse-Version, Namenslaenge und davon, ob ein Kommando ein
    ``help=`` traegt. Genau das macht B2 und B4 wirkungslos.
    """
    import argparse as _ap

    from proofbundle.cli import build_parser

    parser = build_parser()
    for gruppe in parser._subparsers._group_actions:      # noqa: SLF001 — argparse hat keinen oeffentlichen Weg
        if isinstance(gruppe, _ap._SubParsersAction):     # noqa: SLF001
            return dict(gruppe.choices)
    raise AssertionError("kein Unterkommando-Container im Parser gefunden")


def test_das_feld_deckt_JEDES_kommando_des_parsers_auch_das_unsichtbare() -> None:
    """B2/B4: gegen den Parser, nicht gegen die Hilfeausgabe.

    Ein Kommando ohne ``help=`` und ein Kommando mit einem langen Namen sind in der gerenderten
    Hilfe nicht (oder falsch) sichtbar, im Parser aber sehr wohl vorhanden und aufrufbar.
    """
    aus_parser = set(_oberste_choices())
    from proofbundle.cli import MATURITY

    aus_feld = set(MATURITY)
    assert aus_parser == aus_feld, (
        f"Parser und Feld nennen verschiedene Kommandos.\n"
        f"nur im Parser: {sorted(aus_parser - aus_feld)}\n"
        f"nur im Feld:   {sorted(aus_feld - aus_parser)}\n"
        "Ein Kommando, das nur im Parser steht, ist AUFRUFBAR und unklassifiziert — auch wenn die "
        "Hilfeausgabe es nicht zeigt. Ein Kommando, das nur im Feld steht, existiert nicht mehr."
    )


#: Formen, in denen ein Hilfetext eine Marke VERNEINT oder historisiert. Ein Substring-Test liest
#: sie als Bejahung — genau die stille Fehlklassifikation, gegen die dieser Vertrag gebaut ist.
_VERNEINUNGEN = ("no longer ", "not ", "formerly ", "was ", "until ", "since ", "ceased ")


def test_kein_hilfetext_verneint_oder_historisiert_eine_marke() -> None:
    """B3: die Verneinung, die `_reifegrad` nicht sehen kann, wird hier LAUT.

    `_reifegrad` bleibt bewusst ein Substring-Test — er ist genau deshalb richtig, weil die Marke in
    drei Schreibweisen steht. Der Preis ist, dass er `"no longer EXPERIMENTAL"` als EXPERIMENTAL
    liest. Statt ihn zu verkomplizieren (und damit eine vierte Schreibweise zu erfinden, die niemand
    pflegt), wird der Fall hier SEPARAT sichtbar gemacht: taucht vor einer Marke eine Verneinung
    auf, ist die Klassifikation nicht mehr ableitbar und der Vertrag sagt das, statt zu raten.
    """
    treffer = []
    for name, beschreibung in _kommandos(_hilfe()).items():
        klein = beschreibung.lower()
        for marke in ("experimental", "proposed"):
            i = klein.find(marke)
            while i != -1:
                vorspann = klein[max(0, i - 24):i]
                for v in _VERNEINUNGEN:
                    if vorspann.endswith(v) or vorspann.endswith(v + "("):
                        treffer.append(f"  {name}: …{beschreibung[max(0, i-24):i+len(marke)]}…")
                        break
                i = klein.find(marke, i + 1)
    assert not treffer, (
        "Ein Hilfetext verneint oder historisiert eine Reifegrad-Marke:\n" + "\n".join(treffer) +
        "\nEin Substring-Test liest das als Bejahung. Wenn ein Kommando wirklich reifer geworden "
        "ist, gehoert die Marke ENTFERNT und das Feld nachgezogen — nicht negiert stehengelassen."
    )


def test_die_marke_steht_als_literal_im_quelltext_und_wird_nicht_aus_dem_feld_gerendert() -> None:
    """B1: gegen die Tautologie, bevor sie entstehen kann.

    Wuerde der Hilfetext eines Tages AUS `MATURITY` zusammengesetzt, pruefte jede Bindung zwischen
    Feld und Prosa nur noch den Schreiber gegen sein eigenes Echo. Dieser Fall liest die `help=`
    Argumente als LITERALE aus dem Quelltext: eine Marke, die dort nicht woertlich steht, ist
    generiert — und dann ist die Gegenprobe keine mehr.
    """
    import ast

    quelle = (WURZEL / "src" / "proofbundle" / "cli.py").read_text(encoding="utf-8")
    baum = ast.parse(quelle)
    literale: dict[str, str] = {}
    generiert: list[str] = []
    for knoten in ast.walk(baum):
        if not (isinstance(knoten, ast.Call) and isinstance(knoten.func, ast.Name)
                and knoten.func.id == "_oberbefehl"):
            continue
        if len(knoten.args) < 2 or not isinstance(knoten.args[1], ast.Constant):
            continue
        name = knoten.args[1].value
        for kw in knoten.keywords:
            if kw.arg != "help":
                continue
            try:
                literale[name] = ast.literal_eval(kw.value)
            except (ValueError, TypeError):
                generiert.append(f"  {name}: help= ist kein Literal ({type(kw.value).__name__})")
    assert not generiert, (
        "Ein Hilfetext wird berechnet statt geschrieben:\n" + "\n".join(generiert) +
        "\nSobald die Prosa aus dem Feld entsteht, ist jede Bindung zwischen beiden eine "
        "Tautologie — ein Schreiber und sein Echo."
    )
    from proofbundle.cli import MATURITY

    abweichungen = [
        f"  {n}: Quelltext-Literal sagt {_reifegrad(h)!r}, Feld sagt {MATURITY.get(n)!r}"
        for n, h in literale.items() if _reifegrad(h) != MATURITY.get(n)
    ]
    assert not abweichungen, (
        "Feld und QUELLTEXT widersprechen sich:\n" + "\n".join(abweichungen))
    assert len(literale) >= 15, (
        f"nur {len(literale)} help=-Literale gefunden — der AST-Leser greift nicht mehr. Ein "
        "Vertrag, der leer durchlaufen kann, ist keiner.")


def test_jedes_oberste_kommando_geht_wirklich_durch_die_pflicht() -> None:
    """F3 (Linse 1): die WEGFUEHRUNG, nicht nur die Menge.

    Gemessen 15.09.2026: dreht man 17 von 19 Aufrufstellen auf nacktes ``sub.add_parser`` zurueck
    und laesst ``MATURITY`` unangetastet, bleibt jeder andere Fall gruen und der Hilfe-Digest ueber
    alle 39 Flaechen unveraendert — voll gruen, Invariante verletzt. Der einzige Fangnachweis
    existierte per ZUFALL fuer genau ein Kommando, weil ein anderer Fall ``MATURITY["demo"]``
    waehlt.

    Dieser Fall zaehlt beide Seiten waehrend eines echten ``build_parser()``-Laufs: wie oft die
    Pflicht gerufen wurde, und wie oft der oberste Subparser ein Kommando angelegt hat. Sie muessen
    gleich sein.
    """
    import argparse
    from unittest import mock

    from proofbundle import cli

    durch_die_pflicht: list[str] = []
    echt_oberbefehl = cli._oberbefehl

    def zaehlend(sub, name, **kw):
        durch_die_pflicht.append(name)
        return echt_oberbefehl(sub, name, **kw)

    with mock.patch.object(cli, "_oberbefehl", zaehlend):
        parser = cli.build_parser()

    oberste = None
    for gruppe in parser._subparsers._group_actions:      # noqa: SLF001
        if isinstance(gruppe, argparse._SubParsersAction):  # noqa: SLF001
            oberste = set(gruppe.choices)
            break
    assert oberste is not None

    fehlen = oberste - set(durch_die_pflicht)
    assert not fehlen, (
        f"{len(fehlen)} oberste Kommando(s) sind an der Reifegrad-Pflicht vorbei angelegt worden: "
        f"{sorted(fehlen)}. Sie stehen zufaellig in MATURITY, aber nichts erzwingt das — der "
        "naechste Autor, der `sub.add_parser` direkt schreibt, faellt durch jede andere Pruefung "
        "hindurch. Die Pflicht ist der Weg, nicht die Liste."
    )
    assert len(durch_die_pflicht) == len(oberste), (
        f"Pflicht {len(durch_die_pflicht)}x gerufen, aber {len(oberste)} Kommandos im Parser — "
        "ein Aufruf hat kein Kommando erzeugt oder ein Kommando kam doppelt.")
