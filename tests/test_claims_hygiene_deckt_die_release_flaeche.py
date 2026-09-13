"""Die Anspruchshygiene muss das Dokument scannen, in dem die Release-Behauptungen STEHEN.

HERKUNFT: Riegel-Sweep auf Owner-Auftrag, 2026-09-07. `_DEFAULT_DOCS` zaehlt 49 Pfade auf, die ein
Fremder liest — der RELEASE-BELEG war keiner davon; die Zeichenkette `audit_artifacts` kam im
ganzen Skript nicht vor. GEMESSEN: ein gepflanztes `production-ready` in
`audit_artifacts/600/README.md` liess das Tor bei `PASS · 49 docs scanned · 0 violation(s)`,
waehrend dasselbe Wort in einer Commit-Nachricht das Namensgate mit exit 1 rot machte.

Das Tor war nicht kaputt. Falsch war die VERWENDUNG seines PASS: es wurde im Release-Beleg als
Beleg ueber den Release-Text zitiert und sagt ueber die Datei, in der es zitiert wird, nichts.

DIE KLASSE, NICHT DIE DREI NAMEN (Owner: "beide als Klasse, nicht als Einzelfall"). Drei Pfade
nachzutragen haette denselben Fehler beim naechsten Release-Token wiederholt — ein kuenftiges
`audit_artifacts/610/README.md` waere wieder draussen gewesen. `release_flaeche_docs()` LEITET die
Menge ab: die Markdown-Dateien des hoechsten numerischen Tokens plus die `RESTRISIKO_*.md` der
Wurzel. Diese Datei haelt fest, dass die Ableitung die Flaeche wirklich trifft.
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _gate():
    spec = importlib.util.spec_from_file_location(
        "_chc_flaeche", REPO / "scripts" / "claims_hygiene_check.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def test_der_release_beleg_dieses_tokens_wird_gescannt():
    """DIE ZUSICHERUNG. Das Dokument, das die Release-Behauptungen traegt, ist in der Menge."""
    m = _gate()
    flaeche = m.release_flaeche_docs()
    assert flaeche, (
        "Die abgeleitete Release-Flaeche ist LEER. Dann prueft dieser Fall nichts, statt still zu "
        "bestehen — und die Anspruchshygiene liefe wieder nur ueber die getippte Liste.")
    belege = [r for r in flaeche if r.startswith("audit_artifacts/") and r.endswith("README.md")]
    assert belege, (
        f"Kein Release-Beleg in der abgeleiteten Flaeche: {flaeche}. Genau dieses Dokument war am "
        f"2026-09-07 ungescannt, waehrend sein PASS im Beleg selbst zitiert wurde.")


def test_die_risiko_register_der_wurzel_sind_in_der_flaeche():
    """Sie tragen Release-Aussagen (offene Punkte, Restrisiken) und gehoeren derselben Disziplin."""
    m = _gate()
    flaeche = m.release_flaeche_docs()
    vorhanden = sorted(q.name for q in REPO.glob("RESTRISIKO_*.md"))
    assert vorhanden, "Vorbedingung: der Baum traegt RESTRISIKO-Register"
    fehlend = [n for n in vorhanden if n not in flaeche]
    assert not fehlend, (
        f"Diese Risiko-Register liegen im Baum, aber nicht in der gescannten Flaeche: {fehlend}.")


def test_die_flaeche_folgt_dem_TOKEN_und_nicht_einem_getippten_namen():
    """DER KLASSEN-TEIL: die Ableitung nimmt das hoechste numerische Token, nicht '600'.

    ERSTE FASSUNG WAR SELBST DIE KLASSE, gegen die sie antrat. Sie durchsuchte den QUELLTEXT der
    Funktion nach den Zeichenketten ``isdigit`` und ``max(`` — also ihren WORTLAUT. Eine Linse
    ersetzte die Ableitung durch eine getippte Liste und legte zwei tote Zeilen
    ``"600".isdigit()`` und ``max([1, 2, 3])`` daneben: alle vier Faelle blieben gruen, gemessen
    0 von 4. Ein Riegel gegen "aufgezaehlt statt abgeleitet", den man mit zwei Attrappenzeilen
    aushebelt, prueft nichts.

    Diese Fassung prueft die WIRKUNG auf einem eigens gebauten Baum: ein hoeheres Token, das es im
    echten Repo nicht gibt, muss OHNE Codeaenderung in der Flaeche auftauchen. Eine Aufzaehlung
    kann das nicht — sie kennt nur die Namen, die jemand getippt hat.
    """
    m = _gate()
    with tempfile.TemporaryDirectory() as td:
        baum = Path(td)
        for token in ("600", "700"):
            ordner = baum / "audit_artifacts" / token
            ordner.mkdir(parents=True)
            (ordner / "README.md").write_text(f"# Beleg {token}\n", encoding="utf-8")
        (baum / "RESTRISIKO_700.md").write_text("# Restrisiko\n", encoding="utf-8")
        m.REPO = baum                       # die Funktion liest REPO zur Aufrufzeit
        flaeche = m.release_flaeche_docs()
    assert "audit_artifacts/700/README.md" in flaeche, (
        f"Ein NEUES, hoeheres Token faellt nicht von selbst in die Flaeche: {flaeche}. Genau das "
        f"ist der Unterschied zwischen einer Ableitung und einer Aufzaehlung — und der Grund, "
        f"warum `audit_artifacts/600/README.md` am 2026-09-07 ungescannt war.")
    assert "audit_artifacts/600/README.md" not in flaeche, (
        f"Das AELTERE Token wird mitgezogen: {flaeche}. Die Flaeche ist die des aktuellen Release.")
    assert "RESTRISIKO_700.md" in flaeche, (
        f"Das Risiko-Register der Wurzel fehlt in der Flaeche: {flaeche}.")


def test_die_ABLEITUNG_greift_auch_im_ECHTEN_baum():
    """Die Gegenprobe zum gebauten Baum: was synthetisch stimmt, muss hier auch stimmen."""
    m = _gate()
    tokens = [q.name for q in (REPO / "audit_artifacts").iterdir() if q.is_dir() and q.name.isdigit()]
    assert tokens, "Vorbedingung: es gibt nummerierte Release-Ordner"
    hoechstes = max(tokens, key=int)
    assert any(r.startswith(f"audit_artifacts/{hoechstes}/") for r in m.release_flaeche_docs()), (
        f"Das hoechste Token {hoechstes!r} ist nicht in der Flaeche — die Ableitung greift nicht.")


def test_ANTI_PARITAET_ein_HISTORISCHES_token_wird_NICHT_mitgescannt():
    """DIE KONTROLLE, und sie haelt eine bewusste Grenze fest.

    Ein erster Anlauf nahm `rglob("*.md")` ueber das ganze `audit_artifacts/` und zog historische
    Belege sowie den Klassen-Ledger mit herein: 89 statt 49 Dokumente, 9 Treffer — davon acht auf
    "append-only" in Saetzen, die die eigene ARBEITSWEISE beschreiben ("dieser Ledger ist
    append-only"), nicht eine Produktzusage. Die Regelmenge ist fuer Produktzusagen an einen
    Fremden gebaut. Sie auf ein Prozessprotokoll zu richten haette entweder die Regel aufgeweicht
    oder acht Fehlbefunde erzeugt; beides waere schlechter als eine praezise Menge.
    """
    m = _gate()
    flaeche = m.release_flaeche_docs()
    tokens = sorted((q.name for q in (REPO / "audit_artifacts").iterdir()
                     if q.is_dir() and q.name.isdigit()), key=int)
    if len(tokens) < 2:
        return  # nur ein Token im Baum — die Abgrenzung ist dann gegenstandslos, nicht verletzt
    aelteres = tokens[0]
    treffer = [r for r in flaeche if r.startswith(f"audit_artifacts/{aelteres}/")]
    assert not treffer, (
        f"Ein historisches Token ({aelteres}) wird mitgescannt: {treffer}. Die Flaeche ist die des "
        f"AKTUELLEN Release; alte Belege sind Protokoll und stehen unter anderer Disziplin.")
