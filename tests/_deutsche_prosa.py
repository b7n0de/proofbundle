"""EIN Erzeuger fuer die Frage „steht hier deutsche Prosa?" — und genau deshalb ein eigenes Modul.

WARUM ES DIESE DATEI GIBT. Am 2026-09-12 entstand der erste Sprachpruefer des Repos in
``test_aussenflaeche_des_registers_ist_englisch.py``, mit einer sorgfaeltig erarbeiteten
Wortgrenze. Am 2026-09-16 brauchte ein zweiter Vertrag dieselbe Frage fuer die Ausgabe des
Erreichbarkeits-Tors, und der erste Entwurf schrieb sich eine EIGENE Wortliste — mit
Teilzeichenketten statt Wortgrenzen. Gemessen an dieser zweiten Liste: ``"und "`` traf
``"background "`` und ``"refund "``. Der erste Pruefer hatte genau dieses Problem schon geloest.

Zwei Listen fuer eine Frage sind kein Schoenheitsfehler: sie driften, und die schwaechere
entscheidet dort, wo sie steht. Deshalb steht die Liste jetzt einmal hier, und beide Vertraege
lesen sie.

DIE GRENZE SCHLIESST DEN UNTERSTRICH EIN, und das ist der ganze Trick. Mit ``(?<![0-9a-zA-Z])``
traf ``nicht`` in ``test_..._reicht_nicht_mehr`` — ein BEZEICHNER, keine Prosa. Unterstriche
gehoeren nicht zu ``[0-9a-zA-Z]``, also ist ``_nicht_`` fuer diese Grenze ein eigenes Wort.

DIE EHRLICHE GRENZE, aus der Gegenlesung uebernommen: eine Wortliste faengt bekannte Verstoesse
zuverlaessig, aber nicht jede unbekannte deutsche Wendung. Wer damit prueft, benennt seine
Reichweite und behauptet keine Sprachreinheit.
"""
from __future__ import annotations

import re

#: Haeufige deutsche FUNKTIONSWOERTER. Bewusst keine Fachwoerter und keine Namen: Funktionswoerter
#: kommen in jeder deutschen Prosa vor und fast nie in englischer.
FUNKTIONSWOERTER: tuple[str, ...] = (
    "aber", "auch", "damit", "dass", "der", "die", "das", "denn", "durch", "eine", "einen",
    "einer", "fuer", "ist", "sind", "kein", "keine", "nicht", "noch", "oder", "schon", "sondern",
    "ueber", "und", "weil", "werden", "wird", "wurde", "wurden",
    # ERWEITERT 2026-09-16, und zwar aus einem Fehlschlag: der Satz „seine Kontexte entstehen
    # unter keiner Bedingung" enthaelt KEIN einziges Wort der Liste darueber („keiner" ist nicht
    # „keine", die Wortgrenze trennt sie korrekt). Ein Mutant, der genau diesen Satz zurueckholte,
    # UEBERLEBTE. Eine Liste, die den gemessenen Fall nicht faengt, ist an dieser Stelle keine
    # Pruefung. Aufgenommen sind nur Woerter, die im Englischen NICHT als eigenes Wort vorkommen;
    # bewusst DRAUSSEN bleiben „was", „also", „man", „war", „an", „in", „so", „hat" und „will" -
    # jedes davon ist englisch und wuerde den Pruefer unbrauchbar machen.
    "sich", "seine", "seiner", "seinem", "seinen", "ihre", "ihrer", "ihrem", "ihren",
    "diese", "dieser", "diesem", "diesen", "dieses", "einem", "keinem", "keinen", "keiner",
    "dem", "den", "des", "zum", "zur", "beim", "vom", "aus", "auf", "mit", "nach", "vor",
    "unter", "ohne", "wenn", "dann", "hier", "nur", "immer", "muss", "kann", "soll", "darf",
    "sein", "waren", "hatte", "haben", "gibt", "steht", "laeuft", "heisst", "entstehen",
)

#: DIE GRENZE SCHLIESST DEN UNTERSTRICH EIN (siehe Modul-Docstring).
MUSTER = re.compile(
    r"(?<![0-9a-zA-Z_])(" + "|".join(FUNKTIONSWOERTER) + r")(?![0-9a-zA-Z_])", re.I)

#: Code in Backticks ist Zitat, keine Prosa.
CODESPANNE = re.compile(r"`[^`]*`")


def ohne_code(text: str) -> str:
    """Backtick-Spannen entfernen, damit zitierte Bezeichner nicht als Prosa zaehlen."""
    return CODESPANNE.sub(" ", text)


def treffer(text: str) -> list[str]:
    """Die gefundenen deutschen Funktionswoerter — leere Liste heisst: keiner aus der Liste."""
    return MUSTER.findall(ohne_code(text))
