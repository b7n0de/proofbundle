"""Eine Schranke gegen die LAENGE begrenzt nichts, solange der geschuetzte Durchlauf ueberlinear ist.

DIE KLASSE (deep gate 6.0.0, L2-600-01, P2 — die Instanz war ``renewal.verify_sequence``). Jede
Budget-Dimension existiert, um Kosten zu begrenzen. Sie begrenzt aber nur eine ZAHL an der Eingabe:
Eintraege, Knoten, Schritte, Bits. Was diese Zahl KOSTET, sagt sie nicht. Ist der geschuetzte
Durchlauf ueberlinear, dann liegt der teuerste zugelassene Fall beliebig weit ueber dem, was die
Schranke zu verhindern scheint — und der erste ABGEWIESENE Fall ist billig. Gemessen auf diesem Baum
vor dem Fix: ``renewal_ats_chain`` = 10.000 (die Pruefung ist ``value <= limit``, der groesste
ZUGELASSENE Wert ist also 10.000, nicht 9.999) kostete am Limit **59,5 s Rechenzeit** aus 1,26 MB
Eingabe, waehrend 10.001 Eintraege in **0,002 s** abgewiesen wurden. Die Schranke feuerte korrekt und
begrenzte nichts.

DIE ZUSICHERUNG, und sie gilt fuer JEDE Dimension, nicht fuer die eine, an der es auffiel:

1. Der groesste ZUGELASSENE Wert kostet weniger als die erklaerte Obergrenze (``GRENZE_S``).
2. Die drei Punkte um das Limit — L-1, L, L+1 — verhalten sich wie angekuendigt: L-1 und L
   zugelassen, L+1 abgewiesen. Genau dort sass der Sprung von 0,002 s auf 59,5 s.
3. Die Kostenkurve ueber die Verdopplungsreihe L/8, L/4, L/2, L ist nicht ueberlinear
   (Exponent <= ``EXPONENT_MAX``).
4. Auch KOMBINIERTE Achsen, jede an ihrem Limit, bleiben unter der Summe ihrer Obergrenzen.

WARUM RECHENZEIT UND NICHT UHRZEIT. ``resource.getrusage`` misst die Rechenzeit DIESES Prozesses.
Die Uhrzeit misst mit, was 23 andere Kerne gerade tun; auf einer Maschine unter Last waeren die
Zahlen unbrauchbar, und eine unbrauchbare Zahl in einer Zusicherung ist schlimmer als keine.

WARUM ZUSAETZLICH EINE ARBEITSZAEHLUNG. Auch Rechenzeit haengt an der Maschine. Wo der Durchlauf in
Python liegt, wird deshalb zusaetzlich die Zahl der Python-Aufrufe gezaehlt (``sys.setprofile``,
GC aus): eine deterministische, maschinenunabhaengige Groesse. Sie ist nicht ueberall aussagekraeftig
— wo die Arbeit in C liegt (JSON-Parser, Hash-Kern), bleibt sie flach. Genau das wird GEPRUEFT statt
angenommen: waechst die Zaehlung ueber die Reihe nicht mindestens um das Doppelte, gilt sie fuer diese
Dimension als UNEMPFINDLICH und wird nicht als Beleg benutzt. Der dritte Zustand wird berichtet, nicht
verschwiegen.

WARUM EINE RESERVE. Unter ``RESERVE_S`` liegt die Messung im Rauschen (Cache, Zuteilung, Last), und
ein Exponent aus Rauschen ist eine Fehlmeldung. Unterhalb der Reserve wird der Exponent deshalb
BERICHTET, aber er entscheidet nicht — die Obergrenze entscheidet immer. Beispiel aus der eigenen
Messung: ``int_bits`` hat eine quadratische Kurve (der Schiebe-Loop in ``root_from_inclusion``), kostet
am groessten zugelassenen Wert aber 0,0045 s. Bei rund 1/200 der Obergrenze kann die Form der Kurve
keine Ueberlastung mehr erzeugen; sie als Fund zu melden waere ein Fehlbefund.

WARUM DIE GRENZE 1,2 UND NICHT 1,05 IST — GEMESSEN, NICHT GESCHAETZT. Am 2026-09-05 wurde auf dieser
Maschine (Lastmittel 27 bei 24 Kernen, also unter voller Konkurrenz) der Zeit-Exponent der beiden
teuersten LINEAREN Dimensionen je 9 mal erhoben: ``renewal_ats_chain`` 0,960 bis 1,132,
``json_nodes`` 0,975 bis 1,097. Der schlechteste von 18 Werten war 1,132. 1,2 laesst diesem Rauschen
Platz und trennt trotzdem sauber von der gemessenen Kurve VOR dem Fix (1,99). Damit der Abstand
nicht von der Tagesform abhaengt, ist jeder Punkt der EXPONENTEN-Reihe zusaetzlich das MINIMUM aus
mehreren Laeufen (siehe ``_zeit_min``) — Rauschen addiert nur, also ist das Minimum der beste
Schaetzer der wahren KURVENFORM. Fuer die CPU-OBERGRENZE selbst gilt das NICHT (Review Runde 2, B4,
siehe ``_zeit_max``): ein Minimum ist der guenstigste Fall, nicht der schlimmste, und ein
DoS-Gate braucht die andere Richtung — deshalb entscheidet ``kosten_am_limit_max`` (Maximum aus
9 Laeufen), nicht ``kosten_am_limit`` (Minimum, weiter fuer die Kurvenform benutzt).

REFERENZUMGEBUNG (Review Runde 2, B4 — genannt, nicht nur im Kopf einmal erwaehnt). Farmer, 24 Kerne,
Linux 6.8.0-138, CPython 3.10.12. Zum Zeitpunkt dieser Nachbesserung (2026-09-05, ca. 22:5xZ) war die
Maschine SELBST GESAETTIGT: Lastmittel 1-Minute rund 10-24 bei 24 Kernen, ein Sprachmodellserver und
ein Erntehelfer belegten davon rund zwoelf Kerne dauerhaft. Genau deshalb ist Rechenzeit
(``resource.getrusage``, misst NUR diesen Prozess) und nicht Wanduhrzeit die Messgroesse, und genau
deshalb ist ein MAXIMUM/hohes Quantil ueber mehrere Laeufe (B4) und nicht das Minimum der richtige
Schaetzer fuer eine Obergrenze: das Minimum blendet Fremdlast weg, eine Obergrenze soll sie gerade
nicht wegblenden.

EHRLICHE GRENZE, ZWEI STUECK. (a) Gemessen wird EINE Maschine (Farmer, 24 Kerne, Python 3.10). Die
Zahlen sind Obergrenzen mit Reserve, kein Benchmark. Eine schnellere Maschine macht jede Zusicherung
hier nur sicherer; eine langsamere verschiebt alle Werte gleichmaessig, und die Obergrenze hat
ueberall mindestens Faktor 10 Luft — ausser im teuersten kombinierten Fall, der eigens benannt ist.
(b) Die Zusicherung ist EINDIMENSIONAL und kann es nicht anders sein: sie spricht ueber den groessten
ZUGELASSENEN Wert, und den gibt es nur, wo ein Limit steht. Eine Achse OHNE Limit faellt durch — und
genau so eine multiplizierte hier eine begrenzte, bis Review Runde 2 (B1): ``verify_sequence``s
``data_digests`` hatte keine Dimension, und 10.000 ATS (am Limit) mal 50.000 Datendigests kosteten
gemessen 15,9 s (nachgemessen 2026-09-05 unter aktueller Last: 16,2 s). Das ist jetzt GESCHLOSSEN —
``budget.data_digests`` = 2.000, gemessen als eigene Dimension unten UND als eigene KOMBINATION
gegen ``renewal_ats_chain`` an beiden Limits gleichzeitig (``KOMBIS``, ``renewal_ats_chain x
data_digests``) — nicht als spaeterer, von dieser Datei ausdruecklich ungedeckter Befund.
"""
from __future__ import annotations

import base64
import contextlib
import dataclasses
import gc
import hashlib
import json
import math
import os
import resource
import statistics
import sys
import pathlib
import tracemalloc

import pytest
from _pytest.outcomes import Skipped

import proofbundle as pb
from proofbundle import dsse, merkle, sdjwt
from proofbundle._strict_json import loads_strict
from proofbundle.budget import DEFAULT_BUDGET as B

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _lastdeckel import KOSTEN_JE_ELEMENT, gedeckelt  # noqa: E402 — LAUF12-L3: die drei Lastquellen aus B.data_digests waren ungedeckelt (Alias B, vom Riegel nicht gesehen)
from proofbundle.budget import VerificationBudget
from proofbundle.emit import generate_signer
from proofbundle.errors import ProofBundleError
from proofbundle.hashalg import HASH_REGISTRY
from proofbundle.renewal import ArchiveTimeStamp
from proofbundle.trust_pack import validate_trust_pack_predicate

# Die erklaerte Obergrenze: eine Sekunde Rechenzeit am groessten zugelassenen Wert EINER Dimension.
GRENZE_S = 1.0
# Der hoechste Exponent, den eine Kostenkurve haben darf. 1,0 ist linear; 1,2 laesst Messrauschen und
# einen log-Faktor zu. Vor dem Fix mass renewal_ats_chain 1,99.
EXPONENT_MAX = 1.2
# Unterhalb dieser Kosten entscheidet der Exponent nicht mehr (siehe Kopf). 1/50 der Obergrenze.
RESERVE_S = GRENZE_S / 50.0
# So viel muss die Arbeitszaehlung ueber die 8-fache Eingabe wachsen, um als empfindlich zu gelten.
ARBEIT_EMPFINDLICH = 2.0
# Jede benannte Dimension einer KOMBINATION muss mindestens so viel Prozent ihres eigenen Limits
# erreichen (Review Runde 2, B2) — sonst behauptet der Kombi-Test eine Grenzlast, die er gar nicht baut.
KOMBI_ERREICHT_MIN = 0.95
# Spitzenverbrauch (tracemalloc, Review Runde 2, B3): grosszuegige, gemessene Obergrenze. Der groesste
# hier beobachtete Einzelwert ist json_nodes mit ~14,1 MiB (200.000 kleine int-Objekte in einer Liste);
# 32 MiB laesst dem mehr als das Doppelte Luft und faengt trotzdem eine echte Speicher-Vervielfachung
# (siehe TestObergrenzeAmGroesstenZugelassenenWert.test_speicher_am_limit_unter_der_grenze und
# TestKombinierteAchsen.test_kombi_speicher_bleibt_unter_der_grenze).
SPEICHER_GRENZE_BYTES = 32 * 1024 * 1024

HEX32 = "aa" * 32

#: Die aktuellen Registry-Algorithmen, deterministisch geordnet — die Kennungen, die ein
#: Kettenanfang tragen kann, ohne dass der Hash-Resolver sie ablehnt.
_AKTUELLE_ALGS = sorted(n for n, s in HASH_REGISTRY.items() if s.status == "current")
# So oft wird ein billiger Punkt wiederholt; genommen wird das MINIMUM. Ein teurer Punkt braucht das
# nicht — bei 60 s Messwert aendert ein Cache-Miss nichts, und die Wiederholung kostete dort Minuten.
WIEDERHOLUNGEN = 3
WIEDERHOLEN_UNTER_S = 0.2
# CPU-OBERGRENZE (Review Runde 2, B4): eine FESTE Zahl Laeufe, dann das MAXIMUM — nicht das Minimum.
# Ein Minimum schaetzt die guenstigste Ausfuehrung; ein DoS-Gate muss die teuerste tolerierbare
# Ausfuehrung kennen. 9 Laeufe, weil das dieselbe Stichprobengroesse ist, mit der EXPONENT_MAX oben
# bereits kalibriert wurde (je 9 Laeufe je Dimension, siehe Kopf).
MAX_WIEDERHOLUNGEN = 9

# ── REFERENZLAST UND MASCHINENFAKTOR (Owner-Anordnung OA-0646ecdf70, 2026-09-07: „A, mit Deckel") ──
#
# WARUM. Die CPU-Obergrenze oben ist eine Zahl EINER Maschine. Am 2026-09-07 wurde `coverage` rot,
# weil `renewal_work` auf dem CI-Laeufer 3,096 s mass gegen eine Latte von 3,0 s — auf dem Farmer
# misst dieselbe Achse 1,44-1,56 s. Der Laeufer ist gleichmaessig rund doppelt so langsam
# (input_bytes 1,8x, json_nodes 2,1x, signatures 2,5x, data_digests 2,0x). Im GRUENEN Lauf des
# Vorgaengerkopfes stand die Achse bei 2,844 s, also bei 94,8 % der Latte: sie faehrt dort seit jeher
# am Rand und kippt an gewoehnlichem Laeufer-Rauschen. Der Modul-Kopf sagt genau das voraus — „die
# Obergrenze hat ueberall mindestens Faktor 10 Luft, AUSSER im teuersten kombinierten Fall, der eigens
# benannt ist" — und genau der ist gefallen. Eine Vorhersage, die recht behaelt und nichts bewirkt.
#
# WAS SICH AENDERT. Die Latte wird in REFERENZEINHEITEN ausgedrueckt statt in Sekunden: eine
# deterministische, CPU-gebundene Referenzlast wird IM SELBEN LAUF gemessen, und ihr Verhaeltnis zur
# aufgezeichneten Messung auf der Referenzmaschine ist der MASCHINENFAKTOR. Untergrenze 1,0 — eine
# SCHNELLERE Maschine darf die Latte nicht lockern, sie macht die Zusicherung nur strenger.
#
# WAS SICH NICHT AENDERT. Die maschinenUNABHAENGIGE Aussage steht weiterhin woanders: der Exponent
# der Kostenkurve (`EXPONENT_MAX`) und die Arbeitszaehlung sind von der Maschine unberuehrt, und sie
# tragen die eigentliche Behauptung „die Kosten wachsen nicht schneller als linear". Der Faktor
# skaliert nur die WANDUHR-Seite, nicht die Form.

def _referenzlast(n: int = 200_000) -> bytes:
    """Deterministisch, CPU-gebunden, hashlib — dasselbe Kostenprofil wie `renewal.verify_sequence`.

    Bewusst KEINE Messung an einer der geprueften Achsen: waere die Referenz eine davon, koennte eine
    echte Kostensteigerung dort den Faktor mit anheben und sich damit selbst verstecken.
    """
    h = b"\x00" * 64
    for _ in range(n):
        h = hashlib.sha256(h).digest()
    return h


#: Die NEUN Laeufe der Referenzlast auf der Referenzmaschine, gemessen 2026-09-07 (Farmer, 24 Kerne,
#: CPython 3.10.12, Maschine unter Last). Das ist eine AUFZEICHNUNG, keine Politik: sie sagt, was die
#: Referenzlast dort gekostet hat, nicht was sie kosten darf. Streuung max/min 1,046.
_REFERENZ_FARMER_S = (0.06699, 0.06704, 0.06717, 0.06719, 0.06781, 0.06877, 0.06907, 0.06909, 0.07009)

def _referenzlast_hashfrei(n: int = 615_000) -> int:
    """Die ANDERE Kostenfamilie: Ganzzahl-Arithmetik ohne hashlib, auf dieselbe Dauer kalibriert.

    WARUM ES SIE GIBT (fremdfamiliaere Gegenlesung des dritten Einfrier-Kopfes + eigene Nachrechnung,
    08.09.2026): `_referenzlast` ist eine reine sha256-Schleife, aber SECHS der zwoelf Achsen sind
    nicht hash-gebunden — JSON-Parsen, Grosszahl-Arithmetik. Der Faktor ist `hash_hier/hash_ref`,
    die Achse braucht `A_hier/A_ref`. Beide Richtungen sind moeglich: laeuft der Hash relativ
    LANGSAMER (eine Maschine ohne Hardware-SHA), ist die Latte fuer diese sechs Achsen zu locker —
    ein falsches GRUEN; laeuft er relativ schneller, wird sie zu eng.

    Die Linse hatte behauptet, ein falsches GRUEN sei ausgeschlossen 'weil der Faktor nur lockert'.
    Nachgerechnet stimmt das nicht: Hashfaktor 3,0 gegen einen echten Bedarf von 1,5 laesst die
    Latte dreifach zu locker.
    """
    s = 0
    x = 1
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        s += x % 97
    return s


#: Die NEUN Laeufe der hash-freien Referenzlast auf der Referenzmaschine, gemessen 2026-09-08
#: (Farmer, dieselbe Sitzung wie `_REFERENZ_FARMER_S`). AUFZEICHNUNG, keine Politik.
#: Streuung max/min 1,012 — enger als die der Hash-Last (1,046).
_REFERENZ_FARMER_HASHFREI_S = (0.06401, 0.06405, 0.06411, 0.06419, 0.06458,
                               0.06462, 0.06470, 0.06475, 0.06477)

_REFERENZ_HIER: list[float] = []
_REFERENZ_HIER_HASHFREI: list[float] = []


def _referenz_werte() -> list[float]:
    """Misst die Referenzlast `MAX_WIEDERHOLUNGEN` mal — bei JEDEM Aufruf — und gibt ALLES zurueck.

    FRUEHER stand hier `if not _REFERENZ_HIER:`, die Messung lief also genau einmal pro Prozess. Der
    Maschinenfaktor des ganzen Laufs hing damit am Zufallsmoment seines ERSTEN Aufrufs (P0 der
    zweiten Linse, 08.09.2026; nachgemessen: 1,2164 unter Last, danach eingefroren auf 1,2164, frisch
    1,0098). Das ist in beide Richtungen falsch — eine Lastspitze lockert die Latte fuer den Rest des
    Laufs, eine ruhige Minute verschaerft sie und erzeugt genau den falschen Rotlauf, gegen den die
    Anordnung OA-0646ecdf70 gebaut wurde.

    DER ERSTE VERSUCH HING DIE MESSUNGEN AN und nahm den Median ueber ALLE Messungen des Laufs. Zwei
    Gegenlesungen haben das unabhaengig voneinander widerlegt, und die Rechnung ist eindeutig:

    * DRIFT. `_maschinenfaktor()` wird einmal je Dimension gerufen, zwoelf Mal im Lauf. Die erste
      Dimension saehe 9 Werte, die zwoelfte 108 — verschiedene Achsen desselben Laufs wuerden an
      verschiedenen Latten gemessen, je nach ihrer Position in `DIMENSIONEN`.
    * MASKIERUNG, und die ist schlimmer. Ein Median braucht mehr als die Haelfte neuer Werte, um zu
      folgen; eine Verlangsamung ab Aufruf k wird erst ab etwa Aufruf 2k-1 sichtbar. Nachgerechnet
      fuer eine echte 5-fache Verlangsamung ab Aufruf 11 von 12: die angehaeufte Reihe meldet fuer
      BEIDE betroffenen Dimensionen den Faktor 1,000, die eigene Reihe je Aufruf sofort 5,000. Die
      Latte bliebe eng, waehrend die Maschine wirklich langsam ist — der falsche Rotlauf, gegen den
      OA-0646ecdf70 gebaut wurde, nur eine Ebene tiefer versteckt.

    DESHALB: jeder Aufruf misst frisch und ERSETZT die Reihe. Der Faktor beschreibt dann die
    Maschine in dem Zeitfenster, in dem die Kosten gemessen wurden, die er skaliert — Faktor und
    Gegenstand sind gepaart. Gegen die andere Gefahr, eine einzelne unruhige Messreihe, schuetzt
    nicht mehr die Glaettung ueber den Lauf, sondern `_faktor_spanne`: wenn die Streuung der Reihe das
    Verdikt ueberspannt, wird NICHT MESSBAR gemeldet statt geraten.

    Kosten, gemessen: 12 Aufrufe x 9 Messungen x ~0,068 s = +6,9 s auf 54,4 s (+12,7 %).
    """
    frisch = []
    for _ in range(MAX_WIEDERHOLUNGEN):
        t = _cpu()
        _referenzlast()
        frisch.append(_cpu() - t)
    _REFERENZ_HIER[:] = frisch     # ERSETZT, haeuft NICHT an — siehe Docstring
    return _REFERENZ_HIER


def _referenz_werte_hashfrei() -> list[float]:
    """Wie `_referenz_werte`, aber fuer die hash-freie Familie. Frisch je Aufruf, ERSETZT."""
    frisch = []
    for _ in range(MAX_WIEDERHOLUNGEN):
        t = _cpu()
        _referenzlast_hashfrei()
        frisch.append(_cpu() - t)
    _REFERENZ_HIER_HASHFREI[:] = frisch
    return _REFERENZ_HIER_HASHFREI


def _klammer_oder_fehler(werte: list[float] | None, ersatz) -> list[float]:
    """FEHLEND darf ersetzt werden, KAPUTT muss auffallen — und `or` unterscheidet die beiden nicht.

    FUND DER SIEBTEN LINSE (die FREMDE Modellfamilie, 08.09.2026). Vier Stellen dieser Datei
    schrieben `werte or ersatz`. Damit faellt eine LEERE Liste — eine kaputte Klammer — auf
    dieselbe stille Ersatzmessung zurueck wie ein fehlendes Argument. Gemessen: `_faktor_spanne([])`
    loeste EINE frische Messung aus und lieferte klaglos einen Faktor. Der kam dann aus einem
    ANDEREN Zeitfenster als die Kosten, die er skaliert — genau der schwerste Fund dieser Runde,
    eine Ebene tiefer und durch die Hintertuer.

    Sechs Linsen EINER Familie hatten die Datei gelesen und diese Stelle nicht gesehen. Das ist das
    Argument fuer ein gemischtes Panel, in einem Satz.
    """
    if werte is None:
        return list(ersatz())
    if not werte:
        raise ValueError(
            "die uebergebene Referenzklammer ist LEER. Das ist kein fehlender Wert, sondern ein "
            "kaputter: fehlend darf durch eine eigene Messung ersetzt werden, kaputt muss "
            "auffallen. Ein stiller Ersatz haette den Faktor aus einem anderen Zeitfenster geholt "
            "als die Kosten, die er skaliert.")
    return list(werte)


def _maschinenfaktor_hashfrei(werte: list[float] | None = None) -> float:
    """Derselbe Bau wie `_maschinenfaktor`, andere Kostenfamilie. Untergrenze 1,0.

    `werte` erlaubt es, eine SCHON GEMESSENE Reihe zu beurteilen statt frisch zu messen — gebraucht
    fuer die Klammer um die Kostenmessung, siehe `_maschinenfaktor`."""
    hier = statistics.median(_klammer_oder_fehler(werte, _referenz_werte_hashfrei))
    dort = statistics.median(_REFERENZ_FARMER_HASHFREI_S)
    return max(1.0, hier / dort)


def _maschinenfaktor(werte: list[float] | None = None) -> float:
    """Wie viel langsamer diese Maschine ist als die Referenzmaschine — UNTERGRENZE 1,0.

    Verglichen werden die MEDIANE beider Verteilungen, nicht die Maxima: ein einzelner Ausreisser auf
    einer der beiden Seiten soll die Latte weder lockern noch verschaerfen.

    `werte` erlaubt es, eine SCHON GEMESSENE Reihe zu beurteilen statt frisch zu messen. Das ist
    keine Bequemlichkeit, sondern die Reparatur des schwersten Fundes dieser Runde: der Faktor wurde
    NACH der teuren Kostenmessung erhoben, also in einem anderen Zeitfenster als die Kosten, die er
    skaliert. Faellt eine Lastspitze in genau dieses spaete Fenster, lockert sie die Latte, ohne dass
    die Kosten davon beruehrt waeren — und eine ECHTE Verteuerung passt lautlos darunter. Gemessen
    von einer Gegenlesung mit einer echten dreifachen Verteuerung von `renewal_work`: 2 von 5 Laeufen
    liessen sie durch, ohne dass eine der drei Abstinenzen feuerte.
    """
    hier = statistics.median(_klammer_oder_fehler(werte, _referenz_werte))
    dort = statistics.median(_REFERENZ_FARMER_S)
    return max(1.0, hier / dort)


def _faktor_spanne(werte: list[float] | None = None, *,
                   aufzeichnung: tuple[float, ...] = _REFERENZ_FARMER_S,
                   eigene: list[float] | None = None) -> tuple[float, float]:
    """Der Maschinenfaktor am SCHNELLSTEN und am LANGSAMSTEN Ende der eigenen Messreihe.

    ZWEI FAMILIEN, EINE RECHENVORSCHRIFT (Klassenfix, 08.09.2026, Fund einer Gegenlesung). Die
    hash-freie Familie hatte fuer Weg B eine HANDGESCHRIEBENE Kopie dieser Formel daneben stehen —
    `max(1.0, min(frei_klammer) / statistics.median(_REFERENZ_FARMER_HASHFREI_S))`. Die Linse hat
    nachgerechnet, dass eine vertauschte Referenzkonstante dort in JEDER Fixture dieser Datei
    unsichtbar bleibt: alle halten den hash-freien Messwert bei oder unter beiden Konstanten, und
    die Untergrenze `max(1.0, ...)` schluckt die Differenz strukturell. Nicht zufaellig — durch die
    Bauart der Fixtures. Eine Rechenvorschrift mit zwei Schreibern, von denen nur einer eine
    Symmetrie-Bindung hat, ist dieselbe Klasse wie ein Instrument mit zwei Schreibern.

    Deshalb nimmt diese Funktion jetzt die AUFZEICHNUNG als Parameter und wird von beiden Familien
    gerufen. `eigene` ist der Zwischenspeicher der jeweiligen Familie, damit der Rueckfall (noch gar
    nicht gemessen) dieselbe Reihe trifft wie der Median.

    Der Median beschreibt die Maschine gut, solange sie EINEN Zustand hat. Hat sie zwei — ein
    Fremdjob laeuft in fuenf von neun Messfenstern — liegt der Median im langsamen Gipfel, die Latte
    lockert sich um dessen Faktor, und niemand sieht es (die fremdfamiliaere Gegenlesung, 08.09.2026).

    Diese Spanne braucht keine getippte Schwelle fuer 'zu viel Streuung'. Sie beantwortet eine
    andere, schaerfere Frage: HAENGT DAS VERDIKT DAVON AB, WELCHES ENDE MAN NIMMT? Auf einer ruhigen
    Maschine ist das Band so schmal wie ihre Streuung (Referenzmaschine: 1,046), auf einer
    zweigipfligen so breit wie ihr Sprung. Beide Enden tragen dieselbe Untergrenze 1,0.
    """
    # NICHT `_referenz_werte()`: das wuerde eine ZWEITE Messreihe erzeugen, und die Spanne beschriebe
    # dann eine andere Reihe als der Median, den sie einrahmen soll. Sie muss dieselbe Reihe lesen.
    # Erst wenn noch gar nicht gemessen wurde, wird gemessen. (Gemessen: die zweite Reihe kostete
    # 6,4 s zusaetzlich, ohne eine einzige zusaetzliche Aussage zu tragen.)
    if eigene is None:
        eigene = _REFERENZ_HIER
    # FEHLEND vs. KAPUTT, siehe `_klammer_oder_fehler`: `werte or ...` machte aus einer leeren
    # Klammer stillschweigend eine frische Messung. `eigene` bleibt der gewoehnliche Rueckfall
    # (dort ist leer ein legitimer Anfangszustand, kein Bruch).
    werte = _klammer_oder_fehler(werte, lambda: eigene or _referenz_werte())
    dort = statistics.median(aufzeichnung)
    return max(1.0, min(werte) / dort), max(1.0, max(werte) / dort)


def _faktor_spanne_hashfrei(werte: list[float] | None = None) -> tuple[float, float]:
    """Dieselbe Rechnung, andere Kostenfamilie — ein AUFRUF, keine zweite Formel.

    Existiert, weil die Alternative (die Formel ein zweites Mal hinschreiben) am 08.09.2026
    nachweislich unpruefbar war: keine Fixture der Datei konnte eine vertauschte Referenzkonstante
    sichtbar machen. Ein Aufruf kann das Falsche tun; zwei Formeln koennen AUSEINANDERLAUFEN, und
    das faengt kein Test, der nur eine von beiden kennt."""
    return _faktor_spanne(werte, aufzeichnung=_REFERENZ_FARMER_HASHFREI_S,
                          eigene=_REFERENZ_HIER_HASHFREI)


#: DIE KOSTEN JEDER ACHSE AN IHREM LIMIT auf der Referenzmaschine, gemessen 2026-09-08 in einem
#: RUHIGEN Lauf (Farmer, Spalte `CPU@L(max9)` der Dimensionstabelle). AUFZEICHNUNG, keine Politik.
#:
#: WARUM DER DECKEL SIE BRAUCHT statt der Messung des laufenden Tests — der schwerste Fund dieser
#: Runde: die Kopffreiheit aus dem LAUFENDEN Lauf faellt, sobald die Maschine langsamer wird,
#: waehrend der Maschinenfaktor gleichzeitig steigt. Beide laufen aufeinander zu, und
#: `faktor > deckel` wird genau dann wahr, wenn die Maschine belastet ist — also in der Lage, fuer
#: die die Kalibrierung gebaut wurde. Gemessen am Kopf 88a5383: in CI abstinierten daraufhin ALLE
#: ZWOELF Dimensionen (Skip-Delta +12, Zeichenpositionen 745-756 gegen --collect-only), und
#: `coverage` wurde gruen, weil der einzige zuvor rote Test sich aus der Bewertung herausgezogen
#: hatte. Eigene Lastprobe: Deckel 19,54 in Ruhe gegen 1,30 unter zwoelf Fremdlast-Schleifen,
#: waehrend der Faktor von 1,0 auf 2,4 stieg.
_REFERENZ_FARMER_KOSTEN = {
    "input_bytes": 0.0054, "json_nodes": 0.0653, "json_depth": 0.0000, "string_len": 0.0006,
    "signatures": 0.0017, "merkle_path": 0.0002, "disclosures": 0.0032,
    "renewal_ats_chain": 0.1258, "witnesses": 0.0008, "int_bits": 0.0023,
    "data_digests": 0.0007, "renewal_work": 1.5587,
}

#: ENTSCHIEDENE OWNER-KARTE `OA-133b901337` (gestellt und beantwortet 08.09.2026): **schnellstes_ende**,
#: „gilt auf der Referenzmaschine, CI ist nach der zweiten Antwort ausgenommen".
#:
#: Die zweite Antwort ist `OA-dc37e26295` — die Referenzmaschinen-Bindung unten. Die beiden gehoeren
#: zusammen und sind in EINEM Zug gelandet: Weg B allein wuerde auf jedem Laeufer falsche Rotlaeufe
#: erzeugen, und die Bindung allein liesse die Latte am Median stehen. Getrennt gaebe es einen
#: Zwischenstand, in dem genau das passiert, wogegen beide Karten gestellt wurden.
#:
#: Wechselt die Maschine WAEHREND der Messung ihren Zustand, spannt die Klammer auf, und es gibt
#: zwei ehrliche Antworten — aber nur eine kann gelten:
#:
#:   "median"          Weg A: die Latte steht am Median der Klammer. Kippt das Verdikt zwischen den
#:                     Enden, meldet die Streuungs-Abstinenz NICHT MESSBAR. Kein stiller Pass, aber
#:                     auch kein Rot. SO IST ES GEMESSEN (Vollsuite 3897 passed / 24 skipped).
#:   "schnellstes_ende" Weg B: die Latte steht immer am SCHNELLEN Ende. Erfuellt OA-0646ecdf70
#:                     woertlich ("eine echte Kostensteigerung bleibt trotz Faktor rot"), verschaerft
#:                     die Latte aber auf JEDER Maschine um die Streuung der Referenzlast
#:                     (Referenzmaschine 1,046, also rund 4,6 %) — und auf DIESEM Host, wo neun
#:                     pytest-Prozesse aus drei Quellen gemessen wurden, erzeugt das regelmaessig
#:                     falsche Rotlaeufe (Befund 600-MESSFELD-NICHT-RUHIG-HERSTELLBAR-01).
#:
#: Der Schalter steht hier, damit die Entscheidung EIN WORT kostet und keine Umbaurunde — und der
#: Weg "median" BLEIBT deshalb im Code, obwohl er seit dem Entscheid nicht mehr gefahren wird: er ist
#: die Stellung, in die der Owner in einem Wort zurueckkehren kann, nicht toter Code. Gebunden sind
#: beide Wege (`test_der_schalter_..._wirkt_wirklich`, verlangt UNTERSCHIEDLICHE Ausgaenge) UND der
#: geltende Stand (`test_die_OWNER_ENTSCHEIDUNG_zur_latte_steht_im_schalter`). Das sind zwei
#: verschiedene Aussagen: die erste, dass die Wahl etwas entscheidet; die zweite, wie sie ausfiel.
LATTE_AUS_DER_KLAMMER = "schnellstes_ende"

#: WELCHE Achsen zum letzten Deckel beigetragen haben. Instrument, kein Zustand — und es existiert
#: wegen eines Fundes der fremdfamiliaeren Gegenlesung (08.09.2026): der Schutz `if k <= 0: continue`
#: war in seiner WIRKUNG ungebunden. Die Linse ersetzte `k` durch `k or 0.0001`; damit greift der
#: Schutz nie mehr, und ALLE 19 Faelle blieben gruen. Ich hatte das Gegenteil angesagt und lag falsch.
#: Der Grund: eine Null wird durch epsilon zu einer RIESIGEN Kopffreiheit, und die setzt den Deckel
#: ohnehin nicht — 'uebersprungen' und 'mit riesiger Freiheit dabei' sind am Ergebnis nicht zu
#: unterscheiden. Nur die TEILNEHMERLISTE unterscheidet sie.
_DECKEL_BEITRAEGE: list[str] = []

#: WEM die Teilnehmerliste oben gehoert — der `ausser`-Wert des Aufrufs, der sie gefuellt hat, und
#: `None`, sobald sie GELESEN wurde. Eine Liste, die ihren Leser nicht kennt, ist kein Instrument,
#: sondern ein Rest.
#:
#: GEMESSEN 08.09.2026, und zwar an einem Fall, der aus einem ganz anderen Grund fiel: die
#: Referenzmaschinen-Bindung springt VOR `_faktor_deckel`, also rechnet auf einem Bauhost niemand
#: mehr den Deckel — und `test_die_KOMBI_latte_kennt_die_maschine_auf_der_sie_urteilt` las danach
#: die Liste eines FREMDEN Aufrufs (`ausser="renewal_work"` statt `ausser=""`) und urteilte darueber.
#: Der Fall fiel, aber mit einer Meldung ueber eine fehlende Achse statt ueber die fehlende Rechnung.
#: Waere die fremde Liste zufaellig die richtige gewesen, waere er gruen geblieben — und haette eine
#: Rechnung bezeugt, die nie stattgefunden hat.
_DECKEL_FUER: list = [None]


def _deckel_beitraege(ausser: str) -> list[str]:
    """Die Teilnehmerliste — nur, wenn sie aus dem EIGENEN Aufruf stammt.

    Einmalig: nach dem Lesen ist die Liste wieder herrenlos. Sonst koennte ein zweiter Leser
    dieselbe Rechnung ein zweites Mal als seine ausgeben, und genau das ist die Form, in der ein
    veralteter Wert unauffaellig bleibt.
    """
    assert _DECKEL_FUER[0] == ausser, (
        f"Die Teilnehmerliste des Deckels gehoert zu ausser={_DECKEL_FUER[0]!r}, gelesen wird sie "
        f"fuer ausser={ausser!r}. Entweder hat der eigene Aufruf gar nicht gerechnet — etwa weil "
        f"eine Abstinenz vorher gesprungen ist —, oder ein fremder Aufruf hat dazwischen "
        f"geschrieben. In beiden Faellen beschreibt die Liste eine andere Rechnung als die, ueber "
        f"die hier geurteilt wird.")
    _DECKEL_FUER[0] = None
    return list(_DECKEL_BEITRAEGE)


def _faktor_deckel(ausser: str) -> float:
    """DER DECKEL, ABGELEITET — keine getippte Zahl (Owner-Anordnung: „aus der Verteilung der Laeufe").

    Er beantwortet: wie weit darf die Latte ueberhaupt gedehnt werden, bevor die Aussage aufhoert,
    etwas zu heissen? Die Antwort steht in DIESEM Lauf: jede ANDERE Dimension hat eine gemessene
    Kopffreiheit (ihre eigene Latte geteilt durch ihre gemessenen Kosten). Die KLEINSTE davon ist die
    Dehnung, bei der als naechstes eine andere Achse reisst. Wird der Faktor groesser als das, ist
    nicht mehr die Maschine langsam, sondern das Kostenmodell falsch — und dann ist die Messung nicht
    mehr aussagekraeftig, egal in welche Richtung.

    Die Achse unter Test bleibt ausgenommen: ihre eigene Kopffreiheit darf ihre eigene Latte nicht
    bestimmen, sonst waere der Deckel zirkulaer.
    """
    freiheiten = []
    _DECKEL_BEITRAEGE.clear()
    _DECKEL_FUER[0] = ausser
    for d in DIMENSIONEN:
        if d.name == ausser:
            continue
        k = _REFERENZ_FARMER_KOSTEN.get(d.name, 0.0)
        if k <= 0:
            continue
        frei = (d.achsen * GRENZE_S) / k
        # EINE ACHSE UNTER 1,0 IST SELBST SCHON UEBER IHRER LATTE und meldet das in ihrem eigenen
        # Fall. Sie darf keinen Deckel fuer die anderen setzen — sonst bringt EINE kaputte Achse alle
        # anderen zum Schweigen. GEMESSEN im Fangnachweis vom 2026-09-08: eine 17-fache
        # Kostensteigerung in `renewal_work` drueckte dessen Kopffreiheit auf 0,124, und die uebrigen
        # ELF Faelle meldeten daraufhin NICHT MESSBAR statt zu messen. Der Schuldige wurde trotzdem
        # rot (sein eigener Deckel schliesst ihn ja aus) — aber elf stumme Achsen sind ein lauter
        # Ausfall, und er stand so in keiner Ansage.
        if frei >= 1.0:
            freiheiten.append(frei)
            _DECKEL_BEITRAEGE.append(d.name)
    if freiheiten:
        return min(freiheiten)
    # LEERE LISTE HEISST: JEDE andere Achse liegt ueber ihrer eigenen Latte. Das ist der lauteste
    # Befund, den dieser Test haben kann — und der Rueckfallwert 1,0 haette ihn in Stille verwandelt,
    # weil jede Maschine mit einem Faktor ueber 1,0 dann NICHT MESSBAR meldet. Benannt von der
    # fremdfamiliaeren Gegenlesung (2026-09-08) als Kehrseite des Filters darueber: "zwoelf Stille
    # statt zwoelf Rot". Ein unendlicher Deckel laesst die Zusicherung stattdessen SPRECHEN — sie
    # faellt dann an der Latte, wo sie fallen soll.
    return float("inf")



#: Merkmale eines automatisierten Bau-/Pruefhosts. WORTGLEICH mit `_BAUHOST_MERKMALE` in
#: `scripts/pre_tag_receipt.py` — und das ist kein Zufall, sondern gebunden
#: (`test_das_bauhost_vokabular_ist_dasselbe_wie_im_signierweg`). Zwei Stellen, die dasselbe
#: wissen, ohne dass etwas ihre Gleichheit prueft, laufen auseinander, und keiner der beiden
#: Tests sieht es: jeder importiert genau eine der beiden Fassungen.
_BAUHOST_MERKMALE = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "JENKINS_URL")


def _bauhost() -> str:
    """Die gesetzte Bauhost-Marke, oder `""` auf einer Maschine ohne.

    ANWESENHEIT, NICHT WAHRHEITSWERT — und das war der erste Anlauf falsch (ausgefuehrt von einer
    Gegenlesung am 08.09.2026, in BEIDE Richtungen):

    * `os.environ.get(n)` ist eine Wahrheitspruefung. Ein GESETZTES `CI=""` — das Muster, das
      entsteht, wenn ein Docker-Basisimage `ENV CI=` traegt oder ein Skript eine Marke mit
      `export CI=` statt `unset CI` "loescht" — ist falsy. Der Bauhost waere NICHT erkannt worden,
      die Achse haette dort geurteilt, und der falsche Rotlauf waere genau zurueckgekehrt.
    * Umgekehrt sind `"false"` und `"0"` nicht-leere Strings und damit truthy. `CI=false` ist ein
      verbreitetes Muster aus der JS-Werkzeugwelt und landet in gemeinsam benutzten Shells.

    Eine Marke IST das Signal; ihr Wert ist keiner. Deshalb `in os.environ`. Die verbleibende
    Kante — `CI=false` auf einer Maschine, die keine CI ist, schaltet die Achse stumm — ist
    stromabwaerts gefangen und nicht offen: `scripts/budget_axis_measurement.py` weigert sich,
    einen Lauf mit IRGENDEINER gesetzten Marke als Referenzmessung auszugeben
    (`ist_referenzmessung`, `ok`), und die Freigabe-Pruefliste verlangt genau dieses Feld.

    EHRLICHE GRENZE, und sie steht hier statt in einer Zusage: das ist ein MERKMAL, kein
    Maschinen-Fingerabdruck. Ein Laeufer, der keine dieser Marken setzt, wird wie die
    Referenzmaschine behandelt und urteilt — das ist gewollt (die Alternative waere, jede
    unbekannte Maschine stumm zu schalten, und ein stummer Riegel ist von einem bestandenen nicht
    zu unterscheiden), aber es ist eine Annahme ueber die Umgebung und keine Messung.
    """
    for n in _BAUHOST_MERKMALE:
        if n in os.environ:
            return n
    return ""


@contextlib.contextmanager
def _bauhost_marke(marke: str | None):
    """Setzt GENAU EINE Bauhost-Marke — oder KEINE — fuer die Dauer des Blocks.

    JEDER Fall, der die echte Testmethode ruft, MUSS hier hindurch. Sonst haengt sein Ausgang an
    der Umgebung, in der die Suite zufaellig laeuft: mit gesetzter Marke wuerde die
    Referenzmaschinen-Bindung VOR seiner Zusicherung greifen, und der Fangnachweis meldete einen
    sauber aussehenden SKIP statt des Fundes, den er sucht. Dieselbe Klasse wie die
    Streuungs-Abstinenz gegenueber dem Schalter: eine Abstinenz, die die Frage des Falles per
    Regel beantwortet, muss fuer diesen Fall abgeschaltet sein.
    """
    alt = {n: os.environ.get(n) for n in _BAUHOST_MERKMALE}
    for n in _BAUHOST_MERKMALE:
        os.environ.pop(n, None)
    if marke:
        os.environ[marke] = "true"
    try:
        yield
    finally:
        for n, wert in alt.items():
            if wert is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = wert



def _referenzmaschinen_bindung(was: str, faktor: float) -> None:
    """OWNER-ENTSCHEID `OA-dc37e26295` (08.09.2026): „C, mit Bedingung."

    Wortlaut: „Budget-Achse referenzmaschinengebunden kennzeichnen, in CI sichtbar ueberspringen
    mit dem gemessenen Maschinenfaktor als Grund, auf der Referenzmaschine im Release-Buendel
    messen und so im Freigabebericht fuehren."

    WORAUF DAS ANTWORTET. Die CPU-Obergrenze steht seit `OA-0646ecdf70` in Referenzeinheiten, aber
    ihre Kalibrierung — die aufgezeichneten Kosten je Achse und der daraus abgeleitete Deckel —
    stammt von EINER Maschine. Auf dem Laeufer (gemessen rund doppelt so langsam: input_bytes 1,8x,
    json_nodes 2,1x, signatures 2,5x, data_digests 2,0x) laeuft der Maschinenfaktor gegen den
    Deckel der KOMBI-Flaeche (1,925). Was dort herauskommt, ist keine Aussage mehr ueber den Code:
    am 07.09.2026 ein Rot aus Langsamkeit (`renewal_work` 3,096 s gegen 3,0 s), am Kopf 88a5383
    zwoelf Abstinenzen, nach denen `coverage` gruen wurde, weil der einzige rote Fall sich aus der
    Bewertung gezogen hatte.

    SICHTBAR, NICHT STUMM — und das ist der Unterschied zu jeder anderen Abstinenz dieser Datei:
    hier wird nicht behauptet, die Messung sei nicht auswertbar, sondern dass sie AUF DIESER
    MASCHINE NICHT GEFUEHRT WIRD. Die Meldung traegt deshalb drei Dinge, die ein Leser braucht: die
    Kartennummer (WELCHE Entscheidung wirkt), die erkannte Marke (WORAN der Bauhost erkannt wurde)
    und den GEMESSENEN Faktor (WIE weit die Maschine von der Referenz entfernt war). Der Faktor ist
    die Bedingung des Owners, nicht Zierde: ohne ihn waere die Zeile eine Politik, mit ihm ist sie
    eine Messung mit einer Politik daneben.

    EIGENES VOKABULAR, absichtlich. Kein Wort dieser Meldung darf mit dem der drei anderen
    Abstinenzen (Deckel, Streuung, Kostenfamilie) zusammenfallen — sonst haelt ein Fangnachweis,
    der auf deren Wortlaut prueft, diese Bindung fuer seinen eigenen Fund und geht blind. Gebunden
    in `test_die_bindung_teilt_KEIN_erkennungswort_mit_den_anderen_abstinenzen`.

    WAS SIE NICHT TUT: sie nimmt die Achse nicht aus der Welt, sondern aus DIESER Bewertung. Auf
    der Referenzmaschine — im Release-Buendel — wird sie gemessen und so im Freigabebericht
    gefuehrt. Ein Ergebnis, das nur dort entsteht, muss auch von dort berichtet werden.
    """
    marke = _bauhost()
    if not marke:
        return
    pytest.skip(
        f"UEBERSPRUNGEN (referenzmaschinengebunden, Owner-Karte OA-dc37e26295): {was} wird auf "
        f"einem Bauhost nicht bewertet. Erkannt an {marke}; gemessener Maschinenfaktor "
        f"{faktor:.2f} gegen die Referenzmaschine (Farmer, 24 Kerne, CPython 3.10.12). Die "
        f"Kalibrierung dieser Achse — aufgezeichnete Kosten je Achse und der daraus abgeleitete "
        f"Deckel — stammt von dort; hier gemessen ergibt sie ein Urteil ueber die Maschine, nicht "
        f"ueber den Code. Gemessen wird sie auf der Referenzmaschine im Release-Buendel und von "
        f"dort im Freigabebericht gefuehrt.")


def _cpu() -> float:
    r = resource.getrusage(resource.RUSAGE_SELF)
    return r.ru_utime + r.ru_stime


def _zeit(ruf):
    """(Rechenzeit, Ergebnis-oder-Ausnahme). Eine Ausnahme ist hier ein ERGEBNIS: die Schranke, die
    ueber dem Limit zuschlaegt, meldet sich bei den Parser-Flaechen genau so."""
    t = _cpu()
    try:
        r = ruf()
    except ProofBundleError as exc:
        return _cpu() - t, exc
    return _cpu() - t, r


def _zeit_min_fest(ruf, laeufe: int = WIEDERHOLUNGEN):
    """Das Minimum aus GENAU `laeufe` Laeufen — unabhaengig davon, wie teuer die Messung ist.

    WARUM ES DAS BRAUCHT (eigene Lastprobe, 08.09.2026): `_zeit_min` wiederholt nur unterhalb von
    `WIEDERHOLEN_UNTER_S`. Fuer die Verdopplungsreihe von `renewal_work` heisst das: der Punkt bei
    0,18 s bekommt das Minimum aus DREI Laeufen, die Punkte bei 0,36 / 0,71 / 1,43 s je EINEN. Der
    billigste Punkt hat damit den tiefsten Rauschboden, und unter Fremdlast blaeht sich der einmal
    gemessene Punkt relativ staerker auf. Das Verhaeltnis k1/k0 waechst, die Steigung mit ihm —
    gemessen 1,31 gegen die Schranke 1,2, waehrend fuenf Ruhelaeufe sauber blieben.

    Fuer eine SCHRANKE ist die ungleiche Behandlung harmlos (jeder Punkt wird fuer sich beurteilt).
    Fuer eine STEIGUNG ist sie es nicht: sie vergleicht Punkte miteinander, und dafuer muessen sie
    gleich behandelt sein. Deshalb gilt die feste Zahl nur fuer die Kurvenreihe, nicht fuer `rand`
    oder die Ceiling-Messung.

    Kosten, gemessen: die Reihe von `renewal_work` steigt von 2,68 s auf rund 8 s.
    """
    dauer, erg = _zeit(ruf)
    for _ in range(max(0, laeufe - 1)):
        d2, erg = _zeit(ruf)
        dauer = min(dauer, d2)
    _ZEIT_MIN_LAEUFE.append(laeufe)
    return dauer, erg


#: Wie viele Laeufe der JEWEILS LETZTE Kurvenpunkt gebraucht hat — GESCHRIEBEN NUR von
#: `_zeit_min_fest`, GELESEN NUR von `_messung`. Instrument, kein Zustand: nur damit die Messung
#: selbst sagen kann, ob sie ihre Punkte gleich behandelt hat.
#:
#: Bis 08.09.2026 schrieb auch `_zeit_min` (der Weg der Randmessung) hierher. Dass das nie schadete,
#: lag allein an der Reihenfolge in `_messung` — die Randmessung laeuft nach dem Lesen. Das ist eine
#: Eigenschaft der Anordnung, keine des Codes; die fremdfamiliaere Gegenlesung hat es benannt, und
#: der Fangnachweis dazu war rot, bevor diese Trennung existierte.
_ZEIT_MIN_LAEUFE: list[int] = []

#: Dasselbe fuer die Randmessung — eigene Liste, damit die beiden Wege sich nicht ins Instrument
#: des jeweils anderen schreiben.
_RAND_LAEUFE: list[int] = []


def _zeit_min(ruf):
    """Der beste Schaetzer der wahren Kosten: das MINIMUM mehrerer Laeufe.

    Messrauschen (Cache, Zuteilung, fremde Last auf den anderen Kernen) kann Rechenzeit nur
    HINZUFUEGEN, nie abziehen. Ein Mittelwert traegt das Rauschen mit, das Minimum nicht. Wiederholt
    wird nur unterhalb von ``WIEDERHOLEN_UNTER_S``: wo die Messung gross ist, ist das Rauschen relativ
    klein, und die Wiederholung kostete dort Minuten statt Millisekunden.
    """
    dauer, erg = _zeit(ruf)
    if dauer >= WIEDERHOLEN_UNTER_S:
        _RAND_LAEUFE.append(1)
        return dauer, erg
    for _ in range(WIEDERHOLUNGEN - 1):
        d2, erg = _zeit(ruf)
        dauer = min(dauer, d2)
    _RAND_LAEUFE.append(WIEDERHOLUNGEN)
    return dauer, erg


def _zeit_max(ruf, n: int = MAX_WIEDERHOLUNGEN):
    """CPU-OBERGRENZE (Review Runde 2, B4): das MAXIMUM aus einer FESTEN Zahl Laeufe — nicht das
    Minimum.

    ``_zeit_min`` ist der richtige Schaetzer fuer die KURVENFORM (Exponent): Rauschen kann Rechenzeit
    nur hinzufuegen, nie abziehen, also naehert das Minimum die intrinsische Kosten der Berechnung an.
    Eine CPU-OBERGRENZE fuer ein DoS-Gate fragt aber etwas anderes: nicht "wie billig KANN dieser Fall
    sein", sondern "wie teuer WAR er, in den Laeufen, die ich gesehen habe" — und dafuer ist das
    Minimum der FALSCHE Wert, er versteckt genau die Streuung (Cache-Verdraengung, Scheduling,
    GC-Pausen, fremde Last auf den anderen Kernen), vor der die Obergrenze schuetzen soll. Deshalb
    IMMER alle ``n`` Laeufe (keine fruehe Rueckkehr wie bei ``_zeit_min``), und das Maximum entscheidet.
    """
    dauer = 0.0
    erg = None
    for _ in range(n):
        d, erg = _zeit(ruf)
        dauer = max(dauer, d)
    return dauer, erg


def _speicher_peak(ruf) -> int:
    """Gemessener Spitzenverbrauch in Bytes (Review Runde 2, B3): ``tracemalloc`` zaehlt nur
    PYTHON-Objektallokationen waehrend ``ruf()`` — deterministischer als Peak-RSS (das den ganzen
    Prozess inklusive Interpreter-Rauschen mitmisst), und genau die Groesse, die eine Speicherformel
    ueber ``_PraefixDeckung`` / die Parser-Flaechen vorhersagen kann. Eine ``ProofBundleError`` ist wie
    bei ``_zeit`` ein ERGEBNIS, kein Fehlschlag der Messung."""
    tracemalloc.start()
    try:
        try:
            ruf()
        except ProofBundleError:
            pass
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return peak


def _prozess_spitze(ruf) -> tuple[int, str]:
    """``(spitze_bytes, messweg)`` — die SPITZE DES GANZEN PROZESSES, nicht nur der Python-Objekte.

    WARUM ZUSAETZLICH ZU ``tracemalloc`` (Review Runde 3, Abschnitt 6, und Nachtrag 3 Teil A2).
    ``tracemalloc`` startet ERST beim Aufruf und zaehlt NUR Python-Allokationen. Damit fehlt zweierlei:
    die Eingabe, die vor dem Start schon aufgebaut ist (bei D=2000 Digests und N=10.000 ATS ist das
    nicht wenig), und alles, was ausserhalb des Python-Allokators liegt — die Hash-Implementierungen
    in ``hashlib`` allozieren nativ. Der Gegenleser nannte genau das: "``tracemalloc`` startet jedoch
    erst nach Aufbau von Sequenz und Datendigests und misst Python-Allokationen, nicht die gesamte
    Prozessspitze einschliesslich Eingabe, nativer Bibliotheken und RSS."

    GEMESSEN WIRD ``VmHWM`` aus ``/proc/self/status`` — der High Water Mark des Resident Set Size,
    den der Kernel fuehrt. Er ist monoton und deckt den GANZEN Prozess ab, also auch alles, was vor
    diesem Aufruf entstand. Genau deshalb wird die Differenz zum Stand VOR dem Aufruf berichtet UND
    der absolute Wert: die Differenz sagt, was dieser Lauf zusaetzlich brauchte, der absolute Wert,
    wie hoch der Prozess insgesamt stand. Beide Zahlen zusammen sind ehrlich, eine allein nicht.

    EHRLICHE GRENZE, und sie ist der Grund, warum ``tracemalloc`` bleibt und nicht ersetzt wird:
    ``VmHWM`` faellt NIE. Ein frueherer, groesserer Lauf im selben Prozess hebt ihn dauerhaft, und
    die Differenz ist dann null, obwohl der aktuelle Lauf Speicher braucht. Er misst also eine
    OBERGRENZE des Prozesses, keine Zurechnung an diesen Aufruf. ``tracemalloc`` kann die Zurechnung,
    ``VmHWM`` die Vollstaendigkeit — deshalb stehen beide im Rohausgang, mit ihrem jeweiligen Messweg.

    Ohne ``/proc`` (nicht-Linux) gibt es keinen Wert und keine Schaetzung, sondern die Auskunft, dass
    hier nicht gemessen werden kann.
    """
    def hwm() -> int | None:
        try:
            for zeile in pathlib.Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
                if zeile.startswith("VmHWM:"):
                    return int(zeile.split()[1]) * 1024
        except OSError:
            return None
        return None

    vorher = hwm()
    if vorher is None:
        try:
            ruf()
        except ProofBundleError:
            pass
        return -1, "NICHT MESSBAR: /proc/self/status VmHWM ist hier nicht lesbar (kein Linux?)"
    try:
        ruf()
    except ProofBundleError:
        pass
    nachher = hwm()
    if nachher is None:                                        # pragma: no cover
        return -1, "NICHT MESSBAR: VmHWM war vorher lesbar, nachher nicht"
    return nachher - vorher, (
        f"VmHWM aus /proc/self/status: vorher {vorher} B, nachher {nachher} B, "
        f"Differenz {nachher - vorher} B — Obergrenze des GANZEN Prozesses, faellt nie, "
        f"deshalb ist die Differenz eine untere Schranke des Bedarfs dieses Laufs")


def _arbeit(ruf) -> int:
    """Deterministische Arbeitszaehlung: Python-Aufrufe. Haengt nicht an der Maschine."""
    n = 0

    def zaehle(*_):
        nonlocal n
        n += 1

    war_an = gc.isenabled()
    gc.disable()
    sys.setprofile(zaehle)
    try:
        ruf()
    except ProofBundleError:
        pass
    finally:
        sys.setprofile(None)
        if war_an:
            gc.enable()
    return n


def _exponent(punkte) -> float:
    """Exponent aus einer Verdopplungsreihe: Median der einzelnen log-Steigungen.

    Der Median statt einer Ausgleichsgeraden, weil ein einzelner verrauschter Punkt (eine
    Zuteilung, ein Cache-Miss) die Gerade kippt, den Median aber nicht.
    """
    steigungen = []
    for (n0, k0), (n1, k1) in zip(punkte, punkte[1:]):
        if k0 <= 0 or k1 <= 0 or n1 <= n0:
            continue
        steigungen.append(math.log(k1 / k0) / math.log(n1 / n0))
    if not steigungen:
        return float("nan")
    steigungen.sort()
    return steigungen[len(steigungen) // 2]


# --------------------------------------------------------------------------- die Lasten
def _json_mit_genau(n: int) -> str:
    """Ein JSON-Dokument von EXAKT n Bytes, auf jeder anderen Achse zulaessig.

    Exakt, weil die Punkte L-1, L, L+1 sonst keine Punkte an der Grenze waeren, sondern in ihrer
    Naehe — und die Grenze ist genau das, was hier gemessen wird.
    """
    k = max(1, -(-n // 900_000))                      # Aufrunden: jede Zeichenkette bleibt < string_len
    summe = n - 3 * k - 1                             # ["a...","a..."] = sum(len) + 3k + 1
    assert summe >= k, f"n={n} ist zu klein fuer {k} Stuecke"
    q, rest = divmod(summe, k)
    laengen = [q + (1 if i < rest else 0) for i in range(k)]
    txt = "[" + ",".join('"' + "a" * m + '"' for m in laengen) + "]"
    assert len(txt) == n, (len(txt), n)
    return txt


def _last_input_bytes(n):
    txt = _json_mit_genau(n)
    return (lambda: loads_strict(txt)), len(txt)


def _last_json_nodes(n):
    txt = "[" + ",".join("1" for _ in range(n)) + "]"
    return (lambda: loads_strict(txt)), n


def _last_json_depth(n):
    txt = "[" * n + "]" * n
    return (lambda: loads_strict(txt)), n


def _last_string_len(n):
    txt = '["' + "a" * n + '"]'
    return (lambda: loads_strict(txt)), n


_SK = generate_signer()
_PUB = _SK.public_key().public_bytes_raw()


def _last_signatures(n):
    echt = dsse.sign_envelope(b'{"x":1}', _SK, payload_type="application/x.pb-kostenkurve")
    env = dict(echt)
    # die echte Signatur ans ENDE: sonst bricht die Schleife beim ersten Eintrag ab und misst nichts
    env["signatures"] = [{"sig": "AA=="} for _ in range(n - 1)] + list(echt["signatures"])
    return (lambda: dsse.verify_envelope(env, _PUB)), len(env["signatures"])


def _last_merkle_path(n):
    beweis = [bytes([i % 251]) * 32 for i in range(n)]
    wurzel = merkle.root_from_inclusion(0, 2 ** n, merkle.leaf_hash(b"x"), beweis)
    return (lambda: pb.verify_inclusion(b"x", 0, 2 ** n, beweis, wurzel)), len(beweis)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _last_disclosures(n):
    disc = [_b64u(json.dumps([f"salt{i}", f"feld{i}", i], separators=(",", ":")).encode())
            for i in range(n)]
    nutz = {"_sd": [sdjwt._digest(d, "sha-256") for d in disc], "_sd_alg": "sha-256"}
    kopf = _b64u(json.dumps({"alg": "EdDSA", "typ": "example+sd-jwt"}).encode())
    kompakt = "~".join([f"{kopf}.{_b64u(json.dumps(nutz).encode())}.{_b64u(b'x' * 64)}"] + disc) + "~"
    return (lambda: sdjwt.verify_sd_jwt(kompakt)), n


def _last_renewal_ats_chain(n):
    seq = [[ArchiveTimeStamp("sha256", HEX32, i + 1)] for i in range(n)]
    return (lambda: pb.verify_sequence(seq, [HEX32], allow_unauthenticated_anchor=True)), n


def _last_data_digests(n):
    """Review Runde 2, B1: die Kettenanfangs-ANZAHL bleibt bei EINEM ATS — sonst wuerde diese
    Einzel-Achse denselben Produkt-Effekt messen, den erst die KOMBINATION (unten,
    ``renewal_ats_chain x data_digests``) belegen soll."""
    daten = ["%064x" % i for i in range(n)]
    seq = [[ArchiveTimeStamp("sha256", HEX32, 1)]]
    return (lambda: pb.verify_sequence(seq, daten, allow_unauthenticated_anchor=True)), n


def _last_renewal_work(n):
    """Die PRODUKT-Dimension: ATS mal Datendigests mal Kettenanfangs-Algorithmen.

    Eine Produktdimension hat keine eigene Eingabeachse, die man einfach hochdreht — der Zielwert
    muss aus drei Faktoren zusammengesetzt werden, von denen JEDER seine eigene Schranke hat
    (``renewal_ats_chain``, ``data_digests``, und die Registry begrenzt die Algorithmen). Wuerde
    man nur die ATS hochdrehen, feuerte deren Achse zuerst und diese Kurve maesse den falschen
    Riegel. Deshalb: Datendigests fest am eigenen Limit, ATS skaliert, und erst wenn die ATS-Achse
    ueberliefe, kommt ein weiterer Algorithmus dazu.

    Gerundet wird zur richtigen SEITE der Grenze: ein Zielwert unterhalb des Limits darf nicht
    versehentlich darueber landen (sonst prueft der Randtest bei ``limit - 1`` eine Ablehnung, die
    er nicht erwartet), einer oberhalb nicht darunter."""
    D = gedeckelt(B.data_digests, bytes_je_element=KOSTEN_JE_ELEMENT["data_digests"])
    A = 2
    ueber = n > B.renewal_work
    def _n_ats(a):
        roh = (-(-n // (D * a))) if ueber else (n // (D * a))
        return max(1, roh)
    N = _n_ats(A)
    while N > B.renewal_ats_chain and A < len(_AKTUELLE_ALGS):
        A += 1
        N = _n_ats(A)
    N = min(N, B.renewal_ats_chain)
    algs = _AKTUELLE_ALGS[:A]
    daten = ["%064x" % i for i in range(D)]
    seq = [[ArchiveTimeStamp(algs[i % A], HEX32, i + 1)] for i in range(N)]
    return (lambda: pb.verify_sequence(seq, daten, allow_unauthenticated_anchor=True)), N * D * A


def _last_witnesses(n):
    keys = {f"k-{i}": {"publicKey": base64.b64encode(
        generate_signer().public_key().public_bytes_raw()).decode()} for i in range(n)}
    pred = {"schemaVersion": "0.1.0", "trustPackId": "t", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": [f"k-{i}" for i in range(2)], "threshold": 1}},
            "keys": keys, "nonClaims": ["x"]}
    return (lambda: validate_trust_pack_predicate(pred)), n


def _last_int_bits(n):
    """Der groesste zugelassene Betrag ist eine Zahl MIT n Bits, also 2**(n-1) — nicht 2**n."""
    idx = 2 ** (n - 1)
    groesse = idx + 1
    beweis = [b"\x11" * 32]
    wurzel = merkle.root_from_inclusion(idx, groesse, merkle.leaf_hash(b"x"), beweis)
    return (lambda: pb.verify_inclusion(b"x", idx, groesse, beweis, wurzel)), idx.bit_length()


def _kein_fehler(r):
    return not isinstance(r, BaseException)


@dataclasses.dataclass(frozen=True)
class Dimension:
    name: str
    was: str
    baue: object
    zugelassen: object
    #: Wie viele EINGABEACHSEN diese Dimension gleichzeitig an ihre Grenze treibt. Fuer eine
    #: gewoehnliche Achse ist das 1, und die Obergrenze ist ``GRENZE_S``. Eine PRODUKT-Dimension
    #: (``renewal_work`` = ATS x Datendigests x Algorithmen) treibt definitionsgemaess mehrere
    #: zugleich; ihre Obergrenze ist deshalb ``achsen * GRENZE_S`` — dieselbe Rechnung, die
    #: ``test_kombi_bleibt_unter_der_summe_der_obergrenzen`` fuer die Kombinationen schon macht.
    #: Ohne dieses Feld waere eine Produktdimension entweder unmessbar oder gezwungen, ihre
    #: Schranke unter den Wert zu druecken, bei dem die bestehende Zwei-Achsen-Kombination noch
    #: messbar ist — das haette einen echten Kostentest entwertet, um einen Zahlenvergleich zu
    #: retten.
    achsen: int = 1


DIMENSIONEN = [
    Dimension("input_bytes", "_strict_json.loads_strict", _last_input_bytes, _kein_fehler),
    Dimension("json_nodes", "_strict_json.loads_strict", _last_json_nodes, _kein_fehler),
    Dimension("json_depth", "_strict_json.loads_strict", _last_json_depth, _kein_fehler),
    Dimension("string_len", "_strict_json.loads_strict", _last_string_len, _kein_fehler),
    Dimension("signatures", "dsse.verify_envelope", _last_signatures, lambda r: r is True),
    Dimension("merkle_path", "merkle.verify_inclusion", _last_merkle_path, lambda r: r is True),
    Dimension("disclosures", "sdjwt.verify_sd_jwt", _last_disclosures,
              lambda r: isinstance(r, dict) and "too many disclosures" not in r["detail"]),
    Dimension("renewal_ats_chain", "renewal.verify_sequence", _last_renewal_ats_chain,
              lambda r: not any(c.name == "renewal:budget" for c in r.checks)),
    Dimension("witnesses", "trust_pack.validate_trust_pack_predicate", _last_witnesses,
              lambda r: not any("budget.witnesses" in e for e in r)),
    Dimension("int_bits", "merkle.verify_inclusion", _last_int_bits, lambda r: r is True),
    Dimension("data_digests", "renewal.verify_sequence", _last_data_digests,
              lambda r: not any(c.name == "renewal:budget:data_digests" for c in r.checks)),
    Dimension("renewal_work", "renewal.verify_sequence", _last_renewal_work,
              lambda r: not any(c.name == "renewal:budget:renewal_work" for c in r.checks),
              achsen=3),
]

_MESSUNGEN: dict = {}


def _klammer_jetzt() -> tuple[list[float], list[float]]:
    """Die Referenzklammer, gemessen im JETZIGEN Zustand — beide Kostenfamilien.

    FUER FIXTURES, DIE `_MESSUNGEN` FAELSCHEN, und der zweite Anlauf an dieser Stelle. Der erste gab
    den Faellen eine FLACHE Klammer (Faktor 1,0) — und nahm damit fuenf Faellen genau das weg, was
    sie pruefen: die zweigipflige Messreihe, die divergierenden Kostenfamilien, den Faktor GENAU auf
    dem Deckel. Sie liefen danach nicht mehr in ihre Abstinenz, sondern meldeten ROT gegen eine
    Latte, die ihre Faelschung gar nicht mehr sah. Das war dieselbe Klasse, gegen die diese ganze
    Runde arbeitet, in einem einzigen Zug selbst erzeugt.

    Richtig ist, die Klammer DURCH DIE AKTIVE FAELSCHUNG zu messen. Dann beschreibt sie dieselbe
    Maschine wie die Kosten daneben — und genau diese Paarung ist der Zweck der Klammer. Ist keine
    Faelschung aktiv, misst sie die echte Maschine, also das, was die Produktion auch taete.
    """
    return list(_referenz_werte()), list(_referenz_werte_hashfrei())


def _messung(dim: Dimension) -> dict:
    """Einmal messen, mehrfach zusichern — sonst kostet jede Zusicherung die Reihe erneut."""
    if dim.name in _MESSUNGEN:
        return _MESSUNGEN[dim.name]
    limit = getattr(B, dim.name)
    # DIE KLAMMER UM DIE KOSTENMESSUNG (08.09.2026, schwerster Fund dieser Runde). Die Referenzlast
    # wird VOR und NACH der teuren Reihe gemessen, und beide Reihen zusammen beschreiben das
    # Zeitfenster, in dem die Kosten entstanden sind. Vorher wurde der Faktor erst DANACH erhoben —
    # also in einem anderen Fenster als die Kosten, die er skaliert. Eine Lastspitze, die nur in
    # dieses spaete Fenster faellt, lockert die Latte, ohne die Kosten beruehrt zu haben, und eine
    # ECHTE Verteuerung passt lautlos darunter (gemessen: 2 von 5 Laeufen mit einer echten
    # dreifachen Verteuerung von `renewal_work`, ohne dass eine der drei Abstinenzen feuerte).
    #
    # WARUM HIER UND NICHT IN DER ZUSICHERUNG: `_messung` ist gepuffert. Hat eine fruehere Pruefung
    # dieselbe Achse schon gemessen, vergeht in der Zusicherung gar keine Zeit mehr — eine Klammer
    # dort umschloesse nichts.
    klammer_vorher = list(_referenz_werte())
    klammer_vorher_frei = list(_referenz_werte_hashfrei())
    reihe, arbeit = [], []
    reihe_wdh = []
    for n in (limit // 8, limit // 4, limit // 2, limit):
        ruf, ist = dim.baue(n)
        _ZEIT_MIN_LAEUFE.clear()
        dauer, erg = _zeit_min_fest(ruf)
        reihe.append((ist, dauer, erg))
        reihe_wdh.append((ist, dauer, erg, _ZEIT_MIN_LAEUFE[-1] if _ZEIT_MIN_LAEUFE else 0))
        arbeit.append((ist, _arbeit(ruf)))
    rand = {}
    for n in (limit - 1, limit, limit + 1):
        ruf, ist = dim.baue(n)
        dauer, erg = _zeit_min(ruf)
        rand[n] = (ist, dauer, dim.zugelassen(erg))
    # CPU-OBERGRENZE (Review Runde 2, B4): eine SEPARATE Messung, nur fuer den Ceiling-Test unten,
    # mit dem MAXIMUM aus MAX_WIEDERHOLUNGEN Laeufen — nicht mit dem Minimum aus `rand`/`reihe` oben.
    # Die Kurvenform (Exponent) bleibt beim Minimum (die richtige Schaetzung fuer "wie guenstig kann
    # es sein"); die Obergrenze fragt "wie teuer WAR es tatsaechlich", und dafuer ist das Maximum die
    # konservative, DoS-Gate-taugliche Antwort (siehe ``_zeit_max``-Docstring).
    ruf_am_limit, _ = dim.baue(limit)
    kosten_am_limit_max, _ = _zeit_max(ruf_am_limit)
    # Spitzenverbrauch (Review Runde 2, B3): derselbe Aufruf am Limit, diesmal unter tracemalloc.
    speicher_peak = _speicher_peak(ruf_am_limit)
    # ZWEITER MESSWEG (Review Runde 3, Nachtrag 3 Teil A2): die Spitze des GANZEN Prozesses. Der
    # Aufruf wird dafuer NEU gebaut — `ruf_am_limit` haelt seine Eingabe fest, und die soll bei
    # dieser Messung mitzaehlen, nicht schon vorher stehen. Das ist der Unterschied, den der
    # Gegenleser benannt hat: tracemalloc startet nach dem Aufbau, VmHWM kennt ihn.
    ruf_fuer_rss, _ = dim.baue(limit)
    prozess_spitze, spitze_messweg = _prozess_spitze(ruf_fuer_rss)
    m = {
        "limit": limit,
        "reihe": reihe,
        "reihe_wdh": reihe_wdh,
        "arbeit": arbeit,
        "rand": rand,
        "kosten_am_limit": reihe[-1][1],
        "kosten_am_limit_max": kosten_am_limit_max,
        "speicher_peak_am_limit": speicher_peak,
        "prozess_spitze_am_limit": prozess_spitze,
        "prozess_spitze_messweg": spitze_messweg,
        "referenz_klammer": klammer_vorher + list(_referenz_werte()),
        "referenz_klammer_frei": klammer_vorher_frei + list(_referenz_werte_hashfrei()),
        "exponent_zeit": _exponent([(n, k) for n, k, _ in reihe]),
        "exponent_arbeit": _exponent(arbeit),
        "arbeit_empfindlich": (arbeit[-1][1] >= ARBEIT_EMPFINDLICH * max(arbeit[0][1], 1)),
    }
    _MESSUNGEN[dim.name] = m
    return m


IDS = [d.name for d in DIMENSIONEN]


class TestJedeDimensionIstAbgedeckt:
    def test_keine_dimension_ohne_last(self):
        """ABGELEITET, nicht aufgezaehlt: die Menge kommt aus ``VerificationBudget`` selbst. Eine
        neue Dimension ohne Last faellt hier auf, statt still ungemessen zu bleiben."""
        felder = {f.name for f in dataclasses.fields(VerificationBudget)}
        gemessen = {d.name for d in DIMENSIONEN}
        assert felder == gemessen, (
            f"ohne Kostenkurve: {sorted(felder - gemessen)} | "
            f"gemessen, aber keine Budget-Dimension: {sorted(gemessen - felder)}")


class TestObergrenzeAmGroesstenZugelassenenWert:
    @pytest.mark.parametrize("dim", DIMENSIONEN, ids=IDS)
    def test_die_last_erreicht_das_limit_wirklich(self, dim):
        """Eine Last, die das Limit gar nicht erreicht, bestuende jede Obergrenze und pruefte nichts."""
        m = _messung(dim)
        ist = m["reihe"][-1][0]
        assert ist >= 0.95 * m["limit"], (
            f"{dim.name}: die Last erreicht nur {ist} von {m['limit']} — sie misst nicht den "
            "teuersten zugelassenen Fall")

    @pytest.mark.parametrize("dim", DIMENSIONEN, ids=IDS)
    def test_l_minus_eins_l_und_l_plus_eins(self, dim):
        """Die drei Punkte um das Limit. Dort sass der Sprung von 0,002 s auf 59,5 s."""
        m = _messung(dim)
        limit = m["limit"]
        assert m["rand"][limit - 1][2], f"{dim.name}: L-1 wird abgewiesen"
        assert m["rand"][limit][2], (
            f"{dim.name}: L selbst wird abgewiesen — dann ist L-1 der groesste zugelassene Wert und "
            "die Schranke ist anders dokumentiert als sie wirkt")
        assert not m["rand"][limit + 1][2], f"{dim.name}: L+1 wird NICHT abgewiesen"

    @pytest.mark.parametrize("dim", DIMENSIONEN, ids=IDS)
    def test_kosten_am_limit_unter_der_obergrenze(self, dim):
        """CPU-OBERGRENZE aus dem MAXIMUM von ``MAX_WIEDERHOLUNGEN`` Laeufen (Review Runde 2, B4) —
        nicht aus dem Minimum. Referenzumgebung siehe Modul-Kopf (Farmer, 24 Kerne, aktuell gesaettigt)."""
        m = _messung(dim)
        limit = m["limit"]
        k = m["kosten_am_limit_max"]
        # OWNER-ANORDNUNG OA-0646ecdf70: die Latte steht in REFERENZEINHEITEN, nicht in Sekunden.
        # DIE PRUEFUNG STEHT VOR DEM DIAGNOSE-TEXT (gefunden 2026-09-08, als der Skip-Pfad zum ersten
        # Mal wirklich GEGANGEN statt nur berechnet wurde): der Text unten liest `rand` an drei
        # Stellen, und einen Text zu bauen, den man gleich verwirft, ist nicht nur unnoetig — er kann
        # scheitern und macht aus einem sauberen NICHT MESSBAR einen KeyError.
        assert "referenz_klammer" in m, (
            f"{dim.name}: das Messergebnis traegt keine Referenzklammer. Entweder hat `_messung` sie "
            f"nicht gelegt, oder eine Fixture faelscht `_MESSUNGEN` ohne sie — dann benutze "
            f"`_klammer_jetzt()`. NICHT hier frisch nachmessen: genau das war der Fehler, den "
            f"die Klammer behebt (der Faktor lag dann wieder hinter den Kosten statt um sie herum).")
        klammer = m["referenz_klammer"]
        # Der Schalter der offenen Owner-Entscheidung, siehe `LATTE_AUS_DER_KLAMMER`.
        faktor = (_maschinenfaktor(klammer) if LATTE_AUS_DER_KLAMMER == "median"
                  else _faktor_spanne(klammer)[0])
        # OWNER-KARTE OA-dc37e26295 — HIER und nicht weiter unten. Der Faktor ist gemessen (die
        # Karte verlangt ihn als Grund), und jede andere Abstinenz waere auf einem Bauhost eine
        # Diagnose an einer Maschine, ueber die wir gar nicht mehr urteilen. Die Reihenfolge ist
        # die Aussage: erst messen, dann sagen, dass hier nicht bewertet wird.
        _referenzmaschinen_bindung(f"die Budget-Achse {dim.name}", faktor)
        deckel = _faktor_deckel(ausser=dim.name)
        if faktor > deckel:
            pytest.skip(
                f"NICHT MESSBAR: Maschinenfaktor {faktor:.2f} ueber dem abgeleiteten Deckel "
                f"{deckel:.2f}. Der Deckel ist die kleinste gemessene Kopffreiheit ALLER ANDEREN "
                f"Dimensionen in diesem Lauf — wird er ueberschritten, ist nicht die Maschine "
                f"langsam, sondern das Kostenmodell falsch. Ein gruenes Verdikt waere hier eine "
                f"Behauptung ohne Grundlage, ein rotes eine ohne Gegenstand.")
        # ZWEITE ABSTENTION, dieselbe Frage wie bei der Streuung, andere Achse: kippt das Verdikt,
        # je nachdem WELCHE Kostenfamilie die Referenz misst? Die Referenzlast ist sha256, aber
        # sechs der zwoelf Achsen sind nicht hash-gebunden. Faellt der Hash relativ staerker zurueck
        # als die Achse, ist die Latte zu locker — ein falsches GRUEN (nachgerechnet 08.09.2026:
        # Hashfaktor 3,0 gegen einen echten Bedarf von 1,5). Stimmen beide Familien ueberein, aendert
        # sich nichts; das ist der Normalfall auf einer Maschine mit aehnlichem Profil.
        # BEIDE FAMILIEN AM SELBEN ENDE. Der zweite Anlauf an dieser Stelle: stand der Hash-Faktor
        # am schnellen Ende und der hash-freie am Median, kippte das Verdikt ZWISCHEN DEN FAMILIEN,
        # die Kostenfamilien-Abstinenz griff, und Weg B kam nie bis zur Zusicherung. Ein Vergleich
        # zweier Familien ist nur dann eine Aussage ueber die Familien, wenn beide dieselbe Frage
        # beantworten — sonst misst er die Rechenvorschrift statt die Maschine.
        frei_klammer = m["referenz_klammer_frei"]
        # EIN AUFRUF, KEINE ZWEITE FORMEL (Klassenfix 08.09.2026, siehe `_faktor_spanne`): hier
        # stand die Rechenvorschrift ein zweites Mal von Hand, und eine vertauschte
        # Referenzkonstante waere in JEDER Fixture dieser Datei unsichtbar geblieben.
        faktor_frei = (_maschinenfaktor_hashfrei(frei_klammer) if LATTE_AUS_DER_KLAMMER == "median"
                       else _faktor_spanne_hashfrei(frei_klammer)[0])
        if (k <= dim.achsen * GRENZE_S * faktor) != (k <= dim.achsen * GRENZE_S * faktor_frei):
            pytest.skip(
                f"NICHT MESSBAR: das Verdikt haengt davon ab, WELCHE Kostenfamilie die Referenz "
                f"misst. Die Kosten ({k:.3f} s) fallen bei Hash-Faktor {faktor:.2f} anders aus als "
                f"bei hash-freiem Faktor {faktor_frei:.2f} "
                f"({dim.achsen * GRENZE_S * faktor:.3f} s gegen "
                f"{dim.achsen * GRENZE_S * faktor_frei:.3f} s). Diese Maschine hat ein anderes "
                f"Kostenprofil als die Referenzmaschine, und dann sagt eine einzelne Familie nichts "
                f"ueber die sechs Achsen der anderen.")
        # DIE STREUUNGS-ABSTINENZ GEHOERT ZU WEG A, NICHT ZU BEIDEN. Sie fragt: haengt das Verdikt
        # davon ab, WELCHES ENDE man nimmt? Weg B beantwortet genau diese Frage per Politik — immer
        # das schnelle Ende — und dann ist die Frage keine offene mehr. Ohne diese Zeile war der
        # Schalter WIRKUNGSLOS: in beiden Stellungen kam NICHT MESSBAR, weil die Abstinenz vor der
        # Zusicherung greift. Gefunden vom Fall, der den Schalter binden sollte, beim ersten Lauf.
        unten, oben = _faktor_spanne(klammer)
        if (LATTE_AUS_DER_KLAMMER == "median"
                and k > dim.achsen * GRENZE_S * unten and k <= dim.achsen * GRENZE_S * oben):
            pytest.skip(
                f"NICHT MESSBAR: das Verdikt haengt davon ab, welches Ende der eigenen Messreihe man "
                f"nimmt. Die Kosten ({k:.3f} s) liegen zwischen der Latte am schnellsten Ende "
                f"({dim.achsen * GRENZE_S * unten:.3f} s, Faktor {unten:.2f}) und der am langsamsten "
                f"({dim.achsen * GRENZE_S * oben:.3f} s, Faktor {oben:.2f}). Die Streuung der "
                f"Referenzlast ueberspannt hier die Entscheidung — dann sagt die Messung in beide "
                f"Richtungen nichts, und ein gruenes Verdikt waere die gefaehrlichere der beiden "
                f"Luegen. Auf einer ruhigen Maschine ist dieses Band so schmal wie ihre eigene "
                f"Streuung (Referenzmaschine 1,046).")
        drei = " | ".join(f"n={n}: {m['rand'][n][1]:.4f} s "
                          f"({'zugelassen' if m['rand'][n][2] else 'abgewiesen'})"
                          for n in (limit - 1, limit, limit + 1))
        latte = dim.achsen * GRENZE_S * faktor
        assert k <= latte, (
            f"{dim.name}: {k:.3f} s Rechenzeit (Maximum aus {MAX_WIEDERHOLUNGEN} Laeufen) am groessten "
            f"zugelassenen Wert ({limit}), Obergrenze {latte:.3f} s "
            f"= {dim.achsen} x {GRENZE_S} s x Maschinenfaktor {faktor:.2f} (Deckel {deckel:.2f}) "
            f"({dim.achsen} Achse{'n' if dim.achsen > 1 else ''} an ihrer Grenze). Die Schranke "
            f"laesst mehr zu, als "
            f"sie zu begrenzen behauptet — genau der Fund L2-600-01.\n  "
            f"die drei Punkte um das Limit (Minimum, nur zur Einordnung): {drei}")

    @pytest.mark.parametrize("dim", DIMENSIONEN, ids=IDS)
    def test_speicher_am_limit_unter_der_grenze(self, dim):
        """Spitzenverbrauch (Review Runde 2, B3): ``tracemalloc`` am groessten zugelassenen Wert, nicht
        nur Zeit. Die Formel fuer ``renewal_ats_chain``/``data_digests`` steht im Modul-Docstring von
        ``renewal._PraefixDeckung`` und wird hier gegen den echten Wert gehalten, nicht nur behauptet."""
        m = _messung(dim)
        peak = m["speicher_peak_am_limit"]
        assert peak <= SPEICHER_GRENZE_BYTES, (
            f"{dim.name}: {peak / 1024 / 1024:.2f} MiB Spitzenverbrauch (tracemalloc) am groessten "
            f"zugelassenen Wert ({m['limit']}), Obergrenze {SPEICHER_GRENZE_BYTES / 1024 / 1024:.0f} MiB")

    @pytest.mark.parametrize("dim", DIMENSIONEN, ids=IDS)
    def test_die_prozessspitze_wird_gemessen_und_ihr_messweg_genannt(self, dim):
        """AUFLAGE A2 (Nachtrag 3): Speicher zusaetzlich als PROZESSSPITZE, Eingabeaufbau eingeschlossen.

        Der Gegenleser hat den Grund benannt: ``tracemalloc`` startet erst beim Aufruf und zaehlt nur
        Python-Allokationen — die Eingabe, die vorher schon steht, und alles Native (``hashlib``
        alloziert ausserhalb des Python-Allokators) fehlen darin. ``VmHWM`` aus ``/proc/self/status``
        kennt beides.

        WAS HIER GEPRUEFT WIRD, ist bewusst NICHT eine zweite Obergrenze. ``VmHWM`` faellt nie: ein
        frueherer, groesserer Lauf im selben Prozess hebt ihn dauerhaft, und die Differenz waere dann
        null, obwohl der Lauf Speicher braucht. Eine Schranke darauf waere abhaengig von der
        Reihenfolge der Tests — ein Riegel, der von der Laufreihenfolge abhaengt, misst die Umgebung
        und nicht die Eigenschaft. Geprueft wird deshalb, dass die Zahl UEBERHAUPT ERHOBEN ist, dass
        sie ihren Messweg mitfuehrt, und dass sie kein stiller Ausfall ist: ``-1`` heisst hier
        ausdruecklich "nicht messbar" und traegt den Grund im Messweg.
        """
        m = _messung(dim)
        assert "prozess_spitze_am_limit" in m, "die Prozessspitze wird gar nicht erhoben"
        weg = m["prozess_spitze_messweg"]
        assert isinstance(weg, str) and weg, "die Prozessspitze nennt ihren Messweg nicht"
        spitze = m["prozess_spitze_am_limit"]
        if spitze == -1:
            assert "NICHT MESSBAR" in weg, (
                f"{dim.name}: die Prozessspitze meldet -1 ohne den Grund zu nennen: {weg!r}")
        else:
            assert spitze >= 0, f"{dim.name}: negative Prozessspitze {spitze}"
            assert "VmHWM" in weg, (
                f"{dim.name}: ein Wert ohne den Messweg, der ihn erzeugt hat: {weg!r}")


class TestKostenkurve:
    @pytest.mark.parametrize("dim", DIMENSIONEN, ids=IDS)
    def test_die_kurve_ist_nicht_ueberlinear(self, dim):
        m = _messung(dim)
        if m["arbeit_empfindlich"]:
            # maschinenunabhaengiger Beleg: die Arbeitszaehlung waechst mit der Eingabe, also ist ihr
            # Exponent aussagekraeftig und haengt nicht an Takt oder Last
            assert m["exponent_arbeit"] <= EXPONENT_MAX, (
                f"{dim.name}: Arbeits-Exponent {m['exponent_arbeit']:.2f} > {EXPONENT_MAX} "
                f"(Zaehlung {[a for _, a in m['arbeit']]})")
        if m["kosten_am_limit"] > RESERVE_S:
            assert m["exponent_zeit"] <= EXPONENT_MAX, (
                f"{dim.name}: Zeit-Exponent {m['exponent_zeit']:.2f} > {EXPONENT_MAX} bei "
                f"{m['kosten_am_limit']:.3f} s am Limit — ueberlinear INNERHALB der eigenen Schranke")

    def test_der_schaetzer_erkennt_eine_gepflanzte_quadratische_kurve(self):
        """GATE-META-TEST. Ein Schaetzer, der nie ausschlaegt, ist von einem funktionierenden nicht
        zu unterscheiden. Also wird ihm eine Kurve bekannter Form vorgelegt."""
        linear = [(n, 0.001 * n) for n in (1000, 2000, 4000, 8000)]
        quadratisch = [(n, 1e-8 * n * n) for n in (1000, 2000, 4000, 8000)]
        vor_dem_fix = [(1000, 0.691), (2000, 2.745), (4000, 9.344), (8000, 43.240)]
        assert abs(_exponent(linear) - 1.0) < 0.01
        assert abs(_exponent(quadratisch) - 2.0) < 0.01
        assert _exponent(quadratisch) > EXPONENT_MAX
        # die echte Messung von renewal_ats_chain VOR dem Fix, auf diesem Baum am 2026-09-05
        assert _exponent(vor_dem_fix) > EXPONENT_MAX, (
            "die gemessene Kurve vor dem Fix muesste dieser Schaetzer als Fund melden")

    def test_der_schaetzer_meldet_bei_UNBRAUCHBARER_reihe_keine_zahl(self):
        """NACHBAR DERSELBEN KLASSE wie der Nullkosten-Schutz im Deckel, gefunden beim Sweep.

        `_exponent` ueberspringt Punktpaare, aus denen sich keine Steigung bilden laesst (Kosten
        null, keine Zunahme in n). Bleibt danach KEIN Paar uebrig, gibt es keine Steigung — und die
        Funktion meldet `nan`. Das ist die einzige richtige Antwort, denn `nan` faellt bei JEDEM
        Vergleich durch: `nan <= EXPONENT_MAX` ist falsch, die Zusicherung wird rot, jemand schaut hin.

        Gebunden war das bisher NICHT. Gemessen 08.09.2026: `return float("nan")` durch `return 0.0`
        ersetzt — **126 passed**, zweimal, ohne Nebenlast. Eine Null geht als "linear oder besser"
        glatt durch jede Obergrenze. Das ist dieselbe Klasse wie `k <= 0` im Deckel: der Waechter
        greift, aber nichts prueft, WAS er zurueckgibt, wenn er greift. Eine Abstinenz, die durch die
        Zusicherung durchgeht, ist keine Abstinenz — sie ist ein stilles Gruen.

        (Ein erster Messlauf meldete hier faelschlich einen Fang. Er lief, waehrend ich parallel
        arbeitete, 87 s statt 74 s, und was fiel, war der lastempfindliche Steigungstest aus S12 —
        nicht die Mutation.)
        """
        for reihe, warum in (
            ([], "gar keine Punkte"),
            ([(1, 0.5)], "ein einziger Punkt — kein Paar"),
            ([(1, 0.0), (2, 0.0), (4, 0.0)], "alle Kosten null"),
            ([(4, 0.5), (2, 0.5), (1, 0.5)], "n nimmt nicht zu"),
            # DRITTE ENTARTUNGSART, die keine der obigen erzeugt (Gegenlesung 08.09.2026): die
            # Kosten fallen auf exakt null, WAEHREND n weiter waechst. Nur diese Reihe faellt
            # ueber `k1 <= 0` heraus; die anderen drei fallen schon ueber `k0 <= 0` oder `n1 <= n0`.
            # Ohne sie bleibt das Entfernen von `k1 <= 0` unsichtbar — und die Folge waere kein
            # falscher Wert, sondern ein Absturz (`math domain error`) statt der geforderten
            # Nicht-Zahl.
            ([(1, 0.5), (2, 0.0)], "Kosten fallen auf null, waehrend n waechst"),
        ):
            e = _exponent(reihe)
            assert math.isnan(e), (
                f"{warum}: der Schaetzer meldet {e!r} statt nan. Aus dieser Reihe laesst sich keine "
                f"Steigung bilden; jede ZAHL waere hier eine Behauptung ohne Grundlage.")
            assert not (e <= EXPONENT_MAX), (
                f"{warum}: die Antwort {e!r} geht als 'linear oder besser' durch die Obergrenze "
                f"{EXPONENT_MAX}. Genau so sieht ein stilles Gruen aus.")

    def test_die_arbeitszaehlung_ist_mindestens_einmal_empfindlich(self):
        """Sonst waere der maschinenunabhaengige Teil dieser Datei ueberall unentschieden — und ein
        Beleg, der nie greift, ist kein Beleg."""
        empfindlich = [d.name for d in DIMENSIONEN if _messung(d)["arbeit_empfindlich"]]
        assert empfindlich, "keine einzige Dimension hat eine empfindliche Arbeitszaehlung"


# --------------------------------------------------------------------------- kombinierte Achsen
# Review Runde 2, B2: jeder Baustein gibt jetzt (Aufruf, ``erreicht``) zurueck — ``erreicht`` ist ein
# dict {Budget-Dimension: tatsaechlich gebauter Wert}, damit ``TestKombinierteAchsen`` PRUEFEN kann,
# dass jede benannte Achse wirklich an ihrem Limit steht, statt es nur zu behaupten.
def _kombi_renewal_x_int_bits():
    gross = 2 ** (B.int_bits - 1)
    seq = [[ArchiveTimeStamp("sha256", HEX32, gross + i)]
           for i in range(gedeckelt(B.renewal_ats_chain, bytes_je_element=KOSTEN_JE_ELEMENT["renewal_ats_chain"]))]
    erreicht = {"renewal_ats_chain": len(seq), "int_bits": gross.bit_length()}
    return (lambda: pb.verify_sequence(seq, [HEX32], allow_unauthenticated_anchor=True)), erreicht


def _kombi_renewal_x_algorithmen():
    algs = ["sha256", "sha512", "sha3-256", "sha3-512", "sha384"]
    seq = [[ArchiveTimeStamp(algs[i % len(algs)], HEX32, i + 1)]
           for i in range(gedeckelt(B.renewal_ats_chain, bytes_je_element=KOSTEN_JE_ELEMENT["renewal_ats_chain"]))]
    # "5 hash-algorithmen" ist keine Budget-Dimension (die Menge ist durch HASH_REGISTRY auf eine
    # kleine Konstante begrenzt, siehe renewal._PraefixDeckung) — hier wird nur renewal_ats_chain
    # gegen die eigene Dimension geprueft.
    erreicht = {"renewal_ats_chain": len(seq)}
    return (lambda: pb.verify_sequence(seq, [HEX32], allow_unauthenticated_anchor=True)), erreicht


def _kombi_renewal_x_data_digests():
    """Review Runde 2, B1: GENAU der Fall, den diese Lane selbst als 15,9 s / 16,2 s Befund gemessen
    hat (siehe Modul-Kopf und ``budget.VerificationBudget.data_digests``) — jetzt als Kombination mit
    BEIDEN Achsen an ihrem eigenen Limit, nicht als spaeterer, von dieser Datei ungedeckter Befund."""
    daten = ["%064x" % i for i in range(gedeckelt(B.data_digests, bytes_je_element=KOSTEN_JE_ELEMENT["data_digests"]))]
    seq = [[ArchiveTimeStamp("sha256", HEX32, i + 1)]
           for i in range(gedeckelt(B.renewal_ats_chain, bytes_je_element=KOSTEN_JE_ELEMENT["renewal_ats_chain"]))]
    erreicht = {"renewal_ats_chain": len(seq), "data_digests": len(daten)}
    return (lambda: pb.verify_sequence(seq, daten, allow_unauthenticated_anchor=True)), erreicht


def _kombi_renewal_x_data_digests_x_algorithmen():
    """DIE DRITTE ACHSE (Gegenlesung 2026-09-05, Linse 3 von 6). Die beiden Kombinationen darueber
    lassen je einen Faktor auf 1 stehen: die Algorithmen-Kombi haelt D=1, die Datendigest-Kombi haelt
    A=1. Genau dazwischen lag die Luecke — ``_PraefixDeckung`` haelt je Kettenanfangs-Algorithmus einen
    eigenen laufenden Hash-Zustand, und jedes ATS-Token wandert in JEDEN davon.

    Gemessen am 2026-09-05 (Farmer, 24 Kerne, Lastmittel 51, Maximum aus 3 Laeufen) bei vollen ATS-
    und Datendigest-Achsen: A=1 0,813 s · A=2 1,577 s · A=3 1,944 s · A=5 3,621 s. Die Latte liegt bei
    drei Achsen auf ``3 * GRENZE_S`` = 3,0 s, der A=5-Fall reisst sie — und keine Einzelachse meldet
    etwas, weil jede fuer sich eingehalten ist.

    Diese Kombination faehrt deshalb den GROESSTEN vom Produktbudget noch ZUGELASSENEN Fall
    (``budget.renewal_work``), nicht den abgewiesenen: was die Schranke verbietet, kann kein
    Kostentest mehr messen. Dass der abgewiesene Fall wirklich abgewiesen wird, prueft
    ``TestProduktbudget`` weiter unten."""
    algs = ["sha256", "sha512"]                      # zwei Kettenanfangs-Kennungen
    daten = ["%064x" % i for i in range(gedeckelt(B.data_digests, bytes_je_element=KOSTEN_JE_ELEMENT["data_digests"]))]
    n = min(B.renewal_work // (len(daten) * len(algs)),   # so viele ATS, wie das Produktbudget zulaesst
            gedeckelt(B.renewal_ats_chain, bytes_je_element=KOSTEN_JE_ELEMENT["renewal_ats_chain"]))
    seq = [[ArchiveTimeStamp(algs[i % len(algs)], HEX32, i + 1)] for i in range(n)]
    erreicht = {"renewal_work": n * len(daten) * len(algs)}
    return (lambda: pb.verify_sequence(seq, daten, allow_unauthenticated_anchor=True)), erreicht


def _kombi_merkle_x_int_bits():
    """POPCOUNT-Konstruktion (Review Runde 2, B2). ``root_from_inclusion``s fn/sn-Arithmetik verbraucht,
    wenn ``leaf_index == tree_size - 1`` (fn und sn bleiben dann fuer den ganzen Lauf gleich), pro
    Beweisglied GENAU einen zusammenhaengenden Block aus Endnullen-plus-folgender-Eins von
    ``leaf_index``s Binaerdarstellung — die Zahl der noetigen (und einzig gueltigen) Beweisglieder ist
    also exakt ``popcount(leaf_index)``, reproduzierbar gemessen: 255 Glieder wirft "proof too short",
    257 wirft "proof too long", genau 256 geht durch. Die vorige Fassung nutzte ``beweis[:1]`` (ein
    Element), weil sie ``idx = 2**(int_bits-1)`` waehlte — GENAU EIN gesetztes Bit, also ist dort ein
    einzelnes Element das einzig gueltige Mass, ein laengerer Beweis waere IMMER ``ValueError``
    gewesen, nicht nur ungeprueft. Mit einem ZWEITEN Bitblock (``merkle_path - 1`` tiefe Einsen unter
    dem hohen int_bits-Bit) hat ``idx`` weiter ``int_bits`` Bits (die Bitlaenge zaehlt nur die
    hoechste Eins) UND ``popcount(idx) == merkle_path`` — beide Achsen gleichzeitig an ihrem Limit."""
    idx = (1 << (B.int_bits - 1)) + ((1 << (B.merkle_path - 1)) - 1)
    groesse = idx + 1
    beweis = [bytes([i % 251]) * 32 for i in range(gedeckelt(B.merkle_path, bytes_je_element=KOSTEN_JE_ELEMENT["merkle_path"]))]
    wurzel = merkle.root_from_inclusion(idx, groesse, merkle.leaf_hash(b"x"), beweis)
    erreicht = {"int_bits": idx.bit_length(), "merkle_path": len(beweis)}
    return (lambda: pb.verify_inclusion(b"x", idx, groesse, beweis, wurzel)), erreicht


def _kombi_signatures_x_input_bytes():
    """UMBENANNT auf die tatsaechlich erreichbare Achse (Review Runde 2, B2 — Name im ``KOMBIS``-Eintrag
    unten bleibt ``signatures x string_len``, nicht mehr ``x input_bytes``).

    ``dsse._payload_bytes`` ruft ``enforce_structural_budget`` auf dem GANZEN Envelope-Dict auf, BEVOR
    es seinen eigenen ``len(payload) > input_bytes``-Vergleich macht — und dieser generische Walk
    prueft JEDEN String (auch ``envelope["payload"]`` selbst) gegen ``string_len`` (1.000.000), das
    unter ``DEFAULT_BUDGET`` KLEINER ist als ``input_bytes`` (8.388.608). Ein base64-Payload laenger
    als ``string_len`` faellt deshalb IMMER zuerst auf den generischen Check — ``input_bytes`` ist fuer
    dieses Feld ueber ``verify_envelope`` gar nicht erreichbar. Reproduziert: ein Payload mit rund
    8,39 MB base64-Laenge wirft ``BundleFormatError: ... string_len = 8388604 > limit 1000000``, lange
    bevor der ``input_bytes``-Vergleich ueberhaupt gelesen wird. Die VORIGE Fassung dieser Kombination
    (900.000 Nutzbytes, rund 1,2 MB base64) traf denselben generischen ``string_len``-Check schon —
    nur wurde das nie sichtbar, weil ``_zeit`` eine ``ProofBundleError`` als Ergebnis nimmt statt als
    Fehlschlag: sie mass eine SOFORTIGE Ablehnung, keine Grenzlast. Diese Fassung behauptet nur noch,
    was sie tatsaechlich baut: ``signatures`` an seinem Limit, ``string_len`` an SEINEM (des
    base64-Payloads) Limit — und verifiziert wirklich (``ok=True``), keine Ablehnung."""
    ziel_b64 = 999_996                          # durch 4 teilbar -> kein Padding, exakt reproduzierbar
    nutz = b"a" * (3 * (ziel_b64 // 4))
    echt = dsse.sign_envelope(nutz, _SK, payload_type="application/x.pb-kostenkurve")
    env = dict(echt)
    env["signatures"] = ([{"sig": "AA=="} for _ in range(gedeckelt(B.signatures, bytes_je_element=KOSTEN_JE_ELEMENT["signatures"]) - 1)]
                         + list(echt["signatures"]))
    erreicht = {"signatures": len(env["signatures"]), "string_len": len(env["payload"])}
    return (lambda: dsse.verify_envelope(env, _PUB)), erreicht


def _kombi_parser_alle_achsen():
    """Review Runde 2, B2: alle DREI benannten Achsen tatsaechlich >= 95 % ihres Limits, als
    ``erreicht`` GEPRUEFT statt nur behauptet.

    TIEFEN-KORREKTUR gegenueber der vorigen Fassung (gefunden beim Nachbauen, reproduzierbar): die
    vorige Fassung wickelte ``kern`` (selbst schon eine Liste) in ``tief - 1`` weitere Listen — das
    macht ``kern`` zu Tiefe ``tief`` und seine BLATT-Strings zu Tiefe ``tief + 1``. Der Tiefen-Walk in
    ``_strict_json._enforce_structural_budget`` zaehlt aber JEDEN Knoten inklusive der Blaetter, nicht
    nur Container, und schlaegt bei ``tiefe > json_depth`` fehl — die vorige Fassung warf deshalb bei
    JEDEM Lauf ``BundleFormatError: JSON nesting is too deep`` und mass, wie bei der
    Signatur-Kombination oben, eine sofortige Ablehnung statt einer Grenzlast. Mit ``tief - 2``
    Wickel-Ebenen sitzen die Blaetter GENAU auf Tiefe ``json_depth`` (zugelassen, nicht ueberschritten,
    reproduziert: ``tief - 1`` Wickel-Ebenen werfen weiterhin, ``tief - 2`` nicht)."""
    tief = gedeckelt(B.json_depth, bytes_je_element=KOSTEN_JE_ELEMENT["json_depth"])
    leaf_len = 999_000                          # >= 95 % von string_len, echt kleiner als string_len
    anzahl = 8                                  # 8 Blaetter dieser Laenge erreichen >= 95 % von input_bytes
    kern = json.dumps(["a" * leaf_len] * anzahl)
    txt = "[" * (tief - 2) + kern + "]" * (tief - 2)
    erreicht = {"input_bytes": len(txt), "json_depth": tief, "string_len": leaf_len}
    return (lambda: loads_strict(txt)), erreicht


KOMBIS = [
    ("renewal_ats_chain x int_bits", 2, _kombi_renewal_x_int_bits),
    ("renewal_ats_chain x 5 hash-algorithmen", 2, _kombi_renewal_x_algorithmen),
    ("renewal_ats_chain x data_digests", 2, _kombi_renewal_x_data_digests),
    ("merkle_path x int_bits", 2, _kombi_merkle_x_int_bits),
    ("signatures x string_len", 2, _kombi_signatures_x_input_bytes),
    ("renewal_ats_chain x data_digests x hash-algorithmen", 3,
     _kombi_renewal_x_data_digests_x_algorithmen),
    ("input_bytes x json_depth x string_len", 3, _kombi_parser_alle_achsen),
]

_KOMBI_MESSUNGEN: dict = {}


def _kombi_messung(name: str, bau) -> dict:
    """Wie ``_messung`` fuer ``DIMENSIONEN``: einmal bauen und ausfuehren, mehrfach zusichern."""
    if name in _KOMBI_MESSUNGEN:
        return _KOMBI_MESSUNGEN[name]
    fn, erreicht = bau()
    dauer_max, _ = _zeit_max(fn)
    speicher = _speicher_peak(fn)
    m = {"erreicht": erreicht, "dauer_max": dauer_max, "speicher_peak": speicher}
    _KOMBI_MESSUNGEN[name] = m
    return m


class TestKombinierteAchsen:
    """Eine Dimension allein ist nicht der teuerste zugelassene Fall. Zwei Achsen, jede an ihrem
    Limit, sind zwei Budgets — die Obergrenze ist deshalb ihre SUMME, nicht ihr Maximum. Das ist eine
    Regel, keine an das Ergebnis angepasste Zahl.

    Review Runde 2, B1+B2: jede Kombination muss (a) jede benannte Dimension nachweislich zu
    mindestens ``KOMBI_ERREICHT_MIN`` erreichen — sonst behauptet sie eine Grenzlast, die sie gar
    nicht baut (genau der Fund an ``merkle_path x int_bits``, ``signatures x input_bytes`` und dem
    Parser-Kombi) —, und (b) unter der Summe ihrer Obergrenzen bleiben, gemessen als MAXIMUM aus
    ``MAX_WIEDERHOLUNGEN`` Laeufen (B4, dieselbe Begruendung wie bei den Einzeldimensionen oben).

    Der teuerste hier gemessene Fall ist ``renewal_ats_chain x int_bits``: 10.000 ATS mit einer
    8192-Bit-``time``. Sein Anteil ist zu ~0,61 s das einmalige Rendern dieser Zahlen nach dezimal
    (CPython ist dort ueberlinear), und das ist nicht wegzuoptimieren: die dezimale Form IST das
    gedeckte Material. Vor dem Fix wurde sie n mal je ATS gerendert statt einmal.
    """

    @pytest.mark.parametrize("name,achsen,bau", KOMBIS, ids=[k[0] for k in KOMBIS])
    def test_kombi_erreicht_jede_benannte_dimension(self, name, achsen, bau):
        """B2: eine Last, die ihre eigenen Achsen nicht erreicht, prueft nichts — siehe Modul-Docstring
        der drei korrigierten Bausteine oben fuer die reproduzierten Gegenbeispiele."""
        m = _kombi_messung(name, bau)
        for dim_name, wert in m["erreicht"].items():
            limit = getattr(B, dim_name)
            assert wert >= KOMBI_ERREICHT_MIN * limit, (
                f"{name}: Dimension {dim_name} erreicht nur {wert} von {limit} "
                f"({wert / limit:.1%}, mindestens {KOMBI_ERREICHT_MIN:.0%} gefordert) — der Kombi-Test "
                "misst nicht, was er behauptet")

    @pytest.mark.parametrize("name,achsen,bau", KOMBIS, ids=[k[0] for k in KOMBIS])
    def test_kombi_bleibt_unter_der_summe_der_obergrenzen(self, name, achsen, bau):
        """Die Latte steht in REFERENZEINHEITEN, nicht in Sekunden — dieselbe Regel wie fuer die
        Einzelachsen (OA-0646ecdf70).

        NACHGEZOGEN AM 08.09.2026, benannt von einer Gegenlesung: diese Flaeche prueste bis dahin
        gegen `achsen * GRENZE_S`, also gegen eine Zahl, die auf der Referenzmaschine gemessen
        wurde. Auf einem doppelt so langsamen Laeufer wird das rot, weil die Maschine langsam ist —
        genau der Defekt, den diese Runde fuer `DIMENSIONEN` behoben hat, nur auf der KOMBI-Flaeche
        stehengeblieben. Der Fangnachweis dazu (`test_die_KOMBI_latte_kennt_die_maschine_auf_der_
        sie_urteilt`) war rot: 3,000 s gegen eine Latte von 2 x 1,0 bei Maschinenfaktor 2.

        Der Deckel nimmt hier KEINE Achse aus: eine Kombination ist keine der aufgezeichneten
        Dimensionen, es gibt also nichts, was sich selbst begrenzen koennte.
        """
        m = _kombi_messung(name, bau)
        dauer = m["dauer_max"]
        faktor = _maschinenfaktor()
        # DIESELBE KARTE AUF DER NACHBARFLAECHE (Klassen-Sweep, Anker FIX-THE-CLASS): sie misst
        # dieselbe Groesse gegen dieselbe Kalibrierung, und ihr Deckel (1,925) liegt sogar unter
        # dem gemessenen Laeufer-Faktor von rund 2.
        _referenzmaschinen_bindung(f"die Achsenkombination {name}", faktor)
        deckel = _faktor_deckel(ausser="")
        if faktor > deckel:
            pytest.skip(
                f"NICHT MESSBAR: Maschinenfaktor {faktor:.2f} ueber dem abgeleiteten Deckel "
                f"{deckel:.2f}. Wird er ueberschritten, ist nicht die Maschine langsam, sondern das "
                f"Kostenmodell falsch — und dann sagt weder ein gruenes noch ein rotes Verdikt etwas.")
        latte = achsen * GRENZE_S * faktor
        assert dauer <= latte, (
            f"{name}: {dauer:.3f} s Rechenzeit (Maximum aus {MAX_WIEDERHOLUNGEN} Laeufen), Obergrenze "
            f"{latte:.3f} s = {achsen} x {GRENZE_S} s x Maschinenfaktor {faktor:.2f} "
            f"(Deckel {deckel:.2f}, {achsen} Achsen an ihrem Limit)")

    @pytest.mark.parametrize("name,achsen,bau", KOMBIS, ids=[k[0] for k in KOMBIS])
    def test_kombi_speicher_bleibt_unter_der_grenze(self, name, achsen, bau):
        """Spitzenverbrauch der Kombination (Review Runde 2, B3) — dieselbe Obergrenze wie fuer eine
        einzelne Dimension: keine der hier gebauten Kombinationen soll mehr als eine einzelne
        Dimension am Limit im Speicher kosten, sonst multiplizieren sich Achsen auch im Speicher."""
        m = _kombi_messung(name, bau)
        peak = m["speicher_peak"]
        assert peak <= SPEICHER_GRENZE_BYTES, (
            f"{name}: {peak / 1024 / 1024:.2f} MiB Spitzenverbrauch (tracemalloc), Obergrenze "
            f"{SPEICHER_GRENZE_BYTES / 1024 / 1024:.0f} MiB")


class TestBericht:
    def test_zahlen_ausgeben(self, capsys):
        """Kein Urteil, nur die Zahlen — sichtbar mit ``pytest -s``. Ein Riegel, dessen Messwerte
        niemand sehen kann, wird beim naechsten Zweifel neu erfunden statt nachgelesen."""
        zeilen = ["", f"{'Dimension':<20}{'Limit':>10}{'CPU@L(min)':>11}{'CPU@L(max9)':>12}"
                      f"{'Speicher@L':>12}{'Exp(Zeit)':>11}{'Exp(Arbeit)':>13}{'Arbeit empf.':>14}  Flaeche"]
        for d in DIMENSIONEN:
            m = _messung(d)
            zeilen.append(
                f"{d.name:<20}{m['limit']:>10}{m['rand'][m['limit']][1]:>11.4f}"
                f"{m['kosten_am_limit_max']:>12.4f}{m['speicher_peak_am_limit'] / 1024:>10.1f}KiB"
                f"{m['exponent_zeit']:>11.2f}{m['exponent_arbeit']:>13.2f}"
                f"{str(m['arbeit_empfindlich']):>14}  {d.was}")
        zeilen.append("")
        zeilen.append(f"{'Kombination':<45}{'CPU(max9)':>11}{'Speicher':>12}  erreicht")
        for name, achsen, bau in KOMBIS:
            m = _kombi_messung(name, bau)
            erreicht_str = ", ".join(f"{k}={v}" for k, v in m["erreicht"].items())
            zeilen.append(
                f"{name:<45}{m['dauer_max']:>10.4f}s{m['speicher_peak'] / 1024 / 1024:>10.2f}MiB  "
                f"{erreicht_str}")
        with capsys.disabled():
            print("\n".join(zeilen))
        assert len(zeilen) == len(DIMENSIONEN) + len(KOMBIS) + 4


class TestProduktbudget:
    """Die dritte Achse, zweiseitig geprueft (Gegenlesung 2026-09-05, Linse 3 von 6).

    Ein Riegel, der nur zeigt, dass er bei absurder Eingabe feuert, hat die Haelfte bewiesen. Die
    andere Haelfte ist, dass er bei legitimer Eingabe schweigt — und dass er wirklich am PRODUKT
    haengt und nicht an einer Achse, die zufaellig mitlaeuft.
    """

    @staticmethod
    def _budget_checks(r):
        return [c for c in r.checks if c.name.startswith("renewal:budget")]

    def test_die_dimension_existiert_und_ist_erreichbar(self):
        assert isinstance(B.renewal_work, int) and B.renewal_work > 0
        assert B.within("renewal_work", B.renewal_work)
        assert not B.within("renewal_work", B.renewal_work + 1)

    def test_alle_fuenf_aktuellen_algorithmen_an_vollen_achsen_werden_abgewiesen(self):
        """Der gemessene Fall: 10.000 ATS x 2.000 Datendigests x 5 Kettenanfangs-Algorithmen kostete
        3,621 s gegen eine Drei-Achsen-Latte von 3,0 s. Er muss VOR der Arbeit abgewiesen werden —
        weshalb dieser Test in Millisekunden zurueckkommt und nicht in Sekunden."""
        algs = [n for n, s in HASH_REGISTRY.items() if s.status == "current"]
        assert len(algs) >= 5, f"Vorbedingung: mindestens 5 aktuelle Algorithmen, gefunden {algs}"
        daten = ["%064x" % i for i in range(gedeckelt(B.data_digests, bytes_je_element=KOSTEN_JE_ELEMENT["data_digests"]))]
        seq = [[ArchiveTimeStamp(algs[i % len(algs)], HEX32, i + 1)]
               for i in range(gedeckelt(B.renewal_ats_chain, bytes_je_element=KOSTEN_JE_ELEMENT["renewal_ats_chain"]))]
        r = pb.verify_sequence(seq, daten, allow_unauthenticated_anchor=True)
        treffer = self._budget_checks(r)
        assert treffer, "kein Budget-Check auf die gemessene Kombination"
        assert not treffer[0].ok
        assert "renewal_work" in treffer[0].detail
        assert not r.ok

    def test_jede_einzelachse_ist_dabei_eingehalten(self):
        """Der Beweis, dass das Produkt eine EIGENE Aussage ist: beide Achsen melden nichts."""
        assert B.within("renewal_ats_chain", B.renewal_ats_chain)
        assert B.within("data_digests", B.data_digests)
        assert not B.within("renewal_work",
                            B.renewal_ats_chain * B.data_digests * 5)

    def test_eine_legitime_sequenz_kommt_am_riegel_vorbei(self):
        """Gegenrichtung. Ein Riegel, der immer feuert, misst nichts. Der groesste Datendigest-Satz
        im ganzen Repo ist EINER — legitime Nutzung liegt Groessenordnungen unter dem Produkt."""
        daten = ["%064x" % i for i in range(4)]
        seq = pb.build_initial_sequence(daten, hash_alg="sha256", time=100)
        r = pb.verify_sequence(seq, daten, allow_unauthenticated_anchor=True)
        assert not self._budget_checks(r), "das Produktbudget feuert auf einer legitimen Sequenz"
        assert r.ok, [(c.name, c.ok, c.detail) for c in r.checks if not c.ok]

    def test_meta_ein_kuenstlich_kleines_budget_faengt_dieselbe_sequenz(self, monkeypatch):
        """Haengt die Abweisung wirklich am Produkt? Wird die Decke auf 1 gesetzt, muss dieselbe
        harmlose Sequenz fallen — und zwar mit der renewal_work-Meldung, nicht mit einer anderen."""
        import proofbundle.budget as budget_mod
        monkeypatch.setattr(budget_mod, "DEFAULT_BUDGET",
                            budget_mod.VerificationBudget(renewal_work=1))
        daten = ["%064x" % i for i in range(4)]
        seq = [[ArchiveTimeStamp("sha256", HEX32, i + 1)] for i in range(3)]
        r = pb.verify_sequence(seq, daten, allow_unauthenticated_anchor=True)
        treffer = self._budget_checks(r)
        assert treffer and not treffer[0].ok
        assert "renewal_work" in treffer[0].detail


class TestSpeicherUeberN:
    """B3, nachgebessert (Owner-Auflage 2026-09-05): der Beleg gehoert auf die Achse, ueber die er
    etwas aussagt.

    Die erste Fassung belegte "der Speicher waechst UNABHAENGIG von der Zahl der Kettenanfaenge" mit
    zwei Messpunkten, die N festhielten und D variierten. Das ist die falsche Achse: wer die
    Unabhaengigkeit von N behauptet, muss N variieren. Nachgemessen am 2026-09-05 mit festem D:
    N=10 -> 0,27 MiB · N=100 -> 0,27 · N=1.000 -> 0,36 · N=5.000 -> 1,30 · N=10.000 -> 2,48 MiB.

    Der Speicher WAECHST also mit N — nur nicht in ``_PraefixDeckung`` (deren Formel O(A)+O(D) stimmt),
    sondern in der Check-Liste von ``VerificationResult``, die je ATS einen Eintrag bekommt. Dieser
    Test behauptet deshalb NICHT die widerlegte Unabhaengigkeit, sondern nagelt das TATSAECHLICHE
    Verhalten fest: monoton in N, absolut unter der Grenze, und der Zuwachs bleibt in derselben
    Groessenordnung wie die Zahl der Eintraege. Waechst er kuenftig schneller, ist das eine
    Regression, die hier auffaellt statt in einem Docstring zu stehen.
    """

    D_FEST = 200          # klein genug fuer einen Suitenlauf, gross genug fuer einen echten Datenschwanz
    N_REIHE = (100, 1_000, 5_000)

    @staticmethod
    def _peak_bytes(n, d):
        daten = ["%064x" % i for i in range(d)]
        seq = [[ArchiveTimeStamp("sha256", HEX32, i + 1)] for i in range(n)]
        gc.collect()
        tracemalloc.start()
        pb.verify_sequence(seq, daten, allow_unauthenticated_anchor=True)
        _, spitze = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return spitze

    def test_speicher_ist_monoton_in_n_und_bleibt_unter_der_grenze(self):
        gemessen = {n: self._peak_bytes(n, self.D_FEST) for n in self.N_REIHE}
        werte = [gemessen[n] for n in self.N_REIHE]
        assert werte == sorted(werte), f"nicht monoton in N: {gemessen}"
        for n, b in gemessen.items():
            assert b <= SPEICHER_GRENZE_BYTES, (
                f"N={n}, D={self.D_FEST}: {b/1024/1024:.2f} MiB Spitzenverbrauch, Grenze "
                f"{SPEICHER_GRENZE_BYTES/1024/1024:.0f} MiB")

    def test_der_zuwachs_je_ats_bleibt_in_seiner_groessenordnung(self):
        """Die eigentliche Regressionsschranke. Der Zuwachs von der kleinsten zur groessten
        Kettenanfangszahl geteilt durch die Zahl zusaetzlicher ATS ist der Speicher, den EIN ATS
        kostet — bei der gemessenen Kurve rund 250 Byte je Eintrag. 4 KiB je ATS laesst reichlich
        Luft nach oben und faengt trotzdem eine Regression, die das Wachstum um eine
        Groessenordnung verschoebe (etwa weil wieder Tokens aufbewahrt wuerden statt nur gehasht)."""
        klein, gross = self.N_REIHE[0], self.N_REIHE[-1]
        zuwachs = self._peak_bytes(gross, self.D_FEST) - self._peak_bytes(klein, self.D_FEST)
        je_ats = zuwachs / (gross - klein)
        assert je_ats <= 4096, (
            f"{je_ats:.0f} Byte zusaetzlicher Spitzenverbrauch je ArchiveTimeStamp (von N={klein} auf "
            f"N={gross}, D={self.D_FEST}) — erwartet wird die Groessenordnung eines Check-Eintrags, "
            "nicht die eines aufbewahrten Tokens oder Praefix-Bytes")

    def test_die_gegenrichtung_der_datenschwanz_kostet_auch_etwas(self):
        """Anti-Tautologie: waere der Speicher von D voellig unabhaengig, wuerde der Test oben auch
        gruen bleiben, wenn ``_daten_bytes`` gar nicht existierte. Bei festem N muss ein groesserer
        Datenschwanz mehr kosten — sonst misst diese Klasse nicht, was sie zu messen glaubt."""
        n = 1_000
        klein = self._peak_bytes(n, 1)
        gross = self._peak_bytes(n, 2_000)
        assert gross > klein, (
            f"D=2000 kostet nicht mehr als D=1 (beide {klein} Byte) — der Datenschwanz taucht im "
            "Spitzenverbrauch gar nicht auf, die Messung greift also nicht an der erwarteten Stelle")


class TestDerDeckelIstAbgeleitetUndKeineGetippteZahl:
    """OWNER-AUFLAGE OA-0646ecdf70: „der Deckel kommt aus der Verteilung der Laeufe, keine getippte
    Zahl". Eine Auflage, die nur im Kommentar steht, ist eine Zusage — hier wird sie gebunden.

    GEPRUEFT WIRD DIE WIRKUNG, nicht der Wortlaut: der Deckel MUSS sich bewegen, wenn sich die
    Kopffreiheit der anderen Achsen bewegt. Eine getippte Konstante taete das nicht. Der Quelltext
    wird bewusst NICHT nach Zeichenketten durchsucht — genau diese Verwechslung hat in diesem Zyklus
    viermal zugeschlagen, zuletzt in einem Fix, der nach der verschaerften Reihenfolge gebaut wurde.
    """

    @staticmethod
    def _gefaelschte_aufzeichnung(kosten_je_dimension: dict) -> dict:
        """Ein Ersatz fuer die AUFZEICHNUNG der Referenzmaschine — die Quelle des Deckels.

        Getrennt von `_gefaelschte_messungen`, und das ist der ganze Punkt: seit dem 08.09.2026
        liest der Deckel die Aufzeichnung, nicht den laufenden Test. Wer den DECKEL steuern will,
        setzt hier an; wer die Kosten des laufenden Laufs stellen will, dort. Wer beides mit einem
        Griff faelscht, kann nicht mehr zeigen, dass die zwei Quellen getrennt sind — und genau
        diese Trennung ist der Fix.
        """
        vorher = dict(_REFERENZ_FARMER_KOSTEN)
        _REFERENZ_FARMER_KOSTEN.clear()
        _REFERENZ_FARMER_KOSTEN.update(kosten_je_dimension)
        return vorher

    def _gefaelschte_messungen(self, kosten_je_dimension: dict) -> dict:
        """Ein Ersatz fuer den Messungs-Cache: je Dimension die gewuenschten Kosten am Limit."""
        vorher = dict(_MESSUNGEN)
        _kl = _klammer_jetzt()   # durch eine ggf. aktive Faelschung hindurch
        for d in DIMENSIONEN:
            _MESSUNGEN[d.name] = {"limit": 1, "kosten_am_limit_max": kosten_je_dimension[d.name],
                                  "referenz_klammer": _kl[0],
                                  "referenz_klammer_frei": _kl[1],
                                  "rand": {}, "reihe": []}
        return vorher

    def test_der_deckel_FOLGT_der_kopffreiheit_der_anderen_achsen(self):
        """Wird eine ANDERE Achse teurer, muss der Deckel sinken. Eine Konstante taete das nicht.

        GESTELLT WIRD DIE AUFZEICHNUNG, nicht der laufende Test: seit dem 08.09.2026 kommt der
        Deckel aus den aufgezeichneten Kopffreiheiten der Referenzmaschine. Er soll der KOSTENFORM
        folgen — welche Achse wie viel Luft hat —, nicht der Tagesform der Maschine. Genau diese
        Verwechslung liess in CI alle zwoelf Dimensionen abstinieren.
        """
        vorher = dict(_REFERENZ_FARMER_KOSTEN)
        try:
            # Ausgangslage: jede Achse kostet ein Zehntel ihrer Latte -> Kopffreiheit 10 ueberall.
            self._gefaelschte_aufzeichnung(
                {d.name: (d.achsen * GRENZE_S) / 10.0 for d in DIMENSIONEN})
            weit = _faktor_deckel(ausser="renewal_work")
            # Jetzt wird EINE andere Achse zehnmal teurer -> ihre Kopffreiheit faellt auf 1.
            andere = next(d for d in DIMENSIONEN if d.name != "renewal_work")
            _REFERENZ_FARMER_KOSTEN[andere.name] = andere.achsen * GRENZE_S
            eng = _faktor_deckel(ausser="renewal_work")
        finally:
            _REFERENZ_FARMER_KOSTEN.clear()
            _REFERENZ_FARMER_KOSTEN.update(vorher)
        assert eng < weit, (
            f"Der Deckel bewegt sich NICHT mit der Kopffreiheit der anderen Achsen: weit={weit:.2f}, "
            f"eng={eng:.2f}. Dann ist er keine Ableitung aus der Verteilung dieses Laufs, sondern "
            f"eine Zahl, die zufaellig richtig aussieht — genau das, was die Owner-Auflage "
            f"ausschliesst.")
        assert eng == pytest.approx(1.0, rel=0.01), (
            f"Der Deckel ist {eng:.3f}, erwartet wird die kleinste Kopffreiheit (1,0). Er nimmt "
            f"also nicht das MINIMUM ueber die anderen Achsen.")

    def test_die_achse_unter_test_geht_NICHT_in_ihren_eigenen_deckel_ein(self):
        """Sonst waere der Deckel zirkulaer: eine teure Achse hoebe ihre eigene Erlaubnis."""
        vorher = dict(_REFERENZ_FARMER_KOSTEN)
        try:
            self._gefaelschte_aufzeichnung(
                {d.name: (d.achsen * GRENZE_S) / 10.0 for d in DIMENSIONEN})
            # renewal_work wird teuer, ABER NICHT REISSEND -> Kopffreiheit dort 2,0.
            #
            # FRUEHER STAND HIER DAS ZEHNFACHE, also Kopffreiheit 0,1 — und damit prueft der Fall
            # seine eigene Eigenschaft NICHT (dritte Linse, 08.09.2026, P0): eine Kopffreiheit unter
            # 1,0 faellt ohnehin durch den `frei >= 1.0`-Filter heraus, ganz gleich ob die
            # `ausser`-Ausnahme noch existiert. Die Linse entfernte `if d.name == ausser: continue`
            # komplett und ALLE SECHS Faelle blieben gruen. Mit Kopffreiheit 2,0 unterhalb der 10,0
            # der anderen Achsen ist die Ausnahme der EINZIGE Grund, warum sie nicht den Deckel setzt.
            rw = next(d for d in DIMENSIONEN if d.name == "renewal_work")
            _REFERENZ_FARMER_KOSTEN["renewal_work"] = (rw.achsen * GRENZE_S) / 2.0
            deckel = _faktor_deckel(ausser="renewal_work")
        finally:
            _REFERENZ_FARMER_KOSTEN.clear()
            _REFERENZ_FARMER_KOSTEN.update(vorher)
        assert deckel == pytest.approx(10.0, rel=0.01), (
            f"Der Deckel ist {deckel:.3f} statt 10,0 (die 2,0 von renewal_work waere durchgeschlagen) "
            f"— die Achse unter Test geht in ihren eigenen "
            f"Deckel ein. Dann duerfte eine teurer werdende Achse ihre eigene Latte anheben, und der "
            f"Riegel waere selbstbestaetigend.")

    def test_EINE_reissende_achse_bringt_die_anderen_NICHT_zum_schweigen(self):
        """GEFUNDEN VOM FANGNACHWEIS SELBST (2026-09-08), nicht von seiner Ansage.

        Die erste Fassung des Deckels nahm das MINIMUM ueber ALLE anderen Kopffreiheiten — auch ueber
        eine Achse, die selbst schon UEBER ihrer Latte liegt. Gemessen mit einer 17-fachen
        Kostensteigerung in `renewal_work`: dessen Kopffreiheit fiel auf 0,124, und weil es fuer die
        elf anderen eine der "anderen" ist, fiel deren Deckel mit — **1 failed, 11 skipped**. Der
        Schuldige wurde rot (sein eigener Deckel schliesst ihn aus), aber elf stumme Achsen sind ein
        lauter Ausfall, und ein stummer Riegel sieht von aussen aus wie ein bestandener.

        Angesagt war "1 von 12 faellt". Der Treffer stimmte, das Bild dahinter nicht: die 11 Skips
        standen direkt neben dem angesagten 1 failed und waeren beim blossen Abhaken der Ansage
        durchgerutscht. Die Lehre steht als Klasse 236 im Ledger.
        """
        # BLIND GEWORDEN UND WIEDER SEHEND (08.09.2026, gefunden von einer Gegenlesung): dieser Fall
        # faelschte `_MESSUNGEN`. Seit der Deckel aus der AUFZEICHNUNG kommt, erreichte seine
        # Faelschung die gepruefte Funktion nicht mehr — sie lief gegen die echte Aufzeichnung und
        # bestand deshalb IMMER. Gemessen: die Mutation `if frei >= 1.0:` -> `if True:`, also genau
        # die Entfernung des Filters, den dieser Fall verteidigt, liess 21 von 21 Faellen gruen.
        vorher = dict(_REFERENZ_FARMER_KOSTEN)
        try:
            self._gefaelschte_aufzeichnung(
                {d.name: (d.achsen * GRENZE_S) / 10.0 for d in DIMENSIONEN})
            gesund = _faktor_deckel(ausser="renewal_work")
            # EINE andere Achse reisst ihre eigene Latte um das Achtfache.
            reisst = next(d for d in DIMENSIONEN if d.name != "renewal_work")
            _REFERENZ_FARMER_KOSTEN[reisst.name] = reisst.achsen * GRENZE_S * 8
            trotzdem = _faktor_deckel(ausser="renewal_work")
            beteiligt = _deckel_beitraege("renewal_work")
        finally:
            _REFERENZ_FARMER_KOSTEN.clear()
            _REFERENZ_FARMER_KOSTEN.update(vorher)
        assert reisst.name not in beteiligt, (
            f"Die Achse {reisst.name} liegt selbst um das Achtfache ueber ihrer Latte "
            f"(Kopffreiheit 0,125) und ist trotzdem an der Deckelrechnung BETEILIGT "
            f"({beteiligt}). Eine Achse, die selbst schon reisst, darf keinen Deckel fuer die "
            f"anderen setzen — genau das brachte am 08.09. elf Achsen zum Schweigen.")
        assert trotzdem == pytest.approx(gesund, rel=0.01), (
            f"Eine einzige reissende Achse zieht den Deckel der anderen von {gesund:.2f} auf "
            f"{trotzdem:.2f}. Dann meldet ein einziger Ausfall die GANZE uebrige Matrix als NICHT "
            f"MESSBAR — und ein stummer Riegel ist von einem bestandenen nicht zu unterscheiden. "
            f"Eine Achse unter ihrer eigenen Grenze meldet sich in ihrem EIGENEN Fall; sie darf "
            f"keinen Deckel fuer andere setzen.")
        assert trotzdem > 1.0, (
            f"Der Deckel liegt bei {trotzdem:.2f} und damit nicht ueber dem kleinstmoeglichen "
            f"Maschinenfaktor 1,0 — dann schweigt die Matrix auch ohne reissende Achse.")

    def test_der_SKIP_PFAD_wird_wirklich_gegangen_nicht_nur_berechnet(self):
        """GEFUNDEN VON DER FREMDFAMILIAEREN GEGENLESUNG (2026-09-08), fuenfte Instanz derselben
        Klasse in einer Nacht.

        Die Faelle darueber pruefen die FORMEL `_faktor_deckel` — ob sie die richtige Zahl liefert.
        Keiner ruft die TESTMETHODE auf, und keiner prueft, dass ueber dem Deckel wirklich NICHT
        MESSBAR gemeldet wird. Die Linse nannte die Mutation: `_faktor_deckel` bleibt korrekt, aber
        der Vergleich `faktor > deckel` wird nie wahr — alle Faelle gruen, der Riegel stumm. Ein
        stummer Riegel ist von aussen von einem bestandenen nicht zu unterscheiden.

        Dieser Fall GEHT den Pfad: Maschinenfaktor ueber den Deckel, und die echte Testmethode muss
        UEBERSPRINGEN — nicht bestehen, nicht scheitern.
        """
        vorher_m = dict(_MESSUNGEN)
        vorher_r = list(_REFERENZ_HIER)
        # Die Kosten werden am MESSPFAD gesetzt, nicht in `_REFERENZ_HIER` hineingeschrieben: seit
        # dem Fix vom 08.09.2026 misst `_referenz_werte()` bei jedem Aufruf nach, geplante Werte
        # wuerden also von echten ueberlagert. Ein Fall, der Speicher statt Pfad stellt, misst dann
        # etwas anderes, als sein Name sagt.
        wieder, _ = self._referenz_kostet([statistics.median(_REFERENZ_FARMER_S) * 20.0])
        try:
            _kl = _klammer_jetzt()   # durch eine ggf. aktive Faelschung hindurch
            for d in DIMENSIONEN:
                _MESSUNGEN[d.name] = {"limit": 1, "rand": {}, "reihe": [],
                                      "kosten_am_limit_max": (d.achsen * GRENZE_S) / 1.5,
                                      "referenz_klammer": _kl[0],
                                      "referenz_klammer_frei": _kl[1]}
            _REFERENZ_HIER.clear()
            dim = next(d for d in DIMENSIONEN if d.name == "renewal_work")
            faktor = _maschinenfaktor()
            deckel = _faktor_deckel(ausser=dim.name)
            assert faktor > deckel, (
                f"VORBEDINGUNG: der Faktor ({faktor:.2f}) muss ueber dem Deckel ({deckel:.2f}) "
                f"liegen, sonst prueft dieser Fall den Skip-Pfad gar nicht.")
            fall = TestObergrenzeAmGroesstenZugelassenenWert()
            with pytest.raises(Skipped) as skip:
                with _bauhost_marke(None):   # die Marke gehoert dem FALL, nicht der Umgebung
                    fall.test_kosten_am_limit_unter_der_obergrenze(dim)
        finally:
            wieder()
            _MESSUNGEN.clear()
            _MESSUNGEN.update(vorher_m)
            _REFERENZ_HIER.clear()
            _REFERENZ_HIER.extend(vorher_r)
        text = str(skip.value)
        assert "NICHT MESSBAR" in text, (
            f"Ueber dem Deckel wird nicht NICHT MESSBAR gemeldet, sondern: {text!r}")
        assert f"{faktor:.2f}" in text and f"{deckel:.2f}" in text, (
            f"Die Meldung nennt Faktor und Deckel nicht — dann kann ein Leser nicht pruefen, WARUM "
            f"nicht gemessen wurde. Gemeldet wurde: {text!r}")

    def test_wenn_ALLE_achsen_reissen_wird_es_NICHT_still(self):
        """DIE KEHRSEITE DES FILTERS, benannt von der fremdfamiliaeren Gegenlesung (2026-09-08).

        Der Filter (nur Kopffreiheiten ab 1,0 gehen in den Deckel ein) reparierte den Fall, in dem
        EINE reissende Achse elf andere zum Schweigen brachte. Die Linse zeigte die andere Kante:
        reissen ALLE, ist die gefilterte Liste LEER, der Rueckfallwert war 1,0 — und jede Maschine
        mit einem Faktor ueber 1,0 meldet dann NICHT MESSBAR. Aus zwoelf ROT wuerden zwoelf STILLE,
        und ein stummer Riegel ist von aussen von einem bestandenen nicht zu unterscheiden.

        Ein Zustand, in dem JEDE Achse ueber ihrer Latte liegt, ist der lauteste Befund, den dieser
        Test haben kann. Er darf niemals als 'nicht messbar' erscheinen.
        """
        vorher_m = dict(_MESSUNGEN)
        vorher_r = list(_REFERENZ_HIER)
        vorher_a = dict(_REFERENZ_FARMER_KOSTEN)
        wieder, _ = self._referenz_kostet([statistics.median(_REFERENZ_FARMER_S) * 2.0])  # Faktor 2
        try:
            # ZWEI QUELLEN, ZWEI FAELSCHUNGEN — und bis zum 08.09.2026 faelschte dieser Fall nur
            # eine davon. Die Zusicherung liest die MESSUNG (`kosten_am_limit_max` aus
            # `_MESSUNGEN`), der Deckel liest die AUFZEICHNUNG (`_REFERENZ_FARMER_KOSTEN`). Seit der
            # Deckel migriert ist, lief er hier gegen die ECHTE Aufzeichnung — deren kleinste
            # Kopffreiheit ist rund 7,95, die Liste also nie leer, und der Rueckfallpfad, den dieser
            # Fall zu pruefen behauptet, wurde nie betreten. Gemessen von einer Gegenlesung: die
            # Mutation `return float("inf")` -> `return 1.0` liess 21 von 21 Faellen gruen.
            self._gefaelschte_aufzeichnung(
                {d.name: d.achsen * GRENZE_S * 5 for d in DIMENSIONEN})   # ALLE Freiheiten 0,2
            _kl = _klammer_jetzt()   # durch eine ggf. aktive Faelschung hindurch
            for d in DIMENSIONEN:  # ALLE deutlich ueber ihrer eigenen Latte
                # `rand` wird vom Diagnose-Text an drei Stellen gelesen (limit-1, limit, limit+1).
                # Eine Fixture, die es leer laesst, laesst den Fall an einem KeyError sterben statt
                # an der Zusicherung — die Messflaeche muss den Gegenstand abbilden, sonst misst der
                # Fall seinen eigenen Aufbau.
                _MESSUNGEN[d.name] = {
                    "limit": 1, "reihe": [],
                    "rand": {0: (0, 0.1, True), 1: (1, 0.2, True), 2: (2, 0.3, False)},
                    "kosten_am_limit_max": d.achsen * GRENZE_S * 5,
                    "referenz_klammer": _kl[0],
                    "referenz_klammer_frei": _kl[1]}
            _REFERENZ_HIER.clear()
            dim = next(d for d in DIMENSIONEN if d.name == "renewal_work")
            faktor = _maschinenfaktor()
            deckel = _faktor_deckel(ausser=dim.name)
            assert faktor > 1.0, "VORBEDINGUNG: der Faktor muss ueber 1,0 liegen"
            fall = TestObergrenzeAmGroesstenZugelassenenWert()
            # NICHT `pytest.raises(AssertionError)`: ein `Skipped` waere dort durchgereicht worden
            # und haette DIESEN Fall uebersprungen — die Stille haette sich in ihren eigenen
            # Nachweis fortgepflanzt. Gemessen beim ersten Anlauf: der Fall meldete `skipped`
            # statt zu fallen. Deshalb wird das Ergebnis EINGEFANGEN und danach beurteilt.
            ausgang = "kein Fehlschlag"
            try:
                with _bauhost_marke(None):   # die Marke gehoert dem FALL, nicht der Umgebung
                    fall.test_kosten_am_limit_unter_der_obergrenze(dim)
            except Skipped as s:
                ausgang = f"SKIP: {s}"
            except AssertionError as a:
                ausgang = f"ROT: {a}"
        finally:
            wieder()
            _MESSUNGEN.clear()
            _MESSUNGEN.update(vorher_m)
            _REFERENZ_HIER.clear()
            _REFERENZ_HIER.extend(vorher_r)
            _REFERENZ_FARMER_KOSTEN.clear()
            _REFERENZ_FARMER_KOSTEN.update(vorher_a)
        assert deckel == float("inf"), (
            f"VORBEDINGUNG: wenn ALLE Achsen reissen, ist die gefilterte Liste leer und der Deckel "
            f"muss unendlich sein — gemessen {deckel!r}. Ein endlicher Deckel hier heisst, dass die "
            f"Faelschung die Deckelquelle nicht erreicht hat und der Fall an der echten "
            f"Aufzeichnung vorbeimisst.")
        assert ausgang.startswith("ROT"), (
            f"Wenn ALLE Achsen reissen, muss der Fall ROT melden. Gemeldet wurde stattdessen: "
            f"{ausgang[:200]!r} (Deckel {deckel}, Faktor {faktor:.2f}). Das ist der lauteste "
            f"Befund, den dieser Test haben kann, und er verschwindet in der Stille.")

    @staticmethod
    def _referenz_kostet(kosten: list[float], kosten_frei: list[float] | None = None):
        """Ersetzt die MESSUNG der Referenzlast, nicht ihr Ergebnis.

        Die frueheren Faelle dieser Klasse schrieben direkt in `_REFERENZ_HIER` — damit umgingen sie
        `_referenz_werte()` und konnten dessen Cache-Riegel gar nicht sehen. Das ist die Lehre aus
        dem ersten, gruen gewordenen Anlauf dieses Fangnachweises am 08.09.2026: ein Fangnachweis,
        der am Speicher statt am PFAD ansetzt, prueft nicht die Stelle, die er benennt.

        Rueckgabe: (wiederherstellen, zaehler) — `zaehler["mess"]` zaehlt die echten Messungen.
        """
        alt_cpu, alt_last = _cpu, _referenzlast
        alt_frei = _referenzlast_hashfrei
        if kosten_frei is None:
            kosten_frei = kosten
        zaehler = {"mess": 0}
        zustand = {"laeuft": False, "i": 0, "j": 0, "welche": "hash"}

        def fake_cpu() -> float:
            # JEDE Messung startet bei 0,0 statt auf einer fortlaufenden Uhr. Eine fortlaufende
            # waere realistischer, aber die Differenz zweier grosser Gleitkommazahlen ist nicht mehr
            # exakt der bestellte Wert — gemessen 08.09.2026, als ein Fall Faktor und Deckel EXAKT
            # gleich setzen wollte und die Drift den Faktor knapp darueber schob. Ein Messwerkzeug,
            # dessen eigene Ungenauigkeit die gepruefte Groesse verschiebt, misst sich selbst mit.
            if not zustand["laeuft"]:
                zustand["laeuft"] = True
                return 0.0
            zustand["laeuft"] = False
            # WELCHE Last gerade lief, entscheidet die Kostenreihe. Die Last wird ZWISCHEN den
            # beiden Uhrablesungen gerufen, das Kennzeichen steht also fest, wenn hier gelesen wird.
            if zustand["welche"] == "frei":
                k = kosten_frei[zustand["j"] % len(kosten_frei)]
                zustand["j"] += 1
            else:
                k = kosten[zustand["i"] % len(kosten)]
                zustand["i"] += 1
            zaehler["mess"] += 1
            return k

        def fake_hash(n: int = 0) -> bytes:
            zustand["welche"] = "hash"
            return b""

        def fake_frei(n: int = 0) -> int:
            zustand["welche"] = "frei"
            return 0

        def wiederherstellen() -> None:
            globals().update(_cpu=alt_cpu, _referenzlast=alt_last,
                             _referenzlast_hashfrei=alt_frei)

        # ATOMAR und ganz am Schluss (zweite Linse, 08.09.2026): frueher standen hier zwei
        # getrennte Zuweisungen, und der Aufruf steht in jedem Fall VOR dessen `try`. Wuerde
        # zwischen den beiden Zuweisungen je etwas fliegen, bliebe die Haelfte des Patches stehen,
        # ohne dass der Aufrufer `wiederherstellen` je in die Hand bekaeme. Die Linse hat das
        # ausgefuehrt: ein Nachbarfall aus einer ANDEREN Klasse erbte den gefaelschten Zeitgeber und
        # meldete einen erfundenen 'Maschinenfaktor 20.00' als sauber aussehenden SKIP. Mit einem
        # einzigen `globals().update` als letzter Anweisung gibt es dieses Zwischenfenster nicht:
        # entweder ist nichts gepatcht, oder die Funktion ist zurueckgekehrt.
        globals().update(_cpu=fake_cpu, _referenzlast=fake_hash,
                         _referenzlast_hashfrei=fake_frei)
        return wiederherstellen, zaehler

    def test_der_maschinenfaktor_FRIERT_NICHT_auf_seiner_ersten_messung_EIN(self):
        """P0 DER ZWEITEN LINSE (08.09.2026) — und er verkehrt die Owner-Anordnung ins Gegenteil.

        `_referenz_werte()` mass nur, WENN `_REFERENZ_HIER` LEER WAR. Der Maschinenfaktor des ganzen
        Prozesses hing damit am Zufallsmoment seiner ERSTEN Messung. Eigene Nachmessung mit zwoelf
        Fremdprozessen: unter Last 1,2164 — nach deren Ende IMMER NOCH 1,2164 (Cache) — frisch
        1,0098. Verhaeltnis 1,205.

        WARUM DAS SCHLIMMER IST ALS EIN UNGENAUER WERT: die Wirkung geht in BEIDE Richtungen. Eine
        Lastspitze im Messmoment macht die Latte fuer den Rest des Laufs zu locker und verdeckt echte
        Regressionen. Eine ruhige Minute macht sie zu eng — und erzeugt damit genau den falschen
        Rotlauf, gegen den die Anordnung OA-0646ecdf70 gebaut wurde. Das Fix haette seinen eigenen
        Anlass reproduziert.

        Die Suite faehrt sequenziell in EINEM Prozess (kein xdist im Repo) und dauert dokumentiert
        1116 s — die Gefahr haengt an keiner besonderen Konfiguration, nur an einer Lastspitze im
        falschen Moment.
        """
        dort = statistics.median(_REFERENZ_FARMER_S)
        vorher = list(_REFERENZ_HIER)
        wieder, zaehler = self._referenz_kostet([dort * 3.0])
        try:
            _REFERENZ_HIER.clear()
            unter_last = _maschinenfaktor()
            assert unter_last == pytest.approx(3.0, rel=0.02), (
                f"VORBEDINGUNG: die kuenstlich langsame Messung muss einen Faktor um 3,0 geben, "
                f"gemessen {unter_last:.3f}")
            assert zaehler["mess"] >= 1, (
                "VORBEDINGUNG: es wurde ueberhaupt nicht gemessen — der Fall haengt dann an einem "
                "Speicherwert statt am Messpfad und beweist nichts.")
            assert all(w > 0 for w in _REFERENZ_HIER), (
                f"VORBEDINGUNG: mindestens eine Messung ist 0 ({_REFERENZ_HIER}). Dann ist der "
                f"gefaelschte Zeitgeber aus dem Takt (Start und Stopp vertauscht) und der Zaehler "
                f"zaehlt Aufrufe, die nichts gemessen haben. Die zweite Linse hat genau das "
                f"ausgefuehrt: EIN zusaetzlicher ungepaarter Aufruf laesst alle Deltas auf 0,0 "
                f"kollabieren, und `max(1.0, 0/dort)` gibt danach die 1,0, die der Medianfall "
                f"erwartet — der Fall bliebe gruen bei vollstaendig korrupter Messung. Ein Zaehler "
                f"zaehlt Aufrufe, er bindet keine Wirkung.")
            gemessen_erst = zaehler["mess"]
            wieder()
            wieder, zaehler = self._referenz_kostet([dort])   # Maschine wieder frei
            danach = _maschinenfaktor()
        finally:
            wieder()
            _REFERENZ_HIER.clear()
            _REFERENZ_HIER.extend(vorher)
        assert zaehler["mess"] >= 1, (
            f"Nach der ersten Messung wurde KEIN einziges Mal neu gemessen ({gemessen_erst} Messungen "
            f"beim ersten Aufruf, {zaehler['mess']} beim zweiten). Der Maschinenfaktor des ganzen "
            f"Laufs haengt damit am Zufallsmoment seines ersten Aufrufs.")
        assert danach < unter_last, (
            f"Der Maschinenfaktor bewegt sich NICHT, obwohl die Maschine messbar frei wurde: "
            f"{unter_last:.3f} vorher, {danach:.3f} nachher. Eine Lastspitze macht die Latte dann fuer "
            f"den Rest des Laufs zu locker, eine ruhige Minute zu eng — beides falsch.")

    def test_der_faktor_nimmt_den_MEDIAN_und_ein_ausreisser_hebt_die_latte_NICHT(self):
        """P1 der dritten Linse (08.09.2026): die Docstring von `_maschinenfaktor` verspricht den
        Median ausdruecklich („ein einzelner Ausreisser soll die Latte weder lockern noch
        verschaerfen") — und KEIN Fall band das. Die Linse ersetzte `statistics.median` durch `mean`
        und durch `max`: beide Male blieben alle sechs Faelle gruen, weil jeder von ihnen die Werte
        UNIFORM skalierte. Bei uniformer Skalierung sind Median, Mittel und Maximum gleich; die Wahl
        der Statistik war nie unterschieden.

        Hier kostet EINE Messung das Vierzigfache, alle anderen das Normale — das ist genau der Fall,
        gegen den der Median gewaehlt wurde: ein Cron-Job, der waehrend einer einzigen der neun
        Messungen anspringt, darf die Latte des ganzen Laufs nicht anheben.
        """
        dort = statistics.median(_REFERENZ_FARMER_S)
        vorher = list(_REFERENZ_HIER)
        muster = [dort] * (MAX_WIEDERHOLUNGEN - 1) + [dort * 40.0]
        wieder, zaehler = self._referenz_kostet(muster)
        try:
            _REFERENZ_HIER.clear()
            faktor = _maschinenfaktor()
            gemessene_werte = list(_REFERENZ_HIER)
        finally:
            wieder()
            _REFERENZ_HIER.clear()
            _REFERENZ_HIER.extend(vorher)
        assert zaehler["mess"] == MAX_WIEDERHOLUNGEN, (
            f"VORBEDINGUNG: erwartet {MAX_WIEDERHOLUNGEN} Messungen, gezaehlt {zaehler['mess']} — "
            f"sonst trifft der Ausreisser gar nicht die Verteilung, die der Median glaetten soll.")
        assert gemessene_werte and all(w > 0 for w in gemessene_werte), (
            f"VORBEDINGUNG: eine Messung ist 0 ({gemessene_werte}) — der gefaelschte Zeitgeber ist "
            f"aus dem Takt, und `max(1.0, 0/dort)` liefert genau die 1,0, die dieser Fall erwartet. "
            f"Er waere dann gruen bei vollstaendig korrupter Messung (zweite Linse, 08.09.2026).")
        assert max(gemessene_werte) / min(gemessene_werte) == pytest.approx(40.0, rel=0.01), (
            f"VORBEDINGUNG: der Ausreisser ist nicht vierzigmal so teuer wie die uebrigen, gemessen "
            f"{max(gemessene_werte) / min(gemessene_werte):.1f}fach.")
        assert faktor == pytest.approx(1.0, rel=0.02), (
            f"Der Faktor ist {faktor:.3f}, obwohl acht von neun Messungen dem Referenzwert entsprechen "
            f"und nur EINE das Vierzigfache kostet. Dann glaettet der Faktor keinen Ausreisser, "
            f"sondern folgt ihm — und ein einzelner Fremdprozess lockert die Latte des ganzen Laufs "
            f"um das Vielfache. Mittelwert gaebe {statistics.mean(muster) / dort:.2f}, Maximum "
            f"{max(muster) / dort:.2f}.")

    def test_eine_ZWEIGIPFLIGE_messreihe_meldet_NICHT_MESSBAR_statt_die_latte_zu_lockern(self):
        """DIE FREMDFAMILIAERE LINSE, 08.09.2026, Punkt 3 — und sie zielt auf den Fall darueber.

        Der Fall darueber bindet den Median gegen EINEN Ausreisser unter acht normalen Messungen. Die
        Linse nannte die Verteilung, bei der der Median GENAUSO versagt wie der Mittelwert: fuenf von
        neun Messungen langsam, vier normal. Dann liegt der Median IN der langsamen Gruppe, der
        Faktor folgt ihr, und die Latte lockert sich um das Fuenffache — still, denn ein Faktor von 5
        liegt unter dem abgeleiteten Deckel von 7,949. Real ist das ein Runner, auf dem ein
        Fremdjob in fuenf der neun Messfenster laeuft.

        Der Ausweg braucht keine getippte Schwelle. Die Frage ist nicht 'wie stark streut die
        Maschine', sondern: **haengt das Verdikt davon ab, welches Ende der eigenen Messstreuung man
        nimmt?** Liegen die Kosten zwischen der Latte am SCHNELLSTEN und der am LANGSAMSTEN Ende der
        Messreihe, dann sagt die Messung in beide Richtungen nichts — und das ist NICHT MESSBAR, nicht
        gruen. Auf einer ruhigen Maschine ist dieses Band so schmal wie die Streuung selbst (auf der
        Referenzmaschine 1,046), auf einer zweigipfligen so breit wie ihr Sprung.
        """
        vorher_m = dict(_MESSUNGEN)
        vorher_r = list(_REFERENZ_HIER)
        # WEG A WIRD HIER HERGESTELLT, NICHT VORAUSGESETZT (08.09.2026, Owner-Karte OA-133b901337).
        # Die Streuungs-Abstinenz, die dieser Fall bindet, GEHOERT zu Weg A: Weg B beantwortet ihre
        # Frage per Politik (immer das schnelle Ende) und schaltet sie deshalb ab. Seit der Owner
        # `schnellstes_ende` entschieden hat, ist Weg A nicht mehr die Vorbelegung — und der Fall
        # mass ohne diese Zeile eine ganz andere Eigenschaft als die, die sein Name nennt
        # (gemessen: ROT bei Faktor 1,00 statt der erwarteten Abstinenz). Die Eigenschaft bleibt
        # richtig und pruefbar; sie gilt nur fuer die Stellung, in der sie ueberhaupt existiert.
        vorher_s = LATTE_AUS_DER_KLAMMER
        globals()["LATTE_AUS_DER_KLAMMER"] = "median"
        dort = statistics.median(_REFERENZ_FARMER_S)
        # Fuenf langsame, vier normale Messungen — die Reihe wird zyklisch abgerufen, also gibt
        # dieses Muster bei neun Messungen genau 5x langsam und 4x normal.
        wieder, zaehler = self._referenz_kostet(
            [dort * 5.0, dort, dort * 5.0, dort, dort * 5.0, dort, dort * 5.0, dort, dort * 5.0])
        try:
            dim = next(d for d in DIMENSIONEN if d.name == "renewal_work")
            _kl = _klammer_jetzt()   # durch eine ggf. aktive Faelschung hindurch
            for d in DIMENSIONEN:
                _MESSUNGEN[d.name] = {
                    "limit": 1, "reihe": [],
                    "rand": {0: (0, 0.1, True), 1: (1, 0.2, True), 2: (2, 0.3, False)},
                    # Kosten beim Dreifachen der Grundlatte: ueber dem schnellen Ende (1,0),
                    # unter dem langsamen (10,0) — genau im Band, in dem die Streuung entscheidet.
                    "kosten_am_limit_max": d.achsen * GRENZE_S * 3.0,
                    "referenz_klammer": _kl[0],
                    "referenz_klammer_frei": _kl[1]}
            _REFERENZ_HIER.clear()
            # DER FAKTOR KOMMT AUS DER KLAMMER, nicht aus einer frischen Reihe. Die frische Messung
            # stand hier bis zum 08.09.2026 — und war im Kleinen genau der Fehler, den die Klammer
            # im Grossen behebt: ein Faktor aus einem ANDEREN Fenster als die Kosten daneben.
            faktor = _maschinenfaktor(_kl[0])
            assert faktor == pytest.approx(5.0, rel=0.02), (
                f"VORBEDINGUNG: bei fuenf von neun langsamen Messungen liegt der Median IN der "
                f"langsamen Gruppe, erwartet rund 5,0, gemessen {faktor:.2f} — sonst prueft dieser "
                f"Fall die benannte Verteilung gar nicht.")
            assert zaehler["mess"] == 2 * MAX_WIEDERHOLUNGEN, (
                f"VORBEDINGUNG: genau {2 * MAX_WIEDERHOLUNGEN} Messungen erwartet — die Klammer "
                f"misst BEIDE Kostenfamilien mit je {MAX_WIEDERHOLUNGEN} Laeufen, und sonst nichts. "
                f"Gezaehlt {zaehler['mess']}. Eine dritte Reihe hier waere ein Faktor aus einem "
                f"anderen Zeitfenster — der Fehler, gegen den die Klammer gebaut wurde.")
            fall = TestObergrenzeAmGroesstenZugelassenenWert()
            ausgang = "kein Fehlschlag"
            try:
                with _bauhost_marke(None):   # die Marke gehoert dem FALL, nicht der Umgebung
                    fall.test_kosten_am_limit_unter_der_obergrenze(dim)
            except Skipped as s:
                ausgang = f"SKIP: {s}"
            except AssertionError as a:
                ausgang = f"ROT: {a}"
        finally:
            globals()["LATTE_AUS_DER_KLAMMER"] = vorher_s
            wieder()
            _MESSUNGEN.clear()
            _MESSUNGEN.update(vorher_m)
            _REFERENZ_HIER.clear()
            _REFERENZ_HIER.extend(vorher_r)
        assert ausgang.startswith("SKIP") and "NICHT MESSBAR" in ausgang, (
            f"Bei einer zweigipfligen Messreihe (fuenf von neun Messungen fuenfmal langsamer) meldet "
            f"der Fall nicht NICHT MESSBAR, sondern: {ausgang[:300]!r}. Dann folgt die Latte dem "
            f"langsamen Gipfel und laesst das Zehnfache durch, ohne dass es jemand sieht — und ein "
            f"Faktor von 10 bleibt unter dem abgeleiteten Deckel, der Riegel darueber greift also "
            f"nicht.")
        assert "Streuung" in ausgang or "Messreihe" in ausgang, (
            f"Die Meldung nennt den Grund nicht — ein Leser kann dann nicht unterscheiden, ob der "
            f"Deckel oder die Streuung das Verdikt verhindert hat. Gemeldet: {ausgang[:300]!r}")

    def test_die_spanne_beschreibt_DIESELBE_messreihe_wie_der_median(self):
        """ANGESAGT UND GEMESSEN: diese Eigenschaft fing vorher NICHTS (Mutation C der Matrix,
        angesagt 0, gemessen 0 von 9).

        `_faktor_spanne()` rahmt den Median ein. Rahmt sie eine ANDERE Messreihe ein — weil sie
        `_referenz_werte()` ruft und damit neu misst — dann beschreiben Rahmen und Inhalt zwei
        verschiedene Zustaende der Maschine, und die Aussage 'das Verdikt haengt am Ende der Reihe'
        ist keine mehr. Die Mutation ist ein Einzeiler und hinterlaesst keine Spur im Verdikt: sie
        kostet nur Zeit und Sinn.

        Gebunden wird die WIRKUNG (die Reihe waechst nicht), nicht der Wortlaut.
        """
        vorher = list(_REFERENZ_HIER)
        wieder, zaehler = self._referenz_kostet([statistics.median(_REFERENZ_FARMER_S)])
        try:
            _REFERENZ_HIER.clear()
            _maschinenfaktor()
            nach_median = len(_REFERENZ_HIER)
            gemessen_nach_median = zaehler["mess"]
            unten, oben = _faktor_spanne()
            nach_spanne = len(_REFERENZ_HIER)
            gemessen_nach_spanne = zaehler["mess"]
            # INNERHALB des gepatchten Fensters ausgewertet. Frueher stand diese Zusicherung nach
            # dem `finally` und rief dort `_maschinenfaktor()` auf — also eine LIVE-Messung der
            # echten Maschine, mitten in einem Fall, der ueber eine gefaelschte Reihe urteilt.
            # Gemessen 08.09.2026: derselbe mutierte Stand gab in zwei Laeufen zwei verschiedene
            # Ergebnisse (2 gegen 3 gefallene Faelle). Ein Fangnachweis, der von der Tageslast
            # abhaengt, ist kein Nachweis.
            median_in_der_spanne = unten <= _maschinenfaktor() <= oben
            median_wert = _maschinenfaktor()
        finally:
            wieder()
            _REFERENZ_HIER.clear()
            _REFERENZ_HIER.extend(vorher)
        assert nach_median == MAX_WIEDERHOLUNGEN, (
            f"VORBEDINGUNG: nach dem Median stehen {nach_median} Werte in der Reihe, erwartet "
            f"{MAX_WIEDERHOLUNGEN} — sonst prueft dieser Fall den Zuwachs an der falschen Stelle.")
        assert gemessen_nach_median == MAX_WIEDERHOLUNGEN, (
            f"VORBEDINGUNG: {gemessen_nach_median} Messungen statt {MAX_WIEDERHOLUNGEN}.")
        # AM ZAEHLER GEBUNDEN, NICHT AN DER LAENGE (08.09.2026, eigene Matrix): solange die Reihe
        # angehaengt wurde, verriet die Laenge eine zweite Messung. Seit sie ERSETZT wird, bleibt die
        # Laenge gleich, und genau diese Mutation lief in der Matrix von 1 gefangenem Fall auf 0 —
        # angesagt 1, gemessen 0. Ein Riegel, dessen Messgroesse sich unter ihm wegdreht, ist stumm.
        assert gemessen_nach_spanne == gemessen_nach_median, (
            f"Die Spanne hat {gemessen_nach_spanne - gemessen_nach_median} zusaetzliche Messungen "
            f"ausgeloest — sie misst also NEU und rahmt eine andere Reihe ein als den Median, den sie "
            f"einrahmen soll. Rahmen und Inhalt beschreiben dann zwei verschiedene Zustaende der "
            f"Maschine, und die Aussage 'das Verdikt haengt am Ende DIESER Reihe' traegt nicht mehr.")
        assert nach_spanne == nach_median, (
            f"Die Messreihe ist von {nach_median} auf {nach_spanne} Werte gewachsen.")
        assert median_in_der_spanne, (
            f"Der Median ({median_wert:.3f}) liegt nicht in seiner eigenen Spanne "
            f"({unten:.3f} bis {oben:.3f}) — dann beschreiben Rahmen und Inhalt nicht dieselbe Reihe.")

    def test_jeder_aufruf_misst_seine_EIGENE_reihe_und_haeuft_NICHT_an(self):
        """DIE ERSTE LINSE, 08.09.2026, und sie widerlegt meine eigene Entwurfsentscheidung.

        Die erste Fassung des Fixes HING die Messungen an und nahm den Median ueber alles. Die Linse
        zeigte die Mutation, die dabei ALLE acht Faelle gruen laesst — ein `_REFERENZ_HIER.clear()`
        am Anfang der Funktion — und benannte, was die Anhaeufung wirklich anrichtet:

        * DRIFT: `_maschinenfaktor()` laeuft einmal je Dimension. Die erste saehe 9 Werte, die
          zwoelfte 108 — Achsen desselben Laufs an verschiedenen Latten, je nach Listenposition.
        * MASKIERUNG: ein Median folgt erst, wenn mehr als die Haelfte der Werte neu ist. Eigene
          Nachrechnung fuer eine echte fuenffache Verlangsamung ab Aufruf 11 von 12: die angehaeufte
          Reihe meldet fuer BEIDE betroffenen Dimensionen 1,000, die eigene Reihe je Aufruf 5,000.
          Die Latte bliebe eng, waehrend die Maschine wirklich langsam ist.

        Was hier gebunden wird, ist die WIRKUNG: nach zwei Aufrufen stehen genau
        `MAX_WIEDERHOLUNGEN` Werte in der Reihe, und sie stammen aus dem ZWEITEN Aufruf.
        """
        vorher = list(_REFERENZ_HIER)
        dort = statistics.median(_REFERENZ_FARMER_S)
        wieder, zaehler = self._referenz_kostet([dort * 3.0])
        try:
            _REFERENZ_HIER.clear()
            _referenz_werte()
            nach_eins = list(_REFERENZ_HIER)
            wieder()
            wieder, zaehler = self._referenz_kostet([dort * 7.0])
            _referenz_werte()
            nach_zwei = list(_REFERENZ_HIER)
        finally:
            wieder()
            _REFERENZ_HIER.clear()
            _REFERENZ_HIER.extend(vorher)
        assert len(nach_eins) == MAX_WIEDERHOLUNGEN, (
            f"VORBEDINGUNG: nach dem ersten Aufruf stehen {len(nach_eins)} Werte statt "
            f"{MAX_WIEDERHOLUNGEN} in der Reihe.")
        assert len(nach_zwei) == MAX_WIEDERHOLUNGEN, (
            f"Nach dem zweiten Aufruf stehen {len(nach_zwei)} Werte in der Reihe statt "
            f"{MAX_WIEDERHOLUNGEN} — die Messungen HAEUFEN sich an. Dann sieht die erste gepruefte "
            f"Dimension 9 Werte und die zwoelfte 108, und eine spaet einsetzende Verlangsamung wird "
            f"vom Median der frueheren Werte verdeckt: nachgerechnet meldet die angehaeufte Reihe "
            f"1,000, waehrend die Maschine fuenfmal langsamer ist.")
        assert all(w == pytest.approx(dort * 7.0, rel=0.01) for w in nach_zwei), (
            f"Die Reihe nach dem zweiten Aufruf traegt nicht dessen Kosten: erwartet rund "
            f"{dort * 7.0:.5f} s je Messung, gemessen {nach_zwei[:3]}. Dann beschreibt der Faktor "
            f"nicht das Zeitfenster, in dem die Kosten gemessen wurden, die er skaliert.")

    def test_der_deckel_rechnet_die_ACHSENZAHL_der_anderen_dimensionen_mit(self):
        """DRITTE LINSE, 08.09.2026, ueberlebender Mutant Nr. 1.

        `_faktor_deckel` rechnet die Kopffreiheit als `(d.achsen * GRENZE_S) / k`. Die Linse hat den
        Multiplikator entfernt — `GRENZE_S / k` — und ALLE acht Faelle blieben gruen. Der Grund ist
        eine Eigenheit der Fixtures, nicht des Codes: jeder Aufruf der Klasse setzte
        `ausser="renewal_work"`, und `renewal_work` ist die EINZIGE Dimension mit `achsen != 1`. Die
        einzige Achse, deren Multiplikator etwas aendert, war immer die ausgeschlossene — der
        Multiplikator war fuer die ganze Klasse unerreichbar.

        Hier wird eine EINACHSIGE Dimension ausgeschlossen, damit `renewal_work` mit seinen drei
        Achsen IN die Deckelberechnung eingeht und den Deckel setzt.
        """
        vorher = dict(_REFERENZ_FARMER_KOSTEN)
        try:
            rw = next(d for d in DIMENSIONEN if d.name == "renewal_work")
            assert rw.achsen == 3, f"VORBEDINGUNG: renewal_work hat {rw.achsen} Achsen, erwartet 3"
            assert all(d.achsen == 1 for d in DIMENSIONEN if d.name != "renewal_work"), (
                "VORBEDINGUNG: eine zweite Dimension hat mehr als eine Achse — dann prueft dieser "
                "Fall den Multiplikator nicht mehr isoliert.")
            self._gefaelschte_aufzeichnung(
                {d.name: (d.achsen * GRENZE_S) / 20.0 for d in DIMENSIONEN})
            # renewal_work bekommt Kosten, die OHNE den Multiplikator eine Kopffreiheit von 1,0
            # ergaeben und MIT ihm 3,0. Der Deckel ist das Minimum ueber die anderen (20,0) und
            # renewal_work — also 3,0 mit Multiplikator, 1,0 ohne (und 1,0 faellt durch den Filter).
            _REFERENZ_FARMER_KOSTEN["renewal_work"] = GRENZE_S
            einachsig = next(d for d in DIMENSIONEN if d.achsen == 1)
            deckel = _faktor_deckel(ausser=einachsig.name)
        finally:
            _REFERENZ_FARMER_KOSTEN.clear()
            _REFERENZ_FARMER_KOSTEN.update(vorher)
        assert deckel == pytest.approx(3.0, rel=0.01), (
            f"Der Deckel ist {deckel:.3f} statt 3,0. Die Achsenzahl der anderen Dimensionen geht "
            f"nicht in ihre Kopffreiheit ein — eine dreiachsige Dimension darf dreimal so viel "
            f"kosten wie eine einachsige, bevor sie reisst, und wer das weglaesst, setzt den Deckel "
            f"um genau diesen Faktor zu niedrig.")

    def test_eine_dimension_mit_kosten_NULL_setzt_keinen_deckel_und_wirft_nicht(self):
        """DRITTE LINSE, 08.09.2026, ueberlebender Mutant Nr. 2.

        `_faktor_deckel` ueberspringt Dimensionen mit `k <= 0`. Die Linse entfernte den Schutz und
        alle acht Faelle blieben gruen — keine Fixture setzt je Kosten von null. Real wird das, sobald
        eine Achse so billig ist, dass die Messung unter die Aufloesung der Uhr faellt: dann ist `k`
        eine echte Null, und ohne den Schutz stirbt der Deckel an einer Division durch null. Ein Riegel,
        der an einer Ausnahme stirbt, meldet nichts — er reisst den ganzen Lauf mit.
        """
        vorher = dict(_REFERENZ_FARMER_KOSTEN)
        try:
            self._gefaelschte_aufzeichnung(
                {d.name: (d.achsen * GRENZE_S) / 4.0 for d in DIMENSIONEN})
            billig = next(d for d in DIMENSIONEN if d.name not in ("renewal_work",))
            _REFERENZ_FARMER_KOSTEN[billig.name] = 0.0
            deckel = _faktor_deckel(ausser="renewal_work")
        finally:
            _REFERENZ_FARMER_KOSTEN.clear()
            _REFERENZ_FARMER_KOSTEN.update(vorher)
        assert deckel == pytest.approx(4.0, rel=0.01), (
            f"Der Deckel ist {deckel:.3f} statt 4,0 — die Dimension mit Kosten null hat ihn "
            f"veraendert, statt uebersprungen zu werden. Eine Kopffreiheit ist dort nicht definiert, "
            f"und der Riegel darf daran weder sterben noch sie mitrechnen.")

    def test_ein_faktor_GENAU_auf_dem_deckel_wird_noch_gemessen(self):
        """DRITTE LINSE, 08.09.2026, ueberlebender Mutant Nr. 3.

        `if faktor > deckel: skip`. Die Linse ersetzte das durch `>=` und alle acht Faelle blieben
        gruen — keine Fixture konstruiert Gleichheit, nur klar darueber oder klar darunter. Die Grenze
        ist aber eine Aussage: der Deckel ist die Dehnung, bei der die NAECHSTE Achse reisst; genau
        auf ihm reisst noch keine, also ist noch messbar. Wer die Grenze verschiebt, macht aus einem
        messbaren Fall stillschweigend ein NICHT MESSBAR — und ein stummer Riegel ist von einem
        bestandenen nicht zu unterscheiden.
        """
        vorher_m = dict(_MESSUNGEN)
        vorher_a = dict(_REFERENZ_FARMER_KOSTEN)
        vorher_r = list(_REFERENZ_HIER)
        dort = statistics.median(_REFERENZ_FARMER_S)
        wieder, _ = self._referenz_kostet([dort * 2.0])          # Faktor exakt 2,0
        try:
            dim = next(d for d in DIMENSIONEN if d.name == "renewal_work")
            # Der DECKEL kommt aus der Aufzeichnung: dort bekommt jede Achse die Kopffreiheit
            # exakt 2,0, damit der Deckel exakt 2,0 ist. Die Kosten des LAUFENDEN Tests werden
            # getrennt gestellt — genau diese Trennung ist der Fix vom 08.09.2026.
            self._gefaelschte_aufzeichnung(
                {d.name: (d.achsen * GRENZE_S) / 2.0 for d in DIMENSIONEN})
            _kl = _klammer_jetzt()   # durch eine ggf. aktive Faelschung hindurch
            for d in DIMENSIONEN:                                 # Kopffreiheit exakt 2,0
                _MESSUNGEN[d.name] = {
                    "limit": 1, "reihe": [],
                    "rand": {0: (0, 0.1, True), 1: (1, 0.2, True), 2: (2, 0.3, False)},
                    "kosten_am_limit_max": (d.achsen * GRENZE_S) / 2.0,
                    "referenz_klammer": _kl[0],
                    "referenz_klammer_frei": _kl[1]}
            _REFERENZ_HIER.clear()
            faktor = _maschinenfaktor()
            deckel = _faktor_deckel(ausser=dim.name)
            assert faktor == deckel, (
                f"VORBEDINGUNG: Faktor ({faktor!r}) und Deckel ({deckel!r}) muessen EXAKT gleich "
                f"sein, sonst prueft dieser Fall die Grenze gar nicht.")
            fall = TestObergrenzeAmGroesstenZugelassenenWert()
            ausgang = "kein Fehlschlag"
            try:
                with _bauhost_marke(None):   # die Marke gehoert dem FALL, nicht der Umgebung
                    fall.test_kosten_am_limit_unter_der_obergrenze(dim)
            except Skipped as s:
                ausgang = f"SKIP: {s}"
            except AssertionError as a:
                ausgang = f"ROT: {a}"
        finally:
            wieder()
            _MESSUNGEN.clear()
            _MESSUNGEN.update(vorher_m)
            _REFERENZ_FARMER_KOSTEN.clear()
            _REFERENZ_FARMER_KOSTEN.update(vorher_a)
            _REFERENZ_HIER.clear()
            _REFERENZ_HIER.extend(vorher_r)
        # GEMESSEN 08.09.2026, und der Fall stand vorher auf der falschen Seite seiner eigenen
        # Frage: er verlangte nur, dass die DECKEL-Meldung nicht dasteht. Jede ANDERE Abstinenz
        # erfuellte das ebenfalls — mit gesetzter Bauhost-Marke lief er gruen durch, waehrend die
        # Referenzmaschinen-Bindung gesprungen war und er nichts mehr gemessen hatte. Eine
        # Zusicherung ueber die Abwesenheit EINES Textes ist keine Aussage ueber den Ausgang.
        assert ausgang == "kein Fehlschlag", (
            f"Ein Faktor GENAU auf dem Deckel muss GEMESSEN werden — gemeldet wurde: "
            f"{ausgang[:300]!r}. Auf dem Deckel reisst noch keine andere Achse, der Fall ist dort "
            f"messbar, und die Grenze eines Riegels ist eine Aussage, keine Geschmacksfrage. "
            f"Verlangt wird hier das Urteil selbst und nicht die blosse Abwesenheit der "
            f"Deckel-Meldung: jede andere Abstinenz erfuellte die auch, und der Fall waere gruen, "
            f"ohne etwas gesehen zu haben.")

    def test_divergierende_KOSTENFAMILIEN_melden_NICHT_MESSBAR_statt_die_hash_zahl_zu_glauben(self):
        """DIE WIDERLEGUNG DER FREMDFAMILIAEREN LINSE, nachgerechnet 08.09.2026.

        Die Linse schrieb, eine unpassende Referenzfamilie koenne NUR falsches ROT erzeugen, 'weil
        der Faktor nur lockert'. Das gilt in EINER Richtung. Der Faktor ist `hash_hier/hash_ref`,
        die Achse braucht `A_hier/A_ref`; falsch GRUEN entsteht genau dann, wenn der Hash STAERKER
        verlangsamt ist als die Achse — das Profil einer Maschine ohne Hardware-SHA. Zahlenprobe:
        Hashfaktor 3,0 gegen einen echten Bedarf von 1,5 laesst die Latte fuer die sechs hash-freien
        Achsen dreifach zu locker.

        Der Ausweg ist derselbe wie bei der Streuung und braucht wieder keine getippte Schwelle:
        **kippt das Verdikt, je nachdem WELCHE Familie die Referenz misst?** Dann traegt die Messung
        es nicht, und das ist NICHT MESSBAR. Stimmen beide Familien ueberein — der Normalfall auf
        einer Maschine, deren Profil dem der Referenzmaschine aehnelt — aendert sich nichts.

        Hier ist die Maschine im Hash dreimal langsamer und in der Ganzzahl-Arithmetik gar nicht.
        Die Kosten liegen beim Doppelten der Grundlatte: ueber der hash-freien Latte (1,0), unter
        der Hash-Latte (3,0) — genau im Bereich, in dem die Familienwahl das Urteil bestimmt.
        """
        vorher_m = dict(_MESSUNGEN)
        vorher_h = list(_REFERENZ_HIER)
        vorher_f = list(_REFERENZ_HIER_HASHFREI)
        dort_h = statistics.median(_REFERENZ_FARMER_S)
        dort_f = statistics.median(_REFERENZ_FARMER_HASHFREI_S)
        wieder, _ = self._referenz_kostet([dort_h * 3.0], kosten_frei=[dort_f])
        try:
            dim = next(d for d in DIMENSIONEN if d.name == "renewal_work")
            _kl = _klammer_jetzt()   # durch eine ggf. aktive Faelschung hindurch
            for d in DIMENSIONEN:
                _MESSUNGEN[d.name] = {
                    "limit": 1, "reihe": [],
                    "rand": {0: (0, 0.1, True), 1: (1, 0.2, True), 2: (2, 0.3, False)},
                    "kosten_am_limit_max": d.achsen * GRENZE_S * 2.0,
                    "referenz_klammer": _kl[0],
                    "referenz_klammer_frei": _kl[1]}
            _REFERENZ_HIER.clear()
            _REFERENZ_HIER_HASHFREI.clear()
            f_hash = _maschinenfaktor()
            f_frei = _maschinenfaktor_hashfrei()
            assert f_hash == pytest.approx(3.0, rel=0.02), (
                f"VORBEDINGUNG: Hash-Faktor {f_hash:.2f} statt rund 3,0")
            assert f_frei == pytest.approx(1.0, rel=0.02), (
                f"VORBEDINGUNG: hash-freier Faktor {f_frei:.2f} statt rund 1,0")
            fall = TestObergrenzeAmGroesstenZugelassenenWert()
            ausgang = "kein Fehlschlag"
            try:
                with _bauhost_marke(None):   # die Marke gehoert dem FALL, nicht der Umgebung
                    fall.test_kosten_am_limit_unter_der_obergrenze(dim)
            except Skipped as s:
                ausgang = f"SKIP: {s}"
            except AssertionError as a:
                ausgang = f"ROT: {a}"
        finally:
            wieder()
            _MESSUNGEN.clear()
            _MESSUNGEN.update(vorher_m)
            _REFERENZ_HIER.clear()
            _REFERENZ_HIER.extend(vorher_h)
            _REFERENZ_HIER_HASHFREI.clear()
            _REFERENZ_HIER_HASHFREI.extend(vorher_f)
        assert ausgang.startswith("SKIP") and "NICHT MESSBAR" in ausgang, (
            f"Bei divergierenden Kostenfamilien (Hash dreimal langsamer, Ganzzahl-Arithmetik gar "
            f"nicht) meldet der Fall nicht NICHT MESSBAR, sondern: {ausgang[:300]!r}. Dann glaubt "
            f"die Latte der Hash-Zahl und laesst fuer sechs hash-freie Achsen das Dreifache durch — "
            f"ein falsches GRUEN, und zwar genau das, dessen Unmoeglichkeit die Gegenlesung "
            f"behauptet hat.")
        assert "Familie" in ausgang, (
            f"Die Meldung nennt den Grund nicht — ein Leser kann Deckel, Streuung und Familienwahl "
            f"dann nicht unterscheiden. Gemeldet: {ausgang[:300]!r}")

    def test_auch_die_HASHFREIE_familie_nimmt_den_MEDIAN(self):
        """DER NACHBAR, den ich beim Bau der zweiten Familie selbst benannt und zunaechst offen
        gelassen habe — und der beim ersten Anlauf 0 von 16 fing.

        `_maschinenfaktor_hashfrei` nimmt den Median aus demselben Grund wie seine Schwester: ein
        einzelner Fremdprozess waehrend EINER der neun Messungen darf die Latte nicht anheben. Alle
        Fixtures der zweiten Familie skalierten uniform, und bei uniformer Skalierung sind Median und
        Mittelwert gleich — die Wahl der Statistik war nicht unterschieden. Angesagt 0, gemessen 0.

        Das ist dieselbe Klasse, die bei der ERSTEN Familie schon einmal zugeschlagen hat. Eine
        Eigenschaft, die man beim Duplizieren mitnimmt, ist damit noch nicht gebunden.
        """
        vorher_h = list(_REFERENZ_HIER)
        vorher_f = list(_REFERENZ_HIER_HASHFREI)
        dort_f = statistics.median(_REFERENZ_FARMER_HASHFREI_S)
        muster = [dort_f] * (MAX_WIEDERHOLUNGEN - 1) + [dort_f * 40.0]
        wieder, _ = self._referenz_kostet([1.0], kosten_frei=muster)
        try:
            _REFERENZ_HIER_HASHFREI.clear()
            faktor = _maschinenfaktor_hashfrei()
            gemessen = list(_REFERENZ_HIER_HASHFREI)
        finally:
            wieder()
            _REFERENZ_HIER.clear()
            _REFERENZ_HIER.extend(vorher_h)
            _REFERENZ_HIER_HASHFREI.clear()
            _REFERENZ_HIER_HASHFREI.extend(vorher_f)
        assert len(gemessen) == MAX_WIEDERHOLUNGEN and all(w > 0 for w in gemessen), (
            f"VORBEDINGUNG: {len(gemessen)} Messwerte statt {MAX_WIEDERHOLUNGEN}, oder eine davon "
            f"null — dann ist der gefaelschte Zeitgeber aus dem Takt: {gemessen}")
        assert max(gemessen) / min(gemessen) == pytest.approx(40.0, rel=0.01), (
            f"VORBEDINGUNG: der Ausreisser ist nicht vierzigmal so teuer, gemessen "
            f"{max(gemessen) / min(gemessen):.1f}fach.")
        assert faktor == pytest.approx(1.0, rel=0.02), (
            f"Der hash-freie Faktor ist {faktor:.3f}, obwohl acht von neun Messungen dem "
            f"Referenzwert entsprechen und nur EINE das Vierzigfache kostet. Dann folgt er dem "
            f"Ausreisser statt ihn zu glaetten — und weil die Familien-Abstention BEIDE Faktoren "
            f"vergleicht, wuerde ein einzelner Fremdprozess in der zweiten Familie den ganzen Fall "
            f"zum Schweigen bringen. Mittelwert gaebe {statistics.mean(muster) / dort_f:.2f}.")

    def test_auch_der_HASHFREIE_faktor_hat_die_untergrenze_eins(self):
        """ANGESAGT UND GEMESSEN: diese Eigenschaft fing vorher NICHTS (Mutation C der Matrix zur
        zweiten Familie, angesagt 0, gemessen 0 von 15).

        Die Untergrenze 1,0 ist eine Owner-Auflage, und sie gilt fuer BEIDE Familien: eine
        schnellere Maschine darf die Latte nicht lockern. Beim hash-freien Faktor stand sie im Code,
        aber kein Fall band sie — `max(1.0, ...)` zu entfernen liess alle fuenfzehn gruen. Ohne die
        Untergrenze faellt der hash-freie Faktor auf einer schnellen Maschine unter 1,0, und dann
        DIVERGIEREN die Familien allein deshalb, weil eine von beiden nach unten ausbricht: aus der
        Abstention 'die Familien sind sich uneinig' wuerde ein Dauerzustand ohne Aussage.
        """
        vorher_h = list(_REFERENZ_HIER)
        vorher_f = list(_REFERENZ_HIER_HASHFREI)
        dort_f = statistics.median(_REFERENZ_FARMER_HASHFREI_S)
        wieder, _ = self._referenz_kostet([1.0], kosten_frei=[dort_f / 10.0])
        try:
            _REFERENZ_HIER_HASHFREI.clear()
            schnell = _maschinenfaktor_hashfrei()
            wieder()
            wieder, _ = self._referenz_kostet([1.0], kosten_frei=[dort_f * 4.0])
            _REFERENZ_HIER_HASHFREI.clear()
            langsam = _maschinenfaktor_hashfrei()
        finally:
            wieder()
            _REFERENZ_HIER.clear()
            _REFERENZ_HIER.extend(vorher_h)
            _REFERENZ_HIER_HASHFREI.clear()
            _REFERENZ_HIER_HASHFREI.extend(vorher_f)
        assert schnell == 1.0, (
            f"Auf einer zehnmal schnelleren Maschine gibt der hash-freie Faktor {schnell:.3f} statt "
            f"1,0 und LOCKERT damit die Latte. Die Untergrenze gilt fuer beide Familien — eine "
            f"schnelle Maschine macht die Zusicherung strenger, nie schwaecher.")
        assert langsam == pytest.approx(4.0, rel=0.01), (
            f"Auf einer viermal langsameren Maschine folgt der hash-freie Faktor der Messung nicht: "
            f"{langsam:.3f} statt rund 4,0.")

    def test_alle_punkte_der_kurve_werden_GLEICH_oft_gemessen(self):
        """GEFUNDEN VON EINER EIGENEN LASTPROBE, 08.09.2026 — und die Wurzel ist schaerfer als der
        erste Verdacht.

        Unter zwoelf Fremdlast-Schleifen meldete `test_die_kurve_ist_nicht_ueberlinear` fuer
        `renewal_work` einen Zeit-Exponenten von 1,31 gegen die Schranke 1,2 (in Ruhe: fuenf Laeufe,
        122 passed, 0 skipped). Die Kalibrierung faengt das nicht: sie skaliert eine SCHRANKE, der
        Exponent ist eine STEIGUNG — ein konstanter Faktor laesst die log-log-Steigung exakt
        unveraendert (S6: 1,044646 vor und nach x1,5).

        DER GRUND STEHT IN `_zeit_min`: wiederholt wird nur, wenn die Messung unter
        `WIEDERHOLEN_UNTER_S` liegt. Nachgemessen an der Reihe von `renewal_work`:

            n= 5000000  0,18084 s  WIEDERHOLT (Minimum aus 3)
            n=10000000  0,35690 s  EINMAL gemessen
            n=20000000  0,70984 s  EINMAL gemessen
            n=40000000  1,43139 s  EINMAL gemessen

        Der billigste Punkt bekommt also einen Rauschboden aus drei Laeufen, die drei teuren je einen
        aus EINEM. Unter Last wird der Einzelmesswert staerker aufgeblaeht als das Minimum aus drei —
        das Verhaeltnis k1/k0 waechst, und die Steigung mit ihm. Das ist kein Zufall, das ist
        bauartbedingt: **ein Steigungsschaetzer ueber ungleich behandelte Punkte ist verzerrt.**

        Gebunden wird deshalb die Gleichbehandlung, nicht die Zahl: JEDER Punkt der Reihe, aus der
        der Exponent kommt, wird gleich oft gemessen.
        """
        for dim in DIMENSIONEN:
            m = _messung(dim)
            zahlen = {w for _, _, _, w in m["reihe_wdh"]}
            assert len(zahlen) == 1, (
                f"{dim.name}: die vier Punkte der Kurve wurden UNTERSCHIEDLICH oft gemessen "
                f"({sorted(zahlen)}). Der Punkt mit den meisten Wiederholungen hat den tiefsten "
                f"Rauschboden; unter Last blaeht sich der einmal gemessene Punkt staerker auf, und "
                f"die Steigung zwischen beiden kippt. Gemessen 08.09.2026 unter zwoelf "
                f"Fremdlast-Schleifen: Zeit-Exponent 1,31 gegen die Schranke 1,2, waehrend fuenf "
                f"Ruhelaeufe je 122 passed / 0 skipped ergaben.")

    def test_der_deckel_FAELLT_NICHT_wenn_die_maschine_langsamer_wird(self):
        """DER SCHWERSTE FUND DIESER RUNDE, und er widerlegt meine eigene Erfolgsmeldung.

        Ich hatte berichtet, `coverage` sei gruen geworden, weil die Latte in Referenzeinheiten
        steht. Die Gegenlesung hat das mit Positionsbeweis widerlegt: im CI-Lauf am Kopf 88a5383
        stand '3871 passed, 40 skipped, 0 failed', das Skip-Delta gegen den Vorgaengerkopf war genau
        +12 — die Zahl der Dimensionen —, und die zwoelf Skip-Zeichen lagen an den Positionen 745 bis
        756, wo `--collect-only` genau diese zwoelf Faelle auffuehrt. **ALLE ZWOELF abstinierten,
        keine bestand.** Ein uebersprungener Fall ist von aussen von einem bestandenen nicht zu
        unterscheiden — der stumme Riegel, vor dem der Code selbst warnt.

        DIE URSACHE: der Deckel rechnete die Kopffreiheit aus den Kosten der anderen Achsen IM
        SELBEN LAUF. Wird die Maschine langsamer, steigen diese Kosten, also FAELLT der Deckel —
        waehrend der Maschinenfaktor STEIGT. Beide laufen aufeinander zu, und `faktor > deckel` wird
        genau dann wahr, wenn die Kalibrierung gebraucht wird. Eigene Lastprobe: in Ruhe Faktor rund
        1,0 gegen Deckel 19,54 und kein Skip in fuenf Laeufen; unter zwoelf Fremdlast-Schleifen
        Faktor 2,4 gegen Deckel 1,30 und acht Skips.

        Seither kommt der Deckel aus `_REFERENZ_FARMER_KOSTEN`, einer AUFZEICHNUNG. Gebunden wird
        hier die Wirkung: dieselbe Maschine, doppelt so langsam gemessen, ergibt denselben Deckel.
        """
        vorher = dict(_MESSUNGEN)
        vorher_a = dict(_REFERENZ_FARMER_KOSTEN)
        try:
            # Ein RUHIGER Lauf: jede Achse bei einem Zehntel ihrer Latte.
            self._gefaelschte_messungen({d.name: (d.achsen * GRENZE_S) / 10.0 for d in DIMENSIONEN})
            ruhig = _faktor_deckel(ausser="renewal_work")
            # DIESELBE Maschine unter Last: alle gemessenen Kosten verdoppelt.
            self._gefaelschte_messungen({d.name: (d.achsen * GRENZE_S) / 5.0 for d in DIMENSIONEN})
            belastet = _faktor_deckel(ausser="renewal_work")
            # DIE GEGENPROBE, und ohne sie war die Zusicherung darunter eine TAUTOLOGIE
            # (Gegenlesung 08.09.2026, ihr schaerfster Punkt — und er trifft meinen eigenen Text:
            # der Docstring nennt diesen Fall "DER SCHWERSTE FUND DIESER RUNDE"). `_faktor_deckel`
            # liest AUSSCHLIESSLICH `_REFERENZ_FARMER_KOSTEN` und NIE `_MESSUNGEN`. Die Faelschung
            # oben erreicht die gepruefte Funktion also gar nicht; `ruhig` und `belastet` werden
            # denknotwendig aus identischen Daten gerechnet und sind immer gleich. Als
            # Regressionswaechter taugt das (kaeme der Deckel je auf `_MESSUNGEN` zurueck, griffe
            # die Faelschung wieder) — aber es BEWEIST nicht, was der Docstring behauptet.
            #
            # Diese Zeilen machen daraus eine zweiseitige Aussage: der Deckel bewegt sich NICHT mit
            # der laufenden Messung UND er bewegt sich SEHR WOHL mit der Aufzeichnung. Ein Riegel,
            # der auf nichts reagiert, waere von einem, der auf das Richtige reagiert, sonst nicht
            # zu unterscheiden.
            self._gefaelschte_aufzeichnung(
                {d.name: (d.achsen * GRENZE_S) / 10.0 for d in DIMENSIONEN})
            aufzeichnung_weit = _faktor_deckel(ausser="renewal_work")
            self._gefaelschte_aufzeichnung(
                {d.name: (d.achsen * GRENZE_S) / 5.0 for d in DIMENSIONEN})
            aufzeichnung_eng = _faktor_deckel(ausser="renewal_work")
        finally:
            _MESSUNGEN.clear()
            _MESSUNGEN.update(vorher)
            _REFERENZ_FARMER_KOSTEN.clear()
            _REFERENZ_FARMER_KOSTEN.update(vorher_a)
        assert aufzeichnung_eng == pytest.approx(aufzeichnung_weit / 2.0, rel=0.01), (
            f"GEGENPROBE: verdoppelt man die AUFZEICHNUNG, muss der Deckel halbiert werden "
            f"({aufzeichnung_weit:.3f} -> erwartet {aufzeichnung_weit / 2.0:.3f}, gemessen "
            f"{aufzeichnung_eng:.3f}). Reagiert er auch darauf nicht, ist die Zusicherung darunter "
            f"keine Aussage ueber den Deckel, sondern ueber einen Riegel, der auf gar nichts "
            f"reagiert — und der ist von einem funktionierenden nicht zu unterscheiden.")
        assert belastet == pytest.approx(ruhig, rel=0.001), (
            f"Der Deckel faellt von {ruhig:.3f} auf {belastet:.3f}, wenn dieselbe Maschine doppelt "
            f"so langsam MISST. Dann sinkt die Schwelle der Abstention genau in dem Moment, in dem "
            f"der Maschinenfaktor steigt — beide laufen aufeinander zu, und der Riegel schweigt "
            f"genau dann, wenn er gebraucht wird. Am Kopf 88a5383 fuehrte das dazu, dass ALLE ZWOELF "
            f"Dimensionen in CI abstinierten und `coverage` gruen wurde, weil der einzige zuvor rote "
            f"Test sich aus der Bewertung herausgezogen hatte.")

    def test_der_schalter_der_offenen_OWNER_ENTSCHEIDUNG_wirkt_wirklich(self):
        """BEIDE WEGE DER — inzwischen ENTSCHIEDENEN — KARTE `OA-133b901337`, gebunden.

        Dass sie entschieden ist, aendert an diesem Fall nichts: er bindet, dass die Wahl UEBERHAUPT
        etwas entscheidet. Welche Stellung gilt, bindet ein eigener Fall
        (`test_die_OWNER_ENTSCHEIDUNG_zur_latte_steht_im_schalter`) — zwei Aussagen, zwei Faelle.

        Der Schalter `LATTE_AUS_DER_KLAMMER` soll die Owner-Entscheidung auf EIN WORT reduzieren.
        Ein Schalter, der nur im Kommentar steht, ist aber keine Entscheidung, sondern eine
        Behauptung — und genau diese Klasse hat diese Runde durchzogen. Dieser Fall faehrt DIESELBE
        Lage zweimal, einmal je Stellung, und verlangt UNTERSCHIEDLICHE Ausgaenge:

          "median"           -> NICHT MESSBAR (das Verdikt haengt davon ab, welches Ende man nimmt)
          "schnellstes_ende" -> ROT (die Latte steht am schnellen Ende, die Kosten liegen darueber)

        Waeren beide Ausgaenge gleich, waere der Schalter wirkungslos — und der Owner truefe eine
        Entscheidung, die nichts entscheidet.
        """
        dim = next(d for d in DIMENSIONEN if d.name == "renewal_work")
        limit = getattr(B, dim.name)
        ruhe = statistics.median(_REFERENZ_FARMER_S)
        ruhe_frei = statistics.median(_REFERENZ_FARMER_HASHFREI_S)
        vorher_m, vorher_s = dict(_MESSUNGEN), LATTE_AUS_DER_KLAMMER
        ausgaenge = {}
        try:
            for stellung in ("median", "schnellstes_ende"):
                globals()["LATTE_AUS_DER_KLAMMER"] = stellung
                _MESSUNGEN[dim.name] = {
                    "limit": limit, "reihe": [], "arbeit": [], "reihe_wdh": [],
                    "rand": {limit - 1: (limit - 1, 0.1, True), limit: (limit, 0.2, True),
                             limit + 1: (limit + 1, 0.3, False)},
                    "kosten_am_limit_max": dim.achsen * GRENZE_S * 5.0 / 3.0,
                    "referenz_klammer": ([ruhe] * MAX_WIEDERHOLUNGEN
                                         + [ruhe * 3.2] * MAX_WIEDERHOLUNGEN),
                    "referenz_klammer_frei": ([ruhe_frei] * MAX_WIEDERHOLUNGEN
                                              + [ruhe_frei * 3.2] * MAX_WIEDERHOLUNGEN),
                }
                fall = TestObergrenzeAmGroesstenZugelassenenWert()
                try:
                    with _bauhost_marke(None):   # die Marke gehoert dem FALL, nicht der Umgebung
                        fall.test_kosten_am_limit_unter_der_obergrenze(dim)
                    ausgaenge[stellung] = "STILLER PASS"
                except Skipped:
                    ausgaenge[stellung] = "NICHT MESSBAR"
                except AssertionError:
                    ausgaenge[stellung] = "ROT"
        finally:
            globals()["LATTE_AUS_DER_KLAMMER"] = vorher_s
            _MESSUNGEN.clear()
            _MESSUNGEN.update(vorher_m)
        assert ausgaenge["median"] == "NICHT MESSBAR", (
            f"Weg A muss bei wechselnder Last abstinieren, gemeldet: {ausgaenge['median']!r}")
        assert ausgaenge["schnellstes_ende"] == "ROT", (
            f"Weg B muss die echte Kostensteigerung ROT melden — das ist der ganze Unterschied zu "
            f"Weg A und der Grund, warum OA-0646ecdf70 ihn woertlich verlangt. Gemeldet: "
            f"{ausgaenge['schnellstes_ende']!r}")
        assert ausgaenge["median"] != ausgaenge["schnellstes_ende"], (
            f"Beide Stellungen ergeben denselben Ausgang ({ausgaenge}). Dann entscheidet die "
            f"Owner-Karte nichts, und der Schalter ist eine Behauptung statt einer Wahl.")

    def test_der_faktor_gehoert_INS_fenster_der_kosten_nicht_dahinter(self):
        """DER SCHWERSTE FUND DIESER RUNDE, von einer Gegenlesung mit einer ECHTEN Verteuerung.

        Sie baute eine echte dreifache Kostensteigerung in `renewal_work` (zusaetzliche kalibrierte
        sha256-Buerde, keine gefaelschte Zahl) und mass fuenf Laeufe: **2 von 5 liessen sie lautlos
        durch** — kein Rot, kein Skip, ein stiller Pass. Und zwar NICHT ueber eine der drei
        Abstinenzen, sondern an ihnen vorbei: die teure Kostenreihe wurde zuerst gemessen, der
        Maschinenfaktor DANACH. Faellt eine Lastspitze in genau dieses spaete Fenster, lockert sie die
        Latte, ohne die Kosten beruehrt zu haben — und die echte Regression passt darunter.

        Der Fall stellt das deterministisch nach, statt auf ein Rennen zu warten: die Kosten sind im
        RUHIGEN Fenster entstanden (Faktor 1,0), die spaete Referenzmessung sieht eine dreifach
        belastete Maschine (Faktor 3,2), und die Kosten liegen ZWISCHEN beiden Latten. Vor der
        Klammer urteilte nur das spaete Fenster: Latte 9,6 s, Kosten 5,0 s, stiller Pass.

        Was der Fall verlangt, ist ausdruecklich NICHT "rot", sondern "nicht still". Wenn die Maschine
        waehrend der Messung ihren Zustand wechselt, ist NICHT MESSBAR die ehrliche Antwort und ROT
        eine Behauptung ohne Grundlage — aber ein stiller Pass ist die eine Antwort, die es nicht
        geben darf. Ob die Latte stattdessen immer am schnellen Ende der Klammer stehen soll (dann
        bliebe es rot), ist eine Owner-Frage, keine Testfrage: sie verschaerft die Latte auf JEDER
        Maschine um die Streuung der Referenzlast.
        """
        dim = next(d for d in DIMENSIONEN if d.name == "renewal_work")
        limit = getattr(B, dim.name)
        ruhe = statistics.median(_REFERENZ_FARMER_S)
        ruhe_frei = statistics.median(_REFERENZ_FARMER_HASHFREI_S)
        vorher_m = dict(_MESSUNGEN)
        try:
            _MESSUNGEN[dim.name] = {
                "limit": limit, "reihe": [], "arbeit": [], "reihe_wdh": [],
                "rand": {limit - 1: (limit - 1, 0.1, True), limit: (limit, 0.2, True),
                         limit + 1: (limit + 1, 0.3, False)},
                # ECHTE Verteuerung: 5,0 s gegen eine Referenzlatte von 3 x 1,0 s.
                "kosten_am_limit_max": dim.achsen * GRENZE_S * 5.0 / 3.0,
                # Die Klammer SIEHT beide Fenster: ruhig gemessen, laut nachgemessen.
                "referenz_klammer": [ruhe] * MAX_WIEDERHOLUNGEN + [ruhe * 3.2] * MAX_WIEDERHOLUNGEN,
                "referenz_klammer_frei": ([ruhe_frei] * MAX_WIEDERHOLUNGEN
                                          + [ruhe_frei * 3.2] * MAX_WIEDERHOLUNGEN),
            }
            fall = TestObergrenzeAmGroesstenZugelassenenWert()
            ausgang = "STILLER PASS"
            try:
                with _bauhost_marke(None):   # die Marke gehoert dem FALL, nicht der Umgebung
                    fall.test_kosten_am_limit_unter_der_obergrenze(dim)
            except Skipped as s:
                ausgang = f"NICHT MESSBAR: {s}"
            except AssertionError as a:
                ausgang = f"ROT: {a}"
        finally:
            _MESSUNGEN.clear()
            _MESSUNGEN.update(vorher_m)
        # SEIT DEM OWNER-ENTSCHEID OA-133b901337 IST DIE FORDERUNG SCHAERFER. Solange Weg A galt,
        # war „nicht still" das Hoechste, was dieser Fall verlangen durfte: bei wechselndem
        # Maschinenzustand ist NICHT MESSBAR die ehrliche Antwort und ROT eine Behauptung ohne
        # Grundlage. Weg B beantwortet genau diese Frage — die Latte steht immer am schnellen Ende —
        # und damit ist die Antwort auf eine echte Verteuerung wieder ROT. Das ist die woertliche
        # Auflage aus OA-0646ecdf70 („eine echte Kostensteigerung bleibt trotz Faktor rot"), und
        # sie ist erst mit dieser Stellung des Schalters einloesbar.
        #
        # Die schwaechere Fassung (`!= "STILLER PASS"`) hat sich am 08.09.2026 messbar als blind
        # erwiesen: mit gesetzter Bauhost-Marke sprang die Referenzmaschinen-Bindung, der Fall sah
        # einen SKIP, und „nicht still" war erfuellt, ohne dass irgendetwas gemessen worden waere.
        assert ausgang.startswith("ROT"), (
            f"Eine echte Kostensteigerung auf das 1,67-fache der Latte wurde NICHT rot gemeldet "
            f"(gemeldet: {ausgang!r}). Die Kosten sind im ruhigen Fenster entstanden (Faktor 1,0), "
            f"die Latte kam aus dem lauten (Faktor 3,2) — der Faktor beschreibt eine Maschine, auf "
            f"der diese Kosten nie gemessen wurden. Genau so verschluckte das Tor in 2 von 5 "
            f"Laeufen eine echte Verdreifachung.")

    def test_die_KOMBI_latte_kennt_die_maschine_auf_der_sie_urteilt(self):
        """NEBENBEFUND EINER GEGENLESUNG (08.09.2026) — und er ist die Klasse dieser ganzen Runde.

        Die Einzelachsen haben seit OA-0646ecdf70 eine Latte in Referenzeinheiten: `achsen *
        GRENZE_S * Maschinenfaktor`, mit Deckel und Abstinenz. Die KOMBI-Flaeche wurde dabei nicht
        mitgezogen — sie prueft weiter `dauer <= achsen * GRENZE_S`, also gegen eine Zahl, die auf
        der Referenzmaschine gemessen wurde. Auf einem doppelt so langsamen Laeufer wird das rot,
        weil die Maschine langsam ist, nicht weil der Code teurer wurde. Genau dieser Defekt hat
        diese Runde ausgeloest, nur auf der anderen Flaeche.

        Der Fall stellt eine Maschine mit Faktor 1,8 her und legt eine Kombination hin, die das
        Anderthalbfache ihrer Referenzlatte kostet — auf dieser Maschine also INNERHALB. Er verlangt,
        dass die Kombi-Zusicherung das nicht als Fehlschlag meldet.

        WARUM 1,8 UND NICHT 2,0: der erste Anlauf nahm 2,0 und bekam eine ABSTINENZ statt eines
        Urteils — "Maschinenfaktor 2.00 ueber dem abgeleiteten Deckel 1.92". Das ist kein Fehler des
        Falles, sondern der Befund der Owner-Karte OA-dc37e26295, hier ein zweites Mal sichtbar: der
        Deckel aus der Aufzeichnung liegt bei 1,925, und ein CI-Laeufer mit Faktor 2 kann auch diese
        Flaeche nicht mehr beurteilen. Der Fall misst deshalb UNTERHALB des Deckels; die Frage, ob
        der Deckel dort richtig liegt, gehoert dem Owner, nicht diesem Test.
        """
        vorher_k = dict(_KOMBI_MESSUNGEN)
        vorher_r = list(_REFERENZ_HIER)
        wieder, _ = self._referenz_kostet([statistics.median(_REFERENZ_FARMER_S) * 1.8])
        try:
            name, achsen, bau = KOMBIS[0]
            _KOMBI_MESSUNGEN[name] = {"erreicht": {},
                                      "dauer_max": achsen * GRENZE_S * 1.5,
                                      "speicher_peak": 0}
            _REFERENZ_HIER.clear()
            faktor = _maschinenfaktor()
            fall = TestKombinierteAchsen()
            ausgang = "kein Fehlschlag"
            try:
                with _bauhost_marke(None):   # die Marke gehoert dem FALL, nicht der Umgebung
                    fall.test_kombi_bleibt_unter_der_summe_der_obergrenzen(name, achsen, bau)
            except Skipped as s:
                ausgang = f"SKIP: {s}"
            except AssertionError as a:
                ausgang = f"ROT: {a}"
            beteiligt = _deckel_beitraege("")   # WELCHE Achsen die Kombi-Latte gedeckelt haben
        finally:
            wieder()
            _KOMBI_MESSUNGEN.clear()
            _KOMBI_MESSUNGEN.update(vorher_k)
            _REFERENZ_HIER.clear()
            _REFERENZ_HIER.extend(vorher_r)
        assert 1.5 < faktor < _faktor_deckel(ausser=""), (
            f"VORBEDINGUNG: der Maschinenfaktor muss ueber 1,5 UND unter dem Deckel liegen, sonst "
            f"misst der Fall eine Abstinenz statt eines Urteils — ist {faktor:.2f}, Deckel "
            f"{_faktor_deckel(ausser=''):.2f}.")
        # DER DECKEL DER KOMBI-FLAECHE DARF KEINE ACHSE AUSNEHMEN — gegen ein unabhaengig
        # gerechnetes Soll gebunden, nicht gegen die eigene Liste (Gegenlesung 08.09.2026, und der
        # einzige tragfaehige ihrer vier Punkte). Eine Kombination ist keine der aufgezeichneten
        # Dimensionen; es gibt also nichts, was sich selbst begrenzen koennte, und jede Ausnahme
        # LOCKERT nur. Gemessen: `ausser=""` -> `ausser="renewal_work"` hebt den Deckel von 1,925
        # auf 7,95 und blieb bei 43 von 43 Faellen gruen.
        soll = {d.name for d in DIMENSIONEN
                if _REFERENZ_FARMER_KOSTEN.get(d.name, 0.0) > 0
                and (d.achsen * GRENZE_S) / _REFERENZ_FARMER_KOSTEN[d.name] >= 1.0}
        assert set(beteiligt) == soll, (
            f"Der Deckel der Kombi-Flaeche wurde aus {sorted(beteiligt)} gebildet, erwartet waren "
            f"{sorted(soll)}. Fehlt eine Achse, ist der Deckel LOCKERER als er sein darf — die "
            f"Differenz {sorted(soll - set(beteiligt))} nimmt genau die Achse heraus, die ihn "
            f"setzt, und dann abstiniert die Flaeche nicht mehr, wo sie abstinieren muss.")
        assert ausgang == "kein Fehlschlag", (
            f"Die Kombi-Zusicherung meldete {ausgang[:220]!r}. Die Kombination kostet das "
            f"1,5-fache ihrer Referenzlatte auf einer Maschine mit Faktor {faktor:.2f} — sie liegt "
            f"also INNERHALB. Meldet sie trotzdem, misst die Kombi-Latte die Maschine statt den "
            f"Code, und ein langsamer Laeufer erzeugt einen Befund, den es nicht gibt.")

    def test_das_instrument_der_kurvenreihe_wird_von_der_RANDMESSUNG_nicht_ueberschrieben(self):
        """FUND DERSELBEN GEGENLESUNG, Punkt 5 — und er ist heute schon wahr, nicht erst morgen.

        `_ZEIT_MIN_LAEUFE` sagt, wie viele Laeufe hinter EINEM Kurvenpunkt stehen. `_messung` leert
        die Liste vor dem Punkt, `_zeit_min_fest` schreibt hinein, `_messung` liest `[-1]`. BIS ZUM
        08.09.2026 schrieb `_zeit_min` — der Weg der Randmessung — in DIESELBE Liste; dass es nie
        schadete, rettete allein die Reihenfolge (die Randmessung laeuft nach dem Lesen), und jede
        Umstellung haette es gekippt. Seither hat `_zeit_min` sein eigenes `_RAND_LAEUFE`, und
        dieser Fall haelt die Trennung fest. Die Liste ist ein Instrument, kein Zustand, und ein
        Instrument, in das zwei Wege schreiben, misst keinen von beiden.

        Die Gegenleserin nannte auch, warum das keine Gegenlesung faengt: als Modul-Global sieht es
        nicht wie ein Fehler aus, sondern wie ein Log.
        """
        billig = lambda: 0  # noqa: E731 - absichtlich billig: der Wiederholungszweig soll greifen
        _ZEIT_MIN_LAEUFE.clear()
        _zeit_min_fest(billig, laeufe=2)
        assert _ZEIT_MIN_LAEUFE, (
            "VORBEDINGUNG: nach `_zeit_min_fest` ist das Instrument der Kurvenreihe LEER. Dann hat "
            "die feste Messung gar nicht hineingeschrieben — und `_messung` liest hier gleich einen "
            "Index, den es nicht gibt. (Diese Zeile steht hier, weil eine Gegenlesung genau diese "
            "Mutation vorschlug und behauptete, der Fall sehe sie nicht. Er sah sie — aber als "
            "IndexError, also ueber die Ausnahme statt ueber die Eigenschaft. Nachgemessen: "
            "1 failed in 0,47 s mit `IndexError: list index out of range`.)")
        vorher = _ZEIT_MIN_LAEUFE[-1]
        abzug = list(_ZEIT_MIN_LAEUFE)          # die GANZE Liste, nicht nur ihr Ende
        assert vorher == 2, f"VORBEDINGUNG: die Reihe meldet {vorher} statt 2 Laeufe."
        _zeit_min(billig)  # ein ANDERER Weg misst dazwischen
        assert list(_ZEIT_MIN_LAEUFE) == abzug, (
            f"Die Randmessung hat das Instrument der Kurvenreihe VERAENDERT: {abzug} -> "
            f"{list(_ZEIT_MIN_LAEUFE)}. Gebunden ist hier die TRENNUNG der beiden Schreibwege, "
            f"nicht die Stelle, an der geschrieben wird — eine Gegenlesung schlug am 08.09. "
            f"`insert(0, ...)` statt `append(...)` vor, und die frueherere Fassung dieses Falles, "
            f"die nur `[-1]` verglich, blieb dabei gruen.")
        nachher = _ZEIT_MIN_LAEUFE[-1]
        assert nachher == 2, (
            f"Das Instrument der Kurvenreihe meldet nach einer fremden Randmessung {nachher} statt "
            f"{vorher}. `_zeit_min` schreibt in dieselbe Liste, aus der `_messung` den Wert des "
            f"Kurvenpunktes liest. Heute haelt das nur die Reihenfolge der Aufrufe zusammen — das "
            f"ist keine Eigenschaft des Codes, sondern ein Zufall seiner Anordnung.")

    def test_eine_achse_mit_kosten_NULL_ist_gar_nicht_erst_BETEILIGT(self):
        """FUND DER FREMDFAMILIAEREN GEGENLESUNG (08.09.2026) — und ich hatte dagegen gewettet.

        Sie nannte die Mutation, die alles gruen laesst: `k = ...get(d.name, 0.0) or 0.0001`. Ich
        sagte an, der Nullkosten-Fall wuerde fallen. **Gemessen: 19 von 19 gruen.** Sie hatte recht.

        Der Grund ist schaerfer als ihre eigene Begruendung: `or` ersetzt NUR die Null, nicht jeden
        Wert. Die betroffene Achse bekommt damit eine Kopffreiheit von 1/0,0001 = 10000 — und die
        setzt den Deckel nie, weil der das MINIMUM nimmt. 'Uebersprungen' und 'mit riesiger Freiheit
        dabei' sind am ERGEBNIS nicht zu unterscheiden. Der bestehende Fall prueft das Ergebnis und
        kann den Unterschied deshalb prinzipiell nicht sehen.

        Was ihn sichtbar macht, ist die TEILNEHMERLISTE. Eine Achse ohne messbare Kosten hat keine
        definierte Kopffreiheit; sie darf nicht mitrechnen, auch nicht mit einem harmlosen Wert.
        """
        vorher = dict(_REFERENZ_FARMER_KOSTEN)
        try:
            self._gefaelschte_aufzeichnung(
                {d.name: (d.achsen * GRENZE_S) / 4.0 for d in DIMENSIONEN})
            billig = next(d for d in DIMENSIONEN if d.name != "renewal_work")
            _REFERENZ_FARMER_KOSTEN[billig.name] = 0.0
            deckel = _faktor_deckel(ausser="renewal_work")
            beteiligt = _deckel_beitraege("renewal_work")
        finally:
            _REFERENZ_FARMER_KOSTEN.clear()
            _REFERENZ_FARMER_KOSTEN.update(vorher)
        assert deckel == pytest.approx(4.0, rel=0.01), (
            f"VORBEDINGUNG: der Deckel ist {deckel:.3f} statt 4,0.")
        assert billig.name not in beteiligt, (
            f"Die Achse {billig.name} hat Kosten NULL und ist trotzdem an der Deckelrechnung "
            f"BETEILIGT ({beteiligt}). Eine Achse ohne messbare Kosten hat keine definierte "
            f"Kopffreiheit — sie darf nicht mitrechnen, auch nicht mit einem harmlos aussehenden "
            f"Ersatzwert. Am Deckel selbst ist der Unterschied nicht zu sehen, weil eine riesige "
            f"Kopffreiheit das Minimum nie setzt; genau deshalb blieben unter der Mutation "
            f"`k or 0.0001` alle neunzehn Faelle gruen.")
        assert len(beteiligt) == len(DIMENSIONEN) - 2, (
            f"Erwartet werden {len(DIMENSIONEN) - 2} beteiligte Achsen (alle ausser der geprueften "
            f"und der mit Kosten null), gezaehlt {len(beteiligt)}: {beteiligt}")

        # ZWEITER AUSSCHLUSSGRUND, und ohne ihn bindet die Liste nur die HAELFTE ihrer Aufgabe
        # (gefunden von einer Gegenlesung, 08.09.2026): eine Achse faellt auch dann heraus, wenn sie
        # zwar Kosten hat, aber SELBST SCHON ueber ihrer Latte liegt (0 < Kopffreiheit < 1,0). Der
        # Fall oben bindet nur Kosten=NULL; zieht man das `_DECKEL_BEITRAEGE.append` aus dem
        # `if frei >= 1.0`-Block heraus, bleibt er gruen — gemessen 21 von 21 gruen.
        vorher_z = dict(_REFERENZ_FARMER_KOSTEN)
        try:
            self._gefaelschte_aufzeichnung(
                {d.name: (d.achsen * GRENZE_S) / 4.0 for d in DIMENSIONEN})
            reisst = next(d for d in DIMENSIONEN if d.name != "renewal_work")
            _REFERENZ_FARMER_KOSTEN[reisst.name] = reisst.achsen * GRENZE_S * 8   # Freiheit 0,125
            _faktor_deckel(ausser="renewal_work")
            beteiligt_z = _deckel_beitraege("renewal_work")
        finally:
            _REFERENZ_FARMER_KOSTEN.clear()
            _REFERENZ_FARMER_KOSTEN.update(vorher_z)
        assert reisst.name not in beteiligt_z, (
            f"Die Achse {reisst.name} hat eine Kopffreiheit von 0,125 — sie liegt selbst um das "
            f"Achtfache ueber ihrer Latte — und steht trotzdem in der Teilnehmerliste "
            f"({beteiligt_z}). Die Liste soll sagen, WER das Minimum gebildet hat, nicht wer "
            f"ueberhaupt Kosten hat.")
        # DIE KARDINALITAET FEHLTE HIER (Gegenlesung 08.09.2026, Rang 1 ihrer Rangliste): der
        # Zwillingsblock darueber prueft BEIDES — dass die Achse fehlt UND wie viele uebrig sind.
        # Ohne die zweite Zeile bliebe dieser Block gruen, wenn die Liste aus einem ganz anderen
        # Grund falsch waere, solange nur `reisst.name` nicht darin steht. Dass die Mutation heute
        # trotzdem am ersten Block auffiele, ist eine Eigenschaft der Reihenfolge innerhalb dieser
        # Methode — keine Zusicherung dieser Zeile.
        assert len(beteiligt_z) == len(DIMENSIONEN) - 2, (
            f"Erwartet werden {len(DIMENSIONEN) - 2} beteiligte Achsen (alle ausser der geprueften "
            f"und der reissenden), gezaehlt {len(beteiligt_z)}: {beteiligt_z}")

    def test_der_maschinenfaktor_hat_eine_UNTERGRENZE_von_eins(self):
        """Eine SCHNELLERE Maschine darf die Latte nicht lockern (Owner-Auflage, Untergrenze 1,0)."""
        dort = statistics.median(_REFERENZ_FARMER_S)
        vorher = list(_REFERENZ_HIER)
        # Beide Phasen setzen am MESSPFAD an (siehe `_referenz_kostet`) — geplante Listenwerte
        # wuerden seit dem Fix vom 08.09.2026 von echten Messungen ueberlagert.
        wieder, _ = self._referenz_kostet([dort / 10.0])  # zehnmal schnellere Maschine
        try:
            _REFERENZ_HIER.clear()
            assert _maschinenfaktor() == 1.0, (
                "Auf einer schnelleren Maschine sinkt der Faktor unter 1 und LOCKERT die Latte. Die "
                "Untergrenze fehlt — eine schnelle Maschine muss die Zusicherung strenger machen, "
                "nie schwaecher.")
            wieder()
            wieder, _ = self._referenz_kostet([dort * 3.0])
            _REFERENZ_HIER.clear()
            assert _maschinenfaktor() == pytest.approx(3.0, rel=0.01), (
                "Auf einer langsameren Maschine folgt der Faktor der Messung nicht.")
        finally:
            wieder()
            _REFERENZ_HIER.clear()
            _REFERENZ_HIER.extend(vorher)

    def test_die_budget_achse_ist_auf_einem_BAUHOST_sichtbar_gebunden(self):
        """OWNER-ENTSCHEID OA-dc37e26295 (08.09.2026): „C, mit Bedingung — Budget-Achse
        referenzmaschinengebunden kennzeichnen, in CI sichtbar ueberspringen mit dem gemessenen
        Maschinenfaktor als Grund, auf der Referenzmaschine im Release-Buendel messen und so im
        Freigabebericht fuehren."

        WORAUF DIE ENTSCHEIDUNG ANTWORTET. Die CPU-Obergrenze ist in Referenzeinheiten
        ausgedrueckt, aber ihre Kalibrierung — die aufgezeichneten Kosten je Achse, der daraus
        abgeleitete Deckel — stammt von EINER Maschine. Auf einem rund doppelt so langsamen
        Laeufer laeuft der Maschinenfaktor gegen den Deckel (KOMBI-Deckel 1,925), und was dabei
        herauskommt, ist keine Aussage ueber den Code mehr: mal ein Rot aus Langsamkeit, mal eine
        Abstinenz. Der Owner nimmt die Achse deshalb dort aus der Bewertung — sichtbar, nicht
        stumm, und mit der GEMESSENEN Zahl als Grund, damit ein Leser sieht, WIE weit die Maschine
        von der Referenz entfernt war.

        WAS HIER GEBUNDEN WIRD, ist nicht der Wortlaut, sondern die Wirkung: dieselbe Lage, die
        auf der Referenzmaschine ROT ergibt, muss auf einem Bauhost UEBERSPRUNGEN werden — und die
        Meldung muss den gemessenen Faktor, die erkannte Marke und die Kartennummer tragen. Ohne
        die Kartennummer waere die Abstinenz von einem gewoehnlichen NICHT MESSBAR nicht zu
        unterscheiden, und der Freigabebericht koennte nicht sagen, WELCHE Entscheidung hier wirkt.
        """
        dim = next(d for d in DIMENSIONEN if d.name == "renewal_work")
        limit = getattr(B, dim.name)
        # Eine Maschine mit Faktor 2,0 — das gemessene Profil des Laeufers (input_bytes 1,8x,
        # json_nodes 2,1x, signatures 2,5x, data_digests 2,0x) — und Kosten, die auch DORT ueber
        # der Latte liegen: 4 x Grundlatte gegen 2 x Grundlatte. Ohne die Bindung ist das ROT.
        langsam = statistics.median(_REFERENZ_FARMER_S) * 2.0
        langsam_frei = statistics.median(_REFERENZ_FARMER_HASHFREI_S) * 2.0
        vorher_m = dict(_MESSUNGEN)
        ausgang = "STILLER PASS"
        try:
            _MESSUNGEN[dim.name] = {
                "limit": limit, "reihe": [], "arbeit": [], "reihe_wdh": [],
                "rand": {limit - 1: (limit - 1, 0.1, True), limit: (limit, 0.2, True),
                         limit + 1: (limit + 1, 0.3, False)},
                "kosten_am_limit_max": dim.achsen * GRENZE_S * 4.0,
                "referenz_klammer": [langsam] * (2 * MAX_WIEDERHOLUNGEN),
                "referenz_klammer_frei": [langsam_frei] * (2 * MAX_WIEDERHOLUNGEN),
            }
            fall = TestObergrenzeAmGroesstenZugelassenenWert()
            with _bauhost_marke("GITHUB_ACTIONS"):
                try:
                    fall.test_kosten_am_limit_unter_der_obergrenze(dim)
                except Skipped as s:
                    ausgang = f"SKIP: {s}"
                except AssertionError as a:
                    ausgang = f"ROT: {a}"
        finally:
            _MESSUNGEN.clear()
            _MESSUNGEN.update(vorher_m)
        assert ausgang.startswith("SKIP"), (
            f"Auf einem Bauhost muss die Budget-Achse SICHTBAR uebersprungen werden "
            f"(OA-dc37e26295). Gemeldet wurde stattdessen: {ausgang[:300]!r}. Ein Rot aus "
            f"Langsamkeit ist kein Befund ueber den Code — genau daran ist `coverage` am "
            f"07.09.2026 gescheitert, mit 3,096 s gegen eine Latte von 3,0 s.")
        assert "referenzmaschinengebunden" in ausgang, (
            f"Die Abstinenz nennt ihren Grund nicht als Referenzmaschinen-Bindung und ist damit "
            f"von einem gewoehnlichen NICHT MESSBAR (Deckel, Streuung, Kostenfamilie) nicht zu "
            f"unterscheiden: {ausgang[:300]!r}")
        assert "OA-dc37e26295" in ausgang, (
            f"Die Abstinenz nennt die Owner-Karte nicht, unter der sie steht — dann kann der "
            f"Freigabebericht nicht sagen, WELCHE Entscheidung hier wirkt: {ausgang[:300]!r}")
        assert "2.00" in ausgang, (
            f"Der GEMESSENE Maschinenfaktor (2,00) steht nicht in der Meldung. Genau das ist die "
            f"Bedingung der Owner-Karte: der Grund ist die gemessene Zahl, nicht das blosse "
            f"Vorhandensein einer Marke. Gemeldet: {ausgang[:300]!r}")
        assert "GITHUB_ACTIONS" in ausgang, (
            f"Die Meldung nennt die erkannte Marke nicht — dann ist von aussen nicht pruefbar, "
            f"WORAN die Umgebung als Bauhost erkannt wurde: {ausgang[:300]!r}")

    def test_die_KOMBI_achse_ist_auf_einem_BAUHOST_ebenso_gebunden(self):
        """DERSELBE ENTSCHEID AUF DER NACHBARFLAECHE — der Klassen-Sweep zu OA-dc37e26295.

        Die KOMBI-Flaeche misst dieselbe Groesse gegen dieselbe Kalibrierung; ihr Deckel (1,925,
        weil `ausser=""` keine Achse ausnimmt und `renewal_work` mit Kopffreiheit 1,925 das
        Minimum setzt) liegt sogar UNTER dem gemessenen Laeufer-Faktor von rund 2. Sie eine Runde
        spaeter nachzuziehen hiesse, dieselbe Klasse zweimal zu bezahlen — genau der Fehlermodus,
        gegen den der Anker FIX-THE-CLASS steht.

        Der Faktor ist hier 1,8 und nicht 2,0, damit der Fall das URTEIL prueft und nicht die
        Deckel-Abstinenz, die bei 2,0 ohnehin zuerst greift.
        """
        vorher_k = dict(_KOMBI_MESSUNGEN)
        vorher_r = list(_REFERENZ_HIER)
        wieder, _ = self._referenz_kostet([statistics.median(_REFERENZ_FARMER_S) * 1.8])
        ausgang = "STILLER PASS"
        try:
            name, achsen, bau = KOMBIS[0]
            # Das Dreifache der Referenzlatte: auch bei Faktor 1,8 klar darueber -> ohne die
            # Bindung ROT, und zwar aus Langsamkeit.
            _KOMBI_MESSUNGEN[name] = {"erreicht": {}, "dauer_max": achsen * GRENZE_S * 3.0,
                                      "speicher_peak": 0}
            _REFERENZ_HIER.clear()
            fall = TestKombinierteAchsen()
            with _bauhost_marke("CI"):
                try:
                    fall.test_kombi_bleibt_unter_der_summe_der_obergrenzen(name, achsen, bau)
                except Skipped as s:
                    ausgang = f"SKIP: {s}"
                except AssertionError as a:
                    ausgang = f"ROT: {a}"
        finally:
            wieder()
            _KOMBI_MESSUNGEN.clear()
            _KOMBI_MESSUNGEN.update(vorher_k)
            _REFERENZ_HIER.clear()
            _REFERENZ_HIER.extend(vorher_r)
        assert ausgang.startswith("SKIP") and "referenzmaschinengebunden" in ausgang, (
            f"Die KOMBI-Flaeche ist auf einem Bauhost NICHT referenzmaschinengebunden: "
            f"{ausgang[:300]!r}. Sie misst dieselbe Groesse gegen dieselbe Kalibrierung wie die "
            f"Einzelachsen — eine Bindung, die nur die eine Flaeche kennt, laesst die andere "
            f"genau den Fehlschlag erzeugen, den die Owner-Karte abstellt.")
        assert "OA-dc37e26295" in ausgang and "1.80" in ausgang, (
            f"Karte oder gemessener Faktor fehlen in der Meldung: {ausgang[:300]!r}")

    def test_die_OWNER_ENTSCHEIDUNG_zur_latte_steht_im_schalter(self):
        """OWNER-ENTSCHEID OA-133b901337 (08.09.2026): „schnellstes_ende, gilt auf der
        Referenzmaschine, CI ist nach der zweiten Antwort ausgenommen."

        Der Schalter `LATTE_AUS_DER_KLAMMER` wurde gebaut, damit diese Entscheidung EIN WORT
        kostet. Ein Wort, das niemand festhaelt, ist aber wieder eine Vorbelegung — und die naechste
        Runde, die an der Streuungs-Abstinenz arbeitet, stellt es beilaeufig zurueck, ohne dass
        etwas widerspricht. Gebunden wird deshalb der STAND mitsamt seiner Herkunft.

        Der Fall darueber (`test_der_schalter_..._wirkt_wirklich`) bindet, dass BEIDE Stellungen
        verschiedene Ausgaenge haben; dieser bindet, WELCHE davon gilt. Das sind zwei Aussagen,
        und die zweite ist die Owner-Entscheidung.
        """
        assert LATTE_AUS_DER_KLAMMER == "schnellstes_ende", (
            f"Der Schalter steht auf {LATTE_AUS_DER_KLAMMER!r}. Der Owner hat am 08.09.2026 unter "
            f"OA-133b901337 `schnellstes_ende` entschieden — Weg B, die Latte steht immer am "
            f"schnellen Ende der Klammer. Damit bleibt eine echte Kostensteigerung trotz "
            f"Maschinenfaktor rot (die woertliche Auflage aus OA-0646ecdf70), und der Preis "
            f"dafuer — falsche Rotlaeufe auf einer unruhigen Maschine — ist mit der "
            f"Referenzmaschinen-Bindung aus OA-dc37e26295 bezahlt, nicht ignoriert.")

    def test_das_bauhost_vokabular_ist_dasselbe_wie_im_signierweg(self):
        """KOPIE-DRIFT, gebunden statt gehofft.

        `_BAUHOST_MERKMALE` steht hier UND in `scripts/pre_tag_receipt.py`. Zwei Stellen mit
        demselben Wissen laufen auseinander, sobald eine gepflegt wird und die andere nicht — und
        kein Test faellt dabei auf, weil jeder genau eine der beiden Fassungen importiert. Genau
        diese Klasse hat am 08.09.2026 den Messfeld-Zeugen zweimal an derselben Stelle sterben
        lassen: der Fix lag in der einen Kopie, ausgefuehrt wurde die andere.

        Zusammenlegen waere die andere Loesung — sie scheitert daran, dass `scripts/` bewusst
        nicht im sdist liegt (siehe `test_sdist_ohne_signierwerkzeug`). Zwei Kopien mit einer
        gebundenen Gleichheit sind ehrlicher als eine Kopie mit einer Zusage.
        """
        import importlib.util
        q = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "pre_tag_receipt.py"
        if not q.is_file():
            pytest.skip("scripts/pre_tag_receipt.py liegt hier nicht (sdist ohne Repo-Kontext)")
        spec = importlib.util.spec_from_file_location("_ptr_vokabular", str(q))
        m = importlib.util.module_from_spec(spec)
        sys.modules["_ptr_vokabular"] = m
        spec.loader.exec_module(m)
        assert _BAUHOST_MERKMALE == m._BAUHOST_MERKMALE, (
            f"Das Bauhost-Vokabular ist auseinandergelaufen: hier {_BAUHOST_MERKMALE}, im "
            f"Signierweg {m._BAUHOST_MERKMALE}. Eine Marke, die nur eine der beiden Seiten kennt, "
            f"erzeugt genau die Luecke, die beide zu schliessen behaupten — der Signierweg liesse "
            f"einen Schluessel zu, wo diese Datei einen Bauhost sieht, oder umgekehrt.")

    def test_die_bindung_teilt_KEIN_erkennungswort_mit_den_anderen_abstinenzen(self):
        """GEMESSEN AM 08.09.2026, an sechs gefallenen und ZWEI blind bestandenen Faellen.

        Diese Datei hat vier Wege, aus einer Zusicherung herauszukommen: der Deckel, die Streuung,
        die Kostenfamilie — und seit `OA-dc37e26295` die Referenzmaschinen-Bindung. Die ersten drei
        sagen 'NICHT MESSBAR': die Messung liegt vor, sie traegt das Urteil nur nicht. Die vierte
        sagt etwas anderes — auf DIESER Maschine wird nicht bewertet —, und sie darf deshalb nicht
        dasselbe Wort benutzen.

        WARUM DAS EINE ZUSICHERUNG WERT IST und keine Stilfrage: jeder Fangnachweis dieser Datei
        prueft den WORTLAUT der Abstinenz, die er sucht ('Streuung', 'Familie', 'ueber dem
        abgeleiteten Deckel'). Truege die Bindung dieselben Worte, hielte jeder von ihnen sie fuer
        seinen eigenen Fund und bliebe gruen, ohne etwas gemessen zu haben. Gemessen wurde beides:
        weil die Bindung 'UEBERSPRUNGEN' statt 'NICHT MESSBAR' sagt, fielen vier Faelle sichtbar
        auf; die zwei, die nur auf die ABWESENHEIT eines Textes prueften, bestanden blind — und
        genau die sind daraufhin geschaerft worden.
        """
        dim = next(d for d in DIMENSIONEN if d.name == "renewal_work")
        limit = getattr(B, dim.name)
        ruhe = statistics.median(_REFERENZ_FARMER_S)
        ruhe_frei = statistics.median(_REFERENZ_FARMER_HASHFREI_S)
        vorher_m = dict(_MESSUNGEN)
        ausgang = "STILLER PASS"
        try:
            _MESSUNGEN[dim.name] = {
                "limit": limit, "reihe": [], "arbeit": [], "reihe_wdh": [],
                "rand": {limit - 1: (limit - 1, 0.1, True), limit: (limit, 0.2, True),
                         limit + 1: (limit + 1, 0.3, False)},
                "kosten_am_limit_max": dim.achsen * GRENZE_S * 4.0,
                "referenz_klammer": [ruhe * 2.0] * (2 * MAX_WIEDERHOLUNGEN),
                "referenz_klammer_frei": [ruhe_frei * 2.0] * (2 * MAX_WIEDERHOLUNGEN),
            }
            fall = TestObergrenzeAmGroesstenZugelassenenWert()
            with _bauhost_marke("BUILDKITE"):
                try:
                    fall.test_kosten_am_limit_unter_der_obergrenze(dim)
                except Skipped as s:
                    ausgang = str(s)
                except AssertionError as a:
                    ausgang = f"ROT: {a}"
        finally:
            _MESSUNGEN.clear()
            _MESSUNGEN.update(vorher_m)
        assert "referenzmaschinengebunden" in ausgang, (
            f"VORBEDINGUNG: die Bindung hat gar nicht gegriffen, gemeldet: {ausgang[:200]!r}")
        for wort in ("NICHT MESSBAR", "Streuung", "Messreihe", "Familie",
                     "ueber dem abgeleiteten Deckel"):
            assert wort not in ausgang, (
                f"Die Meldung der Referenzmaschinen-Bindung enthaelt {wort!r} — das Erkennungswort "
                f"einer ANDEREN Abstinenz dieser Datei. Jeder Fangnachweis, der darauf prueft, "
                f"haelt die Bindung dann fuer seinen eigenen Fund und bleibt gruen, ohne etwas "
                f"gemessen zu haben. Gemessen am 08.09.2026: genau so bestanden zwei Faelle blind. "
                f"Gemeldet wurde: {ausgang[:300]!r}")

    def test_eine_teilnehmerliste_ohne_eigene_rechnung_wird_nicht_gelesen(self):
        """DER FUND, DEN ICH NICHT ANGESAGT HATTE (08.09.2026).

        `test_die_KOMBI_latte_kennt_die_maschine_auf_der_sie_urteilt` fiel unter einer gesetzten
        Bauhost-Marke — aber nicht an seiner Zusicherung, sondern daran, dass er die
        Teilnehmerliste eines FREMDEN Deckel-Aufrufs las (`ausser="renewal_work"` statt
        `ausser=""`). Der Grund: die Referenzmaschinen-Bindung springt VOR `_faktor_deckel`, es
        rechnete also niemand mehr, und `_DECKEL_BEITRAEGE` behielt den Stand von vorher.

        Er fiel — diesmal. Waere der fremde Stand zufaellig der erwartete gewesen, waere er GRUEN
        geblieben und haette eine Rechnung bezeugt, die nie stattgefunden hat. Ein Modul-Global, das
        seinen Eigentuemer nicht kennt, ist kein Instrument, sondern ein Rest; dieselbe Klasse wie
        `_ZEIT_MIN_LAEUFE`, in das zwei Wege schrieben.

        Gebunden werden beide Kanten: eine Liste ohne eigene Rechnung wird nicht gelesen, und
        DIESELBE Rechnung wird nicht zweimal als die eigene ausgegeben.
        """
        vorher = dict(_REFERENZ_FARMER_KOSTEN)
        try:
            self._gefaelschte_aufzeichnung(
                {d.name: (d.achsen * GRENZE_S) / 4.0 for d in DIMENSIONEN})
            _faktor_deckel(ausser="renewal_work")
            with pytest.raises(AssertionError) as fremd:
                _deckel_beitraege("")
            assert "gehoert zu ausser='renewal_work'" in str(fremd.value), (
                f"Die Absage nennt nicht, WEM die Liste gehoert: {str(fremd.value)[:200]!r}")
            # Die eigene Rechnung wird gelesen — einmal.
            _faktor_deckel(ausser="renewal_work")
            erste = _deckel_beitraege("renewal_work")
            assert erste, "VORBEDINGUNG: die eigene Rechnung liefert eine leere Liste"
            with pytest.raises(AssertionError) as zweitmal:
                _deckel_beitraege("renewal_work")
            assert "gehoert zu ausser=None" in str(zweitmal.value), (
                f"Ein zweiter Leser bekommt dieselbe Rechnung noch einmal als seine: "
                f"{str(zweitmal.value)[:200]!r}. Genau so bleibt ein veralteter Wert unauffaellig.")
        finally:
            _REFERENZ_FARMER_KOSTEN.clear()
            _REFERENZ_FARMER_KOSTEN.update(vorher)
            _DECKEL_FUER[0] = None

    def test_die_hashfreie_spanne_teilt_durch_ihre_EIGENE_aufzeichnung(self):
        """DER FANGNACHWEIS, DEN DIE ZWEITE LINSE VERLANGT HAT (08.09.2026) — und ihr Punkt war,
        dass ihn keine Fixture dieser Datei fuehren konnte.

        Weg B der hash-freien Familie stand bis heute als HANDGESCHRIEBENE Kopie von
        `_faktor_spanne` in der Zusicherung. Die Linse rechnete nach: vertauscht man dort
        `_REFERENZ_FARMER_HASHFREI_S` mit `_REFERENZ_FARMER_S` — ein naheliegender Griff, die
        Nachbarzeile nennt die andere Konstante —, bleibt JEDE Fixture dieser Datei gruen. Nicht
        zufaellig: alle halten den hash-freien Messwert bei oder unter beiden Konstanten, und
        `max(1.0, ...)` schluckt die Differenz dann strukturell. Gemessen an ihrem Beispiel:
        korrekt 0,06458/0,06458 = 1,000, vertauscht 0,06458/0,06781 = 0,952 — beide werden von der
        Untergrenze auf exakt 1,0 gehoben, und keine Zusicherung sieht einen Unterschied.

        DIESER Fall waehlt die Reihe so, dass die Untergrenze NICHT greift: das Minimum liegt weit
        ueber BEIDEN Konstanten, also unterscheiden sich die zwei Nenner im Ergebnis. Die beiden
        Aufzeichnungen liegen nur 5 % auseinander (0,06458 gegen 0,06781) — die Zusicherung muss
        deshalb enger sein als dieser Abstand, sonst prueft sie ihn nicht.
        """
        dort_f = statistics.median(_REFERENZ_FARMER_HASHFREI_S)
        dort_h = statistics.median(_REFERENZ_FARMER_S)
        assert dort_f != dort_h, (
            "VORBEDINGUNG: die beiden Aufzeichnungen sind identisch — dann kann dieser Fall die "
            "Nenner gar nicht unterscheiden und beweist nichts.")
        # Zehnmal die hash-freie Aufzeichnung: klar ueber beiden Konstanten, Untergrenze inaktiv.
        reihe = [dort_f * 10.0] * MAX_WIEDERHOLUNGEN
        unten, oben = _faktor_spanne_hashfrei(reihe)
        assert unten == pytest.approx(10.0, rel=1e-6), (
            f"Die hash-freie Spanne meldet {unten:.4f} statt exakt 10,0. Sie teilt also nicht durch "
            f"ihre EIGENE Aufzeichnung ({dort_f:.5f}), sondern durch eine fremde — mit der "
            f"Hash-Aufzeichnung ({dort_h:.5f}) kaeme {dort_f * 10.0 / dort_h:.4f} heraus. Der "
            f"Unterschied betraegt nur rund 5 %, und genau deshalb faellt er in keiner anderen "
            f"Fixture auf: dort hebt `max(1.0, ...)` beide Ergebnisse auf 1,0.")
        assert oben == pytest.approx(10.0, rel=1e-6)
        # Und die Hash-Familie teilt durch IHRE — sonst waere die Trennung nur halb gebunden.
        h_unten, _ = _faktor_spanne([dort_h * 10.0] * MAX_WIEDERHOLUNGEN)
        assert h_unten == pytest.approx(10.0, rel=1e-6), (
            f"Die Hash-Spanne meldet {h_unten:.4f} statt 10,0 — sie teilt durch die falsche "
            f"Aufzeichnung. Die Bindung muss BEIDE Richtungen halten, sonst verschiebt ein Fix an "
            f"einer Familie die andere unbemerkt mit.")

    def test_die_ZUSICHERUNG_benutzt_fuer_beide_familien_dieselbe_rechenvorschrift(self):
        """DIE KLASSE, nicht die Instanz (Anker FIX-THE-CLASS).

        Der Fall darueber bindet, dass jede Familie durch ihre eigene Aufzeichnung teilt. Er wuerde
        aber gruen bleiben, wenn jemand die Formel EIN DRITTES Mal von Hand in die Zusicherung
        schriebe — die Funktion waere dann weiter richtig und die Zusicherung trotzdem falsch. Was
        hier gebunden wird, ist deshalb die IDENTITAET der Wege: der hash-freie Weg-B-Faktor der
        Zusicherung muss ZAHLENGLEICH dem sein, was `_faktor_spanne_hashfrei` liefert.

        Gemessen wird das ueber eine Klammer, deren Minimum die Untergrenze nicht ausloest — sonst
        stimmen alle Wege bei 1,0 ueberein und die Bindung ist wieder blind.
        """
        dim = next(d for d in DIMENSIONEN if d.name == "renewal_work")
        limit = getattr(B, dim.name)
        dort_h = statistics.median(_REFERENZ_FARMER_S)
        dort_f = statistics.median(_REFERENZ_FARMER_HASHFREI_S)
        klammer_h = [dort_h * 4.0] * (2 * MAX_WIEDERHOLUNGEN)
        klammer_f = [dort_f * 4.0] * (2 * MAX_WIEDERHOLUNGEN)
        vorher_m, vorher_s = dict(_MESSUNGEN), LATTE_AUS_DER_KLAMMER
        try:
            globals()["LATTE_AUS_DER_KLAMMER"] = "schnellstes_ende"
            _MESSUNGEN[dim.name] = {
                "limit": limit, "reihe": [], "arbeit": [], "reihe_wdh": [],
                "rand": {limit - 1: (limit - 1, 0.1, True), limit: (limit, 0.2, True),
                         limit + 1: (limit + 1, 0.3, False)},
                # Kosten UNTER beiden Latten (4 x 3 = 12 s) -> kein Rot, keine Familien-Abstinenz.
                "kosten_am_limit_max": dim.achsen * GRENZE_S * 2.0,
                "referenz_klammer": klammer_h, "referenz_klammer_frei": klammer_f,
            }
            fall = TestObergrenzeAmGroesstenZugelassenenWert()
            ausgang = "kein Fehlschlag"
            with _bauhost_marke(None):
                try:
                    fall.test_kosten_am_limit_unter_der_obergrenze(dim)
                except Skipped as s:
                    ausgang = f"SKIP: {s}"
                except AssertionError as a:
                    ausgang = f"ROT: {a}"
        finally:
            globals()["LATTE_AUS_DER_KLAMMER"] = vorher_s
            _MESSUNGEN.clear()
            _MESSUNGEN.update(vorher_m)
        assert _faktor_spanne_hashfrei(klammer_f)[0] == pytest.approx(4.0, rel=1e-6), (
            "VORBEDINGUNG: der hash-freie Faktor der gestellten Klammer ist nicht 4,0.")
        assert _faktor_spanne(klammer_h)[0] == pytest.approx(4.0, rel=1e-6), (
            "VORBEDINGUNG: der Hash-Faktor der gestellten Klammer ist nicht 4,0.")
        assert ausgang == "kein Fehlschlag", (
            f"Beide Familien melden bei Faktor 4,0 dieselbe Latte (12,0 s) und die Kosten liegen "
            f"mit 6,0 s darunter — die Zusicherung muss schweigend bestehen. Gemeldet: "
            f"{ausgang[:300]!r}. Eine Familien-Abstinenz hier heisst, dass die beiden Wege "
            f"AUSEINANDERLAUFEN, obwohl sie dieselbe Maschine beschreiben.")

    def test_zwei_aufrufe_mit_DEMSELBEN_ausser_erben_die_liste_des_ersten_NICHT(self):
        """DIE MUTATION M2 DER FUENFTEN LINSE (08.09.2026) — die Grenze meines eigenen Stempels.

        Der Eigentuemer-Stempel prueft NAMENSGLEICHHEIT (`_DECKEL_FUER[0] == ausser`), nicht
        Rechnungs-Identitaet. Zwei aufeinanderfolgende Aufrufe mit demselben `ausser` sind fuer ihn
        ununterscheidbar. Die Linse nannte die Mutation, die das ausnutzt: das `clear()` nur noch
        beim EIGENTUEMERWECHSEL ausfuehren —

            if _DECKEL_FUER[0] != ausser:
                _DECKEL_BEITRAEGE.clear()
                _DECKEL_FUER[0] = ausser

        — dann haengt der zweite Aufruf seine Achsen an die des ersten an, der Stempel feuert nie,
        und die Teilnehmerliste beschreibt die VEREINIGUNG zweier verschiedener Rechnungen. Von den
        fuenf Faellen, die zwei Aufrufe hintereinander machen, liest genau EINER die Liste — dass
        es auffiele, waere ein Zufall seiner Testdaten, keine Garantie des Mechanismus.

        Was hier gebunden wird, ist deshalb die Eigenschaft, die M2 verletzt: `_faktor_deckel`
        leert IMMER, nicht nur beim Wechsel. Die zwei Aufrufe tragen denselben `ausser` und
        verschiedene Aufzeichnungen — die zweite Liste muss die zweite Rechnung beschreiben, nicht
        beide.
        """
        vorher = dict(_REFERENZ_FARMER_KOSTEN)
        try:
            # Erster Aufruf: ALLE Achsen sind dabei (Kopffreiheit 4,0 ueberall).
            self._gefaelschte_aufzeichnung(
                {d.name: (d.achsen * GRENZE_S) / 4.0 for d in DIMENSIONEN})
            _faktor_deckel(ausser="renewal_work")
            erste = _deckel_beitraege("renewal_work")
            # Zweiter Aufruf, DERSELBE `ausser`, andere Aufzeichnung: alle ausser einer reissen,
            # fallen also durch den Filter und duerfen NICHT mehr in der Liste stehen.
            behalten = next(d for d in DIMENSIONEN if d.name != "renewal_work")
            self._gefaelschte_aufzeichnung(
                {d.name: (d.achsen * GRENZE_S) * 8 for d in DIMENSIONEN})
            _REFERENZ_FARMER_KOSTEN[behalten.name] = (behalten.achsen * GRENZE_S) / 4.0
            _faktor_deckel(ausser="renewal_work")
            zweite = _deckel_beitraege("renewal_work")
        finally:
            _REFERENZ_FARMER_KOSTEN.clear()
            _REFERENZ_FARMER_KOSTEN.update(vorher)
        assert len(erste) == len(DIMENSIONEN) - 1, (
            f"VORBEDINGUNG: die erste Rechnung nimmt {len(erste)} Achsen statt "
            f"{len(DIMENSIONEN) - 1}: {erste}")
        assert zweite == [behalten.name], (
            f"Die zweite Teilnehmerliste ist {zweite}, erwartet wird genau [{behalten.name!r}]. "
            f"Steht mehr darin, hat der zweite Aufruf die Achsen des ERSTEN geerbt — die Liste "
            f"beschreibt dann die Vereinigung zweier verschiedener Rechnungen, und der "
            f"Eigentuemer-Stempel sieht davon nichts, weil beide Aufrufe denselben `ausser` "
            f"tragen. Genau das ist Mutation M2 der fuenften Linse.")

    def test_eine_achse_GENAU_auf_ihrer_eigenen_latte_zaehlt_noch_mit(self):
        """DIE LUECKE, DIE DIE VIERTE LINSE OFFEN LIESS (08.09.2026) — der innere Filter hatte
        keinen Grenzfall, waehrend der aeussere Vergleich einen hat.

        `_faktor_deckel` nimmt eine Achse in den Deckel auf, wenn `frei >= 1.0`. Der AEUSSERE
        Vergleich (`faktor > deckel`) ist an seiner Grenze gebunden — `test_ein_faktor_GENAU_auf_
        dem_deckel_wird_noch_gemessen` existiert genau dafuer. Der innere war es nicht: alle
        Fixturen legen die Kopffreiheit klar darueber (4,0) oder klar darunter (0,125). Eine
        Mutation `>=` -> `>` faengt deshalb kein Fall der Klasse.

        Die Grenze ist aber dieselbe Aussage wie beim aeusseren Vergleich, nur eine Ebene tiefer:
        `frei == 1.0` heisst, die Achse liegt EXAKT auf ihrer eigenen Latte — sie reisst NICHT.
        Der Filter schliesst reissende Achsen aus („eine Achse, die selbst schon ueber ihrer Latte
        liegt, darf keinen Deckel fuer andere setzen"), und exakt auf der Latte liegt sie nicht
        darueber. Wer die Grenze verschiebt, nimmt genau die Achse aus der Rechnung, die den
        Deckel am ehesten setzt — und lockert ihn damit still.
        """
        vorher = dict(_REFERENZ_FARMER_KOSTEN)
        try:
            self._gefaelschte_aufzeichnung(
                {d.name: (d.achsen * GRENZE_S) / 4.0 for d in DIMENSIONEN})
            # EINE andere Achse liegt EXAKT auf ihrer Latte -> Kopffreiheit exakt 1,0.
            grenzachse = next(d for d in DIMENSIONEN if d.name != "renewal_work")
            _REFERENZ_FARMER_KOSTEN[grenzachse.name] = grenzachse.achsen * GRENZE_S
            deckel = _faktor_deckel(ausser="renewal_work")
            beteiligt = _deckel_beitraege("renewal_work")
        finally:
            _REFERENZ_FARMER_KOSTEN.clear()
            _REFERENZ_FARMER_KOSTEN.update(vorher)
        assert grenzachse.name in beteiligt, (
            f"Die Achse {grenzachse.name} liegt mit Kopffreiheit EXAKT 1,0 auf ihrer eigenen Latte "
            f"— sie reisst nicht — und faellt trotzdem aus der Deckelrechnung ({beteiligt}). Der "
            f"Filter soll Achsen ausschliessen, die UEBER ihrer Latte liegen; genau auf ihr liegt "
            f"keine darueber. Wer die Grenze verschiebt, nimmt die Achse heraus, die den Deckel am "
            f"ehesten setzt, und lockert ihn still.")
        assert deckel == pytest.approx(1.0, rel=1e-9), (
            f"Der Deckel ist {deckel:.4f} statt exakt 1,0. Die Grenzachse setzt ihn nicht — dann "
            f"ist sie entweder nicht beteiligt, oder das Minimum nimmt sie nicht.")

    def test_eine_LEERE_klammer_misst_nicht_still_neu(self):
        """FUND DER SIEBTEN LINSE — der FREMDEN Modellfamilie (qwen3.8:27b, 08.09.2026).

        Sechs Linsen einer Familie hatten diese Datei gelesen. Diese hier kam von aussen und fand
        die Hintertuer, durch die der Fehler zurueckkommt, gegen den die Klammer gebaut wurde:

            werte = werte or eigene or _referenz_werte()

        `or` unterscheidet nicht zwischen 'keine Klammer uebergeben' (None — dann ist der Rueckfall
        richtig) und 'KAPUTTE Klammer uebergeben' (eine leere Liste — dann ist er falsch). Gemessen
        08.09.2026: `_faktor_spanne([])` loeste EINE frische Messung aus und lieferte einen Faktor,
        ohne sich zu beschweren. Damit kommt der Faktor wieder aus einem ANDEREN Zeitfenster als die
        Kosten, die er skaliert — genau der schwerste Fund dieser Runde, nur eine Ebene tiefer.

        Eine leere Klammer ist kein fehlender Wert, sondern ein kaputter. Der Unterschied ist der
        ganze Fund: fehlend darf ersetzt werden, kaputt muss auffallen.
        """
        for name, ruf in (
            ("_faktor_spanne", lambda: _faktor_spanne([])),
            ("_faktor_spanne_hashfrei", lambda: _faktor_spanne_hashfrei([])),
            ("_maschinenfaktor", lambda: _maschinenfaktor([])),
            ("_maschinenfaktor_hashfrei", lambda: _maschinenfaktor_hashfrei([])),
        ):
            with pytest.raises(ValueError) as fehler:
                ruf()
            assert "leer" in str(fehler.value).lower(), (
                f"{name} meldet bei einer leeren Klammer nicht, DASS sie leer ist: "
                f"{str(fehler.value)[:160]!r}")
        # GEGENRICHTUNG: ohne Argument bleibt der Rueckfall richtig — sonst haette diese Zeile den
        # Weg abgeschafft statt eingegrenzt.
        vorher = list(_REFERENZ_HIER)
        try:
            _REFERENZ_HIER.clear()
            unten, oben = _faktor_spanne()
            assert unten >= 1.0 and oben >= unten, (
                f"Ohne Argument liefert die Spanne kein gueltiges Band ({unten}, {oben}) — der "
                f"Rueckfall auf eine eigene Messung MUSS weiter funktionieren.")
        finally:
            _REFERENZ_HIER.clear()
            _REFERENZ_HIER.extend(vorher)
