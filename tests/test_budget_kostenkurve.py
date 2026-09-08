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
import dataclasses
import gc
import hashlib
import json
import math
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

_REFERENZ_HIER: list[float] = []


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


def _maschinenfaktor() -> float:
    """Wie viel langsamer diese Maschine ist als die Referenzmaschine — UNTERGRENZE 1,0.

    Verglichen werden die MEDIANE beider Verteilungen, nicht die Maxima: ein einzelner Ausreisser auf
    einer der beiden Seiten soll die Latte weder lockern noch verschaerfen.
    """
    hier = statistics.median(_referenz_werte())
    dort = statistics.median(_REFERENZ_FARMER_S)
    return max(1.0, hier / dort)


def _faktor_spanne() -> tuple[float, float]:
    """Der Maschinenfaktor am SCHNELLSTEN und am LANGSAMSTEN Ende der eigenen Messreihe.

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
    werte = _REFERENZ_HIER or _referenz_werte()
    dort = statistics.median(_REFERENZ_FARMER_S)
    return max(1.0, min(werte) / dort), max(1.0, max(werte) / dort)


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
    for d in DIMENSIONEN:
        if d.name == ausser:
            continue
        m = _messung(d)
        k = m["kosten_am_limit_max"]
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
    if freiheiten:
        return min(freiheiten)
    # LEERE LISTE HEISST: JEDE andere Achse liegt ueber ihrer eigenen Latte. Das ist der lauteste
    # Befund, den dieser Test haben kann — und der Rueckfallwert 1,0 haette ihn in Stille verwandelt,
    # weil jede Maschine mit einem Faktor ueber 1,0 dann NICHT MESSBAR meldet. Benannt von der
    # fremdfamiliaeren Gegenlesung (2026-09-08) als Kehrseite des Filters darueber: "zwoelf Stille
    # statt zwoelf Rot". Ein unendlicher Deckel laesst die Zusicherung stattdessen SPRECHEN — sie
    # faellt dann an der Latte, wo sie fallen soll.
    return float("inf")



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


def _zeit_min(ruf):
    """Der beste Schaetzer der wahren Kosten: das MINIMUM mehrerer Laeufe.

    Messrauschen (Cache, Zuteilung, fremde Last auf den anderen Kernen) kann Rechenzeit nur
    HINZUFUEGEN, nie abziehen. Ein Mittelwert traegt das Rauschen mit, das Minimum nicht. Wiederholt
    wird nur unterhalb von ``WIEDERHOLEN_UNTER_S``: wo die Messung gross ist, ist das Rauschen relativ
    klein, und die Wiederholung kostete dort Minuten statt Millisekunden.
    """
    dauer, erg = _zeit(ruf)
    if dauer >= WIEDERHOLEN_UNTER_S:
        return dauer, erg
    for _ in range(WIEDERHOLUNGEN - 1):
        d2, erg = _zeit(ruf)
        dauer = min(dauer, d2)
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
    D = B.data_digests
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


def _messung(dim: Dimension) -> dict:
    """Einmal messen, mehrfach zusichern — sonst kostet jede Zusicherung die Reihe erneut."""
    if dim.name in _MESSUNGEN:
        return _MESSUNGEN[dim.name]
    limit = getattr(B, dim.name)
    reihe, arbeit = [], []
    for n in (limit // 8, limit // 4, limit // 2, limit):
        ruf, ist = dim.baue(n)
        dauer, erg = _zeit_min(ruf)
        reihe.append((ist, dauer, erg))
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
        "arbeit": arbeit,
        "rand": rand,
        "kosten_am_limit": reihe[-1][1],
        "kosten_am_limit_max": kosten_am_limit_max,
        "speicher_peak_am_limit": speicher_peak,
        "prozess_spitze_am_limit": prozess_spitze,
        "prozess_spitze_messweg": spitze_messweg,
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
        faktor = _maschinenfaktor()
        deckel = _faktor_deckel(ausser=dim.name)
        if faktor > deckel:
            pytest.skip(
                f"NICHT MESSBAR: Maschinenfaktor {faktor:.2f} ueber dem abgeleiteten Deckel "
                f"{deckel:.2f}. Der Deckel ist die kleinste gemessene Kopffreiheit ALLER ANDEREN "
                f"Dimensionen in diesem Lauf — wird er ueberschritten, ist nicht die Maschine "
                f"langsam, sondern das Kostenmodell falsch. Ein gruenes Verdikt waere hier eine "
                f"Behauptung ohne Grundlage, ein rotes eine ohne Gegenstand.")
        unten, oben = _faktor_spanne()
        if k > dim.achsen * GRENZE_S * unten and k <= dim.achsen * GRENZE_S * oben:
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
    seq = [[ArchiveTimeStamp("sha256", HEX32, gross + i)] for i in range(B.renewal_ats_chain)]
    erreicht = {"renewal_ats_chain": len(seq), "int_bits": gross.bit_length()}
    return (lambda: pb.verify_sequence(seq, [HEX32], allow_unauthenticated_anchor=True)), erreicht


def _kombi_renewal_x_algorithmen():
    algs = ["sha256", "sha512", "sha3-256", "sha3-512", "sha384"]
    seq = [[ArchiveTimeStamp(algs[i % len(algs)], HEX32, i + 1)]
           for i in range(B.renewal_ats_chain)]
    # "5 hash-algorithmen" ist keine Budget-Dimension (die Menge ist durch HASH_REGISTRY auf eine
    # kleine Konstante begrenzt, siehe renewal._PraefixDeckung) — hier wird nur renewal_ats_chain
    # gegen die eigene Dimension geprueft.
    erreicht = {"renewal_ats_chain": len(seq)}
    return (lambda: pb.verify_sequence(seq, [HEX32], allow_unauthenticated_anchor=True)), erreicht


def _kombi_renewal_x_data_digests():
    """Review Runde 2, B1: GENAU der Fall, den diese Lane selbst als 15,9 s / 16,2 s Befund gemessen
    hat (siehe Modul-Kopf und ``budget.VerificationBudget.data_digests``) — jetzt als Kombination mit
    BEIDEN Achsen an ihrem eigenen Limit, nicht als spaeterer, von dieser Datei ungedeckter Befund."""
    daten = ["%064x" % i for i in range(B.data_digests)]
    seq = [[ArchiveTimeStamp("sha256", HEX32, i + 1)] for i in range(B.renewal_ats_chain)]
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
    daten = ["%064x" % i for i in range(B.data_digests)]
    n = B.renewal_work // (len(daten) * len(algs))   # so viele ATS, wie das Produktbudget zulaesst
    n = min(n, B.renewal_ats_chain)
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
    beweis = [bytes([i % 251]) * 32 for i in range(B.merkle_path)]
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
    env["signatures"] = [{"sig": "AA=="} for _ in range(B.signatures - 1)] + list(echt["signatures"])
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
    tief = B.json_depth
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
        m = _kombi_messung(name, bau)
        dauer = m["dauer_max"]
        assert dauer <= achsen * GRENZE_S, (
            f"{name}: {dauer:.3f} s Rechenzeit (Maximum aus {MAX_WIEDERHOLUNGEN} Laeufen), Obergrenze "
            f"{achsen * GRENZE_S:.1f} s ({achsen} Achsen an ihrem Limit)")

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
        daten = ["%064x" % i for i in range(B.data_digests)]
        seq = [[ArchiveTimeStamp(algs[i % len(algs)], HEX32, i + 1)]
               for i in range(B.renewal_ats_chain)]
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

    def _gefaelschte_messungen(self, kosten_je_dimension: dict) -> dict:
        """Ein Ersatz fuer den Messungs-Cache: je Dimension die gewuenschten Kosten am Limit."""
        vorher = dict(_MESSUNGEN)
        for d in DIMENSIONEN:
            _MESSUNGEN[d.name] = {"limit": 1, "kosten_am_limit_max": kosten_je_dimension[d.name],
                                  "rand": {}, "reihe": []}
        return vorher

    def test_der_deckel_FOLGT_der_kopffreiheit_der_anderen_achsen(self):
        """Wird eine ANDERE Achse teurer, muss der Deckel sinken. Eine Konstante taete das nicht."""
        vorher = dict(_MESSUNGEN)
        try:
            # Ausgangslage: jede Achse kostet ein Zehntel ihrer Latte -> Kopffreiheit 10 ueberall.
            self._gefaelschte_messungen({d.name: (d.achsen * GRENZE_S) / 10.0 for d in DIMENSIONEN})
            weit = _faktor_deckel(ausser="renewal_work")
            # Jetzt wird EINE andere Achse zehnmal teurer -> ihre Kopffreiheit faellt auf 1.
            andere = next(d for d in DIMENSIONEN if d.name != "renewal_work")
            _MESSUNGEN[andere.name] = {"limit": 1, "kosten_am_limit_max": andere.achsen * GRENZE_S,
                                       "rand": {}, "reihe": []}
            eng = _faktor_deckel(ausser="renewal_work")
        finally:
            _MESSUNGEN.clear()
            _MESSUNGEN.update(vorher)
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
        vorher = dict(_MESSUNGEN)
        try:
            self._gefaelschte_messungen({d.name: (d.achsen * GRENZE_S) / 10.0 for d in DIMENSIONEN})
            # renewal_work wird teuer, ABER NICHT REISSEND -> Kopffreiheit dort 2,0.
            #
            # FRUEHER STAND HIER DAS ZEHNFACHE, also Kopffreiheit 0,1 — und damit prueft der Fall
            # seine eigene Eigenschaft NICHT (dritte Linse, 08.09.2026, P0): eine Kopffreiheit unter
            # 1,0 faellt ohnehin durch den `frei >= 1.0`-Filter heraus, ganz gleich ob die
            # `ausser`-Ausnahme noch existiert. Die Linse entfernte `if d.name == ausser: continue`
            # komplett und ALLE SECHS Faelle blieben gruen. Mit Kopffreiheit 2,0 unterhalb der 10,0
            # der anderen Achsen ist die Ausnahme der EINZIGE Grund, warum sie nicht den Deckel setzt.
            rw = next(d for d in DIMENSIONEN if d.name == "renewal_work")
            _MESSUNGEN["renewal_work"] = {"limit": 1, "kosten_am_limit_max": (rw.achsen * GRENZE_S) / 2.0,
                                          "rand": {}, "reihe": []}
            deckel = _faktor_deckel(ausser="renewal_work")
        finally:
            _MESSUNGEN.clear()
            _MESSUNGEN.update(vorher)
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
        vorher = dict(_MESSUNGEN)
        try:
            self._gefaelschte_messungen({d.name: (d.achsen * GRENZE_S) / 10.0 for d in DIMENSIONEN})
            gesund = _faktor_deckel(ausser="renewal_work")
            # EINE andere Achse reisst ihre eigene Latte um das Achtfache.
            reisst = next(d for d in DIMENSIONEN if d.name != "renewal_work")
            _MESSUNGEN[reisst.name] = {"limit": 1, "rand": {}, "reihe": [],
                                       "kosten_am_limit_max": reisst.achsen * GRENZE_S * 8}
            trotzdem = _faktor_deckel(ausser="renewal_work")
        finally:
            _MESSUNGEN.clear()
            _MESSUNGEN.update(vorher)
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
            for d in DIMENSIONEN:
                _MESSUNGEN[d.name] = {"limit": 1, "rand": {}, "reihe": [],
                                      "kosten_am_limit_max": (d.achsen * GRENZE_S) / 1.5}
            _REFERENZ_HIER.clear()
            dim = next(d for d in DIMENSIONEN if d.name == "renewal_work")
            faktor = _maschinenfaktor()
            deckel = _faktor_deckel(ausser=dim.name)
            assert faktor > deckel, (
                f"VORBEDINGUNG: der Faktor ({faktor:.2f}) muss ueber dem Deckel ({deckel:.2f}) "
                f"liegen, sonst prueft dieser Fall den Skip-Pfad gar nicht.")
            fall = TestObergrenzeAmGroesstenZugelassenenWert()
            with pytest.raises(Skipped) as skip:
                fall.test_kosten_am_limit_unter_der_obergrenze(dim)
        finally:
            wieder()
            _MESSUNGEN.clear(); _MESSUNGEN.update(vorher_m)
            _REFERENZ_HIER.clear(); _REFERENZ_HIER.extend(vorher_r)
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
        wieder, _ = self._referenz_kostet([statistics.median(_REFERENZ_FARMER_S) * 2.0])  # Faktor 2
        try:
            for d in DIMENSIONEN:  # ALLE deutlich ueber ihrer eigenen Latte
                # `rand` wird vom Diagnose-Text an drei Stellen gelesen (limit-1, limit, limit+1).
                # Eine Fixture, die es leer laesst, laesst den Fall an einem KeyError sterben statt
                # an der Zusicherung — die Messflaeche muss den Gegenstand abbilden, sonst misst der
                # Fall seinen eigenen Aufbau.
                _MESSUNGEN[d.name] = {
                    "limit": 1, "reihe": [],
                    "rand": {0: (0, 0.1, True), 1: (1, 0.2, True), 2: (2, 0.3, False)},
                    "kosten_am_limit_max": d.achsen * GRENZE_S * 5}
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
                fall.test_kosten_am_limit_unter_der_obergrenze(dim)
            except Skipped as s:
                ausgang = f"SKIP: {s}"
            except AssertionError as a:
                ausgang = f"ROT: {a}"
        finally:
            wieder()
            _MESSUNGEN.clear(); _MESSUNGEN.update(vorher_m)
            _REFERENZ_HIER.clear(); _REFERENZ_HIER.extend(vorher_r)
        assert ausgang.startswith("ROT"), (
            f"Wenn ALLE Achsen reissen, muss der Fall ROT melden. Gemeldet wurde stattdessen: "
            f"{ausgang[:200]!r} (Deckel {deckel}, Faktor {faktor:.2f}). Das ist der lauteste "
            f"Befund, den dieser Test haben kann, und er verschwindet in der Stille.")

    @staticmethod
    def _referenz_kostet(kosten: list[float]):
        """Ersetzt die MESSUNG der Referenzlast, nicht ihr Ergebnis.

        Die frueheren Faelle dieser Klasse schrieben direkt in `_REFERENZ_HIER` — damit umgingen sie
        `_referenz_werte()` und konnten dessen Cache-Riegel gar nicht sehen. Das ist die Lehre aus
        dem ersten, gruen gewordenen Anlauf dieses Fangnachweises am 08.09.2026: ein Fangnachweis,
        der am Speicher statt am PFAD ansetzt, prueft nicht die Stelle, die er benennt.

        Rueckgabe: (wiederherstellen, zaehler) — `zaehler["mess"]` zaehlt die echten Messungen.
        """
        alt_cpu, alt_last = _cpu, _referenzlast
        zaehler = {"mess": 0}
        zustand = {"laeuft": False, "i": 0}

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
            k = kosten[zustand["i"] % len(kosten)]
            zustand["i"] += 1
            zaehler["mess"] += 1
            return k

        def wiederherstellen() -> None:
            globals().update(_cpu=alt_cpu, _referenzlast=alt_last)

        # ATOMAR und ganz am Schluss (zweite Linse, 08.09.2026): frueher standen hier zwei
        # getrennte Zuweisungen, und der Aufruf steht in jedem Fall VOR dessen `try`. Wuerde
        # zwischen den beiden Zuweisungen je etwas fliegen, bliebe die Haelfte des Patches stehen,
        # ohne dass der Aufrufer `wiederherstellen` je in die Hand bekaeme. Die Linse hat das
        # ausgefuehrt: ein Nachbarfall aus einer ANDEREN Klasse erbte den gefaelschten Zeitgeber und
        # meldete einen erfundenen 'Maschinenfaktor 20.00' als sauber aussehenden SKIP. Mit einem
        # einzigen `globals().update` als letzter Anweisung gibt es dieses Zwischenfenster nicht:
        # entweder ist nichts gepatcht, oder die Funktion ist zurueckgekehrt.
        globals().update(_cpu=fake_cpu, _referenzlast=lambda n=0: b"")
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
        Faktor folgt ihr, und die Latte lockert sich um das Zehnfache — still, denn ein Faktor von 10
        liegt unter dem abgeleiteten Deckel von rund 19,5. Real ist das ein Runner, auf dem ein
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
        dort = statistics.median(_REFERENZ_FARMER_S)
        # Fuenf langsame, vier normale Messungen — die Reihe wird zyklisch abgerufen, also gibt
        # dieses Muster bei neun Messungen genau 5x langsam und 4x normal.
        wieder, zaehler = self._referenz_kostet(
            [dort * 10.0, dort, dort * 10.0, dort, dort * 10.0, dort, dort * 10.0, dort, dort * 10.0])
        try:
            dim = next(d for d in DIMENSIONEN if d.name == "renewal_work")
            for d in DIMENSIONEN:
                _MESSUNGEN[d.name] = {
                    "limit": 1, "reihe": [],
                    "rand": {0: (0, 0.1, True), 1: (1, 0.2, True), 2: (2, 0.3, False)},
                    # Kosten beim Dreifachen der Grundlatte: ueber dem schnellen Ende (1,0),
                    # unter dem langsamen (10,0) — genau im Band, in dem die Streuung entscheidet.
                    "kosten_am_limit_max": d.achsen * GRENZE_S * 3.0}
            _REFERENZ_HIER.clear()
            faktor = _maschinenfaktor()
            assert faktor == pytest.approx(10.0, rel=0.02), (
                f"VORBEDINGUNG: bei fuenf von neun langsamen Messungen liegt der Median IN der "
                f"langsamen Gruppe, erwartet rund 10,0, gemessen {faktor:.2f} — sonst prueft dieser "
                f"Fall die benannte Verteilung gar nicht.")
            assert zaehler["mess"] == MAX_WIEDERHOLUNGEN, (
                f"VORBEDINGUNG: {MAX_WIEDERHOLUNGEN} Messungen erwartet, {zaehler['mess']} gezaehlt.")
            fall = TestObergrenzeAmGroesstenZugelassenenWert()
            ausgang = "kein Fehlschlag"
            try:
                fall.test_kosten_am_limit_unter_der_obergrenze(dim)
            except Skipped as s:
                ausgang = f"SKIP: {s}"
            except AssertionError as a:
                ausgang = f"ROT: {a}"
        finally:
            wieder()
            _MESSUNGEN.clear(); _MESSUNGEN.update(vorher_m)
            _REFERENZ_HIER.clear(); _REFERENZ_HIER.extend(vorher_r)
        assert ausgang.startswith("SKIP") and "NICHT MESSBAR" in ausgang, (
            f"Bei einer zweigipfligen Messreihe (fuenf von neun Messungen zehnmal langsamer) meldet "
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
        vorher = dict(_MESSUNGEN)
        try:
            rw = next(d for d in DIMENSIONEN if d.name == "renewal_work")
            assert rw.achsen == 3, f"VORBEDINGUNG: renewal_work hat {rw.achsen} Achsen, erwartet 3"
            assert all(d.achsen == 1 for d in DIMENSIONEN if d.name != "renewal_work"), (
                "VORBEDINGUNG: eine zweite Dimension hat mehr als eine Achse — dann prueft dieser "
                "Fall den Multiplikator nicht mehr isoliert.")
            for d in DIMENSIONEN:
                _MESSUNGEN[d.name] = {"limit": 1, "rand": {}, "reihe": [],
                                      "kosten_am_limit_max": (d.achsen * GRENZE_S) / 20.0}
            # renewal_work bekommt Kosten, die OHNE den Multiplikator eine Kopffreiheit von 1,0
            # ergaeben und MIT ihm 3,0. Der Deckel ist das Minimum ueber die anderen (20,0) und
            # renewal_work — also 3,0 mit Multiplikator, 1,0 ohne (und 1,0 faellt durch den Filter).
            _MESSUNGEN["renewal_work"] = {"limit": 1, "rand": {}, "reihe": [],
                                          "kosten_am_limit_max": GRENZE_S}
            einachsig = next(d for d in DIMENSIONEN if d.achsen == 1)
            deckel = _faktor_deckel(ausser=einachsig.name)
        finally:
            _MESSUNGEN.clear(); _MESSUNGEN.update(vorher)
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
        vorher = dict(_MESSUNGEN)
        try:
            for d in DIMENSIONEN:
                _MESSUNGEN[d.name] = {"limit": 1, "rand": {}, "reihe": [],
                                      "kosten_am_limit_max": (d.achsen * GRENZE_S) / 4.0}
            billig = next(d for d in DIMENSIONEN if d.name not in ("renewal_work",))
            _MESSUNGEN[billig.name]["kosten_am_limit_max"] = 0.0
            deckel = _faktor_deckel(ausser="renewal_work")
        finally:
            _MESSUNGEN.clear(); _MESSUNGEN.update(vorher)
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
        vorher_r = list(_REFERENZ_HIER)
        dort = statistics.median(_REFERENZ_FARMER_S)
        wieder, _ = self._referenz_kostet([dort * 2.0])          # Faktor exakt 2,0
        try:
            dim = next(d for d in DIMENSIONEN if d.name == "renewal_work")
            for d in DIMENSIONEN:                                 # Kopffreiheit exakt 2,0
                _MESSUNGEN[d.name] = {
                    "limit": 1, "reihe": [],
                    "rand": {0: (0, 0.1, True), 1: (1, 0.2, True), 2: (2, 0.3, False)},
                    "kosten_am_limit_max": (d.achsen * GRENZE_S) / 2.0}
            _REFERENZ_HIER.clear()
            faktor = _maschinenfaktor()
            deckel = _faktor_deckel(ausser=dim.name)
            assert faktor == deckel, (
                f"VORBEDINGUNG: Faktor ({faktor!r}) und Deckel ({deckel!r}) muessen EXAKT gleich "
                f"sein, sonst prueft dieser Fall die Grenze gar nicht.")
            fall = TestObergrenzeAmGroesstenZugelassenenWert()
            ausgang = "kein Fehlschlag"
            try:
                fall.test_kosten_am_limit_unter_der_obergrenze(dim)
            except Skipped as s:
                ausgang = f"SKIP: {s}"
            except AssertionError as a:
                ausgang = f"ROT: {a}"
        finally:
            wieder()
            _MESSUNGEN.clear(); _MESSUNGEN.update(vorher_m)
            _REFERENZ_HIER.clear(); _REFERENZ_HIER.extend(vorher_r)
        assert "ueber dem abgeleiteten Deckel" not in ausgang, (
            f"Ein Faktor GENAU auf dem Deckel wird als NICHT MESSBAR gemeldet: {ausgang[:200]!r}. "
            f"Auf dem Deckel reisst noch keine andere Achse — der Fall ist dort messbar, und die "
            f"Grenze eines Riegels ist eine Aussage, keine Geschmacksfrage.")

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
