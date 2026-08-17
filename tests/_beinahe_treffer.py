"""Beinahe-Treffer fuer JEDEN Erwartungsvergleich — eine Quelle, viele Flaechen.

WARUM ES DIESES MODUL GIBT. Ein Pruefer pinnt eine erwartete Kennung (einen Origin, eine Audience,
eine Nonce, eine URI, einen Typ), und die Gegenseite waehlt ihr Gegenstueck. Wird dieser Vergleich
NUR mit einem voellig fremden Wert belegt, ist der Beleg wertlos: **gegen einen fremden Wert
verhaelt sich ein gelockerter Vergleich exakt wie ein exakter.** Erst der Beinahe-Treffer trennt
sie — und im Feld ist er der gefaehrliche, weil ein Angreifer den eigenen Namen selbst waehlt.

GEMESSEN 2026-08-16 an sechs Flaechen (kbjwt aud/nonce, statuslist, evalclaim, intoto, policy): jede
einzeln auf `.startswith()` gelockert, volle Suite je Pflanzung — **keine einzige wurde gefangen**.
Der Grund war ueberall derselbe: das vorhandene Korpus bestand aus genau einem fremden Wert.

WARUM EINE GEMEINSAME QUELLE UND NICHT SECHS KORPORA. Sechs Kopien waeren die Klasse als sechs
Instanzen — und die siebte Flaeche haette wieder keins. Hier steht die Regel; eine neue Flaeche
importiert sie und ist gedeckt. Die Formen sind nach der LOCKERUNG benannt, die sie jeweils sichtbar
macht, nicht nach ihrem Aussehen: wer eine Form streicht, streicht eine Lockerungsklasse.
"""
from __future__ import annotations

import unicodedata


def _vollbreite(s: str) -> str:
    """Die Vollbreiten-Form: `NFKC(ergebnis) == s`, aber andere Bytes.

    Der einzige Kandidat, der eine KOMPATIBILITAETS-Normalisierung sichtbar macht. Ein reiner
    ASCII-Wert ist unter allen vier Normalformen sein eigenes Bild und kann das nicht.
    """
    return "".join(chr(ord(c) - 0x21 + 0xFF01) if 0x21 <= ord(c) <= 0x7E else c for c in s)


def beinahe_treffer(wert: str) -> list[tuple[str, str]]:
    """Beinahe-Treffer zu `wert`, je Eintrag `(name_der_lockerung, kandidat)`.

    Jeder Kandidat MUSS von einem exakten Vergleich abgelehnt werden. Wird einer akzeptiert, ist der
    Vergleich um genau die benannte Form gelockert.
    """
    kandidaten: list[tuple[str, str]] = [
        ("praefix",           wert[:-1]),                    # startswith() in die eine Richtung
        ("suffix_angehaengt", wert + "-evil"),               # startswith() in die andere
        ("gross",             wert.upper()),                 # casefold / lower
        ("gemischt",          wert.capitalize()),            # casefold
        ("fuehrendes_leer",   " " + wert),                   # strip / lstrip
        ("folgendes_leer",    wert + " "),                   # strip / rstrip
        ("zeilenumbruch",     wert + "\n"),                  # strip
        ("teilzeichenkette",  "x" + wert + "x"),             # `in` statt `==`
        ("leer",              ""),                           # falsy-Kurzschluss (`not x` statt `is None`)
        ("vollbreite",        _vollbreite(wert)),            # NFKC-Normalisierung
    ]
    # nur wenn der Wert die Form ueberhaupt hergibt — ein Kandidat, der gleich dem Original ist,
    # waere VAKUOS und wuerde als falscher Beleg durchgehen.
    if "/" in wert:
        kandidaten += [
            ("schraegstrich_am_ende", wert + "/"),           # rstrip("/")
            ("doppelter_strich",      wert.replace("/", "//", 1)),   # "//" -> "/"
            ("prozent_kodiert",       wert.replace("/", "%2F", 1)),  # unquote
        ]
    if "." in wert:
        kandidaten += [("punkt_am_ende_des_hosts", wert.replace(".", ".", 1) + ".")]  # rstrip(".")
    zerlegt = unicodedata.normalize("NFD", wert)
    if zerlegt != wert:
        kandidaten.append(("nfd_zerlegt", zerlegt))          # kanonische Normalisierung

    # ZWEI Aussortierungen, beide gegen dieselbe Klasse: ein Kandidat, der NICHTS misst und dabei
    # aussieht, als taete er es.
    #   (1) gleich dem Original -> er wuerde vom exakten Vergleich AKZEPTIERT und der Test faellt
    #       aus dem falschen Grund.
    #   (2) gleich einem frueheren Kandidaten -> zwei benannte Formen, ein Wert. Gemessen bei
    #       `n-1`: `.upper()` und `.capitalize()` liefern beide `N-1`, weil der einzige Buchstabe
    #       vorn steht. Die zweite Form belegt dann ihre Lockerung nicht, obwohl ihr Name es sagt.
    #       Sie wird VERWORFEN, nicht stillschweigend mitgezaehlt — die Abdeckung ist fuer solche
    #       Werte einfach kleiner, und das soll man sehen koennen.
    gesehen: set[str] = {wert}
    aus: list[tuple[str, str]] = []
    for n, k in kandidaten:
        if k in gesehen:
            continue
        gesehen.add(k)
        aus.append((n, k))
    return aus


def entfallene_formen(wert: str) -> list[str]:
    """Welche benannten Formen fallen fuer diesen Wert zusammen oder weg? Fuer die Ehrlichkeit
    eines Berichts: „zehn Kandidaten" ist bei kurzen Werten weniger, als die Liste vermuten laesst."""
    behalten = {n for n, _ in beinahe_treffer(wert)}
    alle = {"praefix", "suffix_angehaengt", "gross", "gemischt", "fuehrendes_leer", "folgendes_leer",
            "zeilenumbruch", "teilzeichenkette", "leer", "vollbreite"}
    return sorted(alle - behalten)


def pruefe_exakt(pruefer, wert: str, testfall) -> None:
    """Fahre `pruefer(kandidat) -> bool` ueber das Korpus. True heisst "akzeptiert".

    Die Gegenrichtung ist Teil der Pruefung: ohne sie waere ein IMMER-FALSCH-Vergleich ebenfalls
    gruen — dieselbe Falle wie ein Riegel, der alles blockt.
    """
    testfall.assertTrue(pruefer(wert), "der ECHTE Wert wird abgelehnt — der Vergleich ist "
                                       "immer-falsch, und das Korpus unten belegt dann nichts")
    for name, kandidat in beinahe_treffer(wert):
        with testfall.subTest(lockerung=name):
            testfall.assertFalse(
                pruefer(kandidat),
                f"{name}: {kandidat!r} wurde als {wert!r} akzeptiert — der Vergleich ist um genau "
                "diese Form gelockert")
