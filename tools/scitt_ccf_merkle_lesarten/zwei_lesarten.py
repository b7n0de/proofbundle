#!/usr/bin/env python3
"""Zwei Lesarten desselben Dokuments, zwei Wurzeln.

draft-ietf-scitt-receipts-ccf-profile-04 (24.06.2026), geholt am 13.09.2026 von
https://www.ietf.org/archive/id/draft-ietf-scitt-receipts-ccf-profile-04.txt
21295 Bytes, sha256 80ba0dd88f5109598952bff4ef0d8f0d83936345abd951f0e330924b149b847a

Die Frage stammt von Henri Sirkkavaara, Befund 4 im Last Call. Gemessen wird nicht eine
Meinung ueber das Dokument, sondern was zwei woertliche Lesarten AUS DEMSELBEN EINGANG
rechnen.

ABSCHNITT 2.1, Merkle Tree Shape, woertlich:

    MTH({})      = HASH().
    MTH({d[0]})  = HASH(d[0]).
    MTH(D_n)     = HASH(MTH(D[0:k]) || MTH(D[k:n])),  k groesste Zweierpotenz < n

  d[i] ist laut 2.1 eine "serialized transaction (as byte string)". WIE eine Transaktion
  serialisiert wird, sagt 2.1 nicht; 2.2 gibt dafuer die CDDL:

    ccf-leaf = [ internal-transaction-hash: bstr .size 32
               , internal-evidence:         tstr .size (1..1024)
               , data-hash:                 bstr .size 32 ]

  Die naheliegende Lesart ist deshalb: d[i] = CBOR(ccf-leaf), Blatt = HASH(CBOR(ccf-leaf)).

ABSCHNITT 3.2, Inclusion Proof Verification Algorithm, woertlich:

    compute_root(proof):
      h := HASH( proof.leaf.internal-transaction-hash
                 || HASH(proof.leaf.internal-evidence)
                 || proof.leaf.data-hash )
      for [left, hash] in proof.path:
          h := HASH(hash + h) if left else HASH(h + hash)
      return h

  Das Blatt ist hier KEINE Serialisierung der drei Felder, sondern eine Verkettung roher
  Bytes, bei der das MITTLERE Feld vorher einzeln gehasht wird.

DER UNTERSCHIED SITZT GENAU AN EINER STELLE, und das ist der ganze Befund: die
Knotenregel ist in beiden Lesarten HASH(links || rechts), identisch. Nur das BLATT hat
zwei Urbilder. Alles andere ist gleich; wer mehr behauptet, uebertreibt.

NICHT GEMESSEN, mit Grund: was eine reale CCF-Instanz rechnet. Gemessen wird das
Dokument, nicht eine Implementierung.

KEIN ZWEITER ERZEUGER: unser eigener Merkle-Code (src/proofbundle/merkle.py) rechnet
RFC 6962 mit den Praefixen 0x00 am Blatt und 0x01 am Knoten (Zeilen 34-41, gemessen).
Der CCF-Baum hat KEINE Praefixe. Das ist eine andere Struktur, nicht dieselbe Frage --
unser Code kann eine CCF-Wurzel nicht rechnen, und ihn hier zu benutzen waere falsch,
nicht sparsam. Die CBOR-Serialisierung dagegen wird NICHT neu geschrieben, sondern aus
tools/scitt_ccf_datahash_vector/cbor_min.py (`schreibe`) uebernommen.
"""

from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import sys

# Der Stand, aus dem cbor_min.py gelesen wird, wenn es nicht im Arbeitsbaum liegt.
# main == Ziel des Tags v6.0.0, am 13.09.2026 gemessen.
CBOR_MIN_COMMIT = "4e32e83b647235bfedf23b55cebe69fdf14fd6f5"

H = lambda b: hashlib.sha256(b).digest()          # noqa: E731 -- H wie im Dokument
hx = lambda b: b.hex()                            # noqa: E731


# --- die CBOR-Serialisierung kommt aus dem vorhandenen Werkzeug, nicht von hier -------
def _repo_wurzel() -> pathlib.Path | None:
    """Die Repo-Wurzel aus der Lage DIESER Datei ableiten, nicht aus $HOME.

    Ein fester Pfad unter dem Heimatverzeichnis traegt den Benutzernamen nach
    draussen und stimmt ausserdem nur auf einer Maschine.
    """
    for eltern in pathlib.Path(__file__).resolve().parents:
        if (eltern / ".git").exists():
            return eltern
    return None


REL = "tools/scitt_ccf_datahash_vector/cbor_min.py"


def _lade_cbor_min():
    """cbor_min.schreibe() des Schwesterwerkzeugs, oder ein benannter Abbruch."""
    hier = pathlib.Path(__file__).resolve().parent
    wurzel = _repo_wurzel()
    kandidaten = [hier.parent / "scitt_ccf_datahash_vector" / "cbor_min.py"]
    if wurzel is not None:
        kandidaten.append(wurzel / REL)
    for p in kandidaten:
        if p.is_file():
            spec = importlib.util.spec_from_file_location("cbor_min", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
            return m, REL + " (Arbeitsbaum)"

    # Dritter Weg, fuer einen Lauf AUSSERHALB des Repos: aus dem festgenagelten Commit
    # lesen. Ausdruecklich keine Kopie -- eine Kopie driftet, ein Ref nicht.
    import subprocess
    ziel = "%s:%s" % (CBOR_MIN_COMMIT, REL)
    if wurzel is not None:
        r = subprocess.run(["git", "show", ziel], capture_output=True, text=True, cwd=wurzel)
        if r.returncode == 0 and r.stdout:
            m = importlib.util.module_from_spec(
                importlib.util.spec_from_loader("cbor_min", loader=None))
            exec(compile(r.stdout, ziel, "exec"), m.__dict__)
            return m, "git show %s" % ziel

    raise SystemExit(
        "NICHT MESSBAR: cbor_min.py nicht gefunden. Gesucht wurde neben diesem "
        "Werkzeug und unter " + REL + ", danach im festgenagelten Commit.\n"
        "Grund: die Serialisierung wird nicht neu geschrieben (kein zweiter Erzeuger)."
    )


CBOR, CBOR_PFAD = _lade_cbor_min()


# --- der Eingang, deterministisch und von Hand nachrechenbar --------------------------
def blatt(i: int) -> dict:
    """Transaktion i. Jedes Feld aus einem sichtbaren Urbild, damit nichts geraten ist."""
    return {
        "internal_transaction_hash": H(b"itx-%d" % i),          # 32 B, wie CDDL verlangt
        "internal_evidence": "ce-%d" % i,                        # tstr, 1..1024
        "data_hash": H(b"dh-%d" % i),                            # 32 B
    }


# --- Lesart A, Abschnitt 2.1 + 2.2 ----------------------------------------------------
def blatt_hash_a(b: dict) -> bytes:
    serialisiert = CBOR.schreibe([
        b["internal_transaction_hash"],
        b["internal_evidence"],
        b["data_hash"],
    ])
    return H(serialisiert)


# --- Lesart B, Abschnitt 3.2 ----------------------------------------------------------
def blatt_hash_b(b: dict) -> bytes:
    return H(
        b["internal_transaction_hash"]
        + H(b["internal_evidence"].encode("utf-8"))
        + b["data_hash"]
    )


# --- die Baumregel ist in BEIDEN Lesarten dieselbe, deshalb steht sie einmal hier ------
def mth(blatt_hashes: list[bytes]) -> bytes:
    """MTH nach 2.1: leere Liste -> HASH(), ein Element -> das Blatt, sonst rekursiv."""
    n = len(blatt_hashes)
    if n == 0:
        return H(b"")
    if n == 1:
        return blatt_hashes[0]
    k = 1
    while k * 2 < n:                       # groesste Zweierpotenz k mit k < n <= 2k
        k *= 2
    return H(mth(blatt_hashes[:k]) + mth(blatt_hashes[k:]))


def wurzeln(n: int) -> tuple[bytes, bytes]:
    blaetter = [blatt(i) for i in range(n)]
    return (mth([blatt_hash_a(b) for b in blaetter]),
            mth([blatt_hash_b(b) for b in blaetter]))


# --- Gegenprobe: der Vergleich MUSS auch "gleich" sagen koennen ------------------------
def gegenprobe() -> tuple[bool, str, str]:
    """Jede Lesart EINZELN auf gleich-Fall und ungleich-Fall pruefen.

    Ohne diese Faelle belegt ein durchgaengiges "weicht ab" nichts: es koennte ebenso gut
    heissen, dass der Vergleich immer ungleich meldet.

    BEIDE LESARTEN, und das ist eine Haertung aus einer Gegenlesung: die erste Fassung fuhr
    ausschliesslich blatt_hash_b. Wer blatt_hash_a durch eine KONSTANTE ersetzte, bekam
    unveraendert "bestanden" und weiter "WEICHT AB" in jeder Zeile -- die Lesart, ueber die
    das Ergebnis etwas aussagt, war selbst nie geprueft. Eine Gegenprobe, die nur EINE Seite
    anfasst, ist gegen jeden Fehler blind, der NUR die andere trifft.
    """
    blaetter = [blatt(i) for i in range(4)]
    verbogen = list(blaetter)
    verbogen[0] = dict(verbogen[0], data_hash=H(b"dh-abweichend"))

    spur = b""
    for name, blatt_hash in (("2.1", blatt_hash_a), ("3.2", blatt_hash_b)):
        links = mth([blatt_hash(b) for b in blaetter])
        rechts = mth([blatt_hash(b) for b in blaetter])
        anders = mth([blatt_hash(b) for b in verbogen])
        # DIE SPUR IST DER NACHWEIS, DASS DIESE ZEILEN LIEFEN. Eine zweite Gegenlesung hat
        # gezeigt: wer ein frueheres `return True, "..."` einsetzt, legt die ganze Pruefung
        # still, ohne dass irgendeine gemessene Groesse reagiert -- die Messflaeche las nur
        # das MELDUNGSERGEBNIS. Ein Wert, der aus der Arbeit selbst faellt, laesst sich nicht
        # behaupten, nur rechnen.
        spur += links + anders
        if links != rechts:
            return False, "Lesart %s meldet ungleich, wo sie gleich melden muss" % name, ""
        # Ein echter Unterschied MUSS durchkommen. Genau hier faellt eine Lesart auf, die
        # ihren Eingang gar nicht liest (konstantes Blatt) -- die Wurzel bliebe dieselbe.
        if anders == links:
            return False, "Lesart %s meldet gleich, wo sie ungleich melden muss" % name, ""

    return True, "gleich-Fall und ungleich-Fall beide richtig", hx(H(spur))[:16]


def main() -> int:
    print("Quelle : draft-ietf-scitt-receipts-ccf-profile-04, Abschnitte 2.1/2.2 und 3.2")
    print("CBOR   :", CBOR_PFAD)
    print()

    ok, grund, spur = gegenprobe()
    print(f"GEGENPROBE: {'BESTANDEN' if ok else 'GEFALLEN'} -- {grund} [spur {spur}]")
    if not ok:
        print("Abbruch: ohne gueltige Gegenprobe ist jedes Ergebnis unten bedeutungslos.")
        return 2
    print()

    print(f"{'n':>2}  {'Wurzel Lesart 2.1':<66}  {'Wurzel Lesart 3.2':<66}  Urteil")
    abweichend = gesamt = 0
    for n in range(0, 6):
        a, b = wurzeln(n)
        gesamt += 1
        if a == b:
            urteil = "gleich"
            if n == 0:
                urteil = "gleich (3.2 kennt keinen leeren Baum -- NICHT ANWENDBAR)"
        else:
            urteil = "WEICHT AB"
            abweichend += 1
        print(f"{n:>2}  {hx(a):<66}  {hx(b):<66}  {urteil}")

    print()
    print(f"ERGEBNIS: {abweichend} von {gesamt} Faellen weichen ab "
          f"(n=0 bis n={gesamt - 1}).")
    print("Der Unterschied sitzt ausschliesslich im Blatt-Urbild; die Knotenregel "
          "HASH(links || rechts) ist in beiden Lesarten dieselbe.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
