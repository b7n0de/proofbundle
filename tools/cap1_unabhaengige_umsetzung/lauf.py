#!/usr/bin/env python3
"""
Laeuft alle drei Lesarten gegen die Sonden und die Positivkontrollen.

usage: lauf.py <cap-1/src-verzeichnis> <sondenverzeichnis> [<rust-binary>]

Drei Lesarten, alle drei nach RFC 8259 zulaessig:
  last-wins   Pythons json (und, wie gemessen, der Referenzverifier des Autors)
  first-wins  derselbe Verifier ueber einen object_pairs_hook
  streng      die Rust-Umsetzung dieses Pakets, eigener Parser, weist Doppelte zurueck
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "py"))
from cap1_verify import verify


def first_wins(pairs):
    d = {}
    for k, v in pairs:
        if k not in d:
            d[k] = v
    return d


def urteil(ok):
    return "CONFORMS" if ok else "REFUSED"


def main(src, sonden, rustbin=None):
    his = os.path.join(src, "verify.py")
    hat_his = os.path.isfile(his)
    dateien = sorted(f for f in os.listdir(sonden) if f.endswith(".json"))

    print("CAP-1 — DOPPELTE JSON-SCHLUESSEL, DREI KONFORME LESARTEN")
    print("=" * 92)
    print("  %-34s %-10s %-10s %-10s %s" % ("Datei", "last-wins", "first-win", "streng", "Autor"))
    print("  " + "-" * 88)

    abweichend = 0
    for f in dateien:
        p = os.path.join(sonden, f)
        try:
            lw = urteil(verify(json.load(open(p)))[0])
        except Exception:
            lw = "JSONFEHL"
        try:
            fw = urteil(verify(json.load(open(p), object_pairs_hook=first_wins))[0])
        except Exception:
            fw = "JSONFEHL"
        st = "-"
        if rustbin and os.path.isfile(rustbin):
            r = subprocess.run([rustbin, p], capture_output=True, text=True)
            st = "JSONFEHL" if "JSON:" in r.stdout else urteil(r.returncode == 0)
        au = "-"
        if hat_his:
            h = subprocess.run([sys.executable, his, p], capture_output=True, text=True)
            au = urteil(h.returncode == 0)
        gemessen = [x for x in (lw, fw, st, au) if x != "-"]
        norm = {("REFUSED" if x == "JSONFEHL" else x) for x in gemessen}
        uneinig = len(norm) > 1
        abweichend += uneinig
        print("  %-34s %-10s %-10s %-10s %-10s%s" % (f[:-5], lw, fw, st, au,
                                                     "   <-- UNEINIG" if uneinig else ""))

    print()
    print("=" * 92)
    print(f"  Dateien mit uneinigem Urteil: {abweichend} von {len(dateien)}")
    print()
    print("  POSITIVKONTROLLEN: K1 und K2 muessen ueberall CONFORMS zeigen, K3 ueberall REFUSED.")
    print("  Zeigen sie das nicht, misst dieser Lauf nichts und das Ergebnis ist zu verwerfen.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None))
