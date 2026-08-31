#!/usr/bin/env python3
"""
Erzeugt die Sonden aus den Vektoren des Autors. Die Vektoren selbst werden NICHT
mitgeliefert — dieses Paket transformiert seinen Baum, statt ihn weiterzuverbreiten.

usage: sonden.py <pfad-zu-cap-1/src/vectors> <ausgabeverzeichnis>
"""
import json
import os
import re
import sys

def main(v, out):
    os.makedirs(out, exist_ok=True)
    gebaut = []

    # ── S10, der scharfe Fall: doppeltes integrity.complete, erst true dann false.
    # PV-03 fuehrt eine fehlgeschlagene Einheit; unter R7 darf complete dann nicht true sein.
    roh = open(os.path.join(v, "PV-03.json")).read()
    m = re.search(r'("complete"\s*:\s*)(true|false)', roh)
    if not m:
        print("PV-03: kein complete gefunden", file=sys.stderr)
        return 2
    p = os.path.join(out, "S10_doppeltes_complete.json")
    open(p, "w").write(roh[:m.start()] + '"complete": true,\n  ' + roh[m.start():])
    gebaut.append(("S10_doppeltes_complete",
                   "PV-03 mit doppeltem integrity.complete: erst true, dann false"))

    # ── S9, die andere Richtung: doppeltes eligible, erst gueltig dann R1-brechend.
    b = json.load(open(os.path.join(v, "PV-01.json")))
    el = b["strata"][0]["eligible"]
    roh1 = json.dumps(b, indent=1)
    alt = f'"eligible": {el},'
    p = os.path.join(out, "S09_doppelter_eligible.json")
    open(p, "w").write(roh1.replace(alt, f'"eligible": {el},\n   "eligible": {el + 7},', 1))
    gebaut.append(("S09_doppelter_eligible",
                   f"PV-01 mit doppeltem eligible: erst {el} (R1 haelt), dann {el+7} (R1 bricht)"))

    # ── POSITIVKONTROLLEN. Ohne sie misst eine Erkennungsrate nichts.
    # K1: der unveraenderte Vektor. Muss von jeder Umsetzung angenommen werden.
    open(os.path.join(out, "K1_positivkontrolle_PV03.json"), "w").write(
        open(os.path.join(v, "PV-03.json")).read())
    gebaut.append(("K1_positivkontrolle_PV03", "PV-03 unveraendert. MUSS angenommen werden"))
    open(os.path.join(out, "K2_positivkontrolle_PV01.json"), "w").write(roh1)
    gebaut.append(("K2_positivkontrolle_PV01", "PV-01 unveraendert. MUSS angenommen werden"))

    # K3: eine ECHTE Regelverletzung ohne doppelten Schluessel. Muss von jeder
    # Umsetzung verweigert werden — zeigt, dass die Sonden nicht 'alles verweigern'.
    b3 = json.load(open(os.path.join(v, "PV-01.json")))
    b3["strata"][0]["eligible"] = el + 7
    json.dump(b3, open(os.path.join(out, "K3_negativkontrolle_R1.json"), "w"), indent=1)
    gebaut.append(("K3_negativkontrolle_R1",
                   "PV-01 mit einfach gebrochenem R1. MUSS verweigert werden"))

    for n, w in gebaut:
        print(f"  {n:34s} {w}")
    return 0

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
