"""Der EINE Deckel für Testlasten, die aus einem Budget-Wert abgeleitet werden.

WARUM ES IHN GIBT. Ein Mutationsoperator, der eine Budget-Konstante hochsetzt
(`idx=90`: `data_digests: 2.000 -> 2.000.000.000`), steuert damit die GRÖSSE jeder Testlast, die
aus diesem Wert gebaut wird. Gemessen 11.09.2026: drei Sampler massen 428,9 -> 51.129,2 MiB in
58 s (rund 874 MiB/s); unter `RLIMIT_AS` von 6 GiB endete derselbe Ausdruck nach 7,87 s mit
`MemoryError`. Auf dem Runner ist das nicht der Fehlschlag des Tests, sondern sein **Tod** — und
ein toter Test tötet den Mutanten nicht, er meldet SIGKILL.

WARUM EINE ELEMENTZAHL DER FALSCHE DECKEL IST, und das ist der Fund beim Bau dieser Datei. Die
erste Fassung deckelte auf 100.000 Elemente, quer über alle Achsen. `DEFAULT_BUDGET.string_len`
ist aber **1.000.000** — ein Deckel von 100.000 hätte `"y" * (string_len - 1)` auf 99.999 Zeichen
gekürzt, und damit hätte dieser Test die Grenze, die er prüft, nicht mehr erreicht. Ein Deckel,
der legitime Werte abschneidet, macht aus einem wirksamen Test einen grünen. Die Achsen sind nicht
vergleichbar: 1.000.000 ZEICHEN sind 1 MB, 1.000.000 DIGESTS à 64 Byte sind 64 MB, und
1.000.000 erzeugte ed25519-Schlüssel sind Minuten CPU.

DIE EIGENSCHAFT, an der dieser Deckel hängt, ist deshalb der **Speicherbedarf**, nicht die Anzahl:
`bytes_je_element` sagt, was ein Element kostet, und der Deckel ergibt sich daraus. Jeder heute
legitime Budget-Wert passt darunter durch — gemessen, nicht gehofft (siehe
`tests/test_lauf11_l3_testlast_ist_gedeckelt.py::test_der_deckel_schneidet_keinen_legitimen_wert_ab`).

Owner-Anordnung OA-afa1e17cfa Option B (11.09.2026) und Deep Gate Lauf 11, Fund `LAUF11-L3`.
"""
from __future__ import annotations

#: Obergrenze für EINE abgeleitete Testlast. 64 MiB ist reichlich über jedem legitimen Wert dieser
#: Suite und weit unter dem, was einen Runner tötet.
MAX_TESTLAST_BYTES = 64 * 1024 * 1024

#: Rückwärtskompatibler Name: `tests/test_budget.py` führte ihn zuerst, Doctors und Kommentare
#: nennen ihn. Er ist der Deckel für die teuerste übliche Elementgröße (ein 64-Zeichen-Digest).
HARTER_LASTDECKEL = MAX_TESTLAST_BYTES // 64


#: Was ein Element auf welcher Achse kostet, in Bytes. GEMESSEN, nicht geschaetzt — und der Beleg
#: ist ausfuehrbar: `tests/test_lauf11_l3_testlast_ist_gedeckelt.py` traegt je Achse die Messform
#: (die Struktur, die die Suite wirklich baut) und misst sie mit `tracemalloc` nach; liegt diese
#: Tabelle unter der Wirklichkeit, faellt `test_die_kostentabelle_ist_gemessen_nicht_geschaetzt`.
#:
#: LAUF12-L3 F3/F4/F5 (P1): die erste Fassung dieser Tabelle behauptete im Kommentar „GEMESSEN" und
#: war es nicht. Gemessen von der Linse (tracemalloc, CPython 3.10): `list(range(n))` kostet 35,97 B
#: je Element (jeder Wert über 256 ist ein eigenes PyLong), nicht 8 — unter dem Mutanten
#: `json_nodes = 200_000_000` wuchs EINE Testlast auf 521 MiB statt der versprochenen 64 MiB.
#: `ArchiveTimeStamp("sha256", "a"*64, i)` kostet 292 B, nicht 256 (305 MiB gemessen); ein
#: 64-Zeichen-Hex-String in einer Liste 121 B, nicht 64. Dieselbe Klasse wie der phi4-Fund an
#: `bytes_je_element=64`: eine Zahl, die an der Form hängt statt an der Messung.
KOSTEN_JE_ELEMENT = {
    "data_digests": 128,  # ["%064x" % i ...]: 121,9 B/Element gemessen (str-Objekt + Zeiger)
    "disclosures": 256,  # sd-jwt-Disclosure
    "input_bytes": 1,  # ein Byte
    "int_bits": 1,  # ein Bit
    "json_depth": 2,  # eine Klammer je Ebene
    "json_nodes": 40,  # list(range(n)): 36,0 B/Element gemessen (PyLong + Zeiger)
    "merkle_path": 128,  # [bytes(32)]: 73,5 B gemessen; Hex-Form wie data_digests 121,9 B
    "renewal_ats_chain": 384,  # [[ArchiveTimeStamp]] wie in der Kostenkurve: 356,7 B gemessen (nackt 292,8)
    "signatures": 320,  # [{"sig": "AA=="} ...] je ein frisches dict: 240,1 B gemessen
    "string_len": 1,  # ein Zeichen
    "witnesses": 2048,  # Witness-vkey: ML-DSA-44 = 1313 B Schluesselmaterial, base64 ~1800 B
}


def gedeckelt(wert: int, *, bytes_je_element: int) -> int:
    """Der Budget-Wert, begrenzt auf das, was `MAX_TESTLAST_BYTES` an Elementen dieser Größe trägt.

    `bytes_je_element` IST PFLICHT UND HAT KEINE VOREINSTELLUNG — das ist der Fund einer
    Gegenlesung durch eine zweite Modellfamilie (phi4:14b, 11.09.2026), und er war berechtigt.

    Die erste Fassung hatte `= 64` als Voreinstellung, mit der Begründung "die teuerste übliche
    Form, ein 64-Zeichen-Digest". Gemessen an einer echten Aufrufstelle war das falsch:
    `test_kappe_vor_arbeit_signaturzeilen.py` baut `[wvkey] * gedeckelt(witnesses)`, und ein
    ML-DSA-44-Witness-vkey trägt 1313 Byte Schlüsselmaterial, base64-kodiert rund 1800 Byte. Mit
    der Voreinstellung 64 hätte der Deckel dort 1.048.576 Elemente zugelassen — **1,9 GB statt der
    beabsichtigten 64 MB**, Faktor 28 zu lasch, und zwar genau im Mutantenfall, für den es ihn
    gibt.

    DIE KLASSE: eine Voreinstellung verlagert eine Entscheidung auf den Aufrufer und wird dann
    nicht getroffen, sondern vergessen. Ohne sie MUSS jede Stelle sagen, was sie baut — und wer es
    nicht weiß, merkt es beim Schreiben statt beim OOM.
    """
    if bytes_je_element < 1:
        raise ValueError("bytes_je_element muss mindestens 1 sein")
    return min(int(wert), MAX_TESTLAST_BYTES // bytes_je_element)
