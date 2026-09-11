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


#: Was ein Element auf welcher Achse kostet — GEMESSEN an dem, was die Teststellen wirklich
#: bauen, nicht geschaetzt. EINE Quelle: die Aufrufstellen und der Gegenrichtungs-Test lesen
#: dieselbe Tabelle, sonst sind es zwei Aussagen ueber dieselbe Sache.
KOSTEN_JE_ELEMENT = {
    "data_digests": 64,  # sha256-Hex
    "disclosures": 256,  # sd-jwt-Disclosure
    "input_bytes": 1,  # ein Byte
    "int_bits": 1,  # ein Bit
    "json_depth": 2,  # eine Klammer je Ebene
    "json_nodes": 8,  # JSON-Knoten, hier Zahlen
    "merkle_path": 64,  # sha256-Hex
    "renewal_ats_chain": 256,  # ArchiveTimeStamp-Objekt
    "signatures": 256,  # Signatur-Eintrag/Notizblock
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
