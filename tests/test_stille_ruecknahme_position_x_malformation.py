"""OWNER-ANORDNUNG 2026-09-08 (Karte OA-dccd141d78) — deep gate Lauf 5, Fund L4-600-01 (P1).

DER FUND: `relation.successor_warning` uebersprang ein angehaengtes, standalone VERIFIZIERTES
Receipt still, sobald dessen EIGENER `relationships`-Block einen Formfehler trug — und mit ihm die
Ruecknahme, die es ueber dieses Receipt deklariert. Der Angreifer legt neben die `retracts`-Kante
eine zweite, absichtlich fehlerhafte; `validate_relationships` meldet einen Fehler, die Schleife
geht weiter, `successor_warning` liefert None. Die ganze Kette dahinter kippt lautlos in die
freundliche Richtung: supersededByAttached fehlt -> `reject_superseded` findet nichts ->
policy_ok bleibt True -> safeForAutomation false->true, CLI exit 3->0.

In Python UND Rust identisch, weshalb das Differential zwischen beiden blind war: ein Vergleich
zweier gleicher Fehler ist still.

DIE OWNER-ENTSCHEIDUNG lautete gegen mein Restrisiko: vor dem Tag schliessen, das stille continue
durch `relation:malformed_successor` ersetzen, die Nachbarn im selben Durchgang, und als Test eine
parametrisierte Matrix `position x malformation`. Das ist diese Datei.

WARUM EINE MATRIX UND KEIN EINZELFALL: der Fund ist keine Eigenschaft EINER Fehlbildung an EINER
Stelle. Er ist die Eigenschaft "ein unlesbarer Block schweigt" — und die muss an jeder Stelle
gelten, an der ein Block unlesbar werden kann, fuer jede Art, auf die er es werden kann. Ein
Punktfixture haette die eine Zelle geschlossen und die Klasse stehen gelassen.

WAS DIE MATRIX HEUTE WIRKLICH DECKT, ehrlich gezaehlt (Gegenlesung 08.09.2026): 4 Positionen x 9
Malformationen sind 36 Zellen, aber KEINE 36 unabhaengigen Bindungen. `validate_relationships`
bewertet den Block ATOMAR — ein einziger kaputter Eintrag entwertet die Liste, unabhaengig von
Position und Anzahl. Drei der vier Positionen laufen deshalb durch denselben Zweig, und alle neun
Malformationen kollabieren, bezogen auf `successor_warning`, auf eine Bedingung. Real sind es ZWEI
Codepfade, achtzehnfach wiederholt. Die Breite ist trotzdem nicht wertlos: sie ist der
Regressionsschutz fuer den Tag, an dem die Auswertung PER KANTE statt pro Block entscheidet — dann
werden aus den zwei Pfaden viele, und die Zellen stehen schon da. Aber wer diese Datei liest, soll
nicht 36 Bindungen sehen, wo zwei sind.

WARUM DIE WIRKUNG UND NICHT NUR DER RUECKGABEWERT (`TestWirkungBisAnsExitTor`): eine Zusicherung
ueber den Rueckgabewert von `successor_warning` bindet den MELDETEXT. Der Fund handelt aber davon,
dass ein zurueckgezogenes Receipt als automatisierungssicher gemeldet wird — das ist eine Aussage
ueber `safeForAutomation` am Ende der Kette. Beides steht hier, und die zweite Klasse ist die,
wegen der jemand dieses Paket einsetzt.
"""
import json
import unittest
from pathlib import Path

from proofbundle.relation import (
    CODE_RELATION_MALFORMED_SUCCESSOR,
    successor_warning,
    validate_relationships,
)

SUBJ = "a" * 64
NACHBAR = "b" * 64
ZWEITER = "c" * 64


def kante(ziel=SUBJ, relation="retracts", **extra):
    e = {"relation": relation,
         "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": ziel}}
    e.update(extra)
    return e


# ── Die zweite Achse: WIE wird ein Block unlesbar? ────────────────────────────────────────────
#
# Jede Fehlbildung ist so gewaehlt, dass `validate_relationships` sie WIRKLICH beanstandet — das
# prueft `test_jede_malformation_wird_von_validate_relationships_auch_beanstandet` ausdruecklich
# nach. Ohne diese Vorbedingung waere eine Zelle gruen, weil sie gar keinen unlesbaren Block
# erzeugt hat: eine Vorbedingung, die sich selbst liefert, prueft nichts.
MALFORMATIONEN = {
    "unbekanntes_feld": lambda: kante(unbekanntes_feld=1),
    "unbekannte_relation": lambda: kante(relation="ersetzt_irgendwie"),
    "digest_kein_hex": lambda: {"relation": "retracts", "targetReceiptDigest": {
        "digestAlgorithm": "jcs-sha256-v1", "digest": "kurz"}},
    "digestalgorithm_fehlt": lambda: {"relation": "retracts",
                                      "targetReceiptDigest": {"digest": SUBJ}},
    "digestalgorithm_fremd": lambda: {"relation": "retracts", "targetReceiptDigest": {
        "digestAlgorithm": "sha3-512-irgendwas", "digest": SUBJ}},
    "kante_ist_skalar": lambda: 42,
    "kante_ohne_ziel": lambda: {"relation": "retracts"},
    "reasoncode_fremd": lambda: kante(reasonCode="weil_ich_es_kann"),
    "declaredat_ohne_z": lambda: kante(declaredAt="2026-09-08 17:00:00"),
}

# ── Die erste Achse: WO sitzt die Fehlbildung? ────────────────────────────────────────────────
#
# `nur_die_kaputte` ist der eigentliche Angriff in Reinform: es gibt NUR den unlesbaren Block,
# und frueher war das Ergebnis Schweigen. Die uebrigen Positionen pruefen, dass die Stelle im
# Block nichts daran aendert — ein Verdikt, das an der Reihenfolge der Kanten haengt, ist ein
# Verdikt, dessen Ausgang der Angreifer mitschreibt.
POSITIONEN = ("nur_die_kaputte", "kaputte_vor_ruecknahme", "kaputte_nach_ruecknahme",
              "kaputte_im_nachbar_receipt")


def baue(position: str, malformation: str) -> dict:
    """Das `related`-Bild fuer eine Zelle der Matrix. Immer so, dass eine Ruecknahme ueber SUBJ
    deklariert ist — die Frage ist nur, ob der Verifizierer sie noch sieht."""
    kaputt = MALFORMATIONEN[malformation]()
    if position == "nur_die_kaputte":
        return {NACHBAR: {"verified": True, "relationships": [kaputt]}}
    if position == "kaputte_vor_ruecknahme":
        return {NACHBAR: {"verified": True, "relationships": [kaputt, kante()]}}
    if position == "kaputte_nach_ruecknahme":
        return {NACHBAR: {"verified": True, "relationships": [kante(), kaputt]}}
    if position == "kaputte_im_nachbar_receipt":
        # Der unlesbare Block sitzt in einem ANDEREN angehaengten Receipt; das erste traegt gar
        # keine Kante auf SUBJ. Es gibt also keine lesbare Ruecknahme — nur eine unlesbare.
        return {ZWEITER: {"verified": True, "relationships": [kante(ziel=NACHBAR,
                                                                   relation="derivedFrom")]},
                NACHBAR: {"verified": True, "relationships": [kaputt]}}
    raise AssertionError(f"unbekannte Position {position!r}")


class TestMatrixPositionXMalformation(unittest.TestCase):
    """Jede Zelle: ein unlesbarer Block SCHWEIGT NICHT."""

    def test_jede_malformation_wird_von_validate_relationships_auch_beanstandet(self):
        """VORBEDINGUNG der ganzen Matrix, ausdruecklich geprueft statt angenommen.

        Erzeugt eine der Fehlbildungen in Wahrheit KEINEN Beanstandungsgrund, dann testet ihre
        Zeile in der Matrix nichts und waere still gruen — genau die Fehlerklasse, die dieser
        Fix schliesst, eine Ebene hoeher."""
        for name, bauen in MALFORMATIONEN.items():
            with self.subTest(malformation=name):
                self.assertTrue(validate_relationships([bauen()]),
                                f"{name} erzeugt keinen Formfehler — die Matrixzeile prueft nichts")

    def test_jede_zelle_meldet_statt_zu_schweigen(self):
        for position in POSITIONEN:
            for malformation in MALFORMATIONEN:
                with self.subTest(position=position, malformation=malformation):
                    meldung = successor_warning(None, baue(position, malformation),
                                                subject_hex=SUBJ)
                    self.assertIsNotNone(
                        meldung,
                        f"[{position} x {malformation}] ein verifiziertes Receipt erklaert etwas "
                        "ueber dieses Receipt, das der Verifizierer nicht lesen kann — und die "
                        "Antwort ist Schweigen. Genau das ist L4-600-01.")

    def test_wo_KEINE_lesbare_ruecknahme_bleibt_nennt_die_meldung_den_stabilen_code(self):
        """`nur_die_kaputte` und `kaputte_im_nachbar_receipt` tragen keine lesbare Ruecknahme —
        dort MUSS der typisierte Code fallen, nicht irgendein Text."""
        for position in ("nur_die_kaputte", "kaputte_im_nachbar_receipt"):
            for malformation in MALFORMATIONEN:
                with self.subTest(position=position, malformation=malformation):
                    meldung = successor_warning(None, baue(position, malformation),
                                                subject_hex=SUBJ)
                    self.assertIn("relation:malformed_successor", meldung)
                    self.assertIn(CODE_RELATION_MALFORMED_SUCCESSOR, meldung)

    def test_eine_LESBARE_ruecknahme_gewinnt_gegen_die_unlesbare(self):
        """Die Ordnung, und sie ist kein Geschmack: `related` ist ein dict, dessen
        Einfuegereihenfolge der Vorleger mitbestimmt. Haenge die unlesbare Meldung an der
        Iterationsreihenfolge, koennte ein Angreifer die praezise Meldung ('dieses Receipt ist
        zurueckgezogen') durch die unpraezise ('da ist etwas, das ich nicht lesen kann')
        ersetzen, indem er die Reihenfolge waehlt. Dieselbe Regel, die `_walk_chain` fuer Zyklen
        anwendet: ein Befund, der ordnungsunabhaengig ist, wird vor dem Abstieg entschieden."""
        for malformation in MALFORMATIONEN:
            for zuerst in (True, False):
                with self.subTest(malformation=malformation, kaputte_zuerst=zuerst):
                    kaputt = {ZWEITER: {"verified": True,
                                        "relationships": [MALFORMATIONEN[malformation]()]}}
                    echt = {NACHBAR: {"verified": True, "relationships": [kante()]}}
                    related = {**kaputt, **echt} if zuerst else {**echt, **kaputt}
                    meldung = successor_warning(None, related, subject_hex=SUBJ)
                    self.assertIn("retracted_by_attached", meldung)


class TestAntiParitaet(unittest.TestCase):
    """Der Riegel darf nicht einfach immer melden — sonst bindet er nichts."""

    def test_ein_receipt_OHNE_relationships_schweigt_weiter(self):
        """Es hat nichts erklaert. Das ist der Unterschied, auf den es ankommt: ein fehlendes
        Feld ist keine unlesbare Aussage, sondern gar keine."""
        self.assertIsNone(successor_warning(None, {NACHBAR: {"verified": True}}, subject_hex=SUBJ))

    def test_ein_receipt_mit_relationships_None_schweigt_weiter(self):
        self.assertIsNone(successor_warning(
            None, {NACHBAR: {"verified": True, "relationships": None}}, subject_hex=SUBJ))

    def test_ein_NICHT_verifiziertes_receipt_hat_keine_stimme_auch_unlesbar_nicht(self):
        """Sonst koennte jeder Beliebige durch Anhaengen von Muell ein fremdes Receipt als
        'moeglicherweise zurueckgezogen' markieren — ein Denial-of-Service auf die Aussage."""
        for malformation in MALFORMATIONEN:
            with self.subTest(malformation=malformation):
                self.assertIsNone(successor_warning(
                    None, {NACHBAR: {"verified": False,
                                     "relationships": [MALFORMATIONEN[malformation]()]}},
                    subject_hex=SUBJ))

    def test_ein_LESBARER_block_ohne_bezug_auf_dieses_receipt_schweigt(self):
        """Eine saubere Kante, die auf ein ANDERES Receipt zeigt, ist kein Fund."""
        self.assertIsNone(successor_warning(
            None, {NACHBAR: {"verified": True, "relationships": [kante(ziel=ZWEITER)]}},
            subject_hex=SUBJ))

    def test_ohne_subject_hex_gibt_es_nichts_zu_entscheiden(self):
        self.assertIsNone(successor_warning(
            None, {NACHBAR: {"verified": True, "relationships": [MALFORMATIONEN["kante_ist_skalar"]()]}},
            subject_hex=None))


class TestDieREICHWEITEIstGEWOLLTUndBenannt(unittest.TestCase):
    """Ein unlesbarer Block blockt AUCH, wenn seine lesbaren Kanten woandershin zeigen.

    GEFUNDEN VON EINER GEGENLESUNG (08.09.2026) als "ungetestete Verhaltensaenderung", und sie
    hatte recht: der Fall stand in keinem Test und in keiner Doku. Gemessen:

        malformed MIT Bezug auf dieses Receipt      -> MELDET
        malformed OHNE Bezug (Kante zeigt woanders) -> MELDET      <- die Reichweite
        sauber OHNE Bezug (Kontrolle)               -> SCHWEIGT

    WARUM DAS RICHTIG IST, und warum es trotzdem einen Fall braucht: der Block ist UNLESBAR. Ob
    eine seiner Kanten auf dieses Receipt zeigt, ist damit unbekannt — die Kanten, die sich lesen
    liessen, sagen ueber die anderen nichts. Ein Verifizierer, der hier schweigt, behauptet
    Wissen, das er nicht hat. Der Preis ist ehrlich zu nennen: ein Anhang mit harmlosem
    Formfehler, der vorher durchlief, blockt ab 6.0.0. Genau deshalb steht die Reichweite jetzt
    auch in docs/predicates/relation.md unter `reject_superseded` und nicht nur hier.

    Der Unterschied zum Nachbarfall im conftest-Riegel, wo eine zu weite Bindung ein DEFEKT war:
    dort verschwand eine ECHTE Fehlermeldung hinter einer falschen Erklaerung. Hier wird eine
    ehrliche Unwissenheit als Blocker gemeldet. Das eine ist ein Fehler, das andere fail-closed.
    """

    def test_ein_unlesbarer_block_OHNE_lesbaren_bezug_blockt_EBENSO(self):
        fremd = "d" * 64
        for malformation in MALFORMATIONEN:
            with self.subTest(malformation=malformation):
                kaputt = MALFORMATIONEN[malformation]()
                if isinstance(kaputt, dict) and "targetReceiptDigest" in kaputt:
                    tgt = kaputt["targetReceiptDigest"]
                    if isinstance(tgt, dict) and isinstance(tgt.get("digest"), str) \
                            and len(tgt["digest"]) == 64:
                        tgt["digest"] = fremd          # die LESBARE Kante zeigt woandershin
                meldung = successor_warning(
                    None, {NACHBAR: {"verified": True, "relationships": [kaputt]}},
                    subject_hex=SUBJ)
                self.assertIsNotNone(meldung, (
                    f"[{malformation}] ein unlesbarer Block wird stillgelegt, weil seine LESBARE "
                    "Kante woandershin zeigt — ueber die unlesbaren Kanten sagt das nichts"))
                self.assertIn(CODE_RELATION_MALFORMED_SUCCESSOR, meldung)

    def test_ein_LESBARER_block_ohne_bezug_blockt_NICHT(self):
        """Die Gegenrichtung, und sie trennt 'unlesbar' von 'unbezogen': eine saubere Kante auf
        ein anderes Receipt ist kein Fund. Ohne diesen Fall wuerde der obige auch dann bestehen,
        wenn der Riegel schlicht JEDEN Anhang blockte."""
        fremd = "d" * 64
        self.assertIsNone(successor_warning(
            None, {NACHBAR: {"verified": True, "relationships": [kante(ziel=fremd)]}},
            subject_hex=SUBJ))


class TestWirkungBisAnsExitTor(unittest.TestCase):
    """DIE KLASSE, WEGEN DER DER OWNER NICHT WARTEN WOLLTE: nicht der Meldetext, sondern
    `safeForAutomation`. End-to-end ueber ein ECHT signiertes Decision-Receipt."""

    def _signiert(self):
        from proofbundle import anchors as _anchors
        from proofbundle.decision import emit_decision_receipt
        from proofbundle.dsse import load_payload
        from proofbundle.emit import generate_signer
        beispiele = Path(__file__).resolve().parent.parent / "examples"
        pred = json.loads((beispiele / "decision_receipt_deny.json").read_text(encoding="utf-8"))
        signer = generate_signer()
        env = emit_decision_receipt(pred, signer, strict=True)
        wurzel = _anchors.statement_content_root(load_payload(env)).hex()
        return env, signer.public_key().public_bytes_raw(), wurzel

    _POLICY = {"relations": {"reject_superseded": True}}

    def _verdikt(self, related):
        from proofbundle.decision import verify_decision_receipt
        env, pub, wurzel = self._signiert()
        # die Ruecknahme zeigt auf den ECHTEN content root des signierten Receipts
        related = {h: json.loads(json.dumps(v).replace(SUBJ, wurzel)) for h, v in related.items()}
        r = verify_decision_receipt(env, pub, policy=self._POLICY, related=related)
        self.assertTrue(r["crypto_ok"], "Vorbedingung: die Bytes sind echt signiert")
        return r

    def test_die_LESBARE_ruecknahme_blockt_die_automatisierung(self):
        """Kontrolle: so soll es aussehen, wenn alles sauber ist."""
        r = self._verdikt({NACHBAR: {"verified": True, "relationships": [kante()]}})
        self.assertFalse(r["policy_ok"])
        self.assertFalse(r["automation"]["safeForAutomation"])

    def test_die_UNLESBARE_ruecknahme_blockt_die_automatisierung_EBENSO(self):
        """Der Fund. Frueher: policy_ok True, safeForAutomation True, exit 0 — obwohl ein
        verifiziertes Receipt eine Ruecknahme ueber dieses hier deklariert hat."""
        for malformation in MALFORMATIONEN:
            with self.subTest(malformation=malformation):
                r = self._verdikt(baue("nur_die_kaputte", malformation))
                self.assertFalse(
                    r["policy_ok"],
                    f"[{malformation}] reject_superseded laesst ein Receipt durch, ueber das eine "
                    "unlesbare Ruecknahme vorliegt")
                self.assertFalse(r["automation"]["safeForAutomation"])
                self.assertIn("LINEAGE_REQUIREMENT_FAILED",
                              r["automation"]["automationBlockers"])

    def test_OHNE_ruecknahme_bleibt_die_automatisierung_unangetastet(self):
        """Anti-Paritaet auf der Wirkungsebene: der Riegel darf nicht jedes Receipt blocken,
        dem irgendein Nachbar beiliegt."""
        r = self._verdikt({NACHBAR: {"verified": True, "relationships": [kante(ziel=ZWEITER)]}})
        self.assertIsNot(r["policy_ok"], False)


class TestDerZWEITEPythonPfadZiehtMit(unittest.TestCase):
    """Die Owner-Anordnung nennt drei Nachbarn: decision.py, outcome.py und den Rust-Verifizierer.

    GEMESSEN beim Volllesen beider Dateien (decision.py 921 Zeilen, outcome.py 979): sie rufen
    `successor_warning` an EINER Stelle auf und legen das Ergebnis in `lineage.supersededByAttached`
    — von dort greift dieselbe Kette. Der Fix an der Quelle zieht sie also mit, statt eigene
    Aenderungen zu brauchen. Das ist eine ANNAHME ueber zwei Aufrufstellen, und Annahmen ueber
    Aufrufstellen sind genau die, die heute dreimal falsch waren; deshalb steht sie hier als Fall
    und nicht als Kommentar. `TestWirkungBisAnsExitTor` belegt den decision-Pfad, dieser den
    outcome-Pfad."""

    def _signiert(self):
        from proofbundle import anchors as _anchors
        from proofbundle.dsse import load_payload
        from proofbundle.emit import generate_signer
        from proofbundle.outcome import emit_outcome_receipt
        pred = {
            "schemaVersion": "0.1.0",
            "outcomeId": "outcome-stille-ruecknahme",
            "decisionRef": {"sha256": "d" * 64},
            "executor": {"id": "executor:pruefstand"},
            "requestedActionDigest": {"sha256": "e" * 64},
            "status": "executed",
            "effectDigest": {"sha256": "f" * 64},
            "performedAt": "2026-09-08T18:00:00Z",
        }
        signer = generate_signer()
        env = emit_outcome_receipt(pred, signer, strict=True)
        wurzel = _anchors.statement_content_root(load_payload(env)).hex()
        return env, signer.public_key().public_bytes_raw(), wurzel

    def _verdikt(self, related):
        from proofbundle.outcome import verify_outcome_receipt
        env, pub, wurzel = self._signiert()
        related = {h: json.loads(json.dumps(v).replace(SUBJ, wurzel)) for h, v in related.items()}
        r = verify_outcome_receipt(env, pub, policy={"relations": {"reject_superseded": True}},
                                   related=related)
        self.assertTrue(r["crypto_ok"], "Vorbedingung: die Bytes sind echt signiert")
        return r

    def test_outcome_die_UNLESBARE_ruecknahme_blockt_die_automatisierung(self):
        for malformation in MALFORMATIONEN:
            with self.subTest(malformation=malformation):
                r = self._verdikt(baue("nur_die_kaputte", malformation))
                self.assertFalse(r["policy_ok"])
                self.assertFalse(r["automation"]["safeForAutomation"])

    def test_outcome_OHNE_ruecknahme_bleibt_unangetastet(self):
        r = self._verdikt({NACHBAR: {"verified": True, "relationships": [kante(ziel=ZWEITER)]}})
        self.assertIsNot(r["policy_ok"], False)


class TestGateMetaTest(unittest.TestCase):
    """Faengt diese Matrix den Defekt, wenn man ihn wieder einpflanzt?

    DIE ERSTE FASSUNG DIESES FALLS WAR WERTLOS, und eine Gegenlesung hat es gefunden: sie baute
    die alte Logik im Test NACH und pruefte den Nachbau. `successor_warning` wurde nirgends
    aufgerufen — keine Aenderung am Produktionscode haette den Fall je rot faerben koennen. Er
    mass, dass meine eigene Attrappe schweigt. Das ist dieselbe Klasse, die am selben Tag schon
    einmal auffiel: ein Fangnachweis, der den ZUSTAND herstellt statt den PFAD zu gehen, beweist
    nichts.

    Diese Fassung geht den Pfad: sie liest den QUELLTEXT von `relation.py`, setzt den Zweig auf
    das alte stille `continue` zurueck, kompiliert das Ergebnis als eigenes Modul und faehrt die
    Matrix gegen DESSEN `successor_warning`. Verschwindet der Zweig aus dem Produktionscode, faellt
    dieser Fall.

    Zwei Riegel sichern den Fall gegen sich selbst ab; beide sind beim Bauen wirklich angesprungen:
      * die Mutations-Vorlage muss GENAU EINMAL passen, sonst rot — wer den Zweig umbaut, muss
        diesen Fall nachziehen, statt ihn still bestehen zu lassen;
      * die mutierte Datei muss aus DIESEM Baum stammen. Das venv traegt `proofbundle` editable aus
        einem anderen Verzeichnis; beim ersten Lauf wurde genau von dort geladen. Ein Meta-Test,
        der die falsche Datei mutiert, behauptet eine Bindung, die es nicht gibt.
    """

    _NEUER_ZWEIG = (
        "        if not isinstance(nested, list) or validate_relationships(nested):\n"
        "            if unlesbar_hex is None or other_hex < unlesbar_hex:")
    _ALTER_ZWEIG = (
        "        if not isinstance(nested, list) or validate_relationships(nested):\n"
        "            continue\n"
        "        if False:\n"
        "            if unlesbar_hex is None or other_hex < unlesbar_hex:")

    def _mit_stillem_continue(self):
        """Die ECHTE Funktion aus einer Fassung von relation.py, in der der Zweig still ueberspringt."""
        import importlib.util
        import sys
        from proofbundle import relation as _rel

        datei = Path(_rel.__file__).resolve()
        erwartet = (Path(__file__).resolve().parents[1] / "src" / "proofbundle" / "relation.py")
        self.assertEqual(
            datei, erwartet.resolve(),
            f"dieser Meta-Test mutiert {datei}, gemeint ist {erwartet}. Das Modul kommt aus einem "
            "fremden Baum (editable-Installation?) — die Messung liefe ueber anderen Code als den "
            "unter Pruefung")
        quelle = datei.read_text(encoding="utf-8")
        self.assertEqual(
            quelle.count(self._NEUER_ZWEIG), 1,
            "die Mutations-Vorlage passt nicht genau einmal — der Zweig wurde umgebaut; dieser "
            "Meta-Test muss nachgezogen werden, statt still zu bestehen")
        mutiert = quelle.replace(self._NEUER_ZWEIG, self._ALTER_ZWEIG)

        name = "relation_mutiert_fuer_den_metatest"
        spec = importlib.util.spec_from_loader(name, loader=None)
        modul = importlib.util.module_from_spec(spec)
        modul.__file__ = str(datei)
        modul.__package__ = _rel.__package__
        sys.modules[name] = modul
        try:
            exec(compile(mutiert, f"{datei} [mutiert]", "exec"), modul.__dict__)
        finally:
            sys.modules.pop(name, None)
        return modul.successor_warning

    def test_die_matrix_wird_ueber_der_mutierten_ECHTEN_fassung_ROT(self):
        alt = self._mit_stillem_continue()
        gefangen = 0
        zellen = 0
        for position in POSITIONEN:
            for malformation in MALFORMATIONEN:
                zellen += 1
                if alt(None, baue(position, malformation), subject_hex=SUBJ) is None:
                    gefangen += 1
        # Ansage VOR dem Lauf: die alte Fassung schweigt ueberall dort, wo keine LESBARE Ruecknahme
        # daneben liegt — und weil validate_relationships den ganzen Block atomar verwirft, faellt
        # auch bei den gemischten Positionen die Ruecknahme mit weg. Erwartung: ALLE Zellen.
        self.assertEqual(gefangen, zellen,
                         f"erwartet: alle {zellen} Zellen schweigen ueber der mutierten Fassung, "
                         f"gemessen {gefangen}")

    def test_die_mutation_laesst_die_ehrlichen_faelle_UNVERAENDERT(self):
        """Anti-Paritaet des Meta-Tests: die Mutation darf nur den Fund zurueckdrehen, nicht alles
        abschalten. Waere die mutierte Fassung ueberall stumm, saehe der Fall oben genauso aus."""
        alt = self._mit_stillem_continue()
        lesbar = {NACHBAR: {"verified": True, "relationships": [kante()]}}
        self.assertIsNotNone(alt(None, lesbar, subject_hex=SUBJ),
                             "die mutierte Fassung meldet nicht einmal mehr eine LESBARE "
                             "Ruecknahme — dann misst der Fall oben die Mutation nicht, sondern "
                             "einen kaputten Nachbau")
        self.assertIsNone(alt(None, {NACHBAR: {"verified": True}}, subject_hex=SUBJ))


if __name__ == "__main__":
    unittest.main()
