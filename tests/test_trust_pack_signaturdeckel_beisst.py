"""Der `signatures`-Deckel in `verify_trust_pack` ist der EINZIGE auf diesem Pfad — und er war
von keiner Zusicherung gebunden.

HERKUNFT: deep gate Lauf 5, Bestaetigungsrunde auf dem zweiten Einfrier-Kopf, Linse 2 (2026-09-07),
VERDIKT REJECT. Der Riegel-Sweep hatte sechs ungebundene Budget-Aufrufpunkte als eine Gruppe
abgelegt. Die Linse hat alle sechs GLEICHZEITIG mutiert und gemessen: fuenf davon sind nicht bloss
ungetestet, sondern PROVABLY DEAD — `dsse.load_payload()` erzwingt eine Zeile vorher bereits
`string_len` (1 000 000) auf dem base64-Payload, und 1 000 000 base64-Zeichen dekodieren maximal
etwa 750 KB, also wird der lokale `input_bytes`-Vergleich (8 388 608) dort nie erreicht.

DER SECHSTE IST ANDERS, und er ist der Grund fuer diese Datei. `verify_trust_pack` ruft NIE
`dsse.verify_envelope` auf — das sagt der Kommentar in seinem eigenen Rumpf — es hat eine eigene
Schwellwert-Schleife. Es profitiert darum NICHT vom `signatures`-Deckel, den `verify_envelope`
setzt. Sein einziges Backstop ohne den lokalen Deckel ist `json_nodes` (200 000), rund 390-mal
loser, weil ein Signatur-Eintrag nur etwa drei Knoten kostet.

GEMESSEN von der Linse mit einem echten, gueltig signierten Pack, aufgeblaeht mit strukturell
validen und kryptografisch falschen Eintraegen: mit Deckel wird jede Liste ueber 512 abgewiesen; ohne
Deckel wird bei 66 600 Eintraegen echte Ed25519-Arbeit geleistet, rund 130-mal der dokumentierte
Worst Case. Und: repo-weit rief KEIN Test `verify_trust_pack` mit ueberlanger Signaturliste. Der
aehnlich benannte `test_resource_budget_bites_on_wide_signatures` prueft `dsse.verify_envelope`,
einen anderen Pfad — ein Nachbar, der wie die Bindung aussieht und keine ist.

WAS HIER GEBUNDEN WIRD, ist die WIRKUNG und nicht der Meldungstext: gezaehlt wird, wie oft die
Krypto-Pruefung ueberhaupt aufgerufen wird. Ein Deckel, der erst nach der Arbeit meldet, waere kein
Deckel. Reihenfolge dieser Runde (Owner 2026-09-07, nach dem dritten Rueckfall): dieser Fall wurde
ZUERST geschrieben und gegen den defekten Zustand rot gemessen, dann erst galt der Deckel als
gebunden — kein Test, der einem Fix nachtraeglich beigelegt wird.
"""
from __future__ import annotations

import base64
import unittest
from datetime import datetime, timezone

from proofbundle import trust_pack as tp
from proofbundle.budget import DEFAULT_BUDGET
from proofbundle.emit import generate_signer
from proofbundle.trust_pack import sign_trust_pack, verify_trust_pack

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _pub(sk) -> str:
    return base64.b64encode(sk.public_key().public_bytes_raw()).decode("ascii")


def _fixture(threshold: int = 2, n: int = 3):
    sks = {f"root-{i}": generate_signer() for i in range(n)}
    keys = {kid: {"publicKey": _pub(sk), "scheme": "ed25519"} for kid, sk in sks.items()}
    pred = {
        "schemaVersion": "0.1.0", "trustPackId": "tp-deckel", "version": 1,
        "expires": "2027-01-01T00:00:00Z", "prevVersionDigest": None,
        "roles": {"root": {"keyIds": list(keys), "threshold": threshold},
                  "outcomeExecutors": {"keyIds": ["root-0"], "threshold": 1}},
        "keys": keys,
        "nonClaims": ["names which keys hold which role, not that the holders are honest"],
    }
    return pred, sks


def _aufblaehen(env: dict, anzahl: int) -> None:
    """Strukturell valide, kryptografisch falsche Eintraege unter einer ECHTEN root-keyid.

    Genau diese Form ist teuer: die Schleife ueberspringt einen Eintrag nur, wenn sein Schluessel
    schon GUELTIG gezaehlt wurde. Ein ungueltiger Eintrag laeuft jedes Mal durch die Krypto-Pruefung.
    """
    falsch = base64.b64encode(b"x" * 64).decode("ascii")
    env["signatures"].extend({"keyid": "root-2", "sig": falsch} for _ in range(anzahl))


class _Zaehler:
    """Zaehlt die Aufrufe der Krypto-Pruefung — die ARBEIT, nicht die Meldung."""

    def __init__(self):
        self.n = 0
        self._echt = tp._verify_signature_for_alg

    def __enter__(self):
        def gezaehlt(*a, **k):
            self.n += 1
            return self._echt(*a, **k)
        tp._verify_signature_for_alg = gezaehlt
        return self

    def __exit__(self, *exc):
        tp._verify_signature_for_alg = self._echt
        return False


class TestDerSignaturdeckelDesTrustPacksBeisst(unittest.TestCase):
    def test_eine_UEBERLANGE_liste_kostet_NULL_kryptopruefungen(self):
        """DIE ZUSICHERUNG. Nicht 'es kommt eine Fehlermeldung', sondern 'es wird nicht gearbeitet'.

        Ohne den Deckel ist der Verdikt trotzdem `ok=False` — die Eintraege sind ja ungueltig, die
        Schwelle wird nicht erreicht. Das Verdikt allein unterscheidet die zwei Zustaende also NICHT.
        Was sie unterscheidet, ist der Aufwand: mit Deckel null Pruefungen, ohne Deckel eine je
        Eintrag. Genau deshalb zaehlt dieser Fall und liest keinen Text.
        """
        grenze = DEFAULT_BUDGET.signatures
        pred, sks = _fixture(threshold=2)
        # VORBEDINGUNG, DIE DIESEM FALL VON EINER FREMDFAMILIAEREN LINSE AUFGEZWUNGEN WURDE
        # (Lauf 5, sechste Linse, 2026-09-07). Ohne sie war die Null hier eine FORM und keine
        # WIRKUNG: der Zaehler patcht ein Modulattribut, und wenn die Schleife eines Tages einen
        # ANDEREN Namen ruft (Umbenennung mit stehengelassenem Alias), patcht er einen Namen, den
        # niemand aufruft — er zaehlt null, weil er nichts sieht, nicht weil der Deckel greift.
        # GEMESSEN: mit genau dieser Mutation fiel 1 von 3 Faellen, und der Zaehler-Fall war NICHT
        # darunter; sein Nachbar hielt ihn. Jetzt haelt er sich selbst: erst wird bewiesen, dass die
        # Messung ueberhaupt etwas sieht, dann erst bedeutet eine Null etwas.
        gut = sign_trust_pack(pred, {"root-0": sks["root-0"], "root-1": sks["root-1"]})
        with _Zaehler() as vor:
            verify_trust_pack(gut, strict=True, now=_NOW)
        self.assertGreater(vor.n, 0, (
            "VORBEDINGUNG: der Zaehler sieht die Kryptopruefung eines GUELTIGEN Packs nicht. Dann "
            "misst er nichts, und die Null weiter unten waere kein Beweis, sondern ein blinder "
            "Fleck — genau die Klasse, gegen die dieser Zyklus antritt."))

        env = sign_trust_pack(pred, {"root-0": sks["root-0"], "root-1": sks["root-1"]})
        _aufblaehen(env, grenze * 2)
        self.assertGreater(len(env["signatures"]), grenze,
                           "Vorbedingung: die Liste muss den Deckel wirklich ueberschreiten")
        with _Zaehler() as z:
            r = verify_trust_pack(env, strict=True, now=_NOW)
        self.assertFalse(r["ok"], "Ein Pack ueber dem Signaturdeckel darf nicht gueltig sein")
        self.assertEqual(z.n, 0, (
            f"Der Deckel hat {z.n} Kryptopruefungen zugelassen, bevor er abgewiesen hat. Ein Deckel, "
            f"der erst NACH der Arbeit meldet, schuetzt vor nichts — `verify_trust_pack` hat keine "
            f"zweite Grenze auf diesem Pfad, weil es `dsse.verify_envelope` nie ruft."))

    def test_ANTI_PARITAET_eine_liste_AN_der_grenze_wird_ganz_normal_geprueft(self):
        """Die Kontrolle: der Deckel darf nicht einfach immer abweisen.

        An der Grenze muss das Pack normal durchlaufen, die Schwelle erreichen und Arbeit leisten.
        Ohne diesen Fall bestuende der obige auch bei einem `verify_trust_pack`, das gar nichts mehr
        prueft.
        """
        grenze = DEFAULT_BUDGET.signatures
        pred, sks = _fixture(threshold=2)
        env = sign_trust_pack(pred, {"root-0": sks["root-0"], "root-1": sks["root-1"]})
        _aufblaehen(env, grenze - len(env["signatures"]))
        self.assertEqual(len(env["signatures"]), grenze, "Vorbedingung: genau AUF der Grenze")
        with _Zaehler() as z:
            r = verify_trust_pack(env, strict=True, now=_NOW)
        self.assertTrue(r["root_threshold_met"], f"Die Schwelle wird an der Grenze nicht erreicht: {r}")
        self.assertTrue(r["ok"], r)
        self.assertGreater(z.n, 0, "An der Grenze muss ueberhaupt geprueft werden")

    def test_dieser_pfad_geht_WIRKLICH_nicht_ueber_verify_envelope(self):
        """Die Praemisse des ganzen Falls, gemessen statt aus dem Kommentar geglaubt.

        Der Deckel hier ist nur dann der einzige, wenn `verify_trust_pack` den DSSE-Pfad nicht
        benutzt. Statt das dem Kommentar im Rumpf zu glauben, wird `dsse.verify_envelope` durch
        etwas ersetzt, das beim Aufruf wirft: laeuft die Pruefung trotzdem durch, ist sie den Weg
        nie gegangen.
        """
        from proofbundle import dsse

        pred, sks = _fixture(threshold=2)
        env = sign_trust_pack(pred, {"root-0": sks["root-0"], "root-1": sks["root-1"]})
        echt = dsse.verify_envelope
        echt_laden = dsse.load_payload
        gesehen = {"laden": 0}

        def sprengfalle(*a, **k):
            raise AssertionError("verify_trust_pack ist doch ueber dsse.verify_envelope gegangen")

        def gezaehltes_laden(*a, **k):
            gesehen["laden"] += 1
            return echt_laden(*a, **k)

        dsse.verify_envelope = sprengfalle
        dsse.load_payload = gezaehltes_laden
        try:
            r = verify_trust_pack(env, strict=True, now=_NOW)
        finally:
            dsse.verify_envelope = echt
            dsse.load_payload = echt_laden
        # VORBEDINGUNG, ebenfalls von der fremdfamiliaeren Linse erzwungen: eine Sprengfalle, die
        # nicht explodiert, beweist nur dann etwas, wenn das Patchen dieses Moduls den Aufrufer
        # UEBERHAUPT erreicht. Bindet `trust_pack` eines Tages lokal (`from .dsse import ...`),
        # geht das Modulattribut ins Leere und die Sprengfalle schweigt aus dem falschen Grund.
        # `load_payload` wird auf demselben Weg gepatcht und MUSS gerufen werden.
        self.assertGreater(gesehen["laden"], 0, (
            "VORBEDINGUNG: das Patchen von dsse-Attributen erreicht verify_trust_pack nicht mehr. "
            "Dann sagt eine schweigende Sprengfalle nichts ueber den benutzten Pfad."))
        self.assertTrue(r["ok"], r)


if __name__ == "__main__":
    unittest.main()
