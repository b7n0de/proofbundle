"""A public surface that takes a filesystem path rejects a non-path with a TYPED error, before the os call.

THE CLASS (deep gate wf_cfe249d0-ee8, finding L1-01, P2). ``evaluation_card_hash`` and ``prereg_hash``
leaked raw exceptions on a non-path argument — measured: OverflowError, TypeError and FileNotFoundError
across the corpus. The int case is worse than a wrong type: ``os.stat(1)`` reads a FILE DESCRIPTOR, not
a path, so an integer argument does not merely fail, it inspects stdout.

WHY A TYPE FLOOR AND NOT A WIDER except-TUPLE. Catching OverflowError closes exactly one member of an
open set; the next ArithmeticError sibling walks through, and the fd side effect happens either way
because the os call still runs. The floor rejects before the boundary.

THE INVARIANT ALREADY EXISTED HERE — ``load_bundle`` implements it verbatim ("bundle path must be a path
string, got int (fail-closed)"). It was never applied to its two siblings. That is why this file is a
FAMILY test: it derives the members from the signatures instead of asserting the two we happen to know.
"""
from __future__ import annotations

import inspect
import unittest

import proofbundle
from proofbundle.errors import ProofBundleError

# Everything that is not a path. The int values matter most: they are the fd-confusion arm.
KORPUS = (2**31, 2**53, 2**63, 10**400, -10**400, 1.5, True, bytearray(b"x"), None, [], {}, object())


def _restargumente(fn):
    """Die uebrigen PFLICHT-Argumente, harmlos befuellt.

    Die erste Fassung rief jede Flaeche mit genau EINEM Argument auf. ``verify_prereg(protocol_path,
    claim)`` nimmt aber zwei, und der resultierende "missing 1 required positional argument"-TypeError
    zaehlte als roh entkommene Ausnahme: 24 gemeldete Fehler, die alle nur ueber meine eigene
    Aufrufform sprachen und nichts ueber den Typboden. Eine Zahl ohne ihren Gegenstand.
    """
    rest = []
    ps = list(inspect.signature(fn).parameters.values())[1:]
    for x in ps:
        if x.default is not inspect.Parameter.empty or x.kind in (
                inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY):
            continue
        # DER INHALT ENTSCHEIDET, OB DER PFAD UEBERHAUPT ANGEFASST WIRD. Ein leeres {} laesst
        # verify_prereg sofort mit "carries no prereg_sha256 (not pre-registered)" zurueckkehren — der
        # Test lief dann gruen, OHNE die Flaeche je zu betreten, und bestand deshalb auch gegen die
        # Vor-Fix-Fassung. Ein Korpus, der den Gegenstand nicht erreicht, misst nichts.
        rest.append({"prereg_sha256": "00" * 32, "evaluation_card_sha256": "00" * 32})
    return rest


def _familie():
    """Public verify_*/load_* surfaces whose FIRST parameter is a path, derived from the signatures."""
    out = []
    for name in dir(proofbundle):
        if not name.startswith(("verify_", "load_")):
            continue
        fn = getattr(proofbundle, name)
        if not callable(fn):
            continue
        try:
            ps = list(inspect.signature(fn).parameters.values())
        except (TypeError, ValueError):
            continue
        if ps and ps[0].name.endswith("_path"):
            out.append((name, fn, ps[0].name))
    return out


class PfadTypBoden(unittest.TestCase):

    def test_die_familie_ist_nicht_leer(self):
        """Ohne das koennte die Ableitung stillschweigend nichts finden und der Test 'bestuende'."""
        familie = _familie()
        self.assertGreaterEqual(len(familie), 2, f"die Familie ist auf {len(familie)} geschrumpft")

    def test_kein_nicht_pfad_entkommt_ungetypt(self):
        for name, fn, param in _familie():
            for wert in KORPUS:
                with self.subTest(flaeche=name, typ=type(wert).__name__):
                    try:
                        fn(wert, *_restargumente(fn))
                    except ProofBundleError:
                        pass                                   # der einzig erlaubte Fehlerpfad
                    except BaseException as exc:               # noqa: BLE001 - genau das ist der Fund
                        self.fail(f"{name}({param}={type(wert).__name__}) liess {type(exc).__name__} "
                                  "roh entkommen")

    def test_gegenrichtung_ein_echter_pfad_wird_nicht_abgelehnt(self):
        """Ohne diese Zeile waere ein Boden, der ALLES ablehnt, von einem richtigen nicht zu unterscheiden.

        Geprueft wird die TYP-Ebene: ein nicht existierender, aber typrichtiger Pfad darf NICHT am
        Typboden scheitern — er darf nur an dem scheitern, was danach kommt.
        """
        import pathlib
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            fehlt = pathlib.Path(td) / "gibt_es_nicht.json"
            for name, fn, _ in _familie():
                for typrichtig in (str(fehlt), fehlt):
                    with self.subTest(flaeche=name, form=type(typrichtig).__name__):
                        try:
                            fn(typrichtig, *_restargumente(fn))
                        except BaseException as exc:           # noqa: BLE001
                            self.assertNotIn("must be a path string", str(exc),
                                             f"{name} wies einen typrichtigen Pfad am Typboden ab")


if __name__ == "__main__":
    unittest.main()
