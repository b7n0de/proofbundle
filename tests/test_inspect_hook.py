"""inspect_ai hook (v1.0): opt-in safety + signed receipt from a real EvalLog (data.log)."""
import asyncio
import json
import os
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

FX = Path(__file__).resolve().parent / "fixtures" / "inspect_logs" / "safety_refusal_demo.eval"


def verhalten_wenn_inspect_fehlt(in_der_bahn: bool) -> str:
    """Was ein FEHLENDES inspect_ai bedeutet — "fail" in der Release-Bahn, sonst "skip".

    WEG B des Nachtrags 20260826T213824Z, und die Begruendung in einer Zeile: Weg A haengt daran,
    dass die Umgebung das Richtige tut — schlaegt die Installation des Extras still fehl, kehrt der
    Skip zurueck und der Lauf sieht wieder gruen aus; Weg B bindet die Eigenschaft an den TEST, wo
    sie eine Umgebungsaenderung nicht verlieren kann.

    Warum "in der Bahn" hier ``CI`` ist und keine neu erfundene Marke: das dev-Extra ENTHAELT
    ``inspect_ai>=0.3.112,<0.4`` (pyproject), und die CI-Jobs installieren ``.[dev,…]``. Dort ist
    ein fehlendes inspect_ai also kein legitimes Fehlen, sondern ein Defekt der Installation. Eine
    eigene Marke haette niemanden, der sie setzt — ein Mechanismus ohne Aufrufer.

    Als reine Funktion, damit die Entscheidung PRUEFBAR ist, ohne einen Import zu faelschen.
    """
    return "fail" if in_der_bahn else "skip"


class TestInspectHook(unittest.TestCase):
    def setUp(self):
        try:
            from inspect_ai.log import read_eval_log  # noqa: F401
        except ImportError:
            grund = ("inspect_ai not installed (pip install proofbundle[inspect])")
            if verhalten_wenn_inspect_fehlt(bool(os.environ.get("CI"))) == "fail":
                self.fail(grund + " — in der Release-Bahn ist das ein Fehlschlag und kein Skip: "
                          "das dev-Extra enthaelt inspect_ai, sein Fehlen ist hier ein Defekt der "
                          "Installation. Ein uebersprungener Test darf in einem "
                          "releaseentscheidenden Lauf nicht wie ein bestandener aussehen.")
            self.skipTest(grund)

    def _data(self):
        from inspect_ai.log import read_eval_log
        log = read_eval_log(str(FX), header_only=True)
        return types.SimpleNamespace(log=log, eval_id="demo", run_id="r", eval_set_id=None)

    def test_opt_in_off_no_receipt(self):
        from proofbundle.inspect_hook import ProofbundleHooks
        with TemporaryDirectory() as d:
            os.environ.pop("PROOFBUNDLE_EMIT", None)
            os.environ["PROOFBUNDLE_OUT"] = d
            asyncio.run(ProofbundleHooks().on_task_end(self._data()))
            self.assertEqual(list(Path(d).glob("*.json")), [])

    def test_opt_in_emits_verifiable_receipt(self):
        from proofbundle import verify_bundle
        from proofbundle.evalclaim import decode_eval_claim
        from proofbundle.inspect_hook import ProofbundleHooks
        with TemporaryDirectory() as d:
            os.environ["PROOFBUNDLE_EMIT"] = "1"
            os.environ["PROOFBUNDLE_OUT"] = d
            os.environ["PROOFBUNDLE_THRESHOLD"] = "0"
            asyncio.run(ProofbundleHooks().on_task_end(self._data()))
            files = list(Path(d).glob("*.json"))
            os.environ.pop("PROOFBUNDLE_EMIT", None)
            self.assertEqual(len(files), 1)
            b = json.loads(files[0].read_text())
            self.assertTrue(verify_bundle(b).ok)
            dec = decode_eval_claim(b)
            self.assertEqual(dec["suite"], "safety_refusal_demo")
            self.assertNotIn("mockllm", json.dumps(dec))        # model stays a salted commitment

    def test_enabled_reflects_env(self):
        from proofbundle.inspect_hook import ProofbundleHooks
        os.environ["PROOFBUNDLE_EMIT"] = "1"
        self.assertTrue(ProofbundleHooks().enabled())
        os.environ["PROOFBUNDLE_EMIT"] = "0"
        self.assertFalse(ProofbundleHooks().enabled())
        os.environ.pop("PROOFBUNDLE_EMIT", None)


class TestUeberspringerIstInDerBahnEinFehlschlag(unittest.TestCase):
    """Der Muss-Fehlschlag zu Weg B — und er laeuft AUCH ohne inspect_ai.

    Genau das ist der Punkt: die Entscheidung, ob ein fehlendes inspect_ai ein Skip oder ein
    Fehlschlag ist, darf nicht selbst davon abhaengen, ob inspect_ai da ist.
    """

    def test_in_der_bahn_ist_es_ein_fehlschlag(self):
        self.assertEqual(verhalten_wenn_inspect_fehlt(True), "fail")

    def test_ausserhalb_bleibt_der_skip(self):
        """ANTI-TAUTOLOGIE: die Funktion sagt nicht immer "fail" — sonst waere der Test oben
        wertlos und jeder Entwicklerlauf ohne das Extra waere rot."""
        self.assertEqual(verhalten_wenn_inspect_fehlt(False), "skip")

