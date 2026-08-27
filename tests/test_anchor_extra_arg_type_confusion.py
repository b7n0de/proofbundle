"""GENERALISIERTER Typ-Konfusions-Fuzzer fuer die dict-EXTRA-Argumente der Anchor-Verifier (frozen,
rp_trust) — die Klasse, die iter9 fand und die `type_confusion_gate` bauartbedingt NICHT sieht (es
verwechselt nur das PRIMAeRargument; die NON_JSON-Anchor-Flaechen ruft es gar nicht, ihre defaulteten
dict-kwargs pinnt es auf ein gutmuetiges Fixture). Deep-Gate iter9 Linse 3d bewies die Blindheit mit
einem gepflanzten Defekt.

Statt eines Punkt-Handtests je Fund (der „verrottet, sobald ihn niemand ergaenzt") ist DIES ein
Generator: eine Matrix aus (Verifier x valider-Primaer x Typ-Konfusions-Payload je Extra-Arg). Ein
neuer Verifier wird gedeckt, sobald er mit seinem Primaer-Konstruktor in REGISTRY steht. INVARIANTE:
jede Anchor-Verifier-Flaeche liefert fuer JEDEN Wert ihrer container-typisierten Extra-Argumente ein
Verdikt (dict) oder eine typisierte ProofBundleError — nie einen rohen AttributeError/TypeError."""
import hashlib
import json
import base64
import unittest

try:  # opentimestamps lives in the [anchors] extra; the REGISTRY verifiers (OTS + markovian)
    import opentimestamps  # noqa: F401  # both need it. Guarded so the module SKIPS (never errors)
    _HAS_OTS = True        # under a bare [test]/[dev] install. Matches the sibling OTS modules.
except ImportError:
    _HAS_OTS = False

from proofbundle.errors import ProofBundleError


def _b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _ots_valid_primary():
    from opentimestamps.core.timestamp import Timestamp, DetachedTimestampFile
    from opentimestamps.core.op import OpSHA256, OpAppend
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.serialize import BytesSerializationContext
    root = hashlib.sha256(b"target").digest()
    ts = Timestamp(root)
    c = ts.ops.add(OpAppend(b"\x01"))
    g = c.ops.add(OpSHA256())
    g.attestations.add(BitcoinBlockHeaderAttestation(700000))
    dtf = DetachedTimestampFile(OpSHA256(), ts)
    ctx = BytesSerializationContext()
    dtf.serialize(ctx)
    return (ctx.getbytes(), root)


def _markovian_valid_primary():
    root = hashlib.sha256(b"x").digest()
    # gueltige Felder (str), damit der Pfad frozen/rp_trust ueberhaupt erreicht (delegiert an OTS)
    env = {"schema": "markovian-provenance/v1", "data_hash": root.hex(), "salt": "s",
           "wallet": "w", "merkle_root": hashlib.sha256(f"{root.hex()}:s:w".encode()).hexdigest(),
           "ots": _b64u(_ots_valid_primary()[0])}
    return (json.dumps(env).encode(), root)


# (Modulpfad, Funktionsname, Primaer-Konstruktor) — erweiterbar; ein neuer Verifier wird auto-gedeckt.
REGISTRY = [
    ("proofbundle.anchors_ots", "verify_opentimestamps", _ots_valid_primary),
    ("proofbundle.anchors_markovian", "verify_markovian", _markovian_valid_primary),
]

# Typ-Konfusions-Payloads je dict-Extra-Arg: Nicht-Mapping + Mapping-mit-Nicht-Mapping-Wert +
# Mapping-mit-Nicht-str-Blatt (die drei Ebenen, die iter9 fand).
_FROZEN_CONFUSIONS = [[], (), 0, "x", [1, 2], {"bitcoinBlockHeaderMerkleRootsByHeight": [1, 2]}]
_RPTRUST_CONFUSIONS = [[], (), 0, "x", [1, 2],
                       {"bitcoin_block_headers": [1, 2]},
                       {"bitcoin_block_headers": {"700000": [1, 2]}},
                       {"bitcoin_block_headers": {"700000": 123}}]


@unittest.skipUnless(_HAS_OTS, "needs proofbundle[anchors] (opentimestamps)")
class TestAnchorExtraArgTypeConfusion(unittest.TestCase):
    def _assert_verdict(self, fn, proof, root, **extra):
        try:
            r = fn(proof, root, **extra)
        except ProofBundleError:
            return   # typisierte Ausnahme ist erlaubt
        except Exception as e:                       # noqa: BLE001
            self.fail(f"{fn.__module__}.{fn.__name__} roher Crash {type(e).__name__}: {e} bei {extra!r}")
        self.assertIsInstance(r, (dict, tuple), f"{fn.__name__} muss ein Verdikt liefern, gab {type(r).__name__}")

    def test_frozen_type_confusion_ueber_alle_verifier(self):
        import importlib
        for mod, name, prim in REGISTRY:
            fn = getattr(importlib.import_module(mod), name)
            proof, root = prim()
            for bad in _FROZEN_CONFUSIONS:
                with self.subTest(verifier=name, frozen=type(bad).__name__, val=repr(bad)[:20]):
                    self._assert_verdict(fn, proof, root, frozen=bad, rp_trust={})

    def test_rp_trust_type_confusion_ueber_alle_verifier(self):
        import importlib
        for mod, name, prim in REGISTRY:
            fn = getattr(importlib.import_module(mod), name)
            proof, root = prim()
            for bad in _RPTRUST_CONFUSIONS:
                with self.subTest(verifier=name, rp_trust=type(bad).__name__, val=repr(bad)[:20]):
                    self._assert_verdict(fn, proof, root, frozen={}, rp_trust=bad)


    def test_virtuelles_mapping_ohne_get_liefert_verdikt(self):
        """iter9 Linse 3a: ein via collections.abc.Mapping.register() virtuell registriertes Objekt
        OHNE `.get` passiert `isinstance(x, Mapping)`, hat aber kein `.get` — der Guard muss die
        Aufrufbarkeit mitpruefen, sonst roher AttributeError. Erreichbar ueber register_anchor_type."""
        from collections.abc import Mapping
        import importlib

        class _NoGet:
            def __getitem__(self, k): raise KeyError(k)
            def __iter__(self): return iter(())
            def __len__(self): return 0
        Mapping.register(_NoGet)
        for mod, name, prim in REGISTRY:
            fn = getattr(importlib.import_module(mod), name)
            proof, root = prim()
            with self.subTest(verifier=name):
                self._assert_verdict(fn, proof, root, frozen=_NoGet(), rp_trust={})


if __name__ == "__main__":
    unittest.main()
