"""A tiny integer can buy a lot of CPU — the magnitude budget, on every surface that takes one.

FOUND BY THE PRE-TAG DEEP GATE, 2026-08-25 (L2-BDOS-HUGEINT, P2, jury-confirmed and independently
re-run by the foreman).

WHAT WAS MEASURED. `verify_inclusion(b'x', 2**300000, 2**300000, [32 bytes], root)` ran **3.334
seconds** and returned the *correct* `False`. At `2**1000000` that scales to roughly 34 seconds.
`verify_bundle` refuses the identical magnitude in about 0.015 s. Correct verdict, unbounded cost
— which is exactly what a denial-of-service looks like.

WHY EVERY OTHER BUDGET MISSED IT. `input_bytes`, `json_nodes` and `string_len` all bound
STRUCTURE, and a huge integer has none: `2**1000000` is seven characters of source and one scalar
node. The `merkle_path` step cap passes too — the attack needs a one-element proof. The cost is
not in the input, it is in the `O(bit_length)` shift loop the input then drives.

WHY THE FIX IS NOT THREE FIXES. `bundle._require_int` has carried an 8192-bit ceiling since the
earlier L2-BDOS-01 round. It lived as a literal *inside that function*, so the three surfaces that
take their integers as ARGUMENTS rather than from a dict never got it — for a month, on exported
public names. A bound that lives inside one function is not a bound anyone else can honour. It is
now a dimension of `VerificationBudget`, and all four call sites read the same one.

THE ANTI-PARITY HALF, and it is why this file is worth having: a guard that refuses everything
would satisfy every timing assertion below and destroy the library. Real sizes must still verify.

HONEST BOUNDARY: measured is the WALL CLOCK of a fail-closed refusal on this machine. A slower
machine shifts every number; the assertion is therefore a generous ceiling (100 ms, per the gate's
oracle) and not a benchmark. What it proves is the absence of the *shift loop*, whose cost is
three orders of magnitude away from the bound.
"""
from __future__ import annotations

import hashlib
import time

import pytest

import proofbundle as pb
from proofbundle.budget import DEFAULT_BUDGET, int_magnitude_ok

# The gate's oracle: a fail-closed verdict in under 100 ms. Measured after the fix: 5-20 ms.
GRENZE_MS = 100.0
RIESE = 2 ** 1_000_000
NULL32 = b"\x00" * 32


def _ms(f):
    t = time.perf_counter()
    r = f()
    return (time.perf_counter() - t) * 1000.0, r


# Every exported surface that takes an untrusted integer size/index as an ARGUMENT.
# Each entry: (name, callable with the huge int, predicate for "refused").
FAMILIE = [
    ("verify_inclusion/leaf_index",
     lambda: pb.verify_inclusion(b"x", RIESE, RIESE, [NULL32], NULL32),
     lambda r: r is False),
    ("verify_consistency/sizes",
     lambda: pb.verify_consistency(RIESE, RIESE, [NULL32], NULL32, NULL32),
     lambda r: r is False),
    ("verify_sample_opening/n",
     lambda: pb.verify_sample_opening(
         {"index": 0, "disclosure": "x", "proof_b64": []}, "AA", RIESE),
     lambda r: isinstance(r, dict) and r.get("ok") is False),
]


class TestDieFamilieRefuedstSchnell:
    @pytest.mark.parametrize("name,ruf,abgelehnt", FAMILIE, ids=[f[0] for f in FAMILIE])
    def test_fail_closed_unter_der_grenze(self, name, ruf, abgelehnt):
        dauer, r = _ms(ruf)
        assert abgelehnt(r), f"{name}: kein fail-closed Verdikt, sondern {r!r}"
        assert dauer < GRENZE_MS, (
            f"{name}: {dauer:.0f} ms fuer eine Ablehnung (Grenze {GRENZE_MS:.0f}) -- der "
            "O(bit_length)-Schiebe-Loop laeuft wieder; vor dem Fix waren es 3300 ms bei 2**300000")

    def test_die_familie_ist_nicht_leer(self):
        """ANTI-TAUTOLOGIE: waere die Liste leer, bestuende der Test darueber leer."""
        assert len(FAMILIE) >= 3


class TestEineDefinitionFuerAlleVier:
    def test_die_schranke_ist_eine_budget_dimension(self):
        assert DEFAULT_BUDGET.int_bits == 8192

    def test_der_bundle_pfad_liest_dieselbe_quelle(self):
        """Der Pfad, der die Schranke seit L2-BDOS-01 hatte, darf keine zweite Kopie fuehren --
        zwei Kopien derselben Zahl sind die naechste Drift, und genau diese Drift ist der Befund."""
        quelle = __import__("pathlib").Path(pb.__file__).with_name("bundle.py").read_text(
            encoding="utf-8")
        assert "int_magnitude_ok" in quelle, "bundle liest die gemeinsame Schranke nicht"
        assert "bit_length() > 8192" not in quelle, "die alte Literal-Kopie steht noch da"

    def test_der_gemeinsame_pruefer_antwortet_wie_erwartet(self):
        assert int_magnitude_ok(2 ** 64) is True
        assert int_magnitude_ok(RIESE) is False
        # Ein Nicht-Integer ist NICHT die Frage dieser Funktion -- Typpruefung macht jeder Aufrufer
        # selbst, und ein gemeinsamer Pruefer, der zwei Fragen beantwortet, wird an der zweiten falsch.
        assert int_magnitude_ok("keine zahl") is True
        assert int_magnitude_ok(None) is True


class TestNichtEinDauerNein:
    """ANTI-PARITY. Ein Waechter, der alles ablehnt, besteht jede Zeitmessung oben und zerstoert
    die Bibliothek."""

    def test_eine_echte_inklusion_verifiziert_weiter(self):
        blatt = b"hallo"
        wurzel = hashlib.sha256(b"\x00" + blatt).digest()
        assert pb.verify_inclusion(blatt, 0, 1, [], wurzel) is True

    def test_eine_echte_konsistenz_verifiziert_weiter(self):
        wurzel = hashlib.sha256(b"\x00" + b"hallo").digest()
        assert pb.verify_consistency(1, 1, [], wurzel, wurzel) is True

    def test_eine_groesse_knapp_unter_der_schranke_wird_nicht_abgelehnt(self):
        """Die Schranke ist 8192 Bit. Eine Zahl knapp darunter ist absurd gross und trotzdem
        erlaubt -- der Waechter soll das Unmoegliche abschneiden, nicht das Unwahrscheinliche."""
        knapp = 2 ** 8000
        assert int_magnitude_ok(knapp) is True
