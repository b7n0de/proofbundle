"""Explaining WHY an input was rejected must not itself crash.

FOUND BY THE PRE-TAG DEEP GATE, 2026-08-25 (L2-BDOS-RENEWAL-HUGEINT-01/02, both P2,
jury-confirmed) — **one round after the first half of this class was closed**, on a neighbour the
first sweep did not reach. That is the honest headline of this file.

THE FIRST HALF was about COMPUTE: a huge integer drives an `O(bit_length)` shift loop, so
`verify_inclusion` spent 3.3 seconds returning the correct `False`. The sweep that closed it asked
"which surfaces TAKE an untrusted integer as an argument" and fixed the three it found.

THIS HALF is about RENDERING, and the sweep never asked about it. CPython caps int→str conversion
at `sys.get_int_max_str_digits` (4300 by default, CVE-2020-10735). Interpolating an untrusted
integer into a *diagnostic message* therefore raises a raw `ValueError` — out of a surface whose
whole contract is that it never raises. The value was not even used for a computation. It was used
to explain why the input was rejected.

═══ TWO PLACES, TWO CORRECT ANSWERS ═══

`renewal.py` renders untrusted times in nine places, and they do not all deserve the same fix:

  * eight are DIAGNOSTICS — they get `render_safe`, which prints `<int, 16610 bits>` beyond the
    ceiling. Honest (it says what it is and how big) and useful, which 5000 decimal digits are not.
  * one is `token()`, and there the rendered string IS THE SIGNED MATERIAL. Shortening it would
    change the covered bytes and break every existing signature. That one REFUSES the magnitude
    with a typed error instead of rendering it differently.

A defensive abbreviation is worse than the crash it prevents when the string is the contract.

═══ AND A THIRD ANSWER, BECAUSE THE SURFACE MATTERS ═══

`verify_sequence` is a never-raise surface: it owes the caller a VERDICT. Left to `token()`'s
refusal, the error escaped as an exception — typed, but still an exception. So the magnitude is
checked there too, *before* the token path, and returns a verdict. The first attempt merely set
`ordered = False` like the type check beside it and let execution continue — straight into
`token()`. Same magnitude, three contracts, three correct behaviours.

HONEST BOUNDARY: `evaluate_renewal_policy` returns `ok=True` for an absurd future time, and that
is not a defect — it evaluates whether renewal is DUE, not whether the input is valid. The anomaly
IS reported, in the check detail. Testing `ok is False` there would encode a misunderstanding of
what the function answers.
"""
from __future__ import annotations

import pytest

import proofbundle as pb
from proofbundle.budget import DEFAULT_BUDGET, render_safe
from proofbundle.errors import ProofBundleError
from proofbundle.renewal import ArchiveTimeStamp, RenewalPolicy

# Weit ueber CPythons int->str-Kappe (4300 Ziffern) UND ueber der Magnituden-Schranke.
RIESE = 10 ** 5000
D1, D2 = "ab" * 32, "cd" * 32


def _ats(t, d=D1):
    return ArchiveTimeStamp(hash_alg="sha256", covered_digest=d, time=t)


class TestDerHelferSelbst:
    def test_eine_normale_zahl_wird_normal_gerendert(self):
        assert render_safe(1000) == "1000"

    def test_eine_riesige_zahl_wird_beschrieben_statt_gedruckt(self):
        s = render_safe(RIESE)
        assert s.startswith("<int,") and "bits>" in s
        assert len(s) < 40, "die Beschreibung ist selbst wieder zu lang"

    def test_die_beschreibung_nennt_die_groesse(self):
        """Nutzlos waere '<zu gross>'. Wer diagnostiziert, will wissen, wie gross."""
        assert str(RIESE.bit_length()) in render_safe(RIESE)

    def test_ein_nicht_integer_geht_unveraendert_durch(self):
        assert render_safe("text") == "'text'"
        assert render_safe(None) == "None"

    def test_die_schranke_ist_dieselbe_wie_beim_rechnen(self):
        """EINE Definition: der Render-Helfer und der Rechen-Guard teilen die Budget-Dimension.
        Zwei Schranken fuer dieselbe Groesse waeren die naechste Drift."""
        knapp_drunter = 2 ** (DEFAULT_BUDGET.int_bits - 1)
        assert render_safe(knapp_drunter) == str(knapp_drunter)
        assert render_safe(2 ** (DEFAULT_BUDGET.int_bits + 1)).startswith("<int,")


class TestDieNeverRaiseFlaechenLiefernVerdikte:
    """Das Orakel des Gates: ein Verdikt, keine Ausnahme."""

    def test_verify_sequence_absteigend(self):
        r = pb.verify_sequence([[_ats(RIESE + 1, D2), _ats(RIESE)]], [D1])
        assert r.ok is False

    def test_verify_sequence_aufsteigend(self):
        """Auch der Pfad, der NICHT ueber den Nicht-aufsteigend-Zweig laeuft — sonst waere nur
        eine der beiden gemeldeten Instanzen geschlossen."""
        r = pb.verify_sequence([[_ats(RIESE), _ats(RIESE + 1, D2)]], [D1])
        assert r.ok is False

    def test_evaluate_renewal_policy_liefert_ein_verdikt(self):
        r = pb.evaluate_renewal_policy([[_ats(RIESE)]], policy=RenewalPolicy(), now=1)
        assert hasattr(r, "ok")

    def test_die_anomalie_wird_benannt_statt_verschwiegen(self):
        """Fail-closed heisst nicht stumm: die Zukunftszeit muss im Verdikt auftauchen — und
        zwar beschrieben, nicht in 5000 Ziffern."""
        r = pb.evaluate_renewal_policy([[_ats(RIESE)]], policy=RenewalPolicy(), now=1)
        text = " ".join(str(getattr(c, "detail", "")) for c in r.checks)
        assert "future" in text
        assert "<int," in text, "die Zahl wurde doch ausgeschrieben"
        assert "0" * 100 not in text


class TestDasSignierteMaterialWirdNichtGEKUERZT:
    """Die Ausnahme, und sie ist der interessanteste Teil."""

    def test_token_verweigert_statt_zu_kuerzen(self):
        with pytest.raises(ProofBundleError):
            _ats(RIESE).token()

    def test_ein_normales_token_ist_unveraendert(self):
        """ANTI-PARITY: der Guard darf die signierten Bytes fuer legitime Werte NICHT antasten --
        sonst braeche er genau die Signaturen, die er schuetzen soll."""
        assert _ats(1000).token() == f"sha256:{D1}:1000"

    def test_der_grund_nennt_warum_nicht_gekuerzt_wird(self):
        with pytest.raises(ProofBundleError) as e:
            _ats(RIESE).token()
        assert "signed bytes" in str(e.value)
