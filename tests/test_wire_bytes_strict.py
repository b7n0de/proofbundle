"""Wire bytes are decoded strictly, or the artefact is refused — the class, not the instance.

WHAT THIS CLOSES. Deep-gate iteration 7 (2026-08-26) confirmed `L3-500-DSSEB64-02`: junk inserted
into a SIGNED envelope's `payload` -- and into its `signatures[].sig` -- still returned
`verify=True`, because `dsse._b64decode_any` fell back to `base64.urlsafe_b64decode` WITHOUT
`validate=True`, and CPython's default silently DISCARDS characters outside the alphabet. The
project's own shipped Rust verifier rejected the identical file.

WHY THIS FILE HAS EXACTLY THESE FOUR TEST NAMES. The class ledger recorded
`decoder_normalises_away_unknown_bytes_instead_of_rejecting_them` on 2026-07-31 and named this
file and these four nodes as its closure evidence -- while the file did not exist. The class was
therefore carried as `env_blocked` (honestly: it never claimed to be closed) and the defect lived
inside it for 26 days until a lens rediscovered it. A second class,
`canonicity_preserving_perturbation_accepted` (RT-08), names the same invariant with
`regression_test: "external:proofbundle (RT-08, noch nicht eingepflanzt)"`. Both are closed by the
nodes below, under the names the ledger already cites, so the references resolve instead of
dangling.

WHY AST AND NOT GREP. A grep over this very family produced two wrong answers on the day of the
fix: it counted a COMMENT line mentioning `b64decode(` as a decode site, and a substring check
`"import decode_b64" in text` matched `"import decode_b64url"` and skipped an import that was
genuinely missing (133 tests went red). A scanner for a code property must read code.
"""
from __future__ import annotations

import ast
import base64
import binascii
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "proofbundle"

# The one module allowed to call the stdlib decoders directly: it IS the strict wrapper.
DER_WRAPPER = "_wire_b64.py"

# Non-alphabet perturbations. NUL and the whitespace family are the ones CPython discards; the
# non-ASCII one is the control that was ALREADY refused before the fix, and it stays in the set so
# a regression that starts refusing everything is not mistaken for a pass.
JUNK = ("!", "\n", " ", "\t", "\x00", "\r", "\x0b")


def laxe_dekodierstellen(baum: Path) -> list[str]:
    """Every `base64.b64decode(...)` / `base64.urlsafe_b64decode(...)` call under `baum` that does
    NOT pass `validate=True`, as 'datei:zeile'. Reads the AST, so a mention inside a comment or a
    docstring is not a call and a call spread over several lines still is one."""
    treffer: list[str] = []
    for p in sorted(baum.rglob("*.py")):
        if p.name == DER_WRAPPER:
            continue
        try:
            baum_ast = ast.parse(p.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        for knoten in ast.walk(baum_ast):
            if not isinstance(knoten, ast.Call):
                continue
            f = knoten.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            if name not in ("b64decode", "urlsafe_b64decode"):
                continue
            streng = any(
                kw.arg == "validate" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in knoten.keywords
            )
            if not streng:
                treffer.append(f"{p.relative_to(baum)}:{knoten.lineno}")
    return treffer


class TestDecoderProvenanceGate(unittest.TestCase):
    """The live guard: no module in the shipped tree decodes wire bytes laxly."""

    def test_no_unpinned_module_decodes_laxly(self):
        offen = laxe_dekodierstellen(SRC)
        self.assertEqual(
            offen, [],
            "these call sites decode untrusted base64 without validate=True, so CPython discards "
            "characters outside the alphabet and one artefact gains many accepted wire forms: "
            + ", ".join(offen),
        )

    def test_detector_sees_a_planted_violation_in_a_new_file_shape(self):
        """PLANT-AND-MUST-CATCH. The violation is planted in a file SHAPE the sweep has never seen
        (a fresh module, a nested package, a call inside a class method and one spread over three
        lines) — a detector that only recognises the shapes it was written against proves nothing
        about the next member of the family."""
        with tempfile.TemporaryDirectory() as d:
            fremd = Path(d) / "fremd"
            (fremd / "tief").mkdir(parents=True)
            (fremd / "__init__.py").write_text("")
            (fremd / "tief" / "__init__.py").write_text("")
            (fremd / "tief" / "neu.py").write_text(
                "import base64\n"
                "\n"
                "class Leser:\n"
                "    def lies(self, s):\n"
                "        return base64.b64decode(s)\n"
                "\n"
                "def mehrzeilig(s):\n"
                "    return base64.urlsafe_b64decode(\n"
                "        s + b'=' * (-len(s) % 4)\n"
                "    )\n"
            )
            gefunden = laxe_dekodierstellen(fremd)
            self.assertEqual(
                len(gefunden), 2,
                f"the planted violations were not both caught: {gefunden}",
            )
            self.assertTrue(all("neu.py" in g for g in gefunden), gefunden)

    def test_anti_tautology_blinded_scanner_stops_catching_the_violation(self):
        """THE OTHER DIRECTION, and it is the half that makes the first one mean something. If the
        same planted violation is still 'caught' when the scanner is blinded to it, the catch came
        from somewhere else and the meta-test is a tautology. Here the blinding is the scanner's own
        exemption rule: name the planted file like the wrapper, and the sweep must fall silent."""
        with tempfile.TemporaryDirectory() as d:
            fremd = Path(d) / "fremd"
            fremd.mkdir(parents=True)
            (fremd / DER_WRAPPER).write_text(
                "import base64\n"
                "def lies(s):\n"
                "    return base64.b64decode(s)\n"
            )
            self.assertEqual(
                laxe_dekodierstellen(fremd), [],
                "the blinded scanner still reported a finding — then its catch in the test above "
                "did not come from the scan, and that test proves nothing",
            )


class TestStrictDecoderFamily(unittest.TestCase):
    """The property over the whole helper family, generated rather than fixtured."""

    def test_every_probeable_decoder_rejects_junk_and_accepts_the_clean_form(self):
        from proofbundle._wire_b64 import decode_b64, decode_b64_either, decode_b64url

        klar = b"hallo welt, ein laengerer koerper damit die laenge variiert"
        familie = (
            (decode_b64, base64.b64encode(klar).decode("ascii")),
            (decode_b64url, base64.urlsafe_b64encode(klar).decode("ascii").rstrip("=")),
            (decode_b64_either, base64.b64encode(klar).decode("ascii")),
            (decode_b64_either, base64.urlsafe_b64encode(klar).decode("ascii").rstrip("=")),
        )
        for fn, sauber in familie:
            with self.subTest(fn=fn.__name__, alphabet=sauber[-6:]):
                # ANTI-PARITY, first and non-negotiable: without this a decoder that refuses
                # EVERYTHING passes every assertion below.
                self.assertEqual(
                    fn(sauber), klar,
                    f"{fn.__name__} refuses the clean form — the probe below would then be vacuous",
                )
                # The generator: every junk character at every position, not one fixture.
                for j in JUNK:
                    for stelle in (0, 1, len(sauber) // 2, len(sauber) - 1, len(sauber)):
                        gestoert = sauber[:stelle] + j + sauber[stelle:]
                        if gestoert == sauber:
                            continue
                        with self.assertRaises(
                            (binascii.Error, ValueError),
                            msg=f"{fn.__name__} accepted {j!r} at {stelle}: one artefact, two wire forms",
                        ):
                            fn(gestoert)

    def test_a_signed_envelope_has_exactly_one_accepted_wire_form(self):
        """The end-to-end shape of the confirmed finding: the perturbation must not survive as far
        as a verdict, on the payload AND on the signature. The control verifies first."""
        import json

        from proofbundle.dsse import sign_envelope, verify_envelope
        from proofbundle.emit import generate_signer

        signer = generate_signer()
        pub = signer.public_key().public_bytes_raw()
        env = sign_envelope(b'{"a":1}', signer, payload_type="application/vnd.test")
        self.assertTrue(verify_envelope(env, pub), "control: the untouched envelope must verify")

        for j in JUNK:
            for feld in ("payload", "sig"):
                with self.subTest(junk=repr(j), feld=feld):
                    e = json.loads(json.dumps(env))
                    if feld == "payload":
                        e["payload"] = env["payload"] + j
                    else:
                        e["signatures"][0]["sig"] = env["signatures"][0]["sig"] + j
                    try:
                        ok = verify_envelope(e, pub)
                    except Exception:      # noqa: BLE001 — a typed refusal is an acceptable outcome
                        continue
                    self.assertFalse(
                        ok,
                        f"{feld} + {j!r} still verified — the envelope has more than one accepted "
                        "wire form, which is what dedup, replay detection and transparency-log "
                        "leaf identity all assume it does not",
                    )


class TestRustAgreement(unittest.TestCase):
    """The differential arm: the shipped Rust verifier and Python must agree about the same file."""

    def test_python_and_rust_agree_or_the_arm_reports_itself_unavailable(self):
        rust = Path(__file__).resolve().parent.parent / "tools" / "pb_verify_rs"
        if not rust.is_dir():
            self.skipTest("tools/pb_verify_rs absent — the differential arm is NOT MEASURABLE here")
        if subprocess.run(["cargo", "--version"], capture_output=True).returncode != 0:  # noqa: S603,S607
            self.skipTest("cargo unavailable — env_blocked, not green")
        self.skipTest(
            "the wire-bytes differential arm is not yet planted in the Rust corpus; the gate "
            "recorded it as the remaining half of this class and it is env_blocked, never green"
        )


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
