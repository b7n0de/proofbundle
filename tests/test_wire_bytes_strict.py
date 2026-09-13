"""Wire bytes are decoded strictly AND canonically, or the artefact is refused — the class, not the instance.

WHAT THIS CLOSES. Deep-gate iteration 7 (2026-08-26) confirmed `L3-500-DSSEB64-02`: junk inserted
into a SIGNED envelope's `payload` -- and into its `signatures[].sig` -- still returned
`verify=True`, because `dsse._b64decode_any` fell back to `base64.urlsafe_b64decode` WITHOUT
`validate=True`, and CPython's default silently DISCARDS characters outside the alphabet. The
project's own shipped Rust verifier rejected the identical file.

WHAT THE FIRST FIX LEFT OPEN, measured by deep gate run 3 on 049b3195 (2026-09-05, L1-600-01 and
L1-600-03, class `canonicity_preserving_perturbation_accepted` / RT-08). `validate=True` refuses a
character outside the alphabet and a MISSING pad character, but not NON-ZERO PAD BITS
(`b64decode(b"QUJ=", validate=True) == b"AB"`, the bytes of the canonical `QUI=`); the url-safe
arm re-padded an UNPADDED standard string; a url-safe spelling was accepted where the format
mandates standard; and the Rust verifier TRIMMED whitespace that Python refuses. This file's
generator only ever APPENDED junk, so it stayed green over four accepted byte-different forms of one
signed envelope, and its Rust arm skipped itself unconditionally. Both are the class named
`family_property_green_over_a_hand_maintained_population_that_omits_members`: the population below
is now ENUMERATED from the definition of canonicality (every way two encodings can decode to the same
bytes) instead of hand-picked, and the differential arm MEASURES when the binary can be built.

WHY THE LEDGER CITES THESE NODE NAMES. The class ledger recorded
`decoder_normalises_away_unknown_bytes_instead_of_rejecting_them` on 2026-07-31 and
`canonicity_preserving_perturbation_accepted` (RT-08) with this file and these nodes as their
closure evidence; the names are kept so the references resolve.

WHY AST AND NOT GREP. A grep over this very family produced two wrong answers on the day of the
first fix: it counted a COMMENT line mentioning `b64decode(` as a decode site, and a substring check
matched an import that was genuinely missing. A scanner for a code property must read code.
"""
from __future__ import annotations

import ast
import base64
import binascii
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "proofbundle"
RUST_DIR = Path(__file__).resolve().parent.parent / "tools" / "pb_verify_rs"
RUST_BIN = RUST_DIR / "target" / "release" / "pb_verify_rs"

# The one module allowed to call the stdlib decoders directly: it IS the strict wrapper. Its
# IDENTITY is its path, not its basename (LAUF12-L2, P1): a scanner that skipped every file NAMED
# `_wire_b64.py` skipped a planted `scripts/x/_wire_b64.py` too. `DER_WRAPPER` stays as the name
# tests and ledgers cite; the exemption below compares resolved paths.
DER_WRAPPER = "_wire_b64.py"
WRAPPER_PFAD = SRC / DER_WRAPPER

# Non-alphabet perturbations. NUL and the whitespace family are the ones CPython discards; the
# non-ASCII one is the control that was ALREADY refused before the fix, and it stays in the set so
# a regression that starts refusing everything is not mistaken for a pass.
JUNK = ("!", "\n", " ", "\t", "\x00", "\r", "\x0b")

_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

#: Every stdlib entry point that decodes base64 LAXLY (discards or tolerates what the wrapper
#: refuses). Bound to the PROPERTY "reaches a lax decoder", not to a spelling: an alias, a `from`
#: import, `__import__`, `getattr` or a local rebinding all resolve to the same (module, name).
#: LAUF12-L2 (P1, executed by the lens): `binascii.a2b_base64` and `codecs.decode(x, "base64")`
#: reach the identical laxness and were invisible to the three-name list that stood here.
_LAXE_MODULE = ("base64", "binascii", "codecs")
_LAXE_ZIELE = {
    ("base64", "b64decode"), ("base64", "urlsafe_b64decode"), ("base64", "standard_b64decode"),
    ("base64", "decodebytes"), ("base64", "decodestring"),
    ("binascii", "a2b_base64"),
}
_LAXE_CODECS = ("base64", "base64_codec", "base_64")


def _konstante(knoten) -> "str | None":
    return knoten.value if isinstance(knoten, ast.Constant) and isinstance(knoten.value, str) else None


def _ziel_von(expr, modul_alias: dict, funk_alias: dict) -> "tuple[str, str] | None":
    """(module, name) that `expr` denotes, following the bindings collected for this file."""
    if isinstance(expr, ast.Name):
        return funk_alias.get(expr.id)
    if isinstance(expr, ast.Attribute):
        basis = expr.value
        if isinstance(basis, ast.Name) and basis.id in modul_alias:
            return (modul_alias[basis.id], expr.attr)
        # __import__("base64").b64decode(...)
        if (isinstance(basis, ast.Call) and isinstance(basis.func, ast.Name) and basis.func.id == "__import__"
                and basis.args and _konstante(basis.args[0]) in _LAXE_MODULE):
            return (_konstante(basis.args[0]), expr.attr)
        return None
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) and expr.func.id == "getattr":
        # getattr(base64, "b64decode")
        if len(expr.args) >= 2:
            modul = expr.args[0]
            name = _konstante(expr.args[1])
            if isinstance(modul, ast.Name) and modul.id in modul_alias and name:
                return (modul_alias[modul.id], name)
    return None


def _ist_laxer_aufruf(call: ast.Call, modul_alias: dict, funk_alias: dict) -> bool:
    ziel = _ziel_von(call.func, modul_alias, funk_alias)
    if ziel in _LAXE_ZIELE:
        return True
    if ziel == ("codecs", "decode"):
        # codecs.decode(x, "base64") — the codec name is the second argument or `encoding=`.
        codec = _konstante(call.args[1]) if len(call.args) >= 2 else None
        for kw in call.keywords:
            if kw.arg == "encoding":
                codec = _konstante(kw.value)
        return bool(codec) and codec.lower().replace("-", "_") in _LAXE_CODECS
    return False


def laxe_dekodierstellen(baum: Path, *, wrapper: "Path | None" = None) -> list[str]:
    """Every call under `baum` that reaches a LAX stdlib base64 decoder -- through any spelling -- as
    'datei:zeile'. Since v1.1 of the wrapper the rule is: the stdlib decoders are called NOWHERE
    outside the wrapper, because `validate=True` alone does not refuse non-zero pad bits and the
    property has to live in one place. Reads the AST, so a mention inside a comment or a docstring is
    not a call and a call spread over several lines still is one.

    THE PROPERTY, NOT THE SPELLING (LAUF12-L2): the file's own import and assignment bindings are
    resolved first, so `import base64 as b`, `from base64 import b64decode as d`, `dec = base64.b64decode`,
    `getattr(base64, "b64decode")`, `__import__("base64").b64decode`, `binascii.a2b_base64` and
    `codecs.decode(x, "base64")` are all one property: a lax decode is reachable. The wrapper is
    exempt by its resolved PATH, never by its basename."""
    wrapper_pfad = (wrapper or WRAPPER_PFAD).resolve()
    treffer: list[str] = []
    for p in sorted(baum.rglob("*.py")):
        if p.resolve() == wrapper_pfad:
            continue
        try:
            baum_ast = ast.parse(p.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        modul_alias: dict[str, str] = {}
        funk_alias: dict[str, tuple[str, str]] = {}
        for knoten in ast.walk(baum_ast):
            if isinstance(knoten, ast.Import):
                for a in knoten.names:
                    if a.name in _LAXE_MODULE:
                        modul_alias[a.asname or a.name] = a.name
            elif isinstance(knoten, ast.ImportFrom) and knoten.module in _LAXE_MODULE:
                for a in knoten.names:
                    funk_alias[a.asname or a.name] = (knoten.module, a.name)
        # Local rebindings, after the imports are known: `dec = base64.b64decode`.
        for knoten in ast.walk(baum_ast):
            if isinstance(knoten, ast.Assign) and len(knoten.targets) == 1 \
                    and isinstance(knoten.targets[0], ast.Name):
                ziel = _ziel_von(knoten.value, modul_alias, funk_alias)
                if ziel:
                    funk_alias[knoten.targets[0].id] = ziel
        for knoten in ast.walk(baum_ast):
            if isinstance(knoten, ast.Call) and _ist_laxer_aufruf(knoten, modul_alias, funk_alias):
                treffer.append(f"{p.relative_to(baum)}:{knoten.lineno}")
    return treffer


def padbit_variant(s: str) -> "str | None":
    """The same decoded bytes with NON-ZERO pad bits in the last symbol: canonicity-preserving, byte-
    different. None when the encoding has no pad bits (length a multiple of 3) or the input is not
    itself canonical."""
    core = s.rstrip("=")
    npad = len(s) - len(core)
    if npad == 0:
        return None
    free = 2 if npad == 1 else 4
    alphabet = _STD if ("+" in s or "/" in s or "-" not in s and "_" not in s) else _STD.replace("+", "-").replace("/", "_")
    idx = alphabet.index(core[-1])
    if idx & ((1 << free) - 1):
        return None
    return core[:-1] + alphabet[idx | 1] + "=" * npad


def canonicity_preserving_variants(s: str, *, alphabet: str) -> dict[str, str]:
    """EVERY way a second spelling can decode to the same bytes, enumerated from the definition of a
    canonical encoding (RFC 4648 sections 3.1 to 3.5): non-zero pad bits, missing padding, surplus
    padding, the other alphabet (with and without padding), and whitespace before, inside and after.
    `alphabet` is 'std' or 'url' and names the canonical spelling `s` is in."""
    v: dict[str, str] = {}
    pv = padbit_variant(s)
    if pv:
        v["padbits"] = pv
    if s.endswith("="):
        v["unpadded"] = s.rstrip("=")
    # UEBERZAEHLIGES PADDING IMMER, nicht im SONST-Zweig (deep gate Lauf 8, Jury zu L1-C2SPPAD-01).
    # Vorher stand diese Zeile im `else`, und der Korpus bestand aus EINEM String, der immer den
    # `if`-Zweig nahm — das Glied war damit tot, und genau die Achse, auf der `decode_b64_c2sp`
    # eine zweite Schreibweise annahm, konnte der Waechter nie erreichen. Ein Generator, dessen
    # Glieder sich gegenseitig ausschliessen, prueft weniger, als seine Liste behauptet.
    v["surplus_padding"] = s + "="
    if alphabet == "std":
        other = s.replace("+", "-").replace("/", "_")
    else:
        other = s.replace("-", "+").replace("_", "/")
    if other != s:
        v["other_alphabet"] = other
        v["other_alphabet_unpadded"] = other.rstrip("=")
    v["lead_space"] = " " + s
    v["trail_newline"] = s + "\n"
    v["inner_newline"] = s[: len(s) // 2] + "\n" + s[len(s) // 2:]
    v["crlf_wrapped"] = s[: len(s) // 2] + "\r\n" + s[len(s) // 2:]
    return {k: val for k, val in v.items() if val != s}


class TestDecoderProvenanceGate(unittest.TestCase):
    """The live guard: no module in the shipped tree calls a stdlib base64 decoder at all."""

    def test_no_unpinned_module_decodes_directly(self):
        offen = laxe_dekodierstellen(SRC)
        self.assertEqual(
            offen, [],
            "these call sites decode untrusted base64 through the stdlib instead of _wire_b64, so the "
            "canonicality property (pad bits, padding, alphabet, whitespace) is not enforced there and "
            "one artefact gains many accepted wire forms: " + ", ".join(offen),
        )

    def test_detector_sees_a_planted_violation_in_a_new_file_shape(self):
        """PLANT-AND-MUST-CATCH. The violation is planted in a file SHAPE the sweep has never seen
        (a fresh module, a nested package, a call inside a class method, one spread over three lines,
        and -- new -- one that DOES pass validate=True, which the old scanner accepted)."""
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
                "\n"
                "def validiert_aber_nicht_kanonisch(s):\n"
                "    return base64.b64decode(s, validate=True)\n"
            )
            gefunden = laxe_dekodierstellen(fremd)
            self.assertEqual(
                len(gefunden), 3,
                f"the planted violations were not all caught: {gefunden}",
            )
            self.assertTrue(all("neu.py" in g for g in gefunden), gefunden)

    def test_anti_tautology_blinded_scanner_stops_catching_the_violation(self):
        """THE OTHER DIRECTION, and it is the half that makes the first one mean something. If the
        same planted violation is still 'caught' when the scanner is blinded to it, the catch came
        from somewhere else and the meta-test is a tautology. The blinding is the scanner's own
        exemption rule — and since LAUF12-L2 that rule is the wrapper's PATH, not its basename:
        name the planted file `_wire_b64.py` and it is STILL reported; point the exemption at that
        exact path and the sweep falls silent."""
        with tempfile.TemporaryDirectory() as d:
            fremd = Path(d) / "fremd"
            fremd.mkdir(parents=True)
            gepflanzt = fremd / DER_WRAPPER
            gepflanzt.write_text(
                "import base64\n"
                "def lies(s):\n"
                "    return base64.b64decode(s, validate=True)\n"
            )
            self.assertEqual(
                len(laxe_dekodierstellen(fremd)), 1,
                "a planted file that merely CARRIES the wrapper's basename was exempted — the "
                "exemption binds to a name, not to the one module that is the wrapper",
            )
            self.assertEqual(
                laxe_dekodierstellen(fremd, wrapper=gepflanzt), [],
                "the blinded scanner still reported a finding — then its catch in the test above "
                "did not come from the scan, and that test proves nothing",
            )

    def test_meta_every_spelling_of_a_lax_decode_is_one_property(self):
        """LAUF12-L2 (P1, gate blindness executed by the lens): `binascii.a2b_base64` and
        `codecs.decode(x, "base64")` reach the same laxness as `base64.b64decode`, and an alias or a
        rebinding is the same call under another name. Each form, planted alone, is exactly one
        finding; the strict wrapper's own call is none."""
        formen = {
            "binascii": "import binascii\ndef f(s):\n    return binascii.a2b_base64(s)\n",
            "codecs": "import codecs\ndef f(s):\n    return codecs.decode(s, 'base64')\n",
            "codecs_kw": "import codecs\ndef f(s):\n    return codecs.decode(s, encoding='base64_codec')\n",
            "modul_alias": "import base64 as b\ndef f(s):\n    return b.b64decode(s)\n",
            "from_alias": "from base64 import b64decode as dec\ndef f(s):\n    return dec(s)\n",
            "from_plain": "from base64 import urlsafe_b64decode\ndef f(s):\n    return urlsafe_b64decode(s)\n",
            "rebinding": "import base64\ndec = base64.b64decode\ndef f(s):\n    return dec(s)\n",
            "getattr": "import base64\ndef f(s):\n    return getattr(base64, 'b64decode')(s)\n",
            "dunder_import": "def f(s):\n    return __import__('base64').b64decode(s)\n",
            "from_binascii": "from binascii import a2b_base64\ndef f(s):\n    return a2b_base64(s)\n",
        }
        with tempfile.TemporaryDirectory() as d:
            for name, quelle in formen.items():
                einzeln = Path(d) / name
                einzeln.mkdir()
                (einzeln / "m.py").write_text(quelle)
                with self.subTest(form=name):
                    self.assertEqual(len(laxe_dekodierstellen(einzeln)), 1,
                                     f"form {name!r} not caught exactly once: {laxe_dekodierstellen(einzeln)}")
            harmlos = Path(d) / "harmlos"
            harmlos.mkdir()
            (harmlos / "m.py").write_text(
                "import codecs\nimport base64\n"
                "def f(s):\n    return codecs.decode(s, 'utf-8')\n"
                "def g(b):\n    return base64.b64encode(b)\n")
            self.assertEqual(laxe_dekodierstellen(harmlos), [],
                             "a utf-8 codec call or an ENcode is not a lax decode")


class TestStrictDecoderFamily(unittest.TestCase):
    """The property over the whole helper family, generated rather than fixtured."""

    def _family(self):
        from proofbundle._wire_b64 import decode_b64, decode_b64_c2sp, decode_b64_either, decode_b64url

        # DREI PAD-KLASSEN, nicht eine (deep gate Lauf 8, Jury zu L1-C2SPPAD-01). Der Korpus war
        # EIN String von 59 Byte, also immer genau ein Fuellzeichen. Damit war der halbe Generator
        # unerreichbar. Die Laengen unten decken Rest 0, 1 und 2 ab und nehmen die vier echten
        # Materiallaengen dieser Flaeche mit: ed25519-Schluessel 33, note root 32,
        # Signaturzeile 68, ed25519-Cosignatur 76.
        koerper = (b"hallo welt, ein laengerer koerper damit die laenge variiert",  # 59, Rest 2
                   b"\x5a" * 33, b"\x5a" * 32, b"\x5a" * 68, b"\x5a" * 76)
        familie = []
        for klar in koerper:
            std = base64.b64encode(klar).decode("ascii")
            url = base64.urlsafe_b64encode(klar).decode("ascii")
            familie.extend((
                (decode_b64, std, "std", set(), klar),
                (decode_b64url, url.rstrip("="), "url", set(), klar),
                (decode_b64_either, std, "std", {"other_alphabet"}, klar),   # DSSE: beide Alphabete, gepolstert
                (decode_b64_either, url, "url", {"other_alphabet"}, klar),
                (decode_b64_c2sp, std, "std", {"padbits"}, klar),            # C2SP: Go-Paritaet Pad-Bits
            ))
        return koerper[0], familie

    def test_every_probeable_decoder_rejects_junk_and_accepts_the_clean_form(self):
        _erstes, familie = self._family()
        for fn, sauber, _alph, _allowed, klar in familie:
            with self.subTest(fn=fn.__name__, laenge=len(klar), alphabet=sauber[-6:]):
                # ANTI-PARITY, first and non-negotiable: without this a decoder that refuses
                # EVERYTHING passes every assertion below.
                self.assertEqual(
                    fn(sauber), klar,
                    f"{fn.__name__} refuses the clean form — the probe below would then be vacuous",
                )
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

    def test_every_decoder_refuses_every_canonicity_preserving_spelling(self):
        """THE MEMBERS THE OLD POPULATION OMITTED (L1-600-03). For every decoder and every second
        spelling of the same bytes: refused, unless the decoder's format explicitly allows that
        spelling (DSSE: the other alphabet, padded; C2SP: non-zero pad bits, Go parity) — and those
        allowances are LISTED, so a new one cannot creep in silently."""
        _erstes, familie = self._family()
        for fn, sauber, alph, allowed, klar in familie:
            varianten = canonicity_preserving_variants(sauber, alphabet=alph)
            self.assertGreaterEqual(len(varianten), 5, "the generator produced too few members")
            for name, val in varianten.items():
                with self.subTest(fn=fn.__name__, laenge=len(klar), variant=name):
                    if name in allowed:
                        self.assertEqual(fn(val), klar, f"{fn.__name__} must accept its format's {name}")
                        continue
                    with self.assertRaises(
                        (binascii.Error, ValueError),
                        msg=f"{fn.__name__} accepted the {name} spelling {val!r}: same bytes, second wire form",
                    ):
                        fn(val)

    def test_a_signed_envelope_has_exactly_one_accepted_wire_form(self):
        """The end-to-end shape of the confirmed finding: NO perturbation — junk OR canonicity-preserving
        — survives as far as a verdict, on the payload AND on the signature. The control verifies
        first. The one spelling the DSSE specification also allows (the other alphabet, padded) is a
        second wire form the FORMAT mandates; it is asserted to verify so a decoder that refuses it
        cannot pass by refusing everything."""
        from proofbundle.dsse import sign_envelope, verify_envelope
        from proofbundle.emit import generate_signer

        signer = generate_signer()
        pub = signer.public_key().public_bytes_raw()
        env = sign_envelope(b'{"a":1,"body":"laenger, damit padding entsteht"}', signer,
                            payload_type="application/vnd.test")
        self.assertTrue(verify_envelope(env, pub), "control: the untouched envelope must verify")

        def variant_envelopes():
            for feld in ("payload", "sig"):
                orig = env["payload"] if feld == "payload" else env["signatures"][0]["sig"]
                spellings = {f"junk:{j!r}": orig + j for j in JUNK}
                spellings.update(canonicity_preserving_variants(orig, alphabet="std"))
                for name, val in spellings.items():
                    e = json.loads(json.dumps(env))
                    if feld == "payload":
                        e["payload"] = val
                    else:
                        e["signatures"][0]["sig"] = val
                    yield feld, name, e

        gesehen = 0
        for feld, name, e in variant_envelopes():
            gesehen += 1
            with self.subTest(feld=feld, variant=name):
                try:
                    ok = verify_envelope(e, pub)
                except Exception:      # noqa: BLE001 — a typed refusal is an acceptable outcome
                    ok = False
                if name == "other_alphabet":
                    self.assertTrue(ok, "DSSE: the url-safe PADDED spelling is a spelling the spec mandates")
                else:
                    self.assertFalse(
                        ok,
                        f"{feld} {name} still verified — the envelope has more than one accepted wire "
                        "form, which is what dedup, replay detection and transparency-log leaf identity "
                        "all assume it does not",
                    )
        self.assertGreater(gesehen, 20, "the population is smaller than the class it must cover")

    def test_a_native_bundle_has_exactly_one_accepted_wire_form(self):
        """Same property on the native bundle (payload_b64 / signature.sig_b64), where the format
        mandates STANDARD base64 — so even the other alphabet is a second form and must be refused."""
        from proofbundle.bundle import verify_bundle

        bundle = json.loads((Path(__file__).resolve().parent.parent / "examples" / "example_bundle.json")
                            .read_text(encoding="utf-8"))
        self.assertTrue(verify_bundle(json.loads(json.dumps(bundle))).ok, "control: the example bundle verifies")
        for feld in ("payload_b64", "sig_b64"):
            orig = bundle["payload_b64"] if feld == "payload_b64" else bundle["signature"]["sig_b64"]
            for name, val in canonicity_preserving_variants(orig, alphabet="std").items():
                with self.subTest(feld=feld, variant=name):
                    b = json.loads(json.dumps(bundle))
                    if feld == "payload_b64":
                        b["payload_b64"] = val
                    else:
                        b["signature"]["sig_b64"] = val
                    try:
                        ok = verify_bundle(b).ok
                    except Exception:  # noqa: BLE001 — a typed refusal is an acceptable outcome
                        ok = False
                    self.assertFalse(ok, f"bundle {feld} {name} still verified: second wire form accepted")

    def test_meta_a_decoder_that_forgets_the_pad_bits_is_caught(self):
        """PLANT-AND-MUST-CATCH for the generator itself: a decoder that is strict on the alphabet and
        the padding but forgets the pad bits (exactly `validate=True` alone — the v1.0 defect) MUST be
        red under the population above. If the population cannot tell it from the real decoder, the
        two tests above prove nothing about the class they name."""
        klar = b"hallo welt, ein laengerer koerper damit die laenge variiert"
        sauber = base64.b64encode(klar).decode("ascii")

        def vergesslich(s):
            return base64.b64decode(s, validate=True)

        varianten = canonicity_preserving_variants(sauber, alphabet="std")
        self.assertIn("padbits", varianten)
        # the planted defect accepts the pad-bit spelling -> the property test would flag it
        self.assertEqual(vergesslich(varianten["padbits"]), klar,
                         "the plant is ineffective: this decoder already refuses pad bits")
        from proofbundle._wire_b64 import decode_b64
        with self.assertRaises((binascii.Error, ValueError)):
            decode_b64(varianten["padbits"])


class TestRustAgreement(unittest.TestCase):
    """The differential arm: the shipped Rust verifier and Python must agree about the same file — for
    the clean form AND for every canonicity-preserving spelling (deep gate 2026-09-05 measured them
    disagreeing in BOTH directions: Python accepted pad bits and unpadded forms Rust refused, Rust
    accepted surrounding whitespace Python refused). When the binary is absent and cargo is available
    it is BUILT here (release profile, the same artefact CI ships); when neither is available the
    arm reports itself NOT MEASURABLE loudly instead of a silent skip."""

    @classmethod
    def _binary(cls) -> "Path | None":
        if RUST_BIN.exists():
            return RUST_BIN
        if not RUST_DIR.is_dir() or shutil.which("cargo") is None:
            return None
        build = subprocess.run(["cargo", "build", "--release"], cwd=RUST_DIR,  # noqa: S603,S607
                               capture_output=True, text=True, timeout=1800)
        if build.returncode != 0 or not RUST_BIN.exists():
            return None
        return RUST_BIN

    def test_python_and_rust_agree_on_every_wire_form(self):
        rust = self._binary()
        if rust is None:
            self.skipTest("NOT MEASURABLE: tools/pb_verify_rs is absent or cargo unavailable — the "
                          "differential arm did not run (env_blocked, never green)")
        from proofbundle.dsse import sign_envelope, verify_envelope
        from proofbundle.emit import generate_signer

        signer = generate_signer()
        pub = signer.public_key().public_bytes_raw()
        pub_b64 = base64.b64encode(pub).decode("ascii")
        env = sign_envelope(b'{"a":1,"body":"laenger, damit padding entsteht"}', signer,
                            payload_type="application/vnd.test")
        cases = {"clean": env}
        for feld in ("payload", "sig"):
            orig = env["payload"] if feld == "payload" else env["signatures"][0]["sig"]
            spellings = {f"junk:{j!r}": orig + j for j in JUNK}
            spellings.update(canonicity_preserving_variants(orig, alphabet="std"))
            for name, val in spellings.items():
                e = json.loads(json.dumps(env))
                if feld == "payload":
                    e["payload"] = val
                else:
                    e["signatures"][0]["sig"] = val
                cases[f"{feld}/{name}"] = e
        disagreements = []
        with tempfile.TemporaryDirectory() as d:
            for name, e in cases.items():
                try:
                    py_ok = bool(verify_envelope(e, pub))
                except Exception:  # noqa: BLE001 — typed refusal counts as "not ok"
                    py_ok = False
                fp = Path(d) / "env.json"
                fp.write_text(json.dumps(e), encoding="utf-8")
                pr = subprocess.run([str(rust), "verify-dsse", str(fp), pub_b64],  # noqa: S603
                                    capture_output=True, text=True, timeout=60)
                rust_ok = pr.returncode == 0
                if py_ok != rust_ok:
                    disagreements.append(f"{name}: python_ok={py_ok} rust_rc={pr.returncode}")
                if name == "clean":
                    self.assertTrue(py_ok and rust_ok, "control: both verifiers must accept the clean form")
        self.assertEqual(disagreements, [], "the two shipped verifiers disagree about the same bytes:\n  "
                         + "\n  ".join(disagreements))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)


class TestC2SPFelderNutzenDenC2SPDecoder(unittest.TestCase):
    """Ein Feld, ein Decoder — die andere Haelfte der Klasse, gefunden von der Gegenlesung vor dem Merge.

    WAS HIER GESCHLOSSEN WIRD. Der Sweep dieser Runde stellte die Dekodierstellen von `checkpoint.py`
    auf `decode_b64_c2sp` um, weil ein C2SP-Note-Feld nach der dokumentierten Ausnahme Pad-Bits
    toleriert (Gos `encoding/base64` StdEncoding tut es ohne `Strict()`, und die Notes dieses
    Oekosystems werden von diesem Decoder geprueft). Neun Stellen wurden umgestellt, die zehnte nicht:
    `_witness_key_material` las denselben vkey-Substring wie `_parse_witness_vkey` weiter mit dem
    inzwischen VERSCHAERFTEN `decode_b64`. Weil der Decoder in derselben Runde strenger wurde, war das
    keine Altlast, sondern eine NEU eingefuehrte Regression: ein gueltig signierter ML-DSA-44-Witness
    traegt 1313 Byte Schluesselmaterial, also genau ein Polsterzeichen und damit eine existierende
    Pad-Bit-Variante — `verify_cosignature` beurteilte die Zeile mit ok=True, und der nachgelagerte
    Dedup-Schritt hob darauf eine unabgefangene `binascii.Error` aus `verify_witnessed_checkpoint` und
    `witness_quorum`, zwei Flaechen, deren Vertrag das Urteilen ist.

    DIE INVARIANTE, ueber die hier quantifiziert wird: in `checkpoint.py` gibt es KEINE strikte
    Dekodierung. Jedes base64-Feld dieses Moduls ist ein C2SP-Feld, also ist der strikte Decoder dort
    nie richtig — die Regel gilt fuer jede Stelle, auch fuer eine, die es noch nicht gibt. Der Riegel
    liest den AST, nicht den Text, aus demselben Grund wie oben in dieser Datei.
    """

    C2SP_MODUL = SRC / "checkpoint.py"

    @staticmethod
    def _strikte_aufrufe(quelle: str) -> list[int]:
        """Zeilen, in denen der STRIKTE Decoder aufgerufen wird (Name oder Attribut), per AST."""
        treffer: list[int] = []
        for knoten in ast.walk(ast.parse(quelle)):
            if not isinstance(knoten, ast.Call):
                continue
            f = knoten.func
            name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else "")
            if name == "decode_b64":
                treffer.append(knoten.lineno)
        return treffer

    def test_kein_c2sp_feld_wird_strikt_dekodiert(self):
        quelle = self.C2SP_MODUL.read_text(encoding="utf-8")
        self.assertEqual(self._strikte_aufrufe(quelle), [],
                         "checkpoint.py ruft den strikten Decoder — jedes Feld dieses Moduls ist ein "
                         "C2SP-Feld, und zwei Decoder fuer dasselbe Feld sind eine Divergenz")
        self.assertNotIn("import decode_b64,", quelle,
                         "der strikte Decoder ist hier importiert und damit aufrufbar")

    def test_meta_die_vor_fix_form_wird_gefangen(self):
        """PLANT-AND-MUST-CATCH: die Zeile, wie sie vor dem Fix stand, muss den Riegel rot machen."""
        gepflanzt = "def f(vkey):\n    return decode_b64(vkey.split('+', 2)[2])\n"
        self.assertEqual(self._strikte_aufrufe(gepflanzt), [2],
                         "der Riegel sieht die Vor-Fix-Form nicht — er misst dann nichts")

    def _mldsa_witness(self):
        """Ein echter, gueltig signierter ML-DSA-44-Witness plus die Pad-Bit-Schreibweise seines
        Schluesselmaterials. ML-DSA-44 ist der Fall, in dem die Variante ueberhaupt existiert: 1313
        Byte sind kein Vielfaches von 3, also gibt es genau ein Polsterzeichen. Ed25519 traegt 33
        Byte und damit keine Polsterung — an ihm ist die Klasse nicht ausloesbar, und genau deshalb
        hat sie kein bestehender Test gefangen."""
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError:  # pragma: no cover
            self.skipTest("NOT MEASURABLE: die pq-Extra fehlt — ohne ML-DSA gibt es kein Feld mit "
                          "Polsterung, an dem diese Klasse ausloesbar waere (env_blocked, nie gruen)")
        from proofbundle import checkpoint as cp

        log_signer = Ed25519PrivateKey.generate()
        note = cp.sign_checkpoint("example.com/log", 5, b"R" * 32, log_signer, "logkey")
        log_vkey = cp.vkey("logkey", log_signer.public_key().public_bytes_raw())
        w_signer = mldsa.MLDSA44PrivateKey.generate()
        w_pub = w_signer.public_key().public_bytes_raw()
        signed = cp.cosign_checkpoint_mldsa(note, w_signer, "witness1", 1700000000)
        witness_vkey = cp.cosign_vkey_mldsa("witness1", w_pub)
        name, kid, keymat = witness_vkey.split("+", 2)
        kern = keymat.rstrip("=")
        npad = len(keymat) - len(kern)
        if npad == 0:  # pragma: no cover - 1313 Byte ergeben immer genau ein Polsterzeichen
            self.skipTest("NOT MEASURABLE: dieses Schluesselmaterial traegt keine Polsterung")
        frei = 2 if npad == 1 else 4
        idx = _STD.index(kern[-1])
        if idx & ((1 << frei) - 1):  # pragma: no cover - Schluessel neu erzeugen waere Flakiness
            self.skipTest("NOT MEASURABLE: die Pad-Bits dieses Schluessels sind bereits gesetzt")
        variante = kern[:-1] + _STD[idx | 1] + "=" * npad
        return cp, signed, log_vkey, witness_vkey, f"{name}+{kid}+{variante}"

    def test_die_pad_bit_schreibweise_liefert_ein_verdikt_statt_eines_wurfs(self):
        cp, signed, log_vkey, witness_vkey, variante = self._mldsa_witness()
        # Die Vorbedingung des Fundes, gemessen statt angenommen: dieselbe Zeile ist gueltig.
        self.assertTrue(cp.verify_cosignature(signed, variante)["ok"],
                        "Vorbedingung verfehlt: die Variante ist gar keine gueltige Gegensignatur")
        ergebnis = cp.verify_witnessed_checkpoint(signed, log_vkey, [variante], threshold=1)
        self.assertTrue(ergebnis["witnesses_ok"],
                        "dieselben Bytes unter anderer Schreibweise zaehlen nicht mehr als Zeuge")
        quorum_ok, _ = cp.witness_quorum(signed, [variante], 1, log_key_material=None)
        self.assertTrue(quorum_ok, "das Quorum urteilt anders als die Gesamtflaeche")

    def test_anti_paritaet_die_kanonische_schreibweise_bleibt_gut(self):
        cp, signed, log_vkey, witness_vkey, _variante = self._mldsa_witness()
        self.assertTrue(cp.verify_witnessed_checkpoint(signed, log_vkey, [witness_vkey],
                                                       threshold=1)["witnesses_ok"],
                        "Kontrolle gefallen: der kanonische Zeuge zaehlt nicht mehr")

    def test_dieselben_bytes_sind_derselbe_zeuge(self):
        """Der eigentliche Zweck der Funktion, jetzt pruefbar: das Quorum zaehlt SCHLUESSELMATERIAL,
        nicht Zeichenketten. Zwei Schreibweisen desselben Schluessels sind EIN Zeuge, nie zwei."""
        cp, signed, log_vkey, witness_vkey, variante = self._mldsa_witness()
        ergebnis = cp.verify_witnessed_checkpoint(signed, log_vkey, [witness_vkey, variante],
                                                  threshold=2)
        self.assertFalse(ergebnis["witnesses_ok"],
                         "zwei Schreibweisen desselben Schluessels wurden als zwei Zeugen gezaehlt")
