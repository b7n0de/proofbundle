"""The Python and the Rust verifier give one verdict on every shared statement-signature vector.

AGENTS.md: Python and the Rust verifier in tools/pb_verify_rs must agree on the same bytes; a divergence
in verdict or exit code is a finding. The surface is `proofbundle.scitt_ccf.verify_statement_signature`,
the Rust side `pb_verify_rs verify-scitt-statement-signature` (tools/pb_verify_rs/src/scitt.rs, which
shares no reading code with the Python module).

The vectors are tests/fixtures/scitt_statement_signature/vectors.json, written by
tools/scitt_ccf_external/statement_signature_vectors.py: real statements a local scitt-ccf-ledger
accepted in the two differential-corpus rounds (two different ES256 signers), and synthetic ones for
every rule on the path, from the CBOR reader to the curve an algorithm names. Each vector carries the
status and verdict it is built to produce (the oracle), and both verifiers are held to it.
"""
from __future__ import annotations

import importlib.util
import json
import math
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VECTORS = Path(__file__).resolve().parent / "fixtures" / "scitt_statement_signature" / "vectors.json"
RUST = [REPO / "tools" / "pb_verify_rs" / "target" / build / "pb_verify_rs" for build in ("release", "debug")]
HAS_CBOR2 = importlib.util.find_spec("cbor2") is not None

#: The exit class of the Rust subcommand, by status.
EXIT = {"confirmed": 0, "statement_signature_invalid": 1}
SHOWN = {True: "true", False: "false", None: "none"}


def _doc() -> dict:
    return json.loads(VECTORS.read_text(encoding="utf-8"))


def _assemble(parts: list, refs: dict) -> bytes:
    out = b""
    for p in parts:
        if isinstance(p, str):
            out += bytes.fromhex(p)
        elif "ref" in p:
            out += bytes.fromhex(refs[p["ref"]])
        else:
            out += bytes(p["zeros"])
    return out


class TheVectors(unittest.TestCase):
    def test_every_status_the_surface_returns_is_covered(self):
        want = {v["want"]["status"] for v in _doc()["vectors"]}
        self.assertEqual(want, {"confirmed", "statement_signature_invalid", "needs_rp_trust",
                                "outside_profile", "malformed"})

    def test_both_signers_of_the_corpus_are_named(self):
        refs = _doc()["refs"]
        self.assertNotEqual(refs["spki_round1_signer"], refs["spki_round2_signer"])


@unittest.skipUnless(HAS_CBOR2, "the [scitt] extra is not installed")
class PythonGivesEveryBuiltVerdict(unittest.TestCase):
    def test_python(self):
        from proofbundle.scitt_ccf import verify_statement_signature  # noqa: PLC0415
        doc = _doc()
        for v in doc["vectors"]:
            with self.subTest(v["id"]):
                got = verify_statement_signature(_assemble(v["statement"], doc["refs"]),
                                                 statement_keys=[_assemble(k, doc["refs"]) for k in v["keys"]])
                self.assertEqual(got, (v["want"]["status"], v["want"]["valid"]), v["what"])


@unittest.skipUnless(any(b.exists() for b in RUST), "pb_verify_rs is not built")
class RustGivesEveryBuiltVerdict(unittest.TestCase):
    def test_rust(self):
        binary = next(b for b in RUST if b.exists())
        doc = _doc()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "statement.cbor"
            for v in doc["vectors"]:
                with self.subTest(v["id"]):
                    path.write_bytes(_assemble(v["statement"], doc["refs"]))
                    keys = [_assemble(k, doc["refs"]).hex() for k in v["keys"]]
                    p = subprocess.run([str(binary), "verify-scitt-statement-signature", str(path), *keys],
                                       capture_output=True, text=True, timeout=60)
                    want = v["want"]
                    self.assertEqual((p.stdout.split(), p.returncode),
                                     ([want["status"], SHOWN[want["valid"]]], EXIT.get(want["status"], 3)),
                                     (v["what"], p.stderr))


def _rust_input_budget(binary: Path) -> int:
    """The input budget the binary really uses, read from its `budget` subcommand."""
    p = subprocess.run([str(binary), "budget"], capture_output=True, text=True, timeout=60, check=True)
    return json.loads(p.stdout)["input_bytes"]


def _confirmed_statement() -> tuple[bytes, list]:
    """The first real vector (one a scitt-ccf-ledger accepted) built to be confirmed, and its keys."""
    doc = _doc()
    v = next(v for v in doc["vectors"] if v["origin"] != "synthetic" and v["want"]["status"] == "confirmed")
    return _assemble(v["statement"], doc["refs"]), [_assemble(k, doc["refs"]) for k in v["keys"]]


@unittest.skipUnless(any(b.exists() for b in RUST), "pb_verify_rs is not built")
class AStatementFileOverTheRustInputBudget(unittest.TestCase):
    """Codex on PR 290 (head f0a15203): a statement file over the Rust input budget ended in `fatal`,
    exit 2, where Python reads the same bytes as `malformed`, which the Rust subcommand maps to exit 3.
    A confirmed statement is padded with zeros to the budget and to one byte past it; the files are made
    here at run time and never checked in. Both sizes are `malformed` in both verifiers: the profile
    reads at most 65536 bytes."""

    def test_both_verifiers_read_it_as_malformed(self):
        binary = next(b for b in RUST if b.exists())
        budget = _rust_input_budget(binary)
        statement, keys = _confirmed_statement()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "statement.cbor"
            for size in (budget, budget + 1):
                with self.subTest(size=size):
                    with path.open("wb") as f:
                        f.write(statement)
                        f.truncate(size)
                    self.assertEqual(path.stat().st_size, size)
                    if HAS_CBOR2:
                        from proofbundle.scitt_ccf import verify_statement_signature  # noqa: PLC0415
                        self.assertEqual(verify_statement_signature(path.read_bytes(), statement_keys=keys),
                                         ("malformed", None))
                    p = subprocess.run([str(binary), "verify-scitt-statement-signature", str(path),
                                        *(k.hex() for k in keys)],
                                       capture_output=True, text=True, timeout=60)
                    self.assertEqual((p.stdout.split(), p.returncode), (["malformed", "none"], 3), p.stderr)


def _generator():
    """The vector generator of this surface, for its CBOR, certificate and SPKI helpers. It makes no key at
    import; only its Builder does."""
    path = REPO / "tools" / "scitt_ccf_external" / "statement_signature_vectors.py"
    spec = importlib.util.spec_from_file_location("statement_signature_vectors", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _with_exponent(base, e_min: int):
    """A private key over the primes of `base` whose public exponent is the first odd number from `e_min`
    on that is prime to (p - 1)(q - 1), and that exponent."""
    from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: PLC0415
    pn = base.private_numbers()
    p, q = pn.p, pn.q
    phi = (p - 1) * (q - 1)
    e = e_min | 1
    while math.gcd(e, phi) != 1:
        e += 2
    d = pow(e, -1, phi)
    return rsa.RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p),
                                 rsa.RSAPublicNumbers(e, p * q)).private_key(), e


@unittest.skipUnless(HAS_CBOR2 and any(b.exists() for b in RUST), "the [scitt] extra or pb_verify_rs is missing")
class TheRsaPublicExponentsOpenSslTakes(unittest.TestCase):
    """Codex on PR 290 (head 84f65117): the checked constructors of the rsa crate refuse a public exponent
    above 2^33 - 1, where OpenSSL, which verifies on the Python side, takes any odd e below n for a modulus of
    up to 3072 bits and an e of at most 64 bits above that. A PS256 statement is signed under each key, its
    leaf certificate and relying-party SPKI name that key, and both verifiers give the verdict OpenSSL gives.
    Keys and statements are made here at run time and never checked in."""

    CASES = ((2048, (1 << 33) + 1, "confirmed"), (2048, (1 << 64) + 1, "confirmed"),
             (2048, 1 << 1000, "confirmed"), (3072, (1 << 64) + 1, "confirmed"),
             (4096, (1 << 33) + 1, "confirmed"), (4096, (1 << 63) + 1, "confirmed"),
             (4096, (1 << 64) + 1, "statement_signature_invalid"))

    def test_both_verifiers_take_the_exponents_openssl_takes(self):
        from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: PLC0415

        from proofbundle.scitt_ccf import _sig_structure, verify_statement_signature  # noqa: PLC0415
        gen = _generator()
        binary = next(b for b in RUST if b.exists())
        bases = {bits: rsa.generate_private_key(public_exponent=65537, key_size=bits) for bits in (2048, 3072, 4096)}
        payload = b"\x11" * 32
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "statement.cbor"
            for bits, e_min, status in self.CASES:
                key, e = _with_exponent(bases[bits], e_min)
                with self.subTest(n_bits=bits, e_bits=e.bit_length()):
                    prot = gen.Builder.cbor_map([(b"\x01", b"\x38\x24"), (gen.uint(258), gen.uint(-16)),
                                                 (gen.uint(33), gen.bstr(gen.certificate(key)))])
                    sig = key.sign(_sig_structure(prot, payload),
                                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
                    statement = b"\xd2\x84" + gen.bstr(prot) + b"\xa0" + gen.bstr(payload) + gen.bstr(sig)
                    spki = gen.spki(key)
                    want = (status, status == "confirmed")
                    self.assertEqual(verify_statement_signature(statement, statement_keys=[spki]), want)
                    path.write_bytes(statement)
                    p = subprocess.run([str(binary), "verify-scitt-statement-signature", str(path), spki.hex()],
                                       capture_output=True, text=True, timeout=60)
                    self.assertEqual((p.stdout.split(), p.returncode),
                                     ([status, SHOWN[want[1]]], EXIT[status]), p.stderr)


if __name__ == "__main__":
    unittest.main()
