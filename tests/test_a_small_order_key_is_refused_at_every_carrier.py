"""A small-order key is refused at every carrier: the AGT signer, the register view, the issuer pin.

WHERE THIS COMES FROM. SPEC section 4b: every Ed25519 key that is not the bundle's own
`signature.public_key_b64` must be canonical and must not be a point of small order, and the
bundle's own key may keep the section 4a profile only because "trust in it comes from a pin that
already carries this rule". #280 applied the rule to about twenty places and left three carriers.
Measured on 126ed1dc with the identity point `0100..00` as key and the signature R = identity,
S = 0, which the section 4a profile accepts for every message:

1. `adapters/agt_receipt.py`: the receipt's `signer_public_key` got the plain profile, `signature`
   True and `ok` True for a receipt nobody signed. AGT's authorization binds `receipt_payload_hash`
   and not the signer key, so the same swap under an externally authorized receipt kept the
   authorization and gave exit 0. The trust-anchor test listed the adapter as IN_BAND.
2. `scripts/gen_findings_register.py`, `_signatur_lage`: `VERIFIZIERT`, and both generated views
   printed "Signed and verified against the canonical body, ed25519."; 32 zero bytes as key and 64
   as signature gave `VERIFIZIERT` for 7 of 16 bodies of the line-610 carrier. Register entry
   `SMALL-ORDER-KEY-AT-CARRIER-SIGNATURE-01`, target 6.2.0.
3. `proofbundle show-eval --expect-issuer ed25519:<identity>`: exit 0 and "=> OK" for a PASS
   receipt nobody signed. The pin was compared as a string with a key the bundle check had accepted
   under section 4a, so the pin did not carry the rule the SPEC says it carries.

WHAT IS PINNED. Per carrier a signature made by nobody, with the precondition that the bare profile
accepts it, next to a positive control made by a real key. The refusal names the reason from
`signature.TRUST_ANCHOR_REFUSAL`. Where a key is AUTHORISED (the AGT relying party's
`trusted_authorizer_keys`, the `--expect-issuer` pin) it is refused there, before any receipt is
read, not only when a receipt happens to use it. Every case that is not a positive control failed
on 126ed1dc, measured by running this file against an export of that commit.
"""
from __future__ import annotations

import base64
import contextlib
import copy
import importlib.util
import inspect
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO), str(REPO / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proofbundle.signature import (  # noqa: E402
    TRUST_ANCHOR_REFUSAL,
    verify_ed25519,
    verify_ed25519_pinned,
)
from tests.test_trust_anchor_keys_refused_on_every_surface import (  # noqa: E402
    I1,
    TORSION_R,
    UNIV,
    WEAK,
    _NO_SMALL_ORDER,
    _Nobody,
    _raw,
)

ZERO = b"\x00" * 32            # y = 0, a point of order 4
ZSIG = b"\x00" * 64            # R = the zero point, S = 0


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


# ── 1. the AGT receipt's signer key and the relying party's authorizer list ──────────────────────

_AGT = REPO / "tests" / "vektoren" / "agt_receipts"


def _agt(name: str) -> dict:
    return json.loads((_AGT / f"{name}.json").read_text(encoding="utf-8"))


def _agt_forged(key: bytes):
    """A receipt signed by nobody that the bare profile accepts under `key`: 01_allow with its own
    `payload_hash` dropped, `receipt_id` varied until a torsion point works as R with S = 0. None for
    the one WEAK entry of large order, which admits no forgery."""
    from proofbundle.adapters.agt_receipt import canonical_payload
    base = _agt("01_allow")
    base.pop("payload_hash", None)
    for i in range(64):
        r = dict(base, receipt_id=f"made-by-nobody-{i}", signer_public_key=key.hex())
        msg = canonical_payload(r)
        for big_r in TORSION_R:
            sig = big_r + b"\x00" * 32
            if verify_ed25519(key, sig, msg):
                return dict(r, signature=sig.hex())
    return None


class AgtSignerKey(unittest.TestCase):

    def test_precondition_the_forgery_is_live_against_the_bare_profile(self):
        from proofbundle.adapters.agt_receipt import canonical_payload
        r = _agt_forged(I1)
        self.assertIsNotNone(r)
        self.assertIs(verify_ed25519(I1, bytes.fromhex(r["signature"]), canonical_payload(r)), True)

    def test_a_receipt_nobody_signed_is_refused_for_every_weak_signer_key(self):
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt
        for key, reason in WEAK:
            with self.subTest(key=key.hex()):
                r = _agt_forged(key)
                if key == _NO_SMALL_ORDER:
                    self.assertIsNone(r)
                    r = dict(_agt_forged(I1), signer_public_key=key.hex())
                else:
                    self.assertIsNotNone(r, "no forgery found; this entry would measure nothing")
                e = verify_agt_receipt(r)
                self.assertIs(e.ok, False)
                self.assertEqual(exit_code(e), 1, "a key that verifies nothing is a crypto failure")
                sig = [c for c in e.checks if c.name == "signature"]
                self.assertEqual([c.ok for c in sig], [False])
                self.assertIn("signer_public_key", sig[0].detail)
                self.assertIn(TRUST_ANCHOR_REFUSAL[reason], sig[0].detail)

    def test_an_authorized_receipt_with_its_signer_swapped_to_nobody_is_refused(self):
        """The authorization binds the payload hash, not the signer key, so on 126ed1dc it stayed
        valid over a receipt re-signed by nobody and the verdict was exit 0."""
        from proofbundle.adapters.agt_receipt import canonical_payload, exit_code, verify_agt_receipt
        r = _agt("03_extern_autorisiert")
        r.update(signer_public_key=I1.hex(), signature=UNIV.hex())
        self.assertIs(verify_ed25519(I1, UNIV, canonical_payload(r)), True)
        e = verify_agt_receipt(r, trusted_authorizer_keys=[r["authorizer_public_key"]])
        self.assertIs(e.ok, False)
        self.assertEqual(exit_code(e), 1)
        self.assertEqual([c.ok for c in e.checks if c.name == "signature"], [False])

    def test_positive_control_a_real_signer_key_verifies(self):
        from proofbundle.adapters.agt_receipt import canonical_payload, exit_code, verify_agt_receipt
        k = Ed25519PrivateKey.generate()
        r = _agt("01_allow")
        r.pop("payload_hash", None)
        r["signer_public_key"] = _raw(k).hex()
        r["signature"] = k.sign(canonical_payload(r)).hex()
        e = verify_agt_receipt(r)
        self.assertIs(e.ok, True, [c.detail for c in e.checks if not c.ok])
        self.assertEqual(exit_code(e), 0)
        self.assertIs(verify_agt_receipt(_agt("01_allow")).ok, True, "the real AGT vector")

    def test_the_path_taken_asks_for_the_key_check_and_no_pin_list(self):
        """The owner's condition for the signer: if the pinned verify wanted a pin list there, only
        the key check would be taken over and the trust chain would stay with the authorizer. It
        wants none: its parameters are the key, the signature and the message, and a receipt with no
        list and no authorization verifies under it (the control above). So the signer goes through
        `verify_ed25519_pinned`, which is exactly the key check followed by the signature."""
        self.assertEqual(list(inspect.signature(verify_ed25519_pinned).parameters),
                         ["public_key", "signature", "message"])
        k = Ed25519PrivateKey.generate()
        self.assertIs(verify_ed25519_pinned(_raw(k), k.sign(b"m"), b"m"), True)
        self.assertIs(verify_ed25519_pinned(I1, UNIV, b"m"), False)


class AgtAuthorizerList(unittest.TestCase):
    """The relying party's `trusted_authorizer_keys` is where a key is authorised."""

    def test_a_weak_key_on_the_list_is_refused_before_the_receipt_is_read(self):
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt
        r = _agt("03_extern_autorisiert")
        for key, reason in WEAK:
            with self.subTest(key=key.hex()):
                e = verify_agt_receipt(r, trusted_authorizer_keys=[key.hex(), r["authorizer_public_key"]])
                self.assertIs(e.ok, False)
                self.assertEqual(exit_code(e), 2, "a weak pin makes the relying party's list malformed")
                self.assertEqual([c.name for c in e.checks], ["trusted-authorizer-keys"])
                self.assertIn(TRUST_ANCHOR_REFUSAL[reason], e.checks[0].detail)
                self.assertIn("trusted_authorizer_keys[0]", e.checks[0].detail)

    def test_the_refusal_does_not_depend_on_the_receipt(self):
        """Refused where it is authorised: an unreadable receipt gets the same answer."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt
        e = verify_agt_receipt({"not": "a receipt"}, trusted_authorizer_keys=[I1.hex()])
        self.assertEqual((e.ok, exit_code(e), e.checks[0].name), (False, 2, "trusted-authorizer-keys"))

    def test_positive_control_and_the_entries_that_name_no_key(self):
        """A real list still authorises, and an entry that decodes to no 32-byte key is left as it
        was: it matches nothing (tests/test_agt_receipt_verifier.py uses one)."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt
        r = _agt("03_extern_autorisiert")
        real = r["authorizer_public_key"]
        for liste in ([real], ["x", real], ["aa" * 31, real], (real,)):
            with self.subTest(liste=[str(x)[:8] for x in liste]):
                e = verify_agt_receipt(r, trusted_authorizer_keys=liste)
                self.assertIs(e.ok, True, [c.detail for c in e.checks if not c.ok])
        self.assertEqual(exit_code(verify_agt_receipt(r, trusted_authorizer_keys=["aa" * 32])), 3,
                         "a real key that is not the authorizer stays a relying-party miss")


# ── 2. the findings register's carrier: `_signatur_lage` and the views ──────────────────────────

_TRAEGER = REPO / "audit_artifacts" / "600" / "findings_register_v2.json"
_TRAEGER_610 = REPO / "audit_artifacts" / "610" / "findings_register_v2.json"


def _gen():
    spec = importlib.util.spec_from_file_location("_t_d3_gfr", REPO / "scripts" / "gen_findings_register.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _signed(doc: dict, key: bytes, sig: bytes) -> dict:
    d = copy.deepcopy(doc)
    d["signature"] = {"alg": "ed25519", "public_key_b64": _b64(key), "sig_b64": _b64(sig)}
    return d


class RegisterCarrier(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not _TRAEGER.is_file():
            raise unittest.SkipTest(f"NOT MEASURABLE: {_TRAEGER} is missing; the carrier cases did NOT run")
        cls.g = _gen()
        cls.doc = json.loads(_TRAEGER.read_text(encoding="utf-8"))

    def _signature_errors(self, d) -> list:
        return [f for f in self.g.pruefe_v2(d, REPO) if f.startswith("Signatur")]

    def test_the_identity_point_is_refused_and_no_view_says_verified(self):
        d = _signed(self.doc, I1, UNIV)
        self.assertIs(verify_ed25519(I1, UNIV, self.g.canonical_bytes(d)), True, "precondition")
        state, detail = self.g._signatur_lage(d)
        self.assertEqual(state, "KEY_REFUSED")
        self.assertIn(TRUST_ANCHOR_REFUSAL["low-order"], detail)
        line = self.g._signaturzeile(d)
        self.assertFalse(line.startswith("Signed"), line)
        self.assertIn("unauthenticated", line)
        for view in (self.g.ansicht_uebersicht(d), self.g.ansicht_html(d)):
            self.assertNotIn("Signed and verified", view)
            self.assertIn("cannot stand as a trusted key", view)
        self.assertTrue(self._signature_errors(d), "pruefe_v2 must count a refused key as an error")

    def test_the_zero_key_is_refused_for_every_body(self):
        """The register entry's own case: 32 zero bytes as key, 64 as signature. It is a point of
        order four, so the forgery holds for some bodies and not others; every one is refused. Over
        the line-610 carrier, where the bare profile accepted 7 of these 16 bodies on 126ed1dc (the
        line-600 carrier admits 1 of 16, too few to lean on). `_signatur_lage` reads no line state,
        so the exit and the view line are measured here; `pruefe_v2` is held above."""
        if not _TRAEGER_610.is_file():
            self.skipTest(f"NOT MEASURABLE: {_TRAEGER_610} is missing; the zero-key case did NOT run")
        doc = json.loads(_TRAEGER_610.read_text(encoding="utf-8"))
        live = 0
        for rev in range(16):
            with self.subTest(register_revision=rev):
                d = _signed(dict(doc, register_revision=rev), ZERO, ZSIG)
                live += verify_ed25519(ZERO, ZSIG, self.g.canonical_bytes(d))
                self.assertEqual(self.g._signatur_lage(d)[0], "KEY_REFUSED")
                self.assertFalse(self.g._signaturzeile(d).startswith("Signed"))
        self.assertGreater(live, 0, "no body admitted the forgery; this case would measure nothing")

    def test_every_weak_key_is_refused_by_name(self):
        for key, reason in WEAK:
            with self.subTest(key=key.hex()):
                state, detail = self.g._signatur_lage(_signed(self.doc, key, UNIV))
                self.assertEqual(state, "KEY_REFUSED")
                self.assertIn(TRUST_ANCHOR_REFUSAL[reason], detail)

    def test_positive_control_a_real_signature_verifies_and_the_view_says_so(self):
        k = Ed25519PrivateKey.generate()
        d = _signed(self.doc, _raw(k), b"\x00" * 64)
        d["signature"]["sig_b64"] = _b64(k.sign(self.g.canonical_bytes(d)))
        self.assertEqual(self.g._signatur_lage(d), ("VERIFIZIERT", "ed25519"))
        self.assertTrue(self.g._signaturzeile(d).startswith("Signed and verified"))
        self.assertEqual(self._signature_errors(d), [])

    def test_a_key_of_the_wrong_length_stays_a_broken_block(self):
        """Not a weak key and not a new state: before the rule it failed in the key constructor."""
        self.assertEqual(self.g._signatur_lage(_signed(self.doc, b"\x01" * 31, UNIV))[0], "GEBROCHEN")


# ── 3. `show-eval --expect-issuer`, the pin the SPEC says carries the rule ───────────────────────

def _cli(*args) -> "tuple[int, str, str]":
    from proofbundle.cli import main
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(list(args))
    return rc, out.getvalue(), err.getvalue()


class ShowEvalIssuerPin(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from proofbundle import evalclaim as ec
        from proofbundle.emit import emit_bundle, generate_signer
        cls.tmp = tempfile.TemporaryDirectory()
        d = Path(cls.tmp.name)
        cls.issuer_i1 = "ed25519:" + _b64(I1)
        try:
            claim, _ = ec.build_eval_claim(
                suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.80",
                score="0.10", n=10, model_id="m", dataset_id="d", issuer=cls.issuer_i1,
                timestamp="2026-09-26T12:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
            forged = emit_bundle(ec.canonicalize(dict(claim, passed=True, issuer=cls.issuer_i1)), _Nobody())
            cls.signer = generate_signer()
            real = ec.emit_eval_receipt(claim, cls.signer)
        except ec.EvalClaimError as exc:
            cls.tmp.cleanup()
            raise unittest.SkipTest(f"NOT MEASURABLE: the [eval] extra is missing ({exc}); the "
                                    "show-eval cases did NOT run") from exc
        cls.forged, cls.real = d / "forged.json", d / "real.json"
        cls.forged.write_text(json.dumps(forged), encoding="utf-8")
        cls.real.write_text(json.dumps(real), encoding="utf-8")
        cls.issuer_real = ec.issuer_fingerprint(cls.signer)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_precondition_the_receipt_nobody_signed_passes_in_the_self_attested_scope(self):
        """Without a pin the bundle's own key is the SPEC's in-band exception; the pin is the guard."""
        rc, out, _ = _cli("show-eval", str(self.forged))
        self.assertEqual(rc, 0)
        self.assertIn("passed     True", out)

    def test_a_small_order_pin_is_refused_typed_and_fail_closed(self):
        rc, out, err = _cli("show-eval", str(self.forged), "--expect-issuer", self.issuer_i1)
        self.assertEqual(rc, 2, out + err)
        self.assertNotIn("=> OK", out)
        self.assertIn("refused as a trusted key", err)
        self.assertIn(TRUST_ANCHOR_REFUSAL["low-order"], err)

    def test_every_weak_pin_is_refused_before_the_receipt_is_read(self):
        """Against a REAL receipt, so the refusal cannot come from the forgery: on 126ed1dc these
        were an ordinary issuer mismatch, exit 1."""
        for key, reason in WEAK:
            with self.subTest(key=key.hex()):
                rc, out, err = _cli("show-eval", str(self.real), "--expect-issuer", "ed25519:" + _b64(key))
                self.assertEqual(rc, 2, out + err)
                self.assertIn(TRUST_ANCHOR_REFUSAL[reason], err)
        rc, out, err = _cli("show-eval", str(self.real), "--expect-issuer", self.issuer_real,
                            "--expect-issuer", self.issuer_i1)
        self.assertEqual(rc, 2, "one weak pin in a rotation list refuses the list")

    def test_positive_control_a_normal_pin_behaves_as_before(self):
        rc, out, err = _cli("show-eval", str(self.real), "--expect-issuer", self.issuer_real)
        self.assertEqual(rc, 0, err)
        self.assertIn("=> OK", out)
        rc, out, err = _cli("show-eval", str(self.real), "--expect-issuer", "ed25519:alt",
                            "--expect-issuer", self.issuer_real)
        self.assertEqual(rc, 0, err)
        other = "ed25519:" + _b64(_raw(Ed25519PrivateKey.generate()))
        rc, out, err = _cli("show-eval", str(self.real), "--expect-issuer", other)
        self.assertEqual(rc, 1)
        self.assertIn("issuer mismatch", err)
        rc, out, err = _cli("show-eval", str(self.forged), "--expect-issuer", self.issuer_real)
        self.assertEqual(rc, 1, "the forgery against a real pin stays a mismatch")


# ── 4. the producers: where a key ENTERS a carrier ─────────────────────────────────────────────────
#
# The three `assemble` steps under scripts/ wrap a signature made elsewhere and the public key handed
# in with it, and write the carrier. Until the follow-up to D3 they checked the pair under the bare
# SPEC section 4a profile and relied on the verifiers that read their output to refuse a weak key.
# Measured on 3c9c98c3: each of the three wrote a carrier under the identity point with the signature
# R = identity, S = 0, and exited 0. The class is "a weak key is accepted where a key enters", so the
# refusal belongs here too, before anything is written.

_PRODUCERS = {
    # script, the assemble function, the module whose `canonical_bytes` the producer signs over
    "gen_findings_register": ("scripts/gen_findings_register.py", "assemble", "gen_findings_register"),
    "sign_readiness_artifact": ("scripts/sign_readiness_artifact.py", "assemble", "sign_readiness_artifact"),
    "pre_tag_receipt": ("scripts/pre_tag_receipt.py", "assemble_receipt", "pre_tag_receipt_lib"),
}


def _script_module(name: str):
    spec = importlib.util.spec_from_file_location(f"_t_d3_{name}", REPO / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _body(producer: str) -> dict:
    """A body each producer accepts in shape; what it says does not matter, who signed it does."""
    if producer == "gen_findings_register":
        return {"schema": "proofbundle.findings_register.v1", "version": "9.9.9",
                "generated_at": "2026-09-26T00:00:00Z", "findings": []}
    if producer == "sign_readiness_artifact":
        return {"schema": "x", "signer_role": "release-runner", "produced_at": "2026-09-26T00:00:00Z"}
    lib = _script_module("pre_tag_receipt_lib")
    return {"schema": lib.RECEIPT_SCHEMA, "version": "9.9.9", "subject_tree_digest": "a" * 64,
            "gate_source_digest": "b" * 64, "audit_command": "nobody ran this", "audit_exit_code": 0,
            "audit_output_digest": "c" * 64, "runner_identity": "nobody",
            "produced_at": "2026-09-26T00:00:00Z"}


def _canonical(producer: str, body: dict) -> bytes:
    return _script_module(_PRODUCERS[producer][2]).canonical_bytes(body)


def _assemble_cli(producer: str, body: dict, pub: bytes, sig: bytes, tmp: Path):
    """The producer's own `--assemble` command line, in a process of its own: pre_tag_receipt.py
    changes the process environment when it is imported, and a test must not inherit that."""
    import os
    import subprocess
    ctx, sig_file, out = tmp / "context.json", tmp / "sig.b64", tmp / "carrier.json"
    ctx.write_text(json.dumps(body), encoding="utf-8")
    sig_file.write_text(_b64(sig), encoding="utf-8")
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"), PYTHONDONTWRITEBYTECODE="1")
    r = subprocess.run([sys.executable, "-B", str(REPO / _PRODUCERS[producer][0]), "--assemble",
                        "--context-in", str(ctx), "--sig-file", str(sig_file),
                        "--signer-pubkey", _b64(pub), "--out", str(out)],
                       capture_output=True, text=True, timeout=120, env=env, cwd=str(tmp))
    return r, out


_DRIVER = """
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("producer", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
fn, body = getattr(mod, sys.argv[2]), json.loads(sys.argv[3])
out = []
for pub, sig in json.loads(sys.argv[4]):
    try:
        fn(body, sig, pub)
        out.append(["ACCEPTED", ""])
    except SystemExit as exc:
        out.append(["REFUSED", str(exc.code)])
print(json.dumps(out))
"""


def _assemble_every_weak_key(producer: str, body: dict) -> list:
    """The producer's `assemble` called once per WEAK key, in one process of its own."""
    import os
    import subprocess
    path, fn, _lib = _PRODUCERS[producer]
    cases = [[_b64(key), _b64(UNIV)] for key, _reason in WEAK]
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"), PYTHONDONTWRITEBYTECODE="1")
    r = subprocess.run([sys.executable, "-B", "-c", _DRIVER, str(REPO / path), fn, json.dumps(body),
                        json.dumps(cases)], capture_output=True, text=True, timeout=120, env=env)
    if r.returncode != 0:
        raise AssertionError(f"driver for {producer} failed: {r.stderr[-800:]}")
    return json.loads(r.stdout.strip().splitlines()[-1])


class ProducerSelfChecks(unittest.TestCase):
    """One refusal and one control per producer."""

    def _refuses(self, producer: str):
        body = _body(producer)
        self.assertIs(verify_ed25519(I1, UNIV, _canonical(producer, body)), True,
                      "precondition: the bare profile accepts the signature nobody made")
        with tempfile.TemporaryDirectory() as d:
            r, out = _assemble_cli(producer, body, I1, UNIV, Path(d))
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertFalse(out.exists(), "a carrier under a weak key was written")
            self.assertIn(TRUST_ANCHOR_REFUSAL["low-order"], r.stderr)
        for (key, reason), (verdict, message) in zip(WEAK, _assemble_every_weak_key(producer, body)):
            with self.subTest(key=key.hex()):
                self.assertEqual(verdict, "REFUSED", message)
                self.assertIn(TRUST_ANCHOR_REFUSAL[reason], message)

    def _control(self, producer: str):
        body = _body(producer)
        k = Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as d:
            r, out = _assemble_cli(producer, body, _raw(k), k.sign(_canonical(producer, body)), Path(d))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            carrier = json.loads(out.read_text(encoding="utf-8"))
        self.assertIn(_b64(_raw(k)), json.dumps(carrier), "the carrier does not name the signer key")
        with tempfile.TemporaryDirectory() as d:     # and a real key under a wrong signature still refuses
            r, out = _assemble_cli(producer, body, _raw(k), k.sign(b"another body"), Path(d))
            self.assertNotEqual(r.returncode, 0)
            self.assertFalse(out.exists())

    def test_gen_findings_register_assemble_refuses_a_weak_key(self):
        self._refuses("gen_findings_register")

    def test_gen_findings_register_assemble_control_with_a_real_key(self):
        self._control("gen_findings_register")

    def test_sign_readiness_artifact_assemble_refuses_a_weak_key(self):
        self._refuses("sign_readiness_artifact")

    def test_sign_readiness_artifact_assemble_control_with_a_real_key(self):
        self._control("sign_readiness_artifact")

    def test_pre_tag_receipt_assemble_refuses_a_weak_key(self):
        self._refuses("pre_tag_receipt")

    def test_pre_tag_receipt_assemble_control_with_a_real_key(self):
        self._control("pre_tag_receipt")


if __name__ == "__main__":
    unittest.main()
