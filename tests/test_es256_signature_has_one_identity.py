"""An ES256 signature has one identity (finding D1, owner decision 2026-09-26).

ECDSA is malleable: whoever sees a valid ES256 signature (r, s) can write (r, n - s) without the key,
and both verify. The owner decided:

1. verification keeps accepting both spellings (RFC 7518 does not require a low s, and two of the five
   vendored IETF SD-JWT VC examples carry a high one), but every identity, digest, dedup or replay key
   formed from ES256 signature bytes is formed over the low-s spelling;
2. eip191 refuses a high s (tested in ``tests/test_anchors_rootcommit.py``);
3. whatever proofbundle emits carries the low s only, the pb1 token included;
4. the pb1 verifier accepts a token with a high s and reads it in the low-s spelling.

The identity sites come from the measured map of D1: the pb1 token (``hf_evals.receipt_token``), the
bundle ``verify_receipt_token`` returns, the receipt anchor root (``anchors.receipt_canonical_root``),
the KB-JWT ``sd_hash`` (``kbjwt.verify_key_binding``) and the one proofbundle signs itself
(``sdjwt_issue.present_with_key_binding``). Each class says whether it was red on 126ed1dc; the few
cases that were green there say so in their docstring, because a case that cannot fall is a guard,
not evidence of the fix.

The twin is built here with the test's own arithmetic and its own copy of n, never with the module's
helpers, so the tests do not agree with the code by construction.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import pathlib
import unittest
import zlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import emit_bundle, generate_signer, verify_bundle
from proofbundle.hf_evals import receipt_token, verify_receipt_token
from proofbundle.kbjwt import verify_key_binding
from proofbundle.sdjwt import verify_sd_jwt
from proofbundle.sdjwt_issue import present_with_key_binding
from proofbundle.signature import verify_ecdsa_p256

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551   # P-256 order (SEC 2)
SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "proofbundle"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _es256_issuer_jwt(payload: dict, key, *, high: "bool | None" = None) -> str:
    """An ES256 issuer JWT over ``payload``. ``high`` forces the half s lies in; None keeps whatever
    the library produced (about half of all signatures carry a high s)."""
    header = _b64u(json.dumps({"alg": "ES256", "typ": "dc+sd-jwt"}).encode())
    body = _b64u(json.dumps(payload).encode())
    r, s = decode_dss_signature(key.sign(f"{header}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
    if high is not None and (s > N // 2) != high:
        s = N - s
    return f"{header}.{body}.{_b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def _twin(compact: str) -> str:
    """``compact`` with its issuer signature's s replaced by n - s; every other byte is kept."""
    jwt, sep, rest = compact.partition("~")
    header, body, sig_b64 = jwt.split(".")
    sig = _unb64u(sig_b64)
    other = sig[:32] + (N - int.from_bytes(sig[32:], "big")).to_bytes(32, "big")
    return f"{header}.{body}.{_b64u(other)}{sep}{rest}"


def _issuer_s(compact: str) -> int:
    return int.from_bytes(_unb64u(compact.split("~", 1)[0].split(".")[2])[32:], "big")


def _p256():
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return key, pub, base64.b64encode(pub).decode("ascii")


def _bundle_with(compact: str, pub_b64: str) -> dict:
    """A bundle that carries ``compact`` exactly as given, the way a bundle can arrive from outside
    (assembled by another producer, or emitted before this change). ``emit_bundle`` itself writes
    the low-s spelling, so the compact is set after emission."""
    bundle = emit_bundle(b'{"hello": 1}', generate_signer(),
                         sd_jwt_vc={"compact": compact, "issuer_public_key_b64": pub_b64})
    bundle["sd_jwt_vc"]["compact"] = compact
    return bundle


def _with_compact(bundle: dict, compact: str) -> dict:
    out = json.loads(json.dumps(bundle))
    out["sd_jwt_vc"]["compact"] = compact
    return out


def _token_as_126ed1dc_packed_it(bundle: dict) -> str:
    """A pb1 token the way 126ed1dc packed it: the bundle as it came, high s included."""
    raw = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "pb1." + _b64u(zlib.compress(raw, 9))


def _compact_in_token(token: str) -> str:
    return json.loads(zlib.decompress(_unb64u(token[len("pb1."):])))["sd_jwt_vc"]["compact"]


def _holder():
    holder = Ed25519PrivateKey.generate()
    x = _b64u(holder.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    return holder, {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": x}}


def _key_binding_over(presented: str, holder, *, aud: str, nonce: str) -> str:
    """A KB-JWT a holder other than proofbundle makes: sd_hash over exactly the bytes it received,
    whatever the spelling of the issuer signature."""
    sd_hash = _b64u(hashlib.sha256(presented.encode("ascii")).digest())
    header = _b64u(json.dumps({"alg": "EdDSA", "typ": "kb+jwt"}).encode())
    body = _b64u(json.dumps({"iat": 1, "aud": aud, "nonce": nonce, "sd_hash": sd_hash}).encode())
    return presented + f"{header}.{body}." + _b64u(holder.sign(f"{header}.{body}".encode()))


class TheVerdictAcceptsBothSpellings(unittest.TestCase):
    """Owner decision, point 1: verification accepts (r, s) and (r, n - s). GREEN on 126ed1dc as
    well; it pins that the fix did not turn acceptance into refusal."""

    def test_primitive_sd_jwt_and_bundle_accept_both_spellings(self):
        key, pub, pub_b64 = _p256()
        for high in (False, True):
            compact = _es256_issuer_jwt({"vct": "https://example.test/vct"}, key, high=high) + "~"
            twin = _twin(compact)
            for spelling in (compact, twin):
                header, body, sig_b64 = spelling.split("~", 1)[0].split(".")
                self.assertTrue(verify_ecdsa_p256(pub, _unb64u(sig_b64), f"{header}.{body}".encode()))
                self.assertTrue(verify_sd_jwt(spelling, pub)["sig_ok"])
                self.assertTrue(verify_bundle(_bundle_with(spelling, pub_b64)).ok)


class ThePb1TokenHasOneIdentity(unittest.TestCase):
    """Rows 1 and 2 of the map. RED on 126ed1dc: the twin gave a second token, a high s went into the
    token as it came, and verify_receipt_token handed back the spelling the token carried."""

    def setUp(self):
        self.key, self.pub, self.pub_b64 = _p256()

    def test_a_bundle_and_its_twin_give_one_token_with_a_low_s(self):
        for high in (False, True):
            compact = _es256_issuer_jwt({"vct": "https://example.test/vct"}, self.key, high=high) + "~"
            bundle = _bundle_with(compact, self.pub_b64)
            twin = _with_compact(bundle, _twin(compact))
            token = receipt_token(bundle)
            self.assertEqual(token, receipt_token(twin), f"high={high}")
            self.assertLessEqual(_issuer_s(_compact_in_token(token)), N // 2, f"high={high}")
            self.assertTrue(verify_receipt_token(token)[0].ok)
            # receipt_token must not rewrite the caller's dict
            self.assertEqual(bundle["sd_jwt_vc"]["compact"], compact)

    def test_a_token_with_a_high_s_is_accepted_and_read_in_the_low_s_spelling(self):
        compact = _es256_issuer_jwt({"vct": "https://example.test/vct"}, self.key, high=True) + "~"
        bundle = _bundle_with(compact, self.pub_b64)
        legacy = _token_as_126ed1dc_packed_it(bundle)
        self.assertGreater(_issuer_s(_compact_in_token(legacy)), N // 2)   # the old token does carry it
        result, unpacked = verify_receipt_token(legacy)
        self.assertTrue(result.ok, result.as_dict())
        self.assertLessEqual(_issuer_s(unpacked["sd_jwt_vc"]["compact"]), N // 2)
        low_result, low_unpacked = verify_receipt_token(receipt_token(_with_compact(bundle, _twin(compact))))
        self.assertTrue(low_result.ok)
        self.assertEqual(unpacked, low_unpacked, "two tokens of one receipt unpack to one bundle")
        self.assertEqual(receipt_token(unpacked), receipt_token(low_unpacked))
        # the verdict on the token's own bytes: both spellings of the bundle verify alike
        self.assertEqual(verify_bundle(bundle).ok, result.ok)

    def test_a_token_whose_key_binding_hashed_a_high_s_verifies_like_its_bundle(self):
        holder, cnf = _holder()
        compact = _es256_issuer_jwt({"vct": "https://example.test/vct", "cnf": cnf}, self.key, high=True) + "~"
        bundle = _bundle_with(_key_binding_over(compact, holder, aud="rp", nonce="n1"), self.pub_b64)
        self.assertTrue(verify_bundle(bundle).ok)                     # the bytes as they came
        result, unpacked = verify_receipt_token(_token_as_126ed1dc_packed_it(bundle))
        self.assertTrue(result.ok, result.as_dict())
        self.assertLessEqual(_issuer_s(unpacked["sd_jwt_vc"]["compact"]), N // 2)
        self.assertTrue(verify_bundle(unpacked).ok)                   # the identity verifies alike
        self.assertEqual(receipt_token(bundle), receipt_token(unpacked))

    def test_an_eddsa_bundle_token_is_unchanged(self):
        # GREEN on 126ed1dc as well: the canonical form touches an ES256 issuer signature only
        bundle = emit_bundle(b'{"suite": "demo", "passed": true}', generate_signer())
        self.assertEqual(receipt_token(bundle), _token_as_126ed1dc_packed_it(bundle))
        self.assertEqual(verify_receipt_token(receipt_token(bundle))[1], bundle)


class TheReceiptAnchorRootHasOneIdentity(unittest.TestCase):
    """Row 3 of the map. RED on 126ed1dc: a bundle and its twin had two roots, so an anchor stamped
    over one spelling failed --require-anchor for the other."""

    def setUp(self):
        try:
            import rfc8785  # noqa: F401,PLC0415
        except ImportError:   # pragma: no cover - a core dependency since 3.6.1
            self.skipTest("rfc8785 not installed")
        self.key, self.pub, self.pub_b64 = _p256()

    def test_a_bundle_and_its_twin_have_one_root(self):
        from proofbundle.anchors import receipt_canonical_root  # noqa: PLC0415
        for high in (False, True):
            compact = _es256_issuer_jwt({"vct": "https://example.test/vct"}, self.key, high=high) + "~"
            bundle = _bundle_with(compact, self.pub_b64)
            twin = _with_compact(bundle, _twin(compact))
            self.assertEqual(receipt_canonical_root(bundle), receipt_canonical_root(twin), f"high={high}")

    def test_an_anchor_over_one_spelling_covers_the_other(self):
        from proofbundle import anchors  # noqa: PLC0415
        from proofbundle.cli import _evaluate_anchor_requirement  # noqa: PLC0415
        type_name = "d1-test-echo/v1"

        def echo(proof, canonical_root, *, frozen, now):
            ok = proof == canonical_root
            return {"ok": ok, "detail": "echo" if ok else "echo mismatch"}
        anchors.register_anchor_type(type_name, echo)
        self.addCleanup(anchors._VERIFIERS.pop, type_name, None)

        compact = _es256_issuer_jwt({"vct": "https://example.test/vct"}, self.key, high=False) + "~"
        bundle = _bundle_with(compact, self.pub_b64)
        root = anchors.receipt_canonical_root(bundle)
        entry = {"type": type_name, "target": "receipt", "canonicalRoot": base64.b64encode(root).decode(),
                 "proof": base64.b64encode(root).decode()}
        for spelling in (bundle, _with_compact(bundle, _twin(compact))):
            anchored = dict(spelling, anchors=[entry])
            verdict = _evaluate_anchor_requirement(anchored, require=type_name, allow_pending=False)
            self.assertTrue(verdict["ok"], verdict)


class TheKeyBindingBindsThePresentationNotTheSpelling(unittest.TestCase):
    """Rows 4 and 5 of the map. RED on 126ed1dc: the twin of a presentation failed the sd_hash check
    (so verify_bundle refused one of the two spellings as soon as a KB-JWT was attached), and
    proofbundle's own presenter passed a high s on and bound it."""

    def setUp(self):
        self.key, self.pub, self.pub_b64 = _p256()
        self.holder, cnf = _holder()
        self.payload = {"vct": "https://example.test/vct", "cnf": cnf}

    def _check_both(self, presentation: str):
        for spelling in (presentation, _twin(presentation)):
            res = verify_key_binding(spelling, expected_aud="rp", expected_nonce="n1")
            self.assertTrue(res["ok"], res["detail"])
            bundle = _bundle_with(spelling, self.pub_b64)
            self.assertTrue(verify_bundle(bundle, expected_aud="rp", expected_nonce="n1").ok)

    def test_a_holder_that_hashed_either_spelling_verifies_in_both(self):
        for high in (False, True):
            compact = _es256_issuer_jwt(self.payload, self.key, high=high) + "~"
            self._check_both(_key_binding_over(compact, self.holder, aud="rp", nonce="n1"))

    def test_proofbundle_presents_and_binds_the_low_s_spelling(self):
        for high in (False, True):
            compact = _es256_issuer_jwt(self.payload, self.key, high=high) + "~"
            presentation = present_with_key_binding(compact, self.holder, aud="rp", nonce="n1", iat=1)
            self.assertLessEqual(_issuer_s(presentation), N // 2, f"high={high}")
            self._check_both(presentation)

    def test_the_other_spelling_widens_nothing_else(self):
        """GREEN on 126ed1dc as well: a dropped disclosure, a foreign KB-JWT or a wrong nonce still
        fail in either spelling. The comparison accepts the second spelling of the issuer signature
        and nothing more."""
        disclosure = _b64u(json.dumps(["salt", "given_name", "Erika"]).encode())
        digest = _b64u(hashlib.sha256(disclosure.encode("ascii")).digest())
        payload = dict(self.payload, _sd=[digest], _sd_alg="sha-256")
        compact = _es256_issuer_jwt(payload, self.key, high=True) + "~" + disclosure + "~"
        presentation = _key_binding_over(compact, self.holder, aud="rp", nonce="n1")
        kb = presentation[len(compact):]
        without_disclosure = compact.split("~", 1)[0] + "~"
        other_holder, _ = _holder()
        foreign = _key_binding_over(compact, other_holder, aud="rp", nonce="n1")
        for spelling in (presentation, _twin(presentation)):
            self.assertFalse(verify_key_binding(spelling, expected_aud="rp", expected_nonce="n2")["ok"])
        for spelling in (without_disclosure, _twin(without_disclosure)):
            self.assertFalse(verify_key_binding(spelling + kb, expected_aud="rp", expected_nonce="n1")["ok"])
        for spelling in (foreign, _twin(foreign)):
            self.assertFalse(verify_key_binding(spelling, expected_aud="rp", expected_nonce="n1")["ok"])


class OwnEs256OutputCarriesALowS(unittest.TestCase):
    """Owner decision, point 3. proofbundle signs no ES256 signature of its own (the inventory case
    below keeps that true); the ES256 bytes it EMITS are the ones it passes on: in a bundle from
    ``emit_bundle`` (``emit_eval_receipt`` goes through it), in a pb1 token and in a presentation.
    Over many signatures, with both halves of s occurring, every one goes out with a low s. RED on
    126ed1dc: every high s went out as it came."""

    ROUNDS = 96

    def test_every_emitted_es256_signature_has_a_low_s(self):
        key, _pub, pub_b64 = _p256()
        holder, _cnf = _holder()
        seen = {"low": 0, "high": 0}
        for i in range(self.ROUNDS):
            compact = _es256_issuer_jwt({"vct": "https://example.test/vct", "i": i}, key) + "~"
            seen["high" if _issuer_s(compact) > N // 2 else "low"] += 1
            sd = {"compact": compact, "issuer_public_key_b64": pub_b64}
            emitted = emit_bundle(b'{"i": %d}' % i, generate_signer(), sd_jwt_vc=sd)
            self.assertLessEqual(_issuer_s(emitted["sd_jwt_vc"]["compact"]), N // 2, f"round {i}: bundle")
            self.assertEqual(sd["compact"], compact, "emit_bundle must not rewrite the caller's dict")
            self.assertTrue(verify_bundle(emitted).ok, f"round {i}")
            token = receipt_token(_bundle_with(compact, pub_b64))
            self.assertLessEqual(_issuer_s(_compact_in_token(token)), N // 2, f"round {i}: pb1 token")
            presentation = present_with_key_binding(compact, holder, aud="rp", nonce=str(i), iat=i)
            self.assertLessEqual(_issuer_s(presentation), N // 2, f"round {i}: presentation")
        self.assertGreater(seen["low"], 0, seen)
        self.assertGreater(seen["high"], 0, seen)

    def test_no_other_ecdsa_signing_path_exists_in_src(self):
        """An inventory, GREEN on 126ed1dc as well. The only ECDSA machinery in the package is the
        ES256 verifier and the secp256k1 recovery in rootcommit. A new path that SIGNS with ECDSA must
        emit the low s and join the property above; this case fails until someone looks."""
        allowed = {("signature.py", "ECDSA"), ("signature.py", "SECP256R1"),
                   ("anchors_rootcommit.py", "SECP256k1")}
        watched = {"ECDSA", "SECP256R1", "SECP256K1", "SECP256k1", "SigningKey", "sign_digest",
                   "sign_deterministic", "sign_digest_deterministic"}
        found = set()
        for path in sorted(SRC.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                name = node.attr if isinstance(node, ast.Attribute) else (
                    node.id if isinstance(node, ast.Name) else (
                        node.name if isinstance(node, ast.alias) else None))
                if name in watched:
                    found.add((path.relative_to(SRC).as_posix(), name))
        self.assertEqual(found - allowed, set(), "an ECDSA path outside the verifiers")
        self.assertTrue(allowed & found, "the inventory walked nothing")


if __name__ == "__main__":
    unittest.main()
