"""An ES256 signature has one identity, and a foreign issuer's bytes are never rewritten (finding D1).

ECDSA is malleable: whoever sees a valid ES256 signature (r, s) can write (r, n - s) without the key,
and both verify. Two owner decisions of 2026-09-26, the second refining the first:

1. verification keeps accepting both spellings (``verify_ecdsa_p256``, ``verify_sd_jwt``,
   ``verify_bundle``, a pb1 token);
2. the bytes of a foreign issuer are never rewritten: not in a compact proofbundle emits, not inside
   a pb1 token, not in the bundle ``verify_receipt_token`` returns, with or without a Key Binding JWT.
   A KB-JWT's ``sd_hash`` covers the issuer JWT as presented (RFC 9901 §4.3); f536af50 rewrote the
   issuer signature to the low s and broke that binding for every verifier that hashes what it gets;
3. every identity (the receipt root, the identity of a pb1 token, a dedup, replay or log key) is
   computed over the form in which EVERY ES256 signature carries the low s, the issuer JWT's and a
   KB-JWT's, so twins have one identity. The cost is stated in the CHANGELOG: a receipt and its twin
   are two token strings with one identity;
4. a low s is required only of signatures proofbundle makes itself (it makes no ES256 signature
   today); eip191 refuses a high s (``tests/test_anchors_rootcommit.py``).

Each class says whether it was red on f536af50 and on 126ed1dc, measured by running this file
against those trees. A case that was green there says so, because a case that cannot fall is a
guard, not evidence of the fix.

The oracles are the test's own: its own copy of n, its own sha256 over the presented bytes for the
RFC 9901 ``sd_hash``, and its own reading of the receipt-root recipe in ``docs/ANCHORS.md``. The
module's helpers are never the oracle.
"""
from __future__ import annotations

import ast
import base64
import contextlib
import copy
import hashlib
import io
import json
import os
import pathlib
import tempfile
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
L = 2 ** 252 + 27742317777372353535851937790883648493                    # Ed25519 order (RFC 8032)
SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "proofbundle"
VCT = "https://example.test/vct"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _es256_jws(header: dict, payload: dict, key, *, high: "bool | None" = None) -> str:
    """A compact ES256 JWS. ``high`` forces the half s lies in; None keeps what the library made
    (about half of all signatures carry a high s)."""
    h = _b64u(json.dumps(header).encode())
    b = _b64u(json.dumps(payload).encode())
    r, s = decode_dss_signature(key.sign(f"{h}.{b}".encode(), ec.ECDSA(hashes.SHA256())))
    if high is not None and (s > N // 2) != high:
        s = N - s
    return f"{h}.{b}.{_b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def _issuer_jwt(payload: dict, key, *, high: "bool | None" = None) -> str:
    return _es256_jws({"alg": "ES256", "typ": "dc+sd-jwt"}, payload, key, high=high)


def _flip_jws(jws: str) -> str:
    """``jws`` with its signature's s replaced by n - s; every other byte is kept."""
    h, b, sig_b64 = jws.split(".")
    sig = _unb64u(sig_b64)
    return f"{h}.{b}.{_b64u(sig[:32] + (N - int.from_bytes(sig[32:], 'big')).to_bytes(32, 'big'))}"


def _twin(compact: str) -> str:
    """The issuer-slot twin: the issuer JWT's s replaced by n - s, every other byte kept."""
    parts = compact.split("~")
    parts[0] = _flip_jws(parts[0])
    return "~".join(parts)


def _kb_twin(compact: str) -> str:
    """The KB-slot twin: the trailing Key Binding JWT's s replaced by n - s, every other byte kept."""
    parts = compact.split("~")
    parts[-1] = _flip_jws(parts[-1])
    return "~".join(parts)


def _s_of(jws: str) -> int:
    return int.from_bytes(_unb64u(jws.split(".")[2])[32:], "big")


def _issuer_s(compact: str) -> int:
    return _s_of(compact.split("~", 1)[0])


def _p256():
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return key, pub, base64.b64encode(pub).decode("ascii")


def _ed25519_holder():
    holder = Ed25519PrivateKey.generate()
    x = _b64u(holder.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    return holder, {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": x}}


def _sd_hash(presented: str) -> str:
    return _b64u(hashlib.sha256(presented.encode("ascii")).digest())


def _eddsa_key_binding(presented: str, holder, *, aud: str = "rp", nonce: str = "n1") -> str:
    """A KB-JWT a holder other than proofbundle makes: sd_hash over exactly the bytes it received."""
    h = _b64u(json.dumps({"alg": "EdDSA", "typ": "kb+jwt"}).encode())
    b = _b64u(json.dumps({"iat": 1, "aud": aud, "nonce": nonce, "sd_hash": _sd_hash(presented)}).encode())
    return presented + f"{h}.{b}." + _b64u(holder.sign(f"{h}.{b}".encode()))


def _es256_key_binding(presented: str, holder_key, *, high: bool) -> str:
    """An ES256 KB-JWT, as IETF example 1 carries one. proofbundle's KB check accepts EdDSA only, so a
    bundle with this KB-JWT does not verify; its identity must still be one."""
    payload = {"iat": 1, "aud": "rp", "nonce": "n1", "sd_hash": _sd_hash(presented)}
    return presented + _es256_jws({"alg": "ES256", "typ": "kb+jwt"}, payload, holder_key, high=high)


def _rfc9901_sd_hash_holds(compact: str) -> bool:
    """RFC 9901 §4.3 over the exact bytes: sha256 of everything up to and including the last "~"
    equals the KB-JWT's sd_hash. No second spelling is tried; this is what any other verifier does."""
    head, _, kb = compact.rpartition("~")
    return json.loads(_unb64u(kb.split(".")[1]))["sd_hash"] == _sd_hash(head + "~")


def _bundle_with(compact: str, pub_b64: "str | None") -> dict:
    """A bundle that carries ``compact`` as the caller hands it to ``emit_bundle``."""
    sd = {"compact": compact}
    if pub_b64 is not None:
        sd["issuer_public_key_b64"] = pub_b64
    return emit_bundle(b'{"hello": 1}', generate_signer(), sd_jwt_vc=sd)


def _carrying(compact: str, pub_b64: str) -> dict:
    """A bundle that carries ``compact`` exactly, whatever an emitter does with it: the way a bundle
    arrives from another producer. The identity cases use it so that they measure the identity rule
    alone."""
    bundle = emit_bundle(b'{"hello": 1}', generate_signer())
    bundle["sd_jwt_vc"] = {"compact": compact, "issuer_public_key_b64": pub_b64}
    return bundle


def _with_compact(bundle: dict, compact: str) -> dict:
    out = copy.deepcopy(bundle)
    out["sd_jwt_vc"]["compact"] = compact
    return out


def _token_as_other_producers_pack_it(bundle: dict) -> str:
    """A pb1 token the way 126ed1dc packed it, and the way anyone following the format does."""
    raw = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "pb1." + _b64u(zlib.compress(raw, 9))


def _compact_in_token(token: str) -> str:
    return json.loads(zlib.decompress(_unb64u(token[len("pb1."):])))["sd_jwt_vc"]["compact"]


_B64URL_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _strict_b64url(segment: str) -> "bytes | None":
    """docs/ANCHORS.md, step 2: the URL-safe alphabet only, no ``=`` padding, pad bits zero. The
    last condition holds exactly when re-encoding the decoded bytes gives the segment back."""
    if not segment or not set(segment) <= _B64URL_ALPHABET or len(segment) % 4 == 1:
        return None
    raw = _unb64u(segment)
    return raw if _b64u(raw) == segment else None


def _strict_json_object(raw: bytes) -> "dict | None":
    """docs/ANCHORS.md, step 2: a JSON object, a duplicate key or a lone surrogate refused."""
    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(pairs)
    try:
        obj = json.loads(raw, object_pairs_hook=no_duplicates)
    except ValueError:
        return None
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, str) and any(0xD800 <= ord(ch) <= 0xDFFF for ch in cur):
            return None
        if isinstance(cur, dict):
            stack.extend(cur.keys())
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return obj if isinstance(obj, dict) else None


def _docs_name_the_fold_domain(text: str) -> list:
    """The conditions of step 2 that the receipt-root section of ``docs/ANCHORS.md`` does not name.
    Empty when the text states the domain the code folds."""
    start = text.index("**The receipt root, step by step**")
    section = " ".join(text[start:text.index("## Schema", start)].split())   # line breaks do not count
    wanted = {"strict base64url": "strict base64url", "no padding": "no `=` padding",
              "pad bits zero": "pad bits zero", "duplicate key refused": "duplicate key",
              "lone surrogate refused": "lone surrogate", "the strict reader": "loads_strict",
              "the signature segment strict too": "signature segment is strict base64url"}
    return [name for name, phrase in wanted.items() if phrase not in section]


def _root_per_docs(bundle: dict) -> bytes:
    """The receipt root as ``docs/ANCHORS.md`` defines it in three steps, written from that text
    rather than from the module: drop ``anchors``; in ``sd_jwt_vc.compact`` fold each candidate slot
    (the first part, and a last part with two dots) that meets every condition of step 2, and keep
    every other byte; sha256 of the RFC 8785 serialization. The size limits of the strict reader are
    not modelled; no input here comes near them."""
    import rfc8785  # noqa: PLC0415 - a core dependency since 3.6.1
    receipt = {k: v for k, v in bundle.items() if k != "anchors"}
    sd = receipt.get("sd_jwt_vc")
    if isinstance(sd, dict) and isinstance(sd.get("compact"), str):
        parts = sd["compact"].split("~")
        slots = [0] + ([len(parts) - 1] if len(parts) > 1 and parts[-1].count(".") == 2 else [])
        for i in slots:
            segments = parts[i].split(".")
            if len(segments) != 3:
                continue
            header_raw, signature = _strict_b64url(segments[0]), _strict_b64url(segments[2])
            header = _strict_json_object(header_raw) if header_raw is not None else None
            if (header is not None and header.get("alg") == "ES256" and signature is not None
                    and len(signature) == 64 and N // 2 < int.from_bytes(signature[32:], "big") < N):
                parts[i] = _flip_jws(parts[i])
        receipt = dict(receipt, sd_jwt_vc=dict(sd, compact="~".join(parts)))
    return hashlib.sha256(rfc8785.dumps(receipt)).digest()


def _cli(argv) -> "tuple[int, str]":
    from proofbundle.cli import main  # noqa: PLC0415
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        try:
            rc = main(argv)
        except SystemExit as exc:   # pragma: no cover - main returns its exit code
            rc = exc.code
    return rc, out.getvalue()


class TheVerdictAcceptsBothSpellings(unittest.TestCase):
    """Owner decision, point 1. GREEN on 126ed1dc and on f536af50: it pins that neither fix turned
    acceptance into refusal."""

    def test_primitive_sd_jwt_and_bundle_accept_both_spellings(self):
        key, pub, pub_b64 = _p256()
        for high in (False, True):
            compact = _issuer_jwt({"vct": VCT}, key, high=high) + "~"
            for spelling in (compact, _twin(compact)):
                header, body, sig_b64 = spelling.split("~", 1)[0].split(".")
                self.assertTrue(verify_ecdsa_p256(pub, _unb64u(sig_b64), f"{header}.{body}".encode()))
                self.assertTrue(verify_sd_jwt(spelling, pub)["sig_ok"])
                self.assertTrue(verify_bundle(_bundle_with(spelling, pub_b64)).ok)


class AForeignIssuersBytesAreNeverRewritten(unittest.TestCase):
    """Owner decision, point 2. The presentation is genuine: the holder hashed the HIGH-s issuer JWT
    it received. RED on f536af50 (``emit_bundle``, ``receipt_token`` and ``verify_receipt_token``
    wrote the low s, the RFC 9901 check failed on what they emitted, and ``present_with_key_binding``
    replaced the handed issuer signature); GREEN on 126ed1dc, which passed the bytes on."""

    def setUp(self):
        self.key, self.pub, self.pub_b64 = _p256()
        self.holder, cnf = _ed25519_holder()
        self.payload = {"vct": VCT, "cnf": cnf}

    def _presentations(self):
        """(label, compact, carries_kb) for a high and a low issuer s, with and without a KB-JWT."""
        for high in (True, False):
            issued = _issuer_jwt(self.payload, self.key, high=high) + "~"
            yield f"high={high} no KB", issued, False
            yield f"high={high} with KB", _eddsa_key_binding(issued, self.holder), True

    def test_emit_bundle_emits_the_presented_compact(self):
        for label, compact, carries_kb in self._presentations():
            sd = {"compact": compact, "issuer_public_key_b64": self.pub_b64}
            emitted = emit_bundle(b'{"hello": 1}', generate_signer(), sd_jwt_vc=sd)
            self.assertEqual(emitted["sd_jwt_vc"]["compact"], compact, label)
            self.assertEqual(sd["compact"], compact, f"{label}: the caller's dict is not modified")
            if carries_kb:
                self.assertTrue(_rfc9901_sd_hash_holds(emitted["sd_jwt_vc"]["compact"]), label)
                self.assertTrue(verify_bundle(emitted, expected_aud="rp", expected_nonce="n1").ok, label)

    def test_emit_eval_receipt_emits_the_presented_compact(self):
        from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt  # noqa: PLC0415
        claim, _salts = build_eval_claim(
            suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.8", score="0.9",
            n=10, model_id="m", dataset_id="d", issuer="Lab", timestamp="2026-07-02T00:00:00Z")
        for label, compact, _carries_kb in self._presentations():
            bundle = emit_eval_receipt(claim, generate_signer(),
                                       sd_jwt={"compact": compact, "issuer_public_key_b64": self.pub_b64})
            self.assertEqual(bundle["sd_jwt_vc"]["compact"], compact, label)

    def test_a_pb1_token_carries_the_presented_compact(self):
        for label, compact, carries_kb in self._presentations():
            bundle = _bundle_with(compact, self.pub_b64)
            token = receipt_token(bundle)
            self.assertEqual(_compact_in_token(token), compact, label)
            self.assertEqual(token, _token_as_other_producers_pack_it(bundle),
                             f"{label}: a token packs the bundle as it is")
            if carries_kb:
                self.assertTrue(_rfc9901_sd_hash_holds(_compact_in_token(token)), label)

    def test_verify_receipt_token_returns_the_presented_compact(self):
        for label, compact, carries_kb in self._presentations():
            bundle = _bundle_with(compact, self.pub_b64)
            for token in (receipt_token(bundle), _token_as_other_producers_pack_it(bundle)):
                result, unpacked = verify_receipt_token(token)
                # the verdict on the token is the verdict on the bundle as it came; without a KB-JWT a
                # cnf-bound issuer JWT fails by design (bearer downgrade), with one it verifies
                self.assertEqual(result.ok, verify_bundle(bundle).ok, label)
                self.assertEqual(unpacked, bundle, label)
                if carries_kb:
                    self.assertTrue(result.ok, f"{label}: {result.as_dict()}")
                    self.assertTrue(_rfc9901_sd_hash_holds(unpacked["sd_jwt_vc"]["compact"]), label)

    def test_present_with_key_binding_presents_the_handed_bytes(self):
        for high in (True, False):
            issued = _issuer_jwt(self.payload, self.key, high=high) + "~"
            presentation = present_with_key_binding(issued, self.holder, aud="rp", nonce="n1", iat=1)
            self.assertTrue(presentation.startswith(issued), f"high={high}")
            self.assertTrue(_rfc9901_sd_hash_holds(presentation), f"high={high}")
            self.assertTrue(verify_key_binding(presentation, expected_aud="rp", expected_nonce="n1")["ok"])

    def test_an_es256_key_binding_jwt_is_not_rewritten_either(self):
        """GREEN on f536af50 and on 126ed1dc (neither touched the KB-JWT slot; the issuer s is low here
        so that only that slot is measured). A guard for this change, which folds the KB-JWT slot for
        identities: that fold must not reach an emitted byte."""
        holder_key, _hpub, _hpub_b64 = _p256()
        issued = _issuer_jwt({"vct": VCT}, self.key, high=False) + "~"
        compact = _es256_key_binding(issued, holder_key, high=True)
        bundle = _bundle_with(compact, self.pub_b64)
        self.assertEqual(bundle["sd_jwt_vc"]["compact"], compact)
        self.assertEqual(_compact_in_token(receipt_token(bundle)), compact)
        self.assertEqual(verify_receipt_token(receipt_token(bundle))[1]["sd_jwt_vc"]["compact"], compact)


class TwinsHaveOneIdentity(unittest.TestCase):
    """Owner decision, point 3: the E-1 sweep of D1, every identity site for a bundle and its twin, in
    the issuer slot and in the KB-JWT slot. RED on f536af50 except the ``verify --json`` case:
    ``receipt_token_identity`` did not exist, and a KB-JWT twin had a second receipt root. RED on
    126ed1dc in every case."""

    def setUp(self):
        try:
            import rfc8785  # noqa: F401,PLC0415
        except ImportError:   # pragma: no cover - a core dependency since 3.6.1
            self.skipTest("rfc8785 not installed")
        self.key, self.pub, self.pub_b64 = _p256()

    def _pairs(self):
        """(label, bundle, twin, verifies). A verifying pair per slot where one exists, and pairs whose
        bundles do not verify, because an identity does not depend on the verdict."""
        holder, cnf = _ed25519_holder()
        holder_key, _hpub, _hpub_b64 = _p256()
        issued = _issuer_jwt({"vct": VCT}, self.key, high=True) + "~"
        with_cnf = _issuer_jwt({"vct": VCT, "cnf": cnf}, self.key, high=True) + "~"
        kb_es256 = _es256_key_binding(_issuer_jwt({"vct": VCT}, self.key, high=False) + "~",
                                      holder_key, high=True)
        both = _es256_key_binding(issued, holder_key, high=True)
        cases = [
            ("issuer slot", issued, _twin(issued), True),
            ("issuer slot under an EdDSA KB-JWT", _eddsa_key_binding(with_cnf, holder),
             _twin(_eddsa_key_binding(with_cnf, holder)), True),
            ("KB-JWT slot", kb_es256, _kb_twin(kb_es256), False),
            ("both slots", both, _kb_twin(_twin(both)), False),
        ]
        for label, compact, twin, verifies in cases:
            bundle = _carrying(compact, self.pub_b64)
            yield label, bundle, _with_compact(bundle, twin), verifies

    def test_the_receipt_root_is_one(self):
        from proofbundle.anchors import receipt_canonical_root  # noqa: PLC0415
        for label, bundle, twin, _verifies in self._pairs():
            self.assertNotEqual(bundle, twin, label)
            self.assertEqual(receipt_canonical_root(bundle), receipt_canonical_root(twin), label)

    def test_a_token_and_its_twin_are_two_strings_with_one_identity(self):
        from proofbundle.hf_evals import receipt_token_identity  # noqa: PLC0415 - red on f536af50
        for label, bundle, twin, verifies in self._pairs():
            token, twin_token = receipt_token(bundle), receipt_token(twin)
            self.assertNotEqual(token, twin_token, f"{label}: the cost, stated in the CHANGELOG")
            self.assertEqual(receipt_token_identity(token), receipt_token_identity(twin_token), label)
            self.assertEqual(verify_receipt_token(token)[0].ok, verifies, label)
            self.assertEqual(verify_receipt_token(twin_token)[0].ok, verifies, label)

    def test_the_identity_of_a_token_is_the_receipt_root_the_docs_define(self):
        """F4: docs/ANCHORS.md read literally. RED on f536af50, where ``receipt_token_identity`` did
        not exist and the root left the KB-JWT slot unfolded (the anchor case below shows it)."""
        from proofbundle.hf_evals import receipt_token_identity  # noqa: PLC0415 - red on f536af50
        from proofbundle.anchors import receipt_canonical_root  # noqa: PLC0415
        for label, bundle, twin, _verifies in self._pairs():
            for spelling in (bundle, twin):
                self.assertEqual(receipt_canonical_root(spelling), _root_per_docs(spelling), label)
                self.assertEqual(receipt_token_identity(receipt_token(spelling)), _root_per_docs(spelling),
                                 label)
            anchored = dict(bundle, anchors=[{"type": "x/v1", "target": "receipt",
                                              "canonicalRoot": "AAAA", "proof": "AAAA"}])
            self.assertEqual(receipt_token_identity(receipt_token(anchored)), _root_per_docs(bundle),
                             f"{label}: anchors are detached evidence and do not enter the identity")

    def test_the_docs_fold_no_wider_domain_than_the_code(self):
        """Lens run 2 at accd932c, E2-2: the docs recipe of that commit folded any header that decodes
        to ``"alg": "ES256"``, the code only what its strict decoders accept. For an issuer JWT with a
        padded header segment or a duplicate key, the twins got one root by the docs and two in code.
        Both forms fail verification, and no issuer emits them; the fix narrows the TEXT to the
        code's domain and leaves the code's fold as it was. So this case is GREEN on accd932c (the
        code already behaved) and pins that code and text now agree on both edge forms; the text
        itself is checked by ``test_the_docs_name_the_domain_of_the_fold``."""
        from proofbundle.anchors import receipt_canonical_root  # noqa: PLC0415

        def signed(header_segment: str) -> str:
            body = _b64u(json.dumps({"vct": VCT}).encode())
            r, s = decode_dss_signature(self.key.sign(f"{header_segment}.{body}".encode(),
                                                      ec.ECDSA(hashes.SHA256())))
            s = s if s > N // 2 else N - s
            return f"{header_segment}.{body}.{_b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}~"

        padded = base64.urlsafe_b64encode(b'{"alg":"ES256" }').decode("ascii")
        self.assertTrue(padded.endswith("=="))
        edge_forms = {"padded header segment": signed(padded),
                      "duplicate key in the header": signed(_b64u(b'{"alg":"ES256","alg":"ES256"}'))}
        for label, compact in edge_forms.items():
            bundle = _carrying(compact, self.pub_b64)
            twin = _with_compact(bundle, _twin(compact))
            self.assertFalse(verify_bundle(bundle).ok, label)
            self.assertFalse(verify_bundle(twin).ok, label)
            for spelling in (bundle, twin):
                self.assertEqual(receipt_canonical_root(spelling), _root_per_docs(spelling), label)
            self.assertNotEqual(receipt_canonical_root(bundle), receipt_canonical_root(twin),
                                f"{label}: not folded, by the code and by the text")

    def test_the_docs_name_the_domain_of_the_fold(self):
        """RED on the docs/ANCHORS.md of accd932c, which named neither condition (measured by running
        ``_docs_name_the_fold_domain`` on that text)."""
        text = (SRC.parents[1] / "docs" / "ANCHORS.md").read_text(encoding="utf-8")
        self.assertEqual(_docs_name_the_fold_domain(text), [])

    def test_an_anchor_stamped_per_the_docs_covers_both_spellings(self):
        """F4, end to end: an anchor whose canonicalRoot a third party computed from docs/ANCHORS.md
        satisfies --require-anchor for both spellings. RED on f536af50 at the first KB-JWT-slot case
        and RED on 126ed1dc at the first case, the issuer slot."""
        from proofbundle import anchors  # noqa: PLC0415
        from proofbundle.cli import _evaluate_anchor_requirement  # noqa: PLC0415
        type_name = "d1-test-echo/v1"

        def echo(proof, canonical_root, *, frozen, now):
            ok = proof == canonical_root
            return {"ok": ok, "detail": "echo" if ok else "echo mismatch"}
        anchors.register_anchor_type(type_name, echo)
        self.addCleanup(anchors._VERIFIERS.pop, type_name, None)
        for label, bundle, twin, _verifies in self._pairs():
            root = base64.b64encode(_root_per_docs(bundle)).decode("ascii")
            entry = {"type": type_name, "target": "receipt", "canonicalRoot": root, "proof": root}
            for spelling in (bundle, twin):
                verdict = _evaluate_anchor_requirement(dict(spelling, anchors=[entry]), require=type_name,
                                                       allow_pending=False)
                self.assertTrue(verdict["ok"], f"{label}: {verdict}")

    def test_the_cli_hf_token_prints_two_strings_with_one_identity(self):
        from proofbundle.hf_evals import receipt_token_identity  # noqa: PLC0415 - red on f536af50
        for label, bundle, twin, _verifies in self._pairs():
            with tempfile.TemporaryDirectory() as tmp:
                printed = []
                for name, spelling in (("b.json", bundle), ("t.json", twin)):
                    path = os.path.join(tmp, name)
                    with open(path, "w", encoding="utf-8") as handle:
                        json.dump(spelling, handle)
                    rc, out = _cli(["hf-token", path])
                    self.assertEqual(rc, 0, label)
                    printed.append(out.strip())
                    self.assertEqual(_compact_in_token(out.strip()), spelling["sd_jwt_vc"]["compact"], label)
            self.assertNotEqual(printed[0], printed[1], label)
            self.assertEqual(receipt_token_identity(printed[0]), receipt_token_identity(printed[1]), label)

    def test_verify_json_reports_one_verdict_for_both_spellings(self):
        """GREEN on f536af50: no field of ``verify --json`` carries signature bytes, and this is a guard
        that none starts to. RED on 126ed1dc, where the twin of a presentation with an EdDSA KB-JWT
        failed the sd_hash check and so got another verdict."""
        for label, bundle, twin, verifies in self._pairs():
            with tempfile.TemporaryDirectory() as tmp:
                outputs = []
                for name, spelling in (("b.json", bundle), ("t.json", twin)):
                    path = os.path.join(tmp, name)
                    with open(path, "w", encoding="utf-8") as handle:
                        json.dump(spelling, handle)
                    rc, out = _cli(["verify", "--json", path])
                    self.assertEqual(rc, 0 if verifies else 1, label)
                    outputs.append(json.loads(out))
            self.assertEqual(outputs[0], outputs[1], label)

    def test_an_eval_results_entry_and_its_verdict_have_one_identity(self):
        from proofbundle.hf_evals import (  # noqa: PLC0415
            eval_results_yaml, receipt_token_identity, to_eval_results_entry, verify_eval_results_entry)
        for label, bundle, twin, verifies in self._pairs():
            entries = [to_eval_results_entry(spelling, dataset_id="d", task_id="t", value=1,
                                             require_verified=verifies) for spelling in (bundle, twin)]
            tokens = [entry.pop("verifyToken") for entry in entries]
            self.assertEqual(entries[0], entries[1], f"{label}: the entries differ in verifyToken only")
            self.assertEqual(receipt_token_identity(tokens[0]), receipt_token_identity(tokens[1]), label)
            for entry, token in zip(entries, tokens):
                entry["verifyToken"] = token
            self.assertNotEqual(eval_results_yaml(entries[:1]), eval_results_yaml(entries[1:]), label)
            self.assertEqual(verify_eval_results_entry(entries[0]), verify_eval_results_entry(entries[1]),
                             label)
            self.assertEqual(verify_eval_results_entry(entries[0])["crypto_ok"], verifies, label)

    def test_the_identity_form_folds_both_slots_and_nothing_else(self):
        """RED on f536af50 in the KB-JWT slot; the issuer slot was folded there already."""
        from proofbundle.sdjwt import canonical_sd_jwt_compact  # noqa: PLC0415
        holder_key, _hpub, _hpub_b64 = _p256()
        issued = _issuer_jwt({"vct": VCT}, self.key, high=True) + "~"
        compact = _es256_key_binding(issued, holder_key, high=True)
        spellings = [compact, _twin(compact), _kb_twin(compact), _twin(_kb_twin(compact))]
        forms = {canonical_sd_jwt_compact(s) for s in spellings}
        self.assertEqual(len(forms), 1, "four spellings, one identity form")
        form = forms.pop()
        self.assertLessEqual(_issuer_s(form), N // 2)
        self.assertLessEqual(_s_of(form.split("~")[-1]), N // 2)
        # only the two signature segments may differ from the presented bytes
        for mine, theirs in zip(form.split("~"), compact.split("~")):
            self.assertEqual(mine.split(".")[:2], theirs.split(".")[:2])
        low = canonical_sd_jwt_compact(compact)
        self.assertIs(canonical_sd_jwt_compact(low), low, "a form already low comes back as it is")


class OwnSignaturesHaveOneSpelling(unittest.TestCase):
    """Owner decision, point 4: a low s is required of the signatures proofbundle makes itself.
    proofbundle makes no ES256 signature (the inventory below keeps that true); the signatures it
    makes on the D1 surfaces are EdDSA: the bundle's own ``signature.sig_b64`` (``emit_bundle``), the
    issuer JWT of ``issue_sd_jwt`` and the KB-JWT of ``present_with_key_binding``. A pb1 token carries
    no signature of its own. Each signature is checked by the rule for the alg it declares: ES256
    must carry s <= n / 2, EdDSA must carry S < L, which leaves it one spelling. An alg without a rule
    here fails, so a new signing path is noticed. GREEN on f536af50 and on 126ed1dc: a guard."""

    ROUNDS = 64

    def _assert_one_spelling(self, alg: str, sig: bytes, where: str):
        self.assertEqual(len(sig), 64, where)
        if alg == "ES256":
            self.assertLessEqual(int.from_bytes(sig[32:], "big"), N // 2, where)
        elif alg in ("EdDSA", "ed25519"):
            self.assertLess(int.from_bytes(sig[32:], "little"), L, where)
        else:   # pragma: no cover - a new alg needs its own rule before it ships
            self.fail(f"{where}: no one-spelling rule for alg {alg!r}")

    def test_every_signature_proofbundle_makes_has_one_spelling(self):
        from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint  # noqa: PLC0415
        from proofbundle.sdjwt_issue import issue_sd_jwt  # noqa: PLC0415
        key, _pub, pub_b64 = _p256()
        holder, cnf = _ed25519_holder()
        halves = {"low": 0, "high": 0}
        for i in range(self.ROUNDS):
            foreign = _issuer_jwt({"vct": VCT, "cnf": cnf, "i": i}, key) + "~"
            halves["high" if _issuer_s(foreign) > N // 2 else "low"] += 1
            bundle = emit_bundle(b'{"i": %d}' % i, generate_signer(),
                                 sd_jwt_vc={"compact": foreign, "issuer_public_key_b64": pub_b64})
            self._assert_one_spelling(bundle["signature"]["alg"],
                                      base64.b64decode(bundle["signature"]["sig_b64"]), f"round {i}: bundle")
            presentation = present_with_key_binding(foreign, holder, aud="rp", nonce=str(i), iat=i)
            kb = presentation.rsplit("~", 1)[1]
            self._assert_one_spelling(json.loads(_unb64u(kb.split(".")[0]))["alg"],
                                      _unb64u(kb.split(".")[2]), f"round {i}: KB-JWT")
            signer = generate_signer()
            claim, _salts = build_eval_claim(
                suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
                score="0.9", n=10, model_id="m", dataset_id="d", issuer=issuer_fingerprint(signer),
                timestamp="2026-07-02T00:00:00Z")
            issued = issue_sd_jwt(claim, signer, root_b64=bundle["merkle"]["root_b64"], exact_score="0.9")
            jwt = issued.split("~", 1)[0]
            self._assert_one_spelling(json.loads(_unb64u(jwt.split(".")[0]))["alg"],
                                      _unb64u(jwt.split(".")[2]), f"round {i}: issued SD-JWT")
        # both halves of the FOREIGN s occurred, and none of them changed what proofbundle signs
        self.assertGreater(halves["low"], 0, halves)
        self.assertGreater(halves["high"], 0, halves)

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


class TheKeyBindingBindsThePresentationNotTheSpelling(unittest.TestCase):
    """From the first decision, unchanged: a relay can flip the issuer s of a genuine presentation,
    and ``verify_key_binding`` accepts the sd_hash over either spelling of the issuer JWT. RED on
    126ed1dc, GREEN on f536af50."""

    def setUp(self):
        self.key, self.pub, self.pub_b64 = _p256()
        self.holder, cnf = _ed25519_holder()
        self.payload = {"vct": VCT, "cnf": cnf}

    def test_a_holder_that_hashed_either_spelling_verifies_in_both(self):
        for high in (False, True):
            presentation = _eddsa_key_binding(_issuer_jwt(self.payload, self.key, high=high) + "~",
                                              self.holder)
            for spelling in (presentation, _twin(presentation)):
                res = verify_key_binding(spelling, expected_aud="rp", expected_nonce="n1")
                self.assertTrue(res["ok"], res["detail"])
                bundle = _bundle_with(spelling, self.pub_b64)
                self.assertTrue(verify_bundle(bundle, expected_aud="rp", expected_nonce="n1").ok)

    def test_the_other_spelling_widens_nothing_else(self):
        """GREEN on 126ed1dc as well: a dropped disclosure, a foreign KB-JWT or a wrong nonce still
        fail in either spelling. The comparison accepts the second spelling of the issuer signature
        and nothing more."""
        disclosure = _b64u(json.dumps(["salt", "given_name", "Erika"]).encode())
        digest = _b64u(hashlib.sha256(disclosure.encode("ascii")).digest())
        payload = dict(self.payload, _sd=[digest], _sd_alg="sha-256")
        compact = _issuer_jwt(payload, self.key, high=True) + "~" + disclosure + "~"
        presentation = _eddsa_key_binding(compact, self.holder)
        kb = presentation[len(compact):]
        without_disclosure = compact.split("~", 1)[0] + "~"
        other_holder, _ = _ed25519_holder()
        foreign = _eddsa_key_binding(compact, other_holder)
        for spelling in (presentation, _twin(presentation)):
            self.assertFalse(verify_key_binding(spelling, expected_aud="rp", expected_nonce="n2")["ok"])
        for spelling in (without_disclosure, _twin(without_disclosure)):
            self.assertFalse(verify_key_binding(spelling + kb, expected_aud="rp", expected_nonce="n1")["ok"])
        for spelling in (foreign, _twin(foreign)):
            self.assertFalse(verify_key_binding(spelling, expected_aud="rp", expected_nonce="n1")["ok"])


if __name__ == "__main__":
    unittest.main()
