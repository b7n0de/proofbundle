"""The producer side of scitt-ccf/v1: a SCITT Signed Statement over a proofbundle receipt.

Owner order of 2026-09-27 (6.4.0 producer, part 1), with the header rules made precise the same day:
the statement is a COSE_Sign1 (RFC 9052) and an RFC 9995 COSE Hash Envelope whose payload is the
receipt's anchor root, the RFC 8785 SHA-256 of the bundle without its ``anchors`` (the root a
``receipt`` anchor stamps). 258 = -16 (SHA-256), 259 = the media type of that preimage, 260 only when
the caller supplies a location; all three only in the protected header. CWT Claims (RFC 9597) exactly
once and protected, with ``iss`` and ``sub`` (RFC 9943 section 6). Content type (label 3) in neither
bucket. The unprotected header is empty, no label stands in both buckets, and the encoding is
deterministic (RFC 8949 section 4.2.1).

Owner decision B: EdDSA (-8) with a protected ``kid`` is the default and the key of the receipt world.

Every expectation here is read back with cbor2 and with the scitt-ccf/v1 reader, never with the
producer's own encoder.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("cbor2") is None or importlib.util.find_spec("rfc8785") is None,
    reason="the producer needs the [scitt] extra (cbor2) and the RFC 8785 canonicalizer")

REPO = Path(__file__).resolve().parents[1]
BUNDLE = REPO / "examples" / "example_bundle.json"
ISSUER = "https://issuer.example"
SUBJECT = "pkg:generic/example-eval@1"


def _p():
    from proofbundle import scitt_statement  # noqa: PLC0415
    return scitt_statement


def _bundle() -> dict:
    return json.loads(BUNDLE.read_text(encoding="utf-8"))


def _signer():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def _spki(key) -> bytes:
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    return key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def _root(bundle: dict) -> bytes:
    from proofbundle.anchors import receipt_canonical_root  # noqa: PLC0415
    return receipt_canonical_root({k: v for k, v in bundle.items() if k != "anchors"})


def _read(data: bytes):
    import cbor2  # noqa: PLC0415
    outer = cbor2.loads(data)
    assert isinstance(outer, cbor2.CBORTag) and outer.tag == 18
    prot_raw, unprot, payload, sig = outer.value
    return prot_raw, cbor2.loads(prot_raw), unprot, payload, sig


def _sign(**kw):
    kw.setdefault("issuer", ISSUER)
    kw.setdefault("subject", SUBJECT)
    return _p().sign_statement(_bundle(), _signer(), **kw)


# ------------------------------------------------------------------------------------------------
# Part 1: what sign_statement writes
# ------------------------------------------------------------------------------------------------
class TestTheSignedStatement:
    def test_a_tagged_hash_envelope_over_the_receipt_root(self):
        data = _sign()
        _prot_raw, prot, unprot, payload, _sig = _read(data)
        assert payload == _root(_bundle())
        assert prot[1] == -8
        assert prot[258] == -16
        assert prot[259] == "application/json"
        assert 260 not in prot
        assert dict(prot[15]) == {1: ISSUER, 2: SUBJECT}
        assert dict(unprot) == {}

    def test_the_kid_is_protected_and_by_default_the_hex_sha256_of_the_spki(self):
        _prot_raw, prot, _unprot, _payload, _sig = _read(_sign())
        assert prot[4] == hashlib.sha256(_spki(_signer())).hexdigest().encode("ascii")
        _prot_raw, prot, _unprot, _payload, _sig = _read(_sign(kid=b"issuer-key-1"))
        assert prot[4] == b"issuer-key-1"

    def test_exactly_these_labels_are_protected(self):
        _prot_raw, prot, _u, _p2, _s = _read(_sign())
        assert sorted(prot) == [1, 4, 15, 258, 259]
        _prot_raw, prot, _u, _p2, _s = _read(_sign(location="https://example.org/receipt.json"))
        assert sorted(prot) == [1, 4, 15, 258, 259, 260]
        assert prot[260] == "https://example.org/receipt.json"

    def test_the_encoding_is_deterministic_and_equals_the_canonical_reencoding(self):
        import cbor2  # noqa: PLC0415
        first, second = _sign(), _sign()
        assert first == second                     # Ed25519 is deterministic, and so is the encoding
        prot_raw, prot, unprot, payload, sig = _read(first)
        assert prot_raw == cbor2.dumps(prot, canonical=True)
        assert first == cbor2.dumps(cbor2.CBORTag(18, [prot_raw, {}, payload, sig]), canonical=True)
        assert first[:2] == b"\xd2\x84"            # tag 18, a definite array of four

    def test_the_signature_verifies_over_the_rfc9052_tobesigned(self):
        import cbor2  # noqa: PLC0415
        prot_raw, _prot, _unprot, payload, sig = _read(_sign())
        tbs = cbor2.dumps(["Signature1", prot_raw, b"", payload])
        _signer().public_key().verify(sig, tbs)    # raises InvalidSignature on failure

    def test_the_reader_decodes_it_with_no_label_in_both_buckets(self):
        from proofbundle import scitt_ccf  # noqa: PLC0415
        st = scitt_ccf.decode_cose_sign1(_sign(), role="statement")
        assert st.tagged and st.unprotected == {} and st.payload == _root(_bundle())

    def test_anchors_on_the_bundle_do_not_change_the_payload(self):
        bundle = _bundle()
        with_anchor = copy.deepcopy(bundle)
        with_anchor["anchors"] = [{"type": "x", "target": "receipt", "canonicalRoot": "AA==", "proof": "AA=="}]
        a = _p().sign_statement(bundle, _signer(), issuer=ISSUER, subject=SUBJECT)
        b = _p().sign_statement(with_anchor, _signer(), issuer=ISSUER, subject=SUBJECT)
        assert _read(a)[3] == _read(b)[3] == _root(bundle)

    @pytest.mark.parametrize("change", [
        {"issuer": ""}, {"issuer": None}, {"issuer": b"iss"}, {"subject": ""}, {"subject": 7},
        {"kid": ""}, {"kid": b""}, {"kid": "text"}, {"location": ""}, {"location": b"url"},
    ])
    def test_it_refuses_a_value_it_cannot_write_honestly(self, change):
        with pytest.raises(_p().ScittStatementError):
            _sign(**change)

    @pytest.mark.parametrize("signer", [None, b"\x00" * 32, "key", 1])
    def test_it_refuses_a_signer_that_is_not_a_key(self, signer):
        with pytest.raises(_p().ScittStatementError):
            _p().sign_statement(_bundle(), signer, issuer=ISSUER, subject=SUBJECT)

    @pytest.mark.parametrize("bundle", [None, [], "bundle", {"a": float("nan")}])
    def test_it_refuses_a_bundle_without_a_receipt_root(self, bundle):
        with pytest.raises(_p().ScittStatementError):
            _p().sign_statement(bundle, _signer(), issuer=ISSUER, subject=SUBJECT)


# ------------------------------------------------------------------------------------------------
# Part 1: the command, `proofbundle scitt sign`
# ------------------------------------------------------------------------------------------------
def _cli(argv) -> "tuple[int, str, str]":
    import contextlib  # noqa: PLC0415
    import io  # noqa: PLC0415

    from proofbundle.cli import main  # noqa: PLC0415
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = main(argv)
        except SystemExit as exc:
            rc = exc.code
    return rc, out.getvalue(), err.getvalue()


class TestTheSignCommand:
    def _seed(self, tmp_path) -> Path:
        path = tmp_path / "seed.key"
        path.write_bytes(bytes(range(32)))
        return path

    def test_it_writes_what_the_library_call_writes(self, tmp_path):
        out, pub = tmp_path / "statement.cose", tmp_path / "statement.pub.pem"
        rc, stdout, _err = _cli(["scitt", "sign", str(BUNDLE), "--out", str(out), "--issuer", ISSUER,
                                 "--subject", SUBJECT, "--key", str(self._seed(tmp_path)),
                                 "--public-key-out", str(pub)])
        assert rc == 0, stdout
        assert out.read_bytes() == _sign()
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
        assert serialization.load_pem_public_key(pub.read_bytes()).public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == _spki(_signer())
        assert "kid" in stdout and hashlib.sha256(_spki(_signer())).hexdigest() in stdout

    def test_kid_and_location_reach_the_protected_header(self, tmp_path):
        out = tmp_path / "statement.cose"
        rc, _o, _e = _cli(["scitt", "sign", str(BUNDLE), "--out", str(out), "--issuer", ISSUER,
                           "--subject", SUBJECT, "--key", str(self._seed(tmp_path)), "--kid", "issuer-key-1",
                           "--location", "https://example.org/r.json"])
        assert rc == 0
        assert out.read_bytes() == _sign(kid=b"issuer-key-1", location="https://example.org/r.json")

    @pytest.mark.parametrize("missing", ["--issuer", "--subject"])
    def test_issuer_and_subject_are_required(self, tmp_path, missing):
        argv = ["scitt", "sign", str(BUNDLE), "--out", str(tmp_path / "s.cose"), "--issuer", ISSUER,
                "--subject", SUBJECT, "--key", str(self._seed(tmp_path))]
        i = argv.index(missing)
        del argv[i:i + 2]
        rc, _o, err = _cli(argv)
        assert rc == 2
        assert f"the following arguments are required: {missing}" in err
        assert not (tmp_path / "s.cose").exists()

    def test_a_bundle_that_does_not_verify_is_not_signed(self, tmp_path):
        bundle = _bundle()
        import base64  # noqa: PLC0415
        sig = bytearray(base64.b64decode(bundle["signature"]["sig_b64"]))
        sig[0] ^= 1                                # a well-formed signature that fails
        bundle["signature"]["sig_b64"] = base64.b64encode(bytes(sig)).decode("ascii")
        src = tmp_path / "broken.json"
        src.write_text(json.dumps(bundle), encoding="utf-8")
        rc, _o, err = _cli(["scitt", "sign", str(src), "--out", str(tmp_path / "s.cose"), "--issuer", ISSUER,
                            "--subject", SUBJECT, "--key", str(self._seed(tmp_path))])
        assert rc == 1, err
        assert not (tmp_path / "s.cose").exists()

    def test_an_empty_issuer_is_refused_with_exit_2(self, tmp_path):
        rc, _o, err = _cli(["scitt", "sign", str(BUNDLE), "--out", str(tmp_path / "s.cose"), "--issuer", "",
                            "--subject", SUBJECT, "--key", str(self._seed(tmp_path))])
        assert rc == 2
        assert "issuer" in err and "invalid choice" not in err
        assert not (tmp_path / "s.cose").exists()
