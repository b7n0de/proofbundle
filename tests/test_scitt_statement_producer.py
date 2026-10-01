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


# ------------------------------------------------------------------------------------------------
# Part 3: the producer's check of a Signed Statement, one change against the control per case
# ------------------------------------------------------------------------------------------------
def _parts(data: bytes) -> dict:
    prot_raw, prot, unprot, payload, sig = _read(data)
    return {"prot": dict(prot), "unprot": dict(unprot), "payload": payload, "sig": sig, "raw": prot_raw}


def _encode(prot, unprot, payload, sig=None, *, key=None, tag=True, prot_raw=None):
    """Re-encode a statement; a changed protected header is signed again with ``key``."""
    import cbor2  # noqa: PLC0415
    from proofbundle import scitt_ccf  # noqa: PLC0415
    raw = prot_raw if prot_raw is not None else cbor2.dumps(prot, canonical=True)
    if sig is None:
        sig = (key or _signer()).sign(scitt_ccf._sig_structure(raw, payload if payload is not None else b""))
    body = [raw, unprot, payload, sig]
    return cbor2.dumps(cbor2.CBORTag(18, body) if tag else body, canonical=True)


def _control() -> dict:
    return _parts(_sign())


def _check(data, keys="default", **kw):
    if keys == "default":
        keys = [_spki(_signer())]
    kw.setdefault("canonical_root", _root(_bundle()))
    return _p().check_signed_statement(data, statement_keys=keys, **kw)


def _moved(label, to_unprotected=True):
    c = _control()
    value = c["prot"].pop(label)
    if to_unprotected:
        c["unprot"][label] = value
    return _encode(c["prot"], c["unprot"], c["payload"])


def _with_prot(**changes):
    c = _control()
    for label, value in changes.items():
        label = int(label.lstrip("l").replace("m", "-"))
        if value is _DROP:
            c["prot"].pop(label, None)
        else:
            c["prot"][label] = value
    return _encode(c["prot"], c["unprot"], c["payload"])


_DROP = object()


class TestTheProducersCheck:
    def test_the_control_is_confirmed_and_not_registered(self):
        r = _check(_sign())
        assert (r.status, r.readable, r.signature_valid) == ("confirmed", True, True)
        assert r.registration == "not_registered"
        assert (r.alg, r.issuer, r.subject) == (-8, ISSUER, SUBJECT)
        assert r.kid == hashlib.sha256(_spki(_signer())).hexdigest().encode("ascii")

    def test_the_control_reencoded_by_the_test_is_the_control(self):
        c = _control()
        assert _encode(c["prot"], c["unprot"], c["payload"], c["sig"], prot_raw=c["raw"]) == _sign()

    @pytest.mark.parametrize("label", [258, 259, 15, 4])
    def test_a_label_moved_to_the_unprotected_header_is_refused(self, label):
        r = _check(_moved(label))
        assert r.status == "outside_profile", r.detail
        assert str(label) in r.detail and r.signature_valid is None

    def test_260_in_the_unprotected_header_is_refused(self):
        c = _control()
        c["unprot"][260] = "https://example.org/r.json"
        r = _check(_encode(c["prot"], c["unprot"], c["payload"], c["sig"], prot_raw=c["raw"]))
        assert r.status == "outside_profile" and "260" in r.detail

    @pytest.mark.parametrize("label", [258, 259, 15, 4])
    def test_a_label_in_both_buckets_is_malformed(self, label):
        c = _control()
        c["unprot"][label] = c["prot"][label]
        r = _check(_encode(c["prot"], c["unprot"], c["payload"], c["sig"], prot_raw=c["raw"]))
        assert r.status == "malformed" and not r.readable

    @pytest.mark.parametrize("label", [258, 15, 4])
    def test_a_required_protected_label_that_is_absent_is_refused(self, label):
        r = _check(_moved(label, to_unprotected=False))
        assert r.status == "outside_profile" and str(label) in r.detail

    def test_content_type_is_refused_in_either_bucket(self):
        assert _check(_with_prot(l3="application/json")).status == "outside_profile"
        c = _control()
        c["unprot"][3] = "application/json"
        r = _check(_encode(c["prot"], c["unprot"], c["payload"], c["sig"], prot_raw=c["raw"]))
        assert r.status == "outside_profile" and "label 3" in r.detail

    @pytest.mark.parametrize("claims", [{1: ISSUER}, {2: SUBJECT}, {1: "", 2: SUBJECT}, {1: ISSUER, 2: ""},
                                        {1: ISSUER, 2: 7}, {1: b"iss", 2: SUBJECT}, "claims", []])
    def test_cwt_claims_need_a_text_iss_and_sub(self, claims):
        r = _check(_with_prot(l15=claims))
        assert r.status == "outside_profile" and "15" in r.detail

    @pytest.mark.parametrize("value", [-7, -35, 99, "EdDSA", _DROP])
    def test_an_algorithm_other_than_eddsa_is_refused_here(self, value):
        assert _check(_with_prot(l1=value)).status in ("outside_profile", "malformed")

    @pytest.mark.parametrize("value", [-43, 0, "sha-256"])
    def test_258_other_than_sha256_is_refused(self, value):
        assert _check(_with_prot(l258=value)).status == "outside_profile"

    @pytest.mark.parametrize("value", [b"application/json", -1, ["a"]])
    def test_259_and_260_keep_their_rfc9995_types(self, value):
        assert _check(_with_prot(l259=value)).status == "outside_profile"
        assert _check(_with_prot(l260=value)).status == "outside_profile"

    def test_the_kid_is_a_non_empty_byte_string(self):
        assert _check(_with_prot(l4="text")).status == "outside_profile"
        assert _check(_with_prot(l4=b"")).status == "outside_profile"

    def test_crit_is_refused_in_the_unprotected_header_and_for_labels_not_processed(self):
        c = _control()
        c["unprot"][2] = [258]
        r = _check(_encode(c["prot"], c["unprot"], c["payload"], c["sig"], prot_raw=c["raw"]))
        assert r.status == "outside_profile"
        assert _check(_with_prot(l2=[15])).status == "outside_profile"
        assert _check(_with_prot(l2=[258])).status == "confirmed"

    @pytest.mark.parametrize("label", [99, 33, 5, "x"])
    def test_the_unprotected_header_carries_nothing_but_receipts(self, label):
        c = _control()
        c["unprot"][label] = b"\x00"
        r = _check(_encode(c["prot"], c["unprot"], c["payload"], c["sig"], prot_raw=c["raw"]))
        assert r.status == "outside_profile" and str(label) in r.detail

    def test_untagged_and_detached_are_refused(self):
        c = _control()
        assert _check(_encode(c["prot"], c["unprot"], c["payload"], c["sig"], prot_raw=c["raw"],
                              tag=False)).status == "outside_profile"
        assert _check(_encode(c["prot"], c["unprot"], None, c["sig"], prot_raw=c["raw"])).status == \
            "outside_profile"

    def test_a_payload_of_another_receipt_is_unbound(self):
        r = _check(_sign(), canonical_root=bytes(32))
        assert r.status == "unbound" and r.signature_valid is None
        assert _check(_sign(), canonical_root=b"short").status == "unbound"
        assert _check(_sign(), canonical_root=None).status == "unbound"

    def test_a_changed_signature_is_invalid(self):
        c = _control()
        sig = bytes([c["sig"][0] ^ 1]) + c["sig"][1:]
        r = _check(_encode(c["prot"], c["unprot"], c["payload"], sig, prot_raw=c["raw"]))
        assert (r.status, r.signature_valid) == ("statement_signature_invalid", False)

    def test_trust_comes_from_the_relying_party_and_the_kid_only_selects(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415
        other = _spki(Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))))
        kid = hashlib.sha256(_spki(_signer())).hexdigest().encode("ascii")
        assert _check(_sign(), keys=None).status == "needs_rp_trust"
        assert _check(_sign(), keys=[]).status == "needs_rp_trust"
        assert _check(_sign(), keys=[other]).status == "needs_rp_trust"      # its own kid differs
        r = _check(_sign(), keys=[{"spki": other, "kid": kid}])              # selected, and it fails
        assert (r.status, r.signature_valid) == ("statement_signature_invalid", False)
        assert _check(_sign(kid=b"k1"), keys=[{"spki": _spki(_signer()), "kid": b"k1"}]).status == "confirmed"
        assert _check(_sign(kid=b"k1")).status == "needs_rp_trust"

    def test_a_key_of_another_type_is_absent_trust(self):
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
        p256 = _spki(ec.generate_private_key(ec.SECP256R1()))
        kid = hashlib.sha256(_spki(_signer())).hexdigest().encode("ascii")
        r = _check(_sign(), keys=[{"spki": p256, "kid": kid}])
        assert r.status == "needs_rp_trust" and r.ignored_trust

    def test_a_low_order_relying_party_key_is_absent_trust(self):
        """The statement key is a trust anchor supplied from outside the statement, so it passes the
        house rule for trusted Ed25519 keys (signature.ed25519_trust_anchor_weakness): under the
        identity point the signature R = identity, S = 0 verifies for every message."""
        identity = bytes([1]) + bytes(31)
        spki = bytes.fromhex("302a300506032b6570032100") + identity
        c = _control()
        forged = _encode(c["prot"], c["unprot"], c["payload"], identity + bytes(32), prot_raw=c["raw"])
        kid = c["prot"][4]
        r = _check(forged, keys=[{"spki": spki, "kid": kid}])
        assert r.status == "needs_rp_trust" and r.signature_valid is None
        assert any("low-order" in why for why in r.ignored_trust)

    def test_a_duplicate_protected_key_is_malformed(self):
        c = _control()
        raw = c["raw"]
        # one more pair with label 258 at the end of the protected map: a5 -> a6, same key twice
        dup = bytes([raw[0] + 1]) + raw[1:] + bytes.fromhex("19010235")
        r = _check(_encode(None, {}, c["payload"], None, prot_raw=dup))
        assert r.status == "malformed"

    @pytest.mark.parametrize("data", [None, 1, "text", b"", b"\x00", b"\xd2\x84", bytes(100), [b"x"]])
    def test_it_never_raises(self, data):
        r = _p().check_signed_statement(data, canonical_root=bytes(32), statement_keys=[b"x"])
        assert r.status == "malformed" and not r.readable

    def test_a_receipt_under_394_makes_it_a_transparent_statement_evaluated_by_the_reader(self):
        c = _control()
        c["unprot"][394] = [b"\xd2\x84\x40\xa0\xf6\x40"]
        data = _encode(c["prot"], c["unprot"], c["payload"], c["sig"], prot_raw=c["raw"])
        r = _check(data)
        assert r.status == "confirmed"                  # the statement itself is unchanged
        assert r.registration == "not_evaluated"        # no service trust supplied
        r = _check(data, rp_trust={"scitt_ccf_services": {"service.example": [b"x"]}})
        assert r.registration != "not_registered" and r.registration != "confirmed"
        assert r.registration_detail


# ------------------------------------------------------------------------------------------------
# Part 3: `proofbundle verify --scitt-statement`, offline; missing registration is a named state
# ------------------------------------------------------------------------------------------------
class TestVerifyWithAStatement:
    def _files(self, tmp_path, data=None, key=True) -> list:
        st = tmp_path / "statement.cose"
        st.write_bytes(_sign() if data is None else data)
        argv = ["verify", str(BUNDLE), "--scitt-statement", str(st)]
        if key:
            from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
            pem = tmp_path / "statement.pub.pem"
            pem.write_bytes(_signer().public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            argv += ["--scitt-statement-key", str(pem)]
        return argv

    def test_a_confirmed_statement_that_is_not_registered_exits_0_and_says_so(self, tmp_path):
        rc, out, err = _cli(self._files(tmp_path))
        assert rc == 0, out + err
        assert "SCITT-STATEMENT: CONFIRMED" in out
        assert "SCITT-REGISTRATION: NOT_REGISTERED" in out

    def test_json_carries_the_statement_verdict(self, tmp_path):
        rc, out, _err = _cli(self._files(tmp_path) + ["--json"])
        assert rc == 0
        doc = json.loads(out)["scitt_statement"]
        assert (doc["status"], doc["registration"], doc["signature_valid"]) == \
            ("confirmed", "not_registered", True)

    def test_without_a_statement_key_it_is_a_trust_requirement_not_met(self, tmp_path):
        rc, out, _err = _cli(self._files(tmp_path, key=False))
        assert rc == 3
        assert "SCITT-STATEMENT: NEEDS_RP_TRUST" in out

    def test_a_changed_signature_fails(self, tmp_path):
        c = _control()
        sig = bytes([c["sig"][0] ^ 1]) + c["sig"][1:]
        rc, out, _err = _cli(self._files(tmp_path, _encode(c["prot"], c["unprot"], c["payload"], sig,
                                                           prot_raw=c["raw"])))
        assert rc == 1
        assert "SCITT-STATEMENT: STATEMENT_SIGNATURE_INVALID" in out

    def test_a_statement_over_another_receipt_fails(self, tmp_path):
        c = _control()
        payload = hashlib.sha256(b"another receipt").digest()
        rc, out, _err = _cli(self._files(tmp_path, _encode(c["prot"], c["unprot"], payload)))
        assert rc == 1
        assert "SCITT-STATEMENT: UNBOUND" in out

    def test_a_header_rule_violation_fails(self, tmp_path):
        rc, out, _err = _cli(self._files(tmp_path, _moved(258)))
        assert rc == 1
        assert "SCITT-STATEMENT: OUTSIDE_PROFILE" in out

    def test_a_custom_kid_is_paired_with_the_key_by_the_relying_party(self, tmp_path):
        argv = self._files(tmp_path, _sign(kid=b"issuer-key-1"))
        assert _cli(argv)[0] == 3
        rc, out, _err = _cli(argv + ["--scitt-statement-kid", "issuer-key-1"])
        assert rc == 0 and "SCITT-STATEMENT: CONFIRMED" in out

    def test_statement_flags_without_a_statement_are_refused(self, tmp_path):
        argv = self._files(tmp_path)
        i = argv.index("--scitt-statement")
        del argv[i:i + 2]
        rc, _out, err = _cli(argv)
        assert rc == 2 and "only apply together with --scitt-statement" in err

    def test_an_unreadable_statement_file_is_exit_2(self, tmp_path):
        argv = self._files(tmp_path)
        argv[argv.index("--scitt-statement") + 1] = str(tmp_path / "missing.cose")
        rc, _out, err = _cli(argv)
        assert rc == 2 and "missing.cose" in err and "unrecognized arguments" not in err

    def test_without_the_flag_the_output_is_unchanged(self, tmp_path):
        rc, out, _err = _cli(["verify", str(BUNDLE)])
        assert rc == 0 and "SCITT" not in out
        rc, out, _err = _cli(["verify", str(BUNDLE), "--json"])
        assert "scitt_statement" not in json.loads(out)

    def test_a_bundle_whose_crypto_fails_does_not_evaluate_the_statement(self, tmp_path):
        import base64  # noqa: PLC0415
        bundle = _bundle()
        sig = bytearray(base64.b64decode(bundle["signature"]["sig_b64"]))
        sig[0] ^= 1
        bundle["signature"]["sig_b64"] = base64.b64encode(bytes(sig)).decode("ascii")
        src = tmp_path / "broken.json"
        src.write_text(json.dumps(bundle), encoding="utf-8")
        argv = self._files(tmp_path)
        argv[1] = str(src)
        rc, out, _err = _cli(argv)
        assert rc == 1 and "SCITT-STATEMENT: NOT_EVALUATED" in out

    def test_a_statement_is_never_a_pass_of_a_required_anchor(self, tmp_path):
        rc, out, _err = _cli(self._files(tmp_path) + ["--require-anchor"])
        assert rc == 3
        assert "SCITT-STATEMENT: CONFIRMED" in out and "ANCHOR: REQUIRED_NOT_MET" in out


# ------------------------------------------------------------------------------------------------
# Owner decision B: ES256 with a protected x5chain, only for statements that must pass the v1 reader,
# register with scitt-ccf-ledger and cross-verify with scitt-verifier. Key and chain from the user.
# ------------------------------------------------------------------------------------------------
N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _p256_chain(curve=None, leaf_key=None):
    import datetime  # noqa: PLC0415

    from cryptography import x509  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
    from cryptography.x509.oid import NameOID  # noqa: PLC0415
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    key = leaf_key or ec.generate_private_key(curve or ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test CA")])

    def cert(subject, pub, ca):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name).public_key(pub)
                .serial_number(x509.random_serial_number()).not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                .sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
    ca_der = cert(ca_name, ca_key.public_key(), True)
    leaf_der = cert(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test leaf")]), key.public_key(), False)
    return key, [leaf_der, ca_der]


def _sign_es256(key=None, chain=None, **kw):
    if key is None:
        key, chain = _p256_chain()
    kw.setdefault("issuer", ISSUER)
    kw.setdefault("subject", SUBJECT)
    return _p().sign_statement(_bundle(), key, x5chain=chain, **kw), key, chain


class TestTheEs256Path:
    def test_a_protected_x5chain_and_no_kid(self):
        data, key, chain = _sign_es256()
        _raw, prot, unprot, payload, _sig = _read(data)
        assert sorted(prot) == [1, 15, 33, 258, 259]
        assert prot[1] == -7 and [bytes(c) for c in prot[33]] == chain
        assert dict(prot[15]) == {1: ISSUER, 2: SUBJECT} and dict(unprot) == {} and payload == _root(_bundle())

    def test_one_certificate_is_a_byte_string_as_rfc9360_requires(self):
        key, chain = _p256_chain()
        data, _k, _c = _sign_es256(key, chain[:1])
        assert _read(data)[1][33] == chain[0]

    def test_it_passes_the_v1_reader_under_the_leaf_key(self):
        from proofbundle import scitt_ccf  # noqa: PLC0415
        data, key, _chain = _sign_es256()
        assert scitt_ccf.verify_statement_signature(data, statement_keys=[_spki(key)]) == ("confirmed", True)
        assert scitt_ccf._statement_profile(scitt_ccf.decode_cose_sign1(data)) is None

    def test_the_producers_check_confirms_it_under_the_leaf_key_only(self):
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
        data, key, _chain = _sign_es256()
        assert _check(data, keys=[_spki(key)]).status == "confirmed"
        other = _spki(ec.generate_private_key(ec.SECP256R1()))
        assert _check(data, keys=[other]).status == "needs_rp_trust"
        assert _check(data, keys=[_spki(_signer())]).status == "needs_rp_trust"

    def test_the_signature_has_a_low_s_and_verifies(self):
        from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: PLC0415
        from proofbundle import scitt_ccf  # noqa: PLC0415
        key, chain = _p256_chain()
        for i in range(32):
            data, _k, _c = _sign_es256(key, chain, subject=f"s{i}")
            raw, _prot, _u, payload, sig = _read(data)
            assert len(sig) == 64 and int.from_bytes(sig[32:], "big") <= N_P256 // 2
            der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            key.public_key().verify(der, scitt_ccf._sig_structure(raw, payload), ec.ECDSA(hashes.SHA256()))

    def test_it_refuses_what_it_cannot_write_honestly(self):
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
        key, chain = _p256_chain()
        E = _p().ScittStatementError
        with pytest.raises(E):
            _p().sign_statement(_bundle(), key, issuer=ISSUER, subject=SUBJECT)              # no x5chain
        with pytest.raises(E):
            _sign_es256(ec.generate_private_key(ec.SECP256R1()), chain)                        # another leaf key
        with pytest.raises(E):
            _sign_es256(*_p256_chain(ec.SECP384R1()))                                          # not P-256
        with pytest.raises(E):
            _sign_es256(key, [b"not a certificate"])
        with pytest.raises(E):
            _sign_es256(key, [])
        with pytest.raises(E):
            _p().sign_statement(_bundle(), _signer(), issuer=ISSUER, subject=SUBJECT, x5chain=chain)  # EdDSA

    def test_the_command_signs_with_a_user_key_and_chain(self, tmp_path):
        from cryptography import x509  # noqa: PLC0415
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
        key, chain = _p256_chain()
        key_pem = tmp_path / "leaf.key.pem"
        key_pem.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        chain_pem = tmp_path / "chain.pem"
        chain_pem.write_bytes(b"".join(x509.load_der_x509_certificate(c).public_bytes(serialization.Encoding.PEM)
                                       for c in chain))
        out, pub = tmp_path / "s.cose", tmp_path / "leaf.pub.pem"
        rc, stdout, err = _cli(["scitt", "sign", str(BUNDLE), "--out", str(out), "--issuer", ISSUER,
                                "--subject", SUBJECT, "--ec-key", str(key_pem), "--x5chain", str(chain_pem),
                                "--public-key-out", str(pub)])
        assert rc == 0, stdout + err
        _raw, prot, _u, _p2, _s = _read(out.read_bytes())
        assert prot[1] == -7 and [bytes(c) for c in prot[33]] == chain
        rc, stdout, _e = _cli(["verify", str(BUNDLE), "--scitt-statement", str(out), "--scitt-statement-key", str(pub)])
        assert rc == 0 and "SCITT-STATEMENT: CONFIRMED" in stdout

    def test_the_command_refuses_two_kinds_of_key(self, tmp_path):
        rc, _o, err = _cli(["scitt", "sign", str(BUNDLE), "--out", str(tmp_path / "s.cose"), "--issuer", ISSUER,
                            "--subject", SUBJECT, "--key", "k", "--ec-key", "e", "--x5chain", "c"])
        assert rc == 2 and "not both" in err and "unrecognized" not in err
        assert not (tmp_path / "s.cose").exists()
