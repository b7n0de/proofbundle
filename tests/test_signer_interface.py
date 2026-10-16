"""The signer interface (Z380): bytes in; signature, algorithm and key id out.

These cases need no optional extra. They pin four things:

* the file signer stays the default and signs exactly as the bare key does, so every receipt it makes is
  byte-identical to the receipt the key makes without the interface, and the verifier judges it as today;
* an external signer (the form a KMS adapter takes) is held to the one algorithm the verifier knows, and
  each signature it returns is checked against its public key before anything uses it;
* the RFC 7512 URI that selects a PKCS#11 key is read strictly: a duplicate, a malformed escape, an
  attribute the reader does not know, a PIN in the URI, a relative module path are each refused, and no
  refusal repeats a value of the URI;
* the command line takes ``--key-uri`` and ``--pin-env`` on every command that signs, refuses them in a
  combination that would be applied by nothing, and never echoes a PIN or a variable name.

The cases against a real token are in ``test_signer_pkcs11_softhsm.py``.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import cli
from proofbundle.emit import emit_bundle, load_signer, save_signer
from proofbundle.errors import ProofBundleError
from proofbundle.evalclaim import (CLAIM_VALID, build_eval_claim, classify_eval_claim, decode_eval_claim,
                                   emit_eval_receipt, issuer_fingerprint)
from proofbundle.signer import (SIGNER_ALGORITHMS, ExternalSigner, FileSigner, SignatureRecord, SignerError,
                                key_id_of, parse_pkcs11_uri, pin_from_env)
from proofbundle.signature import verify_ed25519


def _raw(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _claim():
    claim, _ = build_eval_claim(
        suite="s", suite_version="v1", metric="acc", comparator=">=", threshold="0.80", score="0.90",
        n=100, model_id="m", dataset_id="d", issuer="x", timestamp="2026-07-01T12:00:00Z",
        model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    return claim


class _Remote(ExternalSigner):
    """The shape a KMS adapter takes: the key lives elsewhere, the adapter returns its signature."""

    def __init__(self, key, *, answer=None, algorithm="ed25519"):
        super().__init__(_raw(key), algorithm=algorithm)
        self._key = key
        self._answer = answer
        self.calls = 0

    def _sign_external(self, data: bytes) -> bytes:
        self.calls += 1
        if self._answer is not None:
            return self._answer(data)
        return self._key.sign(data)


# ── the interface ─────────────────────────────────────────────────────────────────────────────────────

def test_the_verifier_knows_one_signature_algorithm():
    assert SIGNER_ALGORITHMS == ("ed25519",)


def test_sign_bytes_gives_signature_algorithm_and_key_id():
    key = Ed25519PrivateKey.generate()
    record = FileSigner(key).sign_bytes(b"payload")
    assert isinstance(record, SignatureRecord)
    assert record.signature == key.sign(b"payload")
    assert record.algorithm == "ed25519"
    assert record.key_id == issuer_fingerprint(key)
    assert record.key_id == "ed25519:" + base64.b64encode(_raw(key)).decode("ascii")


def test_key_id_is_the_issuer_form_of_the_receipt():
    key = Ed25519PrivateKey.generate()
    assert key_id_of(_raw(key)) == issuer_fingerprint(key)
    with pytest.raises(SignerError):
        key_id_of(b"\x00" * 31)


def test_sign_bytes_takes_bytes_like_values_and_refuses_text():
    key = Ed25519PrivateKey.generate()
    signer = FileSigner(key)
    assert signer.sign_bytes(bytearray(b"ab")).signature == key.sign(b"ab")
    assert signer.sign_bytes(memoryview(b"ab")).signature == key.sign(b"ab")
    with pytest.raises(SignerError):
        signer.sign_bytes("ab")


# ── the file signer stays the default and unchanged ───────────────────────────────────────────────────

def test_file_signer_receipt_is_byte_identical_to_the_bare_key_receipt():
    key = Ed25519PrivateKey.generate()
    claim = _claim()
    assert emit_eval_receipt(claim, FileSigner(key)) == emit_eval_receipt(claim, key)
    assert emit_bundle(b"abc", FileSigner(key)) == emit_bundle(b"abc", key)


def test_file_signer_loads_the_same_seed_file(tmp_path):
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "k.key"
    save_signer(key, str(path))
    assert FileSigner.load(str(path)).public_key_raw() == _raw(load_signer(str(path)))


def test_cli_key_file_path_still_passes_the_bare_key(monkeypatch, tmp_path):
    """`--key` hands the producer the key `load_signer` returns, as before: no wrapper in between."""
    key_path = tmp_path / "k.key"
    save_signer(Ed25519PrivateKey.generate(), str(key_path))
    seen = []
    real = cli.emit_bundle

    def spy(payload, signer, **kw):
        seen.append(type(signer))
        return real(payload, signer, **kw)

    monkeypatch.setattr(cli, "emit_bundle", spy)
    payload = tmp_path / "p.bin"
    payload.write_bytes(b"x")
    assert cli.main(["emit", "--payload-file", str(payload), "--out", str(tmp_path / "b.json"),
                     "--key", str(key_path)]) == 0
    assert len(seen) == 1 and issubclass(seen[0], Ed25519PrivateKey) and not issubclass(seen[0], FileSigner)


# ── the external signer (the KMS form) ────────────────────────────────────────────────────────────────

def test_external_signer_receipt_verifies_and_equals_the_file_receipt():
    key = Ed25519PrivateKey.generate()
    remote = _Remote(key)
    claim = _claim()
    bundle = emit_eval_receipt(claim, remote)
    assert bundle == emit_eval_receipt(claim, key)
    assert classify_eval_claim(bundle) == CLAIM_VALID
    assert decode_eval_claim(bundle)["issuer"] == remote.key_id


def test_external_signer_checks_every_signature_before_it_is_used():
    key, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    remote = _Remote(key, answer=other.sign)
    with pytest.raises(SignerError, match="does not verify"):
        remote.sign(b"payload")
    with pytest.raises(SignerError):
        emit_eval_receipt(_claim(), remote)


@pytest.mark.parametrize("answer", [lambda d: b"\x00" * 63, lambda d: "x" * 64, lambda d: None,
                                    lambda d: bytearray(64)])
def test_external_signer_refuses_a_signature_of_the_wrong_form(answer):
    remote = _Remote(Ed25519PrivateKey.generate(), answer=answer)
    with pytest.raises(SignerError):
        remote.sign(b"payload")


def test_external_signer_failure_is_a_signer_error_and_names_no_message():
    def boom(data):
        raise ConnectionError("secret-detail-from-the-provider")

    remote = _Remote(Ed25519PrivateKey.generate(), answer=boom)
    with pytest.raises(SignerError) as info:
        remote.sign(b"payload")
    assert "ConnectionError" in str(info.value)
    assert "secret-detail" not in str(info.value)


@pytest.mark.parametrize("algorithm", ["ecdsa-p256", "ed448", "rsa", "ED25519", ""])
def test_external_signer_refuses_an_algorithm_the_verifier_does_not_know(algorithm):
    with pytest.raises(SignerError, match="ed25519"):
        _Remote(Ed25519PrivateKey.generate(), algorithm=algorithm)


@pytest.mark.parametrize("weak", [b"\x01" + b"\x00" * 31, b"\x00" * 32, b"\xff" * 31 + b"\x7f", b"\x00" * 31])
def test_external_signer_refuses_a_public_key_nobody_holds_a_secret_for(weak):
    class _Weak(ExternalSigner):
        def _sign_external(self, data):
            return b"\x00" * 64

    with pytest.raises(SignerError):
        _Weak(weak)


def test_external_signer_without_an_implementation_cannot_sign():
    key = Ed25519PrivateKey.generate()
    with pytest.raises(SignerError):
        ExternalSigner(_raw(key)).sign(b"x")


def test_external_signer_is_a_proofbundle_error():
    assert issubclass(SignerError, ProofBundleError)


# ── the RFC 7512 URI ──────────────────────────────────────────────────────────────────────────────────

_MOD = "?module-path=/usr/lib/softhsm/libsofthsm2.so"


def test_uri_reads_the_rfc_examples():
    u = parse_pkcs11_uri("pkcs11:token=The%20Software%20PKCS%2311%20Softtoken;manufacturer=Snake%20Oil,%20Inc.;"
                         "model=1.0;object=my-certificate;type=cert;id=%69%95%3E%5C%F4%BD%EC%91;serial=")
    assert u.token == "The Software PKCS#11 Softtoken"
    assert u.manufacturer == "Snake Oil, Inc."
    assert u.model == "1.0"
    assert u.object == "my-certificate"
    assert u.type == "cert"
    assert u.id == bytes.fromhex("69953e5cf4bdec91")
    assert u.serial == ""
    u = parse_pkcs11_uri("pkcs11:token=My%20token%25%20created%20by%20Joe;library-version=3;"
                         "id=%01%02%03%Ba%dd%Ca%fe%04%05%06")
    assert u.token == "My token% created by Joe"
    assert u.library_version == (3, 0)
    assert u.id == bytes.fromhex("010203baddcafe040506")
    assert parse_pkcs11_uri("pkcs11:token=A%20name%20with%20a%20substring%20%25%3B;object=c;type=cert").token \
        == "A name with a substring %;"
    assert parse_pkcs11_uri("pkcs11:token=Name%20with%20a%20small%20A%20with%20acute:%20%C3%A1").token \
        == "Name with a small A with acute: á"
    u = parse_pkcs11_uri("pkcs11:object=my-sign-key;type=private?module-path=/mnt/libmypkcs11.so.1")
    assert u.module_path == "/mnt/libmypkcs11.so.1"
    assert u.token is None and u.id is None
    u = parse_pkcs11_uri("pkcs11:slot-id=7;slot-description=Sun%20Metaslot;library-version=1.23")
    assert (u.slot_id, u.slot_description, u.library_version) == (7, "Sun Metaslot", (1, 23))


def test_uri_empty_path_is_allowed():
    u = parse_pkcs11_uri("pkcs11:" + _MOD)
    assert u.token is None and u.object is None


def test_uri_empty_query_is_grammatical():
    """RFC 7512 2.3: ``pk11-query = [ pk11-qattr *("&" pk11-qattr) ]``, so a ``?`` with nothing after it is a URI;
    a trailing ``;`` or ``&`` is not."""
    assert parse_pkcs11_uri("pkcs11:token=x?").token == "x"


@pytest.mark.parametrize("uri", [
    "",
    "pkcs11",
    "file:token=x",
    " pkcs11:token=x",
    "pkcs11:token=x ",
    "pkcs11:token=a b",
    "pkcs11:token=x\n",
    "pkcs11:token=x#frag",
    "pkcs11:token=x;token=y",                     # duplicate path attribute (RFC 7512 2.3, MUST NOT)
    "pkcs11:token=x;;object=y",                   # empty attribute
    "pkcs11:token=x;",                            # trailing separator
    "pkcs11:token",                               # no value
    "pkcs11:=x",                                  # no name
    "pkcs11:token=%G1",                           # malformed escape
    "pkcs11:token=%4",
    "pkcs11:token=x%",
    "pkcs11:token=%FF",                           # not UTF-8
    "pkcs11:token=%C3",                           # truncated UTF-8
    "pkcs11:token=a/b",                           # '/' must be escaped in the path
    "pkcs11:token=a?b?c",                         # a second '?'
    "pkcs11:vendor-attr=x",                       # unknown path attribute: matches nothing
    "pkcs11:Token=x",                             # attribute names are case-sensitive
    "pkcs11:type=key",
    "pkcs11:library-version=1.2.3",
    "pkcs11:library-version=256",
    "pkcs11:library-version=",
    "pkcs11:slot-id=",
    "pkcs11:slot-id=-1",
    "pkcs11:slot-id=0x1",
    "pkcs11:token=x?pin-value=1234",              # never a PIN in the URI
    "pkcs11:token=x?pin-source=file:/etc/pin",    # never a PIN from a file
    "pkcs11:token=x?module-name=softhsm2",        # a name to search for: refused, give the path
    "pkcs11:token=x?module-path=libsofthsm2.so",  # relative module path (RFC 7512 2.4, SHOULD reject)
    "pkcs11:token=x?module-path=",
    "pkcs11:token=x?module-path=/a&module-path=/b",
    "pkcs11:token=x?vendor-q=1",                  # unknown query attribute: refused, not ignored
    "pkcs11:token=x?module-path=/a&",
    "pkcs11:token=x?module-path=/a%00b",          # NUL in a path
])
def test_uri_refuses_what_it_cannot_read_as_one_selection(uri):
    with pytest.raises(SignerError):
        parse_pkcs11_uri(uri)


@pytest.mark.parametrize("value", [1, None, b"pkcs11:token=x", ["pkcs11:"]])
def test_uri_must_be_text(value):
    with pytest.raises(SignerError):
        parse_pkcs11_uri(value)


def test_uri_scheme_is_case_insensitive_as_rfc3986_says():
    assert parse_pkcs11_uri("PKCS11:token=x").token == "x"


_MARKER = "Zq9Marker4711"


@pytest.mark.parametrize("uri", [
    f"pkcs11:token=x?pin-value={_MARKER}",
    f"pkcs11:token=x?pin-source=file:/{_MARKER}",
    f"pkcs11:token=x?pin-value={_MARKER}%G",
    f"pkcs11:token={_MARKER};token=y",
    f"pkcs11:{_MARKER}=1",
    f"pkcs11:token={_MARKER}%FF",
    f"pkcs11:token=x?module-path={_MARKER}",
    f"pkcs11:token=x?{_MARKER}=1",
    f"pkcs11:type={_MARKER}",
    f"pkcs11:token={_MARKER} ",
])
def test_no_refusal_repeats_a_value_of_the_uri(uri):
    with pytest.raises(SignerError) as info:
        parse_pkcs11_uri(uri)
    assert _MARKER not in str(info.value)


# ── the PIN ───────────────────────────────────────────────────────────────────────────────────────────

def test_pin_from_env_reads_the_named_variable(monkeypatch):
    monkeypatch.setenv("PB_TEST_PIN_X", "4711")
    assert pin_from_env("PB_TEST_PIN_X")() == "4711"


@pytest.mark.parametrize("name", ["1234", "", "A B", "PIN=1", "a-b", "ä"])
def test_pin_from_env_takes_a_name_and_never_shows_a_wrong_one(name):
    with pytest.raises(SignerError) as info:
        pin_from_env(name)
    assert (name not in str(info.value)) or name == ""


@pytest.mark.parametrize("value", [None, ""])
def test_pin_from_env_refuses_an_unset_or_empty_variable_without_naming_it(monkeypatch, value):
    name = "PB_" + _MARKER
    if value is None:
        monkeypatch.delenv(name, raising=False)
    else:
        monkeypatch.setenv(name, value)
    with pytest.raises(SignerError) as info:
        pin_from_env(name)()
    assert _MARKER not in str(info.value)


# ── the command line ──────────────────────────────────────────────────────────────────────────────────

def _signing_commands():
    """Every (sub)command whose parser takes --key: the commands that sign."""
    parser = cli.build_parser()
    found = []

    def walk(p, path):
        for action in p._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, sub in action.choices.items():
                    walk(sub, path + [name])
        if any("--key" in a.option_strings for a in p._actions):
            found.append((tuple(path), p))
    walk(parser, [])
    return found


def test_every_command_that_signs_takes_key_uri_and_pin_env():
    found = _signing_commands()
    assert len(found) >= 7
    for path, p in found:
        options = {o for a in p._actions for o in a.option_strings}
        assert {"--key", "--new-key", "--key-uri", "--pin-env"} <= options, path


def _emit_args(tmp_path, *extra):
    payload = tmp_path / "p.bin"
    payload.write_bytes(b"x")
    return ["emit", "--payload-file", str(payload), "--out", str(tmp_path / "b.json"), *extra]


@pytest.mark.parametrize("extra", [
    ["--key", "k", "--key-uri", "pkcs11:token=x" + _MOD],
    ["--new-key", "k", "--key-uri", "pkcs11:token=x" + _MOD],
    ["--pin-env", "PB_PIN"],
    ["--key", "k", "--pin-env", "PB_PIN"],
    ["--key-uri", ""],
])
def test_cli_refuses_a_key_uri_combination_that_would_be_applied_by_nothing(tmp_path, capsys, extra):
    assert cli.main(_emit_args(tmp_path, *extra)) == 2
    assert not (tmp_path / "b.json").exists()
    assert "Traceback" not in capsys.readouterr().err


def test_cli_key_uri_with_a_pin_in_it_is_refused_and_the_pin_not_shown(tmp_path, capsys):
    assert cli.main(_emit_args(tmp_path, "--key-uri", f"pkcs11:token=x?pin-value={_MARKER}" + "&module-path=/x",
                               "--pin-env", "PB_PIN")) == 2
    captured = capsys.readouterr()
    assert _MARKER not in captured.err and _MARKER not in captured.out
    assert not (tmp_path / "b.json").exists()


def test_cli_pin_env_given_a_pin_instead_of_a_name_does_not_show_it(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("PB_" + _MARKER, raising=False)
    for value in ("47114711", "PB_" + _MARKER):
        assert cli.main(_emit_args(tmp_path, "--key-uri", "pkcs11:token=x?module-path=/nonexistent/lib.so",
                                   "--pin-env", value)) == 2
        captured = capsys.readouterr()
        assert value not in captured.err and value not in captured.out


def test_cli_key_uri_without_the_extra_names_the_extra(tmp_path, capsys, monkeypatch):
    monkeypatch.setitem(sys.modules, "pkcs11", None)
    monkeypatch.setenv("PB_PIN", "1234")
    assert cli.main(_emit_args(tmp_path, "--key-uri", "pkcs11:token=x?module-path=/usr/lib/x.so",
                               "--pin-env", "PB_PIN")) == 2
    assert "proofbundle[pkcs11]" in capsys.readouterr().err


def test_cli_failing_token_never_falls_back_to_a_key_file(tmp_path, monkeypatch, capsys):
    def forbidden(*a, **kw):
        raise AssertionError("a key file was touched after the token failed")

    monkeypatch.setattr(cli, "load_signer", forbidden)
    monkeypatch.setattr(cli, "generate_signer", forbidden)
    monkeypatch.setattr(cli, "save_signer", forbidden)
    monkeypatch.setenv("PB_PIN", "1234")
    assert cli.main(_emit_args(tmp_path, "--key-uri", "pkcs11:token=x?module-path=/nonexistent/lib.so",
                               "--pin-env", "PB_PIN")) == 2
    assert not (tmp_path / "b.json").exists()
    assert "Traceback" not in capsys.readouterr().err


def test_cli_without_any_key_option_keeps_its_message(tmp_path, capsys):
    assert cli.main(_emit_args(tmp_path)) == 2
    assert "ERROR: provide --key <file> or --new-key <file>" in capsys.readouterr().err


def test_cli_key_and_new_key_keep_their_message(tmp_path, capsys):
    assert cli.main(_emit_args(tmp_path, "--key", "a", "--new-key", "b")) == 2
    assert "ERROR: use either --key or --new-key, not both" in capsys.readouterr().err


def test_signature_record_signature_verifies_under_its_key_id():
    key = Ed25519PrivateKey.generate()
    record = FileSigner(key).sign_bytes(b"m")
    raw = base64.b64decode(record.key_id.split(":", 1)[1])
    assert verify_ed25519(raw, record.signature, b"m")
    assert json.dumps({"alg": record.algorithm})  # a plain str, serialisable
