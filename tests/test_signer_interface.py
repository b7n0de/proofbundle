"""The signer interface (Z380): bytes in; signature, algorithm and key id out.

These cases need no optional extra. They pin four things:

* the file signer stays the default and signs exactly as the bare key does, so every receipt it makes is
  byte-identical to the receipt the key makes without the interface, and the verifier judges it as today;
* an external signer (the form a KMS adapter takes) is held to the one algorithm the verifier knows, and
  each signature it returns is checked against its public key before anything uses it;
* the RFC 7512 URI that selects a PKCS#11 key is read strictly: a duplicate, a malformed escape, an
  attribute the reader does not know, a PIN in the URI, a relative module path are each refused, and no
  refusal repeats a value of the URI;
* the command line takes ``--token-uri`` and ``--token-pin-env`` on every command that signs, refuses them in a
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
from proofbundle.signer import (SIGNER_ALGORITHMS, ExternalSigner, FileSigner, Pkcs11Signer, SignatureRecord,
                                SignerError, key_id_of, parse_pkcs11_uri, pin_from_env, pin_from_prompt)
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
    assert classify_eval_claim(bundle)[0] == CLAIM_VALID
    assert decode_eval_claim(bundle)["issuer"] == remote.key_id


def test_external_signer_checks_every_signature_before_it_is_used():
    key, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    remote = _Remote(key, answer=other.sign)
    with pytest.raises(SignerError, match="does not verify"):
        remote.sign(b"payload")
    with pytest.raises(SignerError):
        emit_eval_receipt(_claim(), remote)


@pytest.mark.parametrize("answer,reason", [(lambda d: b"\x00" * 63, "no 64-byte"), (lambda d: "x" * 64, "no 64-byte"),
                                           (lambda d: None, "no 64-byte"), (lambda d: bytearray(64), "does not verify")])
def test_external_signer_refuses_a_signature_of_the_wrong_form(answer, reason):
    remote = _Remote(Ed25519PrivateKey.generate(), answer=answer)
    with pytest.raises(SignerError, match=reason):
        remote.sign(b"payload")


def test_external_signer_failure_is_a_signer_error_and_names_no_message():
    def boom(data):
        raise ConnectionError("secret-detail-from-the-provider")

    remote = _Remote(Ed25519PrivateKey.generate(), answer=boom)
    with pytest.raises(SignerError) as info:
        remote.sign(b"payload")
    assert "ConnectionError" in str(info.value)
    assert "secret-detail" not in str(info.value)
    assert info.value.__context__ is None and info.value.__cause__ is None


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


@pytest.mark.parametrize("value", ["seed", b"\x00" * 32, None, Ed25519PrivateKey.generate().public_key()])
def test_file_signer_holds_only_an_ed25519_private_key(value):
    with pytest.raises(SignerError, match="Ed25519 private key"):
        FileSigner(value)


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
    # RFC 7512 section 3 spells this one as a token label, but it is 34 bytes and CK_TOKEN_INFO.label has 32:
    # section 2.3 says such a value MUST be refused, so the encoding is read here as an object label (CKA_LABEL
    # has no fixed size), and the token form is a refusal below.
    assert parse_pkcs11_uri("pkcs11:object=Name%20with%20a%20small%20A%20with%20acute:%20%C3%A1").object \
        == "Name with a small A with acute: á"
    with pytest.raises(SignerError, match="32-byte"):
        parse_pkcs11_uri("pkcs11:token=Name%20with%20a%20small%20A%20with%20acute:%20%C3%A1")
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


@pytest.mark.parametrize("uri,reason", [
    ("", "begins with 'pkcs11:'"),
    ("pkcs11", "begins with 'pkcs11:'"),
    ("file:token=x", "begins with 'pkcs11:'"),
    (" pkcs11:token=x", "begins with 'pkcs11:'"),
    ("pkcs11:token=x ", "must be percent-encoded"),
    ("pkcs11:token=a b", "must be percent-encoded"),
    ("pkcs11:token=x\n", "must be percent-encoded"),
    ("pkcs11:token=x#frag", "must be percent-encoded"),
    ("pkcs11:token=a/b", "must be percent-encoded"),                    # '/' must be escaped in the path
    ("pkcs11:token=x;token=y", "token twice"),                          # RFC 7512 2.3, MUST NOT
    ("pkcs11:token=x;;object=y", "attribute=value pair"),               # empty element
    ("pkcs11:token=x;", "attribute=value pair"),                        # trailing separator
    ("pkcs11:token", "attribute=value pair"),                           # no value
    ("pkcs11:=x", "attribute=value pair"),                              # no name
    ("pkcs11:token=a?b?c", "attribute=value pair"),                     # the query 'b?c' has no '='
    ("pkcs11:token=%G1", "malformed percent-encoding"),
    ("pkcs11:token=%4", "malformed percent-encoding"),
    ("pkcs11:token=x%", "malformed percent-encoding"),
    ("pkcs11:id=%ZZ", "malformed percent-encoding"),
    ("pkcs11:token=%FF", "not UTF-8"),
    ("pkcs11:token=%C3", "not UTF-8"),                                  # truncated UTF-8
    ("pkcs11:token=a%0Ab", "control character"),
    ("pkcs11:serial=%C3%A1", "printable ASCII"),
    ("pkcs11:vendor-attr=7", "does not know"),                          # unknown path attribute: matches nothing
    ("pkcs11:Token=x", "does not know"),                                # attribute names are case-sensitive
    ("pkcs11:type=key", "none of public"),
    ("pkcs11:library-version=1.2.3", "library-version is M or M.N"),
    ("pkcs11:library-version=256", "library-version is M or M.N"),
    ("pkcs11:library-version=", "library-version is M or M.N"),
    ("pkcs11:slot-id=", "slot-id is a decimal"),
    ("pkcs11:slot-id=-1", "slot-id is a decimal"),
    ("pkcs11:slot-id=0x1", "slot-id is a decimal"),
    ("pkcs11:slot-id=18446744073709551616", "slot-id is a decimal"),     # one more than a 64-bit CK_ULONG
    ("pkcs11:token=x?pin-value=1234", "a PIN never stands"),            # never a PIN in the URI
    ("pkcs11:token=x?pin-source=file:/etc/pin", "a PIN never stands"),  # never a PIN from a file
    ("pkcs11:token=x?module-name=softhsm2", "module-name is not taken"),
    ("pkcs11:token=x?module-path=libsofthsm2.so", "absolute path"),     # RFC 7512 2.4, SHOULD reject
    ("pkcs11:token=x?module-path=", "absolute path"),
    ("pkcs11:token=x?module-path=/a%00b", "absolute path"),             # NUL in a path
    ("pkcs11:token=x?module-path=/a%FF", "absolute path"),              # not UTF-8
    ("pkcs11:token=x?module-path=/a&module-path=/b", "module-path twice"),
    ("pkcs11:token=x?vendor-q=1", "does not know"),                     # unknown query attribute: refused
    ("pkcs11:token=x?module-path=/a&", "attribute=value pair"),
])
def test_uri_refuses_what_it_cannot_read_as_one_selection(uri, reason):
    with pytest.raises(SignerError, match=reason):
        parse_pkcs11_uri(uri)


@pytest.mark.parametrize("value", [1, None, b"pkcs11:token=x", ["pkcs11:"]])
def test_uri_must_be_text(value):
    with pytest.raises(SignerError):
        parse_pkcs11_uri(value)


def test_uri_scheme_is_case_insensitive_as_rfc3986_says():
    assert parse_pkcs11_uri("PKCS11:token=x").token == "x"


def test_uri_scheme_folds_its_ascii_letters_only():
    """`str.lower` folds U+212A KELVIN SIGN to "k", so "p\u212acs11:" passed as the scheme and signed end to end
    (lens run 1, F2). RFC 3986 3.1 folds the ASCII letters of a scheme only."""
    with pytest.raises(SignerError, match="begins with 'pkcs11:'"):
        parse_pkcs11_uri("p\u212acs11:token=x")


@pytest.mark.parametrize("uri,reason", [
    ("pkcs11:slot-id=" + "9" * 4301, "slot-id is a decimal"),
    ("pkcs11:slot-id=1" + "0" * 20, "slot-id is a decimal"),
    ("pkcs11:library-version=" + "9" * 4301, "library-version is M or M.N"),
    ("pkcs11:library-version=1." + "9" * 4301, "library-version is M or M.N"),
    ("pkcs11:library-version=1000", "library-version is M or M.N"),
    ("pkcs11:library-version=1.256", "library-version is M or M.N"),
])
def test_uri_numbers_of_any_length_are_refused_by_the_reader(uri, reason):
    """CPython refuses to convert more than 4300 digits with a raw ValueError, which `parse_pkcs11_uri` and
    `Pkcs11Signer.open` let out (lens run 1, F1). The reader counts the digits first; the refusal is its own."""
    with pytest.raises(SignerError, match=reason):
        parse_pkcs11_uri(uri)


def test_uri_numbers_keep_their_value_whatever_their_leading_zeros():
    """CPython counts leading zeros toward its 4300-digit limit too, so only the significant digits are read."""
    zeros = "0" * 5000
    u = parse_pkcs11_uri(f"pkcs11:slot-id={zeros}7;library-version={zeros}3.{zeros}1")
    assert (u.slot_id, u.library_version) == (7, (3, 1))
    assert parse_pkcs11_uri("pkcs11:slot-id=18446744073709551615;library-version=255.255").slot_id == (1 << 64) - 1
    assert parse_pkcs11_uri("pkcs11:slot-id=0").slot_id == 0


_TOKEN_FIELDS = ["token", "manufacturer", "model", "serial", "library-manufacturer", "library-description",
                 "slot-manufacturer", "slot-description"]


@pytest.mark.parametrize("attribute", _TOKEN_FIELDS)
@pytest.mark.parametrize("value", ["ab%EF%BF%BD", "x%20", "x%C2%A0", "x%E3%80%80"])
def test_uri_values_python_pkcs11_cannot_tell_apart_are_refused(attribute, value):
    """python-pkcs11 0.10.0 gives these fields with bytes that are not UTF-8 replaced by U+FFFD and all trailing
    whitespace removed (`types._CK_UTF8CHAR_to_str`), so `token=ab%EF%BF%BD` selected a token labelled
    b"ab\xff" (lens run 1, F3). A value with U+FFFD or with trailing whitespace is refused."""
    with pytest.raises(SignerError, match="U\\+FFFD or ends in whitespace"):
        parse_pkcs11_uri(f"pkcs11:{attribute}={value}")


def test_uri_object_is_compared_by_the_token_and_keeps_both():
    assert parse_pkcs11_uri("pkcs11:object=ab%EF%BF%BD%20").object == "ab\ufffd "
    assert parse_pkcs11_uri("pkcs11:token=a%20b").token == "a b"   # inner whitespace is spelled as it is


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

def _prompt_raising(monkeypatch, raised):
    import getpass
    import warnings

    def fake(prompt="Password: ", stream=None):
        if raised is getpass.GetPassWarning:
            warnings.warn("Can not control echo on the terminal.", getpass.GetPassWarning, stacklevel=2)
            return "read-from-stdin"
        raise raised()
    monkeypatch.setattr(getpass, "getpass", fake)


@pytest.mark.parametrize("raised,reason", [("GetPassWarning", "no terminal to ask"), (OSError, "no terminal to ask"),
                                           (EOFError, "the input ended"), (KeyboardInterrupt, "interrupted")])
def test_pin_prompt_ends_every_way_in_a_refusal(monkeypatch, raised, reason):
    """Ctrl-C at the prompt ended in a traceback, and Ctrl-D said there was no terminal (lens run 1, F10)."""
    import getpass
    import re
    _prompt_raising(monkeypatch, getpass.GetPassWarning if raised == "GetPassWarning" else raised)
    escaped = refusal = None
    try:
        pin_from_prompt()()
    except SignerError as exc:
        refusal = exc
    except BaseException as exc:  # noqa: BLE001 - a KeyboardInterrupt that got out would end the whole test run
        escaped = type(exc).__name__
    assert escaped is None, f"{escaped} escaped the prompt"
    assert refusal is not None and re.search(reason, str(refusal))
    assert refusal.__context__ is None and refusal.__cause__ is None


def test_no_refusal_of_the_signer_module_is_raised_inside_an_except_block():
    """A refusal raised inside `except` keeps the foreign exception as `__context__`, and a foreign exception can
    hold what the message leaves out: the UnicodeEncodeError of a PIN with a lone surrogate held the whole PIN
    (lens run 1, F8). Every refusal of the module is raised after the block that noted the failure. A bare
    `raise`, which re-raises the module's own error, is allowed."""
    import ast
    import inspect

    from proofbundle import signer as module

    found = []

    def walk(node, inside):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                walk(child, False)
                continue
            if isinstance(child, ast.Raise) and inside and child.exc is not None:
                found.append(child.lineno)
            walk(child, inside or isinstance(child, ast.ExceptHandler))
    walk(ast.parse(inspect.getsource(module)), False)
    assert found == [], f"a refusal raised inside an except block, at lines {found}"


@pytest.mark.parametrize("uri", ["pkcs11:token=%FF", "pkcs11:token=x?module-path=/a%FF"])
def test_a_refusal_of_the_reader_carries_no_foreign_exception(uri):
    with pytest.raises(SignerError) as info:
        parse_pkcs11_uri(uri)
    assert info.value.__context__ is None and info.value.__cause__ is None


def test_pin_from_env_reads_the_named_variable(monkeypatch):
    monkeypatch.setenv("PB_TEST_PIN_X", "4711")
    assert pin_from_env("PB_TEST_PIN_X")() == "4711"


@pytest.mark.parametrize("name", ["1234", "", "A B", "PIN=1", "a-b", "ä"])
def test_pin_from_env_takes_a_name_and_never_shows_a_wrong_one(name, monkeypatch):
    """The name rule refuses, not the unset check: where the platform takes a variable of that very name, it
    is set, so a reader that skipped the rule would find a PIN there."""
    if name and "=" not in name:
        monkeypatch.setenv(name, "4711")
    with pytest.raises(SignerError, match="the value given is not one and is not shown") as info:
        pin_from_env(name)
    assert (name not in str(info.value)) or name == ""


@pytest.mark.parametrize("value", [None, ""])
def test_pin_from_env_refuses_an_unset_or_empty_variable_without_naming_it(monkeypatch, value):
    name = "PB_" + _MARKER
    if value is None:
        monkeypatch.delenv(name, raising=False)
    else:
        monkeypatch.setenv(name, value)
    with pytest.raises(SignerError, match="unset or empty") as info:
        pin_from_env(name)()
    assert _MARKER not in str(info.value)


def test_pin_from_env_checks_the_variable_when_it_is_named(monkeypatch):
    """An unset variable is refused where it is named, before a module is loaded or a token is opened."""
    monkeypatch.delenv("PB_TEST_PIN_UNSET", raising=False)
    with pytest.raises(SignerError, match="unset or empty"):
        pin_from_env("PB_TEST_PIN_UNSET")


def test_pin_from_env_checks_the_variable_again_when_it_is_read(monkeypatch):
    monkeypatch.setenv("PB_TEST_PIN_GONE", "4711")
    read = pin_from_env("PB_TEST_PIN_GONE")
    monkeypatch.setenv("PB_TEST_PIN_GONE", "")
    with pytest.raises(SignerError, match="unset or empty"):
        read()
    monkeypatch.delenv("PB_TEST_PIN_GONE")
    with pytest.raises(SignerError, match="unset or empty"):
        read()


@pytest.mark.parametrize("uri,pin,reason", [
    ("pkcs11:token=x?module-path=/nonexistent/x.so", "1234", "function that returns the PIN"),
    ("pkcs11:token=x;type=public?module-path=/nonexistent/x.so", lambda: "1", "private key"),
    ("pkcs11:token=x;type=cert?module-path=/nonexistent/x.so", lambda: "1", "private key"),
    ("pkcs11:token=x", lambda: "1", "no module-path"),
])
def test_open_refuses_before_any_module_is_loaded(uri, pin, reason):
    """These refusals come before the extra is imported, so they hold without python-pkcs11 as well."""
    with pytest.raises(SignerError, match=reason):
        Pkcs11Signer.open(uri, pin=pin)


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


def test_every_command_that_signs_takes_token_uri_and_token_pin_env():
    found = _signing_commands()
    assert len(found) >= 7
    for path, p in found:
        options = {o for a in p._actions for o in a.option_strings}
        assert {"--key", "--new-key", "--token-uri", "--token-pin-env"} <= options, path


def test_the_token_options_change_no_abbreviation_of_another_option():
    """argparse takes any unique prefix of a long option (`--ke` for `--key`). The token options share no prefix
    with another option of a command that signs, so every abbreviation that named an option before they came
    still names it (lens run 1, F4: `--key-uri` made `--k` and `--ke` ambiguous in seven commands, `--pin-env`
    made `--p` ambiguous beside `--payload-file`)."""
    token_options = {"--token-uri", "--token-pin-env"}
    for path, p in _signing_commands():
        options = sorted({o for a in p._actions for o in a.option_strings if o.startswith("--")})
        assert token_options <= set(options), path   # else the check below would hold over nothing
        others = [o for o in options if o not in token_options]
        for option in others:
            for n in range(3, len(option)):
                prefix = option[:n]
                if sum(o.startswith(prefix) for o in others) == 1:
                    assert sum(o.startswith(prefix) for o in options) == 1, (path, prefix)


def test_cli_abbreviations_of_the_file_options_still_sign(tmp_path):
    key_path = tmp_path / "k.key"
    save_signer(Ed25519PrivateKey.generate(), str(key_path))
    payload = tmp_path / "p.bin"
    payload.write_bytes(b"x")
    for i, option in enumerate(("--k", "--ke")):
        assert cli.main(["emit", "--p", str(payload), "--out", str(tmp_path / f"b{i}.json"), option,
                         str(key_path)]) == 0
    assert (tmp_path / "b0.json").read_bytes() == (tmp_path / "b1.json").read_bytes()


def _emit_args(tmp_path, *extra):
    payload = tmp_path / "p.bin"
    payload.write_bytes(b"x")
    return ["emit", "--payload-file", str(payload), "--out", str(tmp_path / "b.json"), *extra]


@pytest.mark.parametrize("extra,reason", [
    (["--key", "k", "--token-uri", "pkcs11:token=x" + _MOD], "not both"),
    (["--new-key", "k", "--token-uri", "pkcs11:token=x" + _MOD], "not both"),
    (["--token-pin-env", "PB_PIN"], "applies to --token-uri only"),
    (["--key", "k", "--token-pin-env", "PB_PIN"], "applies to --token-uri only"),
    (["--token-uri", ""], "begins with 'pkcs11:'"),
])
def test_cli_refuses_a_token_uri_combination_that_would_be_applied_by_nothing(tmp_path, capsys, extra, reason):
    assert cli.main(_emit_args(tmp_path, *extra)) == 2
    assert not (tmp_path / "b.json").exists()
    err = capsys.readouterr().err
    assert reason in err and "Traceback" not in err


def test_cli_token_uri_with_a_pin_in_it_is_refused_and_the_pin_not_shown(tmp_path, capsys):
    assert cli.main(_emit_args(tmp_path, "--token-uri", f"pkcs11:token=x?pin-value={_MARKER}" + "&module-path=/x",
                               "--token-pin-env", "PB_PIN")) == 2
    captured = capsys.readouterr()
    assert _MARKER not in captured.err and _MARKER not in captured.out
    assert not (tmp_path / "b.json").exists()


def test_cli_token_pin_env_given_a_pin_instead_of_a_name_does_not_show_it(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("PB_" + _MARKER, raising=False)
    for value in ("47114711", "PB_" + _MARKER):
        assert cli.main(_emit_args(tmp_path, "--token-uri", "pkcs11:token=x?module-path=/nonexistent/lib.so",
                                   "--token-pin-env", value)) == 2
        captured = capsys.readouterr()
        assert value not in captured.err and value not in captured.out


def test_cli_token_uri_without_the_extra_names_the_extra(tmp_path, capsys, monkeypatch):
    monkeypatch.setitem(sys.modules, "pkcs11", None)
    monkeypatch.setenv("PB_PIN", "1234")
    assert cli.main(_emit_args(tmp_path, "--token-uri", "pkcs11:token=x?module-path=/usr/lib/x.so",
                               "--token-pin-env", "PB_PIN")) == 2
    assert "proofbundle[pkcs11]" in capsys.readouterr().err


def test_cli_failing_token_never_falls_back_to_a_key_file(tmp_path, monkeypatch, capsys):
    def forbidden(*a, **kw):
        raise AssertionError("a key file was touched after the token failed")

    monkeypatch.setattr(cli, "load_signer", forbidden)
    monkeypatch.setattr(cli, "generate_signer", forbidden)
    monkeypatch.setattr(cli, "save_signer", forbidden)
    monkeypatch.setenv("PB_PIN", "1234")
    assert cli.main(_emit_args(tmp_path, "--token-uri", "pkcs11:token=x?module-path=/nonexistent/lib.so",
                               "--token-pin-env", "PB_PIN")) == 2
    assert not (tmp_path / "b.json").exists()
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize("uri", ["pkcs11:slot-id=" + "9" * 4301 + "?module-path=/nonexistent/x.so",
                                 "pkcs11:library-version=" + "9" * 4301 + "?module-path=/nonexistent/x.so"])
def test_cli_a_number_of_any_length_in_the_uri_is_the_reader_s_refusal(tmp_path, capsys, monkeypatch, uri):
    monkeypatch.setenv("PB_PIN", "1234")
    assert cli.main(_emit_args(tmp_path, "--token-uri", uri, "--token-pin-env", "PB_PIN")) == 2
    err = capsys.readouterr().err
    assert "is a decimal number" in err or "two decimal numbers" in err
    assert "unexpected" not in err and "Traceback" not in err


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
