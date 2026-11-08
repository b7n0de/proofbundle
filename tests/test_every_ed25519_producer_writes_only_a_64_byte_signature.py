"""Every producer of an Ed25519 signature writes only a signer's output of 64 bytes.

THE CLASS, found by Codex in pre-reviews 5 and 6 of the class fix after 6.5.0: a producer asked its signer and wrote
what came back, unchecked, into something its own verifier reads under a budget or as one segment. A signer of
another kind that returned 750,001 bytes gave a bundle (`emit_bundle`), a DSSE envelope (`dsse.sign_envelope`) or a
Trust Pack (`sign_trust_pack`) that the verifier refuses at `string_len`, and 6,500,000 bytes gave a status list token
past the segment bound. The sweep over every `.sign(` of the package found nine Ed25519 sites. Each now reads the
output once through `signature._ed25519_signatur_von` and refuses, with the error it already uses, anything that is
not 64 bytes.

THE GENERATOR, not a fixture per site: every producer below runs against the same odd outputs, and the same two
controls must hold for each. A signer of another kind that returns the real signature, as bytes or as a
``memoryview``, writes exactly what the real key writes (pre-review 6: the SD-JWT producers refused a view while the
emitter took it). A new Ed25519 producer belongs in PRODUCERS; `test_the_list_names_every_ed25519_signing_site`
fails until it is there.

OUT OF THIS CLASS, named: `checkpoint.cosign_checkpoint_mldsa` and `pqsig.sign_mldsa` sign with ML-DSA, whose signature has
another length; they do not write an Ed25519 signature.
"""
from __future__ import annotations

import base64
import re
from pathlib import Path

import pytest

from proofbundle import checkpoint as cp
from proofbundle import dsse
from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.errors import BundleFormatError
from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint
from proofbundle.experimental.enclave import enclave_binding_for, issue_enclave_attestation
from proofbundle.renewal import RenewalError, _sign_ats_content
from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding
from proofbundle.statuslist import issue_status_list_token
from proofbundle.trust_pack import TrustPackError, sign_trust_pack

SRC = Path(__file__).resolve().parents[1] / "src" / "proofbundle"
KEY = generate_signer()
HOLDER = generate_signer()


class _Signer:
    """A signer of another kind: it names the real key and returns ``ausgabe(real signature)``."""

    def __init__(self, ausgabe=lambda s: s):
        self.ausgabe = ausgabe

    def sign(self, data):
        return self.ausgabe(KEY.sign(data))

    def public_key(self):
        return KEY.public_key()


def _note():
    return cp.sign_checkpoint("example.org/log", 3, bytes(range(32)), KEY, "example.org/log")


def _pack_predicate():
    return {"schemaVersion": "0.1.0", "trustPackId": "tp-sig", "version": 1, "expires": "2027-01-01T00:00:00Z",
            "prevVersionDigest": {"sha256": "a" * 64},
            "roles": {"root": {"keyIds": ["k-0"], "threshold": 1}},
            "keys": {"k-0": {"publicKey": base64.b64encode(KEY.public_key().public_bytes_raw()).decode(),
                             "scheme": "ed25519"}},
            "nonClaims": ["signer output test pack"]}


def _claim():
    claim, _ = build_eval_claim(suite="safety", suite_version="v1", metric="accuracy", comparator=">=",
                                threshold="0.65", score="0.92", n=500, model_id="acme/model-x",
                                dataset_id="acme/set", issuer=issuer_fingerprint(KEY),
                                timestamp="2026-07-01T12:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    return claim


def _holder_raw():
    return HOLDER.public_key().public_bytes_raw()


class _HolderSigner(_Signer):
    def sign(self, data):
        return self.ausgabe(HOLDER.sign(data))

    def public_key(self):
        return HOLDER.public_key()


#: name -> (producer of the output from a signer, error the producer refuses with, file:function of the site)
PRODUCERS = {
    "emit_bundle": (lambda s: emit_bundle(b"payload", s), BundleFormatError, "emit.py:emit_bundle"),
    "dsse.sign_envelope": (lambda s: dsse.sign_envelope(b"body", s, payload_type="application/vnd.test"),
                           BundleFormatError, "dsse.py:sign_envelope"),
    "sign_checkpoint": (lambda s: cp.sign_checkpoint("example.org/log", 3, bytes(range(32)), s, "example.org/log"),
                        BundleFormatError, "checkpoint.py:sign_checkpoint"),
    "cosign_checkpoint": (lambda s: cp.cosign_checkpoint(_note(), s, "witness.example", 1_780_000_000),
                          BundleFormatError, "checkpoint.py:cosign_checkpoint"),
    "issue_status_list_token": (lambda s: issue_status_list_token([0, 1], uri="https://example.org/sl", signer=s,
                                                                  iat=1_780_000_000),
                                BundleFormatError, "statuslist.py:issue_status_list_token"),
    "issue_enclave_attestation": (lambda s: issue_enclave_attestation(enclave_binding_for(emit_bundle(b"e", KEY)), s,
                                                                      profile="p", tier="affirming", exp=200),
                                  BundleFormatError, "experimental/enclave.py:issue_enclave_attestation"),
    "renewal ed25519": (lambda s: _sign_ats_content(b"content", "ed25519", {"ed25519": s}), RenewalError,
                        "renewal.py:_sign_ats_content"),
    "sign_trust_pack": (lambda s: sign_trust_pack(_pack_predicate(), {"k-0": s}), TrustPackError,
                        "trust_pack.py:sign_trust_pack"),
    "issue_sd_jwt": (lambda s: issue_sd_jwt(_claim(), s, root_b64="cm9vdA==", holder_public_key=_holder_raw()),
                     ValueError, "sdjwt_issue.py:issue_sd_jwt"),
}

#: The holder signs over the issuer's compact serialization; its signer is the holder's key.
HOLDER_PRODUCER = (lambda s: present_with_key_binding(
    issue_sd_jwt(_claim(), KEY, root_b64="cm9vdA==", holder_public_key=_holder_raw()), s, iat=1792000000,
    aud="https://rp.example", nonce="n1"), ValueError, "sdjwt_issue.py:present_with_key_binding")

ODD = {
    "750,001 bytes": lambda s: b"s" * 750_001,
    "65 bytes": lambda s: s + b"\x00",
    "63 bytes": lambda s: s[:63],
    "a str of 64 characters": lambda s: "s" * 64,
    "an int": lambda s: 64,
}


def _faelle():
    for name, (erzeuge, fehler, _ort) in PRODUCERS.items():
        yield name, erzeuge, fehler, _Signer
    yield "present_with_key_binding", HOLDER_PRODUCER[0], HOLDER_PRODUCER[1], _HolderSigner


FAELLE = list(_faelle())


@pytest.mark.parametrize("odd", sorted(ODD))
@pytest.mark.parametrize("name,erzeuge,fehler,signer_typ", FAELLE, ids=[f[0] for f in FAELLE])
def test_an_output_that_is_no_64_byte_signature_is_refused(name, erzeuge, fehler, signer_typ, odd):
    with pytest.raises(fehler, match="no 64-byte Ed25519 signature"):
        erzeuge(signer_typ(ODD[odd]))


@pytest.mark.parametrize("name,erzeuge,fehler,signer_typ", FAELLE, ids=[f[0] for f in FAELLE])
def test_control_the_real_signature_as_bytes_or_as_a_view_writes_what_the_real_key_writes(name, erzeuge, fehler,
                                                                                          signer_typ):
    echt = erzeuge(HOLDER if signer_typ is _HolderSigner else KEY)
    assert erzeuge(signer_typ()) == echt
    assert erzeuge(signer_typ(memoryview)) == echt
    assert erzeuge(signer_typ(bytearray)) == echt


def test_the_list_names_every_ed25519_signing_site():
    """Every `.sign(` in the package is a site of this list, or one of the two ML-DSA sites named above, or the
    ML-DSA signer `pqsig.sign_mldsa`. A new site fails here until it reads its output through `_ed25519_signatur_von`."""
    gelistet = {ort for _e, _f, ort in PRODUCERS.values()} | {HOLDER_PRODUCER[2]}
    ausserhalb = {"checkpoint.py:cosign_checkpoint_mldsa", "pqsig.py:sign_mldsa"}
    gefunden = set()
    for p in sorted(SRC.rglob("*.py")):
        funktion = None
        for zeile in p.read_text(encoding="utf-8").splitlines():
            m = re.match(r"(?:async )?def (\w+)\(", zeile)
            if m:
                funktion = m.group(1)
            if re.search(r"\.sign\(", zeile) and not zeile.lstrip().startswith("#"):
                gefunden.add(f"{p.relative_to(SRC).as_posix()}:{funktion}")
    assert gefunden == gelistet | ausserhalb, (sorted(gefunden - gelistet - ausserhalb), sorted((gelistet | ausserhalb) - gefunden))
    for ort in gelistet:
        datei, funktion = ort.split(":")
        assert "_ed25519_signatur_von(" in (SRC / datei).read_text(encoding="utf-8"), ort
