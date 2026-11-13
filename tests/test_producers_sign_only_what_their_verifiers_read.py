"""A producer of this package signs only what its own verifier reads.

Deep gate 6.6.0 at c3472f6f, lens L6, finding Z7 (P1): `sign_trust_pack` built its multi-signature envelope itself
and never passed the preflight of `dsse.sign_envelope`, so a pack whose `nonClaims` holds 800,000 characters was
signed and `verify_trust_pack` refused it. A probe over every producer that signs outside the DSSE primitive found two
neighbours of the same class: `issue_status_list_token` signed a `uri` of 1,100,000 characters, and
`issue_enclave_attestation` a `binding` of the same length, and each verifier refused the token with `string_len`.

GENERATOR, NOT A POINT FIXTURE: each producer is driven across the edge of its verifier's budget in even steps, and
for every size the property is the same: the producer refuses with its typed error, or its verifier accepts what it
wrote. A signed artifact its own verifier refuses is the one outcome that fails.
"""
from __future__ import annotations

import base64
import warnings
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle.errors import ProofBundleError

_SK = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
_PUB = _SK.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
_JETZT = datetime(2026, 1, 2, tzinfo=timezone.utc)


def _trust_pack(n: int) -> dict:
    return {"schemaVersion": "0.1.0", "trustPackId": "urn:test:budget", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": ["root"], "threshold": 1}},
            "keys": {"root": {"publicKey": base64.b64encode(_PUB).decode("ascii")}}, "nonClaims": ["x" * n]}


def _trust_pack_lauf(n: int):
    from proofbundle.trust_pack import TrustPackError, sign_trust_pack, verify_trust_pack
    try:
        umschlag = sign_trust_pack(_trust_pack(n), {"root": _SK})
    except TrustPackError:
        return None
    return verify_trust_pack(umschlag, strict=True, now=_JETZT)


def _status_list_lauf(n: int):
    from proofbundle import statuslist
    uri = "https://x.example/" + "u" * n
    try:
        token = statuslist.issue_status_list_token([0, 1], uri=uri, signer=_SK, iat=1_700_000_000)
    except ProofBundleError:
        return None
    return statuslist.verify_status_snapshot(token, expected_uri=uri, index=0, issuer_pubkey=_PUB,
                                             now=1_700_000_001)


def _enclave_lauf(n: int):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from proofbundle.experimental import enclave
    binding = "b" * n
    try:
        token = enclave.issue_enclave_attestation(binding, _SK, profile="tdx", tier="affirming", iat=1_700_000_000,
                                                  exp=1_800_000_000)
    except ProofBundleError:
        return None
    return enclave.verify_enclave_attestation(token, verifier_pubkey=_PUB, expected_binding=binding,
                                              now=1_700_000_001)


#: Each producer with sizes in even steps across the edge where its verifier's budget begins to refuse.
_FAELLE = {
    "trust_pack nonClaims": (_trust_pack_lauf, range(650_000, 900_001, 50_000)),
    "status list uri": (_status_list_lauf, range(950_000, 1_100_001, 25_000)),
    "enclave binding": (_enclave_lauf, range(950_000, 1_100_001, 25_000)),
}


@pytest.mark.parametrize("name", sorted(_FAELLE))
def test_a_producer_refuses_or_its_verifier_accepts_at_every_size(name):
    lauf, groessen = _FAELLE[name]
    widerspruch, abgelehnt, angenommen = [], 0, 0
    for n in groessen:
        r = lauf(n)
        if r is None:
            abgelehnt += 1
        elif r["ok"] is True:
            angenommen += 1
        else:
            widerspruch.append((n, str(r.get("errors") or r.get("detail"))[:120]))
    assert not widerspruch, f"{name}: signed and refused by its own verifier at {widerspruch}"
    # ANTI-PARITY: the sweep crosses the edge, so both outcomes occur; a sweep that only ever refuses or only ever
    # accepts would hold the property trivially and prove nothing about the edge.
    assert angenommen and abgelehnt, (name, angenommen, abgelehnt)


# ── the hybrid neighbour (review of the fix of Z7, round 1, P1) ─────────────────────────────────────────────────────
# `sign_trust_pack` signed a declared hybrid-ed25519-mldsa65 key through one `.sign` and wrote only `sig`;
# `verify_trust_pack` counts such a key only with `sig` AND `sigPq`, so the pack it returned never met its threshold.
# The producer now refuses such a signer before anything is signed.
try:
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa  # noqa: F401
    _HAT_MLDSA = True
except ImportError:
    _HAT_MLDSA = False


def _hybrid_pack(*, mit_ed25519: bool = False, schwelle: int = 0) -> tuple:
    from proofbundle.pqsig import generate_mldsa
    ed, pq = Ed25519PrivateKey.from_private_bytes(b"\x08" * 32), generate_mldsa("mldsa65")
    keys = {"root-hybrid": {"publicKey": base64.b64encode(ed.public_key().public_bytes_raw()).decode("ascii"),
                            "publicKeyPq": base64.b64encode(pq.public_key().public_bytes_raw()).decode("ascii"),
                            "alg": "hybrid-ed25519-mldsa65"}}
    root = ["root-hybrid"]
    if mit_ed25519:
        keys["root-ed"] = {"publicKey": base64.b64encode(_PUB).decode("ascii")}
        root.append("root-ed")
    predicate = {"schemaVersion": "0.1.0", "trustPackId": "urn:test:hybrid", "version": 1,
                 "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
                 "roles": {"root": {"keyIds": root, "threshold": schwelle or len(root)}}, "keys": keys,
                 "nonClaims": ["Threshold signing only."]}
    return predicate, ed, pq


@pytest.mark.skipif(not _HAT_MLDSA, reason="needs cryptography with FIPS 204 (ML-DSA)")
@pytest.mark.parametrize("gemischt", [False, True], ids=["hybrid-alone", "hybrid-and-ed25519"])
def test_a_hybrid_key_is_refused_before_anything_is_signed(gemischt):
    from proofbundle.trust_pack import TrustPackError, sign_trust_pack
    predicate, ed, _pq = _hybrid_pack(mit_ed25519=gemischt)
    gerufen = []

    class Zaehler:
        def __init__(self, sk):
            self.sk = sk

        def sign(self, msg):
            gerufen.append(1)
            return self.sk.sign(msg)

    signers = {"root-hybrid": Zaehler(ed)}
    if gemischt:
        signers["root-ed"] = Zaehler(_SK)
    with pytest.raises(TrustPackError, match="hybrid-ed25519-mldsa65 key, which verify_trust_pack counts only"):
        sign_trust_pack(predicate, signers)
    assert gerufen == [], "nothing is signed before the refusal"


@pytest.mark.skipif(not _HAT_MLDSA, reason="needs cryptography with FIPS 204 (ML-DSA)")
def test_a_hybrid_pack_with_both_legs_still_verifies():
    """ANTI-PARITY: the verifier is unchanged; a pack whose hybrid entry carries `sig` and `sigPq`, built outside the
    producer, verifies as before."""
    from proofbundle import dsse
    from proofbundle.trust_pack import INTOTO_STATEMENT_PAYLOAD_TYPE, _rfc8785_bytes, build_trust_pack_statement
    from proofbundle.trust_pack import verify_trust_pack
    predicate, ed, pq = _hybrid_pack()
    body = _rfc8785_bytes(build_trust_pack_statement(predicate))
    msg = dsse.pae(INTOTO_STATEMENT_PAYLOAD_TYPE, body)
    umschlag = {"payload": base64.b64encode(body).decode("ascii"), "payloadType": INTOTO_STATEMENT_PAYLOAD_TYPE,
                "signatures": [{"keyid": "root-hybrid", "sig": base64.b64encode(ed.sign(msg)).decode("ascii"),
                                "sigPq": base64.b64encode(bytes(pq.sign(msg))).decode("ascii")}]}
    r = verify_trust_pack(umschlag, strict=True, now=_JETZT)
    assert r["ok"] is True, r.get("errors")


@pytest.mark.skipif(not _HAT_MLDSA, reason="needs cryptography with FIPS 204 (ML-DSA)")
def test_with_threshold_one_a_redundant_hybrid_signer_is_refused_and_the_ed25519_signer_alone_signs():
    """Round 2 of the review: with threshold 1, the Ed25519 signer meets the threshold on its own. Passing the hybrid
    signer beside it returned a pack that verified without the hybrid signature before 6.6.0; that call now fails, as
    CHANGELOG.md line 84 says. Declaring a hybrid root key that does not sign stays supported."""
    from proofbundle.trust_pack import TrustPackError, sign_trust_pack, verify_trust_pack
    predicate, ed, _pq = _hybrid_pack(mit_ed25519=True, schwelle=1)
    with pytest.raises(TrustPackError, match="hybrid-ed25519-mldsa65 key"):
        sign_trust_pack(predicate, {"root-hybrid": ed, "root-ed": _SK})
    umschlag = sign_trust_pack(predicate, {"root-ed": _SK})
    r = verify_trust_pack(umschlag, strict=True, now=_JETZT)
    assert r["ok"] is True, r.get("errors")
    assert r["root_signers"] == ["root-ed"]
