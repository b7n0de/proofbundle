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
