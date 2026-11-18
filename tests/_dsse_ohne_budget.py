"""A DSSE envelope built without the producer's budget check, for a test that hands a verifier input past its budget.

Since deep gate 6.6.0 at d8881edc (finding Z7), `dsse.sign_envelope` refuses, before it signs, an envelope that the
verifier would refuse for its budget, and a `+json` payload past the budget of the statement verifiers. A test of
such a verifier needs exactly those envelopes, and an attacker does not build them with this package's producer. This
helper writes the envelope `sign_envelope` writes, with the same PAE, the same base64 and the same keyid, and asks
nothing about size. It is test support only and is imported by no module under `src/`.
"""
from __future__ import annotations

import base64

from proofbundle import dsse


def sign_ohne_budget(body: bytes, signer, *, payload_type: str, keyid: str | None = None) -> dict:
    """The envelope of `dsse.sign_envelope(body, signer, payload_type=..., keyid=...)`, past any budget."""
    sig = signer.sign(dsse.pae(payload_type, bytes(body)))
    entry = {"sig": base64.b64encode(sig).decode("ascii")}
    if keyid is None:
        keyid = dsse._default_keyid(signer)
    if keyid:
        entry = {"keyid": keyid, "sig": entry["sig"]}
    return {"payload": base64.b64encode(bytes(body)).decode("ascii"), "payloadType": payload_type,
            "signatures": [entry]}
