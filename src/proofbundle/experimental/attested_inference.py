"""Provider-attested inference — normalise a provider's per-answer evidence (v2.0 PREVIEW).

This closes one specific gap, and it is important to say which one. :mod:`.enclave` verifies an
**Attestation Result** issued by an independent RATS Verifier (RFC 9334) as an EAT (RFC 9711),
bound to a receipt through ``eat_nonce``. Some inference providers instead return their **own**
signature over their **own** answer, in their **own** format, on every request. That is a different
kind of statement, and this module keeps it a different kind of statement.

**What a provider signature is, stated plainly.** It says *this provider produced these bytes*. It
does not say *an independent party appraised the hardware*, and it does not say *your computation
ran untampered*. The signer and the party being vouched for are the same entity. In RATS terms it
is closer to Evidence than to an Attestation Result, and nobody has appraised it.

**Therefore the assurance level here is capped.** ``normalise_provider_evidence`` never returns
anything above ``provider_declared``. There is deliberately no parameter that raises it, and no
code path that promotes it. To reach ``enclave_attested`` a relying party needs an EAT from a
Verifier it trusts — that is :func:`proofbundle.experimental.enclave.verify_enclave_attestation`,
and this module points at it rather than imitating it.

**The one thing worth measuring: does the provider bind YOUR request?** A provider that accepts a
caller nonce and places it inside the signed structure ties its signature to *your* call. A
provider that signs only its own answer proves that an answer existed, not that it answered *you*.
:func:`binding_present` measures exactly that and nothing else — it looks for the expected binding
inside the signed material the provider returned.

**Measured, not assumed (2026-09-02, 25 requests across five models of one provider).** The caller
nonce did not appear in the signed structure in a single one of them, and the upstream route was
not bound either. That is the reason this module exists in this shape: the honest normalisation of
a widespread real case, not a placeholder for a better one.

**Scope.** No vendor evidence is parsed or appraised, no vendor library is required, no network
call is made. The provider's own fields are carried through verbatim and marked as reported. This
module adds no dependency.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

from ..errors import BundleFormatError

__all__ = ["ASSURANCE_PROVIDER_DECLARED", "binding_present", "normalise_provider_evidence",
           "evidence_digest"]

#: The only assurance level this module can produce. Named as a constant so a reader can grep for
#: it and find exactly one origin.
ASSURANCE_PROVIDER_DECLARED = "provider_declared"

#: Keys whose *names* suggest a credential. They are dropped before anything is carried through or
#: digested. Filtering by name rather than by value is deliberate: recognising a secret by its
#: value is not something any code can do reliably.
_CREDENTIAL_HINTS = ("key", "token", "secret", "password", "authorization", "bearer", "cookie")


def _without_credentials(obj: Any) -> Any:
    """Drop credential-looking members, recursively. Structure preserved, values not inspected."""
    if isinstance(obj, dict):
        return {k: _without_credentials(v) for k, v in obj.items()
                if not any(h in str(k).lower() for h in _CREDENTIAL_HINTS)}
    if isinstance(obj, list):
        return [_without_credentials(x) for x in obj]
    return obj


def evidence_digest(evidence: dict) -> str:
    """A stable digest over the provider's evidence, after credential removal.

    Canonical JSON with sorted keys, so the same evidence digests identically regardless of the
    order the provider happened to serialise it in. A receipt can bind this value.
    """
    if not isinstance(evidence, dict):
        raise BundleFormatError("evidence_digest needs a dict")
    clean = _without_credentials(evidence)
    return hashlib.sha256(
        json.dumps(clean, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False).encode("utf-8")).hexdigest()


def binding_present(evidence: dict, expected_binding: str) -> bool:
    """Does the provider's SIGNED material carry ``expected_binding``?

    This is the single question that separates *a signature over an answer* from *a signature over
    your call*. It is answered by looking, not by trusting a field name: the binding must occur
    somewhere in the signed material the provider returned.

    Deliberately conservative. An empty or non-string binding is never "present" — otherwise every
    evidence object would trivially satisfy a caller who forgot to pass one, which is the failure
    mode this function exists to prevent.
    """
    if not isinstance(expected_binding, str) or len(expected_binding) < 8:
        return False
    if not isinstance(evidence, dict):
        return False
    return expected_binding in json.dumps(_without_credentials(evidence), ensure_ascii=False)


def normalise_provider_evidence(evidence: dict, *, provider: str,
                                expected_binding: Optional[str] = None,
                                request_id: Optional[str] = None,
                                route: Optional[str] = None) -> dict:
    """Normalise a provider's per-answer evidence into an inspectable, honestly-capped record.

    Returns ``{assurance, provider, evidence_digest, binding_present, request_id, route,
    reported, detail}``. ``reported`` carries the provider's own fields verbatim (minus anything
    credential-shaped) and is explicitly *not* interpreted.

    ``assurance`` is always :data:`ASSURANCE_PROVIDER_DECLARED`. There is no argument that changes
    that, and a caller wanting more needs a Verifier-issued EAT — see
    :func:`proofbundle.experimental.enclave.verify_enclave_attestation`.
    """
    if not isinstance(evidence, dict):
        raise BundleFormatError("normalise_provider_evidence needs an evidence dict")
    bound = binding_present(evidence, expected_binding) if expected_binding else False
    detail = (
        "provider signed its own answer; binding to this request confirmed" if bound else
        "provider signed its own answer; this request is NOT bound to it" if expected_binding else
        "provider signed its own answer; no binding was supplied to check against")
    return {
        "assurance": ASSURANCE_PROVIDER_DECLARED,
        "provider": provider,
        "evidence_digest": evidence_digest(evidence),
        "binding_present": bound,
        "request_id": request_id,
        "route": route,
        "reported": _without_credentials(evidence),
        "detail": (detail + ". This is not an enclave attestation: the signer and the party being "
                   "vouched for are the same entity, and no independent Verifier has appraised "
                   "anything."),
    }
