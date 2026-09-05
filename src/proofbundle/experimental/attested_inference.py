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


#: How deep this module will walk a provider's structure. Beyond it, the value is replaced by a
#: marker rather than descended into.
#:
#: WHY A LIMIT AT ALL (found by the repository's never-raise property, 2026-09-03, not by me). The
#: first version recursed without one, and a deeply nested evidence object — which a provider or an
#: attacker chooses, not us — terminated `check_on_receipt` with a raw `RecursionError`. That is
#: precisely the class the property exists to catch: a public checking surface that crashes instead
#: of judging. 64 is far past any real provider payload and far short of the interpreter's limit.
_MAX_DEPTH = 64

#: What replaces a structure that is deeper than we will walk. It is deliberately a VALUE and not an
#: omission: dropping the branch silently would change the digest of two different payloads into the
#: same one, and a digest that collides on demand is worse than no digest.
_TOO_DEEP = "<truncated: nesting deeper than %d levels>" % _MAX_DEPTH


def _without_credentials(obj: Any, _depth: int = 0) -> Any:
    """Drop credential-looking members, recursively. Structure preserved, values not inspected.

    Bounded by :data:`_MAX_DEPTH` — see there for why the bound exists.
    """
    if _depth >= _MAX_DEPTH:
        return _TOO_DEEP
    if isinstance(obj, dict):
        return {k: _without_credentials(v, _depth + 1) for k, v in obj.items()
                if not any(h in str(k).lower() for h in _CREDENTIAL_HINTS)}
    if isinstance(obj, list):
        return [_without_credentials(x, _depth + 1) for x in obj]
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


# ---------------------------------------------------------------------------------------------
# Receive-time checks (C5). Everything below answers one question: may this answer be counted?
# ---------------------------------------------------------------------------------------------

#: The outcome vocabulary. Three states, never two — and the third is not a pass.
OUTCOME_ACCEPTED = "accepted"
OUTCOME_ATTESTATION_FAILURE = "attestation_failure"
OUTCOME_NOT_MEASURABLE = "not_measurable"

#: Why an answer was refused. Named so a caller can branch on the cause instead of on prose.
REASON_STALE_NONCE = "nonce.not_bound_to_this_request"
REASON_REQUEST_HASH = "binding.request_hash_mismatch"
REASON_RESPONSE_HASH = "binding.response_hash_mismatch"
REASON_ROUTE_DRIFT = "route.silent_fallback"
REASON_EVIDENCE_TAMPERED = "evidence.digest_mismatch"
REASON_EVIDENCE_FOREIGN = "evidence.belongs_to_another_answer"
REASON_MALFORMED = "evidence.malformed"
#: Die uebergebenen Bytes sind keine. Eigener Grund, NICHT `REASON_MALFORMED`: dort ist die
#: EVIDENZ kaputt, hier die Frage des Aufrufers — zwei verschiedene naechste Schritte, und wer sie
#: zusammenwirft, schickt den Aufrufer zum falschen Ort. Gefunden 04.09.2026 von einer
#: Gegenlese-Linse: `check_on_receipt(..., request_bytes=None)` warf einen ROHEN TypeError, obwohl
#: der Kommentar zwei Absaetze weiter unten die Zusage traegt, eine Flaeche, die ein Urteil
#: verspricht, muesse ein Urteil liefern. Der Riegel fing es nicht, weil er nur Argument 0 fuzzt.
REASON_BYTES_NOT_BYTES = "input.bytes_expected"


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def check_on_receipt(evidence: dict, *, provider: str, nonce: str,
                     request_bytes: bytes, response_bytes: bytes,
                     planned_route: Optional[str] = None,
                     expected_evidence_digest: Optional[str] = None) -> dict:
    """Decide whether one provider answer may be counted, at the moment it arrives.

    Returns ``{outcome, reasons, normalised}``. ``outcome`` is one of :data:`OUTCOME_ACCEPTED`,
    :data:`OUTCOME_ATTESTATION_FAILURE` or :data:`OUTCOME_NOT_MEASURABLE`.

    **Accepted never means attested.** Even a fully accepted answer carries
    ``assurance == provider_declared`` in ``normalised``; this function decides whether the
    provider's statement is about *this* call, not whether anyone appraised the hardware. A caller
    that reads ``accepted`` as *hardware attested* has misread it, and the returned record says so
    in its own ``detail``.

    **Why a separate not-measurable state.** A provider that returns no route, or a caller that
    supplies no planned route, has not demonstrated a silent fallback — it has demonstrated that
    the question cannot be answered here. Reporting that as a failure would make an absent
    measurement look like a caught defect; reporting it as accepted would make it look like a
    passed check. It is neither, and it is never an acceptance: the caller must treat it as
    PARTIAL or NOT RUN, which is what C0 condition 12 requires.

    **The order of checks is not cosmetic.** Tampering is checked before binding, because evidence
    that has been altered says nothing about what it was bound to; reporting a binding failure on
    altered evidence would name the wrong cause.
    """
    reasons: list[str] = []
    unmeasurable: list[str] = []

    # TOTAL, NOT STRICT — and the distinction is the house contract, not a preference.
    #
    # This is a public checking surface, and the repository's never-raise property forbids such a
    # surface from terminating with a raw exception on hostile input: a caller reaching for a
    # verdict must get a verdict. The strict layer is `evidence_digest`, which still raises on a
    # non-dict; this boundary catches that and NAMES it instead of propagating it.
    #
    # Malformed evidence is an attestation FAILURE, not a not-measurable. Evidence that is not even
    # a mapping has not failed to answer the question — it has failed to be evidence, and an answer
    # backed by it must never be counted. Fail-closed is the only defensible direction here.
    if not isinstance(evidence, dict):
        return {"outcome": OUTCOME_ATTESTATION_FAILURE, "reasons": [REASON_MALFORMED],
                "not_measurable": [], "evidence_digest": None,
                "normalised": {"assurance": ASSURANCE_PROVIDER_DECLARED, "provider": provider,
                               "evidence_digest": None, "binding_present": False,
                               "request_id": None, "route": None, "reported": None,
                               "detail": (f"evidence is {type(evidence).__name__}, not a mapping — "
                                          "this is not an enclave attestation and cannot be "
                                          "counted as anything")}}

    # 1. Has the evidence itself been altered since it was handed to us? Checked FIRST: altered
    #    evidence cannot testify about its own bindings.
    # A MAPPING WITH UNSERIALISABLE CONTENT IS NOT EVIDENCE EITHER (lens 1 on PR 185, F5). The
    # guard above checks only `isinstance(evidence, dict)`; `{"x": {1, 2}}`, `{"x": b"bytes"}` or
    # `{1: "a", "b": 2}` passed it and then raised a raw TypeError out of `json.dumps` — the same
    # class as the depth guard, one hop further in. Same verdict as a non-mapping: attestation
    # failure, REASON_MALFORMED, named instead of propagated.
    try:
        digest = evidence_digest(evidence)
    except (TypeError, ValueError, BundleFormatError) as exc:
        return {"outcome": OUTCOME_ATTESTATION_FAILURE, "reasons": [REASON_MALFORMED],
                "not_measurable": [], "evidence_digest": None,
                "normalised": {"assurance": ASSURANCE_PROVIDER_DECLARED, "provider": provider,
                               "evidence_digest": None, "binding_present": False,
                               "request_id": None, "route": None, "reported": None,
                               "detail": (f"evidence cannot be canonicalised ({type(exc).__name__}: "
                                          f"{exc}) — a mapping whose content has no canonical JSON "
                                          "form cannot be digested and cannot be counted")}}
    if expected_evidence_digest is not None and digest != expected_evidence_digest:
        reasons.append(REASON_EVIDENCE_TAMPERED)

    # 2. Does the provider's signed material carry OUR nonce? A quote that predates this request
    #    cannot contain it. This is the same measurement as `binding_present`, named for the
    #    failure it catches.
    if not binding_present(evidence, nonce):
        reasons.append(REASON_STALE_NONCE)

    # 3. Do the hashes in the signed material match the bytes we actually sent and received?
    #    A mismatch means the statement is about a different exchange than ours.
    signed = json.dumps(_without_credentials(evidence), ensure_ascii=False)
    _falsche = [n for n, v in (("request_bytes", request_bytes), ("response_bytes", response_bytes))
                if not isinstance(v, (bytes, bytearray, memoryview))]
    if _falsche:
        # NICHT MESSBAR, nicht "Angriff": ohne die Bytes kann diese Achse nichts sagen, und eine
        # Ablehnung zu erfinden waere eine Aussage ueber etwas Ungemessenes.
        unmeasurable.append(REASON_BYTES_NOT_BYTES)
    # JE ACHSE gerechnet, nicht im Paar: sind nur die Antwort-Bytes kaputt, bleibt der
    # Anfrage-Hash messbar. Vorher setzte ein kaputter Teil beide auf None und nahm der
    # anderen Achse die Messung, die sie haette liefern koennen.
    req_h = (_sha256_bytes(bytes(request_bytes))
             if isinstance(request_bytes, (bytes, bytearray, memoryview)) else None)
    res_h = (_sha256_bytes(bytes(response_bytes))
             if isinstance(response_bytes, (bytes, bytearray, memoryview)) else None)
    claims_req = "request_hash" in signed or "request_sha256" in signed
    claims_res = "response_hash" in signed or "response_sha256" in signed
    # DREI LAGEN JE ACHSE, nie zwei. Nicht behauptet: nicht messbar. Behauptet, aber ohne Bytes
    # (req_h is None): ebenfalls nicht messbar — eine Ablehnung zu erfinden waere eine Aussage
    # ueber Ungemessenes. Behauptet und mit Bytes: gemessen.
    #
    # GEMESSEN 04.09.2026, gefunden von mypy in der CI von PR 185 und zur Laufzeit nachgestellt:
    # `None not in signed` ist ein TypeError, kein Urteil. Die Regressionsklammer aus 6ac2041
    # deckte nur Belege, die KEINEN Hash behaupten; mit Behauptung und str statt bytes fiel die
    # Flaeche weiter roh — der Typpruefer sah es, der Fuzz nicht.
    if not claims_req:
        unmeasurable.append(REASON_REQUEST_HASH)
    elif req_h is None:
        unmeasurable.append(REASON_REQUEST_HASH)
    elif req_h not in signed:
        reasons.append(REASON_REQUEST_HASH)
    if not claims_res:
        unmeasurable.append(REASON_RESPONSE_HASH)
    elif res_h is None:
        unmeasurable.append(REASON_RESPONSE_HASH)
    elif res_h not in signed:
        reasons.append(REASON_RESPONSE_HASH)

    # 4. Did the route silently move? A change of backend is an attestation failure, not a detail:
    #    the evidence describes a machine that did not serve this answer.
    reported_route = evidence.get("route") or evidence.get("upstream") or evidence.get("backend")
    if planned_route and reported_route and str(reported_route) != str(planned_route):
        reasons.append(REASON_ROUTE_DRIFT)
    elif planned_route and not reported_route:
        unmeasurable.append(REASON_ROUTE_DRIFT)

    normalised = normalise_provider_evidence(
        evidence, provider=provider, expected_binding=nonce,
        request_id=req_h[:16] if req_h else None,
        route=str(reported_route) if reported_route else None)

    if reasons:
        outcome = OUTCOME_ATTESTATION_FAILURE
    elif unmeasurable:
        outcome = OUTCOME_NOT_MEASURABLE
    else:
        outcome = OUTCOME_ACCEPTED
    return {"outcome": outcome, "reasons": reasons, "not_measurable": unmeasurable,
            "evidence_digest": digest, "normalised": normalised}


def counts_as_own_domain(receipt_check: dict) -> bool:
    """May this provider answer count as its own execution domain in a diversity panel?

    Only an ACCEPTED answer may. An attestation failure obviously may not, and a NOT MEASURABLE
    one may not either: an unverified upstream is not a domain, it is an unknown. Counting it
    would inflate the measured diversity of a panel with something nobody checked, which is the
    one thing a diversity floor must never do.
    """
    # Only a mapping can carry an outcome (lens 1 on PR 185, F8): `None`, a string or a list
    # raised a raw AttributeError here — and this is the gate of the diversity floor, where
    # "not judged" must read as "does not count", never as a crash.
    return isinstance(receipt_check, dict) and receipt_check.get("outcome") == OUTCOME_ACCEPTED
