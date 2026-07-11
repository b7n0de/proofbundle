"""RFC 3161 Time-Stamp Authority anchor (EXPERIMENTAL; the `[anchors]` extra).

Verification is OFFLINE (Trail of Bits ``rfc3161-client`` — deliberately no network in verify): an RFC
3161 token is checked against the TSA certificate chain **frozen into the anchor at emit time**. Freezing
matters because a TSA can rotate its certificate (FreeTSA rotated in March 2026); an old token is then
only re-verifiable against the chain that was current when it was issued. The frozen material lives in the
anchor's ``frozen`` block as base64 DER, so no PEM files travel with a receipt.

``proof`` is the base64 DER of the RFC 3161 response; ``canonicalRoot`` is the exact bytes that were
timestamped (the anchor layer has already matched it to the receipt's target root). Creating an anchor
(``create_rfc3161_anchor``) does the network call to the TSA and writes a NEW anchor object; a network
error there never touches the local receipt.
"""
from __future__ import annotations

import base64
from typing import Optional


def _load_der_cert(b64: str):
    from cryptography import x509  # noqa: PLC0415
    return x509.load_der_x509_certificate(base64.b64decode(b64))


def verify_rfc3161(proof: bytes, canonical_root: bytes, *, frozen: dict, now: Optional[int] = None) -> dict:
    """Fail-closed offline verify of an RFC 3161 token against the frozen chain. Returns {ok, detail}.

    **Certificate expiration / verification time.** The chain is validated at the token's OWN
    ``gen_time`` (the trusted TSA-asserted time inside the token), NOT at the current wall clock — this
    is the whole point of freezing the chain: an old token stays offline re-verifiable after the TSA
    certificate has since expired or rotated, because the certificate only has to have been valid WHEN
    the timestamp was created. A certificate that was NOT valid at ``gen_time`` fails closed. ``now`` is
    accepted for interface parity with the generic anchor layer but is deliberately unused here; the
    trusted time comes from the token, never from the caller's clock.

    **Policy OID.** By default no TSA policy OID is pinned (any policy is accepted). If the anchor's
    ``frozen`` block declares ``policyOid`` (a dotted-decimal string), it is pinned: the token's
    ``TSTInfo.policy`` MUST equal it or verification fails closed — a relying party who cares which TSA
    policy issued the timestamp opts in this way. A malformed OID string fails closed too.
    """
    try:
        import rfc3161_client as tsp  # noqa: PLC0415
    except ImportError:
        return {"ok": False, "detail": "rfc3161-tsa anchor needs proofbundle[anchors] (rfc3161-client)"}
    roots = frozen.get("rootCertsDerB64") or []
    if not roots:
        return {"ok": False, "detail": "frozen chain is missing rootCertsDerB64 (cannot verify offline)"}
    try:
        from cryptography.x509 import ObjectIdentifier  # noqa: PLC0415
        response = tsp.decode_timestamp_response(proof)
        builder = tsp.VerifierBuilder()
        for rb in roots:
            builder = builder.add_root_certificate(_load_der_cert(rb))
        for ib in frozen.get("intermediateCertsDerB64", []) or []:
            builder = builder.add_intermediate_certificate(_load_der_cert(ib))
        tsa_b64 = frozen.get("tsaCertDerB64")
        if tsa_b64:
            builder = builder.tsa_certificate(_load_der_cert(tsa_b64))
        policy_oid = frozen.get("policyOid")
        if policy_oid:   # opt-in: pin the TSA policy OID (fail-closed on mismatch / malformed OID)
            builder = builder.policy_id(ObjectIdentifier(policy_oid))
        builder.build().verify_message(response, canonical_root)
    except Exception as exc:   # any verify failure is a FAIL, never a silent pass (fail-closed)
        return {"ok": False, "detail": f"RFC 3161 token did not verify against the frozen chain: {exc}"}
    out = {"ok": True, "detail": "RFC 3161 token verified offline against the frozen TSA chain"}
    # WP-A2: structured trusted time from the VERIFIED token's own gen_time (the TSA-asserted time
    # the whole anchor exists to establish). Best-effort extraction from the verified response —
    # if the library exposes no gen_time, the field is simply absent (never guessed, never taken
    # from the informative anchoredAt).
    try:
        gen_time = response.tst_info.gen_time
        out["trustedTime"] = {"source": "rfc3161_gen_time",
                              "time": gen_time.strftime("%Y-%m-%dT%H:%M:%SZ"), "tz": "Z"}
    except Exception:   # noqa: BLE001 — structured time is additive; its absence is honest
        pass
    return out


def create_rfc3161_anchor(canonical_root: bytes, target: str, *, tsa_url: str,
                          root_certs_der: list, tsa_cert_der: Optional[bytes] = None,
                          intermediate_certs_der: Optional[list] = None,
                          anchored_at: Optional[str] = None, timeout: int = 30) -> dict:
    """Stamp ``canonical_root`` at ``tsa_url`` and return a NEW anchor object with the chain frozen in.

    Network call (POST an RFC 3161 query). The caller supplies the TSA's root cert(s) (and, for TSAs that
    do not embed it, the TSA cert) so the chain can be frozen for offline re-verification. This function
    only builds and returns the anchor dict — writing it into a receipt is the caller's job, so a network
    failure here never corrupts the local receipt.
    """
    import urllib.request  # noqa: PLC0415

    import rfc3161_client as tsp  # noqa: PLC0415
    request = tsp.TimestampRequestBuilder().data(canonical_root).cert_request().build()
    http = urllib.request.Request(
        tsa_url, data=request.as_bytes(), method="POST",
        headers={"Content-Type": "application/timestamp-query",
                 "Accept": "application/timestamp-reply"})
    with urllib.request.urlopen(http, timeout=timeout) as resp:
        token = resp.read()
    # sanity: the response must be granted and verify against the supplied chain before we freeze it
    frozen: dict = {
        "rootCertsDerB64": [base64.b64encode(c).decode("ascii") for c in root_certs_der],
    }
    if tsa_cert_der:
        frozen["tsaCertDerB64"] = base64.b64encode(tsa_cert_der).decode("ascii")
    if intermediate_certs_der:
        frozen["intermediateCertsDerB64"] = [base64.b64encode(c).decode("ascii")
                                             for c in intermediate_certs_der]
    check = verify_rfc3161(token, canonical_root, frozen=frozen)
    if not check["ok"]:
        raise RuntimeError(f"refusing to build anchor: fresh token did not verify — {check['detail']}")
    return {
        "type": "rfc3161-tsa",
        "target": target,
        "canonicalRoot": base64.b64encode(canonical_root).decode("ascii"),
        "proof": base64.b64encode(token).decode("ascii"),
        "anchoredAt": anchored_at,
        "frozen": frozen,
    }
