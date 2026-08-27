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
from ._wire_b64 import decode_b64
from typing import Optional


def _load_der_cert(b64: str):
    from cryptography import x509  # noqa: PLC0415
    return x509.load_der_x509_certificate(decode_b64(b64))


def verify_rfc3161(proof: bytes, canonical_root: bytes, *, frozen: dict, now: Optional[int] = None,
                   rp_trust: Optional[dict] = None) -> dict:
    """Fail-closed offline verify of an RFC 3161 token. Returns {ok, detail}.

    **WP-A1 (Owner-GO, trust from the relying party).** The TSA **root certificate(s)** are the TRUST
    anchor and MUST come from the relying party (``rp_trust.trusted_tsa_roots`` — CLI ``--trusted-tsa-root``
    / policy ``anchors.trusted_tsa_roots``), NEVER from the bundle's own ``frozen`` block: a malicious
    producer could freeze its OWN self-signed root and a backdated token and self-certify. The frozen root
    is surfaced as EVIDENCE (``frozenEvidence``) but is never trusted. Without RP roots the token cannot be
    verified → ``needs_rp_trust`` (ok=False), so ``--require-anchor`` is unmet → exit 3. The frozen
    ``intermediateCertsDerB64`` / ``tsaCertDerB64`` are only path-building material (they are still
    validated up to the RP root), so they stay in ``frozen``.

    **Certificate expiration / verification time.** The chain is validated at the token's OWN
    ``gen_time`` (the trusted TSA-asserted time inside the token), NOT at the current wall clock — an old
    token stays offline re-verifiable after the TSA certificate has since expired or rotated, because the
    certificate only has to have been valid WHEN the timestamp was created. A certificate that was NOT
    valid at ``gen_time`` fails closed. ``now`` is accepted for interface parity but deliberately unused.

    **Policy OID.** No TSA policy OID is pinned by default. A relying party MAY pin one via
    ``rp_trust.trusted_tsa_policy_oids`` (the FIRST listed OID is pinned), or the producer MAY declare a
    stricter-only pin via ``frozen.policyOid``; either way the token's ``TSTInfo.policy`` MUST match or it
    fails closed.
    """
    # TYPE FLOOR on the trust-config arguments (self-gate finding F3, 2026-07-31; still reproducing on
    # main sixteen days later, re-measured 2026-08-16). `register_anchor_type` prescribes to THIRD-PARTY
    # authors that a verifier "MUST be fail-closed … never raise for an ordinary bad proof". This
    # first-party implementation did not hold its own rule: `frozen` and `rp_trust` are consumed with
    # `.get(...)` below, so a non-dict raised a raw `AttributeError` out of a verdict-returning surface.
    #
    # Measured before the fix, with `[anchors]` installed so the code actually reaches these lines (without
    # it the function returns at the import guard above and the probe is green for a reason that has
    # nothing to do with the defence it names):
    #   rp_trust=123 -> AttributeError: 'int' object has no attribute 'get'
    #   frozen=123   -> AttributeError: 'int' object has no attribute 'get'
    #
    # Why the floor and not a wider except: the same reason the evalcard/prereg floors (L1-01) exist. An
    # `except AttributeError` would close this one shape and let the next type-confusion sibling through,
    # and it would swallow a genuine internal AttributeError too. `BundleFormatError` is in the family's
    # accepted, fail-closed set, so the surface still DECIDES instead of crashing.
    #
    # Honest severity, unchanged from the finding: this surface is not exported at package level and
    # `verify_anchor` wraps every verifier in `except Exception`, so nothing leaked over the public path.
    # The contradiction is what mattered — the project's own implementation not keeping the rule it
    # prescribes to others.
    # The check is `Mapping`, not `dict`, and the difference is not pedantry. The counter-read rejected
    # the first attempt for testing the IMPLEMENTATION instead of the INTERFACE, and measuring settled it:
    # every use of these two arguments in this function is `.get(...)` — six call sites, no subscript, no
    # dict-only method, no mutation. `.get` is part of the `Mapping` protocol, so `MappingProxyType`,
    # `OrderedDict` and any dict-like object work here and were being rejected for no reason. A floor that
    # refuses valid input is a defect of its own, just a quieter one than the crash it replaced.
    from collections.abc import Mapping as _Mapping  # noqa: PLC0415

    def _nutzbares_mapping(x) -> bool:
        # isinstance(x, Mapping) beweist `.get` NICHT: `Mapping.register(cls)` macht isinstance True ohne
        # die Mixin-Methoden (Deep-Gate iter9 Linse 3a, ueber register_anchor_type erreichbar). Die
        # sechs .get-Aufrufe unten wuerden sonst roh stuerzen — also `.get`-Aufrufbarkeit mitpruefen.
        # (Dasselbe Muster ist in anchors_ots gefixt; hier dieselbe Klasse, andere Konvention: raise.)
        return isinstance(x, _Mapping) and callable(getattr(x, "get", None))

    if not _nutzbares_mapping(frozen):
        # frozen ist ein REQUIRED dict-Argument (Signatur); `frozen=None` ist ein Fehlaufruf, der bisher
        # den `frozen is not None`-Guard passierte und dann roh an `frozen.get("rootCertsDerB64")` stuerzte
        # (Deep-Gate iter9: reproduziert bei frozen=None + fehlenden roots). Jetzt typisiert abgewiesen,
        # konsistent mit anchors_ots (das None ebenfalls als Nicht-Mapping ablehnt).
        from .errors import BundleFormatError as _BFE  # noqa: PLC0415
        raise _BFE(f"frozen must be a usable mapping (with .get), got {type(frozen).__name__} (fail-closed)")
    if rp_trust is not None and not _nutzbares_mapping(rp_trust):
        from .errors import BundleFormatError as _BFE  # noqa: PLC0415
        raise _BFE(f"rp_trust must be a usable mapping (with .get), got {type(rp_trust).__name__} (fail-closed)")
    try:
        import rfc3161_client as tsp  # noqa: PLC0415
    except ImportError:
        return {"ok": False, "detail": "rfc3161-tsa anchor needs proofbundle[anchors] (rfc3161-client)"}
    rp = rp_trust or {}
    roots = rp.get("trusted_tsa_roots") or []
    if not roots:
        frozen_roots = frozen.get("rootCertsDerB64") or []
        return {"ok": False, "status": "needs_rp_trust", "needs_rp_trust": True,
                "frozenEvidence": bool(frozen_roots),
                "detail": "RFC 3161 token needs a relying-party-supplied TSA root certificate "
                          "(--trusted-tsa-root / policy anchors.trusted_tsa_roots). The bundle's own frozen "
                          "root is producer-controlled evidence, not trust; not claiming a pass"}
    rp_policy_oids = rp.get("trusted_tsa_policy_oids") or []
    try:
        from cryptography.x509 import ObjectIdentifier  # noqa: PLC0415
        response = tsp.decode_timestamp_response(proof)
        builder = tsp.VerifierBuilder()
        for rb in roots:   # WP-A1: trust anchors are the RP roots, never the frozen ones
            builder = builder.add_root_certificate(_load_der_cert(rb))
        for ib in frozen.get("intermediateCertsDerB64", []) or []:
            builder = builder.add_intermediate_certificate(_load_der_cert(ib))
        tsa_b64 = frozen.get("tsaCertDerB64")
        if tsa_b64:
            builder = builder.tsa_certificate(_load_der_cert(tsa_b64))
        # policy OID pin: the RP's first listed OID takes precedence; else the producer's stricter-only frozen pin
        policy_oid = rp_policy_oids[0] if rp_policy_oids else frozen.get("policyOid")
        if policy_oid:   # pin the TSA policy OID (fail-closed on mismatch / malformed OID)
            builder = builder.policy_id(ObjectIdentifier(policy_oid))
        builder.build().verify_message(response, canonical_root)
    except Exception as exc:   # any verify failure is a FAIL, never a silent pass (fail-closed)
        return {"ok": False, "status": "chain_fail", "rp_trusted": True,
                "detail": f"RFC 3161 token did not verify against the relying-party TSA root: {exc}"}
    out = {"ok": True, "rp_trusted": True,
           "detail": "RFC 3161 token verified offline against the relying-party TSA root"}
    # WP-A2: structured trusted time from the VERIFIED token's own gen_time (the TSA-asserted time
    # the whole anchor exists to establish). Best-effort extraction from the verified response —
    # if the library exposes no gen_time, the field is simply absent (never guessed, never taken
    # from the informative anchoredAt).
    try:
        from datetime import timezone  # noqa: PLC0415
        gen_time = response.tst_info.gen_time
        # WP-A2 (six-lens review): normalize to UTC before formatting with a literal 'Z'. RFC 3161
        # genTime is Zulu, but the parsed value may be naive (assume UTC) or tz-aware in another
        # zone (convert) — a bare strftime('…Z') on a non-UTC-aware value would mis-label the time.
        gt = gen_time.replace(tzinfo=timezone.utc) if gen_time.tzinfo is None else gen_time.astimezone(timezone.utc)
        out["trustedTime"] = {"source": "rfc3161_gen_time",
                              "time": gt.strftime("%Y-%m-%dT%H:%M:%SZ"), "tz": "Z"}
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
    # self-check at emit time: the producer HAS the roots it just used, so verify against them as the
    # RP-trust material (WP-A1: frozen roots are no longer a trust source at verify time; a relying party
    # must supply their own — but the emitter legitimately trusts the roots it stamped with).
    check = verify_rfc3161(token, canonical_root, frozen=frozen,
                           rp_trust={"trusted_tsa_roots": frozen["rootCertsDerB64"]})
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
