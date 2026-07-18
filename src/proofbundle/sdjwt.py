"""Minimal SD-JWT selective disclosure verification.

The SD-JWT *core* is now a published standard, RFC 9901 (November 2025). This
module verifies the heart of it: that every presented Disclosure hashes to a
digest that is actually committed in the issuer-signed JWT payload, and, if an
issuer public key is supplied and the algorithm is EdDSA or ES256, that the
issuer signature over the JWT is valid.

Note the layering: RFC 9901 is the SD-JWT mechanism; **SD-JWT VC** (the
credential type profile) is still an IETF draft,
``draft-ietf-oauth-sd-jwt-vc`` — this verifier does not yet do full VC-level
checks (a relying-party ``vct``/``typ`` profile check lives in
:mod:`proofbundle.sdjwt_vc`; an exact-``vct`` trust-policy pin lives in
:mod:`proofbundle.policy`'s ``sd_jwt.expected_vct``).

Scope, stated honestly (see README security notes):
  - Issuer signatures: EdDSA (Ed25519) and, since Finding 20 / issue #27
    (PB-2026-07-15), ES256 (ECDSA P-256, RFC 7518 §3.4) — the algorithm the
    EUDI Digital Identity Wallet and the OAuth WG's own SD-JWT VC worked
    examples use. Any other ``alg`` value fails closed (``sig_ok`` stays
    False, ``detail`` names the unsupported alg) — there is no silent
    downgrade to "unchecked". Dispatch is a strict string match on the
    literal, parsed ``alg`` claim from the SAME ``header_b64`` bytes the
    signature covers (never a re-serialized/canonicalized header), so the
    alg claim is cryptographically bound into the verified bytes: relabelling
    it to reuse a signature under a different verify function/key-length
    expectation changes ``header_b64`` and breaks the original signature.
  - Key Binding JWT verification lives in :mod:`proofbundle.kbjwt` (since
    v1.2, EdDSA-only — holder-binding is a separate, narrower scope than
    issuer-signature interop and is not extended by Finding 20); this module
    verifies issuer signature + disclosure commitments, and the bundle layer
    runs the KB check fail-closed whenever a KB-JWT is attached.
  - No X.509 / trust-list / status-list checks, no ``vct`` type-metadata
    *document* resolution (schema/display metadata) — an offline integrity
    pin on opaque metadata bytes is a separate, already-implemented
    capability (:func:`proofbundle.sdjwt_vc.check_vc_profile`'s
    ``requireTypeMetadataIntegrity``). Full SD-JWT VC conformance remains on
    the roadmap; see ``docs/SD_JWT_VC_PROFILE.md`` for the current, honest
    split.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections import deque
from typing import Optional, Set

from ._strict_json import loads_strict
from .errors import BundleFormatError
from .signature import verify_ecdsa_p256, verify_ed25519

# Finding 20 / issue #27: issuer-signature algorithms this verifier accepts, each dispatched to its
# own alg-specific primitive with its own fixed key/signature length (32-byte Ed25519 raw key + Ed25519
# verify, vs. 65-byte SEC1 P-256 point + ECDSA verify) — no algorithm can be confused for another.
_ISSUER_SIG_VERIFIERS = {"EdDSA": verify_ed25519, "ES256": verify_ecdsa_p256}

__all__ = ["verify_sd_jwt"]

_HASH_ALG = {"sha-256": "sha256", "sha-384": "sha384", "sha-512": "sha512"}

# PB-2026-0715-15a (CWE-400/407, O(n^2) CPU-DoS guard): a real SD-JWT presentation discloses a
# handful to a few dozen claims. Measured: n=4000 adversarially-ordered disclosures drove ~11s of
# CPU from a 520KB bundle reachable via bundle.py::verify_bundle with no prior length check. Refuse
# fail-closed (structure_ok stays False) well above any legitimate use, before the fixpoint below
# even runs — belt-and-suspenders alongside the O(n) algorithm change.
_MAX_DISCLOSURES = 256


def _b64url_decode(s: str) -> bytes:
    raw = s.encode("ascii")
    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


def _b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _digest(disclosure_b64: str, alg: str) -> str:
    h = hashlib.new(_HASH_ALG[alg])
    h.update(disclosure_b64.encode("ascii"))
    return _b64url_nopad(h.digest())


def _collect_committed_digests(node, out: Set[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "_sd" and isinstance(value, list):
                out.update(d for d in value if isinstance(d, str))
            elif key == "...":
                if isinstance(value, str):
                    out.add(value)
            else:
                _collect_committed_digests(value, out)
    elif isinstance(node, list):
        for item in node:
            _collect_committed_digests(item, out)


def verify_sd_jwt(compact: str, issuer_pubkey: Optional[bytes] = None) -> dict:
    """Verify an SD-JWT compact serialization.

    Returns a dict with keys: ``structure_ok`` (disclosures all committed),
    ``sig_checked``, ``sig_ok``, ``alg`` and ``detail``.
    """
    result = {
        "structure_ok": False,
        "sig_checked": False,
        "sig_ok": False,
        "alg": None,
        "detail": "",
    }
    if not isinstance(compact, str):
        # RE-GATE never-raise (breadth sweep): a non-str compact presentation is malformed input — a
        # fail-closed verdict, never a raw AttributeError from `.split("~")`. This dict-returning verify
        # surface (untrusted SD-JWT from a holder) must always return a verdict.
        result["detail"] = "SD-JWT compact presentation must be a string (non-str is malformed, fail-closed)"
        return result
    parts = compact.split("~")
    if len(parts) < 1 or parts[0].count(".") != 2:
        result["detail"] = "not a compact SD-JWT"
        return result

    header_b64, payload_b64, sig_b64 = parts[0].split(".")
    try:
        header = loads_strict(_b64url_decode(header_b64))
        payload = loads_strict(_b64url_decode(payload_b64))
    except BundleFormatError:
        # WP-C1 (F12, 2026-07-12): a DUPLICATE JSON key in the issuer-signed JWT header/payload is a
        # parser differential — plain json.loads is last-wins, so a duplicated `cnf` lets an attacker
        # holder key silently win over the intended one (kbjwt.holder_key_from_cnf). Every other verify
        # path already parses with loads_strict; this closes the documented SD-JWT residual at the
        # structure gate — structure_ok stays False, so the bundle fails fail-closed.
        result["detail"] = "duplicate JSON key in SD-JWT header/payload (parser-differential, rejected)"
        return result
    except (ValueError, json.JSONDecodeError):
        result["detail"] = "malformed JWT header or payload"
        return result
    if not isinstance(header, dict) or not isinstance(payload, dict):
        # a JWT header/payload that decodes to a non-object (e.g. the integer 5) must fail cleanly, not
        # crash later on .get(...) — keeps verify_bundle/verify_receipt_token's "never a crash" contract.
        result["detail"] = "malformed JWT header or payload (not a JSON object)"
        return result

    alg = header.get("alg")
    result["alg"] = alg
    sd_alg = payload.get("_sd_alg", "sha-256")
    if sd_alg not in _HASH_ALG:
        result["detail"] = f"unsupported _sd_alg {sd_alg}"
        return result

    # Disclosures are the non-empty middle parts; a trailing key-binding token
    # (which contains dots) is not a disclosure — it is verified separately by
    # proofbundle.kbjwt (bundle layer, fail-closed) since v1.2.
    disclosures = [p for p in parts[1:] if p and p.count(".") == 0]
    if len(disclosures) > _MAX_DISCLOSURES:
        # PB-2026-0715-15a: reject BEFORE any per-disclosure parsing/hashing work starts.
        result["detail"] = (
            f"too many disclosures ({len(disclosures)} > {_MAX_DISCLOSURES}) — refusing (DoS guard, "
            "PB-2026-0715-15a)"
        )
        return result

    committed: Set[str] = set()
    _collect_committed_digests(payload, committed)

    all_committed = True
    parsed_disclosures: list = []
    for d in disclosures:
        try:
            parsed = loads_strict(_b64url_decode(d))
        except BundleFormatError:
            # a disclosure whose JSON value is an object with a duplicate key is rejected (F12); set a
            # duplicate-specific detail so it is not masked by the generic "N disclosure(s)" fall-through.
            result["detail"] = "duplicate JSON key in an SD-JWT disclosure (parser-differential, rejected)"
            all_committed = False
            break
        except (ValueError, json.JSONDecodeError):
            all_committed = False
            break
        if not (isinstance(parsed, list) and len(parsed) in (2, 3)):
            all_committed = False
            break
        parsed_disclosures.append((d, parsed))

    if all_committed:
        # Recursive disclosures (RFC 9901): a disclosure's VALUE may itself carry ``_sd``/``...`` digests that
        # commit to FURTHER disclosures. A disclosure is committed iff its digest is already in ``committed``;
        # each newly-committed disclosure then contributes the ``_sd``/``...`` digests inside its own value
        # (the last array element). Disclosure order is not guaranteed parent-first, so this resolves to a
        # fixpoint. Security is preserved: the fixpoint only ever GROWS ``committed`` from the issuer-signed
        # payload outward, so a self-referential or otherwise unrooted disclosure never bootstraps itself. At
        # the end EVERY disclosure must be committed (transitively rooted in the signed payload) — fail-closed.
        #
        # PB-2026-0715-15a (O(n^2) -> O(n) CPU-DoS fix): the previous implementation re-scanned EVERY
        # still-unresolved disclosure AND re-computed its SHA-256 digest on EVERY pass — under an
        # adversarial disclosure order (worst case: exactly one disclosure resolves per pass) that is
        # O(n^2) hashing + scanning. This is an algorithmically equivalent BFS/worklist over the SAME
        # fixpoint, not a semantic change: each disclosure's digest is hashed exactly once (grouped by
        # digest — identical disclosures naturally share one digest and resolve together), and a
        # digest is only (re-)examined when something NEW actually lands in ``committed`` because of
        # it, never rescanned on unrelated passes. Total work is O(n + m), where m is the number of
        # _sd/... entries newly produced by resolved disclosures, versus the old O(n^2).
        digest_groups: dict = {}
        for d, parsed in parsed_disclosures:
            digest_groups.setdefault(_digest(d, sd_alg), []).append((d, parsed))

        visited: Set[str] = set()
        queue = deque(dg for dg in digest_groups if dg in committed)
        resolved_count = 0
        while queue:
            dg = queue.popleft()
            if dg in visited:
                continue
            visited.add(dg)
            for _d, parsed in digest_groups[dg]:
                resolved_count += 1
                newly: Set[str] = set()
                _collect_committed_digests(parsed[-1], newly)
                for dg2 in newly - committed:
                    committed.add(dg2)
                    if dg2 in digest_groups and dg2 not in visited:
                        queue.append(dg2)
        if resolved_count != len(parsed_disclosures):
            # at least one disclosure never became committed — uncommitted / not rooted in the signed payload
            all_committed = False

    result["structure_ok"] = all_committed and bool(parts[0])

    if issuer_pubkey is not None:
        result["sig_checked"] = True
        # Finding 20 / issue #27 (PB-2026-07-15): dispatch strictly on the LITERAL alg parsed from
        # header_b64 above — the same bytes signing_input is built from below — never inferred from the
        # issuer_pubkey length or the signature shape. header_b64 is part of the signed bytes (RFC 7515
        # JWS: signing_input = ASCII(header_b64) || "." || ASCII(payload_b64)), so alg is already bound
        # into what the signature covers: an attacker relabelling alg to route a valid EdDSA signature
        # through the ES256 verifier (or vice versa) changes header_b64 and breaks the original
        # signature — there is no code path that lets one algorithm's bytes verify as another's.
        verifier = _ISSUER_SIG_VERIFIERS.get(alg) if isinstance(alg, str) else None
        if verifier is not None:
            signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
            try:
                result["sig_ok"] = verifier(issuer_pubkey, _b64url_decode(sig_b64), signing_input)
            except ValueError:
                result["sig_ok"] = False
        else:
            result["detail"] = f"issuer signature alg {alg} not supported in v0.1"

    if not result["detail"]:
        result["detail"] = f"{len(disclosures)} disclosure(s)"
    return result
