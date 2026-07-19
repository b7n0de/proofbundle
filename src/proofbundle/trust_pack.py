"""Trust Pack predicate `trust-pack/v0.1` — hand-rolled, fail-closed validation + threshold verify.

proofbundle 3.2.0 O2 (EXPERIMENTAL). A TUF-inspired, signed root of trust: each role (root, evalIssuers,
decisionMakers, outcomeExecutors, outcomeReceivers, timeAuthorities, witnesses) maps to a set of key ids and
a signature threshold; a keyId->publicKey map resolves them; a monotone ``version`` with a
``prevVersionDigest`` chain gives rollback/freeze protection; ``expires`` bounds validity; ``revoked`` is an
offline revocation list.

The ``outcomeExecutors`` role supplies the identity that an Action Outcome Receipt (O1) executor is checked
against; ``outcomeReceivers`` (Finding 16, additive) does the same for a third-party receiver/observer that
corroborates an outcome (``outcome.receiver_trusted_by_role``). A Trust Pack is authenticated by a THRESHOLD
of its root keys (not any-single, unlike a plain DSSE
verify). Rotation is a new version signed by the OLD root threshold (two-stage: old root vouches for new),
enforced by ``verify_trust_pack`` when the caller supplies the previous root role (``prev_root_keys`` +
``prev_root_threshold``); a verify without them checks only this pack's own threshold plus the digest chain.

No-Overclaim: the pack names WHICH keys hold WHICH role. It does not assert those key holders are honest,
only that a threshold of the named root keys signed this exact pack. ``nonClaims`` records that verbatim.

Field names are lowerCamelCase (ITE-9).
"""
from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timezone
from typing import Any, TypeGuard

from ._strict_json import loads_strict
from .budget import DEFAULT_BUDGET
from .errors import BundleFormatError, ProofBundleError

TRUST_PACK_PREDICATE_TYPE = "https://b7n0de.com/proofbundle/predicates/trust-pack/v0.1"
TRUST_PACK_SCHEMA_VERSION = "0.1.0"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
INTOTO_STATEMENT_PAYLOAD_TYPE = "application/vnd.in-toto+json"

_RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_SEMVER_0_1_X = re.compile(r"^0\.1\.\d+$")

_ROLE_NAMES = ("root", "evalIssuers", "decisionMakers", "outcomeExecutors", "outcomeReceivers",
              "timeAuthorities", "witnesses")
_REQUIRED_ALWAYS = ("schemaVersion", "trustPackId", "version", "expires", "prevVersionDigest",
                    "roles", "keys", "nonClaims")
_OPTIONAL = ("revoked",)
_ALLOWED_TOP = set(_REQUIRED_ALWAYS) | set(_OPTIONAL)

# Crypto agility (ADR 0006, mirrors renewal.py's `_SIG_ALGS`): a keys[kid] entry declares WHICH signature
# algorithm it holds. Absent `alg` defaults to "ed25519" (backward compatible with every pre-agility pack).
# `hybrid-ed25519-mldsa65` carries TWO legs — `publicKey` (Ed25519 classical, 32 bytes) + `publicKeyPq`
# (ML-DSA-65 PQ, 1952 bytes, FIPS 204) — and BOTH must verify (an attacker must forge both to forge the key).
_KEY_ALGS = ("ed25519", "mldsa65", "hybrid-ed25519-mldsa65")
_KEY_RAW_LEN = {"ed25519": 32, "mldsa65": 1952}  # raw public key byte length (FIPS 204 ML-DSA-65 = 1952 bytes)
_KEY_ALG_LABEL = {"mldsa65": "ML-DSA-65", "hybrid-ed25519-mldsa65": "Ed25519 (hybrid classical leg)"}

# Finding 01 (2026-07 verify-layer hardening): automation_verdict.automation_summary's required_checks for
# this predicate — root_threshold_met is the crypto-equivalent verdict (a Trust Pack has no single
# `crypto_ok`, only the threshold check); "policy" is None (a Trust Pack IS the root of trust, it carries
# no separate external policy/authorization layer to evaluate).
_AUTOMATION_REQUIRED_CHECKS = {
    "crypto": "root_threshold_met", "structure": "structure_ok", "policy": None,
    "references": ["not_expired", "version_monotone", "rotation_authorized"],
}


def _as_dict(v):
    """Berkeley r5/r6 class-fix: Config-Sub-Feld als dict, sonst {} (das ``_as_dict(x.get(k))``-Idiom ersetzte nur FALSY)."""
    return v if isinstance(v, dict) else {}


def _as_list(v):
    return v if isinstance(v, (list, tuple)) else []


class TrustPackError(ProofBundleError):
    """A Trust Pack predicate is malformed (fail-closed)."""


def _is_digest(obj: Any) -> TypeGuard[dict]:
    return isinstance(obj, dict) and isinstance(obj.get("sha256"), str) and bool(_SHA256_HEX.match(obj["sha256"]))


def _is_int(v: Any) -> TypeGuard[int]:
    return isinstance(v, int) and not isinstance(v, bool)


def _parse_rfc3339_z(s: str) -> datetime:
    """Parse an RFC-3339 UTC 'Z' timestamp, tolerating optional fractional seconds of ANY length.

    ``_RFC3339_Z`` accepts ``(\\.\\d+)?`` fractional seconds, but ``strptime`` with ``%S`` (no ``%f``) rejects
    them, and ``%f`` itself caps at 6 digits — so an ``expires`` like ``...T00:00:00.5Z`` (regex-valid) would
    raise and be read as EXPIRED (a false-closed availability bug). This parser splits off the fractional part
    and truncates it to microseconds (enough for an expiry comparison). Raises ``ValueError`` on a non-match."""
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$", s)
    if not m:
        raise ValueError(f"not an RFC-3339 UTC 'Z' timestamp: {s!r}")
    dt = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    frac = m.group(2)
    if frac:
        dt = dt.replace(microsecond=int((frac + "000000")[:6]))
    return dt


def validate_trust_pack_predicate(predicate: Any, *, strict: bool = False) -> list[str]:
    """Return fail-closed errors for a ``trust-pack/v0.1`` predicate (empty = valid).

    Beyond shape this enforces: threshold in 1..len(keyIds) per role; every keyId referenced by a role is
    present in ``keys``; ``revoked`` entries are known keyIds; a role's threshold is not already impossible
    once revoked keys are removed (a pack whose root can never meet threshold is dead-on-arrival, fail-closed);
    a ``version`` > 1 pack MUST carry a non-null ``prevVersionDigest`` (only version 1 may be a genesis).

    ``strict`` currently adds no extra predicate-level required fields (the trust-pack predicate is small and
    fully required by default); it is kept for signature parity with the emit/verify entry points, where it
    additionally makes RFC-8785 canonicality fail-closed in ``verify_trust_pack`` (mirrors ``outcome.py``)."""
    errors: list[str] = []
    if not isinstance(predicate, dict):
        return ["predicate must be a JSON object"]

    for k in predicate:
        if k not in _ALLOWED_TOP:
            errors.append(f"unknown field {k!r} (additionalProperties:false)")
    for req in _REQUIRED_ALWAYS:
        if req not in predicate:
            errors.append(f"missing required field {req!r}")

    sv = predicate.get("schemaVersion")
    if "schemaVersion" in predicate and not (isinstance(sv, str) and _SEMVER_0_1_X.match(sv)):
        errors.append("schemaVersion must match 0.1.x")
    tid = predicate.get("trustPackId")
    if "trustPackId" in predicate and not (isinstance(tid, str) and tid):
        errors.append("trustPackId must be a non-empty string")
    ver = predicate.get("version")
    if "version" in predicate and not (_is_int(ver) and ver >= 1):
        errors.append("version must be an integer >= 1")
    exp = predicate.get("expires")
    if "expires" in predicate and not (isinstance(exp, str) and _RFC3339_Z.match(exp)):
        errors.append("expires must be an RFC3339 UTC 'Z' timestamp")
    pv = predicate.get("prevVersionDigest")
    if "prevVersionDigest" in predicate and pv is not None and not _is_digest(pv):
        errors.append("prevVersionDigest must be a sha256 digest object or null")
    # A version > 1 pack MUST chain to a predecessor (fail-closed, No-Fake): a "version-2 genesis" declaring
    # prevVersionDigest=null evades two-stage rotation authorization entirely — verify_trust_pack only enters
    # the rotation-vouch branch when prevVersionDigest is a digest, so a null predecessor on a v>=2 pack passes
    # on its own self-signature. Only version 1 (the genuine genesis) may have a null prevVersionDigest.
    if _is_int(ver) and ver >= 2 and pv is None:
        errors.append("version > 1 requires a non-null prevVersionDigest (a version-N pack must chain to its "
                      "predecessor; only version 1 may have a null prevVersionDigest)")

    keys = predicate.get("keys")
    key_ids: set[str] = set()
    if "keys" in predicate:
        if not isinstance(keys, dict) or not keys:
            errors.append("keys must be a non-empty object mapping keyId -> {publicKey}")
        elif not DEFAULT_BUDGET.within("witnesses", len(keys)):
            # Finding 15b: refuse an absurdly large keys map BEFORE the per-key base64/length work below
            # runs (a Trust Pack's root-of-trust is a small, human-curated set — not attacker-scalable).
            errors.append(
                f"keys has {len(keys)} entries (> budget.witnesses={DEFAULT_BUDGET.witnesses}) — "
                "refusing (DoS guard, Finding 15b)")
        else:
            for kid, kv in keys.items():
                key_ids.add(kid)
                if not isinstance(kv, dict) or not isinstance(kv.get("publicKey"), str) or not kv.get("publicKey"):
                    errors.append(f"keys[{kid!r}] must be an object with a base64 'publicKey'")
                    continue
                alg = kv.get("alg", "ed25519")
                if alg not in _KEY_ALGS:
                    errors.append(f"keys[{kid!r}].alg must be one of {_KEY_ALGS}, got {alg!r}")
                is_hybrid = alg == "hybrid-ed25519-mldsa65"
                allowed_fields = ("publicKey", "scheme", "alg") + (("publicKeyPq",) if is_hybrid else ())
                for f in kv:
                    if f not in allowed_fields:
                        errors.append(f"keys[{kid!r}].{f} is not an allowed field")
                # the primary `publicKey` field is the ML-DSA-65 key itself for alg=mldsa65, or the Ed25519
                # classical leg for alg=ed25519 / hybrid-ed25519-mldsa65 (an unrecognised alg is checked as
                # 32-byte Ed25519 too — the "alg must be one of" error above already fail-closes it).
                want_len = _KEY_RAW_LEN["mldsa65"] if alg == "mldsa65" else _KEY_RAW_LEN["ed25519"]
                label = _KEY_ALG_LABEL.get(alg, "Ed25519")
                try:
                    raw = base64.b64decode(kv["publicKey"], validate=True)
                    if len(raw) != want_len:
                        errors.append(f"keys[{kid!r}].publicKey must be a {want_len}-byte {label} key (got {len(raw)})")
                except Exception:  # noqa: BLE001
                    errors.append(f"keys[{kid!r}].publicKey is not valid base64")
                if is_hybrid:
                    pq = kv.get("publicKeyPq")
                    if not isinstance(pq, str) or not pq:
                        errors.append(f"keys[{kid!r}].publicKeyPq is required for alg 'hybrid-ed25519-mldsa65'")
                    else:
                        try:
                            rawpq = base64.b64decode(pq, validate=True)
                            if len(rawpq) != _KEY_RAW_LEN["mldsa65"]:
                                errors.append(
                                    f"keys[{kid!r}].publicKeyPq must be a {_KEY_RAW_LEN['mldsa65']}-byte "
                                    f"ML-DSA-65 key (got {len(rawpq)})")
                        except Exception:  # noqa: BLE001
                            errors.append(f"keys[{kid!r}].publicKeyPq is not valid base64")
                elif "publicKeyPq" in kv:
                    errors.append(f"keys[{kid!r}].publicKeyPq is only allowed for alg 'hybrid-ed25519-mldsa65'")

    # No key aliasing (Sybil, release-review fix): two keyIds mapping to the SAME 32-byte key material dilute
    # every threshold — one physical key would count as N signers. checkpoint.py::witness_quorum learned this
    # for witnesses; the higher-stakes root-of-trust must not regress it. Fail-closed at validate time.
    if isinstance(keys, dict):
        _seen_material: dict[str, str] = {}
        for kid, kv in keys.items():
            if not (isinstance(kv, dict) and isinstance(kv.get("publicKey"), str)):
                continue
            try:
                _mat = base64.b64decode(kv["publicKey"], validate=True).hex()
            except Exception:  # noqa: BLE001
                continue
            if _mat in _seen_material:
                errors.append(
                    f"keys[{kid!r}] duplicates the key material of keys[{_seen_material[_mat]!r}] — key "
                    "aliasing dilutes thresholds (Sybil), fail-closed")
            else:
                _seen_material[_mat] = kid

    revoked = predicate.get("revoked", [])
    if "revoked" in predicate and not (isinstance(revoked, list) and all(isinstance(x, str) for x in revoked)):
        errors.append("revoked must be a list of keyId strings")
        revoked = []
    for rk in revoked if isinstance(revoked, list) else []:
        if rk not in key_ids and "keys" in predicate and isinstance(keys, dict):
            errors.append(f"revoked keyId {rk!r} is not present in keys")

    roles = predicate.get("roles")
    if "roles" in predicate:
        if not isinstance(roles, dict) or "root" not in roles:
            errors.append("roles must be an object that includes a 'root' role")
        else:
            _revoked_set = set(revoked) if isinstance(revoked, list) else set()
            for rname, role in roles.items():
                if rname not in _ROLE_NAMES:
                    errors.append(f"roles.{rname} is not an allowed role name")
                    continue
                errors.extend(f"roles.{rname}: {e}" for e in _validate_role(role, key_ids, _revoked_set))

    nc = predicate.get("nonClaims")
    if "nonClaims" in predicate and not (isinstance(nc, list) and nc and all(isinstance(x, str) for x in nc)):
        errors.append("nonClaims must be a non-empty array of strings (No-Overclaim block is mandatory)")

    return errors


def _validate_role(role: Any, key_ids: set[str], revoked: set[str]) -> list[str]:
    errs: list[str] = []
    if not isinstance(role, dict):
        return ["must be an object"]
    for f in role:
        if f not in ("keyIds", "threshold"):
            errs.append(f"unknown field {f!r}")
    kids = role.get("keyIds")
    th = role.get("threshold")
    if not (isinstance(kids, list) and kids and all(isinstance(x, str) and x for x in kids)):
        errs.append("keyIds must be a non-empty list of key id strings")
        kids = []
    elif not DEFAULT_BUDGET.within("witnesses", len(kids)):
        # Finding 15b: a role's keyIds is a human-curated signer set, not attacker-scalable input.
        errs.append(
            f"keyIds has {len(kids)} entries (> budget.witnesses={DEFAULT_BUDGET.witnesses}) — refusing "
            "(DoS guard, Finding 15b)")
        kids = []
    else:
        for k in kids:
            if key_ids and k not in key_ids:
                errs.append(f"keyId {k!r} is not present in keys")
    if not (_is_int(th) and th >= 1):
        errs.append("threshold must be an integer >= 1")
    elif isinstance(kids, list) and isinstance(th, int) and th > len(kids):
        errs.append(f"threshold ({th}) exceeds the number of keyIds ({len(kids)})")
    # dead-on-arrival: after removing revoked keys the role can never meet threshold.
    if isinstance(kids, list) and _is_int(th) and th >= 1:
        live = [k for k in kids if k not in revoked]
        if len(live) < th:
            errs.append(f"threshold ({th}) can never be met — only {len(live)} non-revoked keyIds")
    return errs


def require_valid_trust_pack_predicate(predicate: Any, *, strict: bool = False) -> None:
    errs = validate_trust_pack_predicate(predicate, strict=strict)
    if errs:
        raise TrustPackError("invalid trust-pack predicate: " + "; ".join(errs))


# ── Emit (threshold-signed) / verify ─────────────────────────────────────────
def _rfc8785_bytes(obj: Any) -> bytes:
    from . import canonical  # noqa: PLC0415
    try:
        return canonical.canonicalize_statement(obj)
    except canonical.CanonicalizerUnavailable as exc:
        raise TrustPackError(
            "trust packs need the RFC 8785 (JCS) canonicalizer — install proofbundle[eval]") from exc


def _rfc8785_available() -> bool:
    try:
        import rfc8785  # noqa: F401, PLC0415
        return True
    except Exception:
        return False


def build_trust_pack_statement(predicate: dict, *, subject_name: str | None = None,
                               subject_sha256: str | None = None) -> dict:
    errs = validate_trust_pack_predicate(predicate, strict=False)
    if errs:
        raise TrustPackError("invalid trust-pack predicate: " + "; ".join(errs))
    name = subject_name or f"trust-pack:{predicate.get('trustPackId', '')}:v{predicate.get('version', '')}"
    sha = subject_sha256 or hashlib.sha256(_rfc8785_bytes(predicate)).hexdigest()
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": name, "digest": {"sha256": sha}}],
        "predicateType": TRUST_PACK_PREDICATE_TYPE,
        "predicate": predicate,
    }


def sign_trust_pack(predicate: dict, signers: dict, *, subject_name: str | None = None,
                    subject_sha256: str | None = None, strict: bool = True) -> dict:
    """Threshold-sign a Trust Pack as a MULTI-signature DSSE in-toto Statement. ``signers`` maps keyId ->
    Ed25519 private key; each produces a ``{keyid, sig}`` entry over the same PAE. Fail-closed: an invalid
    predicate raises before signing; a signer keyId not present in the pack's ``keys`` raises (never sign under
    an unknown identity)."""
    from . import dsse  # noqa: PLC0415
    errs = validate_trust_pack_predicate(predicate, strict=strict)
    if errs:
        raise TrustPackError("invalid trust-pack predicate: " + "; ".join(errs))
    known = set(_as_dict(predicate.get("keys")).keys())
    for kid in signers:
        if kid not in known:
            raise TrustPackError(f"signer keyId {kid!r} is not declared in the pack's keys")
    statement = build_trust_pack_statement(predicate, subject_name=subject_name, subject_sha256=subject_sha256)
    body = _rfc8785_bytes(statement)
    msg = dsse.pae(INTOTO_STATEMENT_PAYLOAD_TYPE, body)
    signatures = [{"keyid": kid, "sig": base64.b64encode(sk.sign(msg)).decode("ascii")}
                  for kid, sk in signers.items()]
    return {"payload": base64.b64encode(body).decode("ascii"),
            "payloadType": INTOTO_STATEMENT_PAYLOAD_TYPE, "signatures": signatures}


def _empty_result() -> dict:
    return {"ok": None, "structure_ok": None, "predicate_type_ok": None, "root_threshold_met": None,
            "not_expired": None, "version_monotone": None, "rotation_authorized": None,
            "root_signers": [], "old_root_signers": [],
            # Finding 01 (2026-07 verify-layer hardening, additive): a uniform automation-safety verdict,
            # computed at the end of verify — never gates anything above, `ok` is unchanged.
            "automation": None,
            "warnings": [], "errors": []}


def _finalize_failclosed(r: dict) -> dict:
    """RE-GATE never-raise (MJSON-TP-01): a budget/parse/malformed-envelope failure over untrusted input
    yields ok=False plus a consistent automation verdict (safeForAutomation=False) — the SAME shape as a
    full run, never a raw exception out of this dict-returning verify surface (mirrors decision/outcome)."""
    from .automation_verdict import automation_summary  # noqa: PLC0415
    r["ok"] = False
    r["automation"] = automation_summary(r, required_checks=_AUTOMATION_REQUIRED_CHECKS)
    return r


def _verify_signature_for_alg(alg: str, pub: bytes, pq_pub_b64: Any, entry: dict, msg: bytes) -> bool:
    """True iff ``entry`` (``{"keyid":, "sig":[, "sigPq":]}``) carries a valid signature over ``msg`` for a
    root / old-root key of algorithm ``alg`` (``ed25519`` | ``mldsa65`` | ``hybrid-ed25519-mldsa65``), whose
    classical/primary public key is the already-decoded ``pub`` bytes (``keys[kid].publicKey``); ``pq_pub_b64``
    is the still-base64 ``publicKeyPq`` (the ML-DSA-65 leg), used only for ``hybrid-ed25519-mldsa65``.

    Fail-closed, mirrors ``renewal._verify_ats_signature``: a missing/malformed leg is False, never a
    fallback to a weaker check — a hybrid key is NEVER satisfied by only its Ed25519 ``sig`` leg (no
    downgrade); the ``sigPq`` leg over ``publicKeyPq`` MUST also verify. The alg label itself cannot be
    forged in isolation: it lives inside the signed predicate, so relabeling it invalidates every signature
    over this pack (no separate alg-confusion surface, unlike a JWT ``alg`` header)."""
    from .pqsig import PQUnavailable, verify_hybrid, verify_mldsa  # noqa: PLC0415
    from .signature import verify_ed25519  # noqa: PLC0415
    sig_b64 = entry.get("sig")
    # Bug-hunt follow-up (3.6.2): verify_mldsa / verify_hybrid raise PQUnavailable when the running
    # `cryptography` has no FIPS-204 (ML-DSA) build. That escaped this bool-returning helper (and its two
    # trust_pack verify callers) as a RAW crash on an untrusted trust-pack that names an ML-DSA root key.
    # A signature we cannot verify is not a valid signature: return False (fail-closed — the signer simply
    # does not count toward the threshold), never a raw exception out of the never-raise verify surface.
    if alg == "mldsa65":
        if not isinstance(sig_b64, str):
            return False
        try:
            sig = base64.b64decode(sig_b64, validate=True)
        except Exception:  # noqa: BLE001
            return False
        try:
            return verify_mldsa(pub, sig, msg, level="mldsa65")
        except PQUnavailable:
            return False
    if alg == "hybrid-ed25519-mldsa65":
        sig_pq_b64 = entry.get("sigPq")
        if not isinstance(pq_pub_b64, str) or not isinstance(sig_b64, str) or not isinstance(sig_pq_b64, str):
            return False
        try:
            sig = base64.b64decode(sig_b64, validate=True)
            pq_pub = base64.b64decode(pq_pub_b64, validate=True)
            sig_pq = base64.b64decode(sig_pq_b64, validate=True)
        except Exception:  # noqa: BLE001
            return False
        try:
            return verify_hybrid(classical_pub=pub, classical_sig=sig, pq_pub=pq_pub, pq_sig=sig_pq, message=msg)
        except PQUnavailable:
            return False
    # default / "ed25519" (an unrecognised alg on prev_root_keys — caller-supplied trust material, outside
    # the predicate's own schema gate — safely falls back to the classical check rather than raising).
    if not isinstance(sig_b64, str):
        return False
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except Exception:  # noqa: BLE001
        return False
    return verify_ed25519(pub, sig, msg)


def verify_trust_pack(envelope: dict, *, strict: bool = False, now: datetime | None = None,
                      prev_version: int | None = None, prev_version_digest: str | None = None,
                      prev_root_keys: dict | None = None, prev_root_threshold: int | None = None,
                      allow_unverified_rotation: bool = False) -> dict:
    """Verify a threshold-signed Trust Pack. Unlike a plain DSSE verify (any-single-sig) this counts DISTINCT
    non-revoked ROOT KEY MATERIAL with a valid signature and requires >= the root threshold.

    Checks (each fail-closed): ``root_threshold_met`` (>= threshold distinct valid non-revoked root sigs, by key
    material not keyId label); ``not_expired`` (expires > now); ``version_monotone`` (version > prev_version when
    supplied — rollback/freeze protection) and, when ``prev_version_digest`` is supplied, the pack's
    ``prevVersionDigest`` MUST equal it (chain to the previous pack).

    ROTATION AUTHORIZATION (two-stage, release-review fix): when ``prev_root_keys`` (a ``{keyId: publicKey_b64}``
    map of the PREVIOUS pack's root role) and ``prev_root_threshold`` are supplied, a threshold of the OLD root
    keys MUST also have validly signed THIS pack (old root vouches for the new pack). Without this the documented
    two-stage rotation was documentation-only: ``prevVersionDigest`` is a hash of PUBLIC bytes (no key needed), so
    anyone could mint a ``v2`` naming self-owned keys and chain it to a real ``v1``. Read ``ok`` — never a field
    alone."""
    from . import dsse  # noqa: PLC0415
    r = _empty_result()
    try:
        # RE-GATE never-raise (MJSON-TP-01): trust_pack takes NO public_key and never calls verify_envelope,
        # so its budget/signature-shape/parse raises originate in its OWN body. An oversized payload, a >512
        # signatures array (BudgetExceeded), a non-list `signatures` (BundleFormatError), or a malformed
        # payload must ALL be a fail-closed verdict, never a raw exception out of this dict-returning verify
        # surface (mirrors decision/outcome — BudgetExceeded is a ProofBundleError the old narrow except
        # missed). The documented BundleFormatError raise on non-list signatures is now surfaced as the
        # fail-closed verdict + errors[] entry instead.
        body = dsse.load_payload(envelope)
        # Finding 15b: refuse an absurdly oversized payload BEFORE any JSON parsing/canonicalization work runs.
        DEFAULT_BUDGET.check("input_bytes", len(body))
        _sigs = envelope.get("signatures")
        # Fail-closed on a non-list signatures (crypto-review 2026-07-15): a truthy non-list (JSON true, a
        # number, a huge dict) previously skipped the cap entirely — a 2M-key dict then reached the threshold
        # loop uncapped. Match dsse.verify_envelope's contract: signatures MUST be a non-empty list, then cap.
        if not isinstance(_sigs, list) or not _sigs:
            raise BundleFormatError("DSSE envelope.signatures must be a non-empty list")
        DEFAULT_BUDGET.check("signatures", len(_sigs))
        # O7 payloadType-binding defense-in-depth (3.6.0): the threshold loop below binds its PAE to the
        # INTOTO_STATEMENT constant (already the STRONG binding). Pin the envelope.payloadType FIELD too,
        # fail-closed: a confused / mislabelled envelope must not pass the field through unexamined.
        env_ptype = envelope.get("payloadType")
        if env_ptype != INTOTO_STATEMENT_PAYLOAD_TYPE:
            r["structure_ok"] = False
            r["predicate_type_ok"] = False
            r["errors"].append(
                f"envelope.payloadType is {env_ptype!r}, expected {INTOTO_STATEMENT_PAYLOAD_TYPE!r} "
                "(payloadType-confusion, fail-closed)")
            return _finalize_failclosed(r)
        statement = loads_strict(body.decode("utf-8"))
    except (ProofBundleError, ValueError, UnicodeDecodeError) as exc:
        r["structure_ok"] = False
        r["errors"].append(f"trust pack envelope is malformed or over-limit (fail-closed): {exc}")
        return _finalize_failclosed(r)

    ptype = statement.get("predicateType") if isinstance(statement, dict) else None
    r["predicate_type_ok"] = ptype == TRUST_PACK_PREDICATE_TYPE
    if not r["predicate_type_ok"]:
        r["errors"].append(f"predicateType is {ptype!r}, expected trust-pack/v0.1 (confusion attack?)")

    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    struct_errs = validate_trust_pack_predicate(predicate, strict=strict)
    r["errors"].extend(struct_errs)

    canonical_ok = None
    if _rfc8785_available():
        try:
            canonical_ok = _rfc8785_bytes(statement) == body
        except Exception:
            canonical_ok = False
        if canonical_ok is False:
            r["errors"].append("payload is not RFC-8785 canonical (hash_binding fail-closed)")
    else:
        # PB-06 parity (rfc8785 is now a declared CORE dependency): an absent canonicalizer is a broken
        # install, not a lenient mode — fail closed REGARDLESS of strict (mirrors decision.py).
        r["errors"].append(
            "RFC-8785 (JCS) canonicalizer unavailable — proofbundle requires rfc8785 (core dependency); "
            "hash_binding fail-closed, cannot verify canonicality")
    canonicality_ok = canonical_ok is True  # absent (None) or non-canonical (False) never passes (fail-closed)
    r["structure_ok"] = (not struct_errs) and bool(r["predicate_type_ok"]) and canonicality_ok

    if not isinstance(predicate, dict) or struct_errs:
        r["ok"] = False
        from .automation_verdict import automation_summary  # noqa: PLC0415
        r["automation"] = automation_summary(r, required_checks=_AUTOMATION_REQUIRED_CHECKS)
        return r

    # Threshold-of-root over the EXACT signed bytes.
    keys = _as_dict(predicate.get("keys"))
    revoked = set(_as_list(predicate.get("revoked")))
    root = _as_dict(_as_dict(predicate.get("roles")).get("root"))
    root_ids = [k for k in _as_list(root.get("keyIds")) if k not in revoked]
    threshold = root.get("threshold")
    msg = dsse.pae(INTOTO_STATEMENT_PAYLOAD_TYPE, body)
    # Count DISTINCT KEY MATERIAL, not keyId labels (defense-in-depth beyond the validator's aliasing check):
    # one physical key registered under N keyIds is ONE root signer. Mirrors checkpoint.py::witness_quorum.
    # Alg-aware (crypto agility, ADR 0006): keys[kid].alg selects ed25519 (default) / mldsa65 / hybrid — the
    # alg label lives INSIDE the signed predicate, so an attacker cannot relabel a key without invalidating
    # every signature over this pack.
    valid_root: dict[bytes, str] = {}
    for entry in _as_list(envelope.get("signatures")):
        if not isinstance(entry, dict):
            continue
        kid = entry.get("keyid")
        if not isinstance(kid, str) or kid not in root_ids:
            continue
        kv = keys.get(kid)
        if not isinstance(kv, dict):
            continue
        pub_b64 = kv.get("publicKey")
        if not isinstance(pub_b64, str):
            continue
        try:
            pub = base64.b64decode(pub_b64, validate=True)
        except Exception:  # noqa: BLE001
            continue
        if pub in valid_root:  # same key material already counted — aliasing cannot inflate the threshold
            continue
        alg = kv.get("alg", "ed25519")
        if _verify_signature_for_alg(alg, pub, kv.get("publicKeyPq"), entry, msg):
            valid_root[pub] = kid
    r["root_signers"] = sorted(valid_root.values())
    r["root_threshold_met"] = _is_int(threshold) and len(valid_root) >= threshold
    if not r["root_threshold_met"]:
        r["errors"].append(
            f"root signature threshold not met: {len(valid_root)} valid non-revoked root signature(s), "
            f"need {threshold}")

    # Expiry.
    _now = now or datetime.now(timezone.utc)
    try:
        exp = _parse_rfc3339_z(predicate["expires"])
        r["not_expired"] = exp > _now
    except (ValueError, KeyError, TypeError):
        r["not_expired"] = False
    if r["not_expired"] is False:
        r["errors"].append("trust pack is expired (expires <= now, fail-closed)")

    # Version monotonicity + chain to previous pack.
    if prev_version is not None:
        # Berkeley r6: prev_version kwarg (dok. 'int | None') non-int -> nicht-monoton (fail-closed), kein int>str-Crash
        r["version_monotone"] = (_is_int(predicate.get("version")) and _is_int(prev_version)
                                 and predicate["version"] > prev_version)
        if not r["version_monotone"]:
            r["errors"].append(
                f"version {predicate.get('version')!r} is not greater than the previous version "
                f"{prev_version} (rollback/freeze, fail-closed)")
    if prev_version_digest is not None:
        pvd = predicate.get("prevVersionDigest")
        pvd_hex = pvd.get("sha256") if _is_digest(pvd) else None
        if pvd_hex != prev_version_digest:
            r["version_monotone"] = False
            r["errors"].append("prevVersionDigest does not chain to the supplied previous pack (fail-closed)")

    # Two-stage rotation authorization: the OLD root threshold must ALSO have signed this pack (old root vouches
    # for new). Counts DISTINCT old-root KEY MATERIAL over the exact PAE, using the PREVIOUS pack's key map (the
    # signing keyIds belong to the old pack, not necessarily this pack's `keys`). Only enforced when the caller
    # supplies the previous root role — a first pack / non-rotation verify is unaffected (field stays None).
    if prev_root_keys is not None or prev_root_threshold is not None:
        old_keys = _as_dict(prev_root_keys)  # Berkeley r6: bare kwarg, truthy non-dict -> {} statt 'in'-Crash
        old_valid: dict[bytes, str] = {}
        for entry in _as_list(envelope.get("signatures")):
            if not isinstance(entry, dict):
                continue
            kid = entry.get("keyid")
            if not isinstance(kid, str) or kid not in old_keys:
                continue
            _ok = old_keys[kid]
            # backward compatible: a bare base64 string (legacy callers, ed25519-only) or a full key object
            # ({"publicKey":, "alg":, "publicKeyPq":}) for crypto-agile rotation vouching. An unrecognised
            # alg on this caller-supplied trust material defaults to ed25519 rather than raising.
            if isinstance(_ok, str):
                old_alg, pub_b64, pq_pub_b64 = "ed25519", _ok, None
            elif isinstance(_ok, dict):
                old_alg = _ok.get("alg", "ed25519")
                if old_alg not in _KEY_ALGS:
                    old_alg = "ed25519"
                pub_b64, pq_pub_b64 = _ok.get("publicKey"), _ok.get("publicKeyPq")
            else:
                continue
            if not isinstance(pub_b64, str):
                continue
            try:
                pub = base64.b64decode(pub_b64, validate=True)
            except Exception:  # noqa: BLE001
                continue
            if pub in old_valid:
                continue
            if _verify_signature_for_alg(old_alg, pub, pq_pub_b64, entry, msg):
                old_valid[pub] = kid
        r["old_root_signers"] = sorted(old_valid.values())
        # prev_root_threshold MUST be a positive int: 0/None/negative would "authorize" a rotation with zero
        # old-root vouches (self-review fix, fail-closed defense-in-depth — a correct caller passes the old
        # pack's root threshold, which the validator already guarantees >= 1).
        r["rotation_authorized"] = (_is_int(prev_root_threshold) and prev_root_threshold >= 1
                                    and len(old_valid) >= prev_root_threshold)
        if not r["rotation_authorized"]:
            r["errors"].append(
                f"rotation not authorized by old root: {len(old_valid)} distinct old-root signature(s), "
                f"need {prev_root_threshold} (old root must vouch for the new pack, fail-closed)")
    elif _is_digest(predicate.get("prevVersionDigest")):
        # The pack CLAIMS to be a rotation (non-null prevVersionDigest) but the caller did not supply the
        # previous root role, so two-stage rotation authorization cannot be checked. FAIL CLOSED by default:
        # a v2 minting self-owned keys + a real v1 digest would otherwise pass on its own self-signature
        # (the exact footgun this predicate defends against). A caller that deliberately wants only a
        # standalone self-signature check opts out explicitly with allow_unverified_rotation=True.
        if allow_unverified_rotation:
            r["warnings"].append(
                "this pack declares a prevVersionDigest (claims to be a rotation) but rotation authorization "
                "was NOT verified (allow_unverified_rotation=True) — this proves only self-signature by the "
                "pack's own declared root, NOT that the old root vouches for it")
        else:
            r["rotation_authorized"] = False
            r["errors"].append(
                "this pack declares a prevVersionDigest (claims to be a rotation) but rotation authorization "
                "was NOT verified — pass prev_root_keys + prev_root_threshold to confirm the old root vouches "
                "for it, or allow_unverified_rotation=True to accept a self-signature-only check (fail-closed)")

    r["ok"] = bool(
        r["structure_ok"] and r["predicate_type_ok"] and r["root_threshold_met"]
        and r["not_expired"] and r["version_monotone"] is not False
        and r["rotation_authorized"] is not False)

    # Finding 01 (additive): a uniform automation-safety verdict — never changes `ok` above. A trust pack
    # has no separate policy/authorization layer (it IS the root of trust), so "policy" is not applicable.
    from .automation_verdict import automation_summary  # noqa: PLC0415
    r["automation"] = automation_summary(r, required_checks=_AUTOMATION_REQUIRED_CHECKS)
    return r
