"""Trust Pack predicate `trust-pack/v0.1` — hand-rolled, fail-closed validation + threshold verify.

proofbundle 3.2.0 O2 (EXPERIMENTAL). A TUF-inspired, signed root of trust: each role (root, evalIssuers,
decisionMakers, outcomeExecutors, timeAuthorities, witnesses) maps to a set of key ids and a signature
threshold; a keyId->publicKey map resolves them; a monotone ``version`` with a ``prevVersionDigest`` chain
gives rollback/freeze protection; ``expires`` bounds validity; ``revoked`` is an offline revocation list.

The ``outcomeExecutors`` role supplies the identity that an Action Outcome Receipt (O1) executor is checked
against. A Trust Pack is authenticated by a THRESHOLD of its root keys (not any-single, unlike a plain DSSE
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
from typing import Any

from ._strict_json import loads_strict
from .errors import BundleFormatError, ProofBundleError

TRUST_PACK_PREDICATE_TYPE = "https://b7n0de.com/proofbundle/predicates/trust-pack/v0.1"
TRUST_PACK_SCHEMA_VERSION = "0.1.0"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
INTOTO_STATEMENT_PAYLOAD_TYPE = "application/vnd.in-toto+json"

_RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_SEMVER_0_1_X = re.compile(r"^0\.1\.\d+$")

_ROLE_NAMES = ("root", "evalIssuers", "decisionMakers", "outcomeExecutors", "timeAuthorities", "witnesses")
_REQUIRED_ALWAYS = ("schemaVersion", "trustPackId", "version", "expires", "prevVersionDigest",
                    "roles", "keys", "nonClaims")
_OPTIONAL = ("revoked",)
_ALLOWED_TOP = set(_REQUIRED_ALWAYS) | set(_OPTIONAL)


class TrustPackError(ProofBundleError):
    """A Trust Pack predicate is malformed (fail-closed)."""


def _is_digest(obj: Any) -> bool:
    return isinstance(obj, dict) and isinstance(obj.get("sha256"), str) and bool(_SHA256_HEX.match(obj["sha256"]))


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def validate_trust_pack_predicate(predicate: Any, *, strict: bool = False) -> list[str]:
    """Return fail-closed errors for a ``trust-pack/v0.1`` predicate (empty = valid).

    Beyond shape this enforces: threshold in 1..len(keyIds) per role; every keyId referenced by a role is
    present in ``keys``; ``revoked`` entries are known keyIds; a role's threshold is not already impossible
    once revoked keys are removed (a pack whose root can never meet threshold is dead-on-arrival, fail-closed).
    """
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

    keys = predicate.get("keys")
    key_ids: set[str] = set()
    if "keys" in predicate:
        if not isinstance(keys, dict) or not keys:
            errors.append("keys must be a non-empty object mapping keyId -> {publicKey}")
        else:
            for kid, kv in keys.items():
                key_ids.add(kid)
                if not isinstance(kv, dict) or not isinstance(kv.get("publicKey"), str) or not kv.get("publicKey"):
                    errors.append(f"keys[{kid!r}] must be an object with a base64 'publicKey'")
                    continue
                for f in kv:
                    if f not in ("publicKey", "scheme"):
                        errors.append(f"keys[{kid!r}].{f} is not an allowed field")
                try:
                    raw = base64.b64decode(kv["publicKey"], validate=True)
                    if len(raw) != 32:
                        errors.append(f"keys[{kid!r}].publicKey must be a 32-byte Ed25519 key (got {len(raw)})")
                except Exception:  # noqa: BLE001
                    errors.append(f"keys[{kid!r}].publicKey is not valid base64")

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
    else:
        for k in kids:
            if key_ids and k not in key_ids:
                errs.append(f"keyId {k!r} is not present in keys")
    if not (_is_int(th) and th >= 1):
        errs.append("threshold must be an integer >= 1")
    elif isinstance(kids, list) and th > len(kids):
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
    known = set((predicate.get("keys") or {}).keys())
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
            "root_signers": [], "old_root_signers": [], "warnings": [], "errors": []}


def verify_trust_pack(envelope: dict, *, strict: bool = False, now: datetime | None = None,
                      prev_version: int | None = None, prev_version_digest: str | None = None,
                      prev_root_keys: dict | None = None, prev_root_threshold: int | None = None) -> dict:
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
    from .signature import verify_ed25519  # noqa: PLC0415
    r = _empty_result()
    body = dsse.load_payload(envelope)
    try:
        statement = loads_strict(body.decode("utf-8"))
    except BundleFormatError:
        r["structure_ok"] = False
        r["errors"].append("DSSE payload rejected (duplicate JSON key or malformed)")
        raise
    except (ValueError, UnicodeDecodeError) as exc:
        r["structure_ok"] = False
        r["errors"].append("DSSE payload is not a JSON in-toto Statement")
        raise BundleFormatError("DSSE payload is not a JSON in-toto Statement") from exc

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
    elif strict:
        r["errors"].append("cannot verify RFC-8785 canonicality (install proofbundle[eval]); fail-closed in strict mode")
    else:
        r["warnings"].append("rfc8785 not installed: hash_binding canonicality not checked")
    canonicality_ok = canonical_ok is True or (canonical_ok is None and not strict)
    r["structure_ok"] = (not struct_errs) and bool(r["predicate_type_ok"]) and canonicality_ok

    if not isinstance(predicate, dict) or struct_errs:
        r["ok"] = False
        return r

    # Threshold-of-root over the EXACT signed bytes.
    keys = predicate.get("keys") or {}
    revoked = set(predicate.get("revoked") or [])
    root = (predicate.get("roles") or {}).get("root") or {}
    root_ids = [k for k in (root.get("keyIds") or []) if k not in revoked]
    threshold = root.get("threshold")
    msg = dsse.pae(INTOTO_STATEMENT_PAYLOAD_TYPE, body)
    # Count DISTINCT KEY MATERIAL, not keyId labels (defense-in-depth beyond the validator's aliasing check):
    # one physical key registered under N keyIds is ONE root signer. Mirrors checkpoint.py::witness_quorum.
    valid_root: dict[bytes, str] = {}
    for entry in envelope.get("signatures") or []:
        if not isinstance(entry, dict):
            continue
        kid = entry.get("keyid")
        raw = entry.get("sig")
        if kid not in root_ids or not isinstance(raw, str):
            continue
        try:
            pub = base64.b64decode(keys[kid]["publicKey"], validate=True)
            sig = base64.b64decode(raw, validate=True)
        except Exception:  # noqa: BLE001
            continue
        if pub in valid_root:  # same key material already counted — aliasing cannot inflate the threshold
            continue
        if verify_ed25519(pub, sig, msg):
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
        exp = datetime.strptime(predicate["expires"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        r["not_expired"] = exp > _now
    except (ValueError, KeyError):
        r["not_expired"] = False
    if r["not_expired"] is False:
        r["errors"].append("trust pack is expired (expires <= now, fail-closed)")

    # Version monotonicity + chain to previous pack.
    if prev_version is not None:
        r["version_monotone"] = _is_int(predicate.get("version")) and predicate["version"] > prev_version
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
        old_keys = prev_root_keys or {}
        old_valid: dict[bytes, str] = {}
        for entry in envelope.get("signatures") or []:
            if not isinstance(entry, dict):
                continue
            kid = entry.get("keyid")
            raw = entry.get("sig")
            if kid not in old_keys or not isinstance(raw, str):
                continue
            _pk = old_keys[kid]
            _pk = _pk.get("publicKey") if isinstance(_pk, dict) else _pk
            if not isinstance(_pk, str):
                continue
            try:
                pub = base64.b64decode(_pk, validate=True)
                sig = base64.b64decode(raw, validate=True)
            except Exception:  # noqa: BLE001
                continue
            if pub in old_valid:
                continue
            if verify_ed25519(pub, sig, msg):
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

    r["ok"] = bool(
        r["structure_ok"] and r["predicate_type_ok"] and r["root_threshold_met"]
        and r["not_expired"] and r["version_monotone"] is not False
        and r["rotation_authorized"] is not False)
    return r
