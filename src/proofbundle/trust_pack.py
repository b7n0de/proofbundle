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
import json
import re
from datetime import datetime, timezone
from typing import Any, TypeGuard

from ._membership import require_switch, type_name
from ._statement_payload import load_statement_strict
from .budget import DEFAULT_BUDGET
from .canonical import (KEIN_ZEITPUNKT, _ein_stand, _eine_kopie, _pruefkopie, _richtlinie_von,
                        _zeichen_von, _zeitpunkt_von)
from .errors import BundleFormatError, ProofBundleError
from .signature import TRUST_ANCHOR_REFUSAL, ed25519_trust_anchor_weakness
from ._wire_b64 import decode_b64

TRUST_PACK_PREDICATE_TYPE = "https://b7n0de.com/proofbundle/predicates/trust-pack/v0.1"
TRUST_PACK_SCHEMA_VERSION = "0.1.0"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
INTOTO_STATEMENT_PAYLOAD_TYPE = "application/vnd.in-toto+json"

# The schema's patterns in their ECMA-262 meaning (JSON Schema 2020-12 names that dialect for
# `pattern`): `$` is the end of the input and `\d` is [0-9]. Under Python `re`, `$` also matches before a
# final newline and `\d` matches every Unicode decimal digit, so these are written `\A..\Z` with [0-9]
# (round 11, lens run 10 at fa555f13, finding L8: a hex digest, `expires` and `schemaVersion` with a
# trailing newline, and `expires`/`schemaVersion` with Arabic-Indic digits, validated as []).
_RFC3339_Z = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z\Z")
_SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")
_SEMVER_0_1_X = re.compile(r"\A0\.1\.[0-9]+\Z")

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
# `crypto_ok`, only the threshold check).
# N43 (security-fix 6.2.0): the "policy" dimension is `pinned`. A Trust Pack is the ROOT of trust, so it has
# no EXTERNAL policy layer above it — but a root is trusted only because a RELYING PARTY pinned it out of
# band (a genesis/content-root digest, a root-key set, or a rotation whose pinned predecessor vouched). That
# binding IS the authorization dimension for automation: `safeForAutomation` is positive only under an RP
# anchor. `pinned` is None (no anchor supplied → POLICY_NOT_EVALUATED) / False (anchor supplied, no match →
# POLICY_FAILED) / True (bound). It does NOT feed `ok`, which stays the self-authentication verdict (form,
# threshold, expiry, chain) — see `trust_pack_is_pinned` and `verify_trust_pack`'s `ok`/`pinned` split.
_AUTOMATION_REQUIRED_CHECKS = {
    "crypto": "root_threshold_met", "structure": "structure_ok", "policy": "pinned",
    "references": ["not_expired", "version_monotone", "rotation_authorized"],
}


def _as_dict(v):
    """adversarial re-audit r5/r6 class-fix: Config-Sub-Feld als dict, sonst {} (das ``_as_dict(x.get(k))``-Idiom ersetzte nur FALSY)."""
    return v if isinstance(v, dict) else {}


def _as_list(v):
    return v if isinstance(v, (list, tuple)) else []


class TrustPackError(ProofBundleError):
    """A Trust Pack predicate is malformed (fail-closed)."""


def _is_digest(obj: Any) -> TypeGuard[dict]:
    return isinstance(obj, dict) and isinstance(obj.get("sha256"), str) and bool(_SHA256_HEX.match(obj["sha256"]))


def _zahl_text(v: Any) -> str:
    """A relying party's number for a message: an exact int as its digits, any other value by its type only,
    so rendering it runs none of the caller's methods (deep gate 6.2.0 at 2348f0a7, the number axis)."""
    return int.__repr__(v) if type(v) is int else f"a value of type {type_name(v)}"


def _is_int(v: Any) -> TypeGuard[int]:
    return isinstance(v, int) and not isinstance(v, bool)


def _parse_rfc3339_z(s: str) -> datetime:
    """Parse an RFC-3339 UTC 'Z' timestamp, tolerating optional fractional seconds of ANY length.

    ``_RFC3339_Z`` accepts ``(\\.[0-9]+)?`` fractional seconds, but ``strptime`` with ``%S`` (no ``%f``) rejects
    them, and ``%f`` itself caps at 6 digits — so an ``expires`` like ``...T00:00:00.5Z`` (regex-valid) would
    raise and be read as EXPIRED (a false-closed availability bug). This parser splits off the fractional part
    and truncates it to microseconds (enough for an expiry comparison). Raises ``ValueError`` on a non-match."""
    m = re.match(r"\A([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]+))?Z\Z", s)
    if not m:
        raise ValueError(f"not an RFC-3339 UTC 'Z' timestamp: {s!r}")
    dt = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    frac = m.group(2)
    if frac:
        dt = dt.replace(microsecond=int((frac + "000000")[:6]))
    return dt


@_ein_stand
def validate_trust_pack_predicate(predicate: Any, *, strict: bool = False) -> list[str]:
    """Return fail-closed errors for a ``trust-pack/v0.1`` predicate (empty = valid).

    Beyond shape this enforces: threshold in 1..len(keyIds) per role; every keyId referenced by a role is
    present in ``keys``; ``revoked`` entries are known keyIds; a role's threshold is not already impossible
    once revoked keys are removed (a pack whose root can never meet threshold is dead-on-arrival, fail-closed);
    a ``version`` > 1 pack MUST carry a non-null ``prevVersionDigest`` (only version 1 may be a genesis).

    ``strict`` currently adds no extra predicate-level required fields (the trust-pack predicate is small and
    fully required by default); it is kept for signature parity with the emit/verify entry points, where it
    additionally makes RFC-8785 canonicality fail-closed in ``verify_trust_pack`` (mirrors ``outcome.py``)."""
    try:
        predicate = _pruefkopie(predicate)   # one reading, by what it stores (round 12)
    except ValueError as exc:
        return [f"predicate is not a JSON value: {exc}"]
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
                    raw = decode_b64(kv["publicKey"])
                    if len(raw) != want_len:
                        errors.append(f"keys[{kid!r}].publicKey must be a {want_len}-byte {label} key (got {len(raw)})")
                    elif want_len == _KEY_RAW_LEN["ed25519"]:
                        # A pack IS the root of trust, so its Ed25519 keys get the trust-anchor rule the
                        # policy loader applies to a pinned key (deep gate Z195, L1-Z195-01): a low-order
                        # key lets a signature made with no secret count toward a threshold, and a second
                        # encoding of one point would count twice. The reason text is the shared one.
                        weakness = ed25519_trust_anchor_weakness(raw)
                        if weakness is not None:
                            errors.append(
                                f"keys[{kid!r}].publicKey is a {weakness} {label} key — "
                                f"{TRUST_ANCHOR_REFUSAL[weakness]} (fail-closed)")
                except Exception:  # noqa: BLE001
                    errors.append(f"keys[{kid!r}].publicKey is not valid base64")
                if is_hybrid:
                    pq = kv.get("publicKeyPq")
                    if not isinstance(pq, str) or not pq:
                        errors.append(f"keys[{kid!r}].publicKeyPq is required for alg 'hybrid-ed25519-mldsa65'")
                    else:
                        try:
                            rawpq = decode_b64(pq)
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
                _mat = decode_b64(kv["publicKey"]).hex()
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


@_ein_stand
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


def _read_once(predicate: Any) -> Any:
    """The caller's predicate read ONCE: its RFC 8785 bytes, parsed back into plain JSON values.

    WHAT IS VALIDATED IS WHAT IS SIGNED (lens run 7 at 75c3aa48, F2). The validator read each key
    through the decoder, which called the caller's own `encode`, and through the caller's containers
    (`get`, `__getitem__`), while the canonicaliser wrote what `dict(obj)` yields (the storage, or the
    subclass's `keys()` and `__getitem__` when it overrides `__iter__`; lens run 8, finding H) and the
    text each `str` holds. A `str` subclass whose `encode` answers for a real key and whose text is
    the base64 of the identity point passed the validator and was signed into the pack by
    `sign_trust_pack` and written by `build_trust_pack_statement`; a `dict` subclass whose `get` and
    `__getitem__` answer for a real key while its stored item is the weak one did the same. Now the
    predicate is written once, and the validator, the subject digest and the signature all read the
    parse of those bytes, in which every value is a plain `dict`, `list`, `str`, `int`, `float`,
    `bool` or None, so no method of the caller's runs after that one write. A predicate that cannot
    be written as RFC 8785 JSON is invalid and raises `TrustPackError`, never another exception.

    `json.loads`, not the Statement oracle: the bytes are this function's own RFC 8785 output of a
    predicate, not a received Statement, so they hold no duplicate key and no `_type` to judge, and
    the canonicaliser has already held the value to the structure budget. The received side keeps
    `load_statement_strict` (tests/test_a_statement_says_it_is_an_in_toto_statement.py).

    THE CANONICALISER WAS NOT YET THE ONE READ (lens run 8 at fddc00f4, finding D). It read a number
    through the caller's `__float__` and `__int__` and a dict subclass through `dict(obj)`, which runs
    the subclass's `keys()` and `__getitem__` when it overrides `__iter__`: a float subclass storing
    1.5 whose `__float__` answers 1.0 was signed as version 1, and a `numpy.float64(1.0)` as well, where
    75c3aa48 and main refused both. So the predicate is first copied from its storage by
    `_plain_value.plain_json`, which refuses a subclass of `int` or `float` and a numpy scalar, and only
    that plain copy is canonicalised. An exact float of integral value (`1.0`) and a tuple keep being
    signed as round 8 decided: the RFC 8785 form writes them as the integer and the array."""
    from ._plain_value import plain_json  # noqa: PLC0415
    plain = plain_json(predicate, what="the trust-pack predicate",
                       error=lambda m: TrustPackError(f"invalid trust-pack predicate: {m}"))
    try:
        return json.loads(_rfc8785_bytes(plain))
    except TrustPackError:
        raise
    except Exception as exc:  # noqa: BLE001 — whatever cannot be written is no valid predicate
        # The cause is chained, not formatted: its name and text may be the caller's own code.
        raise TrustPackError("invalid trust-pack predicate: it cannot be written as RFC 8785 JSON "
                             "within the structure budget") from exc


@_ein_stand
def build_trust_pack_statement(predicate: dict, *, subject_name: str | None = None,
                               subject_sha256: str | None = None) -> dict:
    predicate = _read_once(predicate)
    predicate = _eine_kopie(predicate, TrustPackError, "trust-pack predicate")   # one reading (round 12)
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


@_ein_stand(aussen={"signers": "signierer_je_name"})
def sign_trust_pack(predicate: dict, signers: dict, *, subject_name: str | None = None,
                    subject_sha256: str | None = None, strict: bool = True) -> dict:
    """Threshold-sign a Trust Pack as a MULTI-signature DSSE in-toto Statement. ``signers`` maps keyId ->
    Ed25519 private key; each produces a ``{keyid, sig}`` entry over the same PAE. Fail-closed: an invalid
    predicate raises before signing; a signer keyId not present in the pack's ``keys`` raises (never sign under
    an unknown identity). The predicate is read once (`_read_once`): what is validated is what is
    signed.

    ``strict`` (default True) must be a bool; anything else raises
    :class:`~proofbundle.errors.SwitchTypeError` before the predicate is validated or signed. The validator
    reads no ``strict`` today, so nothing relaxed yet; the check keeps a falsy value that is not a bool
    from relaxing it the day the validator does (``emit_decision_receipt`` shows the shape)."""
    from . import dsse  # noqa: PLC0415
    require_switch(strict, "strict")
    from .signature import plain_text  # noqa: PLC0415
    predicate = _read_once(predicate)
    predicate = _eine_kopie(predicate, TrustPackError, "trust-pack predicate")   # one reading (round 12)
    errs = validate_trust_pack_predicate(predicate, strict=strict)
    if errs:
        raise TrustPackError("invalid trust-pack predicate: " + "; ".join(errs))
    known = set(_as_dict(predicate.get("keys")).keys())
    # THE SIGNERS MAP IS READ ONCE, from its storage (lens run 8 at fddc00f4, finding B). The check
    # iterated `for kid in signers` and the signing loop read `signers.items()`: a dict subclass whose
    # `__iter__` yields a declared keyId while its `items()` yields another was signed under the
    # undeclared one, and so was a `str` subclass keyId whose text is undeclared while it hashes and
    # compares as a declared one. Now the stored pairs are read through `dict.items`, each keyId as the
    # text it holds, and the check and the signatures use that list.
    if not issubclass(type(signers), dict):
        raise TrustPackError(f"signers must be a dict mapping keyId -> private key, got {type(signers).__name__}")
    paare: list = []
    for roh_kid, sk in list(dict.items(signers)):
        kid = plain_text(roh_kid)
        if kid is None:
            raise TrustPackError(f"signer keyId must be text, got {type(roh_kid).__name__}")
        if kid not in known:
            raise TrustPackError(f"signer keyId {kid!r} is not declared in the pack's keys")
        if any(kid == frueher for frueher, _ in paare):
            raise TrustPackError(f"signer keyId {kid!r} is named twice")
        paare.append((kid, sk))
    statement = build_trust_pack_statement(predicate, subject_name=subject_name, subject_sha256=subject_sha256)
    body = _rfc8785_bytes(statement)
    msg = dsse.pae(INTOTO_STATEMENT_PAYLOAD_TYPE, body)
    signatures = [{"keyid": kid, "sig": base64.b64encode(sk.sign(msg)).decode("ascii")}
                  for kid, sk in paare]
    return {"payload": base64.b64encode(body).decode("ascii"),
            "payloadType": INTOTO_STATEMENT_PAYLOAD_TYPE, "signatures": signatures}


# ── N43 (security-fix 6.2.0): a relying party's ANCHOR is what binds a pack to trust ──────────────────
# `ok` is the pack's SELF-authentication: its form validates, a threshold of its OWN declared root keys
# signed it, it is unexpired, and (when it claims a predecessor) the chain is intact. A GENESIS pack carries
# its own root keys, so it self-authenticates with NO relying-party input — `ok` is True for a pack the
# relying party has never seen and never chose to trust. Self-authentication is not trust: a Trust Pack is
# the ROOT of trust, and a root is trusted only because a relying party PINNED it out of band. The functions
# below report whether THIS pack is bound to such an anchor (a pinned genesis/content-root digest, a pinned
# root-key set, or a rotation whose pinned predecessor's old root vouched). That verdict (`pinned`) gates the
# automation-safety "policy" dimension and every derived trust statement (outcome.py roles); it never feeds
# `ok`, which stays the documented self-authentication verdict.


def _root_key_identity(value: Any) -> bytes | None:
    """Addendum R6a-3 (`KRAXO-CLOUD-R6A-SIEBEN-P1-VOR-CRIT-JSON-01`): the canonical IDENTITY token of ONE root
    key, covering the ALGORITHM and BOTH legs, not the classical ``publicKey`` alone. So a hybrid key and an
    Ed25519 key that happen to share the classical public bytes are DIFFERENT identities — a relying party's
    pin that declares ``hybrid-ed25519-mldsa65`` is NOT satisfied by a pack whose root key is Ed25519-only (no
    downgrade, docs/predicates/trust-pack.md §roles/keys). Accepts the same shapes as ``prev_root_keys``: a
    bare base64 string (legacy Ed25519-only) or a key object ``{"publicKey", "alg"?, "publicKeyPq"?}``.

    Fail-closed (``None``, counted nowhere, so it can neither be a declared root key nor a pin):
      - an unknown ``alg`` (never silently reduced to its classical leg);
      - an unreadable / missing ``publicKey``;
      - a hybrid key whose ``publicKeyPq`` leg is absent or not decodable (an INCOMPLETE hybrid key).
    ``alg`` absent defaults to ``ed25519`` (backward compatible with every pre-agility pack and bare-string
    pin). The token is length-prefixed, so no two distinct ``(alg, publicKey, publicKeyPq)`` triples collide."""
    alg: str
    pub_b64: Any
    pq_b64: Any
    if isinstance(value, str):
        alg, pub_b64, pq_b64 = "ed25519", value, None
    elif isinstance(value, dict):
        alg = value.get("alg", "ed25519")
        if alg not in _KEY_ALGS:
            return None   # R6a-3: an unknown algorithm is rejected closed, never read as its classical leg
        pub_b64, pq_b64 = value.get("publicKey"), value.get("publicKeyPq")
    else:
        return None
    if not isinstance(pub_b64, str):
        return None
    try:
        pub = decode_b64(pub_b64)
    except Exception:  # noqa: BLE001 — an unreadable public key is no identity
        return None
    pq: bytes | None = None
    if alg == "hybrid-ed25519-mldsa65":
        if not isinstance(pq_b64, str):
            return None   # R6a-3: a hybrid key WITHOUT its PQ leg is incomplete — rejected closed, no downgrade
        try:
            pq = decode_b64(pq_b64)
        except Exception:  # noqa: BLE001 — an undecodable PQ leg is an incomplete hybrid key
            return None
    pq_part = b"" if pq is None else str(len(pq)).encode("ascii") + b":" + pq
    return alg.encode("ascii") + b"|" + str(len(pub)).encode("ascii") + b":" + pub + b"|" + pq_part


def _declared_root_material(predicate: Any) -> tuple[set[bytes], Any]:
    """The pack's own DECLARED, non-revoked root role: ``(set of root key IDENTITY tokens, declared threshold)``.

    Mirrors ``verify_trust_pack``'s own root extraction (count distinct KEY MATERIAL, not keyId labels): for
    each non-revoked root keyId, the full normalized identity of ``keys[kid]`` (R6a-3: algorithm + both legs,
    via ``_root_key_identity``, not ``publicKey`` alone). Fail-closed — an unreadable key, an unknown or
    incomplete algorithm, a malformed role or a non-int threshold contributes nothing (empty set / ``None``
    threshold), never a raise. The threshold is returned only as an exact int (``_is_int``), so an int subclass
    cannot later decide a comparison; a non-int threshold comes back ``None`` and no pin via the root-key anchor
    can pass."""
    if not isinstance(predicate, dict):
        return set(), None
    keys = _as_dict(predicate.get("keys"))
    revoked = set(_as_list(predicate.get("revoked")))
    root = _as_dict(_as_dict(predicate.get("roles")).get("root"))
    material: set[bytes] = set()
    for kid in _as_list(root.get("keyIds")):
        if not isinstance(kid, str) or kid in revoked:
            continue
        kv = keys.get(kid)
        if not isinstance(kv, dict):
            continue
        token = _root_key_identity(kv)   # R6a-3: full normalized identity, never the classical leg alone
        if token is not None:
            material.add(token)
    threshold = root.get("threshold")
    return material, (threshold if _is_int(threshold) else None)


def _pinned_root_material(expected_root_keys: Any) -> set[bytes]:
    """The set of root key IDENTITY tokens a relying party PINNED. Accepts the same shape as ``prev_root_keys``:
    a ``{keyId: publicKey_b64}`` map, or ``{keyId: {"publicKey": ..., "alg"?: ..., "publicKeyPq"?: ...}}``. Read
    ONCE through ``canonical._richtlinie_von`` so a caller's mapping subclass cannot decide membership through
    its own ``get`` / ``__iter__`` / ``values``. R6a-3: each entry is normalized to its full identity
    (``_root_key_identity``: algorithm + both legs), so a pin that declares a hybrid key is matched ONLY by a
    declared hybrid key with the same classical AND post-quantum leg — never by an Ed25519-only key that shares
    the classical bytes. Fail-closed — an entry whose public key is unreadable, whose algorithm is unknown, or
    which is an incomplete hybrid key (no decodable ``publicKeyPq``), contributes nothing."""
    m = _richtlinie_von(expected_root_keys) or {}
    material: set[bytes] = set()
    for v in m.values():
        token = _root_key_identity(v)   # R6a-3: same full normalized identity on both sides of the match
        if token is not None:
            material.add(token)
    return material


@_ein_stand
def trust_pack_is_pinned(predicate: Any, *, expected_genesis_digest: str | None = None,
                         expected_root_keys: dict | None = None,
                         rotation_authorized: bool | None = None) -> bool | None:
    """Is THIS pack bound to a relying-party anchor? THREE states, never two:

      ``True``  — bound to at least one supplied anchor.
      ``False`` — an anchor WAS supplied but none matched (trust REFUTED: a pack the RP did not pin).
      ``None``  — NO anchor was supplied at all (trust UNESTABLISHED: the caller never pinned anything).

    Any ONE anchor suffices:
      1. a rotation whose pinned predecessor's OLD root vouched for this pack. ``rotation_authorized`` is a
         caller-reported VERDICT, counted only as the exact bool: ``None`` means no rotation anchor was
         supplied (don't count it), ``True`` means the pinned predecessor's old root vouched (bound), ``False``
         means a rotation anchor WAS supplied but the old root did not vouch (a supplied anchor that did not
         match). ``verify_trust_pack`` passes ``True``/``False`` only when the caller gave ``prev_root_keys`` /
         ``prev_root_threshold``, and ``None`` otherwise;
      2. a pinned genesis / content-root digest — ``sha256(JCS(predicate))`` equals
         ``expected_genesis_digest``. That is the same content-root a successor carries as its
         ``prevVersionDigest`` (docs/predicates/trust-pack.md §prevVersionDigest; docs/SUBJECT_BINDING.md),
         and the exact value ``build_trust_pack_statement`` writes as the subject digest;
      3. a pinned root-key set — every DECLARED non-revoked root key is in ``expected_root_keys`` AND the
         declared root threshold is a positive int reachable within it, so the pack's root IDENTITY is exactly
         what the RP pinned (the threshold that authenticated it is then pinned too).

    One-reading and fail-closed throughout: the digest is read by its characters (``_zeichen_von``), the
    pinned keys through ``_richtlinie_von``; a computation that cannot run (no RFC-8785 canonicaliser) is a
    non-match, never a raise and never a silent pass. ``ok`` is UNAFFECTED — a pack can be ``ok`` (self-
    authenticated) yet ``pinned is None`` (never anchored by this relying party)."""
    anchor_supplied = False

    # Anchor 1 — a pinned predecessor's old root vouched (rotation authorization proven upstream, by the caller
    # supplying prev_root_keys/prev_root_threshold — the relying party pinning the predecessor's root). Counted
    # only as the exact bool: True binds; False is a supplied-but-unmatched anchor; None is no rotation anchor.
    if rotation_authorized is True:
        return True
    if rotation_authorized is False:
        anchor_supplied = True

    # Anchor 2 — pinned genesis / content-root digest.
    want = _zeichen_von(expected_genesis_digest)
    if want is not None:
        anchor_supplied = True
        try:
            got: Any = hashlib.sha256(_rfc8785_bytes(predicate)).hexdigest()
        except Exception:  # noqa: BLE001 — cannot canonicalize ⇒ cannot confirm the pin (fail-closed)
            got = None
        if got is not None and got == want:
            return True

    # Anchor 3 — pinned root-key set covers the pack's declared root identity.
    if expected_root_keys is not None:
        anchor_supplied = True
        pinned_keys = _pinned_root_material(expected_root_keys)
        declared, threshold = _declared_root_material(predicate)
        if (pinned_keys and declared and declared <= pinned_keys
                and type(threshold) is int and threshold >= 1 and len(declared) >= threshold):
            return True

    return False if anchor_supplied else None


def _empty_result() -> dict:
    return {"ok": None, "structure_ok": None, "predicate_type_ok": None, "root_threshold_met": None,
            "not_expired": None, "version_monotone": None, "rotation_authorized": None,
            # N43 (security-fix 6.2.0, additive): whether THIS pack is bound to a relying-party anchor —
            # True (bound) / False (an anchor was supplied but none matched) / None (no anchor supplied).
            # Gates `automation.safeForAutomation` (the "policy" dimension) and derived trust statements;
            # NEVER feeds `ok`. See `trust_pack_is_pinned`.
            "pinned": None,
            "root_signers": [], "old_root_signers": [],
            # Finding 01 (2026-07 verify-layer hardening, additive): a uniform automation-safety verdict,
            # computed at the end of verify — never gates `ok`.
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
    from .signature import verify_ed25519_pinned  # noqa: PLC0415
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
            sig = decode_b64(sig_b64)
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
            sig = decode_b64(sig_b64)
            pq_pub = decode_b64(pq_pub_b64)
            sig_pq = decode_b64(sig_pq_b64)
        except Exception:  # noqa: BLE001
            return False
        try:
            return verify_hybrid(classical_pub=pub, classical_sig=sig, pq_pub=pq_pub, pq_sig=sig_pq, message=msg)
        except PQUnavailable:
            return False
    # 6.2.1 R6b-3 (Z309): only the exact "ed25519" reaches the classical check. Any other value — an unknown
    # algorithm such as "rsa4096" or "hybrid-ed25519-mldsa87", None, "", a number — vouches for nothing: an
    # unrecognised alg was read as Ed25519 here, so a valid Ed25519 signature over the classical bytes counted
    # for a key declared under an algorithm this verifier does not implement (an absent alg is the documented
    # legacy Ed25519 case and is mapped to "ed25519" by the callers, not here).
    if type(alg) is not str or alg != "ed25519":
        return False
    if not isinstance(sig_b64, str):
        return False
    try:
        sig = decode_b64(sig_b64)
    except Exception:  # noqa: BLE001
        return False
    # root and old-root keys are trust anchors: a low-order key would count toward a threshold with a
    # signature made with no secret (deep gate Z195, L1-Z195-01; pqsig.verify_hybrid carries the same
    # rule for the hybrid's classical leg).
    return verify_ed25519_pinned(pub, sig, msg)


@_ein_stand(aussen={"now": "uhr"})
def verify_trust_pack(envelope: dict, *, strict: bool = False, now: datetime | None = None,
                      prev_version: int | None = None, prev_version_digest: str | None = None,
                      prev_root_keys: dict | None = None, prev_root_threshold: int | None = None,
                      allow_unverified_rotation: bool = False,
                      expected_genesis_digest: str | None = None,
                      expected_root_keys: dict | None = None) -> dict:
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
    alone. ``allow_unverified_rotation`` opts out of that check only as the exact ``True``; a value that is not
    a bool keeps the check, and the error says so and names the value's type.

    RELYING-PARTY ANCHOR (N43, security-fix 6.2.0). ``ok`` above is the pack's SELF-authentication (form,
    threshold of its OWN root, expiry, chain) — a GENESIS pack self-authenticates with NO caller input, so
    ``ok`` can be True for a pack the relying party never pinned. Self-authentication is not trust: a Trust
    Pack is the ROOT of trust, trusted only once a relying party has PINNED it out of band. ``expected_genesis_digest``
    (the content-root ``sha256(JCS(predicate))``, the value a successor carries as ``prevVersionDigest``) and
    ``expected_root_keys`` (a ``{keyId: publicKey_b64}`` / key-object map covering the pack's declared root
    identity) are those anchors; supplying ``prev_root_keys`` + ``prev_root_threshold`` for a rotation is a
    third (the RP pins the predecessor's root). The result field ``pinned`` names the outcome: ``True`` (bound
    to a supplied anchor), ``False`` (an anchor was supplied but none matched), ``None`` (no anchor supplied).
    ``pinned`` does NOT change ``ok``; it is the "policy" dimension of ``automation`` — ``safeForAutomation``
    is positive only under an anchor (unanchored → ``POLICY_NOT_EVALUATED``; mismatch → ``POLICY_FAILED``).
    Every DERIVED trust statement (outcome.py role trust) is positive only under a pinned pack too."""
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
        # ONE READING (round 11, class A, owner decision option A): the envelope is read once into its plain
        # copy (`dsse._read_once`), and the payload, the signatures cap, the payloadType pin and both
        # threshold loops below read that copy. At fa555f13 `signatures` was read through the caller's
        # envelope for the cap and again for the loop: a dict subclass answering 20 000 entries from the
        # second read on passed the cap of 512 with its stored three, and the loop checked 20 000
        # signatures (2.0 s). This path still never calls `verify_envelope`.
        envelope = dsse._read_once(envelope)
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
        # The ONE Statement oracle (strict parse, object, `_type` = in-toto Statement v1; deep gate Z195,
        # L3-Z195-01 class, mirror of decision.py): a pack is a Statement, and structure_ok says so.
        statement = load_statement_strict(body, budget=DEFAULT_BUDGET)
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
            pub = decode_b64(pub_b64)
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

    # Expiry. The clock is read once (`canonical._zeitpunkt_von`, verify lane on pull request 312): a datetime
    # subclass whose own reflected comparison answered made an expired pack unexpired.
    _uhr = _zeitpunkt_von(now)
    if _uhr is KEIN_ZEITPUNKT:
        r["not_expired"] = False
        r["errors"].append(f"now must be a datetime, got {type(now).__name__} — expiry not evaluated (fail-closed)")
    else:
        _now = _uhr if _uhr is not None else datetime.now(timezone.utc)
        try:
            exp = _parse_rfc3339_z(predicate["expires"])
            r["not_expired"] = exp > _now
        except (ValueError, KeyError, TypeError):
            r["not_expired"] = False
        if r["not_expired"] is False:
            r["errors"].append("trust pack is expired (expires <= now, fail-closed)")

    # Version monotonicity + chain to previous pack.
    if prev_version is not None:
        # adversarial re-audit r6: prev_version kwarg (dok. 'int | None') non-int -> nicht-monoton (fail-closed), kein int>str-Crash
        # The relying party's previous version is a plain int (deep gate 6.2.0 at 2348f0a7, found by the
        # extended sweep): an int subclass passed `_is_int` and answered `version > prev_version` through its own
        # reflected comparison, so a rolled-back pack read as monotone.
        r["version_monotone"] = (_is_int(predicate.get("version")) and type(prev_version) is int
                                 and predicate["version"] > prev_version)
        if not r["version_monotone"]:
            r["errors"].append(
                f"version {predicate.get('version')!r} is not greater than the previous version "
                f"{_zahl_text(prev_version)} (rollback/freeze, fail-closed)")
    if prev_version_digest is not None:
        pvd = predicate.get("prevVersionDigest")
        pvd_hex = pvd.get("sha256") if _is_digest(pvd) else None
        # By its characters: `!=` asked a `str` subclass's reflected `__ne__` first (found by the extended
        # sweep). An expectation that is no text never chains.
        _erwartet = _zeichen_von(prev_version_digest)
        if _erwartet is None or pvd_hex != _erwartet:
            r["version_monotone"] = False
            r["errors"].append("prevVersionDigest does not chain to the supplied previous pack (fail-closed)")

    # Two-stage rotation authorization: the OLD root threshold must ALSO have signed this pack (old root vouches
    # for new). Counts DISTINCT old-root KEY MATERIAL over the exact PAE, using the PREVIOUS pack's key map (the
    # signing keyIds belong to the old pack, not necessarily this pack's `keys`). Only enforced when the caller
    # supplies the previous root role — a first pack / non-rotation verify is unaffected (field stays None).
    if prev_root_keys is not None or prev_root_threshold is not None:
        # adversarial re-audit r6: bare kwarg, truthy non-dict -> {} statt 'in'-Crash. ONE READING (deep gate
        # 6.2.0 at 2348f0a7, found by the extended sweep): the previous root keys are the plain copy of what the
        # caller's map stores (`canonical._richtlinie_von`), so its own `__class__`, `__contains__`,
        # `__getitem__` and `get` never decide which old key vouched. A map that holds a value that is no JSON
        # value vouches for nothing (fail-closed), as a non-dict did.
        old_keys = _richtlinie_von(prev_root_keys) or {}
        old_valid: dict[bytes, str] = {}
        for entry in _as_list(envelope.get("signatures")):
            if not isinstance(entry, dict):
                continue
            kid = entry.get("keyid")
            if not isinstance(kid, str) or kid not in old_keys:
                continue
            _ok = old_keys[kid]
            # backward compatible: a bare base64 string (legacy callers, ed25519-only) or a full key object
            # ({"publicKey":, "alg":, "publicKeyPq":}) for crypto-agile rotation vouching. Only an ABSENT alg
            # is the legacy Ed25519 case; 6.2.1 R6b-3 (Z309): an explicit alg this verifier does not implement
            # (or None, "", a number) is no longer read as ed25519 — it reaches _verify_signature_for_alg as
            # given and vouches for nothing.
            if isinstance(_ok, str):
                old_alg, pub_b64, pq_pub_b64 = "ed25519", _ok, None
            elif isinstance(_ok, dict):
                old_alg = _ok.get("alg", "ed25519")
                pub_b64, pq_pub_b64 = _ok.get("publicKey"), _ok.get("publicKeyPq")
            else:
                continue
            if not isinstance(pub_b64, str):
                continue
            try:
                pub = decode_b64(pub_b64)
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
        # A plain int (the one rule for a number, `_plain_value.plain_int`): `_is_int` asks `isinstance`, and an
        # int subclass decided `len(old_valid) >= prev_root_threshold` through its own reflected comparison.
        r["rotation_authorized"] = (type(prev_root_threshold) is int and prev_root_threshold >= 1
                                    and len(old_valid) >= prev_root_threshold)
        if not r["rotation_authorized"]:
            r["errors"].append(
                f"rotation not authorized by old root: {len(old_valid)} distinct old-root signature(s), "
                f"need {_zahl_text(prev_root_threshold)} (old root must vouch for the new pack, fail-closed)")
    elif _is_digest(predicate.get("prevVersionDigest")):
        # The pack CLAIMS to be a rotation (non-null prevVersionDigest) but the caller did not supply the
        # previous root role, so two-stage rotation authorization cannot be checked. FAIL CLOSED by default:
        # a v2 minting self-owned keys + a real v1 digest would otherwise pass on its own self-signature
        # (the exact footgun this predicate defends against). A caller that deliberately wants only a
        # standalone self-signature check opts out explicitly with allow_unverified_rotation=True.
        # Only the exact True opts out: the flag was read by its truth, so "false" accepted an unverified
        # rotation (measured: ok true). A value that is not a bool is the default refusal, named below.
        if allow_unverified_rotation is True:
            r["warnings"].append(
                "this pack declares a prevVersionDigest (claims to be a rotation) but rotation authorization "
                "was NOT verified (allow_unverified_rotation=True) — this proves only self-signature by the "
                "pack's own declared root, NOT that the old root vouches for it")
        else:
            r["rotation_authorized"] = False
            r["errors"].append(
                "this pack declares a prevVersionDigest (claims to be a rotation) but rotation authorization "
                "was NOT verified — pass prev_root_keys + prev_root_threshold to confirm the old root vouches "
                "for it, or allow_unverified_rotation=True to accept a self-signature-only check (fail-closed)"
                + ("" if type(allow_unverified_rotation) is bool else
                   f"; allow_unverified_rotation is not a bool (a value of type "
                   f"{type_name(allow_unverified_rotation)}), and only the exact True opts out"))

    # N43 (security-fix 6.2.0): bind THIS pack to a relying-party anchor, if the caller supplied one. This is
    # computed BEFORE `ok` for ordering only — it never feeds `ok` (a genesis pack self-authenticates with no
    # caller input). It IS the "policy" dimension of the automation verdict and gates every derived trust
    # statement. `rotation_authorized is True` is also an anchor (the caller pinned the predecessor's root).
    # The rotation verdict counts as an anchor only when the caller SUPPLIED a rotation anchor (prev_root_keys /
    # prev_root_threshold). Otherwise it is None here, even though r["rotation_authorized"] may be False for a
    # pack that merely DECLARES a prevVersionDigest without the caller supplying the predecessor's root (that is
    # not a supplied anchor — it is the pack's own claim, already fail-closed into `ok`).
    _rotation_anchor = (r["rotation_authorized"]
                        if (prev_root_keys is not None or prev_root_threshold is not None) else None)
    r["pinned"] = trust_pack_is_pinned(
        predicate,
        expected_genesis_digest=expected_genesis_digest,
        expected_root_keys=expected_root_keys,
        rotation_authorized=_rotation_anchor)

    r["ok"] = bool(
        r["structure_ok"] and r["predicate_type_ok"] and r["root_threshold_met"]
        and r["not_expired"] and r["version_monotone"] is not False
        and r["rotation_authorized"] is not False)

    # Finding 01 (additive): a uniform automation-safety verdict — never changes `ok` above. N43: the "policy"
    # dimension is `pinned` (the relying-party anchor), so `safeForAutomation` is positive only under an anchor
    # even when `ok` is True.
    from .automation_verdict import automation_summary  # noqa: PLC0415
    r["automation"] = automation_summary(r, required_checks=_AUTOMATION_REQUIRED_CHECKS)
    return r
