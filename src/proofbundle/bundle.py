"""Evidence bundle model and offline verification.

An evidence bundle is a single self-contained JSON document. ``verify_bundle``
checks, fully offline and without any running log server:

  1. ed25519-signature   the payload is signed by the stated public key
  2. merkle-inclusion    the payload is anchored under the stated tree root
                         (RFC 6962 / RFC 9162 inclusion proof)
  3. sd-jwt (optional)   any embedded SD-JWT selective-disclosure credential is
                         well formed and, if a key is given, issuer-signed

The verifier treats ``payload`` as opaque bytes: it proves *that these exact
bytes were signed and anchored*, not what they mean. That keeps v0.1 small and
correct. Turning a reproducible eval run into such a payload is the job of the
eval-receipt emitter (see :mod:`proofbundle.evalclaim`, since v0.4).

Malformed input (wrong types, missing or unknown fields) is rejected with a
``BundleFormatError`` — never a raw traceback — so a caller gets the documented
malformed exit code, not a crash.
"""

from __future__ import annotations

import base64
import json
from typing import Union

from . import merkle
from ._strict_json import loads_strict
from .errors import BundleFormatError, UnsupportedError, VerificationResult
from .kbjwt import holder_key_from_cnf, split_key_binding, verify_key_binding
from .signature import verify_ed25519
from .sdjwt import verify_sd_jwt

__all__ = ["SCHEMA", "verify_bundle", "load_bundle", "recompute_merkle_root_b64"]


def _issuer_requires_holder_binding(sd_part: str) -> bool:
    """True iff the issuer-signed SD-JWT payload carries a usable ``cnf`` holder key (RFC 7800) — i.e. the
    issuer REQUIRES proof-of-possession. A presentation without a valid Key Binding JWT is then a bearer
    downgrade and MUST fail. Malformed/absent → False (no cnf ⇒ no binding required, backward-compatible)."""
    try:
        issuer_jwt = sd_part.split("~", 1)[0]
        payload_b64 = issuer_jwt.split(".")[1].encode("ascii")
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + b"=" * (-len(payload_b64) % 4)))
        return isinstance(payload, dict) and holder_key_from_cnf(payload) is not None
    except Exception:
        return False

SCHEMA = "proofbundle/v0.1"

# Allowed keys per object — SPEC.md §3: a verifier MUST reject unknown fields (schema is
# additionalProperties: false). Enforced here so the code matches its own normative spec.
# `anchors` is an OPTIONAL, EXPERIMENTAL detached layer (external time anchors, SPEC.md §7i / the
# `[anchors]` extra): the core crypto verifier merely TOLERATES the field so an anchored receipt is not
# rejected as malformed — it never verifies the anchors here, so a bundle's crypto verdict is identical
# whether or not it carries `anchors`. Anchor verification is a separate, opt-in relying-party step
# (`proofbundle.anchors.verify_anchors` / `verify --require-anchor`), never part of this offline core.
_TOP_KEYS = {"schema", "payload_b64", "signature", "merkle", "sd_jwt_vc", "anchors"}
_SIG_KEYS = {"alg", "public_key_b64", "sig_b64"}
_MERKLE_KEYS = {"hash_alg", "leaf_index", "tree_size", "inclusion_proof_b64", "root_b64"}
_SD_KEYS = {"compact", "issuer_public_key_b64"}


def _b64d(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise BundleFormatError(f"field {field} is not valid base64") from exc


def _require(obj: dict, key: str, field: str):
    if key not in obj:
        raise BundleFormatError(f"missing field {field}")
    return obj[key]


def _require_dict(obj, field: str) -> dict:
    """The value must be a JSON object — a string/list/number is malformed, not a crash."""
    if not isinstance(obj, dict):
        raise BundleFormatError(f"field {field} must be a JSON object")
    return obj


def _require_int(obj: dict, key: str, field: str) -> int:
    """The value must be a JSON integer — reject floats (SPEC §2) and non-numeric strings/None."""
    val = _require(obj, key, field)
    if isinstance(val, bool) or not isinstance(val, int):   # bool is an int subclass; a float/str/None is not
        raise BundleFormatError(f"field {field} must be an integer, got {type(val).__name__}")
    return val


def _reject_unknown(obj: dict, allowed: set, field: str) -> None:
    extra = set(obj) - allowed
    if extra:
        raise BundleFormatError(f"unknown field(s) in {field}: {sorted(extra)}")


def _require_hash_alg(mk: dict) -> str:
    """``merkle.hash_alg`` is REQUIRED (v1.6+, SPEC.md §5) and its value MUST be the one supported
    algorithm: a silently-defaulted OR silently-accepted-arbitrary value is exactly where a future
    multi-alg version would hide an alg-confusion attack. The only realistic way to hit the
    missing-field case is a bundle emitted before v1.6 — every emitter since then always writes the
    field — so that error carries a migration hint rather than a bare "missing field". Shared by
    :func:`verify_bundle` and :func:`recompute_merkle_root_b64` so neither the presence check NOR
    the value check can drift apart between the two call sites (LOW finding, 2026-07-09: the value
    check used to be duplicated separately in each function)."""
    if "hash_alg" not in mk:
        raise BundleFormatError(
            "missing field merkle.hash_alg — REQUIRED since v1.6 (SPEC.md §5). Migrate a "
            'pre-v1.6 bundle by adding "hash_alg": "sha256-rfc6962" to its merkle object; '
            "every proofbundle emitter since v1.6 writes this field automatically.")
    hash_alg = mk["hash_alg"]
    if hash_alg != "sha256-rfc6962":
        raise UnsupportedError(f"merkle hash_alg {hash_alg!r} not supported in v0.1")
    return hash_alg


def load_bundle(path: str) -> dict:
    """Read and JSON-parse a bundle file. Deeply-nested JSON overflows the parser's C-recursion; that
    is malformed input, so it is mapped to BundleFormatError (the documented exit-2 path) rather than
    escaping as a raw RecursionError traceback (verify-lens L3, 2026-07-09)."""
    with open(path, "r", encoding="utf-8") as handle:
        # WP-C1: duplicate keys are rejected fail-closed (loads_strict) — the native bundle path
        # silently kept the LAST duplicate (e.g. a second `root_b64`/`sig_b64`), a classic parser
        # differential across JSON implementations. loads_strict ALSO owns the RecursionError →
        # BundleFormatError mapping for deep nesting (the old outer handler here became dead code).
        return loads_strict(handle.read())


def verify_bundle(bundle: Union[dict, str], *, expected_aud=None, expected_nonce=None) -> VerificationResult:
    """Verify an evidence bundle (a dict or a path to a JSON file).

    ``expected_aud`` / ``expected_nonce`` (v1.3): when the bundle carries a Key Binding JWT, these enforce
    RFC 9901 §7.3 replay/audience binding — the KB-JWT's ``aud`` MUST match ``expected_aud`` and its
    ``nonce`` MUST match ``expected_nonce``. If omitted, the KB-JWT signature + disclosure binding are still
    checked, but the relying party has NOT bound the presentation to itself/this transaction — a stale or
    cross-audience replay would still verify. A relying party doing challenge-response MUST pass both.
    """
    if isinstance(bundle, str):
        bundle = load_bundle(bundle)
    if not isinstance(bundle, dict):
        raise BundleFormatError("bundle must be a JSON object")

    schema = bundle.get("schema")
    if schema != SCHEMA:
        raise UnsupportedError(f"unsupported schema {schema!r}, expected {SCHEMA!r}")
    _reject_unknown(bundle, _TOP_KEYS, "bundle")
    # WP-A7: the anchors field stays UNVERIFIED here (crypto verdict identical with/without it),
    # but its STRUCTURE follows the published JSON Schema — in a v0.1 bundle `target` is the enum
    # receipt|preRegistration only (SPEC §7i: `statement` is exclusively for DETACHED decision
    # evidence). The docs promised "rejected as malformed (exit 2)"; the code now matches them.
    anchors_field = bundle.get("anchors")
    if anchors_field is not None:
        if not isinstance(anchors_field, list):
            raise BundleFormatError("field anchors must be a list")
        for i, entry in enumerate(anchors_field):
            if not isinstance(entry, dict):
                raise BundleFormatError(f"anchors[{i}] must be a JSON object")
            tgt = entry.get("target")
            if tgt not in ("receipt", "preRegistration"):
                raise BundleFormatError(
                    f"anchors[{i}].target {tgt!r} is not allowed in a proofbundle/v0.1 bundle "
                    "(receipt|preRegistration only; 'statement' is for detached decision evidence)")

    result = VerificationResult()
    payload = _b64d(_require(bundle, "payload_b64", "payload_b64"), "payload_b64")

    # 1. signature over the payload
    sig = _require_dict(_require(bundle, "signature", "signature"), "signature")
    _reject_unknown(sig, _SIG_KEYS, "signature")
    alg = sig.get("alg")
    if alg != "ed25519":
        raise UnsupportedError(f"signature alg {alg!r} not supported in v0.1")
    pub = _b64d(_require(sig, "public_key_b64", "signature.public_key_b64"), "signature.public_key_b64")
    raw_sig = _b64d(_require(sig, "sig_b64", "signature.sig_b64"), "signature.sig_b64")
    sig_ok = verify_ed25519(pub, raw_sig, payload)
    result.add("ed25519-signature", sig_ok, "payload signed by stated key" if sig_ok else "invalid signature")

    # 2. merkle inclusion of the payload
    mk = _require_dict(_require(bundle, "merkle", "merkle"), "merkle")
    _reject_unknown(mk, _MERKLE_KEYS, "merkle")
    _require_hash_alg(mk)   # presence + value both enforced by the shared helper
    leaf_index = _require_int(mk, "leaf_index", "merkle.leaf_index")
    tree_size = _require_int(mk, "tree_size", "merkle.tree_size")
    proof_list = _require(mk, "inclusion_proof_b64", "merkle.inclusion_proof_b64")   # required per SPEC §5
    if not isinstance(proof_list, list):
        raise BundleFormatError("field merkle.inclusion_proof_b64 must be a list")
    proof = [_b64d(p, "merkle.inclusion_proof_b64[]") for p in proof_list]
    root = _b64d(_require(mk, "root_b64", "merkle.root_b64"), "merkle.root_b64")
    incl_ok = merkle.verify_inclusion(payload, leaf_index, tree_size, proof, root)
    result.add(
        "merkle-inclusion",
        incl_ok,
        f"anchored at index {leaf_index} of {tree_size}" if incl_ok else "inclusion proof failed",
    )

    # 3. optional SD-JWT selective disclosure credential
    sd = bundle.get("sd_jwt_vc")
    kb_binding_checked = False   # F4: did a KB-JWT (the aud/nonce carrier) actually get verified?
    if sd is not None:
        sd = _require_dict(sd, "sd_jwt_vc")
        _reject_unknown(sd, _SD_KEYS, "sd_jwt_vc")
        compact = _require(sd, "compact", "sd_jwt_vc.compact")
        if not isinstance(compact, str):   # malformed input → BundleFormatError, never a raw traceback
            raise BundleFormatError("field sd_jwt_vc.compact must be a string")
        issuer_pub = None
        if sd.get("issuer_public_key_b64"):
            issuer_pub = _b64d(sd["issuer_public_key_b64"], "sd_jwt_vc.issuer_public_key_b64")
        sd_res = verify_sd_jwt(compact, issuer_pub)
        result.add("sd-jwt-disclosures", sd_res["structure_ok"], sd_res["detail"])
        if sd_res["sig_checked"]:
            result.add(
                "sd-jwt-issuer-signature",
                sd_res["sig_ok"],
                "issuer signature valid" if sd_res["sig_ok"] else "issuer signature invalid",
            )
        else:
            # WP-C2 (6-lens review, Owner-GO breaking / secure-by-default): sd_jwt_vc sits OUTSIDE
            # payload_b64, so the bundle's Ed25519 signature does NOT cover it. A present sd_jwt_vc whose
            # ISSUER SIGNATURE was never verified (no sd_jwt_vc.issuer_public_key_b64) carries disclosures
            # anyone could have authored — previously .ok could still be True over attacker-chosen
            # "disclosed" values. Now a FAILING check makes .ok False (reason: unsigned); there is no
            # opt-out. Supply issuer_public_key_b64 to authenticate the disclosures.
            result.add(
                "sd-jwt-issuer-signature", False,
                "sd_jwt_vc present but no issuer_public_key_b64 — its disclosures are unauthenticated "
                "(reason: unsigned; the bundle signature does not cover sd_jwt_vc). Supply the issuer key.")
        # v1.2/v1.3, fail-closed: a KB-JWT that is PRESENT must verify (RFC 9901 §4.3), AND if the issuer
        # bound a `cnf` holder key (proof-of-possession REQUIRED) a presentation with NO KB-JWT is a bearer
        # downgrade — anyone who sees the disclosed SD-JWT could replay it — so that MUST fail. expected_aud/
        # expected_nonce (v1.3) enforce RFC 9901 §7.3 replay/audience binding when the relying party supplies
        # them. Bundles issued without `cnf` and with no KB-JWT verify exactly as before (backward-compatible).
        #
        # The holder-binding check is only MEANINGFUL when the issuer signature was actually verified: the `cnf`
        # holder key is declared INSIDE the issuer-signed JWT, so without a checked issuer signature an attacker
        # could forge the whole SD-JWT (issuer JWT + cnf + matching KB-JWT). Only run it when the issuer
        # public key was supplied AND its signature verified (release-review HIGH fix) — otherwise the SD-JWT is
        # unauthenticated and no holder-binding claim over it can be trusted.
        if sd_res.get("sig_checked") and sd_res.get("sig_ok"):
            sd_part, kb = split_key_binding(compact)
            if kb is not None:
                kb_res = verify_key_binding(compact, expected_aud=expected_aud, expected_nonce=expected_nonce)
                result.add("sd-jwt-key-binding", kb_res["ok"], kb_res["detail"])
                kb_binding_checked = True
            elif _issuer_requires_holder_binding(sd_part):
                result.add(
                    "sd-jwt-key-binding", False,
                    "issuer bound a holder key (cnf) but the presentation carries NO Key Binding JWT — "
                    "required proof-of-possession is missing (bearer downgrade, RFC 9901 §4.3)")
        elif not sd_res.get("sig_checked"):
            # v1.6 fail-closed (external review, CRITICAL): gating holder-binding on issuer
            # verification opened a KEY-OMISSION downgrade — strip the KB-JWT AND drop
            # issuer_public_key_b64, and a cnf-bound credential silently passed as a bearer
            # token. A `cnf`-carrying SD-JWT whose issuer cannot be verified is REFUSED, never
            # "structure-only passed". SD-JWTs without `cnf` keep the documented no-key
            # backward-compat path unchanged.
            sd_part, _ = split_key_binding(compact)
            if _issuer_requires_holder_binding(sd_part):
                result.add(
                    "sd-jwt-key-binding", False,
                    "SD-JWT declares a cnf holder key but NO issuer key was supplied — holder "
                    "binding is unverifiable, refusing (fail-closed; supply "
                    "sd_jwt_vc.issuer_public_key_b64)")

        # WP-C1 (6-lens review, Owner-GO): bind the sd_jwt_vc to THIS bundle. sd_jwt_vc is outside the
        # signed payload, so an issuer-VALID SD-JWT from bundle B can be swapped into bundle A (cross-receipt
        # credential substitution) — its always-open claims (passed/threshold/comparator/suite/issuer +
        # receipt root) must match A's own signed claim + merkle root, else the disclosures do NOT belong to
        # this bundle. Only meaningful once the issuer signature verified (an unsigned SD-JWT already fails C2).
        if sd_res.get("sig_checked") and sd_res.get("sig_ok"):
            import json as _json  # noqa: PLC0415
            from .sdjwt_issue import check_binds_bundle  # noqa: PLC0415
            try:
                _claim = _json.loads(base64.b64decode(bundle["payload_b64"]).decode("utf-8"))
            except (ValueError, KeyError, TypeError):
                _claim = None
            _root = (bundle.get("merkle") or {}).get("root_b64")
            # only an eval-claim bundle carries the always-open fields check_binds_bundle compares; a
            # non-eval payload with an sd_jwt_vc is out of scope for this binding (nothing to bind against).
            if isinstance(_claim, dict) and _claim.get("schema") == "proofbundle/eval-claim/v0.1" and _root:
                bound = check_binds_bundle(compact, _claim, _root)
                result.add(
                    "sd-jwt-bundle-binding", bound,
                    "sd_jwt_vc always-open claims + receipt root match this bundle" if bound else
                    "sd_jwt_vc disclosures do NOT bind this bundle (reason: unbound/mismatch — cross-receipt "
                    "substitution; the SD-JWT's passed/threshold/comparator/suite/issuer/root differ from the "
                    "signed claim)")

    # F4 (v1.9.2, fail-closed): supplying expected_aud/expected_nonce asks for RFC 9901 §7.3
    # replay/audience binding. A bundle with no verifiable KB-JWT (no sd_jwt_vc at all, or an
    # sd_jwt_vc without a Key Binding JWT) carries nothing to bind to — returning OK anyway is a
    # downgrade trap: the verifier believes the presentation was bound to its aud/nonce when it was
    # not. Refuse the binding it asked for but cannot be enforced. Verifiers that pass no expected_*
    # are unaffected (backward-compatible: the check only fires when a binding was actually requested).
    if (expected_aud is not None or expected_nonce is not None) and not kb_binding_checked:
        result.add(
            "sd-jwt-key-binding", False,
            "expected_aud/expected_nonce were supplied but the bundle carries no verifiable Key "
            "Binding JWT — the requested replay/audience binding cannot be enforced (fail-closed)")

    return result


def recompute_merkle_root_b64(bundle: Union[dict, str]) -> dict:
    """Recompute the Merkle root from the bundle's own payload + inclusion proof (v1.2, issue #2).

    Debugging aid for ``proofbundle verify --verbose``: returns
    ``{"stated_b64": ..., "recomputed_b64": ...}`` where ``recomputed_b64`` is None when the
    proof cannot be evaluated (e.g. index out of range, proof too short/long). Performs the
    same strict format validation as :func:`verify_bundle` — malformed input raises
    ``BundleFormatError``, never a raw traceback.
    """
    if isinstance(bundle, str):
        bundle = load_bundle(bundle)
    if not isinstance(bundle, dict):
        raise BundleFormatError("bundle must be a JSON object")
    payload = _b64d(_require(bundle, "payload_b64", "payload_b64"), "payload_b64")
    mk = _require_dict(_require(bundle, "merkle", "merkle"), "merkle")
    # Validate hash_alg the SAME way verify_bundle does — REQUIRED, not silently defaulted, and the value
    # checked (release-review #13: the docstring claimed strict-as-verify_bundle but this defaulted a
    # missing hash_alg; the shared `_require_hash_alg` helper above keeps both call sites' presence AND
    # value checks from drifting apart).
    _require_hash_alg(mk)
    leaf_index = _require_int(mk, "leaf_index", "merkle.leaf_index")
    tree_size = _require_int(mk, "tree_size", "merkle.tree_size")
    proof_list = _require(mk, "inclusion_proof_b64", "merkle.inclusion_proof_b64")
    if not isinstance(proof_list, list):
        raise BundleFormatError("field merkle.inclusion_proof_b64 must be a list")
    proof = [_b64d(p, "merkle.inclusion_proof_b64[]") for p in proof_list]
    # Display the stated root in CANONICAL base64 (re-encode from the decoded bytes), so a non-canonical but
    # byte-equal stated root does not read as a spurious mismatch next to the canonical recomputed root (LOW #10/#15).
    stated_b64 = base64.b64encode(_b64d(_require(mk, "root_b64", "merkle.root_b64"), "merkle.root_b64")).decode("ascii")
    try:
        recomputed = merkle.root_from_inclusion(
            leaf_index, tree_size, merkle.leaf_hash(payload), proof)
        recomputed_b64 = base64.b64encode(recomputed).decode("ascii")
    except ValueError as exc:
        return {"stated_b64": stated_b64, "recomputed_b64": None, "detail": str(exc)}
    return {"stated_b64": stated_b64, "recomputed_b64": recomputed_b64, "detail": ""}
