"""Trust policy (v0.1) — a relying party's machine-readable, fail-closed trust decision, applied
OVER a completed crypto verification (WP-B3).

`verify` on its own makes NO trust decision: it proves authenticity + integrity of the bytes. A trust
policy is where the relying party states, explicitly and offline, *which* signer, schema, algorithm,
audience, freshness and assurance it will accept. Without a policy `verify` says `POLICY:
NOT_EVALUATED`; with one, the policy result is a separate `policy_ok` and exit code 3 on failure —
never conflated with a crypto failure (exit 1).

Design invariants:
  - **snake_case**, versioned (`schema: proofbundle/trust-policy/v0.1`), consistent with the bundle.
  - **fail-closed**: unknown fields are a parse error (additionalProperties: false); an enabled
    requirement that this verify path cannot evaluate (status, which needs a snapshot input v0.1 does
    not carry) fails closed with a clear reason rather than silently passing.
  - **offline**: no network; trust comes only from the policy file.
  - crypto FIRST, policy over the crypto result — a policy is never evaluated on unverified bytes.
"""

from __future__ import annotations

import json
from typing import Union

from .errors import ProofBundleError
from .evalclaim import ASSURANCE_LEVELS, check_freshness, decode_eval_claim
from .kbjwt import verify_key_binding

__all__ = ["POLICY_SCHEMA", "PolicyError", "load_policy", "evaluate_policy"]

POLICY_SCHEMA = "proofbundle/trust-policy/v0.1"


class PolicyError(ProofBundleError):
    """The trust policy JSON is missing fields, malformed, or carries unknown fields (fail-closed)."""


_TOP_KEYS = {"schema", "policy_id", "allowed_schema_versions", "allowed_issuers", "signature",
             "merkle", "sd_jwt", "status", "assurance"}
_ISSUER_KEYS = {"issuer", "public_key_b64", "kid"}
_SIG_KEYS = {"allowed_algs", "require_expected_signer"}
_MERKLE_KEYS = {"required_hash_alg"}
_SDJWT_KEYS = {"require_key_binding_when_cnf_present", "expected_aud", "require_nonce",
               "max_iat_age_seconds"}
_STATUS_KEYS = {"reject_self_issued", "allowed_status_authorities"}
_ASSURANCE_KEYS = {"minimum_level", "reject_self_attested_without_prereg"}


def _reject_unknown(obj: dict, allowed: set, where: str) -> None:
    extra = set(obj) - allowed
    if extra:
        raise PolicyError(f"unknown field(s) in {where}: {sorted(extra)} (trust policy is fail-closed)")


def _require_dict(value, where: str) -> dict:
    if not isinstance(value, dict):
        raise PolicyError(f"{where} must be a JSON object")
    return value


def load_policy(source: Union[str, dict]) -> dict:
    """Parse and structurally validate a trust policy, fail-closed. ``source`` is a path or a dict.

    Every section is checked for unknown fields (a typo that silently weakens a policy is impossible),
    the schema version is pinned, and ``policy_id`` is required. No network, no I/O beyond reading the
    file. Raises :class:`PolicyError` on anything malformed."""
    if isinstance(source, str):
        try:
            with open(source, encoding="utf-8") as handle:
                policy = json.load(handle)
        except (OSError, ValueError) as exc:
            raise PolicyError(f"cannot read trust policy: {exc}") from exc
    else:
        policy = source
    policy = _require_dict(policy, "trust policy")

    if policy.get("schema") != POLICY_SCHEMA:
        raise PolicyError(
            f"unsupported trust policy schema {policy.get('schema')!r}, expected {POLICY_SCHEMA!r}")
    _reject_unknown(policy, _TOP_KEYS, "trust policy")
    if not (isinstance(policy.get("policy_id"), str) and policy["policy_id"]):
        raise PolicyError("trust policy requires a non-empty string policy_id")

    if "allowed_schema_versions" in policy and not isinstance(policy["allowed_schema_versions"], list):
        raise PolicyError("allowed_schema_versions must be a list")
    for issuer in policy.get("allowed_issuers", []) or []:
        issuer = _require_dict(issuer, "allowed_issuers[]")
        _reject_unknown(issuer, _ISSUER_KEYS, "allowed_issuers[]")
        if not (isinstance(issuer.get("public_key_b64"), str) and issuer["public_key_b64"]):
            raise PolicyError("each allowed_issuers[] entry needs a non-empty public_key_b64")
    if "signature" in policy:
        _reject_unknown(_require_dict(policy["signature"], "signature"), _SIG_KEYS, "signature")
    if "merkle" in policy:
        _reject_unknown(_require_dict(policy["merkle"], "merkle"), _MERKLE_KEYS, "merkle")
    if "sd_jwt" in policy:
        sdj = _require_dict(policy["sd_jwt"], "sd_jwt")
        _reject_unknown(sdj, _SDJWT_KEYS, "sd_jwt")
        mia = sdj.get("max_iat_age_seconds")
        if mia is not None and (isinstance(mia, bool) or not isinstance(mia, int) or mia < 0):
            raise PolicyError("sd_jwt.max_iat_age_seconds must be a non-negative integer or null")
    if "status" in policy:
        _reject_unknown(_require_dict(policy["status"], "status"), _STATUS_KEYS, "status")
    if "assurance" in policy:
        asr = _require_dict(policy["assurance"], "assurance")
        _reject_unknown(asr, _ASSURANCE_KEYS, "assurance")
        lvl = asr.get("minimum_level")
        if lvl is not None and lvl not in ASSURANCE_LEVELS:
            raise PolicyError(f"assurance.minimum_level must be one of {list(ASSURANCE_LEVELS)} or null")
    return policy


def policy_expected_aud(policy: dict):
    """The aud the policy wants bound (sd_jwt.expected_aud), or None. Used by the CLI to reconcile
    with the --aud flag (a policy/flag conflict is an error, never a silent override)."""
    return (policy.get("sd_jwt") or {}).get("expected_aud")


def evaluate_policy(bundle: dict, result, policy: dict, *, now=None) -> dict:
    """Evaluate a trust policy OVER a completed crypto verification.

    ``result`` is the VerificationResult from ``verify_bundle`` (already run, with the effective aud
    the CLI reconciled from policy + --aud). Returns ``{policy_ok, checks, reason}`` where ``checks``
    is a list of ``{name, ok, detail}``. Crypto must have passed for a meaningful verdict; a policy is
    never a reason to trust bytes whose signature failed.

    Offline: the only network-free trust inputs are the policy file and the already-verified bundle.
    """
    checks: list = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    sig = bundle.get("signature") or {}

    # 1. schema version
    allowed_schemas = policy.get("allowed_schema_versions") or []
    if allowed_schemas:
        got = bundle.get("schema")
        add("policy:schema_version", got in allowed_schemas,
            f"schema {got!r} not in allowed {allowed_schemas}" if got not in allowed_schemas
            else f"schema {got!r} allowed")

    # 2. signature algorithm
    allowed_algs = (policy.get("signature") or {}).get("allowed_algs") or []
    if allowed_algs:
        got = sig.get("alg")
        add("policy:signature_alg", got in allowed_algs,
            f"alg {got!r} not in allowed {allowed_algs}" if got not in allowed_algs
            else f"alg {got!r} allowed")

    # 3. issuer / signer — matched by PUBLIC KEY (kid is a hint only)
    allowed_issuers = policy.get("allowed_issuers") or []
    require_signer = bool((policy.get("signature") or {}).get("require_expected_signer"))
    if allowed_issuers or require_signer:
        signer_key = sig.get("public_key_b64")
        allowed_keys = {i.get("public_key_b64") for i in allowed_issuers}
        matched = signer_key in allowed_keys and signer_key is not None
        if not allowed_issuers and require_signer:
            add("policy:signer_allowed", False,
                "require_expected_signer is set but allowed_issuers is empty — no signer can match (fail-closed)")
        else:
            add("policy:signer_allowed", matched,
                "signer public key is in allowed_issuers" if matched
                else "signer public key is NOT in allowed_issuers")

    # 4. merkle required hash alg
    required_hash = (policy.get("merkle") or {}).get("required_hash_alg")
    if required_hash is not None:
        got = (bundle.get("merkle") or {}).get("hash_alg")
        add("policy:merkle_hash_alg", got == required_hash,
            f"merkle.hash_alg {got!r} != required {required_hash!r}" if got != required_hash
            else f"merkle.hash_alg {got!r} matches")

    # 5. SD-JWT / KB-JWT policy. The aud VALUE was already bound by verify_bundle (the CLI passed the
    #    reconciled effective aud); here we enforce the remaining presence/structure requirements.
    sdj = policy.get("sd_jwt") or {}
    sd = bundle.get("sd_jwt_vc")
    kb = None
    if isinstance(sd, dict) and isinstance(sd.get("compact"), str):
        kb = verify_key_binding(sd["compact"])   # read aud/nonce/iat/present (value binding done in verify_bundle)
    if sdj.get("require_key_binding_when_cnf_present"):
        # verify_bundle already fails closed on a cnf-bound SD-JWT without a KB-JWT; reflect it here so
        # the policy states the requirement explicitly. If the crypto result carries the key-binding
        # check, its outcome is authoritative.
        kb_check = next((c for c in result.checks if c.name == "sd-jwt-key-binding"), None)
        if kb_check is not None:
            add("policy:key_binding_present", kb_check.ok,
                "key binding verified" if kb_check.ok else f"key binding failed: {kb_check.detail}")
        elif kb is None or not kb.get("present"):
            # no SD-JWT / no KB-JWT and the verifier did not require one (no cnf) — the policy asked for
            # a KB when cnf is present; with no cnf there is nothing to require, so this passes vacuously.
            add("policy:key_binding_present", True, "no cnf holder key bound; KB not required")
    if sdj.get("require_nonce"):
        has_nonce = bool(kb and kb.get("present") and kb.get("nonce"))
        add("policy:nonce_present", has_nonce,
            "KB-JWT carries a nonce" if has_nonce
            else "policy requires a KB-JWT nonce but none is present")

    # 6. status — verify --policy v0.1 has NO status-snapshot input, so an ENABLED status requirement
    #    cannot be evaluated here. Fail closed rather than silently pass (the honest boundary).
    status = policy.get("status") or {}
    if status.get("reject_self_issued") or (status.get("allowed_status_authorities") or []):
        add("policy:status", False,
            "policy enables a status requirement, but verify --policy (v0.1) has no status-snapshot "
            "input — evaluate revocation separately with verify_status_snapshot (fail-closed)")

    # 7. assurance + freshness — only meaningful for an issuer-bound eval receipt. Decode once.
    asr = policy.get("assurance") or {}
    max_age = sdj.get("max_iat_age_seconds")
    needs_claim = (asr.get("minimum_level") is not None
                   or asr.get("reject_self_attested_without_prereg") or max_age is not None)
    if needs_claim:
        claim = decode_eval_claim(bundle)
        if claim is None:
            add("policy:assurance", False,
                "policy constrains assurance/freshness but the bundle is not a valid issuer-bound eval receipt")
        else:
            min_level = asr.get("minimum_level")
            if min_level is not None:
                got_level = claim.get("assurance_level")
                ok = (got_level in ASSURANCE_LEVELS
                      and ASSURANCE_LEVELS.index(got_level) >= ASSURANCE_LEVELS.index(min_level))
                add("policy:assurance_min_level", ok,
                    f"assurance_level {got_level!r} below minimum {min_level!r}" if not ok
                    else f"assurance_level {got_level!r} meets minimum {min_level!r}")
            if asr.get("reject_self_attested_without_prereg"):
                weak = (claim.get("assurance_level") == "self_attested" and not claim.get("prereg_sha256"))
                add("policy:assurance_prereg", not weak,
                    "self_attested without prereg_sha256 (weakest, rejected by policy)" if weak
                    else "assurance/pre-registration acceptable")
            if max_age is not None:
                fresh = check_freshness(claim, max_age_seconds=max_age, now=now)
                add("policy:freshness", bool(fresh.get("fresh")),
                    fresh.get("reason", ""))

    policy_ok = all(c["ok"] for c in checks)
    reason = "" if policy_ok else next((c["detail"] for c in checks if not c["ok"]), "policy not satisfied")
    return {"policy_ok": policy_ok, "checks": checks, "reason": reason}
