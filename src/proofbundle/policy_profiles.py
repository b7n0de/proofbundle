"""Named trust-policy profiles (WP3) — concrete, loadable presets shipped WITH the package.

`policy.py` defines the trust-policy *mechanism* (schema, fail-closed parsing, evaluation). This
module ships a small, curated set of *instances* of that mechanism under stable names, so a relying
party can start from ``proofbundle policy explain research-preview-v1`` instead of hand-writing a
policy JSON from scratch.

**AP-2 §6 — templates vs instantiated policies (No-Overclaim).** Every strict profile here is a
TEMPLATE, not a deployment-ready policy: it pins the *structural* trust questions (schema / algorithm
/ hash / assurance / anchor shape) but deliberately leaves the signer identity unpinned, because
pinning ``allowed_issuers`` / ``decision_receipt.trusted_decision_makers`` is inherently
deployment-specific (it is literally "whose key do you trust"). Each template therefore carries
``deploymentReady: false`` and ``requiresIdentityOverlay: true`` and must be turned into a concrete
policy with :func:`instantiate_template` (``proofbundle policy instantiate``) before a relying party
depends on it for an automation decision. A raw template used productively is caught by
``policy lint --strict`` and can never yield ``safeForAutomation: true`` (AP-1 §5). See
``docs/POLICY_PROFILES.md``.

``research-preview-v1`` is the one non-template profile: an explicitly-labelled preview a relying
party may point ``verify`` at to sanity-check structure, never a production trust anchor.

**Alias transition (AP-2 §6.1).** The four strict profiles were renamed
``strict-*`` → ``*-template-v1`` to make their template nature undeniable. The OLD names remain
resolvable for a deprecation period as aliases; loading one prints a single deprecation line on
stderr (no break, maturity policy §0.8). ``policy list-profiles`` shows the canonical names first and
marks the aliases.

Two profiles named in the v0.1 audit's WP3 list — ``proofbundle-policy/public-log-required-v1`` (needs
a ``trusted_log_origins`` / ``witness_quorum`` policy section that does not exist in the trust-policy
schema yet, see ``docs/PUBLIC_TRANSPARENCY_PROFILE.md``) and ``proofbundle-policy/sdjwt-vc-v1`` (needs
a ``vct`` allow-list check that does not exist yet, see ``docs/SD_JWT_VC_PROFILE.md``) — are
deliberately NOT shipped here: a policy file that merely LOOKS like it enforces something the
evaluator does not check would be a silent vacuous-pass trap, exactly what ``policy lint`` exists to
catch. They are documented as PROPOSED, not implemented.
"""
from __future__ import annotations

import copy
import importlib.resources
import os
import sys

__all__ = ["PROFILE_NAMES", "PROFILE_ALIASES", "PROFILE_ID_PREFIX", "list_profiles",
           "profile_aliases", "canonical_profile_name", "profile_path", "resolve_policy_source",
           "instantiate_template"]

# The `proofbundle-policy/<name>` id prefix used in each profile's own `policy_id` (WP3 naming
# convention from the audit) and accepted as an alternate spelling by resolve_policy_source().
PROFILE_ID_PREFIX = "proofbundle-policy/"

# canonical short name -> packaged filename, under this package's policies/ directory (declared
# package-data in pyproject.toml: "policies/*.json"). Ascending strictness order (informative only).
PROFILE_NAMES: dict[str, str] = {
    "research-preview-v1": "research-preview-v1.json",
    "strict-eval-template-v1": "strict-eval-template-v1.json",
    "strict-eval-authenticated-root-template-v1": "strict-eval-authenticated-root-template-v1.json",
    "strict-prereg-template-v1": "strict-prereg-template-v1.json",
    "decision-receipt-template-v1": "decision-receipt-template-v1.json",
}

# AP-2 §6.1: deprecated old name -> canonical new name. Resolvable for a deprecation period; each
# resolution prints a deprecation line on stderr. research-preview-v1 was never renamed (it is not a
# template), so it has no alias.
PROFILE_ALIASES: dict[str, str] = {
    "strict-eval-v1": "strict-eval-template-v1",
    "strict-eval-authenticated-root-v1": "strict-eval-authenticated-root-template-v1",
    "strict-prereg-v1": "strict-prereg-template-v1",
    "decision-receipt-v1": "decision-receipt-template-v1",
}

# A-P0-5 §9.2: metadata an instantiate overlay may NEVER set — deploymentReady is derived (§9.3),
# the rest is fixed by the template lifecycle (see instantiate_template).
_RESERVED_OVERLAY_KEYS = {"deploymentReady", "requiresIdentityOverlay", "policyPurpose",
                          "schema", "generatedFromTemplate"}


def _as_dict(v):
    """Berkeley r5/r6 class-fix: Config-Sub-Feld als dict, sonst {} (das ``_as_dict(x.get(k))``-Idiom ersetzte nur FALSY)."""
    return v if isinstance(v, dict) else {}


def _as_list(v):
    return v if isinstance(v, (list, tuple)) else []


def list_profiles() -> list:
    """The sorted list of CANONICAL profile short names (no prefix, no aliases)."""
    return sorted(PROFILE_NAMES)


def profile_aliases() -> dict:
    """A copy of the deprecated-old-name -> canonical-name alias map (AP-2 §6.1)."""
    return dict(PROFILE_ALIASES)


def _strip_prefix(name: str) -> str:
    return name[len(PROFILE_ID_PREFIX):] if name.startswith(PROFILE_ID_PREFIX) else name


def canonical_profile_name(name):
    """Resolve a possibly-prefixed, possibly-deprecated profile name to its canonical short name, or
    None if it names no packaged profile. PURE — never warns, never raises (use for classification)."""
    if not isinstance(name, str):
        return None
    short = _strip_prefix(name)
    if short in PROFILE_NAMES:
        return short
    if short in PROFILE_ALIASES:
        return PROFILE_ALIASES[short]
    return None


def _warn_deprecated_alias(old_short: str, canonical: str) -> None:
    print(f"proofbundle: warning: trust-policy profile {old_short!r} is a deprecated alias for "
          f"{canonical!r}; update to the canonical name (the alias will be removed in a future major "
          "release).", file=sys.stderr)


def profile_path(name: str) -> str:
    """The filesystem path to a packaged profile's JSON, or raise ``FileNotFoundError`` with a clear
    message (never a bare `KeyError`) if `name` is not a known profile. `name` may carry the
    ``proofbundle-policy/`` prefix or not, and may be a canonical name OR a deprecated alias — an alias
    resolves to the canonical file and prints a deprecation line on stderr (AP-2 §6.1)."""
    short = _strip_prefix(name)
    if short in PROFILE_NAMES:
        canonical = short
    elif short in PROFILE_ALIASES:
        canonical = PROFILE_ALIASES[short]
        _warn_deprecated_alias(short, canonical)
    else:
        raise FileNotFoundError(
            f"no such named trust-policy profile {name!r}; known profiles: {list_profiles()}"
            + (f"; deprecated aliases: {sorted(PROFILE_ALIASES)}" if PROFILE_ALIASES else ""))
    ref = importlib.resources.files("proofbundle") / "policies" / PROFILE_NAMES[canonical]
    # as_file() would be needed for a zipped install; policies/*.json ship as plain files in every
    # supported install mode (wheel, sdist, editable) so a direct str(ref) path is sufficient here,
    # and keeps this a plain path load_policy() already knows how to open.
    return str(ref)


def resolve_policy_source(value: str) -> str:
    """Resolve a CLI/library-supplied policy reference to something :func:`proofbundle.policy.load_policy`
    can open. A REAL FILE on disk always wins (a local ``./strict-eval-template-v1.json`` can never be
    shadowed by the packaged profile of the same name); only when no file exists at `value` is it tried
    against the known profile names and deprecated aliases. An unresolved value is returned UNCHANGED,
    so the normal "cannot read trust policy" error from `load_policy` still surfaces — this function
    never itself raises for an unknown name, it only ever WIDENS what resolves, never narrows or hides
    an error. Resolving a deprecated alias prints a deprecation line (via profile_path)."""
    if os.path.exists(value):
        return value
    short = _strip_prefix(value)
    if short in PROFILE_NAMES or short in PROFILE_ALIASES:
        try:
            return profile_path(short)   # emits the deprecation warning for an alias
        except FileNotFoundError:
            return value   # defensive: fall through to the normal load_policy error path
    return value


def instantiate_template(template: str, *, issuer_keys, policy_id, expected_root=None,
                         valid_until=None, overlay=None) -> dict:
    """AP-2 §6.3: turn a shipped TEMPLATE profile into a deployment-ready org policy by pinning a signer
    identity (and, when the template requires an authenticated root, a trusted root). Pure/offline: no
    I/O beyond reading the packaged template. Returns the instantiated policy dict, already re-validated
    by :func:`proofbundle.policy.load_policy` (unknown overlay fields, malformed keys and a bad expiry
    all fail closed there).

    Args:
        template: a template profile name (canonical or a deprecated alias, prefixed or not).
        issuer_keys: non-empty list of base64 Ed25519 public keys — each is validated (low-order /
            non-canonical keys are rejected fail-closed) and pinned as the trusted identity. For an
            eval template they populate ``allowed_issuers`` + set ``signature.require_expected_signer``;
            for the decision-receipt template they populate ``decision_receipt.trusted_decision_makers``.
        policy_id: the new org-namespace ``policy_id`` (must be non-empty and differ from the template's).
        expected_root: optional base64 merkle root pinned as the single ``merkle.trusted_roots`` entry.
            REQUIRED iff the template sets ``merkle.require_authenticated_root`` — a template that
            requires an authenticated root but is instantiated without one stays ``deploymentReady:false``.
        valid_until: optional ISO-8601 UTC expiry stamped onto the instance (AP-2 §6.4).
        overlay: optional dict of extra top-level policy fields merged last; unknown fields fail closed
            via the final load_policy re-validation.
    """
    from .policy import PolicyError, _validate_pinned_ed25519_pubkey, load_policy  # noqa: PLC0415

    canonical = canonical_profile_name(template)
    if canonical is None:
        raise PolicyError(f"no such template profile {template!r}; known profiles: {list_profiles()}")
    base = load_policy(profile_path(template))   # emits a deprecation line for an alias name
    if base.get("requiresIdentityOverlay") is not True and base.get("deploymentReady") is not False:
        raise PolicyError(
            f"profile {canonical!r} is not a template (it carries no requiresIdentityOverlay:true / "
            "deploymentReady:false) — there is nothing to instantiate")
    if not isinstance(issuer_keys, (list, tuple)) or not issuer_keys:
        raise PolicyError("instantiate requires at least one issuer public key to pin")
    if not (isinstance(policy_id, str) and policy_id):
        raise PolicyError("instantiate requires a non-empty policy_id")
    if policy_id == base.get("policy_id"):
        raise PolicyError(
            "policy_id must differ from the template's policy_id (use your own organisation namespace)")

    inst = copy.deepcopy(base)
    is_decision = isinstance(base.get("decision_receipt"), dict)

    entries: list = []
    for key in issuer_keys:
        if not (isinstance(key, str) and key):
            raise PolicyError("each issuer key must be a non-empty base64 string")
        _validate_pinned_ed25519_pubkey(key, "instantiate issuer key")   # fail-closed on low-order/malformed
        entries.append({"public_key_b64": key})
    if is_decision:
        dr = dict(_as_dict(inst.get("decision_receipt")))
        dr["trusted_decision_makers"] = entries
        inst["decision_receipt"] = dr
    else:
        inst["allowed_issuers"] = entries
        sig = dict(_as_dict(inst.get("signature")))
        sig["require_expected_signer"] = True   # enforce the pin (evaluate_policy matches the signer key)
        inst["signature"] = sig

    # root pinning when the template demands an authenticated root (completeness is derived from the
    # RESULTING inst below, not tracked here, so an overlay cannot desync a flag from the actual policy).
    require_auth_root = bool(_as_dict(base.get("merkle")).get("require_authenticated_root"))
    if expected_root is not None:
        if not (isinstance(expected_root, str) and expected_root):
            raise PolicyError("expected_root must be a non-empty base64 string")
        mk = dict(_as_dict(inst.get("merkle")))
        mk["trusted_roots"] = [expected_root]
        inst["merkle"] = mk

    inst["policy_id"] = policy_id
    inst["requiresIdentityOverlay"] = False
    # A-P0-5 §9.2: the instance records its template provenance (display/audit; reserved below).
    inst["generatedFromTemplate"] = canonical
    if valid_until is not None:
        inst["valid_until"] = valid_until
    if overlay is not None:
        if not isinstance(overlay, dict):
            raise PolicyError("overlay must be a JSON object")
        # A-P0-5 §9.2: RESERVED metadata is never overlay-writable — an overlay that sets
        # deploymentReady would ASSERT readiness (it is derived, §9.3), one that clears
        # requiresIdentityOverlay would skip the identity step, one that changes
        # policyPurpose/schema/generatedFromTemplate would repurpose or re-badge the instance.
        # Loud PolicyError, never a silent drop (fail-closed).
        reserved = _RESERVED_OVERLAY_KEYS & set(overlay)
        if reserved:
            raise PolicyError(
                f"overlay may not set reserved metadata {sorted(reserved)} — deploymentReady is "
                "DERIVED (§9.3) and requiresIdentityOverlay/policyPurpose/schema/"
                "generatedFromTemplate are fixed by the template lifecycle")
        inst.update(overlay)   # unknown fields caught fail-closed by the load_policy re-validation below

    # A-P0-5 §9.3 — deploymentReady is DERIVED from the FINAL policy (after any overlay), never
    # asserted: purposeDefined AND identityPinned AND trustMaterialValid AND policyLifecycleValid
    # AND notTemplate. Deriving from the resulting inst — not from the local `entries` — means an
    # overlay that WIPES the just-pinned identity or root cannot leave the policy labelled
    # production-ready (L2 pre-land review). An incomplete instance stays deploymentReady:false so
    # `policy lint --strict` still refuses it (No-Fake).
    from .policy import POLICY_PURPOSES, policy_expired, policy_not_yet_valid  # noqa: PLC0415
    final_identity = (_as_dict(inst.get("decision_receipt")).get("trusted_decision_makers")
                      if is_decision else inst.get("allowed_issuers"))
    final_root_ok = (not require_auth_root) or bool(_as_dict(inst.get("merkle")).get("trusted_roots"))
    purpose_defined = inst.get("policyPurpose") in POLICY_PURPOSES
    lifecycle_ok = policy_expired(inst) is not True and policy_not_yet_valid(inst) is not True
    not_template = inst.get("requiresIdentityOverlay") is not True
    inst["deploymentReady"] = (bool(final_identity) and final_root_ok and purpose_defined
                               and lifecycle_ok and not_template)

    # re-validate the RESULT fail-closed: unknown overlay fields, a malformed pinned key or a bad expiry
    # become a PolicyError here rather than a policy that only LOOKS instantiated.
    return load_policy(inst)
