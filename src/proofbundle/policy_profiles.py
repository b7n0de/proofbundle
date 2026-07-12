"""Named trust-policy profiles (WP3) — concrete, loadable presets shipped WITH the package.

`policy.py` defines the trust-policy *mechanism* (schema, fail-closed parsing, evaluation). This
module ships a small, curated set of *instances* of that mechanism under stable names, so a relying
party can start from ``proofbundle policy explain research-preview-v1`` instead of hand-writing a
policy JSON from scratch.

**Honest scope (No-Overclaim).** Every profile here is a REAL trust policy: it loads with
:func:`proofbundle.policy.load_policy`, ``policy explain`` lists its pins, and ``policy lint`` passes
(non-strict). But a named profile shipped to *every* user cannot pin a signer identity — pinning
``allowed_issuers`` / ``decision_receipt.trusted_decision_makers`` is inherently deployment-specific
(it is literally "whose key do you trust"). So every profile here pins the *structural* trust
questions (schema/algorithm/hash/assurance/anchor shape) and deliberately leaves signer identity
unpinned; ``policy lint <profile>`` therefore reports the "attributes to nobody" WARNING (not an
error) — that is not a bug in the profile, it is the honest state of a template a relying party must
still complete with their own ``allowed_issuers`` (or ``trusted_decision_makers``) before depending on
it for anything more than structural sanity. See ``docs/POLICY_PROFILES.md``.

Two profiles named in the v0.1 audit's WP3 list — ``proofbundle-policy/public-log-required-v1`` (needs
a ``trusted_log_origins`` / ``witness_quorum`` policy section that does not exist in the trust-policy
schema yet, see ``docs/PUBLIC_TRANSPARENCY_PROFILE.md``) and ``proofbundle-policy/sdjwt-vc-v1`` (needs
a ``vct`` allow-list check that does not exist yet, see ``docs/SD_JWT_VC_PROFILE.md``) — are
deliberately NOT shipped here: a policy file that merely LOOKS like it enforces something the
evaluator does not check would be a silent vacuous-pass trap, exactly what ``policy lint`` exists to
catch. They are documented as PROPOSED, not implemented.
"""
from __future__ import annotations

import importlib.resources
import os

__all__ = ["PROFILE_NAMES", "PROFILE_ID_PREFIX", "list_profiles", "profile_path", "resolve_policy_source"]

# The `proofbundle-policy/<name>` id prefix used in each profile's own `policy_id` (WP3 naming
# convention from the audit) and accepted as an alternate spelling by resolve_policy_source().
PROFILE_ID_PREFIX = "proofbundle-policy/"

# short name -> packaged filename, under this package's policies/ directory (declared package-data
# in pyproject.toml: "policies/*.json"). Keep in ascending strictness order (informative only).
PROFILE_NAMES: dict[str, str] = {
    "research-preview-v1": "research-preview-v1.json",
    "strict-eval-v1": "strict-eval-v1.json",
    "strict-eval-authenticated-root-v1": "strict-eval-authenticated-root-v1.json",
    "strict-prereg-v1": "strict-prereg-v1.json",
    "decision-receipt-v1": "decision-receipt-v1.json",
}


def list_profiles() -> list:
    """The sorted list of shippable named profile short names (no prefix)."""
    return sorted(PROFILE_NAMES)


def profile_path(name: str) -> str:
    """The filesystem path to a packaged named profile's JSON, or raise ``FileNotFoundError`` with a
    clear message (never a bare `KeyError`) if `name` is not one of :func:`list_profiles`. `name` may
    carry the `proofbundle-policy/` prefix or not — both spellings resolve the same profile."""
    short = name[len(PROFILE_ID_PREFIX):] if name.startswith(PROFILE_ID_PREFIX) else name
    filename = PROFILE_NAMES.get(short)
    if filename is None:
        raise FileNotFoundError(
            f"no such named trust-policy profile {name!r}; known profiles: {list_profiles()}")
    ref = importlib.resources.files("proofbundle") / "policies" / filename
    # as_file() would be needed for a zipped install; policies/*.json ship as plain files in every
    # supported install mode (wheel, sdist, editable) so a direct str(ref) path is sufficient here,
    # and keeps this a plain path load_policy() already knows how to open.
    return str(ref)


def resolve_policy_source(value: str) -> str:
    """Resolve a CLI/library-supplied policy reference to something :func:`proofbundle.policy.load_policy`
    can open. A REAL FILE on disk always wins (a local ``./research-preview-v1.json`` can never be
    shadowed by the packaged profile of the same name); only when no file exists at `value` is it tried
    against the known profile names (bare ``strict-eval-v1`` or prefixed
    ``proofbundle-policy/strict-eval-v1``). An unresolved value is returned UNCHANGED, so the normal
    "cannot read trust policy" error from `load_policy` still surfaces — this function never itself
    raises for an unknown name, it only ever WIDENS what resolves, never narrows or hides an error."""
    if os.path.exists(value):
        return value
    short = value[len(PROFILE_ID_PREFIX):] if value.startswith(PROFILE_ID_PREFIX) else value
    if short in PROFILE_NAMES:
        try:
            return profile_path(short)
        except FileNotFoundError:
            return value   # defensive: fall through to the normal load_policy error path
    return value
