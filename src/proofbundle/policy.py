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

import base64
import copy
import hmac
from datetime import datetime, timezone
from typing import Union

from ._strict_json import loads_strict
from .errors import BundleFormatError, ProofBundleError
from .evalclaim import ASSURANCE_LEVELS, check_freshness, decode_eval_claim
from .kbjwt import verify_key_binding

__all__ = ["POLICY_SCHEMA", "POLICY_PURPOSES", "PolicyError", "load_policy", "evaluate_policy",
           "explain_policy", "lint_policy", "policy_warnings", "policy_expired",
           "policy_not_yet_valid"]

POLICY_SCHEMA = "proofbundle/trust-policy/v0.1"
POLICY_SCHEMA_V0_2 = "proofbundle/trust-policy/v0.2"
# v0.2 adds ONE additive section (decision_receipt) for the decision-receipt/v0.1 predicate. A v0.1 policy is
# valid unchanged under the v0.2 parser (only additive; fail-closed preserved). The decision_receipt section is
# accepted ONLY when schema == v0.2 (a decision_receipt under a v0.1 schema is a fail-closed error).
_SUPPORTED_SCHEMAS = (POLICY_SCHEMA, POLICY_SCHEMA_V0_2)


class PolicyError(ProofBundleError):
    """The trust policy JSON is missing fields, malformed, or carries unknown fields (fail-closed)."""


_ED25519_P = (1 << 255) - 19          # the field prime 2**255 - 19
_ED25519_SIGN_MASK = 1 << 255         # bit 255 is the x sign, not part of y
_ED25519_Y_MASK = _ED25519_SIGN_MASK - 1


def _low_order_ed25519_y() -> frozenset:
    """The y-coordinates of the Ed25519 8-torsion subgroup (identity y=1, order-2 y=p-1, order-4 y=0,
    and the two order-8 y-values). Checking the y-VALUE (sign-independent) rejects a low-order key under
    ANY encoding — both sign variants — where a hand-kept byte-string blocklist misses the sign/field
    variants (6-lens fix-review re-break found 3 missing). Computed from the known order-8 encodings."""
    ys = {0, 1, _ED25519_P - 1}
    for h in ("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
              "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"):
        ys.add(int.from_bytes(bytes.fromhex(h), "little") & _ED25519_Y_MASK)
    return frozenset(ys)


_LOW_ORDER_ED25519_Y = _low_order_ed25519_y()


def _validate_pinned_ed25519_pubkey(b64: str, ctx: str) -> None:
    """Fail-closed check for a PINNED trusted Ed25519 public key. Must decode to 32 bytes, be a CANONICAL
    encoding (y < p), and NOT be a low-order point. The core verifier deliberately accepts small-order,
    mixed-order and non-canonical keys (SPEC §4a, "Taming the Many EdDSAs"); pinning any of them as a
    trusted identity lets a fixed signature verify for many (for the identity encodings, ALL) messages
    with no private key — forgery of a trusted identity without a secret. Rejects the whole low-order
    class by the y-value (sign-independent) plus the non-canonical (y >= p) class, so no encoding variant
    slips past. Raises PolicyError."""
    import base64  # noqa: PLC0415
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise PolicyError(f"{ctx} public_key_b64 is not valid base64") from exc
    if len(raw) != 32:
        raise PolicyError(f"{ctx} public_key_b64 must decode to 32 bytes, got {len(raw)}")
    y = int.from_bytes(raw, "little") & _ED25519_Y_MASK   # strip the x sign bit
    if y >= _ED25519_P:
        raise PolicyError(
            f"{ctx} public_key_b64 is a non-canonical Ed25519 encoding (y >= p) — rejected: it encodes a "
            "low-order/identity point that a fixed signature verifies against with no private key")
    if y in _LOW_ORDER_ED25519_Y:
        raise PolicyError(
            f"{ctx} public_key_b64 is a low-order Ed25519 point — rejected: a fixed signature under such "
            "a key verifies for many messages with no private key, so it cannot be a trusted identity")


def _pinned_key_forgeable(b64: str) -> bool:
    """True iff the pinned key is a low-order / non-canonical / malformed encoding that must never grant
    trust. Non-raising defense-in-depth for the EVALUATION layer (fix-review Finding 2): load_policy
    already rejects such keys, but evaluate_policy / evaluate_decision_policy are public and a caller
    could hand them a policy dict that never went through load_policy — a matched-but-forgeable pinned
    key must not yield signer_trusted=True there either."""
    try:
        _validate_pinned_ed25519_pubkey(b64, "pinned key")
        return False
    except PolicyError:
        return True


_TOP_KEYS = {"schema", "policy_id", "allowed_schema_versions", "allowed_issuers", "signature",
             "merkle", "sd_jwt", "status", "assurance", "decision_receipt", "anchors",
             "deploymentReady", "requiresIdentityOverlay",   # AP-2 §6.2 template metadata
             "valid_until",                                  # AP-2 §6.4 lifecycle expiry
             "valid_from",                                   # A-P0-2 §6 lifecycle not-before
             "policyPurpose",                                # A-P0-4 §8 purpose binding
             "generatedFromTemplate"}                        # A-P0-5 §9.2 template provenance

# A-P0-4 §8.1: a policy is bound to exactly ONE verifier path. The eval verify path accepts only
# "eval", the decision path only "decision"; "outcome" / "trust-pack" / "public-transparency" are
# reserved for the 3.2.0 verifiers (a policy declaring them is refused by BOTH current paths).
POLICY_PURPOSES = ("eval", "decision", "outcome", "trust-pack", "public-transparency")


def _parse_iso_utc(s):
    """Parse an ISO-8601 string to an aware UTC datetime, or None if unparseable. A naive value is
    assumed UTC. A trailing ``Z`` is normalised to ``+00:00`` first so this works on Python 3.10
    (whose ``datetime.fromisoformat`` does not accept ``Z``) as well as 3.11+."""
    if not isinstance(s, str):
        return None
    norm = s[:-1] + "+00:00" if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(norm)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
_ANCHORS_KEYS = {"require_anchor", "require_anchor_target", "allow_pending",
                 "trusted_tsa_roots", "bitcoin_block_headers", "trusted_tsa_policy_oids"}
_ANCHOR_TARGETS = ("receipt", "preRegistration", "statement")
_DECISION_KEYS = {"trusted_decision_makers", "allowed_decision_types", "allowed_verdicts",
                  "required_evidence_relations", "accepted_predicate_types", "require_policy_digest",
                  "require_external_anchor", "allow_pending", "require_audience", "require_nonce",
                  "require_not_checked", "require_decision_change_conditions", "require_trace_context",
                  "allow_raw_inputs"}
# The decision_receipt boolean knobs (§7.5 / addendum §2.2). allow_raw_inputs defaults FALSE (fail-closed:
# a receipt with privacy.rawInputsIncluded=true is rejected unless the relying party opts in).
_DECISION_BOOL_KEYS = ("require_policy_digest", "require_external_anchor", "allow_pending", "require_audience",
                       "require_nonce", "require_not_checked", "require_decision_change_conditions",
                       "require_trace_context", "allow_raw_inputs")
_DECISION_MAKER_KEYS = {"id", "public_key_b64", "kid"}
_DECISION_TYPES = {"preActionAuthorization", "postHocReview", "humanEscalation", "policySimulation"}
_VERDICTS = {"ALLOW", "DENY", "REFUSE", "ESCALATE", "DEFER", "OBSERVE"}
_ISSUER_KEYS = {"issuer", "public_key_b64", "kid"}
_SIG_KEYS = {"allowed_algs", "require_expected_signer"}
_MERKLE_KEYS = {"required_hash_alg", "require_authenticated_root", "trusted_roots",
                "trusted_checkpoints"}
# A-P0-1 §5.2: a trusted checkpoint pins the SIGNED (origin, treeSize, root) triple ATOMICALLY —
# never root bytes alone. `checkpointSigner` is a §7c C2SP vkey; `signature` is the base64
# (keyID ‖ Ed25519 signature) blob of the checkpoint's signature line; `validUntil` is enforced.
_CHECKPOINT_KEYS = {"origin", "root", "treeSize", "hashAlg", "checkpointSigner",
                    "issuedAt", "validUntil", "signature"}
_CHECKPOINT_REQUIRED = ("origin", "root", "treeSize", "hashAlg", "checkpointSigner", "signature")
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


def _require_bool(obj: dict, key: str, where: str) -> None:
    """A present flag MUST be a real JSON boolean — a string like "false" is truthy and would
    silently flip a fail-closed toggle (the schema declares these boolean)."""
    if key in obj and not isinstance(obj[key], bool):
        raise PolicyError(f"{where}.{key} must be a boolean (true/false)")


def _require_str_or_null(obj: dict, key: str, where: str) -> None:
    if key in obj and obj[key] is not None and not isinstance(obj[key], str):
        raise PolicyError(f"{where}.{key} must be a string or null")


def _require_list_of_str(obj: dict, key: str, where: str) -> None:
    """A present list field MUST be a JSON array of strings — a bare string would degrade Python's
    ``in`` from set-membership to SUBSTRING matching in evaluate_policy, a real bypass (verify-lens
    L1/L3/L4, 2026-07-09: allowed_algs="xed25519y" matched "ed25519")."""
    if key in obj:
        val = obj[key]
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            raise PolicyError(f"{where}.{key} must be a list of strings")


def _validate_root_b64(value, where: str) -> None:
    """A-P0-5 §9.1: a pinned Merkle root MUST be valid standard base64 decoding to exactly 32 bytes
    (SHA-256) — a malformed pin is its OWN loud error at load time, never a silent never-matches.
    (The evaluate layer's skip-on-malformed stays as defense-in-depth for dicts that bypassed
    load_policy; a loaded policy can no longer carry one.)"""
    if not isinstance(value, str):
        raise PolicyError(f"{where} must be a base64 string")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise PolicyError(f"{where} is not valid standard base64 — a trusted_roots/checkpoint root "
                          "pin must be well-formed (fail-closed, own error, never a silent "
                          "non-match)") from exc
    if len(raw) != 32:
        raise PolicyError(f"{where} must decode to exactly 32 bytes (SHA-256 root), got {len(raw)}")


def _validate_checkpoint_entry(entry, idx: int) -> None:
    """A-P0-1 §5.2 structural validation of one merkle.trusted_checkpoints[] entry (fail-closed).
    Signature VERIFICATION happens in evaluate_policy (it needs `now` for validUntil); here every
    field's shape is pinned so a typo cannot silently weaken the atomic tree-context pin."""
    where = f"merkle.trusted_checkpoints[{idx}]"
    entry = _require_dict(entry, where)
    _reject_unknown(entry, _CHECKPOINT_KEYS, where)
    for req in _CHECKPOINT_REQUIRED:
        if req not in entry:
            raise PolicyError(f"{where} is missing required field {req!r}")
    origin = entry["origin"]
    if not isinstance(origin, str) or not origin or "+" in origin \
            or any(c.isspace() for c in origin):
        raise PolicyError(f"{where}.origin must be a non-empty schemeless id without "
                          "whitespace or '+'")
    _validate_root_b64(entry["root"], f"{where}.root")
    ts = entry["treeSize"]
    if isinstance(ts, bool) or not isinstance(ts, int) or ts < 0:
        raise PolicyError(f"{where}.treeSize must be a non-negative integer")
    if not (isinstance(entry["hashAlg"], str) and entry["hashAlg"]):
        raise PolicyError(f"{where}.hashAlg must be a non-empty string")
    if not (isinstance(entry["checkpointSigner"], str)
            and entry["checkpointSigner"].count("+") >= 2):
        raise PolicyError(f"{where}.checkpointSigner must be a C2SP vkey "
                          "(name+hexKeyID+base64KeyMaterial)")
    sig = entry["signature"]
    if not isinstance(sig, str) or not sig:
        raise PolicyError(f"{where}.signature must be a non-empty base64 string")
    try:
        base64.b64decode(sig, validate=True)
    except (ValueError, TypeError) as exc:
        raise PolicyError(f"{where}.signature is not valid base64") from exc
    for tkey in ("issuedAt", "validUntil"):
        if tkey in entry and entry[tkey] is not None:
            if not isinstance(entry[tkey], str) or _parse_iso_utc(entry[tkey]) is None:
                raise PolicyError(f"{where}.{tkey} must be an ISO-8601 timestamp string")


def load_policy(source: Union[str, dict]) -> dict:
    """Parse and structurally validate a trust policy, fail-closed. ``source`` is a path or a dict.

    Every section is checked for unknown fields (a typo that silently weakens a policy is impossible),
    the schema version is pinned, and ``policy_id`` is required. No network, no I/O beyond reading the
    file. Raises :class:`PolicyError` on anything malformed."""
    if isinstance(source, str):
        try:
            with open(source, encoding="utf-8") as handle:
                # WP-C1: a duplicated key in a policy is a differential in the TRUST DECISION
                # itself (two parsers could enforce different allowed_issuers) — reject.
                policy = loads_strict(handle.read())
        except (OSError, ValueError, BundleFormatError) as exc:
            raise PolicyError(f"cannot read trust policy: {exc}") from exc
    else:
        # defensive copy (verify-lens L4): a caller who validates a dict then mutates the SAME object
        # before evaluate_policy must not be able to bypass these checks — evaluate the copy.
        policy = copy.deepcopy(source)
    policy = _require_dict(policy, "trust policy")

    if policy.get("schema") not in _SUPPORTED_SCHEMAS:
        raise PolicyError(
            f"unsupported trust policy schema {policy.get('schema')!r}, expected one of {list(_SUPPORTED_SCHEMAS)}")
    _reject_unknown(policy, _TOP_KEYS, "trust policy")
    # decision_receipt is a v0.2-only additive section; under v0.1 it is a fail-closed error.
    if "decision_receipt" in policy and policy.get("schema") != POLICY_SCHEMA_V0_2:
        raise PolicyError("decision_receipt section requires schema proofbundle/trust-policy/v0.2")
    if not (isinstance(policy.get("policy_id"), str) and policy["policy_id"]):
        raise PolicyError("trust policy requires a non-empty string policy_id")
    # AP-2 §6.2: template metadata. `deploymentReady`/`requiresIdentityOverlay` are optional additive
    # booleans (a hand-written production policy omits them); when present they MUST be real booleans.
    for _meta in ("deploymentReady", "requiresIdentityOverlay"):
        if _meta in policy:
            _require_bool(policy, _meta, "trust policy")
    # A-P0-5 §9.2: contradictory template metadata is refused — "deployment-ready" and "still a raw
    # template needing its identity overlay" cannot both be true.
    if policy.get("deploymentReady") is True and policy.get("requiresIdentityOverlay") is True:
        raise PolicyError("contradictory template metadata: deploymentReady:true together with "
                          "requiresIdentityOverlay:true (a raw template is never deployment-ready)")
    # AP-2 §6.4 / A-P0-2 §6: optional ISO-8601 lifecycle window. A present value MUST parse to a real
    # timestamp (fail-closed); expiry/not-before are then ENFORCED by evaluate_policy /
    # evaluate_decision_policy (POLICY: FAIL, exit 3), and `policy lint` fails an expired policy.
    for _tkey in ("valid_until", "valid_from"):
        if _tkey in policy and policy[_tkey] is not None:
            if not isinstance(policy[_tkey], str) or _parse_iso_utc(policy[_tkey]) is None:
                raise PolicyError(
                    f"{_tkey} must be an ISO-8601 timestamp string (e.g. 2027-01-01T00:00:00Z)")
    _vf, _vu = _parse_iso_utc(policy.get("valid_from")), _parse_iso_utc(policy.get("valid_until"))
    if _vf is not None and _vu is not None and _vf > _vu:
        raise PolicyError("valid_from is after valid_until — an empty validity window can never "
                          "authorise anything (fail-closed)")
    # A-P0-4 §8.1: purpose binding. A present, non-null value MUST be one of the registered purposes;
    # the verifier paths enforce the match (eval path accepts only "eval", decision only "decision").
    # An explicit ``null`` is treated EXACTLY like absent (the transitional legacy default) — matching
    # the schema's nullable enum and the sibling nullable fields valid_until/valid_from/
    # generatedFromTemplate, so a policy that validates against the schema also loads (Lens-4 F1).
    if policy.get("policyPurpose") is not None:
        if policy["policyPurpose"] not in POLICY_PURPOSES:
            raise PolicyError(
                f"policyPurpose must be one of {list(POLICY_PURPOSES)} or null, "
                f"got {policy['policyPurpose']!r}")
    # A-P0-5 §9.2: template provenance is a string (stamped by `policy instantiate`), display/audit only.
    _require_str_or_null(policy, "generatedFromTemplate", "trust policy")

    # Every declared field's TYPE is enforced (verify-lens L4/L3), not just its presence — the schema
    # declares these types and the hand-rolled parser must match it, or a mistyped field silently
    # weakens the policy (the substring-match bug for a string-not-list allowed_algs).
    _require_list_of_str(policy, "allowed_schema_versions", "trust policy")
    if "allowed_issuers" in policy and not isinstance(policy["allowed_issuers"], list):
        raise PolicyError("allowed_issuers must be a list")
    for issuer in policy.get("allowed_issuers", []) or []:
        issuer = _require_dict(issuer, "allowed_issuers[]")
        _reject_unknown(issuer, _ISSUER_KEYS, "allowed_issuers[]")
        if not (isinstance(issuer.get("public_key_b64"), str) and issuer["public_key_b64"]):
            raise PolicyError("each allowed_issuers[] entry needs a non-empty public_key_b64")
        _validate_pinned_ed25519_pubkey(issuer["public_key_b64"], "allowed_issuers[]")
        _require_str_or_null(issuer, "issuer", "allowed_issuers[]")
        _require_str_or_null(issuer, "kid", "allowed_issuers[]")
    if "signature" in policy:
        sig = _require_dict(policy["signature"], "signature")
        _reject_unknown(sig, _SIG_KEYS, "signature")
        _require_list_of_str(sig, "allowed_algs", "signature")
        _require_bool(sig, "require_expected_signer", "signature")
    if "merkle" in policy:
        mk = _require_dict(policy["merkle"], "merkle")
        _reject_unknown(mk, _MERKLE_KEYS, "merkle")
        _require_str_or_null(mk, "required_hash_alg", "merkle")
        _require_bool(mk, "require_authenticated_root", "merkle")   # P0-A §6.2
        _require_list_of_str(mk, "trusted_roots", "merkle")          # base64 roots the RP trusts, out of band
        # A-P0-5 §9.1: every pinned root is hard-validated at load (base64, 32 bytes) — its OWN error.
        for i, tr in enumerate(mk.get("trusted_roots") or []):
            _validate_root_b64(tr, f"merkle.trusted_roots[{i}]")
        # A-P0-1 §5.2: structured trusted checkpoints (atomic root+treeSize pins).
        if "trusted_checkpoints" in mk:
            if not isinstance(mk["trusted_checkpoints"], list):
                raise PolicyError("merkle.trusted_checkpoints must be a list")
            for i, entry in enumerate(mk["trusted_checkpoints"]):
                _validate_checkpoint_entry(entry, i)
    if "sd_jwt" in policy:
        sdj = _require_dict(policy["sd_jwt"], "sd_jwt")
        _reject_unknown(sdj, _SDJWT_KEYS, "sd_jwt")
        _require_bool(sdj, "require_key_binding_when_cnf_present", "sd_jwt")
        _require_str_or_null(sdj, "expected_aud", "sd_jwt")
        _require_bool(sdj, "require_nonce", "sd_jwt")
        mia = sdj.get("max_iat_age_seconds")
        if mia is not None and (isinstance(mia, bool) or not isinstance(mia, int) or mia < 0):
            raise PolicyError("sd_jwt.max_iat_age_seconds must be a non-negative integer or null")
    if "status" in policy:
        st = _require_dict(policy["status"], "status")
        _reject_unknown(st, _STATUS_KEYS, "status")
        _require_bool(st, "reject_self_issued", "status")
        _require_list_of_str(st, "allowed_status_authorities", "status")
    if "assurance" in policy:
        asr = _require_dict(policy["assurance"], "assurance")
        _reject_unknown(asr, _ASSURANCE_KEYS, "assurance")
        lvl = asr.get("minimum_level")
        if lvl is not None and lvl not in ASSURANCE_LEVELS:
            raise PolicyError(f"assurance.minimum_level must be one of {list(ASSURANCE_LEVELS)} or null")
        _require_bool(asr, "reject_self_attested_without_prereg", "assurance")
    if "anchors" in policy:
        # WP-A1: the anchor requirement as a POLICY key (v0.2-gated like decision_receipt) — so a
        # relying party pins "must carry a verifying preRegistration anchor" in the policy file
        # instead of remembering CLI flags.
        if policy.get("schema") != POLICY_SCHEMA_V0_2:
            raise PolicyError("anchors section requires schema proofbundle/trust-policy/v0.2")
        anc = _require_dict(policy["anchors"], "anchors")
        _reject_unknown(anc, _ANCHORS_KEYS, "anchors")
        _require_str_or_null(anc, "require_anchor", "anchors")
        rt = anc.get("require_anchor_target")
        if rt is not None and rt not in _ANCHOR_TARGETS:
            raise PolicyError(f"anchors.require_anchor_target must be one of {list(_ANCHOR_TARGETS)} or null")
        _require_bool(anc, "allow_pending", "anchors")
        # WP-A1: relying-party anchor TRUST material carried in the policy file (self-contained, no file
        # paths). trusted_tsa_roots = list of base64 DER cert strings; bitcoin_block_headers = {height(str):
        # merkleRootHex}; trusted_tsa_policy_oids = list of dotted-decimal strings. All optional + fail-closed.
        if "trusted_tsa_roots" in anc:
            roots = anc["trusted_tsa_roots"]
            if not isinstance(roots, list) or not all(isinstance(r, str) and r for r in roots):
                raise PolicyError("anchors.trusted_tsa_roots must be a list of base64 DER certificate strings")
        if "trusted_tsa_policy_oids" in anc:
            oids = anc["trusted_tsa_policy_oids"]
            if not isinstance(oids, list) or not all(isinstance(o, str) and o for o in oids):
                raise PolicyError("anchors.trusted_tsa_policy_oids must be a list of dotted-decimal strings")
        if "bitcoin_block_headers" in anc:
            hdrs = anc["bitcoin_block_headers"]
            if not isinstance(hdrs, dict) or not all(
                    isinstance(k, str) and k.isdigit() and isinstance(v, str) and len(v) == 64
                    for k, v in hdrs.items()):
                raise PolicyError("anchors.bitcoin_block_headers must map a decimal height string to a "
                                  "64-char hex merkle root")
    if "decision_receipt" in policy:
        dr = _require_dict(policy["decision_receipt"], "decision_receipt")
        _reject_unknown(dr, _DECISION_KEYS, "decision_receipt")
        if "trusted_decision_makers" in dr and not isinstance(dr["trusted_decision_makers"], list):
            raise PolicyError("decision_receipt.trusted_decision_makers must be a list")
        for dm in dr.get("trusted_decision_makers", []) or []:
            dm = _require_dict(dm, "trusted_decision_makers[]")
            _reject_unknown(dm, _DECISION_MAKER_KEYS, "trusted_decision_makers[]")
            if not (isinstance(dm.get("public_key_b64"), str) and dm["public_key_b64"]):
                raise PolicyError("each trusted_decision_makers[] entry needs a non-empty public_key_b64")
            _validate_pinned_ed25519_pubkey(dm["public_key_b64"], "trusted_decision_makers[]")
            _require_str_or_null(dm, "id", "trusted_decision_makers[]")
            _require_str_or_null(dm, "kid", "trusted_decision_makers[]")
        for key in ("allowed_decision_types", "allowed_verdicts", "required_evidence_relations",
                    "accepted_predicate_types"):
            if key in dr:
                _require_list_of_str(dr, key, "decision_receipt")
        for key in _DECISION_BOOL_KEYS:
            if key in dr:
                _require_bool(dr, key, "decision_receipt")
    return policy


def evaluate_decision_policy(statement: dict, verify_result: dict, policy: dict, *,
                             signer_public_key_b64: str, anchor_status: str | None = None) -> dict:
    """Apply the v0.2 decision_receipt policy section over an already crypto-verified Decision Receipt. Returns
    ``{"policy_ok": bool|None, "signer_trusted": bool|None, "errors": [...]}``. Never trusts decisionMaker.id on
    the JSON claim alone: the signer key (that verified the DSSE) is matched against trusted_decision_makers.
    policy_ok is None when the policy carries no decision_receipt section (nothing decision-specific to check).

    ``anchor_status`` is the PASS/WARN/FAIL/SKIP verdict from the DETACHED anchor verification done in
    verify_decision_receipt (anchors are not in the signed predicate; Fix 2). require_external_anchor gates on
    it, never on a claimed in-predicate ``status`` field (which does not exist on a real anchor object)."""
    section = policy.get("decision_receipt")
    if not isinstance(section, dict):
        return {"policy_ok": None, "signer_trusted": None, "errors": []}
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    if not isinstance(predicate, dict):
        return {"policy_ok": False, "signer_trusted": False, "errors": ["statement has no predicate object"]}
    errors: list[str] = []

    # AP-2 SIBLING GATE (L5 pre-land audit): the decision path mirrors the eval-path AP-1/AP-2 guards, which
    # previously had NO analog here — a raw, un-instantiated decision template authorised a receipt signed by
    # ANY key, and an expired policy still authorised. A RAW template (requiresIdentityOverlay:true) pins no
    # decision maker and is not deployment-ready → it must never authorise a decision; an EXPIRED policy
    # (valid_until in the past) must not either. Both fail-closed here → policy_ok=False → CLI exit 3
    # (mirrors the eval TEMPLATE_NOT_INSTANTIATED / POLICY_EXPIRED blockers). signer_trusted below stays the
    # by-key match verdict; policy_ok gates the aggregate regardless.
    if policy.get("requiresIdentityOverlay") is True:
        errors.append("policy is a raw template (requiresIdentityOverlay:true) — instantiate it with "
                      "decision_receipt.trusted_decision_makers before using it to authorise a decision")
    if policy_expired(policy):
        errors.append(f"policy valid_until {policy.get('valid_until')!r} is in the past — expired, cannot "
                      "authorise a decision (re-instantiate with a current validity window)")
    if policy_not_yet_valid(policy):
        errors.append(f"policy valid_from {policy.get('valid_from')!r} is in the future — not yet valid, "
                      "cannot authorise a decision (A-P0-2 lifecycle parity)")
    # A-P0-4 §8.2: the decision verifier accepts only a decision-purpose policy. Absent = transitional
    # default (documented), matching the eval path's treatment of legacy policies without the field.
    if policy.get("policyPurpose") is not None and policy["policyPurpose"] != "decision":  # null == absent
        errors.append(f"policyPurpose {policy['policyPurpose']!r} — this policy is not for the "
                      "decision verify path (wrong purpose, fail-closed)")

    # predicateType allow-list (confusion defense at the policy layer)
    apt = section.get("accepted_predicate_types")
    if apt and statement.get("predicateType") not in apt:
        errors.append(f"predicateType {statement.get('predicateType')!r} not in accepted_predicate_types")

    # signer <-> trusted_decision_makers (by public key; decisionMaker.id only as a hint that must not conflict)
    signer_trusted = None
    tdm = section.get("trusted_decision_makers")
    if tdm:
        claimed_id = (predicate.get("decisionMaker") or {}).get("id")
        match = next((m for m in tdm if m.get("public_key_b64") == signer_public_key_b64), None)
        signer_trusted = match is not None
        if match is None:
            errors.append("signer key is not in trusted_decision_makers")
        elif _pinned_key_forgeable(match.get("public_key_b64") or ""):
            # defense-in-depth (fix-review Finding 2): even if this policy dict never went through
            # load_policy, a matched low-order/non-canonical pinned key must not grant trust.
            signer_trusted = False
            errors.append("trusted_decision_makers entry is a low-order/non-canonical key (forgeable) "
                          "— refusing to trust it")
        elif match.get("id") is not None and claimed_id is not None and match["id"] != claimed_id:
            signer_trusted = False
            errors.append("decisionMaker.id does not match the trusted entry for this signer key")

    dt = predicate.get("decisionType")
    if section.get("allowed_decision_types") and dt not in section["allowed_decision_types"]:
        errors.append(f"decisionType {dt!r} not allowed by policy")
    verdict = (predicate.get("decision") or {}).get("verdict")
    if section.get("allowed_verdicts") and verdict not in section["allowed_verdicts"]:
        errors.append(f"verdict {verdict!r} not allowed by policy")

    req_rel = section.get("required_evidence_relations") or []
    if req_rel:
        have = {r.get("relation") for r in predicate.get("evidenceRefs", []) if isinstance(r, dict)}
        missing = [r for r in req_rel if r not in have]
        if missing:
            errors.append(f"required evidence relations missing: {missing}")

    if section.get("require_policy_digest"):
        pd = (predicate.get("policyBoundary") or {}).get("policyDigest")
        if not (isinstance(pd, dict) and isinstance(pd.get("sha256"), str)):
            errors.append("policy requires policyBoundary.policyDigest but it is absent")

    # validity presence knobs (§7.5): the VALUE binding is still --aud/--nonce; these require the fields be
    # PRESENT so a receipt cannot silently drop replay protection.
    _vraw = predicate.get("validity")
    validity = _vraw if isinstance(_vraw, dict) else {}
    if section.get("require_audience") and not (isinstance(validity.get("audience"), list) and validity.get("audience")):
        errors.append("policy requires validity.audience but it is absent or empty")
    if section.get("require_nonce") and not (isinstance(validity.get("nonce"), str) and validity.get("nonce")):
        errors.append("policy requires validity.nonce but it is absent")

    # reviewability knobs (§5.5): notChecked / decisionChangeConditions must be present, non-empty lists.
    if section.get("require_not_checked") and not (
            isinstance(predicate.get("notChecked"), list) and predicate.get("notChecked")):
        errors.append("policy requires a non-empty notChecked[] but it is absent or empty")
    if section.get("require_decision_change_conditions") and not (
            isinstance(predicate.get("decisionChangeConditions"), list) and predicate.get("decisionChangeConditions")):
        errors.append("policy requires a non-empty decisionChangeConditions[] but it is absent or empty")
    if section.get("require_trace_context") and not isinstance(predicate.get("traceContext"), dict):
        errors.append("policy requires traceContext but it is absent")

    # privacy: allow_raw_inputs defaults FALSE — a receipt carrying raw inputs is rejected unless opted in.
    if not section.get("allow_raw_inputs"):
        _praw = predicate.get("privacy")
        priv = _praw if isinstance(_praw, dict) else {}
        if priv.get("rawInputsIncluded") is True:
            errors.append("privacy.rawInputsIncluded=true but the policy does not allow raw inputs (allow_raw_inputs)")

    if section.get("require_external_anchor"):
        allow_pending = bool(section.get("allow_pending"))
        # Anchors are DETACHED (Fix 2): the real anchor verification ran in verify_decision_receipt and its
        # status is passed in as anchor_status. A PASS (a full verifying anchor) always satisfies; a
        # pending/inclusion-only anchor (WARN) satisfies ONLY when allow_pending is set (default false —
        # pending is the ABSENCE of a time anchor, not a weaker one). SKIP (no anchors) and FAIL never satisfy.
        satisfied = anchor_status == "PASS" or (allow_pending and anchor_status == "WARN")
        if not satisfied:
            errors.append(
                f"policy requires an external anchor but none satisfies it (anchor status: {anchor_status or 'none'}"
                + ("" if allow_pending else "; pending excluded, set allow_pending to accept a pending anchor") + ")")

    policy_ok = (not errors) and (signer_trusted is not False)
    return {"policy_ok": policy_ok, "signer_trusted": signer_trusted, "errors": errors}


def policy_expected_aud(policy: dict):
    """The aud the policy wants bound (sd_jwt.expected_aud), or None. Used by the CLI to reconcile
    with the --aud flag (a policy/flag conflict is an error, never a silent override)."""
    return (policy.get("sd_jwt") or {}).get("expected_aud")


def policy_anchor_trust(policy: dict) -> dict | None:
    """WP-A1: the relying-party anchor TRUST material carried in the policy's ``anchors`` section, as an
    ``rp_trust`` dict (``trusted_tsa_roots`` / ``bitcoin_block_headers`` / ``trusted_tsa_policy_oids``), or
    None when the policy declares none. Mirrors the CLI ``--trusted-tsa-root`` / ``--bitcoin-header``; the
    CLI unions the two. Validated already in ``load_policy`` (fail-closed), so this is a pure projection."""
    anc = policy.get("anchors") or {}
    rp: dict = {}
    if anc.get("trusted_tsa_roots"):
        rp["trusted_tsa_roots"] = list(anc["trusted_tsa_roots"])
    if anc.get("bitcoin_block_headers"):
        rp["bitcoin_block_headers"] = {str(k): v.lower() for k, v in anc["bitcoin_block_headers"].items()}
    if anc.get("trusted_tsa_policy_oids"):
        rp["trusted_tsa_policy_oids"] = list(anc["trusted_tsa_policy_oids"])
    return rp or None


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

    # A policy is NEVER evaluated on unverified bytes (verify-lens L2): enforce the module invariant
    # HERE, not only in the CLI caller, so any public-API consumer of evaluate_policy is safe too.
    if not getattr(result, "ok", False):
        return {"policy_ok": None, "checks": [],
                "reason": "crypto verification did not pass — policy not evaluated"}

    sig = bundle.get("signature") or {}

    # 0. A-P0-2 §6 + A-P0-4 §8: policy LIFECYCLE and PURPOSE are part of the policy evaluation
    # itself (POLICY: FAIL, exit 3) — parity with the decision path's AP-2 sibling gate. Previously
    # an expired eval policy still produced POLICY: OK while only safeForAutomation went false.
    if policy.get("policyPurpose") is not None:   # null == absent (Lens-4 F1)
        purpose_ok = policy["policyPurpose"] == "eval"
        add("policy:purpose", purpose_ok,
            f"policyPurpose {policy['policyPurpose']!r} accepted on the eval verify path" if purpose_ok
            else f"policyPurpose {policy['policyPurpose']!r} — this policy is not for the eval "
                 "verify path (wrong purpose, fail-closed)")
    if policy.get("requiresIdentityOverlay") is True:
        add("policy:not_template", False,
            "policy is a raw template (requiresIdentityOverlay:true) — instantiate it with a "
            "signer identity before using it to authorise anything")
    _expired = policy_expired(policy, now=now)
    if _expired is not None:
        add("policy:not_expired", not _expired,
            f"policy valid_until {policy.get('valid_until')!r} is in the past — expired "
            "(re-instantiate with a current validity window, or verify historically with an "
            "explicit --verification-time)" if _expired
            else f"policy valid until {policy.get('valid_until')!r}")
    _nyv = policy_not_yet_valid(policy, now=now)
    if _nyv is not None:
        add("policy:not_before", not _nyv,
            f"policy valid_from {policy.get('valid_from')!r} is in the future — not yet valid" if _nyv
            else f"policy valid from {policy.get('valid_from')!r}")

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
        # defense-in-depth (fix-review Finding 2): a low-order/non-canonical allowed_issuers key is
        # forgeable — never let it match, even if this policy dict skipped load_policy.
        allowed_keys = {i.get("public_key_b64") for i in allowed_issuers
                        if not _pinned_key_forgeable(i.get("public_key_b64") or "")}
        matched = signer_key in allowed_keys and signer_key is not None
        if not allowed_issuers and require_signer:
            add("policy:signer_allowed", False,
                "require_expected_signer is set but allowed_issuers is empty — no signer can match (fail-closed)")
        else:
            add("policy:signer_allowed", matched,
                "signer public key is in allowed_issuers" if matched
                else "signer public key is NOT in allowed_issuers")

    # 4. merkle required hash alg
    mk_pol = policy.get("merkle") or {}
    required_hash = mk_pol.get("required_hash_alg")
    if required_hash is not None:
        got = (bundle.get("merkle") or {}).get("hash_alg")
        add("policy:merkle_hash_alg", got == required_hash,
            f"merkle.hash_alg {got!r} != required {required_hash!r}" if got != required_hash
            else f"merkle.hash_alg {got!r} matches")

    root_authenticated = None

    # 4b. A-P0-1 §5: trusted CHECKPOINTS — root and tree size authenticated ATOMICALLY from one signed
    # source. A naked root pin (4c) can never tell a (index, tree_size) relabel apart (the relabelled
    # proof carries the SAME root); only a match of BOTH fields against ONE authenticated checkpoint sets
    # tree_context_authenticated. Evaluated BEFORE 4c (Lens-6 review) so a matching checkpoint — which
    # cryptographically authenticates the root, strictly stronger than a trusted_roots byte-pin — also
    # satisfies a belt-and-suspenders require_authenticated_root. Non-empty trusted_checkpoints ENFORCE
    # on their own, exactly like trusted_roots.
    tree_context_authenticated = None
    checkpoint_authenticity = None
    _cp_matched = False
    trusted_checkpoints = mk_pol.get("trusted_checkpoints") or []
    if trusted_checkpoints:
        stated_root_b64 = (bundle.get("merkle") or {}).get("root_b64")
        try:
            stated_root = base64.b64decode(stated_root_b64, validate=True) \
                if isinstance(stated_root_b64, str) else b""
        except (ValueError, TypeError):
            stated_root = b""
        stated_size = (bundle.get("merkle") or {}).get("tree_size")
        matched = False
        reasons: list = []
        for i, entry in enumerate(trusted_checkpoints):
            cp_ok, cp_reason = _authenticate_trusted_checkpoint(entry, now=now)
            if not cp_ok:
                reasons.append(f"[{i}] {cp_reason}")
                continue
            try:
                entry_root = base64.b64decode(entry["root"], validate=True)
            except (ValueError, TypeError):
                reasons.append(f"[{i}] pinned root is not decodable")   # load_policy prevents this
                continue
            root_match = bool(stated_root) and hmac.compare_digest(stated_root, entry_root)
            size_match = stated_size == entry["treeSize"] and not isinstance(stated_size, bool)
            if root_match and size_match:
                matched = True
                break
            # STATIC reason (no root_match/size_match interpolation): both derive from the checkpoint
            # entry (key-adjacent input), so echoing them into the operator-facing POLICY log is flagged
            # py/clear-text-logging-sensitive-data (CodeQL). The message stays informative without the
            # entry-derived booleans.
            reasons.append(f"[{i}] authenticated checkpoint does not match this bundle's "
                           "(root, tree_size) — an atomic pair, a partial match is a substitution signal")
        # checkpoint_authenticity reports whether a checkpoint authenticated AND MATCHED this bundle —
        # NOT merely that some pinned checkpoint's signature verified (Lens-3/4 review: a verified but
        # NON-matching checkpoint must not read PASS, else rootTrustLevel would overclaim CHECKPOINT).
        checkpoint_authenticity = "PASS" if matched else "FAIL"
        tree_context_authenticated = matched
        _cp_matched = matched
        add("policy:trusted_checkpoint", matched,
            "stated (root, tree_size) atomically authenticated by a pinned signed checkpoint" if matched
            else "no pinned trusted checkpoint atomically authenticates this bundle's "
                 f"(root, tree_size): {'; '.join(reasons) or 'no entries'}")
        if matched:
            root_authenticated = True   # the checkpoint authenticates the root bytes too

    # 4c. merkle root AUTHENTICATION (P0-A §6.2): the stated root is not signed, so a coherent one-leaf
    # rewrap re-anchors the same payload under a different root. Require the root be authenticated —
    # either the relying party supplied a matching --expected-root (a passing root-authenticity check
    # ran in verify_bundle) OR the stated root is one of the policy's trusted_roots (compared by BYTES;
    # a malformed trusted entry never matches, fail-closed) OR a pinned checkpoint matched (4b, above).
    # ``root_authenticated`` is surfaced so the CLI can fold it into the structured rootAuthenticity
    # verdict even when no --expected-root was given.
    require_auth_root = bool(mk_pol.get("require_authenticated_root"))
    trusted_roots = mk_pol.get("trusted_roots") or []
    if require_auth_root or trusted_roots:
        ra_check = next((c for c in result.checks if c.name == "root-authenticity"), None)
        via_expected = ra_check is not None and ra_check.ok
        stated_root_b64 = (bundle.get("merkle") or {}).get("root_b64")
        try:
            stated_root = base64.b64decode(stated_root_b64, validate=True) if isinstance(stated_root_b64, str) else b""
        except (ValueError, TypeError):
            stated_root = b""
        via_trusted = False
        for tr in trusted_roots:
            try:
                cand = base64.b64decode(tr, validate=True)
            except (ValueError, TypeError):
                continue   # a malformed trusted_root never matches (fail-closed)
            if stated_root and hmac.compare_digest(stated_root, cand):
                via_trusted = True
                break
        # A matching checkpoint (4b) authenticates the root too (Lens-6 review): a belt-and-suspenders
        # require_authenticated_root + trusted_checkpoints config must not fail closed on a real match.
        root_authenticated = bool(via_expected or via_trusted or _cp_matched)
        # A non-empty trusted_roots ENFORCES on its own (not only when require_authenticated_root is set):
        # listing the roots you trust means the stated root MUST be one of them, else a policy that pins
        # trusted_roots but forgets the boolean would silently pass a foreign root (fail-open footgun,
        # 6-lens review 2026-07-12). explain_policy lists both, so explain⟺enforce parity holds.
        add("policy:authenticated_root", root_authenticated,
            "stated root authenticated (matches --expected-root, a trusted_roots entry, or a pinned "
            "checkpoint)" if root_authenticated
            else "policy requires an AUTHENTICATED merkle root, but the stated root matches neither "
                 "--expected-root nor any trusted_roots entry nor a pinned checkpoint (coherent-rewrap "
                 "guard, fail-closed)")

    # 5. SD-JWT / KB-JWT policy. The aud VALUE was already bound by verify_bundle (the CLI passed the
    #    reconciled effective aud); here we enforce the remaining presence/structure requirements.
    sdj = policy.get("sd_jwt") or {}
    sd = bundle.get("sd_jwt_vc")
    kb = None
    if isinstance(sd, dict) and isinstance(sd.get("compact"), str):
        kb = verify_key_binding(sd["compact"])   # read aud/nonce/iat/present (value binding done in verify_bundle)
    if sdj.get("require_key_binding_when_cnf_present"):
        # verify_bundle already fails closed on a cnf-bound SD-JWT without a KB-JWT; reflect it here so
        # the policy states the requirement explicitly. The crypto result's sd-jwt-key-binding check is
        # authoritative when present.
        kb_check = next((c for c in result.checks if c.name == "sd-jwt-key-binding"), None)
        if kb_check is not None:
            add("policy:key_binding_present", kb_check.ok,
                "key binding verified" if kb_check.ok else f"key binding failed: {kb_check.detail}")
        elif kb is not None and kb.get("present"):
            # a KB-shaped segment IS attached but no crypto verdict exists for it (no cnf AND no issuer
            # key → sd-jwt-key-binding was never run). An UNVERIFIED KB is not an acceptable "key
            # binding present" → fail closed (verify-lens L1, the previously missing else branch).
            add("policy:key_binding_present", False,
                "a KB-JWT segment is attached but its issuer signature was never verified — cannot "
                "confirm key binding (fail-closed; supply sd_jwt_vc.issuer_public_key_b64)")
        else:
            # genuinely no cnf holder key bound and no KB attached → nothing to require, vacuous pass.
            add("policy:key_binding_present", True, "no cnf holder key bound; KB not required")
    if sdj.get("require_nonce"):
        # A nonce only means anything when it comes from a VERIFIED key binding (verify-lens L1/L2,
        # HIGH): reading kb["nonce"] straight from an unauthenticated/unsigned KB-JWT was a false PASS.
        # Gate on the authoritative crypto verdict (the sd-jwt-key-binding check's .ok); no verified KB
        # → fail closed (an unauthenticated nonce provides no replay protection). This enforces the
        # PRESENCE of a nonce in a verified KB-JWT; binding the nonce VALUE to this transaction still
        # requires --nonce (RFC 9901 challenge, exactly like --aud) — see docs/TRUST_ANCHORS.md.
        kb_check = next((c for c in result.checks if c.name == "sd-jwt-key-binding"), None)
        verified_nonce = bool(kb_check is not None and kb_check.ok and kb and kb.get("nonce"))
        add("policy:nonce_present", verified_nonce,
            "verified KB-JWT carries a nonce" if verified_nonce
            else "policy requires a nonce from a VERIFIED key binding, but none is present "
                 "(fail-closed: an unauthenticated nonce provides no replay protection)")

    # 6. status — verify --policy v0.1 has NO status-snapshot input, so an ENABLED status requirement
    #    cannot be evaluated here. Fail closed rather than silently pass (the honest boundary).
    status = policy.get("status") or {}
    if status.get("reject_self_issued") or (status.get("allowed_status_authorities") or []):
        add("policy:status", False,
            "policy enables a status requirement, but verify --policy (v0.1) has no status-snapshot "
            "input — evaluate revocation separately with verify_status_snapshot (fail-closed)")

    # 7. assurance + freshness — only meaningful for an issuer-bound eval receipt. Decode once.
    # NOTE (No-Overclaim, 6-lens review): despite the RFC-9901-evoking name, `sd_jwt.max_iat_age_seconds`
    # bounds the EVAL CLAIM's own `timestamp` (via check_freshness below), NOT the KB-JWT `iat`. It does
    # NOT give KB-JWT presentation-replay freshness (kbjwt.py carries no clock-based iat window); a
    # captured KB-JWT presentation still replays as long as the underlying claim is within this age.
    # explain_policy() labels it "eval claim freshness" for exactly this reason.
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
    return {"policy_ok": policy_ok, "checks": checks, "reason": reason,
            "root_authenticated": root_authenticated,
            # A-P0-1: True/False only when trusted_checkpoints were pinned (enforced), else None.
            "tree_context_authenticated": tree_context_authenticated,
            "checkpoint_authenticity": checkpoint_authenticity}


# ── WP-TP1: explain / lint / vacuous-pass warning ────────────────────────────

def explain_policy(policy: dict) -> list:
    """Human-readable list of the EFFECTIVE pins a (already load_policy-validated) policy makes.

    One line per active constraint; an empty list means the policy pins nothing (see
    :func:`lint_policy` — such a policy is wirkungslos and `POLICY: OK` under it attributes the
    bytes to nobody)."""
    lines: list = []
    # A-P0-4/A-P0-2: purpose, lifecycle and the raw-template flag are ENFORCED by evaluate_policy (exit
    # 3), so explain MUST list them (explain⟺enforce parity — else lint calls a policy vacuous that
    # verify FAILs, Lens-2 review).
    if policy.get("requiresIdentityOverlay") is True:
        lines.append("raw template (requiresIdentityOverlay:true) — must be instantiated (policy:not_template)")
    if policy.get("policyPurpose") is not None:
        lines.append(f"policyPurpose == {policy['policyPurpose']!r} (wrong verifier path fails)")
    if policy.get("valid_from") is not None:
        lines.append(f"not valid before {policy['valid_from']} (policy:not_before)")
    if policy.get("valid_until") is not None:
        lines.append(f"expires {policy['valid_until']} (policy:not_expired)")
    if policy.get("allowed_schema_versions"):
        lines.append(f"schema version in {policy['allowed_schema_versions']}")
    for issuer in policy.get("allowed_issuers", []) or []:
        who = issuer.get("issuer") or issuer.get("kid") or "(unnamed)"
        key = issuer.get("public_key_b64", "")
        lines.append(f"issuer {who}: public key pinned ({key[:12]}…)")
    sig = policy.get("signature") or {}
    if sig.get("allowed_algs"):
        lines.append(f"signature alg in {sig['allowed_algs']}")
    if sig.get("require_expected_signer"):
        lines.append("signer MUST match an allowed_issuers entry (require_expected_signer)")
    mk = policy.get("merkle") or {}
    if mk.get("required_hash_alg") is not None:
        # evaluate_policy enforces this whenever it is not None (incl. an empty string), so explain
        # must list it too — otherwise lint calls the policy vacuous while verify actually FAILs it.
        lines.append(f"merkle.hash_alg == {mk['required_hash_alg']!r}")
    if mk.get("require_authenticated_root"):
        lines.append("merkle root MUST be authenticated (--expected-root or trusted_roots; coherent-rewrap guard)")
    if mk.get("trusted_roots"):
        lines.append(f"merkle root in trusted_roots ({len(mk['trusted_roots'])} pinned) — root BYTES "
                     "only, not tree context")
    if mk.get("trusted_checkpoints"):
        lines.append(f"(root, tree_size) atomically authenticated by a pinned signed checkpoint "
                     f"({len(mk['trusted_checkpoints'])} pinned; A-P0-1 tree-context guard)")
    sdj = policy.get("sd_jwt") or {}
    if sdj.get("require_key_binding_when_cnf_present"):
        lines.append("SD-JWT: key binding required when cnf present")
    if sdj.get("expected_aud") is not None:
        lines.append(f"SD-JWT: audience == {sdj['expected_aud']!r}")
    if sdj.get("require_nonce"):
        lines.append("SD-JWT: nonce required from a VERIFIED key binding")
    if sdj.get("max_iat_age_seconds") is not None:
        lines.append(f"eval claim freshness <= {sdj['max_iat_age_seconds']}s")
    st = policy.get("status") or {}
    if st.get("reject_self_issued") or (st.get("allowed_status_authorities") or []):
        lines.append("status-list requirement declared (v0.1 verify has no snapshot input: fail-closed)")
    asr = policy.get("assurance") or {}
    if asr.get("minimum_level") is not None:
        lines.append(f"assurance_level >= {asr['minimum_level']!r}")
    if asr.get("reject_self_attested_without_prereg"):
        lines.append("self_attested without prereg_sha256 rejected")
    # WP3 (v2-audit): the anchors section is a REAL pin — the CLI (`_cmd_verify`) reads
    # policy["anchors"] to populate the --require-anchor / --anchor-target / --allow-pending gate
    # (exit 3 when unmet), but explain_policy previously never listed it: a policy whose ONLY pin was
    # `anchors.require_anchor` looked "wirkungslos" to `policy lint` (a false vacuous-policy verdict for
    # a pin `verify --policy` genuinely enforces). Listed here so explain/lint agree with what verify
    # actually gates on; evaluate_policy() itself is unchanged (the anchor gate lives in the CLI, not in
    # evaluate_policy, exactly as before).
    anc = policy.get("anchors") or {}
    req_anchor = anc.get("require_anchor")
    req_target = anc.get("require_anchor_target")
    if req_anchor is not None or req_target is not None:
        detail = f"type={req_anchor!r}" if req_anchor is not None else "any type"
        if req_target is not None:
            detail += f", target={req_target!r}"
        if anc.get("allow_pending"):
            detail += " (pending accepted)"
        lines.append(f"external time anchor required ({detail})")
    dr = policy.get("decision_receipt") or {}
    if dr:
        active = [k for k in dr if dr.get(k)]
        lines.append(f"decision_receipt section active ({len(active)} knob(s): {sorted(active)})")
    return lines


def _attributes_to_nobody(policy: dict) -> bool:
    """True iff the policy pins NO signer identity: no allowed_issuers AND no
    require_expected_signer (eval side) AND no trusted_decision_makers (decision side). Crypto OK
    under such a policy proves integrity by an UNKNOWN party — 'attribution to nobody'
    (docs/TRUST_ANCHORS.md's first row)."""
    has_issuers = bool(policy.get("allowed_issuers"))
    has_require = bool((policy.get("signature") or {}).get("require_expected_signer"))
    has_dm = bool((policy.get("decision_receipt") or {}).get("trusted_decision_makers"))
    return not (has_issuers or has_require or has_dm)


def policy_warnings(policy: dict) -> list:
    """Non-fatal honesty warnings for a valid policy (surfaced by `verify` next to POLICY: OK)."""
    warnings: list = []
    if _attributes_to_nobody(policy):
        warnings.append(
            "attributes to nobody: the policy pins no signer (no allowed_issuers, no "
            "require_expected_signer) — POLICY: OK then proves integrity by an UNKNOWN party. "
            "Pin the expected issuer key(s).")
    return warnings


def policy_expired(policy: dict, *, now=None) -> Union[bool, None]:
    """AP-2 §6.4: True iff the policy carries a ``valid_until`` in the PAST, False iff it carries one still
    in the future, None iff it carries none (nothing to expire). ``now`` is an aware datetime for tests
    (defaults to the current UTC time). An unparseable value is treated as None here — load_policy already
    rejects a malformed ``valid_until`` fail-closed, so this projection never sees one from a loaded policy."""
    vu = policy.get("valid_until")
    if vu is None:
        return None
    parsed = _parse_iso_utc(vu)
    if parsed is None:
        return None
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current > parsed


def policy_not_yet_valid(policy: dict, *, now=None) -> Union[bool, None]:
    """A-P0-2 §6: True iff the policy carries a ``valid_from`` still in the FUTURE, False iff it
    carries one already reached, None iff it carries none. Mirrors :func:`policy_expired`; both are
    enforced inside the policy evaluation (POLICY: FAIL, exit 3), never only advisory."""
    vf = policy.get("valid_from")
    if vf is None:
        return None
    parsed = _parse_iso_utc(vf)
    if parsed is None:
        return None
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current < parsed


def _authenticate_trusted_checkpoint(entry: dict, *, now=None) -> tuple[bool, str]:
    """A-P0-1: authenticate ONE merkle.trusted_checkpoints[] entry. Returns (ok, reason).

    The (origin, treeSize, root) triple is reconstructed into the exact C2SP note text and the
    pinned signature is verified under the pinned ``checkpointSigner`` vkey — so tampering ANY of
    the three fields (origin substitution, size relabel, root swap) invalidates the signature.
    ``hashAlg`` must be the one algorithm of this format version and ``validUntil`` (when present)
    must not be in the past. Fail-closed: any parse/crypto error is (False, reason)."""
    from .checkpoint import checkpoint_note, verify_checkpoint  # noqa: PLC0415 — lazy, avoids import cycles
    # The returned reason strings are STATIC (no interpolation of `entry` field values): a
    # trusted_checkpoints entry carries `signature` + `checkpointSigner` key material, so echoing ANY
    # of its fields into a reason that reaches the operator-facing POLICY log is flagged
    # `py/clear-text-logging-sensitive-data` (CodeQL, HIGH) even for a non-secret field — and matches
    # the repo convention of never letting key-adjacent input flow into a clear-text log. The entry is
    # identified by its index in the caller's aggregate reason.
    if entry.get("hashAlg") != "sha256-rfc6962":
        return False, "unsupported checkpoint hashAlg (this format version authenticates " \
                      "sha256-rfc6962 trees only)"
    vu = entry.get("validUntil")
    if vu is not None:
        parsed = _parse_iso_utc(vu)
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        if parsed is not None and current > parsed:
            return False, "trusted checkpoint expired (validUntil is in the past)"
    try:
        root = base64.b64decode(entry["root"], validate=True)
        keyname = entry["checkpointSigner"].split("+", 1)[0]
        note = checkpoint_note(entry["origin"], entry["treeSize"], root)
        signed_note = f"{note}\n— {keyname} {entry['signature']}\n"
        res = verify_checkpoint(signed_note, entry["checkpointSigner"])
    except ProofBundleError:
        return False, "trusted checkpoint does not authenticate (checkpoint note or signature rejected)"
    except (ValueError, TypeError, KeyError, AttributeError):
        # AttributeError (Lens-6 review): a non-string checkpointSigner (.split) in a raw dict that
        # bypassed load_policy must fail closed here, never escape as a traceback — the evaluate layer
        # stays robust for library callers who hand evaluate_policy an unvalidated policy dict. Static
        # reason (no exception text) so no entry-derived value flows to the operator log.
        return False, "trusted checkpoint is malformed (missing or invalid field)"
    if not res.get("ok"):
        return False, "trusted checkpoint signature does not verify under the pinned " \
                      "checkpointSigner (origin/size/root tamper or signer mismatch)"
    return True, "checkpoint signature verified"


def lint_policy(policy: dict, *, strict: bool = False, now=None) -> dict:
    """Lint a policy for WIRKUNGSLOSIGKEIT (vacuous pass), fail-closed style.

    Returns ``{ok, errors, warnings, pins}``. ``errors`` (lint failures, exit != 0 in the CLI):
    the policy makes NO effective pin at all — `evaluate_policy` would return ``policy_ok=True``
    with an EMPTY check list (``all([]) is True``), the exact vacuous-pass trap TP1 closes.
    ``strict`` additionally promotes the attributes-to-nobody warning to an error AND rejects a raw
    template used productively (AP-2 §6.4). ``now`` is threaded into the expiry check for tests."""
    pins = explain_policy(policy)
    errors: list = []
    warnings = policy_warnings(policy)
    if not pins:
        errors.append(
            "policy pins nothing (only schema/policy_id): every verify would report POLICY: OK "
            "with zero checks evaluated — a vacuous pass, not a trust decision")
    # UNSATISFIABLE (six-lens review): require_expected_signer with no allowed_issuers can NEVER pass
    # (no signer key can match an empty list) — evaluate_policy fail-closes every verify to exit 3.
    # That is a policy bug, not a valid pin, so it is a lint ERROR (always, not just --strict).
    if (policy.get("signature") or {}).get("require_expected_signer") and not policy.get("allowed_issuers"):
        errors.append(
            "require_expected_signer is set but allowed_issuers is empty — unsatisfiable: no signer "
            "key can ever match, so every verify FAILs (exit 3). Add the expected issuer key(s).")
    # AP-2 §6.4: an EXPIRED policy is unsafe to depend on — a hard lint failure in BOTH modes (it is a
    # correctness/lifecycle failure, not a strictness preference). valid_until is a new additive field, so
    # no pre-existing policy is affected.
    if policy_expired(policy, now=now):
        errors.append(
            f"policy valid_until {policy.get('valid_until')!r} is in the past — expired, do not deploy "
            "(re-instantiate the template with a current validity window)")
    if strict:
        # A-P0-4 §8.3: in strict mode a policy MUST declare its purpose — an un-purposed policy is
        # usable on any verifier path, exactly the confusion the field exists to close.
        if policy.get("policyPurpose") is None:   # absent OR explicit null (Lens-4 F1)
            errors.append(
                "policyPurpose is missing — declare which verifier path this policy is for "
                f"(one of {list(POLICY_PURPOSES)}); required in strict mode")
        # AP-2 §6.4: a raw TEMPLATE must never back a productive automation decision. deploymentReady:false
        # (an un-instantiated template) and a still-set requiresIdentityOverlay:true (no identity overlay
        # applied) are both lint failures under --strict.
        if policy.get("deploymentReady") is False:
            errors.append(
                "deploymentReady:false — this is a raw trust-policy TEMPLATE, not a deployment-ready "
                "policy; instantiate it first (`proofbundle policy instantiate <name> …`)")
        if policy.get("requiresIdentityOverlay") is True and _attributes_to_nobody(policy):
            errors.append(
                "requiresIdentityOverlay:true but the policy pins no signer identity — a template used "
                "without its identity overlay; pin allowed_issuers (or trusted_decision_makers) first")
        errors.extend(warnings)
        warnings = []
    return {"ok": not errors, "errors": errors, "warnings": warnings, "pins": pins}
