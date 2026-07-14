"""Public Transparency profile — 3.2.0 O3 (EXPERIMENTAL).

A relying-party policy layer over the existing C2SP checkpoint primitives (``checkpoint.py``): it composes
signature / origin / root / tree-context / consistency / witness-quorum checks into ONE unified verdict with
named statuses, so a public-log claim is evaluated against an explicit policy rather than ad hoc.

Named statuses (each PASS / FAIL / NOT_EVALUATED):

  LOG_ORIGIN                the checkpoint origin is on the policy's trusted-origin allowlist
  CHECKPOINT_SIGNATURE      the checkpoint is signed by a trusted log key (verify_checkpoint)
  ROOT_BYTES_AUTHENTICITY   the checkpoint root equals a root the relying party supplied from its own source
  TREE_CONTEXT_AUTHENTICITY the checkpoint tree size equals a size the relying party supplied
  CONSISTENCY               a consistency proof was required and confirmed (append-only, no fork)
  WITNESS_QUORUM            >= threshold distinct witnesses cosigned (witness_quorum)
  PUBLIC_TRANSPARENCY       aggregate: every REQUIRED status PASS and none FAIL

Fail-closed (§O3): a REQUIRED check whose material is missing is FAIL, never NOT_EVALUATED / SKIP — a
requested guarantee that cannot be enforced is a failure. An OPTIONAL check the policy did not request is
NOT_EVALUATED and stays VISIBLE in the output (anchors-present-but-not-evaluated is never silently omitted).

No-Overclaim: PUBLIC_TRANSPARENCY: PASS attests that the named checks held against this policy — never a
general SCITT/RFC-9943 conformance claim without interop vectors, and never that the logged claim is true.
"""
from __future__ import annotations

from typing import Any

from .errors import ProofBundleError

_STATUS_NAMES = (
    "LOG_ORIGIN", "CHECKPOINT_SIGNATURE", "ROOT_BYTES_AUTHENTICITY",
    "TREE_CONTEXT_AUTHENTICITY", "CONSISTENCY", "WITNESS_QUORUM",
)
_POLICY_KEYS = {"requireSignedCheckpoint", "trustedLogOrigins", "trustedLogKeys",
                "requireConsistencyProof", "witnessQuorum"}


class PublicTransparencyError(ProofBundleError):
    """A public-transparency policy is malformed (fail-closed)."""


def validate_public_transparency_policy(policy: Any) -> list[str]:
    """Fail-closed validation of a public-transparency policy object (empty = valid)."""
    errors: list[str] = []
    if not isinstance(policy, dict):
        return ["policy must be a JSON object"]
    for k in policy:
        if k not in _POLICY_KEYS:
            errors.append(f"unknown policy key {k!r}")
    if "requireSignedCheckpoint" in policy and not isinstance(policy["requireSignedCheckpoint"], bool):
        errors.append("requireSignedCheckpoint must be a boolean")
    if "requireConsistencyProof" in policy and not isinstance(policy["requireConsistencyProof"], bool):
        errors.append("requireConsistencyProof must be a boolean")
    for lk in ("trustedLogOrigins", "trustedLogKeys"):
        if lk in policy and not (isinstance(policy[lk], list) and all(isinstance(x, str) for x in policy[lk])):
            errors.append(f"{lk} must be a list of strings")
    wq = policy.get("witnessQuorum")
    if "witnessQuorum" in policy:
        if not isinstance(wq, dict) or "threshold" not in wq:
            errors.append("witnessQuorum must be an object with a 'threshold'")
        else:
            th = wq.get("threshold")
            if not (isinstance(th, int) and not isinstance(th, bool) and th >= 1):
                errors.append("witnessQuorum.threshold must be an integer >= 1")
            for k in wq:
                if k not in ("threshold",):
                    errors.append(f"witnessQuorum.{k} is not an allowed field")
    return errors


def evaluate_public_transparency(
    signed_note: str, policy: dict, *, log_vkey: str | None = None,
    witness_vkeys: list | None = None, expected_root_b64: str | None = None,
    expected_tree_size: int | None = None, consistency_confirmed: bool | None = None,
) -> dict:
    """Evaluate a signed checkpoint against a public-transparency policy → unified named-status verdict.

    ``consistency_confirmed`` is the relying party's OWN result of a consistency-proof check (append-only, no
    fork) computed elsewhere; when the policy requires consistency it MUST be True, else FAIL. It is passed in
    (not computed here) because a consistency proof is between two checkpoints the relying party holds — this
    layer records the verdict, fail-closed. Read PUBLIC_TRANSPARENCY — never an individual status alone."""
    from . import checkpoint as cp  # noqa: PLC0415

    perrs = validate_public_transparency_policy(policy)
    if perrs:
        raise PublicTransparencyError("invalid public-transparency policy: " + "; ".join(perrs))

    statuses: dict[str, str] = {n: "NOT_EVALUATED" for n in _STATUS_NAMES}
    errors: list[str] = []

    # Parse the checkpoint once (origin/tree_size/root need at least a parseable note). A malformed note is a
    # hard structural failure across every check that reads it.
    parsed_ok = True
    origin = tree_size = root = None
    try:
        # verify_checkpoint parses AND checks the signature; when no log_vkey is available we still want the
        # parsed origin/size/root, so parse defensively via a trivial re-parse of the note text.
        note_text = signed_note.split("\n\n", 1)[0] + "\n"
        lines = note_text.split("\n")
        origin = lines[0]
        tree_size = int(lines[1])
        root = lines[2]  # base64 root as-is
    except (ValueError, IndexError):
        parsed_ok = False
        errors.append("checkpoint note is malformed (cannot parse origin/tree_size/root)")

    require_sig = bool(policy.get("requireSignedCheckpoint"))
    trusted_origins = policy.get("trustedLogOrigins")
    trusted_keys = policy.get("trustedLogKeys")

    # CHECKPOINT_SIGNATURE
    if require_sig:
        if not parsed_ok:
            statuses["CHECKPOINT_SIGNATURE"] = "FAIL"
        elif not log_vkey:
            statuses["CHECKPOINT_SIGNATURE"] = "FAIL"
            errors.append("requireSignedCheckpoint but no log vkey supplied (fail-closed)")
        elif isinstance(trusted_keys, list) and trusted_keys and log_vkey not in trusted_keys:
            statuses["CHECKPOINT_SIGNATURE"] = "FAIL"
            errors.append("supplied log vkey is not on the policy's trustedLogKeys allowlist")
        else:
            try:
                res = cp.verify_checkpoint(signed_note, log_vkey)
                statuses["CHECKPOINT_SIGNATURE"] = "PASS" if res.get("ok") else "FAIL"
                if not res.get("ok"):
                    errors.append("checkpoint signature did not verify against the supplied log vkey")
            except ProofBundleError:
                statuses["CHECKPOINT_SIGNATURE"] = "FAIL"
                errors.append("checkpoint signature check raised (malformed note/vkey)")

    # LOG_ORIGIN
    if isinstance(trusted_origins, list) and trusted_origins:
        if parsed_ok and origin in trusted_origins:
            statuses["LOG_ORIGIN"] = "PASS"
        else:
            statuses["LOG_ORIGIN"] = "FAIL"
            errors.append(f"checkpoint origin {origin!r} is not on the trustedLogOrigins allowlist")

    # ROOT_BYTES_AUTHENTICITY — only when the relying party supplied a reference root (else NOT_EVALUATED,
    # honestly: consistency under the STATED root is not authenticity of the root itself).
    if expected_root_b64 is not None:
        statuses["ROOT_BYTES_AUTHENTICITY"] = "PASS" if (parsed_ok and root == expected_root_b64) else "FAIL"
        if statuses["ROOT_BYTES_AUTHENTICITY"] == "FAIL":
            errors.append("checkpoint root does not equal the relying party's expected root")

    # TREE_CONTEXT_AUTHENTICITY
    if expected_tree_size is not None:
        statuses["TREE_CONTEXT_AUTHENTICITY"] = "PASS" if (parsed_ok and tree_size == expected_tree_size) else "FAIL"
        if statuses["TREE_CONTEXT_AUTHENTICITY"] == "FAIL":
            errors.append("checkpoint tree size does not equal the relying party's expected tree size")

    # CONSISTENCY — required-and-confirmed → PASS; required-and-not-confirmed → FAIL (fail-closed).
    if bool(policy.get("requireConsistencyProof")):
        if consistency_confirmed is True:
            statuses["CONSISTENCY"] = "PASS"
        else:
            statuses["CONSISTENCY"] = "FAIL"
            errors.append("requireConsistencyProof but no confirmed consistency proof supplied (fail-closed)")

    # WITNESS_QUORUM
    if isinstance(policy.get("witnessQuorum"), dict):
        th = policy["witnessQuorum"].get("threshold")
        if not (isinstance(th, int) and not isinstance(th, bool) and th >= 1):
            statuses["WITNESS_QUORUM"] = "FAIL"
        elif not witness_vkeys:
            statuses["WITNESS_QUORUM"] = "FAIL"
            errors.append("witnessQuorum required but no witness vkeys supplied (fail-closed)")
        else:
            try:
                ok, _ = cp.witness_quorum(signed_note, witness_vkeys, th)
                statuses["WITNESS_QUORUM"] = "PASS" if ok else "FAIL"
                if not ok:
                    errors.append(f"witness quorum not met (need {th} distinct witnesses)")
            except ProofBundleError:
                statuses["WITNESS_QUORUM"] = "FAIL"
                errors.append("witness quorum check raised (malformed witness vkey)")

    # Aggregate: PASS requires (a) at least one status evaluated, (b) no status FAIL, AND (c) the checkpoint's
    # authenticity is CRYPTOGRAPHICALLY anchored — at least one of CHECKPOINT_SIGNATURE / WITNESS_QUORUM == PASS
    # (release-review #5, fail-closed). Without a signature or witness quorum the origin/root/tree-size are just
    # PLAINTEXT claims parsed from an unsigned note an attacker could author, so a green LOG_ORIGIN/ROOT_BYTES/
    # TREE_CONTEXT on such a note must NOT aggregate to PASS. Enforced even though the module is EXPERIMENTAL/
    # unwired, so the aggregate name can never mislead once it is wired.
    any_fail = any(v == "FAIL" for v in statuses.values())
    any_eval = any(v != "NOT_EVALUATED" for v in statuses.values())
    crypto_anchored = statuses.get("CHECKPOINT_SIGNATURE") == "PASS" or statuses.get("WITNESS_QUORUM") == "PASS"
    public_transparency = "PASS" if (any_eval and not any_fail and crypto_anchored) else "FAIL"
    if not any_eval:
        errors.append("no public-transparency check was requested by the policy (nothing evaluated)")
    elif not any_fail and not crypto_anchored:
        errors.append(
            "public-transparency is not cryptographically anchored: neither CHECKPOINT_SIGNATURE nor "
            "WITNESS_QUORUM verified — origin/root/tree-size are plaintext claims from an unsigned note, so the "
            "aggregate cannot PASS (fail-closed)")

    return {
        "PUBLIC_TRANSPARENCY": public_transparency,
        "statuses": statuses,
        "origin": origin, "tree_size": tree_size,
        "errors": errors,
    }
