"""Evaluation Card digest — bind a receipt to an external, human-readable methodology document.

A receipt proves a threshold verdict; it says nothing about the *methodology* behind the number
(THRESHOLD_VERDICT_VERIFIED + METHODOLOGY_NOT_EVALUATED — see ``evalclaim.eval_evidence_class``).
The Hugging Face EvalEval Coalition's **Evaluation Cards** (arXiv:2606.09809) are a structured,
human-facing account of what an eval result means — bias, provenance, comparability, completeness.
This module does NOT invent a proofbundle-specific card format; it lets a receipt carry a digest
that REFERENCES an external Eval Card (however it was produced — e.g. the EvalEval "Eval Card
Form"), so a relying party can fetch that document and cryptographically confirm it is the exact
one the issuer pointed at when they signed.

Construction is mechanically **identical to prereg.py**: sha256 over the RAW bytes of the card
document. A match proves only "this is the document the issuer committed to" — exactly the same
epistemic strength as ``prereg_sha256`` (THREAT_MODEL.md: a signature binds *who said it*, not
*whether it is true*). It does NOT prove the card is honest, complete, or that the evaluation was
well designed — that remains a human judgement (see EVAL_CLAIM.md §1a, METHODOLOGY_NOT_EVALUATED).

The claim field is the optional, additive ``evaluation_card_sha256`` (schemas/eval_claim_v0_1.schema.json).
Because the eval-claim schema is ``additionalProperties: false``, a receipt carrying this field is a
**one-way compatibility step** exactly like ``anchors[]`` (SPEC.md §7i): an older proofbundle build
that does not know the field will reject such a receipt in ``decode_eval_claim`` (the F3 verify-path
unknown-field guard), not silently ignore it.
"""

from __future__ import annotations

import hashlib

from .errors import ProofBundleError

__all__ = ["evaluation_card_hash", "verify_evaluation_card"]


def evaluation_card_hash(card_path) -> str:
    """Return the lowercase-hex sha256 over the RAW bytes of the Eval Card document — the value to
    place in a claim's ``evaluation_card_sha256`` when signing the receipt."""
    # adversarial re-audit (3.6.2): hash in 1 MiB chunks instead of read_bytes() so memory stays bounded.
    # adversarial re-audit round 4: chunked hashing bounded MEMORY but not TIME — `--card /dev/zero` (a character
    # device) never yields the b'' sentinel, so the loop spun forever (a CPU-bound DoS), and a FIFO with no
    # writer blocked open() forever. verify_evaluation_card checks an UNTRUSTED card, so this is a verify
    # surface: stat-guard (regular files only — refuses /dev/zero AND FIFO before open, os.stat never blocks)
    # + a total-byte cap. A real Eval Card is a methodology document well under the input_bytes budget.
    import os  # noqa: PLC0415
    import stat as _stat  # noqa: PLC0415

    from .budget import DEFAULT_BUDGET  # noqa: PLC0415
    from .errors import BundleFormatError  # noqa: PLC0415
    cap = DEFAULT_BUDGET.input_bytes
    _st = os.stat(card_path)
    if not _stat.S_ISREG(_st.st_mode):
        raise BundleFormatError("eval card path is not a regular file (fail-closed: FIFO/device/socket refused)")
    if _st.st_size > cap:
        raise BundleFormatError(f"eval card exceeds the {cap}-byte read budget (DoS guard)")
    h = hashlib.sha256()
    total = 0
    with open(card_path, "rb") as _handle:
        for _chunk in iter(lambda: _handle.read(1 << 20), b""):
            total += len(_chunk)
            if total > cap:
                raise BundleFormatError(f"eval card exceeds the {cap}-byte read budget (DoS guard)")
            h.update(_chunk)
    return h.hexdigest()


def verify_evaluation_card(card_path, claim: dict) -> dict:
    """Check that ``claim['evaluation_card_sha256']`` matches the sha256 of the card document.

    Returns ``{ok, present, expected, actual, detail}``. ``present`` is False when the claim
    carries no ``evaluation_card_sha256`` (no card referenced) — the caller decides whether that
    is acceptable; ``ok`` is only True on a present-and-matching hash (fail-closed). Mirrors
    ``prereg.verify_prereg`` exactly; callers that need crypto-authenticated claim data (not a
    hand-edited dict) should decode the receipt with ``evalclaim.decode_eval_claim`` first, the
    same discipline ``prereg``'s CLI ``--check`` uses."""
    expected = claim.get("evaluation_card_sha256") if isinstance(claim, dict) else None
    result = {"ok": False, "present": expected is not None, "expected": expected,
              "actual": None, "detail": ""}
    if expected is None:
        result["detail"] = "claim carries no evaluation_card_sha256 (no eval card referenced)"
        return result
    try:
        actual = evaluation_card_hash(card_path)
    except (OSError, TypeError, ValueError, ProofBundleError):
        # 6-lens gate L1-01: a missing / directory / None / NUL / surrogate card_path raised a raw
        # FileNotFoundError/IsADirectoryError/TypeError/ValueError ('embedded null byte' + surrogate are
        # ValueError) from Path(card_path).read_bytes(). This public never-raise surface returns a fail-closed
        # verdict (present, no match) instead of crashing a caller.
        # adversarial re-audit round 4: also catch ProofBundleError — the new stat-guard/over-cap in
        # evaluation_card_hash raises BundleFormatError (a ProofBundleError), which must fail-closed here too.
        result["detail"] = "eval card file could not be read (missing/unreadable/non-regular/over-limit path)"
        return result
    result["actual"] = actual
    if actual == expected:
        result["ok"] = True
        result["detail"] = "eval card document matches the referenced digest"
    else:
        result["detail"] = "eval card document does NOT match the referenced digest (card changed?)"
    return result
