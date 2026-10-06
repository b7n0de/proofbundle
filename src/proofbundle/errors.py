"""Exception and result types for proofbundle."""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, field
from typing import List, Optional

# Nachtrag 46b (`KRAXO-CLOUD-N46B-N48B-BINDUNG-NACH-REVIEW-01`, Z309): the ORIGIN of a verification result.
# A per-process ephemeral key stamps a token over exactly the verified state a result records. A downstream
# judge (policy.evaluate_policy) that takes a result and the judged data separately needs the result to come
# from THIS process's real verifier, not from a hand-built object whose fields merely match — aptly-filled
# result fields are no proof (the review). The key is random per process and is never
# serialised; the threat model is caller mis-wiring (a hand-built or mutated result), NOT arbitrary in-process
# code that could read this key. A hand-built VerificationResult has no token (None) and is refused.
_ORIGIN_KEY = os.urandom(32)


def _tag_part(h, part) -> None:
    """Nachtrag 46e (`KRAXO-CLOUD-N46E-TYPMARKE-IM-HERKUNFTSTOKEN-01`, Z309): absorb one token part into
    ``h`` with a TYPE MARK before its length and content, so no two parts of DIFFERENT types collide. Until
    this Nachtrag bytes and str shared one presence marker and every non-bytes part ran through ``str(...)``,
    so ``b"x"`` and ``"x"``, ``1`` and ``"1"``, ``None`` and ``"None"`` encoded identically. Marks: ``None``
    0x00 (no content), bytes/bytearray 0x01, str 0x02. Any OTHER type takes mark 0x03 and binds its FULL type
    name before ``str(value)`` (VERTRAG 1, variant a): this keeps the encoding TOTAL — every value encodes
    deterministically, so a genuine verification run (where both stamp and verify use this one encoding) stays
    authentic — while still separating e.g. ``int`` 1 from ``str`` "1" by their distinct type names. Variant b
    (fail-closed non-authentic for a non-str/bytes/None part) was not taken because it would turn a genuine run
    into a refusal the moment any real verifier produced a non-str check name or detail; VERTRAG 4 measures
    whether any does (the report names the sites, empty or not). The token is process-internal, never serialised."""
    if part is None:
        h.update(b"\x00")
        return
    if isinstance(part, (bytes, bytearray)):
        mark, b = b"\x01", bytes(part)
    elif isinstance(part, str):
        mark, b = b"\x02", part.encode("utf-8")
    else:
        tname = (type(part).__module__ + "." + type(part).__qualname__).encode("utf-8")
        h.update(b"\x03")
        h.update(len(tname).to_bytes(8, "big"))
        h.update(tname)
        b = str(part).encode("utf-8")
        h.update(len(b).to_bytes(8, "big"))
        h.update(b)
        return
    h.update(mark)
    h.update(len(b).to_bytes(8, "big"))
    h.update(b)


def _compute_origin_token(signer_pub: Optional[bytes], payload_digest: Optional[str],
                          merkle_root: Optional[bytes], checks=()) -> str:
    """HMAC over the captured verified state AND the result's checks. Each part — the three state parts and
    every check's name and detail — is type-marked (None / bytes / str / other, see :func:`_tag_part`) and
    length-prefixed, and the checks are counted and in list order, so two states that differ in any part's
    VALUE or TYPE, or in a check's name, detail, order or count, produce different tokens (Nachtrag 46e closed
    the earlier type collisions: bytes vs str, ``1`` vs ``"1"``, ``None`` vs ``"None"``). The ONE intended
    collapse is a check's ``ok``: it is marked only as exactly ``True``, exactly ``False``, or a third
    "neither" class, because ``ok`` is read by identity and never trusted by its truth, so two distinct
    non-bool ``ok`` values share that third marker by design. Recomputed by the judge from the result's
    recorded fields and checks and compared with ``hmac.compare_digest``; a match proves the token was stamped
    by this process over exactly these fields and checks (origin AND no post-stamp mutation).

    Nachtrag 46c (`KRAXO-CLOUD-N46C-HERKUNFT-DECKT-DIE-CHECKS-01`, Z309): the token additionally covers
    every adopted check (its name, its ``ok`` as an EXACT truth value, and its detail), counted and in
    list order, so a check changed, removed or added after stamping, an ``ok`` flipped (including to a
    truthy non-bool) or a detail changed makes the token no longer match — and no derived verdict stays
    positive (``svr_properties`` reads each check's ``ok`` for ``PROOFBUNDLE_SIGNATURE_VALID`` /
    ``PROOFBUNDLE_RECEIPT_UNCHANGED``; ``policy.evaluate_policy`` gates on this token). Narrowing only.

    The sd_jwt_vc block still needs no field here: a downstream judge's SD-JWT rules are already bound to
    this bundle through the verified signer (Nachtrag 44, the SD-JWT issuer MUST be the bundle signer) and
    that signer (Nachtrag 46), so a swapped sd_jwt is refused — measured in the N46b gegenproben."""
    h = hmac.new(_ORIGIN_KEY, digestmod=hashlib.sha256)
    for part in (signer_pub, payload_digest, merkle_root):
        _tag_part(h, part)   # Nachtrag 46e: type-marked (None/bytes/str/other), so bytes and str never collide
    # Nachtrag 46c: the checks block, after the three state parts, with a fixed section tag and a count so
    # a removed or added check changes the token. The three parts always run exactly above (a fixed count of
    # three), so this section tag sits at a determined position and is never confused with a part marker. `ok`
    # is read by identity (`is True`/`is False`), never by its truth, so a lying `__bool__` runs no code and a
    # truthy non-bool is a third, distinct marker.
    h.update(b"\x02checks")
    h.update(len(checks).to_bytes(8, "big"))
    for c in checks:
        h.update(b"\x01" if c.ok is True else b"\x02" if c.ok is False else b"\x03")
        # Nachtrag 46e: name and detail are type-marked like the state parts, so Check(1, …) and Check("1", …),
        # detail 1 and "1", detail None and "None" no longer collide.
        _tag_part(h, c.name)
        _tag_part(h, c.detail)
    return h.hexdigest()


def _origin_token(domain: bytes, parts) -> str:
    """The same per-process origin token for the DICT-result verify paths (decision, relation, svr), which do
    not return a VerificationResult. ``domain`` is a path tag so a token of one path never validates on another;
    ``parts`` is the captured verified state, each part type-marked (None / bytes / str / other, see
    :func:`_tag_part`, Nachtrag 46e) and length-prefixed so bytes and str no longer collide. The
    producer stamps it on a PASSING verification; a judge that takes such a result as a data argument recomputes
    it from the result's recorded fields and refuses a result this process's verifier did not stamp (a hand-built
    or post-stamp-mutated dict). Nachtrag 46b/48b (`KRAXO-CLOUD-N46B-N48B-BINDUNG-NACH-REVIEW-01`, Z309); reading
    the key is out of the review's threat model (an in-process hand-off)."""
    h = hmac.new(_ORIGIN_KEY, digestmod=hashlib.sha256)
    h.update(len(domain).to_bytes(8, "big"))
    h.update(domain)
    for part in parts:
        _tag_part(h, part)   # Nachtrag 46e: type-marked (None/bytes/str/other), so bytes and str never collide
    return h.hexdigest()


def _origin_authentic(domain: bytes, token, parts) -> bool:
    """True only when ``token`` is the str this process stamped with :func:`_origin_token` over exactly
    ``(domain, parts)``. A dict result carrying no token (hand-built) or one whose captured fields were
    changed after stamping fails. Not a defence against code that can read ``_ORIGIN_KEY``."""
    if not isinstance(token, str):
        return False
    return hmac.compare_digest(token, _origin_token(domain, parts))


class ProofBundleError(Exception):
    """Base class for all proofbundle errors."""


class BundleFormatError(ProofBundleError):
    """The bundle JSON is missing fields or is malformed."""


class UnsupportedError(ProofBundleError):
    """The bundle uses an algorithm or schema this version does not support."""


class SwitchTypeError(ProofBundleError, TypeError):
    """A switch the caller passes is not an exact bool.

    Raised by ``_membership.require_switch`` for a keyword switch whose one side weakens a verdict or a
    check, or changes what is signed or published, before anything is computed or signed. It is a
    ``TypeError`` (the argument has the wrong type) and a ``ProofBundleError`` (every refusal of this
    package is one), and its message names the parameter and the type it got."""


@dataclass
class Check:
    """Result of a single verification step."""

    name: str
    ok: bool
    detail: str = ""

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        mark = "PASS" if self.ok is True else "FAIL"
        return f"[{mark}] {self.name}: {self.detail}".rstrip(": ")


@dataclass
class VerificationResult:
    """Aggregate result of verifying an evidence bundle."""

    checks: List[Check] = field(default_factory=list)
    # Nachtrag 46 (Z309, 6.2.0): what verify_bundle actually verified — additive, set ONLY when the
    # bundle's ed25519 signature verified (sig_ok is True), else None. verified_signer_pub is the raw
    # bytes of the key the payload signature verified under; verified_payload_digest is sha256(payload)
    # as hex. A downstream caller that takes a result and the verified data separately (policy.evaluate_policy)
    # binds the two with these, so a good result of bundle A cannot validate a different bundle B. Excluded
    # from equality/repr and from as_dict so ok, serialisation and existing comparisons are unchanged.
    verified_signer_pub: Optional[bytes] = field(default=None, compare=False, repr=False)
    verified_payload_digest: Optional[str] = field(default=None, compare=False, repr=False)
    # Nachtrag 46b (Z309): the verified state OUTSIDE the payload the N46 digest does not cover. The payload
    # digest binds the signed bytes; it does NOT bind the stated Merkle root (not signed — a coherent one-leaf
    # rewrap re-anchors the same payload under a different root). verified_merkle_root is the stated root bytes
    # the root-authenticity check verified (set only when that check passed). verified_origin is the per-process
    # token over the verified state AND the result's checks (Nachtrag 46c) — see _compute_origin_token. Both are set ONLY on a passing bundle signature;
    # excluded from equality, repr and as_dict so ok, serialisation and existing comparisons are unchanged. The
    # sd_jwt_vc block needs no field: a judge's SD-JWT rules bind to this bundle through the verified signer
    # (N44 issuer==signer + N46), so a swapped sd_jwt is refused — measured in the N46b gegenproben.
    verified_merkle_root: Optional[bytes] = field(default=None, compare=False, repr=False)
    verified_origin: Optional[str] = field(default=None, compare=False, repr=False)

    def stamp_origin(self) -> None:
        """Record the origin token over the verified state AND the checks currently on this result. Called by
        the verifier exactly once, after the signature, the out-of-payload Merkle root and ALL checks are
        recorded (Nachtrag 46c: the token covers the checks, so it must be stamped after the last check)."""
        self.verified_origin = _compute_origin_token(
            self.verified_signer_pub, self.verified_payload_digest, self.verified_merkle_root, self.checks)

    def origin_authentic(self) -> bool:
        """True only when this result carries a token this process's verifier stamped over exactly the fields
        AND checks it now holds. A hand-built result (no token), one whose verified_* fields were changed, or
        one whose checks were changed/removed/added after stamping (Nachtrag 46c) fails. Not a defence against
        code that can read _ORIGIN_KEY (out of scope per the review)."""
        if not isinstance(self.verified_origin, str):
            return False
        return hmac.compare_digest(
            self.verified_origin,
            _compute_origin_token(self.verified_signer_pub, self.verified_payload_digest,
                                  self.verified_merkle_root, self.checks))

    @property
    def ok(self) -> bool:
        """True only if every check that ran passed and at least one ran. A check passes only as the
        exact ``True``: ``all(c.ok ...)`` read each check by its truth, so a caller-built
        ``Check("x", "false")`` made the whole result ok, and the check's own ``__bool__`` ran."""
        return bool(self.checks) and all(c.ok is True for c in self.checks)

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append(Check(name, ok, detail))

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "checks": [
                {"name": c.name, "ok": c.ok, "detail": c.detail} for c in self.checks
            ],
        }
