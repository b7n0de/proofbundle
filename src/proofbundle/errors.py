"""Exception and result types for proofbundle."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


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
