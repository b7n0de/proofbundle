"""Exception and result types for proofbundle."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


class ProofBundleError(Exception):
    """Base class for all proofbundle errors."""


class BundleFormatError(ProofBundleError):
    """The bundle JSON is missing fields or is malformed."""


class UnsupportedError(ProofBundleError):
    """The bundle uses an algorithm or schema this version does not support."""


@dataclass
class Check:
    """Result of a single verification step."""

    name: str
    ok: bool
    detail: str = ""

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        mark = "PASS" if self.ok else "FAIL"
        return f"[{mark}] {self.name}: {self.detail}".rstrip(": ")


@dataclass
class VerificationResult:
    """Aggregate result of verifying an evidence bundle."""

    checks: List[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True only if every check that ran passed and at least one ran."""
        return bool(self.checks) and all(c.ok for c in self.checks)

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append(Check(name, ok, detail))

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "checks": [
                {"name": c.name, "ok": c.ok, "detail": c.detail} for c in self.checks
            ],
        }
