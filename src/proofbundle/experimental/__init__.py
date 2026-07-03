"""Experimental, opt-in features — NOT part of the stable API surface (v2.0 beta).

Everything under ``proofbundle.experimental`` is a preview: its API, wire format, and behavior may
change or be removed in any release without a deprecation cycle. It is deliberately NOT re-exported
from the top-level package — you must import it explicitly, e.g.
``from proofbundle.experimental.enclave import verify_enclave_attestation``. Importing this
subpackage emits an ``ExperimentalWarning`` once, so nobody depends on it by accident.

The stable v1.x trusted core (signature / merkle / bundle) does not import anything here.
"""

from __future__ import annotations

import warnings


class ExperimentalWarning(UserWarning):
    """Raised once when the experimental subpackage is first imported."""


warnings.warn(
    "proofbundle.experimental is a v2.0 preview: its API and wire format may change or be removed "
    "in any release without deprecation. Do not depend on it in production.",
    ExperimentalWarning,
    stacklevel=2,
)

__all__ = ["ExperimentalWarning"]
