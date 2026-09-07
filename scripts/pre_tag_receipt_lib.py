"""Pre-tag audit RECEIPT — a runner-produced, tree-bound, signed attestation that the adversarial
pre-tag audit ACTUALLY RAN for exactly this release digest (makellose-500 Phase 3, reviewer F6).

The old gate granted ok=true from a self-written CHANGELOG line. A line is prose; prose is forgeable
by anyone who can type, and the gate's own docstring admitted it was "provenance-shaped, not
provenance". This module makes the verdict source a STRUCTURED receipt that BINDS the subject tree
digest, the audit command + exit code + output digest, the gate source digest, and a runner identity,
and is SIGNED (ed25519) by a key whose public half is pinned in the repo and whose private half lives
with the runner (CI / owner), OUTSIDE the agent's reach.

HONEST LIMIT: this repo (OSS proofbundle) has no in-repo runner daemon; the private key is a release
secret held by CI/owner. So on a dev tree with no signed receipt the gate is FAIL-CLOSED (correct —
the audit is not signed-attested for this tree). At release, the runner signs; the gate verifies.
"""
from __future__ import annotations

import hashlib
import json
import re as _re
from pathlib import Path

RECEIPT_SCHEMA = "b7n0de.pre_tag_audit_receipt.v1"
_SIGNED_FIELDS = (
    "schema", "version", "subject_tree_digest", "gate_source_digest",
    "audit_command", "audit_exit_code", "audit_output_digest", "runner_identity", "produced_at",
)


#: Was diese Bindung ausschliessen MUSS, und nichts darueber hinaus: die Quittung selbst. Sie liegt
#: in dem Baum, den sie bindet — ohne diesen einen Ausschluss enthielte ihr Digest sich selbst und
#: waere nicht berechenbar. Ein MUSTER und keine Liste, weil jede Version ihre eigene Quittung
#: ablegt und eine Liste beim naechsten Release stillschweigend zu kurz waere.
#:
#: BEIDE SCHREIBWEISEN, und das ist eine gemessene Beobachtung, keine Vorsicht: `pre_tag_receipt.py`
#: schreibt `pre_tag_receipt_{version}.json` OHNE `v` (Zeile 209), im Baum liegen alle drei
#: Quittungen MIT `v` (`pre_tag_receipt_v5.0.0.json`, `_v5.1.0`, `_v6.0.0`). Erzeuger und Bestand
#: benennen also verschieden. Ein Muster, das nur eine Form kennt, laesst die andere im Digest — und
#: genau daran ist die erste Fassung dieser Zeile am 2026-09-07 gescheitert: sie verlangte das `v`
#: und traf die Form nicht, die das Werkzeug tatsaechlich erzeugt.
_RECEIPT_MUSTER = _re.compile(r"audit_artifacts/[^/\t]+/pre_tag_receipt_v?[0-9][0-9A-Za-z.\-]*\.json$")


def subject_tree_digest(repo) -> str:
    """Digest the receipt binds and the gate verifies: a stable sha256 over the RECURSIVE
    ``git ls-tree -r HEAD`` entries, minus exactly the receipt itself and the mutable evidence a
    release run writes while measuring -- never a whole directory.

    WAS HIER BIS 2026-09-07 STAND, und warum es ein Loch war. Die Funktion fuhr ``git ls-tree HEAD``
    OHNE ``-r`` und warf die eine Top-Level-Zeile weg, die auf ``audit_artifacts`` endet. Das
    entfernte nicht nur die Quittung aus der Bindung, sondern den GANZEN Ordner — und damit
    ``audit_artifacts/pre_tag_trusted_pubkeys.txt`` und ``audit_artifacts/readiness_trusted_pubkeys.txt``,
    also genau die Vertrauensanker, gegen die geprueft wird. Ein Schluessel, der im SELBEN Commit in
    den Anker kommt wie der Kandidat, den er autorisieren soll, war fuer diesen Digest unsichtbar.
    Ausgefuehrt in einer isolierten Kopie: fremder Schluessel committet, ``subject_tree_digest``
    byteidentisch, ein selbst signiertes erfundenes Receipt als ``ok=True, state=verified``
    akzeptiert.

    DIESELBE LUECKE WAR IM SELBEN REPO SCHON GESCHLOSSEN. ``sign_readiness_artifact.tree_digest``
    faehrt seit Auflage C3 rekursiv mit einer schmalen Pfadliste und warnt im eigenen Kommentar
    woertlich vor der Ordner-Ausnahme ("never a whole directory"). Zwei Digest-Funktionen mit
    verschiedenen Ausschlussmengen sind zwei verschiedene Aussagen darueber, was ein Kandidat
    bindet — hier zieht die zweite nach.

    DIE MENGE DER VERAENDERLICHEN BELEGE WIRD NICHT UM DEN QUITTUNGSPFAD ERWEITERT (Owner-Grenze).
    Die Quittung steht in einem EIGENEN Muster; ``MUTABLE_EVIDENCE_RELS`` bleibt unveraendert und
    wird nur mitgelesen, damit Erzeuger und Tor dieselben Pfade meinen.
    """
    import hashlib  # noqa: PLC0415
    import subprocess as _sp  # noqa: PLC0415
    from sign_readiness_artifact import MUTABLE_EVIDENCE_RELS  # noqa: PLC0415
    r = _sp.run(["git", "-C", str(repo), "ls-tree", "-r", "HEAD"],
                capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        raise SystemExit(f"cannot read the tree in {repo}: {r.stderr.strip()}")
    veraenderlich = tuple(f"\t{pfad}" for pfad in MUTABLE_EVIDENCE_RELS)
    lines = [ln for ln in r.stdout.splitlines()
             if not ln.endswith(veraenderlich) and not _RECEIPT_MUSTER.search(ln)]
    return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


def canonical_bytes(receipt: dict) -> bytes:
    """The exact bytes signed/verified: the SIGNED fields only, sorted, compact — never the signature
    or the signer pubkey (those wrap it). A missing signed field is a hard error, not a silent default,
    so a receipt cannot omit its way to a shorter signed message."""
    body = {}
    for k in _SIGNED_FIELDS:
        if k not in receipt:
            raise ValueError(f"receipt is missing signed field {k!r}")
        body[k] = receipt[k]
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_trusted_pubkeys(repo: Path, *, ref: str = "HEAD") -> list[str]:
    """Base64 ed25519 public keys the gate trusts to sign a pre-tag receipt, read from the COMMITTED tree
    (``git show {ref}:audit_artifacts/pre_tag_trusted_pubkeys.txt``), NOT the working tree.

    Spur-2 Linse A (2026-08-27): the receipt binds ``subject_tree_digest`` = the COMMITTED ``HEAD^{tree}``,
    so the trust anchor MUST come from that SAME committed tree. Reading the WORKING-tree file let a dirty
    checkout inject a pubkey (uncommitted) and self-sign a receipt that binds the clean committed tree and
    verified — the trusted-key set was NOT covered by the digest the receipt commits to. Reading the
    committed blob binds it by the same digest, so the guarantee no longer depends on a clean checkout.
    An ABSENT/EMPTY file, a non-git repo, or a dangling ref means no trust anchor -> fail closed, never
    trust-all (one key per line, ``#`` comments). The gate resolves the digest from the same ``HEAD``."""
    import subprocess  # noqa: PLC0415
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "show", f"{ref}:audit_artifacts/pre_tag_trusted_pubkeys.txt"],
            capture_output=True, text=True, timeout=10)
    except Exception:  # noqa: BLE001 — no git binary / timeout -> no trust anchor, fail closed
        return []
    if r.returncode != 0:  # file not committed in this tree, or unknown ref -> fail closed
        return []
    out = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def verify_receipt(receipt: dict, *, trusted_pubkeys: list[str], expected_version: str,
                   subject_tree_digest: str, gate_source_digest: str) -> "tuple[bool, str]":
    """(ok, reason). ok iff the receipt is a well-formed, SIGNED (by a trusted key) attestation that
    BINDS this exact tree + version + gate source, and records a SUCCESSFUL audit (exit 0)."""
    import base64  # noqa: PLC0415
    from proofbundle.signature import verify_ed25519  # noqa: PLC0415
    if not isinstance(receipt, dict):
        return False, "receipt is not an object"
    if receipt.get("schema") != RECEIPT_SCHEMA:
        return False, f"unknown schema {receipt.get('schema')!r} (want {RECEIPT_SCHEMA})"
    if receipt.get("version") != expected_version:
        return False, f"receipt version {receipt.get('version')!r} != release {expected_version!r}"
    if receipt.get("subject_tree_digest") != subject_tree_digest:
        return False, ("receipt subject_tree_digest does not bind THIS tree "
                       f"({receipt.get('subject_tree_digest')!r} != {subject_tree_digest!r}) — a copied "
                       "record from another release cannot attest this one")
    if receipt.get("gate_source_digest") != gate_source_digest:
        return False, "receipt gate_source_digest does not match the gate that is judging"
    if receipt.get("audit_exit_code") != 0:
        return False, f"the recorded audit did not succeed (exit {receipt.get('audit_exit_code')!r})"
    if not trusted_pubkeys:
        return False, ("no trusted signing key pinned (audit_artifacts/pre_tag_trusted_pubkeys.txt "
                       "absent/empty) — the gate has no trust anchor and fails closed")
    signer = receipt.get("signer_pubkey")
    if signer not in trusted_pubkeys:
        return False, f"receipt signer_pubkey is not in the trusted set (signer={str(signer)[:20]}...)"
    sig = receipt.get("signature")
    if not isinstance(sig, str):
        return False, "receipt carries no signature"
    try:
        msg = canonical_bytes(receipt)
        ok = verify_ed25519(base64.b64decode(signer), base64.b64decode(sig), msg)
    except Exception as e:  # noqa: BLE001
        return False, f"signature check errored (fail-closed): {type(e).__name__}: {e}"
    if not ok:
        return False, "ed25519 signature does not verify over the canonical receipt bytes"
    return True, "signed, tree-bound, successful-audit receipt verified"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
