#!/usr/bin/env python3
"""Produce a SIGNED pre-tag audit receipt (makellose-500 Phase 3, reviewer F6). Run by the RUNNER
(CI / owner) AFTER the adversarial pre-tag audit succeeds. Signs with an ed25519 key whose PUBLIC half
is pinned in ``audit_artifacts/pre_tag_trusted_pubkeys.txt`` and whose PRIVATE half is a release
secret held OUTSIDE the agent's reach. The gate (pre_tag_audit_gate.py) verifies what this writes.

THREE modes. The signed 9-field CONTEXT is identical in all three; only WHERE the signature comes from
differs. The security-deciding core (``canonical_bytes`` / ``verify_receipt`` in pre_tag_receipt_lib.py)
is byte-identical and untouched by this file:

  inline   (default, --privkey-file): build the context, sign it here, write the receipt. The runner
           holds the key. Unchanged from before the keyless modes existed.
  emit     (--emit-payload P --context-out C): write ``canonical_bytes(context)`` to P and the context
           JSON to C. NO private key is read. This is the Farmer half of the two-half keyless handshake:
           the Farmer emits, the key-holder (Mac) signs P, the Farmer assembles. The private key never
           reaches the Farmer.
  assemble (--assemble --context-in C --sig-file S --signer-pubkey B --out R): wrap the context C + the
           base64 signature in S (over ``canonical_bytes(C)``) + the pubkey B into a receipt R.
           Self-checks the signature under B and REFUSES on a mismatch (fail-closed: a bad sig/context
           pair never becomes a receipt on disk).

Usage (inline, unchanged):
  pre_tag_receipt.py --repo . --version 5.0.0 --audit-command "<cmd>" --audit-exit 0 \
      --audit-output-file <path> --runner-identity <id> --produced-at <iso> --privkey-file <path> [--out <path>]
"""
from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
from pathlib import Path


#: Where Python keeps bytecode for THIS run. Set BEFORE the judged tree's modules are imported.
_CACHE_DIR: str | None = None


def _bytecode_cache_elsewhere() -> None:
    """Keep this run from writing `__pycache__` next to the sources, and from reading one.

    MEASURED 2026-09-20 by the full suite: the cleanliness gate below refused
    `tests/test_pre_tag_receipt_commit_flow.py`, because the subprocess creates
    `scripts/__pycache__/` and `src/proofbundle/__pycache__/` on import and `git status
    --porcelain` reports both. The gate refused BECAUSE IT RAN, which on any tree without a
    `.gitignore` for bytecode is every run, not an edge case.

    A first repair filtered those paths out of the gate's view. That is the weaker answer, and this
    repository already rejects it in as many words: `verify_pre_tag_receipt._bytecode_cache_elsewhere`
    says the fix is not a second guard over `__pycache__`, because a cache that is present is not
    evidence of anything, and it names the attack that guard would miss -- lens C, 2026-09-18, a
    `signature.cpython-310.pyc` carrying `verify_ed25519 -> True` beside an untouched
    `signature.py`, which Python runs and `git status` never lists. Tolerating the cache on the
    EMIT side would have reopened here the hole that was closed on the verify path. Same mechanism,
    same reason, rather than a second idea for the same class.

    What stays trusted and is not measured here: the interpreter and its standard library.
    """
    global _CACHE_DIR
    if _CACHE_DIR is None:
        import atexit     # noqa: PLC0415
        import shutil     # noqa: PLC0415
        import tempfile   # noqa: PLC0415
        # The path has to be UNPREDICTABLE, not merely elsewhere: a fixed prefix is a location an
        # attacker can plant a `.pyc` at ahead of time, which is the same hole one directory over.
        # `mkdtemp` buys that unpredictability, and it is why a constant is not the cheaper answer.
        _CACHE_DIR = tempfile.mkdtemp(prefix="pre_tag_receipt_pyc_")
        # AND IT HAS TO BE GIVEN BACK. Measured 2026-09-20: this session's suite runs left 169 of
        # these directories in /tmp, one per invocation, all empty — `dont_write_bytecode` means
        # nothing is ever written into them. Empty is not harmless when the count has no ceiling.
        atexit.register(shutil.rmtree, _CACHE_DIR, ignore_errors=True)
        sys.pycache_prefix = _CACHE_DIR
        sys.dont_write_bytecode = True


_bytecode_cache_elsewhere()

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pre_tag_receipt_lib import RECEIPT_SCHEMA, canonical_bytes, sha256_text, subject_tree_digest  # noqa: E402


#: Environment variables that RESELECT the repository a git command operates on. `git -C <dir>`
#: sets the working directory and nothing else — an inherited `GIT_WORK_TREE` still wins, so the
#: command answers about a DIFFERENT checkout than the one on the command line.
#:
#: Codex (P1, review of 2026-09-23 on 308b76b), reproduced here before it was fixed: with an
#: untracked `evil.py` in `--repo` and `GIT_WORK_TREE` pointing at a clean alternate directory,
#: `git status` reported `?? evil.py` when run plainly and the emit returned 0 and wrote a payload
#: when the variable was set. Measured rc without it 1, rc with it 0.
#:
#: The list is the whole family, not the one variable that was reported. `GIT_DIR` reselects the
#: object store, `GIT_INDEX_FILE` the index the status is computed against, the object-directory
#: pair where blobs are read from, `GIT_CEILING_DIRECTORIES` where discovery stops and
#: `GIT_NAMESPACE` which refs are visible. Fixing only the reported spelling would leave the class
#: open one variable over, which is the defect this file keeps finding in itself.
_GIT_UMGEBUNG_UEBERSTEUERUNGEN = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CEILING_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
)


def _git_umgebung() -> dict:
    """The environment for every git call in this file, with the repository-reselecting names gone.

    Removed, not overwritten with a guess: an empty `GIT_WORK_TREE` is not the same as an absent
    one, and this guard has already been bitten once by treating a set-but-empty variable as
    absent (see `_inline_erlaubt_oder_stop`, where presence IS the signal). `pop` states the
    intent — this process asks about the repository it was given on the command line, and nothing
    else may answer for it.
    """
    import os  # noqa: PLC0415
    umgebung = dict(os.environ)
    for name in _GIT_UMGEBUNG_UEBERSTEUERUNGEN:
        umgebung.pop(name, None)
    return umgebung


def _git(repo: Path, *argumente: str, text: bool = False, eingabe: bytes | None = None,
         timeout: int = 120) -> subprocess.CompletedProcess:
    """Every git call of this file goes through here, so the isolation cannot be forgotten at one.

    The single funnel is the point. A second call site that builds its own `subprocess.run` would
    reopen the hole for exactly one command, and that is the shape of the reported defect: the
    status check was isolated in the reporter's mind while `ls-tree`, `ls-files` and `hash-object`
    were not.
    """
    return subprocess.run(["git", "-C", str(repo), *argumente], capture_output=True, text=text,
                          input=eingabe, timeout=timeout, env=_git_umgebung())


def _tree_digest(repo: Path) -> str:
    return subject_tree_digest(repo)


def _gate_source_digest(repo: Path) -> str:
    import hashlib
    return hashlib.sha256((repo / "scripts" / "pre_tag_audit_gate.py").read_bytes()).hexdigest()


def _version_token(v: str) -> str:
    return v.replace(".", "")


def build_context(repo: Path, version: str, audit_command: str, audit_exit: int,
                  audit_output: str, runner_identity: str, produced_at: str,
                  audit_output_path: Path | None = None) -> dict:
    """The 9 SIGNED fields — identical across inline / emit / assemble. Exactly what canonical_bytes covers."""
    # THE GATE BELONGS WHERE THE DIGEST IS MADE, not at one caller. The first version put it in
    # the emit branch of main(). A counter-reading pointed at the OTHER caller: `build_and_sign`
    # also calls this function, so the inline signing path reached `subject_tree_digest` with no
    # cleanliness check at all. `_inline_erlaubt_oder_stop` guards that path, but it answers a
    # DIFFERENT question — whether inline signing is permitted, not whether the tree being
    # digested is the tree that was measured. Gating one caller instead of the invariant is the
    # defect this release keeps finding, and it does not get to hide in the fix for itself.
    #
    # `assemble` does NOT pass here: it reads a context that was already built and signed
    # elsewhere, so there is no tree of its own to bind.
    _arbeitsbaum_sauber_oder_stop(repo, audit_output_path)
    return {
        "schema": RECEIPT_SCHEMA,
        "version": version,
        "subject_tree_digest": _tree_digest(repo),
        "gate_source_digest": _gate_source_digest(repo),
        "audit_command": audit_command,
        "audit_exit_code": audit_exit,
        "audit_output_digest": sha256_text(audit_output),
        "runner_identity": runner_identity,
        "produced_at": produced_at,
    }


def build_and_sign(repo: Path, version: str, audit_command: str, audit_exit: int,
                   audit_output: str, runner_identity: str, produced_at: str, privkey_b64: str,
                   audit_output_path: Path | None = None) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from proofbundle._wire_b64 import decode_b64
    priv = Ed25519PrivateKey.from_private_bytes(decode_b64(privkey_b64))
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    receipt = build_context(repo, version, audit_command, audit_exit, audit_output,
                            runner_identity, produced_at, audit_output_path)
    sig = priv.sign(canonical_bytes(receipt))
    receipt["signature"] = base64.b64encode(sig).decode()
    receipt["signer_pubkey"] = pub_b64
    return receipt


def assemble_receipt(context: dict, sig_b64: str, signer_pubkey_b64: str) -> dict:
    """Two-half keyless: wrap a context (the 9 signed fields) + an externally produced signature over
    ``canonical_bytes(context)`` into a receipt. Self-checks the signature under signer_pubkey — a mismatch
    REFUSES (fail-closed), so a bad sig/context pair never becomes a receipt on disk. The bytes signed here
    are byte-identical to what verify_receipt reconstructs, so the assembled receipt verifies at the gate."""
    import binascii
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from proofbundle._wire_b64 import decode_b64
    # LAUF11-L2: eine nicht-kanonische Schreibweise ist ein URTEIL (refusing), kein Absturz —
    # ein Werkzeug der Freigabekette darf nicht sterben, wo es abweisen kann.
    try:
        pub = Ed25519PublicKey.from_public_bytes(decode_b64(signer_pubkey_b64))
        roh_sig = decode_b64(sig_b64)
    except (binascii.Error, ValueError) as e:
        raise SystemExit(f"assemble: signature/pubkey field is not canonical base64 — refusing: {e}")
    try:
        pub.verify(roh_sig, canonical_bytes(context))
    except InvalidSignature:
        raise SystemExit("assemble: signature does not verify over canonical_bytes(context) — refusing (fail-closed)")
    receipt = dict(context)
    receipt["signature"] = sig_b64
    receipt["signer_pubkey"] = signer_pubkey_b64
    return receipt


def _need(args, names: list[str], mode: str) -> None:
    missing = [n for n in names if getattr(args, n.replace("-", "_")) is None]
    if missing:
        raise SystemExit(f"{mode} mode needs: {', '.join('--' + m for m in missing)}")


#: Die ausdrueckliche Freigabe fuer den Inline-Signierweg. Sie wird auf der Maschine des
#: Schluesselhalters gesetzt und nirgends sonst — insbesondere nicht auf dem Bau- und Pruefhost.
INLINE_FREIGABE_ENV = "PB_INLINE_SIGNING"

#: Merkmale eines automatisierten Bau-/Pruefhosts. Auf einem solchen darf der Inline-Weg auch dann
#: nicht laufen, wenn jemand die Freigabe oben gesetzt hat: die Freigabe ist eine Erlaubnis des
#: Menschen an seiner eigenen Maschine, kein Schalter fuer eine Pipeline.
_BAUHOST_MERKMALE = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "JENKINS_URL")


def _inline_erlaubt_oder_stop() -> None:
    """Fail-closed vor dem Inline-Signierweg (Owner-Entscheid 2026-09-06, Karte OA-8b1a31cc4f).

    WARUM ES DIESE SPERRE GIBT. Der Inline-Modus BLEIBT — er ist der Weg, auf dem der Owner an
    seiner eigenen Maschine unterschreibt, und ihn zu entfernen hiesse, den Signierweg abzuschaffen
    statt ihn einzugrenzen. Was nicht bleiben darf, ist seine Erreichbarkeit auf dem Bau- und
    Pruefhost: dort laeuft der messende Agent, und ein Werkzeug, das dort einen privaten Schluessel
    laden KANN, liefert die Faehigkeit zur Selbstbeglaubigung mit — unabhaengig davon, ob sie je
    gerufen wird. Genau diese Trennung beschreibt der Docstring oben schon als die zwei Haelften
    (emit hier, signieren dort, assemble wieder hier); die Sperre macht aus der Beschreibung eine
    Regel.

    WARUM POSITIV UND NAMENLOS. Die Sperre fragt nicht "bin ich auf einem bestimmten Konto" — ein
    Kontoname im Quelltext waere sowohl sproede als auch eine Preisgabe in einem oeffentlichen
    Repository. Sie verlangt stattdessen eine ausdrueckliche Freigabe, die auf der Signiermaschine
    gesetzt ist und sonst nirgends. Ohne sie gibt es keinen Inline-Lauf, und der Weg, der ueberall
    funktioniert, ist der keyless: ``--emit-payload`` hier, Signatur beim Schluesselhalter,
    ``--assemble`` wieder hier.
    """
    import os  # noqa: PLC0415
    # ANWESENHEIT, NICHT WAHRHEITSWERT (08.09.2026, ausgefuehrter Fund einer Gegenlesung an
    # der Schwesterstelle in tests/test_budget_kostenkurve.py): ein gesetztes `CI=""` ist
    # falsy und haette diesen Schluesselriegel auf einem echten Bauhost NICHT greifen lassen.
    # Fuer eine Kostenmessung ist das ein falscher Rotlauf; HIER ist es der Unterschied
    # zwischen "der private Schluessel bleibt draussen" und "er darf geladen werden".
    # Die Richtung ist bewusst fail-closed: eine Marke IST das Signal, ihr Wert ist keiner.
    bauhost = [n for n in _BAUHOST_MERKMALE if n in os.environ]
    if bauhost:
        raise SystemExit(
            f"inline signing is refused on an automated build host ({', '.join(bauhost)} set). "
            "Use the keyless two-half path: --emit-payload here, sign the payload where the key "
            "lives, then --assemble here.")
    if os.environ.get(INLINE_FREIGABE_ENV) != "1":
        raise SystemExit(
            f"inline signing is refused unless {INLINE_FREIGABE_ENV}=1 is set — it marks the "
            "machine that holds the release key, and it is deliberately unset everywhere else "
            "(owner decision 2026-09-06). Use the keyless two-half path instead: --emit-payload "
            "here, sign the payload where the key lives, then --assemble here.")


def _arbeitsbaum_sauber_oder_stop(repo: Path, audit_output_path: Path | None = None) -> None:
    """Refuse to bind a tree digest while the working tree differs from the committed head.

    THE RECEIPT BINDS `git ls-tree -r HEAD` AND THE RUN READS THE WORKING TREE. Those are two
    different sets of bytes whenever anything is uncommitted, and nothing here compared them:
    `subject_tree_digest()` digests the head, the audit whose output this receipt carries ran over
    the checkout. A measurement on the operating tree found two modified paths while a receipt was
    produced, so the receipt attested a tree that was not the tree that had been examined.

    This is the same shape as the hole `subject_tree_digest` already documents for itself, one step
    earlier: there the digest excluded a whole directory and so could not see a key added in the
    same commit; here the digest is correct about the head and the head is not what was measured.
    A digest over the wrong subject is not a weaker binding, it is a binding to something else.

    Fail-closed in both directions. A dirty tree refuses, and a tree whose state cannot be
    determined refuses too: not-determinable is not a clearance, and a release receipt is the last
    place to guess.
    """
    try:
        # WHAT `git status` ANSWERS IS CONFIGURABLE, and this guard believed it.
        #
        # Codex 4057990630 (P1), measured in a throwaway repository: with
        # `status.showUntrackedFiles=no` the command reports NOTHING for an untracked file, and
        # reports it again under `--untracked-files=all`. A release checkout carrying that setting
        # would have made this guard blind to exactly the set its own boundary calls dirty.
        #
        # The command-line flag overrides the configuration; it is ALSO set through `-c`, so a
        # future rename of the switch cannot fall back to the configured value in silence. Two
        # spellings of one statement — not a second source of truth, a bolt against the
        # environment.
        lauf = _git(repo, "-c", "status.showUntrackedFiles=all",
                    "status", "--porcelain", "--untracked-files=all", text=True)
    except (OSError, subprocess.SubprocessError) as fehler:
        raise SystemExit(
            f"emit: cannot determine whether {repo} is clean ({fehler}) — refusing to bind a tree "
            f"digest that may not describe what was measured (fail-closed)") from fehler
    if lauf.returncode != 0:
        grund = (lauf.stderr or "").strip().splitlines()
        raise SystemExit(
            f"emit: `git status --porcelain` failed in {repo}"
            + (f": {grund[0]}" if grund else "")
            + " — refusing to bind a tree digest that may not describe what was measured")
    schmutzig = [z for z in lauf.stdout.splitlines() if z.strip()]
    if schmutzig:
        gezeigt = "\n  ".join(schmutzig[:20])
        mehr = f"\n  … and {len(schmutzig) - 20} more" if len(schmutzig) > 20 else ""
        raise SystemExit(
            f"emit: the working tree of {repo} carries {len(schmutzig)} uncommitted path(s), and "
            f"the receipt would bind `git ls-tree -r HEAD` instead — refusing, because the bytes "
            f"attested would not be the bytes measured:\n  {gezeigt}{mehr}")
    _der_inhalt_stimmt_mit_dem_kopf_oder_stop(repo)
    _audit_lief_auf_diesem_baum_oder_stop(repo, audit_output_path)


def _der_inhalt_stimmt_mit_dem_kopf_oder_stop(repo: Path) -> None:
    """`git status` can be told to stop looking, so the content is COMPARED here instead of asked for.

    Found by a cross-reading and then verified rather than believed. With
    `git update-index --assume-unchanged datei.txt` set and the file rewritten, MEASURED in a
    throwaway repository: `git status --porcelain --untracked-files=all` prints NOTHING, and
    `git diff --quiet HEAD` reports no change either — both consult the index, and that bit lives
    in the index. The emit then produced a payload over a tree whose content differed from the head
    it was about to bind. `skip-worktree` has the same effect by the same route.

    THE CLASS, one level below the configuration fix beside it: forcing a single knob
    (`--untracked-files=all`) keeps one answer honest, while the MECHANISM that produces the answer
    stays configurable. The remedy is not a third knob. It is to stop asking and compute the
    property: for every path the HEAD tree carries, hash the working file and compare it with the
    blob id the tree records. `git hash-object` reads the file, not the index, so no index bit can
    hide a difference.

    The sibling check beside this one still uses `git status` for UNTRACKED paths, and that is
    correct: a file the head does not carry has no blob to compare against, so absence from the
    tree is the only question there and the forced flag is the right tool for it.
    """
    try:
        baum = _git(repo, "ls-tree", "-r", "-z", "HEAD")
    except (OSError, subprocess.SubprocessError) as fehler:
        raise SystemExit(
            f"emit: cannot read the head tree of {repo} ({fehler}) — refusing, because the content "
            f"of the checkout cannot be compared with what the receipt would bind") from fehler
    if baum.returncode != 0:
        raise SystemExit(
            f"emit: `git ls-tree -r HEAD` failed in {repo} — refusing, because the content of the "
            f"checkout cannot be compared with what the receipt would bind")
    erwartet: dict[str, bytes] = {}
    #: The subset of `erwartet` whose mode is 120000 — checked by its LINK TEXT, not by its
    #: target.
    symlinks: dict[str, bytes] = {}
    for satz in baum.stdout.split(b"\0"):
        if not satz:
            continue
        try:
            kopf, pfad_roh = satz.split(b"\t", 1)
            felder = kopf.split()
            art, blob = felder[1], felder[2]
        except (ValueError, IndexError):
            raise SystemExit(
                f"emit: `git ls-tree -r HEAD` produced a record this code cannot read ({satz[:60]!r}) "
                f"— refusing rather than skipping it, because a skipped path is an unchecked path")
        if art != b"blob":
            continue
        rel = pfad_roh.decode("utf-8", errors="replace")
        erwartet[rel] = blob
        # THE MODE DECIDES HOW THE BYTES ARE READ, and it was never looked at. A symlink is a blob
        # too — mode 120000 — whose content is the LINK TEXT. Codex (P2, 2026-09-23 on 308b76b):
        # `git ls-tree` records the hash of that text, while `git hash-object --stdin-paths`
        # follows the link and hashes the TARGET. Reproduced before the fix: a clean repository
        # with `link -> target`, `target` holding bytes other than the string `target`, empty
        # `git status` — refused with `differs: link`, exit 1. A valid clean tree containing a
        # symlink could not produce a receipt at all.
        if felder[0] == b"120000":
            symlinks[rel] = blob
    import os  # noqa: PLC0415

    def _fehlt(rel: str) -> bool:
        p = repo / rel
        # For a symlink the question is whether the LINK is there, not whether it resolves. A
        # broken link is a legitimate tracked object; `is_file()` says False for it and it was
        # classified `missing` — the sibling misreading named in the same finding.
        return not os.path.islink(p) if rel in symlinks else not p.is_file()

    fehlend = [rel for rel in erwartet if _fehlt(rel)]
    fehlend_menge = set(fehlend)
    zu_hashen = [rel for rel in erwartet if rel not in fehlend_menge and rel not in symlinks]
    abweichend = []
    # The link text is hashed as the blob it is. `--stdin` instead of `--stdin-paths`, because the
    # path form is exactly what follows the link; the bytes handed over here are `readlink`'s, so
    # no target is read. One call per symlink: a tree carries a handful of them, while the regular
    # files below stay in the single batched call they need.
    for rel in sorted(set(symlinks) - fehlend_menge):
        try:
            ziel = os.readlink(repo / rel).encode("utf-8", errors="surrogateescape")
        except OSError as fehler:
            raise SystemExit(
                f"emit: cannot read the symlink {rel} of {repo} ({fehler}) — refusing rather than "
                f"skipping it, because a skipped path is an unchecked path")
        h = _git(repo, "hash-object", "-t", "blob", "--stdin", eingabe=ziel)
        if h.returncode != 0 or not h.stdout.split():
            raise SystemExit(
                f"emit: `git hash-object` could not hash the link text of {rel} "
                f"(exit {h.returncode}) — refusing, because that path would stay unchecked")
        if h.stdout.split()[0] != symlinks[rel]:
            abweichend.append(rel)
    if zu_hashen:
        # ONE PROCESS, NOT ONE PER FILE. Measured on the real tree: 1475 tracked blobs, so the
        # per-file form would spawn 1475 subprocesses for a single guard. `--stdin-paths` hashes
        # the whole list in one go, and it still reads the FILES rather than the index, which is
        # the property this check exists for.
        ist = _git(repo, "hash-object", "--stdin-paths",
                   eingabe="\n".join(zu_hashen).encode() + b"\n", timeout=600)
        zeilen = ist.stdout.split()
        if ist.returncode != 0 or len(zeilen) != len(zu_hashen):
            # A SHORT ANSWER IS NOT A CLEAN ONE. If git returned fewer hashes than paths, the
            # mapping below would silently compare the wrong pairs, so this refuses instead.
            raise SystemExit(
                f"emit: `git hash-object --stdin-paths` answered for {len(zeilen)} of "
                f"{len(zu_hashen)} tracked path(s) (exit {ist.returncode}) — refusing, because a "
                f"partial answer cannot show the checkout matches the head")
        # APPEND, do not assign: the symlink check above has already recorded its findings.
        # An assignment here would have discarded them silently — a green verdict over a set
        # that is no longer being looked at.
        abweichend += [rel for rel, h in zip(zu_hashen, zeilen) if h != erwartet[rel]]
    if fehlend or abweichend:
        zeilen = [f"  missing: {x}" for x in sorted(fehlend)[:10]] + \
                 [f"  differs: {x}" for x in sorted(abweichend)[:10]]
        rest = len(fehlend) + len(abweichend) - len(zeilen)
        mehr = f"\n  … and {rest} more" if rest > 0 else ""
        raise SystemExit(
            f"emit: {len(fehlend) + len(abweichend)} tracked path(s) do not match the head this "
            f"receipt would bind, although `git status` reports the tree as clean — an index bit "
            f"(assume-unchanged or skip-worktree) hides them. Refusing:\n"
            + "\n".join(zeilen) + mehr)


def _audit_lief_auf_diesem_baum_oder_stop(repo: Path, audit_output_path: Path | None) -> None:
    """The cleanliness check above happens at RECEIPT time; the audit ran BEFORE it.

    Codex 4057990627 (P1), reproduced in a throwaway repository: modify a tracked file, let the
    audit read those modified bytes into a file OUTSIDE the repository, restore the file with
    `git checkout --`, then emit. The tree is clean, HEAD never moved, the command returns 0, and
    the emitted context binds `subject_tree_digest` of the CLEAN head to an `audit_output_digest`
    computed from bytes that head never carried. Measured: subject e71e8911…, audit 740c408a….
    A receipt in that shape grants the release gate for a tree the recorded audit never examined.

    WHAT IS OBSERVABLE FROM HERE, and it is not the audit. This process cannot watch a run that
    already finished. What it CAN see is the ORDER: restoring a file writes it, so the restored
    path is NEWER than the audit output it is supposed to predate. That is exactly the signature
    of the reported sequence, and it is checked here.

    HONEST LIMIT, MEASURED rather than assumed. Modification times are metadata and can be set,
    so the obvious question is whether this check survives someone setting them. It does not, and
    that was measured instead of guessed: in the same throwaway repository, the reported sequence
    is refused; adding one command — `touch -d "2020-01-01 00:00:00" datei.txt` on the restored
    path — makes the very same invocation emit the payload again.

    So the check is a NARROWING, not a proof: it catches the accident and the ordinary careless
    sequence, a tree touched between the audit and the receipt, and it stops at deliberate
    backdating. Closing that would take a signed statement from the audit runner about the tree it
    saw, which is a schema change and belongs to the owner, not to this fix. Calling this a proof
    would be exactly the kind of claim this whole file exists against.
    """
    if audit_output_path is None:
        raise SystemExit(
            "emit: the path of the audit output was not handed to the cleanliness gate, so the "
            "ORDER of audit and receipt cannot be checked here — refusing, because an unchecked "
            "order is what the reported defect exploits (fail-closed)")
    try:
        audit_zeit = Path(audit_output_path).stat().st_mtime
    except OSError as fehler:
        raise SystemExit(
            f"emit: cannot read the modification time of the audit output {audit_output_path} "
            f"({fehler}) — refusing, because the order of audit and receipt is then unknown") from fehler
    try:
        lauf = _git(repo, "ls-files", "-z")
    except (OSError, subprocess.SubprocessError) as fehler:
        raise SystemExit(
            f"emit: cannot list the tracked files of {repo} ({fehler}) — refusing, because the "
            f"order of audit and receipt cannot be established") from fehler
    if lauf.returncode != 0:
        raise SystemExit(
            f"emit: `git ls-files` failed in {repo} — refusing, because the order of audit and "
            f"receipt cannot be established")
    # THE AUDIT OUTPUT IS NOT YOUNGER THAN ITSELF. It may be tracked and live inside the tree;
    # compared with its own timestamp it is then trivially equal, and the `>=` below would make
    # it refuse itself. Measured while fixing this finding:
    # `test_committed_receipt_verifies_and_src_change_is_rejected` hands `_audit.txt` in as a
    # tracked audit output and failed on exactly that. A path compared with itself says nothing
    # about an order.
    try:
        audit_echt = Path(audit_output_path).resolve()
    except OSError:
        audit_echt = None
    juenger = []
    for roh in lauf.stdout.split(b"\0"):
        if not roh:
            continue
        pfad = repo / roh.decode("utf-8", errors="replace")
        try:
            if audit_echt is not None and pfad.resolve() == audit_echt:
                continue
        except OSError:
            pass
        try:
            # `lstat`, NOT `stat`: for a symlink the question is when the LINK was written, and
            # `stat` answers for its target — a restored link beside an untouched target would
            # have read as old. A broken link raises under `stat` and was silently skipped by the
            # `except` below, which turned the least inspectable case into the quietest one.
            zeit = pfad.lstat().st_mtime
        except OSError:
            continue
        # `>=`, NOT `>`. Codex (P1, 2026-09-23 on 308b76b): when the restored file and the audit
        # output carry the SAME timestamp, the strict comparison reads the restore as "not after"
        # and the emit proceeds. Reproduced before the fix in a throwaway repository — every
        # tracked path at 11:00, the restored `datei.txt` and the audit output both at 12:00,
        # `git status` empty: rc 0, payload written, `subject_tree_digest` 7084edf3… (the clean
        # head) bound to `audit_output_digest` b3ccfeee… (computed over the dirty bytes).
        #
        # Equal is not "before". Two writes sharing a timestamp cannot be ordered from here at
        # all, and a coarse filesystem or a fast sequence produces that constantly. The file's own
        # doctrine settles which way to resolve it: not-determinable is not a clearance, and a
        # release receipt is the last place to guess.
        if zeit >= audit_zeit:
            juenger.append(str(pfad.relative_to(repo)))
    if juenger:
        gezeigt = "\n  ".join(sorted(juenger)[:20])
        mehr = f"\n  … and {len(juenger) - 20} more" if len(juenger) > 20 else ""
        raise SystemExit(
            f"emit: {len(juenger)} tracked path(s) are NOT OLDER than the audit output "
            f"{audit_output_path} — so the audit cannot be shown to have read the bytes this "
            f"receipt would attest. A path with the SAME timestamp counts here: two writes that "
            f"share a timestamp cannot be ordered, and a release receipt does not guess. Re-run "
            f"the audit on the tree as it stands now:\n  {gezeigt}{mehr}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--repo", type=Path, default=Path("."))
    # context (inline + emit)
    p.add_argument("--version", default=None)
    p.add_argument("--audit-command", default=None)
    p.add_argument("--audit-exit", type=int, default=None)
    p.add_argument("--audit-output-file", type=Path, default=None)
    p.add_argument("--runner-identity", default=None)
    p.add_argument("--produced-at", default=None, help="UTC timestamp, measured by the runner")
    p.add_argument("--privkey-file", type=Path, default=None,
                   help="base64 ed25519 private key (32 bytes) — a runner secret, never in the repo (inline mode)")
    p.add_argument("--out", type=Path, default=None)
    # keyless emit
    p.add_argument("--emit-payload", type=Path, default=None,
                   help="keyless: write canonical_bytes(context) here (no privkey); needs --context-out")
    p.add_argument("--context-out", type=Path, default=None)
    # keyless assemble
    p.add_argument("--assemble", action="store_true",
                   help="keyless: build a receipt from --context-in + --sig-file + --signer-pubkey")
    p.add_argument("--context-in", type=Path, default=None)
    p.add_argument("--sig-file", type=Path, default=None)
    p.add_argument("--signer-pubkey", default=None)
    args = p.parse_args(argv)
    repo = args.repo.resolve()

    # ── assemble mode (keyless second half) ──────────────────────────────────────────────────────
    if args.assemble:
        _need(args, ["context-in", "sig-file", "signer-pubkey", "out"], "assemble")
        context = json.loads(args.context_in.read_text(encoding="utf-8"))
        sig_b64 = args.sig_file.read_text(encoding="utf-8").strip()
        receipt = assemble_receipt(context, sig_b64, args.signer_pubkey.strip())
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"assembled receipt -> {args.out}")
        return 0

    # context is needed for both emit and inline
    _need(args, ["version", "audit-command", "audit-exit", "audit-output-file", "runner-identity", "produced-at"],
          "emit/inline")
    audit_output = args.audit_output_file.read_text(encoding="utf-8", errors="ignore")

    # ── emit mode (keyless first half) ───────────────────────────────────────────────────────────
    if args.emit_payload is not None:
        _need(args, ["context-out"], "emit")
        context = build_context(repo, args.version, args.audit_command, args.audit_exit,
                                audit_output, args.runner_identity, args.produced_at,
                                args.audit_output_file)
        args.emit_payload.parent.mkdir(parents=True, exist_ok=True)
        args.emit_payload.write_bytes(canonical_bytes(context))
        args.context_out.parent.mkdir(parents=True, exist_ok=True)
        args.context_out.write_text(json.dumps(context, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"emitted payload -> {args.emit_payload}  context -> {args.context_out}")
        return 0

    # ── inline mode (the OWNER's signing path, gated) ────────────────────────────────────────────
    _inline_erlaubt_oder_stop()
    _need(args, ["privkey-file"], "inline")
    receipt = build_and_sign(
        repo, args.version, args.audit_command, args.audit_exit,
        audit_output, args.runner_identity, args.produced_at,
        args.privkey_file.read_text(encoding="utf-8").strip(),
        args.audit_output_file)
    out = args.out or (repo / "audit_artifacts" / _version_token(args.version)
                       / f"pre_tag_receipt_{args.version}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote signed receipt -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
