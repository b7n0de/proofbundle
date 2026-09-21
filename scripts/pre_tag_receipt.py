#!/usr/bin/env python3
"""Produce a SIGNED pre-tag audit receipt (makellose-500 Phase 3, reviewer F6). Run by the RUNNER
(CI / owner). Signs with an ed25519 key whose PUBLIC half is pinned in
``audit_artifacts/pre_tag_trusted_pubkeys.txt`` and whose PRIVATE half is a release secret held OUTSIDE
the agent's reach. The gate (pre_tag_audit_gate.py) verifies what this writes.

THE AUDIT RUNS INSIDE THIS TOOL, BETWEEN TWO MEASUREMENTS OF THE TREE (2026-09-21). Until then the
audit ran elsewhere and this tool received its output as a file. It then checked the checkout only
while building the receipt, which is AFTER the audit had run, so it could not establish the property
it claims: that the tree whose digest the receipt binds is the tree the audit examined. Measured by a
counter-reading at 9c889f35e34a2e199e65f91694bc49b6f6e3563c: modify a tracked file, produce the audit
output from those bytes, `git checkout --` the file, then emit; the command returned 0 and bound the
clean head to output produced from the dirty tree. Now `--audit-command` is a program that THIS
process starts, in the tree, after measuring it clean and once more after the run; the recorded exit
code is what the program returned, and `--audit-output-file` is where this process writes the bytes it
captured. A typed exit code and a supplied record are no longer accepted, because neither can be bound
to a run that was measured.

THE SECOND AND THIRD ROUND, same day: the tree was compared through `git status`, and the index
flags `assume-unchanged` and `skip-worktree` make git skip a modified tracked file there; then it
was compared through `git diff-index` on a fresh index, and a clean filter from the configuration,
`core.worktree` and `core.fileMode=false` still decided what git reported. The comparison is now
COMPUTED from the bytes on disk against `git ls-tree -r HEAD`, with no filter, attribute, index bit
or `core.*` setting in between; see `_baumzustand_oder_stop`.

WHAT THAT ESTABLISHES, AND WHAT IT DOES NOT. Established: the working tree equalled the committed head
before the run and after it, the head and the tree digest were the same at both points, and the output
digest is over the bytes this process read from that run. Not established: a change made and undone
DURING the run, by the audit program itself or by a concurrent writer, lies between the two
measurements and is invisible to them; the interpreter and its standard library are trusted, not
measured; and the audit program's own behaviour is recorded, not judged.

THREE modes. The signed 9-field CONTEXT is identical in all three; only WHERE the signature comes from
differs. The security-deciding core (``canonical_bytes`` / ``verify_receipt`` in pre_tag_receipt_lib.py)
is byte-identical and untouched by this file:

  inline   (default, --privkey-file): measure, run the audit, measure, build the context, sign it here,
           write the receipt. The runner holds the key.
  emit     (--emit-payload P --context-out C): the same measurement and run, then write
           ``canonical_bytes(context)`` to P and the context JSON to C. NO private key is read. This is
           the Farmer half of the two-half keyless handshake: the Farmer emits, the key-holder (Mac)
           signs P, the Farmer assembles. The private key never reaches the Farmer.
  assemble (--assemble --context-in C --sig-file S --signer-pubkey B --out R): wrap the context C + the
           base64 signature in S (over ``canonical_bytes(C)``) + the pubkey B into a receipt R.
           Self-checks the signature under B and REFUSES on a mismatch (fail-closed: a bad sig/context
           pair never becomes a receipt on disk). Nothing runs and nothing is measured here.

Usage (emit):
  pre_tag_receipt.py --repo . --version 6.1.0 --audit-command "<program and arguments>" \
      --audit-output-file <path outside the tree, not yet existing> --runner-identity <id> \
      --produced-at <iso> --emit-payload <P> --context-out <C>
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shlex
import stat
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

    The audit program this tool starts inherits the same two settings through its environment, so
    the run it records neither writes bytecode into the tree nor executes bytecode it finds there.

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


#: Environment variables through which git answers WHICH repository, WHICH index and WHICH
#: configuration it is talking about, regardless of `-C <repo>`. Measured 2026-09-21: with `GIT_DIR`
#: pointing at another repository, `git -C <repo> status` reported that other repository's state, so
#: the cleanliness gate would have judged a tree nobody named. Dropped from THIS process before the
#: first git call, so every git invocation of this run -- the gate's listings, the tree digest and any
#: git the audit program runs -- answers about the tree given as `--repo`.
_GIT_UMLEITUNG = (
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE",
    "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
)


def _umgebung_ohne_git_umleitung() -> None:
    """Remove the redirecting GIT_* variables from this process (see `_GIT_UMLEITUNG`)."""
    for name in list(os.environ):
        if name in _GIT_UMLEITUNG or name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
            os.environ.pop(name, None)


_bytecode_cache_elsewhere()
_umgebung_ohne_git_umleitung()

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pre_tag_receipt_lib import RECEIPT_SCHEMA, canonical_bytes, subject_tree_digest  # noqa: E402


def _tree_digest(repo: Path) -> str:
    return subject_tree_digest(repo)


def _gate_source_digest(repo: Path) -> str:
    return hashlib.sha256((repo / "scripts" / "pre_tag_audit_gate.py").read_bytes()).hexdigest()


def _version_token(v: str) -> str:
    return v.replace(".", "")


def build_context(repo: Path, version: str, audit_command: str, runner_identity: str,
                  produced_at: str, audit_output_file: Path) -> dict:
    """The 9 SIGNED fields — identical across inline / emit / assemble. Exactly what canonical_bytes covers.

    THE MEASUREMENT AND THE RUN BELONG WHERE THE DIGEST IS MADE, not at one caller. The first version
    put the cleanliness check in the emit branch of main(). A counter-reading pointed at the OTHER
    caller: `build_and_sign` also calls this function, so the inline signing path reached
    `subject_tree_digest` with no cleanliness check at all. `_inline_erlaubt_oder_stop` guards that
    path, but it answers a DIFFERENT question — whether inline signing is permitted, not whether the
    tree being digested is the tree that was measured. Gating one caller instead of the invariant is
    the defect this release keeps finding, and it does not get to hide in the fix for itself.

    The audit runs HERE, between the two measurements, for the same reason: a caller that ran it
    before calling in could not say what the tree looked like while it ran.

    `assemble` does NOT pass here: it reads a context that was already built and signed elsewhere,
    so there is no tree of its own to bind and nothing of its own to run.
    """
    vorher = _baumzustand_oder_stop(repo, "before the audit")
    exit_code, ausgabe_digest, laenge = _audit_ausfuehren(repo, audit_command, audit_output_file)
    nachher = _baumzustand_oder_stop(repo, "after the audit ran")
    if nachher != vorher:
        raise SystemExit(
            f"emit: the tree changed while the audit ran (head {vorher['head'][:12]} -> "
            f"{nachher['head'][:12]}, tree digest {vorher['tree_digest'][:12]} -> "
            f"{nachher['tree_digest'][:12]}) — refusing, because the audit did not examine the "
            "committed head that the receipt would bind")
    print(f"audit ran in {repo}: exit {exit_code}, {laenge} bytes captured -> {audit_output_file} "
          f"(sha256 {ausgabe_digest[:12]}…)")
    if exit_code != 0:
        print(f"note: the audit exited {exit_code}; the receipt records that, and the gate does not "
              "grant a release on a recorded audit that did not succeed")
    return {
        "schema": RECEIPT_SCHEMA,
        "version": version,
        "subject_tree_digest": vorher["tree_digest"],
        "gate_source_digest": _gate_source_digest(repo),
        "audit_command": audit_command,
        "audit_exit_code": exit_code,
        "audit_output_digest": ausgabe_digest,
        "runner_identity": runner_identity,
        "produced_at": produced_at,
    }


def build_and_sign(repo: Path, version: str, audit_command: str, runner_identity: str,
                   produced_at: str, privkey_b64: str, audit_output_file: Path) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from proofbundle._wire_b64 import decode_b64
    priv = Ed25519PrivateKey.from_private_bytes(decode_b64(privkey_b64))
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    receipt = build_context(repo, version, audit_command, runner_identity, produced_at, audit_output_file)
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


def _git_bytes(repo: Path, *args: str, eingabe: bytes | None = None,
               erlaubte_codes: tuple[int, ...] = (0,), umgebung: dict | None = None) -> bytes:
    """One git call in `repo`, its stdout as bytes. Any failure to answer refuses the whole run:
    not-determinable is not a clearance, and a release receipt is the last place to guess."""
    try:
        lauf = subprocess.run(["git", "-C", str(repo), *args], input=eingabe,
                              capture_output=True, timeout=120, env=umgebung)
    except (OSError, subprocess.SubprocessError) as fehler:
        raise SystemExit(
            f"emit: cannot determine whether {repo} is clean (git {' '.join(args[:2])}: {fehler}) "
            "— refusing to bind a tree digest that may not describe what was measured "
            "(fail-closed)") from fehler
    if lauf.returncode not in erlaubte_codes:
        grund = lauf.stderr.decode("utf-8", "replace").strip().splitlines()
        raise SystemExit(
            f"emit: `git {' '.join(args)}` failed in {repo}"
            + (f": {grund[0]}" if grund else "")
            + " — refusing to bind a tree digest that may not describe what was measured")
    return lauf.stdout


def _git_z(repo: Path, *args: str, umgebung: dict | None = None) -> list[str]:
    """A NUL-separated git listing as a list of entries, raw paths, no quoting."""
    return [e.decode("utf-8", "replace")
            for e in _git_bytes(repo, *args, umgebung=umgebung).split(b"\0") if e]


def _versteckte_ignoredateien(repo: Path, sichtbar: set[str], umgebung: dict,
                              baum: str) -> list[str]:
    """Untracked `.gitignore` files that a TRACKED rule does not account for.

    `git ls-files --others --exclude-per-directory=.gitignore` reads every `.gitignore` in the
    working tree, tracked or not. An untracked one whose patterns cover itself (`*`) therefore
    hides itself and its whole directory from that listing, and `git status` shows nothing either
    — measured 2026-09-21 with `sub/.gitignore` containing `*` beside `sub/evil.py`. Tool caches do
    the same legitimately (`.pytest_cache/.gitignore`, `.hypothesis/.gitignore` both contain `*`),
    which is why the shape of the file cannot decide. What decides is the SOURCE of the hiding:
    `git check-ignore -v` names the file and pattern that made the decision. A tracked rule is the
    tree's own word and counts; the untracked file itself, `.git/info/exclude` or a global excludes
    file are outside the committed tree and do not.
    """
    alle = _git_z(repo, baum, "ls-files", "--others", "-z", umgebung=umgebung)
    kandidaten = [p for p in alle if p.rsplit("/", 1)[-1] == ".gitignore" and p not in sichtbar]
    if not kandidaten:
        return []
    verfolgt = set(_git_z(repo, baum, "ls-files", "-z", umgebung=umgebung))
    eingabe = b"".join(p.encode("utf-8") + b"\0" for p in kandidaten)
    # exit 1 means "none of the given paths is ignored"; for paths the listing above hid that
    # cannot happen, and it is not an error of the call either way.
    roh = _git_bytes(repo, baum, "check-ignore", "-v", "-z", "--no-index", "--stdin",
                     eingabe=eingabe, erlaubte_codes=(0, 1), umgebung=umgebung)
    felder = [f.decode("utf-8", "replace") for f in roh.split(b"\0")]
    quelle_je_pfad: dict[str, tuple[str, str]] = {}
    for i in range(0, len(felder) - 3, 4):
        quelle, _zeile, muster, pfad = felder[i:i + 4]
        quelle_je_pfad[pfad] = (quelle, muster)
    fremd: list[str] = []
    for p in kandidaten:
        quelle, muster = quelle_je_pfad.get(p, ("<no source reported>", ""))
        if quelle not in verfolgt:
            fremd.append(f"{p} (hidden by {quelle}: {muster!r}, which is not a tracked rule)")
    return fremd


def _baumzustand_oder_stop(repo: Path, wann: str) -> dict:
    """Refuse unless the working tree equals the committed head; return head and tree digest.

    THE RECEIPT BINDS `git ls-tree -r HEAD` AND THE RUN READS THE WORKING TREE. Those are two
    different sets of bytes whenever anything is uncommitted, and nothing here compared them:
    `subject_tree_digest()` digests the head, the audit whose output this receipt carries runs over
    the checkout. A measurement on the operating tree found two modified paths while a receipt was
    produced, so the receipt attested a tree that was not the tree that had been examined.

    This is the same shape as the hole `subject_tree_digest` already documents for itself, one step
    earlier: there the digest excluded a whole directory and so could not see a key added in the
    same commit; here the digest is correct about the head and the head is not what was measured.
    A digest over the wrong subject is not a weaker binding, it is a binding to something else.

    THREE ROUNDS OF THE SAME CLASS, 2026-09-21, and the class is: STATE OUTSIDE THE COMMITTED TREE
    DECIDES WHAT THE GUARD SEES. The first version asked `git status --porcelain`, and its answer
    was measured to depend on `status.showUntrackedFiles=no`, a global `core.excludesFile`,
    `.git/info/exclude`, an untracked `.gitignore` covering itself and `GIT_DIR` in the environment.
    The second version compared through a fresh index instead, and a counter-reading from another
    model family measured the index bits `assume-unchanged` and `skip-worktree` hiding a modified
    tracked file. The third version compared through `git diff-index` on that fresh index, and the
    own sweep for siblings plus a second counter-reading measured three more: a clean FILTER named
    by `.git/info/attributes` and defined in the configuration (`filter.<x>.clean = git show
    HEAD:%f`) makes a modified file look unchanged, because `diff-index` converts the working file
    before comparing; `core.worktree` makes git compare a directory other than the one the audit
    reads; `core.fileMode=false` hides a mode change. Every one of those is a question asked of git
    about a tree, and git answers through its configuration.

    So the property is COMPUTED FROM THE BYTES rather than asked. For every entry of `git ls-tree
    -r HEAD`:

      a regular file      hashed as a blob with `git hash-object --no-filters` over the bytes on
                          disk, in one batch, and compared with the entry's object id; its mode
                          (100644 or 100755) read from the file itself and compared with the entry;
      a symbolic link     its target hashed as a blob and compared, mode 120000 expected;
      absent, or another  refused by name: a missing file, a directory or device where a file was
      kind of object      committed, a submodule entry (this tool compares none of those);
      staged content      `git diff-index --cached HEAD` on the real index, so a change that sits
                          in the index and not in the head is named as such;
      untracked paths     `git ls-files --others --exclude-per-directory=.gitignore` on a fresh
                          index read from `HEAD`, with the working tree named explicitly on the
                          command line — judged ONLY by the tree's own ignore files, never by the
                          global file, `.git/info/exclude`, `status.showUntrackedFiles` or
                          `core.worktree`;
      untracked ignore    see `_versteckte_ignoredateien`: hidden by a tracked rule is fine, hidden
      files               by anything else refuses.

    No filter, no attribute, no index bit and no `core.*` setting stands between the bytes on disk
    and the comparison. WHAT THAT COSTS, named rather than smoothed over: a checkout whose files
    differ from their blobs BY DESIGN refuses — `core.autocrlf=true` on Windows, a filesystem that
    cannot keep the executable bit, `core.symlinks=false`. Such a checkout is not the tree the head
    names byte for byte, and a release receipt is produced on one that is.

    Fail-closed in both directions. A dirty tree refuses, and a tree whose state cannot be
    determined refuses too: not-determinable is not a clearance, and a release receipt is the last
    place to guess.
    """
    import tempfile  # noqa: PLC0415
    repo_abs = repo.resolve()
    # THE WORKING TREE IS NAMED ON EVERY LISTING COMMAND. `core.worktree` in the checkout's config
    # would otherwise point git at another directory than the one the audit runs in.
    baum = f"--work-tree={repo_abs}"
    schmutzig: list[str] = []
    # ── every committed entry against the bytes on disk ─────────────────────────────────────────
    felder = _git_z(repo, "ls-tree", "-r", "-z", "HEAD")
    regulaer: list[tuple[str, str]] = []            # (path, expected oid) for the batch hash
    for feld in felder:
        kopf, _, pfad = feld.partition("\t")
        try:
            mode, typ, oid = kopf.split()
        except ValueError:
            raise SystemExit(f"emit: cannot read the tree entry {feld!r} — refusing") from None
        if typ != "blob":
            schmutzig.append(f"?! {pfad} (a {typ} entry; this tool compares files and symbolic "
                             "links only, so it refuses rather than guess)")
            continue
        ziel = repo_abs / pfad
        try:
            st = os.lstat(ziel)
        except FileNotFoundError:
            schmutzig.append(f"D {pfad}")
            continue
        except OSError as fehler:
            schmutzig.append(f"?! {pfad} (cannot be read: {fehler})")
            continue
        if stat.S_ISLNK(st.st_mode):
            ist_mode = "120000"
            ist_oid = _git_bytes(repo, "hash-object", "--no-filters", "--stdin",
                                 eingabe=os.fsencode(os.readlink(ziel))).decode("ascii").strip()
            if ist_oid != oid:
                schmutzig.append(f"M {pfad}")
        elif stat.S_ISREG(st.st_mode):
            ist_mode = "100755" if st.st_mode & 0o111 else "100644"
            regulaer.append((pfad, oid))
        else:
            schmutzig.append(f"?! {pfad} (neither a regular file nor a symbolic link)")
            continue
        if ist_mode != mode:
            schmutzig.append(f"mode {pfad} ({mode} -> {ist_mode})")
    if regulaer:
        # ONE BATCH, NO FILTERS: the bytes on disk, hashed the way git stores a blob, and nothing
        # from `.gitattributes`, `.git/info/attributes` or `filter.*` in between.
        # `--stdin-paths` reads one path per LINE and has no NUL form, so a path that carries a
        # newline cannot be named to it; such a path is refused by name rather than mis-hashed.
        krumm = [p for p, _ in regulaer if "\n" in p]
        if krumm:
            raise SystemExit(f"emit: {len(krumm)} tracked path(s) carry a newline in their name "
                             f"and cannot be hashed by path — refusing: {krumm[:3]}")
        eingabe = b"".join(os.fsencode(p) + b"\n" for p, _ in regulaer)
        roh = _git_bytes(repo, "hash-object", "--no-filters", "--stdin-paths", eingabe=eingabe)
        ist = roh.decode("ascii", "replace").split()
        if len(ist) != len(regulaer):
            raise SystemExit(
                f"emit: git hashed {len(ist)} of {len(regulaer)} tracked files — refusing, because a "
                "comparison over a partial set would clear paths nobody looked at")
        schmutzig.extend(f"M {p}" for (p, soll), oid in zip(regulaer, ist) if oid != soll)
    # ── staged content against the head, on the real index ─────────────────────────────────────
    gestaged = _git_z(repo, baum, "diff-index", "--cached", "-z", "--no-renames", "--name-status",
                      "HEAD")
    schmutzig.extend(f"staged {e}" for e in _paare(gestaged))
    # ── untracked paths, through a fresh index that carries nobody's bits ───────────────────────
    frisch = dict(os.environ)
    fd, indexpfad = tempfile.mkstemp(prefix="index_", dir=_CACHE_DIR)
    os.close(fd)
    # git meets a path that does not exist yet: `read-tree` writes it, and no reader of this run
    # ever has to decide what an empty index file means. The directory is this run's own and
    # unpredictable, so no path here can be prepared ahead of time.
    os.unlink(indexpfad)
    frisch["GIT_INDEX_FILE"] = indexpfad
    _git_bytes(repo, baum, "read-tree", "HEAD", umgebung=frisch)
    unverfolgt = _git_z(repo, baum, "ls-files", "--others", "-z",
                        "--exclude-per-directory=.gitignore", umgebung=frisch)
    fremd = _versteckte_ignoredateien(repo, set(unverfolgt), frisch, baum)
    schmutzig += [f"?? {p}" for p in unverfolgt] + [f"!! {x}" for x in fremd]
    if schmutzig:
        gezeigt = "\n  ".join(schmutzig[:20])
        mehr = f"\n  … and {len(schmutzig) - 20} more" if len(schmutzig) > 20 else ""
        raise SystemExit(
            f"emit: {wann}, the working tree of {repo} carries {len(schmutzig)} uncommitted "
            f"path(s), and the receipt would bind `git ls-tree -r HEAD` instead — refusing, because "
            f"the bytes attested would not be the bytes measured:\n  {gezeigt}{mehr}")
    head = _git_bytes(repo, "rev-parse", "--verify", "HEAD").decode("ascii", "replace").strip()
    return {"head": head, "tree_digest": _tree_digest(repo)}


def _paare(eintraege: list[str]) -> list[str]:
    """`diff-index -z --name-status` alternates a status letter and a path; join them again."""
    return [f"{eintraege[i]} {eintraege[i + 1]}" for i in range(0, len(eintraege) - 1, 2)]


def _audit_ausfuehren(repo: Path, audit_command: str, ausgabe: Path) -> tuple[int, str, int]:
    """Start the audit program in the tree and record what it said. -> (exit code, sha256, bytes).

    THE COMMAND IS A PROGRAM AND ITS ARGUMENTS, not a shell line: it is split with `shlex` and
    started without a shell, so what the receipt records as `audit_command` is exactly what ran,
    with one reading. Environment assignments, redirections and pipes are not interpreted; a runner
    that needs them wraps them in a script and names the script.

    THE RECORD IS WRITTEN HERE, AND ONLY HERE. It has to lie outside the tree, because a file that
    appears inside the tree while the audit runs would dirty the very tree the receipt attests, and
    it must not exist beforehand, because a record that was already there is a record this run did
    not produce. Both refuse BEFORE the audit starts, so a long run is not thrown away at the end.

    The digest is over the bytes as captured, and the file is read back and hashed once more after
    it is closed: the receipt's `audit_output_digest` is then recomputable by anyone who holds the
    record, with `sha256sum`, and not only by whoever remembers how it was decoded.
    """
    try:
        argv = shlex.split(audit_command)
    except ValueError as fehler:
        raise SystemExit(f"emit: --audit-command is not a valid command line ({fehler}) — refusing") from fehler
    if not argv:
        raise SystemExit("emit: --audit-command is empty — an audit that runs nothing measures nothing")
    repo_abs = repo.resolve()
    ziel = ausgabe.resolve()
    if ziel == repo_abs or repo_abs in ziel.parents:
        raise SystemExit(
            f"emit: the audit record {ausgabe} lies inside the tree {repo} — refusing before the "
            "run, because writing it there would dirty the tree that the receipt attests")
    if ziel.exists():
        raise SystemExit(
            f"emit: the audit record {ausgabe} already exists — refusing, because this tool writes "
            "the record of the run it measured and does not bind one produced elsewhere")
    umgebung = dict(os.environ)
    umgebung["PYTHONDONTWRITEBYTECODE"] = "1"
    umgebung["PYTHONPYCACHEPREFIX"] = str(_CACHE_DIR)
    hasher = hashlib.sha256()
    laenge = 0
    try:
        ziel.parent.mkdir(parents=True, exist_ok=True)
        with ziel.open("xb") as fh:
            try:
                kind = subprocess.Popen(argv, cwd=str(repo_abs), stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        env=umgebung)
            except OSError as fehler:
                raise SystemExit(
                    f"emit: the audit command could not be started ({fehler}) — refusing, nothing "
                    "was measured") from fehler
            assert kind.stdout is not None
            for stueck in iter(lambda: kind.stdout.read(65536), b""):
                fh.write(stueck)
                hasher.update(stueck)
                laenge += len(stueck)
            exit_code = kind.wait()
    except OSError as fehler:
        raise SystemExit(f"emit: the audit record {ausgabe} could not be written ({fehler}) — refusing") from fehler
    digest = hasher.hexdigest()
    nachgerechnet = hashlib.sha256(ziel.read_bytes()).hexdigest()
    if nachgerechnet != digest:
        raise SystemExit(
            f"emit: the audit record on disk ({nachgerechnet[:12]}…) is not the output that was "
            f"captured ({digest[:12]}…) — refusing, the record would not be recomputable")
    return exit_code, digest, laenge


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--repo", type=Path, default=Path("."))
    # context (inline + emit)
    p.add_argument("--version", default=None)
    p.add_argument("--audit-command", default=None,
                   help="the audit as a program and its arguments (no shell); this tool starts it in "
                        "--repo between two measurements of the tree and records its exit code")
    p.add_argument("--audit-output-file", type=Path, default=None,
                   help="where this tool WRITES the captured output of the audit: outside --repo, "
                        "and not yet existing")
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
    _need(args, ["version", "audit-command", "audit-output-file", "runner-identity", "produced-at"],
          "emit/inline")

    # ── emit mode (keyless first half) ───────────────────────────────────────────────────────────
    if args.emit_payload is not None:
        _need(args, ["context-out"], "emit")
        context = build_context(repo, args.version, args.audit_command, args.runner_identity,
                                args.produced_at, args.audit_output_file)
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
        repo, args.version, args.audit_command, args.runner_identity, args.produced_at,
        args.privkey_file.read_text(encoding="utf-8").strip(), args.audit_output_file)
    out = args.out or (repo / "audit_artifacts" / _version_token(args.version)
                       / f"pre_tag_receipt_{args.version}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote signed receipt -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
