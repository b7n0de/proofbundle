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

import contextlib
import hashlib
import importlib.machinery
import json
import os
import re as _re
import sys
from pathlib import Path

RECEIPT_SCHEMA = "b7n0de.pre_tag_audit_receipt.v1"
_SIGNED_FIELDS = (
    "schema", "version", "subject_tree_digest", "gate_source_digest",
    "audit_command", "audit_exit_code", "audit_output_digest", "runner_identity", "produced_at",
)
#: Every member a receipt may carry: the signed fields and the two that wrap them (DELTA2 N2).
_RECEIPT_MEMBERS = frozenset(_SIGNED_FIELDS) | {"signature", "signer_pubkey"}


# ── ONE FUNNEL FOR EVERY GIT CALL OF THE RECEIPT CHAIN ──────────────────────────────────────────
#
# The producer (`pre_tag_receipt.py`), this library and the release gate (`pre_tag_audit_gate.py`,
# through this library) ask git through `git_run` below. The third-party verifier
# (`verify_pre_tag_receipt.py`) carries a copy of it in its own file, because its first job is to
# refuse a checkout in which THIS file was modified, and a check that ran through this file could be
# answered by the modification it looks for. A contract test derives the call sites of all those
# files, and of everything they import or load by path, from their syntax trees, refuses any git call
# outside the two funnels, and holds the two equal in allowlist, pinned options and built
# environment (`tests/test_pre_tag_chain_asks_git_through_one_funnel.py`).
#
# WHY AN ALLOWLIST, measured 2026-09-27. The first repair removed a LIST of environment names
# (`git rev-parse --local-env-vars` plus the configuration selectors) and a lens found names the
# list did not carry within the hour: `GIT_ICASE_PATHSPECS=1` and `GIT_GLOB_PATHSPECS=1` made a
# clean tree refuse, `GIT_TRACE=/dev/stdout` wrote timestamped lines into the listing the digest
# hashes, and the third-party verifier had never used the list at all (with `GIT_WORK_TREE` on a
# clean clone its cleanliness check came back empty and a modified checkout was VERIFIED). git
# reads more names than any list here will carry, so the environment of a chain call is BUILT:
# the names below pass through, a fixed set is pinned, and nothing else reaches git.
#
# WHY THE CONFIGURATION IS PINNED ON THE COMMAND LINE. `-c` outranks every file git reads (system,
# global, repository, worktree, and anything they include), while an environment switch is read
# BEFORE the configuration and loses to it: measured, `GIT_NO_REPLACE_OBJECTS=1` and
# `--no-replace-objects` both lost to `core.useReplaceRefs=true` in `.git/config`, and the gate
# verified a tampered checkout against the replaced commit's digest. System and global files are
# not read at all; the repository's own file is read, and every key that changes what `ls-tree`,
# `show`, `rev-parse`, `hash-object`, `check-ignore`, `diff-index` or `status` answer is either
# pinned below or named in the CHANGELOG with the reason it is not.

#: Environment names passed through to git unchanged. `PATH` finds git (the interpreter and git
#: are the trusted base, and one `PATH` picks both); `SYSTEMROOT` is needed by processes on
#: Windows and means nothing elsewhere.
_GIT_INHERITED = ("PATH", "SYSTEMROOT")

#: Configuration pinned for every call. What each key did when it was not pinned:
#:   core.useReplaceRefs=false  replacement objects stay off whatever the repository says
#:   core.quotePath=true        the listing the digest hashes has one text form (git's default)
#:   core.excludesFile          a configured excludes file hid an untracked file (it named a
#:                              TRACKED ignore file, and the producer took the rule for the tree's)
#:   core.attributesFile        attributes from outside the tree stay out of `status`
#:   core.fsmonitor=            no hook command runs, and none can report a changed file as clean
#:   core.untrackedCache=false  no cached directory listing stands in for the directory
#:   core.ignoreCase=false      path equality is byte equality
#:   core.commitGraph=false     no cache of commit data stands in for the commit object
#:   core.checkStat=default,    `status` compares the full stat data, so a rewrite that keeps
#:   core.trustctime=true       size and mtime is still rehashed
#:   color.ui=false             no escape codes in what is parsed
GIT_PINNED_OPTIONS = (
    "--no-replace-objects",
    "-c", "core.useReplaceRefs=false",
    "-c", "core.quotePath=true",
    "-c", f"core.excludesFile={os.devnull}",
    "-c", f"core.attributesFile={os.devnull}",
    "-c", "core.fsmonitor=",
    "-c", "core.untrackedCache=false",
    "-c", "core.ignoreCase=false",
    "-c", "core.commitGraph=false",
    "-c", "core.checkStat=default",
    "-c", "core.trustctime=true",
    "-c", "color.ui=false",
)


def git_environment(root: Path) -> dict:
    """The complete environment of a chain git call about the repository whose top level is `root`.

    `GIT_WORK_TREE` is pinned to `root`: `core.worktree` in the repository's configuration made
    `check-ignore` answer from another directory (an untracked file there was hidden by that
    directory's `.gitignore`), and git lets the environment outrank that key. `GIT_DIR` is NOT
    pinned: git then discovers the repository from `root`, and discovery is the step that refuses
    a repository owned by another user (measured: `detected dubious ownership` under discovery,
    none with an explicit `GIT_DIR`). `GIT_CEILING_DIRECTORIES` stops that discovery at `root`, so
    a directory without its own repository never borrows the one around it. System and global
    configuration are not read, so `safe.directory` cannot be supplied from outside either: a
    repository owned by another user fails closed.
    """
    umgebung = {k: os.environ[k] for k in _GIT_INHERITED if k in os.environ}
    umgebung.update({
        "LC_ALL": "C", "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_WORK_TREE": str(root),
        "GIT_CEILING_DIRECTORIES": str(root.parent),
    })
    # No environment name that chooses a program for git to run is inherited (owner OA-4496f29e70; the allowlist
    # already keeps them out, these empties make the funnel neutral even if the allowlist grows).
    umgebung.update({k: "" for k in ("GIT_EXTERNAL_DIFF", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_PAGER", "GIT_EDITOR",
                                     "GIT_SEQUENCE_EDITOR", "GIT_PROXY_COMMAND", "GIT_ASKPASS")})
    return umgebung


#: The configuration keys that make a repository a PARTIAL CLONE, as a pattern `git config --get-regexp` matches.
#:
#: External review of 65d8f8cd, F3 (2026-10-02, measured by the reviewer at d0e47397): a repository with a promisor
#: remote fetches an object it does not hold the moment a command asks for it, and the fetch starts that remote's
#: transport, whose program the repository's own configuration names (`remote.<name>.uploadpack`, an ssh command, a
#: remote helper). A missing object in such a clone ran the configured `remote.origin.uploadpack` from `git_objects`,
#: and from the verifier's `_objekte`, `_baum` and `_measure`, before any refusal; the configuration refusal listed
#: nothing for that key, and a verdict given afterwards does not undo a program that already ran. git makes a remote a
#: promisor through these keys (`remote.<name>.promisor`, `remote.<name>.partialclonefilter`) and through the
#: repository format's `extensions.partialClone`. A repository that carries any of them, whatever the value, is asked
#: nothing further by either funnel, so no object is read from it and nothing is fetched. A full clone from the forge
#: carries none. The verifier carries the same pattern; the funnel contract holds the two equal.
#: The subsection may be EMPTY (`remote..promisor`, which git accepts; external review of d97f6e7b, R2-2), so the middle
#: of the pattern is `.*`, not `.+`.
_TEILKLON_SCHLUESSEL = r"^(extensions\.partialclone|remote\..*\.(promisor|partialclonefilter))$"


def _nennt_die_wurzel(antwort: bytes, root: Path) -> bool:
    """Does git's `--show-toplevel` answer name `root` (already resolved)?

    COMPARED AS PATHS, NOT AS TEXT (Codex on PR 249, round four, P1; estimated there and here, as
    no Windows runner is available). Git for Windows prints the top level with forward slashes
    (`C:/repo`) where the resolved `root` reads `C:\\repo`, so a text comparison refused the real top
    level of every repository on that platform. An answer that is empty or not absolute names no
    directory and is refused: resolved, it would stand for the working directory of this process,
    which may be `root` itself. For an answer that already is the resolved path, as git prints it on
    Linux, the verdict is the one the text comparison gave. The verifier carries a copy of this
    function for the reason it carries a copy of the funnel."""
    text = os.fsdecode(antwort)
    if not text or not Path(text).is_absolute():
        return False
    try:
        return Path(text).resolve() == root
    except (OSError, RuntimeError, ValueError):
        return False


def git_run(repo, *args: str, stdin_bytes: bytes | None = None, timeout: float = 120):
    """Run `git <args>` about the repository whose top level is `repo`; the completed process.

    THE PLACE THE RECEIPT CHAIN STARTS GIT (the verifier's copy aside, see above). It raises
    `BaumNichtLesbar` when git cannot be started or does not finish, and when git does not answer
    for `repo` itself: before the call,
    `rev-parse --show-toplevel --show-prefix` must name `repo` and an empty prefix. A `--repo` that
    names a subdirectory made `ls-tree -r HEAD` list only that subdirectory while `git show
    HEAD:<path>` stayed relative to the root, and the gate then took the digest from one tree and
    the trust anchor from another (measured: `ok=true` for a tampered root). It raises as well when
    `repo` is a partial clone (`_TEILKLON_SCHLUESSEL`), before the call, so no object read can fetch.
    A nonzero exit of the call itself is returned, not raised; what it means is the caller's to decide.
    """
    import subprocess  # noqa: PLC0415
    root = Path(os.fspath(repo)).resolve()
    umgebung = git_environment(root)

    def starte(argumente: tuple, eingabe: bytes | None):
        extra = {"input": eingabe} if eingabe is not None else {"stdin": subprocess.DEVNULL}
        try:
            return subprocess.run(["git", *GIT_PINNED_OPTIONS, "-C", str(root), *argumente],
                                  capture_output=True, timeout=timeout, env=umgebung, **extra)
        except (OSError, subprocess.SubprocessError) as fehler:
            raise BaumNichtLesbar(
                f"git could not be asked about {root}: {type(fehler).__name__}: {fehler}") from fehler

    ort = starte(("rev-parse", "--show-toplevel", "--show-prefix"), None)
    zeilen = ort.stdout.split(b"\n")
    if ort.returncode != 0:
        grund = ort.stderr.decode("utf-8", "replace").strip().splitlines()
        raise BaumNichtLesbar(f"git does not answer for {root} as a repository"
                              + (f": {grund[0]}" if grund else ""))
    if len(zeilen) < 2 or not _nennt_die_wurzel(zeilen[0], root) or zeilen[1] != b"":
        raise BaumNichtLesbar(
            f"git answers for {root} with the top level {os.fsdecode(zeilen[0])!r} and the prefix "
            f"{os.fsdecode(zeilen[1]) if len(zeilen) > 1 else ''!r}; the chain asks only about the "
            "top level of the repository it is given, because a listing relative to a subdirectory "
            "and a path relative to the root describe two different trees")
    # NO QUESTION TO A PARTIAL CLONE (see `_TEILKLON_SCHLUESSEL`). Asked here, in the funnel, so it comes before every
    # object access of every caller, not only of the callers that remember to ask. `git config --get-regexp` reads the
    # configuration and no object; exit 1 with no output is "no such key", anything else refuses.
    teilklon = starte(("config", "-z", "--get-regexp", _TEILKLON_SCHLUESSEL), None)
    if teilklon.returncode == 0 and teilklon.stdout:
        namen = sorted({e.split(b"\n", 1)[0].decode("utf-8", "replace")
                        for e in teilklon.stdout.split(b"\0") if e})
        raise BaumNichtLesbar(
            f"{root} is a partial clone ({', '.join(namen)[:160]}): git fetches an object it does not hold "
            "from the promisor remote and starts the program that remote's configuration names, so no "
            "object is read from it -- clone the repository in full")
    if teilklon.returncode != 1 or teilklon.stdout:
        grund = teilklon.stderr.decode("utf-8", "replace").strip().splitlines()
        raise BaumNichtLesbar(f"git could not say whether {root} is a partial clone"
                              + (f": {grund[0]}" if grund else ""))
    return starte(args, stdin_bytes)


# ── WHAT THE CHAIN READS FROM GIT'S OBJECT STORE IS THE OBJECT ITS ID NAMES ─────────────────────
#
# MEASURED 2026-09-27 (review finding on PR 249, P0): the trust anchor was read with `git show
# HEAD:audit_artifacts/pre_tag_trusted_pubkeys.txt`, and git hands out whatever content lies under
# an object id without hashing it. The loose object of the keys file, rewritten with another key
# under the same id, left the tree digest and the checked-out file unchanged, and the release gate
# answered `ok=true, state=verified` for a receipt signed by a key the committed file does not
# name (git 2.55.0; git 2.34.1 hashes a blob that `show` parses and refused). `refs/replace` was
# the first way to that result and is pinned off above; the object store itself is the second (a
# loose object, an object in a pack whose index names another id, an object in a directory that
# `.git/objects/info/alternates` adds). A tree below the root is read without a hash on both
# versions: rewritten under its id, it listed another blob as the anchor, and the gate verified
# with git 2.34.1 as well. Which object a given git hashes on which path is its own business; the
# chain does not rely on it and hashes every object it reads.
#
# THE FORM: every object is read through one `git cat-file --batch` and its bytes are hashed here,
# as git defines an id (`<type> <size>NUL<content>`, SHA-1 or SHA-256 by the length of the id), and
# compared with the id it was asked for. The other form, reading the file from the working tree
# after the cleanliness check verified it against the id, exists only in the producer; the release
# gate and the third-party verifier have no such check over the whole tree, and one form for every
# site is one property to test. Hashing the bytes that were read, in this process, leaves no second
# read between the check and the use, and it asks git nothing about its own store.

#: The hash of an object id, by the number of hex digits: SHA-1 or SHA-256, the two git uses.
_ID_ALGORITHMUS = {40: "sha1", 64: "sha256"}
_IST_OBJEKT_ID = _re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def git_object_id(typ: str, inhalt: bytes, stellen: int) -> str:
    """The id git gives an object of `typ` with `inhalt`, in the hash an id of `stellen` hex digits
    uses: the hash of `<typ> <size>`, a NUL byte, and the content."""
    try:
        h = hashlib.new(_ID_ALGORITHMUS[stellen])
    except KeyError:
        raise BaumNichtLesbar(f"an object id of {stellen} hex digits names no hash git uses") from None
    h.update(typ.encode("ascii") + b" " + str(len(inhalt)).encode("ascii") + b"\0")
    h.update(inhalt)
    return h.hexdigest()


def git_objects(repo, gesucht) -> dict:
    """{id: content} for `gesucht`, a sequence of `(id, type)`, read through ONE `git cat-file
    --batch`. Each content is returned only if git reports the type asked for and the bytes hash to
    the id; a missing object, another type or other bytes raise `BaumNichtLesbar`."""
    typen: dict = {}
    for oid, typ in gesucht:
        if not isinstance(oid, str) or not _IST_OBJEKT_ID.match(oid):
            raise BaumNichtLesbar(f"{oid!r} is not a full object id; only an id is read by id")
        if typen.setdefault(oid, typ) != typ:
            raise BaumNichtLesbar(f"the object {oid} is asked for as two types")
    if not typen:
        return {}
    r = git_run(repo, "cat-file", "--batch",
                stdin_bytes=b"".join(oid.encode("ascii") + b"\n" for oid in typen))
    if r.returncode != 0:
        grund = r.stderr.decode("utf-8", "replace").strip().splitlines()
        raise BaumNichtLesbar(f"git cat-file --batch failed in {repo}" + (f": {grund[0]}" if grund else ""))
    aus, pos, raus = r.stdout, 0, {}
    for oid, typ in typen.items():
        ende = aus.find(b"\n", pos)
        kopf = aus[pos:ende].split(b" ") if ende >= 0 else []
        if len(kopf) != 3 or kopf[0] != oid.encode("ascii") or not kopf[2].isdigit():
            raise BaumNichtLesbar(f"the object {oid} is not in the object store of {repo} "
                                  f"(git answered {aus[pos:ende][:80]!r})")
        gelesen, groesse = kopf[1].decode("ascii", "replace"), int(kopf[2])
        inhalt = aus[ende + 1:ende + 1 + groesse]
        if len(inhalt) != groesse or aus[ende + 1 + groesse:ende + 2 + groesse] != b"\n":
            raise BaumNichtLesbar(f"git's answer for the object {oid} is cut short")
        pos = ende + 2 + groesse
        if gelesen != typ:
            raise BaumNichtLesbar(f"the object {oid} is a {gelesen}, and a {typ} was named")
        ist = git_object_id(gelesen, inhalt, len(oid))
        if ist != oid:
            raise BaumNichtLesbar(
                f"the {typ} read from {repo} under the id {oid} is not the object its id names: "
                f"its bytes hash to {ist} (a rewritten loose object, a pack whose index names "
                "another id, or an alternate object directory) — what git answers under that id "
                "cannot stand for the tree, and nothing read from it is judged")
        raus[oid] = inhalt
    if pos != len(aus):
        raise BaumNichtLesbar("git cat-file --batch answered more than it was asked")
    return raus


def _modus(roh: bytes) -> tuple[str, str]:
    """(mode as `ls-tree` prints it, object type) for a raw tree entry mode, the way git's
    `canon_mode` and `object_type` read it."""
    if not roh or any(c < 0x30 or c > 0x37 for c in roh):
        raise BaumNichtLesbar(f"a tree entry carries the mode {roh!r}, which is not octal")
    m = int(roh, 8)
    art = m & 0o170000
    if art == 0o100000:
        return ("100755" if m & 0o100 else "100644"), "blob"
    if art == 0o120000:
        return "120000", "blob"
    if art == 0o040000:
        return "040000", "tree"
    return "160000", "commit"


def _baumeintraege(inhalt: bytes, stellen: int) -> list:
    """[(mode, type, id, name)] of a raw tree object, names as bytes."""
    breite, raus, pos = stellen // 2, [], 0
    while pos < len(inhalt):
        leer = inhalt.find(b" ", pos)
        nul = inhalt.find(b"\0", leer + 1) if leer >= 0 else -1
        if leer < 0 or nul < 0 or nul + 1 + breite > len(inhalt) or nul == leer + 1:
            raise BaumNichtLesbar("a tree object is not in the form git writes")
        mode, typ = _modus(inhalt[pos:leer])
        raus.append((mode, typ, inhalt[nul + 1:nul + 1 + breite].hex(), inhalt[leer + 1:nul]))
        pos = nul + 1 + breite
    # A NAME STANDS ONCE IN A TREE (R13-3, external review round 13, measured at f6ea5cc3). A tree
    # written with `hash-object --literally` may name one path twice; `git show` then reads the first
    # entry and a checkout leaves the other on disk, while the digest sorted the listing lines and gave
    # the same value for both orders, so one receipt verified two trees with different content. Every
    # reader of a tree object here goes through this function (`git_tree` for the digest, `git_file`
    # for the trust anchor and the gate source), so the refusal holds on every level and before any
    # exclusion.
    gesehen: set = set()
    for _mode, _typ, _oid, name in raus:
        if name in gesehen:
            raise BaumNichtLesbar(
                f"a tree names {name!r} twice — two readers of one tree read two contents under that "
                "name (`git show` the first entry, a checkout the other), so no digest and no file is "
                "taken from it")
        gesehen.add(name)
    return raus


def _commit_und_wurzel(repo, rev: str) -> tuple[str, str]:
    """(commit id, root tree id) of `rev`, the commit object read and checked against its id."""
    r = git_run(repo, "rev-parse", "--verify", f"{rev}^{{commit}}")
    commit = r.stdout.decode("ascii", "replace").strip()
    if r.returncode != 0 or not _IST_OBJEKT_ID.match(commit):
        raise BaumNichtLesbar(f"{rev} names no commit in {repo}")
    erste = git_objects(repo, [(commit, "commit")])[commit].split(b"\n", 1)[0]
    wurzel = erste[5:].decode("ascii", "replace")
    if not erste.startswith(b"tree ") or len(wurzel) != len(commit) or not _IST_OBJEKT_ID.match(wurzel):
        raise BaumNichtLesbar(f"the commit {commit} names no tree")
    return commit, wurzel


def git_tree(repo, rev: str = "HEAD") -> tuple[str, list]:
    """(commit id, [(mode, type, id, path)]) for every entry below the tree of `rev`, trees
    included and paths as bytes, read from a commit and from trees that each hash to their id. One
    `cat-file --batch` per level of the tree."""
    commit, wurzel = _commit_und_wurzel(repo, rev)
    eintraege: list = []
    ebene = [(wurzel, b"")]
    while ebene:
        gelesen = git_objects(repo, [(oid, "tree") for oid, _ in ebene])
        naechste = []
        for oid, praefix in ebene:
            for mode, typ, eid, name in _baumeintraege(gelesen[oid], len(oid)):
                eintraege.append((mode, typ, eid, praefix + name))
                if typ == "tree":
                    naechste.append((eid, praefix + name + b"/"))
        ebene = naechste
    return commit, eintraege


def git_file(repo, rev: str, pfad: str):
    """(mode, type, id, content) of the entry at `pfad` in the tree of `rev`, or None when there
    is none. Every object on the way, and the blob, is checked against its id; the content of an
    entry that is not a blob is None."""
    _commit, baum = _commit_und_wurzel(repo, rev)
    teile = os.fsencode(pfad).split(b"/")
    for i, teil in enumerate(teile):
        treffer = [e for e in _baumeintraege(git_objects(repo, [(baum, "tree")])[baum], len(baum))
                   if e[3] == teil]
        if not treffer:
            return None
        mode, typ, oid, _name = treffer[0]
        if i < len(teile) - 1:
            if typ != "tree":
                return None
            baum = oid
            continue
        inhalt = git_objects(repo, [(oid, "blob")])[oid] if typ == "blob" else None
        return mode, typ, oid, inhalt
    return None


#: The escapes of git's C-style quoting of a path (`quote_c_style`); every other byte that needs
#: quoting is written as three octal digits.
_C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def _pfad_aus_listing(text: str) -> bytes:
    """The bytes of a path as `ls-tree` printed it with `core.quotePath=true`."""
    if not (len(text) >= 2 and text[0] == '"' and text[-1] == '"'):
        return text.encode("ascii")
    innen, raus, i = text[1:-1], bytearray(), 0
    try:
        while i < len(innen):
            if innen[i] != "\\":
                raus.append(ord(innen[i]))
                i += 1
            elif innen[i + 1] in _C_ESCAPES:
                raus.append(_C_ESCAPES[innen[i + 1]])
                i += 2
            else:
                raus.append(int(innen[i + 1:i + 4], 8))
                i += 4
    except (IndexError, ValueError) as fehler:
        raise BaumNichtLesbar(f"the listed path {text!r} is not in git's quoted form") from fehler
    return bytes(raus)


#: SINCE LESSON 2 ONLY THE PATH FORM, NO LONGER THE EXCEPTION (Codex on pull request 541, round lx4, P0 2; owner
#: choice B, 19 November 2026). Until then EVERY path of this form left the digest, in every version folder and at
#: every mode, a link or a gitlink as well: `audit_artifacts/660/pre_tag_receipt_v6.6.0.json` could be added, changed
#: or removed beside a given 6.6.1 receipt without moving its digest, and neither the gate nor the outside verifier of
#: 6.6.1 looks into the folder of 6.6.0. Left out now is exactly the receipt of the version the tree itself names in
#: `pyproject.toml` (`eigene_quittungen`); the pattern stays as the path form for the transition of the audit matrix
#: and for `sign_readiness_artifact.ist_quittungspfad`.
#:
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
#: VERENGT 2026-09-07 (Gegenlesung, Fund 3): `[^/\t]+` liess JEDEN Ordnernamen als Versions-Token
#: durchgehen, `audit_artifacts/anything_i_want/pre_tag_receipt_v9.9.9.json` fiel also aus der
#: Bindung. Kein Konsument nutzte das aus — `_receipt_candidates` scoped auf den exakten Token —,
#: aber eine Ausnahme, die mehr ausschliesst als sie muss, ist der Anfang derselben Klasse, die
#: dieser Commit gerade schliesst. `_version_token` ist die Version ohne Punkte, beginnt also mit
#: einer Ziffer; genau das verlangt das Muster jetzt auch vom Ordner.
#: `+` UND `!` GEHOEREN IN DIE ZEICHENKLASSE (Gegenlesung 07.09.2026, ausgefuehrt). Die erste
#: Verengung liess sie weg, und damit fiel eine PEP-440-Lokalversion aus dem Ausschluss:
#: `_version_token("6.1.0+local")` ist `610+local`, das Muster traf nicht, die Quittung lag also IM
#: eigenen Digest — zirkulaer, sie kann nie verifizieren. Gemessen ueber sechs Formen: 6.0.0,
#: 6.1.0rc1, 6.1.0.post1 und 6.1.0-rc.1 fielen korrekt raus, `6.1.0+local` und `1!6.0.0` nicht.
#: KORREKTUR AN DIESER BEGRUENDUNG, gemessen: der Defekt ist AELTER als die Verengung. Auch die
#: vorige Fassung liess den Ordner frei (`[^/\t]+`), verlangte fuer den DATEINAMEN aber dieselbe
#: Zeichenklasse ohne `+` — `pre_tag_receipt_v6.1.0+local.json` traf also schon vorher nicht. Eine
#: Gegenlesung hat 13 PEP-440-Formen gegen beide Fassungen gefahren: 26 von 26 identisch. Die
#: Verengung ist keine Regression; sie haette den Fall nur an einer zweiten Stelle wiederholt.
#: Beide Stellen tragen jetzt `+` und `!`. Kein Sicherheitsloch (fail-closed), ein Funktionsdefekt.
#: DER TABULATOR AM ANFANG IST DER ANKER, und er fehlte bis 2026-09-07 (deep gate Lauf 5, Linse 2,
#: Exploit ausgefuehrt). `.search()` prueft die GANZE `ls-tree`-Zeile, und die hat die Form
#: `<mode> <type> <sha>\t<pfad>`. Ohne fuehrenden `\t` traf das Muster jeden Pfad, der IRGENDWO
#: so ENDET — `src/proofbundle/audit_artifacts/1/pre_tag_receipt_v1.json` also auch. Gemessen in
#: einer isolierten Kopie: T0 signiert -> `verified`, Digest `cea597b4`; T1 legt genau diese Datei
#: unter `src/` an, OHNE neu zu signieren -> Digest BYTEIDENTISCH, Tor weiter `verified`.
#: Negativkontrolle auf gewoehnlichem Pfad -> Digest anders, Tor `rejected`. Eine Ausnahme, die
#: mehr ausschliesst als sie darf, ist ein Loch im Ausschluss und nicht seine Grosszuegigkeit.
#: DER NACHBAR ZWEI ZEILEN WEITER MACHTE ES SEIT JE RICHTIG: `MUTABLE_EVIDENCE_RELS` vergleicht mit
#: `endswith("\t" + pfad)` und ist damit verankert. Dieselbe Datei, dieselbe Frage ("meint dieser
#: Text eine Pfadgrenze?"), zwei Vergleichsarten — und nur eine davon band die Grenze. Genau das
#: ist die Klasse, die dieser Commit repoweit sweept: eine Zeichenketten-Suche entscheidet ueber
#: eine Groesse, die eine GRENZE meint.
_RECEIPT_MUSTER = _re.compile(
    r"\taudit_artifacts/[0-9][0-9A-Za-z.+!_\-]*/pre_tag_receipt_v?[0-9][0-9A-Za-z.+!_\-]*\.json$")


#: THE AUDIT OUTPUT BESIDE ITS RECEIPT (owner choice A on card OA-71c0d50067, 2026-11-18, lesson 2).
#: The receipt binds the tree as it was measured BEFORE the audit ran, and the output only exists after
#: the run. Committed afterwards, it changed this digest, so a release could carry its receipt or its
#: audit output but never both (measured on a throwaway clone at v6.6.0: the gate said `verified`, and
#: with the 6.6.0 output committed beside the receipt it said `other_tree`). One path form is therefore
#: left out of the digest, and only when the receipt beside it binds it: see `gebundene_ausgaben`. The
#: form is new on purpose: none of the 58 refs measured on 2026-11-18 (the tags and main) carries it, so this
#: output rule moves none of their digests, while the older name `audit_output_v<version>.txt` lies in four tags
#: and stays in the digest. The receipt rule of `eigene_quittungen` does move the digest of every tree that carries
#: receipts of earlier versions (measured at v6.6.0, lesson 2). The pattern is matched against the whole path, and
#: its folder must be the version's.
_AUSGABE_MUSTER = _re.compile(
    r"\A(audit_artifacts/([0-9][0-9A-Za-z.+!_\-]*))/pre_tag_audit_output_v([0-9][0-9A-Za-z.+!_\-]*)\.txt\Z")

#: The modes of a regular file in a tree. A receipt beside an output may carry either.
_REGULAERE_MODI = ("100644", "100755")

#: THE ONE MODE AN EXCLUDED OUTPUT MAY CARRY (Codex on pull request 541, round lx2, P0 2). The signed
#: digest binds the output's bytes and nothing else, and the excluded listing line carries the mode: an
#: output left out at `100755` and one at `100644` gave the same tree digest, so a change of mode moved
#: the tree without moving any binding. An output at any other mode stays in the digest.
_AUSGABE_MODUS = "100644"
#: The receipt that leaves the digest carries the same one mode, for the same reason (Codex on pull request 541,
#: round lx4, P0 2: the receipt rule matched the path and ignored the mode, so a change of mode moved no binding).
_QUITTUNG_MODUS = _AUSGABE_MODUS

#: The release version a tree declares, read the way `pre_tag_audit_gate.pyproject_version` reads it: the first
#: `version = "X.Y.Z..."` line of `pyproject.toml`. Only the receipt and the output of THIS version may leave the
#: digest.
_VERSION_IN_PYPROJECT = _re.compile(r'(?m)^\s*version\s*=\s*["\']([0-9]+\.[0-9]+\.[0-9]+[^"\']*)["\']')
#: The characters a version may carry before it names a path: the class of `_RECEIPT_MUSTER` and of the audit
#: matrix's transition. A version outside it names no receipt and no output, so nothing leaves the digest.
_VERSION_ALS_PFADTEIL = _re.compile(r"\A[0-9][0-9A-Za-z.+!_\-]*\Z")


def eigene_version(repo, nach_pfad: dict) -> str | None:
    """The version the tree declares in its `pyproject.toml`, or None.

    `nach_pfad` maps a path (bytes) to `(mode, type, id)`, as `git_tree` lists the tree; the blob is read by its id
    and checked against it. None when the file is not a regular blob of the tree, is not UTF-8, names no version, or
    names one that is no path component (`_VERSION_ALS_PFADTEIL`). A tree without a version leaves no receipt and no
    output out of its digest."""
    pp = nach_pfad.get(b"pyproject.toml")
    if pp is None or pp[1] != "blob" or pp[0] not in _REGULAERE_MODI:
        return None
    try:
        m = _VERSION_IN_PYPROJECT.search(git_objects(repo, [(pp[2], "blob")])[pp[2]].decode("utf-8"))
    except UnicodeDecodeError:
        return None
    if not m or not _VERSION_ALS_PFADTEIL.match(m.group(1)):
        return None
    return m.group(1)


def eigene_quittungen(nach_pfad: dict, version: str | None) -> list:
    """The paths (bytes) of the receipts the digest leaves out: in the folder of `version`, under one of the two
    names the house uses (`pre_tag_receipt_v<version>.json` as the bundle carries it, `pre_tag_receipt_<version>.json`
    as `pre_tag_receipt.py` writes it), as a regular file of mode `100644`. Nothing else: a receipt of another version,
    in another folder, under another name, at another mode, a link or a gitlink stays in the digest."""
    if version is None:
        return []
    ordner = f"audit_artifacts/{version.replace('.', '')}"
    aus = []
    for name in (f"{ordner}/pre_tag_receipt_v{version}.json", f"{ordner}/pre_tag_receipt_{version}.json"):
        pfad = name.encode("ascii")
        e = nach_pfad.get(pfad)
        if e is not None and e[1] == "blob" and e[0] == _QUITTUNG_MODUS:
            aus.append(pfad)
    return aus

#: The trust anchor of the pre-tag receipt, as a path in the tree. It is never excluded from the digest.
_SCHLUESSELDATEI = b"audit_artifacts/pre_tag_trusted_pubkeys.txt"


def ist_ausgabepfad(pfad: str) -> bool:
    """True when `pfad` (repository-relative) has the form of an audit output beside its receipt and
    sits in its version's folder. The form alone excludes nothing; `gebundene_ausgaben` decides."""
    m = _AUSGABE_MUSTER.match(pfad)
    return bool(m) and m.group(2) == m.group(3).replace(".", "")


def gebundene_ausgaben(repo, eintraege, *, zeilen: list) -> set:
    """The paths (bytes) of the audit outputs in `eintraege` that the digest leaves out.

    `eintraege` is the listing `git_tree` returns, objects already checked against their ids. An output
    is left out only when all of this holds, and otherwise it stays in the digest:
      - it is a regular file at `audit_artifacts/<token>/pre_tag_audit_output_v<version>.txt`, and
        `<token>` is `<version>` without its dots;
      - its mode is `100644` (`_AUSGABE_MODUS`);
      - `<version>` is the version the tree declares in `pyproject.toml` (`eigene_version`);
      - a receipt that leaves the digest itself lies in the same folder (`eigene_quittungen`: one of the two
        names, a regular file of mode `100644`), is read the one way the gate and the verifier read a receipt
        (`receipt_json`), carries
        the receipt schema, names `<version>` as its `version`, names the SHA-256 of the output's bytes as
        its `audit_output_digest`, and carries a signature over its signed fields by a key that the trust
        anchor of THIS tree (`audit_artifacts/pre_tag_trusted_pubkeys.txt`, itself in the digest) names
        (`signatur_eines_vertrauten`, the check `verify_receipt` ends with).
      - that receipt's signed `subject_tree_digest` is the digest of `zeilen` (the listing lines the tree digest
        hashes) without exactly the outputs left out.
    So no file stands in the excluded path without a trusted signature over a digest that names its bytes, given
    for the tree that is measured.

    THE RECEIPT MUST ATTEST THIS TREE (Codex on pull request 541, round lx3, P0 1). With signature, version and
    output digest alone, a pair that a trusted key once signed for 6.6.0, the receipt and its output, could be added
    to a tree whose 6.6.1 receipt was already given, or taken from it, and both paths left the digest: the gate of
    6.6.1 does not judge the folder of 6.6.0. Now an output is left out only when the receipt beside it attests the
    digest that results without it. The digest depends on which outputs are left out, so the set is a fixed point:
    start from every candidate, take the digest without all of them, keep the candidates whose receipt attests that
    digest, and repeat until nothing more falls away. The set only shrinks, so this ends; an empty set is the
    digest with every output in it.

    THE SIGNATURE IS CHECKED HERE, NOT LEFT TO THE GATE (Codex on pull request 541, round lx2, P0 1). The
    first form of this rule read the receipt beside the output and checked no signature, on the reasoning
    that the gate rejects a receipt that does not verify. The gate judges only the folder of the version
    it is asked about. Under `audit_artifacts/660/` anyone who writes the tree could commit an unsigned
    receipt naming any digest and an output with those bytes, and both left the digest that the receipt of
    6.6.1 binds. The owner's choice A says the output is bound by the SIGNED digest; a digest nobody
    signed binds nothing. The tree a receipt attests is checked as well, in the fixed point described below, and
    only the output of the version the tree itself declares in `pyproject.toml` (a file in the digest) is a
    candidate at all (Codex on pull request 541, round lx4, P0 1: a pair signed for another version over the same
    tree left the digest otherwise). When the signature cannot be checked at all, because the
    signature module of the package cannot be imported, the digest is refused (`BaumNichtLesbar`), never
    taken with or without the output by default."""
    nach_pfad = {pfad: (mode, typ, oid) for mode, typ, oid, pfad in eintraege}
    # ONLY THE TREE'S OWN VERSION, and beside it only the receipts that leave the digest themselves
    # (`eigene_quittungen`). A tree without a readable `pyproject.toml` version leaves nothing out.
    version = eigene_version(repo, nach_pfad)
    if version is None:
        return set()
    pfad = f"audit_artifacts/{version.replace('.', '')}/pre_tag_audit_output_v{version}.txt".encode("ascii")
    e = nach_pfad.get(pfad)
    if e is None or e[1] != "blob" or e[0] != _AUSGABE_MODUS:
        return set()
    quittungen = [nach_pfad[q][2] for q in eigene_quittungen(nach_pfad, version)]
    if not quittungen:
        return set()
    kandidaten = [(pfad, e[2], version, quittungen)]
    anker = nach_pfad.get(_SCHLUESSELDATEI)
    anker_oid = anker[2] if anker is not None and anker[1] == "blob" and anker[0] in _REGULAERE_MODI else None
    gesucht = {(oid, "blob") for _p, oid, _v, qs in kandidaten for oid in [oid, *qs]}
    if anker_oid is not None:
        gesucht.add((anker_oid, "blob"))
    objekte = git_objects(repo, sorted(gesucht))
    try:
        vertraut = _schluessel_aus_text(objekte[anker_oid].decode("utf-8")) if anker_oid is not None else []
    except UnicodeDecodeError:
        vertraut = []
    bezeugt: dict = {}
    # THE SIGNATURE MODULE OF THE MEASURED COMMIT (Codex on pull request 541, round lx4, P0 3): the check below
    # imports `proofbundle.signature`, and it is served from the blobs of the tree that is measured, never from the
    # files of the checkout (`paket_aus_eintraegen`).
    with paket_aus_eintraegen(repo, eintraege):
        for pfad, oid, version, quittungen in kandidaten:
            digest = hashlib.sha256(objekte[oid]).hexdigest()
            for q in quittungen:
                try:
                    rc = receipt_json(objekte[q])
                except ValueError:
                    continue
                if not (isinstance(rc, dict) and rc.get("schema") == RECEIPT_SCHEMA
                        and rc.get("version") == version and rc.get("audit_output_digest") == digest):
                    continue
                try:
                    ok, _grund = signatur_eines_vertrauten(rc, vertraut)
                except ImportError as fehler:
                    raise BaumNichtLesbar(
                        f"the output {pfad.decode('ascii')} lies beside a receipt that names its bytes, and "
                        "whether a trusted key signed that receipt cannot be checked: the signature module of "
                        f"the package is not importable ({fehler}). The digest would be taken over a guess"
                    ) from fehler
                if ok:
                    bezeugt.setdefault(pfad, set()).add(rc.get("subject_tree_digest"))
    gebunden = set(bezeugt)
    while gebunden:
        texte = {q.decode("ascii") for q in gebunden}
        ohne = _digest_der_zeilen([ln for ln in zeilen if ln.partition("\t")[2] not in texte])
        bleibt = {q for q in gebunden if ohne in bezeugt[q]}
        if bleibt == gebunden:
            break
        gebunden = bleibt
    return gebunden


def _digest_der_zeilen(zeilen: list) -> str:
    """The tree digest over listing lines: sha256 of the sorted lines, joined by newlines. One formula for the
    digest and for the fixed point of `gebundene_ausgaben`."""
    return hashlib.sha256("\n".join(sorted(zeilen)).encode("utf-8")).hexdigest()


# ── THE SIGNATURE MODULE COMES FROM THE HELD COMMIT, NOT FROM THE CHECKOUT ──────────────────────
#
# Codex on pull request 541, round lx4, P0 3 (owner choice B, 19 November 2026). The gate put `<repo>/src` in
# front of `sys.path`, and so did the release step for its own check of the committed receipt, so that
# `verify_receipt` could import `proofbundle.signature`. That imported whatever lay on disk: whoever could write the
# checkout while the run went on could make the signature check of a forged receipt pass, with HEAD and every blob
# that was read unchanged. The package is now served from the blobs of the commit that is judged, each read through
# `git_objects` and so checked against its id; the files of the checkout are not read for it.
#
# A commit that carries no `src/proofbundle` (a test tree, or a repository judged with this repository's tools)
# brings no package of its own. Then the interpreter's package is used, found on its search path, and refused when
# it lies inside the judged checkout: code of that checkout which the commit does not carry never judges it.

_PAKET = "proofbundle"
_PAKET_ORDNER = b"src/proofbundle"


def _gehoert_zum_paket(name: str) -> bool:
    return name == _PAKET or name.startswith(_PAKET + ".")


class _PaketAusDemCommit:
    """A finder and loader on `sys.meta_path` for `proofbundle` and its submodules, from the entries of one commit.

    `module` maps a module name to `(blob id, path, is a package)`; None means the commit carries no package. A
    module the commit's package does not hold is refused, never looked for elsewhere: a finder that returned None
    would hand the name to the next finder, and that one reads the disk."""

    def __init__(self, repo, module, wurzel, grund: str | None = None):
        self.repo, self.module, self.wurzel, self.grund = repo, module, wurzel, grund

    def find_spec(self, name, path=None, target=None):
        if not _gehoert_zum_paket(name):
            return None
        if self.grund is not None:
            raise ModuleNotFoundError(f"{name} is not imported: {self.grund}", name=name)
        if self.module is None:
            if name != _PAKET:
                return None                     # a submodule follows its parent's `__path__`, checked below
            spec = importlib.machinery.PathFinder.find_spec(name)
            if spec is None:
                raise ModuleNotFoundError(f"the judged commit carries no {_PAKET} package, and the interpreter "
                                          "finds none on its search path", name=name)
            orte = [spec.origin, *(spec.submodule_search_locations or [])]
            for ort in orte:
                if not isinstance(ort, str):
                    continue
                try:
                    drin = Path(ort).resolve().is_relative_to(self.wurzel)
                except (OSError, RuntimeError, ValueError):
                    drin = True
                if drin:
                    raise ModuleNotFoundError(
                        f"the judged commit carries no {_PAKET} package, and the one on the search path lies in "
                        f"the judged checkout ({ort}); code the commit does not carry does not judge it", name=name)
            return spec
        eintrag = self.module.get(name)
        if eintrag is None:
            raise ModuleNotFoundError(f"the judged commit carries no module {name}", name=name)
        return importlib.machinery.ModuleSpec(name, self, origin=f"{eintrag[1]} (blob {eintrag[0][:12]})",
                                              is_package=eintrag[2])

    def create_module(self, spec):
        return None

    def exec_module(self, modul):
        oid, pfad, _paket = self.module[modul.__name__]
        quelle = git_objects(self.repo, [(oid, "blob")])[oid]
        exec(compile(quelle, pfad, "exec", dont_inherit=True), modul.__dict__)  # noqa: S102 - the committed blob


def _paketmodule(eintraege) -> dict | None:
    """{module name: (blob id, path, is a package)} of `src/proofbundle` in `eintraege`, or None when the tree carries
    no such directory. A `.py` file is a module, a directory is a package when it carries `__init__.py`."""
    nach_pfad = {pfad: (mode, typ, oid) for mode, typ, oid, pfad in eintraege}
    ordner = nach_pfad.get(_PAKET_ORDNER)
    if ordner is None:
        return None
    if ordner[1] != "tree":
        return {}
    module: dict = {}
    for mode, typ, oid, pfad in eintraege:
        if typ != "blob" or mode not in _REGULAERE_MODI or not pfad.startswith(_PAKET_ORDNER + b"/"):
            continue
        if not pfad.endswith(b".py"):
            continue
        try:
            teile = pfad[len(b"src/"):-len(b".py")].decode("ascii").split("/")
        except UnicodeDecodeError:
            continue
        if not all(t.isidentifier() for t in teile):
            continue
        if teile[-1] == "__init__":
            module[".".join(teile[:-1])] = (oid, os.fsdecode(pfad), True)
        else:
            module[".".join(teile)] = (oid, os.fsdecode(pfad), False)
    return module


@contextlib.contextmanager
def paket_aus_eintraegen(repo, eintraege):
    """While the block runs, `import proofbundle...` yields the package of the tree `eintraege` lists (as `git_tree`
    returns it), read blob by blob from the object store; `eintraege=None` refuses every such import. The modules of
    the package that were loaded before are put aside and come back afterwards, and nothing loaded inside stays."""
    wurzel = Path(os.fspath(repo)).resolve()
    if eintraege is None:
        finder = _PaketAusDemCommit(repo, None, wurzel, grund="the held commit could not be read")
    else:
        finder = _PaketAusDemCommit(repo, _paketmodule(eintraege), wurzel)
    beiseite = {n: m for n, m in list(sys.modules.items()) if _gehoert_zum_paket(n)}
    for n in beiseite:
        del sys.modules[n]
    sys.meta_path.insert(0, finder)
    try:
        yield
    finally:
        with contextlib.suppress(ValueError):
            sys.meta_path.remove(finder)
        for n in [n for n in list(sys.modules) if _gehoert_zum_paket(n)]:
            del sys.modules[n]
        sys.modules.update(beiseite)


@contextlib.contextmanager
def paket_aus_commit(repo, commit):
    """`paket_aus_eintraegen` for the tree of `commit` (None: refuse every import of the package)."""
    try:
        eintraege = git_tree(repo, commit)[1] if commit is not None else None
    except BaumNichtLesbar:
        eintraege = None
    with paket_aus_eintraegen(repo, eintraege):
        yield


#: Ein erwarteter Digest ist ein sha256 in Kleinhex, 64 Stellen — und NUR das. Siehe die Pruefung in
#: `verify_receipt`: sie entscheidet ueber die FORM des erwarteten Wertes, damit kein Ersatzwert
#: eines Aufrufers je bindbar wird.
_IST_SHA256 = _re.compile(r"\A[0-9a-f]{64}\Z")


class BaumNichtLesbar(RuntimeError):
    """Der Baum liess sich nicht messen — kein Digest, und ausdruecklich KEIN Ersatzwert.

    WARUM EIN GEWOEHNLICHER FEHLER UND KEIN ``SystemExit`` (2026-09-07). Die erste Fassung dieser
    Haertung warf ``SystemExit``. Das ist eine ``BaseException``, und der einzige Aufrufer im Tor
    faengt ``except Exception`` — die Ausnahme flog also AM Ruecknetz VORBEI und beendete den
    Prozess, statt das Tor urteilen zu lassen. ``pre_tag_audit_gate.evaluate`` traegt im eigenen
    Kommentar den Satz "A gate must RULE, never crash"; eine Bibliothek, die unter ihm den Prozess
    abbricht, nimmt ihm genau das. GEMESSEN: fuenf Tests in
    ``tests/test_roadmap_frontload_foundations.py``, die das Tor gegen einen belegfreien
    Nicht-git-Ordner fahren, starben am Abbruch statt ein ``ok=False`` zu bekommen — ein
    Negativtest, der nicht mehr negativ urteilt, sondern stirbt.

    Die Schwesterfunktion ``sign_readiness_artifact.tree_digest`` wirft weiterhin ``SystemExit``.
    DIE ERSTE BEGRUENDUNG DAFUER WAR FALSCH und ist am 07.09.2026 von einer Gegenlesung widerlegt
    worden: hier stand "sie laeuft nur aus einer CLI heraus". Sie laeuft auch aus einer Bibliothek —
    ``audit_candidate_matrix._live_tree_digest`` ruft sie in Zeile 710. Was dort traegt, ist nicht
    der Aufrufertyp, sondern dass genau dieser Aufrufer ``except SystemExit`` AUSDRUECKLICH faengt.
    Die Trennung bleibt damit richtig, ihre Begruendung ist eine andere: eine Bibliotheksfunktion
    darf ``BaseException`` nur werfen, wenn JEDER ihrer Aufrufer sie sichtbar abfaengt — und das ist
    eine Eigenschaft, die man pruefen muss, keine, die man annehmen darf. Wer eine dritte
    Aufrufstelle baut, bekommt sonst genau die Regression zurueck, die dieser Commit behebt.
    """


def _messung(repo, rev: str = "HEAD") -> tuple:
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
    # DIE AUSSCHLUSSMENGE KOMMT AUS DEM TORVERZEICHNIS, NICHT VOM ANFANG DES SUCHPFADS
    # (Gegenlesung 07.09.2026, ausgefuehrt). `pre_tag_audit_gate.evaluate` legt `<repo>/src` auf
    # `sys.path[0]`, damit `proofbundle.signature` importierbar ist. Ein schlichtes
    # `from sign_readiness_artifact import ...` nimmt dann, was dort ZUERST liegt — und eine
    # UNGETRACKTE Datei `src/sign_readiness_artifact.py` liegt dort, ohne im gemessenen HEAD zu
    # stehen. Gemessen: mit geschatteter Ausschlussmenge blieb `subject_tree_digest` byteidentisch,
    # waehrend eine committete `src/proofbundle/backdoor.py` im Baum lag, und das Tor sagte
    # `ok=True, state=verified`. Der gepruefte Baum lieferte den Code, der ihn misst.
    #
    # Diese Datei liegt in `scripts/` neben `sign_readiness_artifact.py`. Also wird von DORT geladen,
    # ueber den Pfad dieser Datei, statt ueber den Suchpfad. Das schliesst die Schattung fuer diese
    # eine Groesse; die allgemeinere Frage (das Tor importiert `proofbundle.signature` aus dem
    # beurteilten Baum) ist damit NICHT geschlossen und ist als eigener Befund gemeldet.
    import importlib.util as _ilu  # noqa: PLC0415
    _nachbar = Path(__file__).resolve().parent / "sign_readiness_artifact.py"
    try:
        _spec = _ilu.spec_from_file_location("_pre_tag_sra", _nachbar)
        if _spec is None or _spec.loader is None:
            raise ImportError(f"no loader for {_nachbar}")
        _mod = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        MUTABLE_EVIDENCE_RELS = _mod.MUTABLE_EVIDENCE_RELS
    except Exception as e:  # noqa: BLE001 — Ausschlussmenge unbekannt -> KEIN Digest ueber die falsche
        raise BaumNichtLesbar(
            "the mutable-evidence set is not loadable from the gate's own directory "
            f"({_nachbar}) — the exclusion set would be a guess, and a digest over the wrong set "
            f"is worse than none: {type(e).__name__}: {e}") from e
    # `core.quotePath=true` IS PINNED (in `GIT_PINNED_OPTIONS`), not left to the configuration: the
    # digest hashes the TEXT of the listing, and with `core.quotePath=false` in a user's
    # `~/.gitconfig` a non-ASCII path is printed raw instead of octal-quoted. Measured 2026-09-27:
    # `caf\303\251.txt` by default, the two raw UTF-8 bytes under that setting, so two machines
    # would compute two digests for one tree. Pinned to git's default, which leaves every digest
    # computed so far unchanged, and so does `--full-tree`: `git_run` has already refused any
    # prefix, and the option makes the listing independent of the prefix as well.
    # THE LISTING IS HELD AGAINST THE OBJECTS IT IS MADE OF (review finding on PR 249, 2026-09-27).
    # `ls-tree` reads the commit and every tree below it from the object store, and git does not
    # hash what it reads there: a tree rewritten under its id listed another blob, and a commit
    # rewritten under its id named another tree, while the head's id stayed the same. The digest
    # is still taken over the text of `ls-tree`, so no digest computed so far changes; that text
    # must describe, entry for entry, the tree that `git_tree` read from a commit and from trees
    # whose bytes each hash to their id, or there is no digest.
    commit, geprueft = git_tree(repo, rev)
    r = git_run(repo, "ls-tree", "--full-tree", "-r", commit, timeout=10)
    if r.returncode != 0:
        raise BaumNichtLesbar(f"cannot read the tree in {repo}: "
                              f"{r.stderr.decode('utf-8', 'replace').strip()}")
    try:
        # Quoted paths make the listing ASCII; anything else is not the listing this digest means.
        text = r.stdout.decode("ascii")
    except UnicodeDecodeError as e:
        raise BaumNichtLesbar(f"the tree listing of {repo} is not the quoted form: {e}") from e
    gelistet = []
    for zeile in text.splitlines():
        kopf, _tab, pfad = zeile.partition("\t")
        teile = kopf.split(" ")
        if len(teile) != 3 or not _tab:
            raise BaumNichtLesbar(f"the tree listing of {repo} carries the line {zeile[:80]!r}")
        gelistet.append((*teile, _pfad_aus_listing(pfad)))
    if sorted(gelistet) != sorted(e for e in geprueft if e[1] != "tree"):
        raise BaumNichtLesbar(
            f"the listing git printed for {commit} in {repo} is not the tree its checked objects "
            "name — the digest would be taken over a tree the commit does not carry")
    veraenderlich = tuple(f"\t{pfad}" for pfad in MUTABLE_EVIDENCE_RELS)
    # ONLY THE RECEIPT OF THE TREE'S OWN VERSION (Codex on pull request 541, round lx4, P0 2): see
    # `_RECEIPT_MUSTER` for what this line excluded before. A receipt of another version is a committed file like
    # any other and stays in the digest. Its path is ASCII by `eigene_quittungen`, so `ls-tree` prints it unquoted.
    nach_pfad = {pfad: (mode, typ, oid) for mode, typ, oid, pfad in geprueft}
    quittungen = {q.decode("ascii") for q in eigene_quittungen(nach_pfad, eigene_version(repo, nach_pfad))}
    grund = [ln for ln in text.splitlines()
             if not ln.endswith(veraenderlich) and ln.partition("\t")[2] not in quittungen]
    # The audit output beside its receipt, only where that receipt names its bytes (`gebundene_ausgaben`).
    # Its path is ASCII by the pattern, so `ls-tree` prints it unquoted and it compares as text.
    ausgaben = {p.decode("ascii") for p in gebundene_ausgaben(repo, geprueft, zeilen=grund)}
    lines = [ln for ln in grund if ln.partition("\t")[2] not in ausgaben]
    # DIE STILLE LEERMESSUNG (Gegenlesung 07.09.2026, ausgefuehrt — und sie geht MITTEN durch die
    # Formpruefung hindurch, die derselbe Commit eingezogen hat). `git -C <unterordner> ls-tree -r
    # HEAD` endet mit rc=0 und LEERER Ausgabe, wenn unter dem Pfad nichts getrackt ist. Der Digest
    # ist dann sha256("") = e3b0c442... — 64 Stellen Kleinhex, also FORMAL einwandfrei. Eine mit dem
    # legitimen Schluessel darauf signierte Quittung verifizierte gemessen als
    # `ok=true, state=verified`, und danach durfte sich JEDE Datei aendern, ohne den Digest zu
    # bewegen. Die Formpruefung fragt nach der FORM des Wertes, nie nach seiner HERKUNFT; sie kann
    # das hier also nicht fangen, und ein Riegel, der seine eigene Luecke nicht kennt, ist der
    # gefaehrlichere. Ein Baum mit null Eintraegen ist kein Freigabekandidat.
    if not lines:
        raise BaumNichtLesbar(
            f"the tree at {repo} has ZERO entries after the exclusions — `git ls-tree -r HEAD` "
            "succeeded and returned nothing, which happens for a path inside a repository that "
            "tracks no file there. The digest of an empty list is a well-formed sha256 and means "
            "nothing; a candidate with no files is not a candidate")
    return _digest_der_zeilen(lines), ausgaben, quittungen


def subject_tree_digest(repo, rev: str = "HEAD") -> str:
    """Digest the receipt binds and the gate verifies, of the tree of `rev` (see `_messung`)."""
    return _messung(repo, rev)[0]


def gebundene_ausgaben_des_baums(repo, rev: str = "HEAD") -> set:
    """The audit outputs (text paths) the digest of the tree of `rev` leaves out, decided by the same measurement
    as `subject_tree_digest`, so the readiness binding and the receipt can never leave out different sets."""
    return set(_messung(repo, rev)[1])


def ausnahmen_des_baums(repo, rev: str = "HEAD") -> set:
    """Every path (text) the digest of the tree of `rev` leaves out besides the mutable evidence: the receipt of the
    tree's own version and the audit output it binds, from the one measurement `subject_tree_digest` takes. The
    readiness binding leaves out exactly these (ONE RULE FOR BOTH BINDINGS)."""
    _digest, ausgaben, quittungen = _messung(repo, rev)
    return set(ausgaben) | set(quittungen)


def receipt_json(raw: bytes):
    """A receipt file read the one way both of its readers read it: UTF-8 without loss, and every
    member name at most once per object. Raises ValueError naming what is refused.

    TWO READERS OF ONE FILE MUST SEE ONE RECEIPT (local review of 8a05ceef, 2026-11-10, P1). The gate
    decoded with `errors="ignore"` and the third-party verifier strictly, so a byte that is not UTF-8
    was dropped by one and refused by the other. Both parsed with `json.loads`, which keeps the LAST of
    two equal names: a receipt carrying `audit_exit_code` 17 and then 0 verified as 0, while a reader
    that keeps the first saw 17, under one signature. The package refuses duplicates on every verify
    path (`proofbundle._strict_json`); the receipt is read the same way, without importing the judged
    tree's code for it."""
    def _einmal(paare):
        obj = {}
        for name, wert in paare:
            if name in obj:
                raise ValueError(f"the receipt names the member {name!r} twice in one object")
            obj[name] = wert
        return obj
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_einmal)


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
    trust-all (one key per line, ``#`` comments). The gate resolves the digest from the same ``HEAD``.

    THE BLOB IS THE ONE ITS ID NAMES (review finding on PR 249, P0, measured 2026-09-27). This read
    was `git show {ref}:<path>`, and git returns whatever lies under the blob's id: the loose object
    of this file, rewritten with another key under the same id, left the tree digest and the checked-
    out file as they were, and the gate verified a receipt signed by that other key (git 2.55.0; the
    tree `audit_artifacts` rewritten to list another blob did the same with git 2.34.1). The commit,
    each tree on the path and the blob are now read with `git_file`, which hashes what it read;
    content that is not the object its id names is no anchor, and the gate fails closed."""
    try:
        # The anchor is read through the same funnel as the digest: a gate that isolated one of
        # the two would take the tree from `--repo` and the trusted keys from wherever `GIT_DIR`
        # points, and a receipt signed by a key of that other repository would then verify.
        eintrag = git_file(repo, ref, "audit_artifacts/pre_tag_trusted_pubkeys.txt")
        if eintrag is None or eintrag[1] != "blob":  # not committed in this tree -> fail closed
            return []
        text = eintrag[3].decode("utf-8")
    except Exception:  # noqa: BLE001 — not a repository / no git / timeout / not UTF-8 / an object
        return []      # that is not the one its id names -> fail closed
    return _schluessel_aus_text(text)


def _schluessel_aus_text(text: str) -> list[str]:
    """The keys of a trust anchor file: one per line, blank lines and `#` comments left out. One
    reading for the gate's anchor and for the anchor `gebundene_ausgaben` reads from the same tree."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def verify_receipt(receipt: dict, *, trusted_pubkeys: list[str], expected_version: str,
                   subject_tree_digest: str, gate_source_digest: str) -> "tuple[bool, str]":
    """(ok, reason). ok iff the receipt is a well-formed, SIGNED (by a trusted key) attestation that
    BINDS this exact tree + version + gate source, and records a SUCCESSFUL audit (exit 0)."""
    # The signature module is imported FIRST, as before the check moved into its own function: a tree
    # whose package cannot be imported raises here, before any field is judged.
    import proofbundle._wire_b64  # noqa: F401, PLC0415
    import proofbundle.signature  # noqa: F401, PLC0415
    if not isinstance(receipt, dict):
        return False, "receipt is not an object"
    # ── DER ERSATZWERT DARF NICHT BINDBAR SEIN (Gegenlesung 2026-09-07, Fund 1) ────────────────────
    # Das Tor ersetzt einen nicht messbaren Baum durch "unknown" (`_gate_tree_digest`) und eine nicht
    # lesbare Gate-Quelle durch "unreadable" (`_gate_source_digest`), damit es urteilen statt
    # abstuerzen kann. Beide Ersatzwerte landeten hier ungeprueft in einem GLEICHHEITSVERGLEICH gegen
    # ein Feld, das der Gepruefte selbst schreibt. Eine mit dem LEGITIMEN Schluessel signierte
    # Quittung mit `subject_tree_digest: "unknown"` verifizierte deshalb IMMER, unabhaengig vom
    # Baumzustand — gemessen am 2026-09-07: `pre_tag_audit_gate.py --json` -> ok=true, verified.
    #
    # Geprueft wird die FORM des ERWARTETEN Wertes, nicht der Wortlaut des Ersatzes. Damit ist jeder
    # heutige UND jeder kuenftige Ersatzwert unbindbar, ohne dass ihn hier jemand aufzaehlen muss —
    # eine Aufzaehlung waere beim naechsten neuen Ersatzwert stillschweigend zu kurz.
    #
    # Die Nachbarflaeche macht es seit Auflage C3 schon so: `audit_candidate_matrix` prueft
    # `if not gebunden` und `if not heute` VOR dem Gleichheitsvergleich des Ankerdigests. Diese
    # Funktion war der Nachzuegler, nicht der Vorreiter.
    for feld, erwartet in (("subject_tree_digest", subject_tree_digest),
                           ("gate_source_digest", gate_source_digest)):
        if not isinstance(erwartet, str) or not _IST_SHA256.match(erwartet):
            return False, (
                f"the gate could not measure {feld} for this tree (got {str(erwartet)[:32]!r}, which "
                "is not a sha256) — an unmeasured quantity cannot be attested, so this fails closed "
                "instead of comparing against a placeholder that a receipt could simply carry")
    if receipt.get("schema") != RECEIPT_SCHEMA:
        return False, f"unknown schema {receipt.get('schema')!r} (want {RECEIPT_SCHEMA})"
    # A MEMBER BESIDE THE SIGNED ONES TRAVELS UNSIGNED (DELTA2 N2, 2026-11-06): `canonical_bytes`
    # signs `_SIGNED_FIELDS` only, so anything else in the object was carried under a verified
    # receipt without being attested. The receipt is a closed set; each foreign member is named.
    fremd = sorted((k for k in receipt if k not in _RECEIPT_MEMBERS), key=repr)
    if fremd:
        return False, ("receipt carries member(s) outside the signed set, which no signature covers: "
                       + ", ".join(repr(k) for k in fremd))
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
    ok, grund = signatur_eines_vertrauten(receipt, trusted_pubkeys)
    return (True, "signed, tree-bound, successful-audit receipt verified") if ok else (False, grund)


def signatur_eines_vertrauten(receipt: dict, trusted_pubkeys: list[str]) -> "tuple[bool, str]":
    """(ok, reason): does a key of `trusted_pubkeys` sign the canonical bytes of `receipt`?

    The last step of `verify_receipt`, and the whole check `gebundene_ausgaben` asks before it leaves an
    audit output out of the tree digest: one function, so the two readers of a signature cannot drift. It
    judges the signature and the key, nothing about tree, version or exit code. Raises ImportError when the
    package's signature module cannot be imported; every other failure is (False, reason). `receipt` is an
    object: both callers check that before they call."""
    from proofbundle._wire_b64 import decode_b64  # noqa: PLC0415
    from proofbundle.signature import (  # noqa: PLC0415
        TRUST_ANCHOR_REFUSAL,
        ed25519_trust_anchor_weakness,
        verify_ed25519_pinned,
    )
    # NO TYPE GUARD OF ITS OWN (cloud circle at c36cb72e): `verify_receipt` refuses a value that is not an
    # object before it calls this, and `gebundene_ausgaben` skips one. A second guard here could not be
    # reached, so no test could bind it, and it made the strip anchor of the first one appear twice.
    if not trusted_pubkeys:
        return False, ("no trusted signing key pinned (audit_artifacts/pre_tag_trusted_pubkeys.txt "
                       "absent/empty, or not readable as the object its id names) — the gate has "
                       "no trust anchor and fails closed")
    signer = receipt.get("signer_pubkey")
    if signer not in trusted_pubkeys:
        return False, f"receipt signer_pubkey is not in the trusted set (signer={str(signer)[:20]}...)"
    sig = receipt.get("signature")
    if not isinstance(sig, str):
        return False, "receipt carries no signature"
    try:
        msg = canonical_bytes(receipt)
        # LAUF11-L2: strikt und kanonisch. Vorher nahm diese Zeile jede zweite Schreibweise
        # derselben Bytes an — 35 von 35 Mutanten verifizierten weiter (Deep Gate Lauf 11).
        signer_raw = decode_b64(signer)
        # THE PINNED KEY GETS THE TRUST-ANCHOR RULE (SPEC 4b). With the bare profile a receipt nobody
        # signed verified under a low-order key standing in the anchor (gate iteration 3 on the rule,
        # lens A, A3-01, measured). The weakness is named before any signature arithmetic.
        weakness = ed25519_trust_anchor_weakness(signer_raw)
        if weakness is not None:
            return False, (f"receipt signer_pubkey is a {weakness} Ed25519 key, refused as a trusted "
                           f"key: {TRUST_ANCHOR_REFUSAL[weakness]}")
        ok = verify_ed25519_pinned(signer_raw, decode_b64(sig), msg)
    except Exception as e:  # noqa: BLE001
        return False, f"signature check errored (fail-closed): {type(e).__name__}: {e}"
    if not ok:
        return False, "ed25519 signature does not verify over the canonical receipt bytes"
    return True, "signed by a trusted key over the canonical receipt bytes"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
