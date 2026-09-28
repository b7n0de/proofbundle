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
import os
import re as _re
from pathlib import Path

RECEIPT_SCHEMA = "b7n0de.pre_tag_audit_receipt.v1"
_SIGNED_FIELDS = (
    "schema", "version", "subject_tree_digest", "gate_source_digest",
    "audit_command", "audit_exit_code", "audit_output_digest", "runner_identity", "produced_at",
)


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
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_WORK_TREE": str(root),
        "GIT_CEILING_DIRECTORIES": str(root.parent),
    })
    return umgebung


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
    the trust anchor from another (measured: `ok=true` for a tampered root). A nonzero exit of the
    call itself is returned, not raised; what it means is the caller's to decide.
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
    commit, geprueft = git_tree(repo, "HEAD")
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
    lines = [ln for ln in text.splitlines()
             if not ln.endswith(veraenderlich) and not _RECEIPT_MUSTER.search(ln)]
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
    from proofbundle._wire_b64 import decode_b64  # noqa: PLC0415
    from proofbundle.signature import (  # noqa: PLC0415
        TRUST_ANCHOR_REFUSAL,
        ed25519_trust_anchor_weakness,
        verify_ed25519_pinned,
    )
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
    return True, "signed, tree-bound, successful-audit receipt verified"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
