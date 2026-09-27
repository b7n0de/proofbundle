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
    if len(zeilen) < 2 or os.fsdecode(zeilen[0]) != str(root) or zeilen[1] != b"":
        raise BaumNichtLesbar(
            f"git answers for {root} with the top level {os.fsdecode(zeilen[0])!r} and the prefix "
            f"{os.fsdecode(zeilen[1]) if len(zeilen) > 1 else ''!r}; the chain asks only about the "
            "top level of the repository it is given, because a listing relative to a subdirectory "
            "and a path relative to the root describe two different trees")
    return starte(args, stdin_bytes)


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
    r = git_run(repo, "ls-tree", "--full-tree", "-r", "HEAD", timeout=10)
    if r.returncode != 0:
        raise BaumNichtLesbar(f"cannot read the tree in {repo}: "
                              f"{r.stderr.decode('utf-8', 'replace').strip()}")
    try:
        # Quoted paths make the listing ASCII; anything else is not the listing this digest means.
        text = r.stdout.decode("ascii")
    except UnicodeDecodeError as e:
        raise BaumNichtLesbar(f"the tree listing of {repo} is not the quoted form: {e}") from e
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
    trust-all (one key per line, ``#`` comments). The gate resolves the digest from the same ``HEAD``."""
    try:
        # The anchor is read through the same funnel as the digest: a gate that isolated one of
        # the two would take the tree from `--repo` and the trusted keys from wherever `GIT_DIR`
        # points, and a receipt signed by a key of that other repository would then verify.
        r = git_run(repo, "show", f"{ref}:audit_artifacts/pre_tag_trusted_pubkeys.txt", timeout=10)
        if r.returncode != 0:  # file not committed in this tree, or unknown ref -> fail closed
            return []
        text = r.stdout.decode("utf-8")
    except Exception:  # noqa: BLE001 — not a repository / no git / timeout / not UTF-8 -> fail closed
        return []
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
                       "absent/empty) — the gate has no trust anchor and fails closed")
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
