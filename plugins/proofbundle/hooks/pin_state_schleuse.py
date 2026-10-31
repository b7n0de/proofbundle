#!/usr/bin/env python3
"""Pinning the own clone through the lock (owner answers O46-1 and O46-2; D114, D115).

WHAT FOR
  The gate frees git add, git commit and eight read forms in the own tree on the own claude/ branch where the owner
  pinned the state: the hooks, the hooks folder and .git/config, kept in pin-state.json in the gate directory (D114,
  D115). Only the owner pins and renews, never a session (O46-1). This script is the way to do it: it reads the one
  tree the owner names, prints the entry and writes it atomically into the gate directory only once the owner has
  confirmed it with the release value it printed.

WHAT IT READS
  Only the named tree, through the gate itself (`proofbundle_gate.py pin-state <tree>`, which writes nothing), and
  pin-state.json in the gate directory. No other tree, no network, no key.

WHAT IT WRITES
  Only with `schreiben` and the release value `zeigen` printed for exactly this state: pin-state.json in the gate
  directory (new, replaced atomically) and before it a backup beside it, pin-state.json.vor-<time>, with the
  suffix .keine added where there was no file before. One entry per working tree (O46-2); a linked
  working tree is a tree of its own with an entry of its own. Where the tree or the file changed since `zeigen`, the
  value no longer matches and it writes nothing.

CALL (as the account that owns the gate directory, Python 3.10 or newer)
  Show:       python3 -I pin_state_schleuse.py zeigen --baum <working tree> [--tor-verzeichnis <folder>]
  Write:      python3 -I pin_state_schleuse.py schreiben --baum <working tree> --freigabe <value from zeigen>
              [--tor-verzeichnis <folder>]
  List:       python3 -I pin_state_schleuse.py liste [--tor-verzeichnis <folder>]
  Way back:   python3 -I pin_state_schleuse.py zurueck [--sicherung <file name>] [--tor-verzeichnis <folder>]
  Without --tor-verzeichnis the gate's rule applies: PROOFBUNDLE_GATE_DIR, else XDG_CONFIG_HOME/proofbundle, else
  ~/.config/proofbundle. Exit 0: done or nothing to do; 1: refused, the reason is on stderr; 2: a wrong call; 3: the
  release value does not match the state, nothing written.

WAY BACK
  `zurueck` restores the newest backup (with --sicherung a given one) and first backs up the state it replaces, so a
  second `zurueck` without --sicherung undoes the first. A backup ending in .keine removes pin-state.json. Without
  pin-state.json the gate asks as it did before follow-up note 46.

NEVER FROM A SESSION
  The gate rejects recognized session commands that invoke this script. The script
  also rejects the agent environment names it recognizes. These checks do not
  establish operator identity and do not prevent other commands from replacing
  the pin file. Use an access boundary that the session cannot change or bypass.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
GATE = HERE / "proofbundle_gate.py"
sys.path.insert(0, str(HERE))
import proofbundle_gate as gate  # noqa: E402

BACKUP = gate.PIN_STATE_FILE + ".vor-"
NONE_BEFORE = ".keine"


#: Names in the environment of a Bash call of Claude Code or of a Codex turn.
_AGENT_NAMES = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT")


class Refused(Exception):
    """A reason not to go on, printed on stderr; exit 1."""


def _gate_dir(given: str | None) -> pathlib.Path:
    folder = given if given is not None else gate._gate_dir(dict(os.environ))
    if folder is None or not os.path.isabs(folder):
        raise Refused("no gate directory: name one with --tor-verzeichnis and an absolute path")
    path = pathlib.Path(folder)
    if not path.is_dir() or path.is_symlink():
        raise Refused(f"the gate directory {path} is not a folder (or it is a link); create it first")
    return path


def _entries(folder: str) -> list[dict]:
    """The entries of pin-state.json in folder as the gate parses them. The script reads the file it writes, so it
    reads it as with the protected channel of D124; whether the gate itself uses the file stays the hook's setting."""
    return gate._pin_state_entries({"PROOFBUNDLE_GATE_DIR": folder, gate.OWNER_STATE_VARIABLE: gate.OWNER_STATE_PROTECTED})


def entry_now(tree: str) -> dict:
    """The entry of pin-state.json for the tree as it is now, from the gate's own `pin-state`, which writes nothing."""
    if not os.path.isabs(tree):
        raise Refused("--baum needs an absolute path")
    run = subprocess.run([sys.executable, "-I", str(GATE), "pin-state", tree], capture_output=True, text=True,
                         timeout=60, check=False)
    if run.returncode != 0:
        raise Refused(f"the gate does not pin this tree: {run.stderr.strip()}")
    entry = gate.strict_json(run.stdout)
    if not isinstance(entry, dict) or set(entry) != {"pfad", "hakenordner", "haken", "konfig"}:
        raise Refused("the output of pin-state has another form")
    return entry


def _read_file(folder: pathlib.Path) -> tuple[bytes | None, list]:
    """(the bytes of pin-state.json or None where there is none, its entries); refused where the file is there and
    does not read whole for the gate: the script never writes over a file the owner would lose."""
    path = folder / gate.PIN_STATE_FILE
    if not os.path.lexists(path):
        return None, []
    try:
        raw = gate._read_regular(str(path), gate.MAX_PIN_STATE_BYTES + 1)
        data = gate.strict_json(raw) if len(raw) <= gate.MAX_PIN_STATE_BYTES else None
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise Refused(f"{path} does not read whole ({exc}); check it by hand, nothing written") from exc
    klone = data.get("klone") if isinstance(data, dict) and set(data) == {"schema", "klone"} and \
        data["schema"] == gate.PIN_STATE_SCHEMA else None
    if not isinstance(klone, list) or len(_entries(str(folder))) != len(klone):
        raise Refused(f"{path} does not read whole for the gate; check it by hand, nothing written")
    return raw, klone


def _render(klone: list) -> bytes:
    return (json.dumps({"schema": gate.PIN_STATE_SCHEMA, "klone": klone}, indent=2, ensure_ascii=False) + "\n").encode()


def plan(folder: pathlib.Path, tree: str) -> dict:
    """What `schreiben` would do for the tree now: the entry, the action, the new bytes, and the release value that
    binds the write to the directory, the bytes there now and the bytes to come."""
    entry = entry_now(tree)
    old, klone = _read_file(folder)
    same = [i for i, e in enumerate(klone) if gate._realpath(e["pfad"]) == entry["pfad"]]
    if len(same) > 1:
        raise Refused("pin-state.json names this tree twice, so the gate pins nothing; clean it up by hand")
    klone = [dict(e) for e in klone]
    if same and klone[same[0]] == entry:
        action = "unchanged"
    elif same:
        klone[same[0]] = entry
        action = "renewed"
    else:
        klone.append(entry)
        action = "new"
    new = _render(klone) if action != "unchanged" else old
    with tempfile.TemporaryDirectory() as probe:
        (pathlib.Path(probe) / gate.PIN_STATE_FILE).write_bytes(new)
        if len(_entries(probe)) != len(klone):
            raise Refused("the new content would not read whole for the gate; nothing written")
    seal = hashlib.sha256(b"\0".join([b"pin-state-schleuse/v1", str(folder).encode(), old if old is not None
                                      else b"<keine Datei>", new])).hexdigest()
    return {"entry": entry, "action": action, "old": old, "new": new, "freigabe": seal, "folder": folder}


def _write_atomic(folder: pathlib.Path, name: str, data: bytes, mode: int = 0o644) -> None:
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=f".{name}.")
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(tmp, mode)
        if os.geteuid() == 0:
            st = os.stat(folder)
            os.chown(tmp, st.st_uid, st.st_gid)   # the account that owns the gate directory reads it, as the gate does
        os.replace(tmp, folder / name)
    except BaseException:
        if os.path.lexists(tmp):
            os.unlink(tmp)
        raise
    dfd = os.open(folder, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _backup(folder: pathlib.Path, old: bytes | None) -> str:
    now = time.time_ns()
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now // 10**9)) + f".{now % 10**9:09d}"
    name = BACKUP + stamp + (NONE_BEFORE if old is None else "")
    _write_atomic(folder, name, old if old is not None else b"", 0o600)
    return name


class _Lock:
    """One writer at a time in the gate directory, for schreiben and zurueck."""

    def __init__(self, folder: pathlib.Path):
        self.path = folder / ".pin-state.lock"

    def __enter__(self):
        self.fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


def show(folder: pathlib.Path, tree: str) -> int:
    p = plan(folder, tree)
    print(f"Gate directory: {folder}")
    print(f"File: {folder / gate.PIN_STATE_FILE} ({'present' if p['old'] is not None else 'none yet'})")
    print(f"Tree: {p['entry']['pfad']}")
    print(f"Hooks folder: {p['entry']['hakenordner']}")
    print("Hooks: " + (", ".join(f"{n} {s[:12]}…" for n, s in sorted(p['entry']['haken'].items())) or "none"))
    print(f"konfig (sha256 of .git/config): {p['entry']['konfig']}")
    print(f"Effect: {p['action']}")
    print(json.dumps(p["entry"], indent=2, ensure_ascii=False))
    if p["action"] == "unchanged":
        print("Nothing to write: the file already holds this entry.")
        return 0
    print(f"Release value: {p['freigabe']}")
    print("Write only after the owner has checked it, with: schreiben --baum <tree> --freigabe <release value>")
    return 0


def write(folder: pathlib.Path, tree: str, seal: str) -> int:
    with _Lock(folder):
        p = plan(folder, tree)
        if p["action"] == "unchanged":
            print("Nothing to write: the file already holds this entry.")
            return 0
        if seal != p["freigabe"]:
            print("The release value does not match the state now (tree or file changed, or another value); "
                  "nothing written. Show again and release again.", file=sys.stderr)
            return 3
        saved = _backup(folder, p["old"])
        _write_atomic(folder, gate.PIN_STATE_FILE, p["new"])
        back = (folder / gate.PIN_STATE_FILE).read_bytes()
        if back != p["new"] or len(_entries(str(folder))) < 1:
            raise Refused("after the write the file does not read as planned; get the state before back with zurueck")
    print(f"Written ({p['action']}): {folder / gate.PIN_STATE_FILE}")
    print(f"Backup before: {folder / saved}")
    print(f"Way back: python3 -I {pathlib.Path(__file__).name} zurueck --tor-verzeichnis {folder} --sicherung {saved}")
    return 0


def _backups(folder: pathlib.Path) -> list[str]:
    return sorted(n for n in os.listdir(folder) if n.startswith(BACKUP) and not n.startswith("."))


def restore(folder: pathlib.Path, name: str | None) -> int:
    with _Lock(folder):
        names = _backups(folder)
        if name is None:
            if not names:
                raise Refused("no backup in the gate directory")
            name = names[-1]
        if name not in names:
            raise Refused(f"no backup named {name!r}")
        path = folder / gate.PIN_STATE_FILE
        current = gate._read_regular(str(path), gate.MAX_PIN_STATE_BYTES + 1) if os.path.lexists(path) else None
        if name.endswith(NONE_BEFORE):
            saved = _backup(folder, current)
            if current is not None:
                os.unlink(path)
            print(f"Back: no pin-state.json any more (as before {name}); the state before is in {saved}")
            return 0
        raw = gate._read_regular(str(folder / name), gate.MAX_PIN_STATE_BYTES + 1)
        with tempfile.TemporaryDirectory() as probe:
            (pathlib.Path(probe) / gate.PIN_STATE_FILE).write_bytes(raw)
            data = gate.strict_json(raw)
            if len(_entries(probe)) != len(data.get("klone", [])):
                raise Refused(f"the backup {name} does not read whole for the gate; nothing changed")
        saved = _backup(folder, current)
        _write_atomic(folder, gate.PIN_STATE_FILE, raw)
    print(f"Back to {name}; the state before is in {saved}")
    return 0


def listing(folder: pathlib.Path) -> int:
    old, klone = _read_file(folder)
    print(f"Gate directory: {folder}; pin-state.json: {'present' if old is not None else 'none'}")
    for e in klone:
        print(f"  {e['pfad']}  hooks {len(e['haken'])}  konfig {e['konfig'][:12]}…")
    for n in _backups(folder):
        print(f"  Backup: {n}")
    return 0


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pin your own clone through the lock script; "
                                                 "read the header text of this file")
    parser.add_argument("schritt", choices=("zeigen", "schreiben", "liste", "zurueck"))
    parser.add_argument("--baum", help="absolute path of the work tree (zeigen, schreiben)")
    parser.add_argument("--freigabe", help="the release value zeigen printed (schreiben)")
    parser.add_argument("--sicherung", help="name of a backup in the gate directory (zurueck)")
    parser.add_argument("--tor-verzeichnis", dest="tor", help="absolute path of the gate directory")
    args = parser.parse_args(argv)
    if args.schritt in ("zeigen", "schreiben") and not args.baum or args.schritt == "schreiben" and not args.freigabe:
        parser.print_usage(sys.stderr)
        return 2
    agent = [n for n in os.environ if n in _AGENT_NAMES or n.startswith("CODEX_")]
    if agent:
        print(f"refused: the environment is an agent's ({', '.join(sorted(agent))}); only a person pins, "
              "through the lock script (O46-1)", file=sys.stderr)
        return 1
    try:
        folder = _gate_dir(args.tor)
        if args.schritt == "zeigen":
            return show(folder, args.baum)
        if args.schritt == "schreiben":
            return write(folder, args.baum, args.freigabe)
        if args.schritt == "liste":
            return listing(folder)
        return restore(folder, args.sicherung)
    except Refused as why:
        print(f"refused: {why}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
