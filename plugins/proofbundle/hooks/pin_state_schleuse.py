#!/usr/bin/env python3
"""Pin des eigenen Klons über die Schleuse (Nachtrag 51, Punkt 4; Owner-Antworten O46-1 und O46-2; D114, D115).

WOFÜR
  Das Tor gibt git add, git commit und acht Leseformen im eigenen Baum auf dem eigenen claude/-Zweig frei, wo der Owner
  den Stand gepinnt hat: Haken, Hakenordner und .git/config, festgehalten in pin-state.json im Tor-Verzeichnis (D114,
  D115). Pinnen und Erneuern tut nur der Owner, nie eine Sitzung (O46-1). Dieses Skript ist der Weg dafür: es liest
  den einen Baum, den der Owner nennt, druckt den Eintrag und schreibt erst, wenn der Owner ihn mit dem gedruckten
  Freigabe-Wert bestätigt hat, atomar ins Tor-Verzeichnis.

WAS ES LIEST
  Nur den genannten Baum, über das Tor selbst (`proofbundle_gate.py pin-state <Baum>`, das nichts schreibt), und
  pin-state.json im Tor-Verzeichnis. Keinen anderen Baum, kein Netz, keinen Schlüssel.

WAS ES SCHREIBT
  Nur mit `schreiben` und dem Freigabe-Wert, den `zeigen` für genau diesen Stand gedruckt hat: pin-state.json im
  Tor-Verzeichnis (neu, ersetzt atomar) und davor eine Sicherung daneben, pin-state.json.vor-<Zeit> (oder
  pin-state.json.vor-<Zeit>.keine, wenn es vorher keine Datei gab). Ein Eintrag je Arbeitsbaum (O46-2); ein verknüpfter
  Arbeitsbaum ist ein eigener Baum mit eigenem Eintrag. Hat sich der Baum oder die Datei seit dem Zeigen geändert,
  passt der Wert nicht mehr, und es schreibt nichts.

AUFRUF (als das Konto, dem das Tor-Verzeichnis gehört, Python 3.10 oder neuer)
  Zeigen:     python3 -I pin_state_schleuse.py zeigen --baum <Arbeitsbaum> [--tor-verzeichnis <Ordner>]
  Schreiben:  python3 -I pin_state_schleuse.py schreiben --baum <Arbeitsbaum> --freigabe <Wert aus zeigen>
              [--tor-verzeichnis <Ordner>]
  Liste:      python3 -I pin_state_schleuse.py liste [--tor-verzeichnis <Ordner>]
  Rückweg:    python3 -I pin_state_schleuse.py zurueck [--sicherung <Dateiname>] [--tor-verzeichnis <Ordner>]
  Ohne --tor-verzeichnis gilt die Regel des Tors: PROOFBUNDLE_GATE_DIR, sonst XDG_CONFIG_HOME/proofbundle, sonst
  ~/.config/proofbundle. Rückgabe 0: getan oder nichts zu tun; 1: abgelehnt, der Grund steht auf stderr; 2: falscher
  Aufruf; 3: der Freigabe-Wert passt nicht zum Stand, nichts geschrieben.

RÜCKWEG
  `zurueck` stellt die jüngste Sicherung wieder her (mit --sicherung eine bestimmte) und sichert vorher den Stand, den
  es ersetzt; ein zweites `zurueck` ohne --sicherung nimmt das erste also zurück. Eine Sicherung .keine entfernt
  pin-state.json. Ohne pin-state.json fragt das Tor wie vor Nachtrag 46.

NIE AUS EINER SITZUNG
  Das Tor sperrt jeden Befehl einer Sitzung, der dieses Skript nennt und nicht nur liest (D114, Nachtrag 51). Das
  Skript selbst lehnt ab, wenn seine Umgebung die eines Agenten ist (CLAUDECODE, CLAUDE_CODE_ENTRYPOINT oder ein Name
  CODEX_…); das ist eine Bremse, keine Grenze, denn eine Sitzung kann ihre Umgebung ändern. Die Grenze ist das Tor.
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
        raise Refused("kein Tor-Verzeichnis: --tor-verzeichnis mit einem absoluten Pfad nennen")
    path = pathlib.Path(folder)
    if not path.is_dir() or path.is_symlink():
        raise Refused(f"das Tor-Verzeichnis {path} gibt es nicht als Ordner (oder es ist ein Link); erst anlegen")
    return path


def entry_now(tree: str) -> dict:
    """The entry of pin-state.json for the tree as it is now, from the gate's own `pin-state`, which writes nothing."""
    if not os.path.isabs(tree):
        raise Refused("--baum braucht einen absoluten Pfad")
    run = subprocess.run([sys.executable, "-I", str(GATE), "pin-state", tree], capture_output=True, text=True,
                         timeout=60, check=False)
    if run.returncode != 0:
        raise Refused(f"das Tor pinnt diesen Baum nicht: {run.stderr.strip()}")
    entry = gate.strict_json(run.stdout)
    if not isinstance(entry, dict) or set(entry) != {"pfad", "hakenordner", "haken", "konfig"}:
        raise Refused("die Ausgabe von pin-state hat eine andere Form")
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
        raise Refused(f"{path} liest sich nicht ganz ({exc}); von Hand prüfen, nichts geschrieben") from exc
    klone = data.get("klone") if isinstance(data, dict) and set(data) == {"schema", "klone"} and \
        data["schema"] == gate.PIN_STATE_SCHEMA else None
    if not isinstance(klone, list) or len(gate._pin_state_entries({"PROOFBUNDLE_GATE_DIR": str(folder)})) != len(klone):
        raise Refused(f"{path} liest sich für das Tor nicht ganz; von Hand prüfen, nichts geschrieben")
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
        raise Refused("pin-state.json nennt diesen Baum zweimal; das Tor pinnt dann nichts; von Hand bereinigen")
    klone = [dict(e) for e in klone]
    if same and klone[same[0]] == entry:
        action = "unverändert"
    elif same:
        klone[same[0]] = entry
        action = "erneuert"
    else:
        klone.append(entry)
        action = "neu"
    new = _render(klone) if action != "unverändert" else old
    with tempfile.TemporaryDirectory() as probe:
        (pathlib.Path(probe) / gate.PIN_STATE_FILE).write_bytes(new)
        if len(gate._pin_state_entries({"PROOFBUNDLE_GATE_DIR": probe})) != len(klone):
            raise Refused("der neue Inhalt läse sich für das Tor nicht ganz; nichts geschrieben")
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
    print(f"Tor-Verzeichnis: {folder}")
    print(f"Datei: {folder / gate.PIN_STATE_FILE} ({'vorhanden' if p['old'] is not None else 'noch keine'})")
    print(f"Baum: {p['entry']['pfad']}")
    print(f"Hakenordner: {p['entry']['hakenordner']}")
    print("Haken: " + (", ".join(f"{n} {s[:12]}…" for n, s in sorted(p['entry']['haken'].items())) or "keine"))
    print(f"konfig (sha256 von .git/config): {p['entry']['konfig']}")
    print(f"Wirkung: {p['action']}")
    print(json.dumps(p["entry"], indent=2, ensure_ascii=False))
    if p["action"] == "unverändert":
        print("Nichts zu schreiben: der Eintrag steht schon so in der Datei.")
        return 0
    print(f"Freigabe-Wert: {p['freigabe']}")
    print("Schreiben erst nach Prüfung durch den Owner, mit: schreiben --baum <Baum> --freigabe <Freigabe-Wert>")
    return 0


def write(folder: pathlib.Path, tree: str, seal: str) -> int:
    with _Lock(folder):
        p = plan(folder, tree)
        if p["action"] == "unverändert":
            print("Nichts zu schreiben: der Eintrag steht schon so in der Datei.")
            return 0
        if seal != p["freigabe"]:
            print("Freigabe-Wert passt nicht zum Stand von jetzt (Baum oder Datei geändert, oder ein anderer Wert); "
                  "nichts geschrieben. Neu zeigen und neu freigeben.", file=sys.stderr)
            return 3
        saved = _backup(folder, p["old"])
        _write_atomic(folder, gate.PIN_STATE_FILE, p["new"])
        back = (folder / gate.PIN_STATE_FILE).read_bytes()
        if back != p["new"] or len(gate._pin_state_entries({"PROOFBUNDLE_GATE_DIR": str(folder)})) < 1:
            raise Refused("nach dem Schreiben liest sich die Datei nicht wie geplant; mit zurueck den Stand davor holen")
    print(f"Geschrieben ({p['action']}): {folder / gate.PIN_STATE_FILE}")
    print(f"Sicherung davor: {folder / saved}")
    print(f"Rückweg: python3 -I {pathlib.Path(__file__).name} zurueck --tor-verzeichnis {folder} --sicherung {saved}")
    return 0


def _backups(folder: pathlib.Path) -> list[str]:
    return sorted(n for n in os.listdir(folder) if n.startswith(BACKUP) and not n.startswith("."))


def restore(folder: pathlib.Path, name: str | None) -> int:
    with _Lock(folder):
        names = _backups(folder)
        if name is None:
            if not names:
                raise Refused("keine Sicherung im Tor-Verzeichnis")
            name = names[-1]
        if name not in names:
            raise Refused(f"keine Sicherung mit dem Namen {name!r}")
        path = folder / gate.PIN_STATE_FILE
        current = gate._read_regular(str(path), gate.MAX_PIN_STATE_BYTES + 1) if os.path.lexists(path) else None
        if name.endswith(NONE_BEFORE):
            saved = _backup(folder, current)
            if current is not None:
                os.unlink(path)
            print(f"Zurück: keine pin-state.json mehr (wie vor {name}); der Stand davor liegt in {saved}")
            return 0
        raw = gate._read_regular(str(folder / name), gate.MAX_PIN_STATE_BYTES + 1)
        with tempfile.TemporaryDirectory() as probe:
            (pathlib.Path(probe) / gate.PIN_STATE_FILE).write_bytes(raw)
            data = gate.strict_json(raw)
            if len(gate._pin_state_entries({"PROOFBUNDLE_GATE_DIR": probe})) != len(data.get("klone", [])):
                raise Refused(f"die Sicherung {name} liest sich für das Tor nicht ganz; nichts geändert")
        saved = _backup(folder, current)
        _write_atomic(folder, gate.PIN_STATE_FILE, raw)
    print(f"Zurück auf {name}; der Stand davor liegt in {saved}")
    return 0


def listing(folder: pathlib.Path) -> int:
    old, klone = _read_file(folder)
    print(f"Tor-Verzeichnis: {folder}; pin-state.json: {'vorhanden' if old is not None else 'keine'}")
    for e in klone:
        print(f"  {e['pfad']}  Haken {len(e['haken'])}  konfig {e['konfig'][:12]}…")
    for n in _backups(folder):
        print(f"  Sicherung: {n}")
    return 0


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pin des eigenen Klons über die Schleuse (Nachtrag 51); "
                                                 "den Kopftext lesen")
    parser.add_argument("schritt", choices=("zeigen", "schreiben", "liste", "zurueck"))
    parser.add_argument("--baum", help="absoluter Pfad des Arbeitsbaums (zeigen, schreiben)")
    parser.add_argument("--freigabe", help="der Freigabe-Wert, den zeigen gedruckt hat (schreiben)")
    parser.add_argument("--sicherung", help="Name einer Sicherung im Tor-Verzeichnis (zurueck)")
    parser.add_argument("--tor-verzeichnis", dest="tor", help="absoluter Pfad des Tor-Verzeichnisses")
    args = parser.parse_args(argv)
    if args.schritt in ("zeigen", "schreiben") and not args.baum or args.schritt == "schreiben" and not args.freigabe:
        parser.print_usage(sys.stderr)
        return 2
    agent = [n for n in os.environ if n in _AGENT_NAMES or n.startswith("CODEX_")]
    if agent:
        print(f"abgelehnt: die Umgebung ist die eines Agenten ({', '.join(sorted(agent))}); nur ein Mensch pinnt, "
              "über die Schleuse (O46-1)", file=sys.stderr)
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
        print(f"abgelehnt: {why}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
