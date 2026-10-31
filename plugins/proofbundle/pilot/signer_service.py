#!/usr/bin/env python3
"""The signer service of the pilot: it decides the call again and has only its own verdict signed (D58, D64).

Owner choice O405-1 of 2026-10-17: the signer runs under an account of the operator, decides from the hook event with
the same gate file and signs only its own verdict. A receipt then shows that the gate's code, in the state the service
saw, decided so, not only that a signer signed.

The gate hands the program pilot.json names a request (the gate's PILOT_SIGN_REQUEST) on stdin: the hook event as the
host gave it and the host at Level 1, the repository, the remote, the URL and git's ref lines at Level 2, and the
statement it proposes. The service:

1. checks its own copy of the gate file against the sha256 that pilot_start.json of the records keeps, and loads it;
2. decides the call with that copy, in its own environment (`environment` of its configuration and the gate directory
   it names), never with a value of the agent's session: at Level 1 with the gate's tool_outcome, at Level 2 with
   pre_push_verdict; it computes the surface, the target, the bytes, the verdict and the reasons itself;
3. builds the statement again from that decision, the pilot's configuration in the gate directory and the decision's
   id and instant the proposal names, and goes on only where every byte is the same and decidedAt lies within
   `window_seconds` before now (and at most CLOCK_SKEW_SECONDS after it);
4. hands those canonical bytes, and nothing else, to the key signer its configuration names (`key_signer`, the program
   key_signer.py under a second account, D64), and passes its signature on only where it verifies with the gate's
   public key of pilot.json;
5. else signs nothing, exits REFUSED and writes one fixed reason name on stdout.

Owner choice O405S-6 of 2026-10-17 (D64): the service holds no key. It runs git, the gate's decision code and the
verifier on repositories the agent writes, so a configuration the agent planted there reaches at most this account;
the key lies with the key signer's account, which runs none of them.

What the service cannot see gives no signature with its reason, never a guessed one: a working directory its account
does not read (`workdir_unreadable`), a repository git refuses for its account, owned by another account and not named
as safe.directory in its git configuration, where the decision then came out otherwise (`repository_not_safe`), a gate
directory or pilot.json it does not read (`pilot_config_unread`), a decision that came out otherwise because the agent's
session held a value the service does not have (`verdict_differs`).
Each request is one line of the service's journal: the fixed names and numbers, no path, no command, no value. No
signature leaves the service without that line (D65): it is written and synced to the disk before the signature is
written on stdout; a journal the service cannot write gives no signature and the name journal_unwritable. A second line
says whether stdout took the signature (`handedOut`). The key signer keeps the same rule for its own journal, and its
journal_unwritable reaches the gate as key_journal_unwritable.

The autonomous answer and the owner's release on a card (D119, follow-up note 49, O43-1): where the operator sets
`"autonomous": true`, the service decides a Level 1 call with the hook's autonomous answer (D85), in the session the
event names, never one of its configuration. The hook writes the use of an owner's release (D111) only after the
service signed ALLOW for it; the service writes no use of the hook's, and keeps its own record of the releases it
signed ALLOW for, freigaben-geehrt.json beside its journal, each once. Remembered release keys are not evicted.
At 4096 remembered releases, a new release gets no signature (release_record_full). The record is written and synced
before the signature leaves; one it cannot read or write gives no signature (release_record_unread,
release_record_unwritable), and a release already honoured gives none either (release_honoured).

    signer_service.py --config FILE            decide the request on stdin, have it signed or refuse

The configuration is the operator's file, in a folder only the deciding account reads:
    {"schema": "proofbundle/pilot-signer-config/v2", "gate_file": <the service's copy of proofbundle_gate.py, in a
     plugin folder beside its server/>, "records": <the records folder, for pilot_start.json>, "gate_dir": <the gate
     directory the gate reads: mode, rules.json, pilot.json>, "key_signer": [<the program, by its absolute path>,
     <its arguments>...], "journal": <the service's journal>, "environment": {<name>: <value>, ...},
     "window_seconds": <1 to 300>, "autonomous": <true or false, optional, false where it is missing>}
A configuration of v1, which named a key file, is no configuration of this service.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import calendar
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time

CONFIG_SCHEMA = "proofbundle/pilot-signer-config/v2"
CONFIG_KEYS = frozenset({"schema", "gate_file", "records", "gate_dir", "key_signer", "journal", "environment",
                         "window_seconds"})
#: The keys a configuration may hold besides CONFIG_KEYS: the operator's setting of the autonomous answer (D119).
CONFIG_OPTIONAL = frozenset({"autonomous"})
#: D119: the releases the service signed ALLOW for, beside its journal, each once: {key: time}.
HONOURED = "freigaben-geehrt.json"
HONOURED_SCHEMA = "proofbundle/pilot-releases-honoured/v1"
MAX_HONOURED = 4096
#: The exit status of a refusal; the gate reads the one reason name on stdout (its PILOT_SIGNER_REFUSES).
REFUSED = 3
#: How far a decidedAt may lie after the service's own clock: the two clocks are the same machine's.
CLOCK_SKEW_SECONDS = 2
#: The time the service keeps for itself out of the gate's PILOT_SIGNER_SECONDS: loading, building and the key signer.
MARGIN_SECONDS = 1.0
#: The time the service keeps after the key signer answered, out of the gate's PILOT_SIGNER_SECONDS: its journal line
#: and its answer (D64). The key signer gets what is left up to it, at least MARGIN_SECONDS - KEY_MARGIN_SECONDS.
KEY_MARGIN_SECONDS = 0.5
#: The request the service hands the key signer (key_signer.py, D64): the canonical statement in base64, nothing else.
KEY_SIGN_REQUEST = "proofbundle/pilot-key-request/v1"
PAYLOAD_TYPE = b"application/vnd.in-toto+json"
MAX_REQUEST_BYTES = 4 * 1024 * 1024
_DECISION_ID = re.compile(r"(a-[0-9a-f]{32})#([1-9][0-9]{0,5})\Z", re.ASCII)
_INSTANT = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{6})Z\Z", re.ASCII)


class Refused(Exception):
    """No signature: the reason is one fixed name (the class of what the service found, never a value)."""


def _read_json(path: str, limit: int = 1024 * 1024) -> object:
    with open(path, "rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("too large")
    return json.loads(raw)


def load_config(path: str) -> dict:
    config = _read_json(path)
    if not isinstance(config, dict) or not CONFIG_KEYS <= set(config) <= CONFIG_KEYS | CONFIG_OPTIONAL or \
            config["schema"] != CONFIG_SCHEMA:
        raise ValueError("not a configuration of the signer service")
    if type(config.get("autonomous", False)) is not bool:
        raise ValueError("autonomous is not true or false")
    for name in ("gate_file", "records", "gate_dir", "journal"):
        if not (isinstance(config[name], str) and os.path.isabs(config[name])):
            raise ValueError(f"{name} is not an absolute path")
    signer = config["key_signer"]
    if not (isinstance(signer, list) and 1 <= len(signer) <= 32 and all(isinstance(w, str) and w for w in signer)
            and os.path.isabs(signer[0]) and not any(ord(c) < 32 for w in signer for c in w)):
        raise ValueError("key_signer is not a program by its absolute path with its arguments")
    if not (isinstance(config["environment"], dict) and all(isinstance(k, str) and isinstance(v, str)
                                                            for k, v in config["environment"].items())):
        raise ValueError("environment is not a mapping of names to values")
    if type(config["window_seconds"]) is not int or not 1 <= config["window_seconds"] <= 300:
        raise ValueError("window_seconds is not a whole number from 1 to 300")
    return config


def _instant_ns(text: object) -> int:
    """The nanoseconds of an instant as the gate writes it (_pilot_instant: six fraction digits, UTC). A date the
    calendar does not have is none (D122): calendar.timegm would read 2026-09-54 as 2026-10-24."""
    match = _INSTANT.fullmatch(text) if isinstance(text, str) else None
    if match is None:
        raise Refused("statement_malformed")
    year, month, day, hour, minute, second, micro = (int(g) for g in match.groups())
    if not (year >= 1 and 1 <= month <= 12 and 1 <= day <= calendar.monthrange(year, month)[1] and hour < 24
            and minute < 60 and second < 60):
        raise Refused("statement_malformed")
    return (calendar.timegm((year, month, day, hour, minute, second)) * 1_000_000 + micro) * 1000


def _gate(config: dict, records: str):
    """The service's own copy of the gate, loaded once its sha256 is the one pilot_start.json keeps (D58)."""
    try:
        start = _read_json(os.path.join(records, "pilot_start.json"))
        kept = start["files"]["gate"]["sha256"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise Refused("start_unread") from exc
    try:
        with open(config["gate_file"], "rb") as handle:
            own = hashlib.sha256(handle.read()).hexdigest()
    except OSError as exc:
        raise Refused("gate_file_unread") from exc
    if own != kept:
        raise Refused("gate_file_differs")
    spec = importlib.util.spec_from_file_location("proofbundle_gate_of_the_signer_service", config["gate_file"])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, start


def _readable(directory: object) -> str:
    if not (isinstance(directory, str) and os.path.isabs(directory)):
        raise Refused("request_malformed")
    try:
        os.listdir(directory)
    except OSError as exc:
        raise Refused("workdir_unreadable") from exc
    return directory


def _git_refuses(directory: str, deadline: float) -> bool:
    """Whether git refuses the repository at `directory` for the service's account: one another account owns that the
    service's git configuration does not name as safe.directory (git's own answer, LC_ALL=C)."""
    try:
        proc = subprocess.run(["git", "-C", directory, "rev-parse", "--git-dir"], capture_output=True, text=True,
                              env={**os.environ, "LC_ALL": "C"}, check=False,
                              timeout=max(0.1, min(2.0, deadline - time.monotonic())))
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode != 0 and "dubious ownership" in proc.stderr


def decide(gate, request: dict, deadline: float, autonomous: bool = False, honoured: dict | None = None,
           held: dict | None = None) -> tuple[dict, str, str, list[str], str]:
    """(action, key, verdict, reasons, working directory) of the call, as the service's copy of the gate decides it.
    With autonomous, the operator's setting, a Level 1 call gets the hook's autonomous answer in the session its event
    names (D119); an owner's release the service signed ALLOW for before (`honoured`) frees nothing, and one that frees
    the call is put into `held`, for the record the service writes once it has the signature."""
    if request.get("level") == 1:
        if set(request) != {"schema", "level", "host", "event", "statement"} or request["host"] not in gate.HOSTS \
                or not isinstance(request["event"], str):
            raise Refused("request_malformed")
        try:
            event = gate.strict_json(request["event"])
        except ValueError as exc:
            raise Refused("request_malformed") from exc
        cwd = event.get("cwd") if isinstance(event, dict) else None
        os.chdir(_readable(cwd))
        session = event.get("session_id") if isinstance(event, dict) else None
        os.environ.pop("CLAUDE_CODE_SESSION_ID", None)   # the session of a decision is its event's, never a configured one
        if isinstance(session, str) and gate._SESSION_ID.fullmatch(session):
            os.environ["CLAUDE_CODE_SESSION_ID"] = session
        _event, outcome, _actions = gate.tool_outcome(request["event"], request["host"], deadline, autonomous=autonomous)
        release = getattr(outcome, "release", None)
        if release is not None and _release_key(release["freigabe"]) in (honoured or {}):
            outcome = release["ohne"]   # D119: a release the service signed ALLOW for before frees nothing again
        elif release is not None and held is not None:
            held["release"] = release["freigabe"]
        verdict = gate._pilot_tool_verdict(outcome, request["host"]) if outcome is not None else None
        action, key = gate._pilot_tool_action(event)
        reasons = gate._pilot_reasons([v.reason_id for v in outcome.verdicts]) if outcome is not None else []
    elif request.get("level") == 2:
        if set(request) != {"schema", "level", "cwd", "remote", "url", "lines", "line", "statement"}:
            raise Refused("request_malformed")
        lines = request["lines"]
        if not (isinstance(lines, list) and all(isinstance(x, list) and len(x) == 4 and all(isinstance(w, str) for w in x)
                                                for x in lines)) or type(request["line"]) is not int \
                or not 0 <= request["line"] < len(lines) or not isinstance(request["url"], (str, type(None))) \
                or not isinstance(request["remote"], (str, type(None))):
            raise Refused("request_malformed")
        cwd = _readable(request["cwd"])
        os.chdir(cwd)
        lines = [tuple(x) for x in lines]
        try:
            pushed = gate.pre_push_verdict(cwd, lines, deadline, request["remote"], request["url"])
            decision, reasons = pushed.decision, [pushed.reason_id]
        except gate.GateError:
            decision, reasons = "deny", ["pre_push_gate_error"]
        verdict = None if decision == "inactive" else ("ALLOW" if decision == "pass" else "DENY")
        action, key = gate._pilot_push_actions(request["url"], lines)[request["line"]]
        reasons = gate._pilot_reasons(reasons)
    else:
        raise Refused("request_malformed")
    if time.monotonic() >= deadline:
        raise Refused("out_of_time")
    if action is None:
        raise Refused("not_a_pilot_write")
    if verdict is None:
        raise Refused("no_receipt_for_this_decision")
    return action, key, verdict, reasons, cwd


def _differs(proposed: dict, expected: dict) -> str:
    """The class of the first difference between the proposed and the service's own predicate."""
    for field, reason in (("decision", "verdict_differs"), ("proposedAction", "action_differs"),
                          ("policyBoundary", "policy_differs")):
        if proposed.get(field) != expected.get(field):
            if field == "decision" and (proposed.get(field) or {}).get("verdict") == expected[field]["verdict"]:
                return "reasons_differ"
            return reason
    return "statement_differs"


def judge(config: dict, request: object, now_ns: int, started: float, note: dict,
          held: dict | None = None) -> tuple[bytes, str, float]:
    """The canonical statement the service has signed, the gate's public key of pilot.json and the instant (monotonic)
    by which the service answers; Refused where it signs nothing. `note` gathers what the journal names, as far as the
    service came, a refusal included; `held` gets the owner's release the decision used, if any (D119)."""
    if not isinstance(request, dict) or not isinstance(request.get("statement"), str):
        raise Refused("request_malformed")
    note["level"] = request.get("level") if request.get("level") in (1, 2) else None
    gate, start = _gate(config, config["records"])
    if request.get("schema") != gate.PILOT_SIGN_REQUEST:
        raise Refused("request_malformed")
    os.environ.clear()
    os.environ.update({**config["environment"], "PROOFBUNDLE_GATE_DIR": config["gate_dir"]})
    pilot = gate._pilot_config(os.environ)
    if pilot is None:
        raise Refused("pilot_config_unread")
    if (pilot["gate_id"], pilot["observer_id"]) != (start.get("gate_id"), start.get("observer_id")):
        raise Refused("ids_differ")
    try:
        body = base64.b64decode(request["statement"], validate=True)
        statement = gate.strict_json(body)
        predicate = statement["predicate"]
        matched = _DECISION_ID.fullmatch(predicate["decisionId"])
    except (binascii.Error, ValueError, KeyError, TypeError) as exc:
        raise Refused("statement_malformed") from exc
    if matched is None:
        raise Refused("statement_malformed")
    note["decisionId"] = predicate["decisionId"]
    decided_ns = _instant_ns(predicate.get("decidedAt"))
    if not now_ns - config["window_seconds"] * 1_000_000_000 <= decided_ns <= now_ns + CLOCK_SKEW_SECONDS * 1_000_000_000:
        raise Refused("outside_window")
    deadline = started + gate.PILOT_SIGNER_SECONDS - MARGIN_SECONDS
    autonomous = config.get("autonomous") is True
    action, key, verdict, reasons, cwd = decide(gate, request, deadline, autonomous,
                                                honoured(config) if autonomous else {}, held)
    note.update(surface=action["surface"], verdict=verdict)
    if matched.group(1) != gate._pilot_action_id(pilot, action, key):
        raise Refused("action_differs")
    expected = gate._pilot_statement(pilot, os.environ, action, verdict, reasons, predicate["decisionId"], decided_ns)
    if gate._pilot_canonical(expected) != body:
        # a decision that came out otherwise because git refuses the repository for this account is named so: the
        # service did not see it, it did not judge it otherwise
        raise Refused("repository_not_safe" if _git_refuses(cwd, deadline) else _differs(predicate, expected["predicate"]))
    return body, pilot["public_key"], started + gate.PILOT_SIGNER_SECONDS - KEY_MARGIN_SECONDS


def signed_by_the_key_signer(config: dict, body: bytes, public: str, end: float) -> bytes:
    """The signature the key signer makes over the DSSE PAE of `body` (D64). The service holds no key: it hands the
    canonical bytes, and nothing else, to the program `key_signer` names, a second account through sudo, from the root
    folder and with no value of its own environment, and passes the answer on only where it verifies with `public`,
    the gate's public key of pilot.json."""
    request = json.dumps({"schema": KEY_SIGN_REQUEST, "statement": base64.b64encode(body).decode("ascii")},
                         sort_keys=True).encode("ascii")
    remaining = end - time.monotonic()
    if remaining <= 0:
        raise Refused("out_of_time")
    try:
        proc = subprocess.run(config["key_signer"], input=request, capture_output=True, cwd="/",
                              env={"PATH": os.defpath, "LANG": "C"}, timeout=remaining, check=False)
    except subprocess.TimeoutExpired as exc:
        raise Refused("key_signer_timeout") from exc
    except (OSError, ValueError) as exc:
        raise Refused("key_signer_failed") from exc
    answer = proc.stdout.decode("ascii", "replace").strip()
    if proc.returncode == REFUSED and re.fullmatch(r"[a-z_]{1,40}", answer):
        raise Refused(f"key_{answer}")   # the key signer's own name: key_outside_window, key_gate_differs, ...
    if proc.returncode != 0 or len(proc.stdout) > 256:
        raise Refused("key_signer_failed")
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        signature = base64.b64decode(answer, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Refused("key_signer_answer") from exc
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(
            signature, b"DSSEv1 %d %s %d %s" % (len(PAYLOAD_TYPE), PAYLOAD_TYPE, len(body), body))
    except (ValueError, InvalidSignature) as exc:
        raise Refused("key_differs") from exc   # signed with another key than the gate key pilot.json names
    return signature


def _release_key(release: dict) -> str:
    """D119: an owner's release by its card, the sha256 of its line and its session, as the gate keys its use."""
    return f"{release['karte']}:{release['sha256']}:{release['sitzung']}"


def honoured(config: dict) -> dict:
    """D119: the releases the service signed ALLOW for, {key: time}; Refused where the record does not read whole."""
    try:
        data = _read_json(os.path.join(os.path.dirname(config["journal"]), HONOURED))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise Refused("release_record_unread") from exc
    if not isinstance(data, dict) or data.get("schema") != HONOURED_SCHEMA or not isinstance(data.get("geehrt"), dict):
        raise Refused("release_record_unread")
    return dict(data["geehrt"])


def honour(config: dict, release: dict) -> None:
    """D119: write that the service signed ALLOW for this release, under a lock and synced to the disk, before the
    signature leaves; Refused where the record names it already (a second request meanwhile), holds MAX_HONOURED
    releases (release_record_full, no key is evicted) or cannot be written."""
    folder = os.path.dirname(config["journal"])
    try:
        os.makedirs(folder, exist_ok=True)
        lock = os.open(os.path.join(folder, HONOURED + ".lock"),
                       os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            done = honoured(config)
            if _release_key(release) in done:
                raise Refused("release_honoured")
            if len(done) >= MAX_HONOURED:
                raise Refused("release_record_full")
            done[_release_key(release)] = _instant()
            fd, tmp = tempfile.mkstemp(prefix=".freigaben-geehrt-", dir=folder)
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                json.dump({"schema": HONOURED_SCHEMA, "geehrt": done}, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, os.path.join(folder, HONOURED))
            directory = os.open(folder, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            os.close(lock)
    except OSError as exc:
        raise Refused("release_record_unwritable") from exc


def journal(config: dict, entry: dict) -> None:
    """Append one line to the journal and sync it to the disk before returning (D65); OSError where it cannot. A line
    an earlier write left without its end is closed first, so it stands alone and the next line reads."""
    path = config["journal"]
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    data = (json.dumps(entry, sort_keys=True) + "\n").encode("ascii")
    created = not os.path.lexists(path)
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        size = os.fstat(fd).st_size
        if size and os.pread(fd, 1, size - 1) != b"\n":
            data = b"\n" + data
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    if created:
        directory = os.open(folder, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _instant() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    config = load_config(args.config)
    started, now_ns = time.monotonic(), time.time_ns()
    note: dict = {}
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise Refused("request_malformed")
        try:
            request = json.loads(raw)
        except ValueError as exc:
            raise Refused("request_malformed") from exc
        held: dict = {}
        body, public, end = judge(config, request, now_ns, started, note, held)
        signature = signed_by_the_key_signer(config, body, public, end)
        if held.get("release") is not None:
            honour(config, held["release"])   # D119: once per release, before the signature leaves
        reason = None
    except Refused as exc:
        reason, signature = str(exc), None
    except Exception:  # noqa: BLE001 - whatever else happens, nothing is signed
        reason, signature = "internal_error", None
    elapsed_ms = int((time.monotonic() - started) * 1000)
    if signature is not None:
        try:
            journal(config, {"at": _instant(), "signed": True, "reason": None, "elapsedMs": elapsed_ms, **note})
        except OSError:
            # no line, no signature (D65): the signature is dropped before a byte of it is written
            signature, reason = None, "journal_unwritable"
    if signature is None:
        try:
            journal(config, {"at": _instant(), "signed": False, "reason": reason, "elapsedMs": elapsed_ms, **note})
        except OSError:
            pass   # a refusal the journal cannot take stays a refusal
        sys.stdout.write(f"{reason}\n")
        return REFUSED
    try:
        sys.stdout.write(base64.b64encode(signature).decode("ascii") + "\n")
        sys.stdout.flush()
        handed_out = True
    except OSError:
        handed_out = False
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())   # what stdout keeps of it is never written
    try:
        journal(config, {"at": _instant(), "handedOut": handed_out, "decisionId": note.get("decisionId")})
    except OSError:
        pass   # the signed line stands; without this one it reads as unconfirmed
    return 0 if handed_out else REFUSED


if __name__ == "__main__":
    sys.exit(main())
