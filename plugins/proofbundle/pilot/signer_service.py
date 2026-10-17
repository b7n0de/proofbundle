#!/usr/bin/env python3
"""The signer of the pilot as a service of the operator: it decides the call again and signs only its own verdict (D58).

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
   id and instant the proposal names, and signs only where every byte is the same and decidedAt lies within
   `window_seconds` before now (and at most CLOCK_SKEW_SECONDS after it);
4. else signs nothing, exits REFUSED and writes one fixed reason name on stdout.

What the service cannot see gives no signature with its reason, never a guessed one: a working directory its account
does not read (`workdir_unreadable`), a repository git refuses for its account, owned by another account and not named
as safe.directory in its git configuration, where the decision then came out otherwise (`repository_not_safe`), a gate
directory or pilot.json it does not read (`pilot_config_unread`), a decision that came out otherwise because the agent's
session held a value the service does not have (`verdict_differs`).
Each request is one line of the service's journal: the fixed names and numbers, no path, no command, no value.

    signer_service.py --config FILE            decide the request on stdin, sign or refuse
    signer_service.py --config FILE --public   write the public key in hex

The configuration is the operator's file, in a folder only the signer account reads:
    {"schema": "proofbundle/pilot-signer-config/v1", "gate_file": <the service's copy of proofbundle_gate.py, in a
     plugin folder beside its server/>, "records": <the records folder, for pilot_start.json>, "gate_dir": <the gate
     directory the gate reads: mode, rules.json, pilot.json>, "key_file": <64 hex digits, the Ed25519 private key>,
     "journal": <the service's journal>, "environment": {<name>: <value>, ...}, "window_seconds": <1 to 300>}
"""
from __future__ import annotations

import argparse
import base64
import binascii
import calendar
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import time

CONFIG_SCHEMA = "proofbundle/pilot-signer-config/v1"
CONFIG_KEYS = frozenset({"schema", "gate_file", "records", "gate_dir", "key_file", "journal", "environment",
                         "window_seconds"})
#: The exit status of a refusal; the gate reads the one reason name on stdout (its PILOT_SIGNER_REFUSES).
REFUSED = 3
#: How far a decidedAt may lie after the service's own clock: the two clocks are the same machine's.
CLOCK_SKEW_SECONDS = 2
#: The time the service keeps for itself out of the gate's PILOT_SIGNER_SECONDS: loading, building and signing.
MARGIN_SECONDS = 1.0
MAX_REQUEST_BYTES = 4 * 1024 * 1024
_DECISION_ID = re.compile(r"(a-[0-9a-f]{32})#([1-9][0-9]{0,5})\Z", re.ASCII)
_INSTANT = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{6})Z\Z", re.ASCII)
_HEX_KEY = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


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
    if not isinstance(config, dict) or set(config) != CONFIG_KEYS or config["schema"] != CONFIG_SCHEMA:
        raise ValueError("not a configuration of the signer service")
    for name in ("gate_file", "records", "gate_dir", "key_file", "journal"):
        if not (isinstance(config[name], str) and os.path.isabs(config[name])):
            raise ValueError(f"{name} is not an absolute path")
    if not (isinstance(config["environment"], dict) and all(isinstance(k, str) and isinstance(v, str)
                                                            for k, v in config["environment"].items())):
        raise ValueError("environment is not a mapping of names to values")
    if type(config["window_seconds"]) is not int or not 1 <= config["window_seconds"] <= 300:
        raise ValueError("window_seconds is not a whole number from 1 to 300")
    return config


def private_key(config: dict):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    with open(config["key_file"], encoding="ascii") as handle:
        text = handle.read().strip()
    if not _HEX_KEY.fullmatch(text):
        raise ValueError("the key file is not 64 hex digits")
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(text))


def public_hex(config: dict) -> str:
    from cryptography.hazmat.primitives import serialization
    return private_key(config).public_key().public_bytes(serialization.Encoding.Raw,
                                                         serialization.PublicFormat.Raw).hex()


def _instant_ns(text: object) -> int:
    """The nanoseconds of an instant as the gate writes it (_pilot_instant: six fraction digits, UTC)."""
    match = _INSTANT.fullmatch(text) if isinstance(text, str) else None
    if match is None:
        raise Refused("statement_malformed")
    year, month, day, hour, minute, second, micro = (int(g) for g in match.groups())
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


def decide(gate, request: dict, deadline: float) -> tuple[dict, str, str, list[str], str]:
    """(action, key, verdict, reasons, working directory) of the call, as the service's copy of the gate decides it."""
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
        _event, outcome, _actions = gate.tool_outcome(request["event"], request["host"], deadline)
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


def judge(config: dict, request: object, now_ns: int, started: float, note: dict) -> bytes:
    """The canonical statement the service signs; Refused where it signs nothing. `note` gathers what the journal names,
    as far as the service came, a refusal included."""
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
    action, key, verdict, reasons, cwd = decide(gate, request, deadline)
    note.update(surface=action["surface"], verdict=verdict)
    if matched.group(1) != gate._pilot_action_id(pilot, action, key):
        raise Refused("action_differs")
    expected = gate._pilot_statement(pilot, os.environ, action, verdict, reasons, predicate["decisionId"], decided_ns)
    if gate._pilot_canonical(expected) != body:
        # a decision that came out otherwise because git refuses the repository for this account is named so: the
        # service did not see it, it did not judge it otherwise
        raise Refused("repository_not_safe" if _git_refuses(cwd, deadline) else _differs(predicate, expected["predicate"]))
    return body


def journal(config: dict, entry: dict) -> None:
    os.makedirs(os.path.dirname(config["journal"]), exist_ok=True)
    with open(config["journal"], "a", encoding="ascii") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", required=True)
    parser.add_argument("--public", action="store_true")
    args = parser.parse_args(argv)
    config = load_config(args.config)
    if args.public:
        print(public_hex(config))
        return 0
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
        body = judge(config, request, now_ns, started, note)
        kind = b"application/vnd.in-toto+json"
        signature = private_key(config).sign(b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(body), body))
        reason = None
    except Refused as exc:
        reason, signature = str(exc), None
    except Exception:  # noqa: BLE001 - whatever else happens, nothing is signed
        reason, signature = "internal_error", None
    elapsed_ms = int((time.monotonic() - started) * 1000)
    try:
        journal(config, {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "signed": signature is not None,
                         "reason": reason, "elapsedMs": elapsed_ms, **note})
    except OSError:
        pass   # a journal the service cannot write never turns a refusal into a signature, nor the reverse
    if signature is None:
        sys.stdout.write(f"{reason}\n")
        return REFUSED
    sys.stdout.write(base64.b64encode(signature).decode("ascii") + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
