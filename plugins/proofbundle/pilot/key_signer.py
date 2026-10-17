#!/usr/bin/env python3
"""The key signer of the pilot: the one program that reads the gate key, under an account of its own (D64).

Owner choice O405S-6 of 2026-10-17: deciding and signing run under two accounts. The signer service
(signer_service.py, D58) decides the call again under an account that holds no key and hands this program the
canonical statement it decided; only this program, under a second account, reads the key and signs. It runs neither
git nor any code of the gate, and reads nothing of a repository the agent writes: it reads its configuration, its key
and the request on stdin, writes its journal, and imports nothing that starts a process.

What it checks needs none of that, only the bytes it is handed:

1. the request is `{"schema": KEY_SIGN_REQUEST, "statement": <base64>}`, and the statement is ASCII, at most
   MAX_STATEMENT_BYTES, JSON without a repeated key, and in the canonical form the gate writes (sorted keys, no
   spaces), byte for byte;
2. it is an in-toto Statement v1 of decision-receipt/v0.1 with exactly the fields the gate writes, its one subject is
   `decision:<decisionId>` with the sha256 of the canonical predicate, and the decision's maker is the gate of its
   configuration;
3. decidedAt lies within `window_seconds` before now (and at most CLOCK_SKEW_SECONDS after it).

Then it signs the DSSE PAE of the statement and writes the 64-byte signature in base64 on stdout; else it signs
nothing, exits REFUSED and writes one fixed reason name on stdout. Whether the verdict is the gate's is the decider's
to judge, not this program's: it signs what the decider hands it within the window. Each request is one line of its
journal: the fixed names, the decision's id and the sha256 of the statement it signed or refused, no path, no value.

    key_signer.py --config FILE            sign the statement of the request on stdin, or refuse
    key_signer.py --config FILE --public   write the public key in hex

The configuration is the operator's file, in a folder only the key account reads:
    {"schema": "proofbundle/pilot-key-config/v1", "key_file": <64 hex digits, the Ed25519 private key>,
     "journal": <the key signer's journal>, "gate_id": <the gate's name, as pilot.json names it>,
     "window_seconds": <1 to 300>}
"""
from __future__ import annotations

import argparse
import base64
import binascii
import calendar
import hashlib
import json
import os
import re
import sys
import time

CONFIG_SCHEMA = "proofbundle/pilot-key-config/v1"
CONFIG_KEYS = frozenset({"schema", "key_file", "journal", "gate_id", "window_seconds"})
#: The request the decider hands the key signer: the canonical statement in base64, nothing else (D64).
KEY_SIGN_REQUEST = "proofbundle/pilot-key-request/v1"
#: The exit status of a refusal, as the signer service's; the decider reads the one reason name on stdout.
REFUSED = 3
#: How far a decidedAt may lie after the key signer's own clock: the clocks are the same machine's.
CLOCK_SKEW_SECONDS = 2
MAX_REQUEST_BYTES = 256 * 1024
MAX_STATEMENT_BYTES = 64 * 1024
#: The types of the statement, as the gate writes them (its INTOTO_STATEMENT_TYPE, INTOTO_PAYLOAD_TYPE and
#: DECISION_RECEIPT_TYPE); the key signer reads no file of the gate, so it keeps them itself.
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = b"application/vnd.in-toto+json"
DECISION_RECEIPT_TYPE = "https://b7n0de.com/proofbundle/predicates/decision-receipt/v0.1"
STATEMENT_KEYS = frozenset({"_type", "subject", "predicateType", "predicate"})
PREDICATE_KEYS = frozenset({"schemaVersion", "decisionId", "decisionType", "decidedAt", "decisionMaker", "agent",
                            "principal", "proposedAction", "inputSnapshot", "policyBoundary", "evidenceRefs",
                            "decision", "notChecked", "decisionChangeConditions", "privacy", "validity"})
_DECISION_ID = re.compile(r"a-[0-9a-f]{32}#[1-9][0-9]{0,5}\Z", re.ASCII)
_INSTANT = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{6})Z\Z", re.ASCII)
_HEX_KEY = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_GATE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._@/-]{0,63}\Z", re.ASCII)


class Refused(Exception):
    """No signature: the reason is one fixed name (the class of what the key signer found, never a value)."""


def load_config(path: str) -> dict:
    with open(path, "rb") as handle:
        raw = handle.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise ValueError("too large")
    config = json.loads(raw)
    if not isinstance(config, dict) or set(config) != CONFIG_KEYS or config["schema"] != CONFIG_SCHEMA:
        raise ValueError("not a configuration of the key signer")
    for name in ("key_file", "journal"):
        if not (isinstance(config[name], str) and os.path.isabs(config[name])):
            raise ValueError(f"{name} is not an absolute path")
    if not (isinstance(config["gate_id"], str) and _GATE_ID.fullmatch(config["gate_id"])):
        raise ValueError("gate_id is not a name of the pilot")
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


def canonical(value: object) -> bytes:
    """The form the gate writes a statement in (its _pilot_canonical): sorted keys, no spaces, ASCII only."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _no_repeated_key(pairs: list) -> dict:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("a repeated key")
    return dict(pairs)


def _no_constant(name: str) -> object:
    raise ValueError(f"{name} is no JSON number")


def _instant_ns(text: object) -> int:
    """The nanoseconds of an instant as the gate writes it (six fraction digits, UTC)."""
    match = _INSTANT.fullmatch(text) if isinstance(text, str) else None
    if match is None:
        raise Refused("statement_malformed")
    year, month, day, hour, minute, second, micro = (int(g) for g in match.groups())
    return (calendar.timegm((year, month, day, hour, minute, second)) * 1_000_000 + micro) * 1000


def judge(config: dict, request: object, now_ns: int, note: dict) -> bytes:
    """The statement the key signer signs; Refused where it signs nothing. `note` gathers what the journal names."""
    if not (isinstance(request, dict) and set(request) == {"schema", "statement"}
            and request["schema"] == KEY_SIGN_REQUEST and isinstance(request["statement"], str)):
        raise Refused("request_malformed")
    try:
        body = base64.b64decode(request["statement"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Refused("statement_malformed") from exc
    if len(body) > MAX_STATEMENT_BYTES or not body.isascii():
        raise Refused("statement_malformed")
    note["statementSha256"] = hashlib.sha256(body).hexdigest()
    try:
        statement = json.loads(body, object_pairs_hook=_no_repeated_key, parse_constant=_no_constant)
    except ValueError as exc:
        raise Refused("statement_malformed") from exc
    if canonical(statement) != body:
        raise Refused("statement_not_canonical")
    if not (isinstance(statement, dict) and set(statement) == STATEMENT_KEYS and statement["_type"] == STATEMENT_TYPE
            and statement["predicateType"] == DECISION_RECEIPT_TYPE and isinstance(statement["predicate"], dict)
            and set(statement["predicate"]) == PREDICATE_KEYS):
        raise Refused("statement_type")
    predicate = statement["predicate"]
    decision_id = predicate["decisionId"]
    if not (isinstance(decision_id, str) and _DECISION_ID.fullmatch(decision_id)):
        raise Refused("statement_malformed")
    note["decisionId"] = decision_id
    subject = [{"name": f"decision:{decision_id}", "digest": {"sha256": hashlib.sha256(canonical(predicate)).hexdigest()}}]
    if statement["subject"] != subject:
        raise Refused("subject_differs")
    if predicate["decisionMaker"] != {"id": config["gate_id"]}:
        raise Refused("gate_differs")
    decided_ns = _instant_ns(predicate["decidedAt"])
    if not now_ns - config["window_seconds"] * 1_000_000_000 <= decided_ns <= now_ns + CLOCK_SKEW_SECONDS * 1_000_000_000:
        raise Refused("outside_window")
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
        body = judge(config, request, now_ns, note)
        signature = private_key(config).sign(b"DSSEv1 %d %s %d %s" % (len(PAYLOAD_TYPE), PAYLOAD_TYPE, len(body), body))
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
        pass   # a journal the key signer cannot write never turns a refusal into a signature, nor the reverse
    if signature is None:
        sys.stdout.write(f"{reason}\n")
        return REFUSED
    sys.stdout.write(base64.b64encode(signature).decode("ascii") + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
