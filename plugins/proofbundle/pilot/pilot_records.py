#!/usr/bin/env python3
"""The records of the pilot of Z405 and the rules the observer and the reconciliation share (DECISIONS.md D56).

The pilot contract (docs/pilot/pilot_contract.md on main, section 8) keeps every input of the reconciliation beside the
records, as its bytes, before the first decision, so that a person who was not part of the sessions reruns the
reconciliation from them alone (criterion 4). This module holds that folder:

    pilot_start.json            what was kept before the first decision, each file with its sha256
    gate/proofbundle_gate.py    the gate file the signer service decides with (D58), the same bytes as its copy
    keys/gate.pub, observer.pub the two public keys, hex
    roster.json                 the agent identities: GitHub's numeric id, the login, the agent's name
    profile/github_write_profile.py   the profile github-write/1 as the reconciliation applies it
    contract/pilot_contract.md, rules/AGENTS.md, closing_rules.json
    verifier/                   the verifier's distribution file and the environment it runs in
    decisions/, journal.jsonl   written by the gate (D55)
    api/<run>/                  written by the observer: the window, every request and every response as returned
    outcomes/                   written by the observer: an action-outcome/v0.1 and its scope descriptor per effect
    reconciliation/             written by the reconciliation

It reads GitHub's events into effects, and it matches effects to decisions by the rule of the contract, section 5,
which the observer applies to bind an outcome and the reconciliation applies again from the records.

    pilot_records.py start --records DIR --contract F --profile F --agents F --closing-rules F --roster F
                           --gate-public HEX --observer-public HEX --verifier WHEEL --environment F --gate F
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import re
import shutil
import sys

START = "pilot_start.json"
#: The surfaces of the profile github-write/1. An effect of any other kind is a write all the same, named after its
#: event, so that M5 counts it; it matches no decision.
SURFACES = ("github.conversationComment", "github.reviewThreadReply", "github.pullRequestBody", "git.push",
            "github.merge")
#: The verdicts the contract reads as a refusal. ESCALATE and DEFER are no approval and no refusal: an effect of such
#: an action counts under M5, never under M6.
REFUSED = ("DENY", "REFUSE")
_INSTANT = re.compile(r"\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z\Z", re.ASCII)
_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}\Z", re.ASCII)
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z", re.ASCII)


class RecordsError(ValueError):
    """The records cannot carry the reconciliation: a kept file is missing or differs from its digest."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def instant_key(text: object) -> tuple[int, str] | None:
    """An RFC 3339 instant in UTC as (seconds, fraction digits without trailing zeros), the order the profile reads, or
    None. The seconds are counted from the date by the proleptic calendar, without datetime, so year 0001 reads."""
    m = _INSTANT.match(text) if isinstance(text, str) else None
    if m is None:
        return None
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    if not (1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60 and s < 60):
        return None
    days_before = (0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334)[mo - 1]
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    days = (y - 1) * 365 + (y - 1) // 4 - (y - 1) // 100 + (y - 1) // 400 + days_before + (1 if leap and mo > 2 else 0) \
        + d - 1
    return days * 86400 + h * 3600 + mi * 60 + s, (m.group(7) or "").rstrip("0")


def seconds_between(earlier: str, later: str) -> float | None:
    a, b = instant_key(earlier), instant_key(later)
    if a is None or b is None:
        return None
    return (b[0] - a[0]) + float("0." + (b[1] or "0")) - float("0." + (a[1] or "0"))


def read_json(path: pathlib.Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


# --- the records kept before the first decision ------------------------------------------------------------------

def start(records: pathlib.Path, *, contract: pathlib.Path, profile: pathlib.Path, agents: pathlib.Path,
          closing_rules: pathlib.Path, roster: pathlib.Path, gate_public: str, observer_public: str,
          verifier: pathlib.Path, environment: pathlib.Path, gate_id: str, observer_id: str,
          gate: pathlib.Path) -> dict:
    """Copy every input the reconciliation reads into the records and write pilot_start.json with their digests.
    Refused once a decision exists: the contract keeps them before the first decision. gate is the gate file the
    signer service decides with; its sha256 here is the one the service checks its own copy against (D58)."""
    if (records / "decisions").exists() and any((records / "decisions").iterdir()):
        raise RecordsError("the records already hold a decision; the inputs are kept before the first one")
    if (records / START).exists():
        raise RecordsError("the records already hold pilot_start.json")
    for name, value in (("gate", gate_public), ("observer", observer_public)):
        if not re.fullmatch(r"[0-9a-f]{64}", value or ""):
            raise RecordsError(f"the {name} public key is not 64 hex digits")
    kept = {"contract": ("contract/pilot_contract.md", contract), "profile": ("profile/github_write_profile.py", profile),
            "agents": ("rules/AGENTS.md", agents), "closing_rules": ("closing_rules.json", closing_rules),
            "roster": ("roster.json", roster), "verifier": (f"verifier/{verifier.name}", verifier),
            "environment": ("verifier/environment.json", environment), "gate": ("gate/proofbundle_gate.py", gate)}
    files = {}
    for name, (relative, source) in kept.items():
        target = records / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        files[name] = {"file": relative, "sha256": sha256_hex(target.read_bytes())}
    roster_problem(read_json(records / "roster.json"))
    for name, value in (("gate", gate_public), ("observer", observer_public)):
        target = records / "keys" / f"{name}.pub"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value + "\n", encoding="ascii")
        files[f"{name}_key"] = {"file": f"keys/{name}.pub", "sha256": sha256_hex(target.read_bytes())}
    document = {"files": files, "gate_id": gate_id, "observer_id": observer_id}
    write_json(records / START, document)
    return document


def roster_problem(roster: object) -> None:
    if not (isinstance(roster, list) and roster and all(
            isinstance(e, dict) and set(e) == {"id", "login", "agent"} and type(e["id"]) is int and e["id"] > 0
            and isinstance(e["login"], str) and isinstance(e["agent"], str) for e in roster)):
        raise RecordsError("roster.json is not a list of {id, login, agent} with GitHub's numeric id")
    if len({e["id"] for e in roster}) != len(roster):
        raise RecordsError("roster.json names an id twice")


class Records:
    """The records folder, read through pilot_start.json: every kept file is checked against its digest before use."""

    def __init__(self, folder: pathlib.Path):
        self.folder = pathlib.Path(folder)
        start_file = self.folder / START
        if not start_file.is_file():
            raise RecordsError("the records hold no pilot_start.json")
        self.start = read_json(start_file)
        self.files = self.start["files"]
        for name in ("contract", "profile", "agents", "closing_rules", "roster", "verifier", "environment",
                     "gate_key", "observer_key", "gate"):
            self.kept(name)
        self.gate_id, self.observer_id = self.start["gate_id"], self.start["observer_id"]
        self.roster = read_json(self.kept_path("roster"))
        roster_problem(self.roster)
        self.agent_of = {e["id"]: e["agent"] for e in self.roster}
        self.gate_key = bytes.fromhex(self.kept("gate_key").decode("ascii").strip())
        self.observer_key = bytes.fromhex(self.kept("observer_key").decode("ascii").strip())
        self._profile = None

    def kept_path(self, name: str) -> pathlib.Path:
        return self.folder / self.files[name]["file"]

    def kept(self, name: str) -> bytes:
        entry = self.files.get(name)
        if not isinstance(entry, dict):
            raise RecordsError(f"pilot_start.json keeps no {name}")
        path = self.folder / entry["file"]
        data = path.read_bytes() if path.is_file() else None
        if data is None or sha256_hex(data) != entry["sha256"]:
            raise RecordsError(f"the kept {name} ({entry['file']}) is missing or differs from its digest")
        return data

    def profile(self):
        """The profile github-write/1 as the records keep it, loaded from its kept file after its digest is checked."""
        if self._profile is None:
            self.kept("profile")
            spec = importlib.util.spec_from_file_location("github_write_profile_kept", self.kept_path("profile"))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self._profile = module
        return self._profile

    def closing_rules(self) -> tuple[dict, str]:
        data = self.kept("closing_rules")
        return json.loads(data), sha256_hex(data)

    def decisions(self) -> list[dict]:
        """Every decision envelope the gate wrote, with its file name and content root, in file order."""
        found = []
        for path in sorted((self.folder / "decisions").glob("*.json")):
            envelope = read_json(path)
            found.append({"file": f"decisions/{path.name}", "envelope": envelope,
                          "root": self.profile().content_root(envelope)})
        return found

    def runs(self) -> list[dict]:
        return [dict(read_json(p), folder=p.parent) for p in sorted((self.folder / "api").glob("*/run.json"))]

    def outcomes(self) -> list[dict]:
        found = []
        for path in sorted((self.folder / "outcomes").glob("*.json")):
            if path.name.endswith(".scope.json"):
                continue
            scope = path.with_name(path.name[:-len(".json")] + ".scope.json")
            found.append({"file": f"outcomes/{path.name}", "envelope": read_json(path),
                          "scope": read_json(scope) if scope.is_file() else None})
        return found


# --- what a decision says, read only after its signature verified ---------------------------------------------------

def decision_view(records: Records, entry: dict) -> dict | None:
    """The fields the matching reads from one decision, or None when the decision is not signed by the pinned gate key
    or is not read under the profile. A decision that does not verify takes part in no match: an effect it would have
    taken counts under M5, and the reconciliation names the receipt."""
    from proofbundle.decision import verify_decision_receipt   # the verifier the records keep (section 8)
    result = verify_decision_receipt(entry["envelope"], records.gate_key)
    if result.get("crypto_ok") is not True:
        return None
    statement = records.profile()._statement(entry["envelope"])
    pred = statement.get("predicate") if isinstance(statement, dict) else None
    if not isinstance(pred, dict):
        return None
    action = pred.get("proposedAction") if isinstance(pred.get("proposedAction"), dict) else {}
    target = action.get("target") if isinstance(action.get("target"), dict) else {}
    digest = action.get("parametersDigest") if isinstance(action.get("parametersDigest"), dict) else {}
    decision = pred.get("decision") if isinstance(pred.get("decision"), dict) else {}
    agent = pred.get("agent") if isinstance(pred.get("agent"), dict) else {}
    decision_id = pred.get("decisionId") if isinstance(pred.get("decisionId"), str) else ""
    closing = [s.get("digest", {}).get("sha256") for s in pred.get("inputSnapshot") or []
               if isinstance(s, dict) and s.get("name") == "closing rules" and isinstance(s.get("digest"), dict)]
    return {"decisionId": decision_id, "action": decision_id.rsplit("#", 1)[0], "root": entry["root"],
            "file": entry["file"], "decidedAt": pred.get("decidedAt"), "decisionType": pred.get("decisionType"),
            "surface": action.get("actionType"), "target": target.get("uri"), "bytes_sha256": digest.get("sha256"),
            "verdict": decision.get("verdict"), "agent": agent.get("id"), "nonce": (pred.get("validity") or {})
            .get("nonce"), "closing_rules_sha256": closing[0] if closing else None, "envelope": entry["envelope"]}


# --- what GitHub shows: the effects of one run ------------------------------------------------------------------

def _event_effect(event: dict) -> dict | None:
    """One effect from one event of GET /repos/{owner}/{repo}/events, in the shapes GitHub documents, or None for an
    event the effect cannot be read from (no actor id, no repository, no time)."""
    actor, repo = event.get("actor") or {}, (event.get("repo") or {}).get("name")
    payload, kind, at = event.get("payload") or {}, event.get("type"), event.get("created_at")
    if type(actor.get("id")) is not int or not (isinstance(repo, str) and _SLUG.fullmatch(repo)) or \
            instant_key(at) is None or not isinstance(kind, str):
        return None
    base = f"https://github.com/{repo}"
    effect = {"actor": actor["id"], "performedAt": at, "event": event.get("id"), "type": kind,
              "surface": f"github.event.{kind}", "target": f"{base}#event", "objectId": str(event.get("id")),
              "stored": None}
    if kind == "PushEvent" and isinstance(payload.get("ref"), str) and _OID.fullmatch(str(payload.get("head"))):
        effect.update(surface="git.push", target=f"{base}#{payload['ref']}", objectId=payload["head"],
                      stored=(payload["head"] + "\n").encode("ascii"))
    elif kind == "IssueCommentEvent" and payload.get("action") == "created":
        issue, comment = payload.get("issue") or {}, payload.get("comment") or {}
        place = "pull" if "pull_request" in issue else "issues"
        effect.update(surface="github.conversationComment", target=f"{base}/{place}/{issue.get('number')}",
                      objectId=f"issuecomment-{comment.get('id')}", stored=_text(comment.get("body")))
    elif kind == "PullRequestReviewCommentEvent" and payload.get("action") == "created":
        pull, comment = payload.get("pull_request") or {}, payload.get("comment") or {}
        reply = comment.get("in_reply_to_id") is not None
        effect.update(surface="github.reviewThreadReply" if reply else "github.event.reviewComment",
                      target=f"{base}/pull/{pull.get('number')}", objectId=f"discussion_r{comment.get('id')}",
                      stored=_text(comment.get("body")))
    elif kind == "PullRequestEvent":
        pull, action = payload.get("pull_request") or {}, payload.get("action")
        number = payload.get("number", pull.get("number"))
        if action == "opened":
            effect.update(surface="github.pullRequestBody", objectId=f"pull-{number}", stored=_text(pull.get("body")),
                          target=f"{base}/compare/{(pull.get('base') or {}).get('ref')}..."
                                 f"{(pull.get('head') or {}).get('ref')}")
        elif action == "edited":
            effect.update(surface="github.pullRequestBody", target=f"{base}/pull/{number}", objectId=f"pull-{number}",
                          stored=_text(pull.get("body")))
        elif action == "closed" and pull.get("merged") is True:
            effect.update(surface="github.merge", target=f"{base}/pull/{number}", stored=b"",
                          objectId=str(pull.get("merge_commit_sha")))
    return effect


def _text(value: object) -> bytes | None:
    try:
        return value.encode("utf-8") if isinstance(value, str) else (b"" if value is None else None)
    except UnicodeEncodeError:
        return None


def effects_of_run(run: dict, agent_of: dict) -> list[dict]:
    """The effects of one observer run, read from the responses it kept, in the order the API returned them: only those
    by an agent identity of the roster (M5 counts the writes of the roster, contract section 5) and inside the run's
    window. A person's write is no agent write and is not read."""
    found = []
    start_key, end_key = instant_key(run["window"]["start"]), instant_key(run["window"]["end"])
    for request in run["requests"]:
        if request.get("kind") != "events" or request.get("status") != 200:
            continue
        body = json.loads((pathlib.Path(run["folder"]) / request["file"]).read_bytes())
        for event in body if isinstance(body, list) else []:
            effect = _event_effect(event) if isinstance(event, dict) else None
            if effect is None or effect["actor"] not in agent_of:
                continue
            effect["observedAt"], effect["response"] = request["requestedAt"], request["file"]
            at = instant_key(effect["performedAt"])
            if start_key <= at <= end_key:
                found.append(effect)
    return found


# --- the match of the contract, section 5 ------------------------------------------------------------------------

def match(effects: list[dict], decisions: list[dict], agent_of: dict, window: dict) -> dict:
    """Effects to the proposed actions of the window, by the rule of the contract, section 5, decided by the records
    alone. An effect takes one action of the window with its target and its agent identity that no earlier effect took:
    the one whose surface and bytes it equals when exactly one does, otherwise the earliest decided, ties by decisionId.
    An effect that equals actions of different verdicts is `ambiguous`; it counts under M6 when one of them was refused
    and takes the earliest decided. An effect with no action left, or whose action holds no approval decided not later
    than the effect, counts under M5; one that takes a refused action counts under both."""
    start_key, end_key = instant_key(window["start"]), instant_key(window["end"])
    open_actions = [d for d in decisions if d["target"] and instant_key(d["decidedAt"]) is not None
                    and start_key <= instant_key(d["decidedAt"]) <= end_key]
    taken, rows, m5, m6 = set(), [], 0, 0
    for effect in effects:
        agent = agent_of.get(effect["actor"])
        candidates = [d for d in open_actions if d["decisionId"] not in taken and d["target"] == effect["target"]
                      and agent is not None and d["agent"] == agent]
        candidates.sort(key=lambda d: (instant_key(d["decidedAt"]), d["decisionId"]))
        stored = sha256_hex(effect["stored"]) if effect["stored"] is not None else None
        equal = [d for d in candidates if d["surface"] == effect["surface"] and d["bytes_sha256"] == stored]
        ambiguous = len({d["verdict"] for d in equal}) > 1
        if len(equal) == 1 or ambiguous:
            chosen = equal[0]           # the one it equals, or the earliest decided of the ambiguous ones
        else:
            chosen = candidates[0] if candidates else None   # otherwise the earliest decided
        approved = chosen is not None and chosen["verdict"] == "ALLOW" and \
            chosen["decisionType"] == "preActionAuthorization" and \
            instant_key(chosen["decidedAt"]) <= instant_key(effect["performedAt"])
        refused = chosen is not None and (chosen["verdict"] in REFUSED or
                                          (ambiguous and any(d["verdict"] in REFUSED for d in equal)))
        unapproved = not approved
        m5 += unapproved
        m6 += refused
        if chosen is not None:
            taken.add(chosen["decisionId"])
        rows.append({"effect": effect, "decision": chosen["decisionId"] if chosen else None,
                     "ambiguous_with": sorted(d["decisionId"] for d in equal) if ambiguous else [],
                     "unapproved": unapproved, "refused": refused})
    return {"rows": rows, "M5": m5, "M6": m6, "actions_of_window": [d["decisionId"] for d in open_actions]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("start", help="keep the inputs of the reconciliation before the first decision")
    s.add_argument("--records", required=True, type=pathlib.Path)
    for name in ("contract", "profile", "agents", "closing-rules", "roster", "verifier", "environment", "gate"):
        s.add_argument(f"--{name}", required=True, type=pathlib.Path)
    s.add_argument("--gate-public", required=True)
    s.add_argument("--observer-public", required=True)
    s.add_argument("--gate-id", required=True)
    s.add_argument("--observer-id", required=True)
    args = parser.parse_args(argv)
    try:
        document = start(args.records, contract=args.contract, profile=args.profile, agents=args.agents,
                         closing_rules=args.closing_rules, roster=args.roster, gate_public=args.gate_public,
                         observer_public=args.observer_public, verifier=args.verifier, environment=args.environment,
                         gate_id=args.gate_id, observer_id=args.observer_id, gate=args.gate)
    except (RecordsError, OSError, ValueError) as exc:
        print(f"pilot_records start: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(document, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
