#!/usr/bin/env python3
"""Section 3.9 of the 6.0.0 Technical Note: verify the second published v0.2 receipt on PR 185
under the shipped standard policy, once without and once with an expected subject digest.

Run from the repository root (or from an unpacked sdist, which ships receipts/agent_review/):

    $ python3 docs/deposit/6.0.0/example/agent_review_v02_check.py

The second run takes the subject digest from the statement itself, so it proves internal
consistency and policy acceptance, not the binding to a pull request the reader is looking at.
"""
import base64
import json
import pathlib

from proofbundle.agent_review import load_policy, verify_agent_review_any

BASE = pathlib.Path("receipts/agent_review")
env = json.load(open(BASE / "proofbundle_185.r2.receipt.json", encoding="utf-8"))
pub = bytes.fromhex((BASE / "proofbundle_185.r2.publickey.hex").read_text(encoding="utf-8").strip())
subj = json.loads(base64.b64decode(env["payload"]))["subject"][0]
print("subject:", subj["name"], "sha256:", subj["digest"]["sha256"][:16] + "...")

KEYS = ["ok", "crypto_ok", "predicateVersionStatus", "policy_decision", "policy_name", "policy_digest",
        "reason_codes", "advisory_codes", "event_time_status", "observation_time_status",
        "time_consistency_ok", "subject_expectation", "errors"]

print("--- run 1: no expected subject digest supplied")
r = verify_agent_review_any(env, pub, policy=load_policy())
for k in KEYS:
    print(f"{k:<24} {r.get(k)!r}")
print(f"{'limitation_codes':<24} {r['policy_reason'].get('limitation_codes')!r}")
print(f"{'safeForAutomation':<24} {(r.get('automation') or {}).get('safeForAutomation')!r}")

print("--- run 2: expected subject digest supplied (here taken from the statement itself)")
r2 = verify_agent_review_any(env, pub, policy=load_policy(), expected_subject_digest=subj["digest"]["sha256"])
for k in KEYS:
    print(f"{k:<24} {r2.get(k)!r}")
print(f"{'safeForAutomation':<24} {(r2.get('automation') or {}).get('safeForAutomation')!r}")
print(f"{'automationBlockers':<24} {(r2.get('automation') or {}).get('automationBlockers')!r}")
