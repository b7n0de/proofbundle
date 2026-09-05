#!/usr/bin/env bash
# Re-capture of the worked example of the 6.0.0 Technical Note (Section 3.1 to 3.7 and 3.9).
#
# The same command sequence as the 5.0.0 revision used, run against ONE named wheel in a fresh
# virtual environment. Every output lands as transcript_*.txt, every exit code in exitcodes.txt,
# nothing is interpreted. Before the deposit this script is run against the SHIPPED 6.0.0 wheel
# from PyPI; the files committed next to it were produced on 2026-09-05 against the wheel built
# from the frozen head 049b3195 and are provisional until then.
#
# Usage:  PB_VENV=/path/to/venv PB_REPO=/path/to/checkout bash recapture_600.sh /path/to/outdir
#   PB_VENV  a virtual environment with `proofbundle[eval]` installed (the wheel under test)
#   PB_REPO  a checkout or unpacked sdist carrying receipts/agent_review/ (for Section 3.9)
#   outdir   is created fresh; the generated private keys (*.seed) stay there and are NOT deposited
set -u
OUT=${1:?outdir}
V=${PB_VENV:?PB_VENV}
PB=${PB_REPO:?PB_REPO}
HERE=$(cd "$(dirname "$0")" && pwd)
rm -rf "$OUT"; mkdir -p "$OUT"; cd "$OUT" || exit 2
export PATH="$V/bin:$PATH"
: > exitcodes.txt
note() { echo "$1 rc=$2" >> exitcodes.txt; }

echo "start $(date -u +%FT%TZ)" > lauf.txt
proofbundle --version >> lauf.txt 2>&1

# 3.1 the claim (declared example timestamp) and the receipt
cp "$HERE/appendix_claim.json" .
proofbundle emit-eval --claim appendix_claim.json --new-key appendix_key.seed --out receipt.json > transcript_emit.txt 2>&1; note emit $?
proofbundle verify receipt.json > transcript_verify.txt 2>&1; note verify $?
proofbundle show-eval receipt.json > transcript_show.txt 2>&1; note show $?

python3 - <<'EOF'
import json
r = json.load(open("receipt.json"))
open("root.b64", "w").write(r["merkle"]["root_b64"])
open("issuer.pub", "w").write(r["signature"]["public_key_b64"])
EOF
ROOT=$(cat root.b64)
# 3.3 pinned root and tree size, then the strict policy that refuses (exit 3)
proofbundle verify receipt.json --expected-root "$ROOT" --expected-tree-size 1 > transcript_verify_pinned.txt 2>&1; note verify_pinned $?
proofbundle policy instantiate strict-eval-authenticated-root-template-v1 --issuer-key issuer.pub --policy-id b7n0de/note-example-v1 --expected-root-file root.b64 --output note_policy.json > transcript_policy.txt 2>&1; note policy $?
proofbundle verify receipt.json --policy note_policy.json > transcript_verify_policy.txt 2>&1; note verify_policy $?

# 3.4 the decision: digest of the receipt bytes, digest of the gate policy, deterministic uuid5
cp "$HERE/gate_policy_example.json" .
python3 - <<'EOF'
import json, hashlib, uuid
rd = hashlib.sha256(open("receipt.json","rb").read()).hexdigest()
pd = hashlib.sha256(open("gate_policy_example.json","rb").read()).hexdigest()
ns = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
dec = {
  "schemaVersion": "0.1.0",
  "decisionId": "urn:uuid:" + str(uuid.uuid5(ns, "b7n0de technical note 6.0.0 decision " + rd)),
  "decisionType": "preActionAuthorization",
  "decidedAt": "2026-09-05T09:00:00Z",
  "decisionMaker": {"id": "https://b7n0de.com/gate/eval-publish/v1", "version": {"proofbundle": "6.0.0"}},
  "agent": {"id": "agent://b7n0de/release-agent", "version": "1"},
  "principal": {"id": "workload://b7n0de/ci"},
  "proposedAction": {"actionType": "tool.call",
                     "target": {"name": "publish-eval-receipt", "uri": "file://artifacts/receipt.json"},
                     "method": "POST", "parametersDigest": {"sha256": rd}},
  "inputSnapshot": [{"name": "eval-receipt", "uri": "urn:proofbundle:input:0",
                     "digest": {"sha256": rd}, "mediaType": "application/json"}],
  "policyBoundary": {"policyEngine": "opa", "policyId": "https://b7n0de.com/policy/eval-publish/v1",
                     "policyDigest": {"sha256": pd}, "decisionPath": "data.b7n0de.evalpublish.allow"},
  "evidenceRefs": [],
  "decision": {"verdict": "ALLOW", "reasonCodes": ["eval.threshold.pass"],
               "humanReadableSummary": "arc-easy accuracy >= 0.80 receipt verified offline (CRYPTO OK, root and tree size pinned); publishing the receipt is allowed.",
               "obligations": [], "allowedScope": []},
  "notChecked": [{"field": "evaluation design", "reason": "out of scope of this gate",
                  "impact": "a well-formed receipt over a poorly designed eval still passes this gate"}],
  "decisionChangeConditions": [{"conditionType": "additionalApproval",
                                "description": "a revoked trust policy or a failed re-verification withdraws this authorization",
                                "requiredEvidenceType": "approvalReceipt"}],
  "privacy": {"rawInputsIncluded": False, "redactionProfile": "https://b7n0de.com/redaction/none/v1", "erased": [], "masked": []}
}
json.dump(dec, open("decision_predicate.json","w"), indent=2); open("decision_predicate.json","a").write("\n")
open("digests.txt","w").write(f"receipt_sha256 {rd}\ngate_policy_sha256 {pd}\n")
EOF
proofbundle decision emit decision_predicate.json --new-key decision_key.seed --out decision_receipt.json > transcript_dec_emit.txt 2>&1; note dec_emit $?
# the DSSE envelope carries no key: --pub is the Ed25519 public key derived from the 32-byte seed
python3 - <<'EOF'
import json, base64, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
seed = open("decision_key.seed","rb").read()
pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
open("decision_pub.txt","w").write(base64.b64encode(pub).decode())
d = json.load(open("decision_receipt.json"))
open("decision_ref.txt","w").write(hashlib.sha256(base64.b64decode(d["payload"])).hexdigest())
EOF
proofbundle decision verify decision_receipt.json --pub "$(cat decision_pub.txt)" > transcript_dec_verify.txt 2>&1; note dec_verify $?

# 3.5 the outcome: decisionRef = sha256(decision payload bytes), responseDigest = sha256(pinned-verify transcript)
python3 - <<'EOF'
import json, hashlib, uuid
rd = hashlib.sha256(open("receipt.json","rb").read()).hexdigest()
ref = open("decision_ref.txt").read().strip()
resp = hashlib.sha256(open("transcript_verify_pinned.txt","rb").read()).hexdigest()
ns = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
out = {
  "schemaVersion": "0.1.0",
  "outcomeId": "urn:uuid:" + str(uuid.uuid5(ns, "b7n0de technical note 6.0.0 outcome " + ref)),
  "decisionRef": {"sha256": ref},
  "executor": {"id": "workload://b7n0de/release-runner", "keyId": ""},
  "requestedActionDigest": {"sha256": rd},
  "actualActionDigest": {"sha256": rd},
  "responseDigest": {"sha256": resp},
  "effectDigest": {"sha256": rd},
  "status": "executed",
  "performedAt": "2026-09-05T09:02:00Z",
  "policyPurpose": "outcome",
  "traceContext": {"traceparent": ""},
  "limitations": ["status=executed attests the executor's signature over these digests, not the external effect itself"]
}
json.dump(out, open("outcome_predicate.json","w"), indent=2); open("outcome_predicate.json","a").write("\n")
open("digests.txt","a").write(f"decision_ref {ref}\nresponse_sha256 {resp}\n")
EOF
proofbundle outcome emit outcome_predicate.json --new-key executor_key.seed --out outcome_receipt.json > transcript_out_emit.txt 2>&1; note out_emit $?
python3 - <<'EOF'
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
seed = open("executor_key.seed","rb").read()
pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
open("executor_pub.txt","w").write(base64.b64encode(pub).decode())
EOF
proofbundle outcome verify outcome_receipt.json --pub "$(cat executor_pub.txt)" --expected-decision-ref "$(cat decision_ref.txt)" --decision-maker-id https://b7n0de.com/gate/eval-publish/v1 > transcript_out_verify.txt 2>&1; note out_verify $?

# 3.6 / 3.7
proofbundle demo > transcript_demo.txt 2>&1; note demo $?
cp "$HERE/independent_check.py" .
python3 independent_check.py receipt.json > transcript_indep.txt 2>&1; note indep $?

# 3.9 the published v0.2 receipt on PR 185 under the shipped standard policy (run from the checkout root)
( cd "$PB" && python3 "$HERE/agent_review_v02_check.py" ) > transcript_agent_review_v02.txt 2>&1; note agent_review_v02 $?

echo "ende $(date -u +%FT%TZ)" >> lauf.txt
sha256sum receipt.json decision_receipt.json outcome_receipt.json appendix_claim.json note_policy.json gate_policy_example.json decision_predicate.json outcome_predicate.json independent_check.py issuer.pub root.b64 transcript_*.txt > SHA256SUMS_recapture.txt
cat exitcodes.txt
