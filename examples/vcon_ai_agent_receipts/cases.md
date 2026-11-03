# Cases

Written by measure_cases.py. Each case is checked twice with check_example.py; "same" means the two
reports are byte for byte equal. "receipts unchanged" means the decision receipts in the vCon and the
external one are the bytes of the unchanged example, which `proofbundle decision verify` accepts there.

| Case | Change | Expected | Result | Same | Receipts unchanged | As expected | First failure |
|---|---|---|---|---|---|---|---|
| P0 | the example, unchanged | PASS | PASS | yes | yes | yes |  |
| P1 | the example, checked with --action-bytes none | PASS | PASS | yes | yes | yes |  |
| P2 | the example in its RS256 form | PASS | PASS | yes | yes | yes |  |
| F01 | wrong content_hash on the external DENY receipt | FAIL A1 | FAIL A1 | yes | yes | yes | attachments[2] (decision receipt), content_hash sha512 does not match |
| F02 | receipt for another tool call: the input of the call is another command | FAIL R2 | FAIL R2 | yes | yes | yes | attachments[1] (decision receipt) dec-0001, SHA-256 of the RFC 8785 form of events[1].input is not parametersDigest |
| F03 | approval expired at the time of the tool call | FAIL R4b | FAIL R4b | yes | yes | yes | attachments[1] (decision receipt) dec-0001, approval expired at the time of the tool call: time 2026-10-15T09:16:00.000Z, validUntil 2026-10-15T09:15:04Z |
| F04 | DENY followed by a successful tool result | FAIL C2 | FAIL C2 | yes | yes | yes | dec-0002, tool call toolu_example_02, tool result 00000000-0000-4000-8000-000000000009 after DENY counts as executed |
| F05 | vCon changed after it was cited, signed again in both forms | FAIL Z2 | FAIL Z2 | yes | yes | yes | citing receipt dec-0003, SHA-256 of the JWS payload is not the digest in inputSnapshot |
| F06 | attachment without a matching receipt (the ALLOW receipt removed) | FAIL C3 | FAIL C3 | yes | no | yes | attachments[0] (approval record), no receipt in the vCon cites it |
| F07 | payload of the inline receipt changed, old signature | FAIL R1 | FAIL R1 | yes | no | yes | attachments[1] (decision receipt), no DSSE signature of the gate over PAE (step 3 of 3.2) |
| F08 | JWS payload changed, not signed again | FAIL V2 | FAIL V2 | yes | yes | yes | JWS signatures[0], JWS signature does not verify (InvalidSignature) |
| F09 | Event Objects with session instead of sessions | FAIL V4 | FAIL V4 | yes | yes | yes | events[0], parameter sessions missing (event_common_type of vCon core); session is present instead |
| F10 | content_hash without a sha512 token | FAIL A1 | FAIL A1 | yes | yes | yes | attachments[2] (decision receipt), content_hash without sha512 (2.4.2) |
| F11 | approval answer contributed by the agent | FAIL R4a | FAIL R4a | yes | yes | yes | attachments[1] (decision receipt) dec-0001, approver 'user-123' is not the party of the answer ('agent-42') |
| F12 | two ALLOW receipts cite the same approval | FAIL C1 | FAIL C1 | yes | no | yes | approval 5e551011-0000-4000-8000-000000000001/00000000-0000-4000-8000-000000000003, 2 distinct ALLOW payloads cite the same approval |
| F13 | approvedAt is not the time of the answer | FAIL R4a | FAIL R4a | yes | yes | yes | attachments[1] (decision receipt) dec-0001, approvedAt 2026-10-15T09:00:04Z is not the send time of the answer 2026-10-15T09:00:03Z |
| F14 | answer with a duration, approvedAt equals its start | FAIL R4a | FAIL R4a | yes | yes | yes | attachments[1] (decision receipt) dec-0001, approvedAt 2026-10-15T09:00:04Z is not the send time of the answer 2026-10-15T09:00:06Z |
| F15 | tool result after DENY without status and is_error | FAIL C2 | FAIL C2 | yes | yes | yes | dec-0002, tool call toolu_example_02, tool result 00000000-0000-4000-8000-000000000009 after DENY counts as executed |
| F16 | COSE_Sign1 signature changed | FAIL Z3 | FAIL Z3 | yes | yes | yes | COSE_Sign1 signed-agent-record, COSE_Sign1 signature does not verify |
| F17 | trace-metadata content-hash changed (unprotected header) | FAIL Z3 | FAIL Z3 | yes | yes | yes | COSE_Sign1 signed-agent-record, trace-metadata content-hash does not match the payload |
| F18 | COSE_Sign1 over a changed vCon, JWS unchanged | FAIL Z3 | FAIL Z3 | yes | yes | yes | COSE_Sign1 signed-agent-record, COSE payload is not the JWS payload |
| F05R | as F05, the vCon signed again in the RS256 form | FAIL Z2 | FAIL Z2 | yes | yes | yes | citing receipt dec-0003, SHA-256 of the JWS payload is not the digest in inputSnapshot |
| F08R | as F08, in the RS256 form | FAIL V2 | FAIL V2 | yes | yes | yes | JWS signatures[0], JWS signature does not verify (InvalidSignature) |
