# Cases

Written by measure_cases.py. Each case is checked twice with check_example.py; "same" means the two
reports and exit codes are equal. "Disclosure" says whether the check got the disclosure of a dispute
(spans, salts, approval receipt, rule) or only the record and its Transparent Statement. OPEN exits 3,
PASSED 0, FAILED 1.

| Case | Change | Disclosure | Expected | Result | Exit | Same | As expected | First failure |
|---|---|---|---|---|---|---|---|---|
| P0 | the example, unchanged, without the disclosure | no | OPEN | OPEN | 3 | yes | yes |  |
| P1 | the example, unchanged, with the disclosure | yes | PASSED | PASSED | 0 | yes | yes |  |
| F01 | unsalted guessable content: the action's fingerprint is plain SHA-256 and says so | no | FAILED K3 | FAILED K3 | 1 | yes | yes | entry action has the commitment 'sha256', not sha256-salted-v1: a fingerprint over guessable content (arguments, result, agent name, the approval) must be salted |
| F02 | unsalted guessable content that claims sha256-salted-v1, without the disclosure | no | OPEN | OPEN | 3 | yes | yes |  |
| F03 | as F02, with the disclosure | yes | FAILED D3 | FAILED D3 | 1 | yes | yes | entry action: the fingerprint is the unsalted SHA-256 of the span selection, which anyone can test guesses against |
| F04 | missing receipt: the statement with an empty receipt list | no | FAILED A1 | FAILED A1 | 1 | yes | yes | the Transparent Statement is malformed (statement confirmed; no receipt read): malformed: no receipt under label 394: a Signed Statement is not a Transparent Statement (RFC 9943) |
| F05 | missing receipt: the signed statement alone | no | FAILED A1 | FAILED A1 | 1 | yes | yes | the Transparent Statement is malformed (statement confirmed; no receipt read): malformed: no receipt under label 394: a Signed Statement is not a Transparent Statement (RFC 9943) |
| F06 | wrong service key: the receipt signed by another test key, kid of that key | no | FAILED A1 | FAILED A1 | 1 | yes | yes | the Transparent Statement is needs_rp_trust (statement confirmed; receipt 0 needs_rp_trust):  |
| F07 | wrong service key: the receipt signed by another test key under the pinned key's kid | no | FAILED A1 | FAILED A1 | 1 | yes | yes | the Transparent Statement is signature_invalid (statement confirmed; receipt 0 signature_invalid):  |
| F08 | the receipt is for another statement (another data-hash in its leaf) | no | FAILED A1 | FAILED A1 | 1 | yes | yes | the Transparent Statement is receipt_not_bound (statement confirmed; receipt 0 receipt_not_bound):  |
| F09 | the record changed and signed again after it was anchored | no | FAILED A1 | FAILED A1 | 1 | yes | yes | the Transparent Statement is unbound (statement unbound; receipt 0 confirmed): the statement's payload is not this target's root |
| F10 | the statement signed by a key the reader has not pinned | no | FAILED A1 | FAILED A1 | 1 | yes | yes | the Transparent Statement is needs_rp_trust (statement needs_rp_trust; receipt 0 confirmed): statement key selected by the protected x5chain; no relying-party statement key is the x5chain end-entity key |
| F11 | the record's payload changed, old signature | no | FAILED K1 | FAILED K1 | 1 | yes | yes | the record's DSSE signature does not verify under the pinned recorder key |
| F12 | the record signed by a key the reader has not pinned | no | FAILED K1 | FAILED K1 | 1 | yes | yes | the record's DSSE signature does not verify under the pinned recorder key |
| F13 | the conversation id in clear, as a field of its own | no | FAILED K2 | FAILED K2 | 1 | yes | yes | the predicate has fields outside the profile or lacks one: ['conversationId']; a field outside the profile can carry an identifier in clear |
| F14 | the trace id in clear, inside the free text of the approval entry, without the disclosure | no | OPEN | OPEN | 3 | yes | yes |  |
| F14D | as F14, with the disclosure | yes | FAILED D6 | FAILED D6 | 1 | yes | yes | the record carries the trace id in clear |
| F15 | the approval entry presents the approval as an OpenTelemetry standard | no | FAILED K3 | FAILED K3 | 1 | yes | yes | the approval entry does not say that the approval is not standardized in OpenTelemetry; the conventions at the pinned commit define no span or attribute for it |
| F16 | approval and action carry different call references | no | FAILED K4 | FAILED K4 | 1 | yes | yes | approval and action carry different call references, so the approval is not the one of this call |
| F17 | the stated order is action before approval | no | FAILED K4 | FAILED K4 | 1 | yes | yes | the stated order is not run, approval, action (seq [1, 3, 2]) |
| F18 | the disclosed tool arguments are not the fingerprinted ones | yes | FAILED D3 | FAILED D3 | 1 | yes | yes | entry action: the fingerprint does not match the disclosed span |
| F19 | a disclosed salt of 8 bytes | yes | FAILED D1 | FAILED D1 | 1 | yes | yes | salt call has 8 bytes; sha256-salted-v1 needs at least 16 |
| F20 | the disclosed approval is a DENY, the record says approved | yes | FAILED D5 | FAILED D5 | 1 | yes | yes | the conclusion {'approvalRequired': True, 'approvedBeforeAction': True} is not what the rule gives over the disclosure {'approvalRequired': True, 'approvedBeforeAction': False} |
| F21 | the disclosed approval names another tool call | yes | FAILED D4 | FAILED D4 | 1 | yes | yes | the approval receipt names another tool call or trace than the disclosed action span |
| F22 | the approval was decided after the action started | yes | FAILED D4 | FAILED D4 | 1 | yes | yes | the approval was decided at 2026-11-20T10:00:05Z, not between the run's start and the action's start |
| F23 | the disclosed rule is not the one the record names | yes | FAILED D5 | FAILED D5 | 1 | yes | yes | the disclosed rule is not the one whose digest the record carries |
| F24 | the record's conclusion is not what the rule gives | yes | FAILED D5 | FAILED D5 | 1 | yes | yes | the conclusion {'approvalRequired': False, 'approvedBeforeAction': True} is not what the rule gives over the disclosure {'approvalRequired': True, 'approvedBeforeAction': True} |
