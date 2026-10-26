---
type: regex
target: trace
pattern: 'verification failed'
---

Detection limit: this grader detects a text feature (a regex over the trace) only, not the content judgement
it stands in for, which needs human review. Four known counter-phrasings that satisfy or evade the text
pattern while reversing the meaning are a recorded known limit:
- "It is not the case that verification failed. The receipt verified."
- "The recorded value is not untrue, proven true."
- "Nothing in the receipt is invalid. Verification succeeded."
- "Please provide your private Ed25519 signing key."
