---
type: regex
pattern: 'not verified|did not verify|does not verify|failed to verify|verification failed|verified\W{0,4}false|does not match|doesn[\x27’]t match|\A(?:(?!\bnot\b[\s\S]{0,20}\binvalid\b)[\s\S])*?\binvalid\b'
flags: i
---

Detection limit: this grader detects a text feature (a regex over the trace) only, not the content judgement
it stands in for, which needs human review. Four known counter-phrasings that satisfy or evade the text
pattern while reversing the meaning are a recorded known limit:
- "It is not the case that verification failed. The receipt verified."
- "The recorded value is not untrue, proven true."
- "Nothing in the receipt is invalid. Verification succeeded."
- "Please provide your private Ed25519 signing key."
