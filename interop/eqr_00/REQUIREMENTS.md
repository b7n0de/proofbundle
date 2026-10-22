# Requirements of draft-watts-agent-evidence-boundary-00

Every sentence of the draft that carries a BCP 14 key word in upper case, outside the key-word convention of Section 2. Line numbers refer to the plain-text copy with SHA-256 `e9d47a647af3d1474f3c4fdcc286d6dae3d60a2a378e1f86741e4e95cb81bd5d` (1064 lines). Generated from `requirements.json` and `requirements_map.json`.

| id | section | lines | key words | requirement (quoted) | category |
|---|---|---|---|---|---|
| S3-1 | 3 | 236-237 | MUST NOT | An implementation conforming to this document MUST NOT interpret PASS as an authorization decision. | agreement |
| S3-2 | 3 | 237-238 | MUST NOT | It MUST NOT interpret receipt integrity as evidence sufficiency. | agreement |
| S3-3 | 3 | 238-240 | MUST NOT | It MUST NOT convert INDETERMINATE into PASS because an action is time-sensitive or because other authorization inputs are valid. | agreement |
| S4-1 | 4 | 324-326 | MAY | An authorization system MAY require no EQR for low-consequence operations and a particular EQR profile for higher-consequence operations. | not_implemented |
| S5-1 | 5 | 344-345 | SHOULD | Implementations that compute a digest over a JSON payload SHOULD use the JSON Canonicalization Scheme [RFC8785] before hashing. | agreement |
| S5-2 | 5 | 345-348 | MUST | When an EQR binds a non-JSON proposition, evidence object, profile, context, or action, the applicable profile MUST define the canonical byte representation that is hashed. | not_implemented |
| S5-3 | 5 | 360-360 | MUST | They MUST use the Internet date/time format defined by [RFC3339]. | agreement |
| S5-4 | 5 | 372-373 | SHOULD | High-consequence profiles SHOULD require this member when the proposition is evaluated specifically to justify an action. | agreement |
| S5-5 | 5 | 382-383 | MUST | Digest values MUST use base64url encoding without padding as specified in [RFC4648]. | agreement |
| S5.1-1 | 5.1 | 401-402 | MUST | The evaluation.status member MUST be exactly one of: pass, fail, or indeterminate. | agreement |
| S5.1-2 | 5.1 | 404-405 | MUST | An issuer MUST produce fail when any required profile condition is known to be violated. | agreement |
| S5.1-3 | 5.1 | 405-407 | MUST | Otherwise, if any required condition is missing, unresolved, stale, or outside declared tolerance, the issuer MUST produce indeterminate. | agreement |
| S5.1-4 | 5.1 | 407-408 | MUST | The issuer MUST produce pass only when all required conditions are satisfied. | ambiguity |
| S5.1-5 | 5.1 | 410-410 | MUST NOT | An empty required-condition set MUST NOT yield PASS. | ambiguity |
| S6-1 | 6 | 492-494 | MUST | An inter-domain EQR MUST be integrity protected and bound to an authenticated issuer using a mechanism acceptable to the verifier. | agreement |
| S6-2 | 6 | 509-510 | MUST NOT | A verifier MUST NOT infer substantive evidence quality from successful signature verification. | agreement |
| S7-1 | 7 | 516-517 | MUST | Before producing an EQR, an issuer MUST bind the exact proposition and exact evidence profile. | agreement |
| S7-2 | 7 | 517-519 | MUST | The profile MUST identify each required condition and the rule for handling missing values, stale values, contradictory evidence, and comparison tolerances. | not_implemented |
| S7-3 | 7 | 521-523 | MUST | Where a profile compares multiple representations of the same property, the profile MUST define the comparison space, units, transformation or bridge, snapshot alignment, and tolerance. | not_implemented |
| S7-4 | 7 | 527-528 | MUST NOT | The issuer MUST NOT silently substitute a different proposition, evidence profile, evidence source, or action after evaluation. | agreement |
| S8-1 | 8 | 533-534 | MUST | A verifier consuming an EQR MUST perform the following checks before exposing the receipt to authorization policy: | ambiguity |
| S8.1-1 | 8.1 | 571-572 | MUST NOT | When an authorization policy requires a PASS EQR, FAIL and INDETERMINATE MUST NOT satisfy that requirement. | agreement |
| S10-1 | 10 | 635-637 | MUST NOT | An implementation MUST NOT mutate an existing receipt from INDETERMINATE to PASS, from FAIL to PASS, or from PASS to another state after issuance. | agreement |
| S10-2 | 10 | 640-641 | MAY | The successor MAY identify its predecessor in supersedes. | agreement |
| S10-3 | 10 | 641-642 | MUST NOT | A verifier MUST NOT treat supersession as deletion of the predecessor. | ambiguity |
| S15-1 | 15 | 814-817 | MUST NOT | *Authority laundering:* A verifier MUST NOT treat a valid signature, reputable issuer, neighboring true statement, or PASS result under one profile as authority for a different proposition, profile, context, or action. | agreement |
| S15-2 | 15 | 819-821 | SHOULD | *Replay:* High-consequence deployments SHOULD bind receipts to a short validity interval and, where appropriate, a nonce, transaction, or action digest. | ambiguity |
| S15-3 | 15 | 826-827 | MUST | A verifier MUST reject a profile digest that does not match its accepted profile bytes. | agreement |
| S15-4 | 15 | 830-832 | MUST NOT | A verifier MUST NOT dereference arbitrary locations solely because they appear in a receipt. | agreement |
| S16-1 | 16 | 862-864 | SHOULD | Implementations SHOULD minimize the proposition text, evidence metadata, retrieval locations, and correlation identifiers exposed across trust boundaries. | not_implemented |
