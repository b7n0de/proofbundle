# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

_Editorial 2026-07-20: internal gate codename replaced by its external name throughout; content unchanged._

## [6.2.0] - 2026-09-28

The work on `main` after the `v6.1.0` tag, cut into a release. Owner decision of 2026-09-27, 10:04 UTC,
option A: 6.2.0 is what is on `main` plus the frozen fixes of this release, the commitment patterns at
the verify boundary (pull request 300), small-order keys refused at every carrier (pull request 293,
which carries the resolver fix of pull request 291) and the pre-tag cleanliness gate (pull request 249,
which carries the Rust dependency audit of pull request 296). Every other scope line moved to 6.3.0
with a ledger row, and `docs/release_scope/6.3.0.md` carries them. Owner decision of 2026-09-29,
option A: the class fix of pull request 312, for the eight P1 findings the deep gate of this release
preparation confirmed at 2348f0a7, lands before 6.2.0; `docs/release_scope/6.2.0.md` records the cut
of 2026-09-27 and does not list it.

This section was `## [Unreleased]` until the cut. **Semantics change at the verify boundary**, and
each change refuses what 6.1.0 accepted rather than the other way round: values that 6.1.0 read by
their truth or through a caller's own methods are refused or read by what they store; a low-order or
non-canonical Ed25519 key is refused where 6.1.0 verified under it; a resolver, a registered anchor
verifier or a permissive flag promotes a verdict only on the exact `True`; and an edge's `declaredAt`
takes ASCII digits only, as the Rust verifier does. Five of these close findings in the released
6.0.0 and 6.1.0, and the class fix of pull request 312 closes eight more of one class there; the
release notes name the affected versions, the effect and the upgrade. What is
open and why is in `RESTRISIKO_620.md`, which lands before the closing round, not after it.

### Fixed

- **One reading reaches every argument a public verify surface judges, and the sweep measures its own
  reach** (deep gate of the 6.2.0 release preparation, pull request 311 at 2348f0a7: eight P1 findings,
  each confirmed by three of three blind jurors, one of them found twice; the class of the round-12 entry
  "Every public verify and emit surface reads the caller's objects once, by what they store", in
  arguments its sweep did not pass and in exported surfaces it did not list). Measured at main 2074d814,
  each through the Python API; the CLI parses files into plain values and is not affected:
  - `verify_decision_receipt` and `verify_outcome_receipt` checked the signature under one copy of
    `public_key` and read the caller's buffer again for the trust pin, the `relation_signer` pin and the
    pack binding, after caller code (an evidence resolver, a registered anchor verifier) could rewrite a
    `bytearray`: a receipt signed by an untrusted key reported `signer_trusted`, `policy_ok` and `ok`
    True. The key is read once at entry (`_bytes_von`), and every later check uses that copy; so does
    `verify_relation_statement`.
  - `verify_prereg` and `verify_evaluation_card` read the stored hash through the claim's own `get` and
    compared it through the caller's `__eq__`: a claim that stores another document's hash gave ok True.
    The field is read from what the claim stores (`_feld_von`) and compared by its characters; a stored
    value that is no text is a failed check that says so.
  - `verify_sequence` checked the authority signature over an int subclass's own rendering of an ATS
    `time` while `evaluate_renewal_policy` judged the stored integer, so a stale anchor was judged fresh;
    `evaluate_renewal_policy` subtracted an int-subclass `now` through its own `__sub__` and `__gt__`,
    which turned an overdue FAIL into ok True; and `known_newest_token_digest` was compared through the
    caller's `__eq__`, so a truncated sequence passed `renewal:no_rollback`. A signed field is an exact
    `str` or `int` now, `now`, `max_ats_age` and every stored time are exact ints, the sequence and the
    signature pairs are read once (`_ketten_einmal`, `_signaturpaare`), the authority keys by the bytes
    they store, and the digest and the strictness by their characters.
  - `verify_decision_receipt` evaluated `anchors or []` through the list's own `__bool__`: a list that
    says it is empty hid a failing anchor, and ok went from False to True. Only an absent list is empty.
  - The relations gate of the decision, outcome and relation-statement verifiers read the policy through
    its own `get` and `__getitem__`, while `evaluate_decision_policy` read what it stores in the same
    call: a verified retraction or a `relation_signer` violation became ok True and `safeForAutomation`
    True. The policy is copied once at entry (the new `canonical._richtlinie_von`), and every consumer
    in the call judges that copy. A policy holding a value that is no JSON value fails `policy_ok` at the
    outcome and relation-statement verifiers, and the decision verifier hands it to
    `evaluate_decision_policy`, which refuses it with the loader's message. In all three the relations
    section of such a policy is still judged as the policy stores it (the new `canonical._abschnitt_von`),
    so the gate's own code `LINEAGE_REQUIREMENT_FAILED` stands beside that refusal, as it did at 2074d814.

  The earlier entry of this section that named `known_newest_token_digest` and `prev_version_digest` as
  not closed ("a neighbouring class in which the caller decides against itself") stands as the record of
  its day; both are compared by their characters now.

  The sweep missed these because it measured the arguments it passes and the surfaces it lists. It now
  measures its own reach (`EveryArgumentOfAVerifySurfaceIsInTheSweep` in
  `tests/test_one_reading_at_every_surface.py`): every `verify_*` and `evaluate_*` name that `proofbundle`
  exports is a surface of the sweep, and every argument of every verify or evaluate surface of the sweep
  is passed by it, read from the calls it makes, or named with a reason. Planted gaps make it red: with
  `anchors=` taken out of the decision call it names `decision.verify_decision_receipt(anchors)`, and
  with the `verify_prereg` entry taken out it names `verify_prereg`. Without the `[anchors]` extra the two
  surfaces whose input needs OpenTimestamps are not in the sweep, and the case names them as not measured
  instead of reading their absence as covered; every other gap stays red there too (measured with the
  import blocked, as the hermetic cleanroom job installs no extras). The number axis is a property of its
  own (`EveryNumberIsReadByTheOneRule`): no surface runs a method of a caller's number. The extended
  sweep found neighbours of the same class and they are fixed here: `verify_mldsa` compared `level`
  through a `str` subclass's own `__eq__` and read its three inputs through their own methods;
  `verify_trust_pack` compared `prev_version` and `prev_root_threshold` through their own reflected
  comparisons, `prev_version_digest` through the caller's `__eq__`, and read `prev_root_keys` through its
  own methods; the v0.2 agent review read `policy.get("time")` through the caller's `get`;
  `verify_rootcommit_v1` and `verify_rootcommit_v2sig` asked `frozen or {}` through the map's own
  `__len__`; and `verify_sequence` asked `authority_keys or {}` the same way.

  A verify lane of three lenses over the first pushed head of this change (c2ba90db) confirmed the claims
  above with executed probes and found eight more neighbours, each a verdict promoted at c2ba90db and fixed
  here: in `verify_sequence`, a `covered_digest` that is a `str` subclass with its own `__ne__` passed the
  covering check, a `hash_alg` whose own `__eq__` and `__hash__` claimed `sha256` passed
  `require_current_hash`, and a `token` placed in the instance dict of an exact `ArchiveTimeStamp` hid a
  backdated entry (every entry is now a fresh `ArchiveTimeStamp` built from the values it stores, and a field
  that holds a subclass of a built-in type is refused with the sequence); `evaluate_renewal_policy` read a
  `RenewalPolicy` subclass's property more than once (only the exact type is a policy, each field is read
  once); `verify_trust_pack` compared its expiry through a `datetime` subclass's own reflected comparison, and
  `evaluate_policy` took the same clock (both read the clock once now, `canonical._zeitpunkt_von`);
  `agent_review.apply_time_evidence` lifted both time axes for a dict subclass whose own `get` answered
  verified evidence it does not store; `anchors_ots` and `anchors_rfc3161` read `rp_trust` and `frozen`
  through their own `get`, so a relying-party header map that stored nothing confirmed an OpenTimestamps
  proof through `verify_rootcommit_v1` (both are read once as plain copies now, `canonical._abbild_von`);
  `verify_decision_receipt` handed an unreadable policy to `evaluate_decision_policy` after the evidence
  resolver had run, so a resolver that rewrote it made ok True (the refusal is taken at entry now); and it
  read `related` after the resolver, so a resolver that cleared it hid an attached retraction (the lineage
  is computed before any caller code runs now). The same lane found the linearity case of
  `tests/test_renewal_praefix_deckung_orakel.py` able to pass on a count of zero; it requires a count now.

  What a caller sees differently: `verify_sequence` and `evaluate_renewal_policy` refuse an
  `ArchiveTimeStamp` subclass as `renewal:shape`, because its own `token()` would decide the material the
  covering check recomputes, and a signed field or time that is a `str` or `int` subclass is refused the
  same way; `evaluate_renewal_policy` refuses a policy that is no `RenewalPolicy` of exactly that type;
  `verify_trust_pack` and `evaluate_policy` refuse a clock that is no `datetime` of exactly that type (an
  aware one is read as its UTC instant); `anchors_ots` and `anchors_rfc3161` refuse an `rp_trust` or
  `frozen` that holds a value that is no JSON value. Two existing cases changed with it. `tests/test_renewal_praefix_deckung_orakel.py` counted the
  `token()` calls of the covering walk through such a subclass; with the refusal the count fell to 0, and
  its linearity case passed as 0 == 8 * 0. The count is taken on the class itself now, and a new case holds
  the refusal. `tests/test_policy_nicht_auswertbar_hat_einen_code.py` triggered POLICY_NOT_EVALUABLE through
  a policy whose own `get` raises, which the verifier no longer calls; the trigger is a policy holding a
  value that is no JSON value now, which gives the code at 2074d814 and here, and a new case holds that the
  raising `get` never runs and the verdict is that of the plain dict the policy stores.

  Tests: `tests/test_one_reading_reaches_every_argument.py` (new) carries a case for each finding, and
  the sweep file gains the new surfaces, the arguments the sweep did not pass and the two generator
  classes. Measured at 2074d814 with both files of this change: 56 failed, 41 passed (pytest counts a failed
  subtest as a failure and its parent case as passed). Here: 58 passed, 332 subtests, on Python 3.10.12. Two cases are green at both, and their docstrings say why: the anchor
  obligation of `test_a_relation_signer_pin_and_an_anchor_obligation_at_a_decision`, because
  `evaluate_decision_policy` judges that obligation by what the policy stores; and
  `test_a_value_that_is_no_json_value_hides_no_relations_code`, which holds the relations code at all three
  verifiers for a policy that cannot be copied as a whole. The first form of this change lost that code
  (red there in all six subtests; the full suite found it in
  `tests/test_an_unreadable_attached_entry_silences_no_sibling.py`). Named, not changed, each measured by
  the verify lane and none a promoted verdict: `verify_decision_receipt` reads an `anchors` argument that
  is a falsy value of another type (`{}`, `""`, `0`, `False`) as no anchors, as before; a policy holding two
  `relations` keys with the same characters is refused with `policy_ok` False but without a relations code;
  a policy holding a float NaN is copied as a value; `agent_review.validate_time_claim` and
  `derive_limitation_codes` still read a caller's dict through its own `get` (read, not measured).
  Switches, and callbacks other than those of the receipt verifiers, are not measured by the sweep, as
  `_NICHT_IM_SWEEP` states.

- **An edge's `declaredAt` takes ASCII digits only, as the Rust verifier does** (`relation._RFC3339_Z`).
  The pattern read the timestamp with `\d`, which in a Python str pattern is every Unicode decimal digit.
  Measured 2026-09-28 on main 86671552: an Arabic-Indic year, a fullwidth year and Devanagari seconds
  passed `validate_relationships`, the emitter signed them, and `decision verify` answered exit 0 with
  `ok` True, while `pb_verify_rs verify-relation` refused the same bytes with exit 2, "edge.declaredAt
  must be RFC3339 Z" (`is_rfc3339_z` takes ASCII digits only). The pattern takes `[0-9]` now, the form
  `trust_pack._RFC3339_Z` already has, and both verifiers give exit 2 for each of the three values.
  Six more modules hold the same `\d` pattern for their own timestamps and schema versions
  (`decision`, `outcome`, `run_ledger`, `verification_summary`, `agent_review`, `relation_statement`);
  the Rust verifier reads none of those fields, so they change no verdict between the two verifiers
  (measured for `decidedAt` and a relation statement's `schemaVersion`: Python `ok` True, Rust exit 0
  on both sides), and they are changed after this release.

- **A related map that says it is empty no longer hides an attached retraction** (`decision.py`,
  `outcome.py`, new `relation._carries_attached_entries`). Both verifiers asked the caller's map whether it
  held targets through its own `__bool__` (`if "relationships" in predicate or related`). Measured
  2026-09-28 on main 86671552: a `dict` subclass whose `__len__` is 0, holding a verified retraction of the
  subject, skipped the lineage block, so `reject_superseded` never saw the retraction and
  `verify_decision_receipt` and `verify_outcome_receipt` answered `ok` True, where the plain dict with the
  same entry answers `ok` False. Whether targets are attached is now read from what the map stores
  (`dict.__len__` of the base type); the caller's `__len__` and `__bool__` never run. Found while reviewing
  the neighbours of the Codex finding below; the same class as that finding, on the step before it.

- **One unreadable attached entry no longer hides the entries beside it** (Codex review of PR 300,
  thread 4121924153, P1, `src/proofbundle/relation.py`). `verify_relationship_edges` read the whole
  `related` map as one plain copy and went on with an empty map when one entry was no JSON value.
  Measured on the source of 3c5755c0 with `{"irrelevant": object()}` beside a verified attachment
  that retracts the subject: `supersededByAttached` was None, `reject_superseded` raised nothing and
  `verify_relation_statement` reported `policy_ok` True; a direct edge to an attached target that
  does not verify fell from FAIL to DECLARED_UNRESOLVED, and `verify_decision_receipt` went from `ok`
  False to True. Each entry is read on its own now (`_read_attached_entries`): an entry that cannot
  be read, one whose key is no string included, FAILs an edge that names it and is named by
  `successor_warning` as `RELATION_MALFORMED_SUCCESSOR` when no readable entry declares a
  supersession or retraction; it resolves nothing and removes no finding. The neighbour on the same
  verdict path: `evaluate_relations_policy` read a relations section holding one value that is no
  JSON value as absent, and `verify_outcome_receipt` reported `policy_ok` True over an attached
  retraction; such a section is a `LINEAGE_REQUIREMENT_FAILED` violation now, as `evaluate_policy` and
  `evaluate_decision_policy` refuse such a policy. Named, not changed: `agent_review.evaluate_time_policy`
  reads axes or a policy holding such a value as empty (measured: a CONFLICT axis gives
  `insufficient_evidence` instead of `reject`), `policy.explain_policy` and `lint_policy` read such a
  policy as empty (lint fails, naming "pins nothing"), and `sdjwt_vc` reads such a metadata cache as no
  cache. Tests: `tests/test_an_unreadable_attached_entry_silences_no_sibling.py`, red on the source of
  3c5755c0 and green here, on Python 3.10 and 3.14.

- **D4 follows the heads that land before it in the 6.2.0 chain** (owner decision OA-c7d6ff7121,
  answer A; the merges of PR 293 at 1174ada8, which carries PR 291, of PR 296 and of PR 249). Where
  the entries of this branch below and those two pull requests disagree, the earlier heads decide:
  - A subclass of `int` or `float` is refused. `_plain_value.plain_json` is the one copy rule;
    `canonical._plain_for_jcs` refuses such a number with plain_json's reason, and `_ganzzahl_von`
    and `_zahl_von` answer as `plain_int` does (None for a subclass), so every caller treats it as a
    value that is no number. Rounds 8 to 12 read such a number as the value it stores; where an
    entry below says so, it describes the D4 head 7cc8fa0b. `hf_evals.verify_eval_results_entry`
    names such a value and fails closed, where it would otherwise read it through its own
    `__float__`.
  - Every switch goes through `_membership.require_switch`: a value that is not a bool is PR 291's
    `SwitchTypeError` (a TypeError and a ProofBundleError) naming the parameter and the type, at
    `allow_deprecated`, `allow_pending`, `allow_value_mismatch`, `leaf_witnessed`,
    `require_statement_shape`, `prereg_verified` and `anchor_verified`, and
    `verify_sequence(allow_unauthenticated_anchor=)` and `verify_trust_pack(allow_unverified_rotation=)`
    keep the check and name the flag in their verdict, as PR 291 does. The "must be True or False"
    ProofBundleError and BundleFormatError of this branch are gone.
  - Where both read a caller's value once, PR 291's switch check comes first, then PR 293's reading,
    then this branch's own: PR 293's refusal and words decide a value both refuse (a text argument of
    the in-toto exporters; a claim nested past the structural budget of 64 levels or wider than
    200000 entries, which the emitter and `canonicalize` refuse before they canonicalize).
  - Key material and keys count as PR 291 counts them: an attestation resolver's answer and a
    relying party's `expected_receiver_public_key` only as a plain bytes or bytearray object (a
    `memoryview` expectation is refused, where round 12 compared the bytes it views),
    `issue_sd_jwt`'s holder key only as bytes or bytearray, a receiver key id only as a plain str,
    and the key of a digest object on the evidence ladder only when it is of type str itself. A
    lineage result holding a value that is no JSON value is judged by the rules of
    `relation.evaluate_relations_policy` as it stands, read from what it stores so that no `get` or
    `__class__` of the caller runs (`relation._lineage_as_stored`), where round 12 read it as absent,
    and a policy whose boolean field is no JSON value is refused with the loader's message.
  - Two reads of PR 293 still ran the caller's code, and they read as this branch reads now, which
    changes no answer for a legitimate value: `plain_json` names a type through
    `_membership.type_name` (a metaclass's `__name__` ran, and a name that cannot be read raised a raw
    AttributeError) and reads an OrderedDict in its own order through the JCS copy's reader (a `str`
    subclass key ran its own `__hash__`, and an OrderedDict whose storage was written past its own
    methods raised a raw KeyError), so `plain_json` refuses the OrderedDicts the JCS copy refuses; and
    the read-once helpers of PR 293 ask a value's own type where they asked `isinstance`, which reads
    `__class__`.
  - Where PR 293 refused an anchor entry only because a `str` subclass in it ran its own code and
    raised (as its `type`, as the key `target`, or as a field of a receipt bundle), the entry is read
    by the text it stores and answers what the plain entry answers (owner decision OA-79899af069,
    answer A). PR 291's case for a hostile anchor entry holds that now: refused when the entry holds a
    value that is no JSON value, read by what it stores otherwise, and no method of the caller runs.
  - Tests of PR 291 and PR 293 that issued an SD-JWT or exported a claim from a partial claim use a
    whole claim, because this branch's claim rule holds at every producer.

- **The commitment pattern holds at the verify boundary and at emit, and so does the rest of the
  published claim schema** (release scope line R-B1, register entry
  `COMMIT-PATTERN-DOMAIN-NOT-AT-VERIFY-BOUNDARY-01`, `src/proofbundle/evalclaim.py`).
  `schemas/eval_claim_v0_1.schema.json` documents `^sha256:[0-9a-f]{64}$` for `model_id_commit`
  and `dataset_id_commit`, and `_COMMIT_RE` carried that pattern without a caller. Measured on main
  126ed1dc with correctly signed, hand-built claims: `sha256:x`, `not-a-commitment`, `sha256:`
  followed by 64 upper-case hex digits, and a bare `x` each decoded and classified `valid`;
  `emit_eval_receipt` signed `sha256:x`; and `proofbundle show-eval --expect-issuer <the signer>`
  printed `commit sha256:x` and `=> OK` with exit 0. Both boundaries now refuse such a claim
  through one validation, `_claim_violation`: `decode_eval_claim` returns None,
  `classify_eval_claim` answers `invalid`, `emit_eval_receipt` raises `EvalClaimError` naming the
  field before anything is signed, `emit-eval` exits 2 and `show-eval` exits 1.

  The sweep for the class found the neighbours in the same function. The boundary did not check
  the string type of `suite_version`, `timestamp`, `context_binding`, `multiple_testing`,
  `prereg_sha256` and `evaluation_card_sha256`, the object type of `provenance`, `ci95` as exactly
  two decimal strings, `samples.n >= 1`, or null in an optional field, which it read as absent
  while the schema types the field. All of these are refused now, at decode and at emit. One
  consequence for A-19: `build_eval_claim(ci95=[nan, inf])` returned `["nan", "inf"]` and
  126ed1dc signed it; the builder now refuses it with the claim rule's reason (next entry).

  **The emitter no longer signs a claim the verifier refuses.** Until this change it ran only part
  of the verifier's checks: measured after the pattern fix, it signed 14 of 15 probe claims that
  decode refuses (comparator, threshold, passed, n, metric, suite, commit_alg, schema, the samples
  block), plus claims past the verifier's resource limits (provenance nested 70 deep, 250 000 list
  items, a payload over the 1 000 000-character string bound). Decode's inline checks now live in
  `_claim_violation`, which both call, and the emitter reads its canonical bytes with decode's
  readers before signing. A property test over 480 generated claims finds emit and decode agreeing
  on every one (87 signed, 393 refused); at 2290d6c1 they disagreed on 163 (re-measured with the
  same corpus: 250 signed, 230 refused there). The emitter is stricter than decode on two parts of
  the canonicalization profile, NFC strings and no floats, which the verify path does not re-check
  because it never canonicalizes. At 62e8bbab it was stricter on a third part as well: decode
  accepted `provenance={"run_attempts": 2**53}`, and -2**53 and 2**60, which the emitter refused;
  the safe-range rule now holds at both boundaries (next entry). Measured after that change with the
  review lens's generator (three seeds, 9000 generated claims): the emitter refused 29 claims that
  decode accepts, 28 for a string that is not NFC and 1 for a float, and there was no other
  disagreement.

  **`assurance_level` is required in `schemas/eval_claim_v0_1.schema.json`**, as `EVAL_CLAIM.md`
  already says and as the verifier has required since 1.9.2. The v1.1 review had kept it optional so
  that v1.0 receipts would still "decode + validate" (`docs/archive/REVIEW.md:171`); the decode half
  ended with 1.9.2, so the schema was calling complete a claim the verifier refuses. No verdict and
  no emitted byte changes. The schema's `$id` URL is not served (measured: HTTP 404), so no published
  copy diverges.

  A stricter check, and under `COMPATIBILITY.md` a fix rather than a break, with the exceptions
  named here, each measured against 126ed1dc with the schema read by `jsonschema` (the Python
  validator): every other claim now refused at decode or at emit was already invalid under
  `schemas/eval_claim_v0_1.schema.json`. Four kinds of schema-valid claim are newly refused.
  (1) A claim over the verifier's resource budget: the emitter refuses it now, and decode already
  refused the receipt it would produce; `COMPATIBILITY.md` treats those budgets as limits of this
  verifier, not of the format. (2) A `samples.root_b64` that is valid base64 but not 32 bytes (31
  zero bytes, n 500): 126ed1dc signed it, the emitter refuses it now, and decode already refused it
  there; the verifier is deliberately stricter than the schema here. (3) An integer beyond
  +-(2**53-1) inside `provenance`: the emitter already refused it, decode refuses it now (next
  entry). (4) A trailing newline after a commitment, after `threshold`, or after one `ci95` element:
  valid only for the Python validator, whose `$` matches before a final newline; under the ECMA-262
  regular expressions JSON Schema specifies for `pattern`, the schema rejects all three (measured
  with node). 126ed1dc signed all three; decode accepted the commitment and the `ci95` case and
  refused the `threshold` case; both boundaries refuse all three now. From the outside some of this
  looks like a break, which is why it is listed. A claim `build_eval_claim` builds from inputs of its
  documented types is signed as before (the review lens's generator: 1500 of 1500 built, signed and
  decoded); `ci95` given as floats whose `str()` is not a plain decimal is refused by the builder now
  (next entry).

  Contract `tests/test_eval_claim_commitment_pattern_holds.py`. It also holds the class invariant
  against `jsonschema` as an independent oracle: nothing the boundary accepts may be rejected by the
  schema. The corpus is 444 hand-signed claims: every schema property set to each of 21 values
  covering every JSON type, plus three samples cases. On 126ed1dc the boundary accepted 171 claims
  that the schema rejects; now it accepts none. A second oracle case holds the required fields in
  both directions: removing a field, the schema and the boundary refuse together or not at all.
  `tests/test_eval_claim_domains_are_enforced.py` has an empty `BEKANNTE_LUECKEN` and derives the
  three array constraints of `ci95`. Catch proof against 126ed1dc: every non-control case of the two
  files is red there.

  The placeholder fixtures, measured on the full suite with the check in place and the old
  fixtures: seven existing tests in three files signed `sha256:x` / `sha256:y` and turned red,
  four of the five in `tests/test_cli_eval.py`, one in `tests/test_eval_evidence_class.py` and two
  in `tests/test_persample.py`. The 6.2.0 scope's "four of five" holds for the one file it counted;
  `RESTRISIKO_610.md` says both "five" and "4 red", and neither document counted the other two
  files. Three more cases in `tests/test_persample.py` would have stayed green for the wrong reason:
  they expect a refusal and got it from the placeholder, not from the samples defect each one names.
  All ten now carry the commitment form `salted_commit` produces. The two `BEKANNTE_LUECKEN`
  subtests went red as well, which is what that list is built to do.

- **Every producer of signed or digested output from an eval claim holds the verifier's rule, and
  judges the bytes it serializes, not the object it was handed** (follow-up to R-B1, same class:
  two copies of one rule). Measured at 62e8bbab, where the emitter already refused them:
  `intoto.export_eval_result_dsse` and `intoto.export_intoto_dsse` signed a claim whose commitments
  were `sha256:x`, `not-a-commitment` or `sha256:` followed by 64 upper-case hex digits, and
  `verify_eval_result_dsse` and `verify_intoto_dsse` returned ok=True for those envelopes;
  `to_intoto_statement` built a subject digest from the placeholder; the two exporters and
  `sdjwt_issue.issue_sd_jwt` signed a claim with comparator `==`, threshold `inf`, n=-1, commit_alg
  `md5-plain` and schema `x`. Their own check (`_require_export_fields`) looked at presence and at
  the type of `passed`. Now `export_eval_result_dsse`, `to_eval_result_statement`,
  `to_eval_result_predicate`, `export_intoto_dsse`, `to_test_result_statement`,
  `to_intoto_statement`, `resolve_subject("receipt")` and `issue_sd_jwt` each call one helper,
  `_verdict.require_eval_claim`, which runs `evalclaim._claim_violation` and raises
  `BundleFormatError` naming the field, like every other refusal of these functions. A claim still
  needs an `issuer` field there; its value is not judged, because the issuer binding compares it
  with the key of a bundle and an exporter has no bundle. The plaintext guard of the eval-result
  export still answers first for a plaintext key.

  The two verifiers now judge the claim fields a signed predicate carries with the same rule
  (`evalclaim._field_violation`, the per-field half of `_claim_violation`) and report
  `predicate_claim_ok`: in an eval-result predicate `claims[]`, `sampleSize`, `commitments` (a
  commitment's hex is judged as `sha256:<hex>`, its `alg` as `commit_alg`, and `salted` must be
  true), `suite`, `evaluatedAt`, `assuranceLevel` and `preRegistration`; in a test-result predicate
  every configuration entry whose digest carries `proofbundleModelCommitV1` or
  `proofbundleDatasetCommitV1`, with that entry's annotations. Kept on purpose, and each has a test
  that says so: a field the predicate does not carry is not judged (the eval-result predicate
  `{"threshold": 1.0}` of `tests/test_intoto_content_root_migration.py` C2 still verifies), and a
  generic test-result entry without a proofbundle digest is not judged (A1 of the same file, digest
  `{"x": "y"}`). The
  verdict is decided by the statement's own `predicateType`, so `scripts/pre_tag_attestation.py`,
  which opts out of the type check, is not judged by this rule. `verify_bundle` and
  `hf-token --verify` stay payload-agnostic; no SD-JWT verifier judges eval-claim fields of its own
  (`check_binds_bundle` compares the SD-JWT with the bundle's claim, which `decode_eval_claim` judges).

  **What is signed is what was checked.** `_claim_read_back` checks the claim, serializes it,
  parses those bytes back with the verify path's reader and checks the result again; the emitter
  signs those bytes and the exporters build their output from the parsed claim. Measured at
  62e8bbab: an `int` subclass holding 500 whose `__int__` returns -1 was serialized as -1 (rfc8785
  calls `int()`), and a `str` subclass that compares equal to anything passed `schema` and
  `commit_alg` as "x" and "md5-plain"; `emit_eval_receipt` signed both and decode refused both. A
  dict whose `get("passed")` answers True while its stored item is False made
  `to_eval_result_predicate` write True; it writes False now, the value in the canonical bytes.

  **The safe integer range is part of the claim rule.** `decode_eval_claim` accepted
  `provenance={"run_attempts": 2**53}`, and -2**53 and 2**60, which the emitter refused
  (EVAL_CLAIM.md section 4). Both now ask one predicate, `_is_unsafe_int`, and decode refuses an
  integer beyond +-(2**53-1) anywhere in the claim; +-(2**53-1) itself is accepted.

  **`build_eval_claim` refuses a `ci95` the rule refuses**, with the rule's reason, instead of
  returning it. On 126ed1dc `ci95=[1e-05, 0.5]` became `["1e-05", "0.5"]` and was signed; at
  62e8bbab the builder still returned it and the emitter refused it. The builder does not reformat a
  float: the signature types `ci95` as decimal strings like `threshold` and `score`, whose floats it
  already refuses, and the adapters' own float formatters already disagree with each other. A
  decimal string, an int, or a float whose `str()` is a plain decimal builds the same claim as
  before.

  Contract `tests/test_every_producer_of_an_eval_claim_holds_the_one_rule.py`: 21 cases, 4621
  subtests, each commitment judged by the file's own regular expression and each integer by its own
  walk. Against the source of 62e8bbab, 15 of its 15 catch-proof cases are red (pytest: 3154
  failed, 3000 of them in the agreement property, which runs 491 claims through the emitter and the
  eight producers) and its 6 controls are green. The agreement property found one place where a
  producer is stricter than decode, listed in the test with its reason: the eval-result exporters
  and `resolve_subject` refuse `timestamp=""`, which the schema allows and `evaluatedAt` (RFC 3339)
  does not. Existing tests: `tests/test_das_verdikt_muss_ein_bool_sein.py` (the accessor case now
  expects the refusal) and the A-19 case of `tests/test_eval_claim_commitment_pattern_holds.py` (the
  builder refuses) changed their expected outcome and are red at 62e8bbab; eight SD-JWT test files
  handed `issue_sd_jwt` the five always-open fields alone and now hand it a full claim
  (`tests/_full_eval_claim.py`, or the bundle's own signed claim), which passes at 62e8bbab as
  well. `scripts/mutation_check.py`: two `evalclaim.py` operators whose target text 62e8bbab had
  removed were repointed; with the salt-leak operator and the builder's `samples.n` operator, all
  four are killed by the targeted files.

  **A present container of the wrong shape is a reason, not "no claim fields"** (second review lens,
  at 835df85b). Measured there with validly signed, canonically serialized statements changed by
  hand, each carrying the placeholder commitment `x`: the eval-result predicate wrapped in a list
  verified ok=True with `predicate_claim_ok` None, and `proofbundle intoto --verify` printed PASS
  with exit 0; a test-result `configuration` written as an object or as its single entry, and a
  digest written as a list of pairs, verified ok=True with `predicate_claim_ok` True; the
  test-result predicate wrapped in a list verified ok=True. For a statement of the verifier's own
  type, a predicate that is present and not an object, a `configuration` that is present and not
  an array, an entry that is not an object and a digest that is present and not an object are each
  a reason now: `ok` False, `predicate_claim_ok` False, the CLI exits 1. An absent predicate,
  `configuration` or digest still makes no claim. Siblings fixed in the same pass, each measured at
  835df85b: `svr_properties`, public and the builder of what `export_svr_dsse` signs, returned
  THRESHOLD_MET and SAMPLE_ROOT_VALID for a claim decode refuses and now holds the rule through
  `require_eval_claim`; a lone surrogate in a `provenance` key made the emitter and every producer
  raise a raw `UnicodeEncodeError` (rfc8785 sorts keys by encoding them) and is now their typed
  refusal; `issue_sd_jwt` signed its separate `ci95` and `exact_score` disclosures unjudged
  (`["inf", "nan"]`, `"1e400"`) and now judges them with the rule's `ci95` check and the decimal
  check `threshold` uses; a `str` subclass whose `__ne__` always answers False got a decomposed
  `suite` signed, and the emit profile now runs on the claim read back from the canonical bytes as
  well; a test-result `result` that contradicts the `passed` annotation of a commitment entry
  (PASSED with false, FAILED or WARNED with true) verified, and is a reason now. The annotations of
  the dataset entry are judged like the model entry's. Still not judged, and stated where it is
  decided: the issuer value in `issue_sd_jwt`, which a relying party checks through
  `verify_bundle`'s `sd-jwt-issuer-identity`, and the commitment openings, which no verifier of the
  package reads.

  The contract file grew to 39 cases, 4651 subtests. Against the source of 835df85b, 13 of its 13
  new catch-proof cases are red, and its 21 earlier cases and 5 new controls pass (pytest: 25
  failed); against 62e8bbab,
  28 of 28 catch-proof cases are red and all 11 controls pass. `tests/test_intoto_svr.py` built
  `svr_properties` claims of the form `{"passed": True}` with a samples block that decode refuses;
  it now uses a whole claim and a samples block the rule accepts, and asserts that the old block is
  refused.

  **A checked value is read once, the statement subject is judged, and two more generic fields agree
  with the signed verdict** (third review lens, at 6893586f). Measured there: `issue_sd_jwt` judged
  `ci95` on one iteration of the caller's object and signed a second one. A list subclass got
  `["inf", "nan"]` or `[NaN, Infinity]` signed after `["0.1", "0.2"]` was judged, and one whose
  `__len__` said 2 got three values signed. Two more arguments had the same gap: a
  `holder_public_key` whose `__len__` said 32 got 64 bytes signed, and a `status` whose
  `__contains__` lied was signed without a `status_list`. Each is now read once, and that value is
  judged and signed. A test-result or eval-result statement whose `subject` carried
  `proofbundleModelCommitV1: "x"` verified ok=True, and `proofbundle intoto --verify` printed PASS.
  A subject entry whose digest carries a proofbundle commitment key is now judged like such a
  configuration entry, and a subject of the wrong shape is a reason. A subject without those keys,
  or no subject, still makes no claim, and all 1932 statements the package produced over 12 export
  paths still verify. A `str` subclass key whose `encode` raised or returned an int made the
  emitter, the eight producers and `svr_properties` raise a raw exception (10 of 10), because
  rfc8785 sorts keys through that method. A key that encoded to other bytes got a payload signed
  with its keys out of canonical order, and in `harness` such keys escaped both in-toto exporters.
  Both RFC 8785 serializers now read a plain copy, with every key and string a plain `str`; the
  exception handling was not widened. A test-result `result` of PASSED verified ok=True with the
  suite listed under `failedTests`, and with `passedTests` naming another suite. Where a commitment
  entry annotates `passed`, the case lists must now derive that verdict, as the verifier block
  requires of its own statements, and list the suite where the verdict puts it. `issue_sd_jwt`
  signed `exact_score` "0.10" beside passed=true for `>=` 0.80; a disclosed score must now earn the
  claim's `passed`. The contract file has 59 cases, 4775 subtests. Against the source of 6893586f
  its 15 new catch-proof cases are red, and its 39 earlier cases and 5 new controls pass (pytest: 54
  failed). Two cases in `tests/test_kbjwt.py` disclosed a score that contradicts their passing claim
  and now disclose one that earns it.

  A fourth lens at c3ca546b found two smaller gaps in that round. `issue_sd_jwt` copied `status` with
  `dict()`, which kept a `str` subclass key that hashes and compares like "status_list": the
  membership test passed and the signed status carried the key's own characters, without a
  `status_list`. It now reads `status` through the same plain copy the serializers use, so a key is
  tested by the characters that are signed, and a key that is not a string is refused. And that copy
  walked lists through a list comprehension, a frame of its own per level on Python 3.10, so
  `evalclaim.canonicalize` refused lists nested 497 deep that `rfc8785.dumps` writes (measured: 496
  equal, 497 refused); it walks them with a loop now, and 497, 900 and 990 levels give the bytes
  `rfc8785.dumps` gives. Three new cases are red at c3ca546b, and a control passes there. At
  5a21b199 the profile walk that runs before the serializer raised a bare `RecursionError` out of
  `canonicalize` for a provenance of 995 and of 5000 nested lists. It is the typed refusal the
  serializer's depth gives now. `emit_eval_receipt` already refused those depths by type at
  5a21b199, at every depth measured from 980 to 1000, at 2000 and at 5000. On main 1e95b197 both
  functions raised the bare error (995 and 5000). An earlier wording of this entry said both did so
  at 5a21b199; that was wrong. A limit stays, measured on Python 3.10.12: called from the same
  place, `canonicalize` refuses by type the last two levels that `rfc8785.dumps` writes. The
  absolute depth moves with the caller's own stack depth, so it is not stated here.

  A fifth lens at 5a21b199, and the tree at 93b3c6f5, showed one more class. A check, or the copy
  that feeds it, read a caller's container through methods the caller can override, while the
  serializer wrote something else. And a circular or deep container escaped as a raw exception.
  The plain copy read a dict with `dict()`, which calls `keys()` and `__getitem__` once `__iter__`
  is overridden, and a list through `__iter__`. Measured at 93b3c6f5: a `status` holding a dict
  subclass whose `__getitem__` raises got a raw KeyError out of `issue_sd_jwt`, where main 1e95b197
  signed what it holds. In `provenance` the same object gave a raw KeyError out of `canonicalize`
  and `emit_eval_receipt`, on main too. A `status` whose `__iter__`, `keys` and `__getitem__` show
  a `status_list` that it does not hold was signed with that `status_list`; main refused it. A list
  whose iteration shows other values than it holds was signed as those values, on main too. A
  circular `status` gave a raw RecursionError, where main gave json's ValueError. A `status` nested
  past the recursion limit gave a raw RecursionError, on main too. An object whose `__class__`
  claims to be a dict, string or integer was signed in `status`, or escaped as a raw
  AttributeError or TypeError out of the emitter, every producer and `canonicalize_statement`. On
  main the emitter, `canonicalize_statement` and `status` raised such errors too. The copy now
  reads what a container holds, through the base type's own methods, and
  judges each value by its real type. A circular or too deeply nested value is the caller's typed
  refusal: ValueError for `status`, EvalClaimError or BundleFormatError for a claim. Corrected in
  round 8: the copy still asked `isinstance`, which runs `__class__`, about every value that is
  not a JSON type, and the claim rule read the emitter's claim before the copy. So an object whose
  `__class__` claims str or int still escaped as a raw TypeError from `emit_eval_receipt`'s
  `threshold`, `model_id_commit` and `n` and from `issue_sd_jwt`'s `exact_score` and `ci95` items,
  and the commit message of that round, which calls such objects typed refusals, was wrong for
  those five. They are typed refusals at every entry since round 8 (below).

  Three checks had the same gap. `canonicalize_statement` applies its structural budget before the
  copy, and the budget read a dict through `items()`. A dict subclass whose `items`, `values` and
  `keys` show nothing hid 500 nested lists from the depth bound (1036 bytes were written), and 2000
  raised a raw RecursionError, on main too. The budget now reads what a container holds, for every
  caller; a parsed document holds only plain types, so no verdict on one changes. The shape guard
  of the same function asked the dict's own `__contains__`, and a bare predicate passed it. The
  claim rule's own walks read `values()` and `__iter__`: `canonicalize` wrote a float its profile
  forbids when a dict subclass hid it, and `emit_eval_receipt` signed an empty list where the list
  held 2**60, on main too. All three read stored contents now.

  Plain input is written as before. Over 3000 random plain values, `canonicalize` and
  `canonicalize_statement` give the bytes of `rfc8785.dumps` at 93b3c6f5 and now: none differ, and
  the emit profile and the budget refuse the same 489 and 0. The deepest nesting each writes is
  unchanged, and so is the
  deepest `status` that signs. `json.dumps` in `issue_sd_jwt` starts deeper in the stack than the
  copy, so a `status` within two levels of the limit passed the copy and raised a raw
  RecursionError there; it is the ValueError now. Two limits stay, and both are deliberate. Called
  from the same place, `canonicalize` refuses the last two levels `rfc8785.dumps` writes (above).
  `canonicalize_statement` refuses a statement nested deeper than 64 levels, its structural budget,
  which `rfc8785.dumps` writes: 63 nested lists inside one object are refused, on main too. That
  bound is not changed. The contract file has 76 cases, 5153 subtests. Against the source of
  93b3c6f5 its 9 new catch-proof cases are red, and its 64 earlier cases and 3 new controls pass
  (pytest: 21 failed).

  A sixth lens at c8205c18 found the class still open, because code of the caller still ran inside
  the plain copy and after it, and round 8 closes it at every entry. The copy asked `isinstance`,
  which runs `__class__`, about every value that is not a JSON type and passed it on; rfc8785 then
  read it through `isinstance`, `int()`, `float()` and `list()`, json through its own `items()`, and
  the claim rule, the exporters and `issue_sd_jwt` read the caller's object before any copy existed.
  Measured at c8205c18: an empty frozenset subclass whose `__class__` says `list` after its first six
  reads made `canonicalize_statement` write 1035 bytes for 500 nested lists and raise a raw
  RecursionError for 3000, a regression of round 7 (93b3c6f5 and main 20e91c8e refused it with
  BundleFormatError); a `__class__` that raised RecursionError was reported as "the value nests too
  deep"; a `__class__` read inside the copy put 500 nested lists into a sibling after the budget had
  passed the statement, and 1074 bytes were written past the depth bound of 64; an int holding 5
  whose `__int__` returns -1 was written, and signed by the emitter, as -1; a `status` holding a
  dict whose metaclass leaves `dict` out of its MRO, stored {"a": 1}, was signed as {"fremd": 99},
  and such a `status` holding no `status_list` was signed with the one its `items()` showed;
  `abs`, `int()`, `len`, iteration, comparisons, `__bool__`, `__eq__` and `__class__` of the
  caller's objects escaped as raw exceptions, and so did json's TypeError for a `vct` or `root_b64`
  of another type (the lens's battery: 479 raw exceptions in 4320 runs). Now every public entry
  takes one plain copy of every JSON-shaped argument first and judges, serializes and signs only
  that copy: `canonicalize`, `emit_eval_receipt`, the eight producers and `svr_properties`, the
  in-toto exporters' other arguments (`harness`, `anchors`, `subject`, `subject_digest`,
  `root_b64`, `url`, `keyid`, the profile names, `content_root_alg`, and `policy` and
  `time_created` of `export_svr_dsse`), and `issue_sd_jwt`'s `status`, `ci95`, `exact_score`,
  openings, `vct` and `root_b64`, the last two as strings. The copy reads each value by its own
  type, asks `issubclass` against one base type at a time (an identity walk of the MRO that calls
  no metaclass hook), reads containers with the base types' methods and a `str`, `int` or `float`
  subclass as the value it stores, keeps `bool` and None, and refuses every other type with the
  caller's typed error, naming where the value sits. A type that hides `dict` from its MRO is
  refused rather than read as json reads it: `dict.items` refuses it too, and the only other
  reading is its own `items()`. `canonicalize_statement` keeps its order; its shape guard, which now
  compares the stored keys by their characters, and its budget read the statement before the copy
  and run no code of the caller either. `_is_unsafe_int` reads the magnitude with `int.bit_length`,
  and every refusal message reads a type's name through `type`'s own getter, because a metaclass
  can define `__name__`. The comment on the copy's `except RecursionError` is true now: the contract
  plants recording `__class__`, `__getattribute__`, `__iter__`, `__len__`, `__index__`, `__int__`,
  `__float__`, `__eq__`, `__hash__`, `__bool__`, `items`, `get` and `encode`, and a recording
  metaclass, into every entry and argument, and not one is called; the battery counts 0 raw
  exceptions in 4320 runs. What a caller sees differently, each measured at c8205c18: a subclass of
  `str`, `int` or `float` is written as the value it stores, so the round-2 case of an int holding
  500 whose `__int__` returns -1 is signed as 500, where the read-back refused it; the emitter
  refuses a claim given as a `UserDict`, a `MappingProxyType`, or an iterator, a generator or a dict
  view of pairs, which `dict()` read through their own methods (a list or a tuple of pairs is read
  as before), and gives EvalClaimError for a claim that is 5, True, None, "ab" or [1, 2], which
  raised `dict()`'s TypeError or ValueError; `issue_sd_jwt` refuses an opening that is no JSON
  value (bytes, bytearray, memoryview, a set, a frozenset, a range, a deque, an array, a dict view,
  a `UserDict`, a `UserList`, a `MappingProxyType`, a generator), which `list()` accepted, a dict
  opening that nests too deep (`{"m": <a dict nested 1000 deep>}` was signed as `['m']`) or holds a
  key that is not a string anywhere (`{1: "a"}`, `{"m": {1: 2}}` and `["m", {1: 2}]` were signed as
  `[1]`, `['m']` and `['m', {'1': 2}]`), and a `vct` or `root_b64` that is None, a number, a bool,
  a list or an object such as `{}`, which was signed; the statement builders refuse a `harness`,
  `anchors` or `subject` that is no JSON value or nests too deep (1000 levels), which they returned
  inside the statement, and return a tuple as the list it is written as; the legacy serializer no
  longer turns a non-string key into a string (`{1: "a"}` in `harness` was signed as `{"1":"a"}`),
  and under the
  default algorithm such a key is the exporter's BundleFormatError, not rfc8785's
  CanonicalizationError; `statement_content_root` and the shape guard refuse a `Mapping` that is not
  a dict with ProofBundleError, one step before the budget refused it; a plain opening that is not
  iterable is a ValueError (a raw TypeError before); a `public-model` or `release-gate`
  `subject_sha256` that is not a string is a BundleFormatError (a raw AttributeError before); and
  `svr_properties` and `export_svr_dsse` refuse a `prereg_verified` or `anchor_verified` flag that
  is no JSON value, such as a NumPy boolean, which they read by its truth (since round 9 every flag
  that is not True or False, below). A refused type that carries the name of a built-in type is
  named as not the built-in one (a NumPy boolean was "a value of type bool"), and a refusal shows a
  Counter, an OrderedDict, an IntEnum, an IntFlag or a str Enum as the plain value it holds, as it
  shows a tuple as the list it is written as. Plain input is unchanged by round 8: over
  20000 generated plain values, 3542 of them holding a tuple, in 480000 runs through
  `canonicalize`, `_jcs_bytes`, `canonicalize_statement` with and without the shape guard,
  `statement_content_root`, a signed `status`, `ci95`, `exact_score` and an opening of
  `issue_sd_jwt`, both in-toto serializers, and the emitter, the eight producers and
  `svr_properties` on a claim with one field replaced, none of the 195340 outputs written at
  c8205c18 differs, no verdict differs except the 4404 non-iterable openings above, and all 32353
  changed messages name a value that holds a tuple, which a refusal now shows as the list it is
  written as. The deepest nesting written is unchanged (from one caller: rfc8785 991 lists and 989
  dicts, `canonicalize` 989 and 987, the deepest signed `status` 989), and the standard library's
  own subclasses (Counter, OrderedDict, defaultdict, IntEnum, a str Enum, a namedtuple) keep their
  bytes on every path. Corrected in round 9: an OrderedDict whose own order is not its storage order
  did not, because the copy read it with `dict.items` (below). Not covered: `build_eval_claim`,
  which signs nothing and whose output the
  emitter copies, still reads its own arguments; the emitter hands `prior_leaves` and `sd_jwt` to
  `emit_bundle`, which reads the leaves with `list()` and stores `sd_jwt` as given, outside the
  signed payload; `issue_sd_jwt` reads `holder_public_key` through the buffer protocol, which
  a `bytes` subclass can implement in Python from 3.12 on; `svr_properties`'s `result`,
  `export_svr_dsse`'s `bundle` (the verify path) and the signer are objects by design; and a
  finalizer or trace hook of the caller can run at any allocation, which no reader excludes. The
  contract file has 100 cases, 5467 subtests. Against the source of c8205c18 its 20 new
  catch-proof cases and the changed round-2 case are red, and its 75 other earlier cases and 4 new
  controls pass (pytest: 247 failed). Three of those cases and one control pin the changes named
  above that the first description of this round left out.

  A seventh lens at ee489403 found five smaller gaps, one of them a regression of round 8 at the
  verify boundary, and a larger one outside its targets; round 9 closes them. The name a refusal
  gives a type was not always readable: `_type_name` raised a raw TypeError for a type whose
  metaclass leaves `type` out of its MRO, and for a type whose `__name__` is a `str` subclass whose
  metaclass leaves `str` out of its MRO, so the refusal escaped as that TypeError from the emitter,
  every producer, the budget, `statement_content_root` and the shape guard, and through the budget
  from `dsse.verify_envelope` and `verify_bundle` (BundleFormatError at c8205c18) and the three
  `verify_*_dsse` (ok=False at c8205c18); the lens's battery: 219 of 219 runs raw. Such a type is
  named `<unnamed type>` now, by the same MRO walk the getter makes, and no refusal raises while it
  names a type. A serializer that runs after the copy raised its own error: the disclosure's
  `json.dumps` in `issue_sd_jwt` and the legacy serializer start a few frames below the copy, and a
  value nested within those frames of the copy's limit raised a raw RecursionError (from one caller:
  openings 988 to 992 levels, `export_intoto_dsse`'s `harness` 984 to 989,
  `export_eval_result_dsse`'s `harness` and `anchors` 987 to 988, `export_svr_dsse`'s `policy` 986
  to 990); under `jcs-sha256-v1` the exporters raised rfc8785's FloatDomainError for NaN and the
  infinities, IntegerDomainError for 2**53 and 2**64, and the budget's BudgetExceeded for 10**5000,
  and under the legacy algorithm json's ValueError for 10**5000. Each is the entry's own refusal now
  (ValueError for an opening, BundleFormatError for an exporter), caught where the serializer is
  called, so no frame is added before it. `to_test_result_statement` raised `dict()`'s TypeError or
  ValueError for a `subject_digest` of None, 5, "ab", [1] or True; it is BundleFormatError now, and
  an object or a list of pairs is read as before. The copy let any JSON value through where an
  argument must be a string, so a message that interpolated it raised a raw ValueError
  (`root_b64=10**5000` or `content_root_alg=10**5000` at `export_intoto_dsse`,
  `subject_profile=10**5000` at `export_eval_result_dsse`, `expected_predicate_type=10**5000` at a
  verifier, and `passed=10**5000` at `svr_properties`, whose `_verdict.require_bool_verdict` wrote
  `{wert!r}`), and a number, a bool, a list or an object was written as a `url`, `keyid`,
  `root_b64`, `subject_name`, `subject_profile` or `time_created`. Every argument that must be a
  string is now checked as one on its copy (`root_b64`, `url`, `keyid`, `content_root_alg`,
  `profile`, `subject_profile`, `subject_name`, `subject_sha256`, `time_created`, and
  `expected_predicate_type` of the three verifiers, which raise BundleFormatError for it while the
  verdict on an envelope still never raises), None where the argument may be absent, and every value
  those messages and `require_bool_verdict` name is rendered with `budget.render_safe`. The copy
  read an OrderedDict with `dict.items`, its storage order, which `move_to_end` does not change:
  after `move_to_end("identifier")` `issue_sd_jwt` signed the opening `['identifier', 'salt_hex']`
  where c8205c18 and main signed `['salt_hex', 'identifier']`, and `to_test_result_statement` built
  another digest from `subject_digest=[od]`. An OrderedDict, and a subclass of it, is read in the
  order `collections.OrderedDict.__iter__` gives now, whatever its own methods say. That base method
  is C code of the standard library, but it hashes each key to find its node, so the keys are judged
  first without hashing: an OrderedDict holding a `str` subclass key that defines its own `__hash__`
  is refused, because its order cannot be read without running that code, and so is one whose own
  order names other keys than it stores. Corrected in round 10: whether a key's type defines its own
  `__hash__` was decided by reading the class dicts of its MRO, and a `__hash__` bound under a key
  that only compares equal to that name misled the reading, so such a key's hash ran inside the copy;
  since round 10 every key of an OrderedDict must be a `str` itself (below). And the
  caller-attested flags were read by their truth, the R-B4 class:
  `export_svr_dsse(env, signer, anchor_verified="false")` signed
  `PROOFBUNDLE_ANCHOR_VALID`, on main 20e91c8e too. `prereg_verified` and `anchor_verified` must be
  True or False now. What a caller sees differently, measured at ee489403: an int 0 or 1, a string,
  None, a list or an object as a flag is a BundleFormatError, where it was read by its truth; an
  argument of the list above that is not a string is a BundleFormatError, where it was written or
  raised a raw ValueError, and `export_eval_result_dsse` checks `subject_name` and `subject_sha256`
  whether or not the profile reads them; the exporters' serializer errors above, the openings'
  RecursionError and `subject_digest`'s TypeError or ValueError are the typed refusals named above;
  an OrderedDict whose own order is not its storage order is signed and returned in its own order
  (openings, `subject_digest`, the dicts the statement builders return, and `status`, which read the
  storage order at c8205c18 too and now writes main's order), and one holding a key that hashes
  through its own code is refused, where it was written in storage order (since round 10 one
  holding any key that is not a `str` itself, below); a refusal that names the
  first bad value of an OrderedDict names it in the OrderedDict's own order; and the refusal of a
  string argument says "must be a string", where it said "unknown contentRootAlg" or "unknown
  subject profile". Measured with the lens's own generator (6000 values, 1350 holding a tuple, 48
  surfaces, 288000 runs) at ee489403 and now: 3560 outputs differ (1415 in their bytes, 2145 only in
  the key order of a dict a statement builder returns), 3402 of them for a value that holds an
  OrderedDict whose own order is not its storage order and 158 for a falsy `time_created`, which
  both trees replace with the current time, so that count follows the clock of the two runs; 49131
  verdicts differ, each one of the refusals above; 22806 messages differ, each one of the messages
  above. The deepest nesting written from one caller is unchanged at 26 of 26 measured entries,
  arguments and container kinds, and none of them raises outside its typed errors in the twelve
  levels past it or at 5000. The lens's recording set runs no caller code in 89 of 89 runs, and its
  battery gives 219 of 219 typed refusals. Limits, named: the base method could still call a key's
  `__eq__` on a collision of `str`'s own 64-bit hash between two keys with different characters
  (gone in round 10, where every key is a `str` itself, whose comparison is the interpreter's); a
  type whose metaclass hides `OrderedDict`, but not `dict`, from its MRO is read as the dict its MRO
  names, in storage order; and the structural budget walks an OrderedDict in storage order, which
  decides only which of two violations it names. The contract file has 113 cases, 5693 subtests; in
  round 9 the round-8 proof passes plain booleans as the flags of `export_svr_dsse`, and the
  recording ints are a case of their own. Against the source of ee489403 its 10 new catch-proof
  cases are red, 8 of them with PASSED printed beside their failed subtests, and its 100 earlier
  cases and 3 new controls pass (pytest: 197 failed, 195 of them subtests).

  An eighth lens at 493c2f86 found the OrderedDict reading of round 9 misled, and round 10 closes
  the class instead of the instance. Whether hashing a `str` subclass key runs code of the caller
  was decided by reading the class dicts of its MRO for an entry under a key of type `str` spelled
  "__hash__", while CPython binds the hash slot by a lookup that compares keys by equality. A
  `__hash__` bound under a `str` subclass key spelled so, under a key of other characters whose own
  `__eq__` and `__hash__` claim the name, under a key that is no string, set with `setattr` over
  such a key, or inherited from such a base before `str` hashed through the caller's function, and
  the reading called it `str`'s own. Measured at 493c2f86 over the lens's 28 entry and argument
  pairs: the caller's hash ran in 28 of 28, a hash that raised escaped raw in 28 of 28 (from the
  three `verify_*_dsse` too, through `expected_predicate_type`), and a hash that deepened a sibling
  the copy had not reached yet made `canonicalize_statement` return output nested 502 deep against
  the depth bound of 64, and write 300000 list items against the bound of 200000 nodes; on main
  31816e08 the hash ran in 16 of 28 and escaped raw in 16. An OrderedDict is read in its own order
  now only when every key it stores is a `str` itself, whose hash is the interpreter's; any other
  key, a `str` subclass included, is the entry's typed refusal, naming its type, before the order is
  read. `_hasht_als_zeichen` is removed. A plain dict with `str` subclass keys is copied as before,
  because `dict.items` hashes nothing.

  A sibling the lens did not name, measured at 493c2f86 and on main: an OrderedDict whose storage
  was written past its own methods (`dict.__delitem__`) keeps in its own order a key object the
  storage no longer holds, and the base method hashes that object. With every stored key a `str`,
  its `__hash__` and `__eq__` ran and a hash that raised escaped raw (on main as KeyError or the
  raised error). The order cannot be read from Python without hashing, so the copy first bounds
  what it can hold through the interpreter's own traversal, `gc.get_referents` (CPython's
  `tp_traverse`, which names each key of the order, each stored value, the instance dict, the slots
  and a subclass's own class, and calls no method of any of them). Every object it names must be a
  `str`, `int`, `float`, `bool`, `bytes` or None, a `dict` or a `list` (no hash, so never a key), a
  stored value as often as it is stored, or once the OrderedDict's own class; anything else is
  refused. Measured on Python 3.10.12, 3.11.15, 3.12.14, 3.13.15 and 3.14.7, the versions of the CI
  matrix: the probes run no caller code and raise nothing raw on each, and the contract file passes
  on each. The corrupted OrderedDicts of the lens's p09 keep their outcomes: eleven refused as
  before, and the one refilled with its own keys written.

  The lens also found the R-B4 class at a flag and named a sibling of round 9's
  `expected_predicate_type` fix, and a sweep of the class (a caller's value decides a check through
  a method the interpreter dispatches on the caller's class) over the boolean keyword arguments and
  the compared string arguments of these modules found three more. `require_statement_shape` of
  `canonicalize_statement` and `statement_content_root` was read by its truth, at 493c2f86 and on
  main: a caller object's `__bool__` ran, a raising one escaped raw, "false" switched the guard on,
  and 0 or None switched it off. It must be True or False now, and anything else is
  ProofBundleError before anything is read, also on the bytes path of `statement_content_root`,
  which ignored it. `decode_eval_claim(expected_context=...)`, and through it `classify_eval_claim`,
  compared the caller's value through its own `__ne__`: at 493c2f86 and on main a `str` subclass
  whose `__ne__` answers False, and an object of another type with that `__ne__`, returned the claim
  of a receipt bound to another context and of one with no binding. `build_eval_claim` passed a
  `comparator` holding "==" and an `assurance_level` holding "bogus" whose `__eq__` and `__hash__`
  claimed membership; `verify_commitment` verified an `identifier` holding "other" whose `encode`
  gave the committed identifier's bytes, and a `commitment` object whose `__str__` gave the right
  value; `check_binds_bundle` bound an SD-JWT to a root it does not carry for a `root_b64` whose
  `__eq__` answers True, a `str` subclass or another object. Each now compares the characters a
  `str` holds, read with `str.__str__` (`canonical._zeichen_von`), treats a value of another type as
  its refusal (None, `invalid`, EvalClaimError, False), and `verify_commitment` reads its `salt` as
  the bytes it stores. A second lens added `svr_properties`: the `ok` of each check of the caller's
  result was read by its truth, so `Check("ed25519-signature", "false")` and
  `Check("merkle-inclusion", "false")` earned PROOFBUNDLE_SIGNATURE_VALID and
  PROOFBUNDLE_RECEIPT_UNCHANGED, as did [0], 1 and "true"; only True itself earns a check's property
  now, compared by identity.

  What a caller sees differently, measured at 493c2f86: an OrderedDict holding a key that is not a
  `str` itself (a `str` subclass or a str Enum member included, both read in its own order there),
  whose own order holds another object, or whose slot holds an object other than a plain scalar or
  a stored value, is the entry's typed refusal, and a non-string OrderedDict key is named by its type
  where the refusal said "object keys must be strings"; a `require_statement_shape` that is not True
  or False is ProofBundleError at both functions and on both paths; a `str` subclass
  `expected_context`, `comparator`, `assurance_level`, `identifier`, `commitment` or `root_b64` is
  compared by its characters and a value of another type is refused, and `build_eval_claim` stores
  the characters of `comparator` and `assurance_level` where it stored the caller's object (a str
  Enum comparator was stored as the Enum member); a `verify_commitment` salt that is a `bytes` or
  `bytearray` subclass is read as its stored bytes; and a check of `svr_properties`' result whose
  `ok` is 1, a string or another truthy value earns no property. Three changes of round 9 that its
  list left out, measured with the lens's p08 at ee489403 and now: a `str` subclass
  `expected_predicate_type` whose `__eq__` answers True gave ok True for a foreign predicate at
  ee489403 and gives ok False, because it is compared by its characters; the verify side renders
  `predicateType` and `contentRootAlg` in `content_root_detail` with `render_safe` (a 300-character
  predicate type gave a detail of 414 characters at ee489403 and of 352 now); and the
  unknown-profile message quotes the profile by repr (`"it's"`, where it printed `'it's'`). Two
  sentences were false and say what holds now: the round-9 docstring of `to_test_result_statement`
  said a `subject_digest` other than an object or a list of pairs is refused, while `dict()` reads
  `["ab"]`, `[{"k": 1, "v": 2}]` and `[[1, "x"]]` (the behaviour is unchanged); and that a key
  defining its own `__hash__` is refused without running it, that the copy runs no code of the
  caller, and that nothing the caller wrote runs between the budget and the serializer held at
  493c2f86 only for the keys the class-dict reading saw (the round-9 commit message says the first;
  corrected above and in the docstrings).

  Named, not changed, each measured at 493c2f86 and now with the same result: `svr_properties`
  looks a check up by its `name` in a dict, so a name whose `__hash__` and `__eq__` claim
  "ed25519-signature" earns PROOFBUNDLE_SIGNATURE_VALID; `check_binds_bundle` reads `claim` through
  `in` and `get` and compares its values through their own `__ne__` (values that compare equal to
  anything bind), `issuer_matches` compares the claim's issuer through its own `__eq__`, and
  `present_with_key_binding` reads `compact` through its own `endswith` and `encode`, the second
  into `sd_hash`; `loads_strict` and `load_claim_text` measure a `str` subclass `text` for the
  `input_bytes` cap through its own `__len__`; `build_eval_claim` still reads `n`, `samples`,
  `threshold` and `score` through the caller's objects, signs nothing, and the emitter and every
  producer judge its output on the plain copy; `enclave_assurance_proven` reads `eat_jws` by its
  truth and hands `expected_profile` to `experimental.enclave`. A limit of the new check: it reads
  CPython's traversal, so it holds on CPython, the interpreter the CI runs. Against the source of
  493c2f86 the 8 catch-proof cases of the first round-10 commit are red in all 344 of their subtests,
  with PASSED printed beside each case, one of them (the bytes path of `statement_content_root`, 3
  subtests) only because its refusal is new there; the round-9 case whose expected message changed
  fails; and its 112 other earlier cases and 5 new controls pass (pytest: 345 failed, 344 of them
  subtests).

  `verify_commitment` answers a bool for an input it cannot encode (second round-10 commit, on
  6b223d8e). It is documented to answer a bool and checks an untrusted presentation, and at
  493c2f86, at 6b223d8e and on main 31816e08 a `commitment` holding a character outside ASCII (a
  lone surrogate included) raised a raw TypeError from `hmac.compare_digest`, and an `identifier`
  holding a lone surrogate a raw UnicodeEncodeError from `salted_commit`. Each is False now: a
  commitment outside ASCII matches no `sha256:<hex>` and is refused before the comparison, which
  compares the ASCII bytes, and an identifier UTF-8 cannot encode cannot be the committed one; no
  method of the caller runs. An identifier outside ASCII that UTF-8 encodes verifies as before. The
  sweep for the same two raises (`hmac.compare_digest` over a `str` that may leave ASCII, `encode()`
  of a caller string that may hold a lone surrogate) over the functions this branch touches found
  no other on a verify path. Named, not changed, each measured at 6b223d8e and 493c2f86 and on
  main: `salted_commit` and `build_eval_claim` raise a raw UnicodeEncodeError for an identifier
  holding a lone surrogate (emit side), and `present_with_key_binding` raises a UnicodeEncodeError,
  a ValueError, for a `compact` outside ASCII (holder side). The legacy serializer's `encode` of a
  statement with a lone surrogate is each exporter's BundleFormatError since round 9 (a raw
  UnicodeEncodeError on main), and `issue_sd_jwt` escapes a lone surrogate in what it signs.
  `hmac.compare_digest` elsewhere in the package (merkle, policy, statuslist, bundle) is outside the
  functions this branch touches and was not measured. The contract file has 128 cases, 6067
  subtests. Against the source of 6b223d8e the new catch-proof case is red in all 6 of its subtests
  (3 TypeError, 3 UnicodeEncodeError), with PASSED printed beside it, and its control passes.

- **A verify boundary reads the caller's object once, so the bytes a signature covers are the bytes
  it parses** (round 11, lens run 10 at fa555f13, findings L1 to L6, P0, class A: "verified bytes
  and parsed bytes are two readings of the caller's object"). `evalclaim.decode_eval_claim` read
  `payload_b64` once for `verify_bundle` and once to parse it, and `classify_eval_claim` read it
  three times, each time through the caller's object; `intoto.verify_intoto_dsse`,
  `verify_eval_result_dsse` and `verify_svr_dsse` read `payload` through `dsse.verify_envelope` and
  again through `dsse.load_payload`. Measured at fa555f13 with the lens's cases (a dict subclass
  that stores the signed value and whose own `__getitem__` and `get` answer another from a later
  read on, and a `str` subclass whose own `encode` answers another value the second time):
  `decode_eval_claim` returned a claim the signature does not cover (`passed` True, `suite`
  "forged-suite"), `classify_eval_claim` gave `valid` for it, and the three DSSE verifiers returned
  ok=True over a statement nobody signed (a test result PASSED against a signed FAILED, and SVR
  properties nobody signed). The lens measured the same on main 31816e08. The issuer binding of
  `decode_eval_claim` read `signature.public_key_b64` a second time as well: a claim signed by one
  key and naming another as its issuer was returned.

  The caller's object is read once now, by what it stores, and nothing reads it again. A bundle goes
  through `evalclaim._eine_lesung` (a path through `load_bundle`, an object through the structural
  budget and the plain copy `canonical._plain_for_jcs`); `bundle._verify_bundle`, the body of
  `verify_bundle`, returns the payload bytes its signature check read, and those are the bytes
  parsed; the issuer binding reads the key from the same copy. An envelope goes through
  `dsse._read_once` (the budget, then the plain copy), and `dsse._verify_and_load` returns the
  verdict with the payload bytes it judged, which the three in-toto verifiers parse. No
  `__getitem__`, `get` or `__contains__` of a dict subclass and no `encode` of a `str` subclass
  runs: a recording subclass over every dict, list, key and string of the object counts no call at
  the five surfaces, where it counted eleven methods at fa555f13 (among them `get`, `__getitem__`,
  `__contains__`, `__iter__`, `__eq__`, `__hash__` and `encode`). `verify_envelope` and
  `load_payload` are unchanged.

  What a caller sees differently: an object holding a value that is no JSON value (bytes, a set, a
  key that is not a string, two keys with the same characters) is refused at these surfaces (None,
  `invalid`, ok=False), where fa555f13 ignored a field it did not read and returned the claim or
  ok=True; a tuple is read as the array JSON writes it. A parsed file holds only plain JSON values,
  so nothing changes for one, and nothing changes for the Rust verifier, which reads files.
  Tests: `tests/test_verified_bytes_are_the_parsed_bytes.py` carries the lens's cases L1 to L10 from
  e664c010 (L8 in the lens's d6c12c73 form, with its seeds written out), its L13 to L21 from
  7753961d, and this round's own; each is red at fa555f13 and green here, on Python 3.10 to 3.14.

  The owner decided the scope of the class (option A): every `dsse.load_payload` site reads once.
  Measured at fa555f13 with the lens's construction (the envelope stores a statement S1 that the
  verifying key signed and the verifier refuses; the subclass answers S2, a valid statement signed
  by another key, from read `after + 1` on; both controls give ok=False): `decision.py:567`
  (`verify_decision_receipt`), `verification_summary.py:223`, `run_ledger.py:275`,
  `outcome.py:599`, `relation_statement.py:215`, `agent_review.py:2300` (`verify_agent_review`,
  v0.1) and `agent_review.py:2626` (`verify_agent_review_v02`) returned ok=True over S2 at
  after=1, and `agent_review.py:3044` (`verify_agent_review_any`, the version switch) at after=2.
  `trust_pack.py:463` (`verify_trust_pack`) read `payload` once but `signatures` twice, for the
  cap and for the threshold loop: with 20 000 entries answered from the second read, the cap judged
  the stored three and the loop checked 20 000 signatures (2.0 s; the cap is 512). Each site reads
  once now, through `dsse._verify_and_load`, or through `dsse._read_once` where no
  `verify_envelope` is called (the switch, which hands the copy to the verifier it chooses, and the
  trust pack). The CLI's `--with-related` reader (`cli.py:1842`) reads a parsed file and changes no
  verdict; it uses the same call, so that no function pairs `verify_envelope` with `load_payload`.
  A static test holds that: eleven functions paired them at fa555f13. The lens's L13 to L19
  (7753961d) measure the same sites with a second construction: the verifying key signs a statement
  the verifier refuses on one signed field, and a dict subclass, or a `str` subclass in `payload`
  whose own `encode` answers, gives the statement with that field changed from read 2 on (read 3
  through the version switch). At fa555f13 each site gave ok=True for it; here none does.

  The native bundle has the same class beside the five surfaces, and the sweep measured three more
  readers at fa555f13. `verify_bundle` read `payload_b64` and `merkle` again for the SD-JWT
  binding: an SD-JWT issued for receipt B (passed True) grafted onto receipt A (passed False) is
  refused, and with the second reads answering B's fields it verified ok=True. It reads the plain
  copy of the bundle now, after the budget, and so do its direct callers; an object whose
  `__class__` claims dict and which holds another type is its BundleFormatError, where a raw
  AttributeError escaped. `intoto.export_svr_dsse` read the bundle in `decode_eval_claim`,
  `verify_bundle` and `recompute_merkle_root_b64`, and signed an SVR whose subject binds another
  receipt's root; it reads once now. `hf_evals.to_eval_results_entry` read it in `verify_bundle`,
  `decode_eval_claim` and for `payload_b64`, and built an entry whose value contradicts the signed
  verdict; the one reading of `decode_eval_claim` closes it. One existing case changed with it:
  `tests/test_ablehnungstext_rendert_beschraenkt.py` pinned the refusal text of a bundle holding the
  key 5 beside the unknown field "zzz" ("unknown field(s)"); the copy refuses the non-string key
  first now ("object keys must be strings", still BundleFormatError with a bounded text), and the
  case pins that text and, for "zzz" alone, the unknown-field text it pinned before.

- **A permissive flag is True or False** (round 11, lens run 10 at fa555f13, finding L7 and the
  class-B sweep, P1). `hashalg.resolve_hash_alg` and `compute_digest` read `allow_deprecated` by its
  truth: measured at fa555f13, "false", "no", 1 and [0] opened the gate for sha1 and md5. It must be
  True or False now, and anything else is refused before the id is read (this round's own
  ProofBundleError through `canonical._flagge`; PR 291's SwitchTypeError since the chain carries
  it, see the first entry). The sweep measured the bool keywords the lens named and the other
  `allow_*` keywords of `src/` with False, True, "false", 0 and an object whose `__bool__` records
  its call. Five more
  opened a gate for "false" at fa555f13 and are refused the same way:
  `anchors.verify_anchors(allow_pending=...)` let a pending anchor satisfy `require`,
  `renewal.verify_sequence(allow_unauthenticated_anchor=...)` verified an unauthenticated sequence
  ok=True, `hf_evals.to_eval_results_entry(allow_value_mismatch=...)` built an entry whose value
  contradicts the signed verdict, `trust_pack.verify_trust_pack(allow_unverified_rotation=...)`
  accepted a rotation-claiming pack on its own self-signature, and
  `agent_review.render_disclosure_line(leaf_witnessed=...)` dropped "not yet in a witnessed
  checkpoint". `verify_sequence` and `verify_trust_pack` give a fail-closed verdict naming the flag,
  because they never raise; the others raise (SwitchTypeError, see the first entry). Not changed,
  because "false" reads as True there and a truthy value closes the gate: `strict`,
  `require_derived_subject`, `require_canonical`, `require_signature_line` and `applicable`; `include_token` switches content,
  not a gate. Named, not changed: a falsy non-bool (0, None) reads as False at each of these, which
  is the lenient branch where the default is True (`to_eval_results_entry(require_verified=0)`
  built an entry from a receipt that does not verify; `require_signature_line` is a private
  keyword whose callers pass literals). The lens's L20 and L21 (7753961d) hold `allow_pending` and
  `allow_value_mismatch` too. Named, not changed here: the lens's sweep (7753961d) found two more
  flags that open for "false", `legacy_v01` of `agent_review.emit_agent_review`,
  `require_valid_agent_review_predicate_any` and `render_disclosure_block` (a v0.1 predicate judged
  under the legacy rules) and `bound` of `adapters._provenance.bind_reported_version` (the version
  written as `reported`), and it measured the falsy limit above at `applicable` of
  `assurance.classify_digest_evidence` and `strict` of `decision.emit_decision_receipt`. Its cases
  for these, L22 to L25, were red at this round's head and are green at the head of pull request 291
  (76365006), which fixes those flags and which the 6.2.0 chain carries.

- **The trust-pack patterns hold the schema's ECMA-262 meaning** (round 11, lens run 10 at
  fa555f13, finding L8, P1, `src/proofbundle/trust_pack.py`). `_RFC3339_Z`, `_SHA256_HEX` and
  `_SEMVER_0_1_X` were `^...$` with `\d` under Python `re`, where `$` also matches before a final
  newline and `\d` matches every Unicode decimal digit; JSON Schema names ECMA-262 for `pattern`,
  where `$` ends the input and `\d` is [0-9]. Measured at fa555f13: a hex digest, `expires` and
  `schemaVersion` ending in a newline, and `expires` and `schemaVersion` holding Arabic-Indic digits
  validated as []; the lens measured all five refused by node v22.22.2. The three are `\A..\Z` with
  [0-9] now, and so is `_parse_rfc3339_z`, which parsed both kinds of `expires`. Named, not changed:
  eleven patterns in `decision`, `outcome`, `run_ledger`, `verification_summary`, `agent_review`
  and `relation_statement` are `\A..\Z` but still `\d`, and each matches Arabic-Indic digits
  (measured here and on fa555f13); branch 234 (e5b39b81) moves them to one module with [0-9], after
  6.2.0. The twelfth, `relation._RFC3339_Z`, takes [0-9] since the `declaredAt` entry at the top of
  this section, because the Rust verifier reads that field and refused what it accepted.

- **The pair form of `emit_eval_receipt` refuses a duplicate key** (round 11, lens run 10 at
  fa555f13, finding L9, P1). The copy refuses two keys with the same characters in an object, and
  the documented pair form (a list of `[key, value]` pairs) went through `dict()`, which keeps the
  last: measured at fa555f13, `passed` False then True was signed as True, and True then False as
  False. A key that comes twice is `EvalClaimError` naming it now, in either order.

- **`svr_properties` withholds a property when any check of its name failed** (round 11, lens run
  10 at fa555f13, finding L10, P1). The checks of the caller's result were folded into a dict by
  name, so the last of two checks named `ed25519-signature` decided: measured at fa555f13, False
  then True earned PROOFBUNDLE_SIGNATURE_VALID, True then False did not. A property is earned now
  only when its name has at least one check and every check of that name has `ok` True, in any order:
  the conjunction `VerificationResult.ok` applies to the whole result. Refusing a repeated name was
  the other rule; it would make a result that records a check once per signer an error on a surface
  whose output lists passing properties only, where withholding is already the fail-closed answer.
  `verify_bundle` names each check once and `export_svr_dsse` builds its own result, so neither
  changes. Named, not changed: `bundle.root_authenticity_summary` folds the checks the same way
  (measured: `payloadSignature` PASS for False then True, FAIL for True then False), and so do two
  readers in `cli.py` (read, not measured).

- **Every public verify and emit surface reads the caller's objects once, by what they store**
  (round 12, lens run 11 at cd5d39f4: F1 to F3 P0, F4 to F7 P1, and O1 and O2 outside its targets;
  class A of round 11, "the bytes a check judges and the bytes a signature covers are two readings of
  the caller's object", at the surfaces round 11 did not touch). The rule: a surface reads each value
  the caller passes once, into a plain copy of exact built-in types, from what the object stores and
  never through a method its type defines, and every check, parse, signature check and write uses only
  that copy. A dict or list goes through `canonical._plain_for_jcs`, a string through
  `_zeichen_von` (`str.__str__`), bytes through the new `_bytes_von` (the base type's own slice), an
  integer through `_ganzzahl_von` (`int.__index__`), a single field of a dict through `_feld_von`
  (the stored pairs, compared by characters: `dict.get` compares a stored `str` subclass key through
  its own `__eq__`), and a list, tuple or set through `_folge_von` (the base type's own iteration). A
  value that cannot be copied so is refused with the surface's documented typed error or fail-closed
  verdict.

  Measured at cd5d39f4, each red there and green here on Python 3.10 to 3.14
  (`tests/test_one_reading_at_every_surface.py`):
  - F1 `policy.evaluate_policy` read the signer pin and the stated root through the bundle's own
    `get` while `verify_bundle` verified what it stores: a bundle signed by a key the policy does not
    trust got policy_ok True when its own `get("signature")` named a trusted key, when its
    `public_key_b64` was a `str` subclass claiming that key through `__eq__` and `__hash__`, and when
    its own `get("merkle")` answered a trusted root. It reads the plain copy now, and so does
    `load_policy` for a dict (`copy.deepcopy` rebuilt a dict subclass as itself).
  - F2 `adapters.agt_receipt.verify_agt_receipt` covered `receipt[f]` with the signature and judged
    the expiry at `receipt.get("timestamp")`: an authorization that expired at the signed timestamp gave
    ok True. The receipt, the chain (`verify_agt_receipt_chain`), the trusted keys and `now` are read
    once.
  - F3 `checkpoint.verify_checkpoint` took the note text as the caller's own slice: a `str` subclass
    gave ok True with tree size 999 for a note signed with tree size 5. `_split_signed_note` reads the
    characters once, for every surface of the module and for tlogproof, rootcommit and
    public_transparency; the vkey parsers, the witness roster (a `str` subclass's own `split` made one
    witness count as two in `witness_quorum`) and the emitters read by characters and stored integers
    and bytes as well.
  - F4 and F5 `hf_evals.to_eval_results_entry` read `payload_b64` a third time for its "is this an
    eval claim" rule, and `receipt_token` wrote the token through the bundle's own `items()`: an eval
    claim that does not decode was published with a value the signed verdict contradicts, and the token
    held another receipt than the one judged. The bundle is read once (`evalclaim._eine_lesung`), and
    the token is the plain copy.
  - F6 `agent_review.resolve_receipt_chain` took the digest from one reading of each envelope and the
    supersession claims from another: the chain was ordered by a claim nobody signed. Each envelope's
    stored payload is read once.
  - F7 `hf_evals.verify_receipt_token` counted the caller's own `len()` for its pre-decode cap and
    decoded the caller's own slice. It reads the characters once.
  - O1: an expected value the caller supplies was compared through its own `__eq__` or `__ne__`, and a
    `str` subclass answered a match for another value at `agent_review` (`expected_subject_digest`),
    `decision` (`expected_nonce`, `expected_audience`), `outcome` (`expected_decision_ref`),
    `statuslist` (`expected_uri`), `checkpoint` (`expected_origin`) and `public_transparency`
    (`expected_root_b64`). Each is compared by its characters now, as round 10 did for
    `expected_context`; the same holds for kbjwt's `expected_aud` and `expected_nonce`, tlogproof's
    `expected_origin` and dsse's `payload_type` (swept, see below).
  - O2: `evaluate_decision_policy` read `decision_receipt.allow_pending` by its truth when the policy
    skipped `load_policy`, so "false" and 1 let a pending anchor satisfy `require_external_anchor`. It
    is True or False now; anything else is a fail-closed error naming it (with the loader's message
    since the chain carries PR 291, `policy._check_bool_fields`).
  - The sweep's verdict-level cases: `signature.verify_ed25519_pinned` judged the key through one
    `bytes()` of the caller's object and verified under another, so a `bytes` subclass that answered a
    sound key to the rule and the identity point to the check verified the signature (identity, 0) with
    no private key; `witness_quorum` counted one witness twice (above); `evidence_pack.verify_evidence_pack`
    bounded what the pack stores and decoded what its own `__getitem__` answered.
  - A class claim is no type (found by this round's own sweep, outside the lens's targets): an object
    that is no str, dict, list, bytes or number but claims one through `__class__` passes
    `isinstance`, which reads that claim. The copies passed such a value on unread, and the guard
    after them let it through to its own methods. Measured on this tree before the guards changed:
    `verify_receipt_token` decoded 64 MiB behind a claimed length of 12 again (F7 through another
    door), and 26 of the 86 sweep surfaces ran methods of such an object. `_pruefkopie` and
    `_eine_kopie` copy every value now, so one that is no JSON value is refused, and every guard
    after a copy asks `type()`.

  THE SWEEP, measured: 86 public verify, classify, evaluate and emit surfaces fed every caller value
  as a recording subclass that answers exactly what it stores. At cd5d39f4, 77 ran a method of the
  caller's values and 9 ran none (the round-8 to round-11 surfaces: `decode_eval_claim`, `classify_eval_claim`,
  `emit_eval_receipt`, `verify_commitment`, the three in-toto exporters, `svr_properties`,
  `verify_trust_pack`); here none runs one and each returns what it returns for the plain values. The
  second pass feeds every top-level value as an object that claims its type through `__class__`
  (`AClassClaimIsNoType`): at cd5d39f4 56 surfaces run its methods (57 on Python 3.12 to 3.14,
  where `emit_bundle` hashes claimed bytes through their own `__buffer__`), here none does, except one
  iteration of an argument that is documented as any iterable, at the three surfaces that take one
  (`resolve_receipt_chain`'s receipts, `emit_bundle`'s prior leaves, `evaluate_public_transparency`'s
  witness roster), the only reading such a value has. The
  chokepoints that closed most of them at once: `_wire_b64._as_bytes` (every base64 decode read a
  `str` subclass through its own `encode`), the three signature primitives, `dsse.verify_envelope` and
  `load_payload` (they read through `_read_once` now, which makes the `_verify_and_load` docstring true:
  lens run 11 F8 measured the two answering differently), the Merkle verifiers (the step cap counted a
  list subclass's own `len()` and the loop read its own `__iter__`), the note framing, and one copy at
  the entry of each DSSE emitter and each predicate validator (a dict subclass's own `get` showed the
  validator a valid predicate while the stored one was signed).

  What a caller sees differently, measured at cd5d39f4 against this tree: an input holding a value
  that is no JSON value is refused at these surfaces (`verify_envelope` answered True and `load_payload`
  returned the payload for an envelope with a bytes field; `receipt_token` raised a raw TypeError); a
  tuple is read as the array JSON writes it, so `verify_envelope` accepts a tuple of signatures and
  `load_policy` a tuple of schema versions, where cd5d39f4 refused both; `to_eval_results_entry` loads a
  path once and writes its token, where cd5d39f4 refused the token; `issue_status_list_token` refuses
  `bits=True`, which it signed as `"bits": true`; `sign_envelope` refuses a key id that is no string.
  A value that is no JSON value, or whose type is no built-in, is refused by its type where it was
  read before: a validator returns "predicate is not a JSON value: a value of type bytes is not a JSON
  value" for bytes or an object, where it returned "predicate must be a JSON object", and an emitter
  raises its own error with that text; `explain_policy` and `lint_policy` raise PolicyError for such a
  policy, where a raw AttributeError escaped; `verify_anchors` raises BundleFormatError for a
  `require` of such a type, where it gave FAIL (a `require_target` or `anchors` of such a type was
  refused before as well, and its refusal names the type now);
  `verify_outcome_receipt` does not establish role separation for a `decision_maker_id` of such a
  type (True at cd5d39f4; an exact int is compared as before); `root_from_inclusion` raises TypeError
  with its own message for an index or size that is no integer (a TypeError from the arithmetic
  before); `verify_dual_hash` refuses a non-contiguous `memoryview` as not bytes-like, where a raw
  BufferError escaped; the status list refusal names a clock of such a type by its type;
  `classify_receiver_corroboration` never binds an expected key that is no bytes-like value (a raw
  TypeError for a str key at cd5d39f4). Nothing a surface took is narrowed: a `memoryview` and a
  `bytearray` at 26 inputs of 21 bytes-taking surfaces answer as at cd5d39f4
  (`canonical._puffer_von` reads a `memoryview` where the concatenation or `==` took it; the
  `ABytesLikeValueIsReadWhereItWasReadBefore` cases pin that, green at both trees).
  A parsed file holds only plain JSON values, so nothing changes for one: the conformance corpus with
  `--require-anchors` (135 of 135 fully checked), the 439-file JSON differential (155 artefacts, 1833
  verdict lines) and 17 artefact kinds emitted with real keys are byte-identical to cd5d39f4. One
  existing case changed with it, as in round 11: `tests/test_ablehnungstext_rendert_beschraenkt.py`
  pinned the finding of `validate_decision_predicate` for a predicate holding the key 5 beside the
  unknown field "zzz" ("unknown top-level field(s)"); the copy refuses the non-string key first now
  ("object keys must be strings", still a returned finding), and the case pins that text and, for
  "zzz" alone, the finding it pinned before.

  Named, not changed: a caller's own callbacks and result objects (the resolvers, `result` of
  `evaluate_policy` and `svr_properties`, `consistency_result` of `evaluate_public_transparency`) are
  the caller's code by design; a `Mapping` that is no dict can only be read through its own `items()`,
  once, and a buffer that is no bytes, bytearray or memoryview is hashed once through its own buffer
  (`compute_digest`, the resolvers' artifact bytes); `renewal`, `agent_review.apply_time_evidence`
  and the renderers (a refusal text may still render a caller's value through `render_safe`), the
  per-anchor verifiers (`anchors_ots`, `anchors_rfc3161`, `anchors_chia`, `anchors_markovian`), the
  adapters other than AGT and the `experimental` package were not swept.

- **Code a caller hands in promotes a verdict only when it answers the exact True**
  (`assurance.classify_digest_evidence`, `assurance.classify_receiver_corroboration`,
  `renewal.verify_sequence`, `anchors.verify_anchor`). Each of these calls code its caller supplies and
  promoted on the truthiness of the answer, although the documented contract is a bool:
  `bool(evidence_resolver(digest_obj))` lifted a digest from `REFERENCE_WELL_FORMED` to
  `CONTENT_RESOLVED`; `bool(res)`, in the branch of `classify_receiver_corroboration` with neither 32
  bytes of key material nor an expected key, lifted a receiver ref to `INDEPENDENTLY_ATTESTED`;
  `bool(verify_anchor(newest))` anchored the newest ArchiveTimeStamp in the `anchor_verifier` mode; and
  `verify_anchor` read the result of a verifier registered through `register_anchor_type`, a public
  extension point, with `bool(res.get("ok"))`, `bool(res.get("warn"))` and `bool(res.get(flag))` for
  `rp_trusted`, `needs_rp_trust` and `frozenEvidence`.

  Measured on main 20e91c8e: the answers `1`, `1.0`, `"true"`, `"false"`, `[0]` and an object whose
  `__bool__` says True promoted on every one of these surfaces, directly and through
  `verify_decision_receipt` and `verify_outcome_receipt`, which pass `evidence_resolver` and
  `receiver_attestation_resolver` on; a truthy evidence answer next to an attestation resolver answering
  True took a digest nobody had resolved to `INDEPENDENTLY_ATTESTED`. `verify_sequence` returned ok for
  an anchor verifier answering `"false"` or `1`. A registered anchor verifier answering
  `{"ok": "false"}` met `verify_anchors(require="any")` and gave `anchors_ok` true and an aggregate `ok`
  true in `verify_decision_receipt(anchors=...)`; `{"ok": False, "warn": "false"}` turned a failed
  anchor into a pending one that met `require` with `allow_pending`; and a result that is not a dict
  (`True`, `None`, a list, a string, an int) raised a raw AttributeError out of `verify_anchor`,
  `verify_anchors` and the never-raise `verify_decision_receipt`, because the result was read outside
  the `try` that guards the verifier call.

  Now only the exact `True`, or where a key is asked for 32 bytes of key material in a plain `bytes` or
  `bytearray` object, promotes, anchors or counts. Any other answer leaves the level, the anchor check or
  the flag where it was (round 2 below: the first version of this sentence did not hold for an answer
  that only claims to be bytes); none of the answer's own methods is called and the answer is never
  rendered into a detail; and when the answer is not a bool at all, the detail says so and says that
  only the exact True counts. A registered anchor verifier's result is read only when it is a plain
  `dict`; anything else, a dict subclass with its own `get` included, is a failed anchor whose detail
  says the verifier returned no result object. Unchanged, and held by controls: the exact `True`
  promotes, the exact `False` does not and keeps the detail it had, a raising resolver still counts as
  False, a raising anchor verifier is still a failed anchor, and 32 bytes of key material still attest;
  the expected-key branch of `classify_receiver_corroboration` is not touched. The package's own
  verifiers on these paths already return exact bools, read line by line: the authority-signature and
  no-anchor modes of `verify_sequence` and its structural mode for an `anchor_status` that is a str, and
  the anchor verifiers for `rfc3161-tsa`, `opentimestamps`, `chia-datalayer/v1` and the opt-in
  `markovian-provenance/v1`. The per-anchor `status` a registered verifier reports is
  still carried as given; no gate in the package reads it, only `ok` and `warn`.

  Reach: the Python API only. The CLI sets none of these resolvers and registers no anchor type beyond
  the built-ins. The same lines stand in the tagged files of v6.0.0 (4e32e83b) and v6.1.0 (dcac5aee),
  so the released 6.0.0 and 6.1.0 carry the old behavior. Contract
  `tests/test_a_resolver_promotes_only_on_exact_true.py`: against 20e91c8e, 87 subtests fail in 11 of
  its 16 cases, each on the promotion itself or, for a result that is not a dict, on the raw
  AttributeError; the five control cases are green there. With this change all 16 cases and all 87
  subtests pass.

  **Round 2: a type check that believes the answer, and the verdicts a caller builds** (`assurance`,
  `outcome`, `verifier_block`, `policy`, `bundle`, `automation_verdict`). The first version of this
  entry said that any other answer leaves the level where it was. Measured at 6d102950, the first
  version of this change, and on main 31816e08 alike, that was false on the one branch it did not
  touch: `classify_receiver_corroboration` asked `isinstance(res, (bytes, bytearray))`, which believes
  an object's own `__class__`, and then read the object with its own `__len__` and `__bytes__`. An
  answer whose `__class__` says `bytes`, whose `__len__` says 32 and whose `__bytes__` gives `b""`
  reached `INDEPENDENTLY_ATTESTED` with zero bytes of key material, also through
  `verify_outcome_receipt` with `ok` true; a raising `__len__` or `__class__`, or a `__bytes__` that
  returns a str, escaped both functions, which never raise; and a real `bytes` subclass was read the
  same way. `verify_outcome_receipt` repeated the check for `receiver_role_trusted`, and
  `pack_key_binds_signer` for the key it is handed. Key material now counts only as a plain `bytes` or
  `bytearray` object (`assurance._is_key_material`, one predicate for both modules). A `bytes`
  subclass is refused as well, because its `__len__` and `__bytes__` are the caller's code; such an
  answer takes the branch of an answer that is neither True nor key material. The expectation
  `expected_receiver_public_key` is judged the same way (`"abc"` raised a raw TypeError out of
  `bytes()`). The key ids that decide independence and role membership count only as a plain `str`
  (`classify_receiver_corroboration`, `receiver_trusted_by_role`, `executor_trusted_by_role`,
  `pack_key_binds_signer`): a key id whose `__class__` said str had its own `__eq__` decide, measured
  as `INDEPENDENTLY_ATTESTED` for a receiver key id whose `__eq__` said False, and as role membership
  for a key id that is not in the role. `evidence_ladder_best` and `evidence_ladder_summary` take a
  level only as a plain `int` or `EvidenceLevel` in a plain `dict`: a level whose `__class__` said
  int decided the rollup with its own comparisons, and a raising `__class__` escaped both. The digest
  object `classify_digest_evidence` classifies counts only as a plain `dict` holding a plain `str`: one
  whose `__class__` raised escaped a function that never raises, and one that only claimed to be a dict
  reached `REFERENCE_WELL_FORMED` through its own `get`. `verify_bundle(expected_tree_size=)` compares
  the pin only as a plain `int`: a pin whose `__class__` said int and whose `__eq__` said equal passed
  the tree-size check, and a raising `__class__` escaped `verify_bundle` raw.

  The same rule, one level up, for a verdict or flag the caller builds. `build_test_result_statement`
  read a case's `ok` with `not r.get("ok")`, so `"false"`, `"FAIL"`, `1` and `[0]` made the case and
  the statement PASSED, and `sign_test_result_statement` signed it; a case `ok` that is not a bool is
  now a `VerifierBlockError` naming the case. `evaluate_policy` gated on `result.ok`, which
  `VerificationResult` folds by the truth of each check, and read `Check.ok` by its truth: a
  caller-built `Check("root-authenticity", "false")` gave `policy_ok` true under
  `require_authenticated_root`, and the same string on `sd-jwt-key-binding` or
  `sd-jwt-issuer-signature` satisfied `require_key_binding_when_cnf_present`, `require_nonce` and
  `expected_vct` (measured on a real key-bound SD-JWT bundle). Crypto now passes that gate only when
  every check's `ok` and `result.ok` are the exact True (`bundle._checks_passed`); otherwise the
  policy is not evaluated and the reason names each value that is not a bool. `root_authenticity_summary`
  read `Check.ok` by its truth, blocked on `policy_ok`, `anchor_ok`, `public_transparency_ok` and
  `replay_ok` only when they were the exact False, on `policy_expired` and `policy_not_yet_valid` only
  when the exact True, and on `requires_identity_overlay` and `policy_warnings` by their truth;
  `automation_summary` read crypto and structure with `bool(value)` and counted a reference as
  unresolved only on the exact False. Each left `safeForAutomation` true for a string, and
  `{"crypto_ok": "false", "structure_ok": "false", "evidence_bound": "false"}` read as `cryptoValid`
  true. In both summaries a value that is not a bool now never passes, and the summary carries
  `notBooleanInputs` with the names of those values; the key is absent when every input is a bool, so a
  caller that passes bools sees the shape it saw before.

  `evaluate_decision_policy` and `evaluate_policy` read the boolean policy fields by their truth or
  with `is True`. Through `verify_decision_receipt(policy=<dict>)` without `load_policy`,
  `allow_raw_inputs: "false"` and `allow_pending: "false"` gave `policy_ok`, `ok` and
  `safeForAutomation` all true, `requiresIdentityOverlay: "true"` let a raw template authorise, and
  `require_*: 0` switched a requirement off. `load_policy` refuses each of these, and the evaluators
  left types to it. They now refuse a boolean field that is not a bool with the loader's own checker
  and message (`_check_bool_fields`, the loader's `_require_bool` over one table of the boolean
  fields); a contract test derives the boolean fields from `load_policy` itself, so the two paths
  agree field by field. `lint_policy` reports the same message, and `policy_warnings` counts only the
  exact True as a signer requirement. `_require_bool` itself asked `isinstance`, so an object whose
  `__class__` says bool passed `load_policy`; it asks `type()` now, which agrees with `isinstance` for
  every real bool.

  Reach: the Python API only. The CLI loads every policy through `load_policy` and passes exact bools
  to both summaries. Contracts: `tests/test_a_resolver_promotes_only_on_exact_true.py` gains 12 cases
  with 55 subtests; against 44e12b72 (6d102950 merged with main 31816e08), 47 subtests fail in 8 of
  them and the four controls are green. The new `tests/test_a_caller_verdict_counts_only_as_a_bool.py`
  had 21 cases with 268 subtests; against 44e12b72, 14 of its cases are red, 250 subtests fail in 11
  of them and 4 fail outside a subtest (one of those inside as well), and the seven others are green
  there: six controls, and the check that the derivation of the boolean fields finds every section.
  Each red subtest fails on its own defect: a verdict, an escaped exception, a refusal that did not
  happen, a missing detail, or a recorded call of the caller's own method. With the round-2 change all
  49 cases and all 410 subtests of the two files passed, on Python 3.10, 3.11, 3.12, 3.13 and 3.14.

  **Round 3: the flags, type checks and str verdicts the round-2 text left open** (`anchors`,
  `hashalg`, `renewal`, `trust_pack`, `hf_evals`, `agent_review`, `_membership`, `sdjwt_vc`,
  `public_transparency`, `errors`, `verifier_block`, `bundle`, `policy`, `relation`). The round-2
  version of this entry listed them as not closed. Measured at 67bb104e, the round-2 commit:

  A permissive flag relaxed its check on the flag's truth. `anchors.verify_anchors(allow_pending="false")`
  let a pending anchor meet `require`; `hashalg.resolve_hash_alg("sha1", allow_deprecated="false")`,
  and `compute_digest` through it, accepted a deprecated hash;
  `renewal.verify_sequence(allow_unauthenticated_anchor="false")` switched on the structural-only mode
  and returned ok; and `trust_pack.verify_trust_pack(allow_unverified_rotation="false")` accepted a
  rotation nobody had verified. A sweep of every permissive keyword flag in `src` found two more:
  `hf_evals.to_eval_results_entry(allow_value_mismatch="false")` skipped the value-verdict consistency
  check, and `agent_review.render_disclosure_line(leaf_witnessed="false")` dropped the "not yet in a
  witnessed checkpoint" caveat. Now only the exact True relaxes. The functions that raise typed errors
  refuse a flag that is not a bool with their own error (`BundleFormatError`, `HashAlgError`,
  `AgentReviewError`); the two verifiers that report instead of raising keep the check and say that
  the flag is not a bool (the `renewal:last_anchor` detail, the trust pack's rotation error). No method
  of the flag runs. The flags that tighten a check (`strict`, `require_*`) are not in this class: a
  string `"false"` makes them stricter, not weaker.

  A type check believed the value's `__class__`. `_membership.is_bool` and the boolean field checks of
  `sdjwt_vc.validate_vc_policy` and `public_transparency.validate_public_transparency_policy` asked
  `isinstance`: an object whose `__class__` said bool passed and then decided with its own `__bool__`,
  and one whose `__class__` raised escaped `is_bool`. They ask `type(x) is bool` now; `bool` cannot be
  subclassed, so the two tests agree for every real bool, and the callers of `is_bool` behave as before
  for real bools. `VerificationResult.ok` folded its checks by their truth, so a caller-built
  `Check("x", "false")` made the result ok; it counts a check only when its `ok` is the exact True, and
  `Check.__str__` marks it the same way.

  A str verdict was compared with the caller's own `__eq__`. A case `scope` whose `__eq__` said it
  equals `"full"` made the case PASSED instead of WARNED in `build_test_result_statement`; a
  `checkpoint_authenticity` doing the same gave `root_authenticity_summary` the root trust level
  CHECKPOINT; an `anchor_status` doing the same met the anchor requirement of
  `evaluate_decision_policy`. Each is read only as a plain str now; anything else takes the branch that
  does not pass (WARNED, NOT_EVALUATED, no anchor status) and none of its methods runs. The sweep found
  the same in two more evaluators. `agent_review.evaluate_time_policy` accepted an axis state whose own
  `__eq__` and `__hash__` answered its membership test; a state that is not a plain str is now
  NOT_EVALUATED. `relation.evaluate_relations_policy` compared an edge's relation, resolution and target
  digest with the caller's methods and read `supersededByAttached` by its truth: a resolution that
  claimed to be VERIFIED met `require_relation_resolution`, one that claimed not to be skipped the
  same-key check, a target digest that claimed to be the pinned root passed `require_relation_target`,
  and a `supersededByAttached` whose `__bool__` said False hid a supersession. It reads plain values
  now: an edge whose relation is not a plain str fails every rule that is set, a required relation
  resolves only as the plain str VERIFIED, the same-key check runs unless the resolution is a plain str
  other than VERIFIED, and only None and `""` mean not superseded. Its flags `reject_superseded` and
  `reject_retracted` are refused with the loader's `_require_bool` message when they are not bools, as
  the two other evaluators refuse theirs since round 2.

  Reach: the Python API only; on these paths the CLI and the package's own verifiers pass exact bools
  and plain strs. Not closed here, measured and left to their own change: `intoto.svr_properties` and
  `intoto.export_svr_dsse` still read `prereg_verified` and `anchor_verified` by their truth (another
  change edits that file in this round); and an expectation a caller passes as a str
  (`known_newest_token_digest` in `verify_sequence`, `prev_version_digest` in `verify_trust_pack`, the
  `expected_*` arguments of the decision, outcome, key-binding and checkpoint verifiers) is still
  compared with the caller's own `__eq__`, a neighbouring class in which the caller decides against
  itself, not for a document. Contract: `tests/test_a_caller_verdict_counts_only_as_a_bool.py` gains
  22 cases with 48 subtests; against 67bb104e, 18 of them are red (44 subtests fail in 12 cases, and 7
  cases fail outside a subtest, one of those inside as well) and the four controls are green. Each red
  case fails on its own defect: a refusal that did not happen, a verdict, a recorded call of the
  caller's own method, or an escaped exception. With this change the two files have 71 cases and 458
  subtests, and all of them pass on Python 3.10 and 3.12.

  **Round 4: a switch counts only as an exact bool, everywhere, and an honest subclass of the
  documented type is read as what it stores** (`assurance`, `adapters._provenance`, `adapters.eee`,
  `agent_review`, `anchors`, `anchors_chia_add`, `decision`, `outcome`, `run_ledger`, `trust_pack`,
  `verification_summary`, `hashalg`, `hf_evals`, `renewal`, `bundle`, `_integration`, `_membership`,
  `errors`). A review of 3a8074fc, the round-3 commit, measured three switches that still read their
  value by its truth, and one regression of round 1:

  - `assurance.classify_digest_evidence(applicable=)`, and `classify_receiver_corroboration`, which
    passes it on: `None`, `0`, `""` and `[]` made a weak field not applicable, and
    `evidence_ladder_summary` rose past it (CLAIMED and CONTENT_RESOLVED summarised to CONTENT_RESOLVED).
  - `adapters._provenance.bind_reported_version(bound=)`: `"false"`, `"no"`, `1` and `[0]` wrote the
    version with status `reported` into a provenance block that is signed into the receipt.
  - `agent_review.emit_agent_review(legacy_v01=)`: `"false"` and `"no"` issued and signed a v0.1
    predicate under the v0.1 rules, which `False` refuses under the v0.2 rules. The renderers
    (`render_disclosure_block`, `render_disclosure_line`, `require_valid_agent_review_predicate_any`)
    read `legacy_v01` the same way and checked a predicate under the v0.1 rules for `"false"`.
  - `anchors.verify_anchor`: round 1 read a registered verifier's result only as a plain `dict`, so an
    `OrderedDict` or `defaultdict` with `ok` True, a verified anchor on main 31816e08, was a failed
    anchor whose detail said "no result object".

  A sweep of every bool keyword of every public function, discovered at run time (89 at 3a8074fc, 90
  with the helper below), found the rest of the class there: `decision.emit_decision_receipt` with
  `strict=None`, `0` or `""` signed a predicate the strict rules refuse (one without `notChecked`);
  `hf_evals.to_eval_results_entry` with `require_verified=None`, `0` or `""` built an entry from a
  bundle that does not verify (beside `allow_value_mismatch=True`), and with `include_token="false"`
  published the token; `adapters.eee.from_eee_dataset` with `validate=None`, `0` or `""` built a claim
  from a record that fails the schema; and `_integration.emit_enabled("false")` opened the gate that
  decides whether an integration writes a receipt into a host run. `anchors_chia_add.anchor_add` read
  `wait` by its truth as well, so `None` would skip the on-chain confirmation (read, not run: it needs
  a node). `v02` of `agent_review` relaxed only on the exact False, and `strict` of `emit_agent_review`,
  `emit_outcome_receipt`, `emit_run_ledger`, `sign_trust_pack` and `emit_verification_summary` reaches
  a validator that reads no `strict` today; they are held to the same rule, so no later reader can
  reopen the class.

  Now one rule, one helper. A switch whose one side weakens a verdict or a check, or changes what is
  signed or published, goes through `_membership.require_switch`, which reads only an exact bool (and
  None where the switch means "not given") and otherwise raises the new `errors.SwitchTypeError`,
  which is both a `TypeError` and a `ProofBundleError`, naming the parameter and the type, before
  anything is computed or signed. The type is named by `_membership.type_name`, which runs no code of
  the caller and marks a foreign type that carries a built-in name (`numpy.bool` reads
  `bool (not the built-in bool)`). The round-3 refusals of `allow_pending`, `allow_deprecated`,
  `allow_value_mismatch` and `leaf_witnessed` raised each module's own error without the type; they
  raise `SwitchTypeError` now, still a `ProofBundleError`. Three surfaces refuse without raising and
  say why: `renewal.verify_sequence(allow_unauthenticated_anchor=)` and
  `trust_pack.verify_trust_pack(allow_unverified_rotation=)` keep their check and name the type in the
  detail and the error (a raise inside `verify_sequence` would become a failed check anyway), and
  `_integration.emit_enabled` opens only for the exact True, because an integration must never fail
  the host run. The round-3 sentence that the flags that tighten a check (`strict`, `require_*`) are
  not in this class held only for a default of False: `emit_decision_receipt`'s `strict` defaults to
  True, so a falsy value relaxed it. Left as they are, each with its reason in the contract test: 44
  switches that tighten (default False, and True only adds a check or a refusal, so a value read by its
  truth tightens or equals leaving it out), 11 verdict inputs (default None, exact since round 2), two
  that only change how something prints (`render_safe(quote=)`, `run_demo(as_json=)`), and the four of
  `intoto.svr_properties` and `intoto.export_svr_dsse`, which another change closes.

  An honest subclass of the documented type is read by what it stores. A registered verifier's result
  is a dict when its real type is one (`issubclass(type(res), dict)`, an identity walk of the MRO) and
  is read once with `dict.get`, so an `OrderedDict` verifies again, while a subclass whose own `get`,
  `__getitem__`, `__contains__` or `__missing__` answers True promotes nothing, because none of them
  runs; a result that is not a dict names its type in the detail. The round-2 checks in `assurance`
  had the same effect: an `OrderedDict` digest object was CLAIMED (main: REFERENCE_WELL_FORMED), and an
  `OrderedDict` field or a level from the caller's own `IntEnum` was skipped by both rollups, so
  `evidence_ladder_summary` rose past a CLAIMED field (main: CLAIMED). They read with `dict.get`,
  `str.__str__` and `int.__int__` of the base types now. `bundle._checks_passed` read only a plain list
  or tuple of checks, so a duck-typed result whose checks sat in a list subclass passed the crypto gate
  on its own `ok` with `Check("root-authenticity", "false")` inside; it reads list and tuple
  subclasses through the base type's iterator now.

  Reach: the Python API only; the CLI passes exact bools and the package's own verifiers return plain
  dicts. Not closed here: `intoto` (the other change); `evidence_ladder_summary` still skips a field
  that is not a dict holding an int level, which lets an AND summary rise past it, as on main 31816e08;
  and the str, bytes and int checks of rounds 2 and 3 still refuse a subclass (a `StrEnum` relation, a
  bytes subclass key, an int subclass tree-size pin), which fails closed. Contract: the two test files
  gain 25 cases (one of them replaces the round-1 not-a-dict case) and 6 round-3 cases change to the
  new form of the refusal. Against 3a8074fc, 24 cases are red, 18 of the new ones and the 6 changed
  ones, with 375 failing subtests, and 7 new ones are green there (five controls and two premises of
  the sweep). With this change the two files have 95 cases and 964 subtests, and all of them pass on
  Python 3.10, 3.11, 3.12, 3.13 and 3.14.

  The sweep also runs in the as-shipped bare install, which has no optional extra. There
  `inspect_hook` and `_inspect_registry` cannot import (they need `inspect_ai`, extra `inspect`), and
  the first form of the sweep counted that as a failure, so the hermetic cleanroom went red on
  c8865652. A module that fails to import is now left out of the sweep only when the failure is a
  `ModuleNotFoundError` for the top-level module of a package that a declared optional extra
  installs, that no core dependency installs, and that is absent from the running environment; it
  is then named in a skip, together with the classified switches that could not be checked there.
  Every other import failure still fails, and the map from extra to module is held to
  `[project.optional-dependencies]` of pyproject.toml, so it cannot go stale. This adds 5 cases and
  11 subtests (100 cases, 975 subtests); they are green against 3a8074fc as well, because they test
  the sweep itself, and the red case they answer is the cleanroom run of the unchanged file.

  **Round 5: reading what the caller hands in runs none of its code** (`anchors`, `assurance`,
  `decision`, `_membership`). A review of c8865652 found that reading "by what it stores" still ran
  code of the caller. `dict.get` of the base type compares a stored key whose hash equals the looked-up
  one through that key's own `__eq__`. In `verify_anchor`, `status or ...` called the status value's
  `__bool__`, and `isinstance(tt, dict)` read the trustedTime value's `__class__`. When one of them
  raised, a RuntimeError escaped `verify_anchor`, `verify_anchors` and
  `verify_decision_receipt(anchors=...)`, and the four documented never-raise functions of the evidence
  ladder. A key whose `__eq__` answered True stood in for `"ok"` and verified an anchor, and stood in
  for `"sha256"` or `"level"`. The same happened on main 31816e08. The fail-closed try ended at the
  verifier call and did not cover the reading of its answer. Now `_membership.stored_str_items`
  reads a dict by iterating what it stores, and a key counts only when it is exactly a `str`. The
  anchor result and the ladder inputs are read that way, each value only by its exact type (`is True`,
  an exact `str`, an `int` read with `int.__int__`). A carried `trustedTime` is a plain copy of
  JSON scalars. What is not read is named in the detail. The reading of a verifier's result sits
  inside the fail-closed boundary. `verify_anchor`, `verify_anchors` and `receipt_canonical_root` refuse
  input whose own code raises while it is read with their documented `BundleFormatError`. `verify_decision_receipt`'s
  guard around the anchors also takes any other exception, naming only its type. A plain dict,
  `OrderedDict`, `defaultdict` or method-less subclass storing ok exactly True still verifies. The
  resolver answers of the ladder, `verify_sequence` and `verify_outcome_receipt` were already read
  only with `is True` and `type()`, and are held by a test now. Not closed here: validators and
  verifiers elsewhere in the package that read a caller-built dict directly still run the code of a
  stored key or value, 37 and 59 surfaces in two generated sweeps (see the commit message). JSON
  input cannot produce such objects.

- **A producer reads each value it checks and writes once, not only the key** (lens run 8 at
  fddc00f4, findings A, B and D; the class of the entry "A small-order key is refused at every
  carrier" below, widened from keys to every value a producer both checks and writes). That entry
  has a producer read a caller's key object once; the lens then found the same split on names, maps,
  bodies, overlays, ids, status and numbers. A: `checkpoint.vkey` checked a name's stored text,
  hashed `keyname.encode()` into the key ID and wrote `f"{keyname}+…"`, the caller's `__format__`,
  so a `str` subclass name wrote a whole vkey line for the identity point in front of the real one;
  the same split stood at `key_id`, `cosign_vkey`, `cosign_key_id`, the two ML-DSA forms,
  `checkpoint_note` (origin), `sign_checkpoint` (key name) and `cosign_checkpoint` (witness name,
  note and timestamp). B: `sign_trust_pack` checked `for kid in signers` and signed
  `signers.items()`; the three `assemble` steps under `scripts/` checked a body through `items()` or
  `__getitem__` and wrote its storage; `instantiate_template` checked an overlay through `__iter__`
  and a policy_id through `__eq__`; `issue_sd_jwt` checked a status through `__contains__`. D:
  `trust_pack._read_once` read numbers through `__float__` and `__int__`, so a float subclass
  storing 1.5 whose `__float__` answers 1.0 was signed as version 1.

  A producer now reads each such value once, and the check and the writer use only what that read
  returned. Text is the stored text of a `str` (`signature.plain_text`), bytes the stored bytes of a
  `bytes` or `bytearray` (`signature.plain_bytes`), a number an exact `int` (not `bool`) or an exact
  `float`, and a JSON value a copy made by the new `_plain_value.plain_json`, which reads a `dict`
  through `dict.items` (an `OrderedDict` through `OrderedDict.items`), a `list` through `list.copy`
  and a `tuple` through `tuple.__iter__`, keeps the kind of each container, is bounded by the
  structural budget, and refuses anything else with the producer's own typed error naming the
  parameter and the path. A legitimate value is copied to an equal value, so every serialiser writes
  the same bytes as before. The sweep names every public function under `src/` and `scripts/` whose
  name marks it as forming, signing, hashing, linking, measuring or renewing something from its
  arguments, 159 in all (133 under `src/`): 80 read once (79 held by a case of the contract, one
  through the producer it calls), 58 not affected (they check nothing they write, take no caller
  value, or are private helpers called with parsed values) and 21 not producers (verify side and
  lookups). The first pattern of the scan missed 55 of them; a read of every public function it
  missed widened it, and that read found the split in eight more producers, now fixed:
  `beacon.beacon_nonce` and `beacon_audit_challenge` (a NUL check through `__contains__`, the nonce
  over `encode()`, and the request writing the caller's objects), `persample.audit_challenge`
  (length and range checks through `__len__` and comparisons, the seed over the buffer and
  `to_bytes`), `persample.sample_opening` (the proof over one reading of the list, the disclosure
  written from another), `anchors.prereg_canonical_root` (the length through `__len__`, the root
  through the stored text), `run_ledger.link_runs` (the count through `__len__`, the runs through
  `__iter__`, a status checked through `__eq__` and written as the object), `evalclaim.canonicalize`
  (the profile check through `values()` and `__abs__`, the bytes through the canonicaliser's own
  reads) and `hashalg.compute_dual_hash`, whose two digests each read the caller's buffer and could
  bind two different byte strings from 3.12 on.

  What changes for a caller, measured at fddc00f4 and at this change on 3.10: a subclass of `int` or
  `float` (an `IntEnum`, `numpy.float64`) is refused where a producer checks and writes a number, as
  the trust pack's `version`, a checkpoint's tree size, a renewal time, a beacon round or an audit's
  `n` and `k`; before, each was accepted. A value a producer copies as JSON must be null, a boolean,
  an exact int or float, text, a list, a tuple or a dict. `build_evidence_pack` refuses a proof and
  `make_disclosure` a salt that is not `bytes` or `bytearray` (a `memoryview` was accepted before),
  and `build_initial_sequence` refuses an `anchor_status` that is not text (`bytes` was accepted
  before). Where a wrong type raised a raw error it now raises the documented one:
  `present_with_key_binding` with a non-text compact (`ValueError`), `sample_opening` with a
  non-text disclosure and `beacon_nonce` with a non-text beacon id (`BundleFormatError`),
  `issue_status_list_token` with statuses that are not iterable (`BundleFormatError`). A list or
  tuple is read from its storage and any other iterable once through its iterator, so
  `issue_status_list_token`, `link_runs` and `sample_opening` accept a generator, which raised
  `TypeError` before; `issue_status_list_token` reads `bytes` and `bytearray` statuses from their
  storage, and a renewal sequence of other iterables (a `deque`) renews as before. The in-toto
  exporters read a claim's `passed` from its storage: a `dict` subclass whose `get` answers `True`
  while it stores `"false"` was exported by `to_eval_result_predicate` as `True` and is refused now;
  the case of `tests/test_das_verdikt_muss_ein_bool_sein.py` that pinned `True` pins the refusal,
  and a new case pins the reverse (a stored boolean is written whatever `get` answers).
  `instantiate_template` names the type of a non-text template in its refusal, and the statements of
  the `build_*` producers carry a plain copy of the predicate instead of the caller's object.

  Where this meets the entry "Code a caller hands in promotes a verdict only when it answers the
  exact True" above: `build_test_result_statement` now reads its cases once before it judges them.
  A case `ok` or `scope` that is no JSON value (an object whose `__class__` says bool or str) is
  refused by that read, which names its position (`results[0].ok`), where that entry names the case
  or counts such a `scope` as WARNED. A `scope` that is a `str` subclass is judged by the text it
  stores: one storing `"full"` is a full run, one storing other text is WARNED whatever its own
  `__eq__` answers, and none of its methods runs. The crypto gate that `root_authenticity_summary`
  and `policy.evaluate_policy` share (`bundle._checks_passed`) read each check's `ok` for its type and
  then took its verdict from `result.ok`, which reads every `ok` again: a check answering True, then
  False, then True gave `safeForAutomation` True with no blocker (Codex on pull request 293, round
  three, measured). The verdict now comes from one read of each check.

  The residual findings of the lens, measured again at both trees on 3.10 and 3.14: E (`1e16` as a
  trust-pack `version` raises `IntegerDomainError` from `build_trust_pack_statement`), F (the depth
  wording for a `list` subclass on 3.10 and 3.11) and G (the statement's key order without
  `sort_keys`) are unchanged. H changed: a `dict` subclass that stores the identity point and
  answers a real key through `get` and `__iter__` is read from its storage and refused, 0 of 4966
  text cells of the lens harness against 104 at fddc00f4; the `_read_once` docstring now says what
  the canonicaliser read (`dict(obj)`).

  Contract `tests/test_a_producer_reads_a_callers_value_once.py`, 13 tests and 209 subtests: every
  covered producer handed its values as subclasses of `str`, `bytes`, `bytearray`, `dict`, `list`,
  `tuple`, `int` and `float` whose every method records its call, 77 cases, with no method of the
  caller's run, the output equal to the plain call's and holding none of the caller's objects; the
  lens's own forms of A, B and D; 20 number sites; the three `assemble` steps in a process of their
  own; and the scan and the sweep list compared in both directions. Green on 3.10.12, 3.11.15,
  3.12.14, 3.13.15 and 3.14.7. Against the source of fddc00f4 it fails 134 times on 3.10 and 3.11
  and 136 times on 3.12 to 3.14, with all 77 cases among them on 3.12 to 3.14 and 75 on 3.10 and
  3.11: there the dual hash and the audit challenge over a base64 root and a `bytearray` nonce read
  a buffer, which no Python class can steer before 3.12, so they have no second reading. With
  deterministic keys, the 77 cases in three forms each (as built, every list a tuple, every dict an
  `OrderedDict`) and the trust pack with `version` 1 and 1.0 give 233 outputs byte-identical to
  fddc00f4 on all five interpreters, and the lens's D8-3 regression probe gives its 23 outputs
  unchanged. Planted in a throwaway copy, each of eleven second readings turns the contract red: the
  vkey writing the caller's name (3 failures), the trust pack skipping the copy (2), `plain_json`
  keeping number subclasses (19), the status written as handed (1), the signers signed through
  `items()` (2), the register body not copied (2), the audit request writing the caller's beacon id
  (1), the opening writing the caller's item (1), `link_runs` writing the caller's status (1),
  `canonicalize` checking the caller's claim (2), and the dual hash reading the data per digest (1,
  on 3.12 and later only: on 3.10 and 3.11 no Python class can steer a buffer, so two reads of the
  storage give the same bytes).

- **A small-order key is refused at every carrier: the AGT signer, the register view and the
  `show-eval` issuer pin** (SPEC §4b, unchanged; register entry
  `SMALL-ORDER-KEY-AT-CARRIER-SIGNATURE-01`, release scope line R-B2). The trust-anchor rule of the
  entry "A key a verifier relies on …" below reached about twenty places and left three where a key
  is relied on without it. Measured on 126ed1dc with the identity point `0100..00` as key and the
  signature R = identity, S = 0, which the §4a profile accepts for every message:
  `adapters/agt_receipt.py` checked the receipt's `signer_public_key` under §4a and returned
  `ok=True`, exit 0, for a receipt nobody signed. AGT's authorization binds `receipt_payload_hash`
  and not the signer key, so the same swap under an externally authorized receipt kept the
  authorization and still exited 0. `_signatur_lage` in `scripts/gen_findings_register.py` answered
  `VERIFIZIERT`, and both generated views printed "Signed and verified against the canonical body,
  ed25519." (32 zero bytes as key and 64 as signature: `VERIFIZIERT` for 7 of 16 bodies of the
  line-610 carrier). `show-eval --expect-issuer ed25519:<identity>` exited 0 with `=> OK` for a
  PASS receipt nobody signed: the pin was compared as a string with a key the bundle check had
  accepted under §4a, so the pin §4b says carries the rule did not.

  Each site now refuses such a key before any signature arithmetic and names the reason from
  `signature.TRUST_ANCHOR_REFUSAL`. The AGT signer goes through `verify_ed25519_pinned`, which adds
  the key check and asks for no pin list, so trust in the signer still comes through the authorizer
  as before; the adapter left the `IN_BAND` list of the trust-anchor test and no longer imports the
  bare primitive. A key is refused where it is authorised, not only when a receipt uses it: a weak
  key on the relying party's `trusted_authorizer_keys` refuses the list before the receipt is read
  (new check `trusted-authorizer-keys`, exit 2), and a weak `--expect-issuer` pin is refused when it
  is supplied (exit 2, the code a weak trust-policy pin gets). An entry or pin that decodes to no
  32-byte key still matches nothing, as before. A lens run at 053c7800 measured that the list
  refusal walked only list, tuple, set and frozenset while the comparison walked any iterable, so a
  `deque`, a `UserList`, a `dict` or a `dict.keys()` view holding the identity point next to the
  real authorizer key gave exit 0, as did the identity point given as raw bytes, and a nested-list
  entry raised `TypeError` (on main too): the list is now read once, as one tuple that the refusal
  and the comparison share (once per chain), 32 raw bytes are judged as a key, an entry that names
  no key matches nothing and is counted in the check detail, and a value that cannot be walked
  refuses the list (exit 2). A second lens run at 8cf49247 measured three more ways past that
  reading: a list whose walk raised anything but `TypeError` (a generator that yields the real key
  and then raises `ValueError`, a closed file, a generator raising `KeyError`) escaped from both
  verifiers, for a receipt without an authorization as well, which exited 0 at 053c7800; the chain
  caught the `TypeError` of a list that yields the identity point, raises once and then yields the
  real key, and passed the half-read iterator on, exit 0 where the single call gave exit 2; and an
  entry was judged by its Python type, so the identity point as a `memoryview` or an `array('B', …)`
  next to the real key gave exit 0, and one key passed instead of a list was walked character by
  character (the identity point as a bare string: exit 0). Now any `Exception` raised while the
  caller's list is read refuses the list and names the exception type (exit 2); the single call
  and the chain read the list through one helper, once, and when that reading is a refusal every
  receipt of the chain reports it and the list is not read again; an entry that exports a buffer of
  bytes or numbers is judged as its bytes; and a str or byte string passed as the whole list is
  refused as a single key (exit 2). The register exit has a new state `KEY_REFUSED`,
  which `pruefe_v2` counts as an error and the views print as unauthenticated. SPEC §4b needed no
  change: it already covers every key that is not the bundle's own.

  The sweep went over every Ed25519 verification under `src/`, `scripts/` and `tools/`. The bundle's
  own key stays the one in-band key of the package. The three producers under `scripts/` where a key
  enters a carrier (`assemble` in `gen_findings_register.py` and `sign_readiness_artifact.py`,
  `assemble_receipt` in `pre_tag_receipt.py`) refuse such a key too, through the same shared rule,
  with the reason named, a non-zero exit and nothing written; they had checked the handed-in pair
  under §4a and written a carrier under the identity point with exit 0, relying on the verifiers of
  their output, so the in-band list names no script any more, and the producer part of the entry
  "The release tooling refuses a weak key it pins" below no longer holds. The third-party vector
  tools under `tools/` trust nothing and stay named. The same holds for what proofbundle signs
  itself: at 053c7800 `export_svr_dsse` signed `PROOFBUNDLE_SIGNATURE_VALID` and
  `PROOFBUNDLE_THRESHOLD_MET` over a PASS receipt nobody signed under the identity point, and the
  eval-result and test-result exports signed the same claim; all three now refuse with
  `BundleFormatError` (exit 2 on `svr` and `intoto`) when the claim's issuer key is one the rule
  refuses, read by the same issuer parser `--expect-issuer` uses, while verifying a receipt keeps the
  bundle's own key on the §4a profile, as §4b says. Every other place under `src/` that signs was
  swept, and none signs a verdict about a receipt it read; two that the first sweep list left out
  are not the pattern either: `renewal._sign_ats_content` signs a time authority's own archive
  time-stamp content, a digest it computed, and `sdjwt_issue.present_with_key_binding` signs the
  holder's key-binding JWT over the presentation it holds; neither reads an eval receipt. Contract
  `tests/test_a_small_order_key_is_refused_at_every_carrier.py`, as it stood at d461b41a with 48
  cases and 702 subtests: on 126ed1dc 35 cases fail, 15 of them outright (one of those also with
  13 failing subtests) and 20
  only through 623 subtests, 636 failing subtests in all; on 053c7800 23 fail, 7 outright and 16
  through 564 subtests; on 8cf49247 11 fail, 2 outright and 9 through 297 subtests; on 481a1f26 8
  fail, 1 outright and 7 through 429 subtests, and these 8 are the cases of the third lens run
  below; the 13 controls and preconditions pass on every tree. A case counts once, as outright when
  its own assertion fails, whatever its subtests do; two unittest result counters and `pytest -rA`
  give the same numbers.

  A third lens run at 481a1f26 measured a regression against main and one more escape, and a sweep
  of the neighbours found four classes that main has as well. Taking every value that exports a
  buffer as one byte string refused `np.array([key])` and the same array with `dtype=object` as a
  single key, exit 2 where main 20e91c8e gives exit 0: numpy exports them with the formats `64w` and
  `O`. The list reader now goes by the format of the buffer. References (`O`, `P`, `Z`, `z`) and
  text items of more than one character are a collection, walked as main walked it (as an entry
  they refuse the list since the fourth lens run below); single bytes in one dimension,
  fixed-width byte strings and single characters
  stay one key; numbers and records are walked too, after their bytes were judged as the one key
  they spell; and a buffer of more than one dimension is refused whole, as 481a1f26 refused it (main
  raised `TypeError` on it). Reading only a one-dimensional buffer of `B`, `b` or `c` as a byte
  string and everything else as a collection lost the refusal in 3122 of 12672 weak-key cases,
  `array('I')` entries and a weak key given as a numpy uint32 array among them, which is why numbers
  are still judged by their bytes. The reader's `except` handler read the exception's type name
  through its metaclass, so an exception whose metaclass `__name__` raises escaped from both
  verifiers; every message of the module that names a caller's type now reads it through `type`
  itself (the handler, its two sibling reads, the receipt and chain shape checks, a field of the
  wrong type). Only an `Exception` refuses a list: every `BaseException` that is not an `Exception`
  propagates, `GeneratorExit`, `asyncio.CancelledError` and a caller's own subclass as well as
  `KeyboardInterrupt` and `SystemExit`. The sweep called both verify surfaces 16324 times with input
  of the wrong shape (the receipt, the chain value, each chain element, `now`, every field of the
  five vectors) and 3664 calls raised, the same 3664 on main: a field the serialiser cannot encode
  (3168, `TypeError`, `ValueError`, `RecursionError`, and `UnicodeEncodeError` for a lone surrogate,
  which `json.loads` produces from a receipt file), a `cedar_decision` that is not text (450,
  `AGTReceiptError` raised outside its guard), an instant beyond the float range (24,
  `OverflowError` from `float()`), and a chain element that is not an object (22 kinds,
  `AttributeError`). None raises now: 3640 are exit 2, the 23 whose signed instant changed or whose
  `now` lies after the expiry are exit 1, and `now=-10**400` is exit 0. Kept, measured on the final
  tree: the 366-key regression set of the second run is byte-identical (sha256 `5374a6a4…`), the
  1794-key form sweep equals 8cf49247 on its 156 numpy cases and 481a1f26 on the other 1638, the
  12672-case weak-key sweep (the lens's 9504 and 3168 more with numpy text, numpy object and ctypes
  `py_object` arrays) gives exit 2 in every case, and `KeyboardInterrupt` and `SystemExit` still
  propagate.

  A fourth lens run at d461b41a measured two more classes, both on main 20e91c8e as well. Text held
  in a buffer was never read as text: the identity point as hex text W inside `np.array(W)`,
  `np.array(W, dtype=object)`, `ctypes.c_wchar_p(W)`, `ctypes.create_unicode_buffer(W)`,
  `array('u', W)` or `np.array(list(W))`, next to the real key, gave exit 0 for a receipt without an
  authorization, for the authorized one and for the chain, with the detail "1 of which name no key",
  where the plain str W gives exit 2 (main: exit 0 for the first, `TypeError` for the others). The
  lens swept 15 such text forms at 8 positions over 48 weak encodings, 5760 values, and the raw key
  as `ctypes.c_char_p(key)`, 384 more. A buffer of references or of multi-character text at no
  dimension was taken for a collection, and single characters were handed on as their UCS-4 code
  units, 256 or 260 bytes that name no key. Decided: such an entry is not read as the text it holds,
  it refuses the list (exit 2, naming its position, its type and its buffer format). Reading it would
  run code of the caller's object (numpy's `item()`, ctypes' `.value`) or follow a pointer, and
  `ctypes.c_char_p(12345).value` ends the process with SIGSEGV, measured; decoding the code units by
  hand would be a second reading with conventions of its own, since numpy drops trailing NUL
  characters from an item, ctypes stops at the first NUL and `array('u')` keeps them. The same rule
  covers every reference or pointer entry (`c_char_p`, `c_wchar_p`, `c_void_p`, `py_object`, a
  ctypes pointer) and every record entry, so the structured array that `np.genfromtxt(names=True)`
  returns for a key column, which gave exit 0 for a receipt without an authorization, is refused
  too: a record's fields may hold text or references, and a ctypes field name containing `:` makes
  its format ambiguous. This changes one sentence above: a one-dimensional numpy text or object
  array as an entry no longer names no key, it refuses the list; as the whole list it is still
  walked, and a nested list, which exports no buffer, still names no key. Every entry that exports a
  buffer is now either judged by its bytes or refuses the list. The second class: an instant beyond
  the float range still met a comparison that converts to float. `authorization_expires_at` as a
  310-digit JSON integer, judged at `now=np.float64(time.time())`, raised `OverflowError` out of both
  verifiers, because `np.float64` passed the `isinstance` test for float and its own `__le__`
  converts the int; a `now` that is an int or float subclass whose `__le__` raises gave
  `RuntimeError` (exit 0 at 481a1f26 and on main, which converted with `float()` first). Every value
  the verifier compares or tests is now read as its plain value first, through `type()` and
  `float.__float__`, `int.__index__` or `str.__str__`, and compared exactly. The sweep of the module
  found the same class at the claim `assurance_level` and at `parent_receipt_hash` (an int whose
  `__eq__` raises escaped; one whose `__eq__` answers True passed the `chain-link` check for any
  parent), at every text field given as a `str` subclass (`not signatur` ran its `__bool__`, the
  decision lookup its `__hash__`), and at every `isinstance` test on a receipt value, on the receipt
  and on the chain (a `__class__` property that raises escaped); all of them are read the same way
  now. The exact comparison also corrects a rounding that no sentence above names: an expiry of
  2**53 judged at 2**53 + 1 is expired, where 481a1f26 and main converted the instant to 2**53 and
  called it unexpired; 2**53, 2**53 - 1 and `float(2**53)` stay unexpired everywhere.
  `[real key, closed mmap]` is exit 2 where main gives exit 0, and that follows from the rule of the
  second lens run: a closed mmap refuses its buffer with `ValueError`, as a released `memoryview`
  does, and an entry that cannot be read refuses the list. Kept, measured on the final tree: the
  366-key regression set is byte-identical (sha256 `5374a6a4…`), the 1794-key form sweep is
  byte-identical to d461b41a, the 12672-case weak-key sweep gives exit 2 in every case, the real key
  as hex text in 35 container forms by 4 lists keeps all 288 accepts main gives the authorized
  receipt and the two chains, and every `BaseException` that is not an `Exception` still propagates.
  Of the lens's sweeps, the text one has no value left below exit 2 (7920 values) and the raw one 94
  of 50208: the raw key bytes as a numpy `<U8` or `>U4` array passed as the whole list, whose items
  are read as the texts they are and spell no key. For 8 of those 140 lists (the real key inside
  `np.array(key)` or `c_wchar_p(key)` as an entry) the receipt without an authorization gets exit 2
  where d461b41a gave exit 0; main raised `TypeError` there for the authorized one. Not fixed, and
  named: the truth value of `require_external_authorization` is read through the caller's value (a
  numpy array of two booleans raises `ValueError`). The receipt mapping and the chain sequence were
  read through their own methods here as well (a `dict` subclass whose `get` raises escaped from both
  verifiers, on main too); the fifth lens run below closed that. Contract as it stood at c8c61651: 53
  cases and 1159 subtests; at d461b41a 6 cases fail, none outright and all 6 through
  454 subtests, the five new cases and the one whose entry assertion changed, and pytest reports
  those 6 as passed next to 454 failed subtests.

  A fifth lens run at c8c61651 measured two more classes, both on main 20e91c8e as well, and five
  smaller findings. The list reader took the buffer format for the item, and ctypes exports a record
  it cannot describe with the bare format `B`: a `ctypes.Union`, a `Structure` with `_pack_` (a
  big-endian one too) and an array of either, which exports `B` in one dimension. The identity point
  as hex text in a `c_wchar * 65` field of such a record, next to the real key, gave exit 0 for
  receipt 01, for receipt 03 and for the chain, so the sentence above that the rule covers every
  record entry did not hold at c8c61651. The kind is now decided by the type as well as by the
  format: a ctypes Structure, Union, pointer or function pointer is a record whatever it exports, and
  so is any buffer whose one-item format the struct module sizes to another number than the item
  size the buffer reports, which covers an array of such records at any depth without reading its
  element type. Every such entry refuses the list, and a weak key's raw bytes inside one are still
  judged and named in the refusal. numpy cannot hide a record this way: with numpy 2.2.6, every dtype
  with fields that was measured (the lens's eight and ten more, overlay dtypes included) exports
  `T{...}`. Of the lens's 344-form classification table, two rows change class, the Union and the
  packed Structure (numbers to record), and four `P` rows now hand on their bytes. Next to it, a
  whole ctypes pointer (`POINTER(c_char)`) was walked item by item from its address with no end; it
  is refused as a pointer now, before anything is read. The second class: a plain JSON receipt made
  both verifiers raise. The payload was serialised inside the guard for the signature and again
  through `payload_hash` for the self-consistency check, one frame deeper and outside every `try`, so
  a `tool_name` nested 989 deep raised `AGTReceiptError … RecursionError` out of both verifiers, and
  the window moves with the caller's stack (N = 988 at no extra frame, 488 at 500). Each receipt is
  now serialised once, and the self-consistency check, the authorization binding and the chain link
  take their hash from those bytes; a value whose `items()` raises on a second read no longer
  escapes either. Of the smaller findings, two are fixed. A `P` buffer over a weak key's bytes passed
  as the whole list (`memoryview(key).cast('P')`, `(c_void_p * 4)`) was walked as addresses that
  name no key, 96 values at exit 0 or 3, and is judged by its bytes now. A key object whose hash
  equals `hash("agent_did")` and whose `__eq__` raises made both verifiers raise from a plain dict.
  The receipt is now read through `dict.items` into a plain copy and the chain through
  `list.__iter__` or `tuple.__iter__`, which call no method of the caller's, and that also closes the
  limit named above for a `dict` subclass whose `get` raises and a list subclass whose `__len__`
  raises (of the lens's 2765 hostile calls, 3 escaped at c8c61651 and none now). The other three are
  named limits below. Kept, measured on the final tree: the text sweep has 0 of 7920 values below
  exit 2, the raw sweep the same 94 of 50208, the weak-key sweep gives exit 2 in all 12672 cases, the
  real key as hex text in 35 container forms by 4 lists keeps all 288 accepts main gives, the
  366-key regression set (sha256 `5374a6a4…`) and the 1794-key form sweep (sha256 `e534b806…`) are
  byte-identical to c8c61651, the two counter-examples of the fourth run stay fixed, and every
  `BaseException` that is not an `Exception` still propagates (36 of 36 sites). Contract: 59 cases
  and 1542 subtests; at c8c61651 the 6 new cases fail, none outright and all 6 through 342
  subtests, and pytest reports those 6 as passed next to 342 failed subtests.

  The CI test matrix at a4e2fa5c (the fifth run's fix merged with main) measured one verdict that
  depended on the interpreter and two cases whose premise did. A receipt field nested 5000 levels was
  unreadable, exit 2, on Python 3.10 and 3.11 and a failed signature, exit 1, on 3.12, 3.13 and 3.14,
  for all 11 fields of both payloads: the depth was bounded only by where `json.dumps` raised
  `RecursionError`, and that moves with the interpreter (measured at a shallow caller: 3.10 and 3.11
  write 990 levels and not 1500, 3.12 and 3.13 write 5000 and not 20000, 3.14 writes 20000 and not
  200000). The depth is the module's own rule now. A payload whose canonical form nests arrays and
  objects more than 64 deep, the house ceiling `budget.json_depth`, is `readable` False, exit 2, on
  every interpreter; the plain containers are measured before anything is written, without
  recursion, without running a method of the caller's and once per container and level (60 lists
  each held twice by the next, 2**60 paths, cost one visit per list), and what the serialiser reads
  through a caller's own methods (the `items()` of a `dict` subclass, the `__iter__` of a `list`
  subclass, each still read once) is measured in the form it wrote. The message is the same on every
  interpreter except in one case, which the first wording of this entry ("with one message on every
  interpreter") left out and lens run 7 at 75c3aa48 measured (F4): where a caller's own `items()` or
  `__iter__` hands the serialiser a form so deep that `json.dumps` raises `RecursionError` before it
  has written it, 3.10 and 3.11 name that exception ("encoding it raised RecursionError") while 3.12
  to 3.14 write the form and give the depth message; measured at 990, 1500 and 4998 levels, and at
  70 and 600 levels all five give the depth message. The verdict and the exit code are the same on
  all five in every case, and the behaviour is unchanged. `canonical_payload`,
  `payload_hash` and `canonical_authorization_payload` raise `AGTReceiptError` for such a payload the
  same way. This changes the verdict for a value nested past 64 levels that the interpreter could
  still write, from exit 1 to exit 2, and a signature over such a form is no longer checked; an AGT
  payload is one level deep. The sweep of the module found no other verdict that depends on the
  recursion limit: the list reader, the field copy, the chain reading and every message walk no
  nested value, and `_kurzwert` already names a nested value by its type. Of the functions this
  branch changed outside the module, the issuer pin parser, the export refusal and the key checks of
  the three `assemble` steps walk no nested value, and the register and the readiness artifact are
  signed over `canonical.canonicalize_statement`, whose depth bound is explicit already. One
  neighbour is named, not changed: `pre_tag_receipt.py --assemble` over a context file nested 5000
  deep exits 1 without writing a receipt on 3.10, 3.11 and 3.13, from a `RecursionError` traceback
  of `json.loads` on 3.10 and 3.11 and from its signature refusal on 3.13; the load is code this
  branch did not change. The other two findings were premises of the contract, not of the source.
  numpy 2.4.6 (3.11) and 2.5.3 (3.12 to 3.14) cannot infer the types of a CSV whose first key is
  the identity point in hex, 64 digits and no letter, and raise `TypeError` inside
  `np.genfromtxt(dtype=None)`, where numpy 2.2.6 (3.10) fell back to text; the table now names its
  field types (`dtype="U64,U8"`), which gives on all three the `<U64` key column numpy 2.2.6
  inferred (the label is `<U8` where it inferred `<U4`), and numpy's inference still reads the
  table whose first key has letters. From 3.12 on ctypes describes a `Structure` with `_pack_` as a
  record (`T{(65)<u:f:}`, `T{(64)>I:f:}`) instead of the bare `B`, so the precondition that each
  form of the fifth run's case exports `B` failed there; a Union exports `B` on all five. The case
  now demands that each form exports `B` or a record format, that every Union form exports `B`, and
  the refusal for whichever it exports, and the source refused both kinds on every interpreter (10
  forms, exit 2 each on all five). Against the source of a4e2fa5c the three cases of the depth rule
  fail 41 subtests on 3.10 and 3.11 and 45 on 3.12 to 3.14, and the two premise cases pass.

  A Codex review at a4e2fa5c found the same class where a key is AUTHORISED rather than verified:
  `sdjwt_issue.issue_sd_jwt` checked `holder_public_key` only for its length, wrote it into
  `cnf.jwk` and signed. A key a producer writes for a relying party to trust gets the rule its
  verifier applies, before it is written. The sweep went over every producer under `src/` that
  writes an Ed25519 key the caller hands it. Three wrote all 13 weak encodings of the contract at
  a4e2fa5c (main 31816e08 has the same files): `issue_sd_jwt` (the holder binding),
  `checkpoint.vkey` (a log verifier key) and `checkpoint.cosign_vkey` (a witness verifier key).
  Each refuses them now with
  the shared rule: `issue_sd_jwt` raises `ValueError`, its documented refusal for a bad holder key,
  and the two vkey producers raise the `BundleFormatError` their parsers raise. Two refused already
  and are pinned as controls: `policy_profiles.instantiate_template` (pinned issuer keys) and
  `trust_pack.sign_trust_pack` (root keys). The rest write the key of the private key they sign
  with (`emit_bundle`, `emit_eval_receipt`, `sign_checkpoint`, `cosign_checkpoint`, the statement
  emitters, `dsse.sign_envelope`), which is never of small order for a real Ed25519 key, or write a
  key ID. `emit_bundle` also copies a caller's `sd_jwt_vc` verbatim, a foreign issuer's key
  included; the bundle signature does not cover it, and `verify_bundle` checks the SD-JWT under that
  key with the rule. The contract carries this sweep as a list. At the tags v6.0.0 and v6.1.0
  `issue_sd_jwt` carries the same lines (98 to 102), and the verifiers did not refuse either: an
  SD-JWT bound to the identity point and a Key Binding JWT signed by nobody (R = identity, S = 0)
  gave "key binding valid", and all 13 weak log and witness vkeys were written and parsed back; at
  a4e2fa5c the verifiers refused them. The case in
  `tests/test_trust_anchor_keys_refused_on_every_surface.py` that bound the identity point as the
  holder and measured only the verifier now demands the refusal at issuance and measures the
  verifier on a `cnf.jwk` a foreign issuer wrote; its checkpoint cases measure the parsers on vkeys
  written without the rule. The search question of the finding, a key checked by its length alone,
  is a case: every comparison of a `len(...)` with 32 under `src/` (26 in 25 functions) is listed
  with the reason it is no carrier, and a new one turns the contract red until it is named. Three
  more length checks that scan cannot see, found by a wider one (a comparison with a name or with
  33), are named in the case next to `trust_pack`'s `want_len`: two are the vkey parsers, followed
  by the rule, and one compares a hash.
  Contract: 66 cases and 1653 subtests with numpy installed, green on 3.10.12, 3.11.15, 3.12.14,
  3.13.15 and 3.14.7, each with the numpy its CI job installs; against the source of a4e2fa5c 93
  subtests fail on 3.10 and 3.11 and 97 on 3.12 to 3.14 (41 or 45 of the depth rule, 52 of the two
  producer cases). The trust-anchor file has 53 cases and 159 subtests, green on all five; its
  turned case fails outright against the source of a4e2fa5c.

  A lens run at 75c3aa48 measured that those refusals judged one reading of the caller's key and
  wrote another. The rule reads `len(key)` and `bytes(key)`, the caller's `__len__` and `__bytes__`;
  the writers read the key's own buffer (base64) or ran its `__radd__` (a concatenation); and a key
  given as base64 text reached the rule through `_wire_b64`, which called the caller's `encode`,
  while the producer wrote the text itself. A `bytes` subclass whose `__bytes__` returns a real key
  while its own bytes are the identity point was bound by `issue_sd_jwt` and written by
  `checkpoint.vkey` and `checkpoint.cosign_vkey`, and a `bytearray` subclass the same way by
  `issue_sd_jwt`, 13 of 13 weak encodings each on all five interpreters; under v6.0.0 and v6.1.0
  the SD-JWT so issued, with a Key Binding JWT signed by nobody, verifies as "key binding valid". A
  `str` subclass whose `encode` returns the base64 of a real key while its text is the base64 of
  the identity point was pinned by `policy_profiles.instantiate_template`, signed into a pack by
  `trust_pack.sign_trust_pack` and written by `trust_pack.build_trust_pack_statement` and the three
  `assemble` steps under `scripts/`, so "refused already" above holds for a plain `str` only; no
  command line reaches it, since arguments are plain `str`. From Python 3.12 on a class can define
  `__buffer__` (PEP 688), and a `bytes` subclass that stores a real key and whose `__buffer__` names
  the identity point passed the rule, which reads the storage through the inherited
  `bytes.__bytes__`, and had the identity point written, measured on 3.12.14, 3.13.15 and 3.14.7.
  Now each such producer reads the key once, from the value's own storage, into an exact `bytes` or
  `str` (`signature.plain_bytes` and `signature.plain_text`, next to the rule, and
  `_wire_b64.wire_value` for a field that may be either), and the rule, the key ID and the written
  output use that one value. The read is `bytes.__getitem__` or `bytearray.__getitem__` with a full
  slice, and `str.__str__`: on all five interpreters none of them ran a method the caller's class
  defined, while `bytes(x)`, `x[:]`, `b"" + x`, `x.encode()`, `str(x)`, `f"{x}"` and `"" + x` did,
  and from 3.12 on `memoryview(x)`, base64 and `hashlib` too. The decoders of `_wire_b64` read their
  input the same way. `sign_trust_pack` and `build_trust_pack_statement` read the whole predicate
  once: its RFC 8785 bytes are parsed back, and the validator, the subject digest and the signature
  use that parse, so a `dict` subclass whose `get` answers for a real key while it stores the
  identity point is refused too, and a predicate that cannot be written as RFC 8785 JSON raises
  `TrustPackError`. That read changes one verdict for a plain predicate as well, decided and pinned
  by the contract: an integer field given as a float of integral value (`version`, a role's
  `threshold`) and an array given as a tuple (`keyIds`, `nonClaims`) were refused at 75c3aa48 by
  the validator's type checks and are signed now, because the RFC 8785 form does not carry the
  difference; the statement and the signed payload are byte-identical to the ones for the integer
  or the list, and `1.5` or `True` stay refused. The issuer parser of `--expect-issuer` and of the
  exports that refuse to vouch (`evalclaim._issuer_key_weakness`) reads the issuer once, so a `str`
  subclass whose `startswith`
  and `__getitem__` answer for a real key no longer lets `export_eval_result_dsse` or
  `export_intoto_dsse` sign over a claim that holds the identity point. `checkpoint.key_id`,
  `cosign_key_id`, `cosign_key_id_mldsa` and `cosign_vkey_mldsa` read the key once as well, so a key
  ID is the ID of the key written (no rule applies to an ML-DSA key). Which types are read: a raw
  key is `bytes` or `bytearray`, the two types the rule judges. `issue_sd_jwt` wrote a real key
  given as a `memoryview`, an `array('B')`, a ctypes byte array or a numpy uint8 array at a4e2fa5c
  and refused it at 75c3aa48 with the reason "a trusted Ed25519 key is exactly 32 bytes", which is
  wrong for 32 bytes. Decided: it stays refused, because such a value has no storage apart from its
  buffer, which a subclass can steer from 3.12 on, and the refusal now says the key must be `bytes`
  or `bytearray` and to pass `bytes(...)` of it. `vkey`, `cosign_vkey`, `key_id` and `cosign_key_id`
  refused a `bytearray` until now and accept it, as `issue_sd_jwt` did. One effect on the verifier
  side, through the shared decoder, measured on 3.10: `policy.load_policy` accepted a pin given as a
  `str` subclass whose `encode` answers for a real key while its text is the identity point, and
  now refuses it. Contract `tests/test_a_producer_reads_a_callers_key_once.py`, 15 cases and 1008
  subtests, green on 3.10.12, 3.11.15, 3.12.14, 3.13.15 and 3.14.7; every producer of its sweep list
  gets each hostile form in both directions (the weak key stored and a real key answered, and the
  reverse), and a scan names every call of the rule's helpers under `src/` and `scripts/`. Against
  the source of 75c3aa48 it fails 713 times on 3.10 and 3.11 and 805 times on 3.12 to 3.14 (1
  outright, the readers that do not exist there; 4 are the plain trust-pack predicates above; the
  92 more are the `__buffer__` form), with every
  producer of the list among them; of those, the `bytearray` cases of the vkeys and key IDs fail
  because a `bytearray` was refused there, not because it was read twice. Planted in a throwaway
  copy, each of six second readings turns it red: `issue_sd_jwt` writing `bytes(key)`, `vkey`
  concatenating the caller's key, `sign_trust_pack` validating and signing the caller's predicate,
  the issuer parser slicing the caller's `str`, `sign_readiness_artifact` writing `str(key)`, and the
  decoder calling the caller's `encode` (26, 13, 17, 52, 13 and 1 failures).

  Named limits, measured and not stated elsewhere: the AGT adapter does not relate `agent_did` to
  `signer_public_key`. A receipt whose `agent_did` names another party verified with exit 0 under a
  fresh signer key, and the five vectors carry `did:key:z6MkZ179Demo`, which decodes to 8 bytes and
  is no Ed25519 did:key. `trusted_authorizer_keys` is compared as text: the real authorizer key
  listed in capitals gives exit 3, and so does the real key given as a byte string (32 raw bytes,
  a `memoryview`, an `array`), which the rule judges but which is not text, so the error falls on
  the closed side. A whole ctypes array of `c_char_p` or `c_wchar_p` is walked, and ctypes reads the
  text each pointer names: the caller's pointers are followed by design, and the 288 accepts include
  `(c_wchar_p * n)`. Measured with memory the probe allocated, the verdict follows the bytes at the
  address (the weak key there: exit 2, other bytes: exit 0); a pointer in such an array that names
  no valid address was not run and is not detected. Text held where no buffer of text holds it
  names no key: `collections.UserString(W)` as an entry, and the hex text as ASCII bytes (`W.encode()`,
  a `bytearray`, a `memoryview`, `np.bytes_`, an `S64` array, `create_string_buffer`), give exit 0
  next to the real key, because bytes are read as raw key bytes and an object without a buffer names
  no key. A record entry next to the real key refuses a list that main authorised (a read-only numpy
  record: exit 2 where main gives exit 0); it fails closed. Serialising a signed field still runs
  that value's own methods (`items()` of a `dict` subclass, `__iter__` of a `list` subclass, a
  `__class__` property through the serialiser's `default()`); with one serialisation per receipt,
  none of them makes a verifier raise. Four NULL `c_void_p` passed as the whole list are 32 zero
  bytes, a point of small order, and are refused (exit 2) where c8c61651 walked them (exit 0 or 3);
  one, two, three, five or eight are walked as before. A verify function that reads a caller's key
  object twice is not changed here: `verify_ed25519_pinned` reads `bytes(key)` for the rule and again
  for the signature check, and a key object whose `__bytes__` answers a real key first and the
  identity point after verified a signature made by nobody, directly and through
  `dsse.verify_envelope`, measured on 3.10 and 3.13; the round-12 sweep of the commitment-pattern
  branch closes it (the entry on reading a caller's objects once, above), and on that head the
  key object's `__bytes__` is never called. Still read through the caller's own methods, and
  not measured: the name a vkey is written under, the `signers` map of `sign_trust_pack` (checked
  against the pack's keys, then signed with), and the body an `assemble` step checks the signature
  over and then copies.

- **An ES256 or eip191 signature has one identity, and a foreign signer's bytes are never
  rewritten** (finding D1; `signature.canonical_es256_signature`, `sdjwt.canonical_sd_jwt_compact`,
  `kbjwt.verify_key_binding`, `anchors.receipt_canonical_root`, `hf_evals.receipt_token_identity`,
  `anchors_rootcommit.eip191_recover_address`, `anchors_rootcommit.eip191_signature_identity`). ECDSA is
  malleable: from a valid ES256 signature (r, s) anyone can write (r, n − s) without the key, and
  both verify. Measured on main 126ed1dc: `verify_ecdsa_p256`, `verify_sd_jwt` and `verify_bundle`
  accepted both; the `pb1.` tokens of a bundle and of its twin were two different tokens that both
  verified, and nothing gave them one identity; `receipt_canonical_root` gave two roots, so a
  `receipt` anchor over one spelling failed `--require-anchor` for the other; and the Key Binding
  JWT's `sd_hash` check refused the twin of a genuine presentation, so with a KB-JWT attached
  `verify_bundle` accepted one spelling and refused the other. For secp256k1,
  `eip191_recover_address` recovered the same wallet from the vendored `v2sig-01-valid` signature
  and from its twin (r, n − s, recovery id flipped), so one signature made two rootcommit anchor
  lines that both verified.

  The owner decided on 2026-09-26, in two steps; the second refines the first. (1) Verification
  keeps accepting both spellings of an ES256 signature: RFC 7518 §3.4 does not require the low
  half, OpenSSL signs with either half (987 of 2000 signatures in one measurement with
  `cryptography` 49.0.0) and accepts both, and three of the five IETF SD-JWT VC examples vendored in
  `tests/fixtures/sdjwtvc` carry a high s (the fourth and the fifth in the issuer signature, the
  second in its Key Binding JWT); all five and their twins stay green. (2) Every identity, receipt
  root, dedup, replay or log key is computed over the canonical form, in which every ES256 signature
  of the compact, the issuer JWT's and a Key Binding JWT's, has s ≤ n/2; so twins have one identity.
  (3) The bytes of a foreign issuer are never rewritten: not in a bundle from `emit_bundle` or
  `emit_eval_receipt`, not inside a `pb1.` token, not in the bundle `verify_receipt_token` returns,
  not in a presentation from `present_with_key_binding`, with or without a KB-JWT. (4) A low s is
  required only of signatures proofbundle makes itself. It makes no ES256 signature today; its own
  signatures on these paths are Ed25519, which has one spelling by the S bound, and a test keeps an
  inventory of the ECDSA code in the package so a new signing path is noticed. Up to 31816e08 that
  inventory knew two curve names, so a P-384 signing path in `signature.py`, where the verifier's
  `ECDSA` is allowed, passed it. It now knows every curve `cryptography` and python-ecdsa ship, the
  names that make an EC private key and the signing call `<key>.sign(data, algorithm)` itself, and a
  path planted on each curve fails it (a test change; nothing under `src/` changed). proofbundle also
  signs with ML-DSA (`pqsig.sign_mldsa`, `checkpoint.cosign_checkpoint_mldsa`, the renewal layer);
  whether an ML-DSA signature has a second spelling was not measured in this change.

  Why (3), for an external reviewer: a Key Binding JWT's `sd_hash` covers the issuer JWT exactly as
  presented (RFC 9901 §4.3). A first version of this change on the same branch (f536af50) wrote the
  low s into everything proofbundle emitted. Measured there with an independent RFC 9901 check: a
  genuine presentation, whose holder had hashed the high-s issuer JWT it received, failed on the
  compact from `emit_bundle`, on the one inside the `pb1.` token and on the one `verify_receipt_token`
  returned. proofbundle's own verifier still accepted it, because it compares both spellings; a
  verifier that hashes the bytes it gets did not.

  The cost, stated so nobody has to find it: a receipt and its twin are two `pb1.` token strings with
  one identity. `hf_evals.receipt_token_identity(token)` (new) is that identity: the receipt root of
  the bundle the token carries, i.e. `receipt_canonical_root` without `anchors`, the value a
  `receipt` anchor stamps. It is the key to deduplicate, replay-check or log tokens by; the token
  string never was one, since another zlib level or other JSON whitespace also verifies.
  `receipt_canonical_root` folds both ES256 slots, so one receipt has one root, and
  `docs/ANCHORS.md` now gives the steps. The KB-JWT's `sd_hash` is accepted over either spelling of
  the issuer signature, so the verdict does not depend on which one a relay passed on; the two differ
  in that segment only. A `pb1.` token with a high s is accepted and returned as it came.

  eip191 now refuses, before any recovery, a signature whose s lies above n/2, as OpenZeppelin's
  `ECDSA.recover` does (EIP-2); libsecp256k1, which Ethereum wallets sign with, emits the low s
  only, and all five vendored v2-sig vectors carry a low s, so no genuine signature is refused. It
  also refuses s = 0 and r outside (0, n), which no ECDSA signature has (SEC 1) and for which
  `ecrecover` gives the zero address. Measured on f536af50: s = 0 recovered an address for every v,
  and r = n + k recovered one for 21 of the 40 values k < 40. A signature that is not bytes, or a
  message that is not a str, now gives None instead of a raw TypeError or AttributeError, and so
  does a message with no UTF-8 form (a lone surrogate), which raised UnicodeEncodeError on 126ed1dc,
  on f536af50 and on accd932c (lens run 2).

  The same class in a second form, decided by the owner on 2026-09-26 as addendum 11 (the reference
  to `ECDSA.recover` above holds for the high s only): `v` is accepted as 27/28 or as the raw
  recovery id 0/1, which some signers emit, hardware wallets among them, and every other value is
  refused, EIP-155 values from 35 included, because personal_sign has no chain id. That accepted set
  is unchanged; measured over all 256 values of `v` on 126ed1dc and on f536af50, it was
  {0, 1, 27, 28} there too. So one signature has two texts: measured on f536af50, the vendored
  `v2sig-01-valid` checkpoint with v = 27 and the same checkpoint with v = 0 both verified with
  sig_ok True and reject False. The checkpoint bytes are never rewritten. Two texts, one identity:
  `anchors_rootcommit.eip191_signature_identity` (new) gives r ‖ s ‖ v with v written as 27 or 28,
  the form every identity, dedup, replay or log key over such a signature is computed over, and
  None for any signature eip191 refuses, a high s included. No code in the package forms such a key
  today: `verify_rootcommit_v2sig` returns no signature bytes, and nothing else in `src` calls the
  module.

  One consequence is stated here rather than left to be found: a `receipt` anchor stamped by an
  earlier version over a bundle with a high s in either ES256 slot of its `sd_jwt_vc` no longer
  matches its root. None of the 618 JSON files tracked in this repository (616 of them parse)
  carries an ES256 `sd_jwt_vc`. SPEC §6 and §7i state the rules. Before the change, the places where
  signature bytes enter an identity were mapped for ES256, secp256k1, Ed25519 and ML-DSA; the
  Ed25519 row has no such twin, because the S bound and the strict base64 decoders leave one
  spelling, and the ML-DSA row is the one named above as not measured. The receipt-root steps in
  `docs/ANCHORS.md` state the exact domain the code folds: strict unpadded base64url, a header
  read by the strict JSON reader (a duplicate key refused), `alg` ES256, a 64-byte signature with
  n/2 < S < n. An earlier text of this change folded any header that decodes to ES256, wider than
  the code, and a padded or duplicate-key header then got one root by the text and two in code
  (lens run 2 at accd932c); both forms fail verification. The text also names what the reader
  accepts beyond RFC 8259, because the fold follows it there: `NaN`, a UTF-8 byte order mark, and
  UTF-16 or UTF-32 text. A header in such a form verifies, and a third party that read the text as
  RFC 8259 got two roots where the code gives one (lens run 3 at 15d0b643; the anchor then fails
  closed). The text states how the reader's limits apply to the fold: depth counts a value one level
  below its container, the digit limit is the interpreter's setting, and the input and string limits
  never bind there because the receipt's budget refuses a longer compact first (lens run 4 at
  dce5f9ef; each fails closed). Whether verification should accept these forms at all is a question for every verify
  path, not for this change. Contract `tests/test_es256_signature_has_one_identity.py` with cases in
  `tests/test_signature.py`, `tests/test_sdjwtvc_external_vectors.py` and
  `tests/test_anchors_rootcommit.py`: 38 cases, measured with each tree's own src and docs.
  Against f536af50, the first version of this change, 21 are red; the 17 green there are cases
  carried over from it and guards. Against 126ed1dc, 24 are red; the 14 green there are guards and
  the rules 126ed1dc already kept (it never rewrote a foreign issuer's bytes, and it accepted the
  same four values of v). Against accd932c, the second version, 2 are red: the lone surrogate, and
  the case that checks the text of `docs/ANCHORS.md`. Each case says which in its docstring.

- **The mutation gate judges each mutant by the test files that reach it, and only a test that
  passed in the baseline and fails again when it runs by itself kills**
  (`scripts/mutation_check.py`). Run 36253567619, a manual dispatch of CI on the branch of pull request 279 at 57184964 (not
  main), measured a baseline of 1226 to 1661 s over
  the whole suite (seven of ten shards stopped at the 1800 s limit before it ended) and 1174 to 1610
  s per mutant under a job limit of 60 minutes; the three shards that got a baseline judged one
  mutant each before they were cancelled (relation cycle detection, the case-insensitive origin
  comparison and the ML-DSA domain separation label, all three KILLED), and no other operator was
  judged.

  A mutant now runs the test files that reach the mutated file, directly or through other files,
  together with every file that can reach any module and the gate's own controls. The graph holds
  every Python file of the tree as git lists it and every script that is not Python (a shebang,
  `.sh`, a Makefile); the first version covered four directories, and a hop through `conformance/`
  or `examples/` broke the chain: with "strict-json: duplicate-key reject disabled" applied,
  `tests/test_cap1_conformance_runner.py` fails, and it was not in the selection of
  `_strict_json.py`. A file reaches what it imports, a module or file that one of its strings names
  (a bare file name that several files carry names all of them), `__main__` of what runs with `-m`
  or `runpy.run_module` wherever the literal stands, the imports of Python code held in a string
  (after `-c`, or any string with an import statement), and a script that it names. A file that is
  not Python (MANIFEST.in) is reached through every file that names it and every file that reaches
  one of those, and a `conftest.py` reaches every test file below it. A name in a library module
  names only the library, since nothing under `src/` puts a directory on `sys.path`. Imports under
  `TYPE_CHECKING` do not count, and a package's lazy attribute table is read at the importer. Over
  the 33 mutated files a selection holds 106 to 374 of the 376 test files, median 205 (the first
  version: 106 to 374, median 190); MANIFEST.in and ten modules select every test file but the two
  per-mutant exclusions, because `tests/conftest.py` names `__init__.py` in a formatted path and a
  bare file name now names every file that carries it (without that one name they would hold 124 to
  323).

  Its baseline runs over the same files. A mutant is killed only by a test that passed in that
  baseline and is red under the mutant: a test that was red, skipped, xfailed or xpassed there, or
  did not run there, never kills (a test skipped in the baseline that ran and failed under a mutant
  read as a kill in the first version). A killer then runs again by itself, once more under the
  mutant and once on the restored tree, and counts only when it is red and then green; one that
  flips is named unstable in the verdict line and does not count (a timing test green in a baseline
  and red under a mutant only because of machine load read as a kill). Measured in the gate's own
  setup on two real operators with one killer each (the strict-json duplicate-key reject and the
  ML-DSA domain label): confirming took 1.6 s per killed mutant; it grows with the killers and the
  time to collect their files, not with the selection. Before, `red > baseline` counted failures
  plus errors, and a baseline-red test that also failed its teardown under the mutant raised the
  count by one, so the mutant read as killed although no test found it. Every suite run pins
  `PYTHONHASHSEED=0`, so test ids are the same in baseline and mutant runs. The cases are pinned in
  `tests/test_mutation_selection.py`, red against the first version.

  A test that is red in a baseline must stand in `scripts/mutation_baseline_allowlist.json` with the
  class it failed with, or the baseline stops; a timing test red under load stops it as well
  (measured once locally: the selection baseline of `tlogproof.py` had one such test red while the
  whole-suite baseline had none), which costs a shard and never a verdict. The class comes from the
  message of pytest's JUnit record first (`ExcType: text`, or `assert ...`) and from the last
  exception line of the traceback only when the message names none: a RuntimeError whose message
  carried an `assert` line read as AssertionError and matched an entry written for another failure.
  MANIFEST.in ships the list next to `scripts/mutation_check.py`, which reads it. Left undecided, it
  turned `test_jede_datei_unter_scripts_ist_in_manifest_entschieden` red, a test that stands in
  every selection, so the first baseline of every shard stopped, and the list's contract failed from
  the sdist; the sdist test's detector now also sees a path composed from a module constant, the
  form that read the list, and the pinned count of shipped scripts moves from 36 to 37, remeasured
  against a real sdist of the tree (37 files under `scripts/`, the same 37 as the declaration). In
  the gate's own setup a baseline over the sdist test no longer stops (21 passed, 0 red). The work
  tree is a shared clone of the repository with the tracked files copied over it, so tests that ask
  git about the tree run there as they do in a checkout, and the mutation job checks out the full
  history, as `test` does. The file an operator mutates is restored from its bytes and checked byte
  by byte, where a last full run compared a red count (a file with CRLF line ends came back with
  LF). The candidate matrix test `test_c12_1_nicht_anwendbar_vor_dem_tag` joins
  `test_audit_candidate_360` as a per-mutant exclusion: it runs the whole matrix in a subprocess
  twelve times, 766 of the 1534 s the baseline took in the gate's setup, and says nothing about one
  mutated line.

  The selection saves less time than hoped in this repository: the heaviest test files import nearly
  every module. For the first version's selections, local per-file durations scaled by the measured
  CI/local ratio of the whole suite gave about 2000 to 2200 s per selection in CI and 4.8 h for the
  longest of 28 shards; with this version's selections the same estimate gives 4.9 h for the longest
  of 28 and 3.7 h for the longest of 36, which keeps about two hours below the step limit. The limit
  of one suite run rises from 1800 to 3600 s, the CI job runs 36 shards instead of 10 under GitHub's
  six-hour job limit, and the mutation step's limit is 15 minutes below the job's, so the steps
  after it still run: a shard cut at the limit records how many verdicts it wrote (`judged=`), and
  the summary job still fails it. These numbers are provisional and are set again from the first
  measured CI run. The tests of the summary job read the shard count from the workflow, and a test
  holds the matrix, the `--shard i/K` argument and the summary's `K=` to one number.

- **An OTS proof is capped before it is deserialized, on every reader** (`anchors_ots`,
  `evidence_pack`, `anchors_rootcommit`, `anchor upgrade`). The structural budget bounds the base64
  string of a proof, not what the OpenTimestamps deserializer builds from it: every fork creates a
  timestamp holding its own copy of the message. Measured by the deep gate against main 5b53ab3e
  (finding L2-Z195-OTS-WORK-AMPLIFICATION-01,
  confirmed 3 of 3) and again for this change, tracemalloc around the call alone, each figure three
  times in a fresh process: a 732 067-byte proof inside every budget peaked at 134.4 MiB in
  `verify_evidence_pack`. All five places that deserialize a proof now go through one helper that
  refuses a proof over 65 536 bytes first; the same proof is refused as `over_budget` at 3.3 MiB,
  before any deserialization. The length is taken of every bytes-like object in bytes, and anything
  that is not bytes-like is refused before the library reads it (a `memoryview` of any length went
  to the library uncapped in an earlier form of this change). The largest proof this repository carries has 1510 bytes. A proof just
  under the cap, built to amplify as much as the format allows (empty calendar URIs, two-byte fork
  labels), peaks at 18.2 MiB in one deserialization. `describe_proof` deserialized every proof twice
  with both copies alive, on main as well, and peaked at 36.5 MiB on that proof; it now deserializes
  once, as every reader does (18.2 MiB). `describe_proof` gains the state `over_budget`. Adding that
  status showed that three callers decided "bound" by the absence of the refusals they had listed;
  they now read membership in the statuses that say the binding held (`anchors_ots.ots_binding_held`,
  deny by default). So `anchor upgrade` refuses an over-cap proof with exit 2 and names the cap,
  instead of reporting it as not upgraded yet and advising `ots upgrade`, and a rootcommit anchor whose
  proof is over the cap is not bound.

- **A path the sdist promised and does not carry fails the shipped suite instead of skipping it**
  (`tests/conftest.py`). From an extracted sdist, a test module that names an absent root-relative
  path was skipped as repo-context without asking whether the distribution was supposed to carry the
  path. Measured by the deep gate against main 5b53ab3e (finding L6-Z195-01, confirmed 3 of 3) with
  one appended line, `exclude examples/trust_policy_strict.json`, while `graft examples` still stood:
  `tests/test_trust_policy.py` went from 47 passed to 47 skipped and the shipped suite stayed rc 0. A
  path that a positive line of MANIFEST.in promises, that setuptools adds by itself (the template,
  `pyproject.toml`, the README, the license files), or that setuptools' build_py ships from the
  package configuration in `pyproject.toml` (the modules of every package its discovery finds, the
  declared package data), now makes the module run and fail when it is absent; a negative line does
  not withdraw the promise, because that is exactly the accident being caught. The template is read as
  setuptools reads it, including continuation lines, inline comments, `\#`, and the difference between
  the glob behind `include` and the pattern behind `global-include`; vectors from a real `build_sdist`
  with setuptools 69.5.1 are the oracle (`tests/fixtures/manifest_semantics/`, 15 cases, three of them
  varying the package discovery; a directory without `__init__.py` is a package only where that
  discovery allows namespace packages, and a candidate for it holds the reader to setuptools in both
  cases). Measured end to end from sdists built at 66809c50, before build_py was
  read: the planted exclude gave 2 failed, 45 passed, rc 1, and an unplanted sdist ran as before.

- **A signed statement says it is an in-toto Statement v1, and every verifier that reports
  `structure_ok` reads it** (`_statement_payload.load_statement_strict`). Decision, outcome and
  relation-statement verify reported `structure_ok=true`, and `decision verify --strict` under a
  signer-pinning policy `safeForAutomation=true`, for a signed statement whose `_type` was absent,
  JSON null or `Statement/v0.1`; measured on main 10f3466b (deep gate finding L3-Z195-01). Each of
  these verifiers wrote `_type` when it emitted and none read it back. The one Statement oracle
  now refuses any `_type` other than exactly `https://in-toto.io/Statement/v1`, and decision,
  outcome, verification-summary, run-ledger and trust-pack verify parse through it, as
  relation-statement verify and the `--with-related` resolver already did. The Rust verifier
  refuses the same bytes on `verify-relation`, `verify-relation-statement` and for attached
  targets, with the same exit class and lineage, and on `verify-trust-pack-threshold`, which met
  its threshold with exit 0 for a pack whose `_type` was null, absent or `Statement/v0.1` while
  Python refused it (measured on both verifiers). That subcommand also built its signature check
  under whatever `payloadType` the envelope named, so a pack signed under another type met its
  threshold where Python refuses a payloadType confusion; it now pins the in-toto type and reads the
  envelope in Python's order (payload, input size, signature list and cap, type, Statement), and a
  wrong `_type` or payloadType string is written as Python's `repr()` writes it. A sweep fails when a module that reports
  `structure_ok` for an in-toto Statement parses without the oracle, and a second one when a Rust
  function parses a DSSE payload without asking it before the predicate is read. `intoto --verify` and
  `svr --verify` are unchanged: what their `ok` covers is listed in their contract, and `_type`
  is not on that list.

- **The Rust verifier refuses a `relations` policy section that Python refuses** (`tools/pb_verify_rs`,
  `policy_huelle_pruefen`). Measured on the corpus case `relation-signer-cross-issuer-unauthorized`
  with `relation_signer.supersedes.mode` set to `"bogus"`: Python refused the policy (exit 2), the Rust
  reader read the unknown mode as no rule and verified with exit 0 and no reason. It checked the
  policy's hull and read the section it evaluates without judging it. It now judges that section the
  way `policy.load_policy` does, with Python's wording and exit 2: relation names, `relation_signer`
  mode and keys (including the trust-anchor key rule), the two booleans and
  `require_relation_target`. It checks the hull of every section first, in Python's order, and
  writes key names and values as Python prints them, so the reason is the same character for
  character: over a generated corpus of 337 policies, 321 are refused by both with the same words.
  The values of sections outside `relations` are still not read by Rust while Python refuses a bad
  one; the parity registry names that gap and a test measures it.

- **A zlib field is one complete stream and nothing after it, and a receipt token is capped before it
  is decoded** (`hf_evals.verify_receipt_token`, `statuslist.verify_status_snapshot`, new
  `_inflate.inflate_whole_stream`). Measured by the deep gate against main 5b53ab3e (finding
  L2-Z195-TOKEN-TRAILING-DATA-01, confirmed 2 of 3): a genuine `pb1.` token with bytes appended after
  the end of its zlib stream verified ok=True, from the library and from `hf-token --verify`; with
  12 MiB appended the library still said ok=True while the CLI refused the same token on its input
  budget. The token body was also base64-decoded in full before any size check (64 MiB of `A` took
  0.97 s to refuse on main 1f7a62d2, measured again for this change; now about 25 microseconds), where
  kbjwt, sdjwt and statuslist refuse an oversized segment first. Both zlib
  fields now require the stream to end and nothing to follow it, and the token body is refused over
  `input_bytes` before decoding. The status list's `lst` had the same shape. A token still has no
  single wire form: another zlib level or other JSON whitespace verifies as before.

- **A key a verifier relies on is never a low-order or non-canonical Ed25519 key, on any surface**
  (SPEC §4b, `signature.ed25519_trust_anchor_weakness`, `signature.verify_ed25519_pinned`). The core
  verifier keeps the SPEC §4a profile, under which a signature made with no private key verifies under a
  low-order key: the fixed signature R = identity, S = 0 for every message under the identity point, and
  for about one message in the key's order under the other points of small order. A non-canonical
  spelling (y >= p) is refused because a trusted key has exactly one encoding; of the nineteen, only
  y = p and y = p + 1 also spell points of small order, and every refusal message now says which
  reason applies. The trust policy refused such keys; nothing else did. Measured by
  the deep gate against main 5b53ab3e (findings L1-Z195-01 to 03): two witness vkeys carrying the
  identity point, once with the x-sign bit set, met a 2-of-2 witness quorum on a checkpoint neither
  witness saw; `decision verify --pub <identity>` printed `CRYPTO: OK` and exited 0 for a receipt nobody
  signed; a trust pack met its root threshold and a rotation vouch with the same forgery. The rule now
  runs at the C2SP log and witness vkey parsers, `dsse.verify_envelope` (every DSSE verify path), the
  status-list issuer key, the hybrid's classical leg, the renewal time-authority key, the KB-JWT holder
  key, the SD-JWT issuer key, trust-pack keys and caller-supplied previous root keys, the RATS Verifier
  key, and the AGT adapter's authorizer key, which now goes through the house primitive and whose
  "distinct from the signer" check compares key bytes instead of hex spellings. The independent Rust
  verifier applies the same rule on its DSSE, attached-target, SD-JWT and trust-pack paths, and like the
  Python validator it refuses a trust pack with a weak key in any role, not only in the root role. The
  bundle's own key keeps the §4a profile. A sweep test fails when a new Ed25519 verification bypasses
  the rule in any spelling it models: a call, an import alias, a `getattr` string or the `cryptography`
  key class; a second sweep does the same for every place the Rust verifier builds a key. Distinct keys
  are still not distinct parties: one secret can sign under the mixed-order variants of its key, which
  SPEC §4b now says, and a test keeps a 2-of-2 witness quorum met by two points of one secret.
  The release tooling under `scripts/` is covered by the entry below.

- **The release tooling refuses a weak key it pins, like the package does** (SPEC §4b). The pre-tag
  receipt (`pre_tag_receipt_lib.verify_receipt`, which the release workflow and the reader's
  `verify_pre_tag_receipt.py` run), the readiness artefacts of the audit matrix
  (`audit_candidate_matrix._artifact_signature_ok`), the findings register
  (`findings_register._signature_ok`) and the status page's receipt check
  (`render_site_data._check_receipt`) checked their signatures under a pinned key with the §4a profile.
  Measured on each: with the identity point in the trust anchor, a record nobody signed was admitted
  (`ok=True`, `verified`, `signature valid`, `passed`). Each now refuses such a key before any signature
  arithmetic and names the reason from `signature.TRUST_ANCHOR_REFUSAL`. The keys pinned today pass the
  rule, so this closes a path, not a live attack. The package's sweep now also walks `scripts/` and
  `tools/`. It models the spellings of `cryptography` only, so every library those files import is
  classified in a closed table, and an import of a signature library the sweep does not model counts
  as a use; pycose is one. The six places there that check a key arriving with the thing it signs
  (producer self-checks that take the key with the signature or read it from the record itself, and
  the recomputation and reading of a third party's published test vector under its printed test key,
  once through pycose) are named with their reason.

- **A pre-tag verifier judges a tree, it does not install it into the process that asked**
  (`scripts/pre_tag_audit_gate.py`, `scripts/verify_pre_tag_receipt.py`). Both put the judged tree's
  `src/` in front of `sys.path` and set `sys.pycache_prefix` and `sys.dont_write_bytecode`, and neither
  undid it, so a later plain `import pre_tag_receipt_lib` in the same process resolved to whatever the
  judged tree carried under that name. Measured on main 166aec47: eight cases of
  `tests/test_pretag_gate_state_typed_l5_g6_01.py` failed with `cannot import name 'canonical_bytes'`
  under PYTHONHASHSEED 5 and 7, and in 1 of 8 unseeded runs. Each verifier now restores the three
  settings when it returns and sets the bytecode protection on every call, and it removes the
  modules it loaded for the first time from a path it put on `sys.path` (Codex on PR 274: after the
  path was restored, `proofbundle` and `proofbundle._wire_b64` from the judged checkout stayed in
  `sys.modules`). The producer
  `scripts/pre_tag_receipt.py` keeps its process-wide switches on purpose, so that the audit program
  it starts inherits them.

- **The pre-tag receipt chain asks git about the tree it names, and reads each path as git stores
  it** (`scripts/pre_tag_receipt_lib.py`, `scripts/pre_tag_receipt.py`). The library's tree digest
  and trust-anchor read ran with whatever environment their caller had. The producer cleaned its own
  process, the release gate and the third-party verifier did not: measured on 2026-09-27, with
  `GIT_DIR` pointing at a clone of a genuine release, `pre_tag_audit_gate.py` judged a tampered tree
  that carried the copied receipt `ok=true, state=verified`, and `verify_pre_tag_receipt.py` said
  `VERIFIED` for a checkout at a commit that injected a dependency after the receipt. The library
  now passes every git call an environment without the redirecting names, one list shared with the
  producer and checked against `git rev-parse --local-env-vars` (the producer's list lacked five of
  git's own names, and `GIT_INTERNAL_SUPER_PREFIX` made a clean tree refuse), and it pins
  `core.quotePath=true` for the listing it hashes, because `core.quotePath=false` in a user's
  configuration changed the digest of a tree with a non-ASCII path; the pin is git's default, so no
  digest computed so far changes. The producer binds the gate source as the head stores it and
  refuses one that is a symbolic link (it had bound the target's digest while the commit carries
  the link text), and it decodes git's listings the way the filesystem names are, so a committed
  name that is not UTF-8 no longer refuses a clean tree. Contract:
  `tests/test_pre_tag_receipt_git_answers_for_the_named_tree.py`.

- **Every git call of the pre-tag receipt chain goes through a funnel, and git's configuration and
  environment no longer answer for it** (`scripts/pre_tag_receipt_lib.py`,
  `scripts/pre_tag_receipt.py`, `scripts/verify_pre_tag_receipt.py`). The list of redirecting
  environment names above did not hold. Measured on 2026-09-27 on the pushed head:
  - The third-party verifier's own calls had never used it. With `GIT_WORK_TREE` on a clean clone
    of the same commit, its cleanliness check came back empty for a checkout whose `verify_receipt`
    had been edited to return true, and a commit with an invalid receipt was `VERIFIED`, exit 0.
  - A `core.excludesFile` naming a tracked ignore file, set in the repository configuration, in
    `~/.gitconfig`, in `$XDG_CONFIG_HOME/git/config` or through `includeIf`, hid an untracked file.
    The producer took `check-ignore`'s source string for a tracked rule and emitted; on the real
    tree an untracked `conftest.py` that rewrote failing outcomes to passed was bound.
  - `core.useReplaceRefs=true` in the configuration switched replacement back on under
    `GIT_NO_REPLACE_OBJECTS=1`. The release gate said `ok=true` for a tampered checkout, against
    the replaced commit's digest. This holds for git before 2.42.0 (measured with 2.34.1); from
    2.42.0 on the switch is final and the key can only turn replacement off (measured with 2.55.0).
  - `core.worktree`, or a `--repo` naming a subdirectory, made `ls-tree` list relative to a prefix
    while `git show HEAD:<path>` stayed root-relative. Gate and verifier verified a tampered root,
    and with an attacker key in the root anchor the gate trusted it.
  - `check-ignore` read untracked names as pathspecs: `:build/conftest.py` was hidden, and an
    ignored `:!x.log` refused a clean tree.
  - The executable bit was read as `& 0o111` where git reads the owner bit. `run.sh` at 0655 (git:
    modified) emitted, and a file at 0645 (git: clean) refused.
  - A tracked directory replaced by a symbolic link hidden by a tracked rule was read through the
    link.
  - `GIT_ICASE_PATHSPECS` and `GIT_GLOB_PATHSPECS` refused a clean tree, `GIT_LITERAL_PATHSPECS`
    refused one that held an ignored file, and `GIT_TRACE`, `GIT_TRACE_SETUP` or
    `GIT_TRACE2_EVENT` on standard output moved the digest.

  Now `pre_tag_receipt_lib.git_run` is where the chain starts git. The third-party verifier
  carries a copy in its own file (`_git`), because its cleanliness check exists to refuse a
  modified library: routed through the library, a library whose funnel returned an empty `status`
  and whose `verify_receipt` returned true hid itself and was `VERIFIED` (measured on an
  intermediate version of this change). A contract test derives every call site of the chain and
  of everything it loads from the syntax tree, fails on any outside the two funnels, and holds the
  two equal in allowlist, pinned options and built environment. The funnel builds git's
  environment from an allowlist: `PATH` (and `SYSTEMROOT` on Windows) pass through;
  `LC_ALL`/`LANG=C`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL` empty,
  `GIT_NO_REPLACE_OBJECTS=1`, `GIT_OPTIONAL_LOCKS=0` and `GIT_TERMINAL_PROMPT=0` are set; nothing
  else is inherited. `GIT_WORK_TREE` is pinned to `--repo` and discovery stops at it, and git must
  name `--repo` as the top level with an empty prefix before any question is asked; listings use
  `--full-tree`. The configuration is pinned on the command line, where it outranks every file:
  `--no-replace-objects` and `core.useReplaceRefs=false`, `core.quotePath=true`, `core.excludesFile`
  and `core.attributesFile` on an empty file, an empty `core.fsmonitor` (no hook runs),
  `core.untrackedCache=false`, `core.ignoreCase=false`, `core.commitGraph=false`,
  `core.checkStat=default` with `core.trustctime=true`, and `color.ui=false`. A rule hides an
  untracked path only if it comes from a tracked `.gitignore` in a directory that contains the path.
  Names go to `check-ignore` as `./<name>`, because `check-ignore` rejects every path under
  `GIT_LITERAL_PATHSPECS`. The mode is read from `S_IXUSR`, as git does with `core.fileMode=true`.
  Every directory above a tracked path must be a real directory under `lstat`. The audit program
  gets the caller's environment without the `GIT_` namespace.

  Considered and not pinned, with the reason:
  - `core.fileMode`, `core.symlinks`, `core.autocrlf`, `core.eol`, `core.safecrlf`,
    `core.precomposeUnicode` and `core.protectNTFS`. The producer compares bytes and modes itself,
    so these only reach the verifier's listing, where pinning them would refuse checkouts on
    filesystems that need them.
  - `core.sparseCheckout`, `diff.ignoreSubmodules` and `status.*`. They are overridden by
    `--untracked-files=all` and `--ignore-submodules=none`, or they do not change a porcelain
    listing.
  - `core.abbrev`, `pager.*`, `alias.*`, `i18n.*`, `log.*` and `trace2.*`. `ls-tree` prints full ids,
    there is no terminal, built-ins cannot be aliased, no commit is shown, and `trace2.*` is read
    only from the system and global files, which are not read.
  - `extensions.*`, grafts and a shallow file. They decide which objects are present and which
    parents a commit shows, not which tree a commit names or which bytes a blob id stands for.
    Alternates stood on this line and do not: an alternate object directory can hold other bytes
    under an id (see the next entry).
  - `safe.directory`. Nothing can supply it any more (no system or global file is read, and git
    ignores it in a repository's own file), so a repository owned by another user fails closed.

  Named limits, unchanged:
  - A clean tree with a `text eol=crlf` or `ident` attribute, and a tracked or ignored name that
    carries a newline, is refused by design. The real tree has none.
  - A file that a tracked `.gitignore` of the tree ignores stood here as accepted, whatever the
    audit reads from it. It is refused before the audit since the entry on ignored files below.
  - A `PATH` that leads to a git wrapper is part of the trusted base, like the interpreter.
  - The verifier's cleanliness listing is still `git status`. Index bits (`assume-unchanged`,
    `skip-worktree`) and filters named in `.git/info/attributes` are state inside the reader's
    clone, which the printed LIMIT already puts outside the verdict.
  - `scripts/sign_readiness_artifact.py` is loaded for one constant, and its own git calls are
    outside the chain.

  The top level git names is compared with `--repo` as a resolved path, not as text (Codex on this
  PR, round four, P1; estimated there and not measured here, as no Windows runner is available).
  Git for Windows prints it with forward slashes (`C:/repo`) where the resolved `--repo` reads
  `C:\repo`, so the text comparison refused the real top level of every repository on that
  platform, in the library's funnel and in the verifier's copy. Measured with the POSIX form of the
  same defect, a `git` first on `PATH` that answers `<root>/`: both funnels refused it at 0b7252c6
  and accept it now, and the same `git` answering the parent directory is still refused. An answer
  that is empty or not absolute names no directory and is refused, because resolved it would stand
  for the working directory of the process. For an answer that already is the resolved path, as git
  prints it on Linux, the verdict is the one the text comparison gave.

  Contracts: `tests/test_pre_tag_git_configuration_does_not_answer.py` (a case red on the pushed
  head for each finding above, and controls),
  `tests/test_pre_tag_chain_asks_git_through_one_funnel.py`
  (the call-site derivation, the allowlist, and a sweep of 72 environment names and configuration
  keys against a clean baseline) and `tests/test_pre_tag_top_level_is_compared_as_a_path.py` (the
  spelling, the empty and relative answers, and the two copies held to one answer).

- **What the pre-tag receipt chain reads from git's object store is the object its id names**
  (`scripts/pre_tag_receipt_lib.py`, `scripts/pre_tag_receipt.py`,
  `scripts/verify_pre_tag_receipt.py`). git hands out whatever its object store holds under an id,
  and it does not hash what it reads on every path. Measured on 2026-09-27 with plain git on a
  rewritten loose object: 2.34.1 hashes an object it parses from a revision argument and 2.55.0 does
  not, `cat-file` hashes nothing on either, and a tree below the root is read without a hash on both.
  On the head before this change:
  - The loose object of `audit_artifacts/pre_tag_trusted_pubkeys.txt`, rewritten with another key
    under the same id, made the release gate answer `ok=true, state=verified` for a receipt signed
    by that key, with the tree digest and the checked-out file unchanged (a review finding, P0; git
    2.55.0). A pack whose index names that id for other content, and an alternate object directory
    holding other content under it, did the same.
  - The tree `audit_artifacts`, rewritten under its id to list another blob as the anchor, did it
    with git 2.34.1 as well.
  - The producer hashed the gate source from `cat-file blob`; with the gate's object rewritten, it
    bound the digest of a gate the head does not carry (both versions).
  - The third-party verifier read the gate source and the receipts with `show` and the anchor
    through the library, and said `VERIFIED`, exit 0, for a receipt that binds another gate, for a
    committed receipt that does not verify whose object held one that does, and for a key the
    committed anchor does not name (git 2.55.0). With the tree `scripts` rewritten to list a
    modified library, also added to the index, `git status` was clean and that library verified a
    receipt nobody trusted signed (both versions).

  Now every object the chain reads is read through `git cat-file --batch`, hashed in the process as
  git defines an id (SHA-1 or SHA-256 by the length of the id) and compared with the id it was asked
  for: the commit, every tree below it, the anchor and the gate source (`git_objects`, `git_tree`
  and `git_file` in the library). The tree digest is still taken over the text of `ls-tree`, so no
  digest changes, and that text must list exactly the tree read from checked objects. The producer
  compares the checkout with the checked tree. The verifier carries its own copy of the check, runs
  it on the commit and every tree before its cleanliness check, and on the gate source, the anchor
  and each receipt before it uses them; an object that is not the one its id names ends the run as
  `NOT_MEASURABLE`, exit 2. A genuine store in a pack or behind alternates verifies as before.

  Named limits:
  - The check shows that the bytes read are the object the id names. That the head is the commit a
    reader expects stays the job of the tag and the attestation.
  - The verifier's `git status` still takes the index's stat data on trust (the entry above names
    the index as state inside the reader's clone).
  - The verifier's `git status` and its listing of the receipt folder, and the producer's
    `diff-index`, read the trees again after the check; a writer that changes the store in between
    is outside the chain, as it is for the tree measurement.
  - Outside the chain and unchanged: `scripts/sign_readiness_artifact.py` and
    `scripts/audit_candidate_matrix.py` read the readiness anchor with `git show HEAD:<path>`.

  Contract: `tests/test_pre_tag_receipt_git_answers_for_the_named_tree.py`
  (`EachObjectReadIsTheObjectItsIdNames`: the finding, a pack, alternates, a rewritten tree, the
  producer's and the verifier's reads, a generator that rewrites every object of a head in turn, a
  contract that holds the verifier's copy of the check to the library's, and three cases for the
  order of the reads: a writer that rewrites a tree for exactly the duration of a second listing
  must not decide the producer's comparison or the digest, and the verifier checks the commit's
  trees before it loads a library that could act when it is loaded).

- **The pre-tag receipt producer refuses a tree in which ignored files lie**
  (`scripts/pre_tag_receipt.py`). A review comment on the pull request named it, and the maintainer
  decided to close it before the tag: a file that the committed `.gitignore` names, lying
  uncommitted in the checkout, is read by the audit, while the receipt binds `git ls-tree -r HEAD`,
  which does not carry it. Measured on the head before this change: exit 0, and the audit's record
  held that file's content.

  Now every path on disk that the head does not carry refuses before the audit starts, ignored ones
  included, and the audit does not run. The refusal names each such path as ignored, with the rule
  and the file it comes from, and points at a fresh checkout (`git clean -ndX` names what lies
  there). The paths come from the same walk of the filesystem as the untracked ones, so no
  configuration decides the answer; `check-ignore` is asked only which rule to name.

  After the audit, a path that a tracked `.gitignore` ignores is a file the audit wrote, because
  the measurement before refused every one; it does not refuse. A test suite run as the audit writes
  caches into the tree it runs in (hypothesis writes `.hypothesis/`, measured), and refusing them
  would refuse every such audit. A file the audit writes that no tracked rule ignores still refuses.

  The release workflow does not run the producer: its pre-tag step runs the release gate, which
  this change does not touch, so the refusal cannot fire there. On the producer's own path the one
  writer of ignored files that was found is the audit itself, handled above.

  Named limits:
  - An empty directory is not a path the walk reports. `git status --ignored` does not list an
    empty ignored directory either; `git clean -ndX` names it (measured with git 2.34.1).
  - A file that appears during the run and is gone before the second measurement is still
    invisible to both measurements, as the entries above say.

  Contract: `tests/test_pre_tag_receipt_refuses_a_dirty_tree.py` (the finding, five shapes of an
  ignored path planted before the audit, a cache the audit writes, and an untracked file it
  writes). Four cases of `tests/test_pre_tag_git_configuration_does_not_answer.py` that measure how
  the answer of `check-ignore` is read now let the audit write their ignored file, because one that
  lies there before the audit refuses whatever its name.

- **An empty container is malformed in both implementations, and every malformed exit names its
  reason** (release scope lines S106 and S108, `tools/pb_verify_rs`). Python refuses `signatures: []`
  and an empty `payloadType` as "must be a non-empty list/string"; the Rust verifier ran an empty
  signature list through its loop to "not verified". Measured on 2026-09-25 at four surfaces: the
  generic DSSE verify answered `FAIL`/exit 1 where Python refuses the envelope, the trust-pack
  threshold reached the statement and reported on it, and an attached relation target with an empty
  list was carried on as attached-but-unverified, the same exit class as Python with a different
  reason. The empty list and the empty `payloadType` are now errors in Python's wording, the trust
  pack judges the list before the statement as Python does, and a structural error of an attached
  target ends the resolution with "cannot read --with-related", as in Python. A present signature
  that does not verify is unchanged. The three remaining bare `MALFORMED` exits (`verify-bundle`
  twice, `verify-trust-pack-threshold` once) print their reason. `crosscheck.py` holds the empty list
  on three surfaces with the reason, not only the exit; the old behaviour turns all three red.
  The per-target key is not the envelope (Codex on PR 272): key material that decodes but is no
  Ed25519 key leaves the target attached-but-unverified, as Python's `verify_ed25519` answers False,
  and only a `--related-pub` that is not base64 is refused, as "cannot decode --related-pub". The
  checks before the key run in Python's order, the payload first.

- **The parity registry states what the verifier does when no policy is named** (release scope line
  R1, `scripts/rust_parity_registry.json`). The registry ships in the sdist and is what a second
  implementation reads. Its v0.2 entry said the verifier "deliberately does not decide that for it
  (policy_decision stays None)", which reads as a neutral outcome. Measured on 2026-09-25 against
  `verify_agent_review_v02`: without a named policy the result carries `policy_decision: null`, the
  advisory code `POLICY_NOT_EVALUATED`, and `automation.safeForAutomation` is false with that code as
  its blocker; with the named default policy the same receipt is `accept` and released for
  automation. The entry now says so. A new contract measures the no-policy state and requires every
  registry note that speaks of `policy_decision` to name each blocker the verifier reports and the
  false automation verdict; the old wording fails it. `docs/AGENT_REVIEW_PREDICATE.md` already
  described the state correctly and is unchanged.

- **A declared error marker is checked against both implementations** (release scope line S32,
  `tools/pb_verify_rs`). A relation vector's `errorContains` read as a statement about the case,
  and it was held against the Python output only: the Rust verifier printed `{"lineage": ...}` and
  no reason, and the differential compared exit class and lineage. Measured on 2026-09-25: 21
  relation vectors declare a marker, the Python output carried 21, the Rust output 0. So Rust could
  reach the same verdict for a different reason and nothing would notice.

  The Rust relation subcommands now print `reasons` beside `lineage`, in Python's wording and with
  Python's stable codes: the reason of each failing edge, the structural errors, the successor
  warning and the policy violation codes, which were computed and deliberately not printed. The
  paths that returned exit 2 through a bare `Err(_)` now name what failed. The loader keeps the
  target subject's state (present, absent, ambiguous, malformed) as Python does, so a failing
  subject pin names its own code instead of one shared mismatch. `crosscheck.py` requires the
  marker in both outputs: 21 of 21. Verdicts are unchanged, and the common vocabulary still reads
  `lineage` only.

- **A foreign identifier on the bundle itself is a refusal, not `invalid`** (release scope line
  Z.278, `src/proofbundle/evalclaim.py`). `classify_eval_claim` answered `invalid` for a bundle whose
  top-level `schema` names another format: `verify_bundle` raised the typed `UnsupportedError`, and
  the broad `except` above it folded that refusal into the invalid outcome. Measured 2026-09-05 in
  issue 147 with an `inspect-receipts` 0.3 receipt. The envelope identifier is now read first, after
  the verifier's resource limits, which a document given as a dict now meets as one given by path; a
  present, non-empty identifier that is not `proofbundle/v0.1` returns `refused_unknown_schema`.
  An absent identifier, and a present value that cannot be one (empty, a number, a list, null),
  declare no other format and stay `invalid`; so does an unknown `signature.alg` or
  `merkle.hash_alg` under our own identifier, which `verify_bundle` reports with the same exception
  type. `decode_eval_claim` is unchanged.

  Five vectors under `conformance/envelope_profile/`, fifteen there and 135 in the corpus. Seven
  planted defects, all caught by the corpus; three escaped at first and each added a vector. The Rust
  differential was re-measured over the new corpus: 61 of 135 reproduced, 74 named by kind.

- **A verdict field must hold a verdict: five public exporters stopped coercing `passed`** (R-B4,
  `src/proofbundle/intoto.py`, `src/proofbundle/_membership.py`). `bool("false")` is `True`, and
  `"false"` is a non-empty string, so it also survived the presence check that made a required field
  look validated. Called directly, `to_test_result_statement` reported `result: "PASSED"`,
  `to_eval_result_predicate` emitted `passed: true`, `svr_properties` set
  `PROOFBUNDLE_THRESHOLD_MET`, and `to_intoto_statement` passed the string through unexamined. All
  five now go through one predicate (`_membership.is_bool`, a `TypeGuard`) via
  `intoto._require_bool_verdict`, which refuses rather than coercing and names the field and the type
  it received. The verify boundary already typed the field (A-15, 2026-09-19) and is why no signed SVR
  and no CLI path was exposed; it calls the same predicate now instead of its own inline check, so one
  invariant has one home rather than two.

  What this restores is monotonicity, in the sense the in-toto attestation spec gives the word: a
  value that merely looks like a non-pass must never produce a more permissive outcome than the
  non-pass itself. `'False'`, `'FALSE'`, `'0'`, `'no'`, `1`, `[1]` and `{'a': 1}` behaved like
  `'false'`; `1` is the one a type check written against `int` would have let through, because `bool`
  subclasses `int`.

  Contracts `tests/test_das_verdikt_muss_ein_bool_sein.py` and
  `tests/test_verdikt_truthiness_scanner.py`. Catch proof measured against the parent commit without
  the fix: 73 subtest failures and 3 test failures. Three cases carry `_REGRESSIONSWACHE` in their
  names because they were already green there — a case that cannot fall is not evidence, and saying so
  in the name keeps a reader from counting it.

  **A sixth site, and it is the one that signs** (`src/proofbundle/sdjwt_issue.py`). `issue_sd_jwt`
  copied `passed` into the always-open claims of an SD-JWT and signed them three lines later, and
  `check_binds_bundle` then accepted that receipt as bound, because it compares the field to the bundle
  payload for equality and both sides carried the same string. Measured at tag `v6.1.0` (`dcac5aee`) and
  again at this branch's head before the guard. The four `intoto` sites build a statement a caller may
  sign; this one produces a signed artefact whose `passed` is not a verdict, and no downstream reader can
  repair that. It refuses now, through the same `is_bool` predicate and the same `BundleFormatError`.

  Five of the six sites were in one file. Sweeping that file is not sweeping the class, and the scanner
  did not close the gap because it modelled the class as coercion: this site coerces nothing, it hands an
  unexamined value to somebody else's truthiness test. The scanner now also finds the **pass-through**
  shape — a read of the field that leaves the function, as a dict value, a sequence element, a call
  argument or a return — and resolves one level of aliasing, which closed a second, previously unstated
  hole (`v = claim["passed"]` followed by `if v:` was measured as no finding). Its catch proof is the
  real site restored to its `v6.1.0` form, not a planted one. The one site the wider rule newly reports,
  `cli._cmd_show_eval`, is in the documented baseline with the measurement for why it may stand: the
  claim comes from `decode_eval_claim`, and the use is a printed line.

  `policy.py:269` has carried `_require_bool` with this exact reasoning in its docstring since before
  any of this. The knowledge existed in the package at one surface and never travelled to the others,
  which is the more useful lesson than the count.

  **This corrects a sentence in the 6.1.0 release note, and the correction is the point of saying so
  here.** That note reads "Malformed claim values are refused. A string such as passed: \"false\" is no
  longer treated as a true verdict by the affected exporters", citing #231. #231 typed the verify
  boundary; it changed no file in `intoto.py` and none in `sdjwt_issue.py`. Measured at tag `v6.1.0`
  (`dcac5aee`) by calling the surfaces directly: `to_test_result_statement` returned `PASSED`,
  `to_eval_result_predicate` emitted `passed: true`, `svr_properties` set `PROOFBUNDLE_THRESHOLD_MET`,
  `to_intoto_statement` passed the string through, and `issue_sd_jwt` signed it. The CHANGELOG entry for
  that release is narrower and holds — it says three exporters "are covered by it", meaning by the
  boundary, which is true for every path that decodes first. The release note compressed that into a
  statement about the exporters themselves and dropped the condition, and the exporters are public API,
  so a caller who never decodes is exactly the caller it misleads. 6.1.0's own text is left as it was
  published rather than rewritten: the sentence became true with this change, and a release note that
  silently starts describing a later fix is a worse record than one carrying a correction.
- **A bare install degrades to clean skips, and the gate that claims it now runs it**
  (`tests/test_action_input_injection.py`, `.github/workflows/published-artifact-gate.yml`). One
  unguarded `import yaml` aborted the whole pytest run on an install without extras, so 19 of some
  four thousand tests were collected and the rest never ran. Five sibling modules guard the same
  dependency correctly. The import now goes through `pytest.importorskip`.
- The workflow step whose comment claimed this property installed the `[test]` extra and only then
  ran pytest, so the bare case was never exercised there. It now collects on the `[eval]` state
  BEFORE the `[test]` install. A gate whose promise is broader than what it executes reports green
  about a case it did not attempt.

Contract `tests/test_bare_install_degrades_to_clean_skips.py` checks the property over every test
module and reads the optional set from the `test` extra in `pyproject.toml` rather than from a list
typed here, because a typed list is a second statement about what is optional and two statements
drift. Catch proof on a bare venv: with the guard rc 0 and 4948 tests collected, without it rc 2 and
collection interrupted.
- **R1 counts distinct units rather than list entries** (`src/proofbundle/cap1.py`). A coverage list
  naming the same unit twice read as two covered units, so a report could claim a count it had not
  earned. The verdict now names the duplicates, because a number that silently absorbs a duplicate
  is a number nobody can check.
- **R8 validates every element, not only the container** (`src/proofbundle/cap1.py`). The guard
  accepted any list, including one holding `{}` or `None`. The failure now names the offending
  element instead of the field.
- **The CAP-1 early return no longer silences the legacy alias check**
  (`src/proofbundle/agent_review.py`). `_widerspruch_in_altfeldern` ran on the v0.1 path only, so a
  document taking the CAP-1 branch could report `complete` while its own legacy fields said `0 of
  100` with a gap. The check runs on both branches, and `_is_zahl` returns `TypeGuard[int]` so the
  narrowing holds at the call site.

Contract `tests/test_codex_funde_248_20260923.py`, with a catch proof measured on the branch:
reverting `cap1.py` to its `main` state turns 7 cases red, reverting `agent_review.py` turns 3 red,
and both fixes present leave 268 passing with 14 subtests.

- **An absent `contentRootAlg` and a present but unusable one are no longer the same thing**
  (`src/proofbundle/intoto.py`). The guard read `isinstance(alg, str) and alg`, so a PRESENT value
  that was not a non-empty string fell into the absence branch and resolved to the LEGACY algorithm
  with `ok=true`. Measured before the fix, all six reported values resolved to legacy: `""`, `0`,
  `True`, `[]`, `{}` and `null`. An unknown STRING id already failed closed one line later, and that
  is what made the hole hard to see, because the obvious case behaved and only the type-confused one
  did not.

  Absent still means the key is not there, which is how released 2.0.0 receipts keep verifying.
  Present and unusable resolves to a sentinel matching neither registered id, so the serializer
  refuses it as it refuses any unknown algorithm, and the verdict names what was found.

  THE HONEST BOUNDARY: `contentRootAlg` sits INSIDE the signed payload, so this is not a signature
  bypass. The damage is that the verdict describes signed content wrongly, that a receipt the
  contract says to reject is accepted, and that a stricter foreign verifier rules differently on
  identical bytes.

Contract `tests/test_s26_absent_is_not_present_but_unusable.py` binds the equivalence
`(field ABSENT) == (resolved algorithm == LEGACY)` in both directions, with two counter-directions
so a rule refusing everything could not pass as correct. Catch proof: restoring the old guard turns
the two catch cases red, and so does making the sentinel a registered name; 123 passed and 2 skipped
before and after.

- **The release-scope title gate trusts only a tag the clone shows, and the cut's test checks each
  cited line in its own tree** (`scripts/b7_release_scope_title_gate.py`,
  `tests/test_release_scope_cut_holds.py`, pull request 294, the 6.2.0 cut). Two P1 findings of the
  fourth review round, each reproduced at 5a9ddc06 before it was fixed. `git tag --list` lists the
  tags a clone holds, not the tags that exist: with `pyproject.toml` at 6.2.0 and only `v6.1.0`
  fetched, a branch that only the 6.3.0 scope names came back outside the scope with exit 0. Only a
  source tag the clone shows decides now; without it the gate judges the branch by whichever of the
  two candidate scope files names it, and the landing card says NOT MEASURABLE rather than count a
  release it cannot know. And a `path:line` citation passed if any tree its row names matched, so a
  line stale in its claimed revision stayed green beside another revision. Each citation is now
  checked in the tree its own sentence names, or the one its row names for its path, and in the
  working tree only where the row names none; a row that names trees and none for the citation is a
  finding. The cut's R1 and R-B4 rows had one each, true in every tree the rows name, and now name
  `v6.1.0` for them.

- **A reader's NOT MEASURABLE is no longer an empty result in the release-scope gate and the landing
  card** (`scripts/b7_release_scope_title_gate.py`, `scripts/b7_release_scope_landing_card.py`, pull
  request 294, the 6.2.0 cut). The P1 of the fifth and last review round, reproduced at 76f260a2
  before it was fixed: without a tag the clone shows, the gate judges a branch by the candidate scope
  that names it, and a candidate it could not read answered with an empty mapping. A 6.2.0 scope
  naming `fix/a1` without its `## Out`, beside a readable 6.3.0 scope, judged `fix/a1` against 6.3.0,
  outside the scope, exit 0. An unreadable candidate now leaves the release undecided. The sweep for
  the class found two more callers of that shape: the gate kept the list of its guard against lines
  without an identifier and dropped the guard's NOT MEASURABLE, so a scope whose branch column is not
  headed `Branch` or `Zweig` let such a line vanish in green; and the landing card dropped the state of
  the branch reader, so a scope whose branches it could not read counted every line as a rider. Both
  fail closed now. With the source version at 6.2.0 the 6.3.0 scope is a candidate, and it names no
  branch yet, so the gate is red on every pull request until it does (`RESTRISIKO_620.md`).
- **The second reader of the cost bound judges through the curve's own verdict**
  (`tests/test_structural_budget_reachability.py`). The exclusion of `renewal.verify_sequence` from
  the generic budget holds only while the cost curve holds its own bound, and this file checked that
  with a copy of the rule: the maximum against the bare `GRENZE_S`, without the machine factor and
  without the reference-machine binding the curve itself applies. On a CI runner under coverage it
  judged the runner: measured 2026-09-28 at 3977fcdf, 1.025 s against 1.0 s, red, while the curve
  skipped the same axis on that host with the measured factor as its reason. The check now calls
  `test_kosten_am_limit_unter_der_obergrenze` of the curve, as `scripts/budget_axis_measurement.py`
  does, and turns the curve's skip into a visible skip. Three counter-examples plant a measurement
  with the reference machine's recorded clamp: five times the bound stays red with the curve's own
  message, half the bound stays green, and 1.025 s on a build host is skipped naming the owner card.
  Against the old copy the first and the third fail; the second passes in both.

### Added

- **Offline verification of Agent Governance Toolkit (AGT) governance receipts**
  (`src/proofbundle/adapters/agt_receipt.py`). Verifies an AGT MCP tool-call receipt without AGT
  installed and without network access: Ed25519 over the canonical payload, the optional
  external-authorizer signature, the `parent_receipt_hash` chain link, and the house exit-code
  contract (0 verified, 1 crypto or structural failure, 2 malformed input, 3 relying-party
  requirement unmet). No AGT code is copied; the wire format was read from the published tree at
  commit `a917ad4ac04aff11a5e9e21f6a26b91642b750cd` and re-derived. AGT is MIT, Copyright (c)
  Microsoft Corporation.

  **A measured divergence is pinned by this work and belongs in the record.** AGT documents its
  canonicalization as "RFC 8785 JCS canonical JSON" and implements
  `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`. The two disagree on
  `timestamp`, which every receipt carries as a float. Measured on a receipt produced by AGT's own
  signer, timestamp `1758600000.0`: the sort_keys form renders `1758600000.0`, RFC 8785 renders
  `1758600000`, the receipt's own `payload_hash` matches the former, and the Ed25519 signature is
  valid against the former and REJECTED against the latter. A verifier built from the documentation
  therefore rejects valid receipts. This adapter verifies against the form AGT actually signs and
  names that form in the verdict, rather than trying both and reporting whichever matched, which
  would turn "the receipt is valid" into "one of two readings is valid" with no way to tell which.

  Two further readings are kept apart rather than bridged. The proposal document says the decision
  vocabulary is `permit`/`deny`; the implementation says `allow`/`deny`, and a `permit` receipt is
  refused with the reason named. An external authorization is accepted only against a relying
  party's own trusted-key list and only when that key differs from the receipt signer; with no list
  supplied the check is recorded as NOT evaluated, which is not a pass.

Conformance: `tests/test_agt_receipt_verifier.py`, 18 cases over five receipts produced by AGT's
own signer (allow, deny, externally authorized, tampered after signing, wrong key), plus
counter-directions so a verifier that accepts nothing could not pass. Catch proof: five mutations
of the adapter (signature check always true, missing trust list read as acceptance, authorizer
allowed to equal signer, `permit` accepted, empty chain read as clean) each turn the suite red.

- **The release body is rendered from a versioned content source and is the text that gets
  published** (`scripts/render_release.py`, `release_notes/release-source.json`,
  `.github/release.yml`). The grouping of a release comes from a reviewed file, not from the
  conventional-commit prefix of a pull request title. Measured over all 48 entries of 6.1.0: five
  prefixes span more than one group and `fix` alone spans three, so the prefix separates none of
  them. Every entry keeps its editorial short form AND its original title, author and URL, because
  a short form that replaces its original leaves a reader nothing to check it against.

  **The gap this closes was named in the workflow's own comment.** The hygiene step generated the
  notes ahead of time and checked them, while the draft step let GitHub build them a second time:
  over an identical range that is the same text, but byte identity is not guaranteed. The
  step now renders into `/tmp/release_notes.md`, checks that file, records its sha256, and the
  draft receives it via `body_path` with `generate_release_notes: false`. One text, checked and
  published.

  The renderer refuses to run unless the source declares the version asked for. It is deliberately
  not a general generator: a 6.1.0 source carries an audit status measured on the 6.1.0 tree, and
  rendering it under a later tag would publish a claim about a tree nobody examined.

  `.github/release.yml` orders GitHub's own generated notes as a fallback for hand-made releases.
  Its `release:*` labels are proposed, not claimed to exist; the catch-all group is a finding that
  a label is missing, not a home for unclassified entries; and bot or CI pull requests are NOT
  excluded, because in this project a dependency bump can carry a verification property.

Contract `tests/test_render_release.py`, 13 cases. The strongest one renders the real 6.1.0 source
and compares it BYTE FOR BYTE against the independently written, owner-reviewed body in
`release_notes/RELEASE_NOTES_v6.1.0.md`: a renderer measured only against fixtures it also shaped
proves self-consistency and nothing more. Counter-directions included so that neither a renderer
refusing everything nor a check reporting findings for everything could pass.

## [6.1.0] - 2026-09-19

The work on `main` after the `v6.0.0` tag, cut into a release. Owner word, order
`QITEM-PROOFBUNDLE-610-SCHNITT-LANDEN-KETTE-01`, option A: 6.1.0 is what has been on `main` since
`v6.0.0`, plus the two P1 findings of the 2026-09-19 audit, R7 and the cheap documentation
findings. The other 54 lines of the 2026-09-12 scope move to 6.2.0 unchanged, and
`docs/release_scope/6.2.0.md` carries them word for word.

This section was `## [Unreleased]` until the cut, and it said the version was deliberately not
bumped because "a bump without a release would claim a delivery that did not happen". That
sentence was true while it stood and would have become false the moment the number moved, so it is
replaced rather than left standing. What is open and why is in `RESTRISIKO_610.md`, which lands
before the closing round, not after it.

### Added

- **The verifier block, and `agent-review/v0.3` to carry it** (`producer.verifier`,
  `src/proofbundle/verifier_block.py`, `verify_agent_review_v03`, `validate_agent_review_v03_predicate`;
  v0.3 is v0.2 plus this one optional field, and v0.2 stays exactly what 6.0.0 shipped — the same
  bytes were measured refused by 6.0.0 and accepted by a v0.2-extension draft, which is why the block
  is a version and not an extension;
  contract in `docs/VERIFIER_BLOCK.md`). A receipt can now say WHICH build produced it: a digest
  over the package's own files with the measurement's source stated (`installed-record` from the
  installer's RECORD, or `source-tree`), the conformance vector set it was held against (digest
  over manifest and every case file), and a reference to a separate in-toto
  `test-result/v0.1` statement, joinable by digest equality without trusting the issuer for the
  join. Measured on 2026-09-12 against 6.0.0: no receipt and no verify result carried a build
  identity, and two wheels of the same version were indistinguishable from the receipt. The
  block is self-declared and says so; the verifier reports it (`verifier_block`,
  `matches_this_verifier` in MATCH / MISMATCH / NOT_EVALUATED) and never folds it into `ok`.
  v0.1 refuses the field, a 6.0.0 verifier refuses a v0.2 receipt carrying it — loudly, never by
  misreading. Five conformance cases with flip tests.
- `conformance/run_conformance.py --test-result-out PATH` writes the run as that in-toto
  test-result statement: subject the measured build digest, configuration the vector set, result
  by the corpus rule that a skipped check is never a passed one (`FAILED` on any failure,
  `WARNED` when a case ran partially or not at all, `PASSED` only when every case ran in full),
  the case ids listed per outcome. Written unsigned; signing is the producer's step.
- `scripts/verify_pre_tag_receipt.py`: the pre-tag audit receipt, verified by someone who holds
  a clone. Receipt, pinned key and gate source are read from the COMMIT, never from the working
  tree; the tree digest is taken by the same library the release gate uses, at the checked-out
  commit, and a checkout at another head is refused rather than measured. Three contracts, each
  planted and refused: no valid receipt fails; a receipt made for another commit fails; a
  receipt with a correct signature over the wrong subject fails. The limit — the trust root is a
  key committed in the same repository, and script and library are files of the tree they
  verify — is printed with every verdict. `RELEASE.md` names the command where a reader decides
  they have checked a release, and says what it establishes and what it does not;
  `docs/PRE_TAG_AUDIT.md` no longer describes the prose check the gate stopped reading.
- A collector job `all-checks-passed` in ci.yml that ALWAYS reports: it needs the jobs the
  ruleset requires from this file (`test`, `coverage`), runs under `if: ${{ !cancelled() }}`, and
  turns red when any needed job did not succeed -- `skipped` included -- or when the full test
  matrix did not run on the event (fork pull request without the `landung` label). Owner
  decision A on card OA-3c67b06ad6: one always-running context replaces six, four of which a
  condition could leave uncreated. `guard` stays a required context of its own, because it lives in
  fork-pr-isolation.yml and a job cannot need a job of another workflow. The ruleset is NOT
  switched by this change; that is the owner's step once this job has run green.
- The reachability gate learned two shapes of that job. A job condition made only of
  `always()` or `!cancelled()` is unconditional, not `produced-only-if` (the first draft
  would have called the collector conditional and been red for the wrong reason). A REQUIRED
  context on a job with `needs` and no such guard is reported as `skipped-is-passed` and
  turns the gate red: the job is skipped whenever a needed job fails, and a skipped required
  check reads as passed, so it can never block on the failures it depends on. A contract
  holds the collector's copy of the matrix condition byte-identical to the matrix's own.
- Register form 6.1 for the findings register, as a second carrier next to the signed v1: the
  producer emits `findings_register_v2.json` plus two generated views, every record carries the
  byte range of its own evidence, and the three 6.1 register lines are written directly in the new
  form with their measured starting position.
- The 6.0.0 register body now carries the signature of the anchor key, and the written target value
  carries its provenance — a chain is appended rather than the previous value overwritten.
- A guard that no shipped test module imports a non-shipped module by bare name. The
  `published-artifact-gate / hermetic-cleanroom` job aborted at collection because
  `tests/test_belegdatei_traegt_ihren_eigenen_digest.py` put `scripts/` on `sys.path` and then wrote
  `import gen_findings_register`, while that script is deliberately withheld from the sdist. Nothing
  ran, not one of the other tests. The guard decides in the checkout, where both the file and the
  distribution listing are present, and leaves the cleanroom unchanged.
- **Coverage in the language of CAP-1, target 6.1.0 (not part of 6.0.0).** A `proofbundle.cap1` module
  checks a coverage-attestation document of `draft-hillier-coverage-attestation-00` (profile `cap/1`)
  against the draft's rules R0 to R8, never raises, and reads strictly (a duplicate JSON name is a read
  error, not a verdict — RFC 8259 section 4 calls that behaviour unpredictable, and the draft author's
  own probes show three equally conformant readers disagreeing). The fifteen conformance vectors of the
  draft author (Certisyn-Inc/certisyn-drafts, commit 0980d32, Apache-2.0) ship under `conformance/cap1/`
  as cases of the new kind `cap1_document` with one axis, `cap1Rules`, the exact set of rules that must
  fire; NC-05 pins R1 and R5 together, and a counter-proof that fails for the wrong reason fails the
  case. An `agent-review/v0.2` predicate may carry `coverage.strata`, `coverage.integrity` and
  `coverage.absenceAssertions`; the rules are borrowed from `cap1`, each reports its own reason code
  (`COVERAGE_CAP1_SHAPE` … `COVERAGE_CAP1_SUPPORTS_MISSING`, `COVERAGE_CAP1_RULE_UNMAPPED` for a rule the
  mapping does not know), `status` is derived from `integrity.complete` and a stated status that
  disagrees is rejected (`COVERAGE_CAP1_STATUS_CONTRADICTS_STRATA`). The older counters stay readable as
  aliases with a stated decay (COMPATIBILITY.md); a v0.2 receipt without strata carries the advisory
  code `COVERAGE_LEGACY_FIELDS`. v0.1 rejects the three fields as unknown.

### Fixed

- **A-15 / A-55 / A-60 — a loader annotated `-> dict` returned whatever it decoded.** The verify
  boundary now types what it reads instead of trusting the annotation, and three exporters that
  coerced the verdict field with `bool()` are covered by it: a claim carrying `passed` as the
  STRING `"false"` verified as passed. Catch-proofs measure at the export sites, one case each,
  red before the fix and green after, rather than only at the boundary that fixes them.
- **A-16 — the boundary refuses a malformed claim instead of deciding on it.** SemVer: this can
  turn a verdict that was `ok` into a refusal for input that was never valid. That is a behaviour
  change for callers who were relying on the silent acceptance, and it is deliberate — a verifier
  that decides on bytes it could not parse is not stricter, it is wrong. No ADDITIVE version bump
  can carry it, so it rides the MINOR that this release already is.
- **A-39 — CAP-1 coverage divided by a denominator that could be zero.** The null case now has its
  own answer instead of an exception or a silent ratio, and the scope line for CAP-1 in
  `docs/release_scope/6.1.0.md` names this finding, because 6.0.0 deferred CAP-1 to 6.1.0 and main
  carries it.
- **R7 — three numbers in shipped comments that no longer matched the tree.** They are now derived
  by running the cases rather than by counting lines, and the run refuses to report a ratio when it
  did not finish: killed and survived are not an exhaustive pair, and a partial run reports neither.
- **A-70 — the pre-tag receipt could be produced from a tree that was not the one measured.**
  `scripts/pre_tag_receipt.py` refuses a working tree that differs from the committed head, and
  since 2026-09-21 it runs the audit itself between two measurements of that tree: a supplied
  record and a typed exit code are no longer accepted, because a counter-reading bound output
  produced from a modified tree to the clean head by restoring the file before the emit. The
  cleanliness measurement no longer asks `git status`, whose answer depends on state outside the
  committed tree: `status.showUntrackedFiles=no`, a global `core.excludesFile`,
  `.git/info/exclude`, an untracked ignore file covering itself and `GIT_DIR` in the environment
  each hid a path from the first version; a second counter-reading showed the index bits
  `assume-unchanged` and `skip-worktree` hiding a modified tracked file from the version that
  followed; and the own sweep plus a third counter-reading showed a clean filter defined in the
  configuration, `core.worktree` and `core.fileMode=false` still deciding what `git diff-index`
  reported on a fresh index, a fourth counter-reading showed `core.ignoreCase=true` hiding
  an untracked file from `ls-files --others`, and a fifth showed a negated rule in a tracked
  `.gitignore` taken for a hiding rule and `refs/replace` substituting the head's objects. The
  tree is now compared by COMPUTING the property: the bytes on disk against `git ls-tree -r HEAD`
  (`hash-object --no-filters` per entry, modes from the file, symbolic-link targets hashed) and
  the paths on disk against the same listing, with only a non-negated tracked `.gitignore` rule
  allowed to hide one, and every git call of the process reading the raw objects
  (`GIT_NO_REPLACE_OBJECTS=1`); each of the thirteen has a case that was red against the version
  it was measured on. A checkout whose files differ
  from their blobs by design (`core.autocrlf=true`, no executable bit) refuses, and the docstring
  says so.
  `.hypothesis/` is named in `.gitignore`, because hypothesis ignored its cache only through a file
  it wrote itself, which is exactly the shape the gate refuses. Named limit: a change made and
  undone during the run lies between the two measurements.
- Evidence digests: a record named a `path` and a `sha256` that described different objects, the
  digest of the excerpt versus the bytes of the file. Measured across all 145 records, 0 matched the
  file. The checker also never opened the file it named, so a deleted or altered piece of evidence
  stayed green.
- Gaps in the register numbering were silent; they are now named and gated.
- The producer is read against the signed register rather than against its own in-memory list.

### Changed
- `scripts/required_check_reachability_gate.py --verify-live-pr` (#219) judges the LIVE pull request: it evaluates each gating condition against the run's own event and reports per required context whether it arrives, will not arrive, or is not measurable; the advisory job runs it after the offline gate. Measured 2026-09-17 on pull request 218: the offline gate was green while four required contexts could never arrive.
- ci.yml (#220): the full five-version test matrix runs for every pull request from this repository; the `landung` label stays the gate only for fork pull requests (owner directive 2026-09-17, velocity). The reachability declaration re-binds its accepted contexts to the new condition.
- `scripts/audit_candidate_matrix.py` reports three outcomes per cell (PASS, FAIL, NOT_MEASURED with a reason) and exits non-zero only for a release-deciding FAIL, for `NOTHING_MEASURED` or for an unbound version pin; on a pull request candidate-bound release evidence that is not bound to that head is NOT_MEASURED instead of FAIL. New cell C6.4 runs a short fuzz-soak live on the head; the 24h soak moved to `.github/workflows/soak-nightly.yml`. `scripts/pre_tag_audit_gate.py` distinguishes a genuine receipt of another tree (`other_tree`) and a foreign artefact in the receipt folder (`foreign_files`) from a rejected receipt. (Owner order 2026-09-17; measured on pull request 218: the advisory job was red on every pull request with DATA_BLOCKED 0 and FAIL 4.)
- The findings register is scoped to 6.1.0 (`VERSION` and `FINDINGS` in
  `scripts/gen_findings_register.py`): the 21 findings carried from the 6.0.0 register, with `N16`
  closed for this tree and named as still open in the published Action tag, plus the five class
  entries the risk sheets promise as `Register entry`, each with a severity the producer assigned
  from the sheet's stated reach and a note that says so — 26 entries, 14 closed, 12 open, 0 open
  P0/P1. `tests/test_register_610_carries_what_the_sheets_promise.py` binds producer and sheets in
  both directions and the producer's version to `pyproject.toml`; the numbers guard now reads the
  document of the register's own version. The line-610 carrier and `audit_artifacts/610/README.md`
  follow the producer. The signed v1 register is assembled from the owner's signature over the
  emitted payload; until it lands, `tests/test_register_gegen_erzeuger.py` reports the gap, which
  is what it is for.

- Identifiers transcribed, internal codename and account names.
- The twelve evidence files are excerpts and are not rewritten; the earlier rewrite was reverted.

### Fixed — the CI cut (PR 202), four defects the review found in the cut itself

- **Explicit re-pin of one accepted conformance case**
  (`agent_review/agent-review-v02-counter-proof-unknown-predicate-type-is-refused`): its example of
  a foreign predicate version was `…/agent-review/v0.3`, which 6.1.0 turns into a real version. A
  case that files an existing version as unknown measures the opposite of what it says, so the
  foreign example is now `…/v0.9` and the case is regenerated. Recorded here because the corpus
  rule (conformance/README.md, "Adding a case") allows an accepted vector to change only as an
  explicit, reviewed re-pin — this is that record.
- **A concurrency group coalesces a queue, it does not serialize one.** `cancel-in-progress` is
  evaluated on the *arriving* run, but the *group* decides which run dies. The eight workflow groups
  now carry `github.event_name`, so a pull-request run and a push run of the same ref no longer
  displace each other.
- **A called workflow cancelled its caller.** In a `workflow_call` workflow `github.workflow` is the
  *caller's* name, so `reusable-build-attest.yml` shared a concurrency group with whatever invoked
  it. Its `concurrency` block is removed; a reusable workflow does not own the group.
- **A running release could be cancelled.** `release.yml` now carries `cancel-in-progress: false`,
  which `RESTRISIKO_600.md` had required verbatim and which had never been implemented. Between
  draft, upload and publication there is no safe interruption point.
- **Two time budgets sat below the duration they were meant to bound.** `test` was capped at 30
  minutes against a measured 32.3, `coverage` at 30 against a measured 40.0. A timeout reports as
  `cancelled`, not `failure`, so both would have read as somebody's cancellation rather than as too
  small a budget — and under the standing merge rule an unmeasurable required check halts a landing.
  Now 50 and 60.

The matrix expression that drives the cut was also a string where a list was meant, and
`tests/test_der_ci_schnitt_haelt.py` (27 cases) now binds each of these properties with a
counter-example that fails against the pre-fix shape.

## [6.0.0] - 2026-09-05 (v0.2 is what the emitter produces · MAJOR)

**The break in one sentence:** `agent-review/v0.2` is what `build_agent_review_statement` and `emit_agent_review` produce without an argument; v0.1 needs an explicit `legacy_v01=True`, stays readable and verifiable without a deadline, and is reported as `predicateVersionStatus: legacy`.


### Fixed — after the freeze of 2026-09-05, before the tag

The freeze head of 2026-09-05 was not the tagged head. Twelve more deep-gate rounds ran on the
candidate between the freeze and the tag (rounds 3 to 14, six lenses each, a cross-family
reader on every fix head), and what they found in the shipped package is closed here — each entry
names its measurement. From round 12 on the severity rule was sharpened by the owner (2026-09-11):
P0/P1 is reserved for the wheel on PyPI — a verdict, exit code, bound or security property of the
shipped verifier — and everything found in test riegel, measurement scripts, the Rust cross-verifier
or documentation is a register row for 6.0.1 or 6.1 (see *Known issues at the tag* below).

- **A lone UTF-16 surrogate in any JSON string is refused, on the file path and the dict path**
  (2026-09-11, round 13, found by the cross-family reader, not by the six lenses). Python's `json`
  accepts `"\ud800"`, `serde_json` does not, and RFC 8785 cannot canonicalize it — so a DSSE
  envelope carrying a lone surrogate in `keyid` verified in Python (`verify_envelope -> True`) and
  was refused by the Rust verifier: the same file, two verdicts. `_strict_json` now rejects it
  fail-closed as `BundleFormatError` (not I-JSON, RFC 7493 §2.1) wherever the structural budget is
  enforced, so both verifiers agree, and the crosscheck carries the negative vector.
- **The receipt-chain resolver reads the payload with the same strict parser as the verifiers**
  (2026-09-11, round 14, L1). `agent_review.resolve_receipt_chain` parsed the DSSE payload with a raw
  `json.loads` while every `verify_agent_review*` reads the same bytes with `loads_strict`. Measured
  on the candidate: a 3000-deep `supersession` let a raw `RecursionError` out of the resolver, a lone
  surrogate in `priorDigest.sha256` ordered the chain, and a duplicated `sha256` key was read
  last-wins — three forms the verifier refuses that nevertheless decided which receipt is *current*.
  An envelope whose payload the strict parser refuses no longer orders anything; it is named under
  `unaddressable` and counts against `integrity_ok`, exactly like a non-addressable envelope.
- **`verify_sd_jwt` returns a verdict when the SIGNATURE segment exceeds the input budget**
  (2026-09-11, round 14, L2). `_b64url_decode` refuses a segment above `input_bytes` before decoding
  it, raising `BundleFormatError` — a `ProofBundleError`, not a `ValueError` — and the signature call
  site caught only `ValueError`, so the documented never-crash surface crashed; header and payload
  two blocks above had caught `ProofBundleError` for months. The same exception ran through
  `sdjwt_vc.verify_sdjwt_vc`, and `sdjwt_vc` carried a third copy of `_b64url_decode` without the
  pre-decode cap (a 40 MiB segment was fully decoded before any bound applied). Now one decoder, one
  except clause per its contract, and a fail-closed verdict; the sibling in `statuslist` is widened
  the same way although it is unreachable today.
- **`evaluate_policy`, `evaluate_decision_policy` and `relation.evaluate_relations_policy` check the
  policy's shape themselves** (2026-09-11, round 14, L4). `load_policy` promised that "a typo that
  silently weakens a policy is impossible" — and kept it only for the caller that goes through
  `load_policy`. The three evaluators every `verify_*` surface calls read their switches with
  `.get(name)`; measured: `{"signature": {"require_expected_signerr": true}}` (one `r` too many)
  produced `policy_ok: True, checks: []` for a bundle whose signer is the literal text
  `any-attacker-key-at-all`, and `{"reject_superseeded": true}` left an attached supersession
  unenforced. The CLI was never affected (it calls `load_policy` first at all seven sites); the
  library was. One shape check, `_huelle_pruefen`, now serves `load_policy` and the three evaluators —
  no second key list to drift. **Behaviour change for library callers:** a policy dict handed
  directly to an evaluator with an unknown key at any level is now a fail-closed verdict
  (`policy_ok: False`, reason `unknown field(s) in …`), not a silent pass; required fields and types
  remain `load_policy`'s business, so partial policies stay accepted.

- **A placeholder the subject can carry is not a comparison** (2026-09-07). The pre-tag gate
  replaces an unmeasurable tree with `"unknown"` and an unreadable gate source with `"unreadable"`
  so that it can RULE instead of crashing. Both placeholders then went into an equality comparison
  against a field the subject itself writes. Measured: a receipt signed with the LEGITIMATE key
  carrying the literal `subject_tree_digest: "unknown"` verified every time, regardless of the tree
  — `ok=true, state=verified`. `verify_receipt` now checks the FORM of the EXPECTED value (a
  lowercase 64-hex sha256, for both digest fields) before comparing, so every present and future
  placeholder is unbindable without anyone having to enumerate them; an enumeration would be
  silently short at the next one. The neighbouring surface has done it this way since Auflage C3
  (`audit_candidate_matrix` tests `if not gebunden` / `if not heute` before comparing) — this
  function was the straggler. Side effect that confirms the finding: the fixtures in
  `tests/test_pre_tag_receipt_gate.py` and `scripts/gate_qualification_harness.py` carried 40-char
  values — the length of a git SHA-1, never a valid sha256 — and now carry 64.

- **A library under a gate does not raise `SystemExit`** (2026-09-07). `subject_tree_digest` aborted
  the process on an unreadable tree. `SystemExit` is a `BaseException`, and the gate's own backstop
  catches `except Exception`, so the abort flew straight past it: five negative tests that run the
  gate against an evidence-free non-git directory DIED instead of receiving `ok=false` — a guard
  that no longer rejects but expires. It now raises a typed `BaumNichtLesbar`, which the existing
  backstop catches. The sibling `sign_readiness_artifact.tree_digest` keeps `SystemExit` because it
  only runs from a CLI, where the abort IS the verdict. The difference is the caller, not the error.

- **The verdict allowlist has a near-miss case** (2026-09-07). Mutating `not in _GATE_VERDICTS_PASS`
  into a prefix comparison survived the whole matrix unchanged — measured on `b9d35d4` with
  `pytest -k "freigabe_evidenz or commit_flow"`, identical before and after. (The bare number that
  stood here named no head and no command, and a gegenlesung measuring a different head with a
  different selection got a different one. A count without its command is not reproducible.) It
  would have made `WITHSTANDS_DEEPGATE_PARTIALLY` a pass. The three existing cases test absence, a
  known fail value and a foreign word; none tested a value carrying the allowed constant as a
  prefix. A "partially withstood" is not a withstanding.

- **The receipt exclusion applies to version tokens, not to any folder name** (2026-09-07). The
  pattern read the directory as an arbitrary word, so `audit_artifacts/anything/pre_tag_receipt_
  v9.9.9.json` also fell out of the binding. No consumer exploited it, but an exception that
  excludes more than it must is the start of the very class this round closes. A NEW ORDERING
  CONSTRAINT follows from the narrowing and is recorded in `RESTRISIKO_600.md`: everything else
  under `audit_artifacts/<token>/` must be committed BEFORE the receipt context is produced.

- **The wheel is canonicalised in the build path, so the second half of the byte freeze holds**
  (2026-09-07). The release standard requires two byte-identical sdists AND a wheel built from the
  shipped sdist that equals the directly built one. The second half was red: 82 entries per side,
  zero content differences, 11 entries differing in file mode alone (`0o100664` against `0o100644`).
  The cause is measured, not guessed: `normalize_sdist` sets every file in the sdist to `0o644`, the
  same files carry `0o664` in the working tree, and the packer copies the source file's mode into
  the ZIP entry. `normalize_wheel` now rewrites the finished archive with fixed modes and fixed
  timestamps, entry order untouched because `RECORD` sits last by convention; `release.yml` runs the
  same path via `--with-wheel`. Measured with isolation, the way the workflow builds:
  `identical: true`. **The digest is deliberately not repeated here any more.** It read
  `a009a968…` until 2026-09-07 and a gegenlesung could not reproduce it on any head of this
  line (`68aa6f3` gives `deaedb1a…`, `c335b26` `062188c9…`, `0aca175` `bc806f89…`). The number
  was not wrong when it was written; it was written without the two things that make a build
  digest checkable — WHICH head and WHICH toolchain, and `build-system.requires` pins neither
  setuptools nor wheel. A digest without those is a number, not evidence. The verdict
  `identical: true` is the claim that carries, and it was confirmed on four heads.
  An earlier counter-check had ruled out `umask` as the cause: at `umask 022` both digests changed
  and stayed different.

- **The second half of the byte freeze has a measuring point at all** (2026-09-07). It stood in the
  fail-closed sentence of the release standard and nothing measured it: this script built no wheels,
  no other tool under `scripts/` did either, and the audit matrix reads `candidate.wheel_sha256`
  without recomputing it. A condition inside a fail-closed sentence with no measuring point counts
  as green without ever having been measured. `build_reproducible.py --check-wheel` now measures it,
  and it found a real defect on its first run.

- **The skip decision of the Go differential comes from exit codes, not from a message text**
  (2026-09-07). The test decided whether a failure was a network problem by looking for three
  substrings in Go's stderr. That is fragile — a foreign tool's message is not a contract — and a
  scanner read the host substring as a weak host check. Availability is now determined up front by
  commands whose exit codes ARE the class, in three outcomes: obtained (offline, else over the
  network), not obtainable (skip), tooling broken (hard failure). The third exists because a first
  attempt turned EVERY failure of `go mod download` into a skip, which would have swallowed a
  checksum mismatch against `go.sum` — an integrity signal — in a tool whose purpose is verifying
  signatures. A named limit remains and is not fixed: with a cold cache Go discards a mismatching
  download, the module directory never appears, and that case is indistinguishable from "no network"
  without reading text.

- **Tag text and release note pass through the same claim hygiene as the documents** (2026-09-07).
  `claims_hygiene_check.py` scans 49 documents in CI, but the tag text is not a file in the tree and
  the release note is composed by GitHub from pull request titles — both went out unchecked while
  every README line had to pass forty forbidden phrases. `release_text_hygiene.py` calls
  `claims_hygiene_check.scan_text`, the same rule set rather than a second list, and `release.yml`
  runs it before the build.

- **One signed artefact, ONE accepted wire form, and both shipped verifiers agree on it** (deep gate run
  3 on 049b3195, 2026-09-05, findings L1-600-01 and L1-600-03, class
  `canonicity_preserving_perturbation_accepted` / RT-08). `validate=True` alone refused foreign characters
  and a missing pad character but not NON-ZERO PAD BITS (`b64decode(b"QUJ=", validate=True) == b"AB"`),
  the url-safe arm re-padded an unpadded string, and the Rust verifier trimmed whitespace Python refuses —
  so Python and Rust returned different verdicts for the same file, in both directions. `_wire_b64` v1.1
  decodes strictly and then re-encodes: a spelling that does not round-trip byte-for-byte is refused
  (pad bits, padding, alphabet, whitespace). `decode_b64` (standard, padded), `decode_b64url` (JWS,
  unpadded), `decode_b64_either` (DSSE: standard OR url-safe, each padded — RFC 4648 §3.2 applies because
  the DSSE envelope specification says nothing about padding) and `decode_b64_c2sp` (C2SP signed notes:
  non-zero pad bits tolerated for parity with Go's reference decoder, named in one place). Every stdlib
  base64 decode in the package (51 sites) now goes through these helpers; `tests/test_wire_bytes_strict.py`
  refuses any direct stdlib decode outside the wrapper, enumerates the canonicity-preserving population
  (pad bits, unpadded, surplus padding, other alphabet, whitespace) over DSSE envelopes and native bundles,
  and its Rust arm now MEASURES agreement over that population instead of skipping itself. Rust:
  `b64_strict` (bundle fields, keys) and `b64_dsse` (envelopes) without `.trim()`, `b64url_nopad` without
  padding tolerance. **Behaviour change:** an UNPADDED DSSE `payload`/`sig` is now refused by Python as it
  already was by Rust; the padded url-safe spelling the spec mandates still verifies.
- **A Trust Pack role applies to the key that signed, never to a self-declared keyId** (finding
  L1-600-02, P2 fail-open). `verify_outcome_receipt(..., trust_pack=)` reported `executor_role_trusted=True`
  and `safeForAutomation=True` for an outcome signed by a fresh key whose predicate merely claimed
  `executor.keyId = root-0`. It now binds the keyId to the verifying key against `keys[keyId].publicKey`
  (`outcome.pack_key_binds_signer`; `executor_trusted_by_role(..., public_key=)`), reports
  `executor_key_bound` and the blocker `KEY_ID_NOT_BOUND_TO_SIGNER`. On the receiver side a
  `receiver_attestation_resolver` may return the referenced statement's 32-byte signer key; when the pack
  names key material for a `receiverKeyId`, promotion to `INDEPENDENTLY_ATTESTED` and
  `receiver_role_trusted` require that key to match (`receiver_key_bound`); a bare `True` no longer binds a
  label the pack names. Callers without a trust pack are unchanged.
- **A rejection must not fail harder than the check it explains.** The messages of `verify_bundle`,
  `recompute_merkle_root_b64`, `anchors.verify_anchor(s)`, `hashalg.verify_dual_hash` and every
  `_reject_unknown` interpolated a caller-supplied value directly, so an implausibly large integer in an
  enum-typed field (`schema`, `signature.alg`, `merkle.hash_alg`, `anchors[].target`) or a mixed-type key
  set raised a raw `ValueError` / `TypeError` out of a typed-raise surface — and through
  `decision.verify_decision_receipt(anchors=…)` out of a documented never-raise one. The class is closed at
  two chokepoints rather than at nine sites: integer magnitude is now a dimension of the structural budget
  (`enforce_structural_budget`, which also walks tuples), and `budget.render_safe` / `render_keys_safe` are
  the one bounded renderer that never raises. Ordinary values render byte-identically to before.
- **Every relying-party expectation argument is type-floored at entry.** `verify_status_snapshot(now=…)`
  compared the caller's clock raw once the token carried `exp`/`ttl`; a string, list, float or huge integer
  raised a raw `TypeError` on a surface that declares it never crashes. It is now a fail-closed verdict that
  names the reason.
- **The cap runs before the work it bounds, on the C2SP note family and the tlog-proof parser.** A signed
  note carried no count cap on its signature lines: an 8 MiB note with 74,234 lines for the vkey's own key id
  drove ~74k Ed25519 verifications (measured 9.9 s) through the attacker-supplied `verify-proof` file.
  `verify_checkpoint`, `verify_cosignature` and the witness roster now refuse above the `signatures` /
  `witnesses` budget before the first verification, and `parse_tlog_proof` refuses above `merkle_path`
  before decoding a single step; `verify_tlog_proof` routes its inclusion check through
  `merkle.verify_inclusion` so one oracle carries the caps.

- **CLI consumer surfaces never raise (class RT-06, deep gate 2026-09-05, findings L3-600-05/06/07/08).**
  One writer discipline for every untrusted string on the human path: `_safe_line` renders a lone
  UTF-16 surrogate in its escaped form (`\ud800`) instead of dying in `print()` under a strict
  utf-8 stdout, and neutralises control characters in Check rows, `show-eval` fields, `svr --verify`
  property rows, `anchor` calendar lines and every `ERROR:` line on stderr — an embedded newline can
  no longer forge an extra `[PASS] …` / `=> OK` row. `verify_svr_dsse` now carries the SVR predicate
  shape in its verdict (`predicate_shape_ok`): a validly signed SVR whose predicate is not an object,
  or whose `properties` is not a list of strings, is `ok=False`, and `svr --verify` exits 2 without
  printing a PASS line first. `policy._parse_iso_utc` maps the whole stdlib failure family of a
  timestamp parse (`ValueError`, `OverflowError` from `astimezone` on `0001-01-01T00:00:00+23:00`) to
  "unparseable", so `policy lint/explain`, `verify --policy`, `--verification-time` and every
  `<verb> verify --policy` exit 2 with the typed PolicyError instead of a raw OverflowError; the
  sibling datetime sites (`check_freshness`, agent-review time axis) carry the same guard. `main()`
  gains a documented backstop: an `UnicodeEncodeError` or a member of the named type-confusion family
  that escapes a per-command handler ends in exit 2 with an ASCII-safe message (traceback on
  `PROOFBUNDLE_DEBUG=1`), never a raw traceback on a consumer surface.
- **An attached target is VERIFIED only if it verifies standalone (deep gate finding L4-01, P1).** The
  `--with-related` resolver verified a target's SIGNATURE and then parsed its payload leniently, so a
  strict-parser refusal (duplicate JSON key, NaN, BOM, non-canonical, not an object) was swallowed into
  "verified, no edges, subject absent". A chain hidden behind a duplicate `predicate` key therefore came
  out `lineage=VERIFIED` / exit 0 in **both** shipped verifiers, while the same bytes failed standalone.
  Loader and standalone verifier now share ONE payload oracle (`_statement_payload.load_statement_strict`);
  a refused payload is `RELATION_TARGET_MALFORMED` and FAILs at every hop, in Python and in Rust.
- **A retraction is silently suppressed when the attached successor is itself malformed (L4-600-01, P1).**
  `relation.successor_warning` skipped an attached, standalone-verified receipt whose OWN
  `relationships` block failed validation — and with it any `retracts`/`supersedes` edge declared
  inside. One deliberately malformed edge next to the retraction was enough: `supersededByAttached`
  stayed empty, `reject_superseded` found nothing, `safeForAutomation` flipped false→true and the
  CLI exit 3→0. Python and Rust made the SAME mistake, so the differential between them was blind.
  An unreadable block now reports `RELATION_MALFORMED_SUCCESSOR` (a receipt with NO `relationships`
  field still stays silent); a READABLE retraction still wins over the unreadable report, so the
  verdict does not depend on attachment order. Closed on Owner instruction rather than carried as
  a named residual risk.
- **A statement with more than one subject binds to none of them silently (L4-02, P2).**
  `classify_subject` read `subject[0]`, so `[derived, foreign]` classified as `DERIVED` and reached
  `safeForAutomation: true`, while `[foreign, derived]` failed — the verdict depended on the order the
  issuer wrote. `len(subject) != 1` is now its own mode, `AMBIGUOUS`, on the decision, outcome and
  relation-statement paths; `require_derived_subject` fails closed (exit 2). The resolver already
  reported such a target as `ambiguous`; both sides of the invariant now agree.
- **A release gate distinguishes ABSENT from REJECTED by a typed field, never by prose (L5-G6-01, P2).**
  C12.1 narrowed "no receipt binds this tree" to NOT_APPLICABLE on a pull request by matching a substring
  of the gate's reason — a sentence that opens the reason for rejection too. An untrusted signer, a
  tampered signature, a copied v5.0.0 receipt and an unreadable file all inherited that leniency and the
  matrix exited 0. `pre_tag_audit_gate.evaluate` now reports `state` ∈ {absent, rejected, verified,
  not_determinable}, an unreadable candidate is rejected rather than skipped, and C12.1 narrows only on
  `absent`. Neighbour swept with it: `pyproject_version` no longer raises a raw `FileNotFoundError` out
  of a gate whose contract is to rule.
- **A version-scoped signed artefact binds its version to the version under test (L5-G6-02, P1).**
  The release-deciding C12.2 reported PASS for 6.0.0 out of a signed findings register scoped to `3.6.1`;
  a register carrying `0.0.1` or no version at all was accepted just as readily. `verify_and_count` now
  takes `expected_version`, fails closed with `REGISTER_VERSION_MISMATCH` on mismatch, absence or an
  unmeasurable `generated_at`, and reports `version_bound` so an unbound caller is visible as unbound.
  This is the L6-01 lesson applied to the artefact rather than to the matrix pin.
- **An extracted sdist behaves the same wherever it is unpacked (L6-600-01, P2).** The repo-context
  derivation asked `git check-ignore` of whatever repository CONTAINED the tree, so the same sdist bytes
  produced 40 failures under a gitignored `vendor/`, 1 under a non-ignored sibling and 0 in a plain
  directory. git is now consulted only when this tree is itself the repository (`--show-toplevel`
  equality); otherwise the stricter no-git behaviour applies.

### Changed

- **BREAKING (6.0.0): `agent-review/v0.2` is what the emitter produces without an argument.** The
  previous version needs an explicit `legacy_v01=True`; `v02=` is deprecated and warns. v0.2 requires
  `subjectContext.disclosureCoreDigest`, requires `limitationCodes`, separates time claims by source,
  and accepts only the full 40-character `fixCommit` (`FIXCOMMIT_NOT_FULL_SHA` otherwise).
- **A named policy axis, and it is reported rather than assumed.** Without a policy the result
  carries `policy_decision: null`, the reason code `POLICY_NOT_EVALUATED`, and
  `automation.safeForAutomation` is false — the axis was not evaluated and says so. `ok` itself is
  unaffected unless a policy actively rejects (`policy_decision == "reject"`): a check that was
  never run is "not applicable", not "failed", and inventing a rejection for it would be a claim
  about something unmeasured. The named standard policy ships inside the package as
  `proofbundle/policies/agent-review-default-v1.json` (the copy under
  `conformance/agent_review/policies/default_v1.json` is byte-identical and kept so by a test), and
  its digest is reported, so a later reading can say what the decision was made against.
- `agent-review/v0.1` is unchanged and stays readable. Its verifier is byte-pinned to the 5.1.0
  source; the six published receipts under `receipts/agent_review/` verify as before, and a result
  from the new dispatcher `verify_agent_review_any` carries `predicateVersionStatus: legacy` plus the
  `AGENT_REVIEW_LEGACY_V01` reason code.
- **A time conflict is fatal, and no policy can accept it.** Measured by a review lens on
  2026-09-05: a v0.2 predicate with two contradicting `reviewCompleted` time claims verified with
  `ok=True` and `safeForAutomation=True` under the shipped standard policy. The module said
  `CONFLICT` "always" rejects — in `evaluate_time_policy`, which nothing in the verifier called;
  the verifier only evaluated the limitation policy, which reads no time axis. The result now
  carries `time_consistency_ok`, a `CONFLICT` on the event or observation axis adds the fatal
  reason code `TIME_CLAIMS_CONFLICT`, sets `ok` to false and blocks automation. A policy file may
  additionally carry a `time` block (`{"kind": "freshness" | "ttl" | "certificate_validity" |
  "currentness" | "existence"}`); it is then evaluated with `evaluate_time_policy`, reported as
  `time_policy_decision`, and the stricter of the two policy decisions wins. The standard policy
  carries none, and says so (`time_policy_decision: null`).
- **A policy file is validated before it decides.** Measured on 2026-09-05: `blocking:
  "COVERAGE_PARTIAL"` (a string instead of a list) was read as a set of characters and blocked
  nothing, and `require_coverage_status: "XPARTIALX"` turned the membership test into a substring
  test — both accepted with empty `errors`, `warnings` and `reason_codes`. `load_policy` and
  `evaluate_limitation_policy` now reject a policy whose `blocking`, `never_blocking` or
  `require_coverage_status` is not a list, names an unknown code or status, or repeats one, and
  whose `time` block names no known kind; a rejected policy reaches the verifier as
  `POLICY_NOT_EVALUABLE` with `insufficient_evidence`, never as an accept.
- **`verify_agent_review_any` no longer raises on a v0.1 envelope when given `policy=`.** The
  dispatcher passed every keyword to whichever verifier the envelope's `predicateType` selected, so
  the same call was a verdict for v0.2 and a raw `TypeError` for v0.1 — the sender chose which. An
  argument no version knows is now a `TypeError` before the envelope is read, the same for both;
  an argument only the other version knows is dropped, named in `warnings`, and marked with the
  advisory code `ARGUMENT_NOT_APPLICABLE_TO_VERSION` (plus `POLICY_NOT_EVALUATED` and
  `policy_decision: null` when it was the policy). The dispatcher also decodes the payload with the
  same decoder as `dsse.verify_envelope`, so a url-safe base64 envelope that verifies directly no
  longer comes back as `AGENT_REVIEW_ENVELOPE_UNREADABLE` through the dispatcher.
- **Non-fatal codes moved to `advisory_codes`.** `POLICY_NOT_EVALUATED` (no policy given) and
  `AGENT_REVIEW_LEGACY_V01` (a v0.1 receipt read through the dispatcher) describe an axis that was
  not run and a version that is not current; neither makes `ok` false. They were listed in
  `reason_codes`, which the documentation defines as fatal-only. They are now in `advisory_codes`;
  `reason_codes` is empty for a valid receipt, as documented. Consumers that branched on
  `POLICY_NOT_EVALUATED in reason_codes` must read `advisory_codes` instead (6.0.0 is the first
  release with either code, so nothing published changes meaning).
- **The disclosure renderers accept an explicit version, and read three markers instead of one.**
  Measured on 2026-09-05: the renderers detected v0.2 only by `declaration.timeClaims`, which is
  optional in v0.2 and absent from 10 of the 10 v0.2 predicates in the conformance corpus, so the
  three v0.2 counter-proofs (`limitation-codes-are-required`,
  `disclosure-core-digest-is-required`, `fixcommit-must-be-the-full-sha`) rendered under v0.1
  rules. `render_disclosure_block`, `render_disclosure_line` and
  `require_valid_agent_review_predicate_any` take `legacy_v01=` (an explicit answer wins); without
  it, `timeClaims`, `limitationCodes` or `subjectContext.disclosureCoreDigest` select v0.2. The six
  published v0.1 receipts carry none of the three.
- **`attested_inference`: a mapping with unserialisable content is malformed evidence, not a
  crash**, and `counts_as_own_domain` answers false for anything that is not a mapping. Both were
  raw exceptions on hostile input at a public surface.
- **`receipts/agent_review/` ships in the sdist**, so `tests/test_agent_review_v01_regression.py`
  runs from the published package instead of skipping all 20 cases as repo-context (same class as
  PB-2026-0717-02, PB-2026-0831-01 and PB-2026-0902-01).
- **The `Receipt:` line of a published disclosure block is the sha256 of the receipt file as
  published**, and this is now written down: it is what a reader can recompute with `sha256sum`.
  `receipt_digest()` — the canonical digest that supersession (`priorDigest`) and
  `resolve_receipt_chain` key on — is a different value. A correction must cite the canonical
  digest, never the file hash from the block.
- **The disclosure renderers read the predicate version from the predicate.** Measured on
  2026-09-04 while emitting the first real `agent-review/v0.2` receipt (PR 185):
  `render_disclosure_block` validated with the v0.1 rules and refused the predicate with
  `unknown field 'timeClaims'`. The block and the line now choose the validator from the fields
  the predicate carries; a v0.2 predicate is checked with the v0.2 rules, which include v0.1.
- **The standard policy ships inside the package.** Found by the published-artifact gate on
  2026-09-04: `standard_policy_path()` walked three levels up from the module file to the repository
  root, which exists in a checkout and not in an installed package, so `load_policy()` failed with
  `policy not readable` from the very package a stranger installs. The file now lives at
  `proofbundle/policies/agent-review-default-v1.json` and is resolved with `importlib.resources`
  like the other policy profiles; the corpus copy is byte-identical and a test keeps it so.
- **`attested_inference.check_on_receipt` no longer raises on a claimed hash without bytes.**
  Found by the type checker in CI on 2026-09-04: with `request_bytes` of the wrong type and an
  evidence record that claims `request_hash`, the comparison `None not in signed` was a
  `TypeError`, not a verdict. A claimed hash that cannot be measured is now reported as not
  measurable, never as a mismatch, and each axis is hashed on its own, so a broken response
  byte string no longer takes the request hash's measurement with it.

- **The 5.1.0 follow-up landed the parts the tag deliberately skipped.** The release ran its
  pre-flight and was tagged without its follow-up so the tag would not wait; that was right for
  the tag and wrong for the reader. Measured on 2026-09-02, PyPI served 5.1.0 while the site
  still said v5.0.0. The two superseded receipts from the first attempt on 2026-09-01 moved into
  `audit_artifacts/510/superseded/` with a README that records both the intent and the
  measurement correcting it — the gate scans with `rglob`, so they remain rejected candidates
  and the move is organizational, not a removal. `RESTRISIKO_510_NACHTRAG_20260903.md` adds
  A-P0-2 to the residual risk record as a NEW file: the bound `RESTRISIKO_510.md` carries the
  sha256 that the pre-tag receipt pins as `audit_output_digest`, so an edit there would have
  broken the attestation for the sake of a paragraph.

- **A trust anchor's `not_after` now actually expires, on the register path too — and the register
  body has an age.** Two halves of one mechanism, landed together because either alone is a promise
  that only half holds. Measured on 2026-09-06: `_autorisierte_schluessel` read `not_after` from the
  anchor and never evaluated it, filtering on `role` alone. With `not_after=2000-01-01` the key
  stayed authorised and `C12.2` reported PASS — while the shipped anchor says, in its own words,
  that the field is "the last day this key may produce evidence, compared against the artifact's
  `produced_at`", and the role `readiness_und_register_signierer_600` covers `C12.2` explicitly. A
  revocation by lowering `not_after` would have been inert and looked effective; that is the
  direction in which an error costs most. The deadline is now compared against the evidence's own
  measurement time — `produced_at` for the readiness artifacts, `generated_at` for the register —
  never against "now", because evidence from yesterday does not become inadmissible just because the
  matrix runs today. **The second half closes the way around the first:** the signature covers
  `generated_at`, so a holder of a revoked key could have back-dated a register into the window
  where the key was still valid. The register body therefore now carries the same 180-day window and
  future-skew guard the readiness artifacts already had, and a `generated_at` that cannot be read at
  all is `REGISTER_STALE`, fail-closed — an unmeasurable freshness is never a satisfied one.
  Catch-proof, both directions and both halves: without the fix `not_after=2000-01-01` yields 1
  authorised key and PASS, with it 0 and FAIL; `not_after=2099-12-31` still yields 1, so the filter
  is not simply always-reject; `generated_at` at 2020-01-01, absent, or in the future each become
  `REGISTER_STALE`; and the real tree with the real register stays PASS, 20 of 20 evaluated. Reading
  `generated_at` from the not-yet-verified register to pick the key set is safe by direction: it can
  only SHRINK the authorised set, so tampering with it locks the tamperer out rather than in.

  **Where this commit sits in the order of measurement, stated because it matters.** The mutation
  run and the closing deep-gate round (verdict `FIX_FIRST`) both ran on `a62d8cb4`. This change
  landed afterwards, on the owner's decision of 2026-09-06 (card `OA-89f05b70cd`, option A with four
  conditions). **No gate round has seen it.** It is guarded by its own catch-proof and by the suite,
  not by a round — a named gap in the evidence is better than an unnamed one in the guard.

- **The findings register decides a release only if the trust anchor authorises its signer, and only
  for the version it names.** Two holes closed together. The register verifier used to carry its own
  pinned key inside the module, so the artefact and the thing that authorised it lived in the same
  place; the authorised set now travels in from the caller, read from
  `audit_artifacts/readiness_trusted_pubkeys.txt` with the anchor's `role=` field deciding which
  check a key may speak for. A caller that passes no set is refused with
  `REGISTER_UNAUTHORISED_KEY` — an unbound caller does not decide a release — rather than falling
  back on a module default. And the signed `version` of the register is bound to the version under
  test: measured on 049b3195, a register signed `3.6.1` and generated 2026-07-18 reported PASS for
  6.0.0, as did one signed `0.0.1` and one with no version field at all; the signature was valid in
  every case, because nothing compared the two numbers. The generator gained the same emit/assemble
  split the pre-tag receipt already had, so the release signature is produced where the private key
  lives and never on the build host.
- **The mutation gate now compares two numbers from the same test set.** `baseline` and the
  closing run used the full suite while each mutant ran without the excluded module, so
  `red > baseline` weighed two different sets against each other. The bias ran toward false
  SURVIVED — an excluded test going red raised only the baseline, and a real kill was recorded as a
  survivor. Measured with one planted failing test: three of nine operators in shard 1/10 flipped;
  with the fix and the same planted test, the shard is clean.
- **Shard partition is weighted rather than round-robin.** The wall clock of the matrix is set by
  its longest shard, not by the mean; on the first sharded run the shards spanned 931 s to 1232 s
  around a mean of 1116 s. Operator durations are recorded per run and used to balance the shards.

### Documentation

- docs(run-ledger): state the local-chain limit; equivocation across readers is detected only
  by a witnessed checkpoint (SPEC 7d).

### Known issues at the tag

Stated here so a reader of the release notes does not have to open the residual-risk register to
learn them; each has its row in [`RESTRISIKO_600.md`](RESTRISIKO_600.md).

- **The Rust cross-verifier is experimental and advisory.** `tools/pb_verify_rs` is not part of the
  wheel or the sdist (measured: 82 wheel entries, all under `proofbundle/`; 0 of 1107 sdist entries
  under `tools/`). For 6.0.0 it carries no conformance promise: `tools/pb_verify_rs/crosscheck.py`
  and the parity registry are differential-agreement instruments over the recorded vectors, not a
  correctness proof of either implementation (SPEC, "Independent Rust cross-verification";
  `docs/readiness_pack/rust_parity_scope.md`). On the tagged head the crosscheck reports
  `CROSS-IMPL OK` and reproduces 61 of the 110 conformance-corpus cases independently (45 relation
  vectors differentially); the other 49 are Python-only predicates with no Rust counterpart. Rust
  conformance is its own milestone, 6.1; the Rust findings of rounds 12 to 14 (an empty
  `signatures` list classified as malformed by Python and as not-verified by Rust; five `Err(_)`
  sites that print no reason) are 6.1 register rows. The policy-shape check on the Rust side
  (a typo made Rust ignore the whole policy with exit 0 where Python refuses with exit 2) landed in
  the candidate in round 13 with a crosscheck vector, without a conformance claim.
- **`C8.2` (Python↔Rust differential) is a signed, candidate-bound artefact.** The candidate matrix
  reads it from `audit_artifacts/`; it is produced over the tagged tree and signed by the owner on
  the key-holding machine together with the other readiness artefacts, so on any head before that
  signature the check reports the artefact as absent. What is measured on the tagged head without a
  signature is the crosscheck run above. **A constraint on the way to that signature, stated rather
  than discovered later:** emitting the canonical bytes of the readiness artefacts (`C6.2`, `C6.3`,
  `C8.2`) requires the gate line of a deep-gate *workflow* verdict over the tagged head
  (`scripts/sign_readiness_artifact.py --gate-zeile-aus-verdikt`, copied verbatim, never invented),
  and the candidate matrix accepts only `WITHSTANDS_DEEPGATE` there. Rounds 10 to 14 ran as
  lens-and-jury rounds outside that workflow, and the owner closed the round series after round 14;
  at the time of writing no workflow verdict over this head exists, so those three rows stay red
  as known, signature-bound rows (register row S120; owner decision `OA-d29083cead`, 2026-09-11, option A).
  The closing path is decided, not open: after the tag, the classes of the ordered ledger correction get real
  replayable proof nodes (the owner's decision named two; the pre-sweep of 2026-09-11 15:24Z measures six
  non-monotone classes, and the measured number is the one that counts), then the deep-gate v4 *workflow*
  runs over the tagged head. Green: `C6.2`,
  `C6.3` and `C8.2` are emitted, signed and published as an addendum to this release and S120 is closed by
  measurement. Red: a 6.0.1 finding. No round 15 before the signature.
- **One mutation operator is recorded as NOT MEASURABLE, not as killed (N20).** On the round-11
  fix head `e8a7f8e`, the sharded mutation run `mutation (6)` killed 9 of its 10 operators; operator
  90 (`budget: data_digests` ceiling practically removed, `2_000 -> 2_000_000_000`) left no balance
  line inside its window (915.5 s): the mutated tree's own load-building tests explode before any
  test can go red, so the tool reports the third state rather than a kill or a survivor. The
  operator is bounded in the follow-up release. The mutation run on the tagged head, and the
  `git diff --numstat` between the last measured head and the tagged head (N11), are recorded in
  the signature card rather than here.
- **Register rows for 6.0.1 from rounds 12 to 14** (found in the shipped tree, not changing a
  verdict, exit code, bound or security property of the verifier): eight emit-side CLI paths open a
  writer-less FIFO without the stat guard the verify side has (`decision emit <fifo>` hangs, no
  verdict; `decision verify <fifo>` refuses with exit 2); `--json` prints no error object on the
  exit-2 path of nine subcommands (exit code and stderr are correct, stdout is empty, so an
  integrator parsing stdout stops rather than misreads); `rfc8785` has been a core dependency since
  3.6.1 while a dozen messages still say "install proofbundle[eval]"; `SUPPORT.md` says "the current
  line is 3.x"; the sd-jwt structure gate folds every parser refusal into the "duplicate JSON key"
  text (the verdict is right, the sentence is not); the artefact reader of the candidate matrix
  maps `EACCES`/`ELOOP` to "malformed" although they are the machine's state; the AST riegel that
  scan for lax decoders and uncapped test load cannot see dynamically computed imports or
  budget values read from files; the L2 riegel's scan roots omit `conformance/`.
- **`C12.2` turns red on 2027-09-07 by design (N21):** the only anchor key carries
  `not_after=2027-09-06`; rotate it before that date or accept the red.
- **Operator-side gate instrumentation, named because it sits in this tag's evidence chain and
  not because it concerns the package:** the release-side gate replay reports a `regression` on a
  ledger-monotonicity check since 2026-09-09 that is an ordered correction (owner card
  `OA-dcf17fc652`, register row `DAS-LIVE-LEDGER-IST-SEIT-DEM-09-09-NICHT-MONOTON-01`), and its
  witness ran 96 of 192 evidence nodes (the other 96 ran once by hand on 2026-09-11, green). Both
  are fixed after the tag, on the operator's side.

### Known limitation of the 6.0.0 artefacts (N15)

Both distributions of 6.0.0 are **bit-reproducible as shipped**, and this section states the
property with the path to recompute it rather than a digest, because a digest written inside the
tree that produces the artefact is a fixed point nobody can hold: changing the number changes the
tree, the tree changes the artefact, the artefact changes the number. The digests of what is
actually delivered belong in the `SHA256SUMS` of the GitHub Release, outside the tree — the same
place 5.1.0 publishes them.

**How a reader checks it.** Export `SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"`, then run
`python scripts/build_reproducible.py --outdir dist --with-wheel` — exactly the one line
`.github/workflows/release.yml` runs. Do it twice into two separate directories and compare with
`sha256sum`. Measured on this candidate: both runs byte-identical, for the wheel and for the sdist.

**This instruction changed on 2026-09-07, and following the old one would mislead you.** It used to
name two lines, the second of them a bare `python -m build --wheel`. Since the wheel is canonicalised
in the build path, that bare invocation produces an archive whose ZIP entries carry the mode of their
source files — not what is shipped. A reader following the old wording would compute a digest that
differs from the delivered wheel and could reasonably conclude the artefacts do not reproduce. The
single line above is what the workflow runs and what produces the delivered bytes. Note that `SOURCE_DATE_EPOCH` is bound to the HEAD commit time, so a
checkout at a different commit legitimately yields different digests; reproducibility here means
"the same tree twice", not "the same number forever".

**About the sdist, in four statements, because the earlier wording accused this release of something
it does not do.** First: the sdist that ships is the NORMALISED one — `release.yml` builds it with
`scripts/build_reproducible.py`, never the raw `python -m build --sdist` output — and it came out
byte-identical across two independent runs. Second: the RAW setuptools output is genuinely not
bit-reproducible, and the cause is measured to the byte — the sdist path of setuptools 84.0.0
(`setuptools/_distutils/archive_util.py::make_tarball`, which calls `tar.add(base_dir,
filter=_set_uid_gid)` and normalises uid and gid but not mtime) does not honour
`SOURCE_DATE_EPOCH`; the variable occurs exactly once in the whole setuptools tree, in the vendored
wheel writer (`setuptools/_vendor/wheel/wheelfile.py:53`). Each raw archive therefore carries a pax
header with the wall clock at sub-second precision, and the differing number of decimals changes
the pax record length by one byte, which cascades into the header checksum and the compressed size.
Third: whoever builds this project with plain setuptools instead of the shipped path will therefore
NOT reproduce, and that is said here plainly rather than left for them to discover. Fourth: the
normalisation exists precisely for this reason, and `tests/test_reproducible_build_361.py` has
asserted it since 3.3.1.

Owner decision 2026-09-06 (card `OA-b94f677926`, option A): the concrete wheel digest comes out of
this entry, the property with its recomputation path takes its place, and the delivered digest goes
where it is not circular. The earlier wording said "the sdist is not [bit-reproducible]" — true of
the raw intermediate, false of what is delivered. A false self-accusation is as wrong as an
overclaim, only in the other direction. The build-backend change remains a 6.1 item with its own
measurement and no time pressure.

It is recorded as `N15` in `RESTRISIKO_600.md` with the same wording, and repeated here so that a
reader of the release notes does not have to open the residual-risk register to learn it.

### Adversarial pre-tag audit: verdict FIX_FIRST, and the scope each statement holds over

The adversarial deep gate ran a closing round on this candidate (DEEP, six lenses, seven
iterations). Its verdict is **FIX_FIRST**, and **no `WITHSTANDS_DEEPGATE` is claimed for 6.0.0**.
Three findings were confirmed. All three are recorded as open entries in `RESTRISIKO_600.md`, and
all three are closed in the follow-up release rather than here — an owner decision, made with the
findings in view:

- **N16 (P2)** — `action/action.yml:35-36` interpolates `${{ inputs.version }}` and
  `${{ inputs.extras }}` directly into a `run:` shell body, while the step one line below routes
  `inputs.command` through `env:` and says in a comment why it does so. Measured, and it decides
  the ordering: the file is byte-identical to the version at the public tag `v1.0.0` (`a8aca8cd`,
  sha256 prefix `91cfcdc4ecbab94c` on both sides), exactly one commit has ever touched it, and that
  commit is an ancestor of this candidate. 6.0.0 does not introduce the injection, and releasing
  6.0.0 does not remove it. Measured separately: a fix on `main` alone would not reach the
  documented users either — `INTEGRATIONS.md` pins `action@v1.0.0`, no moving major tag exists, and
  the one channel that does update by itself (the composite action's `pip install proofbundle`)
  does not carry `action.yml` at all; the sdist and the wheel contain zero copies of it.
- **N17 (P2)** — `scripts/rust_parity_gate.py` swallows an unparseable or unreadable source file
  and then derives its verdict from the ABSENCE of complaints over the resulting population, so a
  release-deciding check can report PASS over a population that shrank quietly. On this candidate
  the population is complete — 68 of 68 files under `src/proofbundle` parse and read, and the gate
  reports `registry_integrity_ok: true` with `untracked`, `orphaned` and `stale` all empty. What is
  open is the capability, not its occurrence.
- **N18 (P2)** — `pip install <sdist> && pytest` WITHOUT the `[test]` extras is RED, not skipped,
  while the shipped `pyproject.toml` promises that a bare install "degrades to clean skips".
  Measured: 1 failed, 3075 passed, 482 skipped. Either the promise is kept or the wording in
  `pyproject.toml` is corrected; that choice belongs to the follow-up release, and until it is made
  the promise is the thing that is wrong, not the test.

**The scope each of these statements holds over.** Three figures, named here rather than left to be
inferred, because a verdict that rules over an excerpt without saying so cannot be checked by a
reader:

- **2537 of 3702 tests, measured at `59d0679`.** The mutation gate collects its population with
  `unittest discover`, which sees only methods of `unittest.TestCase`; 59 of 252 test files carry
  pytest functions only and are invisible to that collector. Every mutation statement of this run
  holds over that subset and not over the suite (`N19`).

  **The commit is part of the figure, and here is why.** The suite kept growing after that
  measurement: the closing-round fixes added test files, so a re-count on the tagged tree returns a
  larger denominator (3727 collected at the time of writing, 254 test files). The ratio the mutation
  gate ruled over is a property of *the tree it ran on*, not of the release, and a bare number here
  would silently claim otherwise — the same stale-metric failure that `tests/test_docs_truth.py`
  exists to prevent for `README.md`, just outside that test's scope. The figure therefore names its
  commit. A reader who wants today's number runs
  `python -B -m unittest discover -s tests` (the gate's own invocation) against the tagged tree.
- **The coverage of the class-ledger replay: NOT MEASURABLE, and an earlier draft of this section
  said otherwise.** That draft carried "94 of 182 classes" here. The pairing is withdrawn because
  the two numbers do not count the same kind of thing: **94** counts CLASSES whose status is
  `class_closed`; **182** counts the pytest NODES the replay executes. Measured on 2026-09-06: the
  ledger holds 183 effective classes, 94 of them closed, and all 94 carry both evidence fields as
  real in-repo nodes; the node set is 182 rather than 2 x 94 = 188 because six nodes are shared
  between classes. It read as a ratio only because the effective class count happened to be 182 as
  well, until this round's own class was written.
  What is well defined, with its definition beside it: **94 of 183 ledger classes carry in-repo
  runnable evidence** — a class counts iff its status is `class_closed`, which the validator grants
  only for two DISTINCT in-repo pytest nodes, a live regression guard and a plant-and-must-catch
  meta test. The other 89 carry no runnable test, and all 89 state why; none is unexplained. That
  is a property of the ledger's contents. It is NOT the replay's coverage and must not be read as
  one: the replay set is DEFINED by the closed status, so the ratio cannot say how much assurance
  the replay leaves unchecked. Answering that would require knowing the class population is
  complete, which is exactly what is not measured.
- **68 of 68 files.** The parity gate's population on this candidate is complete. This is the one
  figure here that is not a subset, and it is what keeps `N17` below the release-stopping bar.

**The distribution digests in the readiness artifacts are the CANDIDATE BUILD ON `a382eae` — not the
published package.** Owner decision of 2026-09-06 (card `OA-b92bd4ff84`, option A with three naming
conditions), after the following measurement, which was made *before* anything was signed:

`SOURCE_DATE_EPOCH` is taken from the HEAD commit's time, and the tag sits on a later commit than
the build. Measured in a real clone with two worktrees:

| Head | epoch | sdist sha256 | wheel sha256 |
|---|---|---|---|
| `a382eae` (candidate build) | 1788709947 | `c4490ac46c80474c…` | `58759ce9add58a95…` |
| one commit later, touching **only** `audit_artifacts/` | 1788710469 | `168d1e4c351a1695…` | `be66743a1b4dc344…` |

Both differ, at identical byte size (1 958 351 / 540 910): the content is the same, only the
embedded timestamps move. `audit_artifacts/` is not in the package at all — 0 of 1055 sdist entries,
0 of 82 wheel entries, `MANIFEST.in` says `prune audit_artifacts` — so a later evidence commit
changes nothing but the clock. A control build of `a382eae` in the clone reproduced the real build's
digests exactly, so the measurement measures what it claims to.

Three things follow, and they are stated here rather than left to be inferred:

1. **What the fields name.** `candidate.sdist_sha256` and `candidate.wheel_sha256` in the readiness
   artifacts identify the **candidate build on `a382eae`**. They are not a statement about the
   artifact published to PyPI or attached to the GitHub release.
2. **Where the published digest is.** The digests of the *shipped* artifacts are in the release's
   `SHA256SUMS`, outside this tree — the same separation `N15` established for the wheel digest.
3. **What the gate does with them.** Both fields are MANDATORY parts of the candidate binding, and
   `audit_candidate_matrix` recomputes them from the files present in `dist/` at gate time — never
   from a fresh build. They are therefore a binding between *evidence and candidate*, not an
   assurance about the package a user installs. `release.yml` does not invoke the candidate matrix
   at all; `ci.yml` does.

The cleaner mechanism — pinning `SOURCE_DATE_EPOCH` to the candidate commit instead of HEAD, so the
published package carries the same digests — is a change to the release path itself and is deferred
to the 6.1 collection release by the same owner decision.

**What "0 open P0/P1" can and cannot say — and why this sentence is here at all.** The structured,
signed register `audit_artifacts/findings_register_361.json` holds **20 entries as of its
`generated_at` = `2026-09-06T10:27:05Z`**: 13 closed, 7 open, 0 open P0/P1. That count is a state
**at that instant**, not a closure. The register's own preamble calls itself the SINGLE STRUCTURED
SOURCE for the count without naming the time cut; the wording is right about *what it decides* and
silent about *when it was taken*, and the signed artifact cannot be changed any more, so the
correction lives here.

It matters because the review lane kept running after the signature and found four more, one of
them a **P1**: `not_after` was never evaluated on the register path, so an expired anchor key kept
the ability to sign the register — a revocation by lowering `not_after` would have looked effective
and done nothing. It is closed, in `7eba21e` and its two corrections `3385d80` and `2ba939b`, and
it is a code path changed **after** the mutation run and after the closing round; no gate round saw
it. The other three are P2/P2/P3 and stay open; each has its own row in
[`RESTRISIKO_600.md`](RESTRISIKO_600.md).

So, plainly: **zero open P0 and P1 speaks only about the findings already found.** While that P1 was
open and unknown, the register truthfully said 0 open P0/P1. This is the sixth instance of one class
on a single day — a verdict over an excerpt phrased as a verdict over the whole — and this time it
sits in the register itself. The honest form names the excerpt in the same sentence as the verdict,
which is what this paragraph does. For 6.1 the register gets a field naming its own time cut and
where later findings are recorded, so a machine reader does not have to take it out of prose.

`N20` records a mutation operator whose outcome is NOT MEASURABLE rather than killed or survived:
the operator removes the very resource ceiling under test, and the mutated run reached 111 GiB
resident (88.3 % of memory, 1 GiB free) before it was stopped deliberately rather than left to the
OOM killer. Not measurable is its own state; it is not counted as a kill and not counted as a
survivor.

## [5.1.0] - 2026-08-31 (the profile a stranger can read · MINOR)

### Moved from `[Unreleased]` on 2026-09-02, because the release ships it

The five sections below described `agent-review/v0.1` and its hardening while sitting under
`[Unreleased]`. Measured on the frozen release artefacts: `agent_review` is **new after v5.0.0**,
it is in the sdist and in the wheel, and it exposes 45 public names of which 28 are callables.
A section that says "unreleased" about code the release ships is an under-claim, and an
under-claim is the same honesty failure as an over-claim.

Found by an adversarial lens of the closing gate round. The project's own guard did not catch it
because `scripts/check_version_and_changelog.py` verifies the **heading** for the current version,
never its content — it is structurally blind to what the section says. That blindness is recorded
as a finding; this entry is the correction, not the fix for the guard.

Note on scope: `CHANGELOG.md` is in **neither** the sdist nor the wheel (measured: 0 occurrences
in each). Correcting it therefore leaves both release artefacts byte-identical, and the sha256
digests pre-registered for this gate round remain valid.

### Added — `agent-review/v0.1`, a signed self-declaration that says so

A pull request often carries "an AI agent helped here, and it was reviewed". Today a reader has to
believe that sentence. `src/proofbundle/agent_review.py` lets a reader check, offline, that a stated
key signed exactly those bytes and that they have not changed since. It does not make the sentence
true, and every receipt it produces says so in its own `limitations` and `nonClaims` blocks — both
structurally mandatory.

Built against an external adversarial read (18 findings). Its core sentence is adopted: **a strong
signature must not optically harden a weak self-report.** Everything below follows from that.

- **Field provenance.** Every declared item carries an `assurance` rung, and v0.1 emits only
  `selfDeclared`. The higher rungs are refused AT EMIT, not merely reported at verify: a receipt
  that cannot be produced cannot be shown to anyone. `observations` must be empty for the same
  reason — Tier 2 and Tier 3 need a witness outside the agent's own workspace, and that is a
  separate step, deliberately not half-built here.
- **Exact subject binding.** Repository id, PR node id, `headSha`, `baseSha`, reviewed diff digest,
  and `bodyCoreDigest` — taken over the body after the machine-managed disclosure block is replaced
  by a fixed token, because a digest cannot cover bytes containing its own value. Two blocks or an
  unbalanced marker raise instead of picking a winner. Issues get their own profile.
- **`ok` means "usable as proof for the object in front of you".** A receipt that is internally
  sound may still belong to something else, so `internal_consistency_ok` and `ok` are separate
  fields and the second one requires an expectation supplied from outside. A warning beside a green
  verdict does not carry.
- **Validity is not currency.** The offline verifier always reports `CURRENTNESS_UNKNOWN`, and that
  is the point. `anchoredAt` must be null: a signature proves the bytes contain a time value, not
  that the value is externally true.
- **Coverage and findings.** `COMPLETE` requires a stated expectation, `PARTIAL` requires a named
  gap — "incomplete, but I will not say in what" is as unfalsifiable as an unqualified "complete".
  `findingsTotal` separates listed from recorded and may never undercount its own list.
- **Ordering.** `prepare_body_for_disclosure` and `replace_disclosure_block` make the wrong order
  hard to take: introducing the first block moves the body core digest, so a receipt emitted before
  the block exists binds a body that stops existing the moment its own disclosure line is added.

Thirteen conformance vectors under `conformance/agent_review/`, run by the real runner, one
expectation axis each. Three classifications, and the difference between the last two is the
substance: `valid`, `invalid` (produced, then rejected), `refused` (the producer would not build it).

### Added — the visible block is bound, and the chain cannot be taken over

An external counter-reading returned eleven findings against `agent-review/v0.1`. Four of them are
closed here, and two were exploitable rather than theoretical.

- **`disclosureCoreDigest`.** `bodyCoreDigest` replaces the entire disclosure block with a token,
  which is right for its own job and wrong as a statement about the block's content. **Measured:**
  editing the visible `selfDeclared` into `independentlyWitnessed` left every digest unchanged and
  verification green — a reader was told something the signed object does not say. The new digest
  covers the block and excludes only what cannot appear inside its own preimage. Required in v0.2,
  optional in v0.1, because requiring it there would invalidate receipts that already exist.
- **The receipt chain cannot be taken over by a stranger.** `resolve_receipt_chain` let any envelope
  in the given set mark another as corrected. **Measured attack:** an outsider signing with their own
  key added one envelope naming our receipt's digest; afterwards `current` pointed at theirs, ours
  was listed as corrected, and `integrity_ok` was true. Verifying signatures elsewhere did not help,
  because the ordering happened first and was already poisoned. `verified` is now a required
  keyword argument with no default; a rejected takeover attempt is reported rather than dropped.
- **Coverage rejects three shapes it used to accept.** A boolean run count (`isinstance(True, int)`
  is true in Python, so the check was correctly written and still blind), a negative count, and
  `COMPLETE` over zero expected runs. `COMPLETE` now also has to name its sources, its window and
  its collection method.
- **Time is separated by source and by assurance.** `agent-review/v0.2` moves business times into
  `declaration.timeClaims` and reserves `observedAt` for an observation by a separately named
  witness. A self-declared review time cannot satisfy a freshness policy; a verified RFC 3161
  timestamp raises the signature axis and leaves the event axis untouched, because it proves that
  bytes existed, not when a review happened. The two verifiers refuse each other's version rather
  than guessing.
- **`limitationCodes`.** Free-text limitations cannot be held against a policy without being read,
  and what a relying party cannot evaluate it does not evaluate. The codes are derived from the
  predicate rather than typed, because a hand-set code drifts from the content without moving any
  digest.

### Fixed — the conformance corpus had no runner

The entry above under `agent-review/v0.1` says the thirteen vectors are "run by the real runner".
That was written before the runner existed: the corpus held thirteen cases in twenty-six files and
**no test executed them**. There was a generator that writes them and nobody who reads them. It is
true now, and the sentence stays as written rather than being quietly repaired, because a changelog
that edits its own past claims is worth less than one that corrects them in the open.

The runner fails on an unknown expectation shape instead of skipping it, and for every counter-proof
that can be defused it checks that the verdict FLIPS once the defect is removed — without that, a
corpus can consist of cases any validator passes.

### Added — our own entry in a third-party transparency log

`tests/fixtures/anchors/markovian_log/submit_7727` covers the half its neighbour said it could not:
`proof_7271` verifies a proof the log issued about its own stream statement and names the gap in its
own words — the public `POST /submit` path is not exercised there. It is now, with an entry we
submitted. The inclusion path recomputes with standalone RFC 6962 (plain hashlib, written from the
spec, not `proofbundle.merkle`), and the recomputed root is byte-identical to the root in the signed
checkpoint that first covered it.

### Fixed — `_http` had half a fallback

`_http` returned on the first `HTTPError` instead of falling back to GET, while its own docstring
described exactly that case. Measured live: a health endpoint answering HEAD with 501 and GET with
200 counted as dead.



### Added — receipt envelope profile and its conformance vectors

`docs/RECEIPT_ENVELOPE_PROFILE.md` and the ten vectors under `conformance/envelope_profile/`
landed on `main` in #159. This release is what makes them reachable for anyone who is not
reading the repository directly.

### Fixed — the profile was not in the distribution, and no rule had removed it

**Measured before the fix:** `docs/RECEIPT_ENVELOPE_PROFILE.md` appeared **0 times** in the
sdist and **0 times** in the wheel built from `main` at `27a84db3c6dc`. The vectors were
already complete — 21 of 21 files, 10 of 10 `case.json` — because `graft conformance` covers
them.

**The cause is worth stating precisely, because the obvious explanation was wrong.** No
`prune` and no `exclude` rule matched the file. `MANIFEST.in` is an allowlist, and the file
was simply not on any line: it was missing **by absence, not by exclusion**. Looking for the
offending prune rule would have found nothing and left the document out.

One `include docs/RECEIPT_ENVELOPE_PROFILE.md` line fixes it. **Measured after the fix:** 1
occurrence in the sdist, the file readable from the archive at its full 240 lines, `docs`
entries in the sdist 19 → 20 — exactly one more. The wheel still carries 0, and that is
correct: the wheel is the import package and prose does not belong in it.

Why this matters beyond packaging: the profile says a stranger can recompute the result. A
profile that ships its vectors without the document explaining what they prove asks the
stranger to take the explanation on trust.

### Added — mutation operator freshness

`scripts/mutation_operators_fresh.py`. **It is a script, not a gate.** It reports whether the
mutation operator set has gone stale against the code it is meant to mutate; nothing blocks
on its output.

### Why MINOR and not PATCH or MAJOR

Measured against tag `v5.0.0` at the release candidate `cece0cc`: **72 commits, 162 files,
14 498 insertions, 150 deletions, 0 files removed**. Across all of `src/`: **0 removed public
names, 0 removed or changed signatures**. New shipped material (the profile document, ten
vectors, and `agent_review` with 45 public names) rules out PATCH; nothing removed and no
signature changed rules out MAJOR.

**Corrected on 2026-09-02.** These figures previously read "23 commits, 41 files, 2071
insertions" and "one new public function". Those numbers were true for `1cfb4dd` (31 August) and
were never re-derived as 48 further commits landed. An adversarial lens of the closing gate round
measured the difference. The *conclusion* (MINOR) was and remains correct — the reasoning behind
it was measuring a tree that is no longer the one being released.

### Changed — `automation_summary` now blocks on a receipt that is not `ok`

`automation_summary` has been public since 5.0.0. It now adds `RECEIPT_NOT_OK` to `blockers` when
the result carries `ok` and that value is not `True`, so `safeForAutomation` becomes `False`.
Measured on this release: `ok=False` → `safe=False`; `ok=True` → `safe=True`; **`ok` absent →
`safe=True`**, unchanged, because a caller who runs no `ok` check must not be blocked by one.

The change can only ever be *stricter*: it can stop an automated action that was previously
allowed, never allow one that was previously stopped. It exists because a fourth surface was
measured returning `ok=False, safeForAutomation=True, blockers=[]` — a summary more lenient than
the verdict it summarises.

**Reach, measured rather than assumed.** `automation_summary` is called from **17 sites across
seven modules**: `agent_review` (4), `automation_verdict` (2), `decision` (2), `outcome` (2),
`run_ledger` (2), `trust_pack` (3), `verification_summary` (2). Every one of them sets `ok` on the
result it passes in, so every one of them can now report `safeForAutomation: false` where it
previously reported `true` for the same input. An earlier draft of this entry said the change was
confined to `agent_review`; an adversarial lens measured that it is not, and this sentence is the
correction.

It is listed here because `RELEASE.md` requires it: the CHANGELOG entry says explicitly whether
semantics change. This one does, and the earlier version of this section did not say so.


## [5.0.0] - 2026-08-25 (the cap runs before the work it bounds · MAJOR)

### Added — reported-version status (additive; no further major bump)

Every provenance field carrying a harness-reported version (`harness_version`, `task_version`,
`promptfoo_version`) now also carries `<field>_status` with the literals `reported` /
`not_reported` / `not_bound`, plus a `<field>_status_reason` that is **mandatory** whenever the
status is not `reported`.

**The gap this closes.** Until now such a field was simply ABSENT when the harness reported no
version. Absence therefore meant two different things — *the harness ran and reported nothing*
and *no harness was bound* — and the receipt did not say which. For a verifier that is the
failure class the product exists against.

**Not a boolean, deliberately.** A boolean has three states of its own (true, false, absent) and
would move the ambiguity one level up.

**Backwards compatible.** The version field itself is unchanged: when nothing was reported it
stays absent, and no value the harness never reported is ever written (the contract
`test_missing_version_field_stays_absent_not_invented` is untouched). Existing receipts remain
valid; the status is additive metadata. The status is never derived, and `not_reported` never
folds to PASS.

Verifier side: `version_status_issues()` rejects an unknown literal, a missing mandatory reason,
and a status/field contradiction in either direction. Conformance vectors:
`conformance/provenance/version-status-*` (one per status value, one per rejection class).


> **MAJOR (SemVer), and there are TWO independent triggers.** Either would carry the increment on
> its own; both are recorded because a release note that names one and omits the other invites the
> reader to assume it read the whole picture.
>
> **Trigger 1, the exit-code class:** an input class that previously exited **2**
> now exits **1**. `SPEC.md` is normative under RFC 2119 and documents exit 2 as *malformed / usage
> error* and exit 1 as *crypto failure / verdict*. A caller who branches on those numbers takes a
> different branch for this input class from this release on. Semantic Versioning 2.0.0 requires a
> MAJOR increment for any backward-incompatible change to the declared public API, and a declared
> exit-code contract is public API. The change itself is deliberate (Owner decision 2026-08-18) and
> is not being reconsidered here — only the number that carries it.
>
> **Trigger 2, a threshold is now required for a verdict.** The Inspect lifecycle hook and the
> pytest plugin previously defaulted `PROOFBUNDLE_THRESHOLD` to `"0"`, which made `passed: true`
> for *any* non-negative score — a verdict that could not fail by construction. A measured run
> scored `mean 0.0` with both samples wrong and its receipt still said passed. Both integrations
> now require the variable and **skip emission** with a clear message when it is unset.
>
> **Measured, both sides, before the decision:** exit codes do **not** move (both `0` on a trivial
> green test), but the contract surface does. Under identical conditions the previous release
> writes a signed receipt and this one writes none. A caller who relied on getting a receipt gets
> nothing — and for a verification tool that is a break, whatever the return value says. The
> migration is one line: `export PROOFBUNDLE_THRESHOLD=0` for anyone who wants binding without a
> verdict.
>
> **What does NOT change:** no verdict flips. The affected input is simultaneously over the cap
> *and* carries invalid base64; it could never verify under any release. Nothing that verified
> before stops verifying, and nothing that failed before starts passing.
>
> **Support line:** the 4.x line ends here. There is no `release/v4.0.x` maintenance branch, and
> fixes will not be backported to it. Saying so plainly is the honest option: `SECURITY.md` gives
> fixes to the latest released minor of the current major line, and announcing a maintenance branch
> we do not intend to serve would be a promise with nothing behind it.
>
> **The pre-tag audit is PENDING for this scope.** An earlier run reached
> `WITHSTANDS_DEEPGATE` on `9bc179e` after four rounds — but that commit predates the scope
> decision recorded below, and a record over a tree that has since changed is worth nothing. The
> gate runs again over the final scope, and the record under `audit_artifacts/500/` is what counts
> for the tag. What follows describes the earlier run and is kept because its findings are real
> and were fixed as classes; it is **not** the release attestation.
>
> **Earlier run: `WITHSTANDS_DEEPGATE` on `9bc179e`, after four rounds.**
> The six falsification targets were frozen before the first run in
> [audit_artifacts/500/PRE_REGISTRATION_DEEP_500.md](audit_artifacts/500/PRE_REGISTRATION_DEEP_500.md);
> the outcome of all four rounds is in
> [audit_artifacts/500/DEEP_RUN_RECORD_500.md](audit_artifacts/500/DEEP_RUN_RECORD_500.md).
>
> The first three rounds returned `FIX_FIRST` with real findings — a CI gate attesting readiness
> from another release's evidence, an unbounded integer magnitude on three exported verify
> surfaces, and its neighbour on the *rendering* axis that the second round's own sweep had not
> asked about. Each was fixed as a class. The fourth round found nothing that survived the
> three-juror refute-to-kill.
>
> `WITHSTANDS_DEEPGATE` means **ready for the Owner's tag**, not "released" and not "bug-free".
> One reproducible candidate that did *not* survive the jury is recorded in the run record rather
> than dropped, and the round's ledger coverage (80 of 140 learned classes) is stated there too.

### Changed
- **BREAKING. A threshold is now required for a verdict.** `PROOFBUNDLE_THRESHOLD` no longer
  defaults to `"0"`. The Inspect lifecycle hook and the pytest plugin skip emission when it is
  unset, with a message naming the reason. Previously a default of `0` made every non-negative
  score pass; a measured run scored `mean 0.0` with both samples wrong and its receipt still read
  `passed: true`. The published claim schema is untouched — `threshold` and `passed` remain
  required claim fields. Migration: set the threshold explicitly.
- **The `merkle_path` cap now runs BEFORE the decoding it bounds**, on all three surfaces that
  carry an inclusion proof: `verify_bundle`, `recompute_merkle_root_b64`, and
  `verify_sample_opening`. Owner decision 2026-08-18 unifying the class on the budget module's
  documented house pattern ("the cap, then the work"). Measured on a 195000-step proof: the base64
  decoder was called 195002 / 195004 times **before** the refusal, and the time scaled with the
  size of each proof element (365 ms -> 5714 ms at 32 -> 3200 bytes per step). It is now called
  2 / 4 times, and the time no longer scales with element size at all.
  **Verdicts do not change**: an over-cap proof could never verify, so this removes work, not
  acceptance. One error CLASS changes: an input that is simultaneously over the cap *and* carries
  invalid base64 previously surfaced as a format error (CLI exit 2) and now returns a verdict
  (exit 1). That consequence is what caused the first attempt (`2c52596`) to be reverted before the
  4.0.0 release; the Owner has now decided it deliberately.
- **`checkpoint_note` refuses an empty Merkle root.** An empty `root` encoded to an empty third
  note line, which `verify_checkpoint` and `_note_text_of` both reject as malformed — the emitter
  could sign a note that no verifier accepts. The realistic path was `root_bytes_from_b64("")`,
  which returns `b""` rather than `None`. A non-empty root of the wrong length still round-trips
  and is unchanged.
- **`save_signer` validates its path argument** the way its sibling `load_signer` has since
  2026-08-16: a non-path raises a typed `BundleFormatError` instead of a raw `TypeError` from
  `os.open`, and the private seed is no longer materialised before the check.

### Added
- **`capture_mechanism` in signed provenance.** `from_inspect_ai_log(..., capture=...)` records how
  a receipt came into existence: `lifecycle_hook` (live `data.log` read inside the producing
  process), `lifecycle_hook_log_reread` (hook-triggered, log re-read from disk) and
  `persisted_log_reader` (the reader default). Previously a hook-emitted and a reader-emitted
  receipt were byte-indistinguishable, so a verifier could not see how the evidence arose.
- **lm-eval binds its framework version.** `provenance.harness_version` is now taken from the
  `lm_eval_version` field of the results file. If the field is absent the provenance field stays
  honestly absent — nothing is invented. This closes an asymmetry: promptfoo bound
  `promptfoo_version`, Inspect bound `harness_version`, lm-eval bound nothing.
- **`--expect-issuer` on `show-eval`** pins the accepted signer, repeatable for key rotation, and
  compares against the *verified* signature key. A mismatch prints a clear message and exits 1.
  Opt-in and backwards compatible. Adversarially motivated: a flipped receipt re-signed with a
  fresh key previously passed with `rc=0` under self-attested scope.
- `verify_witnessed_checkpoint` and `verify_tlog_proof` results carry
  **`expected_origin_wellformed`** (`True` / `False` / `None` when no pin was supplied), and
  `verify-proof --json` carries it on **every** invocation, including the fail-closed paths. It
  reports whether the caller's own `--expected-origin` satisfies the printable-ASCII rule the log
  side already enforces. The comparison itself is unchanged — a malformed pin still produces a
  verdict, not an exception, because a near-miss must stay distinguishable from a signature failure.

## [4.0.0] - 2026-08-18 (origin-quorum rule · printable-ASCII identities · MAJOR)

> **MAJOR (SemVer):** the printable-ASCII identity rule now refuses a non-ASCII (IDN/Unicode) origin
> or witness name for the verifier's exact identity compare — a deliberate behaviour change at the
> public verify interface (detailed under Changed). A pre-tag adversarial deep-gate (DEEP 6L/7I) was
> run on this digest; its record and attestation are in
> [audit_artifacts/400/DEEP_RUN_RECORD_400.md](audit_artifacts/400/DEEP_RUN_RECORD_400.md).

**Semantics: changed, in one deliberate, fail-closed direction — the origin-quorum rule.**

### Changed

* **Origin-quorum rule: a log does not vote in its own witness quorum.** `checkpoint.witness_quorum`
  (and with it `verify_witnessed_checkpoint`, `tlogproof.verify_tlog_proof` and the experimental
  `public_transparency` profile, which all share it) now **excludes a cosignature when its key
  material equals the audited log's own signing key, OR when its name equals the origin line** —
  fail-closed, before any signature math. The excluded entry stays visible in the `witnesses` dict as
  `ok=False` with `origin_excluded=True` and a `detail` sentence naming which test fired. Two
  operands, chosen because neither is the log's to pick: the caller (which knows the log) passes its
  key material; the origin line is the note's own first line. The key-material test is the robust,
  algorithm-agnostic one; the name test is exact-codepoint (robust for ML-DSA-44, whose signed
  message binds the cosigner name — Colin's live vector — and defence-in-depth for Ed25519, whose
  cosignature/v1 message does NOT bind the name and so can be relabelled). Verdict change, named
  precisely: a roster listing a cosignature made with the log's key (under the origin name or any
  alias) could previously satisfy part — or, at `threshold=1`, all — of the quorum with the log's own
  signature; measured 2026-08-16 with a live probe (`witness_quorum(threshold=1) -> True` for a
  self-cosigned mini-log), decided with the operator in issue #7, and re-gated 2026-08-17 after an
  adversarial pass showed a name-only rule was bypassable (an alias, or a zero-width character in the
  origin line). Honest limit, documented at the call sites: a log cosigning with a SEPARATE key under
  a non-origin alias that a relying party wrongly trusts as an independent witness is roster
  provenance, not a local check. The C2SP specs are silent on self-cosignature (checked 2026-08-17),
  so the verifier holds the line. Rosters without a log-key or origin-named cosignature — including
  every vector previously shipped in this repository — keep their verdict bit for bit.
* **`witness_quorum`'s `log_key_material` is now a required keyword-only argument (pre-tag deep-gate D1,
  BREAKING for a direct caller of the primitive).** It defaulted to `None`, so a bare
  `witness_quorum(note, roster, threshold)` silently ran the name-test-only mode — under which a log
  cosigning under an ALIAS with its own key (name ≠ origin) was counted toward the quorum, because the
  robust key-material prong had nothing to test against. The three shipped verification surfaces
  (`verify_witnessed_checkpoint`, `verify_tlog_proof`, `public_transparency`) always passed the material
  and are unaffected; the change forces a direct caller to STATE the choice — the log's key material for
  the full rule, or an explicit `None` to opt into the documented name-only mode. No silent weak default.
* **Origins and witness names must be printable ASCII (re-gate 2026-08-17).** An adversarial re-gate
  showed the name test was bypassable one character class at a time — a zero-width (Cf), then a NBSP
  (Zs), then a variation selector or Default-Ignorable letter (Mn / Lo), then an appended plain space —
  because the compare used an operand the log writes (its own origin line). The durable fix is a
  POSITIVE, non-enumerated rule: `checkpoint_note`, `verify_checkpoint` and the shared note parser
  require the origin to be printable ASCII with no leading/trailing or double space (a single internal
  space stays legal for Go sumdb's `go.sum database tree`); `_parse_witness_vkey` and the emit path
  require a witness name to be printable ASCII with no space at all. None of the cloaking characters is
  printable ASCII, so the whole look-alike class is closed at once. Fail-closed; measured against every
  shipped external vector (Go sumdb, Rekor, rootcommit, Colin's fixtures) — all pass. **Deliberate,
  documented restriction:** a non-ASCII (IDN/Unicode) origin is now refused for the verifier's identity
  compare; no real tlog origin is non-ASCII. This also closes the NFC/NFD normalisation question at the
  root — a decomposed non-ASCII identity cannot be built or verified at all. **The rule covers all THREE
  identity slots** (re-gate: the first cut hardened origin and witness name but not the log key name —
  the third): `key_id`, `cosign_key_id`, `cosign_key_id_mldsa`, `sign_checkpoint` and `_parse_vkey` all
  require a printable-ASCII name now, so a surrogate name can no longer raise a raw `UnicodeEncodeError`
  out of the public verify API, and a zero-width log key name can no longer substitute for a real one.
  **Honest limit named precisely:** the name compare is exact bytes, so byte-different forms of the SAME
  identity — an ASCII case variant (DNS is case-insensitive), an FQDN trailing dot, a path-normalisation
  form — are not caught by the name prong (they are the same owner, not a look-alike); the robust
  defences for them are the key-material prong and `expected_origin`. Exactness is kept deliberately
  (normalising would loosen `expected_origin` acceptance, whose safe direction is the reverse).
* **`public_transparency` witness-quorum fails closed on an unusable log_vkey (re-gate F-9).** A
  `log_vkey` that is supplied but malformed is now "not measurable", a THIRD state distinct from "no log
  context" — treating it as no-context silently switched the key-material exclusion off and let the log
  vote in its own quorum under an alias with `errors=[]`. A relying party that SUPPLIED log context and
  had it dropped is exactly the hidden fail-open; it now fails closed with a named error. (`_log_key_material_of`
  itself still never raises — re-gate F-7 — but its `None` is no longer read as a pass.)
* **`verify-proof` carries the exclusion reason on BOTH output paths.** `--json` projects
  `origin_excluded` + `detail` per witness; the human text path prints an indented reason line per
  non-verifying witness that has a detail (re-gate F-6 — the reason previously existed only in the
  library and, on the text path, in `--json`; the reader most likely to act saw nothing). The
  pre-existing `[pq]`-missing detail rides along on both.
* **`_log_key_material_of` never raises (re-gate F-7).** It now catches the `ValueError`/`TypeError`
  base families, not just `BundleFormatError`, so a lone-surrogate log-vkey name (which reaches
  `name.encode("utf-8")` → `UnicodeEncodeError`) can no longer escape as a raw traceback out of the
  `public_transparency` fail-closed surface. Honest limit kept: the `public_transparency` witness-quorum
  path applies the key-material exclusion only when a `log_vkey` is supplied (it is optional there, and
  the profile is EXPERIMENTAL); the always-wired surfaces (`verify_witnessed_checkpoint`,
  `verify_tlog_proof`) always pass it.
* **The whole checkpoint note body is validated UTF-8-safe before it is encoded (pre-tag deep-gate D2/D3,
  class fix).** Two parsers encode the note body — origin, size, root AND the optional C2SP extension lines
  — to sign or verify over it: `verify_checkpoint`'s own, and the shared cosignature-path parser
  `_note_text_of`. Both encoded BEFORE checking the body was UTF-8-safe, so a lone/unpaired UTF-16 surrogate
  anywhere in the note (a `str` survives splitting but is not valid UTF-8) raised a raw `UnicodeEncodeError`
  out of a public verify surface. An independent pre-merge fix-review caught that a first cut had fixed only
  `verify_checkpoint`, leaving the shared parser — so a surrogate in an EXTENSION line still crashed the
  top-level `verify_cosignature`, `evaluate_public_transparency`'s witness-quorum branch, and
  `cosign_checkpoint`. Both parsers now validate the whole body first (`_note_text_of` once, for every
  consumer); the encode fails closed with a typed `BundleFormatError`, never a raw traceback.
  `verify_witnessed_checkpoint` and `verify_tlog_proof` were already shielded (call-ordering / a broad
  `except` that already caught the `ValueError` subclass). A fourth adversarial pass then found the note-body
  FIELDS still returned unvalidated: the ML-DSA cosigned *message* excludes extension lines by spec, but the
  ML-DSA cosign *function* (`cosign_checkpoint_mldsa`, a public witness-signing surface) — unlike the verify
  surfaces, which re-validate them — fed the raw size/root lines into `int(size_s).to_bytes(8)` and
  `base64.b64decode`, raising a raw `binascii.Error`/`ValueError`/`OverflowError` on a non-base64 root or a
  non-decimal / negative / ≥2^64 / over-long size (the CVE-2020-10735 integer-string DoS class). `_note_text_of`
  now validates the size (uint64 decimal, no leading zeros) and root (standard base64) too, so every consumer
  of the shared parser is closed.
* **Every public constructor/producer surface validates its argument TYPES, not only their content (pre-tag
  deep-gate iter5).** The identity helpers (`_origin_wellformed`, `_witness_name_wellformed`) and the tlog-proof
  producers checked a string's content but never that it WAS a string, and the key/root/proof/extra byte
  arguments were unguarded — so a non-str / non-bytes / non-dict CALLER argument (a JSON field that came back
  `null` or numeric from an upstream contract violation) raised a raw `AttributeError`/`TypeError` out of
  `checkpoint_note`, `key_id`, `vkey`, `sign_checkpoint`, the `cosign_*` family, `witness_quorum`,
  `format_tlog_proof` and `tlog_proof_for_bundle`, instead of the documented typed `BundleFormatError`. Found by
  a fifth, completeness-critic adversarial pass; the verify surfaces were already safe (they derive identity
  from a prior split). `isinstance` guards — the same the parse helpers already carried — now close the whole
  caller-contract class, confirmed by that pass's own ~1,830-probe battery reporting 0 raw-exception escapes
  across every producer and verify surface.

### Added

* **The `markovian_log/proof_7271` fixture now verifies 8 of its 11 signature lines** (up from 6):
  the two ML-DSA-44 **witness** cosignatures (navigli `6bc44249`, ring-any-bells `5774b075`) are
  covered by operator-published verifier keys fetched from outside the audited log
  (`witness.navigli.sunlight.geomys.org` and `transparency.dev/witnesses`, digest-frozen in
  `SOURCES.md`), each verified independently against the frozen checkpoint with positive and
  bit-flip counter-probes before being carried. Without the `[pq]` extra those two lines count as
  non-verifying (fail-closed) and the fixture still verifies 6 of 11 — now a measured statement in
  `MANIFEST.json` instead of a wrong guess (the pre-3.8.0 wording blamed the missing backend; the
  backend was never the reason). The three remaining unverified lines carry their measured reasons:
  two Ed25519 witnesses deliberately not carried, and the log's own origin-name ML-DSA line, which
  no independent source can key today and which the origin-quorum rule would refuse to count anyway.
* **A live self-signed checkpoint as the origin-quorum test vector**:
  `markovian_log/checkpoint_7397/` freezes the log's checkpoint at tree size 7397 (fetched
  2026-08-17, digest-pinned), which carries the log's own name twice — as its Ed25519 note
  signature (excluded from witness quorums by the existing 0x01/0x04 domain separation) and as an
  ML-DSA-44 line in cosignature shape (excluded by the new rule). `tests/test_origin_quorum_rule.py`
  holds both halves plus the self-cosigned mini-log regression probe from the 2026-08-16 report.

* **A killing test for the NFC-origin mutation operator.** The gate's frozen fixture origin is pure
  ASCII, on which NFC is the identity, so no `--expected-origin` against it could distinguish an
  NFC-normalising origin compare from the exact one — the operator survived as an UNEXPECTED gap.
  Closed with a self-signed checkpoint whose origin carries a `K` and a KELVIN-SIGN (U+212A) near-hit
  (`NFC(kelvin)=='K'`): exact rejects, NFC accepts. Verified against the planted operator line
  (`log_ok` flips False→True under it) — red on the mutant, green on real code; the operator stays
  should-kill.

## [3.8.0] - 2026-08-16 (CLI origin pinning, corpus fixture, BETA, relation EXPERIMENTAL)

> **Aus der `[Unreleased]`-Rubrik auf `main` uebernommen (Merge 2026-08-17).** Diese Rubrik trug
> Aenderungen, die auf `main` lagen und damit in 3.8.0 ausgeliefert werden — gemessen im Baum
> dieses Zweigs (typisierte Fehler in `evalcard`/`prereg` vorhanden, `json_nodes` im Budget).
> Sie als "unveroeffentlicht" stehen zu lassen waere falsch geworden, sobald dieser Tag faellt;
> der Wortlaut ist unveraendert uebernommen, nur die Rubrik-Ueberschrift entfaellt. Die
> `###`-Rubriken darunter stehen am ENDE dieses Abschnitts, damit sie nicht mit den
> gleichnamigen Rubriken dieses Release verwechselt werden.

**Semantics: unchanged. Resource ceilings: one deliberate tightening, disclosed below.**

This banner said "Nothing under `src/` changes" until 2026-08-08. That was **false** by then. Measured
at `bc3ae70` with `git diff --numstat origin/main HEAD -- src/proofbundle/`: **8 files, 196
insertions, 3 deletions**. The sentence was written when it was true and was not pulled when the tree
moved past it — a statement nobody re-measured.

The first correction of this banner then repeated the fault it describes. It claimed "204 lines", a
figure already 9 off when it was written and 17 further off after the revert below landed. A count
against a moving branch is only true at a named ref, so this one names its ref and its command.
Found by the mandatory review lane, both times, and not by a check — `scripts/check_version_and_changelog.py`
reads only headings, and the release-scope checkbox in [RELEASE.md](RELEASE.md) is read by a human,
not by a gate.

What actually changed, and why each is patch-safe:

* **No public interface gains or loses a field**, and no verdict flips from fail to pass. Every change
  below is fail-**closed**: input that was accepted and is over a generous ceiling is now refused
  before the work it would cost.
* **Structural budget on the direct-dict path.** Six public surfaces that accept an already-parsed
  structure now apply the same `VerificationBudget` ceilings the string/file path has always applied
  (`string_len` 1 000 000, `json_nodes` 200 000). On that path the `input_bytes` cap is inert — there
  are no bytes to measure — so those surfaces were unbounded. This is the same deliberate exception
  the project shipped in 3.2.3 (Finding 15b) and is disclosed here for the same reason:
  [COMPATIBILITY.md](COMPATIBILITY.md) requires that a tightening of a previously accepted input say
  so explicitly. Each surface reports it in **its own** documented failure form — a result dict where
  the surface returns dicts, `BundleFormatError` where it raises — so no new exception type appears
  anywhere.
* **Withdrawn before release: moving the `merkle_path` cap earlier.** An earlier commit in this
  cycle moved the `merkle_path` (256) check in `verify_sample_opening` ahead of the base64 decode.
  It was reverted, and this entry records why rather than dropping it silently. The claim it
  originally carried here — that the outcome is unchanged for every input — was **measured false**.
  Method, since the repo asks every number to name its object and its source: two worktrees at the
  commit and its parent, the same `verify-opening` invocation against each, exit codes compared per
  input class. The CLI exit code moved from 2 to 1 whenever any proof element, or `root_b64`, would
  have been rejected by `b64decode(validate=True)`. Two independent partitions were counted — one
  gave at least 12 diverging classes, an independent re-count gave 22; "input class" is not a defined
  unit here, so the lower bound is what the claim rests on. The verdict itself never flipped (`ok`
  stays `False`), but [COMPATIBILITY.md](COMPATIBILITY.md) lists the meaning of exit codes as a
  public surface, and this project already kept `stash@{0}` out of 3.7.1 for the same reason. The
  change also did not achieve what it was for: an `Omega(n)` structural budget walk runs one line
  above the cap, so the cap cannot precede the work it bounds. Peak memory at n=190000 was 11867 KiB
  against 2.2 KiB at n=257 — a linear path, not a flat one. Wall-clock figures for the same runs are
  deliberately not quoted: they were host-dependent and differed by 28% between two measurements of
  the same code. The underlying finding stays open for a minor release.
* **Typed errors on two path arguments.** `evaluation_card_hash` and `prereg_hash` raise
  `BundleFormatError` on a non-path argument instead of leaking `OverflowError` / `TypeError` /
  `FileNotFoundError`. The CLI always passes a `str`, no test or doc pinned the old types, and the
  surrounding failure form in both functions was already `BundleFormatError`.

The planned scope for the next patch is written down in
[docs/release_scope/3.7.1.md](docs/release_scope/3.7.1.md).


Status boundary (No-Overclaim): 3.8.0 remains audit-candidate BETA, relation/v0.1 EXPERIMENTAL. This is a
MINOR release whose one **capability** change is that `verify-proof` gains a command-line flag it did not
have. No crypto verdict (`.ok`) semantics change, and every existing invocation keeps its verdict.

**Corrected 2026-08-16, and the correction matters to anyone who parses our output.** This sentence
said "one behavioural change", which a counter-read measured false: the release changes observable
behaviour in **four** places, of which only the first is the new capability.

1. the new flag itself;
2. `verify-proof --json` gained the key `expected_origin` — **every** invocation now carries it, with
   `null` when the flag is absent. A consumer that enumerates keys strictly sees a new one. This is
   the reason the sentence had to change: "every existing invocation keeps its verdict" is true and
   remains true, but a *verdict* is not an *output shape*, and the earlier wording let one stand for
   the other;
3. three text lines (`log-signature`, `sample-opening`, `enclave-attestation`) now pass their value
   through the control-character neutraliser, so a value containing an escape sequence prints
   differently — see `### Security`;
4. the `SHA256SUMS` file attached to the GitHub Release no longer carries a `dist/` prefix, and the
   Release now appears as a draft until the PyPI upload succeeds — see `### CI`.

None of the four changes a `.ok` verdict. Listing them is not pedantry: the one class of consumer this
project exists for is the one that automates on our output, and "one behavioural change" told them
they had nothing to check.

**Why MINOR, and a retraction.** MINOR follows from the rule this project binds itself to: SemVer 2.0.0
§7 requires MINOR for new backward-compatible functionality in the public API, and `proofbundle` is a
console entry point (`[project.scripts]`), so a new option on the shipped CLI is exactly that. An earlier
draft of this paragraph argued from repository precedent instead, claiming a user-facing CLI flag had
never shipped in a patch release. That claim is retracted here rather than quietly deleted, because it
was measured false: **four** patch releases grew the shipped CLI. The count of *flags* depends on what
is being counted, so both numbers and their rule are given rather than one number without its object —
which is the mistake an earlier draft of this very retraction made. Counting **distinct long-option
names that did not previously occur anywhere in `src/proofbundle/cli.py`**: ten —
`--expected-root-file --issuer-key --output --policy-id --valid-until` (3.1.1),
`--checkpoint-vkey --trusted-checkpoint --verification-time` (3.1.3), `--require-derived-subject`
(3.2.2), `--eat` (3.2.3). Counting **added `add_argument("--…")` lines** in the same diffs, which is a
different thing because one name can appear on several subcommands: sixteen (6 / 3 / 2 / 5). Either way
the precedent points the other way; the rule does not, and the rule governs.

The choice is reinforced by a cost asymmetry. A consumer pinned to `~=3.7.0` picks up a patch
automatically, so under 3.7.1 they would silently acquire a verification capability they never asked
for — in a library whose whole purpose is that nothing arrives unannounced. Under 3.8.0 they stay where
they are until they choose to move, and the larger number harms nobody.

Two further corrections to earlier drafts of this section, kept visible for the same reason: the delta
over 3.7.0 is not "one commit touching the shipped package" — `911fd5c` and this release commit both
touch `src/`, `MANIFEST.in` grafts `tests`, `scripts`, `schemas`, `examples`, `conformance`, `formal`
and `docs/readiness_pack` into the sdist (**23 files over 8 commits** changed across exactly those seven
paths — and these are TWO numbers from two commands, which the first draft gave as one: the files come
from `git diff --name-only v3.7.0..f64d35e -- <the seven paths> | wc -l`, the commits from
`git log --oneline v3.7.0..f64d35e -- <the seven paths> | wc -l`. Naming only the second under both is
exactly the error this paragraph goes on to correct in the sentence after next — that is WITH merge commits; the
`--no-merges` count over the same paths is **6**, and two of the eight merges carry no change
of their own. The number is given with its command because the paragraph below retracts an
earlier pair that did not), and the `dev` extra narrows `ruff>=0.5` to `ruff>=0.5,<0.17` and `mypy>=1.8` to `mypy>=1.8,<3`.
None of that is public API, which is why the version verdict is unchanged, but "for one reason only"
was not accurate.

An earlier draft of this same paragraph said "27 files over 13 commits", and both numbers were wrong in
the same way the sentence above warns about: 27 counts the whole of `docs/` rather than
`docs/readiness_pack`, so it includes four files `MANIFEST.in` deliberately does not graft, inside a
sentence about the sdist; 13 is the repository-wide `--no-merges` count over a DIFFERENT endpoint
(`v3.7.0..ac0688c`), six of which are `ci:` commits that touch neither `src/` nor any
grafted path. So the two numbers differed in THREE ways at once — population, merge policy
and endpoint — and named none of them. A counter-read measured `v3.7.0..f64d35e --no-merges`
= 14, which is what a reader would have had to guess. Two numbers from two populations, neither of them the
one named. They are corrected here rather than quietly replaced, because that is the same discipline
this section asks of the precedent claim above it.

### Added
- **`verify-proof --expected-origin` (#137, `911fd5c`):** `verify_tlog_proof` has accepted
  `expected_origin` since 1.3.0 (release-review fix #5), but the argparse parser carried no flag and the
  command never passed one. A command-line verifier therefore could not reject a validly signed
  checkpoint issued by a DIFFERENT log than the one it meant to trust: the signature check passes, and
  without the origin constraint nothing else looks wrong. The default stays `None` (origin
  unconstrained), so existing invocations keep their **verdict**; their `--json` **output shape**
  does change — see the correction at the top of this section — because the key `expected_origin` is
  now always present, `null` when the flag is absent. The first draft of this bullet said "existing
  invocations are unaffected", which conflated the two.
  On the human path a mismatch now reads `(expected <origin>)` rather than looking like a broken
  signature.
  Covered by `tests/test_verify_proof_expected_origin.py`: flag discoverable in `--help`, default
  unconstrained, matching origin passes, mismatching origin fails closed with `inclusion_ok` still
  true, text output names the expectation — plus, added after a counter-read of this release,
  **seventeen near-miss origins** that each must be rejected (prefix, suffix, case, whitespace,
  newline, trailing slash, scheme, domain-only, empty, full-width, trailing host dot, doubled slash,
  percent-encoding), the positive direction without which an always-false comparison would also be
  green, and a guard that the four control-character call sites stay wrapped.

  **What the new JSON key does NOT do.** It reports what the caller *asked*, not why the answer is
  no. Pin the origin you trust — the documented use — and a foreign origin **is** machine-readable
  (`expected_origin` differs from `origin`). An earlier draft of the test and the commit message
  read as if the field separated three causes; a first correction then overshot and said it
  separated none. Both are wrong in the same way — measured on one construction and reported over
  another — and the measured form is above.

  What remained indistinguishable was a **wrong `--log-vkey`** against a **tampered signature**, and
  that half is now closed too, by a different mechanism: see `signer_present` below.

- **`verify-proof --json` now separates a wrong key from a tampered signature (`signer_present`).**
  This was a different kind of gap from the rest of this release. Everywhere else the information
  existed and was dropped one layer before the output; here it looked as if it did not exist at all,
  because a signature check is a **two-input predicate** and a mismatch does not attribute blame to
  either input. The verifier cannot know whether the key is wrong or the signature is.

  The **key ID** can. A C2SP signature line carries the signer's key ID, and `verify_checkpoint`
  already made the distinction inside its loop — `kid != kid_v` means *this line is not for your
  key* — before collapsing it into a single `ok=False`. Measured, with the good run as the control:
  a valid run reports `signer_present: true`; a foreign key reports **false** ("this key did not
  sign this note"); a tampered signature reports **true** with `log_ok: false` ("it signed, but the
  bytes do not match"). The two outputs are no longer byte-identical.

  **Honest limit, and it is not a weakness of the field:** a tamper that hits exactly the four keyID
  bytes is indistinguishable from a wrong key — at that point the note carries no evidence that this
  key ever signed. That is a true statement about the situation, not a measurement error.

  The guard that pinned the collision carried its own replacement instruction ("if these become
  distinguishable — good, then the finding is closed and this guard belongs replaced by a positive
  assurance"). It went red the moment the flag landed and now asserts the separation. That is the
  difference between pinning a gap and pinning a property: the first **must** go red when the work
  is done, or it holds an old state after it has stopped being true.

- **`verify --expected-origin` and `verify_witnessed_checkpoint(expected_origin=…)` — the same
  binding on the checkpoint surface.** `verify-proof` got the origin pin above; its neighbour,
  the `--trusted-checkpoint` path, still had none. Both flags are new; the library parameter is new.

  **Measured, not assumed.** A C2SP checkpoint's origin line and the name in its signature block
  are separate arguments to `sign_checkpoint`, and C2SP permits one signer to serve several
  origins. Signing a note whose origin line reads `evil.example/other-tree` under a key named
  `example.com/log` therefore produced `ok=True` under the *trusted* verifier key, and its root
  and tree size were adopted as the authenticated tree context. A relying party who pinned only
  the key had not pinned **which tree** was speaking. On the CLI the two verdicts — the honest
  checkpoint and the foreign one — were byte-identical, both `checkpointAuthenticity: PASS`, and
  no parameter separated them.

  The default stays unconstrained (`None`), matching `verify-proof --expected-origin`: there is no
  origin a verifier could honestly default *to*. So this closes the gap **for callers who pin**,
  and an unpinned run is unchanged — which is why the unpinned run keeps naming the origin it
  observed in the `checkpoint-authenticity` detail, and why SPEC.md §9 now states the property
  normatively instead of leaving it to be inferred. A mismatch reads as a mismatch rather than as
  a broken signature, and rides the existing rails: `cp_ok` is bound once, so
  `treeContextAuthenticity`, `treeSizeExpectation` and `safeForAutomation` all follow without a
  parallel code path.

  The comparison is EXACT on both surfaces, and they are **two** comparison sites, so the shared
  near-miss corpus (`tests/_beinahe_treffer.py`, also used by kbjwt, statuslist, intoto, evalclaim
  and policy) runs against both — the library directly, the CLI through `main()`. Six rollback
  probes were run: loosening either comparison to `startswith`, removing either binding entirely,
  and weakening either `is None` to a falsy test (which would silently turn an empty
  `--expected-origin ""` from a question that always fails into no question at all). All six turn
  the guards red, and the baseline returns to exactly 41 passed / 28 subtests.

  **Two more defects, found by reviewing this very change and fixed in it.** The first: a pin
  whose object is absent is not a pin. `verify BUNDLE --expected-origin some.log` **without**
  `--trusted-checkpoint` exited 0 in silence — the caller believes the origin is bound, nothing was
  checked, and nothing says so. That is the same class this release closes, one level up: the
  comparison was not too loose, it did not happen. It is now a usage error (exit 2), the rule the
  neighbouring line already applied to `--trusted-checkpoint`/`--checkpoint-vkey`. A sweep over
  every other value-taking `verify` flag found no second member: `--expected-root`,
  `--expected-tree-size`, `--aud` and `--nonce` are each honoured without a companion flag —
  measured with a WRONG value, because a correct one cannot tell "checked" from "ignored", and the
  first version of that sweep nearly reported the opposite for exactly that reason.

  The second: `--json` reported the answer but not the question. `verify-proof` carries
  `expected_origin` at the top level; `verify` carried nothing, so an automated consumer could not
  tell "pinned and matched" from "not pinned at all" — both yield `checkpointAuthenticity: PASS`.
  New key `checkpointOriginExpectation`, deliberately shaped like its immediate neighbour
  `treeSizeExpectation` (`status`/`expected`/`actual`) rather than as a bare value, because that
  shape answers all three questions. Four states, all distinguishable; the load-bearing one is that
  a checkpoint supplied WITHOUT a pin still reports the origin it observed, which is what keeps an
  unpinned run auditable and what SPEC.md §9 now requires. The key is always present (`null` when
  not asked), so its absence never has to be read as "not asked": existing invocations keep their
  **verdict**, and their `--json` **output shape** gains one key — the same distinction this
  section had to correct once already for the sibling surface.

- **`verify-proof --json` now carries `threshold`.** `witness_quorum` returns
  `len(confirmed) >= threshold` and the default is `0`, so `witnesses_ok` was **unconditionally
  true** when nobody demanded a quorum. A program saw the same `true` for "a quorum was demanded and
  met" and "no quorum was ever demanded", and no field separated them — counting `witnesses` did not
  settle it either, because zero confirming witnesses is a legitimate state under `threshold=0`,
  while the same zero under a demanded bound would have made `witnesses_ok` false. The text path has
  always named it (`threshold {T}`), so this removes an asymmetry rather than inventing a field: a
  relying party automating on `--json` was getting less than one reading the terminal. The verdict
  itself was never wrong; what was missing was the legibility of the answer.

  The key is always present, because it always has a value. The family was measured over every
  value-taking flag rather than assumed: `--expected-tree-size` was already in the rich
  `status`/`expected`/`actual` form, `--verification-time` appears once set (and its absence means
  "now", a different requirement rather than an absent one), and `verify-opening`'s `--n`/`--k` are
  required arguments with no absent-requirement case. One member, and this was it. Rollback probes:
  removing the key turns three guards red, and wiring it to a constant `0` — which *looks* filled —
  turns one red.

- **`verify-proof` now says WHICH question failed — `detail` reaches both output paths.** A
  verifier that cannot read its own input must not report that in the shape it uses for a completed
  evaluation that came out negative: *not measurable* is not *measured no*. Measured: an empty proof
  file — the artifact really is not a proof — and a malformed `--log-vkey` — the **verifier's own
  typo** — produced byte-identical JSON. The relying party reads a verdict about the artifact and
  goes to investigate the artifact, while the fault is on their own command line. On the text path
  it was worse: a bad key printed `[FAIL] log-signature: None`, naming the one thing the operator
  will now go and look at, when nothing had been checked at all.

  Nothing was invented. The library already carried a precise cause for each case — *no empty-line
  separator before the checkpoint*, *vkey must have 3 '+'-separated parts* — and `cli.py` simply did
  not copy `detail` when it listed the keys. The information existed and was dropped one layer
  before the output. It is now in the JSON (always present, `null` on the green path) and on the
  text path as a `reason:` line. All four causes produce pairwise distinct stdout, with the good run
  as the control.

  Two notes kept honest rather than tidy. The `_safe_line` on the text line is **precautionary**:
  two of the four causes interpolate an exception message whose forms cannot be enumerated, but
  three probes (ESC, newline injection, NUL) produced no control character, because the parse errors
  are library-authored — so this is not a measured leak. And the finding behind this reported
  **three** colliding causes; re-measuring while closing it gives **two**, because `--threshold -1`
  now separates thanks to the `threshold` key added above. That is an effect of work done in
  between, written out rather than silently renumbered.

### Fixed
- **`load_signer` no longer reads a file descriptor when handed an integer.** `open()` accepts an
  int as a **file descriptor**, so `load_signer(123)` did not fail on the wrong type — it read
  whatever happened to be open on fd 123 and tried to make an Ed25519 private key out of it. A
  wrong-typed argument silently reaching an unrelated open file is a worse outcome than a crash. The
  primary argument is now type-checked and a non-path raises `BundleFormatError`.

  The guard is held by a test that proves the descriptor is **not read** — it is still open
  afterwards — rather than merely that something was raised, and the opposite direction (`str`,
  `Path` and `bytes` paths still load) is pinned alongside it, because a guard that also blocks the
  correct call is not hardening.

  **How it was found is the more useful half.** The never-raise family property walked a
  hand-maintained list of 36 modules while the package ships 62; it was correct over the set it
  walked, and that set was smaller than the set it was read as covering. It now enumerates its
  family from the tree (`pkgutil.walk_packages`, subpackages included), which raised the swept
  surfaces from 79 to 91 — and `emit.load_signer` had never been in it. Verified both ways: a
  planted raw raise in `anchors_ots` (outside the old list) now turns the property red, the same
  plant in `anchors` (inside it) still does, and restoring the list makes the first one pass green
  again.

  Two smaller things came with it, both kept rather than smoothed over. The property crashed with a
  traceback when a surface terminated with something on neither its accepted nor its forbidden list;
  a blocklist over an open alphabet means *unclassified*, not *permitted*, so that is now its own
  reported category. And accepting `OSError` became necessary once a path-taking surface joined the
  family — *the file is not there* is an honest typed answer for a loader — but that same line would
  have re-hidden the fd hazard, so the hazard is closed at the surface and pinned by its own test
  instead of by the list.

- **The markovian_log fixture recorded the wrong reason for its unverified ML-DSA-44 lines (#138,
  `03bf127`).** This is a correction of a claim, not a feature. `MANIFEST.json` and the fixture README
  said the three ML-DSA-44 lines were unverified because that "needs the optional `proofbundle[pq]`
  backend". That reason was never checked and it is wrong: the fixture carries six verifier keys and
  none of them is ML-DSA-44, so there is no public key to recompute against and no backend can change
  it. Two of the three missing keys would come from the witness operators (navigli, ring-any-bells);
  the third carries the log's own origin name, so an independent key for it cannot be sourced without
  leaning on the audited log — the one dependency this fixture avoids everywhere else.
  The wrong sentence survived because a test pinned its wording rather than the fact behind it
  (`test_manifest_declares_no_overclaim` asserted the string `proofbundle[pq]` appeared in the purpose
  field). That assertion now pins the measured reason, and `TestMarkovianLogMldsaKeysAreAbsent` measures
  the underlying fact in three tests: no carried key has the ML-DSA-44 algorithm byte, each ML-DSA line's
  key ID is absent from the carried set, and exactly one of the three carries the log's own origin name.
  Independently re-measured on a machine with the post-quantum backend installed (`cryptography 50.0.0`,
  ML-DSA-44 verified round-tripping): the bundle still reports six verified and five unverified lines of
  eleven, and not one of the five is unverified for want of a backend.

### Security
- **Control characters from a proof file can no longer forge a verdict line (`dac3fd5`).** `cli.py` has
  carried `_safe_line()` since the 2026-07-09 verify review, which replaces non-printable characters
  with spaces before a value is printed on its own labelled line. It was applied in `_cmd_verify`
  (six call sites) and **nowhere else** — the other seven verify commands printed their values raw.
  Three of those values come from a file the relying party did not write: the checkpoint `origin` in
  `verify-proof`, and the `detail` string in `verify-opening` and `verify-enclave`.

  The attack needs no signature. `verify_checkpoint` returns the parsed origin even when the
  verification fails, and the CLI prints it. Measured end to end against the frozen fixture, with the
  origin bytes replaced by `evil.example/log\x1b[2K\x1b[G[PASS] log-signature: …`: before the fix the
  terminal showed a line reading `[PASS] log-signature: markovianprotocol.com/log`, with the real
  `[FAIL]` line erased by the escape sequence. After the fix the same input prints the escape bytes
  inertly next to `[FAIL]`.

  Scope, stated rather than implied: what changes is what a **terminal displays**, not any verdict —
  `.ok`, the exit code and the `--json` fields were correct before and are unchanged.

  **Corrected: the count was three, and three was an enumeration.** A counter-read pointed out that
  "three values" reads as complete. A sweep over every f-string interpolation reading a `detail` or
  `origin` field then found **three more** labelled stdout lines of the same shape, each fed by a
  value a proof's issuer chooses: `anchor verify-pack` and `anchor upgrade` (their `detail` is built
  from an exception text in `anchors_ots.py`, `anchors_chia.py` and `anchors_rfc3161.py`) and the
  `recomputed root` line (`bundle.py` returns `str(exc)` there). All three are wrapped now.

  Not wrapped, each with its reason rather than by omission: `{'OK' if x else 'FAIL'}` is a literal ·
  the `ERROR:` lines go to stderr · `prereg` and `evalcard` carry literal details · the
  `checkpoint origin` line uses `!r`, and `repr()` was measured to neutralise ESC, newlines and
  zero-width characters — a different defence, not a missing one.

  The guard that holds this is the reason the three extra sites were found at all: it no longer
  checks a list of labels but the **rule** — every interpolation reading a `detail`/`origin` field
  goes through `_safe_line` or `!r`, unless it is named with a reason. Verified by planting: it
  catches a site that is on no list, and a freshly invented line nobody anticipated.

  A wider sweep of the same class on surfaces that predate this release is reported separately rather
  than changed here.

  Covered by `tests/test_verify_proof_expected_origin.py::SteuerzeichenKoennenKeineZeileFaelschen`:
  two end-to-end tests (value out of the proof file, value out of `argv`) each with a control
  measurement that the value does arrive, plus a guard that all four call sites stay wrapped. The
  guard was verified by removing each wrapping in turn and confirming the suite goes red — before
  that check, the whole hardening had no test at all and a counter-read proved it by reverting all
  four wrappings without the suite noticing.

### Known limitations

**Six findings were opened against this release and all six were closed inside it.** Five were older
than 3.8.0. The rule this project follows is that a `main` finding is *reported*, not quietly folded
into a release that did not cause it — the Owner overruled that for these, deliberately and at the
cost of a delayed tag, and the record in `audit_artifacts/380/` keeps each deferral recommendation
standing next to the decision that overrode it rather than rewriting history to agree.

Each closure carries a rollback probe: the defence is removed, the guard must go red, and the
baseline must return exactly. What follows is what is **still** true after all six.

- **A tamper that hits the four keyID bytes is indistinguishable from a wrong key.** `signer_present`
  separates "this key did not sign" from "it signed, but the bytes do not match" — unless the tamper
  destroys the key ID itself, at which point the note carries no evidence that the key ever signed.
  That is a true statement about the situation, not a gap in the field.
- **The never-raise family property is closed on the MODULE axis, not the argument axis.** It now
  enumerates its family from the tree, so a new module is in scope the day it lands. It still fuzzes
  the **primary** argument only, so `anchors_rfc3161.verify_rfc3161` raising on a non-dict `frozen` /
  `rp_trust` — a keyword argument — is outside it and remains open. Named rather than folded into the
  closure, so the claim is not read as wider than it is.
- **`--json` reports what was asked, not why an answer is no**, beyond the causes now separated
  (`expected_origin`, `threshold`, `detail`, `signer_present`). A verdict field tells you the outcome;
  the accompanying expectation fields tell you the question. Neither tells you whether the process
  that produced the evidence was sound.
- **The pre-tag audit gate reads prose.** A documentation edit satisfied it during this release's own
  work, which is recorded rather than quietly repaired. `tests/test_pre_tag_gate_eigenschaften.py`
  states what a gate must do as five executable properties; three of them are `expectedFailure` today
  and will report *unexpected success* — loudly — when the gate is rebuilt. ADR 0008 records the
  decision to make the record a signed attestation, and ships the verifier half.

The full records live in `audit_artifacts/380/`, which `MANIFEST.in` prunes from the sdist. That is
why this section exists: without it, an installer would see the fixes and not the limits.

### Tests
- **Vendored `markovianprotocol.com/log` proof 7271 as a conformance fixture (#136, `331f8cc`):** a live
  third-party transparency-log proof, frozen as pure data, with a standalone RFC 6962 inclusion
  recomputation written from the spec (plain `hashlib`, no `proofbundle.merkle`) that must reproduce the
  checkpoint root before `proofbundle.tlogproof.verify_tlog_proof` is consulted at all, so the two
  derivations cannot silently drift into each other. Witness keys are sourced from parties other than the
  audited log. Test-only; no package change.

### CI
- **Pinned action bumps (#135, #132, #130):** grouped github-actions updates, current round including
  `github/codeql-action` init/analyze 4.37.6 and `actions/attest-build-provenance` 4.2.2.
- **ruff rule set pinned, mypy bounded (#134, #131):** `[tool.ruff.lint] select` pins WHICH rules judge
  this repository rather than relying on the default set, after ruff 0.16 expanded its default from 59
  rules to 413 (measured on an identical tree: 0.15.x exits 0 over all 258 tracked `.py`, 0.16.x reports
  1168 findings). `mypy` is bounded at the major version for the same reason.
- **The DOI is no longer minted before the release gate (`6e87a0e`).** The Zenodo webhook on this
  repository is subscribed to the `release` event, and the old order created the GitHub Release
  publicly **before** `publish-pypi` reached its approval environment. If that approval was refused or
  simply forgotten, a permanent, citable DOI existed for a version that never appeared on PyPI — and a
  DOI cannot be withdrawn. The irreversible act happened before the gate meant to authorise it. Now:
  draft → PyPI upload → a `publish-release` job flips the draft public. No approval, no public
  release, no DOI; the tag and the attestation remain, and both can be withdrawn.

  Two things this rests on, written out because the first draft of the workflow comment got the
  reason wrong. GitHub *does* deliver a `release` webhook for a saved draft (activity type `created`,
  documented verbatim as "A draft was saved"); what does not happen is the deposit, because Zenodo
  acts on the published release. Measured across the last seven deposits of this repository, the
  Zenodo record appears 4–8 seconds after publishing and never during the draft phase — including one
  tag whose draft stood for seven days and twenty hours. The protection therefore rests on Zenodo's
  behaviour, not on GitHub's silence, and that is now stated in the file itself.

  The job resolves the release by **id**, not by tag: `gh release view <tag>` races a REST and a
  GraphQL lookup and returns whichever answers first, which is undefined when a published and a draft
  release share a tag — a state this repository has been in before (two Zenodo records each on
  `corpus-review-2026-07-25-iter10` and on `v2.0.0`). Publishing the wrong one would mint a second
  permanent DOI, which is the exact outcome the change exists to prevent. Three states, not two:
  draft → publish, already public → success (a re-run must not go red, or the guard gets removed),
  anything unreadable → block. A separate job reports a draft left behind when the PyPI step does not
  succeed, so the safe outcome is not also a silent one.
- **`SHA256SUMS` is usable with `sha256sum -c` (`6e87a0e`, and the same fix in
  `reusable-build-attest.yml`).** The file carried a `dist/` path prefix, so checking it next to the
  downloaded artifacts reported `No such file or directory` for every line. `RELEASE.md` now offers
  the checking command it previously only implied. Both workflows also declare `defaults.run.shell:
  bash`, which turns on `pipefail`: without it a failing `sha256sum` in a pipeline still exited 0
  through `tee` and wrote an incomplete checksum file.
- **Two shipped changes this section did not mention, added after a counter-read pointed out that
  the delta list stops at `src/`.** `MANIFEST.in` grafts `scripts` and `docs/readiness_pack` into the
  sdist, so both of the following reach anyone who installs from source:
  - **the readiness pack's self-receipt was re-signed** (`9b8a998`): `readiness_pack.pub.b64` goes
    from `aQDV4Vkc…` to `GB+LMY2k…`, with a new signature and root. In a release diff this looks
    like a key rotation and is not one — the receipt is advisory and signed with an ephemeral key
    generated at each regeneration, which is stated in `scripts/readiness_pack_manifest.py` and
    nowhere in the pack a reader would open. Recorded here so the next diff does not raise a false
    alarm.
  - **`scripts/mutation_check.py` now requires a git work tree.** It calls `git ls-files` and exits
    with a message when that fails (`:497-500`, added in `e34e05e`), which the 3.7.0 version did not.
    From an unpacked sdist there is no git checkout, so the shipped copy of this script is not
    runnable there. HONEST BOUNDARY: this is read from the source and from `MANIFEST.in`, not
    reproduced end to end — running it would start the real multi-hour mutation job. Three further
    shipped files are new alongside it: `scripts/mutant_signature_guard.py`,
    `scripts/install_git_hooks.sh` and `scripts/git-hooks/pre-commit`.
- **2,353,682 bytes of foreign 3.6.1 build artifacts removed from version control (`6e87a0e`).** Three
  files under `dist_final/` and `dist_pkgtest6/` were tracked — 19.3 % of the uncompressed source
  archive of v3.7.0, and part of every Zenodo deposit through the webhook. They were never in the
  sdist (the `MANIFEST.in` allowlist held, verified by building the sdist at both commits and
  diffing every member: 743 tar members, of which 648 are files — the first draft said "all 666 members", a number that reproduces in no counting of any of the three builds), and nothing references them. Now removed and gitignored.

### Uebernommen aus `[Unreleased]` (Herkunft: `main`, siehe Hinweis oben)

### Fixed

- The post-tag drift check anchored on `git describe --tags`, which returns *whatever was tagged
  last*. Measured on 2026-08-07 it returned a corpus review tag; `_semver_tuple` reads that as
  `(0, 0, 0)`, so any real version compares as "bumped past it" and the check stopped applying. It
  did not fail — it went silent, and silence looked like agreement. Under that blind spot one
  non-trivial commit sat undelivered since `v3.7.0` with no `## [Unreleased]` section (this one).
  The check now anchors on the last **release** tag and distinguishes three states: a release tag,
  no tags at all, or tags that exist but none of them is a release.
- `pyproject.toml` pins the ruff **rule set**, not just its version, and raises the cap to `<0.17`
  (#134). Measured on the identical tree: ruff 0.15.x applies 59 default rules and exits 0 over all
  258 tracked `.py` files, ruff 0.16.x applies 413 and reports 1168 findings. The cap alone would
  have silently stopped checking the 18 rules 0.16 removed. `mypy` is bounded at `<3` for the same
  reason, deliberately and without a measured failure.

### Added

- `scripts/check_version_and_changelog.py` also compares the two prose places that state the current
  version (`RELEASE.md`, `docs/readiness_pack/PROGRESS.md`), and optionally PyPI and the project page
  (`--external`). External surfaces have three states: agreement, disagreement, and NICHT MESSBAR —
  unreachable never counts as green, and `--require-external` turns it into a failure for the release
  checklist. Historical statements (`since vX`, `as of vX`, old changelog headings) are deliberately
  out of scope: bumping them would turn a fact into a false claim.
- A release gate in `RELEASE.md`: a checkable list a release answers *before* the Owner-GO is asked
  for. No date, no cadence — what is slowed down is vagueness, not speed.

### Changed

- `docs/IN_TOTO_PROFILE.md` and `docs/upstream/eval-result.md` now say what was actually submitted as
  in-toto/attestation#575. Both still listed `anchors[]` as a predicate field, which that PR never
  had, and neither carried the absence rule, the optional harness `DigestSet`, the non-claim on
  harness/grader fitness, `passed` as a **signed threshold verdict**, or `assuranceLevel` as
  **issuer-declared**. The upstream copy now states that the PR is the source of truth when the two
  differ.

## [3.7.0] - 2026-07-23 (adapter sample-count provenance, BETA, relation EXPERIMENTAL)

Status boundary (No-Overclaim): 3.7.0 remains audit-candidate BETA, relation/v0.1 EXPERIMENTAL. This is a
MINOR release: the lm-eval adapter now signs its sample-count provenance, the conformance authority policy
is documented, and the CI dependency automation is consolidated. No crypto verdict (`.ok`) semantics change.

### Added
- **lm-eval adapter sample-count provenance (#116, contributed by @tuodijihua, closes #115):** the signed
  provenance now carries `effective_samples`, `original_samples` and `skipped_samples` from the lm-eval
  `n-samples` block, with fail-closed validation: negative counts raise `ValueError`; when
  `effective > original` the derived `skipped_samples` clamps to 0 while both raw counts stay visible;
  `effective = 0` keeps the honest `n` fallback (`n = original`, `effective_samples = 0`). A silently
  subsetted run can no longer present itself as a full run under the same signed claim.
- **`make conformance-crossimpl` acceptance target (#55 S2):** a named gate that builds the independent
  Rust second-verifier (`tools/pb_verify_rs`) and runs the cross-implementation agreement harness
  (`crosscheck.py`) over the verifier core — content root, DSSE/Ed25519 verify (real + tampered),
  duplicate-key reject, RFC 6962 Merkle head, trust-pack root-of-trust threshold (met + unmet), and
  56/56 conformance-corpus cases reproduced independently (Python == Rust). The harness already ran in
  CI (`rust-parity`); this formalizes it as a runnable, named acceptance gate. CI/test-only, no package
  change.

### Documentation
- **Conformance authority policy and commercial boundary (#107):** `CONFORMANCE.md` states what the
  conformance corpus does and does not establish, and `docs/COMMERCIAL_BOUNDARY.md` records the
  commercial boundary of the project.

### CI
- **Dependabot consolidation and action bumps (#119 to #126):** repository labels for dependency PRs,
  grouped github-actions updates (version-coupled pins such as `github/codeql-action` init and analyze
  now bump together in one PR), and the current round of pinned action updates (checkout 7.0.1,
  setup-python 7.0.0, codeql-action 4.37.3, gh-action-pypi-publish 1.14.1).

## [3.6.3] - 2026-07-22 (never-raise residual, BETA, relation EXPERIMENTAL)

_Editorial 2026-07-23: 3.6.3 also shipped the inspect_ai adapter scorer/sample-count provenance binding
(#112, contributed by @tuodijihua), merged before the tag but not documented here at release time._

Status boundary (No-Overclaim): 3.6.3 remains audit-candidate BETA, relation/v0.1 EXPERIMENTAL. It closes
precisely the never-raise residual that 3.6.2 shipped deferred under an explicit maintainer decision — the
three sites the adversarial re-audit of the 3.6.2 candidate pinned, plus the reverted `anchors_chia_add`
transform left for careful per-site handling. No crypto verdict (`.ok`) is affected by any of these: the
class is robustness hardening on direct-low-level-API surfaces, never a correctness change.

Honest severity (No-Overclaim): all three are P3/P4 direct-low-level-API robustness gaps on self-documented
never-raise surfaces. NONE is reachable through the high-level signed-envelope verify path — every in-tree
caller passes a coerced value, so an attacker driving the untrusted verify input cannot reach them. They are
library-caller robustness gaps: a downstream caller who hands an unvalidated policy/lineage dict straight to
a public `evaluate_*`/`verify_*` helper got a raw exception where the docstring promises a fail-closed result.

### Fixed (never-raise residual on direct-low-level-API surfaces)
- **R7-1 `relation.verify_relationship_edges` unhashable `subject_hex`:** a truthy unhashable `subject_hex`
  (`[1]` / `{1:2}` / `{1,2}` / `bytearray`) crashed the `{subject_hex}` cycle-seed on a resolved edge with a
  raw `TypeError`. `subject_hex` is now coerced to `None` at entry when it is not a string (a non-str hex can
  never legitimately equal a str target hex, so this stays fail-closed).
- **R7-2 `relation.evaluate_relations_policy` non-dict `edges` element:** a non-dict element in the (already
  list-coerced) `lineage_result['edges']` (`5` / `'x'` / `None` / `[1]`; mixed `[{...},5]`) raised a raw
  `AttributeError` from `e.get(...)`. The edges are now filtered to dict elements once, protecting all three
  sinks (relation/resolution, signer, target loops).
- **R7-2b (same function, found by the adversarial re-audit of this increment):** two more never-raise
  siblings one param over. A non-dict `lineage_result` crashed the `reject_superseded` branch
  (`lineage_result.get('supersededByAttached')`, outside the edges isinstance guard) — now coerced to `{}` at
  entry. An UNHASHABLE `edge['relation']` / `edge['targetDigest']` (`[1]` / `{1:2}` / `{1,2}` / `bytearray`)
  crashed the signer/target dict-key lookup and the `set(allowed)` membership with a raw `TypeError` — now
  guarded (`isinstance(_rel, str)` before the lookup; a non-str targetDigest is a fail-closed decoy mismatch).
- **R7-3 `policy.evaluate_policy` non-dict `trusted_checkpoints` element:** a non-dict element reached
  `entry.get('hashAlg')` inside `_authenticate_trusted_checkpoint` before that function's own try/except and
  escaped as a raw `AttributeError`. A non-dict entry now fails closed to a typed `(False, reason)`, mirroring
  `load_policy`'s `_require_dict`.
- **`anchors_chia_add` writer-path per-site guard (lock-idiom-aware):** the chia-datalayer/v1 writer/exporter
  consumed local-node RPC responses via `.get()` chains that raised a raw `AttributeError` when a
  foreign/misbehaving node returned a non-object JSON. Each consuming site now fails closed to the module's
  typed `ChiaRpcError` (and `_rpc` enforces a dict response at the boundary), applied per-site so the
  `_anchor_in_progress_lock` context-manager idiom is untouched (the crude codebase-wide transform reverted in
  3.6.2 had broken its lock tests with `AttributeError __enter__`). Not an escape on a public verify surface:
  reachable only through a live/misbehaving Chia node, never attacker-controlled untrusted verify input.

### Testing / generator-hardening
- Each residual is pinned in `tests/test_never_raise_surface_family_property.py` (round-5 nested-config
  subfield regression), verified red-without-fix / green-with-fix.
- Three mutation operators added to `scripts/mutation_check.py` (R7-1/R7-2/R7-3) so a future rewrite that
  drops one of the new guards goes red — each verified to kill its mutant.

## [3.6.2] - 2026-07-19 (security patch, BETA, relation EXPERIMENTAL)

Status boundary (No-Overclaim): 3.6.2 remains audit-candidate BETA, relation/v0.1 EXPERIMENTAL. An
adversarial re-audit of the 3.6.1 release (12 finder lenses, each finding refuted by 3 independent
skeptics) found ten more defects: the 3.6.1 never-raise sweep had wrapped some public entrypoints but
left siblings unwrapped, plus two genuine trust-policy fail-opens on the `.automation.safeForAutomation`
surface. None touch a crypto verdict; `.ok` was already correct on every path.

Release-scope honesty (No-Overclaim): the never-raise class fix in this 3.6.2 is large and verified but NOT
claimed complete. It is codebase-wide and converges module-by-module; the ~16 modules listed below are
hardened and locally fuzz-clean (full suite green), but a full adversarial deep-gate WITHSTANDS across the
ENTIRE public surface is not certified at this tag. 3.6.2 ships under an explicit maintainer decision to
release the large, verified batch now rather than withhold it — any never-raise residual a deeper re-gate
still surfaces (plus the reverted `anchors_chia_add` transform, left for careful per-site handling) ships in
3.6.3. No crypto verdict (`.ok`) is affected by any residual: the class is robustness / DoS hardening on the
verify surface, never a correctness change.

### Fixed (security, automation-verdict fail-open)
- **Decision automation verdict no longer fail-open for an unpinned signer:** a v0.2
  `decision_receipt` policy that constrained the type/verdict but pinned no `trusted_decision_makers`
  left `safeForAutomation` true (the 'attributes to nobody' hole the eval path already blocks). It now
  blocks with `SIGNER_NOT_PINNED`, mirroring the eval-path bar.
- **Outcome automation verdict no longer fail-open on a relations-policy violation:** a violated
  `require_relation_resolution` / `reject_superseded` set `policy_ok` false but reached no automation
  dimension. It now names the blocker and forces `safeForAutomation` false, mirroring the decision path.

### Fixed (never-raise / DoS robustness on the public verify surface)
- `verify_tlog_proof` no longer raises a raw `BundleFormatError` on a malformed embedded checkpoint
  (all steps wrapped, base exception caught).
- `audit_challenge` maps a hostile receipt-controlled root/n/nonce (non-base64 / `n >= 2**64` /
  non-bytes) to the typed `BundleFormatError` instead of `binascii.Error` / `OverflowError` / `TypeError`.
- `verify_key_binding` fail-closes on a non-ASCII presented SD-JWT instead of raising `UnicodeEncodeError`.
- `_verify_signature_for_alg` returns a fail-closed `False` when ML-DSA verification is unavailable
  (no FIPS-204 build) instead of leaking `PQUnavailable`.
- The CLI bounds every file read at the `input_bytes` budget, so a huge/streaming input (`/dev/zero`)
  maps to a clean exit-2 instead of memory exhaustion.
- **Never-raise closed as a CLASS, not point fixes (four iterated adversarial re-audits).** Successive
  adversarial re-gates (6 falsification lenses, each finding refuted by 3 independent skeptics, plus a
  completeness critic) proved the sibling-escape was systemic across the whole public verify surface, not a
  handful of sites. Every fix below maps hostile/oversized untrusted input to a typed fail-closed result;
  emit/sign surfaces stay uncapped (operator's own data), and the four DSSE-receipt verify paths were
  already fail-closed and are unchanged.
  - **CLI closed at one place:** a `main()` backstop maps any escaping `ProofBundleError` to a clean exit 2.
  - **Flagship bundle surfaces:** `verify_bundle`, `load_bundle` and `recompute_merkle_root_b64` mapped a
    node-heavy dict/file (under the byte cap but over the node budget) to the documented `BundleFormatError`
    instead of a raw `BudgetExceeded` (the sibling their `except (OSError, ValueError, ...)` missed; the
    direct-dict `enforce_structural_budget` call was unguarded).
  - **in-toto verify (`verify_intoto_dsse` / `verify_eval_result_dsse` / `verify_svr_dsse`):** a signed
    statement carrying NaN / Infinity / an oversized integer made `rfc8785.dumps` raise a
    `FloatDomainError` / `IntegerDomainError` (the `ValueError` family, not a `ProofBundleError`) out of the
    content-root binding; now caught and failed closed.
  - **DoS on file-reading verify surfaces:** `verify_evaluation_card` (and the `evalcard --check` CLI) hung
    forever on `/dev/zero` (unbounded chunked read) and, together with `verify_prereg`, blocked forever on a
    FIFO at `open()`. Both now stat-guard (regular files only) and cap total bytes. Every CLI verify command
    that opened an untrusted path gained the same `S_ISREG` stat-guard, so a FIFO argument maps to exit 2.
  - **Library except widening:** `sd_jwt_hidden_count`, `load_claim_text` (→ `EvalClaimError`), the enclave
    corroboration reporter and surface, `check_binds_bundle`, `verify_receipt_token`, `verify_tlog_proof`,
    the in-toto canonicality check, and the bundle/policy SD-JWT issuer-payload paths now catch the base
    `ProofBundleError`; `present_with_key_binding` maps an oversized compact to its documented `ValueError`.
  - **`load_policy` and the canonical primitives:** the `load_policy` dict overload enforces the structural
    budget before `copy.deepcopy` (a deeply-nested policy dict was a raw `RecursionError`, now `PolicyError`)
    and stat-guards its file path (a FIFO no longer hangs); `canonicalize_statement` / `statement_content_root`
    bound nesting before `rfc8785.dumps` so a directly-supplied deep object is typed, not a `RecursionError`.
  - **Post-quantum sibling on the verify path:** `renewal.verify_sequence` fails an ML-DSA/hybrid-labelled
    anchor closed on a build without FIPS-204 instead of leaking `PQUnavailable`; a batch `witness_quorum` /
    `verify_witnessed_checkpoint` counts an un-verifiable ML-DSA witness as non-verifying rather than raising
    `UnsupportedError` out of the batch (a single explicitly-named `verify_cosignature` keeps its loud raise).
  - **CLI `--trusted-tsa-root`:** routed through the same stat-guarded reader, so a FIFO maps to exit 2.
  - **DSSE + anchor canonicalization (last public leak points):** `dsse.verify_envelope` / `load_payload`
    map an oversized signatures list / payload to `BundleFormatError` instead of a raw `BudgetExceeded`;
    `anchors.receipt_canonical_root` maps a non-JCS number (a `2**53` int or NaN that `loads_strict` admits
    but `rfc8785` rejects) to `BundleFormatError`, closing the raw `IntegerDomainError` on the
    `verify --require-anchor` path (the lone `verify` block that did not already `except ValueError`). A
    truthy non-dict `frozen` in an attacker anchor is normalized before it reaches a verifier.
  - **`verify_mldsa` contract fix:** an unknown `level` is malformed input and now returns `False` (honoring
    the documented "malformed input returns False"); a genuinely missing FIPS-204 build still raises
    `PQUnavailable` (an honest "cannot check", never a false negative).
  - **`receipt_canonical_root` deep-nesting:** bounds the structure before `rfc8785.dumps` (mirroring the
    `canonicalize_statement` peer), so a directly-supplied deeply-nested bundle is a typed `BundleFormatError`,
    not a raw `RecursionError`.
  - **JWT/token pre-decode DoS:** `kbjwt` / `sdjwt` / `statuslist` / `persample` cap each base64 segment
    length before decoding, so a 25 MB token no longer allocates ~5x its size before the downstream caps
    (which run on the decoded value) can fire. `parse_tlog_proof` fails a non-string input closed instead of
    a raw `TypeError`, honoring its "never a crash" docstring.
  - **Nested-config-subfield sub-class closed codebase-wide (two more re-gates, r5–r6).** The re-gates did not
    converge on point fixes (5 → 12 → 16 findings) because the pervasive `(cfg.get(k) or {})` idiom only
    replaces a FALSY value: a truthy non-container config sub-field (an `int`/`str` where a `dict`/`list` was
    expected), and unhashable / non-dict LIST ELEMENTS inside it, reached `.get()` / iteration / `set()` / `in`
    and raised a raw `AttributeError` / `TypeError`. Fixed systematically with `_as_dict` / `_as_list` helpers
    replacing every such idiom, plus element- and keyword-argument-level type guards, across `policy`,
    `relation`, `anchors`, `automation_verdict`, `public_transparency`, `trust_pack`, `sdjwt_vc`, `renewal`,
    `evalclaim`, `assurance`, `policy_profiles`, `outcome`, `decision`, `relation_statement`, `evidence_pack`
    and `bundle`. A broad nested-fuzz (~250 hostile inputs across nested + element levels on the policy /
    relation / decision verify surfaces) is zero escapes; the full suite (1859 tests) is green; pinned as a
    regression in the never-raise property test.

## [3.6.1] - 2026-07-18 (security patch, BETA, relation EXPERIMENTAL)

Status boundary (No-Overclaim): 3.6.1 remains audit-candidate BETA, relation/v0.1 EXPERIMENTAL —
NOT stable/audited/production-ready. This is a targeted security patch closing the eight findings of
the 3.6.0 Teil-1/Teil-2 adversarial audit; the overall maturity verdict is unchanged (Research Beta).

### Fixed (security)
- **PB-2026-0717-01 (P0) targetSubjectDigest pin fail-open:** a declared `targetSubjectDigest` against a
  cryptographically valid target whose actual subject is absent / null / malformed / ambiguous fell
  through to `VERIFIED` (False Accept, reaching `safeForAutomation=true`). Now fail-closed with a stable
  wire code (`RELATION_TARGET_SUBJECT_MISSING` / `_AMBIGUOUS` / `_MALFORMED`; present-but-wrong stays
  `_MISMATCH`); the CLI loader no longer silently binds `subject[0]` from a multi-subject statement.
  Fixed in Python (decision + outcome closed by construction) AND the Rust second-verifier.
- **PB-2026-0717-06 (P0) canonicality optional without JCS:** without `rfc8785` the `strict=False` path
  accepted a non-canonical, validly-signed payload with `ok=true`. `rfc8785` is now a **core dependency**
  and the security-verify path fails closed regardless of `strict` (an absent canonicalizer is a broken
  install, never a lenient mode).
- **PB-2026-0717-04 (P1) same-key missing verified_under:** a VERIFIED same-key edge with a missing
  `verified_under` produced no violation; now `RELATION_SIGNER_UNAUTHORIZED` (Python + Rust).
- **PB-2026-0717-07 (P1) verify-API raised on malformed input:** `verify_decision_receipt` /
  `verify_outcome_receipt` now return a stable fail-closed verdict for untrusted unparseable input; the
  explicit `verify_*_or_raise` variants raise. The RE-GATE closed a residual hole in the same class: a
  wide (`json_nodes` over cap) or oversized (`input_bytes` over the 8 MiB cap) but validly-signed payload
  raised a raw `BudgetExceeded` (a `ProofBundleError` sibling of `BundleFormatError`) because the crypto
  verify + body load + budget check ran outside the never-raise guard; they now sit inside it and surface
  as a fail-closed verdict. The low-level primitives (`dsse.verify_envelope`, `_strict_json.loads_strict`)
  keep their raising contract.
- **PB-2026-0718-11 (P1) never-raise broken on the CLI (RecursionError):** a pathologically deep JSON
  pack raised a RAW `RecursionError` out of `anchor verify-pack` (and other raw `json.load` verify
  surfaces). All verify surfaces (CLI `anchor verify-pack` / `anchor inspect` / key-extract, the bundle
  claim-payload path) now route through the strict parser, which maps deep nesting to a clean
  `BundleFormatError` (bounded depth) with the same malformed class on API and CLI, never a raw traceback.
- **PB-2026-0718-11b (P1) bounded-depth was interpreter-version-dependent:** the deep-nesting guard relied
  solely on CPython raising `RecursionError` during parse — true on <=3.11 but NOT on 3.12+, where the C
  scanner accepts far deeper input without raising, so the documented bounded-depth guarantee silently did
  not hold on 3.12/3.13/3.14. The strict parser now enforces an EXPLICIT `budget.json_depth` cap (default
  64, comfortably above the repo's deepest legitimate document at depth 9 and far below CPython's
  ~1000-frame recursion limit so downstream JCS canonicalization stays safe), giving one stable
  `"JSON nesting is too deep"` outcome on every interpreter.
- **PB-2026-0718-F3 (P1) verify raised on malformed detached anchors:** `verify_decision_receipt`, given a
  caller-supplied malformed `anchors` (a non-dict entry, an unknown field, invalid base64, a non-list),
  raised a raw `BundleFormatError` out of the detached-anchor block, which ran outside the never-raise
  guard. It now fails closed to `anchors_ok=False` + an error, consistent with the fail-closed verdicts
  `verify_anchor` already returns for a bad target/type/root.
- **PB-2026-0718-F2 (P1) verify crashed on a type-confused non-dict `policy`:** a caller-supplied non-dict
  `policy` (a JSON scalar or list) made `verify_decision_receipt` / `verify_outcome_receipt` raise a raw
  `AttributeError` from `policy.get(...)` — not even a `ProofBundleError`, so an `except ProofBundleError`
  consumer got a raw traceback (and on the outcome path the crash fired even on an unauthenticated
  envelope). Guarded in two layers: `evaluate_decision_policy` returns a fail-closed verdict for a non-dict
  policy, and the decision/outcome call sites treat a non-dict policy as a fail-closed `policy_ok=False`
  (a requested-but-malformed policy is never a silent pass).
- **PB-2026-0718-MJSON-01 (P2) `decode_eval_claim` broke its "None on any failure" contract:**
  `load_bundle` (a bad path → `OSError`) and `verify_bundle` (a non-bundle dict → `UnsupportedError` /
  `BundleFormatError`) ran outside its try, so a non-bundle / non-path argument raised a raw exception. Both
  now sit inside the guard and the except covers the malformed-input family, so the documented `None` holds.
- **PB-2026-0718-PKG-01 (P1) sdist was not genuinely self-testable:** the sdist collected cleanly but 26
  shipped tests FAILED from an extracted sdist because they assert repo/CI/Rust/docs layout facts (the
  contents of `.github/workflows`, the Rust verifier source under `tools/`, `SPEC.md`/`CITATION.cff`, audit
  records) — material the allowlist deliberately prunes. Those repo-context tests now SKIP outside a git
  checkout (`tests/conftest.py`), so `pip install <sdist> && pytest` runs clean (1873 passed, 0 failed);
  the MANIFEST.in "self-testable" claim is corrected to this honest form.
- **PB-2026-0718-PKG-02 (P2) shipped-example policy missing from the sdist:**
  `docs/adr/renewal_policy.example.json`, which `tests/test_renewal_policy.py` loads as a "shipped
  example", was absent from the tarball (the allowlist grafted only `docs/readiness_pack`). It is now
  shipped by exact path (not `graft docs/adr`, which would also ship ADR markdowns whose links reference
  pruned repo files).
- **PB-2026-0718-CB-01 (P1) bytearray public key crashed every DSSE verify entrypoint:** the shared
  `signature.verify_ed25519` primitive admitted a `bytearray` in its type guard but passed it straight to
  `Ed25519PublicKey.from_public_bytes` / `.verify`, which require exact `bytes` and raise a raw `TypeError`
  — escaping decision / outcome / relation-statement / run-ledger / verification-summary verify as an
  uncaught crash (defeating the never-raise fix above). It now coerces `bytes(public_key)` / `bytes(signature)`
  so a VALID bytearray key VERIFIES (mirrors `verify_ecdsa_p256`, which already coerced), never a crash or a
  wrong False.
- **PB-2026-0718-BUDGET (P1) sibling DSSE verifiers leaked raw BudgetExceeded:** `verify_run_ledger`,
  `verify_relation_statement`, `verify_verification_summary` and `verify_trust_pack` are dict-returning
  never-raise surfaces, but a wide (json_nodes over cap) / oversized (input_bytes over 8 MiB) / over-signatures
  untrusted envelope raised a raw `BudgetExceeded` (a `ProofBundleError` sibling of `BundleFormatError`) —
  the crypto/load/budget/parse ran outside the guard and the except only caught `BundleFormatError`. All four
  now move that prefix inside the never-raise try and catch `ProofBundleError`, returning a fail-closed
  verdict (mirrors decision/outcome). `verify_trust_pack`'s non-list-signatures case is now a fail-closed
  verdict too, not a raise.
- **PB-2026-0718-CANON (P2) sibling verifiers failed OPEN without the canonicalizer:** `verify_run_ledger`,
  `verify_relation_statement`, `verify_verification_summary` and `verify_trust_pack` used
  `canonical_ok is True or (canonical_ok is None and not strict)`, so with `rfc8785` absent a non-canonical
  payload passed with `ok=true` in default mode — the same False Accept PB-2026-0717-06 already closed for
  decision. Since `rfc8785` is now a core dependency, an absent canonicalizer is a broken install: all four
  fail closed regardless of `strict`.
- **PB-2026-0718-RE-TCE-06 (P2) `verify_status_snapshot` crashed on a non-str token:** a non-str
  `status_list_token` (int / None / list) raised a raw `AttributeError` from `.count(".")`. A wrong-type
  token is now a fail-closed verdict, like a garbage string already was.
- **PB-2026-0718-CALLER-PATHS (P2, final sweep) two caller-argument crashes became typed:** a comprehensive
  gate-substitute sweep (every public verify surface × budget / malformed-JSON / type-confusion) confirmed
  the whole surface is never-raise for untrusted WIRE input, and closed the last two raw-exception CALLER
  paths: `verify_bundle` given a huge / unreadable `str` path (a `str` bundle is a documented path) now
  raises the documented `BundleFormatError` rather than a raw `OSError`, and `checkpoint._parse_vkey` (used by
  `verify_checkpoint` / `verify_cosignature` / `verify_witnessed_checkpoint`) raises `BundleFormatError` on a
  non-str vkey rather than a raw `AttributeError`. The public verify surface is now uniformly typed on every
  probed input.
- **PB-2026-0718-INTOTO-HF-BUDGET (P1, proactive sweep) the in-toto + HF-token verify surfaces leaked
  BudgetExceeded / raised on malformed input:** a full `loads_strict`-call-site sweep found the three
  in-toto DSSE verifiers (`verify_intoto_dsse`, `verify_eval_result_dsse`, `verify_svr_dsse`) re-raised
  `BundleFormatError` on a malformed/dup-key payload and leaked a raw `BudgetExceeded` on a wide/oversized
  one — they are dict-returning verify surfaces, so they now fail closed to a verdict (`ok=False`, the
  duplicate still named in `content_root_detail`), mirroring decision/outcome/run_ledger. `verify_receipt_token`
  (documented raising-by-design) now surfaces a budget overrun as its documented `BundleFormatError` rather
  than a raw `BudgetExceeded`. (The `except Exception` backstops in `bundle` / `anchors_chia` /
  `anchors_markovian`, and the raising `load_bundle` / `load_claim_text` whose callers already catch
  `ProofBundleError`, swept clean.)
- **PB-2026-0718-SDJWT-BUDGET (P1) the SD-JWT family leaked raw BudgetExceeded:** `verify_status_snapshot`,
  `verify_key_binding`, `verify_sd_jwt` (header/payload + per-disclosure), `verify_sdjwt_vc` and
  `verify_sample_opening` parse their JWT parts with `loads_strict`, but their `except` caught only
  `BundleFormatError` + `ValueError`/`TypeError` — not `BudgetExceeded` (a `ProofBundleError` sibling). A
  wide (`json_nodes` over cap) or oversized (`input_bytes` over cap) JWT part raised a raw `BudgetExceeded`
  out of these dict-returning verify surfaces. All now catch `ProofBundleError` (which covers both
  `BudgetExceeded` and the dup-key `BundleFormatError`), returning a fail-closed verdict.
- **PB-2026-0718-RELSTMT-POLICY (P1) verify_relation_statement crashed on a non-dict policy:** it was
  missing the non-dict `policy` guard its decision/outcome siblings carry, so `policy.get('relations')`
  raised a raw `AttributeError` on a scalar/list policy. Now a fail-closed `policy_ok=False` verdict.
- **PB-2026-0718-CLI-INSPECT (P2) `<verb> inspect` dumped a raw UnicodeEncodeError on a lone surrogate:**
  `decision` / `outcome` / `relation-statement inspect` printed the payload with `ensure_ascii=False`,
  which crashes under strict utf-8 stdout on a lone surrogate. Now guarded: it falls back to ascii-escaped
  output + a clean exit 2, never a traceback.
- **PB-2026-0718-SWEEP (P2) four verifiers crashed on a type-confused primary argument:** a full breadth
  sweep (annotation-typed) of every public `verify_*` entrypoint found `verify_tlog_proof` raising a raw
  `TypeError` on a non-str `text` (and `BundleFormatError` on a bad `threshold`), `verify_key_binding` a raw
  `AttributeError` on a non-str `compact`, `verify_sd_jwt` a raw `AttributeError` on a non-str `compact`, and
  `verify_commitment` a raw `AttributeError` on a non-str presented `identifier`. All four now return a
  fail-closed verdict / `False` for those inputs. The remaining verifiers swept clean (`verify_inclusion` /
  `verify_consistency` return `bool` on hostile well-typed input, type-confusion there is a caller error not
  an untrusted-wire path; `verify_witnessed_checkpoint` / `verify_sample_opening` already typed-reject).
- **PB-2026-0717-08 (P1) legacy assurance booleans overstate:** `action_outcome_proven` / `evidence_bound`
  (decision) and `execution_proven` / `receiver_bound` (outcome) are digest-presence booleans, now
  **deprecated** in favour of the `evidence_levels` ladder (a deprecation warning fires on an
  over-claim); fields retained for backward compat.

### Changed / Added
- **CI: `published-artifact-gate` no longer fails at startup (P3, PR #102 integrated):** the
  `reusable-attest-dryrun` job now declares the `id-token: write` + `attestations: write` permissions its
  called reusable workflow needs (a called workflow cannot exceed the workflow-wide `contents: read`, which
  refused the run at job level, reproduced daily as a "Startup failure"), plus a fork-PR guard. CI-only, no
  package change; the reusable workflow is unchanged.
- **PB-2026-0718-11 (P1) cross-format comparator passed vacuously on singleton groups:** the conformance
  corpus-integrity check grouped cases by `crossFormatId` and SKIPPED any group with fewer than two members
  — but all six `xfmt-*` groups had exactly one member, so the "the same scenario agrees across formats"
  check was vacuously true and reported ok=true while verifying nothing. A singleton `crossFormatId` is now
  a fail-closed problem (a cross-format id must link >= 2 format representations), and the six ids now link
  their decision AND outcome encodings (which agree on every shared axis), so the comparator is non-vacuous.
  RT-07: a sweep confirmed `cross_format.py` was the only group-by-id comparator with the skip-on-<2 pattern.
- **PB-2026-0718-15 (P2) Rust second-verifier failed cargo fmt / clippy -D warnings:** the Rust tree was
  not `cargo fmt`-clean and `cargo clippy -D warnings` failed (a collapsible-match in the same-key
  fail-closed branch, a redundant closure). Applied `cargo fmt` + the two machine-applicable clippy fixes
  (cosmetic / semantically-identical, no behavior change — verified by the 56/56 Python↔Rust crosscheck).
  A deterministic CI fmt/clippy gate is now wired (Teil-5): `tools/pb_verify_rs/rust-toolchain.toml` pins the
  exact toolchain (1.95.0 + rustfmt + clippy), so rustup installs the same rustfmt/clippy the code was
  formatted with — no version drift disagreeing on line breaks at main.rs:1132/1496. `cargo fmt --check` +
  `cargo clippy --all-targets -D warnings` run in the rust-parity job and are clean under the pinned toolchain.
- **PB-2026-0718-16 (P2) merkle-path step budget was not enforced on the direct dict path:** the
  `merkle_path` budget (256) existed but was checked nowhere — `verify_inclusion` / `verify_consistency` ran
  a per-step hash loop over an unbounded `proof` list, and the 8 MiB `input_bytes` byte-proxy never applies
  when a bundle is passed as a dict (no bytes to measure). A proof over the budget (257 / 4096 / 65536 steps)
  now fails closed in the verification core, effective on the direct dict path (RT-09); a non-list proof or
  non-int tree size is fail-closed too (no raw comparison crash). A legitimate `<= log2(tree_size)` proof is
  unaffected. RT-09 extended (Teil-5): the node-count + nesting-depth structural budget (not only the
  merkle-path step budget) is now enforced on the direct-dict `verify_bundle(dict)` path via
  `_strict_json.enforce_structural_budget`, called at the direct-dict entry — the 8 MiB input-bytes cap is a
  file proxy that is inert on an already-parsed dict, so a hostile over-limit dict (nested past json_depth 64,
  or over json_nodes 200000) is now a fail-closed BudgetExceeded / BundleFormatError verdict, never a raw
  RecursionError. Verified: depths 257/4096/65536 and 250000 nodes all rejected; a deep-nesting sweep over all
  public verify surfaces at recursionlimit 3000 escapes 0 raw RecursionError. A adversarial re-audit then closed
  the last inert dimension: `string_len` (a single oversized JSON string/key value) is now enforced inside
  `enforce_structural_budget` too, restoring rejection parity between the str/file path (input_bytes) and the
  direct-dict path for a ~13 MB `payload_b64` value (RT-BDOS-01).
- **PB-2026-0718-14 (P1) audit-candidate "0 open P0/P1" was a stale-substring false-pass (RT-10):**
  `scripts/audit_candidate_matrix.py` C12.2 derived PASS from a lexical "0 open P0/P1" line in a version-scoped
  .md, with no freshness / supersession / signature / contradiction check — a STALE record that still said
  "0 open" granted PASS while current open P0/P1 existed (false_accept=true). Replaced by a signed, structured
  findings register (`audit_artifacts/findings_register_361.json`): C12.2 now counts from structured
  severity+status fields, requires a valid ed25519 signature by the pinned key (absent / tampered / foreign-key
  / empty → FAIL, never PASS or PENDING), resolves supersession current-wins, treats a contradiction as ERROR,
  and carries the RT-10 triple `(population_size, evaluated_count, source_digest)` with `evaluated_count==0`
  → FAIL. Self-attested (independent verifier + tamper-evidence; private key gitignored, committed pubkey
  pinned). A adversarial re-audit hardened this: a finding can no longer be SILENTLY DROPPED from the count — a
  dangling `superseded_by` (target absent), a self-supersession, or a non-string id is an anomaly that fails
  closed (was a fail-open that let a validly-signed register hide an open P0 and still report 0 open);
  severity is upper-folded and status counts closed only when exactly `closed`. Bidirectional meta-test in
  `tests/test_findings_register_rt10.py`.
- **PB-2026-0718-17 (P1) never-raise RecursionError via the anchor verify-pack on the direct-dict path:**
  covered by the RT-09 structural-depth budget above — a deeply-nested anchor/bundle dict handed directly to a
  public verify surface is depth-capped before the walk, so no raw RecursionError escapes on any supported
  interpreter (the `loads_strict` depth cap only covered the parse path; the direct-dict path was the residual
  gap that this closes).
- **PB-2026-0717-05 (P1):** conformance corpus gains normative subject-pin negative-state vectors
  `relation/target-subject-missing` + `relation/target-subject-ambiguous` (independent SPEC oracle).
- **PB-2026-0717-02 (P1):** `MANIFEST.in` ships the tests' runtime assets in the sdist (fixtures,
  schemas, examples, conformance, formal, scripts) → a fresh-from-sdist pytest collects with 0 errors
  (was 13); the Rust tree is excluded (not a Python-sdist artifact).
- **PB-2026-0717-03 (P2):** byte-reproducible sdist regression test over the existing F2 normaliser
  (`scripts/build_reproducible.py --check` proves two clean builds are byte-identical). The published
  3.6.0 predates F2 and is honestly NOT byte-reproducible.

## [3.6.0] - 2026-07-17 (audit-candidate, BETA, relation EXPERIMENTAL)

Status boundary (No-Overclaim): 3.6.0 is **NOT** stable, audited, or production-ready. The only
progress claim is **audit-candidate: all internal assurance gates are green; the sole remaining gate to
stable is an independent external security audit**. 4.0.0-stable = 3.6.0 + that external audit closed +
findings accepted + relation wire-freeze. This section was produced under the six-lens / adversarial
master-prompt-v2 pre-tag audit discipline (Front-Load §7); that INTERNAL audit is explicitly not a
substitute for the external one.

### Added (audit-candidate assurance, EXT §10 minus the external audit)
- **33-check audit-candidate matrix (`scripts/audit_candidate_matrix.py`):** one machine-checkable
  check per §9 acceptance obligation, orchestrating the foundation gates (formal model, type-confusion,
  rust-parity, readiness pack, claims-hygiene, test-manifest, fuzz-soak). Honest verdict vocabulary
  (PASS / PENDING_JUSTIFIED / DATA_BLOCKED / EXTERNAL_PENDING / FAIL) — a DATA_BLOCKED (needs
  cargo/24h-soak/build-backend) is never a fake PASS, and the single external audit is EXTERNAL_PENDING.
- **Trust-Pack payloadType-binding defense-in-depth (O7):** `verify_trust_pack` now pins the DSSE
  envelope `payloadType` field fail-closed against the in-toto statement type (the PAE already bound the
  signed bytes to the type; this closes the unexamined field for a downstream consumer). Negative
  vectors in `tests/test_trust_pack_payloadtype_negatives.py`. Formal obligation O7 stays **RESERVED**
  in `formal/model.py` — code-enforced and vector-tested, not a fabricated proof.
- **WP-B locked test manifest (`scripts/test_manifest_gate.py` + `tests/test_manifest_lock.json`):**
  pytest is the normative runner; a drop below the collected-test floor or any collection error is a CI
  FAIL (no silent test schwund), and the pytest-only (unittest-invisible) module class is floor-locked.
- **WP-D fuzz-soak (`scripts/fuzz_soak.py`):** a bounded, wall-clock soak over every AST-discovered
  verifier class asserting never-raise + never-false-accept (0 crash / 0 false-accept on the recorded
  run, hundreds of thousands of iterations); the four EXT robustness classes fixed as regression
  vectors; the continuous coverage-guided leg is `.clusterfuzzlite/` + `fuzz/fuzz_verifiers.py`
  (Atheris). The full 24h soak is an operational artifact (DATA_BLOCKED until an artifact records it).
- **WP-C differential evidence:** `crosscheck.py --matrix` writes the reproducible Python<->Rust matrix
  (40 relation vectors + the 54-case corpus reproduced independently); `docs/readiness_pack/`
  `rust_parity_scope.md` declares the deliberately-PENDING Rust surface (No-Fake, no fake 100%).
- **WP-G external-audit readiness pack (3.6.0 slot filled):** reproduction runbook, auditor open-points
  list, threat-model delta, differential-matrix doc, SHA-256 pack manifest + advisory proofbundle
  self-receipt (`scripts/readiness_pack_manifest.py`).
- **Claims-hygiene extended (§9 criterion 11):** the forbidden list now catches the
  `production-ready` / `externally audited` / `has-been-audited` claim class outside a negation; the
  release-stability claim is guarded mechanically by the pyproject Development-Status classifier
  (stays 4 - Beta).

### Added (OTS hardening + calendar-risk — anchor-longevity moat, EXPERIMENTAL, the `[anchors]` extra)
- **`proofbundle anchor` CLI group (WP-A/B/C):** the honest OpenTimestamps lifecycle as an offline
  toolset. `anchor upgrade` bundles an UPGRADED proof into a self-contained, calendar-independent
  evidence pack (a still-PENDING proof is refused with exit 3 and writes nothing, never a fake pass);
  `anchor verify-pack` verifies a pack OFFLINE (no socket) against a relying-party Bitcoin header
  (exit 0 confirmed / 3 pending-or-needs-header / 1 hard fail / 2 malformed); `anchor inspect` prints
  the lifecycle state and the calendars/operators carrying a proof (transparency, no crypto trust).
  New CLI commands in `src/proofbundle/cli.py`; the pack mechanism (`src/proofbundle/evidence_pack.py`)
  gains `describe_proof`. WP-A1 boundary kept: the pack's own bundled/frozen header is never trusted, so
  a colluding or backdating producer cannot self-certify.
- **Calendar transparency (WP-B):** `anchors_ots.calendar_uris` / `calendar_operator` /
  `calendar_operators` surface WHICH calendars carry a proof and how many INDEPENDENT operators back it
  (`operatorRedundancy`), because two URLs on one operator are one point of failure, not two. The
  `operatorRedundancy` figure is read from the proof bytes (`provenCalendars`) but is an
  embedded-but-UNVERIFIED transparency hint, NOT cryptographic redundancy evidence; producer-declared
  calendars are kept separate (`declaredCalendars`, `declaredCalendarsVerified: false`) and are likewise
  never redundancy evidence (see Fixed below). Docs (`docs/ANCHORS.md`) add how to run or pin your own calendar and how to
  obtain a trusted Bitcoin header for verification.
- **ripemd160-free confirmed-path fixture (WP-D1):** `tests/fixtures/ots/synthetic-upgraded-sha256.*`
  (generator `scripts/gen_synthetic_ots_fixture.py`), a SHA-256-only upgraded proof that deserializes
  and confirms WITHOUT ripemd160, so the confirmed/self-contained OTS path has an UNCONDITIONAL
  regression in the cleanroom pytest where the ripemd160-gated external vector (`hello-world.txt.ots`)
  is honestly skipped. Pinned in `PROVENANCE.json`, labelled synthetic (No-Fake, not an external vector).
- **RFC 3161 framed as a first-class legal second anchor (WP-D3):** `docs/ANCHORS.md` documents the
  eIDAS/QTSP hedge (Regulation 910/2014 Article 41, ETSI EN 319 422 / RFC 5816) as the complementary,
  immediate, legally recognized anchor alongside the trust-minimized OpenTimestamps one. The anchor
  registry stays open and fail-closed (an unknown type is a FAIL).
- **Readiness-pack calendar-independence paragraph (WP-E):**
  `docs/readiness_pack/calendar_independence.md`, wired into `index.json` conclusion C1, states the four
  facts (calendar-independent verification, calendar fragility affects only stamping, verification needs
  a Bitcoin header source, RFC 3161 legal second anchor) before an external audit asks.

### Fixed (OTS hardening — adversarial deep live-reproduced audit, 2026-07-16)
- **`verify-pack` refuses a self-fabricated Null-Op pack and a Litecoin-height confusion (CRITICAL,
  No-Fake, `anchors_ots.verify_opentimestamps` + `cli.py` + `evidence_pack`, 2026-07-17):** the 6-lens
  re-review reproduced a CRITICAL live on the standalone `anchor verify-pack` / `verify_evidence_pack`
  surface (the canonical `verify --require-anchor` path, which cross-checks `canonicalRoot` against an
  independently recomputed root at `anchors.py`, is a DIFFERENT surface and is UNCHANGED). A pack whose
  `file_digest == canonicalRoot` with a `BitcoinBlockHeaderAttestation` planted directly on the root
  (leaf == root, no op chain) returned `ok: true` / `status: confirmed` / exit 0, because the attested
  value equalled the producer-supplied header with no hashing at all. `verify_opentimestamps` now requires
  at least one cryptographic hash op (`CryptOp` / `OpSHA256`) on the path from the file digest to each
  attestation (`_bitcoin_confirmations`); a hash-free branch is refused with `status: null_op`
  (fail-closed) even when its value matches the header, while a genuine branch still confirms alongside it
  (the 2026-07-16 multi-branch scan is preserved). The confirm loop no longer uses `getattr(att, "height")`:
  it filters to `isinstance BitcoinBlockHeaderAttestation`, so a `LitecoinBlockHeaderAttestation` with a
  colliding integer height no longer confirms against a Bitcoin header. `anchor inspect --json` no longer
  echoes a hand-edited `declaredCalendarsVerified: true` (forced `false`, declared is unverified by
  definition) nor the raw pack `selfContained` (only the authoritative recomputed value is reported).
  `docs/ANCHORS.md` gains the honest reservation (a bare `verify-pack` is a lifecycle/header check;
  `canonicalRoot` is self-declared; a trust decision must bind the anchor independently via
  `verify --require-anchor`). The provenance-pinned synthetic confirmed-path fixture was itself a
  leaf == root Null-Op and was regenerated to a real op chain (append a nonce, then double SHA-256);
  `PROVENANCE.json` and `block.json` pins were refreshed. `claims_hygiene_check.scan_cli_surface` now also
  scans argparse `epilog=`. Live: the exact attack pack now returns `ok: false` / `status: null_op` /
  exit 1. Regression: `test_ots_calendar_hardening.py` (Null-Op refused, Litecoin-height not a Bitcoin
  confirmation, `inspect` forces `declaredCalendarsVerified` false, `packSelfContained` dropped,
  `epilog=` scanned) plus a canonical-path-unaffected assertion.
- **Attestation-scan no longer short-circuits (MAJOR, `anchors_ots.verify_opentimestamps`):** the
  confirm loop returned on the FIRST relying-party-covered Bitcoin height, so a single wrong or tampered
  branch masked a genuinely confirmable one (a False-REJECT / DoS: height 111 wrong + height 222 correct
  reported `block_mismatch`). It now scans ALL covered branches and confirms as soon as ANY matches,
  falling through to `block_mismatch` / `bad_header` / `upgraded_unverified` only when NONE match;
  per-branch diagnostics (`mismatchHeights` / `badHeaderHeights`) are retained so real tamper stays
  visible. Sound because the structural binding pins every branch to the same canonical root. Regression:
  `tests/test_anchors_ots.py::TestMultiBranchAttestationScan` (both iteration orderings).
- **Operator redundancy is proof-derived, never producer testimony (MAJOR, `evidence_pack` + CLI):**
  `operatorRedundancy` and `calendarOperators` were fed from the producer-claimed `--calendar` list, which
  for an upgraded pack (`calendar_uris(proof) == []`) was ALWAYS unverifiable, so a fabricated calendar
  list could inflate the "surfaced honestly" redundancy. The pack now splits `provenCalendars`
  (read from the proof bytes) from `declaredCalendars` (producer testimony via a CLI flag,
  `declaredCalendarsVerified: false`, never counted). The CLI flag `--calendar` is renamed
  `--calendar-declared` and its output labels it unverified. Docs (`docs/ANCHORS.md`,
  `docs/readiness_pack/calendar_independence.md`) no longer present declared redundancy as audit evidence.
  Regression: `test_evidence_pack.py::test_declared_calendars_never_count_as_proven_redundancy`.
- **Calendar redundancy is embedded-but-unverified, NOT cryptographic evidence (MAJOR, No-Fake follow-up,
  2026-07-17):** the 2026-07-16 split still over-claimed the proof-embedded set as "proven" / "the only
  redundancy figure a reviewer may treat as evidence". That is false: a `PendingAttestation` URI is
  unauthenticated and offline-constructible (the test helper `_upgraded_proof_retaining_pending` fabricates
  them), so `provenCalendars` / `operatorRedundancy` are an embedded-but-UNVERIFIED transparency hint, not
  audit evidence. The ONLY cryptographic guarantees are (a) the structural binding of the proof to the
  canonical root and (b) the Bitcoin confirmation against a relying-party header. Docstrings, code comments,
  `docs/ANCHORS.md`, `docs/readiness_pack/calendar_independence.md` and ADR 0006 are re-worded accordingly;
  no field is presented as cryptographic redundancy evidence.
- **`anchor verify-pack` recomputes calendar/self-contained fields from the proof bytes (MAJOR, `cli.py`):**
  `verify-pack` passed the pack's own `operatorRedundancy` / `provenCalendars` / `provenCalendarOperators` /
  `selfContained` JSON fields straight into its authoritative `--json` report, so a hand-edited pack could
  report `operatorRedundancy: 3` with fabricated operators under `status: confirmed` / exit 0 while
  `anchor inspect` on the SAME file computed `0`. It now RECOMPUTES all four from the proof bytes via
  `describe_proof`, exactly as `inspect` does; the report never echoes untrusted pack fields. Regression:
  `test_ots_calendar_hardening.py::test_verify_pack_recomputes_calendar_fields_from_proof_not_json`.
- **Operator-label heuristic blind spot documented (MINOR):** `calendar_operator` is a bare-hostname
  heuristic, not a verified-independent-entity claim; the last-two-labels fallback does not resolve the
  public-suffix boundary, so a `co.uk` / `com.au` host can undercount two independent operators as one.
  Documented next to `operatorRedundancy` in the code and both docs (optional `tldextract` noted, not
  added — it stays a heuristic).

### Changed (OTS hardening)
- **`opentimestamps` pin upper-bounded (WP-D2):** the `[anchors]` extra now requires
  `opentimestamps>=0.4.5,<0.5` (the consensus-critical `python-opentimestamps` LIBRARY on the 0.4.x
  line), so a future 0.5 wire/API change is a deliberate opt-in, not a silent break. Documented that the
  `opentimestamps-client` CLI tool (0.7.x) is a SEPARATE package and not a proofbundle dependency.

### Added (relation-statement/v0.1 3.5.0 — standalone profile + Rust parity, still EXPERIMENTAL)
- **`relation-statement/v0.1` standalone profile (WP-A):** a DSSE-signed statement OVER a
  target receipt, carrying EXACTLY ONE typed edge and no decision/outcome payload of its own —
  the retroactive case the in-receipt edges cannot express (declaring a foreign or older receipt
  retracted / superseded / amended without emitting a successor and without touching the
  original). predicateType `.../relation-statement/v0.1`; new module
  `src/proofbundle/relation_statement.py` and CLI `proofbundle relation-statement
  init|emit|verify|inspect` (exit contract 0/1/2/3 identical to the decision/outcome paths). The
  edge validation, lineage resolution and the `relations` trust-policy gate REUSE the in-receipt
  functions (`relation.validate_relationships` / `verify_relationship_edges` /
  `evaluate_relations_policy`) — no second implementation. Status-as-a-separate-object precedent: W3C
  Bitstring Status List v1.0, CT/OCSP revocation, SCITT protected-object-binding.
- **`relations.reject_retracted` trust-policy pin (WP-A):** a relying party who knows BOTH the
  target and a verified retracts statement of a pinned/authorized signer can treat continued
  automated use of the target as an exit-3 block (`LINEAGE_REQUIREMENT_FAILED`);
  `reject_superseded` extends to the successor relations. Without the policy the verified statement
  is pure visibility. Honesty boundary (verbatim): a relation statement proves the issuer DECLARED
  the relation over exact bytes; it does not retract the target's cryptographic validity, and
  whether the issuer may declare it is a relying-party policy decision. `lineage` never feeds
  `cryptoValid` (lattice monotonicity).
- **Rust parity of the relation profile (WP-B):** the independent Rust verifier
  (`tools/pb_verify_rs`) now carries the profile — new subcommands `verify-relation` (in-receipt
  decision/outcome edges) and `verify-relation-statement` (standalone), with its OWN parser
  (serde_json + serde_jcs, sharing NO canonicalizer/parser with Python). `crosscheck.py` drives
  ALL 40 relation vectors — decision, outcome and standalone, positive AND negative (incl. the
  3.4.0 decoy-parent / subject-mismatch / signer / t1 vectors and the wrong-payloadType vector) —
  through BOTH implementations and
  asserts they land on the same common-vocabulary label (exit class + lineage) on every vector.
  Differential AGREEMENT on these vectors, not a correctness proof of either implementation. The
  parity registry (`scripts/rust_parity_registry.json`) is raised from PENDING to COVERED for
  `relation.verify_relationship_edges` and the new
  `relation_statement.verify_relation_statement`, AST-verified by `scripts/rust_parity_gate.py`.
  The Vector × {Python, Rust} matrix is exported with an environment freeze
  (`audit_artifacts/rust_relation_differential_matrix.json`).
- **Conformance + tests:** six new standalone vectors under `conformance/relation/` (retracts
  verified+blocked, retracts visible, retracts unauthorized, retracts declared-unresolved,
  supersedes verified, malformed), a new `relation_statement` runner kind, property + never-raise +
  exit-contract tests (`tests/test_relation_statement.py`) and the Rust differential gate
  (`tests/test_relation_statement_rust_parity.py`). Existing 3.3.0/3.4.0 vectors and behaviour are
  unchanged (pure additivity, no wire break); the profile stays EXPERIMENTAL through 4.0.

### Fixed (relation-statement/v0.1 3.5.0 — pre-release audit)
- **Rust payloadType fail-open (BLOCKER, security):** the independent Rust verifier's `verify_dsse`
  derived the PAE from the envelope's OWN `payloadType` without pinning an expected type, so the
  relation paths (`run_verify_relation` crypto check and `load_related`) would AUTHENTICATE a
  same-key envelope presented under the WRONG payloadType — where Python pins
  `application/vnd.in-toto+json` and rejects it. `verify_dsse` now takes an `expected_payload_type`
  and the relation paths pin the in-toto type, mirroring Python fail-closed; the generic
  `verify-dsse` subcommand stays deliberately type-agnostic. A new same-key wrong-payloadType
  differential vector proves BOTH implementations now reject it (exit 2, lineage FAIL).
- **`policy lint` missed `reject_retracted` (MAJOR):** `explain_policy` had no `reject_retracted`
  branch, so `lint_policy` wrongly called a `reject_retracted`-only policy a vacuous pass while the
  verify path enforces it at exit 3. `explain_policy` now lists it (explain⟺enforce parity).
- **Docs:** the roadmap `O6_RETRACTS_NEVER_RAISES` note corrected to reserved (code-enforced +
  tested + mutation-killed, not yet a formal proof); the dead `RELATION_STATEMENT_SCHEMA_VERSION`
  constant removed; the `reject_superseded` double meaning cross-referenced in
  `evaluate_relations_policy`.

### Added (relation/v0.1 3.4.0 — three lineage pins, still EXPERIMENTAL)
- **`relation_signer` trust-policy pin (WP-A, WHO may replace):** a new fail-closed
  `relations.relation_signer` map — per relation `{"mode":"same-key"}` or
  `{"mode":"pinned","keys":[<b64>,…]}`. The SUCCESSOR's issuer key must satisfy the rule
  (byte membership of the raw Ed25519 key, never a keyId alias). Unmet →
  `RELATION_SIGNER_UNAUTHORIZED`, exit 3. CLI `decision/outcome verify --with-related PATH
  --related-pub B64` (position-paired) enables cross-issuer chains; the check runs against
  the key the target ACTUALLY verified under (`verified_under`), never a claim. In-toto
  layout/functionaries precedent (authorized keys per step); flat set, no thresholds (YAGNI).
- **`require_relation_target` + `targetSubjectDigest` enforcement (WP-A2, WHICH parent —
  KERNFUND F1/O1/O2, from Loek Verdonk / No Silent Landing's byte-verified adversarial
  review):** `relations.require_relation_target` pins the expected parent content root(s)
  per relation; a supersedes-like edge that resolves to any OTHER (even valid) parent →
  `RELATION_TARGET_MISMATCH`, exit 3, on EVERY such edge, the accept path (T2) included —
  closing the decoy-parent gap where `require_relation_resolution` alone only proved SOME
  edge resolves. The previously dormant `targetSubjectDigest` edge field is now binding when
  PRESENT (gegengeprueft against the resolved target's subject; mismatch →
  `RELATION_TARGET_SUBJECT_MISMATCH`, lineage FAIL, exit 2).
- **Outcome-path relations gate (WP-B):** `verify_outcome_receipt(..., policy=…)` /
  `outcome verify --policy` enforce the `relations` section identically to the decision path
  (require_relation_resolution / reject_superseded / relation_signer / require_relation_target),
  same exit-code contract and blocker names. trust_pack role auth is separate and unchanged.
- **Automation-surface consistency (WP-A3 / F5):** `referencesResolved` is no longer `true`
  while a REQUESTED lineage relation is unresolved/failed; `policy explain` lists the two new
  pins (explain⟺enforce parity).
- **Conformance corpus:** the shared `relations`-policy evaluator (`relation.evaluate_relations_policy`,
  cut as its own function for the future relation-statement verifier) and new vectors for
  relation_signer, the decoy-parent fix (target-mismatch + must-pass gegenprobe + accept-path
  + documented no-pin old behavior, `crossFormatId xfmt-t3-decoy`), the `targetSubjectDigest`
  O2 gegenpruefung, a JCS-canonical invalid-signature vector (F2), and an `outcome_relation`
  harness mirror. Lattice monotonicity preserved throughout: relation_signer / target-mismatch
  change ONLY the policy verdict, never `cryptoValid`. relation/v0.1 stays EXPERIMENTAL.
- Honest follow-ups (3.5.0): Rust differential parity for the new surface (NOT_RUN until the
  Rust core carries the profile); threshold signer sets and DID/VC identity indirection remain
  DELIBERATELY out of scope.

## [3.3.0] - 2026-07-16

### Added (relation/v0.1 lineage profile — EXPERIMENTAL)
- **`relation/v0.1` lineage/relationship profile** (EXPERIMENTAL): an optional, SIGNED
  `relationships: [edge, …]` field on the decision-receipt and action-outcome predicates —
  typed edges (`supersedes`/`revises`/`corrects`/`retracts`/`renews`/`derivedFrom`/`amends`,
  closed vocabulary) onto a predecessor's `jcs-sha256-v1` content root, with an EXPLICIT,
  never-defaulted `digestAlgorithm`. Change is expressed by a declared, signed back-edge —
  never by mutation; the old receipt stays valid for its bytes forever. Docs:
  `docs/predicates/relation.md`; interop mapping to W3C PROV and the SCITT relationship
  draft checked against the draft-nobuo-00 FULL TEXT (no `amends` exists there — stated
  honestly, not bent). New module `src/proofbundle/relation.py` (fail-closed, never-raise
  validators; pure offline chain walk with per-path cycle detection and depth cap 32).
- **Lineage verdict in `verify_decision_receipt` / `verify_outcome_receipt`** (additive
  `related=` kwarg + `lineage` result field with the four honest states VERIFIED /
  DECLARED_UNRESOLVED / FAIL / NOT_EVALUATED): computed only over authenticated bytes;
  lattice monotonicity proven by test — lineage never flips the crypto verdict in either
  direction, and DECLARED_UNRESOLVED never reads as a pass.
- **CLI `decision verify --with-related PATH`** (repeatable, offline, same-key contract):
  attached targets are verified standalone and keyed by their computed content root; an
  attached-but-unverified target FAILS lineage (present-and-wrong beats absent); a REQUESTED
  lineage check that FAILs exits 2, never a silent 0. `lineage` emitted in the `--json`
  report projections.
- **Trust-policy v0.2 `relations` section** (`require_relation_resolution`,
  `reject_superseded`) enforced on the decision verify path with the LIVE automation blocker
  `LINEAGE_REQUIREMENT_FAILED`; `policy explain` lists both pins (explain⟺enforce parity);
  retracts-then-use blocked under `reject_superseded`.
- **Conformance corpus `conformance/relation/`**: 15 vectors end-to-end through the real CLI
  (new harness kind `decision_relation`), the five skeleton vectors carrying `crossFormatId`
  `xfmt-c0`/`t1`–`t4` per the No Silent Landing shared-vector convention, plus the internal
  superset incl. the F6 malformed-digest never-raise vector (DSSE-crafted — the honest
  emitter refuses to emit it) and depth-exceeded (real hash cycles are impossible under
  content-root addressing; documented).
- 3 new relation-specific mutation operators (`scripts/mutation_check.py`: cycle-detection
  disabled, malformed-digest guard disabled, verified-flag laxened — each kill hand-verified),
  and a No-Fake aggregate fix (6-lens audit): a requested lineage FAIL is now visible in the
  library `ok` / `automation.safeForAutomation` verdict via a derived `lineage_ok`, not only
  at the CLI exit code (crypto verdict untouched — lattice monotonicity preserved).
- New verify surface honestly registered PENDING in the Rust parity registry (differential
  = NOT_RUN until the core carries the profile). Documented follow-ups: `relation_signer`
  (pinned-set), outcome-path policy gate, `relation-statement/v0.1` standalone profile,
  and the still-unwritten SPEC.md profile chapter + GLOSSARY entry (the canonical prose lives
  in `docs/predicates/relation.md` for now).

## [3.2.3] - 2026-07-15

Second remediation wave of the six-lens post-3.2.2 audit (Findings 01, 03, 11, 12, 15b, 16, 14a, 17, 18, 19, 20). Additive/non-breaking: no
existing `result["ok"]` field changes for any correct caller; every new field/param is opt-in with a
backward-compatible default — with ONE deliberate exception (honest, not opt-in): the Finding 15b
`VerificationBudget` DoS ceilings are enforced unconditionally, so an input that was previously accepted
but is over a generous limit (a DSSE envelope with >512 signature entries, a Trust Pack `keys`/role
`keyIds` map with >256 entries, a renewal sequence with >10,000 ArchiveTimeStamp entries, or a >8 MiB
DSSE payload) now fails closed. The ceilings sit far above any legitimate receipt/pack/sequence; they are
a DoS backstop, not a behavioural knob.

### Security (combined-integration review hardening)

A four-lens combined-integration review of this wave, plus an orthogonal-refuter iteration that refused to
rubber-stamp the first round of fixes, surfaced real fail-open/DoS gaps that each passed the per-finding
tests but not adversarial cross-checking; all are fixed and covered by bidirectional, mutation-verified
tests:

- **DSSE / parse DoS (Finding 15b, extends the cap)**: `dsse.verify_envelope` — the single chokepoint
  `decision`/`outcome`/`verification_summary`/`run_ledger` verify funnel through — now caps the
  attacker-controlled `signatures` list BEFORE its verify loop; and `loads_strict` (the ONE parse
  chokepoint every verify path funnels through) now refuses raw input over `budget.input_bytes` BEFORE
  `json.loads` (an unbounded parse of a 50 MB envelope was a real pre-loop DoS the signature cap could not
  reach) and enforces the previously-dead `budget.json_nodes` as a parsed-structure node-count cap.
  `budget.signatures` was raised 64 → 512 so a legitimate two-stage rotation envelope (new-root threshold +
  old-root vouch reuse one `signatures` list) still verifies. `trust_pack.verify_trust_pack` now also fails
  closed with a clean `BundleFormatError` on a non-list `signatures` (JSON `true` / a huge dict), which
  previously skipped its cap or raised an uncaught `TypeError`. A second refuter round further capped the
  raw base64 `payload` in `dsse._payload_bytes` BEFORE it is decoded (the decode, run twice per verify, was
  a layer earlier than `loads_strict`), and added the same pre-decode cap to `anchors_markovian` (mirroring
  `anchors_chia`).
- **`require_external_token` fail-closed on absent token (Finding 14a)**: `renewal.verify_sequence(...,
  require_external_token=True)` now appends a FAILING `renewal:external_token` check when the newest ATS
  carries no `external_token_type`. The external-token fields are deliberately outside the signed ATS
  bytes, so an attacker/MITM could strip them; previously the whole block was skipped and `.ok` was
  unaffected — a silent no-op "require".
- **Receiver independence is enforced, not just labeled (Finding 16)**: `assurance.
  classify_receiver_corroboration` now takes `executor_key_id`/`receiver_key_id` and reaches
  `INDEPENDENTLY_ATTESTED` ONLY when BOTH key ids are present AND differ. `executor.keyId` is schema-optional
  and executor-controlled, so a one-sided check would be evaded by simply omitting one's own keyId; an
  absent executor key id now blocks promotion too, and both key ids must be STRINGS (a second refuter round
  found that a non-str `receiverKeyId` wrapping the executor's own id, e.g. `["kid-exec"]`, is `!=` the str
  `"kid-exec"` and would read as "distinct"). Wired through `outcome.verify_outcome_receipt`. Honest
  inherent limit: two distinct keys can still belong to the same principal — principal-level independence
  needs the `outcomeReceivers` Trust Pack role (an out-of-band trust binding), documented in the code.

Plus: `decision`/`outcome` `verify --json` now emit `automation`/`evidence_levels`/receiver fields (a
`jq` filter no longer gets `null`, indistinguishable from a real "not evaluated"), and `assurance`/
`budget`/`automation_verdict` are now top-level `from proofbundle import …` exports.

### Added
- **Finding 01 — uniform automation-safety verdict**: new `automation_verdict.automation_summary` mirrors
  `bundle.py::root_authenticity_summary`'s `safeForAutomation`/`automationBlockers` pattern for the other
  five receipt-chain predicates. Each of `decision.verify_decision_receipt`,
  `outcome.verify_outcome_receipt`, `trust_pack.verify_trust_pack`,
  `verification_summary.verify_verification_summary` and `run_ledger.verify_run_ledger` now stashes a
  `result["automation"]` dict; `safeForAutomation` requires the policy/authorization dimension to be
  `True` EXACTLY (never merely `is not False`, unlike the permissive `ok` aggregate). `outcome.py` also
  gains an optional `trust_pack` parameter (`outcome.executor_trusted_by_role`) that checks the executor's
  `keyId` against the Trust Pack's `outcomeExecutors` role — closing the gap
  docs/predicates/action-outcome.md §7 listed as open/future work.
- **Finding 03 — EvidenceLevel ladder**: new `assurance.py` (`EvidenceLevel`,
  `classify_digest_evidence`, `evidence_ladder_summary`/`evidence_ladder_best`) makes the STRENGTH of a
  digest-presence "proven"/"bound" claim explicit and orderable
  (`CLAIMED < REFERENCE_WELL_FORMED < CONTENT_RESOLVED < RECEIPT_CRYPTO_VERIFIED < POLICY_AUTHORIZED <
  INDEPENDENTLY_ATTESTED < EFFECT_OBSERVED`). `decision.verify_decision_receipt` and
  `outcome.verify_outcome_receipt` gain an additive `result["evidence_levels"]` plus an optional
  `evidence_resolver` callable that, when supplied, wires the previously-unused
  `decision.resolve_evidence_ref` primitive into the actual verify path (a digest can now reach
  `CONTENT_RESOLVED`, not only `REFERENCE_WELL_FORMED`). The pre-existing boolean
  `action_outcome_proven`/`outcome_execution_proven`/`evidence_bound` fields are UNCHANGED.
  `EvidenceLevel.EFFECT_OBSERVED` is a real, orderable enum member that stays structurally unreachable (a
  real-world effect-observation channel is a separate, inherent limit outside this repo — see the Finding 16
  entry below for what its self-fixable part DOES now reach: `INDEPENDENTLY_ATTESTED`) — an explicit
  `EFFECT_OBSERVED_NOT_IMPLEMENTED` marker documents this rather than silently omitting it.
- **Finding 15b — VerificationBudget**: new `budget.py` (`VerificationBudget`, `DEFAULT_BUDGET`,
  `BudgetExceeded`) centralizes the DoS-guard pattern already used ad hoc by `sdjwt._MAX_DISCLOSURES`,
  `statuslist._MAX_STATUS_LIST_BYTES`, `hf_evals._MAX_TOKEN_BYTES` and `anchors_chia._MAX_LAYERS`/
  `_MAX_PROOF_BYTES` (which are unchanged and stay the authoritative caps for their own surfaces). Wired
  concretely into the two identified unguarded paths — `trust_pack.validate_trust_pack_predicate`'s
  `keys` map / per-role `keyIds` counts, and `renewal.verify_sequence`'s total ArchiveTimeStamp count
  across a whole sequence — plus a generous `input_bytes` cap on the raw DSSE payload bytes (checked
  BEFORE JSON parsing) on every one of the five receipt-chain `verify_*` entry points named above.
  `BudgetExceeded` is a `ProofBundleError` subclass, so every existing `except (ProofBundleError, ...)`
  call site already handles it identically to any other malformed/over-limit input.

- **Finding 16 — outcome receiver/observer corroboration (self-fixable part, additive)**: an optional
  `receiverRefs[]` on `action-outcome/v0.1` (digest-bound exactly like `evidenceRefs[]`) plus
  `assurance.classify_receiver_corroboration` let a genuinely independent, cryptographically verified
  receiver/observer statement reach `EvidenceLevel.INDEPENDENTLY_ATTESTED` (given a new
  `receiver_attestation_resolver` parameter on `outcome.verify_outcome_receipt`); an additive
  `outcomeReceivers` Trust Pack role (`outcome.receiver_trusted_by_role`, mirrors `outcomeExecutors`) lets a
  verifier check that party against a known list, deliberately advisory (never wired into the aggregate
  `ok`, since `receiverRefs` is optional supplementary evidence). Also additive: `sequence.{runId,seq}` +
  `outcome.detect_outcome_sequence_gaps` for spotting a suppressed outcome later in the same run, when the
  executor opts in. Fully backward compatible — a receipt with no `receiverRefs`/`sequence` is unaffected.
  **Honest, INHERENT limit this increment does NOT close:** proofbundle cannot itself make a downstream
  system SIGN a receiver acknowledgement (ecosystem adoption, outside this repo); `EvidenceLevel.
  EFFECT_OBSERVED` stays structurally unreachable even with a verified receiver corroboration (still a
  receipt about the effect, never a live observation of it) — see `assurance.EFFECT_OBSERVED_NOT_IMPLEMENTED`.
- **Finding 14a — RFC-3161/OTS↔ArchiveTimeStamp integration glue + truncation detection (additive, ADR
  0006 B3 OPEN items)**: an `ArchiveTimeStamp` may now carry a DETACHED `external_token_type` /
  `external_token` / `external_token_frozen`, verified by the new `renewal._verify_ats_external_token` via
  the ALREADY-HARDENED standalone `anchors_rfc3161.verify_rfc3161` / `anchors_ots.verify_opentimestamps` —
  pure glue between two already-hardened modules, no new cryptography. `renewal.verify_sequence` gains
  `rp_trust` (relying-party TSA-root/Bitcoin-header trust material, WP-A1 discipline) and
  `require_external_token` (demand the full verified state, not merely OTS-pending). Separately,
  `verify_sequence(..., known_newest_token_digest=…)` closes the "a stale prefix of a legitimately-renewed
  sequence still verifies" gap: when the relying party supplies the digest of the newest ATS it last
  observed (its own persisted state — no `RelyingPartyStateStore` exists in this repo, so this is the
  additive-parameter fallback), a truncated/rolled-back sequence fails the new `renewal:no_rollback` check.
  None of the three additions are surfaced unless the caller opts in — fully backward compatible with every
  existing `ArchiveTimeStamp`/sequence. **Still OPEN (honest, unchanged):** the full ASN.1/XMLERS export and
  a signature-algorithm staleness trigger in `RenewalPolicy` — see `docs/adr/0006-anchor-longevity.md`.

- **Finding 11 — Rust-parity honesty gate**: `scripts/rust_parity_gate.py` AST-scans every
  `src/proofbundle/*.py` for a module-level `verify_*` function (ground truth, rediscovered each run)
  and cross-checks it against the declarative `scripts/rust_parity_registry.json`. Every COVERED/PARTIAL
  claim is verified against REAL evidence — the claimed `rust_subcommand` must be an actual match arm in
  `main.rs`, appear in the built binary's self-declared `coverage-report`, and the claimed crosscheck
  call site must literally exist; a stale claim is caught (`STALE_COVERED_CLAIM`), a new untracked
  `verify_*` is `UNTRACKED`, a dangling `python_ref` is `ORPHANED`. Advisory by default, `--strict`
  exits 1 on a registry-integrity problem, never on an honestly-declared PENDING. First real portation:
  `main.rs`'s `verify-trust-pack-threshold` (root-of-trust threshold check, Ed25519 leg only, reported
  PARTIAL not COVERED; mldsa65/hybrid skipped-and-reported, never silently accepted). New advisory CI
  `rust-parity` job (`continue-on-error`, non-blocking).
- **Finding 12 — external-audit readiness package (NOT_SELF_FIXABLE, readiness only)**: no audit is
  performed or simulated. `docs/AUDIT_SCOPE.md` (STABLE vs. EXPERIMENTAL module table cross-checked
  against docstrings/SPEC/CODEOWNERS/CHANGELOG, coupled to a format-freeze mechanism), `docs/
  AUDIT_READINESS.md` (OSTIF-facing briefing of existing hardening evidence, honest current-state, no
  audit-completion claim), `docs/adr/0007-crypto-agility-alg-dispatch.md` (the alg-dispatch pattern
  trust_pack.py and renewal.py share), a `Revision:` header on `THREAT_MODEL.md`, a dedicated
  "Security Audit" `funding.json` purpose. Surfaces a CODEOWNERS gap (checkpoint.py/renewal.py/
  anchors_chia_add.py missing from the review-required path list) without silently fixing it.
- **Finding 18 — Evaluation Cards (P2, additive)**: optional `evaluation_card_sha256` claim field +
  `src/proofbundle/evalcard.py` (`evaluation_card_hash`/`verify_evaluation_card`), mechanically
  identical to `prereg_sha256`; references the Hugging Face EvalEval Coalition's Evaluation Cards
  (arXiv:2606.09809) rather than inventing a proofbundle-specific format. CLI `proofbundle evalcard
  <card> [--check RECEIPT]` mirrors `prereg`.
- **Finding 19 — computation-correctness / enclave assurance wiring**: the enclave RATS/EAT bridge was
  already implemented but README's roadmap misclassified it as not-yet-built (a No-Fake UNDERclaim) —
  README framing corrected. Real gap closed: `assurance_level=enclave_attested` was an unverified
  string; new `evalclaim.enclave_assurance_proven(claim, bundle, eat_jws=…, verifier_pubkey=…)`
  (analogous to `decision.action_outcome_proven`) optionally corroborates the declared level against a
  real, receipt-bound Attestation Result (True/False/None), wired into `show-eval --eat/--verifier-key/
  --profile`. Lazy function-local import keeps the ExperimentalWarning from firing on plain
  `evalclaim` import; never force-promotes the signed `assurance_level`.
- **Finding 17 — benchmark-hacking VISIBILITY (OPEN_BY_DESIGN)**: visibility only, no anti-hacking
  guarantee built or implied (BenchJack, arXiv:2605.12673, cited in THREAT_MODEL.md). Optional
  provenance sub-keys `run_attempts`/`aborted_runs` (non-negative ints) and `methodology_sha256`/
  `benchjack_audit_report_sha256` (plain sha256 references), wired via `adapters/_provenance.py`; zero
  schema change (provenance is free-form) and zero `intoto.py` change (`to_test_result_statement`
  already copies the whole provenance dict verbatim — proven by a new regression test).

### Deferred (tracked, not built this increment — the one deliberately BREAKING piece)
- `bundle.py`'s CLI `verify` exit-code default is NOT changed by this increment. `root_authenticity_summary`
  already computes `safeForAutomation`/`automationBlockers` correctly (unaffected); a FUTURE v4 could add an
  opt-in `--strict-automation` CLI flag that gates the process exit code on `safeForAutomation` instead of
  the current crypto-only exit contract (a `POLICY_NOT_EVALUATED` receipt would then exit non-zero even
  though `CRYPTO: OK`). That flip would be a REAL default-behavior change for any script parsing exit
  codes today, so it is explicitly NOT flipped as a default here — only the opt-in flag is a plausible v4
  addition, and even that is not implemented in this increment (No-Fake: the capability described above
  IS built and IS additive; only the CLI default-exit-code change is the deferred, tracked item).

### Added — SD-JWT VC interop, Finding 20 (issue #27)

- **ES256 issuer-signature verification.** `sdjwt.verify_sd_jwt` now verifies ECDSA P-256
  (ES256, RFC 7518 §3.4) issuer signatures alongside EdDSA, dispatched strictly on the issuer
  JWT header's literal `alg` claim — the algorithm the EUDI Digital Identity Wallet and the
  OAuth WG's own SD-JWT VC worked examples use, closing proofbundle's biggest SD-JWT VC interop
  gap (previously every real-world ES256 credential could only be checked structurally, never
  cryptographically). New primitive `signature.verify_ecdsa_p256` (65-byte SEC1 uncompressed
  public key, RFC 7518 §3.4's fixed-width 64-byte `R‖S` JWS signature, converted to DER before
  calling into `cryptography` — never hand-rolled ECDSA math). `bundle.py`'s `sd-jwt-issuer-identity`
  fingerprint prefix is now alg-aware (`"ed25519:"` / `"es256:"`) rather than hardcoded to EdDSA — a
  latent false-reject the new algorithm would otherwise have exposed for an ES256-signed `sd_jwt_vc`
  that discloses proofbundle's own `issuer` claim format.
- **Trust-policy `sd_jwt.expected_vct`.** A relying party can now pin an exact required `vct` in the
  bundle trust policy (`policy.py`'s `_SDJWT_KEYS`); `evaluate_policy` adds a `policy:expected_vct`
  check, read ONLY from an issuer payload whose signature actually verified (mirrors the
  "verified vs. merely present" discipline `policy:nonce_present` already established — an
  unverified `vct` claim proves nothing). Complements, and is distinct from, `sdjwt_vc.py`'s
  standalone `vctAllowlist`.
- **Real cryptographic external conformance.** `tests/fixtures/sdjwtvc/` now also vendors the ES256
  issuer public key the OAuth WG's 5 worked SD-JWT VC examples are signed under (from the same
  pinned commit's `examples/settings.yml`, independently re-verified before vendoring);
  `test_sdjwtvc_external_vectors.py` cryptographically verifies the issuer signature end-to-end, not
  just the structural disclosure-commitment path (previously honestly out of scope — see the removed
  `test_all_examples_have_es256_issuer_alg_by_design_not_checked_here` boundary marker). No official
  NEGATIVE SD-JWT VC vectors were found upstream (checked oauth-wg/oauth-sd-jwt-vc,
  oauth-wg/oauth-selective-disclosure-jwt, and openwallet-foundation-labs/sd-jwt-python's
  `tests/testcases/` — every published example in all three is a positive structural variant), so the
  new negative tests adversarially mutate the vendored positive vectors in code instead (the
  established pattern this suite already used for `test_tampered_disclosure_is_rejected`).
- Docs: `docs/SD_JWT_VC_PROFILE.md` updated to reflect the above against issue #27's roadmap;
  `SPEC.md` §6 documents the alg-keyed `issuer_public_key_b64` encoding and the alg-aware
  `sd-jwt-issuer-identity` fingerprint.

Backward compatible: EdDSA-signed SD-JWTs verify exactly as before (same primitive, same call
sites); the `sd_jwt.expected_vct` policy field is opt-in (absent = unchanged behavior).

## [3.2.2] - 2026-07-15

Security and robustness hardening from a six-lens plus red-team audit of 3.2.1. Additive; no
wire-format change and no change to a correct 3.2.1 caller's result unless the input was actually
malformed or over-limit.

### Security
- **SD-JWT recursive-disclosure O(n^2) CPU-DoS fixed (CWE-400/407)**: `verify_sd_jwt`'s fixpoint
  resolution was quadratic under adversarially-ordered disclosures (n=4000 drove ~11s of CPU from a
  520KB bundle, reachable via `verify_bundle`). Rewritten as an O(n) BFS/worklist over disclosures
  grouped by digest, plus a fail-closed `_MAX_DISCLOSURES = 256` cap before any per-disclosure work.

### Hardening
- **Decision/outcome schema is a strict SSOT now**: `decisionId` type/non-empty enforced;
  `actionOutcome`/`validity` must be JSON objects when present; empty `parametersRef` rejected;
  `additionalProperties:false` enforced on every sub-object of both `*.schema.json`; the existing
  `nested_closure_violations` is wired into the validators; new `test_schema_parity.py` proves the
  hand validator and the docs schema agree on every golden example and 11 negative vectors.
- **Decision subject-rehang gate**: `verify_decision_receipt` classifies the subject (opt-in
  `require_derived_subject`, CLI `--require-derived-subject`); a caller-overridden subject that does
  not derive from the predicate can be made fail-closed. Corrected an earlier CHANGELOG claim that
  overstated the outcome default as "fail-closed" (it is warned-by-default, fail-closed only opt-in).
- **Trust-pack crypto-agility**: root and rotation keys carry an explicit `alg`
  (`ed25519` default, `mldsa65`, or `hybrid-ed25519-mldsa65`), verified alg-aware via the existing
  `pqsig` ML-DSA (FIPS 204) paths; a policy-declared hybrid key is not satisfied by an Ed25519-only
  signature (downgrade defense). Backward compatible for `alg`-less packs.
- **Renewal seed is verifiable, not a bare label**: `renew_*` accept an immutable
  `VerifiedAnchorResult` bound to the prior ATS digest (`require_verified_prior`); the self-asserted
  `anchor_status` path is tagged `renewal_seed_evidence_class` rather than silently trusted.
- **Public-transparency consistency is typed and bound**: a `ConsistencyVerificationResult`
  (old/new origin, tree size and root, plus proof/verifier/policy digests) replaces the ungrounded
  boolean; the confirmed claim is re-bound to the checkpoint actually being evaluated
  (`strict_consistency`), catching wrong-pair and split-view inputs.

## [3.2.1] - 2026-07-14

Anchor-longevity hardening release. A six-lens plus red-team audit of the 3.2.0 anchor modules
(EXPERIMENTAL) found the core cryptographic verify paths solid: every direct forgery attempt was
repelled. This release closes a cluster of defense-in-depth gaps in non-default, incomplete-caller
and weak-input cases. Additive only; no wire-format change and no change to a correct 3.2.0 caller's
result.

### Security and correctness (fail-closed hardening)

- **`require_pq` is a verified-PQ floor, not a label.** `renewal.verify_sequence(..., require_pq=True)`
  now passes only when the newest ArchiveTimeStamp's post-quantum signature was actually verified
  (authority-key mode). A post-quantum label on `sig_alg` under an `anchor_verifier` or unauthenticated
  anchor no longer satisfies the floor, because a label is not verification.
- **Future-dated ArchiveTimeStamp flagged.** `evaluate_renewal_policy` reports a newest ATS whose time
  is in the future as anomalous rather than perpetually fresh (its age went negative, which could
  otherwise evade the renewal-due signal).
- **Hash-strength surfaced.** `verify_sequence` emits a `renewal:current_hash` check when the newest ATS
  uses a deprecated hash, so `.ok` never hides it, and fails closed under the new `require_current_hash=True`.
- **Trust-pack version chain enforced.** A `version > 1` pack with a null `prevVersionDigest` (a
  "version-2 genesis") is rejected at validate time; it previously skipped two-stage rotation authorization.
- **Trust-pack expiry parses fractional seconds.** A validator-legal RFC-3339 `expires` with fractional
  seconds is now parsed correctly; a valid future expiry with a fraction was read as expired (a
  false-closed availability bug from a regex/parser divergence).

### Conformance

- **SD-JWT recursive disclosures (RFC 9901).** `verify_sd_jwt` resolves nested `_sd` digests committed
  inside a parent disclosure's value via a fixpoint, so valid official recursive-disclosure vectors no
  longer fail `structure_ok`. Security is unchanged: every disclosure must still be transitively rooted
  in the issuer-signed payload.

### Tests

- New `tests/test_anchor_hardening_321.py` pins each finding red to green; trust-pack version-chain and
  fractional-seconds tests; five new mutation operators in `scripts/mutation_check.py` (55 operators, 0 gaps).
- Vendored external-vector test suites, each fixture provenance-pinned (source URL + commit + sha256) and
  cryptographically self-verified rather than merely copied: NIST ACVP ML-DSA (FIPS 204) sigVer vectors
  cross-checked against the official answer key (the `verify_mldsa` external/pure/empty-context surface is 3
  vectors per parameter set, an honest property of the source data); real OpenTimestamps fixtures from the
  opentimestamps examples (pending path unconditional; the confirmed Bitcoin-anchored path skips where the
  OpenSSL legacy `ripemd160` provider is unavailable); C2SP signed-note checkpoint KATs (sum.golang.org vkey
  read from the pinned Go toolchain source, Rekor v2 key decoded from Sigstore's trusted root); SD-JWT-VC
  structure vectors from the OAuth-WG editor's copy (signature verification stays EdDSA-only by design).

## [3.2.0] - 2026-07-14

The eval → decision → **outcome** chain, plus a trust root and transparency/credential layers. Everything in
this release is **EXPERIMENTAL** (a v3 preview: API and wire format may change without deprecation; do not
depend on it in production). Additive wire format; no change to the shipped `eval-result` / `decision-receipt`
verify paths. Each predicate carries a hand-rolled fail-closed validator (the JSON Schemas remain docs-only)
and states its non-claims as explicitly as its guarantees. Predicate docs under
[`docs/predicates/`](docs/predicates/README.md).

### Added — anchor longevity (EXPERIMENTAL, ADR 0006)
- Long-term evidence mechanics so an anchor keeps its force as algorithms age. All EXPERIMENTAL, additive,
  fail-closed.
- `hashalg` — an explicit hash-algorithm registry (RFC 6920 model, RFC 4998 `digestAlgorithm` OIDs) with
  fail-closed resolution (no implicit SHA-256; deprecated/unknown rejected) and a dual-hash for new receipts.
- `renewal` — an RFC 4998 `ArchiveTimeStampSequence` (timestamp + hash-tree renewal) with an offline
  end-to-end verify, plus a `RenewalPolicy` (watch-only-newest, no network). An ArchiveTimeStamp MAY carry
  a real time-authority signature (the RFC-4998 TimeStampToken role; unsigned/legacy stays valid) with the
  algorithm bound into the signed bytes (downgrade defense); renewal MIGRATES it ed25519 → hybrid → mldsa65
  (B3↔B5); `verify_sequence(authority_keys=…)` checks the newest signature against the relying party's
  trusted keys, fail-closed by default with an optional `require_pq` floor. ASN.1/XMLERS export, a real
  external RFC-3161/OTS-token binding, and truncation/rollback detection stay OPEN.
- `pqsig` — ML-DSA (FIPS 204) verify/sign + a hybrid Ed25519+ML-DSA verify, wired into `renewal`'s
  signature migration. SLH-DSA (FIPS 205) is OPEN (`PQUnavailable`).
- `evidence_pack` — an offline OTS evidence pack (no network at verify); the WP-A1 boundary holds (a bundled
  header is producer evidence, never trust). A real confirmed-receipt pack is OPEN (needs a calendar submit).

### Added — `action-outcome/v0.1` predicate (EXPERIMENTAL, O1)
- A signed record that a specific executor carried out (or refused/failed) the action a Decision Receipt
  permitted, bound by content root to that decision (`decisionRef`), with the requested action and observed
  effect digest-bound. `proofbundle outcome init|emit|verify|inspect`.
- Verify is fail-closed: crypto → predicate type → `hash_binding` → `decision_bound` (embedded `decisionRef`
  equals the expected content root) → `role_separation` (executor ≠ decision maker) → `execution_proven`
  (`status = executed` only proven when an `effectDigest`/`actualActionDigest` backs it, else self-asserted +
  warning) → audience/nonce. No-Overclaim: never proves the action was correct or safe. Doc:
  [`docs/predicates/action-outcome.md`](docs/predicates/action-outcome.md).

### Added — `trust-pack/v0.1` predicate (EXPERIMENTAL, O2)
- A TUF-inspired root of trust: roles → `{keyIds, threshold}`, a `keyId -> publicKey` map, an offline `revoked`
  list, a monotone `version` with a `prevVersionDigest` chain (rollback/freeze protection), and `expires`.
  `verify_trust_pack` counts DISTINCT valid non-revoked root signatures against the root threshold; validation
  is dead-on-arrival aware (a root that can never meet threshold is rejected). Doc:
  [`docs/predicates/trust-pack.md`](docs/predicates/trust-pack.md).

### Added — `verification-summary/v0.1` predicate (EXPERIMENTAL, O4)
- A signed roll-up of a receipt chain: per level (eval/decision/outcome) the verified receipt content root,
  status (`VERIFIED`/`FAILED`/`NOT_EVALUATED`), and evidence class, with a mandatory `nonClaims` block. The
  `levels_consistent` rule is real (non-tautological): a `VERIFIED` level MUST carry a `receiptRef`; a
  `NOT_EVALUATED` level without one stays consistent. Doc:
  [`docs/predicates/verification-summary.md`](docs/predicates/verification-summary.md).

### Added — `run-ledger/v0.1` predicate (EXPERIMENTAL, O5)
- A signed, gap-free run history against best-of-many cherry-picking: a strictly monotone `seq` (no gaps), a
  `prevDigest` chain (each run links the previous run's `resultDigest`), aborted/failed runs kept VISIBLE, and
  a `runBudget` declared up front. A selection that drops the bad runs cannot produce an intact chain. Doc:
  [`docs/predicates/run-ledger.md`](docs/predicates/run-ledger.md).

### Added — public-transparency policy layer (EXPERIMENTAL, O3)
- `public_transparency.py::evaluate_public_transparency` composes the existing C2SP checkpoint primitives into
  one relying-party verdict with named statuses (`LOG_ORIGIN`, `CHECKPOINT_SIGNATURE`,
  `ROOT_BYTES_AUTHENTICITY`, `TREE_CONTEXT_AUTHENTICITY`, `CONSISTENCY`, `WITNESS_QUORUM`,
  `PUBLIC_TRANSPARENCY`), fail-closed (a required-but-unevaluable check is FAIL; an optional un-requested check
  is `NOT_EVALUATED` and stays visible). It is a library layer; wiring it into the `--policy` FILE of the
  reference CLI remains proposed (see [`docs/PUBLIC_TRANSPARENCY_PROFILE.md`](docs/PUBLIC_TRANSPARENCY_PROFILE.md)).

### Added — subject-binding + SD-JWT VC layers (EXPERIMENTAL, O6, O7)
- `subject_binding.py`: classifies a Statement subject as `DERIVED` (SHA-256 over the RFC-8785 canonical
  predicate, re-derived and matched) vs `EXTERNAL_ATTESTED` (override/tamper). An `EXTERNAL_ATTESTED` subject
  is warned by default on both the decision and outcome verify paths; it is only fail-closed when the caller
  opts in via `require_derived_subject` / `decision verify --require-derived-subject` /
  `outcome verify --require-derived-subject`. Plus nested schema closure. Doc:
  [`docs/SUBJECT_BINDING.md`](docs/SUBJECT_BINDING.md).
- `sdjwt_vc.py`: an SD-JWT VC relying-party profile (`typ = dc+sd-jwt`, `vct` allowlist, offline
  type-metadata integrity, holder-binding required). SSRF-safe by construction — no network I/O, a URL `vct`
  is an opaque identifier and never dereferenced. Doc: [`docs/SDJWT_VC_PROFILE.md`](docs/SDJWT_VC_PROFILE.md).

### Governance
- CODEOWNERS covers the seven new EXPERIMENTAL security modules (outcome, trust-pack, public-transparency,
  subject-binding, run-ledger, verification-summary, sdjwt-vc) — no self-merge for a security path.

## [3.1.3] - 2026-07-13

Security hardening release: the remaining P0 findings of the 3.1.1 audit round (verified live
against 3.1.2). Additive wire format; one deliberate, security-motivated tightening of
`safeForAutomation` (see below). SPEC revision `2026-07-13`.

### Changed — `safeForAutomation` requires the ATOMIC (root, tree size) authentication (A-P0-1, security)
- The sharp audit vector: an RFC 6962 inclusion proof constrains `(leaf_index, tree_size)` only up
  to path-shape equivalence — a real 2-leaf receipt (index 1) relabelled as `(index 2, tree_size 3)`
  verifies with the SAME payload, signature, root and proof. A root-BYTES pin cannot tell the two
  apart (both share the root), so `rootAuthenticity: PASS` + `safeForAutomation: true` was reachable
  for a forged tree context. Now `safeForAutomation` additionally requires
  `TREE_CONTEXT_AUTHENTICITY: PASS`: root AND tree size authenticated atomically from ONE source —
  a signed C2SP checkpoint (`--trusted-checkpoint`/`--checkpoint-vkey`, or a policy
  `merkle.trusted_checkpoints` entry) or an `--expected-root` + `--expected-tree-size` PAIR. A naked
  root pin is reported as `rootTrustLevel: ROOT_BYTES_ONLY` and never automation-safe
  (new blocker `TREE_CONTEXT_NOT_AUTHENTICATED`).
- New additive verdict keys: `rootBytesAuthenticity` (the legacy `rootAuthenticity` key stays as its
  wire-compat alias), `treeContextAuthenticity`, `checkpointAuthenticity`, `rootTrustLevel`
  (`CHECKPOINT` / `ROOT_AND_TREE_SIZE_PINNED` / `ROOT_BYTES_ONLY` / `NONE`).
- New policy section `merkle.trusted_checkpoints[]`: pins a SIGNED `(origin, treeSize, root)` triple
  (C2SP vkey + signature blob, optional `validUntil`); signature-verified, expiry-checked,
  `hashAlg`-checked at evaluation — origin/size/root tamper invalidates the signature. A non-empty
  list enforces on its own, exactly like `trusted_roots`.

### Fixed — expired eval policy now FAILS the policy evaluation (A-P0-2, security)
- The decision path already rejected an expired policy (exit 3); the EVAL path did not — an expired
  eval policy still produced `POLICY: OK` / exit 0 (only `safeForAutomation` went false). Lifecycle
  is now part of `evaluate_policy` itself: `policy:not_template`, `policy:not_expired`,
  `policy:not_before` (new additive `valid_from` field) → `POLICY: FAIL`, exit 3, path parity.
- Historical verification is explicit-only: `verify --verification-time <ISO-8601> --policy …`
  evaluates the policy lifecycle AS OF that instant with labelled output
  (`VERIFICATION_TIME: HISTORICAL`, `CURRENT_POLICY_STATUS`, `HISTORICAL_POLICY_STATUS`); an
  expired-today policy keeps `safeForAutomation: false` even in historical mode. No silent
  backdating, no silent acceptance.

### Fixed — decision `validity.audience` type confusion (found by the new regression corpus, security)
- A wrong-TYPE `validity.audience` (a STRING instead of the required array) satisfied a requested
  audience binding via Python substring matching (`"rp.example" in "rp.example"`). The check now
  requires a real JSON array (fail-closed).

### Added — `policyPurpose` binds a policy to ONE verifier path (A-P0-4)
- New additive field `policyPurpose` ∈ `eval` / `decision` / `outcome` / `trust-pack` /
  `public-transparency` (the latter three reserved for the 3.2.0 verifiers). The eval verify path
  accepts only `eval`, the decision path only `decision`; the wrong purpose is exit 3. Policies
  without the field keep working (documented transitional default); `policy lint --strict` requires
  it. All five shipped profiles now declare their purpose.

### Added — hardened policy metadata (A-P0-5)
- `merkle.trusted_roots` entries are hard-validated at load (standard base64, exactly 32 bytes) with
  their OWN error — never a silent never-matches.
- Reserved metadata (`deploymentReady`, `requiresIdentityOverlay`, `policyPurpose`, `schema`,
  `generatedFromTemplate`) can no longer be set by an instantiate overlay (loud `PolicyError`);
  `deploymentReady` is DERIVED from the final instance (identity pinned AND trust material valid AND
  purpose defined AND lifecycle valid AND not a template), and instances record their
  `generatedFromTemplate` provenance. Contradictory metadata (`deploymentReady: true` +
  `requiresIdentityOverlay: true`) is refused at load.

### Hardened after the 6-lens adversarial review (folded back before release)
- **Historical mode is present-tense-safe (was the one release-blocker).** `safeForAutomation` is a
  "safe to act on now" verdict, so its lifecycle and tree-context inputs are always evaluated at the
  REAL current time — even under `--verification-time`. Previously only `valid_until` had a current-time
  backstop, so a not-yet-valid policy or an expired-today `trusted_checkpoints` entry read
  automation-safe when a past (or future) instant was supplied. Now: `--verification-time` MUST be a
  past instant (a future one is exit 2); a new `POLICY_NOT_YET_VALID` blocker mirrors `POLICY_EXPIRED`;
  and the policy is evaluated twice in historical mode (the historical instant for the exit code + label,
  the current time for `safeForAutomation`). `CURRENT_POLICY_STATUS` now surfaces `NOT_YET_VALID`.
- **No `rootTrustLevel: CHECKPOINT` / `checkpointAuthenticity: PASS` overclaim.** `checkpointAuthenticity`
  now reports whether a checkpoint authenticated AND matched this bundle, not merely that some pinned
  checkpoint's signature verified; a verified-but-non-matching checkpoint reads FAIL and never labels a
  pair-derived context `CHECKPOINT`.
- **A matching `trusted_checkpoints` pin satisfies `require_authenticated_root`** (a checkpoint
  cryptographically authenticates the root, strictly stronger than a `trusted_roots` byte-pin) — the
  checkpoint match is now evaluated before the authenticated-root check.
- `treeSizeExpectation` reports `FAIL` (not `NOT_REQUESTED`) when a checkpoint was supplied but its
  signature did not verify. `policyPurpose: null` now loads and is treated exactly like absent
  (schema⟺parser parity). `evaluate_policy` fails closed (no traceback) on a non-string
  `checkpointSigner` in a raw dict that bypassed `load_policy`. `policy explain` lists the raw-template
  pin so `policy lint` no longer calls a minimal template vacuous.

### Migration notes
- A `merkle.trusted_roots` list mixing a valid 32-byte root with a malformed entry now fails to LOAD
  (exit 2) instead of silently skipping the bad entry (A-P0-5 hard validation); fix the malformed pin.
- `policy lint --strict` now FAILs any policy without `policyPurpose` (declare the verifier path); plain
  `verify` and non-strict `lint` are unaffected.
- Policy artifacts produced by 3.1.3 `policy instantiate` carry `policyPurpose` / `generatedFromTemplate`
  and are refused (fail-closed unknown-field) by 3.1.2 verifiers. In a mixed-version fleet, upgrade
  verifiers to 3.1.3 before re-instantiating policies. Bundles and verify output stay additive.
- `instantiate_template(..., overlay={...})` now rejects the reserved keys `deploymentReady`,
  `requiresIdentityOverlay`, `policyPurpose`, `schema`, `generatedFromTemplate` (they are derived or
  lifecycle-fixed); a `valid_until` overlay still works.

### Regression corpus (A-P0-1 … A-P0-5, plus the A-P0-3 vectors closed in 3.1.2)
- `tests/test_tree_context_authenticity.py` (relabel reproduction, checkpoint pin closes it, origin/
  signer/expiry/hashAlg mismatch vectors, legacy-root-pin-never-tree-context, CLI checkpoint path),
  `tests/test_policy_lifecycle_purpose.py` (lifecycle, historical mode, purpose matrix, metadata
  hardening, and the named decision aud/nonce fail-closed vectors), and
  `tests/test_lens_review_fixes_3_1_3.py` (the historical fail-open, future-instant rejection,
  expired-today checkpoint, require-auth-root-by-checkpoint, lib robustness, explain parity,
  policyPurpose null). Note: decision-receipt/v0.1 `validity` carries only `audience`+`nonce` — there
  is no predicate-level time window to expire; time-windowing lives on the policy
  (`valid_from`/`valid_until`), a predicate-level window would be a format change for the next breaking
  version.

## [3.1.2] - 2026-07-13

Patch release: one fail-closed security fix on the decision-verify path. No new API, no wire-format
change, fully backward-compatible.

### Fixed — `decision verify` audience/nonce binding is fail-closed on an absent validity object (security)
- A relying party that supplies `--aud` / `--nonce` (or `expected_audience` / `expected_nonce`) is
  asking for RFC-9901-§7.3-style replay/audience binding. Previously, if the decision receipt carried
  **no `validity` object** (or a non-dict one), the checks were skipped entirely — `audience_ok` /
  `nonce_ok` stayed `None`, the CLI exit gate (`None is not False`) let it pass **exit 0**, and the
  requested binding was silently unenforced (a fail-OPEN downgrade). Now an absent
  `validity` / `audience` / `nonce` is a FAIL (`audience_ok` / `nonce_ok` = `False`, exit 2) — the
  requested binding is never silently dropped. This mirrors the eval-path F4 hardening and the 3.1.1
  decision-path template/expiry gates. Regression:
  `tests/test_decision_hardening.py::test_missing_validity_with_expected_aud_nonce_fails_closed`.

## [3.1.1] - 2026-07-13

Patch release: automation-safety hardening. Three additive gates plus one fail-closed security fix,
all backward-compatible at the wire-format level. The one behaviour change is deliberate and
security-motivated: `safeForAutomation` is now stricter (see the note below).

### Changed — `safeForAutomation` is a stricter, global trust verdict (AP-1, behaviour change)
- `safeForAutomation` is now `true` **only** when the crypto verdict passed, the Merkle root was
  affirmatively authenticated, a supplied trust policy PASSED (`policy_ok is True` — no policy, i.e.
  `None`, never qualifies), that policy actually **pins a trusted signer**, it carries no blocking
  warning, it is **not expired**, and no required anchor / public-transparency / replay gate FAILED.
  A verify that previously reported `safeForAutomation: true` on a crypto-valid, root-pinned receipt
  **without** an evaluated, signer-pinning policy now reports `false`. This is intended: the flag is a
  global "safe to act on automatically" verdict, not a crypto-only verdict.
- New machine-readable `automationBlockers` array names every reason the flag is false
  (`POLICY_NOT_EVALUATED`, `POLICY_FAILED`, `SIGNER_NOT_PINNED`, `TEMPLATE_NOT_INSTANTIATED`,
  `ROOT_NOT_AUTHENTICATED`, `POLICY_EXPIRED`, `POLICY_WARNINGS_PRESENT`, `ANCHOR_REQUIRED_FAILED`,
  `PUBLIC_TRANSPARENCY_REQUIRED_FAILED`, `REPLAY_BINDING_REQUIRED_FAILED`, `CRYPTO_FAILED`).
  `PUBLIC_TRANSPARENCY_REQUIRED_FAILED` and `REPLAY_BINDING_REQUIRED_FAILED` are forward-compatible and
  **dormant** in this release (no reference call site supplies a `False` value yet); every other blocker
  is live. See SPEC.md "Enforcement status of the gate conditions".
- New human `SAFE_FOR_AUTOMATION: YES/NO` line with per-blocker reasons, derived from the same summary
  so the human and JSON forms can never disagree.
- Migration: `MIGRATION_3.1.0_TO_3.1.1.md`.

### Added — trust-policy templates and instantiation (AP-2)
- The four `strict-*` profiles are renamed `*-template-v1` and carry `deploymentReady: false` +
  `requiresIdentityOverlay: true`. The old names remain resolvable as **deprecated aliases** (a
  deprecation line on stderr, no break); `policy list-profiles` marks them.
- New `proofbundle policy instantiate <template> --issuer-key <pub> [--expected-root-file <f>]
  --policy-id <id> [--valid-until <iso8601>] [--output <f>]` turns a template into a deployment-ready
  org policy that pins your signer identity, offline. It is `deploymentReady: true` only when every
  required field is filled; unknown overlay fields fail closed.
- `policy lint --strict` now fails on a raw template (`deploymentReady: false`) and a still-set
  `requiresIdentityOverlay: true` with no signer pin. An expired `valid_until` fails `policy lint` in
  BOTH modes (strict and non-strict) — it is a lifecycle failure, not a strictness preference.
- New optional policy field `valid_until` (ISO-8601 UTC lifecycle expiry). A raw template used
  productively can never yield `safeForAutomation: true` (AP-1 + AP-2 §6.2).
- `schemas/trust_policy_v0_1.schema.json` gains `deploymentReady`, `requiresIdentityOverlay`,
  `valid_until` (kept in sync with the parser's allow-list).

### Added — `expected-tree-size` machine-readable status (AP-3)
- Verify JSON now carries a `treeSizeExpectation` object (`status: PASS|FAIL|NOT_REQUESTED`,
  `expected`, `actual`), so an integrator never has to infer from a missing line whether the check ran.
  The check itself still runs INDEPENDENTLY of the root (a mismatch already fails the crypto verdict).
- Added regressions for negative / zero / absurdly large expected values, the non-integer CLI usage
  error, and the `NOT_REQUESTED` status when the flag is absent.

### Fixed — unbindable eval SD-JWT graft refused fail-closed (N1, security)
- An eval SD-JWT that carries an eval-binding **root commitment** (a `receipt.root_b64` string, the real
  cross-receipt substitution vector) grafted onto a **non-eval-claim** payload has nothing to bind to and
  is now refused fail-closed (`sd-jwt-bundle-binding` FAIL → the whole bundle FAILs). The discriminator is
  the presence of `receipt.root_b64`, NOT a word-match on `passed`/`threshold`/`comparator`/`suite`, so
  the guard catches a graft even when those facts are moved into selective disclosures and never
  false-refuses a **generic** SD-JWT-VC (`iss` / `vct`, no `receipt.root_b64`) — which stays in scope
  (backward-compatible). Regression: `tests/test_sdjwt_verify_binding.py::TestN1UnbindableEvalSdJwt`.

### Fixed — pre-land 6-lens audit hardening (2026-07-13, security + honesty)
- **Decision path sibling gates (HIGH):** `decision verify` now enforces the same AP-1/AP-2 guards as the
  eval path — a raw, un-instantiated `decision-receipt-template-v1` (or any `requiresIdentityOverlay:true`
  policy) and an expired (`valid_until` past) decision policy no longer authorise a decision (both
  fail-closed → exit 3). `decision verify --policy` also accepts a packaged profile name (parity with
  eval `verify`). Regressions: `tests/test_decision_policy.py::TestDecisionPathTemplateAndExpiryGate`.
- **Honest automation blocker (AP-1):** a policy that DOES pin the signer but still carries an un-cleared
  `requiresIdentityOverlay:true` now reports the distinct `TEMPLATE_NOT_INSTANTIATED` blocker instead of a
  factually-wrong `SIGNER_NOT_PINNED`.
- **N1 empty-root hardening:** an always-open `receipt.root_b64: ""` no longer evades the graft check.

## [3.1.0] - 2026-07-13

Minor release: native Merkle **root authenticity** (relying-party root pinning + a trust-policy
requirement + separate verdicts, ADR 0004), score-vs-**threshold-verdict** evidence classes (P0-B),
**named trust-policy profiles** (WP3), claims-hygiene overclaim vocabulary, and the pre-release
six-lens audit hardening below. All additive and backward-compatible.

### Changed — six-lens audit hardening (2026-07-13, pre-release)
- **`THREAT_MODEL.md`** corrected: the "Merkle-root / inclusion tampering → FAIL" row no longer
  overclaims. A *coherent root rewrap* (the same signed payload re-anchored under a different valid
  root) is now stated honestly as `NOT_EVALUATED` by default, FAIL only under an authenticated-root
  policy / `--expected-root`.
- **`SPEC.md` §7** verification order now documents the additive `root-authenticity` / `tree-size`
  checks and the separate verdicts, so a second implementation knows they exist.
- **Shipped profile `strict-eval-authenticated-root-v1`** — the coherent-rewrap protection is now
  reachable from a NAMED profile (sets `merkle.require_authenticated_root`), not only a bespoke policy;
  the relying party supplies the authenticated root (`--expected-root` / `trusted_roots`).
- **`schemas/trust_policy_v0_1.schema.json`** gains `merkle.require_authenticated_root` +
  `trusted_roots` (they were enforced by the parser but rejected by the schema — a second implementation
  would have rejected the policy the code accepts). Nested schema↔parser parity test added.
- **Claims-hygiene** exception tightened: a genuine OUTER "signed Merkle/bundle root" or a first-party
  "our own tree is append-only" overclaim co-located in a per-sample / Rekor section is no longer
  over-exempted; `signed samples root` and external-log `append-only` stay exempt.
- **Cross-implementation corpus** now carries the coherent-rewrap vectors (verifies without policy;
  FAILs under `--expected-root`), so the finding is cross-checked, not only asserted in unit tests.
- Fixes: `verify --json` error path carries the `root_authenticity` key (was omitted → KeyError);
  `verify_bundle(expected_tree_size=)` rejects a float; a CLI-level root-authenticity + exit-code test;
  a decimal-precision evidence-class test. ADR `docs/adr/0005-eval-semantics-score-vs-threshold.md`.

### Added — score-vs-threshold evidence classes (P0-B, Hardening 3.0.1 §7)
- **`proofbundle.evalclaim.eval_evidence_class`** — a receipt today signs a THRESHOLD VERDICT (`passed`
  against the signed `comparator`/`threshold`); the exact score is used at emit to compute `passed` and
  then discarded, so no output may imply an exact score was verified. The classifier returns one of
  `THRESHOLD_VERDICT_VERIFIED` (the only class the frozen v0.1 schema produces), `EXACT_SCORE_VERIFIED`,
  `SCORE_COMMITMENT_PRESENT` (a binding, NOT a range proof), `SCORE_WITHHELD`, plus the always-present
  `METHODOLOGY_NOT_EVALUATED`. The last four are forward-compatible with the optional, additive
  exact-score profile (§7.2, EXPERIMENTAL, not in the frozen 3.x core).
- **`show-eval`** now prints an `evidence` line declaring the class and a `note` line for methodology,
  so the CLI never implies an exact score. Docs: `EVAL_CLAIM.md` §1a. Tests:
  `tests/test_eval_evidence_class.py`. No schema / wire / API break (additive read-side classifier).

### Added — native Merkle root authenticity (P0-A, Hardening 3.0.1 §6)
- The native Merkle root is NOT in the signature input, so the SAME signed payload verifies under
  DIFFERENT roots (a **coherent one-leaf rewrap**, reproduced in `tests/test_root_authenticity.py`).
  Merkle inclusion proves CONSISTENCY under the stated root, never its authenticity.
- **`verify_bundle(..., expected_root_b64=, expected_tree_size=)`** and CLI **`--expected-root` /
  `--expected-tree-size`** — relying-party root authentication, enforced bit-exactly; a mismatch FAILS.
- **Trust-policy `merkle.require_authenticated_root` + `trusted_roots`** — a policy can DEMAND an
  authenticated root; a stated root matching neither `--expected-root` nor a `trusted_roots` entry is a
  POLICY FAIL (exit 3, compared by bytes, malformed entries never match — fail-closed).
- **`root_authenticity_summary`** + a `ROOT-AUTHENTICITY` CLI line and JSON `root_authenticity` field —
  separate `payloadSignature` / `merkleConsistency` / `rootAuthenticity` / `publicTransparency` verdicts
  plus `safeForAutomation` (true only when the root was affirmatively authenticated). `merkle-inclusion`
  now reads "Merkle-consistent under the STATED root". ADR: `docs/adr/0004-native-root-authenticity.md`.
- Non-breaking: absent an expected root / policy, root authenticity is NOT_EVALUATED and every existing
  verdict is unchanged. `expected_checkpoint` / public-log toggles are the separate §10 profile (a later minor).

### Added — named trust-policy profiles (WP3, v2-audit)
- **`src/proofbundle/policies/*.json`** — four packaged, loadable trust-policy profiles:
  `research-preview-v1` (baseline structural pins only), `strict-eval-v1` (`assurance.minimum_level:
  reproduced`, `reject_self_attested_without_prereg`, KB-JWT required when `cnf` present),
  `strict-prereg-v1` (v0.2, requires a confirmed — not merely pending — external time anchor stamping
  the `preRegistration` target), and `decision-receipt-v1` (v0.2, pins `decision_receipt` structural
  requirements). Every profile is a REAL policy: it loads, `policy explain` lists real pins, and
  `policy lint` passes (non-strict) — see `docs/POLICY_PROFILES.md` for the honest scope (no profile
  pins a signer identity, since that is inherently deployment-specific; each carries the expected
  "attributes to nobody" warning as shipped).
- **`proofbundle.policy_profiles`** (`list_profiles`, `profile_path`, `resolve_policy_source`) — the
  loader. `resolve_policy_source` lets `policy explain` / `policy lint` / `verify --policy` accept a
  bare or `proofbundle-policy/`-prefixed profile name anywhere a policy path is accepted; a real file
  on disk always wins over a same-named packaged profile (never silently shadowed).
- **`proofbundle policy list-profiles`** — a new CLI subcommand listing the shipped profiles.
- **`explain_policy` now reports the `anchors` section as a real pin** (`policy.py`). Previously a
  policy whose ONLY pin was `anchors.require_anchor` / `require_anchor_target` looked "wirkungslos" to
  `policy lint` even though `verify --policy`'s anchor-requirement reconciliation genuinely gates exit
  code 3 on it (`_cmd_verify` reads `policy["anchors"]` directly) — a false vacuous-policy verdict for
  a pin that was, in fact, enforced. `evaluate_policy` itself (and the CLI's own anchor-requirement
  logic) is unchanged; only what `explain`/`lint` REPORT about an already-enforced pin was corrected.
  Tests: `tests/test_policy_profiles.py`.

### Added — v2-audit documentation deliverables (WP5/WP6/WP7/WP9)
- **`docs/PUBLIC_TRANSPARENCY_PROFILE.md`** — the distinction between a bundle's own local Merkle root
  and public transparency-log inclusion (already-implemented C2SP checkpoint/cosignature/tlog-proof
  support, SPEC.md §7c/§7d/§7e); documents the proposed (not implemented) `public-log-required-v1`
  trust-policy section honestly as a gap, not a shipped capability.
- **`docs/SD_JWT_VC_PROFILE.md`** (progresses issue #27) — the implemented SD-JWT core (RFC 9901) plus
  the 3.0.0 secure-by-default hardening (unsigned-fails, issuer-identity, bundle-binding), the emitted-
  but-unenforced SD-JWT VC syntactic markers (`typ: dc+sd-jwt`, `vct`, status-list pointer), and the
  three still-open items from issue #27 (type-metadata resolution, OAuth WG conformance vectors, a
  `vct`-requiring verifier flag) — none of which are implemented in this change; scoped as a follow-up.
- **`docs/MIGRATION_EVAL_PREDICATE.md`** (progresses issue #26) — the content-root canonicalization
  migration (`jcs-sha256-v1` vs. `legacy-sortkeys-json-v0`, already released in 2.1.0/ADR 0002) as a
  practitioner migration guide, plus an honest status check on issue #26's literal ask (an official
  upstream in-toto eval predicate): `in-toto/attestation#565` remains open/unmerged, so there is no
  official type to migrate to yet; the vendored `predicateType` is unchanged.
- **`docs/adr/0003-hybrid-payload-signatures.md`** (WP9) — a forward-looking ADR: a decision to DEFER
  payload-level post-quantum signatures (not implemented), comparing four options (A: status quo
  Ed25519 + hash anchors, B: Ed25519+ML-DSA-44 hybrid, C: DSSE multi-signature, D: COSE/JWS profile)
  and sketching four future trust-policy modes (`require_classical` / `require_pq` /
  `require_hybrid_both` / `allow_legacy_with_confirmed_hash_anchor`) as a design record, not a schema
  change — `policy.py`'s `signature` section is unchanged by this ADR.
- `scripts/claims_hygiene_check.py` scan set gains the four new user-facing docs (33 docs scanned, was
  29) — ADRs stay out of the scan set, matching 0001/0002 precedent.

### Added — claims-hygiene overclaim vocabulary (P0-C, Hardening 3.0.1 §5.4)
- `scripts/claims_hygiene_check.py` now also bans, unless negated: `signed (Merkle) root` (the outer
  root is a commitment, not the signed object), `publicly anchored`, `append-only`, `verified score` /
  `exact score verified`, `benchmark is secure`, `evaluation is correct`, `action was executed`,
  `<EU AI Act|AI Act|GDPR>-compliant`, and `<verifies|guarantees|certifies|…> truth`.
- Two precision exceptions keep the gate honest (a gate that cries wolf gets ignored):
  the **per-sample** exception exempts `signed root` inside a section carrying `per-sample` /
  `samples root` / `audit-challenge` / `prereg` (the samples root IS a field of the signed eval-claim
  payload, docs/DEMO.md); the **external-public-log** exception exempts `append-only` inside a section
  discussing Rekor / a transparency log (it is a correct property there, an overclaim only for a lone
  issuer-local tree). `truth` bans the claim VERBS, never the idioms `source of truth` / `ground truth`;
  `compliant` bans the regulatory sense, never `spec-`/`RFC 9162-`/`C2SP-compliant`. Tests:
  `tests/test_claims_hygiene.py` (`TestP0CAdditions`, both directions).

## [3.0.1] - 2026-07-12

### Security — close the residual model-id oracle in the EEE digest (M2)
- The `every_eval_ever` (EEE) digest stripped `model_info.id` and the top-level `evaluation_id`, but left the
  per-result `evaluation_result_id` (nested in `evaluation_results[*]`) inside the digest, while the `run_id`
  provenance path already guards that same id. An `evaluation_result_id` can embed or correlate the cleartext
  model id, so a digest over it was a model-id confirmation/enumeration oracle, asymmetric to the guarded
  provenance path. `_model_id_stripped` now also strips `evaluation_result_id` from each result. Tamper-evidence
  over scores/timestamps/dataset is unchanged (a tampered score still changes the digest); the id stays available
  for `run_id` provenance with its own leak guard. This closes the gap that shipped in 3.0.0.

### Documentation
- README: add PEP 740 (attestations) and SLSA build-provenance badges now that the first attested release is live.
- README: restructure for scannability (table of contents, deduplication, roadmap section).
- Erratum for the frozen 3.0.0 artifact: its `CHANGELOG.md` stated "811 tests" for the 3.0.0 line; the correct
  count is **817** (corrected on `main` post-tag). Tags are immutable, so the shipped 3.0.0 changelog keeps the
  typo; this 3.0.1 changelog carries the correction.

### CI / release hygiene
- Add a version-and-changelog integrity gate (`.github/workflows` + `scripts/check_version_and_changelog.py`):
  fails CI when `pyproject.toml`, `src/proofbundle/__init__.py` and `CITATION.cff` disagree on the version, or
  when the top changelog heading does not match that version. Closes the "merged but never released / version
  drift" class that let the M2 fix and the 811-vs-817 typo sit unreleased.

## [3.0.0] - 2026-07-12

### Security (BREAKING) — SD-JWT disclosures must be signed AND bind their bundle (WP-C1/C2, 6-lens review)
- An `sd_jwt_vc` block lives OUTSIDE `payload_b64`, so the bundle's Ed25519 signature does not cover it —
  only the issuer signature authenticates its disclosures. Two verify-path holes are now closed
  (secure-by-default; SPEC.md §6/§7 revision 2026-07-11):
  - **Unsigned SD-JWT now FAILS (was null-and-warn).** A bundle carrying an `sd_jwt_vc` with **no**
    `issuer_public_key_b64` previously verified with a warning and a null `sd_jwt_ok`; its disclosures were
    unauthenticated yet the bundle passed. It now fails verification (exit 1) with a failing
    **sd-jwt-issuer-signature** check, `sd_jwt_ok: false`, `sd_jwt_issuer_verified: false`, reason
    `unsigned`. There is no opt-out flag that lets an unsigned SD-JWT verify.
  - **Cross-receipt substitution now FAILS (new sd-jwt-bundle-binding check).** For a
    `proofbundle/eval-claim/v0.1` payload, a *validly issuer-signed* SD-JWT whose always-open disclosures
    (passed/threshold/comparator/suite/issuer + committed merkle root) describe a **different** bundle —
    a receipt lifted and grafted on — now fails (exit 1, `sd-jwt-bundle-binding: false`,
    `sd_jwt_ok: false`, reason `unbound`/`mismatch`).
  - **Forged issuer identity now FAILS (new sd-jwt-issuer-identity check).** A self-signed SD-JWT whose
    issuer signature verifies under an attacker-chosen key while its always-open `issuer` claim names a
    *trusted* party now fails (exit 1, `sd-jwt-issuer-signature: true` but `sd-jwt-issuer-identity: false`,
    `sd_jwt_ok: false`, reason `issuer-key-mismatch`): the verifying key is bound to the disclosed issuer
    (`fingerprint(issuer_public_key_b64) == issuer`).
  - **Migration.** If you emit bundles with an `sd_jwt_vc`, add `sd_jwt_vc.issuer_public_key_b64`
    (Base64 of the 32-byte raw Ed25519 issuer key) so verifiers can authenticate the disclosures, and
    ensure the SD-JWT's disclosed claims + `receipt.root_b64` match the bundle they ship in. Bundles that
    carry no `sd_jwt_vc` are unaffected. The three prior backward-compat tests are re-pinned as negative
    tests of the new secure behaviour; conformance corpus gains `bundle/sd-jwt-unsigned-unauthenticated`,
    `bundle/sd-jwt-signed-but-unbound` and `bundle/sd-jwt-forged-issuer-identity` (all expect exit 1).
### Docs — No-Overclaim scope corrections from the 6-lens review (MED)
- **`intoto.svr_properties` / `export_svr_dsse`** (WP-E1) — PROOFBUNDLE_PREREG_BOUND / PROOFBUNDLE_ANCHOR_VALID
  are emitted from the caller's flags (the function does not call verify_anchors) — caller-attested.
- **`decision.build_decision_statement`** (WP-E2) — a caller-supplied subject_sha256 is verbatim, not
  cross-checked against the predicate (nor re-derived at verify).
- **`merkle.verify_inclusion`** (WP-D2) — documented the RFC 6962 precondition: tree_size + root must come
  atomically from one authenticated source.
- **`policy` sd_jwt.max_iat_age_seconds** (WP-C3) — bounds the eval claim timestamp, NOT the KB-JWT iat.
### Security (BREAKING) — external time-anchor trust comes from the relying party, not the bundle (WP-A1)
- An external time anchor (`anchors[]`) previously took its trust root from the bundle's own `frozen`
  block: `anchors_rfc3161` from `frozen.rootCertsDerB64`, `anchors_ots` from
  `frozen.bitcoinBlockHeaderMerkleRootsByHeight`. That block is producer-controlled, so a malicious
  producer could freeze its OWN self-signed TSA root (or a self-committed backdated Bitcoin header) and
  self-certify a **backdated** timestamp — `--require-anchor` passed on nothing but self-consistency.
  Trust now comes ONLY from the relying party (SPEC.md §7i Trust model, rev 2026-07-11):
  - **rfc3161-tsa** is verified against `--trusted-tsa-root` (repeatable, DER/PEM) or policy
    `anchors.trusted_tsa_roots`; the frozen root is evidence (`frozenEvidence`), never trust.
  - **opentimestamps** is confirmed only against `--bitcoin-header HEIGHT:MERKLEROOT_HEX` (internal byte
    order) or policy `anchors.bitcoin_block_headers`; the frozen header is never trusted.
  - Without relying-party trust material a time anchor is `needs_rp_trust` (ok=False) and
    `--require-anchor` is **unmet → exit 3**, never a silent pass. Per-entry results carry `rp_trusted`,
    `needs_rp_trust`, `frozenEvidence`.
  - The same flags + policy `anchors` trust apply to `decision verify` (a statement time anchor on a
    decision receipt): `verify_decision_receipt(..., rp_trust=...)`, `decision verify --trusted-tsa-root /
    --bitcoin-header`.
  - **Migration.** A relying party that used `--require-anchor` (or `decision verify --anchors`) on a
    TSA/OTS anchor MUST now supply the trust material (`--trusted-tsa-root` / `--bitcoin-header`, or the
    policy `anchors` section). The
    bundle's frozen material stays in the format as evidence (TSA rotation) and is reported, so nothing
    is dropped; only its role as a trust source is removed. Third-party extension anchor verifiers keep
    working (backward-compatible dispatch); anchor tests are re-pinned; conformance gains
    `forged-anchor-own-frozen` (exit 3). THREAT_MODEL.md names the backdating attack.

### Security — pre-auth DoS: bound oversized integer parsing (WP-D1, 6-lens review)
- Python caps `int(str)` at `sys.get_int_max_str_digits()` (default 4300) and raises a raw `ValueError`
  above it (CWE-674 / CVE-2020-10735). A pre-auth parser that fed an unbounded decimal string to
  `int()` surfaced this as an uncaught traceback. Fixed at three sites: `_strict_json.loads_strict`
  maps the int-conversion `ValueError` from an oversized JSON integer literal to `BundleFormatError`
  (covers every JSON verify path — bundle / decision / in-toto / status-list / anchors); `tlogproof`
  and `checkpoint` bound the tree-size / index digit count (<= 20, i.e. 2**64) BEFORE `int()`; and the
  CLI `verify-proof` handler catches `ValueError` as a stopgap. Regression-tested; never a raw traceback.
### Security — verify-path hardening from a 6-lens adversarial review (2026-07-11)
- **Trust policy rejects a low-order / non-canonical pinned key** (`policy.py`) — the core verifier
  deliberately accepts low-order and non-canonical Ed25519 encodings (SPEC §4a). A policy that PINS such
  a key as a trusted issuer / decision-maker would accept a fixed `(pub, sig)` pair for many messages
  (for the identity encodings, ALL messages) with no private key — forgery of a trusted identity without
  a secret. `load_policy` now fail-closed rejects the whole class by the point's **y-value**
  (sign-independent, so no encoding variant slips past — an earlier hand-kept byte-string blocklist
  missed three) plus the non-canonical (`y >= p`) class, in `allowed_issuers` and
  `trusted_decision_makers`; a low-order key is also refused at the evaluation layer
  (`evaluate_policy` / `evaluate_decision_policy`) as defense-in-depth, so a policy dict that skipped
  `load_policy` gets no trust from it either. (Scope: a genuine full-order key from an honest keygen is
  accepted; MIXED-order keys are accepted and are not forgeable via this attack — a full prime-subgroup
  membership check is a follow-up.)
- **`verify_decision_receipt` no longer reports trust fields over unauthenticated bytes** (`decision.py`)
  — a forged/unsigned envelope previously left `audience_ok`/`nonce_ok`/`evidence_bound` computed
  (potentially True) with an empty `errors[]`. Now an aggregate **`ok`** field is the single verdict, the
  trust-derived fields stay `None` when `crypto_ok` is False (mirroring the anchors/policy gates), an
  error is recorded on a crypto failure, and `evidence_bound` is `None` (not a vacuous `all([])` True)
  when there are no evidence refs.
- **Decision trust policy surfaces the "attributes to nobody" warning** (`decision.py`) — a decision
  policy that constrains the verdict/type but pins no `trusted_decision_makers` means `POLICY: OK` proves
  integrity by an unknown signer. `policy_warnings()` (already decision-aware) is now wired into the
  decision verify path, matching the eval path.
- **`evalclaim.load_claim_text` uses the shared strict parser** (`evalclaim.py`) — it reimplemented
  duplicate-key rejection and did not map `RecursionError`, so a pathologically deep-nested claim payload
  crashed `decode_eval_claim` uncaught (CWE-674) — reachable from the batch verifier
  `hf_evals.verify_eval_results_entry`, `policy.evaluate_policy`, and CLI `emit-eval`. It now delegates to
  `loads_strict` (deep nesting and duplicate keys become a clean `EvalClaimError`, never a raw traceback).

### Docs — No-Overclaim corrections from the 6-lens review (2026-07-11)
- **`hf_evals.to_eval_results_entry` docstring + THREAT_MODEL** — the value↔verdict check was described
  as making the published `value` "match" a disclosed score and "stops 0.60 next to 0.99". The signed
  claim carries `threshold`/`comparator`/`passed`, not the exact score, so the check binds the value to
  the correct SIDE of the threshold, not to a true magnitude: an inflated value on the passing side (a
  true `0.81` published as `99.9`, both `>= 0.80`) still verifies. Docstring corrected and a
  value-magnitude boundary row added to THREAT_MODEL.
- **`docs/OPERATIONS_SECURITY.md`** — the `[Owner]` checklist items read as accomplished present-tense
  fact ("account on 2FA", "tags are protected", "Scorecard is enabled"), contradicting the document's
  own "does not assert they are done" preamble. The marker is now **`[Owner · to verify]`** on every
  line so the unverified status survives a reader skimming the list.

### Added — native-bundle conformance vectors (WP-S1)
- **`conformance/bundle/`** — four native proofbundle bundle cases (kind `native_bundle`) checked
  against the CLI verify exit-code contract: `valid-minimal` (a valid bundle verifies, exit 0),
  `duplicate-json-key` (a bundle whose raw JSON carries a duplicate top-level key is rejected as
  malformed, exit 2 — locking the C1 Bishop-Fox parser-differential defense onto the conformance
  gate), `tampered-payload` (a valid bundle with one payload byte flipped fails the signature, exit 1),
  and `corrupted-signature` (payload intact but the signature bytes corrupted, exit 1). The harness `native_bundle` handler runs `proofbundle verify` and asserts the exact exit
  code, with the same fail-closed floor (a case must declare `exitCode`). Anti-tautology regression
  tests: a wrong expected exit code fails, a missing exitCode fails, and the duplicate-key bundle is
  proven rejected.
### Added — MAINTAINERS.md + TRADEMARK.md + OPERATIONS_SECURITY.md governance docs (WP-W5 phase 1-2)
- **`MAINTAINERS.md`** — the conventional human-readable maintainer file: names the single maintainer,
  points to `GOVERNANCE.md`, the DEFAULT-DENY `oss_maintainer_roles.json`, `.github/CODEOWNERS`, and
  `SECURITY.md`. No delegated maintainers today.
- **`TRADEMARK.md`** — an honest use-of-name policy: the MIT-licensed code is free to use and fork; the
  "proofbundle" / "b7n0de" names are **not registered trademarks** (no ® claim) but should not be used
  to name a competing fork/package or imply official status. Protects the one thing the project cannot
  fork away: that a receipt under this name comes from the reviewed, gated releases.
- **`docs/OPERATIONS_SECURITY.md`** — the supply-chain posture checklist (accounts/2FA, PyPI trusted
  publishing, signing-key custody, SHA-pinned CI actions, fork-PR secret isolation, domain lock). It is
  a checklist, not a claim: `[Owner]` items are the maintainer's to verify and are not asserted done;
  `[repo]` items are enforced by files in the repo. Distinct from `SECURITY.md` (which is about
  receiving vulnerability reports).
- **`docs/GRANT_MILESTONES.md`** — the public deliverable/status tracker for the funded independent
  security-review track (M1–M…), factual and linked to repo evidence, never aspirational.
- All four docs are now in the `claims_hygiene_check` scanned set (29 docs), so they are held to the
  same No-Overclaim discipline as the rest of the documentation.

### Added — offline conformance corpus with cross-implementation decision vectors (WP-W2)
- **`conformance/`** — a versioned, digest-pinned corpus verified fully offline by
  `conformance/run_conformance.py` (`make conformance`). Each case declares what it proves AND what
  it does not, so a green run never overclaims. Two cross-implementation decision-receipt vectors
  from MarkovianProtocol/audit-anchor (credited, pure data):
  - `decision/crossimpl/confirmed-anchor-lifecycle` — proves RFC 8785 canonicalization + content-root
    binding cross-implementation **and** a confirmed Bitcoin anchor at block 957504: the OTS proof's
    committed root matches the real block merkle root (independently fetched, frozen in the case,
    verified offline; a wrong frozen root is rejected — `block_mismatch`, covered by `test_anchors_ots.py`).
    Does not prove `decision-receipt/v0.1` schema conformance (predicate reports 12 findings, expected-fail).
  - `decision/crossimpl/canonicalization-root-binding` — proves canonicalization + root binding; anchor
    still pending and predicate not yet schema-conformant (both recorded as expected, not hidden).
  Anchor sub-checks run in the `anchors` CI job (`[anchors]` extra, `--require-anchors`); the corpus's
  non-anchor checks run in every matrix leg. README §Interop precised: canonicalization interop proven,
  full decision-receipt conformance of the external fixture still pending. The harness is fail-closed by a
  required-expectations floor: a `decision_crossimpl` case that under-declares its bindings FAILS rather
  than passing green asserting nothing, and its defining checks (JCS byte-identity, content-root match,
  evidenceRef binding, anchor when a `.ots` ships) run unconditionally; a missing fixture is a per-case
  FAIL, not a run-aborting crash. Hardened further after a 6-lens review: a missing case dir,
  a malformed case.json, or a case.json with no `kind` is now a per-case FAIL (the outer parse was
  outside the try before), and a native_bundle `input` cannot escape its case directory.

### Added — decision-receipt validator API hardening + cross-impl gap record (WP-W6 / WP-W1)
- **`decision.require_valid_decision_predicate(pred)`** — a raising counterpart to
  `validate_decision_predicate`. The list-returning validator (empty list == valid, never raises)
  is easy to misuse as `try: validate(...) ; except: ...`, which silently passes every predicate:
  that idiom produced a public "passes the enforced v0.1 validator as-is" claim for an external
  cross-implementation fixture that in fact reported 12 findings. The wrapper raises
  `DecisionReceiptError` (with the finding count) on an invalid predicate, `None` on a valid one.
  `docs/predicates/decision-receipt.md` §6.1 documents the list-vs-raise contract; a regression
  test (`tests/test_decision_validator_api.py`) pins that the naive try/except idiom wrongly passes.
- **`audit_artifacts/crossimpl_fixture_gap_20260711.md`** — No-Overclaim record for the
  MarkovianProtocol/audit-anchor decision-receipt fixture: the RFC 8785 canonicalization and
  content-root binding are proven byte-identical cross-implementation (evidence `323adb18…`,
  decision `ff05e3e0…`), but the external predicate does not yet satisfy the enforced
  `decision-receipt/v0.1` schema (field mapping thread-prose → v0.1 included). Both statements are
  recorded so neither is overclaimed nor hidden.

### Added — CODEOWNERS + roles registry, dead governance link fixed (WP-G2)
- **`.github/CODEOWNERS`** for the trusted core, `SPEC.md`, `schemas/`, `docs/predicates`,
  `docs/adr`, and the CI/release wiring — a change to those paths requires the maintainer's review
  ("more eyes, not weaker gates", GOVERNANCE.md). Single-maintainer today; co-maintainers are added
  per-person, never implicitly.
- **`oss_maintainer_roles.json`** at the repo root — the delegated-rights registry GOVERNANCE.md
  referenced but which pointed at a non-existent `office/governance/` path (a monorepo path that
  never shipped here). DEFAULT DENY: nobody holds merge/release/secret rights without an explicit
  entry. GOVERNANCE.md now links the real file and CODEOWNERS.
- The project's **first external contributor** (@onxxdatas, issue #28 — `--version` prints the
  pinned spec revision) is recorded in the governance story and the roles registry (no delegated
  rights, like every contributor).

### Added — HF entry verifier-side binding + EEE source digest (WP-I2 / WP-I3)
- **`hf_evals.verify_eval_results_entry(entry)`** — the value↔verdict consistency was emit-side
  only: an `.eval_results` entry whose displayed `value` was edited AFTER the `pb1.` token was
  minted verified fine (the token check covers only the embedded bundle, and a Hub reader sees the
  value, not the token). Now the verifier side checks token crypto AND
  `value <comparator> threshold == passed` against the decoded, issuer-bound claim (fail-closed:
  a non-eval bundle or a non-finite value never judges as consistent). **Documented replay
  boundary** (module + THREAT_MODEL row): the entry's `dataset.id`/`task_id` are NOT bound to the
  receipt's salted dataset commitment — that binding needs the salt opening; this function is a
  value check, never a repo-binding check.
- **`adapters.from_eee_dataset` now binds the receipt to its exact source record** (it was the
  only adapter without a provenance binding): `provenance.eee_record_sha256` =
  `sha256-jcs:<hex>` over the RFC-8785-canonical record (labeled `sha256-sortkeys` fallback,
  mirroring `adapters/_provenance.config_hash`), plus the RESULT-level `evaluation_result_id` as
  `run_id` — guarded: dropped if a producer embedded the cleartext model id in it (the TOP-level
  `evaluation_id` stays excluded for exactly that reason; digest-privacy consideration documented
  in the adapter).
- Hardened after a Tier-1 review (2 P1 privacy findings): the `eee_record_sha256` digest is now computed over a **model-id-stripped** record — an unsalted digest over a record embedding `model_info.id` in cleartext was a model-id confirmation/enumeration oracle (the old "not enumerable" comment was an overclaim); it still binds scores/timestamps/dataset for tamper-evidence. The `run_id` privacy guard now drops the id on ANY model-name component (bare name, slug variants, case-insensitive), not only the full `org/name` id. `verify_eval_results_entry` returns fail-closed (not a raise) for a token-less entry (verifyToken is optional in the HF schema) and rejects a boolean `value` (the builder rejects bool too).

### Added — anchor TARGET gate + structured trustedTime (WP-A1 / WP-A2 / WP-A7)
- **`verify --anchor-target receipt|preRegistration|statement`** (implies `--require-anchor`) and
  the trust-policy **v0.2 `anchors` section** (`require_anchor`, `require_anchor_target`,
  `allow_pending`): the anchor requirement matched the TYPE only, so a `receipt` anchor stamped
  today satisfied a relying party who demanded backdating protection — existence-now proves
  nothing about existence-before-the-run. Matched is now ok ∧ ¬warn ∧ type ∧ **target**; a
  CLI/policy conflict is exit 2 (mirrors `expected_aud`), never a silent override.
- **Structured `trustedTime` in per-anchor results** (SPEC §7i): `{source: rfc3161_gen_time,
  time, tz}` from a verified token's own gen_time; `{source: bitcoin_block, height}` from a
  confirmed OTS attestation (native unit, no wall-clock guess); the markovian type carries the
  delegated OTS time through. Present ONLY when the proof carries it — never derived from the
  informative `anchoredAt` (a tampered `anchoredAt` changes neither verdict nor trustedTime,
  pinned by regression test). Time-window policies over `verify --json` become buildable.
- **A7 regressions closed:** a v0.1 bundle carrying `anchors[].target: "statement"` is now
  rejected as malformed (exit 2) by the verifier itself — the docs promised it, the code never
  enforced it (`statement` is exclusively for DETACHED decision evidence); a non-string
  `anchoredAt` on a detached anchor fails closed; anchoredAt-tamper invariance is pinned.
### Added — `policy explain` / `policy lint` + the vacuous-pass warning (WP-TP1)
- **A policy that pins nothing no longer passes silently.** `evaluate_policy` returns
  `policy_ok = all(checks)`; with an empty/id-only policy `checks` is empty and `all([])` is True —
  a green `POLICY: OK` that evaluated nothing. Now: `proofbundle policy lint <policy>` exits 1 on
  such a wirkungslose policy (`--strict` also fails an attributes-to-nobody policy);
  `proofbundle policy explain <policy>` lists the effective pins (human + `--json`).
- `verify --policy` marks a PASSING policy that pins no signer inline —
  `POLICY: OK (WARNING: attributes to nobody)` — plus a machine-readable `policy_warnings[]` JSON
  field. Exit codes unchanged (a warning, never a new failure mode; fail-closed behavior of real
  policy violations untouched).
- docs/TRUST_ANCHORS.md documents the new subcommands; +9 tests
  (`tests/test_policy_explain_lint.py`).

### Fixed — predicateType enforcement on the in-toto verify paths (WP-I1)
- **`verify_eval_result_dsse` / `verify_svr_dsse` / `verify_intoto_dsse` now ENFORCE the
  `predicateType`, not just return it.** Previously a validly-signed envelope of one predicate type
  verified `ok=True` through the verify function of another (a swapped SVR accepted as an
  eval-result, a test-result as an SVR, …) — the decision-receipt layer already rejected such
  confusion, the eval/SVR/test-result layer did not. Each function now pins its own type by default
  (`expected_predicate_type`, opt out with `None`), returns `ok=False` + a `predicate_type_ok`
  field + a "confusion attack?" detail on a foreign type. Additive return field; the diagonal
  (matching type) verifies exactly as before.
- Cross-predicate matrix test (`tests/test_predicate_type_enforcement.py`): every emitted in-toto
  type signed and run through every verify function — only the diagonal verifies, every
  off-diagonal cell is `ok=False`; plus explicit-expected-type pin, opt-out, and
  wrong-signature-still-fails. A mutation operator (disable the check ⇒ red).
### Fixed — duplicate JSON keys rejected on the verify paths (WP-C1)
- **`json.loads` last-wins duplicate keys are rejected fail-closed** (new stdlib-only
  `proofbundle._strict_json.loads_strict`, `object_pairs_hook`, any nesting depth, clear
  `duplicate JSON key '<k>'` message). A duplicated key is a classic parser differential: two JSON
  implementations can disagree about which `root_b64`/`sig_b64`/`predicateType` they verified —
  for a signed **status-list token** that was a PROVEN VALID-vs-INVALID revocation split-brain.
  Converted: the native bundle (`load_bundle`; the `pb1.` HF receipt token), the DSSE statement
  verifiers (eval-result / test-result / SVR / decision), the **trust-policy loader**, the
  **per-sample opening's committed disclosure record**, the **chia-datalayer and markovian anchor
  envelopes**, the **status-list token**, the **enclave EAT**, and every `json.load` in the CLI
  (`verify-opening`, `intoto --verify`, `svr --verify`, `decision emit/verify/inspect`,
  `--anchors`). Emit side too: a predicate file carrying a duplicate key is refused before
  anything is signed. **SPEC §2 now makes duplicate-key rejection normative** (an interoperating
  implementation that keeps either occurrence is non-conforming); THREAT_MODEL carries the
  parser-differential row.
- Deliberate behavior deltas (each stricter, never looser): `to_eval_results_entry` now REFUSES a
  crypto-valid bundle whose payload carries a duplicate key (previously the entry was built
  last-wins — refusing to publish an unjudgeable value is the honest outcome);
  `decision inspect` exits 2 instead of risking a raw traceback on malformed/duplicated payloads.
- Known residual (documented in `_strict_json`): the SD-JWT/KB-JWT payload parses (`sdjwt.py`,
  `kbjwt.py`, the `bundle._issuer_requires_holder_binding` helper) — a naive conversion would
  INVERT a fail-closed direction (a rejected `cnf` read must not read as "no holder binding
  required"); that group needs its own careful pass. Keys differing only by Unicode normalization
  or a BOM are distinct JSON keys by spec and stay distinct (a downstream-validator concern).
- Negative tests `tests/test_dup_key_reject.py` (native bundle signature/merkle/top-level, HF
  token, all four DSSE verify functions in BOTH content-root modes, decision library+CLI,
  emit-side refusal, policy/statuslist/persample/enclave/anchor-envelope rejects) + a mutation
  operator proving the tests kill a disabled guard.

### Added — Ed25519 verify semantics decided, documented, pinned (WP-C2)
- SPEC.md gains **§4a Verification semantics — the edge-case envelope**: proofbundle's Ed25519
  verification (via `cryptography`/OpenSSL) matches the **BoringSSL / Dalek (non-strict)** row of
  the "Taming the Many EdDSAs" corpus exactly (ACCEPT {0,1,2,3,11}, REJECT {4,5,6,7,8,9,10};
  eprint 2020/1244) — cofactorless, RFC 8032 S-bound enforced, non-canonical R rejected,
  non-canonical A partially accepted, small-order accepted; NEITHER Dalek-strict (rejects
  {0,1,2,11}) NOR ZIP-215 (additionally accepts {4,5,9,10}). Honest RFC 8032 signatures are
  unaffected; the cross-verifier-consensus consequence for crafted signatures is documented here
  and in THREAT_MODEL.md.
- The 12-vector corpus is vendored **byte-identical** (`tests/fixtures/ed25519_speccheck_cases.json`,
  from novifinancial/ed25519-speccheck commit `5e4bfc4…`, blob `8686dcb…`, Apache-2.0 — LICENSE +
  provenance README beside it) and pinned by `tests/test_ed25519_semantics.py` (content SHA-256 +
  per-vector verdict) — a fixture tamper OR a backing-library behavior change turns the
  repository's CI red, demanding a deliberate documented decision, never a silent drift.
  No behavior change; switching profiles would be a versioned, breaking change.
### Fixed — claims-hygiene gate honesty (WP-N1)
- **`scripts/claims_hygiene_check.py` no longer skips missing docs silently.** Six of sixteen
  `_DEFAULT_DOCS` entries did not exist (four lacked the `docs/` prefix; `docs/MATURITY.md` and
  `docs/MIGRATION_2.0.md` never existed), so the gate scanned only 10 docs while reporting PASS. A
  listed-but-missing path is now a FAIL (exit 1, `missing[]` in the JSON), the scan list matches the
  repository exactly, and six more user-facing docs are scanned (`docs/NON_CLAIMS.md`, `docs/DEMO.md`,
  `docs/ANCHORS.md`, `docs/ANCHORS_MARKOVIAN.md`, `docs/REVIEWERS.md`, `docs/EXPERIMENTAL_ENCLAVE.md`).
- **Soft-wrapped Markdown sentences are unwrapped before the negation check.** A negation on the
  previous physical line of the same sentence ("… not a statement that a\n  model is safe to deploy")
  was lost because every newline counted as a sentence boundary; block starts (blank line, heading,
  list item, quote, table row) remain boundaries.
- **New forbidden phrasings** (Gate 3, standard-track): `safe to deploy`, `safe model`,
  `verified result`, `correct decision`, `authorized action`, and positive `trustless` (the allowed
  wording is "trust-minimized (Bitcoin PoW time)", or an explicit negation).

### Changed — wording and reference hygiene (WP-N2)
- `verify` labels the assurance source: `ASSURANCE: <level> (issuer-declared)` plus a machine-readable
  `assurance_declared_by: "issuer"` JSON field (null when the bundle is not an eval receipt, and null
  when crypto failed — no level to attribute) — the level is the issuer's own declaration, never an
  appraisal. **Migration note:** a consumer that matched the FULL line (e.g.
  `^ASSURANCE: reproduced$`) must accept the ` (issuer-declared)` suffix; `assertIn`-style prefix
  matching keeps working.
- `trustless` → `trust-minimized (Bitcoin PoW time)` in `anchors_markovian.py` and
  `docs/ANCHORS_MARKOVIAN.md` (the Bitcoin time component is trust-minimized; nothing here is
  trust-free).
- `docs/NON_CLAIMS.md` gains a **Decision Receipts** section (a verified ALLOW is a *record*, not an
  authorization/bearer token; against cross-context replay issue receipts with `validity.audience`/
  `validity.nonce` and verify with `--aud`/`--nonce` — a v0.2 policy's `require_audience`/
  `require_nonce` enforce their *presence*) and a **TEE bridge** section; `decision verify --help`
  carries the same boundary, including that `--aud`/`--nonce` only bind a receipt that carries a
  `validity` object.
- Reference fixes, pinned by `tests/test_docs_truth.py`: ValiChord URL →
  `github.com/ValiChord/ValiChord` (INTEROP.md, INTEGRATIONS.md); SD-JWT VC citation →
  draft-ietf-oauth-sd-jwt-vc-17 (IESG "Publication Requested"; `dc+sd-jwt` not yet IANA-registered);
  `docs/EXPERIMENTAL_ENCLAVE.md` install no longer pins the stale `2.0.0b1` beta.

### Hardened after the six-lens adversarial review of this change set (2026-07-11)
- **Gate:** a listed-but-unreadable doc is now a FAIL like a missing one (it silently counted as
  scanned + PASS); heading/table-row/fence/setext lines no longer merge forward into the next
  paragraph (a negation inside a heading could exonerate the following prose); clause separators
  (`;`, `:`, `—`) now bound the negation window (a negation in an earlier, grammatically independent
  clause no longer exonerates a later positive claim); the scan set additionally covers
  INTEGRATIONS.md, EVAL_CLAIM.md, RELEASE.md, GOVERNANCE.md, CONTRIBUTING.md (25 docs).
- **Docs truth:** `docs/ANCHORS.md` no longer asserts a positive `trustless` ("run your own and no
  third-party trust remains"); `docs/REVIEWERS.md` drops its stale hard-coded test/operator counts
  (683→ the suite had grown; 26→ the operator list lives in `scripts/mutation_check.py`);
  RELEASE.md's beta section is reframed as convention-for-future-pre-releases (the "v1.x stays the
  default" sentence was stale since 2.0.0 final); THREAT_MODEL.md quotes the new `ASSURANCE:` line
  format; NON_CLAIMS.md says "digest-bound `outcomeRef`" (the verifier checks the digest's presence
  and binding, not a signature on the outcome record).
- **Tests:** content-violation ⇒ exit 1 pinned at the `main()` level; unreadable-doc ⇒ FAIL pinned;
  the exit-2 error path is pinned to carry the FULL `verify --json` field contract (incl.
  `assurance_declared_by`); the CLI-help assertion is terminal-width-independent; a line-number pin
  proves soft-unwrap keeps positions 1:1.
### Verification discipline
- **817 tests** (was 683 at 2.1.0) across the 3.10–3.14 CI matrix, all green. A pre-release audit
  hardened the two anti-regression instruments so they actually cover the code this release adds:
  the mutation gate (`scripts/mutation_check.py`, Anti-Goodhart) now carries an operator for **each of
  the four new breaking defenses** — WP-C2 unsigned-fail, WP-C1 issuer-identity and bundle-binding,
  WP-A1 needs-rp-trust — so a future accidental revert of any of them goes red (the mutation CI job now
  installs `[anchors]` so the WP-A1 operators are exercised, not short-circuited at `no_lib`). The
  offline conformance corpus's `sd-jwt-unsigned-unauthenticated` vector is now **cnf-free so it isolates
  WP-C2** (disabling that defense flips the vector to exit 0), instead of riding on the older v1.6
  cnf-downgrade check.
- **SD-JWT / KB-JWT payloads now parse with `loads_strict`** like every other verify path: a DUPLICATE
  JSON key (e.g. a second `cnf` naming an attacker holder key) is rejected fail-closed at the structure
  gate. The release-audit follow-up extended this to the last parse site of the same class, the
  `evalclaim.sd_jwt_hidden_count` disclosure-transparency helper (a duplicate key now returns `None`,
  not a last-wins count), closing the documented parser-differential residual in full (regression:
  `tests/test_sdjwt_duplicate_cnf.py`).
### Packaging
- The `Development Status` classifier stays **`4 - Beta`** for 3.0.0 (Owner decision E1, 2026-07-12):
  stable is evidenced, not asserted. The move to `5 - Production/Stable` is a separate, audit-gated
  milestone that lands only after the funded external security review passes
  (tracked in `docs/GRANT_MILESTONES.md`), never claimed pre-audit — even for a breaking security release.

## [2.1.0] - 2026-07-10

First release on the 2.x line after **2.0.0 final**: a new vendored **decision-receipt/v0.1** predicate for
agent decisions; a shared **universal content root** (`jcs-sha256-v1`) that the eval-result / test-result / SVR
export paths now adopt with an explicit declared legacy mode (every already-signed 2.0.0 receipt keeps
verifying byte-for-byte); and **anchors v0.1** — a `verify --require-anchor` relying-party gate plus RFC 3161
policy-OID / certificate-expiry hardening over the experimental external-time-anchor layer. All three are
additive over 2.0.0; no released receipt is invalidated.

### Added — Decision Receipt predicate `decision-receipt/v0.1` (Phase D)
- A new **vendored** in-toto predicate for agent decisions:
  `https://b7n0de.com/proofbundle/predicates/decision-receipt/v0.1` (ADR 0001). A Decision Receipt records
  *who decided, what action was proposed, against which policy boundary, on which digest-bound evidence, what
  the verdict was, and what was explicitly not checked*. It is a DSSE-signed in-toto Statement, verified over
  the exact signed bytes.
- **CLI:** `proofbundle decision {init,emit,verify,inspect}`. `verify` follows the Phase B exit contract
  (0 crypto+structure OK · 1 crypto failure · 2 malformed/predicateType-confusion · 3 crypto OK but a supplied
  `--policy` was not satisfied). Without `--policy` the output shows `POLICY: NOT_EVALUATED`. `--version` now
  lists `predicates: eval-result/v0.1 decision-receipt/v0.1`.
- **Emission is RFC-8785 canonical** (JCS); verify never re-serializes and fails closed if the received payload
  is not its own canonical form (hash-binding rule).
- **Trust Policy v0.2** (additive): the v0.1 trust policy gains a `decision_receipt` section
  (`trusted_decision_makers`, `accepted_predicate_types`, `allowed_decision_types`/`verdicts`,
  `required_evidence_relations`, `require_policy_digest`, `require_external_anchor`/`allow_pending`). A v0.1
  policy stays valid unchanged under the v0.2 parser. The signer is matched to `trusted_decision_makers` by
  public key — `decisionMaker.id` is never believed on the JSON claim alone.
- **Non-claims (unchanged boundary):** a Decision Receipt does not prove the decision was correct, legal, safe,
  or fully informed; `actionOutcome=executed` without a separately signed outcome is self-assertion, reported
  as `action_outcome_proven=false`.
- **Decision `anchors[]` composition landed.** A `statement`-target anchor binds the SHA-256 content root
  over the exact signed payload bytes and is kept **detached** (outside the signed predicate — an anchor
  cannot live inside the bytes whose hash it commits; proofbundle#7 consensus, 2026-07-10). `verify` gains
  `--anchors`; with a policy's `require_external_anchor`/`allow_pending`, a pending (calendar-only) anchor
  is the absence of a time anchor → exit 3. See `docs/ANCHORS.md` and `tests/test_decision_anchors.py`.
- **The tamper / replay / fuzz matrix landed.** A systematic, deterministic sweep
  (`tests/test_decision_fuzz.py` — every signature byte, spread payload bytes, every required-field deletion,
  top-level type confusion, ten malformed-envelope classes, a wrong-key batch), plus audience/nonce replay
  gating (`tests/test_decision_hardening.py`, `tests/test_decision_verify.py`).
- Still deferred (not in this core): independent cross-implementation worked vectors over a decision object
  (MarkovianProtocol's reference anchor), iterated on proofbundle#7.

### Added — universal Statement content root `jcs-sha256-v1`, with a declared legacy mode (WP2, ADR 0002)
- A single shared content-root primitive now underlies both the decision-receipt path and the in-toto
  eval-result / test-result / SVR export paths: `statement_content_root` = SHA-256 over the **RFC-8785 (JCS)**
  canonical bytes of the **full** pre-signature Statement (`_type`, `subject`, `predicateType`, `predicate`).
  Signature/envelope bytes are never in the preimage, so a content root survives counter-signing and key
  rotation and a decision receipt composes byte-for-byte with an eval-result statement it cites. Exposed as the
  public `proofbundle.canonicalize_statement` / `proofbundle.statement_content_root` (shared `canonical.py`).
- The algorithm is a first-class **versioned** id (`contentRootAlg`, default `jcs-sha256-v1`), declared inside
  the signed payload so it cannot be flipped after signing. A verifier re-serializes with **exactly** the
  declared algorithm to confirm the payload is its own canonical form (fail-closed), never re-canonicalizes to
  compute a root, and never falls back between algorithms. An unknown algorithm fails closed — the
  anti-algorithm-confusion rule already applied to `merkle.hash_alg`.
- **Migration is a compatible evolution, not a cutover.** The historic `json.dumps(sort_keys=True)` wire is
  retained as an explicitly declared named mode `legacy-sortkeys-json-v0`. **Absent `contentRootAlg` ⇒ legacy**
  (never silently JCS), so every already-signed **2.0.0** eval-result / test-result / SVR receipt keeps
  verifying byte-for-byte; legacy verification is stdlib-only, so those receipts still verify on a base
  install. New receipts default to `jcs-sha256-v1`; verifying JCS canonicality needs the emit-side `[eval]`
  extra and is fail-closed without it.
- **Honest scope (No-Overclaim):** this is **not** a "universal migration complete." The eval-result /
  test-result / SVR producers now default to the new algorithm and a P0 activation test pins the boundary
  (`tests/test_intoto_content_root_migration.py`: a `sort_keys` root offered *as* `jcs-sha256-v1` is rejected;
  genuine JCS bytes declared legacy are rejected; an unknown algorithm fails closed). Still deferred: a CLI
  flag to select the content-root algorithm from the command line, and independent cross-implementation
  (MarkovianProtocol) worked interop vectors.

### Added — anchors v0.1: a `verify --require-anchor` relying-party gate + RFC 3161 hardening (WP4)
- The experimental external-time-anchor layer (`anchors[]`, shipped experimental-gated in 2.0.0) gains a
  relying-party gate: **`verify --require-anchor`** (optionally narrowed by `--anchor-type <type>`) turns "no
  verifying anchor (of that type)" into a failure — a gate layered OVER the crypto result, **exit 3 when
  unmet** (distinct from a crypto failure, exit 1), exactly like `--policy`. A **pending** anchor (an
  un-upgraded OpenTimestamps proof, a Merkle-only chia-datalayer level-i anchor) does NOT satisfy the gate
  unless `--allow-pending` is given; the gate follows the matched anchor's own status, not the global aggregate.
- **`anchors` is now a KNOWN top-level bundle field** (SPEC §7i, JSON Schema): formalized as EXPERIMENTAL and
  **detached** from the content root (an anchor attests *about* a receipt, never part of what it attests; the
  `receipt` target stamps the canonical root computed with `anchors` excluded). One-way compatibility is
  documented: a verifier built against an earlier revision lists no `anchors` field and, under
  `additionalProperties: false`, rejects an anchored bundle as malformed (exit 2) rather than ignoring it.
- **RFC 3161 TSA hardening:** the frozen TSA certificate chain is validated at the token's own `gen_time` (not
  the current wall clock), so a frozen token stays verifiable after the TSA certificate expires or rotates, and
  a certificate not valid at `gen_time` fails closed; a relying party MAY pin the TSA **policy OID** via
  `frozen.policyOid`, in which case a token whose `TSTInfo.policy` differs fails closed. New tests:
  `tests/test_cli_require_anchor.py`, `tests/test_anchors_rfc3161.py`, `tests/test_anchors_generic.py`.

### Verification discipline
- 683 tests (was 550 at 2.0.0): the decision-receipt suite (emit/verify/inspect, the tamper/replay/fuzz
  matrix in `tests/test_decision_fuzz.py` / `tests/test_decision_hardening.py`, `anchors[]` composition),
  the universal content-root migration pins (`tests/test_intoto_content_root_migration.py`: `jcs-sha256-v1`
  vs `legacy-sortkeys-json-v0`, the algorithm-confusion red matrix), and the anchors v0.1 relying-party gate
  (`tests/test_cli_require_anchor.py`, RFC 3161 policy-OID / certificate-expiry). Mutation gate: 39
  operators, all killed; the one documented-equivalent mutant still survives.

## [2.0.0] - 2026-07-09

First **2.0.0 final**. Consolidates the 2.0.0b1–b3 pre-release line (below) with the Phase B P0-core
hardening. **Breaking changes**, each with migration notes in its entry below: `merkle.hash_alg` is now
REQUIRED; `verify`'s human output replaces the bare `=> OK` with a labelled `CRYPTO:` / `POLICY:` /
`ASSURANCE:` / `LIMITATIONS:` block; exit code **3** is new (crypto OK but a supplied `--policy` was not
satisfied, distinct from a crypto failure). New: a machine-readable, fail-closed, offline **trust
policy** (`verify --policy`); an extended `--version`; a stable `verify --json` single-field contract.
The experimental TEE-attestation bridge and `anchors[]` stay experimental-gated as in the betas.

### Added — trust policy v0.1 + `verify --policy` (WP-B3)
- A relying party's trust decision is now first-class and machine-readable. `verify receipt.json
  --policy trust_policy.json` applies a fail-closed, offline trust decision OVER the crypto result:
  the signer (matched by **public key**, kid is a hint only), signature alg, bundle schema, Merkle
  hash alg, SD-JWT audience/nonce/key-binding, eval-claim freshness, and assurance level /
  pre-registration. Without a policy `verify` makes NO trust decision (`POLICY: NOT_EVALUATED`); a
  policy failure is the new exit **3** (crypto OK but policy unmet), distinct from a crypto failure
  (exit 1). A policy is never evaluated on bytes whose crypto failed.
- Policy format `proofbundle/trust-policy/v0.1` (`schemas/trust_policy_v0_1.schema.json`): snake_case,
  versioned, **fail-closed** (an unknown field is a parse error — a typo cannot silently weaken a
  policy), **offline** (no key is ever fetched). Worked example: `examples/trust_policy_strict.json`.
  `verify --json` gains `policy_ok`, `policy_id`, `policy_checks[]`.
- Honest v0.1 boundary: the `status` section is accepted so a policy can declare revocation intent,
  but `verify --policy` has no status-snapshot input in v0.1 — an ENABLED status requirement fails
  closed with a clear reason (evaluate revocation separately with `verify_status_snapshot`). A `--aud`
  flag that conflicts with the policy's `sd_jwt.expected_aud` is exit 2 (ambiguity, never a silent
  override).
- Docs: `docs/TRUST_ANCHORS.md` gains the machine-readable policy profile; the README quickstart shows
  a policy example with the explicit note that verify makes no trust decision without one.

### BREAKING — `verify` output separates CRYPTO / POLICY / ASSURANCE, and a new exit code 3 (WP-B2)
- **The human `verify` output no longer prints a bare `=> OK` / `=> FAILED`.** It now prints a
  context-labelled block so a crypto success can never be read as a policy pass or a truth verdict:
  `CRYPTO: OK|FAILED` (the only thing the offline core proves), `POLICY: NOT_EVALUATED (no trust
  policy supplied)`, `ASSURANCE: <issuer's verbatim self-declared level> | n/a`, and `LIMITATIONS:`
  (the honest "what a signature does NOT mean" line). **A script that greps `verify`'s stdout for
  `=> OK` must switch to `CRYPTO: OK`** (other subcommands — `verify-proof`, `show-eval`, etc. — keep
  their existing `=> OK` for now).
- **New exit code 3.** The `verify` exit-code contract is now `0` = crypto OK (and policy satisfied
  or none supplied), `1` = crypto/verification failure, `2` = malformed input, `3` = crypto OK but a
  supplied `--policy` was NOT satisfied. `--policy` itself lands with WP-B3; until then exit 3 cannot
  occur and `POLICY:` always reads `NOT_EVALUATED`. Documented in `proofbundle verify --help`.
- **`verify --json` gains a stable single-field contract** (additive; the existing `ok`/`checks`/
  `matrix`/`meaning` keys are unchanged): `schema_ok`, `signature_ok`, `merkle_ok`, `sd_jwt_ok`,
  `sd_jwt_issuer_verified`, `key_binding_ok`, `audience_ok`, `nonce_ok`, `freshness_ok`, `anchor_ok`,
  `witness_ok`, `status_ok`, `assurance_policy_ok`, `crypto_ok`, `policy_ok`, `assurance`,
  `warnings[]`, `limitations[]`. A check that did not run in the offline core path is `null` (not
  applicable), **never silently `true`** — in particular `sd_jwt_ok` is `null`, not `true`, when an
  SD-JWT's issuer signature was not checked (no issuer key supplied), with a warning saying so.
- **Hardening (verify-lens review):** `decode_eval_claim` now rejects an out-of-enum `assurance_level`
  on the verify path (closing an ASSURANCE-line injection where a hand-signed claim could embed
  newlines to forge fake `CRYPTO:`/`POLICY:` lines); deeply-nested JSON maps to the documented
  malformed exit (2) instead of a raw `RecursionError`; the error-path JSON carries the full field
  contract so integrators can always read `crypto_ok`.
- **Migration**: replace any `verify`-stdout `=> OK` grep with `CRYPTO: OK`; treat exit 3 as a new
  (policy) outcome distinct from 1 (crypto failure). No bundle format change.

### BREAKING — `merkle.hash_alg` is now a REQUIRED field in SPEC.md and the JSON Schema (WP-B1)
- **The verifier already rejected a missing `hash_alg`** since v1.6 (`bundle.py` `_require`d it) — this
  closes the documentation/schema half of that gap. `SPEC.md` §5 now states `hash_alg` as `required: yes`
  (was `no`, contradicting the code) with an explicit anti-algorithm-confusion MUST: a verifier MUST NOT
  silently default a missing value, and a future hashing algorithm MUST register its own distinct value.
  `schemas/proofbundle_v0_1.schema.json` adds `hash_alg` to `merkle.required` to match.
- **Who this actually breaks:** any consumer that validated bundles against the **JSON Schema only**
  (not `proofbundle verify`) previously accepted a pre-v1.6 bundle missing `hash_alg` that the real
  verifier already rejected — that schema-only path is now correctly stricter, matching the code.
  Every bundle any proofbundle emitter has ever produced since v1.6 already carries `hash_alg`, so this
  affects only hand-authored or archived pre-v1.6 bundles.
- **Migration**: add `"hash_alg": "sha256-rfc6962"` to the bundle's `merkle` object. The verifier's error
  message for a missing field now states this explicitly (`bundle.py::_require_hash_alg`, shared by
  `verify_bundle` and `recompute_merkle_root_b64` so the two call sites cannot drift apart again).
- **Attribution correction**: this entry is a SEPARATE breaking fix and does not close any tracked
  issue. Issue #28 is scoped exclusively to `--version` printing the pinned spec revision — see the
  entry directly below, which is the one that actually closes it.

### BREAKING — `proofbundle --version` output is now multi-line (closes #28)
- Was a single line (`proofbundle <version>`). Now four lines: package version, the pinned `SPEC.md`
  revision (new `SPEC_REVISION` constant next to `__version__`, kept in sync with SPEC.md's own
  `Revision:` header by a doc-truth test), the JSON Schema id, and a best-effort, fail-safe list of
  optional extras actually usable in this install (`eval`/`sdjwt`/`anchors[beta]`/`pq`/`inspect`/
  `experimental` — a missing/broken extra is silently omitted, never a traceback). **A script that
  parsed `--version`'s stdout expecting exactly one line must be updated**; the exit code (0) and the
  first line's `proofbundle <version>` prefix are unchanged.

## [2.0.0b3] - 2026-07-06  (BETA / pre-release)

### Added — external time / provenance anchors (the `anchors[]` layer, EXPERIMENTAL)
- **`chia-datalayer/v1`** (first-party): a fail-closed offline verifier for a canonical root proven included
  under a published Chia DataLayer store root via a level-i Merkle inclusion path. Ships as a built-in anchor
  type; a level-i-only proof reports `warn` (does not satisfy `--require-anchor`). See `docs/ANCHORS.md`.
- **`markovian-provenance/v1`** (third-party worked example, external contributor MarkovianProtocol, #18):
  a wallet-attributable, Bitcoin-anchored stamp registered through `register_anchor_type`. It binds the
  committed data to a wallet (`merkle_root = sha256(data_hash:salt:wallet)`) and delegates the Bitcoin time
  proof verbatim to the built-in OpenTimestamps verifier (compose, not reinvent). Opt-in via `register()`;
  not wired into the built-in set by design.
- README now documents the `anchors[]` extension layer and the `register_anchor_type` bring-your-own-type
  interface (the `[anchors]` extra), with an honest "v2.0 beta" label.

### Changed
- **Repo hygiene**: removed a committed `.venv-anchors/` tree from tracking (cleared 59 OSSF-Scorecard HIGH
  alerts); enabled auto-delete-head-branches, Dependabot alerts/updates, and secret-scanning push protection.
- Type checker (`mypy src`) is clean again after the third-party anchor addition (narrowed envelope fields).

## [2.0.0b2] - 2026-07-05  (BETA / pre-release)

### Added — in-toto eval-result attestation export (PROPOSED; under discussion in-toto/attestation#565)
- **`proofbundle intoto <receipt>`** exports an eval receipt as a DSSE-signed in-toto Statement v1 with
  the dedicated **`eval-result/v0.1`** predicate (vendor namespace `https://b7n0de.com/attestation/eval-result/v0.1`
  for now — the migration path to an `in-toto.io` namespace is documented and needs a redirect PR only
  there). The predicate extends the community `test-result` shape with a threshold-based `claims[]`,
  privacy-preserving **salted-commitment** subjects, and an optional binding to the external signed
  receipt. DSSE `payloadType` is the canonical `application/vnd.in-toto+json`; verification accepts
  standard and url-safe base64.
- **Subject profiles** (`--subject-profile`): `receipt` (default — binds without revealing the model),
  `public-model` and `release-gate` (a disclosed artifact via `--subject-name`/`--subject-sha256`, the
  SLSA "deploy only if the eval passed" hook). Each profile documents what the subject IS.
- **Commitment-only guarantee**: the export refuses a claim that still carries a plaintext identifier or a
  raw salt (fail-closed), is deterministic (byte-identical statement for identical input), and refuses an
  incomplete receipt. New adversarial tests + a salt-leak mutation operator.
- Status is **PROPOSED, not standardized** — see docs and the homepage label. No new runtime dependency;
  the export stays in the pure-Python DSSE path.

### Added — in-toto SVR export (Summary Verification Result, svr/v0.1)
- **`proofbundle svr <receipt>`** emits an in-toto **SVR** (`https://in-toto.io/attestation/svr/v0.1`) for a
  receipt — but ONLY after a real, passing verification. It carries only PASSING property strings
  (`PROOFBUNDLE_SIGNATURE_VALID`, `PROOFBUNDLE_RECEIPT_UNCHANGED`, `PROOFBUNDLE_THRESHOLD_MET`, and, when
  genuinely verified, `PROOFBUNDLE_SAMPLE_ROOT_VALID` / `PROOFBUNDLE_PREREG_BOUND` / `PROOFBUNDLE_ANCHOR_VALID`)
  — type-generic, never a vendor/service name. A missing check produces NO property.
- **No SVR on FAIL**: the export refuses (fail-closed) if the receipt is not a valid eval receipt, does not
  cryptographically verify, or did not pass its threshold. SVR has no FAILED form — a PASSED|FAILED verdict
  would be a VSA, deliberately not implemented here (documented). `verifier.policy` ({uri, digest}) is the
  optional v0.1 extension field. WATCH: in-toto/attestation#551 (verifier.policies as required) is an open
  SVR-v0.2 risk. New adversarial tests + an SVR-passing-only mutation operator.

### Added — external time-anchor layer (EXPERIMENTAL; the `[anchors]` extra)
- **`proofbundle.anchors`** — a generic, fail-closed layer for external time anchors on a receipt. Two
  targets, never mixed: `preRegistration` (the commitment existed before the run — the in-toto#565
  backdating point) and `receipt` (existed from time T). Missing anchors → SKIP; present → a root
  mismatch, unknown type, or broken proof is a FAIL, never silent; `--require-anchor <type|any>`. The
  base install stays anchor-free (only `cryptography`); a receipt with no anchors verifies unchanged.
- **RFC 3161 TSA anchor** (`anchors_rfc3161`): offline verify (`rfc3161-client`) against the TSA chain
  **frozen into the anchor at emit time** (a TSA can rotate — FreeTSA rotated March 2026). Proven
  against a real captured FreeTSA token fixture incl. the frozen-chain rotation test.
- **OpenTimestamps anchor** (`anchors_ots`): honest lifecycle — a PENDING proof is a **WARN**, never a
  full anchor; an upgraded proof needs a Bitcoin block header (a local pruned node) to verify offline,
  and without one it is reported as upgraded-unverified, never a silent pass. Pending vs upgraded are
  distinguished.
- **Extension mechanism** (`register_anchor_type`) for third-party anchor types with a fail-closed
  verify callable. `docs/ANCHORS.md`. A dedicated CI `anchors` job exercises the TSA + OTS tests.

### Added — verify check matrix + honest meaning block
- **`proofbundle verify --matrix`** prints the per-check status matrix plus an explicit "what `=> OK`
  proves / does NOT prove" block (authenticity + integrity of the bytes, never the truth of the result —
  see `NON_CLAIMS.md`). The same `meaning` / `nonMeaning` fields and a `matrix` array are ALWAYS present
  in `verify --json`. Additive and non-breaking: the existing `ok` / `checks` keys are unchanged and the
  default human output is identical unless `--matrix` is passed.
## [1.9.2] - 2026-07-05

Verify-path hardening from an independent six-lens review, plus a public-trust documentation pass.
No wire-format change; no new features.

### Fixed — verify-path completeness (both are stricter, never looser)
- **Eval-claim field set enforced on the VERIFY path** (`decode_eval_claim`, review F3). The exact
  key set (`_REQUIRED` present, no unknown fields) was enforced only when emitting; a hand-signed
  claim missing a required field or carrying an unknown one decoded fine. It is now rejected
  fail-closed. **SemVer note:** claims that were previously *accepted* on decode despite a missing
  or unknown field are now *rejected* — this matches the documented `_REQUIRED` contract, and every
  claim `emit_eval_receipt` produces still decodes unchanged. New regression test + mutation operator.
- **Downgrade trap closed** (`verify_bundle`, review F4): when a relying party passes
  `expected_aud`/`expected_nonce` (CLI `--aud`/`--nonce`) but the bundle carries no verifiable Key
  Binding JWT, verification now FAILs closed with an `sd-jwt-key-binding` check instead of returning
  `=> OK` — the requested RFC 9901 §7.3 replay/audience binding could not be enforced. Backward
  compatible: verifiers that pass no `expected_*` are unaffected. Test + mutation operator.
- **`show-eval`** no longer risks a raw traceback on a malformed claim (the F3 fix makes decode
  reject it first); regression test pins the "never a raw traceback" contract.

### Added — CI gates
- **Claims-hygiene gate** (`scripts/claims_hygiene_check.py`): fails when a forbidden marketing
  overclaim appears in the docs outside a negation (the exact phrase list lives in the script).
- **Doc-link gate** (`scripts/doc_link_check.py`): fails on a broken internal Markdown link.

### Changed — public-trust documentation (truth pass)
- README leads with the receipt kernsatz + a plain-language section; the stale hardcoded test count
  is gone (guarded). New `docs/INSPECT_HAPPY_PATH.md` — the one Inspect-to-receipt walkthrough,
  every command verified against the real API. CITATION version synced + abstract bounded (with a
  version==pyproject test). SECURITY gains a coordinated-disclosure window. COMPLIANCE EU AI Act
  high-risk timeline updated for the Digital Omnibus (2027-12-02 / 2028-08-02). The 95% detection
  claim now states its externally-sourced-challenge condition. Internal review/outreach drafts
  archived out of the repo root.

## [2.0.0b1] - 2026-07-02  (BETA / pre-release)

### Added — TEE-attestation bridge (EXPERIMENTAL v2.0 preview; opt-in, unstable)
- **`proofbundle.experimental.enclave`** (install extra `[experimental]`): make
  `assurance_level = enclave_attested` verifiable. Following the IETF RATS Passport model
  (RFC 9334), a Verifier appraises raw TEE evidence (Intel TDX / NVIDIA GPU) out of band and signs
  an **EAT** (RFC 9711, JSON/JWS, EdDSA); `verify_enclave_attestation` checks it OFFLINE — signature
  under the Verifier key (a supplied trust anchor), `typ`/`alg`, and `eat_nonce ==
  enclave_binding_for(receipt)` (the binding = base64url SHA-256 over the receipt's exact signed
  payload, which the enclave places in its quote user-data / TDX `REPORTDATA` / GPU report nonce).
  The trustworthiness `tier` is REPORTED verbatim (stand-in for the still-draft AR4SI/EAR), never
  interpreted. **Honest scope:** proofbundle does not parse or appraise raw hardware evidence — that
  is the Verifier's role; it verifies the Verifier's signed result + the receipt binding. Standards-
  native (RFC 9334 + 9711), offline, vendor-neutral — vs proprietary certificate + ledger approaches.
  CLI `proofbundle verify-enclave`; `docs/EXPERIMENTAL_ENCLAVE.md`; `examples/experimental_enclave.py`.

### Experimental gating (so nothing depends on a preview by accident)
- Everything lives under `proofbundle.experimental`, is NOT re-exported from the top-level package
  (must be imported explicitly), and emits an `ExperimentalWarning` once on import. The stable v1.x
  trusted core imports none of it.

### Beta-release discipline
- Version `2.0.0b1` (PEP 440 pre-release — `pip install proofbundle` will NOT pull it; use `--pre`
  or an exact pin). The stable **v1.x line remains the default**; the experimental bridge is doubly
  gated (pre-release channel + `[experimental]` extra). No wire-format or behavior change to any v1
  path. Promote toward `2.0.0` only after the preview stabilizes and, ideally, an external audit.

### Verification discipline
- 320 tests (303 on the v1.9.1 base; +16 enclave and +1 EAT-verifier fuzz case: binding, verify roundtrip, freshness,
  and an adversarial red matrix — wrong verifier key, cross-receipt binding, typ/alg confusion,
  profile mismatch, claim tamper, garbage, string-exp — plus the experimental-gating pins). Mutation
  gate: 31 operators (+1 receipt-binding), all killed. Parser fuzz extended to the EAT verifier.

### Notes
- Built on the byte-exact upstream **v1.9.1** tag (which carried extra release-review hardening:
  symmetric `self_issued` type-guard, beacon flag mutual-exclusion + u64 round bound).
- Preview roadmap: migrate `tier` to AR4SI/EAR when they become RFCs; optional CWT/COSE encoding;
  reference Verifier profiles for TDX + GPU (kept out of the core — they pull vendor tooling).
## [1.9.1] - 2026-07-02

### Added — closing the last small review-backlog items
- **Status-list trust-anchor separation** (external review #8/#12): `verify_status_snapshot` gains
  an optional `receipt_issuer_pubkey` and reports `self_issued=True` when the status list is signed
  by the SAME key as the receipt — an issuer attesting its own "still valid" state carries no
  independent revocation assurance. Reported, not fatal (the relying party decides); a distinct,
  independently-operated status authority is the stronger anchor. New THREAT_MODEL row + statuslist
  docstring + tests + mutation operator.
- **`make coverage`** target (line coverage of the core over the suite; needs `coverage`).
- **docs/GLOSSARY.md** — proofbundle in plain terms for a developer without a crypto background
  (the review's Iteration-2 request): the 30-second picture, five steps in order, and a term list,
  plus "what `=> OK` means and doesn't". Linked from the README docs table.

### Verification discipline
- 303 tests (was 299): +3 self-issued separation (not-asked → None, same-key → True, distinct-key →
  False). Mutation gate: 30 operators (+1 self_issued compare), all killed.

### Notes
- No wire-format or verify-behavior change for existing callers — `self_issued` is a new optional
  report; omitting `receipt_issuer_pubkey` behaves exactly as before.
- Remaining backlog is now owner-only (a binary inspect_ai `.eval` fixture for `make full-demo`,
  README design assets, GitHub branch-protection / `pypi` reviewer settings) or human actions
  (outreach, external audit, JOSS paper) — all tracked in REVIEW_v1.6.md and RELEASE.md.

## [1.9.0] - 2026-07-02

### Added — public-beacon audit mode + a rewritten README
- **Public-randomness beacon audits** (`proofbundle.beacon`, CLI `audit-challenge
  --beacon-randomness/--beacon/--round`): the third per-sample challenge mode (after auditor-nonce
  and self-challenge) is now formalized. Derive the challenge from a drand / NIST beacon pulse —
  `nonce = SHA-256("proofbundle/v1.9/beacon-nonce" ‖ beacon_id ‖ round ‖ pulse)` — so the audit is
  **non-interactive** (no live auditor) and **publicly re-derivable** (anyone re-fetches the same
  pulse and gets the same indices). A pulse from a round emitting after the receipt's signed
  timestamp cannot have been ground against (RFC 3797 pattern). `AuditRequest.as_dict()` publishes
  the beacon id + round + indices alongside the receipt. Offline-first: the relying party supplies
  the pulse bytes and validates the beacon's own signature + round timing out of band (stated
  honestly — this module does not verify the BLS/RSA beacon signature). `examples/persample_audit.py`
  gains a beacon variant. SPEC §7g.
- **README rewritten for humans** (556 → ~130 lines): problem-first, a 60-second offline try, the
  "what it proves / does not prove" table up top, one architecture diagram, a features-at-a-glance
  list, and a docs table — the exhaustive standards enumeration and deep-dives moved to the linked
  SPEC/EVAL_CLAIM/INTEROP/FAQ docs. Closes the review's "a fresh reviewer gets lost / quickstart
  needs a checkout" finding.

### Verification discipline
- 299 tests (was 289 test-methods upstream; +10 beacon, roundtrip/binding/red-matrix + CLI mode +
  a pinned nonce-construction KAT). Mutation gate: 29 operators (+1 beacon round-binding), all
  killed; the documented-equivalent survivor still survives.

### Notes
- Built on the byte-exact upstream **v1.8.0** tag (which carried release-review hardening — verify-
  path TOCTOU single-read, `merkle.hash_alg` required, comparator/threshold enforcement in
  `decode_eval_claim`, HF value-check fail-closed, per-sample canonical-order with native-int
  compare, `prereg --check` authenticated, tlog-proof ASCII-digit guard). No wire-format change;
  the beacon mode is a new way to *derive* an existing challenge, not a format change.
## [1.8.0] - 2026-07-02

### Added — provenance, pre-registration, and credibility (external-review backlog P1/P2)
- **Adapter provenance hardening** (`adapters/_provenance.py`): inspect_ai, lm-eval and promptfoo
  claims now record, where the framework exposes it, a stable **run-id**, a **config-hash**
  (`<alg>:<hex>` over canonical config JSON — RFC 8785 JCS when available, deterministic
  sort-keys fallback, labeled either way), and the **log-native timestamp** (inspect
  `eval.created`, lm-eval's Unix-float `date`, promptfoo `evaluationCreatedAt`) instead of only
  the caller's timestamp — this ties the receipt's descriptive run_timestamp to the value the harness's
  own log recorded, narrowing (not eliminating) the "a self-attesting issuer can backdate" gap: a dishonest issuer
  who controls the log can still forge the log-native field. lm-eval
  also carries its native `task_hash`.
- **`proofbundle prereg <protocol>`** (`prereg.py`, CLI): commit to an eval protocol BEFORE the
  run — sha256 over the RAW file bytes (the accepted document-commitment convention: git blob,
  RFC 6962 leaf, in-toto DigestSet all hash raw bytes) → goes in the claim's `prereg_sha256`.
  `--check <receipt>` verifies a disclosed protocol matches. This is the anti-cherry-picking
  mitigation for best-of-many runs (per-sample audit covers within-run doctoring).
- **HF value-consistency guard** (`hf_evals.to_eval_results_entry`): a published `value` that
  contradicts the receipt's signed pass/fail verdict (value `<comparator>` threshold ≠ `passed`)
  is refused unless `allow_value_mismatch=True` — a Hub reader sees the value, not the token.

### Added — security tooling & credibility docs
- **CodeQL** workflow (advanced setup, SHA-pinned to codeql-action v4.35.1 — default setup can't
  be pinned) and **OpenSSF Scorecard** workflow (scorecard-action v2.4.3, publishes results).
- **Property-based parser fuzzing** (`tests/test_fuzz_parsers.py`, Hypothesis): every
  attacker-controlled parser (tlog-proof, checkpoint, cosignature, SD-JWT, KB-JWT, status-list)
  must return-or-raise-a-proofbundle-error on ANY input, never an uncaught crash. (Manually
  smoke-tested over ~16k hostile inputs where Hypothesis was unavailable.)
- **docs/FAQ.md** (skeptics), **docs/TRUST_ANCHORS.md** (where every anchor comes from),
  **docs/PROJECT_BRIEF.md** (funding one-pager + 3 grant-abstract seeds), **examples/README.md**.
- **COMPLIANCE.md**: regulatory-safe wording, an 8-item "claims that must NEVER be made" list, an
  honest capability→concept→gap mapping, and a legal/governance FAQ — standards status verified
  2026-07 (EU AI Act Art. 12 in force 2026-08-02; NIST AI RMF 1.0 + GenAI Profile; no eval-attestation
  standard exists).
- **INTEROP.md**: at-a-glance comparison tables vs Sigstore Rekor, Inspect logs, in-toto
  test-result, ValiChord, plus the ≤25-word niche + its explicit bound.
- **EVAL_CLAIM.md**: field table gains `provenance` and `samples` rows; stale "3.9-safe" comment removed.

### Verification discipline
- 289 tests (was 263): +provenance (config-hash determinism, log-native timestamp, run-id per
  adapter), +prereg (raw-bytes hash, match/mismatch, CLI roundtrip, trailing-byte tamper),
  +HF value-consistency (consistent ok / inconsistent refused / override / non-eval skip),
  +parser fuzz module. Mutation gate: 28 operators (+2 for prereg + HF checks), all killed.

### Notes
- No wire-format or verify-behavior change; `provenance`/`samples` are additive optional claim
  fields (already schema-additive since v1.4/v1.5). CodeQL/Scorecard SHAs are current as of
  2026-07-02 — re-verify before relying on them (RELEASE.md).
## [1.7.0] - 2026-07-02

### Changed — release supply-chain hardening (review P1: attested artifact must equal published artifact)
- **`release.yml` now builds ONCE and publishes the attested bytes.** Previously the `publish-pypi`
  job ran `python -m build` a second time, so the SLSA/PEP-740 provenance covered a *different*
  build than what landed on PyPI. Now `build-and-attest` uploads the exact `dist/` via
  `actions/upload-artifact`; `publish-pypi` downloads it and a **sha256 gate** fails the upload
  unless the bytes equal the attested subject digests. A `SHA256SUMS` file is attached to the
  GitHub Release. This closes the single most important supply-chain gap for a tool whose whole
  premise is provenance.
- **`pypi` GitHub Environment** now carries a `url:` and is documented to require reviewer approval
  (RELEASE.md) so a `v*` tag cannot publish unreviewed; top-level workflow `permissions` reduced to
  `contents: read` with per-job escalation (least privilege).
- All new actions SHA-pinned (`upload-artifact` v4.6.2, `download-artifact` v4.3.0).

### Added
- **RELEASE.md** — one-time setup (Trusted Publishing, `pypi` environment reviewers, branch
  protection, assets, badge gating) + per-release checklist + a "verify a published release" recipe
  (`gh attestation verify`).
- **docs/REVIEWERS.md** — a 30-minute adversarial audit path: the trusted-core map, the two external
  correctness anchors (RFC 6962 vectors + real Rekor proof), the mutation gate, and an explicit
  "where the bodies are buried" list of invitations to attack.
- **CI `crypto-floor` job** — installs `cryptography==42.*` (the declared floor) and runs the suite
  + `proofbundle demo`, proving the lower bound actually works, not just the latest.
- **External-review issue template** (`.github/ISSUE_TEMPLATE/external_review.md`).

### Fixed — scope-honesty (review Lens 1)
- Badges that render broken/false before the first PyPI release (PyPI version/pyversions/downloads,
  SLSA, PEP 740) are commented out with a note to enable them on first publish (RELEASE.md).
- SECURITY.md attestation language moved to conditional ("once the first release is published, each
  release WILL carry…") — no release exists yet, so present-tense claims were premature.

### Notes
- No wire-format change. NOTE: the released v1.7.0 additionally carried pre-release-review security fixes
  (decode_eval_claim TOCTOU single-read, verify-side comparator/threshold validation, persample native-id ordering)
  that DO change verify-path behavior vs v1.6.1 — see the v1.8.0 section and commits. This is a
  release-engineering + docs release. The `pypi` environment reviewers and branch protection are
  GitHub settings the maintainer must apply (documented, not code).
## [1.6.1] - 2026-07-02

### Added — developer experience (review backlog P0-DX; no security or format change)
- **`proofbundle demo`** — a pip-only, offline, in-memory demo: an honest receipt verifies, six
  independent tampers (payload rewrite, signature graft, public-key swap, Merkle-root swap,
  leaf-index shift, dropped `hash_alg`) each verify FAILED, and the per-sample audit catches a
  swapped sample. Exits non-zero if any guarantee breaks, so it doubles as a fail-closed smoke
  test. `--json` for machine output. No files, no network, no optional extras. Closes the
  "quickstart requires a git checkout" gap — the README quickstart now works after a bare
  `pip install`.
- **`examples/persample_audit.py`** — the v1.5 per-sample feature finally has a runnable example:
  build a 1000-sample tree, sign the root into a receipt, auditor challenges 20 random indices
  with a fresh nonce, all openings verify, a swapped-sample opening is rejected.
- **`scripts/demo_tamper.sh`** + Makefile targets `demo`, `tamper-demo`, `persample-demo`,
  `full-demo` (the old real-log demo), `mutation`, `examples`.
- **docs/DEMO.md** — three tiers (pip-only / checkout / extras), each with expected output and
  the reviewer forced-random-sample-check CLI recipe.

### Verification discipline
- 254 tests (was 251): `tests/test_demo.py` pins that all six tampers are caught and none missed,
  in both text and JSON modes and via the CLI entry point.
## [1.6.0] - 2026-07-02

### Fixed — external Principal-Security review (6 lenses + orthogonal iterations); every fix
has a regression test and a mutation operator
- **CRITICAL (P0) — bearer-downgrade via issuer-key omission** (`bundle.py`): the holder-binding
  check was gated on issuer-signature verification, so an attacker could strip the KB-JWT AND
  drop `sd_jwt_vc.issuer_public_key_b64` to silently downgrade a `cnf`-bound credential to a
  passing bearer token. Now a `cnf`-carrying SD-JWT whose issuer cannot be verified is REFUSED
  (`sd-jwt-key-binding` = False), fail-closed. Plain SD-JWTs without `cnf`/KB keep the documented
  no-key path. Proven closed by an executed attack (`test_bundle_cnf_bound_no_issuer_key_fails_closed`)
  + backward-compat pin.
- **P1 — verify-side invariants** (`evalclaim.decode_eval_claim`): the `samples.n == n`,
  `leaf_alg` and 32-byte-root checks (previously only in the emitter) now run on the VERIFY path
  — a hand-signed claim that lies about the committed tree size is rejected. New
  `decode_eval_claim(bundle, *, expected_context=...)` enforces the signed `context_binding`
  (cross-context replay guard); it was signed but never checked.
- **P1 — status-list freshness** (`statuslist.py`): a token with neither `exp` nor `ttl` is no
  longer reported "fresh forever" — `fresh` is `None` (cannot judge) so a stale pre-revocation
  snapshot cannot masquerade as current; `exp`/`ttl` must be integers when present (a string that
  looks like an expiry but never enforces is rejected, not silently ignored).
- **P1 — `merkle.hash_alg` is now REQUIRED** (`bundle.py`): a silently-defaulted algorithm
  contradicted the "reject anything non-canonical" posture and would mask alg-confusion in a
  future multi-alg version.
- **Docs/honesty**: softened the Rekor v2 witnessing claim to "is integrating" (matches the
  Sigstore GA post, which says witnessing is coming, not shipped); quickstart notes that
  `examples/` ships in the repo, not the wheel; SECURITY.md `0.x`→`1.x`; persample module
  docstrings de-drifted from "(v2.0)" to "(v1.5)" (wire constants unchanged).

### Changed
- **Development Status classifier → 4 - Beta** (was Alpha): SemVer-committed, 251 tests, stable
  lazy public API. COMPLIANCE.md still says do not rely on it as a sole compliance control.

### Verification discipline
- 251 tests (was 242): +9 for the fixes above (P0 attack + backward-compat, verify-side samples
  matrix, context_binding enforcement, status freshness/typing). Mutation gate: 26 operators
  (+4 for the v1.6 fixes), all killed; the one documented-equivalent mutant still survives.
- A full REVIEW_v1.6.md accompanies this release: executive verdict, top-10 weaknesses, P0/P1/P2
  plans, README-rewrite proposal, ≥20-row test matrix, 20-issue backlog, outreach pack, pitches.

### Not yet done (tracked in REVIEW_v1.6.md issue backlog, honest)
- `make tamper-demo` + `proofbundle demo` (pip-only) + a per-sample example are DESIGNED and
  specified in the review but not yet shipped in this patch (they are P0 DX, not security).
- Release supply-chain: attested artifact must equal published artifact (`release.yml` rebuilds);
  `pypi` environment reviewers; badges gated behind first publish. Specified, not yet wired.

## [1.5.0] - 2026-07-02

### Added — per-sample receipts (the THREAT_MODEL's named gap, closed; design verified against
TRUCE arXiv:2403.00393, RFC 9901, RFC 6962/9162, RFC 3797, PoR literature)
- **`proofbundle.persample`**: `build_sample_tree` commits every individual sample of a run into
  an RFC 6962 SHA-256 Merkle tree (leaf = 0x00-domain-separated hash over a base64url disclosure
  `[salt, record]` — the RFC 9901 digest mechanic, so verification never canonicalizes JSON).
  Canonical leaf order with the position `idx` embedded INSIDE each committed record; per-leaf
  ≥128-bit salts derived HMAC-SHA-256-as-PRF from ONE holder-kept `tree_secret` (never in the
  receipt; one shared salt would be burned by the first opening — eval answer spaces are tiny).
- **Signed `samples` claim field** `{root_b64, n, leaf_alg}` (schema: additive optional;
  `samples.n` MUST equal the claim's `n`). **Measured, documented finding:** an RFC 6962
  inclusion proof binds n only up to path-shape equivalence (index 4 of a 10-leaf tree verifies
  under any claimed n′ ∈ [9..16]) — the SIGNATURE is the size-truth anchor, and the test suite
  pins the coincidence window so it stays measured fact, not folklore. SPEC §7g.
- **Openings + audit protocol**: `sample_opening` / `verify_sample_opening` (inclusion under the
  signed root, disclosure decode, `record.idx == index` replay guard — the case where the lie
  sits inside a validly-committed leaf, i.e. a lying PRODUCER, is red-tested);
  `audit_challenge` derives k distinct indices via SHA-256 domain-separated seed + HMAC counter
  expansion + rejection sampling (`_map_draw` isolated as a pure function because the rejection
  branch fires with p≈1e-19 and can only be tested in isolation). Modes: auditor nonce
  (grinding-impossible), public beacon (RFC 3797-style), self-challenge (sanity only —
  re-salting grinding bound ≈ g·(1−m/n)^k stated, never hidden; the CLI warns actively).
  PoR soundness table in docs (k=300 → 95% @ m=1%, k=459 → 99%). CLI: `audit-challenge`,
  `verify-opening`. The protocol domain strings are pinned at `proofbundle/v2/*` (protocol
  identifiers, independent of the package version).
- **Sample extractors** (`adapters.samples`): lm-evaluation-harness `--log_samples` JSONL
  (consumes its native `doc_hash`/`prompt_hash`/`target_hash` — wrapped INSIDE the salted leaf,
  since upstream hashes are unsalted and dictionary-attackable alone) and promptfoo v3 rows.
  Two-layer hiding: leaves carry content hashes/compact results, never benchmark plaintext.

### Verification discipline
- 33 new tests (209 → 242): byte-exact pins (salt derivation, RFC 6962 leaf prefix, independent
  challenge re-derivation, rejection sampling in isolation), roundtrips, and an adversarial
  matrix incl. the lying-producer embedded-idx forgery, disclosure/proof tamper, root/n
  confusion, and the pinned n′ shape-equivalence window; 6 new mutation operators (22 total,
  all as expected).
- **Mutation-gate hardening after a real incident**: a same-size mutation on a coarse-mtime
  filesystem left a stale `.pyc` that silently survived restoration and skewed three
  measurements; the runner now purges `__pycache__`, runs with `-B`/PYTHONDONTWRITEBYTECODE,
  and force-touches source mtimes (existing caches are READ even under `-B`).

### Notes
- Versioning: per-sample receipts are strictly additive (no API or format break; v1.4 receipts
  verify unchanged) — hence a MINOR release per SemVer, deliberately NOT a marketing-major.
- Honest residuals (THREAT_MODEL updated): best-of-many full runs remain undetectable without
  pre-registration; opened samples are burned (auditor-directed openings only).

## [1.4.0] - 2026-07-02

### Added — distribution (formats verified against primary sources, 2026-07-02)
- **promptfoo adapter** (`proofbundle.adapters.from_promptfoo_results`): reads a promptfoo
  `eval -o results.json` (summary **version 3**, verified against promptfoo main
  `src/types/index.ts` OutputFile/EvaluateSummaryV3/EvaluateStats) into a `pass_rate` receipt —
  successes/(successes+failures+errors) as a fixed-point decimal, model commitment over the
  sorted provider-id set, dataset commitment over canonical `config.tests` JSON (the test suite
  IS the dataset; promptfoo's internal datasetId is not exported). File-based, no promptfoo
  import. Legacy v1/v2 summaries (a different `table` shape) are REJECTED with a clear message —
  never half-parsed; "v4" is promptfoo's storage version and never appears in output files.
  Committed realistic fixture.
- **Hugging Face Community Evals bridge** (`proofbundle.hf_evals`, CLI `proofbundle hf-token`):
  `receipt_token(bundle)` packs a receipt as `pb1.` + base64url(zlib(bundle JSON)) — the token
  IS the receipt, verified offline by `verify_receipt_token` (zip-bomb-capped, fail-closed);
  `to_eval_results_entry` + `eval_results_yaml` emit schema-faithful `.eval_results/*.yaml`
  entries (spec: hub-docs eval_results.yaml), refusing non-verifying receipts, with a strict
  purpose-built YAML serializer (JSON-escaped scalars — dates and tokens cannot be misparsed).
  **Honesty boundary, stated in code and docs:** HF's *verified badge* is decided server-side by
  HF (HF Jobs + inspect-ai); its token format is not public. The `pb1.` token is
  proofbundle-verifiable and schema-valid in the `verifyToken` field — it is NOT presented as
  HF-endorsed, and the receipt link belongs in `source.url`/`notes` either way.
- **INTEGRATIONS.md**: promptfoo + HF sections; `OUTREACH_pr_every_eval_ever.md` — a draft
  upstream PR description offering the EEE→receipt converter (shipped since v0.9) to
  evaleval/every_eval_ever (the human submits, per that project's contribution norms).

### Changed — BREAKING (deliberate, roadmap item)
- **Python floor is now 3.10** (`requires-python >= 3.10`): Python 3.9 reached end-of-life
  2025-10-31; the ecosystem (NumPy, inspect_ai, current cryptography features) has moved. The
  redundant `python_version >= "3.10"` markers on the inspect extras are gone; CI drops the 3.9
  lane (matrix is now 3.10–3.14). Code changes: none required — the codebase was already
  3.9-clean, the floor change is packaging metadata + CI.

### Verification discipline
- 21 new tests (188 → 209): promptfoo green fixture → verified receipt, data-minimization pin
  (no exact score in the claim), dataset-commitment sensitivity, version-gate red tests,
  zero/negative/bool count guards; `pb1.` token roundtrip, tamper-inside-token, garbage/zip-bomb/
  non-dict red matrix, YAML structure + JSON-scalar parseability pins, broken-receipt refusal.
- 4 new mutation operators (16 total, all as expected): HF broken-receipt guard off, token-verify
  fake OK, promptfoo version gate off, failures dropped from pass_rate.

## [1.3.0] - 2026-07-02

### Security & correctness hardening (full 6-lens re-audit of the whole tool before tag, 2026-07-02)
- **CRITICAL — holder-binding downgrade closed.** A credential issued with a `cnf` holder key now FAILS
  verification if the KB-JWT is stripped (RFC-9901-legal no-key-binding form) — previously a bearer replay of
  a proof-of-possession credential verified OK. Bundles without `cnf` stay backward-compatible.
- **HIGH — RFC 9901 §7.3 audience/replay binding reachable through the public API.** `verify_bundle` (and CLI
  `verify --aud/--nonce`) now accept and enforce `expected_aud`/`expected_nonce`; before, the aud/nonce
  enforcement existed only on the internal `verify_key_binding` helper no public caller could reach.
- **HIGH — holder-binding check requires a verified issuer signature.** The `sd-jwt-key-binding` check now runs
  only when `sd_jwt_vc.issuer_public_key_b64` was supplied and the issuer signature verified — otherwise the
  `cnf` holder key (declared inside the issuer-signed JWT) is unauthenticated and a forged SD-JWT could report
  a valid-looking holder binding.
- **HIGH — witness quorum counts distinct KEY MATERIAL, not names** in BOTH verifiers. `verify_witnessed_checkpoint`
  AND `verify_tlog_proof` now share `checkpoint.witness_quorum`, deduping on the DECODED key bytes (Ed25519 +
  ML-DSA); one physical key under N names no longer satisfies `threshold=N` in either path.
- **HIGH — no raw tracebacks on malformed input:** a non-string `sd_jwt_vc.compact` now raises `BundleFormatError`
  (was `AttributeError`); CLI `verify`/`show-eval` catch file/JSON errors cleanly.
- **MEDIUM:** KB-JWT `aud` restricted to a single string (RFC 9901 §4.3); C2SP tree-size rejects non-ASCII
  digits; `present_with_key_binding` hashes `sd_hash` with the SD-JWT's OWN declared `_sd_alg` (read from the
  presented compact, not a module constant); the lm-eval adapter formats scores as fixed-point (no
  scientific-notation drop); `sign_checkpoint` validates keyname; origin/witness names reject all Unicode
  whitespace; `recompute_merkle_root_b64` validates `hash_alg` and shows the stated root canonically; the
  ML-DSA verify path builds its signed message inside the fail-closed guard; the status-list zlib decompression
  is size-bounded (CWE-409); `verify_tlog_proof` accepts an optional `expected_origin`.
- 188 tests (adds regressions for every item above, incl. one-key-under-many-names in tlog-proof, and a
  holder-binding check skipped when the issuer signature is unverified).

### Added — the portable proof (spec-verified against primary sources, 2026-07-02)
- **C2SP tlog-proof** (`proofbundle.tlogproof`, new CLI `proofbundle verify-proof`): emit and
  verify `.tlog-proof` files — index + RFC 6962 inclusion proof + verbatim (co)signed checkpoint,
  the C2SP "transparent signature" envelope (`c2sp.org/tlog-proof@v1`). `tlog_proof_for_bundle`
  refuses a checkpoint that disagrees with the bundle's root/size (No-Fake at build time); the
  verifier recomputes the leaf hash from the exact payload bytes, never trusts the file, treats
  `extra` as unauthenticated, and reports log/witness/inclusion sub-verdicts with a conjunction
  verdict. Rekor v2 institutionalizes exactly this persist-your-proof model. SPEC §7e.
- **ML-DSA-44 witness cosignatures** (C2SP type 0x06, FIPS 204 — the spec's SHOULD for new
  witness deployments): `cosign_checkpoint_mldsa` / `cosign_vkey_mldsa`; `verify_cosignature` now
  dispatches on the vkey algorithm byte (0x04 Ed25519 / 0x06 ML-DSA-44 — a 0x01 LOG key is still
  never a witness). Signed message = the C2SP `cosigned_message` struct (label `"subtree/v1\n\0"`,
  name-committing, RFC 8446 serialization) — pinned byte-exact by a KAT test, not just a
  roundtrip. Optional extra `proofbundle[pq]` (= `cryptography>=48`, PQ in default wheels since
  2026-05); on builds without ML-DSA a configured 0x06 witness raises UnsupportedError —
  fail-closed, never a silent False. Ed25519 stays the default; primary signatures unchanged.
  SPEC §7d.
- **Token Status List snapshot** (`proofbundle.statuslist`): offline revocation per
  draft-ietf-oauth-status-list (RFC-Editor queue, format frozen at -21). `status_claim(uri, idx)`
  goes into the receipt SD-JWT; `verify_status_snapshot` checks a supplied signed
  `statuslist+jwt` (EdDSA, `sub`↔`uri` binding, bits ∈ {1,2,4,8}, zlib bit-array) and reads the
  status. Freshness (`iat`/`exp`/`ttl`) is reported, and judged ONLY when the caller supplies
  `now` — no wall-clock assumptions in an offline verifier. Bundle format v0.1 unchanged: the
  snapshot is a separate verifier input. SPEC §7f.
- **SD-JWT VC markers** (`sdjwt_issue`): issuer header `typ: dc+sd-jwt`, a `vct` type URI
  (default `https://b7n0de.com/proofbundle/vct/eval-receipt/v1`), optional `status` claim — the
  four stable interop markers of draft-ietf-oauth-sd-jwt-vc (pre-IESG; full VC conformance stays
  deferred, type-metadata resolution deliberately not implemented).
- **COMPLIANCE.md** — an honest, non-legal mapping of receipts onto EU AI Act Article 12
  record-keeping (applies to high-risk systems from 2026-08-02), the GPAI Code of Practice Model
  Report evidence, NIST AI RMF MEASURE, and prEN 18229-1 / ISO/IEC DIS 24970 — including the
  anti-patterns section (what NOT to claim).

### Verification discipline
- **`scripts/mutation_check.py` + a CI `mutation` job** — the orthogonal mutation suite is now a
  repeatable repo gate (12 operators across kbjwt/bundle/checkpoint/tlogproof/statuslist/CLI),
  differential against the baseline; documented-equivalent mutants are asserted to SURVIVE so a
  stale equivalence argument also fails the gate. The suite immediately earned its keep: the
  ML-DSA domain-separation-label mutant survived the first run (emit+verify shared the constant —
  a self-consistency tautology) and is now killed by a byte-exact `cosigned_message` KAT.
- 44 new tests (133 → 177 in-tree): green roundtrips + red matrices (wrong leaf/log key/index,
  proof-hash tamper, unauthenticated-extra probes, quorum shortfall, ML-DSA name-commitment
  forgery, timestamp/body tamper, status-list signature/uri/typ/index attacks, bit-flip
  needs-resign) + the ML-DSA KAT pins.
- CI matrix extended to Python 3.13 / 3.14.

### Notes
- Still deferred, stated honestly: full SD-JWT VC conformance + `vct` type metadata (pre-IESG),
  per-sample Merkle receipts (v2.0 direction, THREAT_MODEL's named gap), an official in-toto
  eval predicate (proposal path via OpenSSF/CoSAI), Python-3.10 floor.

## [1.2.0] - 2026-07-02

### Added — holder binding + witness quorum (verified against primary sources)
- **Key Binding JWT verification** (`proofbundle.kbjwt`, closes #1): RFC 9901 §4.3, fully offline —
  header `typ` MUST be `kb+jwt` (alg EdDSA), payload MUST carry `iat`/`aud`/`nonce`/`sd_hash`,
  `sd_hash` recomputed over the US-ASCII bytes of the presented `JWT~disclosures…~` with the SD-JWT's
  `_sd_alg` (binds the *presented disclosure set* — dropping or swapping a disclosure after signing is
  detected), signature verified under the issuer-bound `cnf.jwk` holder key (RFC 7800; a supplied holder
  key is the fallback, the issuer's binding wins). `expected_aud`/`expected_nonce` for relying-party
  policy; `iat` freshness stays caller policy (offline verifier, no trusted clock). SPEC §6/§7.
- **KB-JWT issuance/presentation** (`sdjwt_issue`): `issue_sd_jwt(..., holder_public_key=...)` embeds
  `cnf.jwk` (OKP/Ed25519); new `present_with_key_binding(compact, holder_signer, aud=, nonce=, iat=)`
  builds the holder presentation. Explicit `iat` — the library never samples wall clocks for signatures.
- **New bundle check `sd-jwt-key-binding`** — **fail-closed**: a KB-JWT that is present must verify;
  previously a trailing KB-JWT was **silently ignored**, a downgrade risk (a bundle carrying holder
  binding verified `OK` without the binding being checked). Bundles *without* a KB-JWT are untouched —
  no new check, behavior identical to v1.1. SPEC §7 order gains step 5.
- **C2SP tlog-cosignature, Ed25519 cosignature/v1** (`proofbundle.checkpoint`): `cosign_checkpoint` /
  `verify_cosignature` / `verify_witnessed_checkpoint(..., threshold=)` — witness key ID algorithm byte
  **0x04** (domain-separated from the log's 0x01 by construction), signature blob
  `keyID[4]‖u64-BE-timestamp‖sig[64]` (exactly 76 bytes), signed message
  `"cosignature/v1\n" + "time <ts>\n" + note body`. Verifying a witness quorum rules out a split view
  by the log operator, offline — the pattern Rekor v2 (GA 2025-10) institutionalizes. The log's own
  signature stays required (witnesses attest consistency, they don't replace the log). SPEC §7d.
- **CLI `proofbundle verify --verbose`** (closes #2): prints the recomputed Merkle root next to the
  stated root (also under `--json` as `merkle_root.{stated_b64,recomputed_b64}`), via the new public
  `recompute_merkle_root_b64`. Debugging inclusion-proof failures no longer needs a REPL.

### Verification discipline
- 37 new tests: green roundtrips plus an adversarial red matrix per feature (disclosure drop/swap after
  KB signing, `typ`/`alg` confusion, missing required claims, fail-open probes, cosignature
  timestamp/body tamper, log-vkey-as-witness type confusion, quorum double-count, oversized signature
  blob). An orthogonal mutation suite (9 operators across kbjwt/bundle/checkpoint/CLI) kills 8/9
  mutants; the survivor is provably equivalent (oversized blobs already die at `verify_ed25519`'s hard
  64-byte signature length check).

### Notes
- Python floor stays **3.9** in this release (no floor change in a minor); 3.9 is EOL since 2025-10 —
  bumping to 3.10 is a deliberate follow-up decision.
- Still deferred, stated honestly: SD-JWT VC conformance / `vct` type metadata
  (draft-ietf-oauth-sd-jwt-vc-16, RFC expected ~Q4 2026), Token Status List verification (draft-21 in
  the RFC-Editor queue; frozen bit-array+zlib format — a good candidate as a bundled snapshot),
  ML-DSA-44 cosignatures (C2SP SHOULD for new deployments; needs an ML-DSA dependency).

## [1.1.0] - 2026-07-02

### Added — trust hardening: the honest foundation (authorship + integrity, stated precisely)
- **Signed `assurance_level`** (required field, enum `self_attested` | `third_party` | `reproduced` |
  `enclave_attested`, default `self_attested`) in the eval claim + schema + EVAL_CLAIM.md. The 1.0
  integrations emit self_attested. `show-eval` always displays it; the level is signed (tamper-evident,
  issuer-declared) — a third party cannot alter it, though a dishonest issuer can self-declare a higher level
  (the signature binds who claimed it, not that it is true). Schema keeps assurance_level OPTIONAL for v1.0
  backward-compat; the code always emits it (setdefault). Pre-1.1 claim JSONs default to self_attested.
- **THREAT_MODEL.md** — what `verify` catches (tampering, issuer swap, model swap, filtered disclosure,
  replay, weak-assurance-masking) and what it structurally cannot (dishonest self-attested issuer,
  publish-best-of-many without pre-registration, suite validity, per-sample sub-sampling = roadmap).
- **`claim_warnings`** — warns on the weakest combination (self_attested with no `prereg_sha256`); shown by
  `show-eval`.
- **`verify_commitment(identifier, salt, commitment)`** — checks a presented model/dataset identifier against
  the salted commitment, so a model swap is visible.
- **`check_freshness(claim, max_age_seconds)`** — reports receipt age (replay protection); the timestamp was
  carried but never judged before.
- **`sd_jwt_hidden_count`** — surfaces the number of withheld SD-JWT fields, so omission is visible.
- **`tests/test_adversarial.py`** — actively forges receipts: invented-numbers-with-valid-signature (PASS is
  EXPECTED + warned — binds authorship not truth), tampered payload (FAIL), withheld-field count, model swap
  (mismatch), replay (detectable), honest receipt still verifies.
- A consolidated **"What a receipt proves (and what it does not)"** section high in the README + assurance table.

### Note
- Terminology hygiene throughout: *tamper-evident signed evidence*, not *proof*; *authenticity and
  integrity*, not *correctness of the computation*.

## [1.0.0] - 2026-07-02

### Added — distribution: opt-in framework integrations (the 1.0 milestone: usable with zero third-party wiring)
- **inspect_ai end-of-task hook** (`proofbundle._inspect_registry` via the `inspect_ai` entry-point): auto-
  emits a signed receipt from the eval log at task end. Requires `inspect_ai>=0.3.112`. `data.log` is the
  EvalLog (no re-read for a normal `eval()`; header-only `eval_set()` falls back to reading the log).
- **pytest plugin** (`proofbundle.pytest_plugin` via the `pytest11` entry-point): auto-emits a signed
  receipt of the run (metric `pass_rate` over UNIQUE tests, per-outcome counts + exit status in provenance)
  from `terminalreporter.stats`. New optional `[pytest]` extra.
- **OPT-IN SAFETY** (the top rule): both integrations emit ONLY when explicitly enabled (`PROOFBUNDLE_EMIT=1`
  or `pytest --proofbundle`) — never silently write a file, never fail the host run, crypto imported lazily.
- Composite **GitHub Action** prepared under `action/action.yml` (SHA-pinned, env-indirect command) +
  `INTEGRATIONS.md` with a complementary `attest-build-provenance` recipe.
- The package `__init__` is now lazy (PEP 562): loading the plugin/hook no longer pulls the crypto core until
  a public name is actually used, keeping framework startup light.

### Changed
- README leads with the integration story; fair demarcation from ai-audit-trail (runtime agent Decision
  Receipts) and ValiChord (which builds attestation bundles from inspect_ai logs *post-hoc* — its v1 library
  is unsigned; signatures are v2 scope). Honest novelty: proofbundle auto-emits an **Ed25519-signed**
  receipt of an inspect_ai eval / pytest run via the framework's native plugin, a capability not found in
  a comparable released tool at the time of writing.
- The inspect_ai adapter renders metric scores as fixed-point decimals (not `repr`), so tiny/large values
  (e.g. `1e-05`) no longer fail the claim's decimal format.

## [0.9.0] - 2026-07-02

### Added — the standards moat (verified against primary sources)
- **DSSE-signed in-toto test-result export** (`proofbundle.intoto.export_intoto_dsse` + `verify_intoto_dsse`,
  new `proofbundle.dsse`): a receipt as a DSSE envelope over the GENERIC in-toto `test-result/v0.1`
  predicate (result PASSED/FAILED, `configuration` ResourceDescriptors with real digests, metrics in
  `annotations`). PAE is signed over the RAW Statement bytes (never base64), payloadType is pinned. SPEC §7b.
- **C2SP tlog-checkpoint** (`proofbundle.checkpoint`): a signed note over the RFC 6962 Merkle root
  (origin / tree size / standard-base64 root; EM DASH U+2014 signature line; keyID =
  SHA-256(name‖0x0A‖0x01‖pubkey)[:4]; vkey encoding). Raw note bytes signed, no PAE. SPEC §7c.
- **Every Eval Ever converter** (`proofbundle.adapters.from_eee_dataset`): reads an EEE v0.2.2 aggregate
  JSON into a signed receipt, validated against the vendored EEE schema, with NO runtime import of
  `every_eval_ever` (it needs Python 3.12; proofbundle stays 3.9+). The EEE `evaluation_id` (which embeds
  the model id) is deliberately NOT copied into provenance — the receipt keeps the model a salted commitment.
- Examples for all three (`examples/intoto_dsse_export.py`, `checkpoint_example.py`, `eee_receipt.py`).

### Changed — standards-native repositioning
- README tagline + "How it fits" name the neighbours fairly (Every Eval Ever, OpenSSF Model Signing,
  ValiChord, Attestable Audits) with the honesty guardrail visible; INTEROP.md gains a ValiChord section.
- SD-JWT digest mechanic re-verified against RFC 9901 §4.2.3 (Nov 2025) + the sd-jwt-python reference.

## [0.8.1] - 2026-07-01

### Fixed
- `make demo` / `scripts/demo.sh` / `Makefile` now invoke **`python3`** (overridable via `PYTHON=...`),
  not a bare `python`, so the documented demo works on systems where only `python3` is on PATH (PEP 394).

## [0.8.0] - 2026-07-01

### Added
- **Offline demonstrator**: `make demo` / `scripts/demo.sh` + `Makefile` turn genuine eval logs (an
  inspect_ai `mockllm` `.eval` and an lm-eval `--model dummy` `results.json`, committed fixtures generated
  offline) into signed, Merkle-anchored receipts and verify them — no network, API key, or GPU.
  `examples/inspect_receipt.py` added; a "Demo" README section makes it prominent.
- **Honesty guardrail** (README + SPEC): a receipt attests authenticity + integrity of a *claimed* result,
  **not** the correctness of the computation nor the absence of cherry-picking (TEE audits target that,
  different trust model). Demarcated from a bare hash (ref inspect_evals PR #1610) and from TEE approaches.
- INTEROP.md: Every Eval Ever (integration target, converter bridge) + Attestable Audits (TEE, different
  trust model) sections; SECURITY.md notes the SLSA v1.2 attestation model.
- Engagement drafts (`OUTREACH_issue_inspect_evals.md` + updated outreach note) — clearly marked
  draft-only; the human posts and replies personally per the inspect_evals AI-use policy.

### Note
- v0.6/v0.7 already delivered the lm-eval + inspect_ai adapters, INTEROP.md, PEP 740 docs and CITATION.cff;
  this release skipped those and added only the open points (demo, guardrail, outreach), per the update.

## [0.7.1] - 2026-07-01

### Fixed
A holistic 6-lens review of the whole integration (v0.1-v0.7) found robustness/conformance/CI gaps the
per-version reviews missed; all fixed here:
- **Verifier robustness**: `verify_bundle` now rejects malformed input with a `BundleFormatError` (the
  documented malformed path) instead of a raw traceback - type-confused `leaf_index`/`tree_size`
  (non-int/float), a non-object `signature`/`merkle`, a missing `inclusion_proof_b64` (required per SPEC),
  and unknown top-level/nested fields (SPEC additionalProperties:false, previously unenforced).
- **Eval-claim schema conformance**: `build_eval_claim` rejects values that fail its own published schema -
  negative `n`, and non-plain-decimal `threshold`/`score` (`1e2`, `Infinity`, `+5`, spaces).
- **CI on Python 3.9**: `inspect_ai` (requires Python >=3.10) is gated by a `python_version >= "3.10"`
  marker in the `inspect`/`dev` extras, so `pip install .[dev]`/`[inspect]` no longer fails on 3.9.
- **inspect_ai provenance parity**: the inspect adapter now captures run provenance (git commit, harness
  version, task version) into `provenance`, matching the lm-eval adapter.
- mypy is now run in CI (declared but never enforced); fixed two real mypy errors in `intoto.py`. A clear
  error names the missing `[eval]` extra if `rfc8785` is absent on the emit path.

### Changed (docs)
- Zenodo DOI wording made aspirational (no DOI assigned yet). INTEROP.md updated to CycloneDX v1.7 + C2PA
  ~v2.4. Corrected the arXiv:2507.06893 attribution (inspect_evals maintainers, Arcadia Impact, UK-AISI-
  funded). Refreshed stale CONTRIBUTING/PR/issue-template wording.

## [0.7.0] - 2026-07-01

### Added
- CITATION.cff now carries the author ORCID (0009-0006-8947-6065); a Zenodo DOI placeholder is marked in
  the README + CITATION.cff (a DOI is assigned once Zenodo archives a release; none exists yet — human checklist).
- `docs/in_toto_predicate_proposal.md` — a draft proposing an ML eval-result predicate upstream to
  in-toto/attestation (no registered ML-eval predicate exists yet); the human decides whether to submit.

### Unchanged (already delivered in v0.6, verified, not rebuilt)
- inspect_ai adapter (non-deprecated `results.scores[*].metrics[name].value` path), lm-evaluation-harness
  adapter (real `acc,none` format + provenance), INTEROP.md, PEP 740 attestations + badge fixes. This
  release re-confirmed each is present and correct rather than duplicating it.

## [0.6.0] - 2026-07-01

### Added
- **Second eval adapter, EleutherAI lm-evaluation-harness** — `proofbundle.adapters.from_lm_eval_results`
  reads a real `results_*.json` (no `lm_eval` import), handling the genuine 0.4.x format: metric keys with
  a filter suffix (`acc,none`) and the sibling `acc_stderr,none`. Captures run provenance (git_hash, task
  version, n-shot, stderr) into the receipt's optional `provenance` field. Validated against a committed
  real fixture (`tests/fixtures/lm_eval_arc_easy_real.json`, harness 0.4.12) + `examples/lm_eval_receipt.py`.
- **INTEROP.md** — honest mapping to OpenSSF Model Signing (complement, not eval), CycloneDX ML-BOM v1.6
  (can reference a receipt), in-toto test-result/v0.1 (the open ML-eval niche), C2PA (out of scope).
- **CITATION.cff** so the repo shows a "Cite this repository" button.
- Optional additive `provenance` field on the eval claim (backward-compatible, schema string unchanged).

### Changed
- inspect_ai adapter confirmed on the non-deprecated `results.scores[*].metrics[name].value` path with a
  None-guard (already correct since v0.5; documented).
- README/SPEC positioned as the verification layer for trustworthy eval logs; PEP 740 attestations
  documented (verified present on PyPI via the Integrity API, publisher = GitHub Trusted Publishing).
- Badges: python-version badge cache-buster (`?cacheSeconds=3600`) + a pepy downloads badge.

### Deferred (not built)
- No CycloneDX / C2PA / OMS re-implementation, no `lm_eval` runtime dependency, no `.zenodo.json`
  (would shadow CITATION.cff), no official in-toto predicate PR (drafted for the human to submit).

## [0.5.0] - 2026-07-01

### Added
- **SD-JWT issuance** (RFC 9901) — `proofbundle.sdjwt_issue.issue_sd_jwt`: issue an eval receipt so a
  holder can disclose `passed`+`threshold` while withholding the exact score and the identifier openings.
  The signed bundle payload is the **source of truth**; the SD-JWT is a derived view, binds the bundle
  merkle root (`receipt.root_b64`), and is signed with the same Ed25519 key as `issuer`. Digest byte-chain
  exactly per RFC 9901 §4.2.4.1 (over the base64url-encoded disclosure string). Verified by proofbundle's
  own verifier **and** the openwallet-foundation-labs/sd-jwt-python reference; divergence + tamper red-tests.
- **in-toto Statement v1** view — `proofbundle.intoto.to_intoto_statement`: self-hosted predicate type
  `https://b7n0de.com/proofbundle/eval-receipt/v0.1`. The subject digest is a salted commitment under a
  custom key `proofbundleModelCommitV1` (NOT `sha256`, which would imply an artifact hash). Validated
  against the in-toto Statement-v1 JSON schema via jsonschema. See PREDICATE.md.
- **inspect_ai adapter** via the stable `read_eval_log(header_only=True)` API (lazy import, optional
  extra `proofbundle[inspect]` pinned `>=0.3.100,<0.4`), with a real committed `.eval` fixture.

### Changed
- The inspect_ai adapter now uses the stable API instead of parsing the `.eval` file (robust across
  versions). The lm-eval adapter still reads `results.json` without importing the framework.

### Deferred (explicitly not in v0.5)
- SD-JWT VC conformance + `vct` type metadata, Key-Binding JWT, status lists / revocation, an official
  in-toto/attestation PR, a DSSE envelope or full in-toto verification client.

## [0.4.1] - 2026-07-01

### Fixed
- Removed a dead v0.3 `emit_eval_receipt` roadmap stub from `emit.py` that contradicted
  the real emitter now in `evalclaim.py`.
- Corrected the RFC 9901 publication date to November 2025 (was "December 2025") in the
  README, `sdjwt.py`, and this changelog.
- Doc staleness: test count and version wording in the README.
- Release workflow: the PyPI publish step is now idempotent (`skip-existing`) so a
  re-tagged release does not fail on an already-uploaded file.

## [0.4.0] - 2026-07-01

### Added
- **Eval-receipt emitter** (`src/proofbundle/evalclaim.py`): turn a reproducible eval
  run into a signed, Merkle-anchored receipt that proves *suite S `comparator` threshold
  T, passed* while carrying only **salted commitments** to the model and dataset
  identifiers (never the weights, data, or plaintext names). Built on `emit_bundle`, so
  the existing `verify_bundle` verifies a receipt unchanged.
  - `build_eval_claim` computes `passed` itself; `emit_eval_receipt` binds the receipt to
    the signer (`issuer` field in the signed payload); `decode_eval_claim` verifies the
    bundle **and** the issuer binding.
  - RFC 8785 JCS canonicalization on the **emit path only** (UTF-16 key sort, NFC, duplicate-
    key + Python-float rejection, safe-int range); the verify path checks stored bytes, so the
    verifier stays dependency-free.
- File-based framework adapters (`proofbundle.adapters.from_lm_eval_results`,
  `from_inspect_ai_log`) that read exported result JSON without importing the framework.
- CLI: `proofbundle emit-eval` and `proofbundle show-eval`.
- `EVAL_CLAIM.md` (normative claim spec + data-minimization) and
  `schemas/eval_claim_v0_1.schema.json` with a validation test.
- Optional extras: `proofbundle[eval]` (RFC 8785 canonicalizer, emit side), `proofbundle[adapters]`.

## [0.3.0] - 2026-07-01

### Added
- **External RFC 6962 conformance**: verifies canonical inclusion vectors vendored
  from transparency-dev/merkle (tests/fixtures/rfc6962_vectors.json) — proven
  RFC-conformant, not merely self-consistent. Plus Hypothesis property tests
  (inclusion + consistency) for trees up to several hundred leaves.
- **Sigstore Rekor interop**: `examples/rekor_interop.py` verifies a real Sigstore
  Rekor inclusion proof (logIndex 25579, tree size 4.16M) fully offline, with a
  committed fixture and a field-mapping doc (Rekor bundle / C2SP checkpoint).
- SD-JWT is an optional extra: `pip install "proofbundle[sdjwt]"` (core stays
  cryptography-only).
- Normative format specification `SPEC.md` (fields, encodings, RFC 6962 hashing,
  verification order), consistent with the JSON Schema.
- `.github/dependabot.yml` (github-actions + pip).
- PyPI Trusted Publishing (OIDC) publish job in the release workflow.

### Changed
- All GitHub Actions pinned to full commit SHAs (post tj-actions incident).
- SD-JWT docstrings/README cite RFC 9901 (SD-JWT core, November 2025); clarify SD-JWT VC
  is still an IETF draft.

## [0.2.0] - 2026-07-01

### Added
- Bundle emitter: `emit_bundle` signs a payload with Ed25519 and anchors it as
  the last leaf of an RFC 6962 Merkle tree, producing a bundle that
  `verify_bundle` accepts — the offline counterpart to the verifier.
- Signing-key helpers `generate_signer`, `save_signer`, `load_signer` (raw 32
  byte Ed25519 seeds).
- `proofbundle emit` command line interface (`--payload-file`, `--new-key` /
  `--key`, `--out`).
- Emit-then-verify round-trip tests, including prior-leaf anchoring, tamper
  detection and key save/load.

### Notes
- No new runtime dependency; the emitter reuses the existing Merkle logic and
  `cryptography`. The v0.3 eval-receipt emitter remains a roadmap stub.

## [0.1.0] - 2026-07-01

### Added
- Offline evidence bundle verifier (`proofbundle/v0.1` schema).
- Published JSON Schema (`schemas/proofbundle_v0_1.schema.json`) with a
  validation test, `py.typed` marker and community files (Code of Conduct,
  issue and pull-request templates).
- RFC 6962 / RFC 9162 Merkle inclusion and consistency proof verification.
- Ed25519 signature verification via `cryptography`.
- Minimal SD-JWT selective-disclosure verification (EdDSA issuer signatures,
  disclosure-digest commitment check).
- `proofbundle verify` command line interface with human and JSON output.
- Example bundle generator (`examples/make_example.py`) and a real example bundle.
- Full unit test suite (Merkle round-trip across sizes, signature, bundle, CLI).
- Emitter roadmap stub for v0.2 (bundle emission) and v0.3 (eval receipts).
