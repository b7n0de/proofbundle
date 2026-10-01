# Residual risk, release 6.2.0 — the record before the closing gate round


This file lands before the closing round, not after it, as for 6.0.0 and 6.1.0: it goes on `main`
first, the head that carries it is the frozen tree, and the closing round runs on exactly that head.

**Nothing in this file claims the release is defect free.** It is the list of what was known and
open when the tree was frozen, and why each item was judged not to block.

## The exit rule this release was cut under

Owner choice of 2026-09-27: for every fix branch of this release the round that was running was the
last ordinary one. From its end, a finding blocked the release only if it changed a verdict, an exit
code, a bound or a security property (P0 or P1). Every other finding is a line in this file and
belongs to the next patch release. The lens rounds that closed the branches ran with three model
families each, against targets fixed before each run, and every objection of the two foreign
families was re-measured before it was filed. Each pull request's Codex review series was capped at five
requests; an answer without P0 or P1 ended a series, and its P2 went into this file without a fix at the head.
Pull request 312 is the exception to the three families: its verify lane ran with one family, and the deep gate
at the new head of pull request 311, which carries this file, is its closing round. Pull request 313 closes
the six P1 findings of that gate at 7409b123, whose panel ran with three families. The gate at the next head of
pull request 311, d97de8e5, ended FIX_FIRST for two P1 findings; the commit of pull request 311 that the release
notes name as their release commit closes both (the section on them below), and the gate at the head that carries
the pre-tag receipt is the closing round. That gate, at 99f76ceb, ended FIX_FIRST for one P1, seen by two lenses:
the fix of the empty option judged `audit-challenge --nonce` by its spelling (the section below). The commit that
closes it is the new release commit, and the gate at the next head that carries a pre-tag receipt is the closing round.
That gate, at d388ed3d, ended FIX_FIRST for two P1 findings, each confirmed by two of three blind jurors: the decision
and outcome verifiers read the caller's `related` map twice, and `decision verify --anchors` read a file holding
`null` like no option (the section below). The commit that closes both is the new release commit, and the gate at the
next head that carries a pre-tag receipt is the closing round.

| Branch | Pull request | Head that landed | Last lens round | Codex series |
|---|---|---|---|---|
| Small-order keys | 293 | c9c274c4, main 86671552 | Claude lens run 8 at fddc00f4; its three P1 went into a further round, 068cd349 | 4 requests, the last with one P2 (thread 4121890211) |
| Resolver promotes on the exact True | 291 | 3977fcdf, landed inside 293 | final round of the branch | 3 requests, the last with one P2 (thread 4119394589) |
| Pre-tag cleanliness gate | 249 | 68745704, main 8da7ce16; carries 296 and the cost-bound class fix | Claude lens run 4 at f5939ab0, WITHSTANDS | 5 requests, the last without a finding |
| Rust dependency audit | 296 | 2cf9908f, landed inside 249 | run 4 at d30f236e, FIX_FIRST for C3, fixed at f97cb257 | 2 requests, the last without a finding |
| Commitment patterns at the verify boundary | 300 | 373bf64b, main a1e9774e | Claude lens run 11 at cd5d39f4; its P0 and P1 closed in round 12 | 3 requests, the last with one P2 (thread 4124587746) |
| Release-scope cut | 294 | 903325f3, main 2074d814 | Claude lens at 989b582c; its four P1 closed in 346fa924 | 5 requests; the fifth, at 76f260a2, reported one P1 (thread 4125291621), fixed without a further request as the owner's rule sets it after the budget, and one P2 (thread 4125291624) |
| One reading at every verify surface | 312 | b19d6ef3, main 52231c95 | verify lane of three Claude lenses at c2ba90db; its eight neighbours fixed in a9bfe2e2 and b19d6ef3 | 2 requests, both without a finding |
| The loader's rule at every evaluator, one reading before caller code | 313 | 37fc3cac, main f237ff1a | deep gate at 7409b123 (pull request 311), FIX_FIRST; its six P1, 24 of the 26 candidates of an independent cross-check and the sites of four verify lenses closed here | 2 requests, the first without a major finding, the second one P2 that does not reproduce at the head |

## Closed in 6.2.0 — the open items of the 6.1.0 record

Each is stated as closed only where it is measured on the tree that carries this file. Measured again on
2026-09-28 before the freeze, on main 86671552 and on the head of pull request 300, 657cc67c; the closing round repeats each
on the frozen tree.

- **The two commitment patterns at the verify boundary** (`COMMIT-PATTERN-DOMAIN-NOT-AT-VERIFY-BOUNDARY-01`).
  Measured 2026-09-27 before the freeze (to be repeated on the frozen tree): `emit_eval_receipt` with
  `model_id_commit="sha256:x"` signs on main `31816e08` and is refused (`EvalClaimError`, the commitment
  must be `sha256:<64 lowercase hex>`) at the head of the eval-claim branch, `493c2f86`. On 2026-09-28 it
  still signs on main 86671552 and is refused at 657cc67c, the head of pull request 300, which carries the fix.
- **A small-order key at the carrier's signature block** (`SMALL-ORDER-KEY-AT-CARRIER-SIGNATURE-01`).
  Measured 2026-09-27 before the freeze (to be repeated on the frozen tree), at `_signatur_lage` over
  16 bodies (`register_revision` 0 to 15): the identity point as key with R = identity, S = 0 came back
  `VERIFIZIERT` 16 of 16 times on main `31816e08`, and 32 zero bytes as key and 64 as signature 2 of 16
  times; at the head of the small-order branch, `06f84b88`, both are `KEY_REFUSED` 16 of 16 times, and so on
  main 86671552 (where the branch landed) and at 657cc67c, the head of pull request 300, measured 2026-09-28. The AGT signer,
  the register view and the `--expect-issuer` pin were not measured again here; the closing round measures
  them on the frozen tree. At the released tags v6.0.0 (`4e32e83b`) and v6.1.0 (`dcac5aee`) the identity
  point as a plain key verifies the signature (identity, 0), which no private key made: `verify_ed25519` and
  `dsse.verify_envelope` answer True, measured 2026-09-28. `verify_ed25519_pinned` does not exist at either
  tag; the double read of a caller's key object it had on main after pull request 293 (a `bytes` subclass
  answering a real key to the rule and the identity point to the check verified that signature) is closed on
  the head of pull request 300, where the key object's `__bytes__` is never called.
- **Three public exporters coerced the verdict field** (`DREI-VERBRAUCHER-COERCEN-PASSED-DOKUMENTIERT-IST-EINER-01`).
  Measured 2026-09-27: `passed="false"` is already refused (`BundleFormatError`, `passed` must be a
  boolean) at all three on main `31816e08`, so this closed before the cut and not with a branch of it.
  The same on main 86671552 and at 657cc67c, the head of pull request 300, on 2026-09-28 (there `to_test_result_statement`
  names `passed must be a boolean`; the control `passed=False` gives FAILED). To be repeated on the frozen tree.

## Open — the released 6.0.0 and 6.1.0 carry a resolver that promotes on truth

Four public functions call code their caller supplies and read the answer by its truth, although each
documents a bool: `assurance.classify_digest_evidence`, `assurance.classify_receiver_corroboration`,
`renewal.verify_sequence` and `anchors.verify_anchor` (for a verifier registered through
`register_anchor_type`). 6.2.0 promotes only on the exact `True`. Measured 2026-09-27 by executing
each function at the tagged trees of v6.0.0 (`4e32e83b`) and v6.1.0 (`dcac5aee`), with the answers
`"false"`, `1` and `[0]`: `classify_digest_evidence` reached `CONTENT_RESOLVED`,
`classify_receiver_corroboration` reached `INDEPENDENTLY_ATTESTED`, `verify_sequence` gave `ok=True`
with the last anchor held, and `verify_anchors(require="any")` gave `require_met=True`, at both tags;
the exact `False` promoted nowhere. At the head of the fix (`3a8074fc`) none of the three answers
promotes and the exact `True` still does. The reach is the Python API; the CLI sets none of these
resolvers. The caller-attested flags of `svr_properties` and
`export_svr_dsse` had the same shape (`anchor_verified="false"` signed `PROOFBUNDLE_ANCHOR_VALID`,
measured on main `31816e08`); 6.2.0 refuses any flag that is not True or False.

The release notes of 6.2.0 name the affected versions, the effect and the upgrade (owner decision of
2026-09-28). A security advisory is a separate outward act and is not part of this file.

## Open — the released 6.0.0 and 6.1.0 accept a key binding that no key made

`sdjwt_issue.issue_sd_jwt` bound a holder key of small order, and the verifier accepted a Key Binding
JWT under such a key. Measured 2026-09-27 by executing it at v6.0.0 (`4e32e83b`) and v6.1.0
(`dcac5aee`): an eval receipt carrying an SD-JWT bound to the identity point, presented with a Key
Binding JWT whose signature is R = identity, S = 0 (made with no private key), gave
`verify_key_binding` `{"ok": true, "detail": "key binding valid (cnf.jwk)"}`, `verify_bundle` `ok=True`
with no failing check, and `proofbundle verify <receipt> --aud v --nonce n` exit 0 with
`[PASS] sd-jwt-key-binding: key binding valid (cnf.jwk)`, both when proofbundle bound the key and when
another issuer bound it. On main `31816e08` the verifier already refuses it (exit 1, `KB-JWT
signature invalid (cnf.jwk)`), while `issue_sd_jwt` still binds the key; at the head of the
small-order branch (`76c900ea`) `issue_sd_jwt` refuses the key with `ValueError` and the verifier
refuses the presentation.

The release notes of 6.2.0 name the affected versions, the effect and the upgrade (owner decision of
2026-09-28). A security advisory is a separate outward act and is not part of this file.

## Open — the released 6.0.0 and 6.1.0 let a related map that says it is empty hide a retraction

`verify_decision_receipt` and `verify_outcome_receipt` asked the caller's `related` map whether it held
targets through its own `__bool__`. Measured 2026-09-28 by executing both at the tagged trees of v6.0.0
(`4e32e83b`) and v6.1.0 (`dcac5aee`), and on main `86671552`: a `dict` subclass whose `__len__` is 0,
holding a verified retraction of the subject, with `reject_superseded` set, gave `ok` True at both
tags and on main (decision: `policy_ok` None; outcome: `policy_ok` True); the plain dict with the same
entry gives `ok` False. 6.2.0 reads the map by what it stores (pull request 300,
`relation._carries_attached_entries`, commit 1f08bd50), and since the fix of the gate at d388ed3d once, in one
reading that also decides whether there are targets (`relation._related_lesen`, the section below). The reach is the
Python API: the CLI builds a plain dict.

The release notes of 6.2.0 name the affected versions, the effect and the upgrade (owner decision of
2026-09-28). A security advisory is a separate outward act and is not part of this file.

## Open — the released 6.0.0 and 6.1.0 read an edge's declaredAt with any Unicode digit

`relation._RFC3339_Z` read `declaredAt` with `\d`, which in a Python str pattern is every Unicode decimal
digit, while the Rust verifier takes ASCII digits only. Measured 2026-09-28 by executing
`validate_relationships` at the tagged trees of v6.0.0 (`4e32e83b`) and v6.1.0 (`dcac5aee`): an
Arabic-Indic year, a fullwidth year and Devanagari seconds are accepted at both tags. On main
86671552 a signed decision receipt carrying such an edge verified in Python (`decision verify` exit 0,
`ok` True) and was refused by `pb_verify_rs verify-relation` (exit 2, "edge.declaredAt must be RFC3339
Z"): the same bytes got two verdicts. 6.2.0 takes `[0-9]` (pull request 300,
`tests/test_declared_at_takes_only_ascii_digits.py`; red against the source of 1f08bd50 on all twelve
non-ASCII cases, both verifiers exit 2 at the fix). The reach is any producer that signs such a
timestamp; this package's own emitter signed it before the fix.

The release notes of 6.2.0 name the affected versions, the effect and the upgrade (owner decision of
2026-09-28). A security advisory is a separate outward act and is not part of this file.

## Open — the released 6.0.0 and 6.1.0 let a caller's own objects decide eight verify verdicts

The deep gate of the release preparation (pull request 311 at 2348f0a7) confirmed eight P1 findings of one
class, each by three of three blind jurors: a public verify surface read an argument of the caller a second
time, or through a method of the caller's own type. Pull request 312 (main 52231c95) closes the class. The
gate's reproducers were run on 2026-09-29 by executing them at the tagged trees of v6.0.0 (`4e32e83b`) and
v6.1.0 (`dcac5aee`), at main `2074d814` and at `87090ef2`, the merge of the new main into this branch
(Python 3.10.12). Unless a line says otherwise, every promotion below holds at both tags and at `2074d814`,
with the plain control giving the refusal:
- `verify_decision_receipt` judged the trust pin on a second reading of the caller's `public_key`, after the
  evidence resolver ran: a `bytearray` key the resolver rewrote gave `ok`, `signer_trusted` and
  `safeForAutomation` True for a receipt signed by an untrusted key. The reproducer drives the decision
  verifier; the outcome verifier's same read is recorded at `2074d814` in the CHANGELOG entry of pull
  request 312.
- `verify_prereg` and `verify_evaluation_card` read the stored hash through the claim's own `get`,
  `__class__` and `__eq__`: a claim that stores another document's hash gave `ok` True.
- `verify_sequence` checked the authority signature over an `int` subclass's own rendering of an ATS
  `time` while `evaluate_renewal_policy` judged the stored integer, so an overdue anchor was judged within
  policy; `evaluate_renewal_policy` took an `int` subclass as `now` and turned an overdue FAIL into `ok`
  True; and `known_newest_token_digest` was compared through the caller's `__eq__`, so a truncated sequence
  passed `renewal:no_rollback` with `ok` True.
- `verify_decision_receipt` asked a list subclass of anchors whether it is empty through its own
  `__bool__`: a failing anchor was hidden and `ok` went from False to True.
- The relations gate of the decision, outcome and relation-statement verifiers read the policy through its
  own `get`: a lineage requirement the plain policy fails (`LINEAGE_REQUIREMENT_FAILED`) and a
  `relation_signer` pin to another key (`RELATION_SIGNER_UNAUTHORIZED`) gave `ok` True. At the two tags the
  same policy object also hid a `require_external_anchor` obligation from the decision verifier (`ok` True);
  at `2074d814` that obligation already held.

At `87090ef2` none of the eight promotes, and every control gives the verdict it gives at the tags. One
named limit stood at every tree measured, `87090ef2` included: an `anchors` argument that is a falsy value
of another type (`{}`, `""`, `0`, `False`) was read as no anchors, with `safeForAutomation` False, as the
CHANGELOG entry of pull request 312 names it. Pull request 313 refuses it (the section below). The reach is the Python API: the CLI parses files into plain
values and passes none of these objects.

The release notes of 6.2.0 name the affected versions, the effect and the upgrade (owner decision of
2026-09-28). A security advisory is a separate outward act and is not part of this file.

## Open — the released 6.0.0 and 6.1.0 let a wrong-typed policy field, a callback or a wrong container decide a verdict

The deep gate of the release preparation at the new head of pull request 311 (7409b123, after pull request 312)
ended FIX_FIRST for six P1 findings, each confirmed by a majority of three blind jurors: one from the re-measurement
of a foreign-family lens, five from the panel. An independent cross-check of the first class on main 52231c95 named 26
candidate sites. Pull request 313 (main f237ff1a) closes the six findings and 24 of the 26 candidates; the other two,
`agent_review` reading `blocking` and `require_coverage_status` of null as no rule, the owner kept for 6.2.0 (limits
below). The three new test
files of that pull request were run on 2026-09-29 against the source of the tagged trees v6.0.0 (`4e32e83b`) and
v6.1.0 (`dcac5aee`) (Python 3.10.12). The loader-rule file failed 1505 subtests at each tag, the cross-check file 233
at each tag (232 assertions and the raw `ValueError` of `lint_policy` below; an earlier version of this line gave 242,
the count of an intermediate version of the file, measured again on 2026-09-29 with the file that landed), and each
promotion below failed its case there with an assertion, not with a missing name:
- `evaluate_policy`, `evaluate_decision_policy` and `relation.evaluate_relations_policy` read a present policy field
  of another type as no constraint where `load_policy` refuses it: `policy_ok` True with no check, and
  `verify_decision_receipt` `ok` True for a receipt signed by a key the policy does not trust when
  `trusted_decision_makers` is not a list.
- `verify_decision_receipt` read `anchors` and `rp_trust` after the evidence resolver, and `verify_anchors` read
  each entry, the roots and `rp_trust` after the verifier of the entry before: a failing anchor was hidden, a pending
  one confirmed, and a later anchor rewritten.
- `verify_sequence` read the newest ArchiveTimeStamp after the caller's `anchor_verifier` had been handed it: a
  failing external token was skipped and a sha1 entry passed `require_current_hash`.
- `verify_outcome_receipt` read the attestation resolver's answer again after the next call, and
  `assurance.classify_receiver_corroboration` read its expected key after the resolver: a receiver label was bound to
  a key it is not.
- A `related` that is no dict was read as no attached entries at the decision, outcome and relation statement
  verifiers, so `reject_superseded` did not see a verified retraction; a falsy `anchors` that is no list was read as
  no anchors. A relations section held as JSON null, or present and no dict, was read as no rule at the outcome and
  relation statement verifiers.
- `RenewalPolicy.from_dict` read a `deprecated_algs` of another type, a Python set included, and an entry that is no
  text, as no deprecated algorithm, so `evaluate_renewal_policy` reported `renewal:policy` True over a hash the policy
  meant to deprecate.
- Beyond the policy dict, found by the verify lenses of that pull request: an `rp_trust.trusted_tsa_policy_oids` of
  another shape was no TSA policy pin; a trust pack `revoked` of another type revoked nobody, so the outcome verifier
  trusted a revoked executor; a malformed pack key for a receiver let a bare True reach INDEPENDENTLY_ATTESTED; an
  `automation_summary` references requirement of another shape was no requirement; a `decision_maker_id` that is no
  text showed role separation; `check_on_receipt` accepted an answer without a planned route; and the decision verifier and `verify_sequence` read the anchor verifier registry
  and `HASH_REGISTRY` after caller code had run. `lint_policy` raised a raw `ValueError` for a huge freshness bound.

The warn polarity finding is a regression of pull request 291 and not in the tags: there `bool()` read a truthy
`warn` as pending and a falsy one (`0`, `""`, None, `{}`) as a full anchor. The reach of every line is the Python API
with a policy dict, a callback or a container the caller supplies; the CLI loads policies with `load_policy` and passes
no callbacks. The one line the CLI reaches is the falsy `anchors`: it passes the content of `--anchors <file>` on, and a
file holding `{}`, `0`, `false` or `""` read as no anchors.

The release notes of 6.2.0 name the affected versions, the effect and the upgrade (owner decision of
2026-09-28). A security advisory is a separate outward act and is not part of this file.

## Open — the released 6.0.0 and 6.1.0 read a subject state open-world, and the CLI dropped a restriction given an empty value

The deep gate of the release preparation at d97de8e5 (pull request 311, after pull request 313) ended FIX_FIRST for
two P1 findings, each confirmed by two of three blind jurors. Pull request 311 closes both before the closing round.
Their test files were run on 2026-09-29 against the source of the tagged trees v6.0.0 (`4e32e83b`) and v6.1.0
(`dcac5aee`) (Python 3.10.12):
- `relation._target_subject_pin_error` failed only the lowercase words "ambiguous", "absent" and "malformed" of an
  attached target's `subject_digest_state` and read every other explicit state as "present". An attached target
  labelled "AMBIGUOUS", "multiple" or `["ambiguous"]`, whose `subject_digest` holds its first subject, bound a
  declared `targetSubjectDigest` to that subject: lineage VERIFIED and `ok` True at the decision, outcome and
  relation statement verifiers, at the receipt's own edge and at every hop (the gate's lens measured
  `safeForAutomation` True as well at the decision verifier under a policy that pins the signer).
  `tests/test_a_subject_state_is_read_closed_world.py` fails 50 cases at each tag over the engine at the edge and at
  a hop and over the decision verifier. 6.2.0 reads the state closed-world: every explicit state but the four words
  is malformed, a missing one is still inferred from the digest, and a `str` subclass is read by what it stores. The
  reach is the Python API: `cli._load_related` writes only the four words, and the Rust verifier derives the state
  from the payload and reads none from a caller.
- A restricting CLI option given the empty string was read by its truth and dropped: `verify --policy ''`,
  `verify --anchor-type ''`, `decision verify --policy ''` and `--anchors ''`, and `outcome verify --policy ''`
  exited 0 at each tag, where a policy the receipt does not satisfy gives 3 and a path that does not exist gives 2;
  so did `relation-statement verify --policy ''`, `show-eval --eat ''`, `policy instantiate --expected-root-file ''`
  and `audit-challenge --nonce ''` (measured at both tags by a verify lens of pull request 311). 6.2.0 reads these
  options with `is not None`; `tests/test_an_option_given_an_empty_value_is_not_dropped.py` checks each site and
  holds every truth read of a one-value option in `cli.py`, in the forms it reads, to a named list with its reason
  (eleven, each refusing an empty value itself or on an emit or output path).
  `outcome verify --decision-maker-id ''` is unchanged on purpose: the library reads it with `is not None`, an
  empty maker id cannot equal an executor id, and `role_separation_ok` reports the check as run.
- The fix of that option was incomplete at `audit-challenge --nonce` (deep gate at 99f76ceb, L3-620v4-T11-NONCE-WS-01
  and L5-620v4-NONCE-WHITESPACE-01, one defect, each confirmed P1 by three of three blind jurors). It refused the
  spelling `""`, while the command used `bytes.fromhex(value)`, which skips ASCII whitespace: `--nonce ' '`, a tab,
  a newline, a carriage return, a vertical tab, a form feed or a mix decoded to no bytes and gave exactly the
  self-challenge indices a producer can grind, under the mode `auditor-nonce`, with no warning and exit 0. Measured
  by the filer on 2026-09-29, seven spellings each: the same at 99f76ceb and at the source of v6.0.0 and v6.1.0,
  where `--nonce ''` itself also ran as the self-challenge. The nonce is decoded once now, before a mode is chosen; a
  nonce that decodes to no bytes is refused with exit 2, and the mode follows the decoded bytes. The test file above
  runs every site with whitespace spellings of the empty value, checks the audit challenge as a property of the bytes
  it uses, and refuses a comparison of an option's spelling with the literal `""` by `==` or `!=`, directly or through a
  local name (no other form, and none stands in `cli.py`); at 99f76ceb it fails 25 times, as pytest
  counts them. Two sweeps with the empty value and whitespace, over 24 option and `--pub` sites at 99f76ceb and over
  the 16 inputs the CLI itself normalises (`bytes.fromhex`, `strip`, base64, a file's content) at the commit of the
  fix, found no other site that reads whitespace like an absent option; `--related-pub ''` still means the same
  key, as documented.

The release notes of 6.2.0 name the affected versions, the effect and the upgrade (owner decision of
2026-09-28). A security advisory is a separate outward act and is not part of this file.

## Open — the released 6.0.0 and 6.1.0 read a related map twice, and the CLI read an anchors file holding null as absent

The deep gate at d388ed3d (pull request 311, the head that carried the pre-tag receipt after the fix of 99f76ceb)
ended FIX_FIRST for two P1 findings, each confirmed by two of three blind jurors. The commit that closes both is the
new release commit. Measured on 2026-09-30 by executing each against the source of the tagged trees v6.0.0
(`4e32e83b`) and v6.1.0 (`dcac5aee`) and at d388ed3d (Python 3.10.12):
- `verify_decision_receipt` and `verify_outcome_receipt` judged the edges of the caller's `related` map in
  `verify_relationship_edges` and read the map again in `successor_warning`, whose `supersededByAttached` they
  recorded (L4-620v5-T5-SECOND-READING-01). Under a policy with `reject_superseded` and
  `require_relation_resolution: ["derivedFrom"]`, which refuses the full map and the empty map alike, a gc callback
  of the caller that emptied its own map between the two readings gave `ok` True: at both tags the two readers were
  called three times per verification, and a sweep over every collection start of a call gave `ok` True at four to
  seven of them (the gate's lens measured `safeForAutomation` True as well under a policy that pins the decision
  maker). 6.2.0 reads the map once and judges that reading; the reach is the Python API, since the CLI builds a
  plain dict and runs no caller code between the readings. The first fix (6d674973) read each such value once where
  the body read it; the three verify lanes on it found the class where no single reading of one parameter shows it (a
  loop of readings, a copy per chain or receipt, two parameters each read once at two times, a budget and a copy, a
  Mapping or an object read through its own methods, and a pause that a second thread ended), each measured with a
  sweep over every collection start and present at d388ed3d. So every public function now reads all of its
  arguments in one reading at its call (`canonical._ein_stand`, `canonical._stand`). The three verify lanes on that
  second fix (8f2fa980, not pushed) found what its reading left out (a public classmethod, the package's own
  dataclasses, a dict keyed by a `str` subclass, a resolver that is a partial of a public function) and what its
  pause of the collector for the whole process cost; the reading copies those values now, and reads every container
  twice instead of pausing. The two verify lanes on that third fix (085869313, not pushed) found that the reader of a
  Mapping ran once, before the collects, and that a deque, an array and a view of a dict were not copied; the reader
  is part of both collects now and those values are copied. The CHANGELOG entry of this fix names each surface, and
  `tests/test_a_verifier_reads_a_callers_value_once.py` holds the class: the sweep at the measured surfaces, a guard
  that every public function, classmethod and staticmethod carries the reading and that every call of a caller's
  callable is named, and the one reading itself with a sweep that falls when the second collect is taken away.
- `decision verify --anchors FILE` whose content is `null` became `anchors=None`, the value of a call without the
  option, and exited 0 with the output of no `--anchors`, while `--anchors ''` exits 2 at d388ed3d
  (L3-620v5-T14-ANCHORS-NULL-FILE-01); an empty list, which the anchor layer reads None as, ended the same way. At
  both tags a file holding `null`, one holding `null` in whitespace and one holding `[]` exited 0 like no option, and
  so did `--anchors ''` (refused since pull request 311); `{}`, `""`, `0` and `false` did too (verify lane V1 on
  6d674973). 6.2.0 refuses a file holding null or an empty list with exit 2, and one holding `{}`, `""`, `0` or
  `false` with exit 1, as no list of anchors. `tests/test_an_option_given_an_empty_value_is_not_dropped.py`
  runs every file option whose absence is a state of its own, fifteen, with a generator of contents, and holds every
  other file option of `cli.py` to a named list with the reason no content can read as its absence. One level down,
  a valid policy that holds no section a command evaluates ended `decision verify`, `outcome verify` and
  `relation-statement verify` like no `--policy`, at d388ed3d and at both tags (verify lane V3); it is refused with
  exit 2 now, and so is a policy whose `relations` section sets no rule, and an empty `--key` or `--new-key` beside the
  other, which `emit` dropped.

The release notes of 6.2.0 name the affected versions, the effect and the upgrade (owner decision of
2026-09-28). A security advisory is a separate outward act and is not part of this file.

## Open — findings of the last rounds judged not to block

One line per P2 and P3 of the closing lens and Codex rounds of the branches in this release (the small-order keys, the commitment patterns,
the resolver fix, the pre-tag cleanliness gate, the Rust dependency audit, the release-scope cut) and of the
deep gate of the release preparation at 2348f0a7, each
with branch, head, file and line, and the sentence why it is not P0 or P1. 234, 236 and the tooling stack
moved to 6.3.0 (owner word of 2026-09-27); their lines are not part of this file.

Kept from the lenses of branches that moved to 6.3.0, because each describes main as well and so the
tree of this release (owner word of 2026-09-27: 234, 236 and the tooling stack moved to 6.3.0; their other
lens lines travel with them):
- **`__debug__` used as a truth value at a check is not seen by classes A and C of the mutant signature
  guard** (P2, stated by the stack's lens at 0b9edc94 as the same on main): no mutation tool writes it, it has
  no occurrence in `src` or `scripts`, and `if __debug__:` is a legitimate idiom. Measured on main 0ace3039 (the
  guard from main, `--base` over one added commit in a throwaway repository): `if __debug__:` before `return True` and
  `return __debug__` in `verify_a` both pass (rc 0, clean); the control `if False:` is blocked (rc 1).

- **A shipped test walks the package and drops every module that does not import** (P2, on main, reported by
  the resolver round 3 and read by the filer): `tests/test_automation_nie_nachsichtiger_als_ok.py`,
  `_alle_verifier`, catches any exception from `importlib.import_module` and continues, so a `verify_*`
  function in a module that fails to import is never checked, and the test cannot go red for it. No verdict
  of the package changes; the guard is weaker than its name. The resolver branch fixed the same assumption
  in its own sweep (3d5b992a: only a declared optional extra that is absent is named and left out, anything
  else fails); this test gets the same rule after 6.2.0.

- **`root_authenticity_summary` reads a caller's check twice: once for its rows, once for its crypto
  gate** (P2, Codex round four on pull request 293 at c9c274c4, thread 4121890211, `src/proofbundle/bundle.py:643`
  and `:694`). Measured by Codex and reproduced on main 86671552 (whose tree is the tree of c9c274c4, Python
  3.10.12): a `merkle-inclusion` check whose `ok` answers False, then True, then True gives
  `merkleConsistency: FAIL` in the row and `safeForAutomation: true` with no blocker, because the gate
  (`_checks_passed`, one read since round three) and the row read the check separately, and `result.ok`
  folds the checks a third time; `evaluate_policy` reads each check twice through that same `result.ok`.
  The control, the same check answering False three times, gives `CRYPTO_FAILED`.
  Same class as the round-three finding that was fixed (split reads of a caller-controlled verdict). Not
  P0 or P1 under the owner's line for this class: the check and its `ok` are the caller's own claim, so the
  sequence reaches no verdict that a check answering True would not reach, and nothing the package itself
  established is hidden (unlike the related map above, where the caller's container hid a retraction the
  verifier had verified); `verify_bundle` never builds a check whose `ok` changes between reads (`Check` is
  a plain dataclass field, `src/proofbundle/errors.py:30-36`). What the sequence breaks is the agreement of
  the row and the verdict of one summary. The fix is one snapshot of the checks per call, shared by the
  rows, the gate and the policy, with the reversed sequence as its red case; it goes into the first cycle
  after the tag (the owner's exit rule for this release: a P2 travels with this file).

- **Two tests change the working tree that the rest of a parallel suite reads** (on main since #280,
  ef832a92, found while measuring a local merge of the first landing window on 2026-09-28). `tests/test_gate_qualification_harness.py`
  writes stripped versions of `scripts/pre_tag_receipt_lib.py` and `scripts/type_confusion_gate.py` into the real
  tree and puts them back; under `pytest -n 8` a test that loads the library in that window sees the
  stripped check (measured on 3.12: a receipt signed by an untrusted key read as verified in
  `test_verify_pre_tag_receipt_third_party.py`; on 3.11 the library was read half written and lacked
  `load_trusted_pubkeys`). `tests/test_byte_freeze_zweite_haelfte.py` unpacks an sdist into the tree root while
  it runs. Both pass alone. Not P0 or P1: CI runs pytest in one process, so the release gates never see
  the race, and no shipped code is involved; the local parallel measurements of this chain carry it as
  known noise. The fix is to strip and unpack in a copy of the tree, after the tag.

- **A shipped test rewrites real repository files in place while it runs** (P3, on main, seen by the rounds of
  the small-order branch and the pre-tag cleanliness gate): `tests/test_gate_qualification_harness.py` plants
  its strips in `scripts/pre_tag_receipt_lib.py` and `scripts/type_confusion_gate.py` and restores them after.
  Under a parallel local run (`-n 8`) another worker can read a stripped copy: measured, a third-party receipt
  test copied `if False and (signer not in trusted_pubkeys):` into its fixture and reported VERIFIED for an
  untrusted key, and a site-data test read an empty file. CI runs `python -m pytest -q` without workers, so its
  verdicts are not affected; the harness gets private copies after 6.2.0.

- **Six more modules read a timestamp or a schema version with `\d`** (P2, the neighbours of the declaredAt fix
  above; owner choice of 2026-09-28: fixed after the tag as a small pull request). Lines as at 373bf64b:
  `decision.py:30` and `:32` (read at `:200` for `decidedAt`/`recordedAt` and `:182`), `outcome.py:36` and `:38`
  (`:146`, `:114`), `run_ledger.py:30` and `:32` (`:158` `startedAt`, `:76`), `verification_summary.py:29` and `:31`
  (`:81` `producedAt`, `:73`), `agent_review.py:91` and `:94` (`:494` `revisedAt`, `:913`, `:390`),
  `relation_statement.py:37` (`:79`); each accepts a non-ASCII digit that the JSON schema's ECMA-262 `\d`
  refuses. Not P0 or P1: the Rust verifier reads none of these fields (`is_rfc3339_z` has one call site,
  `edge.declaredAt`, and no version check), so they change no verdict between the two verifiers. Measured
  at 373bf64b over signed bytes: `decidedAt` with an Arabic-Indic digit, Python `ok` True and Rust
  `verify-relation` exit 0; a relation statement's `schemaVersion` `0.1.` with an Arabic-Indic digit, Python
  `ok` True and Rust `verify-relation-statement` exit 0, the same as for the ASCII controls. The fix takes
  `[0-9]` in all six, as `trust_pack.py:49` already does. Swept and not of this class:
  `adapters/agt_receipt.py:354` (`_POSTEN`, a CPython buffer format) and `:1069` (`_KETTENPRAEFIX`, a
  prefix the package builds itself); outside the package, `scripts/findings_register.py:291` holds the same
  pattern for the register's own timestamps.

- **Pull request 300 copies every attached entry without the structural budget** (P2, Codex round three on pull request 300
  at 373bf64b, thread 4124587746, `src/proofbundle/relation.py`, `_read_attached_entries`). Reading each entry on
  its own, the fix of thread 4121924153 takes a plain copy of every attached entry, also one no edge names, and
  that copy does not apply `enforce_structural_budget`. Measured 2026-09-28 with an entry holding ten times the
  `json_nodes` budget (2 000 000 `None`): on main 86671552 the call takes 0.2 MB at most and does not read the
  entry; at 373bf64b it takes 0.44 to 0.51 s and 33.1 MB at its peak, with one edge and without. The verdicts are
  the same on both trees in every case measured (`NOT_EVALUATED` without edges, `DECLARED_UNRESOLVED` and `FAIL`
  with one). Not P0 or P1: no verdict, exit code or signed property changes, and the cost is linear in an object
  the caller already holds; the release exit rule's "a bound" is read here as a bound a verdict states, which
  this is not. The fix copies only the entries an edge names, and those through the budget, after 6.2.0.

Named by the fix of the Codex P1 on pull request 300 (thread 4121924153) as the same pattern elsewhere and
not changed there, each measured by that fix's sweep:
- **`agent_review.evaluate_time_policy` reads axes or a policy that hold one value that is no JSON value as empty**
  (P2, `agent_review.py:2266`, `_gelesen_oder_leer`): a CONFLICT axis beside such a value gives
  `insufficient_evidence` instead of `reject`; neither answer accepts.
- **`policy.explain_policy` and `lint_policy` read such a policy as empty** (P2, `policy.py:1369`,
  `_gelesene_richtlinie`): `explain_policy` returns no pins and `lint_policy` fails naming "pins nothing"; both
  are diagnostics, no verdict reads them.
- **`sdjwt_vc` reads a metadata cache holding such a value as no cache** (P3, `sdjwt_vc.py:113`,
  `_plain_metadata`): documented, and fail-closed.

Drafted from the lens of the small-order branch at 06f84b88 (pull request 293), measured by that lens:
- **A caller object's finalizer runs when the list reader lets go of its last reference** (P3): an
  exception there is unraisable and the verdict is the one of a direct call. It can only be named, not
  closed.
- **A receipt key that is a `str` subclass with its own `__hash__` is read by its text** (P3): the
  verdicts move from 2 or 1 to 0 with a valid signature over exactly the judged bytes, and the
  CHANGELOG line for it is missing; the public `payload_hash` and `canonical_payload` still read by
  lookup, so for the same receipt `payload_hash` raises `AGTReceiptError` while the chain verifier
  accepts it.

Drafted from the lens of the release-scope cut (pull request 294) at 3892f291, measured by that lens; its
P2 was corrected in 351fce0c:
- **Four quoted titles are the commit subjects on main, not the later pull-request titles** (P3, #246,
  #268, #269, #286): no item moves between releases because of it.
- **"Named by a landing" is loose for the rewrite of the scope file by pull request 251** (P3): no line
  of the scope moves because of it.
- **The column-rename test measures nothing for the 6.2.0 scope file** (P3): the file has no `| Item |`
  header left, so its four subtests for this file cannot fail; for the 6.3.0 file (nine headers) it
  still measures.

From the filer's re-measurement of a foreign review of the resolver branch (pull request 291) at 3a8074fc:
- **The case that passes the resolvers through the public verifiers does not assert that the answer's
  own `__bool__` stayed unasked** (P3): measured, it stays unasked (`asked` 0 through
  `verify_outcome_receipt` and `verify_decision_receipt`); only the test's assertion is missing.

Drafted from the lens of the small-order branch at 75c3aa48 (pull request 293, run 7), measured by that
lens; its two P1s went into round 8 and are not listed here:
- **Large legitimate AGT payloads are canonicalised 4 to 8 times slower than before the depth ceiling**
  (P3): 10^6 small lists 0.30 s against 2.0 to 2.6 s, a 24 MB form 2.0 s against 8.2 s, measured on 3.10
  under a load near 30; linear, and no verdict changes. Not measured again after round 8; the branch landed at
  c9c274c4.

Drafted from the reviews of the Rust dependency audit (pull request 296 at 47adce3e and 5138b4d2):
- **The self-test prints the exit code of `cargo audit --deny warnings` and does not assert it** (P3, a
  foreign review, confirmed by reading): a non-zero exit there fails the step at the command before the
  gate, so no verdict depends on the missing assertion.
- **The self-test's listed-exception case passes because cargo-audit leaves an ignored ID out of its
  JSON** (P3, observation): measured with cargo-audit 0.22.2, a lock with rsa 0.9.10 beside the
  committed audit.toml gives `vulnerabilities.count` 0; the gate's own comparison against the listed
  IDs is exercised by the unit cases, not by the run against the real tool.

From lens run 4 on pull request 296 at d30f236e (verdict FIX_FIRST for one P1, C3, which is not listed here: it was
fixed at f97cb257 and re-measured there; Codex's later P1 on the database work tree, thread 4117518025, was reproduced
red in ce3430bd and ac9bea55 and fixed in 77a5bfb3 and 2cf9908f, the head that landed; the Codex series of the pull
request ended there without a finding). The author's three unmeasured points were measured by
run 4 and held: a sparse-spelling lock written by cargo itself fails the step, and an audit.toml under CARGO_HOME is
ignored while the checked-in one exists and refused otherwise. cargo-audit versions other than 0.22.2 stay out of scope
(the step pins 0.22.2).
- **The step audits `tools/pb_verify_rs/Cargo.lock` even when cargo builds pb_verify_rs from another lock** (P2): a root
  `[workspace]` with pb_verify_rs as a member makes cargo write and build from `/Cargo.lock` (smallvec 1.6.0 there,
  RUSTSEC-2021-0003), while the audited file is unchanged and the step ends with 0. P1 only if "pb_verify_rs's
  Cargo.lock" is read as the lock it is built from. The neighbour `package.workspace` was not measured.
- **A lock entry without a `source` line passes unaudited** (P2, from run 3): a path or workspace package, not a crates.io
  identity RustSec covers; the docstring says so.
- **A crates.io name in the wrong case passes** (P3): advisory names match case-sensitively. cargo 1.95 refuses such a
  dependency, and the job's build step removes the entry from a committed lock before the audit.
- **11 of 32 planted gate defects pass both the self-test and the unit tests** (P2; run 3 counted 19 planted, 2 caught
  by the self-test, 12 by the unit cases): the shipped gate has none of them, and the gap only lets a later regression
  through.
- **Sentences the measurements contradict** (P3): 4cc525d6 says "a line it cannot read is exit 2" (an unreadable
  audit.toml line outside the ignore list gives 1); MANIFEST.in says the shipped test loads the script (from the sdist
  the module is skipped at import, because `tools/` is pruned); the test's readiness check reads `Path.home()` instead
  of CARGO_HOME; "the self-test proves F1 to F3" proves one instance of each.
- **A lock file written by hand in a form cargo does not write** (a list entry without its trailing comma) is refused
  with exit 2 (the gemma review of run 4, measured by the filer: both real locks carry the comma on every entry); this
  fails closed.

From the review lens of the resolver branch (pull request 291) at 3a8074fc, measured by that lens:
- **`hf_evals.to_eval_results_entry(include_token="false")` included the token** (P3). Round 3 closes it,
  measured at c8865652 on Python 3.10.12: `"false"` raises `SwitchTypeError` naming `include_token`,
  the exact True includes the token, and False leaves it out. The line leaves this list once that head
  (or its successor) lands; until then it is kept as a record of what the round closed.

From the Claude lens run 3 of the resolver branch (pull request 291) at c8865652, measured by that lens; its two P1s
(an exception escaping a never-raise surface through a registered verifier's result or a passed dict) went into a
further round and are not listed here:
- **`root_authenticity_summary` reads a list subclass two ways** (P2): `bundle.py` builds its name map through the
  subclass's own `__iter__`, while the crypto gate reads what the list stores. The aggregate is fail-closed
  (safeForAutomation False, the stored value named); the single fields show PASS from an exact True that the
  caller's own object yields. Nothing reads worse than at 3a8074fc.
- **`_membership.type_name` has no test of its own** (P3): two planted defects in it stay green; its claims hold
  as measured, and it only builds message text.
- **A verifier result that is a `UserDict` or a `MappingProxyType` is a failed anchor** (P3): refused since the
  first round of this branch, documented ("the result must be a dict"), and fail-closed; main verified both.

From the Claude lens run 4 of the pre-tag cleanliness gate (pull request 249) at f5939ab0 (verdict WITHSTANDS),
measured by that lens:
- **The documentation still names `git show` as the way the anchor is read** (P3): `docs/PRE_TAG_AUDIT.md:28`, the
  docstring of `load_trusted_pubkeys` and the verifier's `receipt_read_from` field; the chain runs no `show` any more
  (traced: 30 git calls in the gate, 62 in the verifier), and the real read is stricter than the text.
- **An unreadable directory in the tree is refused with a Python traceback instead of a named reason** (P3): exit 1,
  no payload, and the audit does not run.
- **A foreign writer in the moment between the producer's walk and the start of the audit** (P3 by the lens): a file
  ignored by a tracked rule, written by a process other than the producer and the audit in that window, is not
  refused (simulated in process). The same write a moment later, during the audit, is outside the property by design
  and yields the identical receipt, so the window adds no capability (owner decision of 2026-09-27: P3). The
  remedy is to run the audit from an exported tree (`git archive` or a fresh checkout), where no foreign writer
  shares the directory; a candidate for 6.3.0.

From the Claude lens run 8 of the small-order branch (pull request 293) at fddc00f4, measured by that lens; its three
P1s (a caller's value checked through one read and written through another: the vkey name, the signers map, the
assemble body, the template overlay, the status, and a float subclass) went into a further round and are not listed here:
- **A large integral float in a trust-pack predicate raises the canonicaliser's own error** (P3): `version=1e16` gives
  `rfc8785` IntegerDomainError instead of TrustPackError in `build_trust_pack_statement`; `sign_trust_pack` gives
  TrustPackError, and the input is refused either way.
- **The depth statement for 600 levels does not hold for a list subclass on 3.10 and 3.11** (P3): those give the
  RecursionError message instead of the depth message; exit 2 and `readable` False on all five interpreters.
- **`build_trust_pack_statement` returns a parsed copy in RFC 8785 key order** (P3): `json.dumps` without `sort_keys`
  differs from the earlier head; the canonical bytes, the signed payload and every verdict are identical.
- **Two sentences on a dict subclass did not hold for one with its own `__iter__`** (P3), closed in the further round
  (068cd349): every checked and written value is read once from its storage, and the lens harness finds 0 of 4966 text
  cells against 104 at fddc00f4 (measured by that round, not re-measured here). By the same round's measurement, the
  three findings above are unchanged at 068cd349.

From the Claude lens of the release-scope cut (pull request 294) at 989b582c; its four P1s were closed in round 5
(346fa924) and are not listed here:
- **A reference whose line holds another quoted word of the same row passes** (P2): the reader checks that the named
  line holds a word the row quotes, not the one symbol the reference is about; the test names this limit itself.
- **Five- and six-digit abbreviations of a commit are not read** (P3): git resolves them, the reader starts at seven
  digits, and no scope file uses a shorter one.

From Codex round five on the release-scope cut (pull request 294) at 76f260a2, the last request of its series; its
P1 (an unreadable candidate scope read as one that names nothing) is fixed on the head that carries this file:
- **A shallow clone passes the case that holds the list of main against git without comparing anything** (P2, thread
  4125291624, `tests/test_release_scope_cut_holds.py`,
  `test_what_landed_on_the_day_of_the_cut_is_in_the_list_of_main_and_the_counts_match`): at depth 1 the case returns
  before its comparison with git and reports passed, where it should skip with NOT MEASURED. The same early return
  stands in `test_a_word_the_reader_takes_for_a_name_stands_in_the_files_and_names_no_commit`, whose history check
  is left out in a shallow clone. Not P0 or P1: both check this file's own record, not a verdict of the package, and
  CI's test job checks out the full history, where both compare. The fix skips with the reason, after 6.2.0.
- **Once the source version is 6.2.0, the title gate cannot read the 6.3.0 scope, and it is red on every pull
  request** (P2, found by the sweep for that P1 and measured at 76f260a2 over the real scope files, with the source
  version at 6.2.0 and no tag the clone shows): `docs/release_scope/6.3.0.md` has no `## Out` section and names no
  branch, so `lies_umfang` answers NOT MEASURABLE for it. While the source version is 6.1.0 the candidates are 6.1.0
  and 6.2.0, both readable, and nothing changes. With the source at 6.2.0, at 76f260a2 a branch of 6.2.0 was judged
  against 6.2.0 and every other branch against 6.3.0, red with NOT MEASURABLE; since the fix of that P1 every branch
  is red, because an unreadable candidate decides nothing. After the tag the gate judges 6.3.0 and stays red. Not P0
  or P1: the job is not a required context of `protect-main`, so it shows red and stops no merge, and every branch of
  6.2.0 has landed with this pull request. It ends when 6.3.0 names its first branch and its `## Out` section, which
  is work of 6.3.0.

From the deep gate of the release preparation (pull request 311) at 2348f0a7, which ended FIX_FIRST for the eight P1
in the section on the released 6.0.0 and 6.1.0 above. The owner's decision of 2026-09-29 made that a new iteration:
the class fix in pull request 312, this branch on the new main, and the gate once at its new head. These lines
entered with that iteration, before the gate at the new head, so they are not an edit after a closing round. Each
was judged real by at least two of three blind jurors; lines are as at 2348f0a7, and a line the filer measured
again at 87090ef2 says so, the others carry the jurors' measurement. Eight further lens claims were refuted by a
majority of the jury and are not listed. One of them still reproduces at 87090ef2: `automation_summary` reads the
caller's `result` through its own `get` and `__contains__`, so a dict subclass storing `ok` False reads as
`safeForAutomation` True, against its docstring's "ALWAYS blocks". The lens claimed P1; three of three jurors
refuted it as the caller's own claim with no fact of the package hidden, the shape of the
`root_authenticity_summary` line above, and every call site in the package passes a plain dict.
- **Merkle proof elements are copied before their count is capped** (P2): `verify_inclusion` and `verify_consistency`
  copy every `bytearray` or `memoryview` proof element before the `merkle_path` cap of 256, so 5000 aliases of one
  1 MB buffer raise a raw `MemoryError` out of a surface documented to return a bool. The direct Python API only:
  the bundle and the CLI decode proofs to `bytes`.
- **A witness roster is copied before its cap** (P2): `checkpoint.witness_quorum` materialises the whole roster and
  copies each entry through `str.__str__` before the `witnesses` cap of 256; `verify_tlog_proof` lets a raw
  `MemoryError` escape for aliased `str`-subclass entries or an unbounded iterator. The roster is relying-party
  configuration.
- **An OpenTimestamps height too large to render raises** (P2): `verify_evidence_pack` raises a raw `ValueError`
  (CPython's limit of 4300 digits on `int` to `str`) for a proof whose Bitcoin height is a huge varuint. Measured by
  the filer at 87090ef2: a 7226-byte proof with height 2^50000 raises at `anchors_ots.py:225` without and at `:253`
  with a relying-party header (`:211` and `:239` at 2348f0a7), where the height 800000 gives `needs_rp_trust` and
  `block_mismatch`. The CLI stays fail-closed with exit 2 (jurors' measurement).
- **Renewal work counts entries, not digest bytes** (P2 by the jury; the lens said P3): `renewal_work` bounds counts
  only. Measured by the filer at 87090ef2: `verify_sequence` over 10 000 single-ATS chains and one data digest of
  10^6 hex characters takes 5.4 s of CPU, 0.14 s with a 64-character digest, at a `renewal_work` of 10 000 against
  its 40 000 000; 2000 aliases of one ATS whose covered digest has 10^6 hex characters take 13.7 s, and 57.3 s
  with 4 000 000. Every verdict stays `ok` False, and the cost-curve test uses 64-character digests only.
- **The dual hash re-hashes the data once per key** (P3): `verify_dual_hash` hashes all of `data` once per
  `str`-subclass key that reads as a registry id (entries times `len(data)`, about 100 s per MB at the `json_nodes`
  cap). The direct dict path only, and the verdict stays correct; `compute_dual_hash` already deduplicates by
  `spec.id`.
- **A caller's own method escapes as a raw error at public surfaces** (P2): at 2348f0a7, `load_bundle`,
  `verify_evaluation_card`, `verify_prereg`, `verify_sample_opening` and `verify_mldsa` ran a caller's `__class__`,
  `get` or `__eq__` and let a planted `RuntimeError` escape. Measured by the filer at 87090ef2 with the jurors'
  reproducer: `verify_evaluation_card`, `verify_prereg` and `verify_mldsa` return their result now (pull request
  312); `load_bundle` (`bundle.py:256`) and `verify_sample_opening` (`persample.py:222`) still let it escape, and
  so does `automation_summary(required_checks=)`, which is outside the verify naming. A neighbour of the class
  named under "a caller's own Python objects can make a never-raise surface raise" below; JSON cannot reach it.
- The rollback comparison of `verify_sequence` was also filed as a P2 of this gate (two jurors P2, one P1). It is
  the site of the P1 on `known_newest_token_digest` above and closed with it.
- **Python and Rust disagree on a null relationships list** (P2): `relationships: null` on an attached target gives
  `VERIFIED` and exit 0 in `decision verify --with-related` and `FAIL` with exit 2 in the Rust `verify-relation`,
  whose `walk_chain` lacks the null guard that `successor_warning` has. A parity divergence; the Rust verifier is
  not shipped in the wheel, and no Python verdict is promoted.
- **An attached target that fails its own schema resolves VERIFIED** (P2): a target that fails its predicate schema
  standalone (exit 2) resolves `VERIFIED` in both verifiers, so the texts that say a target is `VERIFIED` only if it
  verifies standalone claim more than the parse check holds. No retraction is hidden; the fix narrows the texts or
  validates each type's schema.
- **The findings-register CLI does not apply key expiry** (P2): `scripts/findings_register.py` authorises anchor keys
  by role only and never applies `not_after`, so it exits 0 for an expired key where C12.2 fails. It is outside the
  wheel and no workflow runs it; the fix routes it through `audit_candidate_matrix._autorisierte_schluessel`.
- **C12.2 does not apply the self-registration check** (P2): C12.2 and the register CLI never apply the C3
  self-registration check that C6.2, C6.3 and C8.2 apply for the same anchor role, so a key added in the candidate
  commit turns C12.2 PASS. The jurors judged it P2; it is P1 only where C12.2's trust binding is read as claimed
  closed.
- **C11.2 decides the classifier by a pattern over the whole file** (P2): the release-deciding C11.2 decides that the
  package stays `4 - Beta` by a regular expression over the whole `pyproject.toml` text, so a Mature, Inactive or
  absent classifier passes when a comment or a description holds the Beta string. The fix parses the classifiers
  list.
- **Three readers of receipts and the register catch only decode errors** (P2 by two jurors; the third refuted it as
  outside the scope): `pre_tag_audit_gate._receipt_candidates`, `findings_register.verify_and_count` and the C12.2
  pre-read catch only `JSONDecodeError` and `ValueError`, so a deep array or a huge integer raises `RecursionError`
  or `ValueError` instead of a rejection. Fail-closed everywhere (CLI exit 1, matrix FAIL).
- **`render_release` binds `release_commit` by its length only** (P3): a 40-character revision expression (`HEAD~0`
  or `@~0` followed by more characters) or upper-case hex renders with exit 0 in a depth-1 and in a full clone, so
  the tree binding holds nothing for it. The fix requires `\A[0-9a-f]{40}\Z`, as `_HEX40` does.
- **`render_release` does not bind the source's tags to `--version`** (P3 by two jurors): a 6.2.0 note renders with
  exit 0 and a `v6.0.0...v6.1.0` comparison link.
- **`render_release.pruefe` compares `release_commit` through a `str` subclass's `__ne__`** (P3 by two jurors): from
  the Python API only, it then skips the ancestry and diff check; the CLI and JSON cannot reach it.

From the deep gate of the release preparation at the next head of pull request 311, 7409b123, after pull request 312
landed, which ended FIX_FIRST for the six P1 in the section on the released 6.0.0 and 6.1.0 above. These lines enter
with the iteration that fixes those P1, before the gate at the head after it. Each was judged real by at least two
of three blind jurors; lines are as at 7409b123 and carry the jurors' measurement. Six claims were refuted by a majority
of their jury and are not listed: five of the panel and one of the foreign-family re-measurement.
- **The renewal policy copies every entry before it reads the newest** (P2): `evaluate_renewal_policy` never had a
  `renewal_ats_chain` cap, and since pull request 312 it builds a fresh ArchiveTimeStamp for every entry. Three million
  aliases of one entry take 10 to 19 s and about 596 MB, about 120 times the CPU of the earlier reading; the verdict is
  unchanged, and only a caller's own Python list reaches it.
- **The renewal verifier caps its chain after the copy** (P2): `verify_sequence` applies `renewal_ats_chain` (10 000)
  only after it has built one fresh ArchiveTimeStamp for every entry, against its own comment; three million entries
  took 597 to 872 MB before the refusal `renewal:budget` False.
- **The FIFO guard checks a path and then opens it** (P2, CWE-367): `prereg`, `evalcard`, `load_bundle` and the CLI's
  input opener stat a path and then open it, so a path swapped in between, or a PathLike whose `__fspath__` answers
  twice, hangs the library and the CLI with no verdict. The fix opens once with O_NONBLOCK, stats the descriptor and
  calls `fspath` once.
- **The path argument of two verifiers still lets a caller's exception escape** (P2): the path of `verify_prereg` and
  `verify_evaluation_card` lets a caller's `__class__` or `__fspath__` raise a RuntimeError raw; the line above that
  says these surfaces return their result holds for the claim argument only.
- **The null relationships row, measured again** (P2): the row on `relationships: null` (Python VERIFIED, Rust FAIL)
  holds unchanged at 7409b123. Python itself refuses the same target standalone, and `walk_chain` treats null as
  absent, so the fix belongs on the Python side.
- **The small-order count of the carrier row** (P3): the row and the register note say that at 31816e08 the zero key
  verified 2 of 16; no committed carrier reproduces it (610 gives 7 of 16, 600 gives 1 of 16). The body set is to be
  named or the number corrected.
- **The row on three readers and a huge integer** (P3): it holds for `pre_tag_audit_gate._receipt_candidates` only;
  `verify_and_count` and the C12.2 pre-read refuse a huge integer cleanly, and the deep-array half holds at all three.
- The outcome verifier's second reading of a `bytearray` answer was filed once as P2 by its own jury; it is the P1
  above and closed with it.

From the deep gate of the release preparation at d97de8e5, the next head of pull request 311, which ended FIX_FIRST
for the two P1 in the section on the subject state and the empty CLI option above. These lines enter with the
iteration that fixes those P1, before the closing round. Each was judged real by at least two of three blind jurors;
lines are as at d97de8e5 and carry the jurors' measurement unless a line says otherwise. Three claims were refuted by
all three jurors and are not listed.
- The FIFO row above (CWE-367) holds at d97de8e5 and has more sites than it names: a PathLike that answers a regular
  file and then a FIFO passes the guard of `verify_evaluation_card`, `verify_prereg` and `load_bundle`, and the CLI's
  verify blocks in `openat` on a FIFO a symlink race swaps in (1 to 6 of 40 runs per juror); the same window stands
  at `policy.py:428`, `evalcard.py:63` and `prereg.py:63`, found by search. The fix is one shared opener with
  O_NONBLOCK and an fstat of the descriptor.
- **The structural walk bounds each string and not their sum** (P2): on the direct-dict path of `verify_bundle`,
  `verify_evidence_pack`, `verify_sample_opening` and `recompute_merkle_root_b64`, N aliases of one string of 999,999
  characters cost about 2.85 ms each (20,000 aliases about 60 s of CPU), where the file path refuses the same content
  by `input_bytes` at once. The fix is a running total of string and bytes lengths, keys included, capped at
  `input_bytes`.
- **Aliased `str`-subclass values are copied once per alias** (P2): after the walk, `canonical._plain_value` copies
  each alias, and a raw `MemoryError` escapes `verify_bundle`, `verify_evidence_pack` and `verify_sample_opening`
  under a 2 GB address-space limit. The Python API only; a new site of the class under "a caller's own Python objects
  can make a never-raise surface raise" below, closed by the same total cap.
- The row above on a caller's `__class__` at `load_bundle` and `verify_sample_opening` holds at d97de8e5.
- **The Rust relation statement verifier accepts seven statements the Python CLI refuses** (P2): `pb_verify_rs
  verify-relation-statement` exits 0 on a `schemaVersion` of 1.0.0, an integer or absent, on a `statementId` empty,
  an integer or absent, and on a non-canonical payload, where `relation-statement verify` exits 2. The row on six
  more modules above names only the non-ASCII `schemaVersion`, and the COVERED wording of the Rust parity registry
  for this pair claims more than holds. Rust is outside the wheel and the sdist.
- The null relationships row above holds at d97de8e5. The gate's lens read its sentence on `walk_chain` as wrong; a
  verify lens of pull request 311 measured it right for Python, whose `relation._walk_chain` reads null as absent,
  while the Rust `walk_chain` sends null to `malformed_ancestor`, which is the divergence the row names.
- **`render_release.lade` catches only `JSONDecodeError`** (P2): a very deep array, a 5000-digit integer or bytes
  that are no UTF-8 give a raw traceback with exit 1 instead of a refusal with exit 2. Fail-closed: no notes are
  written and the release step fails. A fourth neighbour of the row on three readers that catch only decode errors.
- **`pre_tag_receipt.py --assemble` reads `--context-in` and `--sig-file` without a guard** (P2, votes P2, P2 and
  refuted): a missing, invalid, non-UTF-8 or directory input gives a raw traceback with exit 1. Fail-closed, no
  receipt is written, and the tool is not shipped.
- **The docstring of `anchors.verify_anchors` says `require=''` is refused; the code reads it as no requirement**
  (P3): the result is SKIP without `require_met`, and a test pins that. The CLI fails closed on it
  (`verify --anchor-type ''` exits 3 since pull request 311). The fix corrects the docstring or refuses the empty
  string as `require_target` is refused.
- The count of the cross-check file in the section on pull request 313 above was wrong and is corrected there (P3;
  the filer measured 233 at both tags on 2026-09-29, as the jurors did).
- The README's current-release block named five and eight findings in the released versions; pull request 311 brings
  it in line with this file (P3).
- **`pre_tag_receipt_lib.verify_receipt` judges a receipt through its `get` and reads the signed items by index**
  (P3, votes refuted, P3 and P3): a dict subclass holding a receipt signed for another tree verifies for this one.
  Both shipped callers pass plain dicts from `json.loads`; the tool is not in the wheel.
- The row above on `render_release` binding `release_commit` by its length still reproduces at d97de8e5.

From the deep gate at 99f76ceb, the head of pull request 311 that carried the pre-tag receipt, which ended FIX_FIRST
for the one P1 on the whitespace nonce in the section above. These lines enter with the iteration that fixes it,
before the next closing round. Each was judged real by at least two of three blind jurors; lines are as at 99f76ceb
and carry the jurors' measurement. Four claims of the panel and one of the foreign-family re-measurement were refuted
by all three jurors and are not listed. The packaging lens of that gate ran no reproducer, so its targets were not
attacked there; that is a limit of the gate, not a line of this file.
- **A shared container is copied once per path** (P2): `canonical._plain_for_jcs` and `_plain_value` copy a container
  that appears on many paths once per path, with no node bound. Arguments that no budget walks,
  `verify_status_snapshot(now=)` and `verify_evidence_pack(rp_trust=)`, take four times the CPU for every two further
  levels of such a graph, and at a depth of 40 a raw `MemoryError` escapes. The Python API only, and no verdict is
  promoted. The fix routes these copies through the node and path bound of `plain_json`, or walks every copied
  argument through the budget.
- The row above on the sum of strings holds at 99f76ceb: the dict path accepts nine anchors of 999,999 characters
  each with `ok` True, which the file path refuses by `input_bytes`. No running total has landed.
- **The anchors container is budgeted per entry, not as a whole, and `rp_trust` is copied per entry** (P3, two of
  three jurors; the third read `verify_decision_receipt` as outside the scope, since it is not in `dir(proofbundle)`):
  the cost is the number of anchors times the nodes of `rp_trust`, on the CLI too with a large relying-party policy.
  The verdicts are right; only the cost grows.
- **`_strict_json` measures a `memoryview` by `len()`** (P3): a two-dimensional view or one cast to `Q` counts its
  first dimension, not its bytes, so 13 MB pass `string_len`; `verify_dual_hash` then skips its budget refusal and
  still answers `ok` False. The fix counts `nbytes`, as `anchors_ots` already does.
- **A multi-dimensional `memoryview` as the witness roster raises** (P2, three of three jurors; the lens said P3):
  `witness_vkeys` as such a view, even of one byte, lets a raw `NotImplementedError` escape `verify_tlog_proof`, a
  never-raise surface, and `verify_witnessed_checkpoint`; a zero-dimensional view raises a raw `TypeError` at the
  latter. The roster guard admits a `memoryview`, `_folge_von` calls `list()` on it, and `tlogproof` catches only
  `ProofBundleError`, `ValueError`, `TypeError` and `KeyError`. Relying-party configuration through the Python API
  only; not the row above on a roster copied before its cap.
- The null relationships row above holds at 99f76ceb: Python gives lineage VERIFIED and exit 0, Rust
  `malformed_ancestor` and exit 2, and both refuse the same target standalone.
- **`scripts/verify_pre_tag_receipt.py` catches only decode errors in `_measure`** (P2): a committed receipt holding
  a deep array raises `RecursionError` with a traceback and exit 1, which reads NOT_VERIFIED, against its docstring's
  "never raises". A fifth reader of the row above on readers that catch only decode errors; the tool is in the sdist
  only, and nothing is promoted.

From the deep gate at d388ed3d, the head of pull request 311 that carried the pre-tag receipt after the fix of
99f76ceb, which ended FIX_FIRST for the two P1 in the section above. These lines enter with the iteration that fixes
them, before the next closing round (owner decision of 2026-09-30). Each was judged real by at least two of three
blind jurors; lines are as at d388ed3d and carry the jurors' measurement. Four claims were refuted by the jury and are
not listed.
- **`verify_dual_hash` runs a non-dict Mapping's own `items()` unguarded** (P2): `hashalg.py:196-197`, so a raw
  `RuntimeError`, `KeyError` or `TypeError` escapes an exported never-raise surface. Nothing is promoted, since the
  structural budget refuses every non-dict Mapping afterwards. It came with pull request 300 (a1e9774e) and is a new
  site of the class under "a caller's own Python objects can make a never-raise surface raise" below.
- **`witness_quorum` frames the whole note once per roster entry** (P2): an in-budget tlog proof of 8 MiB with 510
  signature lines and 256 witnesses costs tens of seconds of CPU with a correct `ok` True (the jurors measured 40
  to 62 s, a verify lane on 6d674973 31.0 s on another machine load; the cost is the machine's). Each cap holds; their
  product (`input_bytes` times witnesses) has no bound. A sibling of the capped-axes product rows above; the roster
  is relying-party configuration.
- **`input_bytes` does not bind the direct text API of three verifiers** (P3): `verify_tlog_proof`,
  `verify_witnessed_checkpoint` and `verify_key_binding` take 67 to 136 MB and answer a correct `ok` True, while the
  CLI's `verify-proof` (exit 2) and `verify_bundle` over a dict (`string_len`) refuse the same bytes. Rejection
  parity breaks; nothing is promoted.
- The row above on an OpenTimestamps height too large to render holds at d388ed3d: a height of 2**50000 gives a raw
  `ValueError` from `verify_evidence_pack` (`anchors_ots.py:225` and `:253`), and the CLI stays at exit 2 without a
  traceback.
- **The wording of the empty-comparison guard claimed more than it reads** (P3): this file, the CHANGELOG and the
  test's docstring said the guard refuses "any comparison" of an option's spelling with `""`; `_leervergleiche` reads
  `==` and `!=` against the literal `""`, directly or through a local name, and no `in`, `is`, pattern, walrus,
  annotated or tuple alias or `b""`. No such form stands in `cli.py` at d388ed3d. The wording is narrowed in this
  iteration in all three places; the guard is not widened.
- **The Rust `verify-relation` does not check the canonical form of the main payload** (P2): `main.rs:2222-2231`
  (only `load_related` does, at `:2062-2065`), so a decision receipt with a JSON-escaped digit in `declaredAt`, or
  any other non-canonical byte, exits 0 in Rust and 2 in `decision verify`. The Rust binary is not shipped, and the
  `declaredAt` digit rule of pull request 300 holds (28 values, 0 differences). The `verify-relation` neighbour of
  the row above on the relation statement verifier and a non-canonical payload.
- **The README block and the release notes attribute the findings of d97de8e5 to the last round before the closing
  one, and do not name the whitespace nonce** (P3): the README's current-release block (the sdist's long
  description) and line 7 of `release_notes/RELEASE_NOTES_v6.2.0.md` call d97de8e5 "the last gate round before the
  closing one", which was 99f76ceb, and name no whitespace-nonce defect of the released 6.0.0 and 6.1.0 (exit 0 under
  the label `auditor-nonce` with the self-challenge indices), so this file's sentence that the notes name the
  affected versions and the effect does not hold for it. Text only. This iteration's README sentence on d388ed3d no
  longer calls d97de8e5 the last round; the nonce stays unnamed there.
- **`pre_tag_receipt_lib.verify_receipt` judges `audit_exit_code` by `!= 0`** (P3): line 651, so a receipt signed by
  a trusted key with `audit_exit_code` false, 0.0, -0.0 or 0e0 verifies as a successful audit. Reaching it needs the
  trusted signer, and the tool is in the sdist only. The fix is `type(x) is int and x == 0`.
- **The reproducible build takes untracked files** (P3): `build_reproducible.py` builds from the file system through
  `MANIFEST.in` with no cleanliness check, so an untracked file in a grafted directory ships in the sdist with exit 0
  and another digest, while `tree_digest` (from `ls-tree` of HEAD) stays the same. `release.yml` builds in a fresh
  checkout and is not affected. The same class as row S27 of `RESTRISIKO_600.md`, carried to 6.3.0.
- **`head_commit_epoch` reads the log's commit time under the caller's git configuration** (P3): with
  `log.showSignature=true` and a signed epoch commit, `int()` fails and the function returns 1700000000 without a
  word. d388ed3d is not affected, since c91da604 is unsigned. The fix pins `-c log.showSignature=false` (or the
  configuration environment) and makes the fallback loud.

From the verify lanes V4, V5 and V6 on 8f2fa980, the second fix of the gate at d388ed3d, before it was pushed. Their
P1 findings are closed by the fix and named in its CHANGELOG entry; these lines are what the lanes found that the fix
does not change. Each carries its lane's measurement unless it says otherwise.
- **At `decision verify` a passing `relations` section reads as no policy** (P2, V6-F2, the same at d388ed3d):
  `verify_decision_receipt` sets `policy_ok` from the `decision_receipt` section only, so a policy whose only section
  is `relations` makes the verify fail when one of its rules is broken (exit 3), and when every rule holds leaves
  `policy_ok` None and prints `POLICY: NOT_EVALUATED (no decision policy supplied)`: with `reject_retracted: true` or
  `reject_superseded: false` and no attached target the output is byte-identical to a verify without the policy.
  The section is applied; its verdict on a pass is not shown. A `relations` section that sets no rule is refused now
  (the CHANGELOG entry). The fix shows the relations verdict, in `policy_ok` or in a line of its own, after 6.2.0.
- **`verify --policy` reports `POLICY: OK` for a policy with nothing in it `verify` evaluates** (P3, V6-F13): a policy
  with only its schema and id, or only a `relations` or a `decision_receipt` section, gives `policy_ok` True with the
  warning that it attributes to nobody and `safeForAutomation` False, where the three receipt verify commands refuse
  such a policy. Its output is not that of no policy, and the warning is the documented answer of `verify` to a
  vacuous policy (P0-B of the audit of 2026-07-13); the rule of the receipt commands would change that contract, an
  item after 6.2.0.
- **An empty or unwritable `--out` escapes a signing command as a raw exception** (P3, V6-F11, the same at d388ed3d):
  `emit`, `emit-eval`, `intoto`, `svr` and the three `emit` subcommands open `--out` after they signed, and
  `FileNotFoundError` or another `OSError` leaves `main()` with a traceback. Nothing is signed that should not be; the
  output is lost. The template printers and `policy instantiate --output` write an empty value to stdout, named in the
  test's list of truth reads. The fix catches the write as the key file's is caught.
- **`join_test_result` raises `FloatDomainError` for a statement holding NaN** (P3, V6-F12, the same at d388ed3d and
  6d674973): an exception out of a never-raise surface; the input is refused either way.
- **What the reading at the call costs** (P3, V6-F6 and V6-F7, measured by the lane at 8f2fa980 with the pause):
  the lane measured 2 to 5 times the time of d388ed3d for a call with a small dict argument and about three times the peak memory for a structure argument, and a 200 MiB `bytearray` message copied twice where d388ed3d copies it once; a `memoryview` message that `verify_ed25519` refuses at every tree is copied first. The third form of the fix (085869313), measured by the filer on 2026-09-30 as the least of three alternating rounds over the lane's 55 cases: a median of 1.5 times the time at d388ed3d and 1.06 times that of 8f2fa980, at most 7.1 times for a small call (`cap1.check_cap1_document`, 0.010 against 0.071 ms) and 3.4 times for a large one (`validate_decision_predicate` over 90 000 nodes, 53 against 181 ms); the peak memory of a structure argument is about three times that at d388ed3d, and `verify_sequence` over 2000 renewals peaks at 3.3 MB against 0.4 MB, because each ArchiveTimeStamp is copied. Every case stays linear. A large `bytearray` is copied by each of the two collects, and the first copy is the one the body reads. Measured again at bdcbe909 in the same way, with nothing else of this release's work on the machine: a median of 1.01 times the time at 085869313 (at most 1.06), 1.47 times that at d388ed3d and 1.10 times that of 8f2fa980, at most 6.8 times for a small call and 3.47 times for a large one; the comparison of a named reader's two answers over 100 000 pairs or items takes 0.10 to 0.17 s and peaks at 35 to 56 MiB, linear in their size.

From the verify lanes V7 and V8 on 085869313, the third fix of the gate at d388ed3d, before it was pushed. The
P1 findings F1 and F3 of V8 and the P2 findings of both lanes are closed by the fix and named in its CHANGELOG entry;
these lines are what the lanes found that the fix does not change.
- **A memoryview whose format no view of private bytes can take stays the caller's view** (P1, V8-F2, the same at
  8f2fa980 and d388ed3d): a view of a ctypes array (`<H`, `>I`, `T{...}`) or of an `array('u')` is read by both
  collects and handed on, and a view that is not C-contiguous (a slice with a step, a Fortran-ordered view) is not
  read at all and handed on (its bytes are no one buffer, the lanes V12 to V14); the body reads the caller's view when
  it reads it.
  `merkle.verify_inclusion` read the proof first and the leaf later from two such views and gave True in 8 of 533
  runs where each state gives False. `memoryview.cast` takes none of these formats, and a view of the same bytes in
  format `B` would be another value to a reader that judges a buffer by its format (`adapters.agt_receipt._puffer`
  reads `<u` as text and `B` as bytes), so the copy keeps the caller's view. A buffer object that is no memoryview (a
  ctypes array, an mmap, a NumPy array) is handed on as the caller's object as well. The reach is the Python API,
  with such a buffer that the caller's own code changes during the call.
- **A value of the caller's own class inside a copied container decides through its own methods** (V8, E10, within
  the named limit above): a `str` subclass value whose `__ne__` depends on state gave `decision.action_outcome_proven`
  True in 62 of 183 runs where the states give None and False.
- **What the lanes did not run:** 123 public functions without a recorded call pair (V8, `not_swept_head.txt`), the
  corpus sweep with the free list drained, keys of a `bytes` subclass in a verdict sweep, a caller's `tzinfo`, a
  collection of the package's dataclasses racing a module import, fork, signal handlers and `sys.settrace`, and the
  cost of the third fix (measured by the lane V9 after the full suite).

From the verify lanes V10 and V11 on d58be0b8, the fourth form of that fix, before it was pushed. Their P2 findings
are closed by the fix and its fifth form and named in its CHANGELOG entry, up to the values the block of the lane V12
below names; these lines are what the lanes found that the fix does not change.
- **An iterator or a generator handed in as an argument is read by the body, after the other arguments were copied**
  (P1, V10-F1, the same at 085869313, 8f2fa980 and d388ed3d): an iterator over the caller's list, a generator
  expression, `map`, `itertools.chain` or `reversed` is no container the reading can copy, and it cannot be read
  twice, so the double collect cannot tell one state of it. `evaluate_public_transparency(witness_vkeys=<iterator>)`
  gave PUBLIC_TRANSPARENCY PASS in 297 of 968 runs where each state fails, and `emit_bundle(prior_leaves=<iterator>)`
  signed the payload of one state over the leaves of the other in 110 of 533; a list gives 0. `verify_anchors`, whose
  body reads the iterator at once, gave 0. The reach is the Python API, with an iterator over state the caller's own
  code changes during the call; the command line passes lists. Reading it at the call would consume the caller's
  iterator where the body refused before reading it and would not close the window; refusing it would change what a
  caller with a generator gets. Pass a list or a tuple instead, not an iterator, a generator, `map`, `chain` or
  `reversed`: with a list the same sweeps give 0 mixed verdicts. A fix comes after 6.2.0 as an item of its own.

From the verify lane V12 on d1c39ae3, the fifth form of that fix, before it was pushed. Its findings F2 to F4 are
closed by the fix and named in its CHANGELOG entry; these lines are what the lane found that the fix does not change.
- **A value the comparison does not read, built anew on each read by a Mapping that never changes, is refused as
  changed** (P2, V12-F1; 8f2fa980 and d388ed3d give a verdict, 085869313 and d58be0b8 refuse these and more): a
  `Fraction`, a `UUID`, a path, an `ipaddress` value, a `slice`, a `timezone`, a `str` or `bytes` subclass as a
  value, a datetime or time with a tzinfo, a memoryview that is not C-contiguous or a released one, a view of an
  OrderedDict, and an object of the caller's class; as a key or set item such a value built anew is compared with the
  one at the same place of the other answer, so the same keys in another order are refused too. `automation_summary` raises `_StandGestoert`, a `ProofBundleError`, where it gave a
  verdict; no verdict is promoted. Comparing such values would run code that is not the interpreter's own types' (a
  tzinfo's `utcoffset`, a caller's `__eq__`), or the copy hands them on as the caller's objects. `verify_rfc3161`
  refuses such an `rp_trust` in its body at 8f2fa980 already. A Mapping that returns the same objects on each read, or
  a dict, is read as before.
- **A plain dict in another order is one value, and the body writes the first answer's order** (P3, V12-F3): a
  result object whose `validate` lists the same pairs of a plain dict in another order on each call gives
  `evaluate_public_transparency` an error text in either order; the copy keeps the first answer's order, and the
  verdict is FAIL both ways (the rule of the lane V11: a dict that is no OrderedDict has no order in its value).
- **What the lane did not run:** the cost on a Mapping of 100 000 pairs, other Python versions, `-bb`, real threads, a
  reader that raises a RecursionError only on its second run, and plants of the second test file's own code.

From the verify lane V13 on 95c9f82a, the sixth form of that fix, before it was pushed. Its findings are closed by the
fix and named in its CHANGELOG entry. From this block on, by owner decision of 2026-09-30, a finding blocks this
release only when it gives a wrong verdict or shows a sentence of these texts to be wrong; a wrong sentence is put
right. Every other finding is a line here with an identifier, a severity and a workaround, and follows after the tag.
- **R620-V13-1, P2. A key of a type the comparison does not read, built anew, meets its counterpart only at the same
  place**: two answers that list such keys (a Fraction, a UUID, an object of the caller's class) in another order are
  paired in their stored order and called different, and the call is refused with `_StandGestoert`; no verdict is
  given and none is promoted. The values themselves are the first line of the block of the lane V12 above.
  Workaround: a Mapping that returns the same key objects on each read or lists its keys in one order, or a dict.
- **What the lane did not run:** real threads, other Python versions, `-W error` beyond `-bb`, tracing, a view changed
  while it is read, the cost on 100 000 pairs (the suite ran), and plants of the second test file's own code.

From the verify lane V14 on 6723bf24, the seventh form of that fix, before it was pushed. It found no two answers
called the same whose copies differ (about 1.3 million comparisons against an independent oracle) and no method of the
caller run. Its wrong sentences are put right in the CHANGELOG entry, the docstrings and the head of the class test
file; these lines are its other findings.
- **R620-V14-1, P2. Keys of one type and the same stored bits, built anew in another order, are refused** (V14-F1):
  the pairing takes the first key of the same type and bits, and the rest in stored order, so `{nan_1: "A",
  nan_2: "B"}` against `{nan_3: "B", nan_4: "A"}` is called different; the same for NaN inside a Decimal, a complex,
  a tuple or a frozenset key, and for a shared NaN key beside a fresh one. A never-changed Mapping that lists such keys
  in another order on each read is refused with `_StandGestoert`, where 8f2fa980 and d388ed3d give a verdict; in the
  same order it gives a verdict. No verdict is promoted. Workaround: list the keys in one order, or return the same key
  objects on each read.
- **R620-V14-2, P3. Keys the pairing cannot type, built anew in another order, are refused** (V14-F2): a subclass of
  tuple or frozenset (a namedtuple), a tuple or frozenset nested deeper than 16, and a tuple or frozenset holding a
  value the pairing cannot type are paired in stored order, so the same keys in another order are called different and
  the call is refused; in the same order the answers are one value. No verdict is promoted. Workaround: as R620-V14-1.
- **R620-V14-3, P2. 33 single defects of the comparison's rules are caught by no case of the class tests** (V14-F3):
  among them a float compared by part of its bytes, an int compared without its sign or its high part, a field of a
  date, a timedelta, a time or a datetime left out, the tail of an array or of an OrderedDict left out, 20 defects of
  the typed key, one of the pairing, and one that hashes a type through the caller's metaclass. The
  rules themselves hold at this commit: the lane found no false "same" and no caller code run. Workaround: none is
  needed by a caller; the cases follow after the tag.
- **What the lane did not run:** Python 3.12 and later, `sys.settrace`, fork and signals, plants in `_ein_stand`,
  `_abbild_stand` and `_bauen`, and the end-to-end cost of `automation_summary`.
- **R620-F12-1, P3. The generator of dataclass pairs skips a module that fails to import** (text lens on 6f485214,
  B-07): `test_the_second_collect_sees_a_change_of_class_of_each_kind` collects the dataclasses of the modules it can
  import and asserts only the measured pair `VerificationResult` to `Check`, so a dataclass in a module that fails to
  import is paired with none, and the case still passes (the lane planted `renewal.py` not to import: 30 pairs instead
  of 72). Measured at 6f485214 with the optional extras blocked: all nine dataclasses are found, and only the two
  `inspect_ai` modules, which define none, fail to import. No verdict is affected. Workaround: none is needed by a
  caller; the case will name the modules it could not import after the tag.
- **R620-F12-2, P2. The type comparison of a reader's two answers is held by no case for containers** (adversarial
  lens on 6f485214, F1): `canonical._derselbe` compares the type of two answers before it reads them
  (`typ is not type(b)`). The class tests hold that comparison for leaves (`1` against `True`), not for containers.
  With it kept for leaves and taken out for containers, the class test file passes (93 passed, 176 subtests), and a
  Mapping read through its own methods whose values are `Check` objects in one answer and `VerificationResult` objects
  with the same fields in the next gave a copy holding one of each, a state it never held, in 45 of 1349 swept calls;
  80 pairs of answers of the same contents but another class (the 72 pairs of the package's dataclasses and 8 kinds)
  were judged the same. At 6f485214 the comparison is in place: 0 of 1349, and none of the 80 judged the same. No verdict is affected. Workaround: none is needed by a caller; a case that falls
  without the comparison follows after the tag.
- **R620-F16-1, P3. "Every tuple is copied as a plain tuple" holds for a tuple the reading reaches as a value** (text
  lens on 2f858cce and cf5e1799, F-2): a tuple subclass used as a key of a dict or as an item of a set is not copied,
  because that dict or set stays the caller's object by the rule for keys that `canonical._bauen` names. The sentence
  stands in the docstring of `canonical._gleich_gelesen`, in CHANGELOG.md for 6f485214 and in the head of
  `test_the_second_collect_sees_a_change_of_class_of_each_kind`. No verdict is affected. Workaround: none is needed by a
  caller; the sentences are narrowed after the tag.
- **R620-F16-2, P3. The tuple case of the class generator holds the plain copy for a tuple in a list, not for a tuple
  inside a tuple** (same lens, F-3): a plant that keeps the class of a tuple subclass only where it sits inside another
  tuple passes the case (1 passed, 13 subtests). No verdict is affected. Workaround: none is needed by a caller; a case
  for the nested tuple follows after the tag.
- **R620-F16-3, P3. CHANGELOG.md and `canonical._gleich_gelesen` name the change of class for a tuple subclass without
  an instance dict only** (same lens, F-5): on Python 3.12 a tuple subclass with an instance dict takes another one's
  class too (hermetic-cleanroom at 238b23b7), where 3.10.12 and 3.11.15 refuse it. The copy is a plain tuple either
  way. No verdict is affected. Workaround: none is needed by a caller.

## Open — named limits carried by the fixes themselves

Collected from the CHANGELOG entries of this release; each entry names its own limits, and this list gathers
those on a verify, emit or release path:
- A key's `__eq__` can still run on a collision of `str`'s own 64-bit hash while an OrderedDict's own
  order is read.
- A whole ctypes array of `c_char_p` or `c_wchar_p` in a relying party's authorizer list is walked and
  each pointer read, by design; a pointer that names no valid address is not detected.
- A registered anchor verifier's `status`, `detail` and `trustedTime` are carried as given; no gate
  reads them.
- The pre-tag receipt producer refuses a clean tree that carries a `text eol=crlf` or `ident`
  attribute, a tracked or ignored name with a newline, or a gitlink (a submodule entry, also an
  uninitialised one). The release tree has none of these (the attributes and names measured by the
  review lens of pull request 249; 0 gitlinks and 0 names with a newline on main and on the
  branch head, measured on 2026-09-28); the fix comes after 6.2.0 as an item of its own.
- The pre-tag receipt chain is measured on Linux only. Its funnels compared git's top level with
  `--repo` as text, which refuses `C:/repo` against `C:\repo` on Windows (Codex on pull request 249,
  round four, P1, estimated); a510fc5a compares them as resolved paths, measured in the POSIX form of
  the defect (a `git` that answers `<root>/`). Windows itself was run neither for the defect nor for
  the fix, and no other place where the chain meets a Windows path was reviewed.
- The inventory that keeps proofbundle from signing with ECDSA reads the source, not types: a
  python-ecdsa signing key handed in from outside and called as `key.sign(data)` has the shape of the
  package's own Ed25519 signing and is not seen (a review finding on pull request 295). The case
  guards against a mistake, not against someone writing the package on purpose; the fix comes after
  6.2.0 as an item of its own.
- The Rust dependency audit reads its exceptions from `tools/pb_verify_rs/.cargo/audit.toml` beside the lock;
  when no such file lies there, cargo-audit 0.22.2 falls back to `$CARGO_HOME/audit.toml` (measured: an
  exception there is ignored while the file beside the lock exists, and applied without it). The CI step runs
  beside the committed file. At d30f236e the gate reads the file cargo-audit applied and refuses it when the one
  beside the lock is missing (lens run 4: exit 1), so the fallback no longer passes unseen.
- `build_eval_claim` with an identifier holding a lone surrogate raises a raw `UnicodeEncodeError` from
  `salted_commit` instead of `EvalClaimError` (a review lens on the commitment-pattern branch at
  fa555f13, finding L12; named there as not changed). It fails closed at the emitter; the error type is wrong.
- The copy of an OrderedDict bounds what its own order can hold through CPython's
  `gc.get_referents`; on another interpreter that check falls back to the earlier behaviour
  (commitment-pattern branch, round 10).
- `svr_properties` looks a check up by its name in a dict, `check_binds_bundle` compares the
  claim's values through their own `__ne__`, and `build_eval_claim` reads `n`, `samples`,
  `threshold` and `score` through the caller's objects; each signs nothing on its own and is named
  in the CHANGELOG of the commitment-pattern branch.
- The AGT adapter does not relate `agent_did` to `signer_public_key`: a receipt whose `agent_did` names
  another party verified with exit 0 under a fresh signer key. `trusted_authorizer_keys` is compared as text,
  so the real key in capitals or as raw bytes gives exit 3, on the closed side (small-order entry).
- A permissive flag reads a falsy non-bool (0, None) as False, the lenient branch where its default is True:
  `to_eval_results_entry(require_verified=0)` built an entry from a receipt that does not verify ("A
  permissive flag is True or False").
- `canonicalize` refuses the last two nesting levels `rfc8785.dumps` writes, and `canonicalize_statement`
  refuses a statement nested deeper than 64 levels, its structural budget; both deliberate (the eval-claim
  producer entry).
- The pre-tag receipt chain: an empty ignored directory is not reported (as with `git status --ignored`); a
  file that appears and is gone again between the two measurements is invisible to both; the verifier's
  `git status` takes the index's stat data on trust; a `PATH` that leads to a git wrapper is part of the
  trusted base, like the interpreter (the three pre-tag entries).
- The class fix of pull request 312 names four limits, none a promoted verdict: an `anchors` argument that is
  a falsy value of another type is read as no anchors (refused since pull request 313); a policy holding two `relations` keys with the same
  characters is refused with `policy_ok` False but without a relations code; a policy holding a float NaN is
  copied as a value; `agent_review.validate_time_claim` and `derive_limitation_codes` still read a caller's
  dict through its own `get` (read, not measured). Switches, and callbacks other than those of the receipt
  verifiers, are outside the sweep, as `_NICHT_IM_SWEEP` in `tests/test_one_reading_at_every_surface.py`
  states.
- The same fix makes `verify_sequence` build a fresh `ArchiveTimeStamp` from every stored entry, and that
  costs CPU time the CHANGELOG entry of pull request 312 does not name. Measured on 2026-09-29 at the
  `renewal_ats_chain` limit of 10 000 single-ATS chains, seven calls per run, three alternating rounds under a
  load near 12: a median of 0.072 to 0.074 s at 2074d814 against 0.123 to 0.141 s at 52231c95, about 1.8
  times. The cost stays linear and no verdict changes; the coverage job passed at the head of pull request 312.
  The wall-clock case of this axis in `tests/test_budget_kostenkurve.py` failed one run in three on each tree
  under a load between 17 and 22 (time exponent 1.23 at 2074d814, 1.33 at 52231c95), the class named under
  "wall-clock cases of the cost curve under load" below.
- Pull request 313 names these limits, none a promoted verdict: `statuslist.verify_status_snapshot`
  reports `self_issued` False when `receipt_issuer_pubkey` is no bytes value, a reported field no verdict
  reads; `verify_decision_receipt` reads `strict` and `require_derived_subject`, and `verify_sequence` reads
  `require_pq`, `require_current_hash` and `require_external_token`, by their truth, where a falsy value of
  another type means the default; the decision and outcome verifiers read the relations section of a policy
  that holds a value that is no JSON value after the resolvers ran, where `policy_ok` is False already;
  `agent_review` reads `blocking` and `require_coverage_status` of null as no rule, as its own loader does,
  kept for 6.2.0 by owner decision; and four mutation anchors of `scripts/mutation_check.py` for
  `relation.py` matched nothing, at main 52231c95 already (repaired in pull request 311, next line). One
  stricter verdict it names too: a well-formed `mldsa65` receiver key in a trust pack no longer lets a bare
  True reach INDEPENDENTLY_ATTESTED.
- The mutation anchors, repaired in pull request 311 before its gate. At main 52231c95, 19 of the 106
  operators of `scripts/mutation_check.py` named no site of the source (at v6.1.0 each of the then 100
  named one): the round-12 reading had rewritten the guarded lines. Pull request 313 brought one back; the
  18 others, four on `relation.py` among them, now name exactly one site, and
  `tests/test_every_mutation_operator_names_one_site.py` holds every operator to that on each pull
  request. Each of the 18 mutants was killed by its own test file in a local probe on 2026-09-29; two, the
  R7-2b lookups on `relation.py`, survived until a case with an empty or absent rule was added to
  `tests/test_never_raise_surface_family_property.py`. Operators 90 and 99 named guards no input reaches any
  more (pull request 313 refuses a non-dict checkpoint entry in the loader rule first, pull request 312 put the
  `data_digests` budget before the copy); each survived the test files that reach its module, and pull request 311
  draws them onto the live guards, where each is killed. The limit: the probe ran named test files, not the
  canonical mutation run, which is still to come.
- The build epoch was the commit time of HEAD, so the sdist and the wheel changed with every commit of the tag chain
  although their content did not, and the tagged commit, made after the signing, never built the bytes the signed
  soak and differential bind. Measured on 2026-09-29 in a local copy of the chain: the receipt commit, the evidence
  commit and the merge built three different sdists; with one epoch the three were byte-identical. The signed evidence of 6.1.0 binds sdist `62a00fb7…` and wheel `20bf3210…`, and PyPI
  carries `d6355491…` and `f4316416…`. Since pull request 311 the epoch is the time of the last commit that touches
  a path outside `release_notes/` and `audit_artifacts/`, the only two the tag chain writes (owner decision of
  2026-09-29). Whether the sdist and the wheel of 6.2.0 on PyPI equal the digests
  bound at the receipt head is measured after the release and recorded then.
- The fix of the gate at d388ed3d names these limits, none a promoted verdict but the first line of the block of
  the lanes V7 and V8 below. The reading at the call copies every dict, list, tuple, set, bytearray, deque and array
  and their subclasses, every memoryview it can rebuild, every view of a dict and every object of a dataclass of this
  package; a value of the caller's own class that is none (an object, a Mapping that is no dict, an object of a
  caller's subclass of such a dataclass) is read through its own methods by a named reader where a function reads one
  (`rp_trust`, `frozen`, the result of `automation_summary`, the consistency result of
  `evaluate_public_transparency`), before the first collect and after the second, and the two answers must be the
  same value; it is otherwise handed on as the caller's object. The items of a frozenset, a keys, values or items
  view of an OrderedDict (also `dict.keys(od)`), an iterator and a generator are handed on as they are (the last two: the first line of the block of the lanes V10
  and V11 below). The public instance methods of the package's classes do not take the reading. A dict with a key
  that is no exact str, int, float, bool, bytes or None, no `str` or `bytes` subclass and no tuple or frozenset of exact
  str, int, float, bool, bytes or None values, a dict whose keys meet as one in the copy (a `str` subclass beside the `str` it spells), a set of such
  items, and an OrderedDict whose own order cannot be read without hashing stay the caller's object inside the copy:
  a copy would run the key's own hash, or lose a key. The reading touches no state of the process: it reads every
  container twice and keeps the first reading when the second finds each of the same type and holding the same
  objects (the type since the Codex review of pull request 311, thread 4151141239: up to 6b02d9f7 a change of class
  between the collects was not seen, and a `VerificationResult` made a `Check` gave a copy of a state the value never
  held). A change that is made and undone between the two reads of one container, a change of its class included, is
  not seen (the ABA case of the double collect), and a change
  another thread makes in several steps is read in one of the states it passes through. After three readings in each
  of which the value changed, the function raises `_StandGestoert`, a `ProofBundleError`, also where a never-raise
  surface would otherwise answer. Two readings that are no one value cause it: code that changes the value while it
  is read, the caller's own or another thread's, or a Mapping or result object whose reader answers two reads with
  values that are no one value. Two answers are one value when the copies made from them would hold the same
  (`canonical._derselbe`): equal contents, in any order for a set, a frozenset, a dict that is no OrderedDict and the
  fields of an object of this package (up to keys that only their stored order pairs: R620-V13-1, R620-V14-1 and
  R620-V14-2 above), a caller's object only as itself, and an exact str, bytes, int, bool, a float
  of the same bits, a complex of the same bits, a range of the same start, stop and step, a Decimal of the same sign,
  digits and exponent, a date, a timedelta or a naive time or datetime of equal value and fold. Any other value built anew on
  each read is a change even when it is equal: the first line of the block of the lane V12 above. A RecursionError raised while the arguments are read is raised as it is, before
  the body runs, also at a never-raise surface. The reading costs two reads and one copy of the arguments per call
  from outside the package, linear in their size, and two runs of a named reader with one comparison of their two answers (the line on its cost above). A public function that the package's own code calls from inside the body of another
  reads nothing again, because what it is passed is that reading or was made from it, and a value the package hands
  on uncopied (a value of the caller's class under the limit above) is read by the inner function as the outer one
  would. A caller's code that names a module of this package as its own and runs while the package's code runs, as a
  gc callback can, is not read again at such a call; what it computes reaches no verdict of that call. The sweep
  reaches a window only if a tracked object is allocated in it. `verifier_block.attach` fills the caller's predicate
  in place by contract and does not take the reading. The file generator of
  `tests/test_an_option_given_an_empty_value_is_not_dropped.py` reads the options whose value reaches one of eight
  file readers in `cli.py`; a file read through another function is outside it.

## Open — a caller's own Python objects can make a never-raise surface raise

Owner decision of 2026-09-27 (the line for this class in 6.2.0): where a caller's object makes a verifier answer ok, PASS
or a signed property it should not, or makes a written byte differ from the judged one, the release blocks and the
branch closes it; where the object only makes an exception escape, with no promotion, it is a named limit here and gets
a branch of its own after 6.2.0.

Measured by the resolver branch's final round (pull request 291) over all 133 surfaces the package documents as never
raising: a planted dict holding a colliding key whose `__eq__` raises, or a value every special method of which raises,
lets the exception escape at 60 surfaces in 24 modules (the predicate validators, `agent_review`, `subject_binding`, the
`evalclaim` helpers; 23 of them at one shared read in the structural budget walk, `_strict_json.py:91`). The same holds
on main. JSON, the CLI and files cannot produce such objects; only a caller's own Python objects reach these
surfaces, and no promotion was measured at any of them. The branch closed the two sites where the same class did
promote (a registered anchor verifier's result, and the evidence ladder's digest object).

The shared reader of the producers (`_plain_value.plain_json`, small-order branch, pull request 293) belongs to the same
class (Codex, thread 4119391971, measured on 2026-09-28 at 068cd349): a value whose metaclass answers `__name__` by
raising, in a list, as a key, alone or as an `int` subclass, lets the caller's exception escape where the reader
promises its typed refusal; a plain `object()` gets the typed refusal. The value is refused either way, and nothing is
written.

A neighbour in the other direction (Codex, thread 4119394589, read on 2026-09-28 at 18e93d7a): the exact-type guard
on `policy_warnings` in `root_authenticity_summary` reads any `list` or `tuple` subclass, an empty one included, as
warnings present, so `safeForAutomation` stays false for an honest empty subclass (reproduced on main 86671552,
Python 3.10.12: `POLICY_WARNINGS_PRESENT`; a plain empty list gives no blocker). The guard does not read a
subclass through its own `__len__` on purpose; it fails towards no automation, never towards yes. The fix reads
the subclass by what it stores (`list.__len__` and `tuple.__len__` of the base type, as pull request 300 does for the related
map) and sweeps the sibling exact-type guards on containers, after 6.2.0.

## Open — `subjectContext.humanRef` is untyped

Owner decision of 2026-09-27: the typing comes with the next predicate version after 6.2.0.

## Open — the mutation gate counts a confirmation run without a verdict as SURVIVED

Measured by a review lens of the child memory cap (pull request 289): a confirmation run that ends
without a verdict is counted as SURVIVED rather than NOT MEASURED. The same stands on main before that
change, and that change adds no path to it on Linux. The shard-26 run of operator 96 belongs to the
canonical mutation run on the frozen tree, the first after the cap landed; this file is written before it.

## Open — wall-clock cases of the cost curve under load

`tests/test_budget_kostenkurve.py` measures time exponents. Under a machine load near 15 the
`input_bytes` case failed with an exponent of 1.23 against a bound of 1.2, on a tree with and on a
tree without the change being tested; alone it passed. The resolver branch's final 3.10 suite showed it
again (exponent 1.29 under a load between 14.5 and 35; the load-independent work-count exponent stayed
within its bound; 3 of 3 passes alone). On 2026-09-28, three alternating local runs of the curve test under a load
between 9 and 13: main passed 3 of 3; the resolver branch at 18e93d7a passed 1 of 3, failing `input_bytes` (1.27)
once and `json_nodes` (1.23) once, although `loads_strict` runs the same code on both trees. CI's test jobs passed
at the branch's previous head on all five interpreters. The same class outside this file: in a full 3.13 suite
of the commitment-pattern branch at 7cc8fa0b, run beside a second full suite, `tests/test_cap1_regeln.py`'s
linearity case measured an exponent of 1.354 against its bound of 1.35; alone it passed 3 of 3, and the branch
does not touch that file. In a local mutation baseline the
`renewal_work` case stopped the baseline of `bundle.py`. Whether CI on the frozen head shows it is a
measurement of the closing round; the mutation baseline allowlist is the owner's weighing.

The CPU bound of the same curve is at its edge on CI's shared runners. `renewal_ats_chain` at its limit of
10,000 has a bound of 1.0 s CPU (maximum over nine runs) under coverage. The coverage job of the resolver
branch failed on it at 1f76a305 twice (1.042 s, 1.068 s), passed at 18e93d7a, and failed at 3977fcdf (1.070 s).
The test's own measurement, run locally under coverage in three alternating rounds on 2026-09-28, gave a
maximum of 0.165 to 0.236 s on main 0ace3039 and 0.156 to 0.165 s at 3977fcdf: the branch does not raise the
cost, the runner does. The same job ran 57:49 of its 60-minute limit at 3977fcdf. A second attempt there failed
again (1.061 s). The cause is a second reader of the bound: `tests/test_structural_budget_reachability.py`
compared the maximum with the bare bound, without the machine factor and the reference-machine binding the
curve applies itself. The class fix (the second reader calls the curve's own verdict) lands with pull request 300 (commit 262ade50 there, cherry-picked from b8d7112c) and with pull request 249 (68745704, main 8da7ce16),
where the coverage job then passed in 37:19 against 58:51 before.

## Open — a docstring in shipped source names a local checkout path

`src/proofbundle/_membership.py` (the `is_bool` docstring, added in 1a1b09f2 on 2026-09-24) names the
local path of the maintainer's checkout. It is the only such path under `src/`; release records on main
(`RESTRISIKO_600.md`, `audit_artifacts/`) have carried local paths since 6.0.0. No verdict depends on
it. It stays in 6.2.0 because only a P0 or P1 reopens a frozen head; the sentence is rewritten after
6.2.0.

## Honest limits of this file

- **This file is written before the closing round**, so it cannot contain that round's findings. A
  finding of the closing round is a new iteration with a new freeze, never an edit to this file.
- **Several lines are measured before the freeze, on main or on a branch head**, each naming the tree it
  was measured on; the closing round repeats the ones it names on the frozen tree.
- **Lines from a lens or from Codex that the filer did not re-measure say so**; they carry the source's
  measurement, not this file's.
