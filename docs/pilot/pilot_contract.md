# Pilot contract: approved agent actions and what GitHub shows

This contract fixes the first pilot of proofbundle's decision and outcome receipts. The pilot uses the
project's own work: coding-agent sessions write to this repository on GitHub, an outbound gate decides
before each write, and GitHub's API shows afterwards what arrived. An outside receiver comes later; this
contract does not cover one.

Status: a contract for a pilot that has not started. Nothing below is measured unless it says so, and no
number in it is a target.

## 1. The named question

**Which approved action actually arrived on GitHub, and in which form?**

"Arrived" means the GitHub API returns it. "Form" means the bytes, the surface (conversation comment,
review-thread reply, pull request body, commit, merge) and the closing lines the surface requires. An action
can arrive with its approved bytes on a surface it was not approved for, and that is an answer to the
question, not a success.

## 2. Scope

In scope:

- every write an agent session makes to this repository through the GitHub CLI, the GitHub API or
  `git push`: conversation comments, review-thread replies, pull request titles and bodies, commits pushed to
  a branch, and merges;
- the outbound gate's verdict for each such write, as the gate records it;
- the GitHub API's view of the repository after each write.

Out of scope:

- whether the written text is true, and whether the change it describes is correct;
- writes by people, and by bots other than the agent sessions;
- other repositories, other forges, and anything outside GitHub;
- the agent's reasoning or intent.

## 3. Roles

| role | who | what it does | key |
|---|---|---|---|
| producer | an agent session | proposes one action: surface, target and the exact bytes | none of the keys below |
| decider | the outbound gate, run by the operator | allows or refuses the proposed action, with a reason, before the write | the gate's signing key, held by the operator |
| executor | the client call that performs the write | carries the approved bytes to GitHub | none (its effect is observed, not trusted) |
| observer | a reader of the GitHub API, run by the operator | reads what GitHub stores after the write | the observer's signing key, held by the operator, not by the agent |
| relying party | the operator and the maintainer | read the reconciliation and decide what to change | none |

The agent never holds the gate's or the observer's key. The observer reads a source the agent does not
control: what GitHub returns, not what the agent says it sent.

## 4. Records

For every proposed action the pilot keeps a signed decision receipt and, once GitHub shows an effect of it,
a signed outcome receipt, and joins them:

- a **decision receipt** (`decision-receipt/v0.1`) that the gate issues for its verdict: who proposed what,
  on which surface, over which bytes, and the verdict with its reason;
- an **outcome receipt** (`action-outcome/v0.1`, EXPERIMENTAL in the current release) that the observer
  issues for what GitHub shows: the observed surface and target, and the SHA-256 of the stored bytes.

Each decision receipt names its action and attempt in its `decisionId`, as `<action id>#<attempt>`, the form the
pilot profile fixes, so the stored records tell two verdicts for one retried action from one verdict for each of two
actions, and M8 counts the decision receipts that share an action id.

The outcome refers to the decision by its content root, never the reverse. The mapping of gate fields and
GitHub observations onto the two predicates is the pilot profile (PB-02); this contract fixes only what must
be recorded. Refused actions get a decision receipt and, if GitHub nevertheless shows a matching effect, an
outcome receipt; that pair is the most important mismatch the pilot can find.

## 5. Measures

Per proposed action, each with a closed set of values. `unknown` and `not measured` are values of their
own and are never counted as agreement.

| measure | question | values |
|---|---|---|
| M1 arrival | Does the API return an effect for this proposed action? | arrived, not arrived, ambiguous, not yet observed, unknown |
| M2 bytes | Is the SHA-256 of the stored bytes the SHA-256 of the approved bytes? | identical, different, not measured |
| M3 surface | Is the observed surface the approved surface? | same, different, not measured |
| M4 closing lines | Do the stored bytes end with the closing lines the approved surface requires at approval time, as recorded with the decision (section 8)? | yes, no, not measured |
| M5 unapproved effect | How many writes by an agent identity of the roster (section 8) with no approval that matches them does the API show? | a count (0 is none found), not measured |
| M6 refused but arrived | How many effects match an action the gate refused? | a count (0 is none found), not measured |
| M7 delay | Time from the verdict to the first observation | seconds, recorded, never judged against a target; no observation; not measured |
| M8 attempts | How many verdicts were recorded for one action id, read from the `decisionId` of the decision receipts (section 4)? | a count, not measured |

An approved action reconciles only when M1 is arrived and M2, M3 and M4 each hold. A refused action
reconciles only when M1 is not arrived; M2, M3 and M4 are not part of it. Every other combination is a
mismatch with a name. M5 and M6 are measured over the observation window, not per action, and each is a count, so
two writes are recorded as two; "none found" is the count 0 and means none found in what the API returned then, and
says nothing about writes the API does not list.

An effect is matched to a proposed action by its target and by the agent identity that wrote it, since the API shows
no proposal identifier. Surface, bytes and closing lines are not part of the match: they are what M2, M3 and M4
compare, so an action that arrived altered or on another surface answers under M2 or M3. Effects are taken in the
order the API shows them, and each takes one proposed action of the window with the same target and identity that
no earlier effect took: the one whose surface and bytes it equals when exactly one does, otherwise the earliest
decided, and among decisions with the same `decidedAt` the one whose `decisionId` sorts first, so the order is total. An effect that equals, in surface and bytes, actions of different verdicts is the mismatch class
`ambiguous effect`: M1 is `ambiguous` for each of them, it counts under M6 when any of them was refused, and it
still takes the earliest decided of them. An effect that finds no action left counts under M5 as an unapproved
effect, so one approval never covers two writes. The rule decides by the stored records alone, so a rerun under
criterion 4 reproduces every match. Matching by identity needs identities that only agent sessions write under: a
dedicated account or app per agent, named by the operator before the pilot starts (section 10) and kept as the roster
of section 8, so a rerun reads which writer is an agent's from the records and not from the operator. A write by a
person under such an identity cannot be told from an agent write, so the pilot stops when one is known to have
happened.

## 6. Exit criteria

The pilot ends, with a written result, when all of these hold:

1. every surface in scope that the repository's rules let an agent session write has at least one action
   the gate approved before the write, by a decision of type `preActionAuthorization` whose `decidedAt` is not later
   than the `performedAt` of the effect (a post-hoc review, a simulation, or an approval recorded after the effect
   does not count here), whose decision and outcome receipts verify offline with the operator's two public keys, and
   whose reconciliation is recorded with M1, M2, M3 and M4 each measured: an action with `not measured` or
   `unknown` in any of them does not count here, because it does not answer in which form it arrived, and a
   refused action does not count here even when it arrived, because the named question asks which approved
   action arrived, and a refused action that arrived is a mismatch under M6; a
   surface the rules forbid to agents (AGENTS.md forbids opening, marking ready,
   approving and merging a pull request) needs no approved action and is covered by M5 and M6, where any agent
   write found on it is a mismatch;
2. M5 and M6 have each been measured over the whole observation window, on every surface in scope, the forbidden
   ones included: a `not measured` value for either keeps the pilot open, because it would let a forbidden write
   pass unseen; and every proposed action carries the records and measures section 4 and section 5 define per
   action, as its reconciliation reads them: a decision receipt that verifies offline with the operator's gate
   key, and, for every effect GitHub shows of it, an outcome receipt that verifies with the operator's observer
   key; M1 as arrived, not arrived, or `ambiguous` once the maintainer has decided that class under criterion 3,
   M2, M3 and M4 measured when it was approved and arrived, and M7 and M8 recorded. A receipt that does not verify,
   `unknown` or `not yet observed` in M1, or `not measured` where one of the others is required, keeps the pilot
   open, because a mismatch whose authorship or form is not established cannot be decided; an action whose M1 is
   `ambiguous` is never the witness of criterion 1;
3. every mismatch observed has a named class and a decision by the maintainer (change the gate, change the
   agent, change the rule, or accept);
4. a person who was not part of the sessions reruns the reconciliation from the records section 8 keeps, and from
   nothing else, and gets the same classification for every action;
5. none of the stop conditions below has fired.

It stops early, with the reason written down, when:

- recording the gate's verdict would require changing how the gate decides;
- the observer would need a credential that an agent session holds;
- a receipt would have to carry a secret, a token or a private key;
- a person is known to have written under an identity the pilot reads as an agent's;
- the operator withdraws the pilot.

## 7. What the pilot does not claim

- A verified decision receipt proves that the gate signed that verdict over those bytes. It does not prove
  that the verdict was right, or that the gate saw everything relevant.
- A verified outcome receipt proves that the observer signed what it read from the API. It does not prove
  that the API was complete, that the content was not changed after the observation, or that nothing was
  deleted before it.
- Byte identity (M2) does not make an action correct, and does not by itself make the surface right; the
  first example below is a case of exactly that.
- "Not arrived" for M1 and "none found" for M5 and M6 are bounded by what the API returned during the
  window: pagination limits, deleted content, rate limits and eventual consistency can all hide an effect.
- The pilot says nothing about agents or gates outside this repository.

## 8. Data

- Approved bytes of actions that arrived are public on GitHub already; the records keep their SHA-256 and
  may keep the bytes.
- Refused actions keep only the SHA-256 of the proposed bytes and the gate's reason, never the bytes, in the
  gate's records and in the decision receipt. When a refused action nevertheless arrives, its bytes are public on
  GitHub, and the stored API response below keeps them as returned, because criterion 4 needs them to reproduce the
  M6 classification; that response is the only record of the pilot that holds them.
- No record carries an access token, a request header, a private key or the content of the environment.
- The stored API responses are kept as returned, with the time of the request, so that criterion 4 can be
  met without calling the API again.
- The closing rule each surface requires at approval time is kept with the decision record, as its text or as the
  digest of a versioned rule file kept beside the records, so that criterion 4 reads M4 against the rule that
  applied and not against a later one.
- The roster of agent identities, as the operator names it before the pilot starts (section 10), is kept beside the
  records before the first decision and is not changed during the pilot: each account or app by the numeric id GitHub
  gives it, which a rename does not change, and by its name. The match and M5 read which writer is an agent's from
  this roster and from nothing else.
- The observation window of each run, its start and its end as the observer applied them, is kept with that run's
  stored API responses, so that criterion 4 reads M5 and M6 over the same window.
- The two public keys the receipts verify with, the gate's and the observer's, are kept beside the records before the
  first decision, so that a rerun verifies against the keys the pilot named and not against keys handed over later.
- The reconciliation reads no input that this section does not keep. An input it would need and no record keeps is a
  gap in this contract, and the pilot does not start, or stays open, until a record keeps it.

## 9. First reconciliation example

A conversation comment on
[b7n0de/proofbundle#279](https://github.com/b7n0de/proofbundle/pull/279#issuecomment-5851339484), written
by an agent session on 27 September 2026, 00:40:09Z.

Measured on 27 September 2026, from the session's own record of what it sent and from the GitHub API:

- sent: 843 bytes, SHA-256 `16f9cad116366d7ada21de5327ed034c73a8d7eae69cd3508d449e125321ef92`;
- stored: 843 bytes, the same SHA-256; `created_at` and `updated_at` both 2026-09-27T00:40:09Z.

So M1 is arrived and M2 is identical. The mismatch is in the form: the comment ends with a closing sentence
that was written for replies in the threads of an external code-review agent, and it stands on a
conversation comment, a different surface. M3 depends on what the gate approved the comment as, and M4 on
the closing rule for that surface at the time. Neither the gate's verdict nor the surface it approved is in
the session's record, so both are **not measured** here. The operator has since retired that closing
sentence on every surface. The comment is left unedited, and the correction belongs to another session.

What the example fixes for the pilot: a reconciliation that compares bytes only would have called this
action reconciled. The surface and the closing lines have to be part of the approved action and of the
observation, or the named question cannot be answered.

## 10. Open before the pilot starts

- How the gate exposes its verdict, and in which format: not known to this contract; the operator names it.
- Whether writes made through an API client, rather than the command-line client, pass the same gate: not
  known. They stay in scope either way: a write that does not pass the gate has no decision receipt, so the
  observer reports it under M5 as an unapproved effect, and the result says how many there were.
- The observation window and how often the observer reads the API: the operator's choice, kept with each run
  (section 8).
- The identities that only agent sessions write under, one dedicated account or app per agent: the operator names
  them before the pilot starts and keeps them as the roster of section 8, and no person writes under them during it.
