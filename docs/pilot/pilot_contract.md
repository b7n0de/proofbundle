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

The outcome refers to the decision by its content root, never the reverse. The mapping of gate fields and
GitHub observations onto the two predicates is the pilot profile (PB-02); this contract fixes only what must
be recorded. Refused actions get a decision receipt and, if GitHub nevertheless shows a matching effect, an
outcome receipt; that pair is the most important mismatch the pilot can find.

## 5. Measures

Per proposed action, each with a closed set of values. `unknown` and `not measured` are values of their
own and are never counted as agreement.

| measure | question | values |
|---|---|---|
| M1 arrival | Does the API return an effect for this proposed action? | arrived, not arrived, not yet observed, unknown |
| M2 bytes | Is the SHA-256 of the stored bytes the SHA-256 of the approved bytes? | identical, different, not measured |
| M3 surface | Is the observed surface the approved surface? | same, different, not measured |
| M4 closing lines | Do the stored bytes end with the closing lines the approved surface requires at approval time? | yes, no, not measured |
| M5 unapproved effect | Does the API show a write by an agent identity with no approval that matches it? | none found, found, not measured |
| M6 refused but arrived | Does an effect match an action the gate refused? | none found, found, not measured |
| M7 delay | Time from the verdict to the first observation | seconds, recorded, never judged against a target |
| M8 attempts | How many verdicts were recorded for one action id? | a count |

An approved action reconciles only when M1 is arrived and M2, M3 and M4 each hold. A refused action
reconciles only when M1 is not arrived; M2, M3 and M4 are not part of it. Every other combination is a
mismatch with a name. M5 and M6 are measured over the observation window, not per action; "none found"
means none found in what the API returned then, and says nothing about writes the API does not list.

## 6. Exit criteria

The pilot ends, with a written result, when all of these hold:

1. every surface in scope that the repository's rules let an agent session write has at least one action
   whose decision and outcome receipts verify offline with the operator's two public keys, and whose
   reconciliation is recorded; a surface the rules forbid to agents (AGENTS.md forbids opening, marking ready,
   approving and merging a pull request) needs no approved action and is covered by M5 and M6, where any agent
   write found on it is a mismatch;
2. every mismatch observed has a named class and a decision by the maintainer (change the gate, change the
   agent, change the rule, or accept);
3. a person who was not part of the sessions reruns the reconciliation from the stored receipts and the
   stored API responses and gets the same classification for every action;
4. none of the stop conditions below has fired.

It stops early, with the reason written down, when:

- recording the gate's verdict would require changing how the gate decides;
- the observer would need a credential that an agent session holds;
- a receipt would have to carry a secret, a token or a private key;
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
- Refused actions keep only the SHA-256 of the proposed bytes and the gate's reason, never the bytes.
- No record carries an access token, a request header, a private key or the content of the environment.
- The stored API responses are kept as returned, with the time of the request, so that criterion 3 can be
  met without calling the API again.

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
- The observation window and how often the observer reads the API: the operator's choice, recorded with each
  run.
