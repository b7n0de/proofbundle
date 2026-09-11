# DRAFT — security advisory for the composite action (register entry N16)

**NOT PUBLISHED. NOT APPROVED.** Owner card `OA-78427865c7` answers option A with four
conditions, and the fourth is that the owner gives the GO per text and per target. This is
the text, for that decision. Nothing here has been sent anywhere.

The card's first condition fixes the order: **the advisory goes out TOGETHER with the new
tag, never before it.** A warning without an available fix is a public description of the
route, and a reader could do nothing but remove the action. Two further conditions from the
card are already built into the branch: the new tag is a PATCH tag and `v1.0.0` stays where
it is, and a moving major tag is introduced so a future fix reaches users at all.

---

## Draft text

**Affected:** `b7n0de/proofbundle/action` at `v1.0.0`.
**Fixed in:** `v1.0.1`, and available as the moving `v1` tag.

**What it is.** Two inputs of the composite action, `version` and `extras`, were placed
directly into the text of a shell script rather than passed as environment variables. A
workflow that forwards a value from an untrusted source into either input could therefore
have that value executed as part of the install step.

**When it matters.** Only when a calling workflow passes an externally controlled value
into `version` or `extras` — for example a value taken from a pull request title, a branch
name, or an issue body. A workflow that uses fixed values, as the documented examples do,
is not affected.

**What to do.** Change the reference from `action@v1.0.0` to `action@v1`, or pin
`action@v1.0.1`. No other change is needed. If your workflow forwards values from an
untrusted source into ANY action input, review that separately — this advisory covers this
action only.

**What changed.** Both inputs now travel through the environment, and each is checked
against its expected shape before use: a PEP 440 specifier for `version`, a
comma-separated list of names for `extras`. A value outside that shape stops the step with
an error rather than being passed on.

**Credit.** Found in an internal review of the release record, not reported externally.

---

## Deliberately absent

No exploitation instructions, per the card's fourth condition. The text names the affected
version, the new tag, what a user should do, and the condition under which it is dangerous —
and stops there. The shape of the vulnerable construction is common knowledge in GitHub's
own hardening guidance; the specific payload is not written here.

## What still needs the owner

1. **The tag.** `v1.0.1` plus the moving `v1`. Outward-facing, per the card.
2. **This text.** GO per text and per target, per the card.
3. **The target.** GitHub Security Advisory, release note, or both — the card leaves this open.

Until all three are answered, `INTEGRATIONS.md` keeps pointing at `v1.0.0`: a document that
names a tag which does not exist yet would be worse than one naming an old tag.
