# Addendum to RESTRISIKO_610, 2026-09-25: two named limits of the release-integrity gate

`RESTRISIKO_610.md` is frozen, and what comes after the tag is recorded in a dated addendum next to
it, never as an edit to that file. This is the second addendum. It carries two limits of
`scripts/check_version_and_changelog.py` that Codex measured on pull request 266 and that the pull
request names instead of closing. Both are register lines for the next patch release, and both err
in the same direction: a red finding over something unusual, never a silent pass over a stale pin.

## VERSION-GATE-COMMAND-SUBSTITUTION-NOT-LEXED-01

Codex on PR 266, round seven, thread 4106147217. A POSIX shell lexes a command substitution, `$(...)`
or backticks, recursively, so a `#` inside `"$(cmd # note \` starts a comment there and the trailing
backslash continues nothing. `_kommentar_beginnt` keeps the outer quote state and reads that `#` as
text, so `_logische_zeilen` joins the next line. Measured at the head of PR 266: the two-line script
`echo "$(pip install requests # comment \` followed by `proofbundle==X)"` is reported as a project
pin, where the shell runs two separate commands.

Why it does not block: the error is loud. A joined line can at most produce a finding a person looks
at, and a real pin on the next line stays in the joined text. The opposite error, a comment read
where the shell reads text, would hide a pin. `test_a_command_substitution_is_not_lexed_and_the_error_is_loud`
pins the direction, so a change that closes the limit turns that case red on purpose.

What closing it needs: a reader that tracks nested substitution contexts instead of one outer quote
state. Its target is the next patch release.

## VERSION-GATE-AMBIGUOUS-REF-END-READS-LOUD-01

Codex on PR 266, round eleven, thread 4106823987. `git check-ref-format` accepts `refs/tags/vX,`, so
a Markdown link whose destination ends in `…/releases/tag/vX,` right before its closing parenthesis
can select the tag `vX,`, and both URL shapes read it as release X.
The same run before a closer is prose in `(released as …/vX!)`. The two texts differ only in what
stands before the URL, and reading that context would need a second capture in every pattern that
Check 4 and Check 6 read with one.

Why it does not block: where the text is ambiguous, the reading is the loud one, a red finding over
an unusual tag name. Where it is not ambiguous (`vX,notes`), the name continues, as round ten made
it. The four cases of `test_a_terminal_run_before_a_closer_is_read_as_the_version` pin the direction,
each with the precondition that git accepts the tag the run would name. The sibling, a closer
directly after the version with more of a tag name behind it, is pinned by
`test_a_closer_directly_followed_by_more_of_a_tag_name_is_read_as_the_version`.

What closing it needs: telling a Markdown link destination from prose by the text before the URL,
in each pattern that reads a version at a ref position. Its target is the next patch release.

## What this addendum does not do

It does not change the frozen file or any digest recorded about it. It does not claim that these are
the only limits of the gate: the module and the comment on `_REF_ENDE` name others, among them a
range that excludes the current release without pinning one, a compare URL read at its first ref
only, and a correct headline hidden in an HTML comment next to a reworded visible one.
