# Addendum to RESTRISIKO_610, 2026-09-25: named limits Codex measured and the pull requests kept

`RESTRISIKO_610.md` is frozen, and what comes after the tag is recorded in a dated addendum next to
it, never as an edit to that file. This is the second addendum. It carries limits that Codex measured on pull requests of this
repository and that the pull requests name instead of closing: two of
`scripts/check_version_and_changelog.py` (pull request 266), one of the receipt chain of pull
requests 257 to 259 (pull request 265), and one of `classify_eval_claim` (pull request 268). All
four are register lines for the next patch release, and none of them turns a wrong input into a
`valid` or a silent pass.

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

## RECEIPT-CHAIN-PUBLISHED-INTERMEDIATES-UNNAMED-01

Codex on PR 265, threads 4104450705, 4104541548 and 4104709532. The receipts for pull requests 257,
258 and 259 were reissued several times, and each reissue on `main` names its predecessors, so the
chain of the files `main` carries today resolves to one current receipt per family. Measured on
2026-09-25 with `resolve_receipt_chain` over every version that was ever published at those paths,
in the history of `main` and on the branch of PR 265: five versions are named by no successor, the
first receipts of 257 from d4f5e478 and of 258 from e86d0d1f, and the `r2` receipts of all three
families as they stood at 92139fa9 on the branch of PR 265. A reader who kept one of them, for example from a commit-pinned link
in an earlier answer, and holds the current receipt too, sees two current candidates.

Why it does not block: the files on `main` resolve without ambiguity, every published version stays
signature-valid and reachable, and the ambiguity is loud, two candidates rather than a wrong one.

What closing it needs: one successor per family whose supersession names every remaining candidate
with its digest and a reason. Its target is the next patch release.

## FOREIGN-FORMAT-VERDICT-DEPENDS-ON-TRANSPORT-01

Codex on PR 268, thread 4105230532. `classify_eval_claim` reads a path through `load_bundle`, which
applies the byte cap before any field, while a parsed document carries no bytes and gets the
structural limits only. Measured on `main` on 2026-09-25: a document with a foreign `schema` and a
payload of 9.5 MiB split into strings under the per-string limit is `refused_unknown_schema` as a
parsed document and `invalid` as a file. The single long string Codex measured falls in both
transports today, through the string-length limit; the class does not.

Why it does not block: neither outcome is `valid`, the document is foreign in both readings, and
the asymmetry is stated in the function's own docstring.

What closing it needs: the byte cap applied to a parsed document through its canonical
serialisation, so that both transports refuse by the same rule. Its target is the next patch
release.

## What this addendum does not do

It does not change the frozen file or any digest recorded about it. It does not claim that these are
the only limits of the gate: the module and the comment on `_REF_ENDE` name others, among them a
range that excludes the current release without pinning one, a compare URL read at its first ref
only, and a correct headline hidden in an HTML comment next to a reworded visible one.
