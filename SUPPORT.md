# Support

Where to ask, what is maintained, and what belongs somewhere else. This page describes what already
happens; it does not add a promise.

## Which versions are maintained

**Only the latest released minor version of the current major line.** That is the same sentence
[SECURITY.md](SECURITY.md) states for security fixes, and it is deliberately not a second, softer
rule for non-security questions — two rules would mean the stricter one is only true on paper.

At the time of writing the current line is **3.x**, and the latest release is the version in
[`pyproject.toml`](pyproject.toml). This page does not repeat the number: a page that states a
version becomes a place that goes stale, and `scripts/check_version_and_changelog.py` reports exactly
that class of drift.

Older lines (`release/*` branches, older tags) stay readable and stay published on PyPI. They do
**not** receive fixes. If you depend on one, pin it and read the
[CHANGELOG](CHANGELOG.md) before you move.

## Where to ask

| You want to | Go to |
|---|---|
| ask a question, report a bug, request a feature | **[GitHub Issues](https://github.com/b7n0de/proofbundle/issues)** |
| report a vulnerability | **not here** — see [SECURITY.md](SECURITY.md) |
| propose a change | [CONTRIBUTING.md](CONTRIBUTING.md) |
| know who decides | [GOVERNANCE.md](GOVERNANCE.md), [MAINTAINERS.md](MAINTAINERS.md) |

GitHub Discussions is **switched off** for this repository, so Issues is the one place. That is a
measured statement, not a preference: a link to a forum that does not exist is worse than no link.

## A question and a security report are not the same thing

A question is public by design: it is filed in the open, answered in the open, and the answer helps
the next reader.

A vulnerability report is **not**, and it must not arrive as an Issue. The process, the contact and
the disclosure handling live in [SECURITY.md](SECURITY.md) and are deliberately **not repeated here** —
a duplicated security process is a process with two versions, and the one you read might be the old
one. If you are unsure which of the two you have: treat it as a vulnerability and follow SECURITY.md.

## What you can expect, honestly

There is no response-time commitment, and this page will not invent one. proofbundle is maintained
by a single maintainer (see [MAINTAINERS.md](MAINTAINERS.md)); issues are read, and there is no
staffed rotation behind them. Stating a service level nobody is on call to keep would be worth less
than saying so plainly.

What *is* enforced rather than promised: every release answers the release gate in
[RELEASE.md](RELEASE.md) before it goes out, and the CI checks that gate mechanically.
