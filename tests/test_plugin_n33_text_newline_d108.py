"""D108, Nachtrag 33, point 3 (fallbook S4): a gh text with a literal backslash-n is denied.

The order: where the command names a text, the gate checks it with the house's form; the fallbook's S4 denies `gh api
replies` whose text carries a literal line break character. Found by delta's fallbook (gate 44db2056): `gh api <path>
-f <value>` asked for another reason (net_unmodeled_git) and never for the text.

The rule: _guard_text_newline reads the texts a gh call sends as written, the value of --body, -b, --title, -t, --notes,
-n, --subject and of each field of `gh api` (-f, --raw-field, -F, --field, after `key=`), and denies, under both hosts, a
text that carries the two characters backslash and n: bash keeps them in double quotes and GitHub shows them where a
line break was meant. A text in $'…' carries the line break itself.

Outside `gh api`, -F names a body file and -m a milestone or the merge strategy (gh 2.89.0), so their values are no
text; a word the shell builds (an expansion, a substitution) is no text as written.

RED at 63b88d07: no such form got this reason. The controls get none.
"""
from __future__ import annotations

import time

import pytest

import test_plugin_n30_short_line_d72 as d72

gate = d72.gate
pytestmark = d72.pytestmark
_clean = d72._clean
HOSTS = ("claude", "codex")


@pytest.fixture
def repo(tmp_path):
    return d72._repo(tmp_path)


def _ids(out):
    return [] if out is None else [v.reason_id for v in out.verdicts]


def _out(repo, form, host="claude"):
    return gate.decide(form, str(repo), time.monotonic() + 60, host)


FORMS = [
    "gh api repos/b7n0de/proofbundle/pulls/12/comments -f 'body=Zeile eins\\nZeile zwei'",
    "gh api repos/b7n0de/proofbundle/pulls/12/comments/99/replies -f body=\"a\\nb\"",
    "gh api repos/b7n0de/proofbundle/issues/12/comments --raw-field body='a\\nb'",
    "gh api repos/b7n0de/proofbundle/issues/12/comments -F 'body=a\\nb'",
    "gh api repos/b7n0de/proofbundle/issues/12/comments --field=body='a\\nb'",
    "gh api repos/b7n0de/proofbundle/issues/12/comments -fbody='a\\nb'",
    "gh pr comment 12 -R b7n0de/proofbundle --body \"a\\nb\"", "gh pr comment 12 -b 'a\\nb'",
    "gh pr create -R b7n0de/proofbundle --title t --body \"a\\nb\"", "gh issue comment 3 --body='a\\nb'",
    "gh pr review 12 --comment --body 'a\\nb'", "gh pr comment 12 -b'a\\nb'", "gh release create v1 -n 'a\\nb'",
    "gh pr merge 12 --squash --subject 'a\\nb'", "gh pr create -t 'a\\nb' -b x", "gh pr create --title=x --body='a\\nb'",
    "gh api repos/b7n0de/proofbundle/issues -f 'title=a\\nb'", "bash -c \"gh pr comment 12 --body 'a\\\\nb'\"",
    "git status && gh pr comment 12 -b 'a\\nb'", "env GH_REPO=b7n0de/proofbundle gh pr comment 12 -b 'a\\nb'",
]


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", FORMS)
def test_D108_a_gh_text_with_a_literal_backslash_n_is_denied(repo, form, host):
    out = _out(repo, form, host)
    assert out is not None and out.decision == "deny" and "text_literal_newline" in _ids(out), (form, host, _ids(out))


@pytest.mark.parametrize("form", ["gh pr comment 12 --body $'a\\nb'", "gh pr comment 12 --body-file note.md",
                                  "gh pr view 12 -R b7n0de/proofbundle", "echo 'a\\nb'",
                                  "gh api repos/b7n0de/proofbundle/pulls/12 --jq '.body | split(\"\\n\")'",
                                  "gh pr comment 12 --body 'one line'", "printf 'a\\nb' > note.md",
                                  "gh pr comment 12 --body \"$(printf 'a\\nb')\"", "gh pr comment 12 --body \"$TEXT\"",
                                  "gh pr create -m 'milestone\\nx' -t t -b b", "gh pr comment 12 -F 'notes\\new.md'",
                                  "gh api graphql -f query='{ viewer { login } }'"])
def test_D108_control_no_literal_backslash_n_in_a_text(repo, form):
    assert "text_literal_newline" not in _ids(_out(repo, form)), form


def test_D108_the_reason_catches():
    assert "text_literal_newline" in gate.FANG_REASONS and gate._SHORT_REASONS["text_literal_newline"][0] == "D108"
