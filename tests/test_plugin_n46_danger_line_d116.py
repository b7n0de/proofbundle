"""D116, Nachtrag 46, Teil C: every ask and every block of the gate names the danger in everyday words, before the D number.

The order: to each D number that asks or blocks, a short line in everyday language of what can go wrong, before the
number, which stays at the end. Measured in the retrospective of 89d2e8b7 (delta, 2026-10-18): of 13 mishaps the gate
saw it held 9, and only 3 of them with a fitting reason; a fitting reason names the real danger, not only an id like D3
or D27. The 18 cases of the retrospective stand below as a fixture, each with its mishap, its reason at 89d2e8b7 as the
order names it, a command that rebuilds it here, and the words of the danger the line of the head names. Whether the
line fits the mishap is for the retrospective at echo to judge, not for this test: it shows only that the line names
the words, and it names the cases where it does not, with the reason.

The rule (_SHORT_DANGER, _short_danger): the short line of an ask, a block and a warning gives, after "because" or
"weil", what can go wrong, in place of what the gate cannot tell (that stays in the long reason and the log); for the
not-free answer of D3 by its form (a commit, an add, a read). A reason of D53 that names the danger already stands
(_SHORT_DANGER_IN_REASON: the house rules of D73, the push targets of D86, the backslash-n of D108), and the held end of
the Stop hook keeps its line (Nachtrag 47). The block of D85 and a rewrite name the danger
first and then that there is no free way or the rewrite, so a cut at SHORT_LINE_MAX never takes the danger or its D
number. A card of D93 names the danger of the call the card asks about and then the card.

RED at 70e98e91 (before the rule), measured 19 of 35: the cases C1, C2, C3, S2, S5 and S9 of the retrospective in both
languages and S7 in German, the table of dangers, the cut, delta's rev-parse and the object form of a block without a
step. Green there as at the head: S1, S4 and S7 in English, whose old reason already named the danger, the hints S6 and
S8, the silent cases S3 and S10, and the controls.
"""
from __future__ import annotations

import os
import pathlib
import time

import pytest

import test_plugin_n29_work_profile_d71 as d71

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean

#: The ids of the table of D53 that are no ask and no block: a pass the user sees, an inactive gate, a hand-over, a
#: hint (D105, a pass with a line).
NOT_ASKING = {"free_work_branch_go", "free_local_reversible", "released_by_owner", "free_recorded_hooks",
              "free_bundle_fetch", "free_pr_edit_form", "free_pinned_state", "nothing_declared",
              "nothing_declared_locally", "done_only", "no_repository", "no_done_check", "local_order_stands",
              "handover_no_update", "handed_over", "hint_move_out", "hint_tmp_not_scratch"}

#: The 18 cases of the retrospective of 89d2e8b7. heute: the reason the order names; befehl: the rebuild ({R} the
#: repository, {T} the test's folder); de/en: words the line of the head names; None with warum: where it names none.
RUECKBLICK = [
    {"fall": "C1", "panne": "PR 2350 ohne Lesung gelandet", "heute": "D27 net_unmodeled_git",
     "befehl": 'gh pr merge 2350 --squash --body "$(cat notes.md)"', "kopf": "net_unmodeled_git",
     "de": ["nach außen", "Merge", "(D27)"], "en": ["act outside", "merge", "(D27)"]},
    {"fall": "C2", "panne": "25 offene PRs einer Sitzung", "heute": "D73 house_pr_limit, D3 push_not_measured",
     "befehl": "gh pr create --title t --body b", "kopf": "house_pr_limit",
     "de": ["offene PRs", "(D73)", "Karte"], "en": ["open PRs", "(D73)", "card"]},
    {"fall": "C3", "panne": "Codex-Antworten mit Werkzeugzeile", "heute": "D27 net_unmodeled_git",
     "befehl": 'gh issue comment 12 --body "$(cat answer.md)"', "kopf": "net_unmodeled_git",
     "de": ["nach außen", "Kommentar", "(D27)"], "en": ["act outside", "comment", "(D27)"]},
    {"fall": "S1", "panne": "Admin-Merge am roten Pflichttor",
     "heute": "D73 house_admin_merge, D27, D33 step_after_state_change", "befehl": "gh pr merge 330 --admin --squash",
     "kopf": "house_admin_merge", "de": ["--admin", "Schutz des Zweigs", "(D73)"],
     "en": ["--admin", "branch protection", "(D73)"]},
    {"fall": "S2", "panne": "Tag v6.2.0 ohne Messung der Schutzregel pypi",
     "heute": "D33 directory_unresolved, D73 house_tag_out", "befehl": "git tag v6.2.0 && git push origin v6.2.0",
     "kopf": "house_tag_out", "de": ["Tag nach außen", "Veröffentlichung", "Owner-GO", "(D73)"],
     "en": ["tag goes out", "release", "owner GO", "(D73)"]},
    {"fall": "S3", "panne": "Commit-Nachricht ohne Form gepusht", "heute": "still",
     "befehl": "git commit -m 'fix stuff' && git push origin claude/work", "kopf": "git_form_not_free",
     "de": None, "en": None,
     "warum": "das Tor prüft die Form einer Commit-Nachricht nicht; die Zeile nennt die Gefahr des Commits (D3)"},
    {"fall": "S4", "panne": "Codex-Antwort mit wörtlichem \\n", "heute": "D27 net_unmodeled_git",
     "befehl": "gh pr comment 12 --body 'Zeile eins\\nZeile zwei'", "kopf": "text_literal_newline",
     "de": ["wörtliches Backslash-n", "Zeilenumbruch", "(D108)"], "en": ["literal backslash-n", "line break", "(D108)"]},
    {"fall": "S5", "panne": "Commit nahm gestagte Löschung mit", "heute": "D3 git_form_not_free",
     "befehl": "git commit -m work", "kopf": "git_form_not_free",
     "de": ["Gestagte", "Löschungen", "(D3)"], "en": ["everything staged", "deletions", "(D3)"]},
    {"fall": "S6", "panne": "Prüfmanifest verschoben statt kopiert", "heute": "still",
     "befehl": "mv {R}/.proofbundle/evidence.json {T}/evidence.json", "kopf": "hint_move_out",
     "de": ["mv", "cp", "(D105)"], "en": ["mv", "a copy", "(D105)"]},
    {"fall": "S7", "panne": "pkill -f in der Kette", "heute": "D73 house_kill_pattern",
     "befehl": "make test; pkill -f pytest", "kopf": "house_kill_pattern",
     "de": ["Muster", "eigene Befehlszeile", "(D73)"], "en": ["pattern", "own command line", "(D73)"]},
    {"fall": "S8", "panne": "Hilfsdateien nach /tmp", "heute": "still", "befehl": "cp notes.md /tmp/helper.md",
     "kopf": "hint_tmp_not_scratch", "de": ["/tmp", "Scratch", "(D105)"], "en": ["/tmp", "scratch", "(D105)"]},
    {"fall": "S9", "panne": "168 Zeilen an ein Audit-Log", "heute": "still",
     "befehl": "cat lines.txt >> {T}/audit.log", "kopf": "append_outside_work",
     "de": ["außerhalb des Arbeitsordners", "Log", "(D104)"], "en": ["outside the work folder", "log", "(D104)"]},
    {"fall": "S10", "panne": "leere Datei /tmp/null", "heute": "D3 git_form_not_free",
     "befehl": "git status > /tmp/null", "kopf": "git_form_not_free", "de": None, "en": None,
     "warum": "die Zeile nennt die Gefahr des Lesebefehls (D3), nicht die Umleitung in eine Datei /tmp/null"},
] + [{"fall": f"F{k}", "panne": "Fertigmeldung ohne Beleg", "heute": "still", "befehl": None, "kopf": None,
      "de": None, "en": None, "warum": "eine Fertigmeldung; die prüft Nachtrag 47 am Stop-Haken"} for k in range(1, 6)]


def _repo(tmp_path):
    """delta's setting: the repository of b7n0de in the work profile of D71, on the own branch claude/work, with the
    repository's own pre-commit hook, a staged deletion, a reply with a tool line and 168 lines to append."""
    repo = d71._repo(tmp_path)
    d71._git(repo, "checkout", "-q", "-b", "claude/work", "topic")
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\nexit 0\n")
    hook.chmod(0o755)
    (repo / "answer.md").write_text("Antwort\n\nTool: Bash(git status)\n")
    (repo / "lines.txt").write_text("".join(f"line {i}\n" for i in range(168)))
    d71._git(repo, "rm", "-q", "README.md")
    return repo


@pytest.fixture
def session(monkeypatch, tmp_path):
    """A session of Claude Code under the temp folder (D104, D105), so the hint of a write into /tmp can stand."""
    temp = tmp_path / "temp"
    (temp / f"claude-{os.getuid()}" / "p" / "sess-n46").mkdir(parents=True)
    monkeypatch.setenv("TMPDIR", str(temp))
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", "sess-n46")


def _line(repo, command, language):
    """The answer of the hook under --autonomous and the short line the user sees, as pre_tool_answer builds it."""
    deadline = time.monotonic() + 60
    out = gate.decide(command, str(repo), deadline, "claude")
    if out is not None and out.decision == "ask":
        out = gate.autonomous_outcome(out, command, str(repo), deadline, "claude")
    if out is None:
        return None, None
    printed = gate.pre_tool_answer(out, "claude", {"session_id": "s"}, gate._short_step_name(command, str(repo)),
                                   environ={"PROOFBUNDLE_GATE_DIR": str(_language(language))})
    return out, (printed or {}).get("systemMessage")


def _language(language):
    folder = pathlib.Path(os.environ["PROOFBUNDLE_GATE_DIR"])
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "language").write_text(language + "\n")
    return folder


@pytest.mark.parametrize("language", ["de", "en"])
@pytest.mark.parametrize("case", [c for c in RUECKBLICK if c["befehl"]], ids=lambda c: c["fall"])
def test_D116_the_line_of_each_case_of_the_retrospective_names_its_danger(tmp_path, case, language, session):
    repo = _repo(tmp_path)
    command = case["befehl"].replace("{R}", str(repo)).replace("{T}", str(tmp_path))
    out, line = _line(repo, command, language)
    assert out is not None and line, (case["fall"], out)
    assert case["kopf"] in [v.reason_id for v in out.verdicts], (case["fall"], [v.reason_id for v in out.verdicts])
    words = case[language]
    if words is None:
        assert case["warum"], case
        return
    missing = [w for w in words if w not in line]
    assert missing == [], (case["fall"], line)
    d = next(w for w in words if w.startswith("(D"))
    assert line.index(d) <= gate.SHORT_LINE_MAX - len(d), line


def test_D116_the_fixture_holds_the_18_cases_of_the_order():
    assert [c["fall"] for c in RUECKBLICK] == ["C1", "C2", "C3"] + [f"S{k}" for k in range(1, 11)] + \
        [f"F{k}" for k in range(1, 6)]
    assert all(c["de"] or c["warum"] for c in RUECKBLICK)


def test_D116_every_reason_that_asks_or_blocks_has_a_danger():
    asking = set(gate._SHORT_REASONS) - NOT_ASKING
    assert sorted(asking - set(gate._SHORT_DANGER) - gate._SHORT_DANGER_IN_REASON) == []
    assert not set(gate._SHORT_DANGER) & gate._SHORT_DANGER_IN_REASON
    assert all(len(pair) == 2 and all(pair) for pair in gate._SHORT_DANGER.values())


@pytest.mark.parametrize("language", ["de", "en"])
def test_D116_no_danger_and_its_d_number_is_ever_cut(language):
    step, hint = "x" * gate._SHORT_STEP_MAX, "y" * max(len(v) for pair in gate._AUTONOMY_HINT_LABELS.values()
                                                       for v in pair)
    dangers = list(gate._SHORT_DANGER.values()) + list(gate._SHORT_DANGER_GIT_FORM.values()) + \
        list(gate._SHORT_DANGER_SPECIAL.values()) + [gate._SHORT_REASONS[r][1:] for r in gate._SHORT_DANGER_IN_REASON]
    for en, de in dangers:
        reason = de if language == "de" else en
        for form in ("ask", "deny", "warn", "sperre", "umweg", "karte"):
            line = gate._SHORT_TEMPLATES[language][form].format(step=step, reason=reason, d="D116", when="", hint=hint)
            assert line.index("(D116)") + len("(D116)") <= gate.SHORT_LINE_MAX - 2, (form, line)
            if form in ("ask", "deny", "warn"):
                assert len(line) <= gate.SHORT_LINE_MAX, (form, line)


def test_D116_delta_rev_parse_names_the_danger_of_the_read_before_its_d_number(tmp_path):
    repo = _repo(tmp_path)
    d71._git(repo, "config", "frob.knob", "1")
    _out, line = _line(repo, "git rev-parse HEAD", "de")
    assert line.startswith("Tor sperrt git rev-parse, weil auch dieser Lesebefehl ein ungeprüftes Programm"), line
    # the read profile names D34 after D3 (the last D number of its long reason); the block of D85 follows the danger
    # and may be cut
    assert "(D34); kein freier Weg" in line, line


def test_D116_the_long_reason_still_says_what_the_gate_cannot_tell(tmp_path):
    repo = _repo(tmp_path)
    out, _line_ = _line(repo, "git commit -m work", "en")
    assert "the state check found" in out.text and "DECISIONS.md D3" in out.text, out.text


@pytest.mark.parametrize("language,start", [("de", "Tor sperrt diesen Befehl, weil es in eine Datei"),
                                            ("en", "Gate blocks this command because it writes into a file"),
                                            ("de-ask", "Tor fragt bei diesem Befehl, weil")])
def test_D116_a_line_without_a_step_names_the_command_in_the_case_its_template_takes(language, start):
    decision = "ask" if language.endswith("-ask") else "deny"
    verdict = gate.Verdict(decision, "x", "append_outside_work" if decision == "deny" else "code_names_git")
    line = gate.short_line(decision, gate.Outcome(decision, "x", [verdict], None), None, language.split("-")[0])
    assert line.startswith(start), line


@pytest.mark.parametrize("language,step,other", [("de", "Tor sperrt git push, weil ", "Gestagte"),
                                                 ("en", "Gate blocks git push because ", "everything staged")])
def test_D116_a_card_names_the_danger_of_the_step_it_names(tmp_path, session, language, step, other):
    """S3 of the retrospective: the card for a commit and a push names the push, the step of D72; its danger is the
    push's own reason, not the danger of the commit before it, where neither is more than the gate's blind spot."""
    repo = _repo(tmp_path)
    out, line = _line(repo, "git commit -m 'fix stuff' && git push origin claude/work", language)
    assert line.startswith(step) and "(D93)." in line and other not in line, line


@pytest.mark.parametrize("language,start,end", [("de", "Tor sperrt git xxx", "(D5). Codex kann nicht fragen."),
                                                ("en", "Gate blocks git xxx", "(D5). Codex cannot ask.")])
def test_D116_a_long_step_is_shortened_before_the_danger_or_the_codex_sentence_is_cut(language, start, end):
    """A line over SHORT_LINE_MAX takes the short Codex sentence, then a shorter step, and only then a cut."""
    verdict = gate.Verdict("ask", "x", "absence_not_measured")
    line = gate.short_line("ask", gate.Outcome("ask", "x", [verdict], None), "git " + "x" * 36, language, form="deny",
                           suffix=gate._SHORT_CODEX_DENY[language])
    assert len(line) <= gate.SHORT_LINE_MAX and line.startswith(start) and "x…" in line and line.endswith(end), line


def test_D116_a_card_takes_the_danger_of_its_step_over_an_earlier_one_of_another_step():
    """Two asks that are more than the gate's blind spot, the first of another step: the card names the danger of the
    step the line names (D72), here the tag of the push, not the limit of open pull requests of the gh call."""
    pr = gate.Verdict("ask", "x", "house_pr_limit", failed="gh pr create may open a pull request")
    tag = gate.Verdict("ask", "x", "house_tag_out", failed="git push may send a tag")
    card = gate.Verdict("deny", "x", "autonomy_card")
    line = gate.short_line("deny", gate.Outcome("deny", "x", [pr, tag, card], None, cause=card), "git push", "en")
    assert line.startswith("Gate blocks git push because a tag goes out") and "(D93)." in line, line
