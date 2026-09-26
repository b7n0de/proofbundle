"""The advisory `codex-threads` check: three numbers, measured at the origin, red when a Codex thread
has no answer or its answer names no commit on the head.

THE PREVIOUS STATE, and why this file exists. The house rule said since 2026-09-13 that no pull
request lands while a Codex thread is without an answer, and nothing measured it. On 2026-09-25 four
pull requests of this repository landed with 11 Codex threads that had no answer (264 with 4, 265
with 5, 268 and 272 with 1 each), and pull request 266 carried 31 threads without an answer of 33
when its answers began. No check on any of them said so, because none existed. The catch proofs
below build that state and require red; the live measurement of the same day is in the commit that
added this file.

The rule is read at the data, not at the network: `measure` takes the comments and a function that
answers whether a commit is on the head, so every case here runs offline.
"""
from __future__ import annotations

import importlib.util
import pathlib
import unittest
from unittest import mock
from urllib.parse import urlsplit

REPO = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("_codex_threads_check",
                                               REPO / "scripts" / "codex_threads_check.py")
ct = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ct)

R = "b7n0de/proofbundle"
OWNER = "b7n0de"
HEAD = "a" * 40
OLD = "b" * 40
REVIEWED = "f" * 40


def codex(cid: int, reviewed: str = REVIEWED) -> dict:
    return {"id": cid, "in_reply_to_id": None, "user": {"login": ct.CODEX_BOT}, "body": "P2 finding",
            "original_commit_id": reviewed}


def reply(cid: int, root: int, body: str, login: str = OWNER) -> dict:
    return {"id": cid, "in_reply_to_id": root, "user": {"login": login}, "body": body}


def issue(body: str, login: str = OWNER) -> dict:
    return {"id": 1, "user": {"login": login}, "body": body}


def register_answer(pr: int, cid: int, sha: str | None) -> str:
    line = f"Commit measured `{sha}`\n\n" if sha else ""
    return (f"Confirmed, and fixed at the head of this pull request. Measured.\n\n{line}"
            f"## Register\n\nThread `{R}#{pr}:{cid}`. Verdict Confirmed. Register `X-Y-Z`.\n")


def verdict(review, issues, at_head=lambda s, reviewed: s == HEAD, pr=7) -> dict:
    return ct.measure(R, pr, OWNER, review, issues, at_head)


class AThrowawayPullRequest(unittest.TestCase):
    """The catch proof the order names: one open thread is red, the answer at head turns it green."""

    def test_one_open_codex_thread_is_red(self):
        e = verdict([codex(10)], [])
        self.assertEqual((e["verdict"], e["open"], e["not_at_head"]), ("red", 1, 0), e)
        self.assertEqual(e["open_threads"], [10])

    def test_the_same_thread_with_an_answer_at_head_is_green(self):
        e = verdict([codex(10)], [issue(register_answer(7, 10, HEAD))])
        self.assertEqual((e["verdict"], e["open"], e["not_at_head"]), ("green", 0, 0), e)

    def test_a_reply_inside_the_thread_is_an_answer_too(self):
        e = verdict([codex(10), reply(11, 10, f"Fixed.\n\nCommit measured `{HEAD}`\n")], [])
        self.assertEqual(e["verdict"], "green", e)

    def test_an_answer_whose_commit_is_not_on_the_head_is_red(self):
        e = verdict([codex(10)], [issue(register_answer(7, 10, OLD))])
        self.assertEqual((e["verdict"], e["open"], e["not_at_head"]), ("red", 0, 1), e)

    def test_an_answer_that_names_no_commit_is_not_at_head(self):
        e = verdict([codex(10)], [issue(register_answer(7, 10, None))])
        self.assertEqual((e["verdict"], e["not_at_head"]), ("red", 1), e)

    def test_the_measured_line_decides_over_an_earlier_id_in_the_text(self):
        """The house answer names the reviewed commit first and the measured head below it."""
        text = f"Reproduced at `{OLD}`.\n\n" + register_answer(7, 10, HEAD)
        self.assertEqual(ct.answer_commit(text), HEAD)
        self.assertEqual(verdict([codex(10)], [issue(text)])["verdict"], "green")


class TheEvidenceStandsOnItsLine(unittest.TestCase):
    """Codex on PR 275, round one: an id elsewhere in an answer is not the answer's commit, and a
    thread id elsewhere in a comment does not make it an answer."""

    def test_a_reply_that_names_the_head_in_prose_is_not_at_head(self):
        e = verdict([codex(10), reply(11, 10, f"Reproduced at {HEAD}; still investigating")], [])
        self.assertEqual((e["verdict"], e["open"], e["not_at_head"]), ("red", 0, 1), e)

    def test_the_measured_words_inside_a_sentence_are_not_the_line(self):
        text = f"Thread `{R}#7:10`.\n\nWe will name the Commit measured {HEAD} next time."
        self.assertIsNone(ct.answer_commit(text))
        self.assertEqual(verdict([codex(10)], [issue(text)])["not_at_head"], 1)

    def test_a_thread_id_in_prose_makes_no_answer(self):
        text = f"See {R}#7:10 later.\n\nCommit measured `{HEAD}`\n"
        self.assertEqual(verdict([codex(10)], [issue(text)])["open"], 1)

    def test_a_closer_with_text_after_it_does_not_close_the_fence(self):
        """Confirmation lens C, mutant M4: a line of fence characters followed by text is no closer."""
        text = "```\nexample\n``` trailing text\n\n" + register_answer(7, 10, HEAD)
        self.assertEqual(verdict([codex(10)], [issue(text)])["open"], 1)

    def test_the_same_measured_commit_twice_is_one_commit(self):
        """Confirmation lens C, mutant M7: two measured lines naming the SAME commit name it."""
        text = register_answer(7, 10, HEAD) + f"\nCommit measured `{HEAD}`\n"
        self.assertEqual(ct.answer_commit(text), HEAD)
        self.assertEqual(verdict([codex(10)], [issue(text)])["verdict"], "green")

    def test_an_id_with_a_suffix_names_no_thread(self):
        """Codex on PR 275, round five: `(?!\\d)` let `#7:10x` name thread 10, in both forms. The id
        ends where the reference ends; the house forms still name their thread."""
        for ref in (f"{R}#7:10x", f"{R}#7:10_a", f"{R}#7:10-1", f"{R}#7:10.5",
                    "https://github.com/x/y/pull/7#discussion_r10x"):
            with self.subTest(ref=ref):
                text = f"Thread `{ref}`. Verdict Confirmed.\n\nCommit measured `{HEAD}`\n"
                self.assertEqual(ct.register_threads(text, R, 7), set())
        for line in (f"Thread `{R}#7:10`. Verdict Confirmed.", f"Thread {R}#7:10.",
                     f"Thread [link](https://github.com/{R}/pull/7#discussion_r10), confirmed",
                     f"Thread https://github.com/{R}/pull/7#discussion_r10"):
            with self.subTest(line=line):                   # PRECONDITION: the house forms still count
                self.assertEqual(ct.register_threads(line + "\n", R, 7), {10})

    def test_a_longer_id_does_not_answer_a_shorter_one(self):
        self.assertEqual(verdict([codex(10)], [issue(register_answer(7, 100, HEAD))])["open"], 1)


class WhoCounts(unittest.TestCase):

    def test_a_thread_a_person_opened_is_outside_the_check(self):
        human = {"id": 20, "in_reply_to_id": None, "user": {"login": "someone"}, "body": "nit"}
        e = verdict([human], [])
        self.assertEqual((e["codex_threads"], e["verdict"]), (0, "green"), e)

    def test_a_reply_by_another_account_is_no_answer(self):
        e = verdict([codex(10), reply(11, 10, f"done at {HEAD}", login="someone")], [])
        self.assertEqual((e["verdict"], e["open"]), ("red", 1), e)

    def test_one_comment_that_names_two_threads_answers_neither(self):
        """Deep gate, lens 1, P1: one comment, two register lines and two measured lines; the first
        measured line was read for both threads, so the second, unfixed one went green."""
        text = (register_answer(7, 10, HEAD) + "\n" + register_answer(7, 20, OLD))
        e = verdict([codex(10), codex(20)], [issue(text)])
        self.assertEqual((e["verdict"], e["open"]), ("red", 2), e)

    def test_threads_still_open_and_threading_are_prose(self):
        """Codex on PR 275, round two, and deep gate lens 1: a line that only starts with the letters
        `Thread` is not a register line."""
        for line in (f"Threads still open: {R}#7:10", f"Threading pool bumped, see {R}#7:10"):
            with self.subTest(line=line):
                text = f"{line}\n\nCommit measured `{HEAD}`\n"
                self.assertEqual(verdict([codex(10)], [issue(text)])["open"], 1)

    def test_a_quoted_or_listed_register_line_is_not_one(self):
        for prefix in ("> ", "- ", "* "):
            with self.subTest(prefix=prefix):
                text = f"{prefix}Thread `{R}#7:10`. Verdict Confirmed.\n\nCommit measured `{HEAD}`\n"
                self.assertEqual(verdict([codex(10)], [issue(text)])["open"], 1)

    def test_lines_a_reader_does_not_see_are_not_read(self):
        """Deep gate, lens 1: an HTML comment is not shown, and a fenced block is an example."""
        hidden = f"<!--\nThread `{R}#7:10`. Verdict Confirmed.\n\nCommit measured `{HEAD}`\n-->\n"
        fenced = f"```text\nThread `{R}#7:10`. Verdict Confirmed.\nCommit measured `{HEAD}`\n```\n"
        for text in (hidden, fenced):
            with self.subTest(text=text[:12]):
                self.assertEqual(verdict([codex(10)], [issue(text)])["open"], 1)
        # and a measured line inside a fence does not count for a visible register line
        text = f"Thread `{R}#7:10`. Verdict Confirmed.\n\n```\nCommit measured `{HEAD}`\n```\n"
        self.assertEqual(verdict([codex(10)], [issue(text)])["not_at_head"], 1)

    def test_two_different_measured_lines_name_no_commit(self):
        text = register_answer(7, 10, HEAD) + f"\nCommit measured `{OLD}`\n"
        self.assertIsNone(ct.answer_commit(text))

    def test_a_fence_or_comment_that_never_closes_hides_the_rest(self):
        """Deep gate iteration 2, lens 1, P1: GitHub renders an unclosed fence as code and an unclosed
        HTML comment as hidden, both to the end of the text. The regular expressions needed a closer,
        so the register and measured lines after an unclosed opener were read, and a thread without a
        visible answer went green."""
        for opener in ("```", "~~~~", "<!-- draft"):
            with self.subTest(opener=opener):
                text = f"An example for context.\n\n{opener}\n" + register_answer(7, 10, HEAD)
                self.assertEqual(verdict([codex(10)], [issue(text)])["open"], 1)

    def test_a_fence_closes_only_on_its_own_kind_and_length(self):
        """A shorter fence or the other character does not close it, as in GitHub's rendering; a
        proper closer does, and the answer after it counts (the precondition of the red cases)."""
        for inner in ("```", "~~~~"):
            with self.subTest(inner=inner):
                text = f"````\nexample\n{inner}\n" + register_answer(7, 10, HEAD)
                self.assertEqual(verdict([codex(10)], [issue(text)])["open"], 1)
        text = "````\nexample\n`````\n\n" + register_answer(7, 10, HEAD)
        self.assertEqual(verdict([codex(10)], [issue(text)])["verdict"], "green")
        # The most common fence of all, closed by one of the same length (deep gate iteration 3, lens 3:
        # a closer that had to be LONGER than its opener survived every case above).
        for fence in ("```", "~~~"):
            with self.subTest(equal=fence):
                text = f"{fence}\nexample\n{fence}\n\n" + register_answer(7, 10, HEAD)
                self.assertEqual(verdict([codex(10)], [issue(text)])["verdict"], "green")

    def test_a_form_the_check_does_not_model_hides_the_rest(self):
        """Deep gate iteration 3, lens 1, three P1: a fence in a list item, a backtick fence whose info
        string holds a backtick (not an opener in CommonMark, so the NEXT bare fence opens one that
        never closes) and a collapsed <details> were shown to the check while GitHub hid them. The
        check does not chase the renderer; past a form it does not model, it reads nothing."""
        answer = register_answer(7, 10, HEAD)
        for before in ("- ```\n  ", "> ```\n> ", "```see `x` here\ncode\n```\n\n",
                       "<details>\n<summary>Register</summary>\n\n", "<pre>\n", "Use ```x``` inline.\n\n"):
            with self.subTest(before=before[:14]):
                self.assertEqual(verdict([codex(10)], [issue(before + answer)])["open"], 1)
        # PRECONDITION: a house answer with a proper fence before its register line is read
        text = "## Fix\n\n```\ngit diff-tree -r -z a b\n```\n\n" + answer
        self.assertEqual(verdict([codex(10)], [issue(text)])["verdict"], "green")

    def test_a_register_line_indented_like_code_is_code(self):
        """Four spaces or a tab before the line make it code on GitHub; up to three do not."""
        for pad in ("    ", "\t"):
            with self.subTest(pad=repr(pad)):
                text = register_answer(7, 10, HEAD).replace("Thread `", pad + "Thread `")
                self.assertEqual(verdict([codex(10)], [issue(text)])["open"], 1)
        text = register_answer(7, 10, HEAD).replace("Thread `", "   Thread `")
        self.assertEqual(verdict([codex(10)], [issue(text)])["verdict"], "green")
        # and the measured line: indented like code, it names no commit
        text = register_answer(7, 10, HEAD).replace("Commit measured", "    Commit measured")
        self.assertEqual(verdict([codex(10)], [issue(text)])["not_at_head"], 1)

    def test_the_bot_is_known_by_its_login_not_by_a_name_in_the_text(self):
        pretend = {"id": 30, "in_reply_to_id": None, "user": {"login": OWNER},
                   "body": f"posted by {ct.CODEX_BOT}"}
        self.assertEqual(verdict([pretend], [])["codex_threads"], 0)

    def test_an_issue_comment_naming_another_pull_requests_thread_is_no_answer(self):
        e = verdict([codex(10)], [issue(register_answer(8, 10, HEAD))])
        self.assertEqual(e["open"], 1, e)

    def test_rounds_count_only_the_owners_requests(self):
        issues = [issue("@codex review"), issue("@codex review\n\nRound two at head x."),
                  issue("@codex review", login="someone"),
                  issue("Please @codex review this")]
        self.assertEqual(verdict([], issues)["rounds"], 2)


class ThePreviousState(unittest.TestCase):
    """Pull request 266 as it stood when its answers began: 33 Codex threads, two answered in the
    thread, 31 without an answer. Without this check nothing was red; with it, it is."""

    def test_the_state_before_the_answers_is_red_with_31_open(self):
        threads = [codex(4104495438 + i) for i in range(33)]
        # The two replies of that evening named the head in prose and carried no `Commit measured`
        # line, so they are answers whose commit is not established: not at head, and said so.
        replies = [reply(9000 + i, threads[31 + i]["id"], f"Fixed at head {HEAD}.") for i in range(2)]
        e = verdict(threads + replies, [issue("@codex review")] * 16, pr=266)
        self.assertEqual((e["verdict"], e["rounds"], e["open"], e["not_at_head"]),
                         ("red", 16, 31, 2), e)

    def test_the_state_after_the_answers_is_green(self):
        threads = [codex(4104495438 + i) for i in range(33)]
        answers = [issue(register_answer(266, t["id"], HEAD)) for t in threads]
        e = verdict(threads, answers, pr=266)
        self.assertEqual((e["verdict"], e["open"], e["not_at_head"]), ("green", 0, 0), e)


class TheOrigin(unittest.TestCase):
    """Three states, not two: an origin that cannot be read is never green."""

    def test_an_unreadable_origin_is_not_measurable(self):
        def broken(url, token):
            raise ct.NotMeasurable(f"{url}: HTTP 502")
        with mock.patch.object(ct, "_get", broken):
            self.assertEqual(ct.main(["--repo", R, "--pr", "7"]), 2)

    def test_a_truncated_response_is_not_measurable(self):
        """Codex on PR 275, round one, measured: `IncompleteRead` escaped `main`."""
        import http.client

        class Truncated:
            headers: dict = {}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                raise http.client.IncompleteRead(b"{")

        with mock.patch.object(ct.urllib.request, "urlopen", lambda *a, **k: Truncated()):
            self.assertEqual(ct.main(["--repo", R, "--pr", "7"]), 2)

    def test_an_error_nobody_foresaw_is_not_measurable_and_never_green(self):
        def boom(*a, **k):
            raise RuntimeError("unforeseen")
        with mock.patch.object(ct, "measure_at_origin", boom):
            self.assertEqual(ct.main(["--repo", R, "--pr", "7"]), 2)

    def _origin(self, compare_status):
        pages = {
            f"{ct.API}/repos/{R}/pulls/7": {"head": {"sha": HEAD}},
            f"{ct.API}/repos/{R}/pulls/7/comments?per_page=100": [codex(10)],
            f"{ct.API}/repos/{R}/issues/7/comments?per_page=100": [issue(register_answer(7, 10, OLD))],
        }

        def fake(url, token):
            if "/compare/" in url:
                if compare_status is None:
                    raise ct.Missing(f"{url}: 404")
                return {"status": compare_status}, None
            return pages[url], None
        return fake

    def test_a_commit_the_head_is_ahead_of_is_at_head(self):
        with mock.patch.object(ct, "_get", self._origin("ahead")):
            e = ct.measure_at_origin(R, 7, OWNER, None)
        self.assertEqual((e["verdict"], e["head"]), ("green", HEAD), e)

    def test_a_commit_on_another_line_is_not_at_head(self):
        with mock.patch.object(ct, "_get", self._origin("diverged")):
            self.assertEqual(ct.measure_at_origin(R, 7, OWNER, None)["not_at_head"], 1)

    def test_a_compare_status_the_api_does_not_document_is_not_measurable(self):
        """Deep gate iteration 2, lens 2: a value outside identical, ahead, behind and diverged was
        read as "not ahead", a verdict about an answer nobody could interpret."""
        with mock.patch.object(ct, "_get", self._origin("quantum-entangled")):
            with self.assertRaises(ct.NotMeasurable):
                ct.measure_at_origin(R, 7, OWNER, None)
        for known in ("behind", "diverged"):                 # PRECONDITION: documented values judge
            with self.subTest(known=known), mock.patch.object(ct, "_get", self._origin(known)):
                self.assertEqual(ct.measure_at_origin(R, 7, OWNER, None)["not_at_head"], 1)

    def test_a_next_page_of_another_list_is_not_followed(self):
        """Deep gate iteration 2, lens 2: a next link on the API host into another repository was
        followed, and its comments were counted for this pull request."""
        for nxt in (f"{ct.API}/repos/acme/other/pulls/999/comments?page=2",
                    f"{ct.API}/repositories/42/pulls/7/comments?page=2",
                    f"{ct.API}/repositories/1285988816/issues/7/comments?page=2"):
            def fake(url, token, nxt=nxt):
                return ([codex(10)], nxt) if "page=2" not in url else ([codex(99)], None)
            with self.subTest(next=nxt[23:60]), mock.patch.object(ct, "_get", fake):
                with self.assertRaises(ct.NotMeasurable):
                    ct._pages(f"repos/{R}/pulls/7/comments", None, 1285988816)

    def test_the_next_link_github_writes_is_followed(self):
        """Measured on 2026-09-26: GitHub writes the next page of `repos/<owner>/<repo>/...` as
        `/repositories/<id>/...`. With this repository's id, that page belongs to the same list."""
        nxt = f"{ct.API}/repositories/1285988816/pulls/7/comments?per_page=100&page=2"

        def fake(url, token):
            return ([codex(10)], nxt) if url.endswith("per_page=100") else ([codex(11)], None)
        with mock.patch.object(ct, "_get", fake):
            got = ct._pages(f"repos/{R}/pulls/7/comments", None, 1285988816)
        self.assertEqual([c["id"] for c in got], [10, 11])

    def test_a_commit_from_before_the_reviewed_one_is_not_at_head(self):
        """Deep gate, lens 1: any ancestor of the head is on the head, the first commit of the
        repository too. Only a commit that contains the reviewed one can carry a fix for it."""
        answer = OLD
        status = {f"{answer}...{HEAD}": "ahead", f"{REVIEWED}...{answer}": "behind"}
        pages = {
            f"{ct.API}/repos/{R}/pulls/7": {"head": {"sha": HEAD}},
            f"{ct.API}/repos/{R}/pulls/7/comments?per_page=100": [codex(10)],
            f"{ct.API}/repos/{R}/issues/7/comments?per_page=100": [issue(register_answer(7, 10, answer))],
        }

        def fake(url, token):
            if "/compare/" in url:
                return {"status": status.get(url.rsplit("/", 1)[1], "diverged")}, None
            return pages[url], None
        with mock.patch.object(ct, "_get", fake):
            self.assertEqual(ct.measure_at_origin(R, 7, OWNER, None)["not_at_head"], 1)
        status[f"{REVIEWED}...{answer}"] = "ahead"          # PRECONDITION: after it, it counts
        with mock.patch.object(ct, "_get", fake):
            self.assertEqual(ct.measure_at_origin(R, 7, OWNER, None)["verdict"], "green")

    def test_a_thread_without_a_reviewed_commit_is_not_at_head(self):
        """Confirmation lens C, mutant M11: without the commit Codex reviewed, nothing shows that the
        answer's commit came after it, so the thread is not closed on an open pull request."""
        bare = {"id": 10, "in_reply_to_id": None, "user": {"login": ct.CODEX_BOT}, "body": "P2"}
        pages = {
            f"{ct.API}/repos/{R}/pulls/7": {"head": {"sha": HEAD}},
            f"{ct.API}/repos/{R}/pulls/7/comments?per_page=100": [bare],
            f"{ct.API}/repos/{R}/issues/7/comments?per_page=100": [issue(register_answer(7, 10, HEAD))],
        }

        def fake(url, token):
            return ({"status": "identical"}, None) if "/compare/" in url else (pages[url], None)
        with mock.patch.object(ct, "_get", fake):
            self.assertEqual(ct.measure_at_origin(R, 7, OWNER, None)["not_at_head"], 1)

    def test_a_next_link_with_a_fragment_is_not_the_same_list(self):
        """Confirmation lens C, mutant M14."""
        base = f"{ct.API}/repos/{R}/pulls/7/comments?per_page=100&page=2"
        self.assertTrue(ct._same_list(base, f"repos/{R}/pulls/7/comments", None))
        self.assertFalse(ct._same_list(base + "#x", f"repos/{R}/pulls/7/comments", None))

    def test_pagination_reads_exactly_max_pages(self):
        """Confirmation lens C, mutant M16: the limit is a number, so it is measured exactly."""
        calls: list = []

        def fake(url, token):
            calls.append(url)
            return [], f"{ct.API}/repos/{R}/pulls/7/comments?per_page=100&page={len(calls) + 1}"
        with mock.patch.object(ct, "_get", fake), self.assertRaises(ct.NotMeasurable):
            ct._pages(f"repos/{R}/pulls/7/comments", None)
        self.assertEqual(len(calls), ct.MAX_PAGES)

    def test_main_exits_0_for_green_and_1_for_red(self):
        """Confirmation lens C, mutant M17: the exit code is what the workflow reports, and no case
        called main on a measured verdict."""
        for e, code in ((verdict([codex(10)], [issue(register_answer(7, 10, HEAD))]), 0),
                        (verdict([codex(10)], []), 1)):
            with self.subTest(verdict=e["verdict"]), \
                    mock.patch.object(ct, "measure_at_origin", lambda *a, e=e: e):
                self.assertEqual(ct.main(["--repo", R, "--pr", "7", "--json"]), code)

    def test_pagination_stays_on_the_api_host_and_ends(self):
        """Deep gate, lens 2: the next page came from a header and was followed to any host, with the
        token, and without an end."""
        calls: list = []
        endless = iter(f"{ct.API}/repos/{R}/pulls/7/comments?page={i}" for i in range(10 ** 6))
        cases = (("another host", lambda url: "https://evil.example.com/next"),
                 ("the same page again", lambda url: url),
                 ("always a new page", lambda url: next(endless)))
        for label, following in cases:
            def fake(url, token, following=following):
                calls.append(url)
                if len(calls) > 3 * ct.MAX_PAGES:            # an unbounded loop fails, it does not hang
                    raise AssertionError("pagination did not end")
                return [], following(url)
            calls.clear()
            with self.subTest(case=label), mock.patch.object(ct, "_get", fake):
                with self.assertRaises(ct.NotMeasurable):
                    ct._pages(f"repos/{R}/pulls/7/comments", "secret")
                # the host is compared whole, since a substring test reads a foreign host as ours
                api_host = urlsplit(ct.API).hostname
                self.assertTrue(all(urlsplit(u).hostname == api_host for u in calls), calls[:3])

    def test_a_pr_number_that_is_not_a_number_is_not_measurable(self):
        self.assertEqual(ct.main(["--repo", R, "--pr", "abc"]), 2)

    def test_a_commit_the_repository_does_not_know_is_not_at_head(self):
        with mock.patch.object(ct, "_get", self._origin(None)):
            self.assertEqual(ct.measure_at_origin(R, 7, OWNER, None)["not_at_head"], 1)

    def test_a_landed_pull_request_counts_its_merge_commit_as_a_head(self):
        """Measured on PR 264: answers written after the squash name the commit on main, which is
        no ancestor of the old branch head. The first version called all four not at head."""
        merge = "c" * 40
        pages = {
            f"{ct.API}/repos/{R}/pulls/7": {"head": {"sha": HEAD}, "merged": True,
                                            "merge_commit_sha": merge},
            f"{ct.API}/repos/{R}/pulls/7/comments?per_page=100": [codex(10)],
            f"{ct.API}/repos/{R}/issues/7/comments?per_page=100": [issue(register_answer(7, 10, merge))],
        }

        def fake(url, token):
            if "/compare/" in url:
                return {"status": "identical" if url.endswith(f"{merge}...{merge}") else "diverged"}, None
            return pages[url], None
        with mock.patch.object(ct, "_get", fake):
            e = ct.measure_at_origin(R, 7, OWNER, None)
        self.assertEqual((e["verdict"], e["merge_commit"]), ("green", merge), e)
        # PRECONDITION: without the merge commit as a head, the same answer is not at head.
        pages[f"{ct.API}/repos/{R}/pulls/7"] = {"head": {"sha": HEAD}}
        with mock.patch.object(ct, "_get", fake):
            self.assertEqual(ct.measure_at_origin(R, 7, OWNER, None)["not_at_head"], 1)

    def test_after_landing_a_later_main_commit_carries_the_fix_and_an_earlier_one_does_not(self):
        """The direction of the merged case. An answer measured on main after the landing names a
        commit that CONTAINS the merge commit; a commit of main from before the landing is contained
        in it and carries none of the fix. The second version of this check had it backwards."""
        merge, later, earlier = "c" * 40, "d" * 40, "e" * 40
        status = {f"{merge}...{later}": "ahead", f"{merge}...{earlier}": "behind"}

        def fake_for(answer_sha):
            pages = {
                f"{ct.API}/repos/{R}/pulls/7": {"head": {"sha": HEAD}, "merged": True,
                                                "merge_commit_sha": merge},
                f"{ct.API}/repos/{R}/pulls/7/comments?per_page=100": [codex(10)],
                f"{ct.API}/repos/{R}/issues/7/comments?per_page=100":
                    [issue(register_answer(7, 10, answer_sha))],
            }

            def fake(url, token):
                if "/compare/" in url:
                    return {"status": status.get(url.rsplit("/", 1)[1], "diverged")}, None
                return pages[url], None
            return fake
        with mock.patch.object(ct, "_get", fake_for(later)):
            self.assertEqual(ct.measure_at_origin(R, 7, OWNER, None)["verdict"], "green")
        with mock.patch.object(ct, "_get", fake_for(earlier)):
            self.assertEqual(ct.measure_at_origin(R, 7, OWNER, None)["not_at_head"], 1)


class TheWorkflow(unittest.TestCase):
    """The workflow runs this check on every pull request, read-only, with no event value spliced
    into a shell body."""

    def setUp(self):
        try:
            import yaml
        except ImportError:  # the same guard as the other workflow readers of this suite
            self.skipTest("PyYAML not installed (dev-only dependency)")
        self.wf = yaml.safe_load((REPO / ".github" / "workflows" / "codex-threads.yml")
                                 .read_text(encoding="utf-8"))

    def test_it_runs_on_pull_requests_and_is_read_only(self):
        on = self.wf.get(True) or self.wf.get("on")
        self.assertIn("pull_request", on)
        self.assertEqual(set(self.wf["permissions"].values()), {"read"}, self.wf["permissions"])

    def test_its_run_step_calls_this_script_and_interpolates_nothing(self):
        steps = [s for job in self.wf["jobs"].values() for s in job["steps"] if "run" in s]
        self.assertTrue(any("scripts/codex_threads_check.py" in s["run"] for s in steps), steps)
        for s in steps:
            self.assertNotIn("${{", s["run"], s["run"])


if __name__ == "__main__":
    unittest.main()
