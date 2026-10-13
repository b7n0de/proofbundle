#!/usr/bin/env python3
"""Contract tests of the challenge set for a second implementation of draft-gruszka-signed-evaluation-receipts-02
(card FOXTROT-CLOUD-SER-PRUEFMENGE-01, owner choice of 2026-10-13, 18:2x Berlin, A and A).

The 66 vectors of Appendix A are public with their expected results, so a submission that reports 66 of 66 proves
nothing. Each submission answers a fresh challenge set instead: generated from a seed that never enters the
repository, an entry count and the submission's name, with fresh test keys and salts; its expected answers come from
both verifiers of this folder's parent (the generator author's and the one written from the text alone), and an entry
on which they disagree is left out and reported as a finding on the text. The comparison reads a submission's
answers; it never runs foreign code.

Contract (point 5 of the card): both verifiers, as submitters, reach 100 percent; an answer of PASS for everything, an
answer taken from the results of Appendix A in order and a mixed answer file fall clearly short; missing and
duplicate ids are found; two runs with the same seed are byte-identical, with another seed different.

Run: python3 -m unittest test_pruefmenge   (in this folder; standard library only)
"""
from __future__ import annotations

import base64
import io
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import pruefmenge  # noqa: E402

#: Test seeds only; a real challenge set takes its seed from os.urandom and keeps it outside the repository.
SEED = bytes(range(32))
OTHER_SEED = bytes(range(1, 33))
N = 200
VECTORS = HERE.parent / "examples" / "vectors.json"

_CACHE: dict = {}


def _set(seed: bytes = SEED, anzahl: int = N, kennung: str = "test-einsendung"):
    key = (seed, anzahl, kennung)
    if key not in _CACHE:
        _CACHE[key] = pruefmenge.erzeugen(seed, anzahl, kennung)
    return _CACHE[key]


def _lines(raw: bytes) -> list:
    return [json.loads(line) for line in raw.decode("utf-8").splitlines()]


def _rate(answers: bytes, expected: bytes) -> float:
    result = pruefmenge.vergleichen(answers, expected)
    return result.uebereinstimmung / result.gesamt


class ChallengeSet(unittest.TestCase):

    def test_the_set_has_the_count_and_the_form_of_the_prompt(self):
        made = _set()
        challenge, expected = _lines(made.challenge), _lines(made.expected)
        self.assertEqual(len(challenge), N)
        self.assertEqual([c["id"] for c in challenge], [e["id"] for e in expected])
        self.assertEqual(len({c["id"] for c in challenge}), N)
        for entry in challenge:
            self.assertEqual(set(entry), {"id", "receipt_b64", "key_b64"})
            for name in ("receipt_b64", "key_b64"):
                raw = base64.b64decode(entry[name], validate=True)
                self.assertEqual(base64.b64encode(raw).decode("ascii"), entry[name])   # with padding, canonical
            self.assertEqual(len(base64.b64decode(entry["key_b64"])), 32)
        for answer in expected:
            self.assertEqual(set(answer), {"id", "verdict", "step", "detail"})
            self.assertIn(answer["verdict"], ("PASS", "FAIL", "ERROR"))
            if answer["verdict"] == "PASS":
                self.assertEqual((answer["step"], answer["detail"]), (None, None))
            else:
                self.assertIn(answer["step"], range(1, 12))
                self.assertEqual(answer["detail"] is not None, answer["step"] == 11)

    def test_the_set_mixes_all_eleven_steps_and_the_four_profile_rules(self):
        expected = _lines(_set().expected)
        steps = {e["step"] for e in expected if e["verdict"] == "FAIL"}
        self.assertEqual(steps, set(range(1, 12)))
        details = {e["detail"] for e in expected if e["step"] == 11}
        self.assertEqual(details, {"profile 1", "profile 2", "profile 3", "profile 4"})
        valid = sum(e["verdict"] == "PASS" for e in expected)
        self.assertTrue(0.25 * N <= valid <= 0.40 * N, valid)        # about a third valid

    def test_no_expected_answer_is_error(self):
        # O3: no entry is meant to reach a resource limit; ERROR belongs to an implementation's own limit only
        self.assertEqual([e["id"] for e in _lines(_set().expected) if e["verdict"] == "ERROR"], [])
        self.assertEqual([e["id"] for e in _lines(pruefmenge.erwartung_anhang_a()) if e["verdict"] == "ERROR"], [])

    def test_entries_with_two_faults_ask_for_the_order_of_the_text(self):
        # Section 5: the first step that fails gives FAIL; Section 4: the rules in the order given, within rules 1
        # and 2 the key before R. With one fault per entry, an implementation that checks in another order answers
        # the same; with two, it does not.
        made = _set()
        double = [b for b in made.bauarten if b["bauart"] == "mehrfach"]
        self.assertGreaterEqual(len(double), 5)
        self.assertEqual([b for b in double if b["beabsichtigt"] != b["pruefer"]], [])
        self.assertEqual(made.meta["bau_anders_als_beabsichtigt"], 0)

    def test_no_entry_is_a_vector_of_appendix_a_byte_for_byte(self):
        doc = json.loads(VECTORS.read_text(encoding="utf-8"))
        vectors = {bytes.fromhex(v["receipt_hex"]) for v in doc["vectors"]}
        keys = {base64.b64decode(v["verification_key_b64"]) for v in doc["vectors"]}
        for entry in _lines(_set().challenge):
            self.assertNotIn(base64.b64decode(entry["receipt_b64"]), vectors, entry["id"])
        # fresh test keys: the issuer key of the set is none of the keys of Appendix A
        self.assertNotIn(_set().schluessel_aussteller, keys)

    def test_the_same_seed_gives_the_same_bytes_and_another_seed_others(self):
        first, again = pruefmenge.erzeugen(SEED, 40, "gleich"), pruefmenge.erzeugen(SEED, 40, "gleich")
        self.assertEqual((first.challenge, first.expected), (again.challenge, again.expected))
        other = pruefmenge.erzeugen(OTHER_SEED, 40, "gleich")
        self.assertNotEqual(first.challenge, other.challenge)
        self.assertNotEqual(first.expected, other.expected)
        named = pruefmenge.erzeugen(SEED, 40, "andere-einsendung")
        self.assertNotEqual(first.challenge, named.challenge)

    def test_entries_the_verifiers_disagree_on_are_left_out_and_reported(self):
        made = _set()
        for finding in made.befunde:
            self.assertNotEqual(finding["autor"], finding["text"])
        listed = {e["id"] for e in _lines(made.expected)}
        self.assertEqual(len(listed), N)


class OurVerifiersAsSubmitters(unittest.TestCase):

    def test_both_verifiers_reach_100_percent(self):
        made = _set()
        for name in ("autor", "text"):
            answers = pruefmenge.antworten_von(name, made.challenge)
            result = pruefmenge.vergleichen(answers, made.expected)
            self.assertTrue(result.vollstaendig, name)
            self.assertEqual((result.uebereinstimmung, result.gesamt), (N, N), name)
            self.assertEqual(result.abweichungen, [], name)


class AnswersThatFallShort(unittest.TestCase):

    def test_pass_for_everything_falls_clearly_short(self):
        made = _set()
        answers = "".join(json.dumps({"id": c["id"], "verdict": "PASS", "step": None, "detail": None}) + "\n"
                          for c in _lines(made.challenge)).encode()
        self.assertLess(_rate(answers, made.expected), 0.5)

    def test_the_results_of_appendix_a_in_order_fall_clearly_short(self):
        made = _set()
        annex = _lines(pruefmenge.erwartung_anhang_a())
        answers = "".join(json.dumps(dict(annex[i % len(annex)], id=c["id"])) + "\n"
                          for i, c in enumerate(_lines(made.challenge))).encode()
        self.assertLess(_rate(answers, made.expected), 0.5)

    def test_a_mixed_answer_file_falls_clearly_short(self):
        made = _set()
        answers = pruefmenge.gemischte_antworten(made.challenge, made.expected, SEED)
        rate = _rate(answers, made.expected)
        self.assertLess(rate, 0.75)
        self.assertGreater(rate, 0.0)

    def test_the_right_verdict_at_a_wrong_step_is_no_agreement(self):
        made = _set()
        shifted = []
        for e in _lines(made.expected):
            if e["verdict"] == "FAIL" and e["step"] < 11:
                e = dict(e, step=e["step"] + 1)
            shifted.append(json.dumps(e) + "\n")
        result = pruefmenge.vergleichen("".join(shifted).encode(), made.expected)
        self.assertTrue(result.vollstaendig)
        self.assertLess(result.uebereinstimmung / result.gesamt, 0.75)
        self.assertEqual(result.urteil_gleich, N)


class IncompleteAnswers(unittest.TestCase):

    def _answers(self):
        return _lines(pruefmenge.antworten_von("autor", _set().challenge))

    @staticmethod
    def _write(rows) -> bytes:
        return "".join((r if isinstance(r, str) else json.dumps(r)) + "\n" for r in rows).encode()

    def test_a_missing_id_is_found(self):
        rows = self._answers()
        gone = rows.pop(7)["id"]
        result = pruefmenge.vergleichen(self._write(rows), _set().expected)
        self.assertFalse(result.vollstaendig)
        self.assertEqual(result.fehlend, [gone])

    def test_a_duplicate_id_is_found(self):
        rows = self._answers()
        twice = rows[9]["id"]
        rows.insert(3, dict(rows[9]))
        result = pruefmenge.vergleichen(self._write(rows), _set().expected)
        self.assertFalse(result.vollstaendig)
        self.assertEqual(result.doppelt, [twice])

    def test_a_foreign_id_and_a_broken_line_are_found(self):
        rows = self._answers() + [{"id": "x999", "verdict": "PASS", "step": None, "detail": None},
                                  "{not json", {"id": "c001", "verdict": "MAYBE", "step": None, "detail": None}]
        result = pruefmenge.vergleichen(self._write(rows), _set().expected)
        self.assertFalse(result.vollstaendig)
        self.assertEqual(result.fremd, ["x999"])
        self.assertEqual([number for number, _why in result.kaputt], [N + 2, N + 3])

    def test_deviations_alone_leave_the_answer_complete(self):
        rows = self._answers()
        rows[0] = dict(rows[0], verdict="FAIL", step=3, detail=None) if rows[0]["verdict"] == "PASS" else \
            dict(rows[0], verdict="PASS", step=None, detail=None)
        result = pruefmenge.vergleichen(self._write(rows), _set().expected)
        self.assertTrue(result.vollstaendig)
        self.assertEqual(result.uebereinstimmung, N - 1)
        self.assertEqual([a["id"] for a in result.abweichungen], [rows[0]["id"]])


class HostileAnswers(unittest.TestCase):
    """An answer file is foreign input: a line the comparison cannot read unambiguously is a broken line, the report
    still comes out, and no foreign string reaches the terminal unescaped."""

    def _rows(self):
        return pruefmenge.antworten_von("autor", _set().challenge)

    def test_a_line_nested_too_deep_is_a_broken_line(self):
        answers = self._rows() + b"[" * 100000 + b"]" * 100000 + b"\n"
        result = pruefmenge.vergleichen(answers, _set().expected)
        self.assertEqual([number for number, _why in result.kaputt], [N + 1])
        self.assertEqual(result.uebereinstimmung, N)

    def test_a_line_with_a_duplicate_name_is_a_broken_line(self):
        lines = self._rows().splitlines(keepends=True)
        first = json.loads(lines[0])
        lines[0] = ('{"id": "%s", "id": "x1", "verdict": "PASS", "step": null, "detail": null}\n' % first["id"]).encode()
        result = pruefmenge.vergleichen(b"".join(lines), _set().expected)
        self.assertEqual([number for number, _why in result.kaputt], [1])
        self.assertEqual((result.fremd, result.fehlend), ([], [first["id"]]))

    def test_a_line_that_is_no_utf8_is_a_broken_line(self):
        answers = self._rows() + b'{"id": "c0\xff1", "verdict": "PASS", "step": null, "detail": null}\n'
        result = pruefmenge.vergleichen(answers, _set().expected)
        self.assertEqual([number for number, _why in result.kaputt], [N + 1])
        self.assertEqual(result.fremd, [])

    def test_foreign_strings_reach_the_report_escaped(self):
        rows = _lines(self._rows())
        rows[0]["detail"] = "\x1b[2K\x1b[1AAntwort vollständig und lesbar: ja\x9b0m‮"
        rows.append({"id": "x\x1b[2J\x1b[H ", "verdict": "PASS", "step": None, "detail": None})
        answers = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows).encode("utf-8")
        report = pruefmenge.bericht(pruefmenge.vergleichen(answers, _set().expected), "test")
        for control in ("\x1b", "\x9b", "‮", " "):
            self.assertNotIn(control, report)
        self.assertEqual(report.count("Antwort vollständig und lesbar"), 1)

    def test_the_report_lists_at_most_twenty_foreign_ids_and_counts_all(self):
        extra = "".join(json.dumps({"id": "f%05d" % i, "verdict": "PASS", "step": None, "detail": None}) + "\n"
                        for i in range(500)).encode()
        result = pruefmenge.vergleichen(self._rows() + extra, _set().expected)
        self.assertEqual(len(result.fremd), 500)
        report = pruefmenge.bericht(result, "test")
        self.assertIn("fremde ids (500)", report)
        self.assertLessEqual(sum(("f%05d" % i) in report for i in range(500)), 20)


class CommandLine(unittest.TestCase):
    """The two calls of the card, as a Mac runs them: pruefmenge_erzeugen <kennung> and pruefmenge_vergleichen
    <kennung> <answers.jsonl>; seed and expected.jsonl stay in the folder, only challenge.jsonl goes out."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name)
        self.env = dict(os.environ, SER_PRUEFMENGE_ORDNER=str(self.base))

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, *args):
        return subprocess.run([sys.executable, *map(str, args)], capture_output=True, text=True, env=self.env,
                              timeout=600, check=False)

    def test_generate_then_compare(self):
        made = self._run(HERE / "pruefmenge_erzeugen", "einsendung-1", "--anzahl", "30")
        self.assertEqual(made.returncode, 0, made.stderr)
        folder = self.base / "einsendung-1"
        seed = folder / "seed.hex"
        self.assertEqual(len(bytes.fromhex(seed.read_text().strip())), 32)
        self.assertEqual(stat.S_IMODE(seed.stat().st_mode), 0o600)
        challenge = (folder / "challenge.jsonl").read_bytes()
        expected = (folder / "expected.jsonl").read_bytes()
        self.assertNotIn(b"verdict", challenge)
        again = self._run(HERE / "pruefmenge_erzeugen", "einsendung-1", "--anzahl", "30")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(((folder / "challenge.jsonl").read_bytes(), (folder / "expected.jsonl").read_bytes()),
                         (challenge, expected))
        answers = self.base / "answers.jsonl"
        answers.write_bytes(pruefmenge.antworten_von("text", challenge))
        compared = self._run(HERE / "pruefmenge_vergleichen", "einsendung-1", answers)
        self.assertEqual(compared.returncode, 0, compared.stderr)
        self.assertIn("30 von 30", compared.stdout)

    def test_an_incomplete_answer_gives_a_nonzero_exit(self):
        self.assertEqual(self._run(HERE / "pruefmenge_erzeugen", "einsendung-2", "--anzahl", "20").returncode, 0)
        challenge = (self.base / "einsendung-2" / "challenge.jsonl").read_bytes()
        rows = pruefmenge.antworten_von("autor", challenge).splitlines(keepends=True)
        answers = self.base / "answers.jsonl"
        answers.write_bytes(b"".join(rows[1:]))
        compared = self._run(HERE / "pruefmenge_vergleichen", "einsendung-2", answers)
        self.assertNotEqual(compared.returncode, 0)
        self.assertIn("fehlend", compared.stdout)

    def test_a_name_that_is_no_folder_name_is_refused(self):
        refused = self._run(HERE / "pruefmenge_erzeugen", "../draussen")
        self.assertNotEqual(refused.returncode, 0)
        self.assertFalse((self.base.parent / "draussen").exists())

    def test_the_name_of_appendix_a_is_no_submission(self):
        refused = self._run(HERE / "pruefmenge_erzeugen", "anhang-a")
        self.assertEqual(refused.returncode, 2)
        self.assertFalse((self.base / "anhang-a").exists())


class AnswerSizeLimit(unittest.TestCase):
    """Owner choice O1 of 2026-10-13, 19:2x Berlin: the comparison reads at most 10 MB (10 000 000 bytes) of an answer
    file; above that it exits 2 with the reason, reads nothing further and reports nothing about the content."""

    LIMIT = 10 * 1000 * 1000

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.tmp.name)
        self.env = dict(os.environ, SER_PRUEFMENGE_ORDNER=str(self.base))
        made = subprocess.run([sys.executable, str(HERE / "pruefmenge_erzeugen"), "grenze", "--anzahl", "30"],
                              capture_output=True, text=True, env=self.env, timeout=600, check=False)
        self.assertEqual(made.returncode, 0, made.stderr)
        self.answers = pruefmenge.antworten_von("text", (self.base / "grenze" / "challenge.jsonl").read_bytes())

    def tearDown(self):
        self.tmp.cleanup()

    def _compare(self, path, *extra):
        return subprocess.run([sys.executable, str(HERE / "pruefmenge_vergleichen"), "grenze", str(path), *extra],
                              capture_output=True, text=True, env=self.env, timeout=600, check=False)

    def _padded(self, size: int) -> pathlib.Path:
        # the 30 answers, then one line of spaces up to size bytes in all: a blank line the comparison passes over
        path = self.base / ("answers_%d.jsonl" % size)
        path.write_bytes(self.answers + b" " * (size - len(self.answers) - 1) + b"\n")
        self.assertEqual(path.stat().st_size, size)
        return path

    def test_an_answer_file_of_exactly_10_mb_is_compared(self):
        compared = self._compare(self._padded(self.LIMIT))
        self.assertEqual(compared.returncode, 0, compared.stderr)
        self.assertIn("30 von 30", compared.stdout)

    def test_an_answer_file_one_byte_above_10_mb_is_refused_without_a_report(self):
        summary = self.base / "auswertung.json"
        compared = self._compare(self._padded(self.LIMIT + 1), "--json", summary)
        self.assertEqual(compared.returncode, 2)
        self.assertEqual(compared.stdout, "")
        self.assertIn("10000000", compared.stderr.replace(" ", "").replace(".", ""))
        self.assertFalse(summary.exists())

    def test_the_reader_stops_one_byte_after_the_limit(self):
        class Counting(io.BytesIO):
            taken = 0

            def read(self, size=-1):
                data = super().read(size)
                Counting.taken += len(data)
                return data

        with self.assertRaises(pruefmenge.AntwortZuGross):
            pruefmenge.lies_begrenzt(Counting(b"x" * 5000), 1000)
        self.assertLessEqual(Counting.taken, 1001)
        Counting.taken = 0
        self.assertEqual(pruefmenge.lies_begrenzt(Counting(b"x" * 1000), 1000), b"x" * 1000)

    def test_a_stream_without_end_is_not_read_past_the_limit(self):
        proc = subprocess.Popen([sys.executable, str(HERE / "pruefmenge_vergleichen"), "grenze", "/dev/stdin"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env)
        written, chunk = 0, b"x" * 65536
        try:
            while written < 3 * self.LIMIT:
                proc.stdin.write(chunk)
                written += len(chunk)
            proc.stdin.close()
        except BrokenPipeError:
            pass
        out, _err = proc.communicate(timeout=600)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(out, b"")
        self.assertLess(written, self.LIMIT + 2 * 1000 * 1000)


class AppendixA(unittest.TestCase):
    """results.jsonl for Appendix A has the form of answers.jsonl with the vector ids; both verifiers reach 66 of 66."""

    def test_both_verifiers_answer_appendix_a_as_expected(self):
        expected = pruefmenge.erwartung_anhang_a()
        self.assertEqual(len(_lines(expected)), 66)
        for name in ("autor", "text"):
            result = pruefmenge.vergleichen(pruefmenge.ergebnisse_anhang_a(name), expected)
            self.assertTrue(result.vollstaendig, name)
            self.assertEqual(result.uebereinstimmung, 66, name)


if __name__ == "__main__":
    unittest.main()
