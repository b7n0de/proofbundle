#!/usr/bin/env python3
"""site-data.json: every value with its source, every gap with its reason.

The three required cases: a missing source yields not_measurable, a tampered receipt yields failed,
and the file is byte-stable while its sources do not change.

THE FOURTH CASE IS HERE BECAUSE IT WAS MISSING. While building the generator the call was
`verify_ed25519(pubkey, message, signature)` instead of `(pubkey, signature, message)`. The call
succeeded, returned a bool, and the bool was wrong: ALL FOUR genuine release receipts reported that
their ed25519 signature does not hold, and that would have gone onto a public page as an accusation.
It showed only because four independently produced receipts failed identically; one alone might have
looked like a real finding.

`test_a_genuine_receipt_counts_as_passed` is the case that would have shown it at once. It stands
BEFORE the tampering case, because a check that refuses everything passes the tampering case as well
- and then the tampering case proves nothing.

THREE STATES, NEVER TWO, and that is this file's load-bearing promise: `passed`, `failed`,
`not_checkable`. `failed` means checked and failed. Writing it for an artefact kind touched with
the wrong tool is an accusation without a measurement.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _generator():
    s = importlib.util.spec_from_file_location("_rsd", REPO / "scripts" / "render_site_data.py")
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


RSD = _generator()

REAL_RECEIPT = REPO / "audit_artifacts" / "610" / "pre_tag_receipt_v6.1.0.json"


def _receipt() -> dict:
    return json.loads(REAL_RECEIPT.read_text(encoding="utf-8"))


class TestTheReceiptIsCheckedWithITSOwnChecker:

    @pytest.mark.skipif(not REAL_RECEIPT.is_file(), reason="no genuine receipt in this tree")
    def test_a_genuine_receipt_counts_as_passed(self):
        # THE CASE THAT WOULD HAVE SHOWN THE SWAPPED ARGUMENT AT ONCE. Without it the tampering
        # case passes even when the check refuses EVERYTHING, and then it proves nothing.
        e = RSD._check_receipt(_receipt())
        assert e["state"] == "passed", (
            "a genuine signed release receipt does not count as passed. First suspicion: the "
            "argument order of verify_ed25519 is (pubkey, signature, message). "
            f"Result: {e}")
        assert "signature_by_trusted_key" in e["checked"]
        assert "audit_exit_code_0" in e["checked"]

    @pytest.mark.skipif(not REAL_RECEIPT.is_file(), reason="no genuine receipt in this tree")
    def test_a_tampered_receipt_yields_failed(self):
        d = _receipt()
        # ONE character in a SIGNED field. This is the required case: a tampered receipt yields
        # failed.
        d["subject_tree_digest"] = "0" * len(str(d.get("subject_tree_digest") or "0"))
        e = RSD._check_receipt(d)
        assert e["state"] == "failed", f"a tampered receipt passed: {e}"
        assert "signature" in e["reason"], e

    @pytest.mark.skipif(not REAL_RECEIPT.is_file(), reason="no genuine receipt in this tree")
    def test_tampering_a_signed_field_is_caught_by_the_signature(self):
        # WHAT THE EARLIER CASE ACTUALLY MEASURED, now under its real name. It set audit_exit_code
        # and claimed to prove the exit-code check, but audit_exit_code is in
        # pre_tag_receipt_lib._SIGNED_FIELDS, so the change breaks the signature and the earlier
        # branch answers first. Its assertion was an `or` over both reasons and absorbed exactly
        # that. Measured 2026-09-25: the reason is always the signature, and deleting the exit-code
        # check left the case green - it could not fail against the defect it named.
        d = _receipt()
        d["audit_exit_code"] = 1
        e = RSD._check_receipt(d)
        assert e["state"] == "failed", f"a failed audit passed: {e}"
        assert "signature" in e["reason"], e
        assert "audit_exit_code" not in e["reason"], (
            "the exit-code branch answered first, so this case is not about the signature and the "
            f"staged case below is measuring the wrong thing: {e}")

    @pytest.mark.skipif(not REAL_RECEIPT.is_file(), reason="no genuine receipt in this tree")
    def test_a_failed_audit_yields_failed_although_the_signature_holds(self, monkeypatch):
        """The exit-code branch, with the signature STAGED as holding, and this says so.

        A validly signed receipt about a FAILED run is not evidence: the signature says someone
        attested it, not that the run went well. That input cannot be produced honestly here, because
        audit_exit_code is a SIGNED field and re-signing would need the release key, which is out of
        scope for a test. So the verifier is staged instead, and staged visibly - at the module
        `_check_receipt` imports from on every call, which is why the patch reaches it.

        Measured 2026-09-25: the patch takes effect and the exit-code reason appears, so the branch
        is reachable and not dead code. What this does NOT prove is that a real receipt can ever
        carry a valid signature over a failed audit.
        """
        import sys  # noqa: PLC0415
        sys.path.insert(0, str(REPO / "src"))
        import proofbundle.signature as sig  # noqa: PLC0415
        monkeypatch.setattr(sig, "verify_ed25519", lambda *a, **k: True)
        d = _receipt()
        d["audit_exit_code"] = 1
        e = RSD._check_receipt(d)
        assert e["state"] == "failed", e
        assert "audit_exit_code" in e["reason"], (
            "with the signature staged as holding the exit-code branch must answer; if it does not, "
            f"the branch is unreachable: {e}")

    def test_a_foreign_artefact_kind_is_NOT_CHECKABLE_and_not_failed(self):
        # THE DIFFERENCE THAT MADE THE FIRST DRAFT WRONG: the bundle verifier on a pre-tag
        # receipt produced no check names and the code wrote `failed`. `failed` is an accusation;
        # for a kind with no declared checker, `not_checkable` belongs there.
        for foreign in ({"schema": "b7n0de.something_else.v1"}, {}, {"schema": None}):
            e = RSD._check_receipt(foreign)
            assert e["state"] == "not_checkable", f"{foreign} yielded {e['state']!r}"
            assert e["state"] != "failed"
            assert "reason" in e and e["reason"]
            # The OTHER end of the severity distinction: this one really is neutral. If both ends
            # carried the same severity the field would say nothing.
            assert e["not_checkable_cause"] == "kind_has_no_declared_checker", e
            assert e["severity"] == "neutral", e

    @pytest.mark.skipif(not REAL_RECEIPT.is_file(), reason="no genuine receipt in this tree")
    def test_the_tree_binding_is_named_not_checkable_instead_of_claimed(self):
        # An honest limit: verify_receipt requires the EXPECTED tree digest, and holding a
        # historical receipt against TODAY's tree would have to fail. It therefore stands as not
        # checkable instead of missing or counting as checked.
        e = RSD._check_receipt(_receipt())
        assert e.get("tree_binding") == "not_checkable_without_checkout_at_tag", e
        # THE KEY IS `tree_binding`. This line said `baumbindung`, which the generator never
        # writes, so it could not fall - the second one of that kind in this file. Named correctly it
        # measures what it means: the tree binding must not appear among the CHECKED items.
        assert "tree_binding" not in (e.get("checked") or [])


class TestAMissingSourceYieldsNotMeasurable:

    def test_interop_without_the_file_is_not_measurable_with_a_reason(self, tmp_path, monkeypatch):
        """The absence is STAGED on a throwaway tree, and the first form measured the real one.

        Two reasons, and the second one is the harder lesson. First: a case that asserts against the
        real absent file stops measuring the moment that file lands, silently and with no red signal.
        Second, and this is what CI caught: naming a root-relative path that is ABSENT here makes the
        whole module a repo-context module by this repository's own classifier, which means it would be
        SKIPPED outside a checkout - and a guard asserts that no module is ever in that state inside a
        checkout. The job `crypto-floor` failed on exactly that, with my module as the single name in
        the list, while 38 cases were green under pytest locally. The curated list is knowledge someone
        keeps, so a crafted tree without it is the honest way to measure its absence.
        """
        (tmp_path / "docs").mkdir()
        monkeypatch.setattr(RSD, "REPO", tmp_path)
        d = RSD.interop()
        assert d.get("not_measurable") is True, d
        assert d.get("reason"), "a gap without a reason is a gap that looks like a value"
        assert "value" not in d, "a gap must not carry a value"

    def test_interop_with_a_present_file_names_the_rows_missing_required_fields(
            self, tmp_path, monkeypatch):
        """THE BRANCH THE ABSENCE CASE CANNOT REACH, and the day it could it stops measuring.

        The case above skips as soon as the curated file exists, and there was no companion case, so
        coverage of this field would drop to zero the moment the real file lands - silently, with no
        red signal. The present-file branch is therefore measured on a crafted tree instead of
        waiting for the real one. Rows missing any required field must be NAMED and not silently
        completed.
        """
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "interop_status.json").write_text(json.dumps({"rows": [
            {"state": "ok", "evidence": "r1", "date": "2026-09-25"},
            {"state": "ok", "evidence": "r2"},
            {"state": "ok", "date": "2026-09-25"},
        ]}), encoding="utf-8")
        monkeypatch.setattr(RSD, "REPO", tmp_path)
        d = RSD.interop()
        assert not d.get("not_measurable"), d
        assert len(d["value"]) == 3, d
        assert d["rows_without_required_fields"] == [1, 2], (
            "an incomplete row is not named, so a gap in the curated list reads as complete: "
            f"{d.get('rows_without_required_fields')}")

    def test_the_gap_never_carries_null_or_an_empty_list(self):
        gap = RSD._gap(source="x", reason="y")
        assert gap.get("value", "MISSING") == "MISSING"
        assert gap["not_measurable"] is True and gap["reason"] == "y"

    def test_scorecard_without_the_network_is_not_measurable_with_that_exact_reason(self):
        d = RSD.scorecard(network=False)
        assert d.get("not_measurable") is True
        assert "not asked" in d["reason"], d
        assert d.get("stable") is False, "a network field is never marked stable"


class TestByteStableOverTheTreeFields:
    """The promise holds for the fields from the TREE and explicitly not for those from the network.

    Asserting it over everything would give a test that is red on every second run and therefore
    gets switched off. A network field has no source time in the tree; its measurement time IS the
    run time.
    """

    def test_two_runs_without_a_source_change_give_the_same_tree_fields(self):
        a = RSD.tree_fields(RSD.build(network=False, check=False))
        b = RSD.tree_fields(RSD.build(network=False, check=False))
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True), (
            "two runs without a source change gave different tree fields - somewhere a run time "
            "stands where a source time should")

    def test_a_run_time_inside_a_stable_field_is_caught_structurally_and_not_by_luck(self,
                                                                                    monkeypatch):
        """The case above is a timing coincidence, and a review lens measured that.

        Both builds finish in about 0.15 s and therefore land in the same UTC second, so a run time
        that leaked into a `stable: true` field would come out byte-identical and the comparison would
        pass. That makes it a lucky green, not a structural one. Here `_now` is forced to differ
        between the two builds: any tree field that reads the clock then shows up as a difference,
        whatever the wall clock does.
        """
        ticks = iter(["2026-01-01T00:00:00Z", "2099-12-31T23:59:59Z"])
        stamp = {"v": next(ticks)}
        monkeypatch.setattr(RSD, "_now", lambda: stamp["v"])
        a = RSD.tree_fields(RSD.build(network=False, check=False))
        stamp["v"] = next(ticks)
        b = RSD.tree_fields(RSD.build(network=False, check=False))
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True), (
            "a tree field changed when only the clock moved, so a run time stands inside the "
            "stability promise")

    def test_a_network_field_is_explicitly_not_part_of_the_promise(self):
        d = RSD.build(network=False, check=False)
        assert d["scorecard"].get("stable") is False
        assert "scorecard" not in RSD.tree_fields(d), (
            "the network field is inside the stability promise, which makes it unkeepable")

    def test_a_changed_source_changes_the_field(self, tmp_path, monkeypatch):
        """COUNTER-CONTROL, and the first draft was not one.

        Without a counter-control a generator that ALWAYS writes the same value passes the stability
        test. The first draft monkeypatched `_TEST_COUNTING_RULE` and compared whole dicts, so the
        only difference was the rule text the test had just set: measured 2026-09-25, `value` was
        4657 before and after. A frozen count would have sailed through it.

        The lever has to be the SOURCE, so the generator is pointed at a crafted tree. Three
        functions in two files, one of them an indented class method - which is precisely the
        difference the counting rule documents.
        """
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_a.py").write_text(
            "def test_one():\n    pass\n\n\ndef test_two():\n    pass\n", encoding="utf-8")
        (tmp_path / "tests" / "test_b.py").write_text(
            "class X:\n    def test_three(self):\n        pass\n", encoding="utf-8")
        monkeypatch.setattr(RSD, "REPO", tmp_path)
        d = RSD.test_surface()
        assert d["tests_files"]["value"] == 2, d["tests_files"]
        assert d["tests_functions"]["value"] == 3, (
            "the count does not follow the source, so the number could be frozen: "
            f"{d['tests_functions']}")


class TestEveryValueNamesItsSourceAndItsMeasurementTime:

    def test_every_field_carries_a_source_and_a_measured_at(self):
        d = RSD.build(network=False, check=False)
        fields = {k: v for k, v in d.items() if isinstance(v, dict) and "stable" in v}
        assert fields, "the generator produced not a single field"
        for k, v in fields.items():
            assert v.get("source"), f"{k} names no source"
            if v.get("not_measurable"):
                assert v.get("measured_at") is None, f"{k} is not measurable and carries a time"
                assert v.get("reason"), f"{k} is not measurable without a reason"
            else:
                assert "value" in v, f"{k} carries no value"

    def test_the_explanation_block_does_NOT_count_as_a_measured_field(self):
        # MEASURED ON THE FIRST RUN: the block used the same key names as the data fields (then
        # spelled `messzeit`, `stabil`, `nicht_messbar` - quoted here as the names they were), and
        # the gap loop took it for a field without a reason: KeyError. Fixed at the COLLISION, not
        # with a special case.
        d = RSD.build(network=False, check=False)
        how_to_read = d["how_to_read"]
        assert "stable" not in how_to_read and "not_measurable" not in how_to_read, (
            "the explanation block carries data-field names again and is counted as a field: "
            f"{sorted(how_to_read)}")
        assert all(k.endswith("_means") for k in how_to_read), sorted(how_to_read)
        # HONEST ABOUT WHAT THE NEXT LINE IS. It asserted `lesart` once, a key the generator never
        # writes, so it could not fall. Naming the real key does not make it fallible either:
        # `tree_fields` keys on `stable`, so the exclusion already follows from the assertion above,
        # and the key name is already pinned by the `d["how_to_read"]` access, which is what the
        # rename catch proof falls on. It stays as a guard against a `tree_fields` that one day
        # selects differently - not as an independent measurement.
        assert "how_to_read" not in RSD.tree_fields(d)

    def test_checks_names_the_bundle_it_was_measured_on(self):
        # A number without its object is the very constant this avoids, only by a detour.
        # Measured on an envelope bundle it is TWO and not three.
        d = RSD.verifier_checks()
        if d.get("not_measurable"):
            assert d.get("reason")
            return
        assert "bundle.json" in d["source"], d["source"]
        assert d.get("checks_measured"), "the number stands without the list it came from"
        assert d["value"] == len(d["checks_measured"])

    def test_a_missing_bundle_is_a_gap_and_the_field_stays_stable(self, monkeypatch):
        # A MISSING FILE IS A PROPERTY OF THE TREE. The first fix marked every gap here unstable,
        # which was conservative but imprecise - an absent file gives the same reason on every run,
        # and calling that unstable teaches a reader that `stable` means little.
        monkeypatch.setattr(RSD, "_MEASURED_BUNDLES", ("does/not/exist/bundle.json",))
        d = RSD.verifier_checks()
        assert d.get("not_measurable") is True, d
        assert d.get("stable") is True, d
        assert d["runs"][0]["reason_is_run_dependent"] is False, d

    def test_a_run_dependent_failure_takes_the_field_out_of_the_stability_promise(self,
                                                                                monkeypatch):
        """The branch this tree never reaches, and the one the catch proof found uncovered.

        `_verify` spawns a subprocess with a timeout, and a timeout or an OSError produces a reason
        carrying a return code or stderr: properties of the RUN. A field that keeps `stable: true`
        through that promises byte-stability it cannot hold. A non-bundle file does NOT stage this -
        measured 2026-09-25, verify then answers deterministically with "no check names" - so the
        failure is staged where it arises.
        """
        monkeypatch.setattr(RSD, "_verify",
                            lambda _p: ("NOT MEASURABLE: TimeoutExpired: rc=124", None, True))
        d = RSD.verifier_checks()
        assert d.get("not_measurable") is True, d
        assert d.get("stable") is False, (
            "a run-time failure left the field inside the stability promise: " + repr(d))
        assert d.get("unstable_reason"), d

    def test_verify_marks_an_os_error_as_run_dependent_and_a_bare_file_as_not(self, monkeypatch):
        # The flag itself, at both ends. Without this the mapping above could be fed a wrong flag.
        def boom(*a, **k):
            raise OSError("no such executable")
        monkeypatch.setattr(RSD.subprocess, "run", boom)
        _state, names, run_dependent = RSD._verify(REPO / "pyproject.toml")
        assert names is None and run_dependent is True
        monkeypatch.undo()
        _state, names, run_dependent = RSD._verify(REPO / "pyproject.toml")
        assert names is None and run_dependent is False, (
            "a file that is simply not a bundle is reported as a run-time problem")

    def test_the_test_count_carries_its_counting_rule(self):
        d = RSD.test_surface()
        for k in ("tests_files", "tests_functions"):
            if d[k].get("not_measurable"):
                continue
            assert d[k].get("counting_rule"), f"{k} names no counting rule, so the number is bare"
            assert "def test_" in d[k]["counting_rule"]



class TestAMissingTrustAnchorIsAGapAndNotAnAccusation:
    """A missing anchor and an untrusted key both stop the verdict, but they are not the same thing.

    With no anchor pinned NOTHING about the signature was checked, so `failed` - which this file
    defines as checked and failed - would blame the receipt for a missing anchor. A review lens fed
    the old form a fabricated receipt with a junk key and got exactly that accusation. The honest
    state is `not_checkable`, and a reader must be able to tell whether to add a key or repair the
    anchor.

    THE CONDITION IS STAGED FOR REAL HERE, and an earlier form of this class said it could not be.
    That was wrong: `load_trusted_pubkeys` reads the committed tree of whatever `REPO` points at, so
    pointing `REPO` at a throwaway tree carrying only the checker library reaches the branch. The
    earlier form asserted on SOURCE TEXT instead, which proves the strings exist somewhere in the
    file and nothing about whether the branch runs. Measured 2026-09-25.
    """

    def _tree_without_an_anchor(self, tmp_path):
        (tmp_path / "scripts").mkdir()
        (tmp_path / "scripts" / "pre_tag_receipt_lib.py").write_bytes(
            (REPO / "scripts" / "pre_tag_receipt_lib.py").read_bytes())
        return tmp_path

    def test_without_an_anchor_the_state_is_not_checkable_and_not_failed(self, tmp_path,
                                                                        monkeypatch):
        monkeypatch.setattr(RSD, "REPO", self._tree_without_an_anchor(tmp_path))
        e = RSD._check_receipt({"schema": "b7n0de.pre_tag_audit_receipt.v1",
                               "signer_pubkey": "not-even-real", "signature": "also-not-real",
                               "version": "9.9.9", "audit_exit_code": 0})
        assert e["state"] == "not_checkable", (
            "a fabricated receipt under a missing anchor is reported as an accusation, although "
            f"nothing about its signature was checked: {e}")
        assert "no trust anchor pinned" in e["reason"], e
        assert "not a statement about the receipt" in e["reason"], (
            "the reason blames the receipt for a missing anchor: " + e["reason"])
        # AND THE CAUSE MUST SAY THAT IT IS ALARMING. An un cross-reading refuted the bare state: a
        # reader takes `not_checkable` for "no data yet", which is neutral or even pending, while a
        # missing trust anchor means the control is broken.
        assert e["not_checkable_cause"] == "control_missing", e
        assert e["severity"] == "alarming", (
            "a broken control is reported with the same weight as an artefact nobody declared a "
            f"checker for, so a reader reads an alarm as pending: {e}")

    def test_the_two_reasons_are_different_and_name_different_causes(self):
        # A single shared text would make the distinction unobservable, which is the same as not
        # having it. The untrusted-key branch cannot be staged as cheaply (it needs a real anchor
        # list plus a receipt signed by another key), so it is asserted on the source - and that is
        # said here rather than left to look like a runtime measurement.
        src = (REPO / "scripts" / "render_site_data.py").read_text(encoding="utf-8")
        assert "no trust anchor pinned" in src
        assert "the signing key is not in" in src
        i, j = src.index("if not trusted:"), src.index("if pub not in trusted:")
        assert i < j, "the anchor branch must come first, otherwise an empty list falls through it"


class TestTheVersionBindingIsMeasuredAndNotClaimed:
    """The docstring named this check before the code did it.

    A review lens ran the genuine v6.1.0 receipt through `_check_receipt` as if it had been filed
    under v9.9.9 and got a byte-identical `passed`: the function only ever saw the receipt, never a
    release to bind it to, while its docstring listed "the version binding" among what is checked.
    """

    @pytest.mark.skipif(not REAL_RECEIPT.is_file(), reason="no genuine receipt in this tree")
    def test_a_receipt_filed_under_another_version_yields_failed(self):
        e = RSD._check_receipt(_receipt(), expected_version="9.9.9")
        assert e["state"] == "failed", (
            "a receipt signed for one release passes under another, so the proof log could show it "
            f"next to the wrong version: {e}")
        assert e["failure_kind"] == "filing_mismatch", (
            "a filing error and a broken signature wear the same label, so a reader concludes the "
            f"audit failed when the signature held: {e}")
        assert "filing error" in e["reason"], e
        assert "the signature holds" in e["reason"], (
            "the reason does not say that the signature held, which is the whole point of "
            f"separating the two causes: {e}")

    @pytest.mark.skipif(not REAL_RECEIPT.is_file(), reason="no genuine receipt in this tree")
    def test_with_the_right_version_the_binding_is_named_among_the_checks(self):
        d = _receipt()
        e = RSD._check_receipt(d, expected_version=d["version"])
        assert e["state"] == "passed", e
        assert "version_binding" in e["checked"], e

    @pytest.mark.skipif(not REAL_RECEIPT.is_file(), reason="no genuine receipt in this tree")
    def test_without_an_expected_version_the_binding_is_NOT_claimed(self):
        # The unbound call must not pretend. This is the case that would have caught the old state,
        # where `checked` was identical whether or not a binding had been made.
        e = RSD._check_receipt(_receipt())
        assert "version_binding" not in e["checked"], e
        assert e["version_binding"].startswith("not_checked"), e

    def test_the_proof_log_binds_every_entry_to_the_version_in_its_file_name(self):
        d = RSD.proof_log(check=True)
        if d.get("not_measurable"):
            pytest.skip("no receipt in this tree")
        for e in d["value"]:
            assert e["filed_under"], f"the entry names no release it is filed under: {e}"
            if e["check"]["state"] == "passed":
                assert "version_binding" in e["check"]["checked"], (
                    f"an entry passes without its version having been bound: {e}")


class TestAValueWithoutATimeSaysWhy:
    """A field that looks fully measured while its time is unknown.

    `_source_time` returns no time for an untracked path, and every call site used to pass that
    straight through: a real value, `measured_at: null`, and no marker anywhere. A review lens
    produced it on a throwaway untracked file. It also found the reverse trap, which is the one that
    matters more: the VALUE is read from the working tree while the TIME comes from `git log`, so with
    an uncommitted edit the time named superseded content while looking measured.
    """

    def test_every_field_without_a_time_carries_a_reason(self):
        d = RSD.build(network=False, check=False)
        for k, v in d.items():
            if not (isinstance(v, dict) and "stable" in v):
                continue
            if v.get("not_measurable") or v.get("measured_at") is not None:
                continue
            assert v.get("measured_at_note"), (
                f"{k} carries a value with no time and no note, so it reads as measured: {v}")

    def test_no_field_falls_back_to_the_placeholder_reason(self):
        # The fallback in `_field` exists so a missing reason is visible rather than silent. If it
        # ever appears, a call site forgot to name its own reason.
        d = json.dumps(RSD.build(network=False, check=False))
        assert "the call site named no reason" not in d, (
            "a call site passed no time and no reason, and the placeholder went into the output")

    def test_an_uncommitted_source_gives_the_working_tree_time_and_leaves_the_promise(
            self, tmp_path, monkeypatch):
        """THE TRAP ITSELF, staged, and the second form of the fix.

        A tracked-then-edited file is the case where value and commit time describe different
        content, so the commit time must NOT be used. The first fix returned a bare `None`, and an un
        cross-reading refuted that: the value is present and current, so a null time reads as unknown
        or pending for something that is neither. What is honest is the working-tree write time plus
        `stable: false` - a time that holds for this checkout and for no other.
        """
        import subprocess  # noqa: PLC0415
        for args in (["init", "-q"], ["config", "user.email", "t@t"], ["config", "user.name", "t"]):
            subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)
        (tmp_path / "pyproject.toml").write_text('version = "1.0.0"\n', encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "pyproject.toml"], check=True,
                       capture_output=True)
        subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "x"], check=True,
                       capture_output=True)
        monkeypatch.setattr(RSD, "REPO", tmp_path)
        at_clean, note_clean, stable_clean = RSD._source_time("pyproject.toml")
        assert at_clean and note_clean is None and stable_clean is True, (at_clean, note_clean)
        (tmp_path / "pyproject.toml").write_text('version = "2.0.0"\n', encoding="utf-8")
        at_dirty, note_dirty, stable_dirty = RSD._source_time("pyproject.toml")
        assert at_dirty != at_clean, (
            "the time of the old commit is returned for content that has already changed: "
            f"{at_dirty}")
        assert at_dirty is not None, (
            "a bare null reads as unknown or pending, and the value is neither - it is current")
        assert stable_dirty is False, (
            "a working-tree time is inside the byte-stability promise, which cannot hold")
        assert "uncommitted" in (note_dirty or ""), note_dirty

class TestNoAssertionNamesAStringTheSurfaceNeverProduces:
    """THE CLASS, not the two instances.

    This file carried two assertions naming a key the generator never writes: `baumbindung` for
    `tree_binding` and `lesart` for `how_to_read`. Both were green and both measured nothing, because
    a literal that never occurs cannot make a `not in` fail. Fixing the two would have left the class
    open; the next rename puts a third one in.

    The rule: every key-shaped literal this file compares against must occur either in the
    generator's source or in its output. A literal that occurs in neither is either a typo or a
    leftover from a rename, and in both cases the assertion around it is decoration.

    Measured 2026-09-25: with the two defects planted back in, this catches 2 of 2.
    """

    #: Literals DELIBERATELY absent from the surface, each with its reason. Without this set the
    #: widened detector flags them, and a detector that cries wolf gets narrowed again.
    DELIBERATELY_ABSENT = {
        "MISSING": "a sentinel default for dict.get - it must NOT occur in the surface",
    }

    def test_every_key_shaped_literal_in_here_exists_in_the_generator_or_its_output(self):
        """WIDENED after a review lens named six blind spots in the first form.

        The first form matched `^[a-z][a-z0-9_]{3,}$` over `In`/`NotIn`/`Eq` only, so every one of
        these reproduced the original class unseen: an uppercase letter, a space, a dot, a literal
        shorter than four characters, and `!=`. All five are covered now. A dict subscript such as
        `d["typo"]` is deliberately NOT scanned: a wrong key there raises KeyError and fails loudly,
        so it is self-detecting and needs no guard.
        """
        import ast  # noqa: PLC0415
        import re  # noqa: PLC0415
        source = (REPO / "scripts" / "render_site_data.py").read_text(encoding="utf-8")
        # ADJACENT LITERALS JOINED. This guard caught one of its own author's new assertions,
        # `"different release"`, and was wrong to: the generator composes that text from
        # `"...a different "` and `"release than..."` across a line break, so it exists at runtime
        # and in no single line of the source. Joining adjacent quoted fragments sees through that.
        # The honest cost: joining can also glue two UNRELATED neighbouring strings, which can let a
        # bad literal pass. A guard that cries wolf gets deleted, so a false negative is the cheaper
        # error here - this catches typos and leftover renames, it is not a proof.
        source += re.sub(r'"\s*\n\s*"', "", source)
        output = json.dumps(RSD.build(network=False, check=False))
        key_shaped = re.compile(r"^[A-Za-z][A-Za-z0-9_. -]{2,}$")
        mine = Path(__file__).read_text(encoding="utf-8")
        suspects = []
        for n in ast.walk(ast.parse(mine)):
            if not isinstance(n, ast.Compare):
                continue
            if not any(isinstance(o, (ast.In, ast.NotIn, ast.Eq, ast.NotEq)) for o in n.ops):
                continue
            for k in [n.left, *n.comparators]:
                if (isinstance(k, ast.Constant) and isinstance(k.value, str)
                        and key_shaped.match(k.value)
                        and k.value not in self.DELIBERATELY_ABSENT
                        and k.value not in source and k.value not in output):
                    suspects.append((n.lineno, k.value))
        assert not suspects, (
            "an assertion names a string that neither the generator's source nor its output "
            f"contains, so it cannot fail: {suspects}")

    def test_no_f_string_stands_on_either_side_of_a_membership_or_equality_check(self):
        """THE ONE BLIND SPOT THAT CANNOT BE CLOSED BY LOOKING, so it is forbidden instead.

        An f-string is an `ast.JoinedStr` and not an `ast.Constant`, so the case above cannot read
        its value - a wrong key hidden in one would reproduce the original class unseen. Measured
        2026-09-25: this file contains none in a comparison, so forbidding them costs nothing today
        and keeps the guard whole tomorrow. An f-string in an assertion MESSAGE stays allowed; only
        the compared operands are covered.
        """
        import ast  # noqa: PLC0415
        joined = []
        for n in ast.walk(ast.parse(Path(__file__).read_text(encoding="utf-8"))):
            if not isinstance(n, ast.Compare):
                continue
            if not any(isinstance(o, (ast.In, ast.NotIn, ast.Eq, ast.NotEq)) for o in n.ops):
                continue
            joined += [n.lineno for k in [n.left, *n.comparators] if isinstance(k, ast.JoinedStr)]
        assert not joined, (
            "an f-string is compared, and the key-shaped-literal guard cannot see through it; "
            f"write the operand as a plain literal instead. Lines: {sorted(set(joined))}")


class TestEveryVerdictNamesItsCauseAndNotJustItsState:
    """A state is not a cause, and two causes must not wear one label.

    An un cross-reading refuted two places where they did: `failed` covered both a broken signature
    and a receipt filed under the wrong release - and the file name is NOT part of the signed payload,
    so the second is a filing error while the signature held. `not_checkable` covered both a missing
    trust anchor (the control is broken, alarming) and an artefact kind nobody declared a checker for
    (neutral). A reader who can only see the state draws the wrong conclusion in both directions.
    """

    @staticmethod
    def _verdict_dicts(state: str) -> list[tuple[int, set[str]]]:
        """Every dict literal in the generator whose `state` is `state`, with its key names.

        BY AST AND NOT BY REGEX, and the first form of this guard is why. It matched
        `{"state": "failed"` and demanded `"failure_kind"` immediately after, which is a rule about
        LINE LAYOUT and not about the dict: the filing-mismatch return carries the key on the next
        line and was reported as missing it. A pattern recognises a form, never an identity - the
        recurring mistake this repository pays for, and this guard walked straight into it while being
        built to catch exactly that shape of error.
        """
        import ast  # noqa: PLC0415
        src = (REPO / "scripts" / "render_site_data.py").read_text(encoding="utf-8")
        out = []
        for n in ast.walk(ast.parse(src)):
            if not isinstance(n, ast.Dict):
                continue
            keys = {k.value for k in n.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)}
            for k, v in zip(n.keys, n.values):
                if (isinstance(k, ast.Constant) and k.value == "state"
                        and isinstance(v, ast.Constant) and v.value == state):
                    out.append((n.lineno, keys))
        return out

    def test_every_failed_path_carries_a_failure_kind(self):
        # Asserted on the source because not every failure path can be staged cheaply (an untrusted
        # key needs a real anchor list plus a receipt signed by another key). Said here rather than
        # left to look like a runtime measurement.
        found = self._verdict_dicts("failed")
        assert found, "no failed verdict found at all; the guard lost its subject"
        bare = [ln for ln, keys in found if "failure_kind" not in keys]
        assert not bare, (
            "a failed verdict is returned without naming its kind, so a filing error and a broken "
            f"signature read the same. Lines: {bare}")

    def test_every_not_checkable_path_carries_a_cause_and_a_severity(self):
        found = self._verdict_dicts("not_checkable")
        assert len(found) >= 5, f"only {len(found)} not_checkable paths found; the guard lost its subject"
        bare = [(ln, sorted(keys)) for ln, keys in found
                if not {"not_checkable_cause", "severity"} <= keys]
        assert not bare, (
            "a not_checkable verdict names no cause or no severity, so a broken control reads like "
            f"a pending measurement: {bare}")

    @pytest.mark.skipif(not REAL_RECEIPT.is_file(), reason="no genuine receipt in this tree")
    def test_a_passing_receipt_carries_no_failure_kind(self):
        # The counter-control: a guard that demanded the key everywhere would also pass if the key
        # were bolted onto every verdict including the good ones, which would make it meaningless.
        e = RSD._check_receipt(_receipt())
        assert e["state"] == "passed", e
        assert "failure_kind" not in e, e
        assert "not_checkable_cause" not in e, e


class TestTheStageIsDerivedUnambiguouslyOrNotAtAll:
    """Found by reading the one function no review lens had looked at.

    Two latent defects sat in `audit_state_field`. The stage name was built by concatenating the
    major and minor digits and appending a zero, so 6.10.0 and 61.0.0 both produced "6100" - and the
    naming scheme (major*100 + minor*10) has no unambiguous name for a minor of 10 or more at all. And
    the stage list was sorted as TEXT, which makes "90" the last of ["610", "90"] and "700" the last
    of ["6100", "700"], although 6100 is the later stage. Today every stage name has three digits, so
    both orders agree and neither defect shows; they fire with the first four-digit stage, which is
    version 6.10.0.
    """

    def test_a_minor_of_ten_or_more_is_refused_instead_of_guessed(self):
        d = RSD.audit_state_field("6.10.0")["audit_state"]
        assert d.get("not_measurable") is True, (
            "a stage is derived from an ambiguous key, which would send a reader to another "
            f"release's audit directory: {d}")
        assert "not derivable" in d["reason"], d
        assert "value" not in d, d

    def test_a_single_digit_minor_still_yields_its_stage(self):
        # COUNTER-CONTROL. Without it a generator that refused EVERY version would pass the case
        # above, and the refusal would measure nothing.
        d = RSD.audit_state_field("6.1.0")["audit_state"]
        assert d.get("not_measurable") is not True, d
        assert d["value"] == "610", d

    def test_the_stage_list_is_ordered_numerically_and_not_as_text(self, tmp_path, monkeypatch):
        # WITHOUT A VERSION the newest stage is the fallback, and "newest" must mean the greatest
        # number. As text, "90" sorts after "610" and the fallback would name a stage nine times
        # smaller.
        (tmp_path / "audit_artifacts" / "90").mkdir(parents=True)
        (tmp_path / "audit_artifacts" / "610").mkdir(parents=True)
        (tmp_path / "audit_artifacts" / "6100").mkdir(parents=True)
        monkeypatch.setattr(RSD, "REPO", tmp_path)
        d = RSD.audit_state_field(None)
        assert d["audit_state"]["value"] == "6100", (
            "the fallback picked a stage by text order, so the newest audit is not the one named: "
            f"{d['audit_state']}")
        assert d["audit_state"]["stages"] == ["90", "610", "6100"], d["audit_state"]["stages"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
