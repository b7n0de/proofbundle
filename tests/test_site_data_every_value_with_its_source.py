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
    def test_a_failed_audit_yields_failed_even_with_a_valid_signature(self):
        # A validly signed receipt about a FAILED run is not evidence. The signature says that
        # someone attested it, not that it went well.
        d = _receipt()
        d["audit_exit_code"] = 1
        e = RSD._check_receipt(d)
        assert e["state"] == "failed", f"a failed audit passed: {e}"
        # The reason names either the exit code or the signature broken by changing it; both are
        # an honest failed, but it must not be passed.
        assert "audit_exit_code" in e["reason"] or "signature" in e["reason"], e

    def test_a_foreign_artefact_kind_is_NOT_CHECKABLE_and_not_failed(self):
        # THE DIFFERENCE THAT MADE THE FIRST DRAFT WRONG: the bundle verifier on a pre-tag
        # receipt produced no check names and the code wrote `failed`. `failed` is an accusation;
        # for a kind with no declared checker, `not_checkable` belongs there.
        for foreign in ({"schema": "b7n0de.something_else.v1"}, {}, {"schema": None}):
            e = RSD._check_receipt(foreign)
            assert e["state"] == "not_checkable", f"{foreign} yielded {e['state']!r}"
            assert e["state"] != "failed"
            assert "reason" in e and e["reason"]

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

    def test_interop_without_the_file_is_not_measurable_with_a_reason(self):
        # `docs/interop_status.json` is not in this tree. The field must NOT appear as an empty
        # list: 0, an empty list and a last-known value are all forbidden, and all three share one
        # property, they read like a measurement.
        d = RSD.interop()
        if (REPO / "docs" / "interop_status.json").is_file():
            pytest.skip("the curated list now exists - this case tests its absence")
        assert d.get("not_measurable") is True, d
        assert d.get("reason"), "a gap without a reason is a gap that looks like a value"
        assert "value" not in d, "a gap must not carry a value"

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

    def test_a_network_field_is_explicitly_not_part_of_the_promise(self):
        d = RSD.build(network=False, check=False)
        assert d["scorecard"].get("stable") is False
        assert "scorecard" not in RSD.tree_fields(d), (
            "the network field is inside the stability promise, which makes it unkeepable")

    def test_a_changed_source_changes_the_field(self, tmp_path, monkeypatch):
        # COUNTER-CONTROL: without it a generator that ALWAYS writes the same would pass the
        # stability test. Measured on the counting rule that stands as data next to the number: if
        # it changes, the field has to change.
        before = RSD.test_surface()["tests_functions"]
        monkeypatch.setattr(RSD, "_TEST_COUNTING_RULE", "a different rule")
        after = RSD.test_surface()["tests_functions"]
        assert before != after, "a changed counting rule left the field unchanged"


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

    def test_the_test_count_carries_its_counting_rule(self):
        d = RSD.test_surface()
        for k in ("tests_files", "tests_functions"):
            if d[k].get("not_measurable"):
                continue
            assert d[k].get("counting_rule"), f"{k} names no counting rule, so the number is bare"
            assert "def test_" in d[k]["counting_rule"]



class TestAnEmptyTrustListIsNotAnUntrustedKey:
    """Both block, but the reason must name the real cause.

    FOUND BY CHECKING A PLACE AN un CROSS-READING DID NOT NAME. With no anchor pinned, NOTHING about
    the signature was checked, and a reason saying "this key is not trusted" would blame the receipt
    for a missing anchor. A reader has to be able to tell whether to add a key or repair the anchor.
    """

    def test_the_runtime_condition_is_NOT_staged_here_and_this_says_so(self):
        """The empty-anchor case is asserted on the SOURCE and not by staging the condition.

        HONEST ABOUT WHAT THIS DOES NOT DO. `_check_receipt` loads `pre_tag_receipt_lib` fresh on
        every call, and `load_trusted_pubkeys` reads the COMMITTED tree, so an empty anchor list
        cannot be staged from a test without writing to the repository. Faking it by injecting a
        module under a private name was tried and did not take effect, which would have produced a
        green test that measures nothing - the worse outcome of the two.

        So this file asserts the property it can: the two reasons exist and differ. That the
        runtime path reaches them is UNPROVEN here and is named as such.
        """
        src = (REPO / "scripts" / "render_site_data.py").read_text(encoding="utf-8")
        assert "if not trusted:" in src, "the empty-anchor branch is gone"
        assert "no trust anchor pinned" in src
        assert "if pub not in trusted:" in src, "the untrusted-key branch is gone"
        i, j = src.index("if not trusted:"), src.index("if pub not in trusted:")
        assert i < j, "the anchor branch must come first, otherwise an empty list falls through it"

    def test_the_two_reasons_are_different_texts(self):
        # A single shared text would make the distinction unobservable, which is the same as not
        # having it.
        src = (REPO / "scripts" / "render_site_data.py").read_text(encoding="utf-8")
        assert "no trust anchor pinned" in src
        assert "the signing key is not in" in src

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

    def test_every_key_shaped_literal_in_here_exists_in_the_generator_or_its_output(self):
        import ast  # noqa: PLC0415
        import re  # noqa: PLC0415
        source = (REPO / "scripts" / "render_site_data.py").read_text(encoding="utf-8")
        output = json.dumps(RSD.build(network=False, check=False))
        key_shaped = re.compile(r"^[a-z][a-z0-9_]{3,}$")
        mine = Path(__file__).read_text(encoding="utf-8")
        suspects = []
        for n in ast.walk(ast.parse(mine)):
            if not isinstance(n, ast.Compare):
                continue
            if not any(isinstance(o, (ast.In, ast.NotIn, ast.Eq)) for o in n.ops):
                continue
            for k in [n.left, *n.comparators]:
                if (isinstance(k, ast.Constant) and isinstance(k.value, str)
                        and key_shaped.match(k.value)
                        and k.value not in source and k.value not in output):
                    suspects.append((n.lineno, k.value))
        assert not suspects, (
            "an assertion names a string that neither the generator's source nor its output "
            f"contains, so it cannot fail: {suspects}")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
