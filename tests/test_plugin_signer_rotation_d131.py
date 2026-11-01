"""D131, owner answer 7 of Nachtrag 7 (2026-10-26, option A): "Signer at full capacity: A, a documented rotation by the
owner (the record archived and emptied with the service stopped)."

At 4096 remembered releases the signer service refuses a new release with release_record_full and evicts no key (D119,
finding S-F1); the runbook named that name and no way on from it. Here the runbook is held to the rotation: a section
that names release_record_full and the record file, then the steps stop, archive, empty and start in that order; the
place of the archive; how the record is emptied so that the service reads it as empty and not as damaged; what the
rotation means for the releases the record named and what the archive is for. And the code is held to the steps as the
runbook writes them: the service, which starts once per request and reads its record at each start, signs ALLOW for a
new release on a removed record, end to end through the hook of D119 and the service with a plugin data directory of
its own (A2); at the capacity it still signs a call without a release, and it refuses a release only after the key
signer signed it; a record of zero bytes or of another form it reads as damaged and signs nothing at all; after the
rotation it honours a release of the archive again, the limit the runbook names.

RED at f21f785d: the runbook has no rotation and D131 does not stand (the cases of the runbook and of D131). The cases
of the code are green there: the code supports the steps as the runbook writes them, and this slice changes no code.
NOT MEASURED: the stop and the start as sudo rules of real accounts; the wait of step 1 against a real clock; the
reconciliation's count of the key signer's line that has no receipt.
"""
from __future__ import annotations

import json
import pathlib
import re
import shutil

import pytest
from _owner_state import owner_state_protected  # noqa: F401 - D124: a person's release is read

import test_plugin_n29_work_profile_d71 as d71
import test_plugin_n49_release_once_d119 as d119
import test_plugin_signer_release_capacity as cap
import test_plugin_z405_decision_receipt as p1

gate = d71.gate
service = cap.service
pytestmark = d71.pytestmark
ROOT = pathlib.Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "proofbundle"
RUNBOOK = (PLUGIN / "pilot" / "RUNBOOK.md").read_text(encoding="utf-8")
DECISIONS = (PLUGIN / "DECISIONS.md").read_text(encoding="utf-8")
HEADING = "## The rotation of the service's record of releases"
ARCHIVE = "<records folder>/honoured-releases/freigaben-geehrt-<UTC time of the rotation>.json"
RECORD = "<service folder>/freigaben-geehrt.json"


def _flat(text: str) -> str:
    return " ".join(text.split())


def _section(text: str, heading: str) -> str:
    """The section under `heading` up to the next heading of its level; empty where the text has none."""
    start = text.find(heading)
    if start < 0:
        return ""
    end = text.find("\n## ", start + len(heading))
    return text[start:] if end < 0 else text[start:end]


def _steps(section: str) -> list[tuple[str, str]]:
    """The numbered steps of a section: (number, the step's text up to the next step, the last one up to the first
    paragraph after the list that is not indented)."""
    found = list(re.finditer(r"^(\d+)\. ", section, re.M))
    if not found:
        return []
    after = re.search(r"\n\n(?=\S)", section[found[-1].start():])
    ends = [m.start() for m in found[1:]] + [found[-1].start() + after.start() if after else len(section)]
    return [(m.group(1), section[m.start():end]) for m, end in zip(found, ends)]


ROTATION = _section(RUNBOOK, HEADING)


# --- the runbook ------------------------------------------------------------------------------------------------------

def test_the_runbook_names_the_full_record_its_file_and_then_stop_archive_empty_start_in_that_order():
    """The owner's answer as the runbook's order: release_record_full and the record file before the steps, and the
    steps stop, archive, empty and start, numbered 1 to 4, each beginning with its verb."""
    assert ROTATION, "the runbook has no section on the rotation"
    text = _flat(ROTATION)
    first = ROTATION.find("\n1. ")
    assert 0 < ROTATION.find("release_record_full") < first and 0 < ROTATION.find(service.HONOURED) < first
    assert f"At {service.MAX_HONOURED} of them" in text
    verbs = [(number, step.split()[1]) for number, step in _steps(ROTATION)]
    assert verbs == [("1", "Stop"), ("2", "Archive"), ("3", "Empty"), ("4", "Start")], verbs


def test_the_runbook_gives_the_record_with_the_form_and_the_place_the_service_reads():
    """The service reads its record beside its journal, by the name HONOURED and of the form HONOURED_SCHEMA."""
    text = _flat(ROTATION)
    assert "in the folder of its journal (`<service folder>` below)" in text
    assert f'"schema": "{service.HONOURED_SCHEMA}"' in text and '"geehrt": {"<card>:<sha256 of the line>:<session>"' \
        in text
    assert "the gate starts it once per request through the sudo rule of the agent's user" in text
    assert "each start reads the record anew" in text


def test_the_stop_and_the_start_are_the_sudo_rule_and_the_stop_waits_out_the_time_of_a_release():
    steps = dict(_steps(ROTATION))
    stop, start = _flat(steps.get("1", "")), _flat(steps.get("4", ""))
    assert "remove the sudo rule of the agent's user onto the service" in stop
    assert "a release lets nothing run (D119)" in stop and "counts under M5" in stop
    minutes = (gate.RELEASE_SECONDS + gate.RELEASE_SKEW_SECONDS) // 60
    assert (gate.RELEASE_SECONDS, gate.RELEASE_SKEW_SECONDS, minutes) == (900, 60, 16)
    assert f"until the newest time in the record lies more than {minutes} minutes back" in stop
    assert "RELEASE_SECONDS, 15 minutes, and RELEASE_SKEW_SECONDS, 60 s" in stop
    assert "A request that started before the stop does not change a full record." in stop
    assert "put the sudo rule back" in start and "signs ALLOW for a new release again" in start


def test_the_archive_is_named_and_the_record_is_emptied_by_removing_it_never_as_a_file_of_zero_bytes():
    steps = dict(_steps(ROTATION))
    archive, empty = steps.get("2", ""), steps.get("3", "")
    assert f"cp {RECORD} \\\n     {ARCHIVE}" in archive, archive
    assert "`honoured-releases/` is owned by root, mode 755" in _flat(archive)
    assert f"rm {RECORD}" in empty
    flat = _flat(empty)
    assert "The service reads a record that is not there as empty." in flat
    assert "A file in its place of zero bytes, `{}` or another form it reads as damaged" in flat
    assert "(release_record_unread)" in flat and "no release and no other request" in flat


def test_the_runbook_says_what_the_rotation_means_for_the_releases_it_named_and_what_the_archive_is_for():
    text = _flat(ROTATION)
    assert "the service refuses a release it signed ALLOW for only while its record names it" in text
    assert "a release of the archive gets ALLOW again where it still binds" in text
    assert "only the hook's own record of the uses (D111) holds it" in text
    assert "a key that stands in an archive and again in a later record is a release the service signed ALLOW for " \
           "twice" in text
    assert "The reconciliation does not read the archive." in text


def test_d131_names_the_owners_answer_the_steps_and_what_the_code_does_not_support():
    d131 = _flat(_section(DECISIONS, "## D131. "))
    assert "Owner answer 7 of Nachtrag 7" in d131 and "the record archived and emptied with the service stopped" \
        in d131
    assert "in this order: stop, archive, empty, start" in d131 and "release_record_full" in d131
    assert "The service has no start and no stop of its own" in d131
    assert "tests/test_plugin_signer_rotation_d131.py" in d131


# --- the code, as the steps use it -----------------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _hook_environment(monkeypatch, tmp_path):
    d71._clean.__wrapped__(monkeypatch, tmp_path)


def _seed_full(folder: pathlib.Path) -> bytes:
    """A full record (MAX_HONOURED releases) as the service writes it, in the service's folder; returns its bytes."""
    cap._seed({"journal": str(folder / "journal.jsonl")}, service.MAX_HONOURED)
    return (folder / service.HONOURED).read_bytes()


def _rotate(folder: pathlib.Path, records: pathlib.Path) -> pathlib.Path:
    """Steps 2 and 3 as the runbook writes them: the record copied into honoured-releases/ of the records, then
    removed. The service is stopped in between: no hook call runs."""
    archive = records / "honoured-releases"
    archive.mkdir(mode=0o755)
    kept = archive / "freigaben-geehrt-20261027T120000Z.json"
    shutil.copyfile(folder / service.HONOURED, kept)
    (folder / service.HONOURED).unlink()
    return kept


def _signed(folder: pathlib.Path) -> list[tuple[bool, str | None]]:
    return [(x["signed"], x["reason"]) for x in d119._service_lines(folder)]


def test_the_service_started_on_an_emptied_record_signs_allow_for_a_new_release(tmp_path):
    """End to end: at the capacity a call without a release still gets its receipt, and a release gets no signature
    and the call stays blocked; after the rotation the next start of the service reads no record, signs ALLOW, and the
    release lets the call run once. The refusal at the capacity comes after the key signer signed (honour runs after
    the signature, D119): its journal holds a signed line that has no receipt."""
    world = d119.World(tmp_path)
    folder = world.variant("A2", True, own_data=True)
    before = _seed_full(folder)
    assert world.hook()[0] == "deny" and world.receipts() == ["DENY"]
    world.release()
    decision, entry = world.hook()
    assert decision == "deny" and "released_by_owner" not in entry["reason_ids"], (decision, entry)
    assert _signed(folder) == [(True, None), (False, "release_record_full")] and world.receipts() == ["DENY"]
    assert p1.journal(world.service.records)[-1]["why"] == "signer_refused_release_record_full"
    assert [x["signed"] for x in world.service.key_lines()] == [True, True]
    assert (folder / service.HONOURED).read_bytes() == before and world.used() == {}
    kept = _rotate(folder, world.service.records)
    decision, entry = world.hook()
    assert decision == "pass" and entry["autonomy"]["klasse"] == "freigabe", (decision, entry)
    assert world.receipts().count("ALLOW") == 1 and len(world.used()) == 1
    release = json.loads(next((tmp_path / "gatedir" / "freigaben").iterdir()).read_text(encoding="utf-8"))
    assert list(d119._honoured(folder)) == [service._release_key(release)]
    assert kept.read_bytes() == before
    assert world.hook()[0] == "deny" and world.receipts().count("ALLOW") == 1


def test_a_record_of_zero_bytes_or_of_another_form_is_damaged_and_the_service_signs_nothing_at_all(tmp_path):
    """Emptied the wrong way, the record stops every signature, not only a release's: a call without a release gets no
    receipt (release_record_unread); removed, the same call gets its receipt DENY."""
    world = d119.World(tmp_path)
    folder = world.variant("A2", True, own_data=True)
    for text in ("", "{}", json.dumps({"schema": service.HONOURED_SCHEMA})):
        (folder / service.HONOURED).write_text(text, encoding="ascii")
        with pytest.raises(service.Refused, match="release_record_unread"):
            service.honoured({"journal": str(folder / "journal.jsonl")})
    (folder / service.HONOURED).write_text("", encoding="ascii")
    assert world.hook()[0] == "deny"
    assert _signed(folder) == [(False, "release_record_unread")] and world.receipts() == []
    (folder / service.HONOURED).unlink()
    assert service.honoured({"journal": str(folder / "journal.jsonl")}) == {}
    assert world.hook()[0] == "deny"
    assert _signed(folder)[-1] == (True, None) and world.receipts() == ["DENY"]


def test_after_the_rotation_the_service_honours_a_release_of_the_archive_again(tmp_path):
    """The limit the runbook names: a release the service signed ALLOW for is refused only while its record names it.
    Each step in a fresh process of the service, as each request starts it."""
    config = cap._config(tmp_path)
    cap._seed(config, service.MAX_HONOURED - 1)
    assert cap._fresh(config, cap.RECENT) == "honoured"
    assert (cap._fresh(config, cap.RECENT), cap._fresh(config, cap.NEXT)) == ("release_honoured", "release_record_full")
    records = tmp_path / "records"
    records.mkdir()
    kept = _rotate(pathlib.Path(config["journal"]).parent, records)
    assert (cap._fresh(config, cap.NEXT), cap._fresh(config, cap.RECENT)) == ("honoured", "honoured")
    archived = json.loads(kept.read_text(encoding="ascii"))["geehrt"]
    assert len(archived) == service.MAX_HONOURED and set(service.honoured(config)) == {cap._key(cap.NEXT),
                                                                                       cap._key(cap.RECENT)}
    assert set(archived) & set(service.honoured(config)) == {cap._key(cap.RECENT)}
