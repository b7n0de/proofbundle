"""Finding S-F1 of the external review (section SIGNER), the owner's order N4-5: the signer service forgets no release
it remembers; at the capacity of its record it refuses a new release instead (release_record_full).

The service keeps the releases it signed ALLOW for in freigaben-geehrt.json beside its journal (D119). Before, honour
kept at most MAX_HONOURED (4096) keys and, past that, dropped the first key of the dictionary. The record is written
with sorted keys, so after a read the first key is the lexically first, not the oldest: with 4095 old entries, one
recent release whose key sorts before them and one more new release, the recent key was dropped, and a fresh process
honoured the recent release again while it could still be presented. The owner's order: refuse new releases at the
capacity instead of evicting old keys, document release_record_full, and test 4095 old plus one new across fresh
processes.

Here honour runs in new Python processes (-I) that load signer_service.py by its path, and in this process; the
record is seeded with synthetic releases as the service writes it. A second signed ALLOW receipt and a repeated real
effect are NOT MEASURED here, nor the refusal's way through main() and the gate.

RED at 16cffca (the base of slice N4-5): at the capacity the next new release is honoured, the recent key is dropped,
a fresh process honours the recent release again, and the record changes. Below the capacity both states honour a
new release.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICE = ROOT / "plugins" / "proofbundle" / "pilot" / "signer_service.py"
SESSION = "operator-session-1"
OLD_TIME = "2026-10-01T00:00:00Z"

from _gate_answer import skip_where_the_gate_is_not_shipped  # noqa: E402

# MANIFEST.in prunes plugins/: in the extracted sdist this module is one skip that names the path, not a collection
# error (hermetic-cleanroom of pull request 460 at eab4fb3d).
skip_where_the_gate_is_not_shipped(SERVICE, ROOT)
sys.path.insert(0, str(SERVICE.parent))
try:
    import signer_service as service
finally:
    sys.path.pop(0)

#: Loads the service from its path in a new interpreter and honours one release: prints "honoured" or the refusal.
FRESH = """
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("signer_service", sys.argv[1])
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)
try:
    service.honour(json.loads(sys.argv[2]), json.loads(sys.argv[3]))
except service.Refused as exc:
    print(exc)
else:
    print("honoured")
"""


def _release(card: str, digit: str) -> dict:
    return {"karte": card, "sha256": digit * 64, "sitzung": SESSION, "antwort": "2026-10-26T12:00:00Z"}


#: A recent release whose key sorts before every old one, and two other new releases whose keys sort after them.
RECENT = _release("OA-0000000000", "a")
NEXT = _release("OA-2000000000", "c")
OTHER = _release("OA-3000000000", "d")


def _key(release: dict) -> str:
    return service._release_key(release)


def _config(tmp_path: pathlib.Path) -> dict:
    folder = tmp_path / "dienst"
    folder.mkdir()
    return {"journal": str(folder / "journal.jsonl"), "records": str(tmp_path / "records")}


def _record(config: dict) -> pathlib.Path:
    return pathlib.Path(config["journal"]).parent / service.HONOURED


def _seed(config: dict, count: int) -> set[str]:
    """A valid record with count old releases, written as the service writes it; returns their keys."""
    old = {_key(_release(f"OA-1{i:09x}", "b")): OLD_TIME for i in range(count)}
    _record(config).write_text(json.dumps({"schema": service.HONOURED_SCHEMA, "geehrt": old}, sort_keys=True),
                               encoding="ascii")
    return set(old)


def _fresh(config: dict, release: dict) -> str:
    proc = subprocess.run([sys.executable, "-I", "-c", FRESH, str(SERVICE), json.dumps(config), json.dumps(release)],
                          capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def test_the_capacity_is_4096_releases():
    assert service.MAX_HONOURED == 4096


def test_4095_old_and_one_recent_a_new_release_is_refused_and_the_recent_one_stays_honoured_in_a_fresh_process(
        tmp_path):
    """The reviewer's reproduction at the bound, each step in a fresh process of the service."""
    config = _config(tmp_path)
    old = _seed(config, service.MAX_HONOURED - 1)
    assert _fresh(config, RECENT) == "honoured"
    assert _fresh(config, RECENT) == "release_honoured"
    assert min(service.honoured(config)) == _key(RECENT) and len(service.honoured(config)) == service.MAX_HONOURED
    answer = _fresh(config, NEXT)
    remembered = service.honoured(config)
    again = _fresh(config, RECENT)
    assert (answer, _key(RECENT) in remembered, _key(NEXT) in remembered, old <= set(remembered), again) == \
        ("release_record_full", True, False, True, "release_honoured")
    assert len(service.honoured(config)) == service.MAX_HONOURED


def test_below_the_capacity_new_releases_are_still_honoured_and_no_key_is_dropped(tmp_path):
    config = _config(tmp_path)
    old = _seed(config, service.MAX_HONOURED - 2)
    service.honour(config, NEXT)
    assert _fresh(config, OTHER) == "honoured"
    remembered = service.honoured(config)
    assert old | {_key(NEXT), _key(OTHER)} == set(remembered) and len(remembered) == service.MAX_HONOURED
    assert _fresh(config, NEXT) == "release_honoured" and _fresh(config, OTHER) == "release_honoured"


def test_a_release_refused_at_the_capacity_leaves_the_record_byte_for_byte(tmp_path):
    config = _config(tmp_path)
    _seed(config, service.MAX_HONOURED - 1)
    service.honour(config, RECENT)
    folder, before = _record(config).parent, _record(config).read_bytes()
    names = sorted(p.name for p in folder.iterdir())
    try:
        service.honour(config, OTHER)
        answer = "honoured"
    except service.Refused as exc:
        answer = str(exc)
    assert (answer, _record(config).read_bytes() == before) == ("release_record_full", True)
    assert sorted(p.name for p in folder.iterdir()) == names
    with pytest.raises(service.Refused, match="release_honoured"):
        service.honour(config, RECENT)
