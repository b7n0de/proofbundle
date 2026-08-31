"""Our own entry in a third-party transparency log — and the half of the claim that is NOT yet true.

WHY THIS MODULE EXISTS. `tests/test_anchors_markovian_log.py` verifies a proof the log issued about
its OWN stream statement. Its manifest names the gap in its own words: the public `POST /submit`
path is not exercised there. On 2026-08-31 we submitted the sha256 of an agent-review receipt and
vendored what came back. This module checks that submission offline.

THE POINT OF THE MODULE IS THE SEPARATION, not the green line. Three statements are routinely
collapsed into one, and each of them is a different fact:

  1. the entry is IN THE TREE            — the log answered an inclusion query and the path recomputes
  2. the entry is WITNESSED              — a signed checkpoint of sufficient size is cosigned by quorum
  3. the entry is ANCHORED               — that checkpoint reached the Bitcoin anchor

At vendoring time only (1) held. The log said so itself: `GET /proof/7727` returned 404 with
"leaf not yet in a witnessed checkpoint; retry after the next witness round". The module therefore
asserted (1) and asserted that (2) was PENDING.

ABOUT AN HOUR LATER (2026-08-31, same session) the witness round completed, the checkpoint advanced
to size 7728, and the PENDING assertion went RED — exactly as it was built to. That is the half of
the design that mattered: a gate catching only overclaim would have left this fixture quietly stale,
still saying "pending" about something long since witnessed.

The load-bearing assertion therefore MOVED rather than being deleted. It now reads: WITNESSED may be
claimed only if the root recomputed here from the vendored leaf and path is BYTE-IDENTICAL to the
root in a vendored signed checkpoint of sufficient size. Measured: it is
(`N9rmdtCUMVkId/T5rLPe2g49K70hh4dKkps8ZnBqjr4=`, computed with plain hashlib before the log's own
bundle was fetched). A state word is cheap; a matching root is not.

(3) is still NOT claimed. Witnessed and anchored are two facts.

Everything here is offline: vendored bytes only, no network at test time.
"""
import base64
import hashlib
import json
from pathlib import Path

import pytest

FIX = Path(__file__).parent / "fixtures" / "anchors" / "markovian_log" / "submit_7727"
LEAF_INDEX = 7727
TREE_SIZE = 7728


def _manifest() -> dict:
    return json.loads((FIX / "MANIFEST.json").read_text(encoding="utf-8"))


def _path_nodes() -> list[bytes]:
    zeilen = [z for z in (FIX / "inclusion_path.txt").read_text(encoding="utf-8").splitlines() if z.strip()]
    return [base64.b64decode(z + "=" * (-len(z) % 4)) for z in zeilen]


def _rfc6962_root(leaf: bytes, path: list[bytes], index: int, size: int) -> bytes:
    """Standalone RFC 6962 inclusion recomputation — plain hashlib, written from the spec.

    Deliberately NOT `proofbundle.merkle`: a fixture whose recomputation shares an implementation
    with the thing it checks can only find disagreements the shared code does not have.
    """
    h = hashlib.sha256(b"\x00" + leaf).digest()
    i, sz = index, size
    for node in path:
        if sz == 1:
            raise AssertionError("inclusion path is longer than the tree allows")
        if i % 2 == 1 or i == sz - 1:
            h = hashlib.sha256(b"\x01" + node + h).digest()
            while i % 2 == 0 and i != 0:
                i //= 2
                sz = (sz + 1) // 2
        else:
            h = hashlib.sha256(b"\x01" + h + node).digest()
        i //= 2
        sz = (sz + 1) // 2
    return h


def _required_path_length(index: int, size: int) -> int:
    """How many nodes RFC 6962 requires — derived, not copied from the log's answer."""
    k, i, n = 0, index, size
    while n > 1:
        if i % 2 == 1 or i != n - 1:
            k += 1
        i //= 2
        n = (n + 1) // 2
    return k


# ── (1) the entry is in the tree ───────────────────────────────────────────────────────────────

def test_leaf_bytes_are_the_ones_we_submitted():
    """The leaf must carry OUR digest. A log that stored something else would still answer an
    inclusion query happily."""
    leaf = (FIX / "leaf.txt").read_bytes().decode("utf-8")
    m = _manifest()
    assert m["submitted"]["body"] in leaf, leaf
    assert leaf.startswith("public-note:v1 "), leaf


def test_leaf_hash_matches_the_recorded_measurement():
    leaf = (FIX / "leaf.txt").read_bytes()
    got = base64.b64encode(hashlib.sha256(b"\x00" + leaf).digest()).decode()
    assert got == _manifest()["measured_2026_08_31"]["leaf_hash_b64"]


def test_path_length_is_what_rfc6962_requires_not_what_the_log_offered():
    """A path of the wrong length cannot be a valid inclusion path, whatever it recomputes to.
    The requirement is DERIVED here; taking the log's word for it would check nothing."""
    verlangt = _required_path_length(LEAF_INDEX, TREE_SIZE)
    assert verlangt == len(_path_nodes()) == _manifest()["measured_2026_08_31"]["inclusion_path_nodes"]


def test_inclusion_recomputes_to_the_recorded_root():
    leaf = (FIX / "leaf.txt").read_bytes()
    root = _rfc6962_root(leaf, _path_nodes(), LEAF_INDEX, TREE_SIZE)
    assert base64.b64encode(root).decode() == _manifest()["measured_2026_08_31"]["recomputed_root_b64"]


def test_a_flipped_bit_in_the_leaf_changes_the_root():
    """The counter-proof. Without it the recomputation above could be reproducing a constant."""
    leaf = bytearray((FIX / "leaf.txt").read_bytes())
    leaf[10] ^= 0x01
    root = _rfc6962_root(bytes(leaf), _path_nodes(), LEAF_INDEX, TREE_SIZE)
    assert base64.b64encode(root).decode() != _manifest()["measured_2026_08_31"]["recomputed_root_b64"]


# ── (2) the entry is NOT yet witnessed, and that must stay checkable ───────────────────────────

def test_a_witnessed_claim_is_backed_by_a_matching_root():
    """THE LOAD-BEARING ASSERTION, and it MOVED — which is the point.

    Its first form said: as long as no sufficient checkpoint is vendored, the manifest may not claim
    coverage. On 2026-08-31 at 17:5x the witness round completed, the log's checkpoint advanced to
    size 7728, and that assertion went RED — exactly as designed. A gate that only catches overclaim
    lets a fixture go quietly stale; this one demanded completion instead.

    Its second form is the harder one: WITNESSED may be claimed only if the root recomputed from the
    vendored leaf and path is BYTE-IDENTICAL to the root in the vendored signed checkpoint. A state
    word is cheap; a matching root is not."""
    w = _manifest()["witness_coverage"]
    assert w["state"] in ("PENDING", "WITNESSED")
    if w["state"] == "PENDING":
        assert w["checkpoint_size_required"] > w["checkpoint_size_at_submission"]
        return

    zeilen = (FIX / "checkpoint_witnessed.txt").read_text(encoding="utf-8").splitlines()
    groesse, wurzel = int(zeilen[1].strip()), zeilen[2].strip()
    assert groesse >= TREE_SIZE, (
        f"claims WITNESSED but the vendored checkpoint has size {groesse} < {TREE_SIZE}")
    leaf = (FIX / "leaf.txt").read_bytes()
    errechnet = base64.b64encode(_rfc6962_root(leaf, _path_nodes(), LEAF_INDEX, TREE_SIZE)).decode()
    assert errechnet == wurzel, (
        f"recomputed root {errechnet} does not match the signed checkpoint root {wurzel} — a "
        "WITNESSED claim without a matching root is exactly the lie this fixture exists to prevent")
    assert w["witnessed_root_b64"] == wurzel


def test_the_manifest_may_not_claim_a_root_it_did_not_measure():
    """Die Gegenrichtung. Ein Manifest, das eine Wurzel NENNT, muss dieselbe meinen, die in den
    Bytes steht — sonst waere die Angabe Dekoration."""
    w = _manifest()["witness_coverage"]
    if w["state"] != "WITNESSED":
        pytest.skip("noch nicht bezeugt")
    zeilen = (FIX / "checkpoint_witnessed.txt").read_text(encoding="utf-8").splitlines()
    assert w["witnessed_root_b64"] == zeilen[2].strip()


def test_the_submission_time_checkpoint_stays_as_evidence_of_the_earlier_state():
    """Der Checkpoint VOM Einreichungszeitpunkt bleibt liegen, auch nachdem die Zeugenrunde durch
    ist. Er belegt, dass die Deckung NICHT sofort da war — eine Historie, die man nicht loeschen
    darf, weil sonst 'sofort bezeugt' und 'nach einer Runde bezeugt' ununterscheidbar werden."""
    zeilen = (FIX / "checkpoint_at_submit.txt").read_text(encoding="utf-8").splitlines()
    assert int(zeilen[1].strip()) < TREE_SIZE


def test_no_overclaim_block_names_the_next_unproven_step():
    """Der Block muss die naechste NICHT belegte Stufe benennen. Solange nicht bezeugt war, war das
    die Zeugendeckung; jetzt, wo sie belegt ist, ist es der Bitcoin-Anker. Ein No-Overclaim-Block,
    der nach jedem Fortschritt derselbe bleibt, hoert auf, eine Grenze zu sein."""
    m = _manifest()
    assert m["no_overclaim"], "a fixture without a stated limit claims more than it shows"
    verbunden = " ".join(m["no_overclaim"]).lower()
    if m["witness_coverage"]["state"] == "WITNESSED":
        assert "bitcoin" in verbunden, (
            "witnessed is claimed, so the next unproven step is the anchor — and it must be named")
    else:
        assert "witnessed" in verbunden


@pytest.mark.parametrize("datei", ["leaf.txt", "inclusion_path.txt", "checkpoint_at_submit.txt",
                                   "checkpoint_latest.txt", "submit_response.json", "MANIFEST.json",
                                   "checkpoint_witnessed.txt", "proof_bundle.json"])
def test_every_declared_file_exists(datei):
    assert (FIX / datei).is_file(), f"{datei} is declared in the fixture but absent"
