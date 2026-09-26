"""An OTS proof over the cap is refused before the deserializer does any work, on every reader.

WHERE THIS COMES FROM. Deep gate against main 5b53ab3e, finding L2-Z195-OTS-WORK-AMPLIFICATION-01
(P3, jury 3 of 3). The structural budget bounds the base64 string of a proof, not what the
OpenTimestamps deserializer builds from it: every fork creates a Timestamp holding its own copy of the
message. One append of 4000 bytes and forks of about 26 bytes each made a 732 067-byte proof, inside
every budget, peak at 134.4 MiB in `verify_evidence_pack`; with the cap it is refused at 3.3 MiB,
before any deserialization (measured again for this change on 12eb4e0e and on this change, tracemalloc
around the call alone, each figure three times in a fresh process; the gate's own window gave 137 MiB).

WHAT IS PINNED. All four readers (`verify_opentimestamps`, `calendar_uris`,
`ots_upgraded_proof_is_self_contained`, `describe_proof`) and the pack verifier refuse a proof over the
cap with their own verdict, and the library's deserializer is not called for it. A proof of exactly the
cap's length still reaches the library, so the cap cannot be read as refusing more than it says, and
every OTS proof this repository carries fits under it with room to spare. Every reader deserializes a
proof once, and only through the one helper. The binding is read by membership in the statuses that
say it held, so a refusal added later cannot read as bound (`anchor upgrade`, the rootcommit anchors).
"""
from __future__ import annotations

import base64
import hashlib
import pathlib
import unittest
from unittest import mock

try:
    import opentimestamps  # noqa: F401
    _HAS_OTS = True
except ImportError:
    _HAS_OTS = False

REPO = pathlib.Path(__file__).resolve().parents[1]
_ROOT = hashlib.sha256(b"canonical").digest()
_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"


def _amplifying_proof(forks: int, *, bitcoin: bool = False) -> bytes:
    """The gate's construction: one 4000-byte append, then `forks` branches of about 26 bytes, each
    ending in a pending attestation, or with `bitcoin` in a Bitcoin block-header attestation (an
    UPGRADED proof, so a reader that bypasses the cap answers True where the cap answers False)."""
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    from opentimestamps.core.op import OpAppend, OpSHA256
    from opentimestamps.core.serialize import BytesSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    ts = Timestamp(_ROOT)
    big = ts.ops.add(OpAppend(b"\x00" * 4000))
    for i in range(forks):
        att = BitcoinBlockHeaderAttestation(800_000 + i) if bitcoin else PendingAttestation("https://a")
        big.ops.add(OpAppend(i.to_bytes(3, "big"))).attestations.add(att)
    ctx = BytesSerializationContext()
    DetachedTimestampFile(OpSHA256(), ts).serialize(ctx)
    return ctx.getbytes()


@unittest.skipUnless(_HAS_OTS, "NOT MEASURABLE: needs proofbundle[anchors] (opentimestamps); did NOT run")
class TheCap(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from proofbundle import anchors_ots
        cls.cap = anchors_ots._MAX_OTS_PROOF_BYTES
        cls.over = _amplifying_proof(2400)
        cls.under = _amplifying_proof(2360)
        cls.over_upgraded = _amplifying_proof(3400, bitcoin=True)
        cls.under_upgraded = _amplifying_proof(3100, bitcoin=True)

    def test_precondition_the_proofs_sit_on_either_side_of_the_cap(self):
        self.assertGreater(len(self.over), self.cap)
        self.assertLess(len(self.under), self.cap)
        self.assertGreater(len(self.over_upgraded), self.cap)
        self.assertLess(len(self.under_upgraded), self.cap)
        from proofbundle.evidence_pack import ots_upgraded_proof_is_self_contained
        self.assertIs(ots_upgraded_proof_is_self_contained(self.under_upgraded), True)

    def test_every_reader_refuses_a_proof_over_the_cap(self):
        from proofbundle.anchors_ots import calendar_uris, verify_opentimestamps
        from proofbundle.evidence_pack import (describe_proof, ots_upgraded_proof_is_self_contained,
                                               verify_evidence_pack)
        r = verify_opentimestamps(self.over, _ROOT, frozen={})
        self.assertEqual((r["ok"], r["status"]), (False, "over_budget"))
        self.assertIn("before deserializing", r["detail"])
        pack = {"proof": base64.b64encode(self.over).decode(), "canonicalRoot": base64.b64encode(_ROOT).decode()}
        self.assertEqual(verify_evidence_pack(pack)["status"], "over_budget")
        self.assertEqual(calendar_uris(self.over), [])
        self.assertIs(ots_upgraded_proof_is_self_contained(self.over_upgraded), False)
        self.assertEqual(describe_proof(self.over)["state"], "over_budget")

    def test_the_deserializer_is_not_called_over_the_cap(self):
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from proofbundle.anchors_ots import verify_opentimestamps
        with mock.patch.object(DetachedTimestampFile, "deserialize",
                               wraps=DetachedTimestampFile.deserialize) as seen:
            verify_opentimestamps(self.over, _ROOT, frozen={})
            self.assertEqual(seen.call_count, 0)
            verify_opentimestamps(self.under, _ROOT, frozen={})
            self.assertEqual(seen.call_count, 1)

    def test_every_reader_deserializes_a_proof_once(self):
        """Gate on the cap, lens A (229A-01): `describe_proof` deserialized the same proof twice, both
        copies alive at once, so a proof just under the cap cost twice the peak the cap was sized for.
        `build_evidence_pack` did the same one after the other. Every reader that takes a proof now
        deserializes it once per call."""
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from proofbundle.anchors_ots import calendar_uris, verify_opentimestamps
        from proofbundle.evidence_pack import (build_evidence_pack, describe_proof,
                                               ots_upgraded_proof_is_self_contained)
        readers = {
            "verify_opentimestamps": lambda p: verify_opentimestamps(p, _ROOT, frozen={}),
            "calendar_uris": calendar_uris,
            "ots_upgraded_proof_is_self_contained": ots_upgraded_proof_is_self_contained,
            "describe_proof": describe_proof,
            "build_evidence_pack": lambda p: build_evidence_pack(_ROOT, p),
        }
        for name, read in readers.items():
            with self.subTest(reader=name), mock.patch.object(
                    DetachedTimestampFile, "deserialize", wraps=DetachedTimestampFile.deserialize) as seen:
                read(self.under)
                self.assertEqual(seen.call_count, 1, f"{name} deserialized the proof {seen.call_count} times")
        pack = build_evidence_pack(_ROOT, self.under)
        self.assertEqual((pack["selfContained"], pack["provenCalendars"]), (False, ["https://a"]))
        self.assertIs(build_evidence_pack(_ROOT, self.under_upgraded)["selfContained"], True)

    def test_a_proof_under_the_cap_still_reads(self):
        from proofbundle.anchors_ots import calendar_uris, verify_opentimestamps
        from proofbundle.evidence_pack import describe_proof
        self.assertEqual(verify_opentimestamps(self.under, _ROOT, frozen={})["status"], "pending")
        self.assertEqual(calendar_uris(self.under), ["https://a"])
        self.assertEqual(describe_proof(self.under)["state"], "pending")

    def test_the_cap_refuses_a_proof_over_it_not_one_of_its_length(self):
        """Gate on the cap, lens B, 229B-02: no case sat on the boundary, so `>=` in place of `>` left every
        case green and refused a 65536-byte proof as "over the 65536-byte cap". A proof of exactly the cap's
        length reaches the library (which refuses these bytes for its own reason); one byte more does not."""
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from proofbundle.anchors_ots import verify_opentimestamps
        at, over = _MAGIC.ljust(self.cap, b"\x00"), _MAGIC.ljust(self.cap + 1, b"\x00")
        with mock.patch.object(DetachedTimestampFile, "deserialize",
                               wraps=DetachedTimestampFile.deserialize) as seen:
            r_at = verify_opentimestamps(at, _ROOT, frozen={})
            self.assertEqual(seen.call_count, 1)
            r_over = verify_opentimestamps(over, _ROOT, frozen={})
            self.assertEqual(seen.call_count, 1)
        self.assertEqual(r_at["status"], "malformed")
        self.assertNotIn("cap", r_at["detail"])
        self.assertEqual(r_over["status"], "over_budget")
        self.assertIn(f"is {self.cap + 1} bytes, over the {self.cap}-byte cap", r_over["detail"])

    def test_anchor_upgrade_refuses_an_over_cap_proof_without_a_false_remedy(self):
        """Gate on the cap, lens B, 229B-01: `anchor upgrade` listed the refusals it knew, `over_budget` was
        not among them, and an over-cap proof fell through to the pending branch: exit 3 and "run `ots
        upgrade`", which can never help a proof nobody read. It is a refused input now, exit 2, named."""
        import contextlib
        import io
        import os
        import tempfile
        from proofbundle.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            runs = {}
            for label, proof in (("over", self.over), ("under", self.under)):
                path, out = os.path.join(tmp, f"{label}.ots"), os.path.join(tmp, f"{label}.json")
                with open(path, "wb") as handle:
                    handle.write(proof)
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    rc = main(["anchor", "upgrade", "--proof", path, "--canonical-root-hex", _ROOT.hex(),
                               "--out", out])
                runs[label] = (rc, stdout.getvalue(), stderr.getvalue(), os.path.exists(out))
        rc, out, err, wrote = runs["over"]
        self.assertEqual(rc, 2, out + err)
        self.assertIn(f"over the {self.cap}-byte cap", err)
        self.assertNotIn("ots upgrade", out + err)
        self.assertIs(wrote, False)
        # the counter-direction: a pending proof under the cap keeps its exit 3 and its remedy
        rc, out, err, wrote = runs["under"]
        self.assertEqual(rc, 3, out + err)
        self.assertIn("ots upgrade", out)
        self.assertIs(wrote, False)


_FIXDIR = REPO / "tests" / "fixtures" / "anchors" / "tlog_bitcoin_anchor" / "rootcommit"


def _rootcommit_with_proof(vector: str, ots: bytes, *, v2sig: bool) -> str:
    """A genuine rootcommit vector whose one anchor line is replaced by one that carries `ots`."""
    from proofbundle import anchors_rootcommit as rc
    wallet = b"0xdaE76a3C848CafD453dB5EBF8cEb0DbBA7610273"
    if v2sig:
        ident, opaque = rc.ID_V2SIG.encode(), b"\x02" + bytes([len(wallet)]) + wallet + b"\x41" + b"\x00" * 65 + ots
    else:
        ident, opaque = rc.ID_V1.encode(), b"\x01" + bytes([len(wallet)]) + wallet + ots
    payload = rc.expected_key_id(ident) + bytes([rc.SIG_TYPE, len(ident)]) + ident + opaque
    prefix = f"— {rc.KEY_NAME} "
    body, sigs = (_FIXDIR / vector).read_text().split("\n\n", 1)
    rest = [line for line in sigs.splitlines() if not line.startswith(prefix)]
    return body + "\n\n" + "\n".join([prefix + base64.b64encode(payload).decode()] + rest) + "\n"


class TheBindingIsReadByMembership(unittest.TestCase):
    """The class behind 229B-01, found by sweeping its neighbours: three callers decided "bound" by the
    ABSENCE of a refusal they had listed ("unbound", "malformed", "no_lib"). The cap added a fourth refusal,
    and two of the three callers, in `anchors_rootcommit`, then read a proof nobody had deserialized as
    bound: measured on fd1a5708, a rootcommit/v1 anchor whose proof commits a different digest, padded to
    66 467 bytes, came out binding=True, reject=False; on 12eb4e0e, without the cap, the same anchor is
    unbound. The binding is now read by membership in `anchors_ots._BINDING_HELD`, deny by default."""

    def test_every_status_the_verifier_returns_is_classified_exactly_once(self):
        import ast
        from proofbundle.anchors_ots import _BINDING_HELD, _BINDING_NOT_HELD
        tree = ast.parse((REPO / "src" / "proofbundle" / "anchors_ots.py").read_text())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "verify_opentimestamps")
        returned = {v.value for d in ast.walk(fn) if isinstance(d, ast.Dict)
                    for k, v in zip(d.keys, d.values)
                    if isinstance(k, ast.Constant) and k.value == "status" and isinstance(v, ast.Constant)}
        self.assertGreaterEqual(len(returned), 12, f"the sweep found too little to hold anything: {returned}")
        self.assertEqual(returned, _BINDING_HELD | _BINDING_NOT_HELD)
        self.assertEqual(_BINDING_HELD & _BINDING_NOT_HELD, frozenset())

    def test_no_caller_decides_the_binding_by_a_list_of_refusals(self):
        import ast
        refusals = {"unbound", "over_budget", "no_lib"}
        found = []
        for path in sorted((REPO / "src" / "proofbundle").rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, ast.Compare):
                    continue
                for op, right in zip(node.ops, node.comparators):
                    if (isinstance(op, (ast.In, ast.NotIn)) and isinstance(right, (ast.Tuple, ast.List, ast.Set))
                            and any(isinstance(e, ast.Constant) and e.value in refusals for e in right.elts)):
                        found.append(f"{path.relative_to(REPO).as_posix()}:{node.lineno}")
        self.assertEqual(found, [], "read the binding with anchors_ots.ots_binding_held, not a list of refusals")

    def test_the_helper_denies_what_it_does_not_know(self):
        from proofbundle.anchors_ots import ots_binding_held
        self.assertIs(ots_binding_held({"status": "pending"}), True)
        for verdict in ({"status": "over_budget"}, {"status": "a status added later"}, {}, None, "pending"):
            with self.subTest(verdict=verdict):
                self.assertIs(ots_binding_held(verdict), False)

    @unittest.skipUnless(_HAS_OTS, "NOT MEASURABLE: needs proofbundle[anchors] (opentimestamps); did NOT run")
    def test_a_rootcommit_anchor_whose_proof_is_over_the_cap_is_not_bound(self):
        from opentimestamps.core.notary import PendingAttestation
        from opentimestamps.core.op import OpAppend, OpSHA256
        from opentimestamps.core.serialize import BytesSerializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
        from proofbundle import anchors_ots, anchors_rootcommit as rc
        ts = Timestamp(b"\x11" * 32)            # commits a digest that is NOT the anchor's commitment
        big = ts.ops.add(OpAppend(b"\x00" * 4000))
        for i in range(2400):
            big.ops.add(OpAppend(i.to_bytes(3, "big"))).attestations.add(PendingAttestation("https://a"))
        ctx = BytesSerializationContext()
        DetachedTimestampFile(OpSHA256(), ts).serialize(ctx)
        ots = ctx.getbytes()
        self.assertGreater(len(ots), anchors_ots._MAX_OTS_PROOF_BYTES)
        for label, verify, vector, v2sig in (
                ("v1", rc.verify_rootcommit_v1, "vectors/rootcommit-01-valid.txt", False),
                ("v2-sig", rc.verify_rootcommit_v2sig, "vectors_sig/v2sig-01-valid.txt", True)):
            text = _rootcommit_with_proof(vector, ots, v2sig=v2sig)
            with self.subTest(anchor=label):
                r = verify(text)
                self.assertEqual((r["status"], r["binding"], r["reject"]), ("over_budget", False, True))
                # precondition: without the cap the same proof is read, and it does not bind
                with mock.patch.object(anchors_ots, "_MAX_OTS_PROOF_BYTES", 10 ** 9):
                    r = verify(text)
                self.assertEqual((r["status"], r["binding"], r["reject"]), ("unbound", False, True))


class TheLibraryIsReachedThroughOneHelper(unittest.TestCase):
    """Gate on the cap, lens B, 229B-03: "one way to deserialize" was written down, not held; a new reader
    calling the library directly left every case green. Every reference to a deserialization context and
    every `.deserialize` on an OTS timestamp class under src/proofbundle sits in `_deserialize_detached`."""

    def test_every_deserialization_site_is_the_helper(self):
        import ast
        sites = []

        def visit(node, path, where):
            for child in ast.iter_child_nodes(node):
                inner = f"{where}.{child.name}" if isinstance(
                    child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else where
                named = (getattr(child, "id", None) or getattr(child, "attr", None)
                         or getattr(child, "name", None) or "")
                is_context = isinstance(named, str) and "DeserializationContext" in named
                is_call = (isinstance(child, ast.Attribute) and child.attr == "deserialize"
                           and isinstance(child.value, ast.Name)
                           and child.value.id in ("DetachedTimestampFile", "Timestamp"))
                if is_context or is_call:
                    sites.append((path, inner, "deserialize" if is_call else "context"))
                visit(child, path, inner)

        for path in sorted((REPO / "src" / "proofbundle").rglob("*.py")):
            rel = path.relative_to(REPO / "src").with_suffix("").as_posix().replace("/", ".")
            visit(ast.parse(path.read_text()), rel, rel)
        self.assertEqual({(p, w) for p, w, _ in sites},
                         {("proofbundle.anchors_ots", "proofbundle.anchors_ots._deserialize_detached")}, sites)
        self.assertEqual(sum(1 for *_, kind in sites if kind == "deserialize"), 1, sites)


class TheCapFitsWhatThisRepositoryCarries(unittest.TestCase):

    def test_every_ots_proof_in_the_tree_fits_with_room_to_spare(self):
        from proofbundle.anchors_ots import _MAX_OTS_PROOF_BYTES
        sizes = []
        for p in REPO.rglob("*.ots"):
            if ".git" in p.parts:
                continue
            data = p.read_bytes()
            if data.startswith(_MAGIC):
                sizes.append((len(data), p.relative_to(REPO).as_posix()))
        self.assertNotEqual(sizes, [], "no OTS proof found; this case would measure nothing")
        largest = max(sizes)
        self.assertLess(largest[0] * 10, _MAX_OTS_PROOF_BYTES,
                        f"the largest proof in the tree, {largest}, is within a factor ten of the cap")


if __name__ == "__main__":
    unittest.main()
