"""Catch-proofs for scripts/markovian_submit.py — register entry N23.

The recomputation is an INDEPENDENT oracle: forty lines of RFC 6962 written from the
spec, not a call into this project's own anchor code. A proof checked only by the
implementation that produced it is checked by nobody.

So these cases attack the oracle, not the fixture. Each one breaks the proof in exactly
one way and insists the walk says so.
"""
import base64
import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "markovian_submit.py"
FIXTURE = REPO / "tests" / "fixtures" / "anchors" / "markovian_log" / "submit_7727"

spec = importlib.util.spec_from_file_location("markovian_submit_ut", SCRIPT)
ms = importlib.util.module_from_spec(spec)
sys.modules["markovian_submit_ut"] = ms
spec.loader.exec_module(ms)


@unittest.skipUnless(FIXTURE.is_dir(), "submit fixture not in this tree")
class TestInklusionspfad(unittest.TestCase):
    def setUp(self):
        self.resp = ms._json_prefix(FIXTURE / "submit_response.json")
        self.leaf = (FIXTURE / "leaf.txt").read_bytes().rstrip(b"\n")
        self.pfad = ms._path_hashes(FIXTURE / "inclusion_path.txt")
        _, self.size, self.root = ms._checkpoint(FIXTURE / "checkpoint_witnessed.txt")
        self.index = self.resp["leaf_index"]

    def _wurzel(self, leaf=None, index=None, size=None, pfad=None):
        return ms.root_from_inclusion_path(
            self.leaf if leaf is None else leaf,
            self.index if index is None else index,
            self.size if size is None else size,
            self.pfad if pfad is None else pfad,
        )

    def test_die_kontrolle_trifft_die_bezeugte_wurzel(self):
        """Without this, every red result below could mean 'everything is red'."""
        self.assertEqual(self._wurzel(), self.root)

    def test_die_zahlen_stimmen_mit_denen_der_fixture_von_2026_08(self):
        """Agreeing with a figure someone else wrote is worth more than agreeing with us."""
        soll = json.loads((FIXTURE / "MANIFEST.json").read_text())["measured_2026_08_31"]
        self.assertEqual(base64.b64encode(ms.leaf_hash(self.leaf)).decode(),
                         soll["leaf_hash_b64"])
        self.assertEqual(base64.b64encode(self._wurzel()).decode(),
                         soll["recomputed_root_b64"])
        self.assertEqual(len(self.pfad), soll["inclusion_path_nodes"])

    def test_EIN_GEKIPPTES_BIT_IM_BLATT_aendert_die_wurzel(self):
        roh = bytearray(self.leaf)
        roh[10] ^= 0x01
        self.assertNotEqual(self._wurzel(leaf=bytes(roh)), self.root)

    def test_EIN_GEKIPPTES_BIT_IM_PFAD_aendert_die_wurzel(self):
        p = list(self.pfad)
        b = bytearray(p[0])
        b[0] ^= 0x01
        p[0] = bytes(b)
        self.assertNotEqual(self._wurzel(pfad=p), self.root)

    def test_ein_ZU_KURZER_pfad_faellt_am_WALK_nicht_an_einer_formel(self):
        """The length is bound by the walk. sn != 0 at the end means: not proven."""
        with self.assertRaises(ValueError) as ctx:
            self._wurzel(pfad=self.pfad[:-1])
        self.assertIn("shorter", str(ctx.exception))

    def test_ein_ZU_LANGER_pfad_faellt_ebenfalls_am_WALK(self):
        with self.assertRaises(ValueError) as ctx:
            self._wurzel(pfad=self.pfad + [b"\x00" * 32])
        self.assertIn("longer", str(ctx.exception))

    def test_VERTAUSCHTE_pfadknoten_aendern_die_wurzel(self):
        """Order carries meaning: a set of siblings is not a path."""
        p = list(self.pfad)
        p[0], p[1] = p[1], p[0]
        self.assertNotEqual(self._wurzel(pfad=p), self.root)

    def test_ein_index_ausserhalb_des_baums_wird_abgewiesen(self):
        with self.assertRaises(ValueError):
            self._wurzel(index=self.size)

    def test_die_praefixe_0x00_und_0x01_sind_verschieden_und_das_ist_der_schutz(self):
        """RFC 6962's domain separation: without it a leaf could pose as an interior node."""
        h = hashlib.sha256(b"x").digest()
        self.assertNotEqual(ms.leaf_hash(b"x" * 64), ms.node_hash(h, h))

    def test_die_ganze_nachrechnung_meldet_OK_und_rc_0(self):
        self.assertEqual(ms.recompute(FIXTURE), 0)

    def test_eine_VERFAELSCHTE_bezeugte_wurzel_ergibt_FAIL_und_rc_1(self):
        """The end-to-end direction: the walk is right, the checkpoint lies."""
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp) / "fixture"
            shutil.copytree(FIXTURE, z)
            cp = z / "checkpoint_witnessed.txt"
            zeilen = cp.read_text(encoding="utf-8").split("\n")
            roh = bytearray(base64.b64decode(zeilen[2]))
            roh[0] ^= 0xFF
            zeilen[2] = base64.b64encode(bytes(roh)).decode()
            cp.write_text("\n".join(zeilen), encoding="utf-8")
            self.assertEqual(ms.recompute(z), 1)


class TestKeineAussenwirkung(unittest.TestCase):
    """A submission is permanent and outward-facing; the owner gate must be structural."""

    @staticmethod
    def _wurzelmodule(quelle: str) -> set:
        """Top-level module names this source imports, via AST — not via grep.

        A regex over `import` lines misses an indented import inside a function, which is
        exactly where someone would put the one that matters.
        """
        import ast
        module = set()
        for n in ast.walk(ast.parse(quelle)):
            if isinstance(n, ast.Import):
                module.update(a.name.split(".")[0] for a in n.names)
            elif isinstance(n, ast.ImportFrom) and n.module:
                module.add(n.module.split(".")[0])
        return module

    VERBOTEN = ("socket", "http", "requests", "urllib", "httpx")

    def test_keine_einzige_netzfunktion_im_quelltext(self):
        module = self._wurzelmodule(SCRIPT.read_text(encoding="utf-8"))
        for verboten in self.VERBOTEN:
            self.assertNotIn(verboten, module,
                             f"{verboten} is importable here — the owner gate is then a promise")

    def test_META_der_netz_test_faengt_einen_eingepflanzten_import(self):
        """Without this, the case above could be green because it inspects nothing.

        An absence check that has never seen a presence is indistinguishable from a
        check that always passes.
        """
        gepflanzt = "import urllib.request\ndef f():\n    from socket import socket\n"
        module = self._wurzelmodule(gepflanzt)
        self.assertIn("urllib", module)
        self.assertIn("socket", module, "an import nested in a function must be seen too")

    def test_der_trockenlauf_sendet_nichts_und_sagt_das_auch(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as tmp:
            q = Path(tmp) / "r.json"
            q.write_text('{"a":1}')
            aus = io.StringIO()
            with contextlib.redirect_stdout(aus):
                rc = ms.dryrun(q, "example.org/log")
            self.assertEqual(rc, 0)
            text = aus.getvalue()
            self.assertIn("DRY RUN", text)
            self.assertIn("OWNER GATE", text)
            self.assertIn(hashlib.sha256(b'{"a":1}').hexdigest(), text,
                          "the dry run must name the exact bytes it would send")


if __name__ == "__main__":
    unittest.main(verbosity=2)
