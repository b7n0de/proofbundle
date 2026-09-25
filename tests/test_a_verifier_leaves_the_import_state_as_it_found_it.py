"""A verifier judges a tree; it does not install it into the process that asked.

THE CLASS (measured 2026-09-25 on main 166aec47). Both pre-tag verifiers put the JUDGED tree's `src/`
in front of `sys.path` so that `verify_receipt` can import `proofbundle.signature`, and both set
`sys.pycache_prefix` / `sys.dont_write_bytecode` so that no bytecode next to the judged sources is
read. Neither undid it. In the same process a later plain `import pre_tag_receipt_lib` then resolved
to whatever the judged tree carried under that name: in tests/test_pretag_gate_state_typed_l5_g6_01.py
the forged library one case plants, which failed eight other cases with `cannot import name
'canonical_bytes'` under PYTHONHASHSEED 5 and 7, the orders in which they happened to run.

The gate itself was safe, it loads its library by path. Everyone who ran after it in the same process
was not. That is the by-path fix of 2026-09-17 left open one step further out.

THE PROPERTY, per verifier: after a call over a tree that carries its own `src/pre_tag_receipt_lib.py`,
`sys.path`, `sys.pycache_prefix` and `sys.dont_write_bytecode` are what they were, and a fresh import
by name finds the real library. `scripts/pre_tag_receipt.py` (the producer) is a neighbour on purpose
NOT held to this: it sets the bytecode switches for its whole process so that the audit program it
starts inherits them, and restoring them would break that.
"""
from __future__ import annotations

import importlib
import json
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
_SCRIPTS = str(REPO / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def _tree_with_a_forged_library() -> pathlib.Path:
    """A committed git tree whose own `src/` carries a module named like the receipt library."""
    d = pathlib.Path(tempfile.mkdtemp(prefix="importzustand_"))
    (d / "pyproject.toml").write_text('[project]\nversion = "6.0.0"\n', encoding="utf-8")
    (d / "src").mkdir()
    (d / "src" / "pre_tag_receipt_lib.py").write_text("RECEIPT_SCHEMA = 'forged'\n", encoding="utf-8")
    for args in (["init", "-q"], ["add", "-A"],
                 ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "basis"]):
        subprocess.run(["git", "-C", str(d), *args], check=True, capture_output=True, timeout=60)
    return d


def _zustand():
    return list(sys.path), sys.pycache_prefix, sys.dont_write_bytecode


class TheImportStateIsRestored(unittest.TestCase):

    def _the_real_library_is_found_by_name(self, d: pathlib.Path) -> None:
        alt = sys.modules.pop("pre_tag_receipt_lib", None)
        try:
            lib = importlib.import_module("pre_tag_receipt_lib")
            self.assertTrue(hasattr(lib, "canonical_bytes"), lib.__file__)
            self.assertNotIn(str(d), str(lib.__file__))
        finally:
            sys.modules.pop("pre_tag_receipt_lib", None)
            if alt is not None:
                sys.modules["pre_tag_receipt_lib"] = alt

    def test_the_release_gate(self):
        gate = _load("_importzustand_gate", "scripts/pre_tag_audit_gate.py")
        d = _tree_with_a_forged_library()
        vorher = _zustand()
        r = gate.evaluate(d, "6.0.0")
        self.assertFalse(r["ok"], r)
        self.assertEqual(_zustand(), vorher)
        self._the_real_library_is_found_by_name(d)

    def test_the_readers_verifier(self):
        ver = _load("_importzustand_verify", "scripts/verify_pre_tag_receipt.py")
        d = _tree_with_a_forged_library()
        kopf = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True, timeout=30).stdout.strip()
        vorher = _zustand()
        r = ver.measure(d, kopf, "6.0.0")
        # PRECONDITION: the measurement got past the checkout checks, to the point where the judged
        # src is put on the path. Refused earlier, it would never have touched the import state, and
        # the assertion below would hold for a reason that has nothing to do with the restore.
        self.assertEqual(r["verdict"], "NOT_VERIFIED", r)
        self.assertEqual(_zustand(), vorher)
        self._the_real_library_is_found_by_name(d)

    def test_a_second_call_runs_with_the_bytecode_protection_too(self):
        """Restored after each call, the protection must also be SET on each call; set once per
        process, a second call would run without it. Measured inside the call, at a function each
        verifier reaches only after its setup."""
        for rel, name, einstieg in (("scripts/pre_tag_audit_gate.py", "_iz_gate2", "_gate_tree_digest"),
                                    ("scripts/verify_pre_tag_receipt.py", "_iz_ver2", "_version_token")):
            mod = _load(name, rel)
            gesehen = []
            echt = getattr(mod, einstieg)

            def spion(*a, _echt=echt, **kw):
                gesehen.append((sys.pycache_prefix, sys.dont_write_bytecode))
                return _echt(*a, **kw)

            setattr(mod, einstieg, spion)
            d = _tree_with_a_forged_library()
            kopf = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], capture_output=True,
                                  text=True, check=True, timeout=30).stdout.strip()
            for _ in range(2):
                if rel.endswith("pre_tag_audit_gate.py"):
                    mod.evaluate(d, "6.0.0")
                else:
                    mod.measure(d, kopf, "6.0.0")
            with self.subTest(verifier=rel):
                self.assertEqual(len(gesehen), 2, gesehen)
                for praefix, kein_schreiben in gesehen:
                    self.assertIsNotNone(praefix)
                    self.assertEqual(praefix, mod._CACHE_DIR)
                    self.assertTrue(kein_schreiben)


_VERIFIER = (("scripts/pre_tag_audit_gate.py", "_iz_mod_gate"),
             ("scripts/verify_pre_tag_receipt.py", "_iz_mod_ver"))


class TheModulesItLoadedFromTheJudgedTreeLeave(unittest.TestCase):
    """Codex on PR 274, measured in a fresh interpreter: after `measure()` returned, `proofbundle` and
    `proofbundle._wire_b64` stayed in `sys.modules`, loaded from the judged checkout. The path was
    restored and the modules were not; import state is the path, the switches AND the module cache."""

    def test_a_module_from_the_judged_path_leaves_and_one_from_before_stays(self):
        import uuid
        for rel, name in _VERIFIER:
            mod = _load(name, rel)
            paket = f"iz_fremdpaket_{uuid.uuid4().hex[:8]}"
            src = pathlib.Path(tempfile.mkdtemp(prefix="iz_src_"))
            (src / paket).mkdir()
            (src / paket / "__init__.py").write_text("", encoding="utf-8")
            (src / paket / "teil.py").write_text("X = 1\n", encoding="utf-8")
            # PRECONDITION: a standard-library module this process has not loaded yet, so that the
            # control below really is a first load during the call, from a path that was there before.
            std = next(m for m in ("colorsys", "sndhdr", "tabnanny", "netrc", "mailcap", "xdrlib", "nntplib")
                       if m not in sys.modules and importlib.util.find_spec(m) is not None)
            with mod._importzustand():
                sys.path.insert(0, str(src))
                importlib.import_module(f"{paket}.teil")
                importlib.import_module(std)
                self.assertIn(paket, sys.modules)
            with self.subTest(verifier=rel):
                self.assertNotIn(paket, sys.modules)
                self.assertNotIn(f"{paket}.teil", sys.modules)
                self.assertIn(std, sys.modules, "a module from a path that was there before must stay")
                self.assertNotIn(str(src), sys.path)

    def test_a_measurement_in_a_fresh_interpreter_leaves_no_module_of_the_judged_tree(self):
        """End to end, as measured: a fresh interpreter, a committed tree whose own `src/proofbundle`
        is loaded by the receipt check. A marker file proves it WAS loaded; afterwards no module whose
        file lies in the tree may remain."""
        d = pathlib.Path(tempfile.mkdtemp(prefix="iz_e2e_"))
        marker = d.parent / f"{d.name}.geladen"
        (d / "pyproject.toml").write_text('[project]\nversion = "6.0.0"\n', encoding="utf-8")
        pb = d / "src" / "proofbundle"
        pb.mkdir(parents=True)
        (pb / "__init__.py").write_text(
            f"open({str(marker)!r}, 'a', encoding='utf-8').write('x')\n", encoding="utf-8")
        (pb / "_wire_b64.py").write_text("def decode_b64(s):\n    return b''\n", encoding="utf-8")
        (pb / "signature.py").write_text("def verify_ed25519(*a, **k):\n    return False\n", encoding="utf-8")
        # The reader's case: the scripts run from the clone they judge. `sign_readiness_artifact.py`
        # puts ITS tree's `src/` first on the path, so the scripts must live in the judged tree for the
        # judged `proofbundle` to be the one that loads.
        (d / "scripts").mkdir()
        for name in ("verify_pre_tag_receipt.py", "pre_tag_receipt_lib.py", "pre_tag_audit_gate.py",
                     "sign_readiness_artifact.py"):
            (d / "scripts" / name).write_bytes((REPO / "scripts" / name).read_bytes())
        (d / "audit_artifacts" / "600").mkdir(parents=True)
        (d / "audit_artifacts" / "600" / "receipt.json").write_text(
            '{"schema": "not-a-receipt-we-know", "signer_pubkey": "AA=="}\n', encoding="utf-8")
        for args in (["init", "-q"], ["add", "-A"],
                     ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "basis"]):
            subprocess.run(["git", "-C", str(d), *args], check=True, capture_output=True, timeout=60)
        kopf = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True, timeout=30).stdout.strip()
        programm = (
            "import json, pathlib, sys\n"
            f"sys.path.insert(0, {str(d / 'scripts')!r})\n"
            "import verify_pre_tag_receipt as v\n"
            f"d = pathlib.Path({str(d)!r})\n"
            "vorher = set(sys.modules)\n"
            f"r = v.measure(d, {kopf!r}, '6.0.0')\n"
            "rest = sorted(n for n, m in list(sys.modules.items()) if n not in vorher\n"
            "              and str(getattr(m, '__file__', '') or '').startswith(str(d)))\n"
            "print(json.dumps({'verdict': r['verdict'], 'rest': rest}))\n")
        # `-B`: importing the script must not write `__pycache__` into the judged `scripts/`, which the
        # verifier would rightly refuse as an untracked file.
        out = subprocess.run([sys.executable, "-B", "-c", programm], capture_output=True, text=True,
                             timeout=120,
                             cwd=str(d.parent), env={"PATH": "/usr/bin:/bin", "HOME": str(d.parent)})
        self.assertEqual(out.returncode, 0, out.stderr[-800:])
        ergebnis = json.loads(out.stdout.strip().splitlines()[-1])
        # PRECONDITION: the judged tree's package was really loaded during the call.
        self.assertTrue(marker.is_file(), f"the judged src was never imported: {ergebnis}")
        self.assertEqual(ergebnis["verdict"], "NOT_VERIFIED", ergebnis)
        self.assertEqual(ergebnis["rest"], [], ergebnis)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
