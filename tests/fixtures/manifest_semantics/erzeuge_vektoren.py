"""Build the vectors for tests/test_a_promised_path_that_is_absent_is_a_packaging_failure.py from setuptools.

Run with an interpreter whose setuptools can build this project (pyproject.toml requires >= 68):

    python3 tests/fixtures/manifest_semantics/erzeuge_vektoren.py

For each template below it writes a throwaway project (pyproject.toml, one package, the candidate files,
the template as MANIFEST.in), calls `setuptools.build_meta.build_sdist` offline, and records which
candidates the real sdist carries. Nothing here is read by the test at run time except vectors.json.

WHAT SETUPTOOLS SHIPS WITHOUT A TEMPLATE LINE is measured too (gate run 2, lens 227-A, 227-2-01): the
modules of every package its package discovery finds and the package data the project declares go into
the sdist through `build_py`, whatever MANIFEST.in says. So the candidates include files under `src/`,
each case records the pyproject.toml it was built with, and three cases vary the discovery (the plain
`where = ["src"]` of this repository, an `exclude`, and `namespaces = false`).

A DIRECTORY WITHOUT `__init__.py` carries declared package data too (`src/ohneinit/`, gate run 3 on
this change): setuptools builds it as a namespace package and ships the data, and with
`namespaces = false` it builds nothing there and ships nothing. The reader must say the same.

ONLY POSITIVE LINES. `tests/conftest.py::_manifest_verspricht` deliberately does not let a negative line
withdraw a promise (that is how an accidental `exclude` is caught), so a template with `exclude` or
`prune` would measure a difference that is the design. The vectors pin the reading of the positive lines
and of what setuptools adds by itself.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile

HIER = pathlib.Path(__file__).resolve().parent

KANDIDATEN = [
    "MANIFEST.in", "pyproject.toml", "README.md", "LICENSE",
    "examples/a.json", "examples/.hidden.json", "examples/sub/b.json",
    "docs/top.md", "docs/adr/nested.md", "docs/NAMED.md",
    "receipts/agent_review/r1.receipt.json", "receipts/agent_review/sub/r2.receipt.json",
    "receipts/agent_review/d.txt", "receipts/other/e.receipt.json",
    "data/a.txt", "data/b.txt", "data/-.txt", "data/d.txt",
    "the/planet.txt", "noise", "weird#name.txt", "ships",
    "src/vektorpaket/__init__.py", "src/vektorpaket/mod.py", "src/vektorpaket/py.typed",
    "src/vektorpaket/notes.md", "src/vektorpaket/data/a.json", "src/vektorpaket/data/b.txt",
    "src/vektorpaket/sub/deep.py", "src/vektorpaket/sub/deep.json", "src/loose.py", "src/dotted.dir/x.py",
    "src/ohneinit/data.json",
]

#: The package configuration every case is built with, unless the case names another one.
PAKETE = ('[tool.setuptools.packages.find]\nwhere = ["src"]\n\n'
          '[tool.setuptools.package-data]\nvektorpaket = ["py.typed", "data/*.json"]\n'
          'ohneinit = ["data.json"]\n')
PAKETE_VARIANTEN = {
    "find_excludes_a_subpackage": ('[tool.setuptools.packages.find]\nwhere = ["src"]\n'
                                   'exclude = ["vektorpaket.sub*"]\n\n'
                                   '[tool.setuptools.package-data]\nvektorpaket = ["py.typed", "data/*.json"]\n'
                                   'ohneinit = ["data.json"]\n'),
    "find_without_namespaces": ('[tool.setuptools.packages.find]\nwhere = ["src"]\nnamespaces = false\n\n'
                                '[tool.setuptools.package-data]\nvektorpaket = ["py.typed", "data/*.json"]\n'
                                'ohneinit = ["data.json"]\n'),
}

TEMPLATES = {
    "continuation": "recursive-include receipts/agent_review \\\n    *.receipt.json\n",
    "comment_inside_continuation": "recursive-include receipts \\\n# a comment line\n    *.json\n",
    "inline_comments": "graft examples   # ships the fixtures\ninclude docs/top.md  # comment noise\n",
    "escaped_hash": "include weird\\#name.txt\n",
    "star_stays_in_its_segment": "include docs/*.md\n",
    "hidden_files_are_not_ignored": "include examples/*.json\n",
    "recursive_include_any_depth": "recursive-include receipts *.json\n",
    "graft_takes_everything_below": "graft examples\n",
    "character_class_in_include": "include data/[a-c].txt\n",
    "character_class_in_global_include": "global-include [a-c].txt\n",
    "negated_class_in_include": "include data/[!a].txt\n",
    "lines_setuptools_refuses": "graft examples docs\nfoo bar\ninclude\nrecursive-include receipts\n",
    "no_template_lines": "# only a comment\n",
    "find_excludes_a_subpackage": "# only a comment\n",
    "find_without_namespaces": "# only a comment\n",
}


def _pyproject(pakete: str) -> str:
    return ('[build-system]\nrequires = ["setuptools>=68"]\nbuild-backend = "setuptools.build_meta"\n\n'
            '[project]\nname = "vektorprojekt"\nversion = "0.0.1"\nreadme = "README.md"\n\n' + pakete)


def _messen(template: str, pyproject: str) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        wurzel = pathlib.Path(tmp)
        (wurzel / "pyproject.toml").write_text(pyproject, encoding="utf-8")
        for rel in KANDIDATEN:
            if rel in ("MANIFEST.in", "pyproject.toml"):
                continue
            p = wurzel / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("x\n", encoding="utf-8")
        (wurzel / "MANIFEST.in").write_text(template, encoding="utf-8")
        dist = wurzel / "dist"
        skript = "import setuptools.build_meta as b; print(b.build_sdist('dist'))"
        r = subprocess.run([sys.executable, "-c", skript], cwd=wurzel, capture_output=True, text=True,
                           env={**os.environ, "PIP_NO_INDEX": "1"})
        if r.returncode != 0:
            raise SystemExit(f"build_sdist failed for {template!r}:\n{r.stderr[-2000:]}")
        name = r.stdout.strip().splitlines()[-1]
        with tarfile.open(dist / name) as tar:
            glieder = [m.name.split("/", 1)[1] for m in tar.getmembers() if m.isfile() and "/" in m.name]
        return sorted(k for k in KANDIDATEN if k in glieder)


def main() -> None:
    import setuptools
    faelle = {}
    for name, t in TEMPLATES.items():
        pyproject = _pyproject(PAKETE_VARIANTEN.get(name, PAKETE))
        faelle[name] = {"template": t, "pyproject": pyproject, "shipped": _messen(t, pyproject)}
    ziel = HIER / "vectors.json"
    ziel.write_text(json.dumps({"setuptools": setuptools.__version__, "candidates": KANDIDATEN,
                                "cases": faelle}, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{len(faelle)} cases written to {ziel} with setuptools {setuptools.__version__}")


if __name__ == "__main__":
    main()
