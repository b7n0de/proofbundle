"""Section 15 (S15-4): a verifier must not dereference arbitrary locations because they appear in a receipt. This
reader dereferences nothing: no module of the package imports a network or URL library."""
from __future__ import annotations

import ast
import os

PACKAGE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "eqr00")
NETWORK = {"socket", "ssl", "http", "urllib", "urllib3", "requests", "httpx", "aiohttp", "ftplib", "smtplib",
           "xmlrpc", "asyncio", "subprocess"}


def _imports(path):
    tree = ast.parse(open(path, encoding="utf-8").read())
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            out.add(node.module.split(".")[0])
    return out


def test_the_package_imports_no_network_module():
    seen = {}
    for name in sorted(os.listdir(PACKAGE)):
        if name.endswith(".py"):
            seen[name] = sorted(_imports(os.path.join(PACKAGE, name)) & NETWORK)
    assert seen and not any(seen.values()), seen


def test_counter_probe_a_planted_import_is_found(tmp_path):
    p = tmp_path / "planted.py"
    p.write_text("import urllib.request\nfrom http import client\n", encoding="utf-8")
    assert _imports(str(p)) & NETWORK == {"urllib", "http"}
