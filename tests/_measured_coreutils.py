"""The read programs of D77 in a version the test names, for a test whose expectation needs a measured version (follow-up note 38,
point 4).

The gate frees a read chain of D77 only where each read program it starts names a measured version of GNU coreutils
first on PATH (`<program> --version`, _READ_PROGRAM_VERSIONS). A test that expected such a chain to be free read the
version of the host it ran on: green in this container (9.4), red on the operator's machine (GNU coreutils 8.32, account A's run of
2026-10-18: 11 cases of D83 and 1 of D84), where the gate rightly keeps the chain (B36-1). `version_on_path` puts a folder
first on PATH whose read programs name the version the test asks for and run the host's program for every other call, so
the expectation is the rule's, not the host's; a test with "8.32" is the catch case of the same chain.
"""
from __future__ import annotations

import os
import shutil

#: The read programs of D77 the gate asks for their version (`[` and test are the shell's builtins and are never asked).
READ_PROGRAMS = ("head", "tail", "ls", "date", "sleep", "wc", "sort")


def version_on_path(folder, monkeypatch, version: str = "9.4") -> str:
    """Write the read programs into folder, each naming `version` for --version, put folder first on PATH with
    monkeypatch and return the new PATH."""
    folder.mkdir(parents=True, exist_ok=True)
    host_path = os.environ.get("PATH", "")
    for name in READ_PROGRAMS:
        real = shutil.which(name, path=host_path)
        run = f"exec '{real}' \"$@\"" if real else "exit 127"
        program = folder / name
        program.write_text(f"#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '%s\\n' '{name} (GNU coreutils) "
                           f"{version}'; exit 0; fi\n{run}\n")
        program.chmod(0o755)
    path = f"{folder}{os.pathsep}{host_path}"
    monkeypatch.setenv("PATH", path)
    return path
