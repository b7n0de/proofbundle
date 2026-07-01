#!/usr/bin/env python3
"""Regenerate assets/demo.svg from the REAL `proofbundle verify` output.

This keeps the terminal graphic honest: the lines drawn in the SVG are the exact
lines the verifier prints on examples/example_bundle.json. Run it after changing
the CLI output format.

    python scripts/render_demo.py

Dev-only. Not part of the package, no runtime dependency.
"""
from __future__ import annotations

import html
import io
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "assets" / "demo.svg"
EXAMPLE = ROOT / "examples" / "example_bundle.json"

ACCENT = "#D6248A"


def _capture_verify() -> list[str]:
    """Run the real verifier on the example bundle and return its stdout lines."""
    sys.path.insert(0, str(ROOT / "src"))
    from proofbundle import cli  # noqa: PLC0415

    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            cli.main(["verify", str(EXAMPLE)])
    except SystemExit:
        pass
    lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
    if not lines:  # fallback via subprocess if imported main writes elsewhere
        out = subprocess.run([sys.executable, "-m", "proofbundle.cli", "verify", str(EXAMPLE)],
                             capture_output=True, text=True, cwd=ROOT,
                             env={"PYTHONPATH": str(ROOT / "src")})
        lines = [ln for ln in out.stdout.splitlines() if ln.strip()]
    return lines


def _line_svg(y: int, text: str) -> str:
    esc = html.escape(text)
    if text.startswith("[PASS]"):
        return (f'    <text x="24" y="{y}"><tspan class="pass">[PASS]</tspan>'
                f'<tspan class="txt">{html.escape(text[6:])}</tspan></text>')
    if text.startswith("=>"):
        return f'    <text x="24" y="{y}"><tspan class="ok">{esc}</tspan></text>'
    return f'    <text x="24" y="{y}"><tspan class="txt">{esc}</tspan></text>'


def main() -> int:
    lines = _capture_verify()
    body_lines = ['    <text x="24" y="70"><tspan class="prompt">$ </tspan>'
                  '<tspan class="cmd">proofbundle verify bundle.json</tspan></text>']
    y = 100
    for ln in lines:
        body_lines.append(_line_svg(y, ln))
        y += 26
    height = y + 40
    body = "\n".join(body_lines)
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="740" height="{height}" viewBox="0 0 740 {height}" role="img" aria-label="proofbundle verify terminal demo">
  <title>proofbundle verify — terminal demo</title>
  <defs><style>
    .win {{ fill: #0f172a; }} .bar {{ fill: #1e293b; }}
    .mono {{ font-family: 'DejaVu Sans Mono','SFMono-Regular',Consolas,'Liberation Mono',monospace; font-size: 16px; }}
    .prompt {{ fill: #64748b; }} .cmd {{ fill: #e2e8f0; }} .pass {{ fill: {ACCENT}; font-weight: 700; }}
    .txt {{ fill: #cbd5e1; }} .ok {{ fill: #34d399; font-weight: 700; }}
  </style></defs>
  <rect x="0" y="0" width="740" height="{height}" rx="12" class="win" />
  <rect x="0" y="0" width="740" height="34" rx="12" class="bar" />
  <rect x="0" y="22" width="740" height="12" class="bar" />
  <circle cx="22" cy="17" r="6" fill="#ef4444" /><circle cx="44" cy="17" r="6" fill="#f59e0b" /><circle cx="66" cy="17" r="6" fill="#22c55e" />
  <g class="mono">
{body}
  </g>
</svg>
"""
    DEMO.write_text(svg, encoding="utf-8")
    print(f"wrote {DEMO} from {len(lines)} real verify lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
