#!/usr/bin/env bash
# Ein Einstiegspunkt. Kein Netz, keine Uhr, keine Installation.
#   ./run.sh /pfad/zu/certisyn-drafts/cap-1
set -euo pipefail
CAP1="${1:-}"
if [ -z "$CAP1" ] || [ ! -d "$CAP1/src/vectors" ]; then
  echo "usage: ./run.sh <pfad-zu-cap-1>" >&2
  echo "  erwartet <pfad>/src/vectors/ mit PV-01.json und PV-03.json" >&2
  echo "  Baum: https://github.com/Certisyn-Inc/certisyn-drafts  Commit 0980d32" >&2
  echo "  klonen mit:  git -c core.autocrlf=false clone <url> && git checkout 0980d32" >&2
  exit 2
fi
HIER="$(cd "$(dirname "$0")" && pwd)"
OUT="$HIER/sonden"

echo "== 1. Sonden aus dem Baum des Autors erzeugen (seine Dateien werden nicht kopiert)"
python3 "$HIER/sonden.py" "$CAP1/src/vectors" "$OUT"

echo
echo "== 2. Zweite Umsetzung bauen (Rust, ohne Abhaengigkeiten)"
RUSTBIN=""
if command -v cargo >/dev/null 2>&1; then
  ( cd "$HIER/rs" && cargo build --release --offline >/dev/null 2>&1 ) \
    && RUSTBIN="$HIER/rs/target/release/cap1_verify_rs" \
    && echo "   gebaut: $RUSTBIN"
else
  echo "   cargo fehlt — die strenge Lesart wird als '-' gemeldet, nicht als gruen"
fi

echo
echo "== 3. Lauf"
python3 "$HIER/lauf.py" "$CAP1/src" "$OUT" "$RUSTBIN"
