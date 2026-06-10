#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="$HOME/.local/lib/tracemap"
BIN_DIR="$HOME/.local/bin"
SYSTEMD_FLAG=0

for arg in "$@"; do
  [ "$arg" = "--systemd" ] && SYSTEMD_FLAG=1
done

python3 -c "import sys; assert sys.version_info >= (3,10), 'Python 3.10+ required'" \
  || { echo "ERROR: Python 3.10+ required"; exit 1; }

echo "[install] Installing tracemap to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR" "$BIN_DIR"

cp -r *.py static "$INSTALL_DIR/"

cat > "$BIN_DIR/tracemap" << 'LAUNCHER'
#!/usr/bin/env bash
exec python3 "$HOME/.local/lib/tracemap/tracemap.py" "$@"
LAUNCHER
chmod +x "$BIN_DIR/tracemap"

if [ $SYSTEMD_FLAG -eq 1 ]; then
  UNIT_DIR="$HOME/.config/systemd/user"
  mkdir -p "$UNIT_DIR"
  cp packaging/tracemap.service "$UNIT_DIR/"
  systemctl --user daemon-reload
  systemctl --user enable --now tracemap
  echo "[install] systemd service enabled"
fi

echo "[install] Done. Make sure $BIN_DIR is on your PATH, then run: tracemap"
