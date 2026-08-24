#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
if command -v node >/dev/null 2>&1 && [ "$(node -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null || printf 0)" -ge 20 ]; then
  NODE_BIN=$(command -v node)
else
  NODE_BIN=$(LOOKOUT_SOURCE_DIR="$SOURCE_DIR" LOOKOUT_PROVISION_ONLY=1 "$SCRIPT_DIR/install.sh")
fi
exec "$NODE_BIN" "$SCRIPT_DIR/fleet.js" "$@"
