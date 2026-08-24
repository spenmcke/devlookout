#!/bin/sh
set -eu
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
if command -v node >/dev/null 2>&1 && [ "$(node -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null || printf 0)" -ge 20 ]; then
  NODE_BIN=$(command -v node)
elif [ "$(uname -s)" = Linux ] && [ -x "$SOURCE_DIR/runtime/bin/node" ]; then
  NODE_BIN=$SOURCE_DIR/runtime/bin/node
else
  printf '%s\n' 'lookout-setup: Node.js 20+ is required on a non-Linux orchestration host' >&2
  exit 1
fi
exec "$NODE_BIN" "$SCRIPT_DIR/onboard.js"
