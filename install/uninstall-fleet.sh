#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
command -v node >/dev/null 2>&1 || { echo 'lookout-uninstall: Node.js 20+ is required on the administrator workstation' >&2; exit 1; }
exec node "$SCRIPT_DIR/uninstall-fleet.js" "$@"
