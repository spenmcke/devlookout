#!/bin/sh
# One-command bootstrap. From a checkout it dispatches locally. Remote use must
# pin both a source revision and its SHA-256 digest.
set -eu
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || true)
if [ -n "$script_dir" ] && [ -f "$script_dir/install/install.sh" ] && [ -f "$script_dir/package.json" ]; then
  if [ "${LOOKOUT_MODE:-auto}" = local ] || [ -n "${LOOKOUT_ROOT:-${DESTDIR:-}}" ]; then exec "$script_dir/install/install.sh" "$@"; fi
  exec "$script_dir/install/fleet.sh" "$@"
fi

command -v curl >/dev/null 2>&1 || { echo 'lookout-bootstrap: curl is required' >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo 'lookout-bootstrap: tar is required' >&2; exit 1; }

repository=${LOOKOUT_REPOSITORY:-Everest-Summit/secops}
version=${LOOKOUT_VERSION:-}
[ -n "$version" ] || { echo 'lookout-bootstrap: remote installation requires LOOKOUT_VERSION pinned to a release or commit' >&2; exit 1; }
[ -n "${LOOKOUT_ARCHIVE_SHA256:-}" ] || { echo 'lookout-bootstrap: remote installation requires LOOKOUT_ARCHIVE_SHA256 from a trusted release channel' >&2; exit 1; }
archive_url=${LOOKOUT_SOURCE_URL:-https://github.com/$repository/archive/$version.tar.gz}
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

if [ -n "${GH_TOKEN:-}" ]; then
  if [ -z "${LOOKOUT_SOURCE_URL:-}" ]; then archive_url=https://api.github.com/repos/$repository/tarball/$version; fi
  headers=$temporary/headers
  printf '%s\n' 'Accept: application/vnd.github+json' "Authorization: Bearer $GH_TOKEN" > "$headers"
  chmod 600 "$headers"
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 \
    --header @"$headers" \
    -o "$temporary/source.tar.gz" "$archive_url"
else
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 \
    -o "$temporary/source.tar.gz" "$archive_url"
fi

if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$temporary/source.tar.gz" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then actual=$(shasum -a 256 "$temporary/source.tar.gz" | awk '{print $1}')
else echo 'lookout-bootstrap: SHA-256 utility required' >&2; exit 1; fi
[ "$actual" = "$LOOKOUT_ARCHIVE_SHA256" ] || { echo 'lookout-bootstrap: source checksum mismatch' >&2; exit 1; }

mkdir "$temporary/source"
tar -xzf "$temporary/source.tar.gz" -C "$temporary/source" --strip-components=1
LOOKOUT_SOURCE_DIR="$temporary/source" export LOOKOUT_SOURCE_DIR
if [ "${LOOKOUT_MODE:-auto}" = local ]; then "$temporary/source/install/install.sh" "$@"
else "$temporary/source/install/fleet.sh" "$@"; fi
