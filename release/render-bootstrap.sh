#!/bin/sh
set -eu
umask 022

fail() { printf '%s\n' "render-bootstrap: $*" >&2; exit 1; }
[ "$#" -eq 6 ] || fail 'usage: render-bootstrap.sh <version> <orchestration-url> <orchestration-sha256> <target-url> <target-sha256> <output-file>'
version=$1
orchestration_url=$2
orchestration_digest=$3
target_url=$4
target_digest=$5
output=$6
case "$version" in v[0-9]*.[0-9]*.[0-9]*) ;; *) fail 'invalid version' ;; esac
case "$version" in *[!A-Za-z0-9._-]*) fail 'invalid version' ;; esac
for url in "$orchestration_url" "$target_url"; do
  case "$url" in https://*) ;; *) fail 'artifact URLs must use HTTPS' ;; esac
  case "$url" in *[!A-Za-z0-9:/._-]*) fail 'artifact URL contains unsupported characters' ;; esac
done
for digest in "$orchestration_digest" "$target_digest"; do
  case "$digest" in *[!0-9a-f]*|'') fail 'invalid SHA-256 digest' ;; esac
  [ "${#digest}" -eq 64 ] || fail 'invalid SHA-256 digest'
done

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
template=$repository/bootstrap/hosted-install.sh.in
awk -v version="$version" -v orchestration_url="$orchestration_url" -v orchestration_digest="$orchestration_digest" -v target_url="$target_url" -v target_digest="$target_digest" '
  { gsub(/@LOOKOUT_RELEASE_VERSION@/, version); gsub(/@LOOKOUT_ORCHESTRATION_URL@/, orchestration_url); gsub(/@LOOKOUT_ORCHESTRATION_SHA256@/, orchestration_digest); gsub(/@LOOKOUT_TARGET_URL@/, target_url); gsub(/@LOOKOUT_TARGET_SHA256@/, target_digest); print }
' "$template" > "$output"
chmod 0755 "$output"
