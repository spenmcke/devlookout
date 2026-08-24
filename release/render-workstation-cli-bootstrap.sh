#!/bin/sh
set -eu

fail() { printf '%s\n' "render-workstation-cli-bootstrap: $*" >&2; exit 1; }
[ "$#" -eq 11 ] || fail 'usage: render-workstation-cli-bootstrap.sh <version> <tar-url> <tar-sha256> <zip-url> <zip-sha256> <amd64-url> <amd64-sha256> <arm64-url> <arm64-sha256> <shell-output> <powershell-output>'

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=$1
tar_url=$2
tar_digest=$3
zip_url=$4
zip_digest=$5
amd64_url=$6
amd64_digest=$7
arm64_url=$8
arm64_digest=$9
shell_output=${10}
powershell_output=${11}

case "$version" in v[0-9]*.[0-9]*.[0-9]*) ;; *) fail 'invalid release version' ;; esac
for url in "$tar_url" "$zip_url" "$amd64_url" "$arm64_url"; do case "$url" in https://*) ;; *) fail 'artifact URLs must use HTTPS' ;; esac; done
for digest in "$tar_digest" "$zip_digest" "$amd64_digest" "$arm64_digest"; do
  case "$digest" in *[!0-9a-f]*|'') fail 'invalid artifact digest' ;; esac
  [ "${#digest}" -eq 64 ] || fail 'invalid artifact digest'
done

render() {
  template=$1
  orchestration_url=$2
  orchestration_digest=$3
  output=$4
  mkdir -p "$(dirname -- "$output")"
  awk -v version="$version" -v orchestration_url="$orchestration_url" -v orchestration_digest="$orchestration_digest" -v amd64_url="$amd64_url" -v amd64_digest="$amd64_digest" -v arm64_url="$arm64_url" -v arm64_digest="$arm64_digest" '
    { gsub(/@LOOKOUT_RELEASE_VERSION@/, version); gsub(/@LOOKOUT_ORCHESTRATION_URL@/, orchestration_url); gsub(/@LOOKOUT_ORCHESTRATION_SHA256@/, orchestration_digest); gsub(/@LOOKOUT_TARGET_AMD64_URL@/, amd64_url); gsub(/@LOOKOUT_TARGET_AMD64_SHA256@/, amd64_digest); gsub(/@LOOKOUT_TARGET_ARM64_URL@/, arm64_url); gsub(/@LOOKOUT_TARGET_ARM64_SHA256@/, arm64_digest); print }
  ' "$template" > "$output"
  if grep '@LOOKOUT_' "$output" >/dev/null 2>&1; then fail 'bootstrap template is incomplete'; fi
}

render "$repository/bootstrap/workstation-cli-install.sh.in" "$tar_url" "$tar_digest" "$shell_output"
render "$repository/bootstrap/workstation-cli-install.ps1.in" "$zip_url" "$zip_digest" "$powershell_output"
chmod 755 "$shell_output"
