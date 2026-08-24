#!/bin/sh
set -eu
umask 022

fail() { printf '%s\n' "build-release: $*" >&2; exit 1; }
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || fail 'usage: build-release.sh <vMAJOR.MINOR.PATCH> [output-directory]'
version=$1
output_directory=${2:-dist}
case "$version" in v[0-9]*.[0-9]*.[0-9]*) ;; *) fail 'version must look like vMAJOR.MINOR.PATCH' ;; esac
case "$version" in *[!A-Za-z0-9._-]*) fail 'version contains unsupported characters' ;; esac

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target_architecture=${LOOKOUT_TARGET_ARCH:-}
target_node=${LOOKOUT_TARGET_NODE_BIN:-}
case "$target_architecture" in ''|amd64|arm64) ;; *) fail 'LOOKOUT_TARGET_ARCH must be amd64 or arm64' ;; esac
if [ -n "$target_node" ]; then [ -x "$target_node" ] || fail 'LOOKOUT_TARGET_NODE_BIN must be executable'; fi
for command in git gzip tar zip node; do command -v "$command" >/dev/null 2>&1 || fail "$command is required"; done
git -C "$repository" rev-parse --verify "$version^{commit}" >/dev/null 2>&1 || fail "git tag $version does not resolve to a commit"
if git -C "$repository" ls-tree -r "$version" | awk '$1 == "120000" || $1 == "160000" { found=1 } END { exit found ? 0 : 1 }'; then
  fail 'release trees must not contain symbolic links or submodules'
fi
package_version=$(git -C "$repository" show "$version:package.json" | sed -n 's/^[[:space:]]*"version":[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
[ "v$package_version" = "$version" ] || fail "package.json version $package_version does not match tag $version"
[ -d "$repository/node_modules" ] || fail 'npm ci must run before building release artifacts'

temporary=$(mktemp -d "${TMPDIR:-/tmp}/lookout-release.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
tree=$temporary/tree
mkdir -p "$tree"
git -C "$repository" archive "$version" | tar -xf - -C "$tree"
cp -R "$repository/node_modules" "$tree/node_modules"
mkdir -p "$tree/runtime/bin"
cp "${target_node:-$(command -v node)}" "$tree/runtime/bin/node"
mkdir -p "$output_directory"
output_directory=$(CDPATH= cd -- "$output_directory" && pwd)

orchestration_root=$temporary/lookout-orchestration-$version
mkdir -p "$orchestration_root"
for entry in package.json package-lock.json src bin install tools config node_modules; do cp -R "$tree/$entry" "$orchestration_root/"; done
orchestration_tar=$output_directory/lookout-orchestration-$version.tar.gz
tar --dereference --sort=name --mtime='UTC 2026-08-19' --owner=0 --group=0 --numeric-owner -C "$temporary" -cf - "lookout-orchestration-$version" | gzip -n -9 > "$orchestration_tar"
(cd "$temporary" && zip -X -q -r "$output_directory/lookout-orchestration-$version.zip" "lookout-orchestration-$version")

target_suffix=linux
if [ -n "$target_architecture" ]; then target_suffix=$target_suffix-$target_architecture; fi
target=$output_directory/lookout-target-$target_suffix-$version.tar.gz
tar --dereference --sort=name --mtime='UTC 2026-08-19' --owner=0 --group=0 --numeric-owner --transform="s,^,lookout-$version/," -C "$tree" -cf - package.json package-lock.json install.sh uninstall.sh src public bin scripts install config node_modules runtime | gzip -n -9 > "$target"

for artifact in "$orchestration_tar" "$output_directory/lookout-orchestration-$version.zip" "$target"; do
  if command -v sha256sum >/dev/null 2>&1; then digest=$(sha256sum "$artifact" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then digest=$(shasum -a 256 "$artifact" | awk '{print $1}')
  else fail 'a SHA-256 utility is required'; fi
  printf '%s\n' "$digest" > "$artifact.sha256"
done
printf '%s\n' "$orchestration_tar" "$output_directory/lookout-orchestration-$version.zip" "$target"
