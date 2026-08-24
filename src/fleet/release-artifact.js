'use strict';

const requiredArtifactPaths = [
  'package.json',
  'package-lock.json',
  'install/install.sh',
  'src/server.js',
  'runtime/bin/node',
  'node_modules/yaml/package.json'
];

function artifactPreflightScript() {
  return `set -eu
archive=$1
expected=$2
unpacked=$3
listing=$4
validate_runtime=\${5:-1}
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$archive" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$archive" | awk '{print $1}')
fi
test "$actual" = "$expected" || { printf 'release artifact SHA-256 mismatch\n' >&2; exit 31; }
tar -tzf "$archive" | sed 's#^\./##' > "$listing"
while IFS= read -r entry; do
  case "$entry" in
    /*|../*|*/../*|*/..|*//*) printf 'release artifact contains an unsafe path\n' >&2; exit 32 ;;
  esac
done < "$listing"
prefix=
if grep -Fxq 'install/install.sh' "$listing"; then
  prefix=
else
  matches=$(awk -F/ 'NF == 3 && $2 == "install" && $3 == "install.sh" { print $1 }' "$listing" | sort -u)
  test "$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')" = 1 || { printf 'release artifact has no unique install root\n' >&2; exit 33; }
  prefix=$(printf '%s\n' "$matches" | sed '/^$/d')/
fi
for required in package.json package-lock.json install/install.sh src/server.js runtime/bin/node node_modules/yaml/package.json; do
  grep -Fxq "\${prefix}\${required}" "$listing" || { printf 'release artifact is missing %s\n' "$required" >&2; exit 34; }
done
if test -n "$prefix"; then
  while IFS= read -r entry; do
    case "$entry" in "$prefix"*) ;; *) printf 'release artifact contains content outside its install root\n' >&2; exit 34 ;; esac
  done < "$listing"
fi
rm -rf "$unpacked"
mkdir -p "$unpacked"
if test -n "$prefix"; then
  tar -xzf "$archive" -C "$unpacked" --strip-components=1
else
  tar -xzf "$archive" -C "$unpacked"
fi
for required in package.json package-lock.json install/install.sh src/server.js runtime/bin/node node_modules/yaml/package.json; do
  test -f "$unpacked/$required" && test ! -L "$unpacked/$required" || { printf 'release artifact extracted an invalid %s\n' "$required" >&2; exit 35; }
done
test -x "$unpacked/install/install.sh" || { printf 'release installer is not executable\n' >&2; exit 36; }
test -x "$unpacked/runtime/bin/node" || { printf 'release runtime is not executable\n' >&2; exit 37; }
if test "$validate_runtime" = 1; then
  test "$(uname -s)" = Linux || { printf 'release target requires Linux\n' >&2; exit 38; }
  test -d /run/systemd/system || { printf 'release target requires systemd\n' >&2; exit 38; }
  for command in awk base64 chown cp cut find getent install mv openssl runuser sort systemctl tar useradd; do
    command -v "$command" >/dev/null 2>&1 || { printf 'release target is missing required command: %s\n' "$command" >&2; exit 38; }
  done
  "$unpacked/runtime/bin/node" --version >/dev/null || { printf 'release runtime is incompatible with this VM\n' >&2; exit 38; }
fi
printf 'prepared\n'`;
}

module.exports = { artifactPreflightScript, requiredArtifactPaths };
