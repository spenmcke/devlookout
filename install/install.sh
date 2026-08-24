#!/bin/sh
# Lookout unattended Linux installer. This file is POSIX sh so it can run on a
# minimal host. All target paths pass through LOOKOUT_ROOT/DESTDIR for testing.
set -eu

umask 077

PROGRAM=lookout-install
SOURCE_DIR=${LOOKOUT_SOURCE_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
TARGET_ROOT=${LOOKOUT_ROOT:-${DESTDIR:-/}}
PREFIX=${LOOKOUT_PREFIX:-/opt/lookout}
CONFIG_DIR=${LOOKOUT_CONFIG_DIR:-/etc/lookout}
COLLECTOR_CONFIG_DIR=${LOOKOUT_COLLECTOR_CONFIG_DIR:-/etc/lookout-collector}
DATA_DIR=${LOOKOUT_DATA_DIR:-/var/lib/lookout}
COLLECTOR_DATA_DIR=${LOOKOUT_COLLECTOR_DATA_DIR:-/var/lib/lookout-collector}
SYSTEMD_DIR=${LOOKOUT_SYSTEMD_DIR:-/etc/systemd/system}
BIN_DIR=${LOOKOUT_BIN_DIR:-/usr/local/bin}
SBIN_DIR=${LOOKOUT_SBIN_DIR:-/usr/local/sbin}
INSTALL_STATE_DIR=${LOOKOUT_INSTALL_STATE_DIR:-/var/lib/lookout-install}
UPDATE_CONFIG_DIR=${LOOKOUT_UPDATE_CONFIG_DIR:-/etc/lookout-update}
UPDATE_CHANNEL_URL=${LOOKOUT_UPDATE_CHANNEL_URL:-https://app.devlookout.com/v1/updates/stable}
UPDATE_ARTIFACT_ORIGINS=${LOOKOUT_UPDATE_ARTIFACT_ORIGINS:-https://github.com}
PORT=${LOOKOUT_PORT:-4173}
BIND_HOST=${LOOKOUT_BIND_HOST:-127.0.0.1}
ENABLE_COLLECTOR=${LOOKOUT_ENABLE_COLLECTOR:-1}
INSTALL_NODE=${LOOKOUT_INSTALL_NODE:-auto}
NODE_VERSION=${LOOKOUT_NODE_VERSION:-24.19.0}
SKIP_START=${LOOKOUT_SKIP_START:-0}
DRY_RUN=${LOOKOUT_DRY_RUN:-0}
ADMIN_TOKEN_OUTPUT=${LOOKOUT_ADMIN_TOKEN_FILE:-$CONFIG_DIR/admin-token}
JOURNAL_GROUP=${LOOKOUT_JOURNAL_GROUP:-auto}
ROLE=${LOOKOUT_ROLE:-standalone}
COLLECTOR_SERVER_URL=${LOOKOUT_COLLECTOR_SERVER_URL:-http://127.0.0.1:$PORT}
COLLECTOR_CA_SOURCE=${LOOKOUT_COLLECTOR_CA_SOURCE:-}
ENROLLMENT_TOKEN_SOURCE=${LOOKOUT_ENROLLMENT_TOKEN_SOURCE:-}
REPLACE_ENROLLMENT=${LOOKOUT_REPLACE_ENROLLMENT:-0}
COLLECTOR_ASSET_ID=${LOOKOUT_COLLECTOR_ASSET_ID:-}
DEPLOYMENT_ID=${LOOKOUT_DEPLOYMENT_ID:-}
TLS_CERT_SOURCE=${LOOKOUT_TLS_CERT_SOURCE:-}
TLS_KEY_SOURCE=${LOOKOUT_TLS_KEY_SOURCE:-}
TAILSCALE_ALLOWED_USER_IDS=${LOOKOUT_TAILSCALE_ALLOWED_USER_IDS:-}
CONSOLE_ENDPOINT=${LOOKOUT_CONSOLE_ENDPOINT:-}
CONSOLE_CREDENTIAL_SOURCE=${LOOKOUT_CONSOLE_CREDENTIAL_SOURCE:-}
CONSOLE_DEPLOYMENT_ID=${LOOKOUT_CONSOLE_DEPLOYMENT_ID:-}
RECONCILE_CONFIG=${LOOKOUT_RECONCILE_CONFIG:-0}
ATTACH_CONSOLE_ONLY=${LOOKOUT_ATTACH_CONSOLE_ONLY:-0}

say() { printf '%s\n' "$*"; }
die() { printf '%s: error: %s\n' "$PROGRAM" "$*" >&2; exit 1; }
target() {
  case $TARGET_ROOT in
    /) printf '%s\n' "$1" ;;
    *) printf '%s%s\n' "${TARGET_ROOT%/}" "$1" ;;
  esac
}
is_sandbox() { [ "$TARGET_ROOT" != / ] || [ "$DRY_RUN" = 1 ]; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else die 'sha256sum or shasum is required'; fi
}
validate_absolute_path() {
  path_label=$1 path_value=$2
  case $path_value in /*) ;; *) die "$path_label must be an absolute path" ;; esac
  case $path_value in *'/../'*|*'/..'|*'/./'*|*'/.'|*'//'*) die "$path_label must be canonical and contain no dot or empty components" ;; esac
}
validate_service_path() {
  validate_absolute_path "$1" "$2"
  case $path_value in *[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-]*) die "$path_label contains unsupported characters" ;; esac
}
atomic_symlink() {
  link=$1 value=$2 temporary=${link}.new.$$
  rm -f "$temporary"
  ln -s "$value" "$temporary"
  if mv --help 2>&1 | grep -q -- '--no-target-directory'; then mv -Tf "$temporary" "$link"
  else mv -fh "$temporary" "$link"; fi
}

cleanup_paths=''
cleanup() {
  for cleanup_path in $cleanup_paths; do
    [ ! -e "$cleanup_path" ] || rm -rf "$cleanup_path"
  done
}
trap cleanup EXIT HUP INT TERM

validate_inputs() {
  if [ "$(uname -s)" != Linux ] && ! is_sandbox; then die 'only Linux is currently supported'; fi
  case $(uname -m) in x86_64|amd64|aarch64|arm64) ;; *) die "unsupported CPU architecture: $(uname -m)" ;; esac
  validate_absolute_path LOOKOUT_ROOT "$TARGET_ROOT"
  validate_absolute_path LOOKOUT_SOURCE_DIR "$SOURCE_DIR"
  validate_service_path LOOKOUT_PREFIX "$PREFIX"
  validate_service_path LOOKOUT_CONFIG_DIR "$CONFIG_DIR"
  validate_service_path LOOKOUT_COLLECTOR_CONFIG_DIR "$COLLECTOR_CONFIG_DIR"
  validate_service_path LOOKOUT_DATA_DIR "$DATA_DIR"
  validate_service_path LOOKOUT_COLLECTOR_DATA_DIR "$COLLECTOR_DATA_DIR"
  validate_service_path LOOKOUT_SYSTEMD_DIR "$SYSTEMD_DIR"
  validate_service_path LOOKOUT_BIN_DIR "$BIN_DIR"
  validate_service_path LOOKOUT_SBIN_DIR "$SBIN_DIR"
  validate_service_path LOOKOUT_INSTALL_STATE_DIR "$INSTALL_STATE_DIR"
  validate_service_path LOOKOUT_UPDATE_CONFIG_DIR "$UPDATE_CONFIG_DIR"
  validate_service_path LOOKOUT_ADMIN_TOKEN_FILE "$ADMIN_TOKEN_OUTPUT"
  [ "$TARGET_ROOT" = / ] || { [ -d "$TARGET_ROOT" ] && [ ! -L "$TARGET_ROOT" ]; } || die 'LOOKOUT_ROOT/DESTDIR must be an existing, non-symlink directory'
  [ -f "$SOURCE_DIR/package.json" ] && [ -f "$SOURCE_DIR/package-lock.json" ] && [ -f "$SOURCE_DIR/src/server.js" ] || die "LOOKOUT_SOURCE_DIR is not a Lookout source tree: $SOURCE_DIR"
  case $PORT in ''|*[!0-9]*) die 'LOOKOUT_PORT must be an integer' ;; esac
  [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die 'LOOKOUT_PORT must be between 1 and 65535'
  case $BIND_HOST in 127.0.0.1|::1|localhost) ;; *)
    if [ "$ROLE" = central ] && [ -n "$TLS_CERT_SOURCE" ] && [ -n "$TLS_KEY_SOURCE" ]; then :; else
    [ "${LOOKOUT_ALLOW_PLAINTEXT_NETWORK:-0}" = 1 ] || die 'network binding requires LOOKOUT_ALLOW_PLAINTEXT_NETWORK=1; terminate TLS before exposing Lookout'
    fi
  esac
  case $INSTALL_NODE in auto|never) ;; *) die 'LOOKOUT_INSTALL_NODE must be auto or never' ;; esac
  case $NODE_VERSION in ''|*[!0-9.]*) die 'LOOKOUT_NODE_VERSION must contain only digits and periods' ;; esac
  case $ENABLE_COLLECTOR in 0|1) ;; *) die 'LOOKOUT_ENABLE_COLLECTOR must be 0 or 1' ;; esac
  case $JOURNAL_GROUP in auto|none|systemd-journal) ;; *) die 'LOOKOUT_JOURNAL_GROUP must be auto, none, or systemd-journal' ;; esac
  case $ROLE in standalone|central|collector) ;; *) die 'LOOKOUT_ROLE must be standalone, central, or collector' ;; esac
  case $REPLACE_ENROLLMENT in 0|1) ;; *) die 'LOOKOUT_REPLACE_ENROLLMENT must be 0 or 1' ;; esac
  case $RECONCILE_CONFIG in 0|1) ;; *) die 'LOOKOUT_RECONCILE_CONFIG must be 0 or 1' ;; esac
  case $ATTACH_CONSOLE_ONLY in 0|1) ;; *) die 'LOOKOUT_ATTACH_CONSOLE_ONLY must be 0 or 1' ;; esac
  case ${LOOKOUT_TEST_SKIP_DETECTION_VALIDATION:-0} in 0|1) ;; *) die 'LOOKOUT_TEST_SKIP_DETECTION_VALIDATION must be 0 or 1' ;; esac
  if [ "${LOOKOUT_TEST_SKIP_DETECTION_VALIDATION:-0}" = 1 ] && ! is_sandbox; then die 'LOOKOUT_TEST_SKIP_DETECTION_VALIDATION is restricted to offline test roots'; fi
  case $UPDATE_CHANNEL_URL in https://*) ;; *) die 'LOOKOUT_UPDATE_CHANNEL_URL must use https' ;; esac
  case $UPDATE_CHANNEL_URL in *[[:space:]]*|*'?'*|*'#'*) die 'LOOKOUT_UPDATE_CHANNEL_URL is invalid' ;; esac
  case $UPDATE_ARTIFACT_ORIGINS in https://*) ;; *) die 'LOOKOUT_UPDATE_ARTIFACT_ORIGINS must contain HTTPS origins' ;; esac
  case $UPDATE_ARTIFACT_ORIGINS in *[[:space:]]*|*'?'*|*'#'*) die 'LOOKOUT_UPDATE_ARTIFACT_ORIGINS is invalid' ;; esac
  case $COLLECTOR_ASSET_ID in ''|*[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/-]*) [ -z "$COLLECTOR_ASSET_ID" ] || die 'LOOKOUT_COLLECTOR_ASSET_ID is invalid' ;; esac
  case $TAILSCALE_ALLOWED_USER_IDS in ''|*[!0123456789,]*) [ -z "$TAILSCALE_ALLOWED_USER_IDS" ] || die 'LOOKOUT_TAILSCALE_ALLOWED_USER_IDS must be comma-separated numeric IDs' ;; esac
  if [ -n "$CONSOLE_ENDPOINT$CONSOLE_CREDENTIAL_SOURCE$CONSOLE_DEPLOYMENT_ID" ]; then
    case $ROLE in standalone|central) ;; *) die 'SaaS console configuration belongs on the standalone or central service only' ;; esac
    case $CONSOLE_ENDPOINT in https://*) ;; *) die 'LOOKOUT_CONSOLE_ENDPOINT must use https' ;; esac
    case $CONSOLE_ENDPOINT in *[[:space:]]*) die 'LOOKOUT_CONSOLE_ENDPOINT contains whitespace' ;; esac
    case ${CONSOLE_ENDPOINT#https://} in *@*) die 'LOOKOUT_CONSOLE_ENDPOINT must not contain credentials' ;; esac
    case $CONSOLE_ENDPOINT in *'?'*|*'#'*) die 'LOOKOUT_CONSOLE_ENDPOINT must not contain query parameters or fragments' ;; esac
    case $CONSOLE_DEPLOYMENT_ID in ''|*[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-]*) die 'LOOKOUT_CONSOLE_DEPLOYMENT_ID is invalid' ;; esac
    validate_absolute_path LOOKOUT_CONSOLE_CREDENTIAL_SOURCE "$CONSOLE_CREDENTIAL_SOURCE"
    [ -f "$CONSOLE_CREDENTIAL_SOURCE" ] && [ ! -L "$CONSOLE_CREDENTIAL_SOURCE" ] || die 'LOOKOUT_CONSOLE_CREDENTIAL_SOURCE must be a regular, non-symlink file'
  fi
  if [ "$ROLE" = central ]; then
    for tls_source in "$TLS_CERT_SOURCE" "$TLS_KEY_SOURCE"; do
      validate_absolute_path LOOKOUT_TLS_SOURCE "$tls_source"
      [ -f "$tls_source" ] && [ ! -L "$tls_source" ] || die 'central TLS sources must be regular, non-symlink files'
    done
  fi
  if [ "$ROLE" = collector ]; then
    case $COLLECTOR_SERVER_URL in https://*) ;; *) die 'collector-only installation requires an https LOOKOUT_COLLECTOR_SERVER_URL' ;; esac
    case $COLLECTOR_SERVER_URL in *[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/+\-]*) die 'LOOKOUT_COLLECTOR_SERVER_URL contains unsupported characters' ;; esac
    validate_absolute_path LOOKOUT_COLLECTOR_CA_SOURCE "$COLLECTOR_CA_SOURCE"
    [ -f "$COLLECTOR_CA_SOURCE" ] && [ ! -L "$COLLECTOR_CA_SOURCE" ] || die 'LOOKOUT_COLLECTOR_CA_SOURCE must be a regular, non-symlink file'
    [ -n "$COLLECTOR_ASSET_ID" ] || die 'LOOKOUT_COLLECTOR_ASSET_ID is required for collector-only installation'
    case $DEPLOYMENT_ID in ''|*[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-]*) die 'LOOKOUT_DEPLOYMENT_ID is invalid' ;; esac
    existing_enrollment=$(target "$COLLECTOR_CONFIG_DIR/enrollment.json")
    if [ "${LOOKOUT_SKIP_ENROLLMENT:-0}" = 1 ] && ! is_sandbox; then die 'LOOKOUT_SKIP_ENROLLMENT is restricted to offline test roots'; fi
    if [ "${LOOKOUT_SKIP_ENROLLMENT:-0}" != 1 ] && { [ ! -f "$existing_enrollment" ] || [ "$REPLACE_ENROLLMENT" = 1 ]; }; then
      validate_absolute_path LOOKOUT_ENROLLMENT_TOKEN_SOURCE "$ENROLLMENT_TOKEN_SOURCE"
      [ -f "$ENROLLMENT_TOKEN_SOURCE" ] && [ ! -L "$ENROLLMENT_TOKEN_SOURCE" ] || die 'LOOKOUT_ENROLLMENT_TOKEN_SOURCE must be a regular, non-symlink file'
    fi
  fi
  if [ "$TARGET_ROOT" = / ] && [ "$DRY_RUN" != 1 ]; then
    [ "$PREFIX" = /opt/lookout ] && [ "$CONFIG_DIR" = /etc/lookout ] && \
      [ "$COLLECTOR_CONFIG_DIR" = /etc/lookout-collector ] && \
      [ "$DATA_DIR" = /var/lib/lookout ] && [ "$COLLECTOR_DATA_DIR" = /var/lib/lookout-collector ] && \
      [ "$SYSTEMD_DIR" = /etc/systemd/system ] && [ "$BIN_DIR" = /usr/local/bin ] && \
      [ "$SBIN_DIR" = /usr/local/sbin ] && [ "$INSTALL_STATE_DIR" = /var/lib/lookout-install ] && \
      [ "$UPDATE_CONFIG_DIR" = /etc/lookout-update ] && \
      [ "$ADMIN_TOKEN_OUTPUT" = /etc/lookout/admin-token ] || \
      die 'custom installation paths are supported only with LOOKOUT_ROOT/DESTDIR test fixtures'
  fi
  if ! is_sandbox && [ "$(id -u)" -ne 0 ]; then die 'run as root (for example: sudo ./install/install.sh)'; fi
  if ! is_sandbox; then
    [ -d /run/systemd/system ] || die 'systemd is required for this installer'
    need systemctl
  fi
  need awk; need find; need sort; need tar
}

node_major() { "$1" -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null || printf '0\n'; }

install_bundled_runtime() {
  runtime_root=$(target "$PREFIX/runtime")
  mkdir -p "$runtime_root"
  chmod 755 "$runtime_root"
  bundled=$SOURCE_DIR/runtime/bin/node
  [ -x "$bundled" ] && [ "$(node_major "$bundled")" -ge 20 ] || die 'the verified release does not contain a compatible bundled Node.js runtime'
  runtime_id=$(sha256 "$bundled" | cut -c1-16)
  node_home=$runtime_root/bundled-$runtime_id
  mkdir -p "$node_home/bin"
  temporary=$node_home/bin/node.new.$$
  cp "$bundled" "$temporary"
  chmod 755 "$temporary"
  mv -f "$temporary" "$node_home/bin/node"
  if ! is_sandbox; then
    chown -R root:root "$node_home"
  fi
  find "$node_home" -type d -exec chmod a+rx {} \;
  chmod -R a+r,a-w "$node_home"
  NODE_BIN=$node_home/bin/node; NPM_BIN=''
}

select_node() {
  if [ -x "$SOURCE_DIR/runtime/bin/node" ]; then install_bundled_runtime
  elif command -v node >/dev/null 2>&1 && [ "$(node_major "$(command -v node)")" -ge 20 ]; then NODE_BIN=$(command -v node); NPM_BIN=''
  else die 'Node.js 20+ is required when using a development source tree without a bundled runtime'; fi
  [ -x "$NODE_BIN" ] || die 'unable to provision Node.js'
}

ensure_accounts() {
  CREATED_USER_LOOKOUT=0
  CREATED_USER_LOOKOUT_COLLECTOR=0
  prior_manifest=$(target "$INSTALL_STATE_DIR/manifest")
  if [ -f "$prior_manifest" ]; then
    [ "$(awk -F= '$1 == "created_user_lookout" { print $2 }' "$prior_manifest")" = 1 ] && CREATED_USER_LOOKOUT=1
    [ "$(awk -F= '$1 == "created_user_lookout_collector" { print $2 }' "$prior_manifest")" = 1 ] && CREATED_USER_LOOKOUT_COLLECTOR=1
  fi
  is_sandbox && return
  accounts='lookout lookout-collector'
  [ "$ROLE" != collector ] || accounts='lookout-collector'
  for account in $accounts; do
    if ! id "$account" >/dev/null 2>&1; then
      case $account in lookout) account_home=$DATA_DIR; CREATED_USER_LOOKOUT=1 ;; *) account_home=$COLLECTOR_DATA_DIR; CREATED_USER_LOOKOUT_COLLECTOR=1 ;; esac
      useradd --system --user-group --home-dir "$account_home" --no-create-home --shell /usr/sbin/nologin "$account"
    fi
  done
}

fingerprint_source() {
  digest_input=$(mktemp); cleanup_paths="$digest_input $cleanup_paths"
  find "$SOURCE_DIR" -type f \
    ! -path "$SOURCE_DIR/.git/*" ! -path '*/node_modules/*' ! -path '*/.next/*' \
    ! -path "$SOURCE_DIR/data/*" ! -name '.env*' ! -name '._*' ! -name '.DS_Store' \
    -print | LC_ALL=C sort | while IFS= read -r file; do
      printf '%s  %s\n' "$(sha256 "$file")" "${file#"$SOURCE_DIR"/}"
    done > "$digest_input"
  sha256 "$digest_input" | cut -c1-16
}

install_application() {
  version=$($NODE_BIN -e 'process.stdout.write(require(process.argv[1]).version)' "$SOURCE_DIR/package.json")
  case $version in ''|*[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.+-]*) die 'package version is not safe for a release directory name' ;; esac
  release_id=$version-$(fingerprint_source)
  prefix=$(target "$PREFIX")
  releases=$(target "$PREFIX/releases")
  release=$releases/$release_id
  current=$(target "$PREFIX/current")
  mkdir -p "$releases"
  chmod 755 "$prefix" "$releases"
  if [ -e "$release" ] && [ ! -f "$release/.lookout-release" ]; then
    die "incomplete release directory requires operator inspection: $release"
  fi
  if [ ! -f "$release/.lookout-release" ]; then
    staging=$releases/.staging.$$
    cleanup_paths="$staging $cleanup_paths"
    mkdir -p "$staging"
    tar -C "$SOURCE_DIR" --exclude=.git --exclude=node_modules --exclude=.next --exclude=data --exclude='.env*' --exclude='._*' --exclude=.DS_Store --exclude='*.log' -cf - . | tar -C "$staging" -xf -
    if [ -d "$SOURCE_DIR/node_modules" ] && [ -f "$SOURCE_DIR/node_modules/yaml/package.json" ]; then
      cp -R "$SOURCE_DIR/node_modules" "$staging/node_modules"
    else
      die 'the verified release does not contain prebuilt production dependencies'
    fi
    printf '%s\n' "$release_id" > "$staging/.lookout-release"
    if ! is_sandbox; then
      chown -R root:root "$staging"
      find "$staging" -type d -exec chmod a+rx {} \;
      chmod -R a+r,a-w "$staging"
    fi
    mv "$staging" "$release"
  fi
  PREVIOUS_RELEASE=''
  [ ! -L "$current" ] || PREVIOUS_RELEASE=$(readlink "$current")
  atomic_symlink "$current" "$release"
  RELEASE=$release
  RELEASE_ID=$release_id
}

write_file() {
  mode=$1 owner=$2 destination=$3; shift 3
  temporary=${destination}.new.$$
  mkdir -p "$(dirname "$destination")"
  "$@" > "$temporary"
  chmod "$mode" "$temporary"
  if ! is_sandbox; then chown "$owner:$owner" "$temporary"; fi
  mv -f "$temporary" "$destination"
}

json_string() { "$NODE_BIN" -e 'process.stdout.write(JSON.stringify(process.argv[1]))' -- "$1"; }
random_token() { "$NODE_BIN" -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("base64url"))'; }
token_hash() { "$NODE_BIN" -e 'process.stdout.write(require("node:crypto").createHash("sha256").update(process.argv[1]).digest("hex"))' -- "$1"; }

configure_installation() {
  cfg=$(target "$CONFIG_DIR"); ccfg=$(target "$COLLECTOR_CONFIG_DIR")
  data=$(target "$DATA_DIR"); cdata=$(target "$COLLECTOR_DATA_DIR")
  if [ "$ROLE" = collector ]; then
    mkdir -p "$ccfg" "$cdata"
    chmod 700 "$ccfg" "$cdata"
    if ! is_sandbox; then chown lookout-collector:lookout-collector "$ccfg" "$cdata"; fi
    collector_master=$ccfg/master-key
    if [ ! -f "$collector_master" ]; then write_file 600 lookout-collector "$collector_master" random_token; fi
    ca_file=$ccfg/ca.pem
    if [ ! -f "$ca_file" ] || ! cmp -s "$COLLECTOR_CA_SOURCE" "$ca_file"; then
      temporary=${ca_file}.new.$$
      cp "$COLLECTOR_CA_SOURCE" "$temporary"; chmod 644 "$temporary"
      if ! is_sandbox; then chown root:root "$temporary"; fi
      mv -f "$temporary" "$ca_file"
    fi
    enrollment=$ccfg/enrollment.json
    enrollment_result=$cdata/enrollment-result.json
    retired=''
    if [ "$REPLACE_ENROLLMENT" = 1 ] && [ -f "$enrollment" ]; then
      if ! is_sandbox; then systemctl stop lookout-collector.service >/dev/null 2>&1 || true; fi
      retired=$(target "$INSTALL_STATE_DIR/retired-collectors/$DEPLOYMENT_ID-$(date +%s)-$$")
      mkdir -p "$retired/data"; chmod 700 "$(dirname "$retired")" "$retired" "$retired/data"
      mv "$enrollment" "$retired/enrollment.json"
      find "$cdata" -mindepth 1 -maxdepth 1 -exec mv {} "$retired/data/" \;
      if ! is_sandbox; then chown -R root:root "$retired"; fi
    fi
    if { [ ! -f "$enrollment" ] || [ ! -s "$enrollment_result" ]; } && [ "${LOOKOUT_SKIP_ENROLLMENT:-0}" != 1 ]; then
      invite=$ccfg/.enrollment-invitation
      if [ -f "$enrollment" ]; then
        "$NODE_BIN" -e 'const fs=require("node:fs"); const bundle=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(`${bundle.request.enrollmentToken}\n`)' "$enrollment" > "$invite"
      else cp "$ENROLLMENT_TOKEN_SOURCE" "$invite"; fi
      chmod 600 "$invite"
      if ! is_sandbox; then
        chown lookout-collector:lookout-collector "$invite"
        command -v runuser >/dev/null 2>&1 || die 'collector enrollment requires runuser from util-linux'
        if ! runuser -u lookout-collector -- env LOOKOUT_CONFIG= LOOKOUT_DATA_DIR="$COLLECTOR_DATA_DIR" LOOKOUT_REQUIRE_ENCRYPTION=true LOOKOUT_MASTER_KEY_FILE="$COLLECTOR_CONFIG_DIR/master-key" LOOKOUT_ENROLLMENT_TOKEN_FILE="$COLLECTOR_CONFIG_DIR/.enrollment-invitation" "$NODE_BIN" "$RELEASE/bin/lookout.js" collector-enroll "$COLLECTOR_CONFIG_DIR" "$COLLECTOR_SERVER_URL" "$COLLECTOR_ASSET_ID" "$DEPLOYMENT_ID" "$COLLECTOR_CONFIG_DIR/ca.pem" > "$enrollment_result"; then
          rm -f "$invite" "$enrollment" "$enrollment_result"
          if [ -n "$retired" ]; then
            mv "$retired/enrollment.json" "$enrollment"
            find "$retired/data" -mindepth 1 -maxdepth 1 -exec mv {} "$cdata/" \;
            if ! is_sandbox; then chown -R lookout-collector:lookout-collector "$enrollment" "$cdata"; systemctl start lookout-collector.service >/dev/null 2>&1 || true; fi
            die 'collector enrollment failed; the previous collector identity was restored'
          fi
          die 'collector enrollment failed'
        fi
        chmod 600 "$enrollment_result"; chown lookout-collector:lookout-collector "$enrollment_result"
      fi
      rm -f "$invite"
    fi
    CONFIG_FILE=''; MASTER_FILE=$collector_master; ADMIN_OUTPUT=''; NEW_ADMIN_TOKEN=0
    return
  fi
  mkdir -p "$cfg" "$ccfg" "$data" "$cdata"
  chmod 700 "$cfg" "$ccfg" "$data" "$cdata"
  if ! is_sandbox; then chown lookout:lookout "$data" "$cfg"; chown lookout-collector:lookout-collector "$cdata" "$ccfg"; fi

  master=$cfg/master-key collector_master=$ccfg/master-key credentials=$cfg/credentials.json collectors=$cfg/collectors.json
  admin_output=$(target "$ADMIN_TOKEN_OUTPUT")
  if [ ! -f "$master" ]; then
    write_file 600 lookout "$master" random_token
  fi
  if [ ! -f "$collector_master" ]; then
    write_file 600 lookout-collector "$collector_master" random_token
  fi
  if [ "$ROLE" = central ]; then
    tls_dir=$cfg/tls; mkdir -p "$tls_dir"; chmod 700 "$tls_dir"
    if ! is_sandbox; then chown lookout:lookout "$tls_dir"; fi
    write_file 644 lookout "$tls_dir/server.crt" cat "$TLS_CERT_SOURCE"
    write_file 600 lookout "$tls_dir/server.key" cat "$TLS_KEY_SOURCE"
    write_file 644 lookout-collector "$ccfg/ca.pem" cat "$TLS_CERT_SOURCE"
  fi
  console_file=$cfg/console-token
  if [ -n "$CONSOLE_ENDPOINT" ]; then
    write_file 600 lookout "$console_file" cat "$CONSOLE_CREDENTIAL_SOURCE"
  fi
  if [ "$ATTACH_CONSOLE_ONLY" = 1 ] && { [ "$ROLE" != central ] || [ -z "$CONSOLE_ENDPOINT" ]; }; then die 'console-only attachment requires the central role and complete console configuration'; fi
  if [ ! -f "$credentials" ]; then
    admin_token=$(random_token); collector_token=$(random_token)
    admin_hash=$(token_hash "$admin_token"); collector_hash=$(token_hash "$collector_token")
    write_file 600 lookout "$credentials" printf '%s\n' "{\"schemaVersion\":1,\"credentials\":[{\"id\":\"installer-admin\",\"tokenHash\":\"$admin_hash\",\"roles\":[\"admin\"]},{\"id\":\"local-collector\",\"tokenHash\":\"$collector_hash\",\"roles\":[\"collector\"]}]}"
    write_file 600 root "$admin_output" printf '%s\n' "$admin_token"
    write_file 600 lookout-collector "$ccfg/api-token" printf '%s\n' "$collector_token"
    NEW_ADMIN_TOKEN=1
  else NEW_ADMIN_TOKEN=0; fi
  if [ "$ENABLE_COLLECTOR" = 1 ] && [ ! -f "$ccfg/api-token" ]; then
    die "$ccfg/api-token is missing while credentials already exist; refusing to silently rotate only one side"
  fi

  identity=$ccfg/identity
  if [ "$ENABLE_COLLECTOR" = 1 ] && [ ! -f "$identity/collector.json" ]; then
    mkdir -p "$identity"; chmod 700 "$identity"
    LOOKOUT_CONFIG= LOOKOUT_DATA_DIR="$cdata" "$NODE_BIN" "$RELEASE/bin/lookout.js" collector-keygen "$identity" >/dev/null
    if ! is_sandbox; then chown -R lookout-collector:lookout-collector "$identity"; fi
  fi
  if [ "$ENABLE_COLLECTOR" = 1 ]; then
    if [ -n "$COLLECTOR_ASSET_ID" ]; then
      identity_json=$($NODE_BIN -e 'const fs=require("node:fs");const file=process.argv[1],assetId=process.argv[2],doc=JSON.parse(fs.readFileSync(file,"utf8"));doc.assetId=assetId;process.stdout.write(JSON.stringify(doc,null,2)+"\n")' "$identity/collector.json" "$COLLECTOR_ASSET_ID") || die 'unable to bind local collector to its surveyed asset identity'
      write_file 600 lookout-collector "$identity/collector.json" printf '%s' "$identity_json"
    fi
    collector_id=$($NODE_BIN -e 'process.stdout.write(require(process.argv[1]).collectorId)' "$identity/collector.json")
    collector_json=$($NODE_BIN - "$collectors" "$collector_id" "$identity/collector-public.pem" "$RELEASE/src/core/canonical.js" <<'NODE'
const fs = require('node:fs');
const crypto = require('node:crypto');
const [filename, localId, localKeyFile, canonicalModule] = process.argv.slice(2);
const { stableId } = require(canonicalModule);
const localKey = fs.readFileSync(localKeyFile, 'utf8');
let mapping = {};
if (fs.existsSync(filename)) {
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('Collector registry must be a regular, non-symlink file');
  if ((stat.mode & 0o077) !== 0) throw new Error('Collector registry must not be accessible by group or other users');
  if (stat.size > 4 * 1024 * 1024) throw new Error('Collector registry exceeds the 4 MiB size limit');
  const document = JSON.parse(fs.readFileSync(filename, 'utf8'));
  mapping = document && typeof document === 'object' && !Array.isArray(document) && document.collectors !== undefined ? document.collectors : document;
  if (!mapping || typeof mapping !== 'object' || Array.isArray(mapping)) throw new Error('Collector registry must contain an object mapping');
}
for (const [id, pem] of Object.entries(mapping)) {
  if (typeof pem !== 'string') throw new Error(`Collector registry key ${id} is not a PEM string`);
  let key;
  try { key = crypto.createPublicKey(pem); } catch { throw new Error(`Collector registry key ${id} is invalid`); }
  if (key.asymmetricKeyType !== 'ed25519' || stableId('collector', pem) !== id) throw new Error(`Collector registry identity does not match key: ${id}`);
}
if (stableId('collector', localKey) !== localId) throw new Error('Local collector identity does not match its public key');
mapping[localId] = localKey;
process.stdout.write(JSON.stringify({ schemaVersion: 1, collectors: Object.fromEntries(Object.entries(mapping).sort(([a], [b]) => a.localeCompare(b))) }));
NODE
)
    write_file 600 lookout "$collectors" printf '%s\n' "$collector_json"
  elif [ ! -f "$collectors" ]; then write_file 600 lookout "$collectors" printf '%s\n' '{"schemaVersion":1,"collectors":{}}'; fi

  config_file=$cfg/lookout.json
  if [ ! -f "$config_file" ] || [ "${LOOKOUT_REWRITE_CONFIG:-0}" = 1 ]; then
    logical_credentials=$CONFIG_DIR/credentials.json; logical_collectors=$CONFIG_DIR/collectors.json
    bind_json=$(json_string "$BIND_HOST"); data_json=$(json_string "$DATA_DIR")
    tls_json=''
    if [ "$ROLE" = central ]; then tls_json=',"tls":{"certificateFile":"/etc/lookout/tls/server.crt","privateKeyFile":"/etc/lookout/tls/server.key"}'; fi
    tailscale_auth_json=$($NODE_BIN -e 'const ids=(process.argv[1]||"").split(",").filter(Boolean); process.stdout.write(JSON.stringify({enabled:Boolean(ids.length),socketPath:"/var/run/tailscale/tailscaled.sock",allowedUserIds:[...new Set(ids)].sort(),allowedNodeIds:[],roles:["admin"]}))' -- "$TAILSCALE_ALLOWED_USER_IDS")
    console_json=''
    secret_files_json='{}'
    if [ -n "$CONSOLE_ENDPOINT" ]; then
      endpoint_json=$(json_string "$CONSOLE_ENDPOINT"); deployment_json=$(json_string "$CONSOLE_DEPLOYMENT_ID")
      secret_files_json="{\"console-token\":\"$CONFIG_DIR/console-token\"}"
      console_json=",\"consoleSync\":{\"enabled\":true,\"endpoint\":$endpoint_json,\"credentialReference\":\"console-token\",\"deploymentId\":$deployment_json}"
    fi
    write_file 600 lookout "$config_file" printf '%s\n' "{\"schemaVersion\":1,\"server\":{\"host\":$bind_json,\"port\":$PORT,\"allowLoopbackAdmin\":false$tls_json},\"storage\":{\"dataDirectory\":$data_json,\"requireEncryption\":true,\"retentionDays\":7,\"auditRetentionDays\":7,\"maximumPercent\":2},\"auth\":{\"credentialsFile\":\"$logical_credentials\",\"legacyTokenEnvironment\":null,\"tailscale\":$tailscale_auth_json},\"collectors\":{\"keysFile\":\"$logical_collectors\"},\"secrets\":{\"environment\":{},\"files\":$secret_files_json},\"export\":{\"enabled\":false,\"batchSize\":100,\"maxPending\":50000,\"flushIntervalSeconds\":30,\"categories\":[],\"attributeAllowlist\":[],\"includeActor\":false}$console_json}"
  elif [ -n "$TAILSCALE_ALLOWED_USER_IDS" ]; then
    updated_config=$($NODE_BIN -e 'const fs=require("node:fs");const file=process.argv[1],ids=process.argv[2].split(",").filter(Boolean),doc=JSON.parse(fs.readFileSync(file,"utf8"));doc.auth.tailscale={enabled:true,socketPath:"/var/run/tailscale/tailscaled.sock",allowedUserIds:[...new Set(ids)].sort(),allowedNodeIds:[],roles:["admin"]};process.stdout.write(JSON.stringify(doc))' "$config_file" "$TAILSCALE_ALLOWED_USER_IDS") || die 'unable to update Tailscale identity configuration safely'
    write_file 600 lookout "$config_file" printf '%s\n' "$updated_config"
  fi
  if [ -n "$CONSOLE_ENDPOINT" ] && [ -f "$config_file" ]; then
    updated_config=$($NODE_BIN -e 'const fs=require("node:fs");const [file,endpoint,deploymentId,tokenFile,reconcile,role,host,port]=process.argv.slice(1);const doc=JSON.parse(fs.readFileSync(file,"utf8"));doc.secrets ||= {};doc.secrets.environment ||= {};doc.secrets.files ||= {};doc.secrets.files["console-token"]=tokenFile;doc.consoleSync={...(doc.consoleSync||{}),enabled:true,endpoint,credentialReference:"console-token",deploymentId};if(reconcile==="1"){doc.server ||= {};doc.server.host=host;doc.server.port=Number(port);if(role==="central")doc.server.tls={certificateFile:"/etc/lookout/tls/server.crt",privateKeyFile:"/etc/lookout/tls/server.key"};else delete doc.server.tls;}process.stdout.write(JSON.stringify(doc))' "$config_file" "$CONSOLE_ENDPOINT" "$CONSOLE_DEPLOYMENT_ID" "$CONFIG_DIR/console-token" "$RECONCILE_CONFIG" "$ROLE" "$BIND_HOST" "$PORT") || die 'unable to configure SaaS console sync safely'
    deployment_changed=$($NODE_BIN -e 'const fs=require("node:fs");const [file,next]=process.argv.slice(1);const previous=JSON.parse(fs.readFileSync(file,"utf8")).consoleSync?.deploymentId;process.stdout.write(previous&&previous!==next?"1":"0")' "$config_file" "$CONSOLE_DEPLOYMENT_ID") || die 'unable to inspect the previous console deployment safely'
    if [ "$deployment_changed" = 1 ] && ! is_sandbox; then systemctl stop lookout.service >/dev/null 2>&1 || true; fi
    archive_root=$(target "$INSTALL_STATE_DIR/console-outbox-archive")
    data_root=$(target "$DATA_DIR")
    archive_status=0
    $NODE_BIN - "$config_file" "$data_root" "$archive_root" "$CONSOLE_DEPLOYMENT_ID" <<'NODE' || archive_status=$?
const fs = require('node:fs');
const path = require('node:path');
const [configFile, dataDirectory, archiveRoot, deploymentId] = process.argv.slice(2);
const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
const previous = config.consoleSync?.deploymentId;
if (previous && previous !== deploymentId) {
  const candidates = ['console-sync.jsonl', 'console-sync.checkpoint.json'];
  const existing = candidates.filter((name) => fs.existsSync(path.join(dataDirectory, name)));
  if (existing.length) {
    if (fs.existsSync(archiveRoot)) {
      const root = fs.lstatSync(archiveRoot);
      if (!root.isDirectory() || root.isSymbolicLink()) throw new Error('Unsafe console outbox archive directory');
    }
    fs.mkdirSync(archiveRoot, { recursive: true, mode: 0o700 });
    const archive = fs.mkdtempSync(path.join(archiveRoot, 'deployment-transition-'));
    fs.chmodSync(archive, 0o700);
    for (const name of existing) {
      const source = path.join(dataDirectory, name);
      const stat = fs.lstatSync(source);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`Unsafe console outbox file: ${name}`);
      fs.renameSync(source, path.join(archive, name));
    }
    fs.writeFileSync(path.join(archive, 'transition.json'), `${JSON.stringify({ schemaVersion: 1, previousDeploymentId: previous, nextDeploymentId: deploymentId, archivedAt: new Date().toISOString() })}\n`, { mode: 0o600 });
  }
}
NODE
    if [ "$archive_status" -ne 0 ]; then
      if [ "$deployment_changed" = 1 ] && ! is_sandbox; then systemctl start lookout.service >/dev/null 2>&1 || true; fi
      die 'unable to archive the previous deployment console outbox safely'
    fi
    write_file 600 lookout "$config_file" printf '%s\n' "$updated_config"
  elif [ "$RECONCILE_CONFIG" = 1 ] && [ -f "$config_file" ]; then
    updated_config=$($NODE_BIN -e 'const fs=require("node:fs");const [file,role,host,port]=process.argv.slice(1);const doc=JSON.parse(fs.readFileSync(file,"utf8"));doc.server ||= {};doc.server.host=host;doc.server.port=Number(port);if(role==="central")doc.server.tls={certificateFile:"/etc/lookout/tls/server.crt",privateKeyFile:"/etc/lookout/tls/server.key"};else delete doc.server.tls;process.stdout.write(JSON.stringify(doc))' "$config_file" "$ROLE" "$BIND_HOST" "$PORT") || die 'unable to reconcile the service role safely'
    write_file 600 lookout "$config_file" printf '%s\n' "$updated_config"
  fi
  CONFIG_FILE=$config_file; MASTER_FILE=$master; ADMIN_OUTPUT=$admin_output
}

write_units() {
  units=$(target "$SYSTEMD_DIR"); mkdir -p "$units"
  node=$NODE_BIN
  # Alternate roots are test fixtures; service paths deliberately remain the
  # logical production paths that will exist on the installed host.
  if [ "$TARGET_ROOT" != / ]; then
    case $node in "${TARGET_ROOT%/}"/*) node=${node#"${TARGET_ROOT%/}"} ;; esac
  fi
  current=$PREFIX/current
  journal_group_line=''
  if [ "$JOURNAL_GROUP" = systemd-journal ] || { [ "$JOURNAL_GROUP" = auto ] && command -v getent >/dev/null 2>&1 && getent group systemd-journal >/dev/null 2>&1; }; then
    journal_group_line='SupplementaryGroups=systemd-journal'
  fi
  if [ "$ROLE" != collector ]; then
    write_file 644 root "$units/lookout.service" printf '%s\n' \
"[Unit]
Description=Lookout security observability service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=lookout
Group=lookout
WorkingDirectory=$current
Environment=NODE_ENV=production
Environment=NODE_OPTIONS=--max-old-space-size=160
Environment=LOOKOUT_CONFIG=$CONFIG_DIR/lookout.json
Environment=LOOKOUT_MASTER_KEY_FILE=$CONFIG_DIR/master-key
ExecStartPre=$node $current/scripts/lookout-preflight-upgrade.js
ExecStart=$node $current/src/server.js
Restart=on-failure
RestartSec=5s
MemoryHigh=224M
MemoryMax=256M
MemorySwapMax=128M
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectKernelLogs=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid
RestrictSUIDSGID=true
LockPersonality=true
RestrictRealtime=true
RemoveIPC=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target"
  fi

  collector_identity=$COLLECTOR_CONFIG_DIR/identity
  collector_url=http://127.0.0.1:$PORT
  collector_api_line="Environment=LOOKOUT_API_TOKEN_FILE=$COLLECTOR_CONFIG_DIR/api-token"
  collector_ca_line=''
  collector_survey_line="Environment=LOOKOUT_SURVEY_EXCLUDED_LISTENER_PORTS=$PORT"
  collector_unit_dependencies="After=lookout.service
Requires=lookout.service"
  if [ "$ROLE" = central ]; then
    collector_url=https://$BIND_HOST:$PORT
    collector_ca_line="Environment=LOOKOUT_COLLECTOR_CA_FILE=$COLLECTOR_CONFIG_DIR/ca.pem"
  fi
  if [ "$ROLE" = collector ]; then
    collector_identity=$COLLECTOR_CONFIG_DIR
    collector_url=$COLLECTOR_SERVER_URL
    collector_api_line=''
    collector_ca_line="Environment=LOOKOUT_COLLECTOR_CA_FILE=$COLLECTOR_CONFIG_DIR/ca.pem"
    collector_survey_line=''
    collector_unit_dependencies="After=network-online.target
Wants=network-online.target"
  fi
  write_file 644 root "$units/lookout-collector.service" printf '%s\n' \
"[Unit]
Description=Lookout continuous local endpoint collector
$collector_unit_dependencies

[Service]
Type=simple
User=lookout-collector
Group=lookout-collector
$journal_group_line
WorkingDirectory=$current
Environment=NODE_ENV=production
Environment=NODE_OPTIONS=--max-old-space-size=64
Environment=LOOKOUT_DATA_DIR=$COLLECTOR_DATA_DIR
Environment=LOOKOUT_REQUIRE_ENCRYPTION=true
Environment=LOOKOUT_MASTER_KEY_FILE=$COLLECTOR_CONFIG_DIR/master-key
$collector_api_line
$collector_ca_line
$collector_survey_line
ExecStart=$node $current/bin/lookout.js collector-run $collector_identity $collector_url
Restart=on-failure
RestartSec=5s
MemoryHigh=112M
MemoryMax=128M
MemorySwapMax=64M
TimeoutStopSec=15s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectKernelLogs=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictSUIDSGID=true
LockPersonality=true
RestrictRealtime=true
RemoveIPC=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ReadOnlyPaths=$COLLECTOR_CONFIG_DIR
ReadWritePaths=$COLLECTOR_DATA_DIR

[Install]
WantedBy=multi-user.target"

  legacy_timer=$units/lookout-collector.timer
  if ! is_sandbox; then systemctl disable --now lookout-collector.timer >/dev/null 2>&1 || true; fi
  [ ! -e "$legacy_timer" ] && [ ! -L "$legacy_timer" ] || rm -f "$legacy_timer"

  write_file 644 root "$units/lookout-update.service" printf '%s\n' \
"[Unit]
Description=Lookout signed automatic update check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
Group=root
WorkingDirectory=$current
RuntimeDirectory=lookout-update
RuntimeDirectoryMode=0700
Environment=LOOKOUT_UPDATE_LOCK=/run/lookout-update/update.lock
ExecStart=$node $PREFIX/updater-current/scripts/lookout-update.js
UMask=0077
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectKernelLogs=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid
RestrictSUIDSGID=true
LockPersonality=true
RestrictRealtime=true
RemoveIPC=true
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_FOWNER
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadOnlyPaths=$UPDATE_CONFIG_DIR
ReadWritePaths=$PREFIX $INSTALL_STATE_DIR -/run/lookout-update"

  write_file 644 root "$units/lookout-update.timer" printf '%s\n' \
"[Unit]
Description=Poll for signed Lookout updates

[Timer]
OnActiveSec=1min
OnUnitActiveSec=1min
RandomizedDelaySec=30s
Persistent=true
AccuracySec=1s

[Install]
WantedBy=timers.target"
}

write_update_configuration() {
  update_dir=$(target "$UPDATE_CONFIG_DIR")
  state_dir=$(target "$INSTALL_STATE_DIR")
  mkdir -p "$update_dir" "$state_dir"
  chmod 700 "$update_dir" "$state_dir"
  trusted_keys=$($NODE_BIN -e 'const fs=require("node:fs");const value=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));if(value.schemaVersion!==1||!Array.isArray(value.trustedKeys)||value.trustedKeys.length<1)process.exit(1);process.stdout.write(JSON.stringify(value.trustedKeys))' "$SOURCE_DIR/config/update-signing-public-keys.json") || die 'update signing key configuration is invalid'
  update_json=$($NODE_BIN -e 'const [channel,originsText,keys]=process.argv.slice(1);const channelUrl=new URL(channel);if(channelUrl.protocol!=="https:"||channelUrl.username||channelUrl.password||channelUrl.search||channelUrl.hash)process.exit(1);const artifactOrigins=originsText.split(",").map((value)=>{const url=new URL(value);if(url.protocol!=="https:"||url.username||url.password||url.search||url.hash||url.pathname!=="/")process.exit(1);return url.origin});process.stdout.write(JSON.stringify({schemaVersion:1,channelUrl:channelUrl.toString(),artifactOrigins,trustedKeys:JSON.parse(keys)}))' "$UPDATE_CHANNEL_URL" "$UPDATE_ARTIFACT_ORIGINS" "$trusted_keys") || die 'unable to create update configuration'
  write_file 600 root "$update_dir/update.json" printf '%s\n' "$update_json"
  atomic_symlink "$(target "$PREFIX/updater-current")" "$RELEASE"
}

write_entrypoints() {
  bin=$(target "$BIN_DIR"); sbin=$(target "$SBIN_DIR")
  mkdir -p "$bin" "$sbin"
  entry_node=$NODE_BIN
  if [ "$TARGET_ROOT" != / ]; then
    case $entry_node in "${TARGET_ROOT%/}"/*) entry_node=${entry_node#"${TARGET_ROOT%/}"} ;; esac
  fi
  write_file 755 root "$bin/lookout" printf '%s\n' \
"#!/bin/sh
export LOOKOUT_CONFIG=${CONFIG_FILE:-}
export LOOKOUT_MASTER_KEY_FILE=$MASTER_FILE
exec $entry_node $PREFIX/current/bin/lookout.js \"\$@\""
  if [ -f "$SOURCE_DIR/install/uninstall.sh" ]; then
    temporary=$sbin/lookout-uninstall.new.$$
    cp "$SOURCE_DIR/install/uninstall.sh" "$temporary"
    chmod 755 "$temporary"
    if ! is_sandbox; then chown root:root "$temporary"; fi
    mv -f "$temporary" "$sbin/lookout-uninstall"
  fi
}

write_manifest() {
  manifest=$(target "$PREFIX/install-manifest.json")
  temporary=${manifest}.new.$$
  mkdir -p "$(dirname "$manifest")"
  "$NODE_BIN" - "$temporary" "$RELEASE_ID" "$PREFIX" "$CONFIG_DIR" "$COLLECTOR_CONFIG_DIR" "$DATA_DIR" "$COLLECTOR_DATA_DIR" "$SYSTEMD_DIR" "$ROLE" <<'NODE'
const fs = require('node:fs');
const [file, release, prefix, config, collectorConfig, data, collectorData, systemd, role] = process.argv.slice(2);
const paths = role === 'collector' ? {prefix, collectorConfig, collectorData, systemd} : {prefix, config, collectorConfig, data, collectorData, systemd};
const units = role === 'collector'
  ? ['lookout-collector.service', 'lookout-update.service', 'lookout-update.timer']
  : ['lookout.service', 'lookout-collector.service', 'lookout-update.service', 'lookout-update.timer'];
fs.writeFileSync(file, `${JSON.stringify({schemaVersion: 1, product: 'lookout', role, release, installedAt: new Date().toISOString(), paths, units, entrypoints: ['/usr/local/bin/lookout', '/usr/local/sbin/lookout-uninstall']}, null, 2)}\n`, {mode: 0o600});
NODE
  chmod 600 "$temporary"; mv -f "$temporary" "$manifest"

  state=$(target "$INSTALL_STATE_DIR"); mkdir -p "$state"; chmod 700 "$state"
  state_tmp=$state/manifest.new.$$
  {
    printf '%s\n' 'schema_version=1'
    printf '%s\n' "product=lookout"
    printf '%s\n' "release=$RELEASE_ID"
    printf '%s\n' "source_release=$RELEASE_ID"
    printf '%s\n' "created_user_lookout=$CREATED_USER_LOOKOUT"
    printf '%s\n' "created_user_lookout_collector=$CREATED_USER_LOOKOUT_COLLECTOR"
  } > "$state_tmp"
  chmod 600 "$state_tmp"
  if ! is_sandbox; then chown root:root "$state_tmp"; fi
  mv -f "$state_tmp" "$state/manifest"
}

verify_and_start() {
  if is_sandbox || [ "$SKIP_START" = 1 ]; then
    if [ "$ROLE" != collector ]; then LOOKOUT_CONFIG="$CONFIG_FILE" LOOKOUT_MASTER_KEY_FILE="$MASTER_FILE" "$NODE_BIN" "$RELEASE/bin/lookout.js" config-check >/dev/null; fi
    return
  fi
  COLLECTOR_WAS_ENABLED=0
  if systemctl is-enabled --quiet lookout-collector.service >/dev/null 2>&1; then COLLECTOR_WAS_ENABLED=1; fi
  systemctl daemon-reload
  if [ "$ROLE" = collector ]; then
    systemctl enable lookout-collector.service >/dev/null
    if ! systemctl restart lookout-collector.service; then rollback 'collector service failed to restart'; fi
    return
  fi
  systemctl enable lookout.service >/dev/null
  if ! systemctl restart lookout.service; then rollback 'service failed to start'; fi
  if [ "$ENABLE_COLLECTOR" = 1 ]; then
    systemctl enable lookout-collector.service >/dev/null
    if ! systemctl restart lookout-collector.service; then rollback 'collector service failed to restart'; fi
  else
    systemctl disable --now lookout-collector.service >/dev/null 2>&1 || true
  fi
  attempts=0
  while [ "$attempts" -lt 90 ]; do
    if [ "$ROLE" = central ]; then
      health_ok=0
      curl --fail --silent --show-error --max-time 2 --cacert "$CONFIG_DIR/tls/server.crt" "https://$BIND_HOST:$PORT/health" >/dev/null 2>&1 || health_ok=$?
    else
      health_ok=0
      curl --fail --silent --show-error --max-time 2 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 || health_ok=$?
    fi
    if [ "$health_ok" = 0 ]; then return; fi
    attempts=$((attempts + 1)); sleep 1
  done
  rollback 'health verification failed after 90 seconds'
}

enable_updater() {
  if is_sandbox || [ "$SKIP_START" = 1 ]; then return; fi
  systemctl enable lookout-update.timer >/dev/null
  systemctl start lookout-update.timer
}

verify_detection_pipeline() {
  if is_sandbox && [ "${LOOKOUT_TEST_SKIP_DETECTION_VALIDATION:-0}" = 1 ]; then return; fi
  if ! "$NODE_BIN" "$RELEASE/bin/lookout.js" validate-detection-pipeline >/dev/null; then
    die 'built-in detection pipeline validation failed; services were not started'
  fi
}

rollback() {
  reason=$1
  if [ -n "$PREVIOUS_RELEASE" ]; then
    atomic_symlink "$(target "$PREFIX/current")" "$PREVIOUS_RELEASE"
    rollback_failed=0
    systemctl daemon-reload >/dev/null 2>&1 || rollback_failed=1
    if [ "$ROLE" != collector ]; then systemctl restart lookout.service >/dev/null 2>&1 || rollback_failed=1; fi
    if [ "${COLLECTOR_WAS_ENABLED:-0}" = 1 ]; then
      systemctl restart lookout-collector.service >/dev/null 2>&1 || rollback_failed=1
    fi
    if [ "$rollback_failed" = 1 ]; then die "$reason; the previous release was selected but one or more services failed to recover"; fi
    die "$reason; the previous release and previously enabled services were restored"
  fi
  systemctl stop lookout.service >/dev/null 2>&1 || true
  systemctl stop lookout-collector.service >/dev/null 2>&1 || true
  die "$reason; no previous release was available to restore"
}

main() {
  validate_inputs
  if [ "$DRY_RUN" = 1 ]; then
    say "Would install Lookout from $SOURCE_DIR into $PREFIX using local-only address http://127.0.0.1:$PORT"
    say 'Dry run: no files, accounts, or services were changed.'
    return
  fi
  select_node
  if [ "${LOOKOUT_PROVISION_ONLY:-0}" = 1 ]; then
    printf '%s\n' "$NODE_BIN"
    return
  fi
  if [ "$ATTACH_CONSOLE_ONLY" = 1 ]; then
    RELEASE=$(target "$PREFIX/current")
    [ -L "$RELEASE" ] && [ -f "$RELEASE/.lookout-release" ] || die 'console-only attachment requires an existing verified Lookout installation'
    RELEASE_ID=$(cat "$RELEASE/.lookout-release")
    configure_installation
    if ! is_sandbox; then
      systemctl restart lookout.service
      attempts=0
      while [ "$attempts" -lt 90 ]; do
        if curl --fail --silent --show-error --max-time 2 --cacert "$CONFIG_DIR/tls/server.crt" "https://$BIND_HOST:$PORT/health" >/dev/null 2>&1; then return; fi
        attempts=$((attempts + 1)); sleep 1
      done
      die 'service health verification failed after console attachment'
    fi
    return
  fi
  ensure_accounts
  install_application
  verify_detection_pipeline
  configure_installation
  write_update_configuration
  write_units
  write_entrypoints
  verify_and_start
  write_manifest
  enable_updater
  say ''
  say "Lookout $RELEASE_ID is installed."
  if [ "$ROLE" = collector ]; then
    say "Collector destination: $COLLECTOR_SERVER_URL"
  else
    if [ "$ROLE" = central ]; then say "Address: https://$BIND_HOST:$PORT"; else say "Address: http://127.0.0.1:$PORT"; fi
    say "Administrator token: $ADMIN_TOKEN_OUTPUT"
    if [ "$NEW_ADMIN_TOKEN" = 1 ]; then say 'The administrator token was generated once and stored with root-only permissions.'; fi
  fi
  if is_sandbox; then say "Test root: $TARGET_ROOT (services were not started)"; fi
}

main "$@"
