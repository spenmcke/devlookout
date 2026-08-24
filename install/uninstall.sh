#!/bin/sh
# Safely uninstall Lookout from a Linux host.
set -eu

PROGRAM_NAME="lookout-uninstall"
ROOT_PREFIX=${LOOKOUT_ROOT:-/}
PURGE=false
COMPLETE=false
ASSUME_YES=false
DRY_RUN=false
SKIP_CONSOLE_NOTIFICATION=${LOOKOUT_SKIP_CONSOLE_NOTIFICATION:-0}
PRESERVE_INSTALL_STATE=${LOOKOUT_PRESERVE_INSTALL_STATE:-0}

usage() {
  cat <<'EOF'
Usage: uninstall.sh [--purge|--complete] [--yes] [--dry-run] [--root PATH]

Remove the Lookout application and systemd units. Configuration, encryption
keys, collector identities, and event data are preserved unless --purge is
specified. A purge requires interactive confirmation unless --yes is also
specified.

Options:
  --purge       Also remove Lookout configuration, secrets, and local data
  --complete    Completely remove Lookout for a clean-install test
  --yes         Confirm an irreversible purge or complete removal
  --dry-run     Print the actions without changing the host
  --root PATH   Apply filesystem changes below PATH (also: LOOKOUT_ROOT)
  -h, --help    Show this help
EOF
}

die() {
  printf '%s: %s\n' "$PROGRAM_NAME" "$*" >&2
  exit 1
}

case "$SKIP_CONSOLE_NOTIFICATION" in
  0|1) ;;
  *) die "LOOKOUT_SKIP_CONSOLE_NOTIFICATION must be 0 or 1" ;;
esac
case "$PRESERVE_INSTALL_STATE" in
  0|1) ;;
  *) die "LOOKOUT_PRESERVE_INSTALL_STATE must be 0 or 1" ;;
esac

note() {
  printf '%s\n' "$*"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --purge) PURGE=true ;;
    --complete) COMPLETE=true; PURGE=true ;;
    --yes) ASSUME_YES=true ;;
    --dry-run) DRY_RUN=true ;;
    --root)
      [ "$#" -ge 2 ] || die "--root requires an absolute path"
      ROOT_PREFIX=$2
      shift
      ;;
    --root=*) ROOT_PREFIX=${1#--root=} ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

[ "$ASSUME_YES" = false ] || [ "$PURGE" = true ] || die "--yes is only valid with --purge or --complete"

case "$ROOT_PREFIX" in
  /*) ;;
  *) die "root prefix must be an absolute path: $ROOT_PREFIX" ;;
esac
case "/$ROOT_PREFIX/" in
  */../*|*/./*) die "root prefix must not contain . or .. path components" ;;
esac

# Strip trailing slashes without relying on realpath, since the test root may
# not exist yet. The actual host root remains exactly '/'.
while [ "$ROOT_PREFIX" != "/" ] && [ "${ROOT_PREFIX%/}" != "$ROOT_PREFIX" ]; do
  ROOT_PREFIX=${ROOT_PREFIX%/}
done

if [ "$ROOT_PREFIX" != "/" ]; then
  [ -d "$ROOT_PREFIX" ] || die "offline root does not exist or is not a directory: $ROOT_PREFIX"
  PHYSICAL_ROOT=$(CDPATH= cd -- "$ROOT_PREFIX" 2>/dev/null && pwd -P) || die "cannot resolve offline root: $ROOT_PREFIX"
  [ "$PHYSICAL_ROOT" != "/" ] || die "offline root resolves to the host filesystem root"
  ROOT_PREFIX=$PHYSICAL_ROOT
fi

rooted() {
  case "$1" in
    /*) ;;
    *) die "internal error: relative installation path: $1" ;;
  esac
  if [ "$ROOT_PREFIX" = "/" ]; then
    printf '%s\n' "$1"
  else
    printf '%s%s\n' "$ROOT_PREFIX" "$1"
  fi
}

APP_DIR=$(rooted /opt/lookout)
SERVER_UNIT=$(rooted /etc/systemd/system/lookout.service)
COLLECTOR_UNIT=$(rooted /etc/systemd/system/lookout-collector.service)
COLLECTOR_TIMER=$(rooted /etc/systemd/system/lookout-collector.timer)
UPDATE_SERVICE=$(rooted /etc/systemd/system/lookout-update.service)
UPDATE_TIMER=$(rooted /etc/systemd/system/lookout-update.timer)
LOOKOUT_COMMAND=$(rooted /usr/local/bin/lookout)
UNINSTALL_COMMAND=$(rooted /usr/local/sbin/lookout-uninstall)
SERVER_CONFIG=$(rooted /etc/lookout)
COLLECTOR_CONFIG=$(rooted /etc/lookout-collector)
UPDATE_CONFIG=$(rooted /etc/lookout-update)
SERVER_DATA=$(rooted /var/lib/lookout)
COLLECTOR_DATA=$(rooted /var/lib/lookout-collector)
INSTALL_STATE=$(rooted /var/lib/lookout-install)
INSTALL_MANIFEST="$INSTALL_STATE/manifest"

CREATED_USER_LOOKOUT=0
CREATED_USER_COLLECTOR=0

read_manifest_marker() {
  key=$1
  [ -f "$INSTALL_MANIFEST" ] && [ ! -L "$INSTALL_MANIFEST" ] || return 0
  values=$(sed -n "s/^${key}=\([01]\)$/\1/p" "$INSTALL_MANIFEST")
  case "$values" in
    0|1) printf '%s\n' "$values" ;;
    *) printf '0\n' ;;
  esac
}

if [ "$ROOT_PREFIX" = "/" ] && [ -f "$INSTALL_MANIFEST" ] && [ ! -L "$INSTALL_MANIFEST" ]; then
  # The manifest controls account deletion, so accept it only when root owns it
  # and no group or other user can modify it.
  manifest_security=$(stat -c '%u:%a' -- "$INSTALL_MANIFEST" 2>/dev/null || printf 'invalid')
  if [ "$manifest_security" = "0:600" ]; then
    CREATED_USER_LOOKOUT=$(read_manifest_marker created_user_lookout)
    CREATED_USER_COLLECTOR=$(read_manifest_marker created_user_lookout_collector)
  else
    note "Ignoring account ownership markers in an insecure install manifest."
  fi
fi

assert_target() {
  candidate=$1
  shift
  for expected in "$@"; do
    [ "$candidate" != "$expected" ] || return 0
  done
  die "refusing unexpected removal target: $candidate"
}

assert_offline_parent() {
  target=$1
  [ "$ROOT_PREFIX" != "/" ] || return 0
  parent=${target%/*}
  [ -d "$parent" ] || return 0
  physical_parent=$(CDPATH= cd -- "$parent" 2>/dev/null && pwd -P) || die "cannot resolve removal target parent: $parent"
  case "$physical_parent/" in
    "$ROOT_PREFIX"/*) ;;
    *) die "refusing target whose parent escapes offline root: $target" ;;
  esac
}

run_systemctl() {
  if [ "$DRY_RUN" = true ]; then
    note "+ systemctl $*"
  else
    systemctl "$@" >/dev/null 2>&1
  fi
}

remove_file() {
  target=$1
  shift
  assert_target "$target" "$@"
  assert_offline_parent "$target"
  if [ ! -e "$target" ] && [ ! -L "$target" ]; then
    return 0
  fi
  if [ "$DRY_RUN" = true ]; then
    note "+ remove file $target"
  else
    rm -f -- "$target"
  fi
}

remove_tree() {
  target=$1
  shift
  assert_target "$target" "$@"
  assert_offline_parent "$target"
  [ "$target" != "/" ] || die "refusing to remove filesystem root"
  [ "$target" != "$ROOT_PREFIX" ] || die "refusing to remove installation root"
  if [ ! -e "$target" ] && [ ! -L "$target" ]; then
    return 0
  fi
  if [ "$DRY_RUN" = true ]; then
    note "+ remove tree $target"
  elif [ -L "$target" ]; then
    # Never traverse a replaced installation-directory symlink.
    rm -f -- "$target"
  else
    find "$target" -xdev -depth -delete
  fi
}

remove_installer_user() {
  account=$1
  expected_home=$2
  marker=$3
  [ "$marker" = "1" ] || return 0
  command -v getent >/dev/null 2>&1 || {
    note "Preserving $account account: getent is unavailable."
    return 1
  }
  record=$(getent passwd "$account" || true)
  [ -n "$record" ] || return 0
  old_ifs=$IFS
  IFS=:
  # passwd record fields: name, password, uid, gid, gecos, home, shell.
  set -- $record
  IFS=$old_ifs
  [ "$#" -eq 7 ] || {
    note "Preserving $account account: unexpected passwd record."
    return 1
  }
  account_name=$1
  account_uid=$3
  account_home=$6
  account_shell=$7
  case "$account_uid" in *[!0-9]*|'') account_uid=999999 ;; esac
  case "$account_shell" in /usr/sbin/nologin|/sbin/nologin|/bin/false|/usr/bin/false) safe_shell=true ;; *) safe_shell=false ;; esac
  if [ "$account_name" != "$account" ] || [ "$account_home" != "$expected_home" ] || [ "$safe_shell" != true ] || [ "$account_uid" -ge 1000 ]; then
    note "Preserving $account account: its UID, home, or shell no longer matches the installer-created account."
    return 1
  fi
  if [ "$DRY_RUN" = true ]; then
    note "+ userdel $account"
    return 0
  fi
  if command -v userdel >/dev/null 2>&1 && userdel "$account"; then
    note "Removed installer-created system account: $account"
    return 0
  fi
  note "Preserving $account account: userdel failed or is unavailable."
  return 1
}

if [ "$PURGE" = true ] && [ "$ASSUME_YES" = false ]; then
  [ -t 0 ] || die "--purge requires an interactive terminal or --yes"
  note "WARNING: purge permanently removes Lookout configuration, keys, identities, and event data."
  printf 'Type DELETE to continue: '
  IFS= read -r answer
  [ "$answer" = "DELETE" ] || die "purge cancelled"
fi

if [ "$ROOT_PREFIX" = "/" ]; then
  [ "$(id -u)" -eq 0 ] || die "run as root (or use --root for an offline test root)"
  if command -v systemctl >/dev/null 2>&1; then
    note "Stopping and disabling Lookout services..."
    run_systemctl disable --now lookout-collector.timer || true
    run_systemctl disable --now lookout-update.timer || true
    run_systemctl stop lookout-update.service || true
    run_systemctl disable --now lookout-collector.service || true
    run_systemctl disable --now lookout.service || true
  fi
else
  note "Offline root selected; systemd processes will not be changed."
fi

if [ "$SKIP_CONSOLE_NOTIFICATION" = "0" ] && [ "$ROOT_PREFIX" = "/" ] && [ -x "$LOOKOUT_COMMAND" ]; then
  if [ "$DRY_RUN" = true ]; then
    note "+ runuser -u lookout -- $LOOKOUT_COMMAND deployment-uninstall"
  elif ! command -v runuser >/dev/null 2>&1; then
    note "Warning: the SaaS console could not be updated because runuser is unavailable. Local uninstall will continue."
  else
    notification=$(runuser -u lookout -- "$LOOKOUT_COMMAND" deployment-uninstall 2>/dev/null || true)
    case "$notification" in
      *'"notified":true'*) note "SaaS now shows this deployment as uninstalled." ;;
      *'"reason":"not_configured"'*) ;;
      *) note "Warning: the SaaS console could not be updated. Local uninstall will continue." ;;
    esac
  fi
fi

note "Removing Lookout application and systemd units..."
remove_file "$SERVER_UNIT" "$SERVER_UNIT" "$COLLECTOR_UNIT" "$COLLECTOR_TIMER" "$UPDATE_SERVICE" "$UPDATE_TIMER"
remove_file "$COLLECTOR_UNIT" "$SERVER_UNIT" "$COLLECTOR_UNIT" "$COLLECTOR_TIMER" "$UPDATE_SERVICE" "$UPDATE_TIMER"
remove_file "$COLLECTOR_TIMER" "$SERVER_UNIT" "$COLLECTOR_UNIT" "$COLLECTOR_TIMER" "$UPDATE_SERVICE" "$UPDATE_TIMER"
remove_file "$UPDATE_SERVICE" "$SERVER_UNIT" "$COLLECTOR_UNIT" "$COLLECTOR_TIMER" "$UPDATE_SERVICE" "$UPDATE_TIMER"
remove_file "$UPDATE_TIMER" "$SERVER_UNIT" "$COLLECTOR_UNIT" "$COLLECTOR_TIMER" "$UPDATE_SERVICE" "$UPDATE_TIMER"
remove_file "$LOOKOUT_COMMAND" "$LOOKOUT_COMMAND" "$UNINSTALL_COMMAND"
remove_file "$UNINSTALL_COMMAND" "$LOOKOUT_COMMAND" "$UNINSTALL_COMMAND"
remove_tree "$APP_DIR" "$APP_DIR"

if [ "$ROOT_PREFIX" = "/" ] && command -v systemctl >/dev/null 2>&1; then
  run_systemctl daemon-reload || true
  run_systemctl reset-failed lookout.service lookout-collector.service lookout-update.service || true
fi

if [ "$PURGE" = true ]; then
  note "Purging Lookout configuration, secrets, and local data..."
  remove_tree "$SERVER_CONFIG" "$SERVER_CONFIG" "$COLLECTOR_CONFIG" "$UPDATE_CONFIG" "$SERVER_DATA" "$COLLECTOR_DATA"
  remove_tree "$COLLECTOR_CONFIG" "$SERVER_CONFIG" "$COLLECTOR_CONFIG" "$UPDATE_CONFIG" "$SERVER_DATA" "$COLLECTOR_DATA"
  remove_tree "$UPDATE_CONFIG" "$SERVER_CONFIG" "$COLLECTOR_CONFIG" "$UPDATE_CONFIG" "$SERVER_DATA" "$COLLECTOR_DATA"
  remove_tree "$SERVER_DATA" "$SERVER_CONFIG" "$COLLECTOR_CONFIG" "$SERVER_DATA" "$COLLECTOR_DATA"
  remove_tree "$COLLECTOR_DATA" "$SERVER_CONFIG" "$COLLECTOR_CONFIG" "$SERVER_DATA" "$COLLECTOR_DATA"
  users_removed=true
  if [ "$ROOT_PREFIX" = "/" ]; then
    remove_installer_user lookout /var/lib/lookout "$CREATED_USER_LOOKOUT" || users_removed=false
    remove_installer_user lookout-collector /var/lib/lookout-collector "$CREATED_USER_COLLECTOR" || users_removed=false
  fi
  if [ "$users_removed" = true ] && [ "$PRESERVE_INSTALL_STATE" = "0" ]; then
    remove_tree "$INSTALL_STATE" "$INSTALL_STATE"
  else
    note "Preserving $INSTALL_MANIFEST so retained installer-created accounts can be reviewed safely."
  fi
  if [ "$COMPLETE" = true ]; then
    note "Lookout was completely removed for a clean-install test."
  else
    note "Lookout was uninstalled and its local configuration and data were purged."
  fi
else
  note "Lookout was uninstalled. Configuration, secrets, and data were preserved at:"
  note "  $SERVER_CONFIG"
  note "  $COLLECTOR_CONFIG"
  note "  $UPDATE_CONFIG"
  note "  $SERVER_DATA"
  note "  $COLLECTOR_DATA"
  note "  $INSTALL_STATE"
  note "Reinstall Lookout to reuse them, or rerun this command with --purge to remove them."
fi
