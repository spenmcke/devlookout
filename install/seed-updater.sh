#!/bin/sh
# One-time bridge for Lookout installations created before automatic updates.
set -eu
umask 077

SOURCE_DIR=${LOOKOUT_SOURCE_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
PREFIX=${LOOKOUT_PREFIX:-/opt/lookout}
UPDATE_CONFIG_DIR=${LOOKOUT_UPDATE_CONFIG_DIR:-/etc/lookout-update}
INSTALL_STATE_DIR=${LOOKOUT_INSTALL_STATE_DIR:-/var/lib/lookout-install}
SYSTEMD_DIR=${LOOKOUT_SYSTEMD_DIR:-/etc/systemd/system}
CHANNEL_URL=${LOOKOUT_UPDATE_CHANNEL_URL:-https://app.devlookout.com/v1/updates/stable}
ARTIFACT_ORIGINS=${LOOKOUT_UPDATE_ARTIFACT_ORIGINS:-https://github.com}

fail() { printf '%s\n' "lookout-seed-updater: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail 'run as root'
[ -L "$PREFIX/current" ] || fail 'an existing atomic Lookout installation is required'
for file in scripts/lookout-update.js src/update/manifest.js src/fleet/release-artifact.js config/update-signing-public-keys.json; do
  [ -f "$SOURCE_DIR/$file" ] && [ ! -L "$SOURCE_DIR/$file" ] || fail "verified updater source is missing $file"
done
case $CHANNEL_URL in https://*) ;; *) fail 'update channel must use HTTPS' ;; esac
case $ARTIFACT_ORIGINS in https://*) ;; *) fail 'artifact origins must use HTTPS' ;; esac

runtime=$PREFIX/current/runtime/bin/node
[ -x "$runtime" ] || fail 'the installed Lookout runtime is missing'
seed=$PREFIX/updater-seed
temporary=$PREFIX/.updater-seed.$$
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
mkdir -p "$temporary/scripts" "$temporary/src/update" "$temporary/src/fleet"
install -m 755 "$SOURCE_DIR/scripts/lookout-update.js" "$temporary/scripts/lookout-update.js"
install -m 644 "$SOURCE_DIR/src/update/manifest.js" "$temporary/src/update/manifest.js"
install -m 644 "$SOURCE_DIR/src/fleet/release-artifact.js" "$temporary/src/fleet/release-artifact.js"
rm -rf -- "$seed"
mv "$temporary" "$seed"
ln -sfn "$seed" "$PREFIX/updater-current.new"
mv -Tf "$PREFIX/updater-current.new" "$PREFIX/updater-current"

mkdir -p "$UPDATE_CONFIG_DIR" "$INSTALL_STATE_DIR"
chmod 700 "$UPDATE_CONFIG_DIR" "$INSTALL_STATE_DIR"
"$runtime" - "$SOURCE_DIR/config/update-signing-public-keys.json" "$UPDATE_CONFIG_DIR/update.json" "$CHANNEL_URL" "$ARTIFACT_ORIGINS" <<'NODE'
const fs = require('node:fs');
const [keysFile, destination, channelUrl, origins] = process.argv.slice(2);
const keys = JSON.parse(fs.readFileSync(keysFile, 'utf8'));
if (keys.schemaVersion !== 1 || !Array.isArray(keys.trustedKeys) || keys.trustedKeys.length < 1) throw new Error('invalid update signing keys');
const channel = new URL(channelUrl);
if (channel.protocol !== 'https:' || channel.username || channel.password || channel.search || channel.hash) throw new Error('invalid update channel');
const artifactOrigins = origins.split(',').map((value) => {
  const origin = new URL(value);
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/') throw new Error('invalid update artifact origin');
  return origin.origin;
});
const temporary = `${destination}.new.${process.pid}`;
fs.writeFileSync(temporary, `${JSON.stringify({ schemaVersion: 1, channelUrl: channel.toString(), artifactOrigins, trustedKeys: keys.trustedKeys })}\n`, { mode: 0o600 });
fs.renameSync(temporary, destination);
NODE

install -m 644 /dev/stdin "$SYSTEMD_DIR/lookout-update.service" <<EOF
[Unit]
Description=Lookout signed automatic update check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
Group=root
WorkingDirectory=$PREFIX/current
RuntimeDirectory=lookout-update
RuntimeDirectoryMode=0700
Environment=LOOKOUT_UPDATE_LOCK=/run/lookout-update/update.lock
ExecStart=$runtime $PREFIX/updater-current/scripts/lookout-update.js
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
ReadWritePaths=$PREFIX $INSTALL_STATE_DIR -/run/lookout-update
EOF

install -m 644 /dev/stdin "$SYSTEMD_DIR/lookout-update.timer" <<'EOF'
[Unit]
Description=Poll for signed Lookout updates

[Timer]
OnActiveSec=1min
OnUnitActiveSec=1min
RandomizedDelaySec=30s
Persistent=true
AccuracySec=1s

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now lookout-update.timer >/dev/null
printf '%s\n' 'Lookout signed automatic updates are enabled.'
