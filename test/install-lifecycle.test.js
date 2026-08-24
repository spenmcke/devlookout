'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { stableId } = require('../src/core/canonical');

const repository = path.resolve(__dirname, '..');
const bootstrap = path.join(repository, 'install.sh');
const installer = path.join(repository, 'install', 'install.sh');
const uninstaller = path.join(repository, 'install', 'uninstall.sh');

async function temporaryRoot(label) {
  return fs.mkdtemp(path.join(os.tmpdir(), `lookout-${label}-`));
}

function run(script, arguments_, { environment = {}, input } = {}) {
  return spawnSync('sh', [script, ...arguments_], {
    cwd: repository,
    encoding: 'utf8',
    input,
    timeout: 60_000,
    env: {
      PATH: process.env.PATH,
      ...environment
    }
  });
}

function assertSucceeded(result) {
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
}

async function writeFixture(root, relative, contents = 'fixture') {
  const filename = path.join(root, relative);
  await fs.mkdir(path.dirname(filename), { recursive: true });
  await fs.writeFile(filename, contents);
  return filename;
}

async function linuxTestPath(root) {
  const directory = path.join(root, 'test-bin');
  await fs.mkdir(directory);
  const uname = path.join(directory, 'uname');
  await fs.writeFile(uname, `#!/bin/sh
case "\${1:-}" in
  -s) printf '%s\\n' Linux ;;
  -m) printf '%s\\n' x86_64 ;;
  *) printf '%s\\n' Linux ;;
esac
`, { mode: 0o755 });
  return `${directory}:${process.env.PATH}`;
}

async function minimalInstallerSource(root) {
  const source = path.join(root, 'installer-source');
  for (const relative of ['package.json', 'package-lock.json']) {
    const destination = path.join(source, relative);
    await fs.mkdir(path.dirname(destination), { recursive: true });
    await fs.copyFile(path.join(repository, relative), destination);
  }
  for (const relative of ['src', 'bin', 'config', 'install', 'scripts', 'node_modules/yaml']) {
    await fs.cp(path.join(repository, relative), path.join(source, relative), { recursive: true });
  }
  return source;
}

function mode(stat) {
  return stat.mode & 0o777;
}

async function readTree(directory) {
  const result = new Map();
  async function visit(current) {
    for (const entry of await fs.readdir(current, { withFileTypes: true })) {
      const filename = path.join(current, entry.name);
      if (entry.isDirectory()) await visit(filename);
      else if (entry.isFile()) result.set(path.relative(directory, filename), await fs.readFile(filename, 'utf8'));
    }
  }
  await visit(directory);
  return result;
}

test('offline one-command install creates a complete least-privilege deployment without exposing literal secrets', async (t) => {
  const root = await temporaryRoot('install');
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const testPath = await linuxTestPath(root);
  const environment = {
    PATH: testPath,
    LOOKOUT_ROOT: root,
    LOOKOUT_SOURCE_DIR: repository,
    LOOKOUT_INSTALL_NODE: 'never',
    LOOKOUT_USE_SOURCE_DEPENDENCIES: '1',
    LOOKOUT_SKIP_START: '1',
    LOOKOUT_ENABLE_COLLECTOR: '1',
    LOOKOUT_JOURNAL_GROUP: 'none'
  };

  const first = run(bootstrap, [], { environment });
  assertSucceeded(first);
  assert.doesNotMatch(`${first.stdout}\n${first.stderr}`, /[A-Za-z0-9_-]{43}/, 'installer output may contain secret material');

  const configDirectory = path.join(root, 'etc/lookout');
  const collectorDirectory = path.join(root, 'etc/lookout-collector');
  const dataDirectory = path.join(root, 'var/lib/lookout');
  const collectorDataDirectory = path.join(root, 'var/lib/lookout-collector');
  const masterKeyFile = path.join(configDirectory, 'master-key');
  const credentialsFile = path.join(configDirectory, 'credentials.json');
  const administratorTokenFile = path.join(configDirectory, 'admin-token');
  const collectorTokenFile = path.join(collectorDirectory, 'api-token');
  const collectorMasterKeyFile = path.join(collectorDirectory, 'master-key');
  const privateKeyFile = path.join(collectorDirectory, 'identity/collector-private.pem');

  assert.equal(mode(await fs.stat(path.join(root, 'opt/lookout'))), 0o755, 'service accounts must be able to traverse the application prefix');
  assert.equal(mode(await fs.stat(path.join(root, 'opt/lookout/releases'))), 0o755, 'service accounts must be able to traverse releases');
  const currentRelease = await fs.realpath(path.join(root, 'opt/lookout/current'));
  await assert.rejects(fs.access(path.join(currentRelease, '.env')), { code: 'ENOENT' });
  await assert.rejects(fs.access(path.join(currentRelease, '.env.swp')), { code: 'ENOENT' });

  for (const directory of [configDirectory, collectorDirectory, dataDirectory, collectorDataDirectory]) {
    assert.equal(mode(await fs.stat(directory)), 0o700, `${directory} must be private`);
  }
  for (const filename of [masterKeyFile, credentialsFile, administratorTokenFile, collectorTokenFile, collectorMasterKeyFile, privateKeyFile]) {
    assert.equal(mode(await fs.stat(filename)), 0o600, `${filename} must be private`);
  }
  for (const unit of ['lookout.service', 'lookout-collector.service', 'lookout-update.service', 'lookout-update.timer']) {
    assert.equal(mode(await fs.stat(path.join(root, 'etc/systemd/system', unit))), 0o644);
  }
  await assert.rejects(fs.access(path.join(root, 'etc/systemd/system/lookout-collector.timer')), { code: 'ENOENT' });
  const serverUnit = await fs.readFile(path.join(root, 'etc/systemd/system/lookout.service'), 'utf8');
  const collectorUnit = await fs.readFile(path.join(root, 'etc/systemd/system/lookout-collector.service'), 'utf8');
  const updateUnit = await fs.readFile(path.join(root, 'etc/systemd/system/lookout-update.service'), 'utf8');
  const updateTimer = await fs.readFile(path.join(root, 'etc/systemd/system/lookout-update.timer'), 'utf8');
  assert.match(serverUnit, /^Environment=LOOKOUT_MASTER_KEY_FILE=\/etc\/lookout\/master-key$/m);
  assert.match(serverUnit, /^MemoryMax=256M$/m);
  assert.match(serverUnit, /^MemoryHigh=224M$/m);
  assert.doesNotMatch(serverUnit, /lookout-collector\/master-key/);
  assert.match(collectorUnit, /^Environment=LOOKOUT_MASTER_KEY_FILE=\/etc\/lookout-collector\/master-key$/m);
  assert.doesNotMatch(collectorUnit, /^Environment=LOOKOUT_MASTER_KEY_FILE=\/etc\/lookout\/master-key$/m);
  assert.match(collectorUnit, /^Type=simple$/m);
  assert.match(collectorUnit, /collector-run \/etc\/lookout-collector\/identity http:\/\/127\.0\.0\.1:4173/);
  assert.match(collectorUnit, /^Restart=on-failure$/m);
  assert.match(collectorUnit, /^MemoryMax=128M$/m);
  assert.match(collectorUnit, /^MemoryHigh=112M$/m);
  assert.match(collectorUnit, /^User=lookout-collector$/m);
  assert.match(collectorUnit, /^CapabilityBoundingSet=$/m);
  assert.doesNotMatch(collectorUnit, /^ProcSubset=pid$/m, 'collector must retain access to the kernel boot ID required by journalctl');
  assert.doesNotMatch(collectorUnit, /^SupplementaryGroups=/m);
  assert.doesNotMatch(collectorUnit, /auditctl|CAP_[A-Z_]+|User=root/);
  assert.match(updateUnit, /^User=root$/m);
  assert.match(updateUnit, /updater-current\/scripts\/lookout-update\.js/);
  assert.match(updateUnit, /^RuntimeDirectory=lookout-update$/m);
  assert.match(updateUnit, /^RuntimeDirectoryMode=0700$/m);
  assert.match(updateUnit, /^Environment=LOOKOUT_UPDATE_LOCK=\/run\/lookout-update\/update\.lock$/m);
  assert.match(updateUnit, /^ReadWritePaths=.* -\/run\/lookout-update$/m);
  assert.doesNotMatch(updateUnit, /\/run\/lookout-update\.lock/);
  assert.match(updateUnit, /^ProtectSystem=strict$/m);
  assert.match(updateTimer, /^OnUnitActiveSec=1min$/m);
  assert.match(updateTimer, /^OnActiveSec=1min$/m);
  assert.match(updateTimer, /^RandomizedDelaySec=30s$/m);
  assert.equal(mode(await fs.stat(path.join(root, 'etc/lookout-update/update.json'))), 0o600);
  const updateConfig = JSON.parse(await fs.readFile(path.join(root, 'etc/lookout-update/update.json'), 'utf8'));
  assert.equal(updateConfig.channelUrl, 'https://app.devlookout.com/v1/updates/stable');
  assert.deepEqual(updateConfig.artifactOrigins, ['https://github.com']);
  assert.match(updateConfig.trustedKeys[0].publicKeySpkiPem, /BEGIN PUBLIC KEY/);
  assert.equal(Object.hasOwn(updateConfig.trustedKeys[0], 'privateKeyPem'), false);
  assert.equal(await fs.realpath(path.join(root, 'opt/lookout/updater-current')), currentRelease);

  const remotePublicKey = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
  const remoteCollectorId = stableId('collector', remotePublicKey);
  const collectorRegistryFile = path.join(configDirectory, 'collectors.json');
  const collectorRegistry = JSON.parse(await fs.readFile(collectorRegistryFile, 'utf8'));
  collectorRegistry.collectors[remoteCollectorId] = remotePublicKey;
  await fs.writeFile(collectorRegistryFile, `${JSON.stringify(collectorRegistry)}\n`, { mode: 0o600 });

  await fs.writeFile(path.join(root, 'etc/systemd/system/lookout-collector.timer'), '[Timer]\nOnUnitActiveSec=5min\n', { mode: 0o644 });
  const repeatEnvironment = { ...environment, LOOKOUT_TEST_SKIP_DETECTION_VALIDATION: '1' };
  assertSucceeded(run(installer, [], { environment: { ...repeatEnvironment, LOOKOUT_JOURNAL_GROUP: 'systemd-journal' } }));
  assert.match(await fs.readFile(path.join(root, 'etc/systemd/system/lookout-collector.service'), 'utf8'), /^SupplementaryGroups=systemd-journal$/m);
  assert.equal(JSON.parse(await fs.readFile(collectorRegistryFile, 'utf8')).collectors[remoteCollectorId], remotePublicKey, 'upgrade removed a remote collector registration');
  await assert.rejects(fs.access(path.join(root, 'etc/systemd/system/lookout-collector.timer')), { code: 'ENOENT' });
  assertSucceeded(run(installer, [], { environment: repeatEnvironment }));

  const installerSource = await fs.readFile(installer, 'utf8');
  const collectorEnable = installerSource.indexOf('systemctl enable lookout-collector.service');
  const collectorRestart = installerSource.indexOf('systemctl restart lookout-collector.service');
  assert.ok(collectorEnable >= 0 && collectorRestart > collectorEnable, 'collector upgrades must enable and then explicitly restart the loaded service');
  assert.doesNotMatch(installerSource, /systemctl enable --now lookout-collector\.service/);
  assert.match(installerSource, /COLLECTOR_WAS_ENABLED:-0.*= 1[\s\S]*systemctl restart lookout-collector\.service/, 'rollback must recover a previously enabled collector service');
  assert.match(installerSource, /previous release was selected but one or more services failed to recover/, 'rollback service failures must not be masked');

  const config = JSON.parse(await fs.readFile(path.join(configDirectory, 'lookout.json'), 'utf8'));
  assert.equal(config.storage.requireEncryption, true);
  assert.equal(config.storage.retentionDays, 7);
  assert.equal(config.storage.auditRetentionDays, 7);
  assert.equal(config.storage.maximumPercent, 2);
  assert.equal(config.server.allowLoopbackAdmin, false, 'loopback trust can become remote admin through a reverse proxy');
  assert.equal(config.auth.credentialsFile, '/etc/lookout/credentials.json');
  const credentials = JSON.parse(await fs.readFile(credentialsFile, 'utf8'));
  assert.equal(credentials.credentials.length, 2);
  for (const credential of credentials.credentials) {
    assert.match(credential.tokenHash, /^[a-f0-9]{64}$/);
    assert.equal(Object.hasOwn(credential, 'token'), false);
  }

  const administratorToken = (await fs.readFile(administratorTokenFile, 'utf8')).trim();
  const collectorToken = (await fs.readFile(collectorTokenFile, 'utf8')).trim();
  assert.notEqual(administratorToken, collectorToken);
  assert.notEqual(await fs.readFile(masterKeyFile, 'utf8'), await fs.readFile(collectorMasterKeyFile, 'utf8'), 'server and collector encryption keys must be separate');
  const installedFiles = await readTree(path.join(root, 'etc'));
  for (const [relative, contents] of installedFiles) {
    if (!relative.endsWith('admin-token')) assert.equal(contents.includes(administratorToken), false, `administrator token leaked into ${relative}`);
    if (!relative.endsWith('api-token')) assert.equal(contents.includes(collectorToken), false, `collector token leaked into ${relative}`);
  }
  assert.ok((await fs.readlink(path.join(root, 'opt/lookout/current'))).startsWith(path.join(root, 'opt/lookout/releases/')));
  assert.equal(JSON.parse(await fs.readFile(path.join(root, 'opt/lookout/install-manifest.json'), 'utf8')).product, 'lookout');
  for (const relative of ['usr/local/bin/lookout', 'usr/local/sbin/lookout-uninstall']) {
    const entrypoint = path.join(root, relative);
    assert.equal(mode(await fs.stat(entrypoint)), 0o755);
    assert.match(await fs.readFile(entrypoint, 'utf8'), /^#!\/bin\/sh/);
  }

  const stableSecrets = new Map();
  for (const filename of [masterKeyFile, credentialsFile, administratorTokenFile, collectorTokenFile, collectorMasterKeyFile, privateKeyFile]) {
    stableSecrets.set(filename, await fs.readFile(filename, 'utf8'));
  }
  config.storage.retentionDays = 77;
  await fs.writeFile(path.join(configDirectory, 'lookout.json'), `${JSON.stringify(config)}\n`, { mode: 0o600 });

  assertSucceeded(run(installer, [], { environment: repeatEnvironment }));
  for (const [filename, contents] of stableSecrets) assert.equal(await fs.readFile(filename, 'utf8'), contents, `${filename} changed during reinstall`);
  assert.equal(JSON.parse(await fs.readFile(path.join(configDirectory, 'lookout.json'), 'utf8')).storage.retentionDays, 77, 'reinstall overwrote local tuning');

  assertSucceeded(run(uninstaller, ['--root', root]));
  await assert.rejects(fs.access(path.join(root, 'opt/lookout')), { code: 'ENOENT' });
  await assert.rejects(fs.access(path.join(root, 'usr/local/bin/lookout')), { code: 'ENOENT' });
  await assert.rejects(fs.access(path.join(root, 'usr/local/sbin/lookout-uninstall')), { code: 'ENOENT' });
  assert.equal(JSON.parse(await fs.readFile(path.join(configDirectory, 'lookout.json'), 'utf8')).storage.retentionDays, 77);

  assertSucceeded(run(installer, [], { environment: repeatEnvironment }));
  for (const [filename, contents] of stableSecrets) assert.equal(await fs.readFile(filename, 'utf8'), contents, `${filename} changed after uninstall/reinstall`);
});

test('uninstall preserves configuration and data, is idempotent, and never traverses an application symlink', async (t) => {
  const root = await temporaryRoot('uninstall-preserve');
  const outside = await temporaryRoot('uninstall-outside');
  t.after(() => Promise.all([
    fs.rm(root, { recursive: true, force: true }),
    fs.rm(outside, { recursive: true, force: true })
  ]));

  const outsideMarker = await writeFixture(outside, 'must-survive', 'outside');
  await fs.mkdir(path.join(root, 'opt'), { recursive: true });
  await fs.symlink(outside, path.join(root, 'opt', 'lookout'));
  await writeFixture(root, 'etc/systemd/system/lookout.service');
  await writeFixture(root, 'etc/systemd/system/lookout-collector.service');
  await writeFixture(root, 'etc/systemd/system/lookout-collector.timer');
  await writeFixture(root, 'etc/systemd/system/lookout-update.service');
  await writeFixture(root, 'etc/systemd/system/lookout-update.timer');
  const preserved = [
    await writeFixture(root, 'etc/lookout/lookout.json'),
    await writeFixture(root, 'etc/lookout-collector/collector.json'),
    await writeFixture(root, 'var/lib/lookout/events.jsonl'),
    await writeFixture(root, 'var/lib/lookout-collector/state.json'),
    await writeFixture(root, 'etc/lookout-update/update.json')
  ];

  const first = run(uninstaller, ['--root', root]);
  assertSucceeded(first);
  await assert.rejects(fs.lstat(path.join(root, 'opt', 'lookout')), { code: 'ENOENT' });
  assert.equal(await fs.readFile(outsideMarker, 'utf8'), 'outside');
  for (const filename of preserved) assert.equal(await fs.readFile(filename, 'utf8'), 'fixture');
  await assert.rejects(fs.access(path.join(root, 'etc/systemd/system/lookout.service')), { code: 'ENOENT' });
  await assert.rejects(fs.access(path.join(root, 'etc/systemd/system/lookout-update.service')), { code: 'ENOENT' });
  await assert.rejects(fs.access(path.join(root, 'etc/systemd/system/lookout-update.timer')), { code: 'ENOENT' });

  assertSucceeded(run(uninstaller, ['--root', root]));
  for (const filename of preserved) assert.equal(await fs.readFile(filename, 'utf8'), 'fixture');
});

test('installer rejects path traversal, relative destinations, and a symlinked offline root before mutation', async (t) => {
  const root = await temporaryRoot('install-safety');
  const symlinkRoot = `${root}-link`;
  await fs.symlink(root, symlinkRoot);
  t.after(async () => {
    await fs.rm(symlinkRoot, { force: true });
    await fs.rm(root, { recursive: true, force: true });
  });
  const base = {
    LOOKOUT_ROOT: root,
    LOOKOUT_SOURCE_DIR: repository,
    LOOKOUT_INSTALL_NODE: 'never',
    LOOKOUT_USE_SOURCE_DEPENDENCIES: '1',
    LOOKOUT_SKIP_START: '1'
  };
  for (const environment of [
    { ...base, LOOKOUT_PREFIX: '/opt/../escape' },
    { ...base, LOOKOUT_ADMIN_TOKEN_FILE: 'relative-token' },
    { ...base, LOOKOUT_ROOT: `${root}/../escape` },
    { ...base, LOOKOUT_ROOT: symlinkRoot }
  ]) {
    const result = run(installer, [], { environment });
    assert.notEqual(result.status, 0, `unsafe path unexpectedly succeeded:\n${result.stdout}`);
  }
  for (const relative of ['opt/lookout', 'etc/lookout', 'var/lib/lookout']) {
    await assert.rejects(fs.access(path.join(root, relative)), { code: 'ENOENT' });
  }
});

test('installer refuses to replace an invalid existing collector registry', async (t) => {
  const root = await temporaryRoot('invalid-collector-registry');
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const source = await minimalInstallerSource(root);
  const environment = {
    PATH: await linuxTestPath(root),
    LOOKOUT_ROOT: root,
    LOOKOUT_SOURCE_DIR: source,
    LOOKOUT_INSTALL_NODE: 'never',
    LOOKOUT_USE_SOURCE_DEPENDENCIES: '1',
    LOOKOUT_SKIP_START: '1',
    LOOKOUT_TEST_SKIP_DETECTION_VALIDATION: '1'
  };
  assertSucceeded(run(installer, [], { environment }));
  const registry = path.join(root, 'etc/lookout/collectors.json');
  const invalid = '{"schemaVersion":1,"collectors":{"collector_forged":"not a public key"}}\n';
  await fs.writeFile(registry, invalid, { mode: 0o600 });
  const reinstall = run(installer, [], { environment });
  assert.notEqual(reinstall.status, 0);
  assert.match(reinstall.stderr, /Collector registry key .* is invalid/);
  assert.equal(await fs.readFile(registry, 'utf8'), invalid, 'invalid registry was overwritten instead of failing closed');
});

test('collector-only role creates no central-server state and preserves its identity state', async (t) => {
  const root = await temporaryRoot('collector-only');
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const source = await minimalInstallerSource(root);
  const ca = await writeFixture(root, 'staging/fleet-ca.pem', 'test-only-ca');
  const environment = {
    PATH: await linuxTestPath(root),
    LOOKOUT_ROOT: root,
    LOOKOUT_SOURCE_DIR: source,
    LOOKOUT_INSTALL_NODE: 'never',
    LOOKOUT_USE_SOURCE_DEPENDENCIES: '1',
    LOOKOUT_SKIP_START: '1',
    LOOKOUT_TEST_SKIP_DETECTION_VALIDATION: '1',
    LOOKOUT_ROLE: 'collector',
    LOOKOUT_COLLECTOR_SERVER_URL: 'https://central.private:4173',
    LOOKOUT_COLLECTOR_CA_SOURCE: ca,
    LOOKOUT_COLLECTOR_ASSET_ID: 'generic:node-02',
    LOOKOUT_DEPLOYMENT_ID: 'fleet-01',
    LOOKOUT_SKIP_ENROLLMENT: '1'
  };
  assertSucceeded(run(installer, [], { environment }));
  for (const relative of ['etc/lookout', 'var/lib/lookout', 'etc/systemd/system/lookout.service']) {
    await assert.rejects(fs.access(path.join(root, relative)), { code: 'ENOENT' });
  }
  const collectorConfig = path.join(root, 'etc/lookout-collector');
  const master = await fs.readFile(path.join(collectorConfig, 'master-key'), 'utf8');
  assert.equal(await fs.readFile(path.join(collectorConfig, 'ca.pem'), 'utf8'), 'test-only-ca');
  const unit = await fs.readFile(path.join(root, 'etc/systemd/system/lookout-collector.service'), 'utf8');
  assert.match(unit, /LOOKOUT_COLLECTOR_CA_FILE=\/etc\/lookout-collector\/ca\.pem/);
  assert.match(unit, /collector-run \/etc\/lookout-collector https:\/\/central\.private:4173/);
  assert.doesNotMatch(unit, /LOOKOUT_API_TOKEN_FILE/);
  assert.match(unit, /^After=network-online\.target$/m);
  assert.doesNotMatch(unit, /(?:After|Requires)=lookout\.service/);
  assert.equal(JSON.parse(await fs.readFile(path.join(root, 'opt/lookout/install-manifest.json'), 'utf8')).role, 'collector');
  assertSucceeded(run(installer, [], { environment }));
  assert.equal(await fs.readFile(path.join(collectorConfig, 'master-key'), 'utf8'), master);
});

test('central role binds TLS externally while keeping collector transport pinned', async (t) => {
  const root = await temporaryRoot('central-tls');
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const source = await minimalInstallerSource(root);
  const certificate = await writeFixture(root, 'staging/server.crt', 'test-certificate');
  const privateKey = await writeFixture(root, 'staging/server.key', 'test-private-key');
  const environment = {
    PATH: await linuxTestPath(root), LOOKOUT_ROOT: root, LOOKOUT_SOURCE_DIR: source,
    LOOKOUT_INSTALL_NODE: 'never', LOOKOUT_USE_SOURCE_DEPENDENCIES: '1', LOOKOUT_SKIP_START: '1', LOOKOUT_TEST_SKIP_DETECTION_VALIDATION: '1',
    LOOKOUT_ROLE: 'central', LOOKOUT_BIND_HOST: '0.0.0.0',
    LOOKOUT_TLS_CERT_SOURCE: certificate, LOOKOUT_TLS_KEY_SOURCE: privateKey
  };
  assertSucceeded(run(installer, [], { environment }));
  const config = JSON.parse(await fs.readFile(path.join(root, 'etc/lookout/lookout.json'), 'utf8'));
  assert.equal(config.server.host, '0.0.0.0');
  assert.deepEqual(config.server.tls, { certificateFile: '/etc/lookout/tls/server.crt', privateKeyFile: '/etc/lookout/tls/server.key' });
  assert.equal(await fs.readFile(path.join(root, 'etc/lookout/tls/server.crt'), 'utf8'), 'test-certificate');
  assert.equal(mode(await fs.stat(path.join(root, 'etc/lookout/tls/server.key'))), 0o600);
  const collectorUnit = await fs.readFile(path.join(root, 'etc/systemd/system/lookout-collector.service'), 'utf8');
  assert.match(collectorUnit, /LOOKOUT_COLLECTOR_CA_FILE=\/etc\/lookout-collector\/ca\.pem/);
  assert.match(collectorUnit, /collector-run \/etc\/lookout-collector\/identity https:\/\/0\.0\.0\.0:4173/);
});

test('installation provisions a tenant-scoped outbound console credential without exposing it', async (t) => {
  const root = await temporaryRoot('console-sync');
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const source = await minimalInstallerSource(root);
  const credential = await writeFixture(root, 'staging/console-token', 'tenant-secret-token\n');
  await fs.chmod(credential, 0o600);
  const environment = {
    PATH: await linuxTestPath(root), LOOKOUT_ROOT: root, LOOKOUT_SOURCE_DIR: source,
    LOOKOUT_INSTALL_NODE: 'never', LOOKOUT_USE_SOURCE_DEPENDENCIES: '1', LOOKOUT_SKIP_START: '1', LOOKOUT_TEST_SKIP_DETECTION_VALIDATION: '1',
    LOOKOUT_CONSOLE_ENDPOINT: 'https://console.example.test/v1/snapshots',
    LOOKOUT_CONSOLE_CREDENTIAL_SOURCE: credential,
    LOOKOUT_CONSOLE_DEPLOYMENT_ID: 'deployment-tenant-a'
  };
  const installed = run(installer, [], { environment });
  assertSucceeded(installed);
  assert.doesNotMatch(`${installed.stdout}\n${installed.stderr}`, /tenant-secret-token/);
  const config = JSON.parse(await fs.readFile(path.join(root, 'etc/lookout/lookout.json'), 'utf8'));
  assert.deepEqual(config.consoleSync, {
    enabled: true, endpoint: 'https://console.example.test/v1/snapshots',
    credentialReference: 'console-token', deploymentId: 'deployment-tenant-a'
  });
  assert.equal(config.secrets.files['console-token'], '/etc/lookout/console-token');
  const installedCredential = path.join(root, 'etc/lookout/console-token');
  assert.equal(await fs.readFile(installedCredential, 'utf8'), 'tenant-secret-token\n');
  assert.equal(mode(await fs.stat(installedCredential)), 0o600);

  const dataDirectory = path.join(root, 'var/lib/lookout');
  const releaseBeforeAttachment = await fs.realpath(path.join(root, 'opt/lookout/current'));
  await fs.writeFile(path.join(dataDirectory, 'console-sync.jsonl'), 'encrypted-old-snapshot\n', { mode: 0o600 });
  await fs.writeFile(path.join(dataDirectory, 'console-sync.checkpoint.json'), 'encrypted-old-checkpoint\n', { mode: 0o600 });
  const certificate = await writeFixture(root, 'staging/transition.crt', 'transition-certificate');
  const privateKey = await writeFixture(root, 'staging/transition.key', 'transition-private-key');
  const transitioned = run(installer, [], { environment: {
    ...environment,
    LOOKOUT_ROLE: 'central',
    LOOKOUT_BIND_HOST: '10.0.0.5',
    LOOKOUT_TLS_CERT_SOURCE: certificate,
    LOOKOUT_TLS_KEY_SOURCE: privateKey,
    LOOKOUT_CONSOLE_DEPLOYMENT_ID: 'deployment-tenant-b',
    LOOKOUT_RECONCILE_CONFIG: '1',
    LOOKOUT_ATTACH_CONSOLE_ONLY: '1'
  } });
  assertSucceeded(transitioned);
  assert.equal(await fs.realpath(path.join(root, 'opt/lookout/current')), releaseBeforeAttachment);
  const transitionedConfig = JSON.parse(await fs.readFile(path.join(root, 'etc/lookout/lookout.json'), 'utf8'));
  assert.equal(transitionedConfig.server.host, '10.0.0.5');
  assert.deepEqual(transitionedConfig.server.tls, { certificateFile: '/etc/lookout/tls/server.crt', privateKeyFile: '/etc/lookout/tls/server.key' });
  assert.equal(transitionedConfig.consoleSync.deploymentId, 'deployment-tenant-b');
  await assert.rejects(fs.access(path.join(dataDirectory, 'console-sync.jsonl')), { code: 'ENOENT' });
  await assert.rejects(fs.access(path.join(dataDirectory, 'console-sync.checkpoint.json')), { code: 'ENOENT' });
  const archives = await fs.readdir(path.join(root, 'var/lib/lookout-install/console-outbox-archive'));
  assert.equal(archives.length, 1);
  const archive = path.join(root, 'var/lib/lookout-install/console-outbox-archive', archives[0]);
  assert.equal(await fs.readFile(path.join(archive, 'console-sync.jsonl'), 'utf8'), 'encrypted-old-snapshot\n');
  assert.equal(await fs.readFile(path.join(archive, 'console-sync.checkpoint.json'), 'utf8'), 'encrypted-old-checkpoint\n');
  const transition = JSON.parse(await fs.readFile(path.join(archive, 'transition.json'), 'utf8'));
  assert.equal(transition.previousDeploymentId, 'deployment-tenant-a');
  assert.equal(transition.nextDeploymentId, 'deployment-tenant-b');

  const incomplete = run(installer, [], { environment: { ...environment, LOOKOUT_CONSOLE_DEPLOYMENT_ID: '' } });
  assert.notEqual(incomplete.status, 0);
  assert.match(incomplete.stderr, /LOOKOUT_CONSOLE_DEPLOYMENT_ID is invalid/);
});

test('purge removes only the allowlisted Lookout state below an offline root', async (t) => {
  const root = await temporaryRoot('uninstall-purge');
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  for (const relative of [
    'opt/lookout/app.js',
    'etc/lookout/lookout.json',
    'etc/lookout-collector/collector.json',
    'var/lib/lookout/events.jsonl',
    'var/lib/lookout-collector/state.json',
    'etc/systemd/system/lookout.service'
  ]) await writeFixture(root, relative);
  const unrelated = await writeFixture(root, 'var/lib/unrelated/must-survive');

  assertSucceeded(run(uninstaller, ['--root', root, '--purge', '--yes']));
  for (const relative of ['opt/lookout', 'etc/lookout', 'etc/lookout-collector', 'var/lib/lookout', 'var/lib/lookout-collector']) {
    await assert.rejects(fs.access(path.join(root, relative)), { code: 'ENOENT' });
  }
  assert.equal(await fs.readFile(unrelated, 'utf8'), 'fixture');
});

test('complete removal provides an explicit clean-install state', async (t) => {
  const root = await temporaryRoot('uninstall-complete');
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await writeFixture(root, 'opt/lookout/app.js');
  await writeFixture(root, 'etc/lookout/lookout.json');
  await writeFixture(root, 'var/lib/lookout/events.jsonl');
  await writeFixture(root, 'var/lib/lookout-install/manifest');
  const unrelated = await writeFixture(root, 'var/lib/unrelated/must-survive');

  const result = run(uninstaller, ['--root', root, '--complete', '--yes']);
  assertSucceeded(result);
  assert.match(result.stdout, /completely removed/);
  for (const relative of ['opt/lookout', 'etc/lookout', 'var/lib/lookout', 'var/lib/lookout-install']) await assert.rejects(fs.access(path.join(root, relative)), { code: 'ENOENT' });
  assert.equal(await fs.readFile(unrelated, 'utf8'), 'fixture');
});

test('fresh reinstall purge preserves orchestration state while removing installed Lookout', async (t) => {
  const root = await temporaryRoot('fresh-reinstall-purge');
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await writeFixture(root, 'opt/lookout/app.js');
  const orchestrationState = await writeFixture(root, 'var/lib/lookout-install/orchestration-session.json');

  assertSucceeded(run(uninstaller, ['--root', root, '--purge', '--yes'], {
    environment: { LOOKOUT_SKIP_CONSOLE_NOTIFICATION: '1', LOOKOUT_PRESERVE_INSTALL_STATE: '1' }
  }));

  await assert.rejects(fs.access(path.join(root, 'opt/lookout')), { code: 'ENOENT' });
  assert.equal(await fs.readFile(orchestrationState, 'utf8'), 'fixture');
});

test('uninstall dry-run and invalid roots cannot mutate the filesystem', async (t) => {
  const root = await temporaryRoot('uninstall-safety');
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const application = await writeFixture(root, 'opt/lookout/app.js');

  assertSucceeded(run(uninstaller, ['--root', root, '--purge', '--yes', '--dry-run']));
  assert.equal(await fs.readFile(application, 'utf8'), 'fixture');

  for (const invalidRoot of ['relative-root', `${root}/../escape`, `${root}/./escape`]) {
    const result = run(uninstaller, ['--root', invalidRoot, '--purge', '--yes']);
    assert.notEqual(result.status, 0, `unexpected success for ${invalidRoot}`);
  }
  assert.equal(await fs.readFile(application, 'utf8'), 'fixture');

  const unconfirmed = run(uninstaller, ['--root', root, '--purge']);
  assert.notEqual(unconfirmed.status, 0);
  assert.match(unconfirmed.stderr, /interactive terminal|--yes/);
  assert.equal(await fs.readFile(application, 'utf8'), 'fixture');
});
