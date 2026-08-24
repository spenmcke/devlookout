'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { install } = require('../install/workstation-cli-install');

async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-cli-installer-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const source = path.join(root, 'source');
  for (const directory of ['bin', 'install', 'src/cli', 'tools', 'node_modules/yaml']) await fs.mkdir(path.join(source, directory), { recursive: true });
  await fs.writeFile(path.join(source, 'package.json'), '{"version":"9.8.7"}\n');
  await fs.writeFile(path.join(source, 'bin/lookout.js'), '#!/usr/bin/env node\n');
  await fs.writeFile(path.join(source, 'install/fleet.js'), "'use strict';\n");
  await fs.writeFile(path.join(source, 'install/workstation-link.js'), "'use strict';\n");
  await fs.writeFile(path.join(source, 'src/cli/workstation-prepare.js'), "'use strict';\n");
  await fs.writeFile(path.join(source, 'tools/lookout-support-report.js'), "'use strict';\n");
  await fs.writeFile(path.join(source, 'node_modules/yaml/package.json'), '{}\n');
  const data = path.join(root, 'data');
  const bin = path.join(root, 'bin');
  const environment = {
    LOOKOUT_CLI_SOURCE_DIR: source,
    LOOKOUT_CLI_RELEASE_VERSION: 'v9.8.7',
    LOOKOUT_CLI_ARTIFACT_SHA256: 'a'.repeat(64),
    LOOKOUT_CLI_TARGET_AMD64_URL: 'https://releases.example/lookout-linux-amd64.tar.gz',
    LOOKOUT_CLI_TARGET_AMD64_SHA256: 'b'.repeat(64),
    LOOKOUT_CLI_TARGET_ARM64_URL: 'https://releases.example/lookout-linux-arm64.tar.gz',
    LOOKOUT_CLI_TARGET_ARM64_SHA256: 'd'.repeat(64),
    LOOKOUT_CLI_NODE_PATH: process.execPath,
    LOOKOUT_CLI_DATA_DIR: data,
    LOOKOUT_CLI_BIN_DIR: bin
  };
  return { root, data, bin, environment };
}

test('workstation CLI installer creates an immutable per-user release and launcher', async (t) => {
  const item = await fixture(t);
  const result = await install({ environment: item.environment, platform: 'linux', home: item.root });
  assert.equal(result.version, 'v9.8.7');
  assert.equal((await fs.lstat(result.executable)).isSymbolicLink(), true);
  const marker = JSON.parse(await fs.readFile(path.join(result.releaseDirectory, '.lookout-cli-release.json'), 'utf8'));
  assert.deepEqual(marker.targets, {
    amd64: { url: 'https://releases.example/lookout-linux-amd64.tar.gz', sha256: 'b'.repeat(64) },
    arm64: { url: 'https://releases.example/lookout-linux-arm64.tar.gz', sha256: 'd'.repeat(64) }
  });
  assert.equal((await install({ environment: item.environment, platform: 'linux', home: item.root })).releaseDirectory, result.releaseDirectory);
});

test('workstation CLI installer does not replace an unrelated executable', async (t) => {
  const item = await fixture(t);
  await fs.mkdir(item.bin, { recursive: true });
  await fs.writeFile(path.join(item.bin, 'lookout'), 'unrelated\n');
  await assert.rejects(() => install({ environment: item.environment, platform: 'linux', home: item.root }), /Refusing to replace/);
});

test('workstation CLI installer requires the support report tool', async (t) => {
  const item = await fixture(t);
  await fs.rm(path.join(item.environment.LOOKOUT_CLI_SOURCE_DIR, 'tools/lookout-support-report.js'));
  await assert.rejects(() => install({ environment: item.environment, platform: 'linux', home: item.root }), /Support report tool/);
});

test('workstation CLI installer requires the preparation tool', async (t) => {
  const item = await fixture(t);
  await fs.rm(path.join(item.environment.LOOKOUT_CLI_SOURCE_DIR, 'src/cli/workstation-prepare.js'));
  await assert.rejects(() => install({ environment: item.environment, platform: 'linux', home: item.root }), /Workstation preparation tool/);
});

test('workstation CLI installer does not replace an unrelated symlink', async (t) => {
  const item = await fixture(t);
  await fs.mkdir(item.bin, { recursive: true });
  const unrelated = path.join(item.root, 'unrelated');
  await fs.writeFile(unrelated, 'unrelated\n');
  await fs.symlink(unrelated, path.join(item.bin, 'lookout'));
  await assert.rejects(() => install({ environment: item.environment, platform: 'linux', home: item.root }), /Refusing to replace/);
});

test('workstation CLI installer upgrades an owned symlink', async (t) => {
  const item = await fixture(t);
  const first = await install({ environment: item.environment, platform: 'linux', home: item.root });
  const environment = { ...item.environment, LOOKOUT_CLI_RELEASE_VERSION: 'v9.8.8', LOOKOUT_CLI_ARTIFACT_SHA256: 'c'.repeat(64) };
  const second = await install({ environment, platform: 'linux', home: item.root });
  assert.notEqual(second.releaseDirectory, first.releaseDirectory);
  assert.equal(await fs.readlink(second.executable), path.join(second.releaseDirectory, 'bin', 'lookout.js'));
});

test('workstation CLI installer pins Node and replaces its Windows launcher', async (t) => {
  const item = await fixture(t);
  const first = await install({ environment: item.environment, platform: 'win32', home: item.root });
  assert.match(await fs.readFile(first.executable, 'utf8'), new RegExp(`@"${process.execPath.replaceAll('\\', '\\\\')}"`));
  const environment = { ...item.environment, LOOKOUT_CLI_RELEASE_VERSION: 'v9.8.8', LOOKOUT_CLI_ARTIFACT_SHA256: 'c'.repeat(64) };
  const second = await install({ environment, platform: 'win32', home: item.root });
  assert.notEqual(second.releaseDirectory, first.releaseDirectory);
  assert.match(await fs.readFile(second.executable, 'utf8'), /v9\.8\.8/);
});

test('workstation CLI installer accepts a Homebrew-style Node symlink and pins its target', async (t) => {
  const item = await fixture(t);
  const nodeLink = path.join(item.root, 'node');
  await fs.symlink(process.execPath, nodeLink);
  item.environment.LOOKOUT_CLI_NODE_PATH = nodeLink;
  const result = await install({ environment: item.environment, platform: 'win32', home: item.root });
  assert.match(await fs.readFile(result.executable, 'utf8'), new RegExp(process.execPath.replaceAll('\\', '\\\\')));
  assert.doesNotMatch(await fs.readFile(result.executable, 'utf8'), new RegExp(nodeLink.replaceAll('\\', '\\\\')));
});
