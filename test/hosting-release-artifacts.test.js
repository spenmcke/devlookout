'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { loadReleaseArtifacts } = require('../hosting/release-artifacts');

const version = 'v9.8.7';
const names = {
  orchestrationTar: `lookout-orchestration-${version}.tar.gz`,
  orchestrationZip: `lookout-orchestration-${version}.zip`,
  linuxTargetAmd64: `lookout-target-linux-amd64-${version}.tar.gz`,
  linuxTargetArm64: `lookout-target-linux-arm64-${version}.tar.gz`
};

test('release artifacts load from local files or a small external-storage manifest', async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-release-artifacts-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const manifest = { schemaVersion: 1, releaseVersion: version, artifacts: {} };
  for (const [key, name] of Object.entries(names)) {
    const bytes = Buffer.from(key);
    const digest = crypto.createHash('sha256').update(bytes).digest('hex');
    await fs.writeFile(path.join(root, name), bytes);
    await fs.writeFile(path.join(root, `${name}.sha256`), `${digest}\n`);
    manifest.artifacts[key] = { name, digest };
  }

  const local = loadReleaseArtifacts({ version, publicBase: new URL('https://app.example.test'), root });
  assert.equal(local.orchestrationTar.stat.size, Buffer.byteLength('orchestrationTar'));
  assert.equal(local.orchestrationTar.url, `https://app.example.test${local.orchestrationTar.route}`);

  const manifestPath = path.join(root, 'release-manifest.json');
  await fs.writeFile(manifestPath, JSON.stringify(manifest));
  const external = loadReleaseArtifacts({ version, publicBase: new URL('https://app.example.test'), root: '/unused', manifestPath });
  assert.equal(external.orchestrationTar.filename, null);
  assert.equal(external.orchestrationTar.stat, null);
  assert.equal(external.linuxTargetArm64.digest, manifest.artifacts.linuxTargetArm64.digest);

  manifest.artifacts.unexpected = { name: 'unexpected', digest: '0'.repeat(64) };
  await fs.writeFile(manifestPath, JSON.stringify(manifest));
  assert.throws(() => loadReleaseArtifacts({ version, publicBase: new URL('https://app.example.test'), root: '/unused', manifestPath }), /unexpected entries/);
});
