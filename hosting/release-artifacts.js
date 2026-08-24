'use strict';

const fs = require('node:fs');
const path = require('node:path');

const definitions = [
  ['orchestrationTar', 'lookout-orchestration-{version}.tar.gz', 'application/gzip'],
  ['orchestrationZip', 'lookout-orchestration-{version}.zip', 'application/zip'],
  ['linuxTargetAmd64', 'lookout-target-linux-amd64-{version}.tar.gz', 'application/gzip'],
  ['linuxTargetArm64', 'lookout-target-linux-arm64-{version}.tar.gz', 'application/gzip']
];

function artifactMetadata({ name, digest, contentType, version, publicBase, filename = null }) {
  if (!/^[a-f0-9]{64}$/.test(digest || '')) throw new Error(`Artifact digest is invalid for ${name}`);
  const route = `/releases/${version}/${digest}/${name}`;
  return { name, filename, digest, route, url: new URL(route, publicBase).toString(), contentType, stat: filename ? fs.statSync(filename) : null };
}

function loadReleaseArtifacts({ version, publicBase, root, manifestPath = '' }) {
  let manifest = null;
  if (manifestPath) {
    manifest = JSON.parse(fs.readFileSync(path.resolve(manifestPath), 'utf8'));
    if (manifest?.schemaVersion !== 1 || manifest.releaseVersion !== version || !manifest.artifacts || Array.isArray(manifest.artifacts)) throw new Error('Release artifact manifest is invalid');
    const expectedKeys = definitions.map(([key]) => key).sort();
    if (JSON.stringify(Object.keys(manifest.artifacts).sort()) !== JSON.stringify(expectedKeys)) throw new Error('Release artifact manifest has unexpected entries');
  }
  const artifacts = {};
  for (const [key, pattern, contentType] of definitions) {
    const name = pattern.replace('{version}', version);
    if (manifest) {
      const entry = manifest.artifacts[key];
      if (!entry || entry.name !== name || Object.keys(entry).sort().join(',') !== 'digest,name') throw new Error(`Release artifact manifest entry is invalid: ${key}`);
      artifacts[key] = artifactMetadata({ name, digest: entry.digest, contentType, version, publicBase });
    } else {
      const filename = path.join(root, name);
      const digest = fs.readFileSync(`${filename}.sha256`, 'utf8').trim();
      artifacts[key] = artifactMetadata({ name, digest, contentType, version, publicBase, filename });
    }
  }
  return Object.freeze(artifacts);
}

module.exports = { loadReleaseArtifacts };
