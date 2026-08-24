'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const repository = path.resolve(__dirname, '..');
function run(command, arguments_, environment = {}) {
  return spawnSync(command, arguments_, { cwd: repository, encoding: 'utf8', env: { PATH: process.env.PATH, ...environment } });
}

async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-cli-bootstrap-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const payload = path.join(root, 'payload', 'lookout-orchestration-v9.8.7');
  for (const directory of ['bin', 'install', 'src/cli', 'tools', 'node_modules/yaml']) await fs.mkdir(path.join(payload, directory), { recursive: true });
  await fs.writeFile(path.join(payload, 'package.json'), '{"name":"lookout"}\n');
  await fs.writeFile(path.join(payload, 'bin/lookout.js'), "'use strict';\n");
  await fs.writeFile(path.join(payload, 'install/fleet.js'), "'use strict';\n");
  await fs.writeFile(path.join(payload, 'install/workstation-link.js'), "'use strict';\n");
  await fs.writeFile(path.join(payload, 'src/cli/workstation-prepare.js'), "'use strict';\n");
  await fs.writeFile(path.join(payload, 'tools/lookout-support-report.js'), "'use strict';\n");
  await fs.writeFile(path.join(payload, 'node_modules/yaml/package.json'), '{"name":"yaml"}\n');
  await fs.writeFile(path.join(payload, 'install/workstation-cli-install.js'), "'use strict';\nrequire('node:fs').writeFileSync(process.env.LOOKOUT_TEST_RESULT, JSON.stringify({ version: process.env.LOOKOUT_CLI_RELEASE_VERSION, amd64Url: process.env.LOOKOUT_CLI_TARGET_AMD64_URL, amd64Sha256: process.env.LOOKOUT_CLI_TARGET_AMD64_SHA256, arm64Url: process.env.LOOKOUT_CLI_TARGET_ARM64_URL, arm64Sha256: process.env.LOOKOUT_CLI_TARGET_ARM64_SHA256, nodePath: process.env.LOOKOUT_CLI_NODE_PATH }));\n");
  const archive = path.join(root, 'orchestration.tar.gz');
  assert.equal(run('tar', ['-czf', archive, '-C', path.dirname(payload), path.basename(payload)]).status, 0);
  const digest = crypto.createHash('sha256').update(await fs.readFile(archive)).digest('hex');
  const targetDigest = 'b'.repeat(64);
  const armTargetDigest = 'c'.repeat(64);
  const fakeCurl = path.join(root, 'curl');
  await fs.writeFile(fakeCurl, '#!/bin/sh\nout=\nwhile [ "$#" -gt 0 ]; do\n  if [ "$1" = --output ]; then out=$2; shift 2; else shift; fi\ndone\ncp "$LOOKOUT_TEST_ARCHIVE" "$out"\n', { mode: 0o755 });
  const shell = path.join(root, 'lookout-cli-install.sh');
  const powershell = path.join(root, 'lookout-cli-install.ps1');
  const rendered = run('sh', [path.join(repository, 'release/render-workstation-cli-bootstrap.sh'), 'v9.8.7', 'https://releases.example/orchestration.tar.gz', digest, 'https://releases.example/orchestration.zip', digest, 'https://releases.example/target-amd64.tar.gz', targetDigest, 'https://releases.example/target-arm64.tar.gz', armTargetDigest, shell, powershell]);
  assert.equal(rendered.status, 0, rendered.stderr);
  return { root, archive, digest, targetDigest, armTargetDigest, fakeCurl, shell, powershell };
}

test('workstation CLI bootstrap verifies its artifact and passes pinned target metadata', async (t) => {
  const item = await fixture(t);
  const resultFile = path.join(item.root, 'result.json');
  const result = run('sh', [item.shell], {
    LOOKOUT_CLI_BOOTSTRAP_TEST_MODE: '1', LOOKOUT_CLI_BOOTSTRAP_CURL: item.fakeCurl,
    LOOKOUT_CLI_BOOTSTRAP_NODE: process.execPath, LOOKOUT_TEST_ARCHIVE: item.archive,
    LOOKOUT_TEST_RESULT: resultFile
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(await fs.readFile(resultFile, 'utf8')), {
    version: 'v9.8.7', amd64Url: 'https://releases.example/target-amd64.tar.gz', amd64Sha256: item.targetDigest,
    arm64Url: 'https://releases.example/target-arm64.tar.gz', arm64Sha256: item.armTargetDigest, nodePath: process.execPath
  });
  assert.doesNotMatch(await fs.readFile(item.powershell, 'utf8'), /@LOOKOUT_/);
});

test('workstation CLI bootstrap rejects a checksum mismatch before execution', async (t) => {
  const item = await fixture(t);
  const resultFile = path.join(item.root, 'result.json');
  const result = run('sh', [item.shell], {
    LOOKOUT_CLI_BOOTSTRAP_TEST_MODE: '1', LOOKOUT_CLI_BOOTSTRAP_CURL: item.fakeCurl,
    LOOKOUT_CLI_BOOTSTRAP_NODE: process.execPath, LOOKOUT_CLI_BOOTSTRAP_SHA256: '0'.repeat(64),
    LOOKOUT_TEST_ARCHIVE: item.archive, LOOKOUT_TEST_RESULT: resultFile
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /checksum mismatch/);
  await assert.rejects(fs.access(resultFile), { code: 'ENOENT' });
});
