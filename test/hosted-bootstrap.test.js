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
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-hosted-bootstrap-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const payload = path.join(root, 'payload', 'lookout-orchestration-v9.8.7');
  await fs.mkdir(path.join(payload, 'install'), { recursive: true });
  await fs.writeFile(path.join(payload, 'package.json'), '{"name":"lookout"}\n');
  await fs.writeFile(path.join(payload, 'install', 'fleet.js'), "'use strict';\n");
  await fs.writeFile(path.join(payload, 'install', 'onboard.js'), "'use strict';\nconst fs = require('node:fs');\nfs.writeFileSync(process.env.LOOKOUT_TEST_RESULT, JSON.stringify({ argv: process.argv.slice(2), targetUrl: process.env.LOOKOUT_RELEASE_URL, targetSha256: process.env.LOOKOUT_RELEASE_SHA256, tokenFile: process.env.LOOKOUT_SETUP_TOKEN_FILE }));\n");
  const archive = path.join(root, 'orchestration.tar.gz');
  assert.equal(run('tar', ['-czf', archive, '-C', path.dirname(payload), path.basename(payload)]).status, 0);
  const digest = crypto.createHash('sha256').update(await fs.readFile(archive)).digest('hex');
  const targetDigest = 'b'.repeat(64);
  const downloadLog = path.join(root, 'downloads');
  const fakeCurl = path.join(root, 'curl');
  await fs.writeFile(fakeCurl, '#!/bin/sh\nout=\nurl=\nwhile [ "$#" -gt 0 ]; do\n  if [ "$1" = --output ] || [ "$1" = -o ]; then out=$2; shift 2\n  else url=$1; shift\n  fi\ndone\nprintf \'%s\\n\' "$url" >> "$LOOKOUT_TEST_DOWNLOADS"\n[ -z "$out" ] || cp "$LOOKOUT_TEST_ARCHIVE" "$out"\n', { mode: 0o755 });
  const tokenFile = path.join(root, 'setup-token');
  await fs.writeFile(tokenFile, `lst_${'a'.repeat(43)}\n`, { mode: 0o600 });
  const bootstrap = path.join(root, 'install.sh');
  const rendered = run('sh', [path.join(repository, 'release/render-bootstrap.sh'), 'v9.8.7', 'https://releases.example/orchestration.tar.gz', digest, 'https://releases.example/target-linux.tar.gz', targetDigest, bootstrap]);
  assert.equal(rendered.status, 0, rendered.stderr);
  return { root, archive, digest, targetDigest, downloadLog, fakeCurl, bootstrap, tokenFile };
}

test('hosted bootstrap verifies only the orchestration artifact and starts onboard.js with the system Node', async (t) => {
  const item = await fixture(t);
  const resultFile = path.join(item.root, 'result');
  const result = run('sh', [item.bootstrap], {
    LOOKOUT_BOOTSTRAP_TEST_MODE: '1', LOOKOUT_BOOTSTRAP_CURL: item.fakeCurl,
    LOOKOUT_TEST_ARCHIVE: item.archive, LOOKOUT_TEST_DOWNLOADS: item.downloadLog,
    LOOKOUT_TEST_RESULT: resultFile, LOOKOUT_SETUP_TOKEN_FILE: item.tokenFile,
    LOOKOUT_SETUP_CODE: 'must-not-pass', LOOKOUT_ENROLLMENT_CODE: 'nor-this'
  });
  assert.equal(result.status, 0, result.stderr);
  const invoked = JSON.parse(await fs.readFile(resultFile, 'utf8'));
  assert.deepEqual(invoked.argv, []);
  assert.equal(invoked.targetUrl, 'https://releases.example/target-linux.tar.gz');
  assert.equal(invoked.targetSha256, item.targetDigest);
  assert.equal(invoked.tokenFile, item.tokenFile);
  assert.deepEqual((await fs.readFile(item.downloadLog, 'utf8')).trim().split('\n'), ['https://releases.example/orchestration.tar.gz']);
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /Connected|must-not-pass|nor-this/);
});

test('missing or old Node fails before HTTP and download without Connected', async (t) => {
  const item = await fixture(t);
  for (const [nodeCommand, expected] of [['missing-lookout-node', /Node\.js 20\+ is required/], [path.join(item.root, 'old-node'), /found major version 18/]]) {
    if (nodeCommand.endsWith('old-node')) await fs.writeFile(nodeCommand, '#!/bin/sh\nprintf \'18\\n\'\n', { mode: 0o755 });
    await fs.rm(item.downloadLog, { force: true });
    const result = run('sh', [item.bootstrap], {
      LOOKOUT_BOOTSTRAP_TEST_MODE: '1', LOOKOUT_BOOTSTRAP_NODE: nodeCommand, LOOKOUT_BOOTSTRAP_CURL: item.fakeCurl,
      LOOKOUT_TEST_ARCHIVE: item.archive, LOOKOUT_TEST_DOWNLOADS: item.downloadLog, LOOKOUT_SETUP_TOKEN_FILE: item.tokenFile
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, expected);
    assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /Connected|Needs access/);
    await assert.rejects(fs.access(item.downloadLog), { code: 'ENOENT' });
  }
});

test('checksum mismatch fails before orchestrator launch without Connected', async (t) => {
  const item = await fixture(t);
  const resultFile = path.join(item.root, 'result');
  const result = run('sh', [item.bootstrap], {
    LOOKOUT_BOOTSTRAP_TEST_MODE: '1', LOOKOUT_BOOTSTRAP_CURL: item.fakeCurl,
    LOOKOUT_BOOTSTRAP_ORCHESTRATION_SHA256: '0'.repeat(64), LOOKOUT_TEST_ARCHIVE: item.archive,
    LOOKOUT_TEST_DOWNLOADS: item.downloadLog, LOOKOUT_TEST_RESULT: resultFile, LOOKOUT_SETUP_TOKEN_FILE: item.tokenFile
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /checksum mismatch/);
  assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /Connected/);
  await assert.rejects(fs.access(resultFile), { code: 'ENOENT' });
});

test('hosted bootstrap never accepts a setup token argument', async (t) => {
  const item = await fixture(t);
  const result = run('sh', [item.bootstrap, 'secret-token']);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /arguments are not accepted/);
  assert.doesNotMatch(result.stdout, /secret-token|Connected/);
});
