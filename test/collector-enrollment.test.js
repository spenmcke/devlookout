'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { CollectorEnrollmentAuthority, createCollectorEnrollmentRequest, loadOrCreateEnrollmentBundle, submitEnrollment } = require('../src/collector/enrollment');
const { postJson } = require('../src/collector/transport');
const { EventEmitter } = require('node:events');

async function temporary(operation) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'lookout-enrollment-'));
  try { return await operation(directory); }
  finally { await fs.rm(directory, { recursive: true, force: true }); }
}

test('collector enrollment keeps endpoint secrets local and is safely idempotent', async () => temporary(async (directory) => {
  const now = new Date('2026-08-18T12:00:00.000Z');
  const authority = await new CollectorEnrollmentAuthority({ dataDirectory: directory }).initialize();
  const invitation = await authority.issueInvitation({ now, ttlSeconds: 300, label: 'server-a', assetId: 'site-a/linux/server-01', deploymentId: 'deploy-1' });
  const bundle = createCollectorEnrollmentRequest(invitation.token, { assetId: 'site-a/linux/server-01', deploymentId: 'deploy-1' });
  assert.equal(Object.hasOwn(bundle.request, 'privateKeyPem'), false);
  assert.equal(Object.hasOwn(bundle.request, 'submissionToken'), false);
  const enrolled = await authority.enroll(bundle.request, { now });
  assert.equal(enrolled.collectorId, bundle.private.collectorId);
  assert.equal(enrolled.assetId, 'site-a/linux/server-01');
  assert.equal(enrolled.idempotent, false);
  assert.equal((await authority.enroll(bundle.request, { now })).idempotent, true);
  const principal = authority.authenticateBearer(`Bearer ${bundle.private.submissionToken}`);
  assert.equal(principal.collectorId, bundle.private.collectorId);
  assert.deepEqual(principal.roles, ['collector']);
  assert.equal(authority.publicKeys()[bundle.private.collectorId], bundle.request.publicKeyPem);

  const restarted = await new CollectorEnrollmentAuthority({ dataDirectory: directory }).initialize();
  assert.equal(restarted.authenticateBearer(`Bearer ${bundle.private.submissionToken}`).collectorId, bundle.private.collectorId);
  assert.equal(restarted.publicKeys()[bundle.private.collectorId], bundle.request.publicKeyPem);
}));

test('running enrollment authority refreshes invitations issued by the privileged local CLI', async () => temporary(async (directory) => {
  const running = await new CollectorEnrollmentAuthority({ dataDirectory: directory }).initialize();
  const cli = await new CollectorEnrollmentAuthority({ dataDirectory: directory }).initialize();
  const invitation = await cli.issueInvitation({ assetId: 'provider:host-9', deploymentId: 'fleet-refresh' });
  const bundle = createCollectorEnrollmentRequest(invitation.token, { assetId: 'provider:host-9', deploymentId: 'fleet-refresh' });
  await assert.rejects(() => running.enroll(bundle.request), /not valid/);
  const result = await running.enroll(bundle.request, { refresh: true });
  assert.equal(result.collectorId, bundle.private.collectorId);
}));

test('enrollment invitations are single-purpose, expire, and reject identity substitution', async () => temporary(async (directory) => {
  const now = new Date('2026-08-18T12:00:00.000Z');
  const authority = await new CollectorEnrollmentAuthority({ dataDirectory: directory }).initialize();
  const firstInvitation = await authority.issueInvitation({ now, ttlSeconds: 60, assetId: 'asset-1', deploymentId: 'deploy-1' });
  const first = createCollectorEnrollmentRequest(firstInvitation.token, { assetId: 'asset-1', deploymentId: 'deploy-1' });
  const substituted = structuredClone(first.request);
  substituted.collectorId = `wrong-${first.private.collectorId}`;
  await assert.rejects(() => authority.enroll(substituted, { now }), /does not match/);
  await authority.enroll(first.request, { now });
  const different = createCollectorEnrollmentRequest(firstInvitation.token, { assetId: 'asset-1', deploymentId: 'deploy-1' });
  await assert.rejects(() => authority.enroll(different.request, { now }), /already been used/);

  const expiredInvitation = await authority.issueInvitation({ now, ttlSeconds: 60, assetId: 'asset-1', deploymentId: 'deploy-1' });
  const expired = createCollectorEnrollmentRequest(expiredInvitation.token, { assetId: 'asset-1', deploymentId: 'deploy-1' });
  await assert.rejects(() => authority.enroll(expired.request, { now: new Date(now.getTime() + 60001) }), /expired/);
}));

test('invitation retention stays restart-safe and submission credentials are unique', async () => temporary(async (directory) => {
  const now = new Date('2026-08-18T12:00:00.000Z');
  const authority = await new CollectorEnrollmentAuthority({ dataDirectory: directory, maximumInvitations: 2 }).initialize();
  let firstBundle;
  for (let index = 1; index <= 2; index += 1) {
    const invitation = await authority.issueInvitation({ now, assetId: `asset-${index}`, deploymentId: 'deploy-1' });
    const bundle = createCollectorEnrollmentRequest(invitation.token, { assetId: `asset-${index}`, deploymentId: 'deploy-1' });
    if (index === 1) firstBundle = bundle;
    await authority.enroll(bundle.request, { now });
  }
  await authority.issueInvitation({ now, assetId: 'asset-3', deploymentId: 'deploy-1' });
  await new CollectorEnrollmentAuthority({ dataDirectory: directory, maximumInvitations: 2 }).initialize();

  const duplicateInvitation = await authority.issueInvitation({ now, assetId: 'asset-4', deploymentId: 'deploy-1' });
  const duplicate = createCollectorEnrollmentRequest(duplicateInvitation.token, { assetId: 'asset-4', deploymentId: 'deploy-1' });
  duplicate.request.submissionTokenHash = firstBundle.request.submissionTokenHash;
  await assert.rejects(() => authority.enroll(duplicate.request, { now }), /credential is already enrolled/);
}));

test('enrolled collectors can be durably disabled without deleting identity history', async () => temporary(async (directory) => {
  const authority = await new CollectorEnrollmentAuthority({ dataDirectory: directory }).initialize();
  const invitation = await authority.issueInvitation({ assetId: 'asset-1', deploymentId: 'deploy-1' });
  const bundle = createCollectorEnrollmentRequest(invitation.token, { assetId: 'asset-1', deploymentId: 'deploy-1' });
  await authority.enroll(bundle.request);
  await authority.setDisabled(bundle.private.collectorId, true);
  assert.equal(authority.authenticateBearer(`Bearer ${bundle.private.submissionToken}`), null);
  assert.equal(authority.publicKeys()[bundle.private.collectorId], undefined);
  await authority.setDisabled(bundle.private.collectorId, false);
  assert.ok(authority.authenticateBearer(`Bearer ${bundle.private.submissionToken}`));
}));

test('remote enrollment transport requires TLS and does not follow redirects', async () => {
  await assert.rejects(() => submitEnrollment('http://192.0.2.1:4173', {}, { fetchImpl: async () => { throw new Error('must not run'); } }), /requires HTTPS/);
  let options;
  const response = await submitEnrollment('https://lookout.example/base', { schemaVersion: 1 }, { fetchImpl: async (url, supplied) => {
    assert.equal(url.toString(), 'https://lookout.example/api/v1/collector/enroll');
    options = supplied;
    return { ok: true, async text() { return '{"enrolled":true}'; } };
  } });
  assert.deepEqual(response, { enrolled: true });
  assert.equal(options.redirect, 'error');
  assert.equal(options.method, 'POST');
});

test('endpoint enrollment credentials persist before network use and reload exactly on upgrade', async () => temporary(async (directory) => {
  const authority = await new CollectorEnrollmentAuthority({ dataDirectory: path.join(directory, 'server') }).initialize();
  const invitation = await authority.issueInvitation({ assetId: 'provider/asset-42', deploymentId: 'fleet-tx-7' });
  const identityDirectory = path.join(directory, 'endpoint');
  const first = await loadOrCreateEnrollmentBundle(identityDirectory, invitation.token, { assetId: 'provider/asset-42', deploymentId: 'fleet-tx-7' });
  const mode = (await fs.stat(path.join(identityDirectory, 'enrollment.json'))).mode & 0o777;
  assert.equal(mode, 0o600);
  const second = await loadOrCreateEnrollmentBundle(identityDirectory, invitation.token, { assetId: 'provider/asset-42', deploymentId: 'fleet-tx-7' });
  assert.deepEqual(second, first);
  await authority.enroll(first.request);
  assert.equal((await authority.enroll(second.request)).idempotent, true);
  if (process.platform !== 'win32') {
    await fs.chmod(path.join(identityDirectory, 'enrollment.json'), 0o644);
    await assert.rejects(() => loadOrCreateEnrollmentBundle(identityDirectory, invitation.token, { assetId: 'provider/asset-42', deploymentId: 'fleet-tx-7' }), /permissions are too broad/);
  }
}));

test('fetch transport bounds chunked responses before buffering', async () => {
  const body = { async *[Symbol.asyncIterator]() { yield Buffer.from('{"data":"'); yield Buffer.alloc(32, 120); yield Buffer.from('"}'); } };
  await assert.rejects(() => postJson('https://lookout.internal/enroll', {}, { maximumResponseBytes: 16, fetchImpl: async () => ({ ok: true, body }) }), /exceeds configured bound/);
});

test('CA-pinned transport passes a private trust bundle and requires certificate verification', async () => {
  let supplied;
  const fakeRequest = (_url, options, callback) => {
    supplied = options;
    const request = new EventEmitter();
    request.end = () => {
      const response = new EventEmitter();
      response.statusCode = 200;
      callback(response);
      response.emit('data', Buffer.from('{"ok":true}'));
      response.emit('end');
    };
    request.destroy = (error) => request.emit('error', error);
    return request;
  };
  const caPem = '-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n';
  assert.deepEqual(await postJson('https://lookout.internal/enroll', {}, { caPem, httpsRequestImpl: fakeRequest }), { ok: true });
  assert.equal(supplied.ca, caPem);
  assert.equal(supplied.rejectUnauthorized, true);
});

test('privileged fleet retries replace only an unused invitation for the same asset binding', async () => temporary(async (directory) => {
  const authority = await new CollectorEnrollmentAuthority({ dataDirectory: directory }).initialize();
  const first = await authority.issueInvitation({ assetId: 'asset-a', deploymentId: 'deploy-a' });
  await assert.rejects(() => authority.issueInvitation({ assetId: 'asset-a', deploymentId: 'deploy-a' }), /active invitation/);
  const replacement = await authority.issueInvitation({ assetId: 'asset-a', deploymentId: 'deploy-a', replaceActive: true });
  assert.notEqual(replacement.token, first.token);
  await assert.rejects(() => authority.enroll(createCollectorEnrollmentRequest(first.token, { assetId: 'asset-a', deploymentId: 'deploy-a' }).request), /not valid/);
  assert.equal((await authority.enroll(createCollectorEnrollmentRequest(replacement.token, { assetId: 'asset-a', deploymentId: 'deploy-a' }).request)).assetId, 'asset-a');
}));
