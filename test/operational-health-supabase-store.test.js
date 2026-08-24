'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { SupabaseOperationalHealthStore } = require('../src/operations-health/supabase-store');

function recordingDatabase(results = []) {
  const requests = [];
  return {
    requests,
    fetchImpl: async (url, options) => {
      requests.push({ url: String(url), method: options.method, headers: options.headers, body: options.body && JSON.parse(options.body) });
      return Response.json(results.shift() ?? null);
    }
  };
}

function store(database) {
  return new SupabaseOperationalHealthStore({ supabaseUrl: 'https://project.supabase.co', serviceKey: 's'.repeat(40), fetchImpl: database.fetchImpl });
}

test('operational sample insertion uses the server-side idempotent retention RPC', async () => {
  const database = recordingDatabase([{ sample_id: 'sample_1', expires_at: '2026-09-22T12:00:00.000Z' }]);
  const result = await store(database).insertSample({
    sampleId: 'sample_1', tenantId: 'tenant_1', deploymentId: 'deployment_1', collectorId: 'collector_1',
    sampledAt: '2026-08-23T12:00:00Z', payload: { vm: { memory: { usedPercent: 70 } } }
  });
  assert.equal(result.sample_id, 'sample_1');
  const request = database.requests[0];
  assert.match(request.url, /\/rpc\/lookout_operational_insert_sample$/);
  assert.equal(request.body.p_input.sampledAt, '2026-08-23T12:00:00.000Z');
  assert.equal(Object.hasOwn(request.body.p_input, 'expiresAt'), false);
  assert.equal(request.headers.Authorization, `Bearer ${'s'.repeat(40)}`);
});

test('operational store queries recent and missing telemetry with bounded filters', async () => {
  const database = recordingDatabase([[{ sample_id: 'sample_1' }], [{ deployment_id: 'deployment_2' }]]);
  const subject = store(database);
  assert.equal((await subject.recentSamples({ tenantId: 'tenant_1', deploymentId: 'deployment_1', since: '2026-08-23T00:00:00Z', limit: 12 })).length, 1);
  assert.equal((await subject.missingTelemetry({ now: '2026-08-23T12:00:00Z', thresholdMinutes: 15 })).length, 1);
  const recent = new URL(database.requests[0].url);
  assert.equal(recent.searchParams.get('sampled_at'), 'gte.2026-08-23T00:00:00.000Z');
  assert.equal(recent.searchParams.get('limit'), '12');
  const missing = new URL(database.requests[1].url);
  assert.equal(missing.searchParams.get('last_seen_at'), 'lte.2026-08-23T11:45:00.000Z');
});

test('operational alert and notification operations use atomic RPCs', async () => {
  const database = recordingDatabase([
    { alert_key: 'vm_disk_critical' }, { outbox_id: 'out_1' }, { outbox_id: 'out_1', attempts: 1 }, true, true
  ]);
  const subject = store(database);
  const identity = { tenantId: 'tenant_1', deploymentId: 'deployment_1', alertKey: 'vm_disk_critical' };
  await subject.upsertAlertState({ ...identity, status: 'open', severity: 'critical', openedAt: '2026-08-23T12:00:00Z', updatedAt: '2026-08-23T12:00:00Z', details: { usedPercent: 96 } });
  await subject.enqueueNotification({ outboxId: 'out_1', idempotencyKey: 'alert:1', ...identity, channel: 'slack', payload: { text: 'critical' } });
  await subject.claimNotification({ now: '2026-08-23T12:01:00Z' });
  await subject.acknowledgeNotification({ outboxId: 'out_1', attempt: 1, now: '2026-08-23T12:02:00Z', providerMessageId: 'provider_1' });
  await subject.failNotification({ outboxId: 'out_1', attempt: 1, now: '2026-08-23T12:02:00Z', nextAttemptAt: '2026-08-23T12:07:00Z', error: 'temporary', maximumAttempts: 10 });
  assert.deepEqual(database.requests.map((request) => new URL(request.url).pathname.split('/').at(-1)), [
    'lookout_operational_upsert_alert', 'lookout_operational_enqueue_notification', 'lookout_operational_claim_notification',
    'lookout_operational_ack_notification', 'lookout_operational_fail_notification'
  ]);
  assert.equal(database.requests[2].body.p_lease_seconds, 300);
  assert.equal(database.requests[3].body.p_attempt, 1);
  assert.equal(database.requests[4].body.p_error, 'temporary');
});

test('operational retention and tenant erasure use server-side cascade operations', async () => {
  const database = recordingDatabase([4, 2]);
  const subject = store(database);
  assert.equal(await subject.deleteExpired({ now: '2026-09-23T12:00:00Z' }), 4);
  assert.equal(await subject.deleteTenant('tenant_1'), 2);
  assert.equal(database.requests[0].body.p_now, '2026-09-23T12:00:00.000Z');
  assert.equal(database.requests[1].body.p_tenant_id, 'tenant_1');
});

test('operational health migration is service-role-only and durable', () => {
  const sql = fs.readFileSync(path.join(__dirname, '../supabase/migrations/20260823200000_operational_health.sql'), 'utf8');
  for (const table of ['targets', 'samples', 'alert_state', 'notification_outbox']) {
    assert.match(sql, new RegExp(`alter table public\\.lookout_operational_${table} enable row level security`, 'i'));
    assert.match(sql, new RegExp(`revoke all on table public\\.lookout_operational_${table} from public, anon, authenticated`, 'i'));
  }
  assert.match(sql, /now\(\) \+ interval '30 days'/i);
  assert.match(sql, /on conflict \(sample_id\) do nothing/i);
  assert.match(sql, /for update skip locked/i);
  assert.match(sql, /lease_expires_at/i);
  assert.match(sql, /grant execute on function public\.lookout_operational_claim_notification.*to service_role/is);
  assert.match(sql, /delete from public\.lookout_operational_targets where tenant_id = p_tenant_id/i);
});
