'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { DataProtector } = require('../src/security/data-protector');
const { SupabaseSnapshotStore } = require('../src/storage/supabase-snapshot-store');

function databaseFetch() {
  let row = null;
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url: String(url), options: structuredClone({ method: options.method, headers: options.headers, body: options.body }) });
    if (options.method === 'GET') return Response.json(row ? [row] : []);
    const body = JSON.parse(options.body);
    if (body.p_expected_revision !== (row?.revision || 0)) return Response.json({ message: 'hosted state revision conflict' }, { status: 409 });
    row = { revision: (row?.revision || 0) + 1, payload: body.p_payload };
    return Response.json(row.revision);
  };
  return { fetchImpl, requests, row: () => row };
}

test('Supabase snapshot state is encrypted, integrity checked, and revision guarded', async () => {
  const database = databaseFetch();
  const options = {
    supabaseUrl: 'https://project.supabase.co', serviceKey: 's'.repeat(40), stateKey: 'setup',
    protector: new DataProtector(Buffer.alloc(32, 7)), fetchImpl: database.fetchImpl
  };
  const first = new SupabaseSnapshotStore(options);
  assert.equal(await first.load(), null);
  await first.save({ schemaVersion: 1, secret: 'never-plaintext' });
  assert.equal(database.row().revision, 1);
  assert.doesNotMatch(database.requests.at(-1).options.body, /never-plaintext/);

  const second = new SupabaseSnapshotStore(options);
  assert.deepEqual(await second.load(), { schemaVersion: 1, secret: 'never-plaintext' });
  await second.save({ schemaVersion: 1, secret: 'rotated' });
  await assert.rejects(first.save({ schemaVersion: 1, secret: 'stale' }), /revision conflict/);
});

test('Supabase hosted-state migration locks access to the service role', () => {
  const sql = fs.readFileSync(path.join(__dirname, '../supabase/migrations/20260820103000_hosted_state.sql'), 'utf8');
  assert.match(sql, /enable row level security/i);
  assert.match(sql, /revoke all on table .* from public, anon, authenticated/i);
  assert.match(sql, /grant execute .* to service_role/i);
  assert.match(sql, /p_expected_revision/i);
});

