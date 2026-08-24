create table if not exists public.lookout_operational_targets (
  tenant_id text not null,
  deployment_id text not null,
  collector_id text not null,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  primary key (tenant_id, deployment_id, collector_id)
);

create table if not exists public.lookout_operational_samples (
  sample_id text primary key,
  tenant_id text not null,
  deployment_id text not null,
  collector_id text not null,
  sampled_at timestamptz not null,
  received_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '30 days'),
  payload jsonb not null,
  foreign key (tenant_id, deployment_id, collector_id)
    references public.lookout_operational_targets (tenant_id, deployment_id, collector_id) on delete cascade
);

create index if not exists lookout_operational_samples_recent
  on public.lookout_operational_samples (tenant_id, deployment_id, collector_id, sampled_at desc);
create index if not exists lookout_operational_samples_expiry
  on public.lookout_operational_samples (expires_at);
create index if not exists lookout_operational_targets_last_seen
  on public.lookout_operational_targets (last_seen_at);

create table if not exists public.lookout_operational_alert_state (
  tenant_id text not null,
  deployment_id text not null,
  alert_key text not null,
  status text not null check (status in ('pending', 'open', 'resolved')),
  severity text not null check (severity in ('warning', 'critical')),
  opened_at timestamptz not null,
  updated_at timestamptz not null,
  resolved_at timestamptz,
  last_notified_at timestamptz,
  expires_at timestamptz not null default (now() + interval '30 days'),
  details jsonb not null default '{}'::jsonb,
  primary key (tenant_id, deployment_id, alert_key)
);
create index if not exists lookout_operational_alert_expiry
  on public.lookout_operational_alert_state (expires_at);

create table if not exists public.lookout_operational_notification_outbox (
  outbox_id text primary key,
  idempotency_key text not null unique,
  tenant_id text not null,
  deployment_id text not null,
  alert_key text not null,
  channel text not null check (channel in ('slack', 'email')),
  payload jsonb not null,
  status text not null default 'pending' check (status in ('pending', 'delivering', 'delivered', 'failed')),
  attempts integer not null default 0 check (attempts >= 0),
  next_attempt_at timestamptz not null default now(),
  lease_expires_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '30 days'),
  provider_message_id text,
  last_error text,
  foreign key (tenant_id, deployment_id, alert_key)
    references public.lookout_operational_alert_state (tenant_id, deployment_id, alert_key) on delete cascade
);

create index if not exists lookout_operational_outbox_pending
  on public.lookout_operational_notification_outbox (next_attempt_at)
  where status in ('pending', 'delivering');
create index if not exists lookout_operational_outbox_expiry
  on public.lookout_operational_notification_outbox (expires_at);

alter table public.lookout_operational_targets enable row level security;
alter table public.lookout_operational_samples enable row level security;
alter table public.lookout_operational_alert_state enable row level security;
alter table public.lookout_operational_notification_outbox enable row level security;

revoke all on table public.lookout_operational_targets from public, anon, authenticated;
revoke all on table public.lookout_operational_samples from public, anon, authenticated;
revoke all on table public.lookout_operational_alert_state from public, anon, authenticated;
revoke all on table public.lookout_operational_notification_outbox from public, anon, authenticated;
grant select, insert, update, delete on table public.lookout_operational_targets to service_role;
grant select, insert, update, delete on table public.lookout_operational_samples to service_role;
grant select, insert, update, delete on table public.lookout_operational_alert_state to service_role;
grant select, insert, update, delete on table public.lookout_operational_notification_outbox to service_role;

create or replace function public.lookout_operational_insert_sample(p_input jsonb) returns jsonb
language plpgsql set search_path = '' as $$
declare result public.lookout_operational_samples; inserted boolean := true;
begin
  insert into public.lookout_operational_targets (tenant_id, deployment_id, collector_id, first_seen_at, last_seen_at)
  values (p_input->>'tenantId', p_input->>'deploymentId', p_input->>'collectorId', now(), now())
  on conflict (tenant_id, deployment_id, collector_id) do nothing;

  insert into public.lookout_operational_samples (sample_id, tenant_id, deployment_id, collector_id, sampled_at, received_at, expires_at, payload)
  values (p_input->>'sampleId', p_input->>'tenantId', p_input->>'deploymentId', p_input->>'collectorId', (p_input->>'sampledAt')::timestamptz, now(), now() + interval '30 days', p_input->'payload')
  on conflict (sample_id) do nothing
  returning * into result;

  if result.sample_id is null then
    inserted := false;
    select * into result from public.lookout_operational_samples where sample_id = p_input->>'sampleId';
    if result.tenant_id <> p_input->>'tenantId' or result.deployment_id <> p_input->>'deploymentId' or result.collector_id <> p_input->>'collectorId' or result.sampled_at <> (p_input->>'sampledAt')::timestamptz or result.payload <> p_input->'payload' then
      raise exception 'operational sample idempotency conflict' using errcode = '23505';
    end if;
  end if;
  update public.lookout_operational_targets set last_seen_at = greatest(last_seen_at, result.received_at)
  where tenant_id = result.tenant_id and deployment_id = result.deployment_id and collector_id = result.collector_id;
  return to_jsonb(result) || jsonb_build_object('inserted', inserted);
end $$;

create or replace function public.lookout_operational_upsert_alert(p_input jsonb) returns jsonb
language plpgsql set search_path = '' as $$
declare result public.lookout_operational_alert_state;
begin
  insert into public.lookout_operational_alert_state
    (tenant_id, deployment_id, alert_key, status, severity, opened_at, updated_at, resolved_at, last_notified_at, expires_at, details)
  values
    (p_input->>'tenantId', p_input->>'deploymentId', p_input->>'alertKey', p_input->>'status', p_input->>'severity',
     (p_input->>'openedAt')::timestamptz, (p_input->>'updatedAt')::timestamptz,
     (p_input->>'resolvedAt')::timestamptz, (p_input->>'lastNotifiedAt')::timestamptz, now() + interval '30 days', coalesce(p_input->'details', '{}'::jsonb))
  on conflict (tenant_id, deployment_id, alert_key) do update set
    status = excluded.status, severity = excluded.severity, updated_at = excluded.updated_at,
    resolved_at = excluded.resolved_at, last_notified_at = excluded.last_notified_at, expires_at = excluded.expires_at, details = excluded.details
  returning * into result;
  return to_jsonb(result);
end $$;

create or replace function public.lookout_operational_enqueue_notification(p_input jsonb) returns jsonb
language plpgsql set search_path = '' as $$
declare result public.lookout_operational_notification_outbox;
begin
  insert into public.lookout_operational_notification_outbox
    (outbox_id, idempotency_key, tenant_id, deployment_id, alert_key, channel, payload, next_attempt_at, created_at, updated_at, expires_at)
  values
    (p_input->>'outboxId', p_input->>'idempotencyKey', p_input->>'tenantId', p_input->>'deploymentId', p_input->>'alertKey',
     p_input->>'channel', p_input->'payload', coalesce((p_input->>'nextAttemptAt')::timestamptz, now()), now(), now(), now() + interval '30 days')
  on conflict (idempotency_key) do nothing returning * into result;
  if result.outbox_id is null then
    select * into result from public.lookout_operational_notification_outbox where idempotency_key = p_input->>'idempotencyKey';
  end if;
  return to_jsonb(result);
end $$;

create or replace function public.lookout_operational_claim_notification(p_now timestamptz, p_lease_seconds integer, p_maximum_attempts integer) returns jsonb
language plpgsql set search_path = '' as $$
declare result public.lookout_operational_notification_outbox;
begin
  update public.lookout_operational_notification_outbox set status = 'failed', updated_at = p_now, last_error = 'maximum_attempts_exceeded', lease_expires_at = null
  where status = 'delivering' and lease_expires_at <= p_now and attempts >= p_maximum_attempts;

  select * into result from public.lookout_operational_notification_outbox
  where attempts < p_maximum_attempts
    and ((status = 'pending' and next_attempt_at <= p_now) or (status = 'delivering' and lease_expires_at <= p_now))
  order by next_attempt_at, created_at for update skip locked limit 1;
  if result.outbox_id is null then return null; end if;

  update public.lookout_operational_notification_outbox set
    status = 'delivering', attempts = attempts + 1,
    lease_expires_at = p_now + make_interval(secs => p_lease_seconds), updated_at = p_now
  where outbox_id = result.outbox_id returning * into result;
  return to_jsonb(result);
end $$;

create or replace function public.lookout_operational_ack_notification(p_outbox_id text, p_attempt integer, p_now timestamptz, p_provider_message_id text) returns boolean
language plpgsql set search_path = '' as $$
begin
  update public.lookout_operational_notification_outbox set status = 'delivered', provider_message_id = p_provider_message_id,
    lease_expires_at = null, updated_at = p_now, last_error = null
  where outbox_id = p_outbox_id and status = 'delivering' and attempts = p_attempt;
  return found;
end $$;

create or replace function public.lookout_operational_fail_notification(p_outbox_id text, p_attempt integer, p_now timestamptz, p_next_attempt_at timestamptz, p_error text, p_maximum_attempts integer) returns boolean
language plpgsql set search_path = '' as $$
begin
  update public.lookout_operational_notification_outbox set
    status = case when attempts >= p_maximum_attempts then 'failed' else 'pending' end,
    next_attempt_at = p_next_attempt_at, lease_expires_at = null, updated_at = p_now, last_error = left(p_error, 500)
  where outbox_id = p_outbox_id and status = 'delivering' and attempts = p_attempt;
  return found;
end $$;

create or replace function public.lookout_operational_delete_expired(p_now timestamptz) returns integer
language plpgsql set search_path = '' as $$
declare removed integer; outbox_removed integer; alerts_removed integer;
begin
  delete from public.lookout_operational_notification_outbox where expires_at <= p_now;
  get diagnostics outbox_removed = row_count;
  delete from public.lookout_operational_alert_state where expires_at <= p_now;
  get diagnostics alerts_removed = row_count;
  delete from public.lookout_operational_samples where expires_at <= p_now;
  get diagnostics removed = row_count;
  return removed + outbox_removed + alerts_removed;
end $$;

create or replace function public.lookout_operational_delete_tenant(p_tenant_id text) returns integer
language plpgsql set search_path = '' as $$
declare removed integer;
begin
  delete from public.lookout_operational_alert_state where tenant_id = p_tenant_id;
  delete from public.lookout_operational_targets where tenant_id = p_tenant_id;
  get diagnostics removed = row_count;
  return removed;
end $$;

create or replace function public.lookout_operational_delete_deployment(p_tenant_id text, p_deployment_id text) returns integer
language plpgsql set search_path = '' as $$
declare removed integer; targets_removed integer;
begin
  delete from public.lookout_operational_alert_state where tenant_id = p_tenant_id and deployment_id = p_deployment_id;
  get diagnostics removed = row_count;
  delete from public.lookout_operational_targets where tenant_id = p_tenant_id and deployment_id = p_deployment_id;
  get diagnostics targets_removed = row_count;
  return removed + targets_removed;
end $$;

revoke all on function public.lookout_operational_insert_sample(jsonb) from public, anon, authenticated;
revoke all on function public.lookout_operational_upsert_alert(jsonb) from public, anon, authenticated;
revoke all on function public.lookout_operational_enqueue_notification(jsonb) from public, anon, authenticated;
revoke all on function public.lookout_operational_claim_notification(timestamptz, integer, integer) from public, anon, authenticated;
revoke all on function public.lookout_operational_ack_notification(text, integer, timestamptz, text) from public, anon, authenticated;
revoke all on function public.lookout_operational_fail_notification(text, integer, timestamptz, timestamptz, text, integer) from public, anon, authenticated;
revoke all on function public.lookout_operational_delete_expired(timestamptz) from public, anon, authenticated;
revoke all on function public.lookout_operational_delete_tenant(text) from public, anon, authenticated;
revoke all on function public.lookout_operational_delete_deployment(text, text) from public, anon, authenticated;
grant execute on function public.lookout_operational_insert_sample(jsonb) to service_role;
grant execute on function public.lookout_operational_upsert_alert(jsonb) to service_role;
grant execute on function public.lookout_operational_enqueue_notification(jsonb) to service_role;
grant execute on function public.lookout_operational_claim_notification(timestamptz, integer, integer) to service_role;
grant execute on function public.lookout_operational_ack_notification(text, integer, timestamptz, text) to service_role;
grant execute on function public.lookout_operational_fail_notification(text, integer, timestamptz, timestamptz, text, integer) to service_role;
grant execute on function public.lookout_operational_delete_expired(timestamptz) to service_role;
grant execute on function public.lookout_operational_delete_tenant(text) to service_role;
grant execute on function public.lookout_operational_delete_deployment(text, text) to service_role;
