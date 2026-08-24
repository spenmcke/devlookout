create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.lookout_support_tokens (
  token_id text primary key check (token_id ~ '^sat_[A-Za-z0-9_-]{32}$'),
  token_digest text not null unique check (token_digest ~ '^[a-f0-9]{64}$'),
  tenant_id text not null,
  user_id text not null,
  account_email text not null,
  name text not null check (char_length(name) between 1 and 64),
  created_at timestamptz not null,
  expires_at timestamptz not null,
  last_used_at timestamptz,
  revoked_at timestamptz
);
create index if not exists lookout_support_tokens_owner on public.lookout_support_tokens (tenant_id, user_id, created_at desc);
create index if not exists lookout_support_tokens_active_expiry on public.lookout_support_tokens (expires_at) where revoked_at is null;

create table if not exists public.lookout_support_conversations (
  conversation_id text primary key check (conversation_id ~ '^scv_[A-Za-z0-9_-]{32}$'),
  tenant_id text not null,
  user_id text not null,
  account_email text not null,
  status text not null check (status in ('open', 'waiting_on_lookout', 'replied', 'closed')),
  created_at timestamptz not null,
  updated_at timestamptz not null,
  expires_at timestamptz not null,
  provider_message_id text,
  rfc_message_id text
);
create index if not exists lookout_support_conversations_owner on public.lookout_support_conversations (tenant_id, user_id, updated_at desc);
create index if not exists lookout_support_conversations_expiry on public.lookout_support_conversations (expires_at);

create table if not exists public.lookout_support_requests (
  request_id text primary key check (request_id ~ '^srq_[A-Za-z0-9_-]{32}$'),
  support_token_id text not null references public.lookout_support_tokens(token_id) on delete cascade,
  client_request_id text not null check (client_request_id ~ '^[A-Za-z0-9_-]{16,128}$'),
  request_hash text not null check (request_hash ~ '^[a-f0-9]{64}$'),
  status text not null check (status in ('processing', 'completed')),
  lease_expires_at timestamptz,
  conversation_id text references public.lookout_support_conversations(conversation_id) on delete cascade,
  completed_result jsonb,
  created_at timestamptz not null,
  updated_at timestamptz not null,
  unique (support_token_id, client_request_id)
);

create table if not exists public.lookout_support_messages (
  message_id text primary key check (message_id ~ '^scm_[A-Za-z0-9_-]{32}$'),
  conversation_id text not null references public.lookout_support_conversations(conversation_id) on delete cascade,
  role text not null check (role in ('customer', 'assistant', 'staff')),
  content text not null check (octet_length(content) <= 65536),
  citations jsonb not null default '[]'::jsonb,
  created_at timestamptz not null,
  request_id text references public.lookout_support_requests(request_id) on delete set null
);
create index if not exists lookout_support_messages_order on public.lookout_support_messages (conversation_id, created_at, message_id);

create table if not exists public.lookout_support_email_outbox (
  outbox_id text primary key check (outbox_id ~ '^seo_[A-Za-z0-9_-]{32}$'),
  conversation_id text not null references public.lookout_support_conversations(conversation_id) on delete cascade,
  request_id text not null references public.lookout_support_requests(request_id) on delete cascade,
  idempotency_key text not null unique,
  payload jsonb not null,
  status text not null check (status in ('pending', 'delivering', 'delivered', 'failed')),
  attempts integer not null default 0 check (attempts >= 0),
  next_attempt_at timestamptz not null,
  provider_message_id text,
  rfc_message_id text,
  created_at timestamptz not null,
  updated_at timestamptz not null
);
create index if not exists lookout_support_email_pending on public.lookout_support_email_outbox (next_attempt_at) where status = 'pending';

create table if not exists public.lookout_support_inbound_events (
  provider_event_id text primary key,
  provider_message_id text not null unique,
  conversation_id text not null references public.lookout_support_conversations(conversation_id) on delete cascade,
  message_id text not null references public.lookout_support_messages(message_id) on delete cascade,
  created_at timestamptz not null
);

alter table public.lookout_support_tokens enable row level security;
alter table public.lookout_support_requests enable row level security;
alter table public.lookout_support_conversations enable row level security;
alter table public.lookout_support_messages enable row level security;
alter table public.lookout_support_email_outbox enable row level security;
alter table public.lookout_support_inbound_events enable row level security;
revoke all on public.lookout_support_tokens, public.lookout_support_requests, public.lookout_support_conversations, public.lookout_support_messages, public.lookout_support_email_outbox, public.lookout_support_inbound_events from public, anon, authenticated;
grant select, insert, update, delete on public.lookout_support_tokens, public.lookout_support_requests, public.lookout_support_conversations, public.lookout_support_messages, public.lookout_support_email_outbox, public.lookout_support_inbound_events to service_role;

create or replace function public.lookout_support_random_id(prefix text) returns text language sql volatile set search_path = '' as $$
  select prefix || '_' || substring(translate(trim(trailing '=' from encode(extensions.gen_random_bytes(24), 'base64')), '+/', '-_') from 1 for 32)
$$;

create or replace function public.lookout_support_token_json(t public.lookout_support_tokens) returns jsonb language sql immutable set search_path = '' as $$
  select jsonb_build_object('tokenId', t.token_id, 'digest', t.token_digest, 'tenantId', t.tenant_id, 'userId', t.user_id, 'accountEmail', t.account_email, 'name', t.name, 'createdAt', t.created_at, 'expiresAt', t.expires_at, 'lastUsedAt', t.last_used_at, 'revokedAt', t.revoked_at)
$$;

create or replace function public.lookout_support_conversation_json(c public.lookout_support_conversations) returns jsonb language sql immutable set search_path = '' as $$
  select jsonb_build_object('conversationId', c.conversation_id, 'tenantId', c.tenant_id, 'userId', c.user_id, 'accountEmail', c.account_email, 'status', c.status, 'createdAt', c.created_at, 'updatedAt', c.updated_at, 'expiresAt', c.expires_at, 'providerMessageId', c.provider_message_id, 'rfcMessageId', c.rfc_message_id)
$$;

create or replace function public.lookout_support_create_token(p_record jsonb) returns jsonb language plpgsql security definer set search_path = '' as $$
declare result public.lookout_support_tokens;
begin
  perform pg_advisory_xact_lock(hashtextextended((p_record->>'tenantId') || chr(31) || (p_record->>'userId'), 0));
  if (select count(*) from public.lookout_support_tokens where tenant_id = p_record->>'tenantId' and user_id = p_record->>'userId' and revoked_at is null and expires_at > (p_record->>'createdAt')::timestamptz) >= 5 then raise exception 'maximum active support tokens reached' using errcode = '23505'; end if;
  insert into public.lookout_support_tokens(token_id, token_digest, tenant_id, user_id, account_email, name, created_at, expires_at)
  values (p_record->>'tokenId', p_record->>'digest', p_record->>'tenantId', p_record->>'userId', p_record->>'accountEmail', p_record->>'name', (p_record->>'createdAt')::timestamptz, (p_record->>'expiresAt')::timestamptz) returning * into result;
  return public.lookout_support_token_json(result);
end $$;

create or replace function public.lookout_support_list_tokens(p_tenant_id text, p_user_id text) returns jsonb language sql security definer set search_path = '' as $$
  select coalesce(jsonb_agg(public.lookout_support_token_json(t) order by t.created_at desc), '[]'::jsonb)
  from public.lookout_support_tokens t
  where t.tenant_id = p_tenant_id and t.user_id = p_user_id
    and (t.expires_at > now() - interval '30 days' or t.revoked_at > now() - interval '30 days')
$$;

create or replace function public.lookout_support_revoke_token(p_tenant_id text, p_user_id text, p_token_id text, p_now timestamptz) returns jsonb language plpgsql security definer set search_path = '' as $$
declare result public.lookout_support_tokens;
begin update public.lookout_support_tokens set revoked_at = coalesce(revoked_at, p_now) where token_id = p_token_id and tenant_id = p_tenant_id and user_id = p_user_id returning * into result; if result.token_id is null then return null; end if; return public.lookout_support_token_json(result); end $$;

create or replace function public.lookout_support_authenticate_token(p_digest text, p_now timestamptz) returns jsonb language sql security definer set search_path = '' as $$
  select public.lookout_support_token_json(t) from public.lookout_support_tokens t where token_digest = p_digest and revoked_at is null and expires_at > p_now limit 1
$$;

create or replace function public.lookout_support_touch_token(p_token_id text, p_now timestamptz) returns boolean language plpgsql security definer set search_path = '' as $$
declare item public.lookout_support_tokens;
begin
  select * into item from public.lookout_support_tokens where token_id = p_token_id for update;
  if item.token_id is null or item.revoked_at is not null or item.expires_at <= p_now then return false; end if;
  if item.last_used_at is null or item.last_used_at <= p_now - interval '1 hour' then update public.lookout_support_tokens set last_used_at = p_now where token_id = p_token_id; end if;
  return true;
end $$;

create or replace function public.lookout_support_authorize_conversation(p_conversation_id text, p_tenant_id text, p_user_id text) returns jsonb language sql security definer set search_path = '' as $$
  select public.lookout_support_conversation_json(c) from public.lookout_support_conversations c where conversation_id = p_conversation_id and tenant_id = p_tenant_id and user_id = p_user_id and expires_at > now()
$$;
create or replace function public.lookout_support_get_inbound_conversation(p_conversation_id text) returns jsonb language sql security definer set search_path = '' as $$
  select public.lookout_support_conversation_json(c) from public.lookout_support_conversations c where conversation_id = p_conversation_id and expires_at > now()
$$;

create or replace function public.lookout_support_reserve_request(p_input jsonb) returns jsonb language plpgsql security definer set search_path = '' as $$
declare item public.lookout_support_requests; now_value timestamptz := (p_input->>'now')::timestamptz;
begin
  perform pg_advisory_xact_lock(hashtextextended((p_input->>'supportTokenId') || chr(31) || (p_input->>'clientRequestId'), 1));
  select * into item from public.lookout_support_requests where support_token_id = p_input->>'supportTokenId' and client_request_id = p_input->>'clientRequestId' for update;
  if item.request_id is not null then
    if item.request_hash <> p_input->>'requestHash' then return jsonb_build_object('state', 'conflict'); end if;
    if item.status = 'completed' then return jsonb_build_object('state', 'completed', 'result', item.completed_result); end if;
    if item.lease_expires_at > now_value then return jsonb_build_object('state', 'processing'); end if;
    update public.lookout_support_requests set lease_expires_at = now_value + make_interval(secs => ((p_input->>'leaseMs')::integer / 1000)), updated_at = now_value where request_id = item.request_id;
    return jsonb_build_object('state', 'acquired', 'requestId', item.request_id);
  end if;
  item.request_id := public.lookout_support_random_id('srq');
  insert into public.lookout_support_requests(request_id, support_token_id, client_request_id, request_hash, status, lease_expires_at, created_at, updated_at) values (item.request_id, p_input->>'supportTokenId', p_input->>'clientRequestId', p_input->>'requestHash', 'processing', now_value + make_interval(secs => ((p_input->>'leaseMs')::integer / 1000)), now_value, now_value);
  return jsonb_build_object('state', 'acquired', 'requestId', item.request_id);
end $$;

create or replace function public.lookout_support_release_request(p_input jsonb) returns void language sql security definer set search_path = '' as $$
  update public.lookout_support_requests set lease_expires_at = (p_input->>'now')::timestamptz, updated_at = (p_input->>'now')::timestamptz where support_token_id = p_input->>'supportTokenId' and client_request_id = p_input->>'clientRequestId' and request_hash = p_input->>'requestHash' and status = 'processing'
$$;

create or replace function public.lookout_support_complete_request(p_input jsonb) returns jsonb language plpgsql security definer set search_path = '' as $$
declare req public.lookout_support_requests; conv public.lookout_support_conversations; conv_id text := nullif(p_input->>'conversationId', ''); now_value timestamptz := (p_input->>'now')::timestamptz; retention_days integer := least(365, greatest(1, coalesce((p_input->>'retentionDays')::integer, 90))); customer_id text; assistant_id text; outbox_id text; completed jsonb;
begin
  select * into req from public.lookout_support_requests where request_id = p_input->>'requestId' and support_token_id = p_input#>>'{principal,tokenId}' and client_request_id = p_input->>'clientRequestId' for update;
  if req.request_id is null or req.request_hash <> p_input->>'requestHash' then raise exception 'request lease lost' using errcode = '23505'; end if;
  if req.status = 'completed' then return req.completed_result; end if;
  if conv_id is not null then select * into conv from public.lookout_support_conversations where conversation_id = conv_id and tenant_id = p_input#>>'{principal,tenantId}' and user_id = p_input#>>'{principal,userId}' for update; if conv.conversation_id is null then raise exception 'conversation not found' using errcode = 'P0002'; end if; end if;
  if conv_id is null then
    conv_id := public.lookout_support_random_id('scv');
    insert into public.lookout_support_conversations(conversation_id, tenant_id, user_id, account_email, status, created_at, updated_at, expires_at) values (conv_id, p_input#>>'{principal,tenantId}', p_input#>>'{principal,userId}', p_input#>>'{principal,accountEmail}', 'open', now_value, now_value, now_value + make_interval(days => retention_days)) returning * into conv;
  end if;
  customer_id := public.lookout_support_random_id('scm'); assistant_id := public.lookout_support_random_id('scm');
  insert into public.lookout_support_messages(message_id, conversation_id, role, content, citations, created_at, request_id) values
    (customer_id, conv_id, 'customer', p_input->>'customerText', '[]', now_value, req.request_id),
    (assistant_id, conv_id, 'assistant', (p_input->'result')::text, coalesce(p_input#>'{result,sources}', '[]'), now_value + interval '1 millisecond', req.request_id);
  update public.lookout_support_conversations set status = 'waiting_on_lookout', updated_at = now_value, expires_at = now_value + make_interval(days => retention_days) where conversation_id = conv_id returning * into conv;
  completed := (p_input->'result') || jsonb_build_object('request_id', req.request_id, 'conversation_id', conv_id, 'support_notification', jsonb_build_object('status', 'queued'));
  update public.lookout_support_requests set status = 'completed', lease_expires_at = null, conversation_id = conv_id, completed_result = completed, updated_at = now_value where request_id = req.request_id;
  outbox_id := public.lookout_support_random_id('seo');
  insert into public.lookout_support_email_outbox(outbox_id, conversation_id, request_id, idempotency_key, payload, status, attempts, next_attempt_at, created_at, updated_at) values (outbox_id, conv_id, req.request_id, 'support:' || req.request_id, (p_input->'outboxPayload') || jsonb_build_object('conversationId', conv_id, 'requestId', req.request_id, 'createdAt', now_value, 'customerText', p_input->>'customerText', 'result', completed, 'threadRfcMessageId', conv.rfc_message_id), 'pending', 0, now_value, now_value, now_value);
  return completed;
end $$;

create or replace function public.lookout_support_check_conversation(p_input jsonb) returns jsonb language plpgsql security definer set search_path = '' as $$
declare conv public.lookout_support_conversations; messages jsonb; after_time timestamptz := '-infinity'; after_id text := coalesce(p_input->>'afterMessageId', ''); row_limit integer := least(50, greatest(1, coalesce((p_input->>'limit')::integer, 20)));
begin
  select * into conv from public.lookout_support_conversations where conversation_id = p_input->>'conversationId' and tenant_id = p_input->>'tenantId' and user_id = p_input->>'userId' and expires_at > now(); if conv.conversation_id is null then return null; end if;
  if after_id <> '' then select created_at into after_time from public.lookout_support_messages where conversation_id = conv.conversation_id and message_id = after_id and role = 'staff'; end if;
  select coalesce(jsonb_agg(item order by item->>'createdAt', item->>'messageId'), '[]') into messages from (select jsonb_build_object('messageId', m.message_id, 'text', m.content, 'createdAt', m.created_at) item from public.lookout_support_messages m where m.conversation_id = conv.conversation_id and m.role = 'staff' and (m.created_at > after_time or (m.created_at = after_time and m.message_id > after_id)) order by m.created_at, m.message_id limit row_limit) selected;
  return jsonb_build_object('conversation', public.lookout_support_conversation_json(conv), 'messages', messages, 'nextAfterMessageId', case when jsonb_array_length(messages) = row_limit then messages->(row_limit - 1)->>'messageId' else null end);
end $$;

create or replace function public.lookout_support_claim_email(p_input jsonb) returns jsonb language plpgsql security definer set search_path = '' as $$
declare item public.lookout_support_email_outbox;
begin update public.lookout_support_email_outbox set status = 'failed', updated_at = (p_input->>'now')::timestamptz where status = 'delivering' and attempts >= (p_input->>'maximumAttempts')::integer and updated_at <= (p_input->>'now')::timestamptz - interval '5 minutes'; select * into item from public.lookout_support_email_outbox where attempts < (p_input->>'maximumAttempts')::integer and ((status = 'pending' and next_attempt_at <= (p_input->>'now')::timestamptz) or (status = 'delivering' and updated_at <= (p_input->>'now')::timestamptz - interval '5 minutes')) order by next_attempt_at for update skip locked limit 1; if item.outbox_id is null then return null; end if; update public.lookout_support_email_outbox set status = 'delivering', attempts = attempts + 1, updated_at = (p_input->>'now')::timestamptz where outbox_id = item.outbox_id returning * into item; return jsonb_build_object('outboxId', item.outbox_id, 'conversationId', item.conversation_id, 'requestId', item.request_id, 'idempotencyKey', item.idempotency_key, 'payload', item.payload, 'attempts', item.attempts, 'rfcMessageId', item.rfc_message_id); end $$;
create or replace function public.lookout_support_complete_email(p_input jsonb) returns void language plpgsql security definer set search_path = '' as $$
declare conv_id text; begin update public.lookout_support_email_outbox set status = 'delivered', provider_message_id = p_input->>'providerMessageId', rfc_message_id = p_input->>'rfcMessageId', updated_at = (p_input->>'now')::timestamptz where outbox_id = p_input->>'outboxId' returning conversation_id into conv_id; update public.lookout_support_conversations set provider_message_id = coalesce(provider_message_id, p_input->>'providerMessageId'), rfc_message_id = coalesce(rfc_message_id, p_input->>'rfcMessageId') where conversation_id = conv_id; end $$;
create or replace function public.lookout_support_fail_email(p_input jsonb) returns void language sql security definer set search_path = '' as $$
  update public.lookout_support_email_outbox set status = case when attempts >= (p_input->>'maximumAttempts')::integer then 'failed' else 'pending' end, next_attempt_at = (p_input->>'nextAttemptAt')::timestamptz, updated_at = (p_input->>'now')::timestamptz where outbox_id = p_input->>'outboxId'
$$;

create or replace function public.lookout_support_append_staff_reply(p_input jsonb) returns jsonb language plpgsql security definer set search_path = '' as $$
declare message_id_value text; now_value timestamptz := (p_input->>'now')::timestamptz; retention_days integer := least(365, greatest(1, coalesce((p_input->>'retentionDays')::integer, 90)));
begin
  perform pg_advisory_xact_lock(hashtextextended(p_input->>'providerMessageId', 2));
  if exists(select 1 from public.lookout_support_inbound_events where provider_event_id = p_input->>'providerEventId' or provider_message_id = p_input->>'providerMessageId') then return jsonb_build_object('duplicate', true); end if;
  if not exists(select 1 from public.lookout_support_conversations where conversation_id = p_input->>'conversationId') then return null; end if;
  message_id_value := public.lookout_support_random_id('scm');
  insert into public.lookout_support_messages(message_id, conversation_id, role, content, citations, created_at) values (message_id_value, p_input->>'conversationId', 'staff', p_input->>'text', '[]', now_value);
  insert into public.lookout_support_inbound_events(provider_event_id, provider_message_id, conversation_id, message_id, created_at) values (p_input->>'providerEventId', p_input->>'providerMessageId', p_input->>'conversationId', message_id_value, now_value);
  update public.lookout_support_conversations set status = 'replied', updated_at = now_value, expires_at = now_value + make_interval(days => retention_days) where conversation_id = p_input->>'conversationId';
  return jsonb_build_object('duplicate', false, 'message', jsonb_build_object('messageId', message_id_value, 'text', p_input->>'text', 'createdAt', now_value));
end $$;

create or replace function public.lookout_support_delete_tenant(p_tenant_id text) returns void language plpgsql security definer set search_path = '' as $$
begin delete from public.lookout_support_conversations where tenant_id = p_tenant_id; delete from public.lookout_support_tokens where tenant_id = p_tenant_id; end $$;
create or replace function public.lookout_support_delete_expired(p_now timestamptz) returns integer language plpgsql security definer set search_path = '' as $$
declare count_value integer; begin with removed as (delete from public.lookout_support_conversations where expires_at <= p_now returning 1) select count(*) into count_value from removed; return count_value; end $$;

revoke all on function public.lookout_support_random_id(text), public.lookout_support_token_json(public.lookout_support_tokens), public.lookout_support_conversation_json(public.lookout_support_conversations), public.lookout_support_create_token(jsonb), public.lookout_support_list_tokens(text,text), public.lookout_support_revoke_token(text,text,text,timestamptz), public.lookout_support_authenticate_token(text,timestamptz), public.lookout_support_touch_token(text,timestamptz), public.lookout_support_authorize_conversation(text,text,text), public.lookout_support_get_inbound_conversation(text), public.lookout_support_reserve_request(jsonb), public.lookout_support_release_request(jsonb), public.lookout_support_complete_request(jsonb), public.lookout_support_check_conversation(jsonb), public.lookout_support_claim_email(jsonb), public.lookout_support_complete_email(jsonb), public.lookout_support_fail_email(jsonb), public.lookout_support_append_staff_reply(jsonb), public.lookout_support_delete_tenant(text), public.lookout_support_delete_expired(timestamptz) from public, anon, authenticated;
grant execute on function public.lookout_support_create_token(jsonb), public.lookout_support_list_tokens(text,text), public.lookout_support_revoke_token(text,text,text,timestamptz), public.lookout_support_authenticate_token(text,timestamptz), public.lookout_support_touch_token(text,timestamptz), public.lookout_support_authorize_conversation(text,text,text), public.lookout_support_get_inbound_conversation(text), public.lookout_support_reserve_request(jsonb), public.lookout_support_release_request(jsonb), public.lookout_support_complete_request(jsonb), public.lookout_support_check_conversation(jsonb), public.lookout_support_claim_email(jsonb), public.lookout_support_complete_email(jsonb), public.lookout_support_fail_email(jsonb), public.lookout_support_append_staff_reply(jsonb), public.lookout_support_delete_tenant(text), public.lookout_support_delete_expired(timestamptz) to service_role;
