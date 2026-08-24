alter table public.lookout_support_tokens
  add column if not exists token_envelope jsonb,
  add column if not exists account_token boolean not null default false;

create unique index if not exists lookout_support_tokens_one_account_token
  on public.lookout_support_tokens (tenant_id, user_id)
  where account_token and revoked_at is null;

create or replace function public.lookout_support_get_or_create_account_token(p_record jsonb) returns jsonb language plpgsql security definer set search_path = '' as $$
declare result public.lookout_support_tokens;
begin
  perform pg_advisory_xact_lock(hashtextextended((p_record->>'tenantId') || chr(31) || (p_record->>'userId'), 3));
  select * into result
  from public.lookout_support_tokens
  where tenant_id = p_record->>'tenantId'
    and user_id = p_record->>'userId'
    and account_token
    and revoked_at is null
    and expires_at > (p_record->>'createdAt')::timestamptz
  limit 1;
  if result.token_id is null then
    if jsonb_typeof(p_record->'envelope') <> 'object' then raise exception 'support token envelope is required'; end if;
    insert into public.lookout_support_tokens(token_id, token_digest, tenant_id, user_id, account_email, name, created_at, expires_at, token_envelope, account_token)
    values (p_record->>'tokenId', p_record->>'digest', p_record->>'tenantId', p_record->>'userId', p_record->>'accountEmail', p_record->>'name', (p_record->>'createdAt')::timestamptz, (p_record->>'expiresAt')::timestamptz, p_record->'envelope', true)
    returning * into result;
  end if;
  return public.lookout_support_token_json(result) || jsonb_build_object('envelope', result.token_envelope, 'accountToken', result.account_token);
end $$;

revoke all on function public.lookout_support_get_or_create_account_token(jsonb) from public, anon, authenticated;
grant execute on function public.lookout_support_get_or_create_account_token(jsonb) to service_role;
