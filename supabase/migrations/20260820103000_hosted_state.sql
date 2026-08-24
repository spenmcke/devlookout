create table if not exists public.lookout_hosted_state (
  state_key text primary key,
  revision bigint not null check (revision > 0),
  payload jsonb not null,
  updated_at timestamptz not null default now(),
  constraint lookout_hosted_state_key_format check (state_key ~ '^[a-z][a-z0-9_-]{0,63}$')
);

alter table public.lookout_hosted_state enable row level security;
revoke all on table public.lookout_hosted_state from public, anon, authenticated;
grant select, insert, update on table public.lookout_hosted_state to service_role;

create or replace function public.lookout_save_hosted_state(
  p_state_key text,
  p_expected_revision bigint,
  p_payload jsonb
) returns bigint
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  next_revision bigint;
begin
  if p_state_key !~ '^[a-z][a-z0-9_-]{0,63}$'
     or p_expected_revision < 0
     or p_payload is null then
    raise exception 'invalid hosted state write' using errcode = '22023';
  end if;

  if p_expected_revision = 0 then
    insert into public.lookout_hosted_state (state_key, revision, payload)
    values (p_state_key, 1, p_payload)
    on conflict (state_key) do nothing
    returning revision into next_revision;
  else
    update public.lookout_hosted_state
       set revision = revision + 1,
           payload = p_payload,
           updated_at = now()
     where state_key = p_state_key
       and revision = p_expected_revision
    returning revision into next_revision;
  end if;

  if next_revision is null then
    raise exception 'hosted state revision conflict' using errcode = '40001';
  end if;
  return next_revision;
end;
$$;

revoke all on function public.lookout_save_hosted_state(text, bigint, jsonb) from public, anon, authenticated;
grant execute on function public.lookout_save_hosted_state(text, bigint, jsonb) to service_role;

