create table if not exists public.lookout_update_channels (
  channel text primary key check (channel = 'stable'),
  sequence bigint not null check (sequence > 0),
  manifest jsonb not null,
  updated_at timestamptz not null default now()
);

alter table public.lookout_update_channels enable row level security;
revoke all on table public.lookout_update_channels from public, anon, authenticated;
grant select, insert, update on table public.lookout_update_channels to service_role;
