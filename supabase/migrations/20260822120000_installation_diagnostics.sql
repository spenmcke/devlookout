create table if not exists public.lookout_installation_diagnostics (
  report_id text primary key check (report_id ~ '^diag_[A-Za-z0-9_-]{32}$'),
  kind text not null check (kind in ('installer_failure', 'installer_diagnostic', 'agent_report')),
  status text not null check (status in ('survey_pending', 'received')),
  tenant_id text not null,
  user_id text not null,
  account_email text,
  setup_session_id text not null,
  deployment_id text,
  survey_version integer,
  submission_token_hash text,
  payload jsonb,
  idempotency_key text,
  created_at timestamptz not null default now(),
  received_at timestamptz,
  expires_at timestamptz not null,
  slack_status text not null check (slack_status in ('not_ready', 'pending', 'delivering', 'delivered', 'not_applicable', 'disabled')),
  slack_attempts integer not null default 0 check (slack_attempts >= 0),
  slack_next_attempt_at timestamptz,
  slack_delivered_at timestamptz,
  slack_last_error text
);

create index if not exists lookout_installation_diagnostics_slack_pending
  on public.lookout_installation_diagnostics (slack_next_attempt_at)
  where slack_status = 'pending';

create index if not exists lookout_installation_diagnostics_tenant
  on public.lookout_installation_diagnostics (tenant_id, created_at desc);

create unique index if not exists lookout_installation_diagnostics_idempotency
  on public.lookout_installation_diagnostics (idempotency_key)
  where idempotency_key is not null;

alter table public.lookout_installation_diagnostics enable row level security;
revoke all on table public.lookout_installation_diagnostics from public, anon, authenticated;
grant select, insert, update, delete on table public.lookout_installation_diagnostics to service_role;
