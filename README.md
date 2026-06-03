# Everest Himalayas demo

This project builds the Himalayas production incident demo:

- `himalayas-api`: Node.js, TypeScript, Express service that sends real fault events to Sentry.
- `himalayas-orchestrator`: Node.js, TypeScript, Express service that reads Sentry, CRM, Jira, and Anthropic, then returns one context JSON.
- `apps/frontend`: static Everest context screen wired to live orchestrator data.
- `apps/crm`: Flask CRM service backed by `customers.json`.

The Node services load environment variables from this project first, then from
`../.env`, so keys in `/Users/home/Projects/demo/.env` are picked up without
copying secrets into this folder.

## Install

```bash
npm install
pip install flask flask-cors
```

## Environment

Copy `.env.example` to `.env` if you want local overrides. Existing parent env
values are also supported.

Required for live demo:

```bash
SENTRY_DSN=
SENTRY_PERSONAL_TOKEN=
SENTRY_AUTH_TOKEN=
SENTRY_ORG_TOKEN=
SENTRY_API_KEY=
SENTRY_LEGACY_API_KEY=
SENTRY_BASE_URL=https://sentry.io
SENTRY_ORG_SLUG=
SENTRY_PROJECT_SLUG=himalayas-api

ANTHROPIC_API_KEY=
ANTHROPIC_KEY=
ANTHROPIC_MODEL=claude-sonnet-4-5-20250929
ANTHROPIC_TIMEOUT_MS=30000

ATLASSIAN_BASE_URL=https://your-domain.atlassian.net
ATLASSIAN_EMAIL=
ATLASSIAN_API_KEY=
ATLASSIAN_BEARER_TOKEN=
JIRA_PROJECT_KEY=HIM
```

Aliases are intentional: `SENTRY_API_KEY`, `ATLASSIAN_API_KEY`, and
`ANTHROPIC_KEY` are accepted.

Sentry event ingestion requires a DSN. You can set `SENTRY_DSN` directly, or set
`SENTRY_ORG_SLUG`, `SENTRY_PROJECT_SLUG`, and `SENTRY_AUTH_TOKEN` so
`himalayas-api` can read the first active project client key from Sentry.

For Jira Cloud, use either:

- API token Basic Auth: `ATLASSIAN_BASE_URL`, `ATLASSIAN_EMAIL`, and
  `ATLASSIAN_API_KEY`
- OAuth 2.0: `ATLASSIAN_BEARER_TOKEN`; the orchestrator will try Atlassian
  accessible resource discovery

## Run everything

```bash
npm run dev
```

Open `http://localhost:8080`. The orchestrator serves the static frontend from
that port.

## Seed Sentry

Start `npm run dev` first, then run:

```bash
npm run seed-faults
```

Each call intentionally returns HTTP 500 from `himalayas-api`; that is the
expected signal that the SDK captured a real exception.

## Trigger one fault live

```bash
curl -X POST http://localhost:7070/faults/locale-expiry \
  -H 'content-type: application/json' \
  -d '{"account_domain":"kintaro.jp","locale":"ja_JP"}'

curl -X POST http://localhost:7070/faults/webhook-retry \
  -H 'content-type: application/json' \
  -d '{"account_domain":"northwind.io","region":"EMEA"}'

curl -X POST http://localhost:7070/faults/pool-exhaust \
  -H 'content-type: application/json' \
  -d '{"account_domain":"pineconeretail.com"}'

curl -X POST http://localhost:7070/faults/dkim-verify \
  -H 'content-type: application/json' \
  -d '{"account_domain":"velto.de"}'
```

## API endpoints

```bash
GET  http://localhost:8080/cases
GET  http://localhost:8080/context/latest?fault=locale-expiry
GET  http://localhost:8080/context/:sentryIssueId
POST http://localhost:8080/pr/draft
```

The frontend case picker uses `/cases`, then re-renders from
`/context/latest?fault={key}`.
