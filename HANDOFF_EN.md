# EverestAI Sentry Demo Handoff

Last verified: June 3, 2026

GitHub repo: `https://github.com/yolandaycao/demo-sentry`

The repo is private. Secrets and generated artifacts are ignored by git: `.env`, `.env.local`, `node_modules/`, `dist/`, and `data/cache/*.json`.

## What This Demo Does

This demo shows Everest turning a production incident into actionable engineering context.

Main flow:

- `himalayas-api` creates intentionally broken fault paths and sends real exceptions to Sentry.
- `himalayas-orchestrator` reads Sentry, local CRM, Jira, source files, and Anthropic, then returns one context JSON.
- `apps/frontend` is a static Everest escalation context screen served by the orchestrator.
- `apps/crm` is a local Flask CRM backed by `customers.json`.

Open `http://localhost:8080`. The frontend loads `/cases`, then renders incident context from `/context/latest?fault={key}`.

## Local Setup

```bash
git clone https://github.com/yolandaycao/demo-sentry.git
cd demo-sentry
npm install
python3 -m pip install flask flask-cors
```

Create local env:

```bash
cp .env.example .env.local
```

Required live demo variables:

```bash
SENTRY_AUTH_TOKEN=
SENTRY_BASE_URL=https://sentry.io
SENTRY_ORG_SLUG=everest-ai
SENTRY_PROJECT_SLUG=himalayas-api

ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-sonnet-4-5-20250929
ANTHROPIC_TIMEOUT_MS=30000

ATLASSIAN_BASE_URL=https://everestai.atlassian.net
ATLASSIAN_EMAIL=
ATLASSIAN_API_KEY=
JIRA_PROJECT_KEY=HIM

HIMALAYAS_API_PORT=7070
ORCHESTRATOR_PORT=8080
CRM_BASE_URL=http://localhost:8787
DIAGNOSIS_CACHE_DIR=data/cache
NODE_ENV=production
HIMALAYAS_API_RELEASE=api@2.14.3
HIMALAYAS_API_URL=http://localhost:7070
```

Notes:

- `SENTRY_DSN` is optional. The API can fetch the active project client key using `SENTRY_AUTH_TOKEN`, `SENTRY_ORG_SLUG`, and `SENTRY_PROJECT_SLUG`.
- `ATLASSIAN_BEARER_TOKEN` is not needed when using Jira Basic Auth with `ATLASSIAN_EMAIL` and `ATLASSIAN_API_KEY`.
- `SENTRY_API_KEY`, `SENTRY_PERSONAL_TOKEN`, `SENTRY_ORG_TOKEN`, `ANTHROPIC_KEY`, and `JIRA_API_TOKEN` are aliases. Prefer the canonical variables above to avoid duplication.

## Run Locally

```bash
npm run dev
```

Expected local services:

- CRM: `http://localhost:8787`
- API: `http://localhost:7070`
- Orchestrator and frontend: `http://localhost:8080`

## Railway Deployment

Railway config is checked in as `railway.json`.

Railway settings:

- Builder: Nixpacks
- Build command: `npm run build`
- Nixpacks providers: `node`, `python` via `nixpacks.toml`
- Dependency installs are handled by the Node and Python Nixpacks providers.
- Start command: `npm run start:railway`
- Healthcheck path: `/health`

Important deployment behavior:

- Railway exposes one public `$PORT`.
- The orchestrator reads `$PORT` first, then falls back to `ORCHESTRATOR_PORT`.
- CRM and API run inside the same Railway container on localhost.
- `start:railway` starts CRM, API, and orchestrator together with `concurrently`.

For Railway env vars, use the same canonical variables from the Local Setup section. Do not add optional aliases unless you intentionally want them.

## Read-Only Smoke Tests

These do not write Sentry events.

```bash
curl -sS http://localhost:8787/health
curl -sS http://localhost:7070/health
curl -sS http://localhost:8080/health
curl -sS http://localhost:8080/cases
curl -sS 'http://localhost:8080/context/latest?fault=locale-expiry'
```

Expected results:

- CRM health returns `himalayas-crm`.
- API health returns `himalayas-api` and `sentry: true`.
- Orchestrator health returns `sentry: true`, `anthropic: true`, and `jira.configured: true`.
- `/cases` returns four demo faults.
- `/context/latest?fault=locale-expiry` returns `ESC-2418`, `Kintaro K.K.`, `HIM-2`, `Dan Kim`, and `DateFormatError`.

## Browser Check

Open:

```bash
open http://localhost:8080
```

Expected UI:

- Everest sidebar
- Case picker in the top bar
- Ticket `ESC-2418`
- Customer `Kintaro K.K.`
- Diagnosis panel
- Sentry read-only panel on the right
- Suggested fix panel with `Open draft PR`

Recent UI change:

- The top-left logo mark is now more square: `24px` by `24px` with `border-radius: 3px`.
- File: `apps/frontend/styles.css`

## Live Sentry Event Tests

These write real Sentry events. Only run them when you need to validate capture.

Seed all faults:

```bash
npm run seed-faults
```

Trigger one fault:

```bash
curl -X POST http://localhost:7070/faults/locale-expiry \
  -H 'content-type: application/json' \
  -d '{"account_domain":"kintaro.jp","locale":"ja_JP"}'
```

Expected behavior:

- Fault endpoints intentionally return HTTP 500.
- The 500 is the signal that the SDK should capture a real Sentry exception.

## Draft PR Flow

`POST /pr/draft` is currently stubbed. It does not create a real GitHub PR.

```bash
curl -sS -X POST http://localhost:8080/pr/draft \
  -H 'content-type: application/json' \
  -d '{"fault":"locale-expiry"}'
```

Expected response:

- `status: "stubbed"`
- A branch name like `everest/{fault}/{timestamp}`
- A GitHub pull URL

## Code Map

- `apps/frontend/index.html`: static shell and DOM targets
- `apps/frontend/app.js`: case picker, context fetch, render logic, draft PR click handler
- `apps/frontend/styles.css`: visual system and layout
- `apps/himalayas-api/src/server.ts`: API routes and fault trigger routes
- `apps/himalayas-api/src/faults/*`: intentionally broken paths used by the demo
- `apps/himalayas-orchestrator/src/server.ts`: `/health`, `/cases`, `/context/latest`, `/context/:id`, `/pr/draft`
- `apps/himalayas-orchestrator/src/context/buildContext.ts`: joins Sentry, CRM, Jira, source, and Anthropic diagnosis
- `apps/himalayas-orchestrator/src/clients/*`: Sentry, Jira, CRM, and Anthropic clients
- `apps/crm/customers.json`: demo account and support engineer data
- `packages/shared/src/faults.ts`: canonical fault list shared by API, orchestrator, and frontend case data
- `railway.json`: Railway build, start, and healthcheck config

## Adding A New Fault

1. Add the canonical case in `packages/shared/src/faults.ts`.
2. Add or update broken behavior in `apps/himalayas-api/src/faults/`.
3. Register the fault route in `apps/himalayas-api/src/server.ts`.
4. Add CRM data in `apps/crm/customers.json` if the account is new.
5. Add source mapping support in `apps/himalayas-orchestrator/src/context/sourceLoader.ts` if needed.
6. Add or verify Jira matching labels in the shared fault definition.
7. Run the read-only smoke tests.
8. Trigger the fault once only if Sentry capture needs verification.

## Known Caveats

- `POST /pr/draft` is intentionally stubbed.
- `data/cache/*.json` is ignored. If Anthropic is unavailable, there may be no fallback cache until a successful run writes one locally.
- Startup may log a Sentry warning about Express instrumentation. Health showed `sentry: true`, and context reads worked in local testing. If event capture is flaky, revisit import order around `apps/himalayas-api/src/instrument.ts`.
- `npm run seed-faults` writes real Sentry events and intentionally produces HTTP 500 responses.
- There is no CI yet.
- Do not run `npm build` for simple CSS, HTML, or TypeScript source edits unless dependencies or build behavior changed.

## Suggested Next Iterations

- Turn `/pr/draft` from a stub into real branch and PR creation.
- Add a browser test for the context page after `/context/latest` resolves.
- Add focused unit tests for `ContextBuilder` with mocked Sentry, CRM, Jira, and Anthropic clients.
- Improve diagnosis caching so the demo stays stable when Anthropic rate limits.
- Add a small admin or reset script for clearing local diagnosis cache.
- Add screenshot checks for the sidebar, case picker, diagnosis panel, and Sentry panel.
