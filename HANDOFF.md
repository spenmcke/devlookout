# EverestAI Sentry Demo Handoff

最后验证日期：2026-06-03

GitHub repo: `https://github.com/yolandaycao/demo-sentry`

当前 repo 是 private。`.env`、`node_modules/`、`dist/` 和 `data/cache/*.json` 都被 `.gitignore` 排除，不会随代码推送。

## Demo 目标

这个 demo 展示 Everest 如何把一个 production incident 自动整理成 engineer 可行动的 escalation context。

核心体验：

- `himalayas-api` 负责制造和发送真实 Sentry fault events。
- `himalayas-orchestrator` 聚合 Sentry、CRM、Jira 和 Anthropic，返回一个 context JSON。
- `apps/frontend` 是静态 Everest context screen，由 orchestrator 直接服务。
- `apps/crm` 是本地 Flask CRM service，使用 `customers.json`。

打开 `http://localhost:8080` 后，case picker 会加载 `/cases`，然后用 `/context/latest?fault={key}` 渲染 ticket、customer、diagnosis、Jira、assignee 和 suggested fix。

## 本地 Setup

```bash
git clone https://github.com/yolandaycao/demo-sentry.git
cd demo-sentry
npm install
python3 -m pip install flask flask-cors
```

复制 env 模板：

```bash
cp .env.example .env
```

需要的 live demo secrets：

```bash
SENTRY_AUTH_TOKEN=
SENTRY_ORG_SLUG=
SENTRY_PROJECT_SLUG=himalayas-api

ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-sonnet-4-5-20250929

ATLASSIAN_BASE_URL=
ATLASSIAN_EMAIL=
ATLASSIAN_API_KEY=
JIRA_PROJECT_KEY=HIM
```

`SENTRY_DSN` 可以直接设置，也可以不设。当前代码支持用 Sentry token、org slug 和 project slug 自动读取 active project client key。

## Run

```bash
npm run dev
```

预期服务：

- CRM: `http://localhost:8787`
- API: `http://localhost:7070`
- Orchestrator and frontend: `http://localhost:8080`

## Read-Only Smoke Tests

这些不会写 Sentry，适合每次改动后快速验证。

```bash
curl -sS http://localhost:8787/health
curl -sS http://localhost:7070/health
curl -sS http://localhost:8080/health
curl -sS http://localhost:8080/cases
curl -sS 'http://localhost:8080/context/latest?fault=locale-expiry'
```

关键预期：

- CRM health 返回 `himalayas-crm`
- API health 返回 `himalayas-api`，并且 `sentry` 为 `true`
- Orchestrator health 返回 `sentry: true`、`anthropic: true`、`jira.configured: true`
- `/cases` 返回 4 个 demo faults
- `/context/latest?fault=locale-expiry` 返回 `ESC-2418`、`Kintaro K.K.`、`HIM-2`、`Dan Kim` 和 `DateFormatError`

## Browser Check

打开：

```bash
open http://localhost:8080
```

首屏应该显示：

- 左侧 Everest sidebar
- topbar 的 case picker
- ticket `ESC-2418`
- customer `Kintaro K.K.`
- Diagnosis panel
-右侧 Sentry read-only panel
- Suggested fix 和 `Open draft PR` button

最近 UI 改动：左上 logo 已从较圆的 22px mark 改为更 square 的 24px mark，`border-radius` 是 `3px`。对应文件是 `apps/frontend/styles.css`。

## Live Sentry Event Tests

这些会写真实 Sentry events。只有需要验证 capture flow 时再跑。

```bash
npm run seed-faults
```

或者单独触发一个 fault：

```bash
curl -X POST http://localhost:7070/faults/locale-expiry \
  -H 'content-type: application/json' \
  -d '{"account_domain":"kintaro.jp","locale":"ja_JP"}'
```

注意：fault endpoints 故意抛错，所以返回 HTTP 500 是 expected。目标是让 Sentry SDK capture exception。

## Draft PR Flow

当前 `POST /pr/draft` 是 stub，不会创建真实 GitHub PR。

```bash
curl -sS -X POST http://localhost:8080/pr/draft \
  -H 'content-type: application/json' \
  -d '{"fault":"locale-expiry"}'
```

预期返回：

- `status: "stubbed"`
- 一个 `everest/{fault}/{timestamp}` branch name
- 一个 GitHub pull URL

## 代码地图

- `apps/frontend/index.html`: static shell and DOM targets
- `apps/frontend/app.js`: case picker, context fetch, render logic, draft PR click handler
- `apps/frontend/styles.css`: visual system and layout
- `apps/himalayas-api/src/server.ts`: API routes and fault trigger routes
- `apps/himalayas-api/src/faults/*`: intentionally broken code paths used by the demo
- `apps/himalayas-orchestrator/src/server.ts`: `/health`、`/cases`、`/context/latest`、`/context/:id`、`/pr/draft`
- `apps/himalayas-orchestrator/src/context/buildContext.ts`: joins Sentry, CRM, Jira, source, Anthropic diagnosis
- `apps/himalayas-orchestrator/src/clients/*`: Sentry, Jira, CRM, Anthropic clients
- `apps/crm/customers.json`: demo account and support engineer data
- `packages/shared/src/faults.ts`: canonical fault list used by API, orchestrator and frontend case data

## Adding A New Fault

1. Add the canonical case in `packages/shared/src/faults.ts`.
2. Add or update broken behavior in `apps/himalayas-api/src/faults/`.
3. Register the fault route in `apps/himalayas-api/src/server.ts`.
4. Add CRM data in `apps/crm/customers.json` if the account is new.
5. Add source mapping support if needed in `apps/himalayas-orchestrator/src/context/sourceLoader.ts`.
6. Add or verify Jira matching labels in the shared fault definition.
7. Run read-only smoke tests.
8. Trigger the fault once only if Sentry capture needs verification.

## Known Caveats

- `POST /pr/draft` is intentionally stubbed.
- `data/cache/*.json` is ignored. If Anthropic is unavailable, there may be no fallback cache until a successful run writes one locally.
- Startup may log a Sentry warning about Express instrumentation. Health showed `sentry: true`, and context reads worked in local testing. If new event capture becomes flaky, revisit import order around `apps/himalayas-api/src/instrument.ts`.
- `npm run seed-faults` writes real events and intentionally produces HTTP 500 responses.
- There is no CI yet.
- No need to run `npm build` for CSS, HTML or TypeScript source edits unless packages or build behavior change.

## Suggested Next Iterations

- Turn `/pr/draft` from stub into a real branch and PR creation flow.
- Add a browser test for the context page after `/context/latest` resolves.
- Add focused unit tests for `ContextBuilder` with mocked Sentry, CRM, Jira and Anthropic clients.
- Improve diagnosis caching so demo remains stable when Anthropic rate limits.
- Add a small admin or reset script for clearing local diagnosis cache.
- Add screenshot-based checks for the sidebar, case picker, diagnosis panel and Sentry panel.
