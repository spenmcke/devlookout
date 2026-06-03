import path from "node:path";
import cors from "cors";
import express from "express";
import { faultList } from "../../../packages/shared/src/faults";
import { AnthropicDiagnosisClient } from "./clients/anthropicClient";
import { CrmClient } from "./clients/crmClient";
import { JiraClient } from "./clients/jiraClient";
import { SentryClient } from "./clients/sentryClient";
import { config } from "./config";
import { ContextBuilder } from "./context/buildContext";
import { DiagnosisCache } from "./context/cache";

const app = express();

const builder = new ContextBuilder(
  new SentryClient(config.sentry),
  new CrmClient(config.crmBaseUrl),
  new JiraClient(config.jira),
  new AnthropicDiagnosisClient(config.anthropic),
  new DiagnosisCache(config.cacheDir)
);

app.use(cors());
app.use(express.json({ limit: "512kb" }));

app.get("/health", (_req, res) => {
  const jiraDirect = Boolean(config.jira.baseUrl && (config.jira.bearerToken || (config.jira.email && config.jira.apiToken)));
  const jiraOauth = Boolean(config.jira.bearerToken && !config.jira.baseUrl);
  const jiraBasicMissing =
    Boolean(config.jira.apiToken) && (!config.jira.baseUrl || !config.jira.email) && !config.jira.bearerToken;

  res.json({
    ok: true,
    service: "himalayas-orchestrator",
    crm: config.crmBaseUrl,
    sentry: Boolean(config.sentry.authToken || config.sentry.legacyApiKey),
    jira: {
      configured: jiraDirect || jiraOauth,
      mode: jiraDirect && config.jira.email ? "basic" : jiraOauth ? "oauth" : "missing",
      missing_basic_fields: jiraBasicMissing ? ["ATLASSIAN_BASE_URL", "ATLASSIAN_EMAIL"] : []
    },
    anthropic: Boolean(config.anthropic.apiKey)
  });
});

app.get("/cases", (_req, res) => {
  res.json({
    cases: faultList.map((fault) => ({
      key: fault.key,
      label: fault.label,
      account_domain: fault.accountDomain,
      platform: fault.platform,
      region: fault.region,
      api_route: fault.apiRoute
    }))
  });
});

app.get("/context/latest", async (req, res, next) => {
  try {
    const fault = typeof req.query.fault === "string" ? req.query.fault : "locale-expiry";
    res.json(await builder.latest(fault));
  } catch (error) {
    next(error);
  }
});

app.get("/context/:sentryIssueId", async (req, res, next) => {
  try {
    res.json(await builder.byIssue(req.params.sentryIssueId));
  } catch (error) {
    next(error);
  }
});

app.post("/pr/draft", async (req, res) => {
  const fault = typeof req.body?.fault === "string" ? req.body.fault : "latest";
  const branch = `everest/${fault}/${Date.now()}`;
  res.status(202).json({
    status: "stubbed",
    branch,
    url: `https://github.com/himalayas/email-api/pull/new/${encodeURIComponent(branch)}`,
    message: "Draft PR creation is wired as a stub for this demo phase."
  });
});

app.use(express.static(path.resolve(process.cwd(), "apps/frontend")));

app.use((error: unknown, _req: express.Request, res: express.Response, next: express.NextFunction) => {
  if (res.headersSent) {
    next(error);
    return;
  }

  const err = error instanceof Error ? error : new Error(String(error));
  res.status(500).json({
    error: {
      type: err.name,
      message: err.message
    }
  });
});

app.listen(config.port, () => {
  console.log(`himalayas-orchestrator listening on http://localhost:${config.port}`);
});
