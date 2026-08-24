import path from "node:path";
import { envNumber, firstEnv, loadEnvFiles } from "../../../packages/shared/src/env";

loadEnvFiles();

export const config = {
  port: envNumber("PORT", envNumber("ORCHESTRATOR_PORT", 8080)),
  crmBaseUrl: firstEnv(["CRM_BASE_URL"], "http://localhost:8787"),
  cacheDir: firstEnv(["DIAGNOSIS_CACHE_DIR"], path.resolve(process.cwd(), "data/cache")),
  sentry: {
    authToken: firstEnv(["SENTRY_PERSONAL_TOKEN", "SENTRY_AUTH_TOKEN", "SENTRY_ORG_TOKEN", "SENTRY_API_KEY"]),
    legacyApiKey: firstEnv(["SENTRY_LEGACY_API_KEY"]),
    baseUrl: firstEnv(["SENTRY_BASE_URL", "SENTRY_API_BASE_URL"], "https://sentry.io"),
    orgSlug: firstEnv(["SENTRY_ORG_SLUG", "SENTRY_ORG"]),
    projectSlug: firstEnv(["SENTRY_PROJECT_SLUG", "SENTRY_PROJECT"], "himalayas-api")
  },
  jira: {
    baseUrl: firstEnv(["ATLASSIAN_BASE_URL", "JIRA_BASE_URL"]),
    email: firstEnv(["ATLASSIAN_EMAIL", "JIRA_EMAIL"]),
    apiToken: firstEnv(["ATLASSIAN_API_KEY", "JIRA_API_TOKEN"]),
    bearerToken: firstEnv(["ATLASSIAN_BEARER_TOKEN", "JIRA_BEARER_TOKEN"]),
    projectKey: firstEnv(["JIRA_PROJECT_KEY", "ATLASSIAN_PROJECT_KEY"], "HIM")
  },
  anthropic: {
    apiKey: firstEnv(["ANTHROPIC_API_KEY", "ANTHROPIC_KEY"]),
    model: firstEnv(["ANTHROPIC_MODEL"], "claude-sonnet-4-5-20250929"),
    timeoutMs: envNumber("ANTHROPIC_TIMEOUT_MS", 30000)
  }
};
