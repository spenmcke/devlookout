import { envNumber, firstEnv, loadEnvFiles } from "../../../packages/shared/src/env";

loadEnvFiles();

export const config = {
  port: envNumber("HIMALAYAS_API_PORT", 7070),
  sentryDsn: firstEnv(["SENTRY_DSN"]),
  sentryAuthToken: firstEnv(["SENTRY_PERSONAL_TOKEN", "SENTRY_AUTH_TOKEN", "SENTRY_ORG_TOKEN", "SENTRY_API_KEY"]),
  sentryLegacyApiKey: firstEnv(["SENTRY_LEGACY_API_KEY"]),
  sentryBaseUrl: firstEnv(["SENTRY_BASE_URL", "SENTRY_API_BASE_URL"], "https://sentry.io"),
  sentryOrgSlug: firstEnv(["SENTRY_ORG_SLUG", "SENTRY_ORG"]),
  sentryProjectSlug: firstEnv(["SENTRY_PROJECT_SLUG", "SENTRY_PROJECT"], "himalayas-api"),
  environment: firstEnv(["NODE_ENV"], "development"),
  release: firstEnv(["HIMALAYAS_API_RELEASE"], "api@2.14.3")
};
