import * as Sentry from "@sentry/node";
import type { FaultCase } from "../../../packages/shared/src/faults";
import { sentryTagsForFault } from "../../../packages/shared/src/faults";
import { config } from "./config";
import { resolveSentryDsn } from "./sentryDsn";

let enabled = false;

export async function initSentry(): Promise<boolean> {
  const dsn = await resolveSentryDsn();
  if (!dsn) {
    enabled = false;
    return false;
  }

  Sentry.init({
    dsn,
    environment: config.environment,
    release: config.release,
    tracesSampleRate: 1.0,
    sendDefaultPii: false,
    integrations: [Sentry.httpIntegration()]
  });

  enabled = true;
  return true;
}

export function setupSentryErrorHandler(app: unknown): void {
  if (!enabled) {
    return;
  }

  Sentry.setupExpressErrorHandler(app as Parameters<typeof Sentry.setupExpressErrorHandler>[0]);
}

export function tagFault(fault: FaultCase, overrides: Record<string, string | undefined> = {}): void {
  const tags = { ...sentryTagsForFault(fault), ...compact(overrides) };
  const scope = Sentry.getCurrentScope();

  for (const [key, value] of Object.entries(tags)) {
    scope.setTag(key, value);
  }

  scope.setContext("himalayas_fault", {
    fault: fault.key,
    account_domain: tags.account_domain,
    platform: tags.platform,
    region: tags.region,
    locale: tags.locale,
    api_route: tags.api_route
  });
}

export function addBreadcrumb(message: string, data: Record<string, string | number | boolean> = {}): void {
  Sentry.addBreadcrumb({
    category: "himalayas",
    level: "info",
    message,
    data
  });
}

function compact(input: Record<string, string | undefined>): Record<string, string> {
  const output: Record<string, string> = {};
  for (const [key, value] of Object.entries(input)) {
    if (value) {
      output[key] = value;
    }
  }
  return output;
}
