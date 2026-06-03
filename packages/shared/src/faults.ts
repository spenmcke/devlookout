export type FaultKey = "locale-expiry" | "webhook-retry" | "pool-exhaust" | "dkim-verify";

export type FaultCase = {
  key: FaultKey;
  label: string;
  route: string;
  accountDomain: string;
  platform: string;
  region: string;
  locale?: string;
  apiRoute: string;
  issueLabel: string;
  errorType: string;
  ticket: {
    id: string;
    title: string;
    priority: string;
  };
  release: string;
  jiraLabels: string[];
  jiraKey: string;
  sourceFile: string;
};

export const faultCases: Record<FaultKey, FaultCase> = {
  "locale-expiry": {
    key: "locale-expiry",
    label: "ja_JP locale expiry",
    route: "/faults/locale-expiry",
    accountDomain: "kintaro.jp",
    platform: "ios",
    region: "APAC",
    locale: "ja_JP",
    apiRoute: "/v2/messages",
    issueLabel: "locale",
    errorType: "DateFormatError",
    ticket: {
      id: "ESC-2418",
      title: "Message retry fails after token refresh for ja_JP mobile users",
      priority: "P1 · blocker"
    },
    release: "ios@8.21.0",
    jiraLabels: ["locale", "ios"],
    jiraKey: "HIM-2",
    sourceFile: "apps/himalayas-api/src/faults/retryCoordinator.ts"
  },
  "webhook-retry": {
    key: "webhook-retry",
    label: "EU webhook retry stall",
    route: "/faults/webhook-retry",
    accountDomain: "northwind.io",
    platform: "server",
    region: "EMEA",
    apiRoute: "/v2/webhooks",
    issueLabel: "webhooks",
    errorType: "RetryScheduleError",
    ticket: {
      id: "ESC-2440",
      title: "Webhook delivery stalls on the fourth EMEA retry attempt",
      priority: "P1 · blocker"
    },
    release: "api@2.14.3",
    jiraLabels: ["webhooks", "delivery"],
    jiraKey: "HIM-1",
    sourceFile: "apps/himalayas-api/src/faults/webhookRetry.ts"
  },
  "pool-exhaust": {
    key: "pool-exhaust",
    label: "Connection pool exhaustion",
    route: "/faults/pool-exhaust",
    accountDomain: "pineconeretail.com",
    platform: "android",
    region: "NA",
    apiRoute: "/v2/messages",
    issueLabel: "HIM-7",
    errorType: "PoolTimeoutError",
    ticket: {
      id: "ESC-2447",
      title: "Burst sends exhaust the bounded message connection pool",
      priority: "P2 · degraded"
    },
    release: "android@4.9.2",
    jiraLabels: ["pool", "android"],
    jiraKey: "HIM-7",
    sourceFile: "apps/himalayas-api/src/faults/connectionPool.ts"
  },
  "dkim-verify": {
    key: "dkim-verify",
    label: "DKIM false negative",
    route: "/faults/dkim-verify",
    accountDomain: "velto.de",
    platform: "server",
    region: "EMEA",
    apiRoute: "/v2/messages",
    issueLabel: "deliverability",
    errorType: "DkimVerificationError",
    ticket: {
      id: "ESC-2451",
      title: "Forwarded messages fail DKIM verification with multiple signatures",
      priority: "P1 · blocker"
    },
    release: "api@2.14.3",
    jiraLabels: ["dkim", "deliverability"],
    jiraKey: "HIM-3",
    sourceFile: "apps/himalayas-api/src/faults/dkimVerifier.ts"
  }
};

export const faultList = Object.values(faultCases);

export function getFaultCase(key: string): FaultCase | undefined {
  return faultCases[key as FaultKey];
}

export function sentryTagsForFault(fault: FaultCase): Record<string, string> {
  return {
    account_domain: fault.accountDomain,
    platform: fault.platform,
    region: fault.region,
    locale: fault.locale ?? "",
    api_route: fault.apiRoute,
    fault: fault.key
  };
}
