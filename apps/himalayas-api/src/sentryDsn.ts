import { config } from "./config";

type SentryKey = {
  isActive?: boolean;
  dsn?: {
    public?: string;
  };
};

export async function resolveSentryDsn(): Promise<string> {
  if (config.sentryDsn) {
    return config.sentryDsn;
  }

  if (!config.sentryOrgSlug || !config.sentryProjectSlug) {
    return "";
  }

  const headers = sentryAuthHeaders();
  if (!headers) {
    return "";
  }

  const url = new URL(
    `/api/0/projects/${encodeURIComponent(config.sentryOrgSlug)}/${encodeURIComponent(config.sentryProjectSlug)}/keys/`,
    config.sentryBaseUrl
  );

  try {
    const response = await fetch(url, { headers });
    if (!response.ok) {
      console.warn(
        `Sentry DSN discovery failed with ${response.status}. Set SENTRY_DSN directly, or use a Sentry token with project:read for the configured org and project.`
      );
      return "";
    }

    const keys = (await response.json()) as SentryKey[];
    const active = keys.find((key) => key.isActive !== false && key.dsn?.public);
    return active?.dsn?.public ?? "";
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`Sentry DSN discovery failed: ${message}`);
    return "";
  }
}

function sentryAuthHeaders(): Record<string, string> | undefined {
  if (config.sentryAuthToken) {
    return {
      Authorization: `Bearer ${config.sentryAuthToken}`
    };
  }

  if (config.sentryLegacyApiKey) {
    return {
      Authorization: `Basic ${Buffer.from(`${config.sentryLegacyApiKey}:`).toString("base64")}`
    };
  }

  return undefined;
}
