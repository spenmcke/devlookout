import { DateFormatError } from "../errors";
import { addBreadcrumb } from "../sentry";

type RetryToken = {
  value: string;
  expiryDisplay: string;
  expiryDate: Date;
};

export async function sendWithLocaleSensitiveRetry(locale: string): Promise<void> {
  addBreadcrumb("message send started", { route: "/v2/messages", locale });
  const token = await refreshTokenMidFlight(locale);
  addBreadcrumb("token refreshed mid-flight", { expiry: token.expiryDisplay });
  const expiry = parseExpiryForRetry(locale, token);
  addBreadcrumb("retry expiry parsed", { expiry: expiry.toISOString() });
}

async function refreshTokenMidFlight(locale: string): Promise<RetryToken> {
  await new Promise((resolve) => setTimeout(resolve, 8));

  if (locale === "ja_JP") {
    return {
      value: "tok_refresh_jp",
      expiryDisplay: "\u4ee4\u548c6\u5e74",
      expiryDate: new Date("2026-06-02T08:44:00.000Z")
    };
  }

  return {
    value: "tok_refresh_default",
    expiryDisplay: "2026-06-02T08:44:00.000Z",
    expiryDate: new Date("2026-06-02T08:44:00.000Z")
  };
}

function parseExpiryForRetry(locale: string, token: RetryToken): Date {
  addBreadcrumb("retry path parsing expiry", { locale, token: token.value });

  if (locale === "ja_JP") {
    return parseJapaneseEraDate(token.expiryDisplay);
  }

  const parsed = new Date(token.expiryDisplay);
  if (Number.isNaN(parsed.getTime())) {
    throw new DateFormatError(`unparseable date "${token.expiryDisplay}"`);
  }
  return parsed;
}

function parseJapaneseEraDate(value: string): Date {
  if (/\u4ee4\u548c\d+\u5e74/u.test(value)) {
    throw new DateFormatError(
      `unparseable date "${value}" - expected ISO-8601 in RetryCoordinator.parseExpiry()`
    );
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    throw new DateFormatError(`unparseable date "${value}"`);
  }
  return parsed;
}
