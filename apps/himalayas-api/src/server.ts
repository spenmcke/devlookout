import type { Express } from "express";
import { faultList, getFaultCase } from "../../../packages/shared/src/faults";
import { config } from "./config";
import { verifyForwardedMessageDkim } from "./faults/dkimVerifier";
import { sendBurstThroughPool } from "./faults/connectionPool";
import { sendWithLocaleSensitiveRetry } from "./faults/retryCoordinator";
import { scheduleWebhookRetries } from "./faults/webhookRetry";
import { asyncHandler, errorHandler, notFoundHandler } from "./http";
import { acceptWebhook, createMessage, getMessage } from "./messages/store";
import { initSentry, setupSentryErrorHandler, tagFault } from "./sentry";

async function main(): Promise<void> {
  const sentryEnabled = globalThis.__HIMALAYAS_SENTRY_READY
    ? await globalThis.__HIMALAYAS_SENTRY_READY
    : await initSentry();
  const { default: express } = await import("express");
  const app = express();

  app.use(express.json({ limit: "256kb" }));
  registerRoutes(app, () => sentryEnabled);
  app.use(notFoundHandler);
  setupSentryErrorHandler(app);
  app.use(errorHandler);

  app.listen(config.port, () => {
    console.log(`himalayas-api listening on http://localhost:${config.port}`);
  });
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

function registerRoutes(app: Express, sentryEnabled: () => boolean): void {
  app.get("/health", (_req, res) => {
    res.json({
      ok: true,
      service: "himalayas-api",
      sentry: sentryEnabled()
    });
  });

  app.post("/v2/messages", (req, res) => {
    const from = requiredString(req.body, "from");
    const to = requiredString(req.body, "to");
    const subject = requiredString(req.body, "subject");
    const body = requiredString(req.body, "body");

    if (!from || !to || !subject || !body) {
      res.status(400).json({
        error: {
          type: "ValidationError",
          message: "from, to, subject, and body are required"
        }
      });
      return;
    }

    const message = createMessage({
      from,
      to,
      subject,
      body,
      locale: optionalString(req.body, "locale")
    });

    res.status(202).json(message);
  });

  app.get("/v2/messages/:id", (req, res) => {
    const message = getMessage(req.params.id);
    if (!message) {
      res.status(404).json({
        error: {
          type: "NotFound",
          message: `message ${req.params.id} was not found`
        }
      });
      return;
    }

    res.json(message);
  });

  app.post("/v2/webhooks/test", (req, res) => {
    const messageId = requiredString(req.body, "message_id");
    if (!messageId) {
      res.status(400).json({
        error: {
          type: "ValidationError",
          message: "message_id is required"
        }
      });
      return;
    }

    const message = acceptWebhook(messageId);
    res.status(202).json({
      ok: true,
      message_id: messageId,
      status: message?.status ?? "accepted"
    });
  });

  app.post(
    "/faults/locale-expiry",
    asyncHandler(async (req, res) => {
      const fault = requireFault("locale-expiry");
      const accountDomain = optionalString(req.body, "account_domain") ?? fault.accountDomain;
      const locale = optionalString(req.body, "locale") ?? fault.locale ?? "ja_JP";
      tagFault(fault, { account_domain: accountDomain, locale });
      await sendWithLocaleSensitiveRetry(locale);
      res.json({ ok: true });
    })
  );

  app.post(
    "/faults/webhook-retry",
    asyncHandler(async (req, res) => {
      const fault = requireFault("webhook-retry");
      const accountDomain = optionalString(req.body, "account_domain") ?? fault.accountDomain;
      const region = optionalString(req.body, "region") ?? fault.region;
      tagFault(fault, { account_domain: accountDomain, region });
      await scheduleWebhookRetries(region);
      res.json({ ok: true });
    })
  );

  app.post(
    "/faults/pool-exhaust",
    asyncHandler(async (req, res) => {
      const fault = requireFault("pool-exhaust");
      const accountDomain = optionalString(req.body, "account_domain") ?? fault.accountDomain;
      tagFault(fault, { account_domain: accountDomain });
      await sendBurstThroughPool();
      res.json({ ok: true });
    })
  );

  app.post(
    "/faults/dkim-verify",
    asyncHandler(async (req, res) => {
      const fault = requireFault("dkim-verify");
      const accountDomain = optionalString(req.body, "account_domain") ?? fault.accountDomain;
      tagFault(fault, { account_domain: accountDomain });
      verifyForwardedMessageDkim();
      res.json({ ok: true });
    })
  );

  app.get("/faults", (_req, res) => {
    res.json({
      faults: faultList.map((fault) => ({
        key: fault.key,
        label: fault.label,
        route: fault.route,
        account_domain: fault.accountDomain,
        platform: fault.platform,
        region: fault.region,
        locale: fault.locale,
        api_route: fault.apiRoute
      }))
    });
  });
}

function requireFault(key: string) {
  const fault = getFaultCase(key);
  if (!fault) {
    throw new Error(`missing fault case ${key}`);
  }
  return fault;
}

function requiredString(body: unknown, key: string): string | undefined {
  if (!isRecord(body)) {
    return undefined;
  }

  const value = body[key];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function optionalString(body: unknown, key: string): string | undefined {
  if (!isRecord(body)) {
    return undefined;
  }

  const value = body[key];
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
