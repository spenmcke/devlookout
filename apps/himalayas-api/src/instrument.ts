import { initSentry } from "./sentry";

declare global {
  var __HIMALAYAS_SENTRY_READY: Promise<boolean> | undefined;
}

globalThis.__HIMALAYAS_SENTRY_READY ??= initSentry();
