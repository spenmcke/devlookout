import type { FaultCase } from "../../../../packages/shared/src/faults";
import { buildUrl, fetchJson, HttpError } from "../http";
import type { NormalizedSentryIssue, StackFrame } from "../types";

type SentryConfig = {
  authToken: string;
  legacyApiKey: string;
  baseUrl: string;
  orgSlug: string;
  projectSlug: string;
};

type ProjectRef = {
  orgSlug: string;
  projectSlug: string;
};

type RawSentryIssue = Record<string, unknown>;
type RawSentryEvent = Record<string, unknown>;

export class SentryClient {
  private projectRef?: ProjectRef;

  constructor(private readonly config: SentryConfig) {}

  async findLatestIssueForFault(fault: FaultCase): Promise<NormalizedSentryIssue> {
    const queries = [
      `is:unresolved fault:${fault.key}`,
      `is:unresolved account_domain:${fault.accountDomain}`,
      `fault:${fault.key}`,
      `account_domain:${fault.accountDomain}`,
      `${fault.errorType}`
    ];

    for (const query of queries) {
      const issues = await this.listProjectIssues(query);
      for (const issue of issues.slice(0, 8)) {
        const issueId = readString(issue, "id");
        if (!issueId) {
          continue;
        }

        const event = await this.getLatestEvent(issueId);
        const normalized = await this.normalize(issue, event, fault);
        if (this.matchesFault(normalized.tags, fault)) {
          return normalized;
        }
      }
    }

    throw new Error(`No Sentry issue found for fault ${fault.key}`);
  }

  async getIssueContext(issueId: string, fallbackFault?: FaultCase): Promise<NormalizedSentryIssue> {
    const [issue, event] = await Promise.all([this.getIssue(issueId), this.getLatestEvent(issueId)]);
    return this.normalize(issue, event, fallbackFault);
  }

  private async listProjectIssues(query: string): Promise<RawSentryIssue[]> {
    const project = await this.resolveProject();
    try {
      return await fetchJson<RawSentryIssue[]>(
        buildUrl(this.config.baseUrl, `/api/0/projects/${project.orgSlug}/${project.projectSlug}/issues/`, {
          query,
          sort: "date",
          limit: 25
        }),
        {
          headers: this.authHeader()
        },
        9000
      );
    } catch (error) {
      throw this.describeSentryError(error, `read issues for ${project.orgSlug}/${project.projectSlug}`);
    }
  }

  private async getIssue(issueId: string): Promise<RawSentryIssue> {
    try {
      return await fetchJson<RawSentryIssue>(
        buildUrl(this.config.baseUrl, `/api/0/issues/${encodeURIComponent(issueId)}/`),
        {
          headers: this.authHeader()
        },
        9000
      );
    } catch (error) {
      throw this.describeSentryError(error, `read issue ${issueId}`);
    }
  }

  private async getLatestEvent(issueId: string): Promise<RawSentryEvent> {
    try {
      return await fetchJson<RawSentryEvent>(
        buildUrl(this.config.baseUrl, `/api/0/issues/${encodeURIComponent(issueId)}/events/latest/`),
        {
          headers: this.authHeader()
        },
        9000
      );
    } catch (error) {
      throw this.describeSentryError(error, `read latest event for issue ${issueId}`);
    }
  }

  private async normalize(
    issue: RawSentryIssue,
    event: RawSentryEvent,
    fallbackFault?: FaultCase
  ): Promise<NormalizedSentryIssue> {
    const issueId = readString(issue, "id") || readString(event, "groupID") || "";
    const exception = extractException(event);
    const tags = normalizeTags(event.tags ?? issue.tags);
    const frames = extractFrames(exception);
    const statsCount = await this.getEvents24h(issueId).catch(() => undefined);

    return {
      issueId,
      issueTitle: readString(issue, "title") || readString(event, "title") || fallbackFault?.ticket.title || "Sentry issue",
      culprit: readString(issue, "culprit") || readString(event, "culprit") || "",
      errorType:
        readString(exception, "type") ||
        readNestedString(issue, ["metadata", "type"]) ||
        fallbackFault?.errorType ||
        "Error",
      message:
        readString(exception, "value") ||
        readNestedString(issue, ["metadata", "value"]) ||
        readString(event, "message") ||
        readString(issue, "title") ||
        "No Sentry message",
      firstSeen: readString(issue, "firstSeen") || readString(event, "dateCreated") || new Date().toISOString(),
      events24h: statsCount ?? readNumber(issue, "count") ?? 1,
      release: extractRelease(event) || fallbackFault?.release || "unknown",
      tags,
      frames,
      logLines: extractLogLines(event, frames)
    };
  }

  private async getEvents24h(issueId: string): Promise<number | undefined> {
    if (!issueId) {
      return undefined;
    }

    const since = Math.floor((Date.now() - 24 * 60 * 60 * 1000) / 1000);
    const stats = await fetchJson<unknown>(
      buildUrl(this.config.baseUrl, `/api/0/issues/${encodeURIComponent(issueId)}/stats/`, {
        since,
        resolution: "1h"
      }),
      {
        headers: this.authHeader()
      },
      9000
    );

    if (!Array.isArray(stats)) {
      return undefined;
    }

    return stats.reduce((sum, point) => {
      if (!Array.isArray(point)) {
        return sum;
      }
      const count = Number(point[1]);
      return sum + (Number.isFinite(count) ? count : 0);
    }, 0);
  }

  private matchesFault(tags: Record<string, string>, fault: FaultCase): boolean {
    if (tags.fault === fault.key) {
      return true;
    }

    return tags.account_domain === fault.accountDomain || tags.account === fault.accountDomain;
  }

  private async resolveProject(): Promise<ProjectRef> {
    if (this.projectRef) {
      return this.projectRef;
    }

    this.assertToken();

    if (this.config.orgSlug && this.config.projectSlug) {
      this.projectRef = {
        orgSlug: this.config.orgSlug,
        projectSlug: this.config.projectSlug
      };
      return this.projectRef;
    }

    const organizations = await fetchJson<Array<Record<string, unknown>>>(
      buildUrl(this.config.baseUrl, "/api/0/organizations/"),
      {
        headers: this.authHeader()
      },
      9000
    );

    const orgSlug = this.config.orgSlug || readString(organizations[0], "slug");
    if (!orgSlug) {
      throw new Error("Sentry organization could not be discovered");
    }

    const projects = await fetchJson<Array<Record<string, unknown>>>(
      buildUrl(this.config.baseUrl, `/api/0/organizations/${orgSlug}/projects/`),
      {
        headers: this.authHeader()
      },
      9000
    );

    const configuredProject = projects.find((project) => readString(project, "slug") === this.config.projectSlug);
    const himalayasProject = projects.find((project) => /himalayas/i.test(readString(project, "slug")));
    const projectSlug = readString(configuredProject, "slug") || readString(himalayasProject, "slug") || readString(projects[0], "slug");

    if (!projectSlug) {
      throw new Error("Sentry project could not be discovered");
    }

    this.projectRef = { orgSlug, projectSlug };
    return this.projectRef;
  }

  private authHeader(): Record<string, string> {
    this.assertToken();
    if (this.config.authToken) {
      return {
        Authorization: `Bearer ${this.config.authToken}`
      };
    }

    return {
      Authorization: `Basic ${Buffer.from(`${this.config.legacyApiKey}:`).toString("base64")}`
    };
  }

  private assertToken(): void {
    if (!this.config.authToken && !this.config.legacyApiKey) {
      throw new Error("Sentry token missing. Set SENTRY_AUTH_TOKEN, SENTRY_API_KEY, or SENTRY_LEGACY_API_KEY.");
    }
  }

  private describeSentryError(error: unknown, action: string): Error {
    if (error instanceof HttpError && error.status === 403) {
      return new Error(
        `Sentry returned 403 while trying to ${action}. Confirm SENTRY_ORG_SLUG, SENTRY_PROJECT_SLUG, and a token with project:read, event:read, and org:read scopes.`
      );
    }

    if (error instanceof HttpError && error.status === 404) {
      return new Error(
        `Sentry returned 404 while trying to ${action}. Confirm the configured org and project identifiers.`
      );
    }

    return error instanceof Error ? error : new Error(String(error));
  }
}

function extractException(event: RawSentryEvent): Record<string, unknown> {
  const directValues = readNestedArray(event, ["exception", "values"]);
  const direct = lastRecord(directValues);
  if (direct) {
    return direct;
  }

  const entries = Array.isArray(event.entries) ? event.entries : [];
  for (const entry of entries) {
    if (!isRecord(entry) || entry.type !== "exception") {
      continue;
    }
    const values = readNestedArray(entry, ["data", "values"]);
    const value = lastRecord(values);
    if (value) {
      return value;
    }
  }

  return {};
}

function extractFrames(exception: Record<string, unknown>): StackFrame[] {
  const frames = readNestedArray(exception, ["stacktrace", "frames"]);
  return frames.filter(isRecord).map((frame) => ({
    file: readString(frame, "filename") || readString(frame, "absPath") || readString(frame, "module") || "unknown",
    line: readNumber(frame, "lineno") ?? 0,
    function: readString(frame, "function") || "<anonymous>",
    in_app: readBoolean(frame, "in_app")
  }));
}

function extractLogLines(event: RawSentryEvent, frames: StackFrame[]): string[] {
  const entries = Array.isArray(event.entries) ? event.entries : [];
  const breadcrumbs: string[] = [];

  for (const entry of entries) {
    if (!isRecord(entry) || entry.type !== "breadcrumbs") {
      continue;
    }

    const values = readNestedArray(entry, ["data", "values"]);
    for (const value of values) {
      if (!isRecord(value)) {
        continue;
      }
      const timestamp = readString(value, "timestamp") || "";
      const level = readString(value, "level") || "info";
      const message = readString(value, "message") || readString(value, "category") || "breadcrumb";
      breadcrumbs.push(`${timestamp} ${level.toUpperCase()} ${message}`.trim());
    }
  }

  if (breadcrumbs.length) {
    return breadcrumbs.slice(-40);
  }

  return frames.slice(-12).map((frame) => `${frame.file}:${frame.line} in ${frame.function}`);
}

function extractRelease(event: RawSentryEvent): string | undefined {
  const release = event.release;
  if (typeof release === "string") {
    return release;
  }
  if (isRecord(release)) {
    return readString(release, "version") || readString(release, "shortVersion");
  }
  return readNestedString(event, ["contexts", "trace", "release"]);
}

function normalizeTags(input: unknown): Record<string, string> {
  const tags: Record<string, string> = {};

  if (Array.isArray(input)) {
    for (const tag of input) {
      if (Array.isArray(tag) && tag.length >= 2) {
        tags[String(tag[0])] = String(tag[1]);
        continue;
      }

      if (isRecord(tag)) {
        const key = readString(tag, "key") || readString(tag, "name");
        const value = readString(tag, "value");
        if (key && value) {
          tags[key] = value;
        }
      }
    }
  }

  if (isRecord(input)) {
    for (const [key, value] of Object.entries(input)) {
      if (typeof value === "string") {
        tags[key] = value;
      }
    }
  }

  return tags;
}

function readString(record: unknown, key: string): string {
  if (!isRecord(record)) {
    return "";
  }
  const value = record[key];
  return typeof value === "string" ? value : "";
}

function readNumber(record: unknown, key: string): number | undefined {
  if (!isRecord(record)) {
    return undefined;
  }
  const value = record[key];
  const parsed = typeof value === "number" ? value : typeof value === "string" ? Number(value) : Number.NaN;
  return Number.isFinite(parsed) ? parsed : undefined;
}

function readBoolean(record: unknown, key: string): boolean {
  if (!isRecord(record)) {
    return false;
  }
  return record[key] === true;
}

function readNestedString(record: unknown, path: string[]): string {
  const value = readNested(record, path);
  return typeof value === "string" ? value : "";
}

function readNestedArray(record: unknown, path: string[]): unknown[] {
  const value = readNested(record, path);
  return Array.isArray(value) ? value : [];
}

function readNested(record: unknown, path: string[]): unknown {
  let current: unknown = record;
  for (const key of path) {
    if (!isRecord(current)) {
      return undefined;
    }
    current = current[key];
  }
  return current;
}

function lastRecord(values: unknown[]): Record<string, unknown> | undefined {
  for (let index = values.length - 1; index >= 0; index -= 1) {
    const value = values[index];
    if (isRecord(value)) {
      return value;
    }
  }
  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
