import { faultCases, faultList, getFaultCase, type FaultCase } from "../../../../packages/shared/src/faults";
import type { AnthropicDiagnosisClient } from "../clients/anthropicClient";
import type { CrmClient } from "../clients/crmClient";
import type { JiraClient, RelatedJiraIssue } from "../clients/jiraClient";
import type { SentryClient } from "../clients/sentryClient";
import type { Diagnosis, ContextResponse, NormalizedSentryIssue, StackFrame } from "../types";
import type { DiagnosisCache } from "./cache";
import { readFaultSource } from "./sourceLoader";

export class ContextBuilder {
  constructor(
    private readonly sentry: SentryClient,
    private readonly crm: CrmClient,
    private readonly jira: JiraClient,
    private readonly anthropic: AnthropicDiagnosisClient,
    private readonly cache: DiagnosisCache
  ) {}

  async latest(faultKey: string): Promise<ContextResponse> {
    const fault = getFaultCase(faultKey);
    if (!fault) {
      throw new Error(`Unknown fault ${faultKey}`);
    }

    const sentry = await this.sentry.findLatestIssueForFault(fault);
    return this.build(fault, sentry);
  }

  async byIssue(issueId: string): Promise<ContextResponse> {
    const sentry = await this.sentry.getIssueContext(issueId);
    const fault = findFaultForSentry(sentry);
    return this.build(fault, sentry);
  }

  private async build(fault: FaultCase, sentry: NormalizedSentryIssue): Promise<ContextResponse> {
    const accountDomain = sentry.tags.account_domain || fault.accountDomain;
    const platform = sentry.tags.platform || fault.platform;
    const label = fault.issueLabel;

    const [account, assigneeMatch, related, source] = await Promise.all([
      this.crm.getAccountByDomain(accountDomain),
      this.crm.matchEngineer(platform, label).catch(() => ({ assignee: null, score: 0 })),
      this.jira.findRelatedIssue({
        preferredKey: fault.jiraKey,
        labels: fault.jiraLabels,
        errorType: sentry.errorType,
        message: sentry.message
      }).catch(() => undefined),
      readFaultSource(fault)
    ]);

    const { diagnosis, stale } = await this.generateDiagnosisWithCache({
      fault,
      sentry,
      account,
      related,
      source
    });

    const codeLocation = selectCodeLocation(sentry.frames, diagnosis);
    const assignee = assigneeMatch.assignee;

    return {
      ticket: {
        id: fault.ticket.id,
        title: sentry.issueTitle || fault.ticket.title,
        escalated_ago: formatAge(sentry.firstSeen),
        priority: fault.ticket.priority,
        tags: buildTicketTags(fault, sentry)
      },
      customer: {
        account: account.name,
        plan: account.plan,
        arr_usd: account.arr_usd,
        region: account.region,
        managed: account.managed,
        csm: account.csm
      },
      diagnosis,
      contacts: account.contacts.map((contact) => ({
        name: contact.name,
        role: contact.role,
        email: contact.email,
        source: "CRM"
      })),
      assignee: {
        name: assignee?.name ?? "Unassigned",
        role: assignee ? `${assignee.focus} · ${assignee.embedded_team}` : "No CRM match",
        why: assignee ? buildAssigneeReason(assignee.prior_fixes, assignee.embedded_team) : "No support engineer matched this case"
      },
      related: related ?? noRelatedIssue(),
      code_location: codeLocation,
      sentry: {
        issue_id: sentry.issueId,
        error_type: sentry.errorType,
        message: sentry.message,
        first_seen: sentry.firstSeen,
        events_24h: sentry.events24h,
        release: sentry.release,
        log_lines: sentry.logLines
      },
      ...(stale ? { stale: true } : {})
    };
  }

  private async generateDiagnosisWithCache(input: {
    fault: FaultCase;
    sentry: NormalizedSentryIssue;
    account: Parameters<AnthropicDiagnosisClient["generate"]>[0]["account"];
    related?: RelatedJiraIssue;
    source: { file: string; contents: string };
  }): Promise<{ diagnosis: Diagnosis; stale: boolean }> {
    try {
      const diagnosis = await this.anthropic.generate(input);
      await this.cache.write(input.fault.key, diagnosis);
      return { diagnosis, stale: false };
    } catch (error) {
      const cached = await this.cache.read(input.fault.key);
      if (cached) {
        return { diagnosis: cached, stale: true };
      }
      throw error;
    }
  }
}

function findFaultForSentry(sentry: NormalizedSentryIssue): FaultCase {
  const faultTag = sentry.tags.fault;
  if (faultTag && faultCases[faultTag as keyof typeof faultCases]) {
    return faultCases[faultTag as keyof typeof faultCases];
  }

  const byDomain = faultList.find((fault) => fault.accountDomain === sentry.tags.account_domain);
  if (byDomain) {
    return byDomain;
  }

  const byError = faultList.find((fault) => fault.errorType === sentry.errorType);
  if (byError) {
    return byError;
  }

  throw new Error(`Could not map Sentry issue ${sentry.issueId} to a demo fault`);
}

function buildTicketTags(fault: FaultCase, sentry: NormalizedSentryIssue): string[] {
  const tags = sentry.tags;
  return [
    `Region · ${tags.region || fault.region}`,
    `Platform · ${tags.platform || fault.platform}`,
    tags.locale || fault.locale ? `Locale · ${tags.locale || fault.locale}` : "",
    `API · ${tags.api_route || fault.apiRoute}`
  ].filter(Boolean);
}

function selectCodeLocation(frames: StackFrame[], diagnosis: Diagnosis): { file: string; lines: string } {
  const frame =
    [...frames].reverse().find((item) => item.in_app && item.file.includes("himalayas-api")) ||
    [...frames].reverse().find((item) => item.line > 0);

  if (frame) {
    return {
      file: frame.file,
      lines: frame.line ? `L${frame.line}` : "unknown"
    };
  }

  return {
    file: diagnosis.suggested_fix.file,
    lines: diagnosis.suggested_fix.line ? `L${diagnosis.suggested_fix.line}` : "unknown"
  };
}

function buildAssigneeReason(priorFixes: string[], embeddedTeam: string): string {
  const fixes = priorFixes.length ? `prior fixes ${priorFixes.join(", ")}` : "no prior fixes";
  return `${fixes}; embedded in ${embeddedTeam}`;
}

function noRelatedIssue(): RelatedJiraIssue {
  return {
    jira_key: "No match",
    jira_summary: "No Jira issue matched this Sentry event",
    jira_status: "unlinked",
    jira_url: ""
  };
}

function formatAge(value: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    return "unknown";
  }

  const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (seconds < 60) {
    return `${seconds}s ago`;
  }

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes}m ago`;
  }

  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}h ago`;
  }

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
