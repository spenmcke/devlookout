import { buildUrl, fetchJson } from "../http";

type JiraConfig = {
  baseUrl: string;
  email: string;
  apiToken: string;
  bearerToken: string;
  projectKey: string;
};

type JiraSearchResponse = {
  issues?: Array<{
    key: string;
    fields?: {
      summary?: string;
      status?: {
        name?: string;
      };
    };
  }>;
};

type JiraIssue = {
  key: string;
  fields?: {
    summary?: string;
    status?: {
      name?: string;
    };
  };
};

type JiraResource = {
  id?: string;
  url?: string;
  name?: string;
  scopes?: string[];
};

type JiraTarget = {
  baseUrl: string;
  browserBaseUrl: string;
  headers: Record<string, string>;
};

export type RelatedJiraIssue = {
  jira_key: string;
  jira_summary: string;
  jira_status: string;
  jira_url: string;
};

export class JiraClient {
  private target?: JiraTarget;

  constructor(private readonly config: JiraConfig) {}

  async findRelatedIssue(input: {
    preferredKey?: string;
    labels: string[];
    errorType: string;
    message: string;
  }): Promise<RelatedJiraIssue | undefined> {
    const target = await this.resolveTarget();
    if (!target) {
      return undefined;
    }

    if (input.preferredKey) {
      const preferred = await this.getIssueByKey(target, input.preferredKey).catch(() => undefined);
      if (preferred) {
        return this.toRelatedIssue(target, preferred);
      }
    }

    const jql = this.buildJql(input.labels, input.errorType, input.message);
    const response = await fetchJson<JiraSearchResponse>(
      buildUrl(target.baseUrl, "/rest/api/3/search/jql"),
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...target.headers
        },
        body: JSON.stringify({
          jql,
          maxResults: 5,
          fields: ["summary", "status", "labels"]
        })
      },
      8000
    );

    const issue = response.issues?.[0];
    if (!issue) {
      return undefined;
    }

    return this.toRelatedIssue(target, issue);
  }

  private async getIssueByKey(target: JiraTarget, key: string): Promise<JiraIssue> {
    return fetchJson<JiraIssue>(
      buildUrl(target.baseUrl, `/rest/api/3/issue/${encodeURIComponent(key)}`, {
        fields: "summary,status,labels"
      }),
      {
        headers: target.headers
      },
      8000
    );
  }

  private toRelatedIssue(target: JiraTarget, issue: JiraIssue): RelatedJiraIssue {
    return {
      jira_key: issue.key,
      jira_summary: issue.fields?.summary ?? "Untitled Jira issue",
      jira_status: issue.fields?.status?.name ?? "Unknown",
      jira_url: `${target.browserBaseUrl}/browse/${issue.key}`
    };
  }

  private async resolveTarget(): Promise<JiraTarget | undefined> {
    if (this.target) {
      return this.target;
    }

    if (this.config.baseUrl && this.config.bearerToken) {
      this.target = {
        baseUrl: trimSlash(this.config.baseUrl),
        browserBaseUrl: trimSlash(this.config.baseUrl),
        headers: {
          Authorization: `Bearer ${this.config.bearerToken}`
        }
      };
      return this.target;
    }

    if (this.config.baseUrl && this.config.email && this.config.apiToken) {
      this.target = {
        baseUrl: trimSlash(this.config.baseUrl),
        browserBaseUrl: trimSlash(this.config.baseUrl),
        headers: {
          Authorization: `Basic ${Buffer.from(`${this.config.email}:${this.config.apiToken}`).toString("base64")}`
        }
      };
      return this.target;
    }

    if (!this.config.bearerToken) {
      return undefined;
    }

    const resources = await fetchJson<JiraResource[]>(
      "https://api.atlassian.com/oauth/token/accessible-resources",
      {
        headers: {
          Authorization: `Bearer ${this.config.bearerToken}`
        }
      },
      8000
    ).catch(() => []);

    const resource = resources.find((item) => item.id && item.url) ?? resources[0];
    if (!resource?.id) {
      return undefined;
    }

    this.target = {
      baseUrl: `https://api.atlassian.com/ex/jira/${resource.id}`,
      browserBaseUrl: trimSlash(resource.url ?? "https://jira.atlassian.com"),
      headers: {
        Authorization: `Bearer ${this.config.bearerToken}`
      }
    };
    return this.target;
  }

  private buildJql(labels: string[], errorType: string, message: string): string {
    const labelClause = labels.length ? labels.map((label) => `labels = ${quoteJql(label)}`).join(" OR ") : "";
    const summaryTerms = [errorType, ...message.split(/\s+/).slice(0, 4)]
      .map(cleanTerm)
      .filter(Boolean)
      .slice(0, 4);
    const summaryClause = summaryTerms.map((term) => `summary ~ ${quoteJql(term)}`).join(" OR ");
    const matchClause = [labelClause, summaryClause].filter(Boolean).join(" OR ") || "summary ~ \"error\"";

    return `project = ${quoteIdentifier(this.config.projectKey)} AND (${matchClause}) ORDER BY updated DESC`;
  }
}

function quoteJql(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll("\"", "\\\"")}"`;
}

function quoteIdentifier(value: string): string {
  return /^[A-Z][A-Z0-9_]*$/.test(value) ? value : quoteJql(value);
}

function cleanTerm(value: string): string {
  return value.replace(/[^A-Za-z0-9_./-]/g, "").slice(0, 48);
}

function trimSlash(value: string): string {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}
