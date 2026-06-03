export type Diagnosis = {
  what_is_happening: string;
  who_is_affected: string;
  when_it_triggers: string;
  likely_root_cause: string;
  suggested_fix: {
    summary: string;
    file: string;
    line: number;
    diff: string;
    scope: string;
  };
};

export type Contact = {
  name: string;
  role: string;
  email: string;
  source: string;
};

export type ContextResponse = {
  ticket: {
    id: string;
    title: string;
    escalated_ago: string;
    priority: string;
    tags: string[];
  };
  customer: {
    account: string;
    plan: string;
    arr_usd: number;
    region: string;
    managed: boolean;
    csm: string | null;
  };
  diagnosis: Diagnosis;
  contacts: Contact[];
  assignee: {
    name: string;
    role: string;
    why: string;
  };
  related: {
    jira_key: string;
    jira_summary: string;
    jira_status: string;
    jira_url: string;
  };
  code_location: {
    file: string;
    lines: string;
  };
  sentry: {
    issue_id: string;
    error_type: string;
    message: string;
    first_seen: string;
    events_24h: number;
    release: string;
    log_lines: string[];
  };
  stale?: boolean;
};

export type StackFrame = {
  file: string;
  line: number;
  function: string;
  in_app: boolean;
};

export type NormalizedSentryIssue = {
  issueId: string;
  issueTitle: string;
  culprit: string;
  errorType: string;
  message: string;
  firstSeen: string;
  events24h: number;
  release: string;
  tags: Record<string, string>;
  frames: StackFrame[];
  logLines: string[];
};
