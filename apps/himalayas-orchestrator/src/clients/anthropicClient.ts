import Anthropic from "@anthropic-ai/sdk";
import type { FaultCase } from "../../../../packages/shared/src/faults";
import type { CrmAccount } from "./crmClient";
import type { RelatedJiraIssue } from "./jiraClient";
import type { NormalizedSentryIssue, Diagnosis } from "../types";

type AnthropicConfig = {
  apiKey: string;
  model: string;
  timeoutMs: number;
};

export type DiagnosisInput = {
  fault: FaultCase;
  sentry: NormalizedSentryIssue;
  account: CrmAccount;
  related?: RelatedJiraIssue;
  source: {
    file: string;
    contents: string;
  };
};

export class AnthropicDiagnosisClient {
  private readonly client?: Anthropic;

  constructor(private readonly config: AnthropicConfig) {
    if (config.apiKey) {
      this.client = new Anthropic({ apiKey: config.apiKey });
    }
  }

  async generate(input: DiagnosisInput): Promise<Diagnosis> {
    if (!this.client) {
      throw new Error("Anthropic API key missing. Set ANTHROPIC_API_KEY or ANTHROPIC_KEY.");
    }

    const response = await withTimeout(
      this.client.messages.create({
        model: this.config.model,
        max_tokens: 1200,
        temperature: 0.4,
        system: systemPrompt(),
        messages: [
          {
            role: "user",
            content: userPrompt(input)
          }
        ]
      }),
      this.config.timeoutMs,
      "Anthropic diagnosis timed out"
    );

    const text = response.content
      .map((block) => (block.type === "text" ? block.text : ""))
      .filter(Boolean)
      .join("\n");

    return parseDiagnosis(text);
  }
}

function systemPrompt(): string {
  return [
    "You diagnose production software incidents for a transactional email API company named Himalayas.",
    "Return strict JSON only. Do not include prose, markdown fences, headings, or comments.",
    "Use the provided Sentry event, CRM account, Jira issue, and source file.",
    "The suggested_fix.diff must be a concise unified diff against the provided source file.",
    "Do not invent customer data, Jira keys, stack frame files, or code locations."
  ].join(" ");
}

function userPrompt(input: DiagnosisInput): string {
  return JSON.stringify(
    {
      required_schema: {
        what_is_happening: "string",
        who_is_affected: "string",
        when_it_triggers: "string",
        likely_root_cause: "string",
        suggested_fix: {
          summary: "string",
          file: "string",
          line: 0,
          diff: "unified diff string with minus and plus lines",
          scope: "string"
        }
      },
      fault: input.fault,
      sentry: input.sentry,
      crm_account: input.account,
      jira: input.related ?? null,
      source: input.source
    },
    null,
    2
  );
}

export function parseDiagnosis(raw: string): Diagnosis {
  const trimmed = stripFences(raw).trim();
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) {
    throw new Error("Anthropic response did not contain JSON");
  }

  const parsed = JSON.parse(trimmed.slice(start, end + 1)) as Partial<Diagnosis>;
  assertDiagnosis(parsed);
  return parsed;
}

function assertDiagnosis(value: Partial<Diagnosis>): asserts value is Diagnosis {
  const fix = value.suggested_fix;
  if (
    typeof value.what_is_happening !== "string" ||
    typeof value.who_is_affected !== "string" ||
    typeof value.when_it_triggers !== "string" ||
    typeof value.likely_root_cause !== "string" ||
    !fix ||
    typeof fix.summary !== "string" ||
    typeof fix.file !== "string" ||
    typeof fix.line !== "number" ||
    typeof fix.diff !== "string" ||
    typeof fix.scope !== "string"
  ) {
    throw new Error("Anthropic response did not match diagnosis schema");
  }
}

function stripFences(value: string): string {
  return value.replace(/^```(?:json)?/i, "").replace(/```$/i, "");
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timeout: NodeJS.Timeout | undefined;
  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => reject(new Error(message)), timeoutMs);
  });

  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
  }
}
