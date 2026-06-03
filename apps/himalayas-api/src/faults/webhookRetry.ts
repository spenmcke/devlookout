import { RetryScheduleError } from "../errors";
import { addBreadcrumb } from "../sentry";

type RetryPolicy = {
  region: string;
  configuredCap: number;
  expectedCap: number;
};

export async function scheduleWebhookRetries(region: string): Promise<void> {
  const policy = buildPolicy(region);
  addBreadcrumb("webhook retry policy loaded", {
    region: policy.region,
    configured_cap: policy.configuredCap,
    expected_cap: policy.expectedCap
  });

  for (let attempt = 1; attempt <= policy.expectedCap; attempt += 1) {
    await scheduleAttempt(policy, attempt);
  }
}

function buildPolicy(region: string): RetryPolicy {
  if (region === "EMEA") {
    return {
      region,
      configuredCap: 3,
      expectedCap: 5
    };
  }

  return {
    region,
    configuredCap: 5,
    expectedCap: 5
  };
}

async function scheduleAttempt(policy: RetryPolicy, attempt: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 4));
  addBreadcrumb("webhook retry attempt scheduled", { attempt, region: policy.region });

  if (attempt > policy.configuredCap) {
    throw new RetryScheduleError(
      `retry loop capped at ${policy.configuredCap}; attempt ${attempt} cannot be scheduled for ${policy.region}`
    );
  }
}
