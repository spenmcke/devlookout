'use client';

import type { MouseEvent, ReactNode } from 'react';

const events = new Set(['docs_index_copied', 'docs_full_copied', 'agent_prompt_copied', 'support_guide_opened']);

export function AgentOnboardingAnalytics({ children }: { children: ReactNode }) {
  function capture(event: MouseEvent<HTMLElement>) {
    const target = event.target instanceof Element ? event.target : null;
    const action = target?.closest<HTMLElement>('[data-agent-event]');
    const name = action?.dataset.agentEvent;
    if (!name || !events.has(name)) return;
    if (!target?.closest('button, a')) return;
    void fetch('/api/agent-events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event: name }),
      keepalive: true,
    }).catch(() => undefined);
  }

  return <div onClick={capture}>{children}</div>;
}
