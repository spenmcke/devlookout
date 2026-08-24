'use client';

import { useState } from 'react';

const supportMcpUrl = 'https://app.devlookout.com/support/mcp';
const supportInstruction = `Configure ${supportMcpUrl} as a Streamable HTTP remote MCP server. It uses Bearer token authentication, not OAuth. I will get the Support token from Lookout Settings at https://app.devlookout.com/settings by opening Support AI and using the copy button under the Support MCP setup preview, then provide that complete setup to this trusted local coding agent. Extract the Bearer token from the copied setup and store it in the MCP client's secret field or the LOOKOUT_SUPPORT_TOKEN environment variable. Do not open the MCP URL in a browser, run an OAuth login, or ask me to paste the token by itself into chat.`;

export function AgentCommandLinks({ compact = false }: { compact?: boolean }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(supportInstruction);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }

  return (
    <aside className={`agent-links${compact ? ' agent-links-compact' : ''}`} aria-label="Coding agent resources">
      {!compact && (
        <p>
          Sign in to Lookout, open Settings &gt; Support AI, and use the copy button under the Support MCP setup preview. Paste it only into a trusted local coding agent. The copied setup includes your secret Support token and configures Streamable HTTP with Bearer authentication, not OAuth.
        </p>
      )}
      <div className="agent-command">
        <div className="agent-command-heading">
          <span>Support MCP setup</span>
          <button type="button" onClick={() => void copy()}>
            <b aria-live="polite">{copied ? 'Copied' : 'Copy instruction'}</b>
          </button>
        </div>
        <pre><code>{supportInstruction}</code></pre>
      </div>
    </aside>
  );
}
