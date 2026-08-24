# Lookout

Lookout is security observability for private networks and self-hosted applications.

Use [Lookout](https://app.devlookout.com) to set up and monitor your environment.

## Install Lookout

Install the checksum-verified Lookout CLI on the administrator workstation without `sudo`:

```sh
installer=$(mktemp)
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location https://app.devlookout.com/cli/install.sh --output "$installer"
sh "$installer"
rm -f "$installer"
export PATH="$HOME/.local/bin:$PATH"
lookout version
```

Then configure and install the approved VMs:

```sh
lookout vm add --name api-1 --address 10.0.1.10 --ssh-host production-api
lookout vm add --name db-1 --address 10.0.1.11 --ssh-user ubuntu
lookout vm central api-1
lookout login
lookout install
```

The coding agent may discover and configure the VMs and run installation. The user completes `lookout login` personally in the browser. The CLI receives one short-lived installation permission, not a general SaaS account credential.

The CLI checks SSH host identities and uses the workstation's existing SSH agent without forwarding it. The central VM proves possession of its deployment key before SaaS activates the deployment. Incomplete installations can be inspected with `lookout diagnose` and resumed with `lookout install --retry`.

For an unresolved blocker after login, run `lookout report`, complete the generated survey, then run `lookout report submit SURVEY_FILE`. The CLI links the report with the existing login permission and scans it locally for secrets before submission.

From an authorized source checkout, the legacy local installer remains available:

```sh
./install.sh
```

Verify an installation:

```sh
sudo lookout doctor
```

Remove Lookout while retaining its data:

```sh
./uninstall.sh
```

Permanently remove Lookout-managed data only when explicitly intended:

```sh
./uninstall.sh --purge
```

## Lookout Support AI production runbook

The MVP support limiter and generation concurrency controls are in memory. Run the hosted application as exactly one replica and set `LOOKOUT_SUPPORT_SINGLE_REPLICA=true`. The server refuses to enable Support AI unless this guard is present together with the OpenAI, Resend, support inbox, reply-domain, signing, webhook, and allowlisted staff configuration.

Required configuration: `OPENAI_API_KEY`, `LOOKOUT_SUPPORT_MODEL`, `LOOKOUT_RESEND_API_KEY`, `LOOKOUT_SUPPORT_EMAIL_FROM`, `LOOKOUT_SUPPORT_INBOX_EMAIL`, `LOOKOUT_SUPPORT_REPLY_DOMAIN`, `LOOKOUT_SUPPORT_REPLY_SIGNING_SECRET`, `LOOKOUT_RESEND_WEBHOOK_SECRET`, `LOOKOUT_SUPPORT_STAFF_EMAILS`, and `LOOKOUT_SUPPORT_SINGLE_REPLICA=true`.

Optional limits and timeouts: `LOOKOUT_DOCS_INDEX_URL`, `LOOKOUT_DOCS_TIMEOUT_MS`, `LOOKOUT_SUPPORT_TIMEOUT_MS`, `LOOKOUT_SUPPORT_MAX_OUTPUT_TOKENS`, `LOOKOUT_SUPPORT_HOURLY_LIMIT`, `LOOKOUT_SUPPORT_DAILY_LIMIT`, `LOOKOUT_SUPPORT_CHECK_HOURLY_LIMIT`, `LOOKOUT_SUPPORT_GLOBAL_CONCURRENCY`, `LOOKOUT_SUPPORT_TOKEN_CONCURRENCY`, `LOOKOUT_SUPPORT_RETENTION_DAYS`, `LOOKOUT_SUPPORT_EMAIL_MAX_ATTEMPTS`, and `LOOKOUT_SUPPORT_EMAIL_TIMEOUT_MS`.

Before increasing the application replica count, replace the in-memory hourly, daily, and concurrency limiter with an atomic Supabase implementation, verify cross-replica idempotency and email delivery claims, and remove the single-replica guard. Keep the Fumadocs deployment separate. It serves public documentation and agent-readable Markdown, not an MCP server.

Configure the support mailbox and Resend retention to match the 90-day Lookout support-conversation retention policy where the provider permits it. Register `POST /v1/support/email/resend` for `email.received` events and keep the Resend signing secret separate from the reply-address HMAC secret.
