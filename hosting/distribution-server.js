'use strict';

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const crypto = require('node:crypto');
const { Readable } = require('node:stream');
const { protectorFromEnvironment } = require('../src/security/data-protector');
const { SnapshotStore } = require('../src/storage/snapshot-store');
const { SupabaseSnapshotStore } = require('../src/storage/supabase-snapshot-store');
const { SetupSessionAuthority } = require('../src/onboarding/setup-session-authority');
const { CliAuthorizationAuthority } = require('../src/onboarding/cli-authorization-authority');
const { createSupabaseBrowserAuthenticator } = require('../src/onboarding/supabase-browser-auth');
const { createSupabaseAuthUserDeleter } = require('../src/onboarding/supabase-account-delete');
const { deleteHostedAccount } = require('../src/onboarding/account-delete');
const { SaasConsoleStore } = require('../src/console/saas-store');
const { createHostedSaasApi } = require('../src/hosting/saas-api');
const { CentralRecoveryMonitor } = require('../src/hosting/central-recovery');
const { RecoveryEmailNotifier } = require('../src/notifications/recovery-email');
const { InstallationDiagnosticsService } = require('../src/diagnostics/service');
const { SupabaseDiagnosticsStore } = require('../src/diagnostics/supabase-store');
const { SlackDiagnosticsNotifier } = require('../src/diagnostics/slack');
const { SupabaseOperationalHealthStore } = require('../src/operations-health/supabase-store');
const { OperationalHealthService } = require('../src/operations-health/service');
const { OperationalHealthNotifier, OperationalNotificationWorker } = require('../src/operations-health/notifier');
const { SupportAccessTokenAuthority } = require('../src/support/access-token-authority');
const { SupabaseSupportStore } = require('../src/support/conversation-store');
const { createSupportTokenHttpHandler } = require('../src/support/token-http');
const { SupportRateLimiter } = require('../src/support/rate-limiter');
const { LookoutDocsRetriever } = require('../src/support/docs-retriever');
const { OpenAIResponsesClient } = require('../src/support/openai-responses-client');
const { LookoutSupportAgent } = require('../src/support/support-agent');
const { createSupportMcpHttpHandler } = require('../src/support/mcp-http');
const { ResendSupportEmailNotifier } = require('../src/support/email-notifier');
const { SupportEmailOutboxWorker } = require('../src/support/email-outbox');
const { createResendInboundHandler } = require('../src/support/resend-inbound');
const updateSigningKeys = require('../config/update-signing-public-keys.json');
const { SupabaseUpdateChannelStore } = require('../src/update/supabase-channel-store');
const { createUpdateChannelHttp } = require('../src/update/http');
const { SupabaseArtifactStore, artifactRoute, MAXIMUM_ARTIFACT_BYTES } = require('../src/hosting/supabase-artifact-store');
const { loadReleaseArtifacts } = require('./release-artifacts');

const version = process.env.LOOKOUT_RELEASE_VERSION || 'v0.1.0';
const port = Number(process.env.PORT || 3000);
const publicBase = new URL(process.env.PUBLIC_BASE_URL || 'https://app.devlookout.com');
const supabaseUrl = process.env.LOOKOUT_SUPABASE_URL || '';
const supabasePublishableKey = process.env.LOOKOUT_SUPABASE_PUBLISHABLE_KEY || '';
const supabaseServiceKey = process.env.LOOKOUT_SUPABASE_SERVICE_KEY || '';
const dataDirectory = path.resolve(process.env.LOOKOUT_HOSTING_DATA_DIR || '/data/lookout');
const posthogProjectToken = process.env.LOOKOUT_POSTHOG_PROJECT_TOKEN || '';
const posthogHost = process.env.LOOKOUT_POSTHOG_HOST || 'https://us.i.posthog.com';
const posthogUiHost = process.env.LOOKOUT_POSTHOG_UI_HOST || 'https://us.posthog.com';
const diagnosticsSlackWebhook = process.env.LOOKOUT_INSTALLATION_DIAGNOSTICS_SLACK_WEBHOOK_URL || '';
const operationalSlackWebhook = process.env.LOOKOUT_OPERATIONAL_SLACK_WEBHOOK_URL || '';
const operationalAlertEmail = process.env.LOOKOUT_OPERATIONAL_ALERT_EMAIL || '';
const operationalEmailFrom = process.env.LOOKOUT_OPERATIONAL_EMAIL_FROM || '';
const operationsApiToken = process.env.LOOKOUT_OPERATIONS_API_TOKEN || '';
const supportRequired = ['OPENAI_API_KEY', 'LOOKOUT_SUPPORT_MODEL', 'LOOKOUT_RESEND_API_KEY', 'LOOKOUT_SUPPORT_EMAIL_FROM', 'LOOKOUT_SUPPORT_INBOX_EMAIL', 'LOOKOUT_SUPPORT_REPLY_DOMAIN', 'LOOKOUT_SUPPORT_REPLY_SIGNING_SECRET', 'LOOKOUT_RESEND_WEBHOOK_SECRET', 'LOOKOUT_SUPPORT_STAFF_EMAILS'];
const supportSingleReplica = process.env.LOOKOUT_SUPPORT_SINGLE_REPLICA === 'true';
const supportConfigured = Boolean(supabaseServiceKey && supportSingleReplica && supportRequired.every((name) => process.env[name]));
function supportInteger(name, fallback, minimum, maximum) {
  if (!supportConfigured || process.env[name] === undefined) return fallback;
  const value = Number(process.env[name]);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(`${name} is invalid`);
  return value;
}
const diagnosticsSlackBotToken = process.env.LOOKOUT_INSTALLATION_DIAGNOSTICS_SLACK_BOT_TOKEN || '';
const diagnosticsSlackChannelId = process.env.LOOKOUT_INSTALLATION_DIAGNOSTICS_SLACK_CHANNEL_ID || '';
if (publicBase.protocol !== 'https:' || publicBase.username || publicBase.password || publicBase.search || publicBase.hash || (publicBase.pathname !== '/' && publicBase.pathname !== '')) throw new Error('PUBLIC_BASE_URL must be an HTTPS origin');
if (!/^v\d+\.\d+\.\d+$/.test(version) || !Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('Distribution service configuration is invalid');

const root = path.resolve(process.env.LOOKOUT_ARTIFACT_ROOT || path.join(__dirname, 'artifacts'));
const releaseArtifacts = loadReleaseArtifacts({ version, publicBase, root, manifestPath: process.env.LOOKOUT_ARTIFACT_MANIFEST || '' });
const orchestrationTar = releaseArtifacts.orchestrationTar;
const orchestrationZip = releaseArtifacts.orchestrationZip;
const linuxTargets = {
  amd64: releaseArtifacts.linuxTargetAmd64,
  arm64: releaseArtifacts.linuxTargetArm64
};
const artifacts = [orchestrationTar, orchestrationZip, ...Object.values(linuxTargets)];
function renderBootstrap(templateName, orchestration) {
  const template = fs.readFileSync(path.resolve(__dirname, `../bootstrap/${templateName}`), 'utf8');
  const rendered = template
    .replaceAll('@LOOKOUT_RELEASE_VERSION@', version)
    .replaceAll('@LOOKOUT_ORCHESTRATION_URL@', orchestration.url)
    .replaceAll('@LOOKOUT_ORCHESTRATION_SHA256@', orchestration.digest)
    .replaceAll('@LOOKOUT_TARGET_URL@', linuxTargets.amd64.url)
    .replaceAll('@LOOKOUT_TARGET_SHA256@', linuxTargets.amd64.digest)
    .replaceAll('@LOOKOUT_TARGET_AMD64_URL@', linuxTargets.amd64.url)
    .replaceAll('@LOOKOUT_TARGET_AMD64_SHA256@', linuxTargets.amd64.digest)
    .replaceAll('@LOOKOUT_TARGET_ARM64_URL@', linuxTargets.arm64.url)
    .replaceAll('@LOOKOUT_TARGET_ARM64_SHA256@', linuxTargets.arm64.digest);
  if (rendered.includes('@LOOKOUT_')) throw new Error(`Hosted bootstrap template is incomplete: ${templateName}`);
  return rendered;
}
const bootstrap = renderBootstrap('hosted-install.sh.in', orchestrationTar);
const powershellBootstrap = renderBootstrap('hosted-install.ps1.in', orchestrationZip);
const cliBootstrap = renderBootstrap('workstation-cli-install.sh.in', orchestrationTar);
const cliPowershellBootstrap = renderBootstrap('workstation-cli-install.ps1.in', orchestrationZip);
const publicRoot = path.resolve(__dirname, '../public');
const vendorBundle = path.resolve(__dirname, '../vendor/supabase.js');
const supportReporter = path.resolve(__dirname, '../tools/lookout-support-report.js');
const mimeTypes = new Map([
  ['.html', 'text/html; charset=utf-8'], ['.css', 'text/css; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'], ['.png', 'image/png'],
  ['.jpg', 'image/jpeg'], ['.jpeg', 'image/jpeg'], ['.svg', 'image/svg+xml'],
  ['.ico', 'image/x-icon']
]);

function contentSecurityPolicy() {
  const connect = ["'self'"];
  let posthogScriptSource = 'https://*.posthog.com';
  try {
    const auth = new URL(supabaseUrl);
    if (auth.protocol === 'https:') connect.push(auth.origin, `wss://${auth.host}`);
  } catch { /* The login page reports missing or invalid authentication configuration. */ }
  try {
    const analytics = new URL(posthogHost);
    if (analytics.protocol === 'https:') {
      connect.push(analytics.origin);
      posthogScriptSource = `${posthogScriptSource} ${analytics.origin}`;
    }
  } catch { /* Analytics stays disabled when its host is invalid. */ }
  return `default-src 'self'; style-src 'self'; script-src 'self' ${posthogScriptSource}; img-src 'self' data: https://*.googleusercontent.com; connect-src ${connect.join(' ')} https://*.posthog.com; worker-src 'self' blob: data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`;
}

function headers(contentType, length, cacheControl) {
  return {
    'Content-Type': contentType,
    'Content-Length': length,
    'Cache-Control': cacheControl,
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': contentSecurityPolicy(),
    'Referrer-Policy': 'no-referrer'
  };
}

function sendFile(req, res, filename) {
  let stat;
  try { stat = fs.statSync(filename); } catch { res.writeHead(404).end(); return; }
  if (!stat.isFile() || stat.size > 8 * 1024 * 1024) { res.writeHead(404).end(); return; }
  res.writeHead(200, headers(mimeTypes.get(path.extname(filename)) || 'application/octet-stream', stat.size, 'no-store'));
  if (req.method === 'HEAD') res.end(); else fs.createReadStream(filename).pipe(res);
}

async function main() {
  const protector = protectorFromEnvironment();
  if (!protector) throw new Error('LOOKOUT_MASTER_KEY is required for hosted multitenant state');
  const artifactStore = supabaseServiceKey ? new SupabaseArtifactStore({ supabaseUrl, serviceKey: supabaseServiceKey }) : null;
  const localArtifacts = artifacts.filter((item) => item.filename);
  if (artifactStore && localArtifacts.length) await artifactStore.publishAll(localArtifacts);
  if (artifactStore && !localArtifacts.length) await artifactStore.ensureBucket();
  if (localArtifacts.length !== artifacts.length && !artifactStore) throw new Error('Externally stored release artifacts require the Supabase artifact store');
  const authenticateBrowser = createSupabaseBrowserAuthenticator({ supabaseUrl, publishableKey: supabasePublishableKey });
  const deleteSupabaseAuthUser = supabaseServiceKey
    ? createSupabaseAuthUserDeleter({ supabaseUrl, serviceKey: supabaseServiceKey })
    : async () => { throw new Error('Supabase account deletion is not configured'); };
  const stateStore = async (stateKey, filename) => {
    const local = new SnapshotStore(dataDirectory, filename, { protector, requireEncryption: true });
    if (!supabaseServiceKey) return local;
    const remote = new SupabaseSnapshotStore({ supabaseUrl, serviceKey: supabaseServiceKey, stateKey, protector });
    if (await remote.load() === null) {
      const existing = await local.load();
      if (existing !== null) await remote.save(existing);
    }
    return remote;
  };
  const consoleStore = await new SaasConsoleStore({ snapshotStore: await stateStore('console', 'saas-console.json') }).initialize();
  const setupAuthority = await new SetupSessionAuthority({
    snapshotStore: await stateStore('setup', 'setup-sessions.json'), sessionTtlMs: 60 * 60 * 1000,
    activeDeploymentChecker: async ({ tenantId, deploymentIds }) => {
      const deployments = await consoleStore.listDeployments({ tenantId });
      return deployments.some((deployment) => deploymentIds.includes(deployment.deployment_id) && deployment.status !== 'uninstalled');
    },
    deploymentReplacementHandler: ({ tenantId, deploymentId, replacementDeploymentId }) => replacementDeploymentId === deploymentId
      ? consoleStore.resetForRetry({ tenantId, deploymentId })
      : consoleStore.markReplaced({ tenantId, deploymentId }),
    completionValidator: async ({ tenantId, deploymentId }) => {
      try { await consoleStore.snapshot({ tenantId, deploymentId }); }
      catch { throw new Error('Setup provisioning is not ready'); }
    },
    provisioningFactory: ({ deploymentId }) => ({
      console_sync: {
        endpoint: new URL(`/v1/console-sync/${deploymentId}`, publicBase).toString(),
        credential: crypto.randomBytes(32).toString('base64url')
      },
      dashboard_url: new URL('/map', publicBase).toString()
    })
  }).initialize();
  const cliAuthorizationAuthority = await new CliAuthorizationAuthority({
    setupAuthority,
    store: await stateStore('cli-authorizations', 'cli-authorizations.json')
  }).initialize();
  const diagnosticsService = supabaseServiceKey ? new InstallationDiagnosticsService({
    store: new SupabaseDiagnosticsStore({ supabaseUrl, serviceKey: supabaseServiceKey }),
    slackNotifier: diagnosticsSlackWebhook || diagnosticsSlackBotToken || diagnosticsSlackChannelId
      ? new SlackDiagnosticsNotifier({ webhookUrl: diagnosticsSlackWebhook, botToken: diagnosticsSlackBotToken, channelId: diagnosticsSlackChannelId })
      : null
  }) : null;
  const operationalStore = supabaseServiceKey ? new SupabaseOperationalHealthStore({ supabaseUrl, serviceKey: supabaseServiceKey }) : null;
  const operationalNotifier = operationalStore ? new OperationalHealthNotifier({
    slackWebhookUrl: operationalSlackWebhook,
    resendApiKey: process.env.LOOKOUT_RESEND_API_KEY || '', emailFrom: operationalEmailFrom, emailTo: operationalAlertEmail
  }) : null;
  const operationalNotificationChannel = operationalNotifier?.hasSlack() ? 'slack' : operationalNotifier?.hasEmail() ? 'email' : null;
  const operationalHealthService = operationalStore ? new OperationalHealthService({ store: operationalStore, notificationChannel: operationalNotificationChannel }) : null;
  const operationalNotificationWorker = operationalStore && operationalNotifier ? new OperationalNotificationWorker({ store: operationalStore, notifier: operationalNotifier }) : null;
  const supportRetentionDays = supportInteger('LOOKOUT_SUPPORT_RETENTION_DAYS', 90, 1, 365);
  const supportStore = supabaseServiceKey ? new SupabaseSupportStore({ supabaseUrl, serviceKey: supabaseServiceKey, retentionDays: supportRetentionDays }) : null;
  const supportLogger = (record) => console.log(JSON.stringify(record));
  const supportTokenAuthority = supportConfigured ? new SupportAccessTokenAuthority({ store: supportStore, protector }) : null;
  const supportTokenHandler = supportTokenAuthority ? createSupportTokenHttpHandler({ tokenAuthority: supportTokenAuthority, authenticateBrowser, logger: supportLogger }) : null;
  const supportLimiter = supportConfigured ? new SupportRateLimiter({
    hourlyLimit: supportInteger('LOOKOUT_SUPPORT_HOURLY_LIMIT', 30, 1, 1000), dailyLimit: supportInteger('LOOKOUT_SUPPORT_DAILY_LIMIT', 200, 1, 10000),
    checkHourlyLimit: supportInteger('LOOKOUT_SUPPORT_CHECK_HOURLY_LIMIT', 120, 1, 10000), globalConcurrency: supportInteger('LOOKOUT_SUPPORT_GLOBAL_CONCURRENCY', 8, 1, 100), tokenConcurrency: supportInteger('LOOKOUT_SUPPORT_TOKEN_CONCURRENCY', 2, 1, 20)
  }) : null;
  const supportAgent = supportConfigured ? new LookoutSupportAgent({
    store: supportStore,
    docsRetriever: new LookoutDocsRetriever({ indexUrl: process.env.LOOKOUT_DOCS_INDEX_URL || 'https://docs.devlookout.com/llms.txt', timeoutMs: supportInteger('LOOKOUT_DOCS_TIMEOUT_MS', 10000, 1000, 30000) }),
    modelClient: new OpenAIResponsesClient({ apiKey: process.env.OPENAI_API_KEY, model: process.env.LOOKOUT_SUPPORT_MODEL, timeoutMs: supportInteger('LOOKOUT_SUPPORT_TIMEOUT_MS', 45000, 1000, 120000), maxOutputTokens: supportInteger('LOOKOUT_SUPPORT_MAX_OUTPUT_TOKENS', 1400, 100, 4096) }),
    limiter: supportLimiter, logger: supportLogger
  }) : null;
  const supportMcp = supportTokenAuthority ? createSupportMcpHttpHandler({ tokenAuthority: supportTokenAuthority, supportAgent, logger: supportLogger }) : null;
  const supportEmailWorker = supportConfigured ? new SupportEmailOutboxWorker({
    store: supportStore,
    notifier: new ResendSupportEmailNotifier({ apiKey: process.env.LOOKOUT_RESEND_API_KEY, from: process.env.LOOKOUT_SUPPORT_EMAIL_FROM, inbox: process.env.LOOKOUT_SUPPORT_INBOX_EMAIL, replyDomain: process.env.LOOKOUT_SUPPORT_REPLY_DOMAIN, replySigningSecret: process.env.LOOKOUT_SUPPORT_REPLY_SIGNING_SECRET, timeoutMs: supportInteger('LOOKOUT_SUPPORT_EMAIL_TIMEOUT_MS', 10000, 1000, 30000) }),
    maximumAttempts: supportInteger('LOOKOUT_SUPPORT_EMAIL_MAX_ATTEMPTS', 10, 1, 20), logger: supportLogger
  }) : null;
  const resendInbound = supportConfigured ? createResendInboundHandler({ store: supportStore, apiKey: process.env.LOOKOUT_RESEND_API_KEY, webhookSecret: process.env.LOOKOUT_RESEND_WEBHOOK_SECRET, staffEmails: process.env.LOOKOUT_SUPPORT_STAFF_EMAILS.split(',').map((value) => value.trim()), replyDomain: process.env.LOOKOUT_SUPPORT_REPLY_DOMAIN, replySigningSecret: process.env.LOOKOUT_SUPPORT_REPLY_SIGNING_SECRET, logger: supportLogger }) : null;
  const updateChannelHttp = supabaseServiceKey ? createUpdateChannelHttp({
    store: new SupabaseUpdateChannelStore({ supabaseUrl, serviceKey: supabaseServiceKey, trustedKeys: updateSigningKeys.trustedKeys })
  }) : null;
  const recoveryMonitor = new CentralRecoveryMonitor({
    consoleStore,
    setupAuthority,
    heartbeatTimeoutMs: Number(process.env.LOOKOUT_CENTRAL_HEARTBEAT_TIMEOUT_MS || 5 * 60 * 1000),
    emailNotifier: new RecoveryEmailNotifier({
      apiKey: process.env.LOOKOUT_RESEND_API_KEY,
      from: process.env.LOOKOUT_RECOVERY_EMAIL_FROM,
      dashboardUrl: new URL('/map', publicBase).toString()
    })
  });
  const hostedApi = createHostedSaasApi({
    setupAuthority, cliAuthorizationAuthority, consoleStore, authenticateBrowser, recoveryMonitor, diagnosticsService,
    supportTokenHandler, operationalHealthService, operationsApiToken, logger: supportLogger,
    deleteAccount: ({ tenantId, userId }) => deleteHostedAccount({
      tenantId, userId, setupAuthority, consoleStore, diagnosticsService, operationalHealthService,
      supportStore, deleteAuthUser: deleteSupabaseAuthUser
    })
  });
  const recoveryTimer = setInterval(() => recoveryMonitor.sweep().catch((error) => console.error(`lookout-recovery: ${error.message}`)), 60 * 1000);
  recoveryTimer.unref();
  const diagnosticsTimer = diagnosticsService ? setInterval(() => diagnosticsService.sweep().catch((error) => console.error(`lookout-diagnostics: ${error.message}`)), 30 * 1000) : null;
  diagnosticsTimer?.unref();
  const supportTimer = supportEmailWorker ? setInterval(() => supportEmailWorker.sweep().catch(() => supportLogger({ event: 'lookout_support_email', outcome: 'worker_error' })), 15 * 1000) : null;
  supportTimer?.unref();
  const supportRetentionTimer = supportStore ? setInterval(() => supportStore.deleteExpired({ now: new Date().toISOString() }).catch(() => supportLogger({ event: 'lookout_support_retention', outcome: 'worker_error' })), 60 * 60 * 1000) : null;
  supportRetentionTimer?.unref();
  operationalHealthService?.sweepMissing().catch((error) => console.error(`lookout-operational-sweep: ${error.message}`));
  const operationalSweepTimer = operationalHealthService ? setInterval(() => operationalHealthService.sweepMissing().catch((error) => console.error(`lookout-operational-sweep: ${error.message}`)), 60 * 1000) : null;
  operationalSweepTimer?.unref();
  const operationalNotificationTimer = operationalNotificationWorker ? setInterval(() => operationalNotificationWorker.flush().catch((error) => console.error(`lookout-operational-notification: ${error.message}`)), 15 * 1000) : null;
  operationalNotificationTimer?.unref();
  const operationalRetentionTimer = operationalHealthService ? setInterval(() => operationalHealthService.deleteExpired().catch((error) => console.error(`lookout-operational-retention: ${error.message}`)), 60 * 60 * 1000) : null;
  operationalRetentionTimer?.unref();

  http.createServer(async (req, res) => {
  let url;
  try { url = new URL(req.url, publicBase); } catch { res.writeHead(400).end(); return; }
  if (url.pathname === '/support/mcp') {
    if (!supportMcp) { res.writeHead(503, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }).end('{"error":"unavailable"}'); return; }
    try { await supportMcp(req, res, url); }
    catch { if (!res.headersSent) res.writeHead(503, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }).end('{"error":"unavailable"}'); }
    return;
  }
  if (url.pathname === '/v1/support/email/resend') {
    if (!resendInbound) { res.writeHead(503, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }).end('{"error":"unavailable"}'); return; }
    await resendInbound(req, res, url); return;
  }
  try { if (await hostedApi(req, res, url)) return; }
  catch { res.writeHead(503, { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }).end(); return; }
  try { if (updateChannelHttp && await updateChannelHttp(req, res, url)) return; }
  catch { res.writeHead(503, { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }).end(); return; }
  const cliLoginQuery = url.pathname === '/cli-login' && url.searchParams.size === 1 && /^cla_[A-Za-z0-9_-]{32}$/.test(url.searchParams.get('request') || '');
  const signupQuery = url.pathname === '/signup' && url.searchParams.size === 1 && /^\/cli-login\?request=cla_[A-Za-z0-9_-]{32}$/.test(url.searchParams.get('next') || '');
  if ((url.search && !cliLoginQuery && !signupQuery) || url.hash || !['GET', 'HEAD'].includes(req.method)) { res.writeHead(404).end(); return; }
  if (url.pathname === '/health') {
    const body = Buffer.from(JSON.stringify({ status: 'ok', version, features: { support_ai: { configured: supportConfigured, single_replica: supportSingleReplica } }, artifacts: { orchestration_tar_sha256: orchestrationTar.digest, orchestration_zip_sha256: orchestrationZip.digest, linux_target_amd64_sha256: linuxTargets.amd64.digest, linux_target_arm64_sha256: linuxTargets.arm64.digest } }));
    res.writeHead(200, headers('application/json; charset=utf-8', body.length, 'no-store'));
    if (req.method === 'GET') res.end(body); else res.end();
    return;
  }
  if (url.pathname === '/install.sh') {
    const body = Buffer.from(bootstrap);
    res.writeHead(200, headers('text/x-shellscript; charset=utf-8', body.length, 'no-store'));
    if (req.method === 'GET') res.end(body); else res.end();
    return;
  }
  if (url.pathname === '/install.ps1') {
    const body = Buffer.from(powershellBootstrap);
    res.writeHead(200, headers('text/plain; charset=utf-8', body.length, 'no-store'));
    if (req.method === 'GET') res.end(body); else res.end();
    return;
  }
  if (url.pathname === '/cli/install.sh') {
    const body = Buffer.from(cliBootstrap);
    res.writeHead(200, headers('text/x-shellscript; charset=utf-8', body.length, 'no-store'));
    if (req.method === 'GET') res.end(body); else res.end();
    return;
  }
  if (url.pathname === '/cli/install.ps1') {
    const body = Buffer.from(cliPowershellBootstrap);
    res.writeHead(200, headers('text/plain; charset=utf-8', body.length, 'no-store'));
    if (req.method === 'GET') res.end(body); else res.end();
    return;
  }
  if (url.pathname === '/support-report.js') return sendFile(req, res, supportReporter);
  const hostedArtifact = localArtifacts.find((item) => item.route === url.pathname);
  if (hostedArtifact) {
    res.writeHead(200, { ...headers(hostedArtifact.contentType, hostedArtifact.stat.size, 'public, max-age=31536000, immutable'), ETag: `"sha256-${hostedArtifact.digest}"` });
    if (req.method === 'HEAD') res.end(); else fs.createReadStream(hostedArtifact.filename).pipe(res);
    return;
  }
  const historicalArtifact = artifactStore && artifactRoute(url.pathname);
  if (historicalArtifact) {
    let stored;
    try { stored = await artifactStore.download(url.pathname); }
    catch { res.writeHead(503, { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }).end(); return; }
    if (stored.status === 404) { res.writeHead(404).end(); return; }
    if (!stored.ok || !stored.body) { res.writeHead(503, { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }).end(); return; }
    const length = stored.headers.get('content-length');
    if (!/^\d+$/.test(length || '') || Number(length) > MAXIMUM_ARTIFACT_BYTES) { await stored.body.cancel(); res.writeHead(503, { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }).end(); return; }
    res.writeHead(200, { ...headers(historicalArtifact.name.endsWith('.zip') ? 'application/zip' : 'application/gzip', Number(length), 'public, max-age=31536000, immutable'), ETag: `"sha256-${historicalArtifact.digest}"` });
    if (req.method === 'HEAD') { await stored.body.cancel(); res.end(); } else Readable.fromWeb(stored.body).pipe(res);
    return;
  }
  if (url.pathname === '/auth/config.js') {
    const config = JSON.stringify({
      supabaseUrl,
      publishableKey: supabasePublishableKey,
      configured: Boolean(supabaseUrl && supabasePublishableKey),
      hosted: true,
      posthogProjectToken,
      posthogHost,
      posthogUiHost
    }).replaceAll('<', '\\u003c');
    const body = Buffer.from(`'use strict';\nwindow.__LOOKOUT_AUTH__ = ${config};\n`);
    res.writeHead(200, headers('text/javascript; charset=utf-8', body.length, 'no-store'));
    if (req.method === 'GET') res.end(body); else res.end();
    return;
  }
  if (url.pathname === '/vendor/supabase.js') return sendFile(req, res, vendorBundle);
  const appRoutes = new Set(['/', '/map', '/assets', '/alerts', '/rules', '/logs', '/settings', '/setup']);
  const route = url.pathname === '/signup' ? '/signup.html' : url.pathname === '/cli-login' ? '/cli-login.html' : (appRoutes.has(url.pathname) || /^\/deployments\/dpl_[A-Za-z0-9_-]{32}$/.test(url.pathname)) ? '/index.html' : url.pathname;
  const relative = path.posix.normalize(route).replace(/^\/+/, '');
  const file = path.resolve(publicRoot, relative);
  if (file === publicRoot || !file.startsWith(`${publicRoot}${path.sep}`)) { res.writeHead(404).end(); return; }
  if (fs.existsSync(file)) return sendFile(req, res, file);
  res.writeHead(404, { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end();
  }).listen(port, '0.0.0.0', () => console.log(`Lookout distribution listening on ${port}`));
}

main().catch((error) => { console.error(`lookout-hosting: ${error.message}`); process.exitCode = 1; });
