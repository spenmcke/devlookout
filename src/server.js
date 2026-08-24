'use strict';

const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { snapshot: prototypeSnapshot } = require('./model');
const { LookoutRuntime } = require('./runtime');
const { CollectorRegistry } = require('./collector/registry');
const { CollectorEnrollmentAuthority } = require('./collector/enrollment');
const { parseSigmaYaml } = require('./detection/sigma');
const { protectorFromEnvironment } = require('./security/data-protector');
const { ApiAuthenticator } = require('./security/auth');
const { TailscaleAuthenticator } = require('./security/tailscale-auth');
const { loadConfig, readSecureJson } = require('./config');
const { createConfiguredCloudExport } = require('./export/configured');
const { createConfiguredAlertWebhook: createLegacyAlertWebhook } = require('./alerts/configured');
const { createConfiguredAlertWebhook } = require('./notifications/configured');
const { createConfiguredConsoleSync, createConfiguredOperationalHealthSync } = require('./console/configured');
const { LocalOperationalHealthRegistry } = require('./operations-health/local-registry');
const { operationalHealthCollector } = require('./collector/operational-telemetry');

const publicDir = path.join(__dirname, '..', 'public');
const supabaseBrowserBundle = path.join(__dirname, '..', 'node_modules', '@supabase', 'supabase-js', 'dist', 'umd', 'supabase.js');
const mimeTypes = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };

function loadLocalEnvironment(filename = path.join(__dirname, '..', '.env.local')) {
  if (!fs.existsSync(filename)) return;
  const contents = fs.readFileSync(filename, 'utf8');
  if (Buffer.byteLength(contents) > 128 * 1024) throw new Error('.env.local exceeds the 128 KiB size limit');
  for (const line of contents.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!match || process.env[match[1]] !== undefined) continue;
    let value = match[2];
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    process.env[match[1]] = value;
  }
}

loadLocalEnvironment();

function contentSecurityPolicy() {
  const connectSources = ["'self'"];
  let posthogScriptSource = 'https://*.posthog.com';
  try {
    const authUrl = new URL(process.env.LOOKOUT_SUPABASE_URL || '');
    connectSources.push(authUrl.origin);
    if (authUrl.protocol === 'https:') connectSources.push(`wss://${authUrl.host}`);
    if (authUrl.protocol === 'http:') connectSources.push(`ws://${authUrl.host}`);
  } catch { /* An invalid or missing URL is reported by the signup screen. */ }
  try {
    const posthogUrl = new URL(process.env.LOOKOUT_POSTHOG_HOST || 'https://us.i.posthog.com');
    if (posthogUrl.protocol === 'https:') {
      connectSources.push(posthogUrl.origin);
      posthogScriptSource = `${posthogScriptSource} ${posthogUrl.origin}`;
    }
  } catch { /* Analytics stays disabled when its host is invalid. */ }
  return `default-src 'self'; style-src 'self'; script-src 'self' ${posthogScriptSource}; font-src 'self' https://infisical.com; img-src 'self' data: https://*.googleusercontent.com; connect-src ${connectSources.join(' ')} https://*.posthog.com; worker-src 'self' blob: data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`;
}

function browserAuthConfig() {
  const supabaseUrl = process.env.LOOKOUT_SUPABASE_URL || '';
  const publishableKey = process.env.LOOKOUT_SUPABASE_PUBLISHABLE_KEY || process.env.LOOKOUT_SUPABASE_ANON_KEY || '';
  const posthogProjectToken = process.env.LOOKOUT_POSTHOG_PROJECT_TOKEN || '';
  const posthogHost = process.env.LOOKOUT_POSTHOG_HOST || 'https://us.i.posthog.com';
  const posthogUiHost = process.env.LOOKOUT_POSTHOG_UI_HOST || 'https://us.posthog.com';
  return { supabaseUrl, publishableKey, configured: Boolean(supabaseUrl && publishableKey), hosted: false, posthogProjectToken, posthogHost, posthogUiHost };
}

function reply(res, status, body, type = 'application/json; charset=utf-8', headers = {}) {
  res.writeHead(status, {
    'Content-Type': type,
    'Cache-Control': 'no-store',
    'Content-Security-Policy': contentSecurityPolicy(),
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    ...headers
  });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}

function authorized(req, token) {
  if (!token) return true;
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return false;
  const supplied = Buffer.from(header.slice(7));
  const expected = Buffer.from(token);
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

async function readBody(req, maximumBytes = 1024 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maximumBytes) { const error = new Error('Request body too large'); error.statusCode = 413; throw error; }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function readJson(req, maximumBytes = 1024 * 1024) {
  try { return JSON.parse(await readBody(req, maximumBytes));
  } catch { const error = new Error('Request body must be valid JSON'); error.statusCode = 400; throw error; }
}

function permissionFor(method, pathname) {
  if (method === 'GET' && pathname === '/api/v1/console-snapshot') return 'read:console';
  if (method === 'GET' && pathname === '/api/v1/me') return 'read:health';
  if (method === 'GET' && pathname === '/api/v1/graph') return 'read:graph';
  if (method === 'GET' && ['/api/v1/detection-plan', '/api/v1/behaviors'].includes(pathname)) return 'read:behaviors';
  if (method === 'GET' && pathname === '/api/v1/rules') return 'read:rules';
  if (method === 'POST' && pathname === '/api/v1/rules/import/sigma') return 'manage:rules';
  if (pathname === '/api/v1/events') return method === 'GET' ? 'read:events' : method === 'POST' ? 'ingest:events' : null;
  if (method === 'POST' && pathname.startsWith('/api/v1/ingest/')) return 'ingest:events';
  if (method === 'POST' && pathname === '/api/v1/collector/submissions') return 'ingest:collector';
  if (method === 'GET' && pathname === '/api/v1/alerts') return 'read:alerts';
  if (pathname.startsWith('/api/v1/alerts/')) return method === 'GET' ? 'read:alerts' : method === 'PATCH' ? 'manage:alerts' : null;
  if (method === 'GET' && pathname === '/api/v1/incidents') return 'read:incidents';
  if (method === 'POST' && pathname === '/api/v1/incidents/promote') return 'manage:incidents';
  return null;
}

function createServer({ runtime, apiToken = null, authenticator = null, identityAuthenticator = null, collectorRegistry = null, operationalHealthRegistry = null, enrollmentAuthority = null, tls = null, approvedSourceAddresses = ['127.0.0.1', '::1', '::ffff:127.0.0.1'] } = {}) {
  if (!runtime) throw new Error('createServer requires a LookoutRuntime');
  if (!Array.isArray(approvedSourceAddresses)) throw new Error('createServer approvedSourceAddresses must be an array');
  const approvedSources = new Set(approvedSourceAddresses);
  const auth = authenticator || ApiAuthenticator.legacy(apiToken, { allowLocalAdmin: !apiToken });
  const listener = async (req, res) => {
    let auditContext = null;
    try {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname === '/health' && req.method === 'GET') return reply(res, 200, await runtime.status());
      if (url.pathname === '/auth/config.js' && req.method === 'GET') {
        const serialized = JSON.stringify(browserAuthConfig()).replaceAll('<', '\\u003c');
        return reply(res, 200, `'use strict';\nwindow.__LOOKOUT_AUTH__ = ${serialized};\n`, 'text/javascript; charset=utf-8');
      }
      if (url.pathname === '/vendor/supabase.js' && req.method === 'GET') {
        const data = await fs.promises.readFile(supabaseBrowserBundle);
        return reply(res, 200, data, 'text/javascript; charset=utf-8');
      }
      const enrollmentRequest = url.pathname === '/api/v1/collector/enroll' && req.method === 'POST';
      let principal = null;
      if (url.pathname.startsWith('/api/v1/') && !enrollmentRequest) {
        principal = auth.authenticate(req);
        if (!principal && identityAuthenticator) principal = await identityAuthenticator.authenticate(req);
        if (!principal) {
          await runtime.recordAudit({ action: 'api.authenticate', target: url.pathname, outcome: 'failure', sourceAddress: req.socket.remoteAddress });
          return reply(res, 401, { error: 'unauthorized' }, undefined, { 'WWW-Authenticate': 'Bearer' });
        }
        const permission = permissionFor(req.method, url.pathname);
        if (permission && !auth.authorize(principal, permission)) {
          await runtime.recordAudit({ principal: principal.id, action: 'api.authorize', target: url.pathname, outcome: 'failure', sourceAddress: req.socket.remoteAddress, attributes: { permission } });
          return reply(res, 403, { error: 'forbidden' });
        }
      }
      if (enrollmentRequest) {
        auditContext = { action: 'collector.enroll', target: 'pending', sourceAddress: req.socket.remoteAddress };
        if (!enrollmentAuthority || !collectorRegistry) return reply(res, 503, { error: 'collector enrollment is not configured' });
        // Invitations may be issued by the privileged local CLI while this
        // process is running. Refresh the encrypted authority snapshot inside
        // the enrollment transaction before consuming one.
        const enrollment = await enrollmentAuthority.enroll(await readJson(req, 128 * 1024), { refresh: true });
        collectorRegistry.register(enrollment.collectorId, enrollment.publicKeyPem);
        auditContext.target = enrollment.collectorId;
        await runtime.recordAudit({ action: 'collector.enroll', target: enrollment.collectorId, outcome: 'success', sourceAddress: req.socket.remoteAddress, attributes: { assetId: enrollment.assetId, deploymentId: enrollment.deploymentId, idempotent: enrollment.idempotent } });
        return reply(res, enrollment.idempotent ? 200 : 201, enrollment);
      }
      if (url.pathname === '/api/v1/graph' && req.method === 'GET') return reply(res, 200, await runtime.refreshGraph());
      if (url.pathname === '/api/v1/console-snapshot' && req.method === 'GET') return reply(res, 200, await runtime.consoleSnapshot());
      if (url.pathname === '/api/v1/me' && req.method === 'GET') return reply(res, 200, {
        id: principal.id,
        displayName: principal.displayName || null,
        loginName: principal.loginName || null,
        roles: Array.isArray(principal.roles) ? principal.roles : [],
        authentication: principal.authentication || null
      });
      if (url.pathname === '/api/v1/detection-plan' && req.method === 'GET') return reply(res, 200, runtime.detectionPlan());
      if (url.pathname === '/api/v1/behaviors' && req.method === 'GET') return reply(res, 200, runtime.behaviorPlan());
      if (url.pathname === '/api/v1/rules' && req.method === 'GET') return reply(res, 200, runtime.analytics);
      if (url.pathname === '/api/v1/rules/import/sigma' && req.method === 'POST') {
        auditContext = { principal: principal.id, action: 'rules.import', target: 'sigma', sourceAddress: req.socket.remoteAddress };
        let rules;
        try { rules = parseSigmaYaml(await readBody(req, 2 * 1024 * 1024)); }
        catch (error) { error.statusCode ||= 400; throw error; }
        const imported = await runtime.importAnalytics(rules);
        await runtime.recordAudit({ principal: principal.id, action: 'rules.import', target: 'sigma', outcome: 'success', sourceAddress: req.socket.remoteAddress, attributes: { count: imported.length } });
        return reply(res, 201, imported);
      }
      if (url.pathname === '/api/v1/events' && req.method === 'GET') {
        const source = url.searchParams.get('source') || undefined;
        const keyword = url.searchParams.get('q') || undefined;
        if (source?.length > 128 || keyword?.length > 256) return reply(res, 400, { error: 'log search filter is too long' });
        return reply(res, 200, await runtime.eventStore.query({ since: url.searchParams.get('since') || undefined, until: url.searchParams.get('until') || undefined, category: url.searchParams.get('category') || undefined, entityKey: url.searchParams.get('entity') || undefined, source, keyword, limit: Number(url.searchParams.get('limit') || 1000) }));
      }
      if (url.pathname === '/api/v1/events' && req.method === 'POST') {
        auditContext = { principal: principal.id, action: 'events.ingest', target: 'normalized', sourceAddress: req.socket.remoteAddress };
        const body = await readJson(req);
        const events = Array.isArray(body) ? body : body.events;
        if (!Array.isArray(events)) return reply(res, 400, { error: 'body must be an event array or { events: [] }' });
        const result = await runtime.ingest(events);
        await runtime.recordAudit({ principal: principal.id, action: 'events.ingest', target: 'normalized', outcome: 'success', sourceAddress: req.socket.remoteAddress, attributes: { accepted: result.accepted.length } });
        return reply(res, 202, result);
      }
      if (url.pathname.startsWith('/api/v1/ingest/') && req.method === 'POST') {
        const normalizerId = decodeURIComponent(url.pathname.slice('/api/v1/ingest/'.length));
        auditContext = { principal: principal.id, action: 'events.ingest', target: normalizerId || 'unknown', sourceAddress: req.socket.remoteAddress };
        if (!normalizerId) return reply(res, 400, { error: 'normalizer ID is required' });
        const body = await readJson(req);
        const records = Array.isArray(body) ? body : body.records;
        if (!Array.isArray(records)) return reply(res, 400, { error: 'body must be a record array or { records: [] }' });
        const context = { ...(Array.isArray(body) ? {} : body.context), receivedAt: new Date().toISOString(), logType: url.searchParams.get('logType') || body.context?.logType, tailnet: url.searchParams.get('tailnet') || body.context?.tailnet };
        const result = await runtime.ingestRaw(normalizerId, records, context);
        await runtime.recordAudit({ principal: principal.id, action: 'events.ingest', target: normalizerId, outcome: 'success', sourceAddress: req.socket.remoteAddress, attributes: { accepted: result.accepted.length } });
        return reply(res, 202, result);
      }
      if (url.pathname === '/api/v1/collector/submissions' && req.method === 'POST') {
        auditContext = { principal: principal.id, action: 'collector.submit', target: 'submission', sourceAddress: req.socket.remoteAddress };
        if (!collectorRegistry) return reply(res, 503, { error: 'collector registry is not configured' });
        // Collector envelopes are independently schema- and count-bounded to
        // 4 MiB; allow that signed format plus modest JSON envelope overhead.
        const envelope = await readJson(req, 5 * 1024 * 1024);
        if (principal.collectorId && principal.collectorId !== envelope?.payload?.collectorId) {
          await runtime.recordAudit({ principal: principal.id, action: 'collector.submit', target: envelope?.payload?.collectorId || 'unknown', outcome: 'failure', sourceAddress: req.socket.remoteAddress, attributes: { reason: 'credential_identity_mismatch' } });
          return reply(res, 403, { error: 'collector credential does not match signed identity' });
        }
        const result = await collectorRegistry.accept(envelope, async (payload) => {
          const operational = operationalHealthRegistry && payload.operationalHealth?.length
            ? await operationalHealthRegistry.accept({ collectorId: payload.collectorId, sequence: payload.sequence, samples: payload.operationalHealth })
            : { accepted: 0 };
          const graph = payload.facts.length ? await runtime.applySurveyFacts(payload.facts) : runtime.graph.snapshot();
          const cases = payload.events.length ? await runtime.ingest(payload.events) : { accepted: [], ...runtime.cases.snapshot() };
          return { collectorId: payload.collectorId, sequence: payload.sequence, graph: { entities: graph.entities.length, relationships: graph.relationships.length }, acceptedEvents: cases.accepted.length, acceptedOperationalHealth: operational.accepted };
        });
        await runtime.recordAudit({ principal: principal.id, action: 'collector.submit', target: result.collectorId, outcome: 'success', sourceAddress: req.socket.remoteAddress, attributes: { sequence: result.sequence, acceptedEvents: result.acceptedEvents } });
        return reply(res, 202, result);
      }
      if (url.pathname === '/api/v1/alerts' && req.method === 'GET') return reply(res, 200, runtime.cases.snapshot().alerts);
      if (url.pathname.startsWith('/api/v1/alerts/') && req.method === 'GET') {
        const alertId = decodeURIComponent(url.pathname.slice('/api/v1/alerts/'.length));
        if (!alertId) return reply(res, 400, { error: 'alert ID is required' });
        return reply(res, 200, await runtime.alertDetail(alertId));
      }
      if (url.pathname.startsWith('/api/v1/alerts/') && req.method === 'PATCH') {
        const alertId = decodeURIComponent(url.pathname.slice('/api/v1/alerts/'.length));
        if (!alertId) return reply(res, 400, { error: 'alert ID is required' });
        auditContext = { principal: principal.id, action: 'alert.status.update', target: alertId, sourceAddress: req.socket.remoteAddress };
        const body = await readJson(req, 128 * 1024);
        const alert = await runtime.updateAlert(alertId, { status: body.status, reason: body.reason, actor: principal.id, at: new Date().toISOString() });
        await runtime.recordAudit({ principal: principal.id, action: 'alert.status.update', target: alertId, outcome: 'success', sourceAddress: req.socket.remoteAddress, attributes: { status: alert.status } });
        return reply(res, 200, alert);
      }
      if (url.pathname === '/api/v1/incidents' && req.method === 'GET') return reply(res, 200, runtime.cases.snapshot().incidents);
      if (url.pathname === '/api/v1/incidents/promote' && req.method === 'POST') {
        auditContext = { principal: principal.id, action: 'incident.promote', target: 'pending', sourceAddress: req.socket.remoteAddress };
        const body = await readJson(req);
        if (!Array.isArray(body.alertIds)) return reply(res, 400, { error: 'alertIds must be an array' });
        const incident = await runtime.promoteIncident(body.alertIds, { actor: principal.id, reason: body.reason, at: new Date().toISOString() });
        await runtime.recordAudit({ principal: principal.id, action: 'incident.promote', target: incident.id, outcome: 'success', sourceAddress: req.socket.remoteAddress, attributes: { alertCount: body.alertIds.length } });
        return reply(res, 201, incident);
      }
      if (url.pathname === '/api/snapshot' && req.method === 'GET') return reply(res, 200, prototypeSnapshot());
      if (url.pathname.startsWith('/api/')) return reply(res, 404, { error: 'not found' });
      if (!['GET', 'HEAD'].includes(req.method)) return reply(res, 405, { error: 'method not allowed' }, undefined, { Allow: 'GET, HEAD' });

      const rawPath = url.pathname === '/'
        ? '/index.html'
        : url.pathname === '/signup'
          ? '/signup.html'
          : url.pathname === '/cli-login'
            ? '/cli-login.html'
          : ['/setup', '/map', '/assets', '/alerts', '/rules', '/logs', '/settings'].includes(url.pathname)
            ? '/index.html'
            : url.pathname;
      const safePath = path.normalize(rawPath).replace(/^(\.\.[/\\])+/, '');
      const filePath = path.join(publicDir, safePath);
      if (!filePath.startsWith(publicDir)) return reply(res, 403, 'Forbidden', 'text/plain; charset=utf-8');
      fs.readFile(filePath, (error, data) => {
        if (error) return reply(res, error.code === 'ENOENT' ? 404 : 500, 'Not found', 'text/plain; charset=utf-8');
        reply(res, 200, req.method === 'HEAD' ? '' : data, mimeTypes[path.extname(filePath)] || 'application/octet-stream');
      });
    } catch (error) {
      if (auditContext) {
        try { await runtime.recordAudit({ ...auditContext, outcome: 'failure', attributes: { errorType: error.name, statusCode: error.statusCode || 500 } }); }
        catch { /* The response must still complete if audit storage is unavailable. */ }
      }
      reply(res, error.statusCode || (error.name === 'ValidationError' ? 400 : 500), { error: error.statusCode || error.name === 'ValidationError' ? error.message : 'internal error', issues: error.issues });
    }
  };
  return tls ? https.createServer(tls, listener) : http.createServer(listener);
}

function readTlsFile(filename, label, { privateFile = false } = {}) {
  const descriptor = fs.openSync(path.resolve(filename), fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.size > 1024 * 1024) throw new Error(`${label} must be a bounded regular file`);
    if (privateFile && process.platform !== 'win32' && (stat.mode & 0o077) !== 0) throw new Error(`${label} permissions must be owner-only`);
    if (privateFile && typeof process.geteuid === 'function' && stat.uid !== process.geteuid()) throw new Error(`${label} must be owned by the service user`);
    return fs.readFileSync(descriptor, 'utf8');
  } finally { fs.closeSync(descriptor); }
}

async function main() {
  const config = loadConfig();
  const { host, port } = config.server;
  const apiToken = config.auth.legacyTokenEnvironment ? process.env[config.auth.legacyTokenEnvironment] : null;
  if (config.auth.legacyTokenEnvironment && !apiToken) throw new Error(`Authentication environment variable is unset: ${config.auth.legacyTokenEnvironment}`);
  const dataDirectory = config.storage.dataDirectory;
  const protector = protectorFromEnvironment();
  const requireEncryption = config.storage.requireEncryption;
  if (requireEncryption && !protector) throw new Error('A LOOKOUT_MASTER_KEY or LOOKOUT_MASTER_KEY_FILE is required for encrypted storage');
  const cloudExport = createConfiguredCloudExport(config, { protector });
  const consoleSync = createConfiguredConsoleSync(config, { protector });
  const operationalHealthSync = createConfiguredOperationalHealthSync(config, { protector });
  const operationalHealthRegistry = operationalHealthSync
    ? await new LocalOperationalHealthRegistry({ dataDirectory, protector, requireEncryption }).initialize()
    : null;
  const alertWebhook = config.webhook.enabled ? createConfiguredAlertWebhook(config, { protector }) : createLegacyAlertWebhook(config, { protector });
  const runtime = await new LookoutRuntime({ dataDirectory, protector, requireEncryption, maximumStoragePercent: config.storage.maximumPercent, cloudExport, alertWebhook }).initialize();
  const compact = () => runtime.compactRetention({ eventRetentionDays: config.storage.retentionDays, auditRetentionDays: config.storage.auditRetentionDays }).catch((error) => console.error(`Retention compaction failed: ${error.message}`));
  await compact();
  const retentionTimer = setInterval(compact, 24 * 60 * 60 * 1000);
  retentionTimer.unref();
  if (cloudExport) {
    const flush = () => runtime.flushCloudExport().catch((error) => console.error(`Cloud export delivery failed: ${error.message}`));
    flush();
    const exportTimer = setInterval(flush, config.export.flushIntervalSeconds * 1000);
    exportTimer.unref();
  }
  if (consoleSync) {
    await consoleSync.initialize();
    const sync = async () => {
      try { await consoleSync.capture(runtime); }
      catch (error) { console.error(`Console snapshot queueing failed: ${error.message}`); }
      try { await consoleSync.flush(); }
      catch (error) { console.error(`Console synchronization failed: ${error.message}`); }
    };
    sync();
    const consoleTimer = setInterval(sync, config.consoleSync.intervalSeconds * 1000);
    consoleTimer.unref();
  }
  if (operationalHealthSync) {
    await operationalHealthSync.initialize();
    const centralCollectorId = `central:${config.consoleSync.deploymentId}`;
    const localCollector = operationalHealthCollector({ collectorId: centralCollectorId, entityKey: `lookout-central:${config.consoleSync.deploymentId}`, dataDirectory });
    const syncOperationalHealth = async () => {
      try {
        const output = await localCollector.collect({ collectedAt: new Date().toISOString() });
        await operationalHealthRegistry.accept({ collectorId: centralCollectorId, sequence: Date.now(), samples: output.operationalHealth });
        await operationalHealthSync.capture(operationalHealthRegistry, { deploymentId: config.consoleSync.deploymentId });
      } catch (error) { console.error(`Operational health queueing failed: ${error.message}`); }
      try { await operationalHealthSync.flush(); }
      catch (error) { console.error(`Operational health synchronization failed: ${error.message}`); }
    };
    syncOperationalHealth();
    const operationalTimer = setInterval(syncOperationalHealth, 5 * 60 * 1000);
    operationalTimer.unref();
  }
  if (alertWebhook) {
    const flush = () => runtime.flushAlertWebhook().catch((error) => console.error(`Alert webhook delivery failed: ${error.message}`));
    flush();
    const webhookTimer = setInterval(flush, (config.webhook.enabled ? config.webhook.flushIntervalSeconds : config.alertWebhook.flushIntervalSeconds) * 1000);
    webhookTimer.unref();
  }
  const enrollmentAuthority = await new CollectorEnrollmentAuthority({ dataDirectory, protector, requireEncryption }).initialize();
  let configuredCollectorKeys = {};
  if (config.collectors.keysFile) {
    const keyDocument = readSecureJson(config.collectors.keysFile, 'Collector key registry');
    configuredCollectorKeys = keyDocument.collectors || keyDocument;
  }
  const collectorRegistry = await new CollectorRegistry({ dataDirectory, publicKeys: { ...configuredCollectorKeys, ...enrollmentAuthority.publicKeys() }, protector, requireEncryption }).initialize();
  let authenticator = null;
  if (config.auth.credentialsFile) {
    const authDocument = readSecureJson(config.auth.credentialsFile, 'Authentication configuration');
    authenticator = new ApiAuthenticator({ credentials: authDocument.credentials || [], allowLocalAdmin: config.server.allowLoopbackAdmin });
  }
  if (!authenticator && !apiToken) authenticator = new ApiAuthenticator({ allowLocalAdmin: config.server.allowLoopbackAdmin });
  const configuredAuthenticator = authenticator || ApiAuthenticator.legacy(apiToken, { allowLocalAdmin: !apiToken });
  authenticator = {
    authenticate(req) { return configuredAuthenticator.authenticate(req) || enrollmentAuthority.authenticateBearer(req.headers.authorization); },
    authorize(principal, permission) { return configuredAuthenticator.authorize(principal, permission); }
  };
  const identityAuthenticator = config.auth.tailscale.enabled ? new TailscaleAuthenticator(config.auth.tailscale) : null;
  const tls = config.server.tls ? { cert: readTlsFile(config.server.tls.certificateFile, 'TLS certificate'), key: readTlsFile(config.server.tls.privateKeyFile, 'TLS private key', { privateFile: true }) } : null;
  createServer({ runtime, apiToken, authenticator, identityAuthenticator, collectorRegistry, operationalHealthRegistry, enrollmentAuthority, tls, approvedSourceAddresses: config.server.approvedSourceAddresses }).listen(port, host, () => console.log(`Lookout listening on ${tls ? 'https' : 'http'}://${host}:${port}`));
}

if (require.main === module) main().catch((error) => { console.error(error.message); process.exitCode = 1; });

module.exports = { createServer, authorized, permissionFor, readBody, readJson, readTlsFile, loadLocalEnvironment };
