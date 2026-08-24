'use strict';

/* Client for the versioned Lookout backend API. All UI data access goes
   through here; no view code builds requests directly. */
const LookoutApi = (() => {
  const REQUEST_TIMEOUT_MS = 10000;
  const deploymentMatch = /^\/deployments\/(dpl_[A-Za-z0-9_-]{32})$/.exec(window.location.pathname);
  const hosted = Boolean(window.__LOOKOUT_AUTH__?.hosted || deploymentMatch);
  let deploymentId = deploymentMatch?.[1] || null;
  let cachedSnapshot = null;
  let cachedAt = 0;
  let snapshotRequest = null;

  async function authHeaders() {
    return typeof LookoutAuth !== 'undefined' ? LookoutAuth.authorizationHeaders() : {};
  }

  async function timedFetch(path, options = {}) {
    const controller = new AbortController();
    let timeout;
    const timeoutError = new Error(`${path} timed out`);
    timeoutError.code = 'LOOKOUT_REQUEST_TIMEOUT';
    const deadline = new Promise((resolve, reject) => {
      timeout = setTimeout(() => {
        controller.abort();
        reject(timeoutError);
      }, REQUEST_TIMEOUT_MS);
    });
    try {
      const headers = await Promise.race([authHeaders(), deadline]);
      const response = await Promise.race([
        fetch(path, {
          ...options,
          cache: 'no-store',
          signal: controller.signal,
          headers: { Accept: 'application/json', ...headers, ...(options.headers || {}) }
        }),
        deadline
      ]);
      return await Promise.race([response.json().then((body) => ({ response, body })), deadline]);
    } catch (error) {
      if (controller.signal.aborted) throw timeoutError;
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }

  async function get(path, headers = {}) {
    const { response, body } = await timedFetch(path, { headers });
    if (!response.ok) {
      const error = new Error(`${path} responded ${response.status}`);
      error.status = response.status;
      throw error;
    }
    return body;
  }

  async function request(path, options) {
    const { response, body } = await timedFetch(path, { ...options, headers: { 'Content-Type': 'application/json', ...(options?.headers || {}) } });
    if (!response.ok) {
      const error = new Error(body.error || `${path} responded ${response.status}`);
      error.status = response.status;
      throw error;
    }
    return body;
  }

  async function deploymentSnapshot() {
    if (!deploymentId) return null;
    if (cachedSnapshot && Date.now() - cachedAt < 1000) return cachedSnapshot;
    if (!snapshotRequest) snapshotRequest = get(`/v1/deployments/${encodeURIComponent(deploymentId)}/snapshot`)
      .then((value) => {
        cachedSnapshot = value;
        cachedAt = Date.now();
        return value;
      })
      .finally(() => { snapshotRequest = null; });
    return snapshotRequest;
  }

  function selectDeployment(value) {
    if (!/^dpl_[A-Za-z0-9_-]{32}$/.test(value || '')) throw new Error('Deployment ID is invalid');
    deploymentId = value;
    cachedSnapshot = null;
    cachedAt = 0;
    snapshotRequest = null;
  }

  async function hostedOr(path, selector) {
    if (!deploymentId) return get(path);
    return selector(await deploymentSnapshot());
  }

  async function hostedAlert(id) {
    const snapshot = await deploymentSnapshot();
    const alert = snapshot.alerts.find((item) => item.id === id);
    if (!alert) throw Object.assign(new Error('Alert not found'), { status: 404 });
    const entities = new Map((snapshot.graph.entities || []).map((entity) => [entity.key, entity]));
    return {
      ...alert,
      affectedSystems: (alert.entities || []).map((key) => {
        const entity = entities.get(key);
        return entity ? { key, name: entity.name, type: entity.type } : { key, name: key.split(':').at(-1), type: 'unknown' };
      }),
      evidenceTimeline: [],
      evidenceRemote: true
    };
  }

  async function updateAlert(id, status, reason) {
    const path = deploymentId ? `/v1/deployments/${encodeURIComponent(deploymentId)}/alerts/${encodeURIComponent(id)}` : `/api/v1/alerts/${encodeURIComponent(id)}`;
    const normalizedReason = reason?.trim() || '';
    const result = await request(path, { method: 'PATCH', body: JSON.stringify({ status, ...(normalizedReason ? { reason: normalizedReason } : {}) }) });
    cachedSnapshot = null;
    cachedAt = 0;
    return result;
  }

  function eventQuery(options = {}) {
    if (typeof options === 'number') options = { limit: options };
    const query = new URLSearchParams({ limit: String(options.limit || 500) });
    const dateValue = (value) => value && !Number.isNaN(new Date(value).valueOf()) ? new Date(value).toISOString() : '';
    const since = dateValue(options.from) || (!options.from && !options.to && options.period && options.period !== 'all'
      ? new Date(Date.now() - ({ '1h': 3600000, '24h': 86400000, '7d': 604800000, '30d': 2592000000 }[options.period] || 0)).toISOString()
      : '');
    const until = dateValue(options.to);
    if (since) query.set('since', since);
    if (until) query.set('until', until);
    if (options.source && options.source !== 'all') query.set('source', options.source);
    if (options.keyword) query.set('q', options.keyword);
    return `/api/v1/events?${query}`;
  }

  return {
    health: () => get('/health'),
    me: () => hosted ? get('/v1/me') : get('/api/v1/me'),
    deployments: () => get('/v1/deployments'),
    selectDeployment,
    graph: () => hostedOr('/api/v1/graph', (snapshot) => snapshot.graph),
    consoleHealth: () => deploymentId ? deploymentSnapshot().then((snapshot) => snapshot.health) : Promise.resolve(null),
    detectionPlan: () => hostedOr('/api/v1/detection-plan', (snapshot) => snapshot.detections),
    rules: () => hosted ? get('/v1/rules') : get('/api/v1/rules'),
    behaviors: () => hostedOr('/api/v1/behaviors', () => []),
    alerts: () => hostedOr('/api/v1/alerts', (snapshot) => snapshot.alerts),
    alert: (id) => deploymentId ? hostedAlert(id) : get(`/api/v1/alerts/${encodeURIComponent(id)}`),
    updateAlert,
    incidents: () => hostedOr('/api/v1/incidents', (snapshot) => snapshot.incidents),
    events: (options = 500) => deploymentId ? Promise.resolve([]) : get(eventQuery(options)),
    createSetupSession: () => request('/v1/setup-sessions', { method: 'POST', body: '{}' }),
    activeSetup: () => get('/v1/setup-sessions/active'),
    resetSetup: () => request('/v1/setup-sessions/reset', { method: 'POST', body: '{}' }),
    supportAccountToken: () => get('/v1/support/account-token'),
    supportTokens: () => get('/v1/support/tokens'),
    createSupportToken: (name) => request('/v1/support/tokens', { method: 'POST', body: JSON.stringify({ name }) }),
    revokeSupportToken: (tokenId) => request(`/v1/support/tokens/${encodeURIComponent(tokenId)}`, { method: 'DELETE' }),
    setupStatus: (sessionId) => get(`/v1/setup-sessions/${encodeURIComponent(sessionId)}`),
    deleteAccount: () => request('/v1/account', { method: 'DELETE', body: JSON.stringify({ confirmation: 'DELETE' }) }),
    hosted,
    get deploymentId() { return deploymentId; }
  };
})();
