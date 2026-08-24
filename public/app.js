'use strict';

/* Lookout console. Reads live state from the /api/v1 backend and answers one
   question: has anyone been hacking my systems, and if so, what is the impact? */

const REFRESH_MS = 15000;
const MAP_WIDTH = 1100;
const BASE_MAP_HEIGHT = 680;
const MAP_LANE_CAPACITY = 4;
const MAP_NODE_SCALE = 1.35;
const MAP_NODE_RADIUS = 30;
const SETUP_SESSION_STORAGE = 'lookout.setup.session.v1';

const state = {
  graph: { entities: [], relationships: [], capabilities: [] },
  alerts: [],
  plan: [],
  rules: [],
  behaviors: [],
  events: [],
  user: null,
  reachable: false,
  loaded: false,
  lastUpdated: null,
  view: 'overview',
  selectedKey: null,
  assetFilter: 'map',
  alertFilters: { period: 'all', severity: 'all', status: 'active', from: '', to: '' },
  activityFilters: { period: '24h', from: '', to: '', keyword: '', source: 'all' },
  layout: new Map(),
  layoutSignature: null,
  dragSuppression: null,
  selectedAlertId: null,
  alertDetail: null,
  reviewAlertAfterNavigation: false,
  selectedEventId: null,
  setup: null,
  setupStatus: null,
  setupCompleted: null,
  setupTotal: null,
  setupPreparationFailed: false,
  accountDangerOpen: false,
  supportAccountToken: null,
  installationStatus: null,
  recoverySetup: null,
  logSearchError: null
};

let setupInitialization = null;
let setupPollTimer = null;
let logSearchTimer = null;
let supplementalRefresh = null;

/* ---------- helpers ---------- */

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[character]));
}

function humanize(identifier) {
  const text = String(identifier || '').replaceAll(/[-_]/g, ' ');
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function formatRelative(iso) {
  const time = Date.parse(iso);
  if (Number.isNaN(time)) return '—';
  const seconds = Math.max(0, Math.round((Date.now() - time) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

function truncate(text, length) {
  const value = String(text || '');
  return value.length > length ? `${value.slice(0, length - 1)}…` : value;
}

/* ---------- derived state ---------- */

function entityByKey() {
  return new Map(state.graph.entities.map((entity) => [entity.key, entity]));
}

function openAlerts() { return state.alerts.filter((alert) => ['open', 'to_fix'].includes(alert.status)); }

function stateSets() {
  return {
    watch: new Set(openAlerts().flatMap((alert) => alert.entities || []))
  };
}

function stateForKey(key, sets) {
  if (sets.watch.has(key)) return 'watch';
  return 'ok';
}

function overallState() {
  if (!state.reachable) return 'down';
  if (openAlerts().length) return 'watch';
  return 'ok';
}

function displayEntityName(entity) {
  if (entity?.type === 'network' && entity.name === '-') return 'Tailnet';
  return entity?.name || '';
}

function entityName(key) {
  const entity = entityByKey().get(key);
  return displayEntityName(entity) || String(key || '').split(':').pop();
}

function nameList(keys, limit = 3) {
  const names = (keys || []).map((key) => entityName(key));
  const shown = names.slice(0, limit).join(', ');
  return names.length > limit ? `${shown} +${names.length - limit}` : shown || '—';
}

function alertTime(alert) {
  return alert.time || alert.lastSeen || alert.firstSeen || '';
}

/* ---------- header, banner, sidebar ---------- */

const VIEW_TEXT = {
  overview: null,
  assets: 'Assets',
  alerts: 'Alerts',
  rules: 'Rules',
  logs: 'Log search',
  setup: 'Setup',
  settings: 'Settings'
};

const VIEW_PATHS = {
  overview: '/map',
  assets: '/assets',
  alerts: '/alerts',
  rules: '/rules',
  logs: '/logs',
  setup: '/setup',
  settings: '/settings'
};

function accountInitials(value) {
  const parts = String(value || '').trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return '?';
  return parts.slice(0, 2).map((part) => part[0]).join('').toUpperCase();
}

function safeProfileImage(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && url.href.length <= 2048 ? url.href : null;
  } catch { return null; }
}

function renderAccount() {
  const account = document.querySelector('#sidebarAccount');
  if (!state.user) { account.hidden = true; return; }
  const name = state.user.displayName || state.user.email || state.user.loginName || 'Lookout account';
  const avatar = document.querySelector('#accountAvatarImage');
  const fallback = document.querySelector('#accountAvatarFallback');
  const avatarUrl = safeProfileImage(state.user.avatarUrl);
  avatar.hidden = !avatarUrl;
  if (avatarUrl) avatar.src = avatarUrl;
  else avatar.removeAttribute('src');
  fallback.hidden = Boolean(avatarUrl);
  fallback.textContent = accountInitials(name);
  document.querySelector('#accountName').textContent = name;
  account.title = [...(state.user.roles || []), state.user.authentication].filter(Boolean).join(' · ');
  account.hidden = false;
}

function sessionUser(session) {
  if (!session?.user) return null;
  return {
    email: session.user.email || null,
    displayName: session.user.user_metadata?.full_name || session.user.user_metadata?.name || null,
    avatarUrl: session.user.user_metadata?.avatar_url || session.user.user_metadata?.picture || null
  };
}

function renderHeader() {
  const setupInProgress = state.setup && !['pending', 'complete', 'failed', 'expired'].includes(state.setupStatus);
  const level = state.view === 'setup' || setupInProgress ? 'ok' : overallState();
  const uninstalled = state.installationStatus === 'uninstalled';
  document.body.className = `state-${level === 'down' ? 'down' : level}`;
  document.body.classList.toggle('has-no-systems', state.loaded && !state.graph.entities.length);
  document.body.classList.toggle('overview-has-systems', state.view === 'overview' && state.graph.entities.length > 0);
  document.body.classList.toggle('setup-active', state.view === 'setup');
  const title = document.querySelector('#pageTitle');

  if (state.view !== 'overview') {
    title.textContent = VIEW_TEXT[state.view];
  } else if (setupInProgress) {
    title.textContent = state.setupStatus === 'needs_access' ? 'Setup needs access.' : 'Lookout setup is in progress.';
  } else if (level === 'down') {
    title.textContent = 'Lookout is offline.';
  } else if (uninstalled) {
    title.textContent = 'Lookout is uninstalled.';
  } else if (!state.graph.entities.length) {
    title.textContent = 'No systems connected yet';
  } else if (level === 'watch') {
    const count = openAlerts().length;
    title.textContent = `${count} alert${count === 1 ? '' : 's'} need${count === 1 ? 's' : ''} review.`;
  } else {
    title.textContent = 'Systems are normal.';
  }

  const emptyEyebrow = document.querySelector('#mapEmptyEyebrow');
  const emptyTitle = document.querySelector('#mapEmptyTitle');
  const emptyDetail = document.querySelector('#mapEmptyDetail');
  const emptyAction = document.querySelector('#mapEmptyAction');
  if (setupInProgress) {
    const needsAccess = state.setupStatus === 'needs_access';
    emptyEyebrow.textContent = needsAccess ? 'ACTION REQUIRED' : 'INSTALLING';
    emptyTitle.textContent = needsAccess ? 'Setup needs access' : mapSetupPhaseText(state.setupStatus, state.setupCompleted, state.setupTotal);
    emptyDetail.textContent = needsAccess
      ? 'Open Setup for the exact access step required to continue.'
      : `${setupEtaText(state.setupStatus, state.setupCompleted, state.setupTotal)} Data will appear here automatically as systems connect.`;
    emptyAction.textContent = 'View setup';
  } else {
    emptyEyebrow.textContent = uninstalled ? 'UNINSTALLED' : 'GET STARTED';
    emptyTitle.textContent = uninstalled ? 'Nothing is installed or tracked anymore' : 'Install Lookout on your first system';
    emptyDetail.textContent = uninstalled
      ? 'This deployment was removed from its host. Install Lookout again whenever you want to resume monitoring.'
      : 'Lookout installs on the Linux VMs you approve and shows the monitored network here.';
    emptyAction.textContent = uninstalled ? 'Install again' : 'Continue setup';
  }

}

function renderBanner() {
  const banner = document.querySelector('#banner');
  if (state.view === 'setup') { banner.hidden = true; return; }
  const action = document.querySelector('#bannerAction');
  const setupInProgress = state.setup && !['pending', 'complete', 'failed', 'expired'].includes(state.setupStatus);
  if (setupInProgress) {
    banner.hidden = false;
    banner.classList.remove('impact');
    document.querySelector('#bannerTitle').textContent = state.setupStatus === 'needs_access' ? 'Setup needs access.' : mapSetupPhaseText(state.setupStatus, state.setupCompleted, state.setupTotal);
    document.querySelector('#bannerDetail').textContent = state.setupStatus === 'needs_access'
      ? 'Open Setup for the exact least-privilege access action.'
      : `${setupEtaText(state.setupStatus, state.setupCompleted, state.setupTotal)} Data will appear in the console automatically as systems connect.`;
    action.textContent = 'View setup';
    action.dataset.goto = 'setup';
    return;
  }
  if (state.installationStatus === 'central_missing') {
    banner.hidden = false;
    banner.classList.add('impact');
    document.querySelector('#bannerTitle').textContent = 'Lookout has not received a recent update.';
    document.querySelector('#bannerDetail').textContent = 'Check the central VM and its outbound connection. Local collectors may still be running.';
    action.textContent = 'Troubleshoot';
    action.dataset.goto = 'recovery';
    return;
  }
  const level = overallState();
  if (level === 'ok' || (!state.loaded && level !== 'down')) { banner.hidden = true; return; }
  banner.hidden = false;
  banner.classList.remove('impact');
  if (level === 'down') {
    document.querySelector('#bannerTitle').textContent = 'Live state is stale.';
    document.querySelector('#bannerDetail').textContent = state.lastUpdated
      ? `Showing the latest available data from ${formatRelative(state.lastUpdated.toISOString())}.`
      : 'Lookout has not loaded data yet.';
    action.textContent = 'Retry now';
    action.dataset.goto = '';
  } else {
    const alerts = openAlerts();
    document.querySelector('#bannerTitle').textContent = `${alerts.length} alert${alerts.length === 1 ? '' : 's'} open or marked to fix`;
    document.querySelector('#bannerDetail').textContent = `Latest: ${alerts[0].title}, ${formatRelative(alertTime(alerts[0]))}.`;
    action.textContent = 'Review alerts';
    action.dataset.goto = 'alerts';
  }
}

function renderBadges() {
  const alertCount = openAlerts().length;
  const alertBadge = document.querySelector('#alertBadge');
  alertBadge.hidden = !alertCount;
  alertBadge.textContent = alertCount;
}

/* ---------- overview ---------- */

function safeClass(value) {
  return String(value || 'unknown').toLowerCase().replace(/[^a-z0-9_-]/g, '-');
}

function endpointIcon(entity) {
  const platform = String(entity.platform || '').toLowerCase();
  if (/(ios|android|mobile)/.test(platform)) return '<rect class="icon-fill" x="-9" y="-15" width="18" height="30" rx="4"></rect><rect class="icon-cut-fill" x="-6" y="-11" width="12" height="19" rx="1.5"></rect><circle class="icon-cut-fill" cy="11.5" r="1.5"></circle>';
  return '<path class="icon-fill" d="M -14 -11 H 14 A 2 2 0 0 1 16 -9 V 7 A 2 2 0 0 1 14 9 H 4 V 12 H 9 V 15 H -9 V 12 H -4 V 9 H -14 A 2 2 0 0 1 -16 7 V -9 A 2 2 0 0 1 -14 -11 Z"></path><rect class="icon-cut-fill" x="-11" y="-7" width="22" height="11" rx="1"></rect>';
}

const NODE_ICONS = {
  network: () => '<path class="icon-fill" d="M -16 9 H 13 C 19 9 21 0 15 -3 C 14 -12 3 -16 -4 -9 C -10 -12 -16 -7 -15 -1 C -22 1 -21 9 -16 9 Z"></path><path class="icon-cut" d="M -8 2 H 8 M 3 -3 L 8 2 L 3 7 M -3 -3 L -8 2 L -3 7"></path>',
  zone: () => '<rect class="icon-fill" x="-16" y="-13" width="32" height="26" rx="6"></rect><rect class="icon-cut-fill" x="-10" y="-7" width="20" height="14" rx="3"></rect><circle class="icon-fill" r="3"></circle>',
  endpoint: endpointIcon,
  service: () => '<rect class="icon-fill" x="-15" y="-13" width="30" height="11" rx="3"></rect><rect class="icon-fill" x="-15" y="2" width="30" height="11" rx="3"></rect><rect class="icon-cut-fill" x="-10" y="-9" width="12" height="3" rx="1.5"></rect><rect class="icon-cut-fill" x="-10" y="6" width="12" height="3" rx="1.5"></rect><circle class="icon-cut-fill" cx="10" cy="-7.5" r="2"></circle><circle class="icon-cut-fill" cx="10" cy="7.5" r="2"></circle>',
  software: () => '<path class="icon-fill" d="M 0 -16 L 15 -8 V 8 L 0 16 L -15 8 V -8 Z"></path><path class="icon-cut" d="M 0 0 L 15 -8 M 0 0 L -15 -8 M 0 0 V 16"></path>',
  identity: () => '<circle class="icon-fill" cy="-8" r="7"></circle><path class="icon-fill" d="M -15 15 C -14 4 14 4 15 15 Z"></path>',
  credential: () => '<circle class="icon-fill" cx="-7" cy="-5" r="8"></circle><circle class="icon-cut-fill" cx="-7" cy="-5" r="3"></circle><path class="icon-fill" d="M -1 0 L 15 12 L 11 16 L 7 12 L 4 15 L 0 11 L 3 8 L -5 2 Z"></path>',
  control: () => '<path class="icon-fill" d="M 0 -17 L 15 -11 V -1 C 15 10 8 16 0 19 C -8 16 -15 10 -15 -1 V -11 Z"></path><path class="icon-cut" d="M -7 -3 H 7 M -7 3 H 7"></path>',
  route: () => '<ellipse class="icon-fill" cx="0" cy="0" rx="17" ry="12"></ellipse><path class="icon-cut" d="M -10 2 H 9 M 4 -3 L 9 2 L 4 7 M 9 -6 H -7 M -2 -11 L -7 -6 L -2 -1"></path>',
  exposure: () => '<circle class="icon-fill" r="16"></circle><path class="icon-cut" d="M -16 0 H 16 M 0 -16 C 9 -8 9 8 0 16 M 0 -16 C -9 -8 -9 8 0 16"></path>',
  telemetry: () => '<circle class="icon-fill" cy="10" r="4"></circle><path class="icon-solid-stroke" d="M 0 5 V -1 M -7 2 C -12 -4 -8 -11 0 -12 M 7 2 C 12 -4 8 -11 0 -12"></path>',
  cloud_resource: () => NODE_ICONS.network(),
  data_resource: () => '<path class="icon-fill" d="M -15 -9 C -15 -16 15 -16 15 -9 V 10 C 15 18 -15 18 -15 10 Z"></path><ellipse class="icon-cut-fill" cy="-9" rx="10" ry="3"></ellipse><path class="icon-cut" d="M -15 1 C -15 8 15 8 15 1"></path>'
};

function nodeIcon(entity) {
  const draw = NODE_ICONS[entity.type];
  return draw ? draw(entity) : '<path class="icon-fill" d="M 0 -16 L 16 13 H -16 Z"></path><circle class="icon-cut-fill" cy="5" r="2"></circle>';
}

function zoneBoxes() {
  const zones = state.graph.entities.filter((entity) => entity.type === 'zone');
  if (!zones.length) return '';
  return zones.map((zone) => {
    const keys = new Set([zone.key]);
    for (const edge of state.graph.relationships) {
      if (edge.toKey === zone.key && ['member_of', 'in_zone', 'contained_by'].includes(edge.relation)) keys.add(edge.fromKey);
      if (edge.fromKey === zone.key && ['contains', 'protects'].includes(edge.relation)) keys.add(edge.toKey);
    }
    const points = [...keys].map((key) => state.layout.get(key)).filter(Boolean);
    if (points.length < 2) return '';
    const minX = Math.max(24, Math.min(...points.map((point) => point.x)) - 62);
    const maxX = Math.min(MAP_WIDTH - 24, Math.max(...points.map((point) => point.x)) + 62);
    const minY = Math.max(24, Math.min(...points.map((point) => point.y)) - 54);
    const maxY = Math.min(mapHeight() - 24, Math.max(...points.map((point) => point.y)) + 70);
    return `<g class="topology-zone"><rect x="${minX.toFixed(1)}" y="${minY.toFixed(1)}" width="${(maxX - minX).toFixed(1)}" height="${(maxY - minY).toFixed(1)}" rx="20"></rect><text x="${(minX + 16).toFixed(1)}" y="${(minY + 24).toFixed(1)}">${escapeHtml(zone.name)}</text></g>`;
  }).join('');
}

function mapRelationships() {
  const keys = new Set(mapEntities().map((entity) => entity.key));
  return state.graph.relationships.filter((edge) => keys.has(edge.fromKey) && keys.has(edge.toKey));
}

function mapEntities() {
  return state.graph.entities.filter((entity) => GraphLayout.isTopologyEntity(entity, state.graph.capabilities));
}

function mapHeight() {
  const laneCounts = new Map();
  for (const entity of mapEntities()) {
    const lane = GraphLayout.laneFor(entity);
    laneCounts.set(lane, (laneCounts.get(lane) || 0) + 1);
  }
  const busiestLane = Math.max(0, ...laneCounts.values());
  const requiredRows = Math.ceil(busiestLane / MAP_LANE_CAPACITY);
  return BASE_MAP_HEIGHT + Math.max(0, requiredRows - 2) * 180;
}

function deviceOwnerName(deviceKey) {
  const ownership = state.graph.relationships.find((edge) => edge.relation === 'owns' && edge.toKey === deviceKey);
  return ownership ? entityName(ownership.fromKey) : '';
}

function ensureLayout() {
  const entities = mapEntities();
  const relationships = mapRelationships();
  const height = mapHeight();
  const signature = `${height}#${entities.map((entity) => entity.key).join('|')}#${relationships.map((edge) => `${edge.fromKey}:${edge.relation}:${edge.toKey}`).join('|')}`;
  if (signature === state.layoutSignature) return;
  state.layout = GraphLayout.layout(entities, relationships, MAP_WIDTH, height);
  state.layoutSignature = signature;
}

function mapPoint(svg, event) {
  const point = svg.createSVGPoint();
  point.x = event.clientX;
  point.y = event.clientY;
  return point.matrixTransform(svg.getScreenCTM().inverse());
}

function straightEdgePath(edge) {
  const from = state.layout.get(edge.fromKey);
  const to = state.layout.get(edge.toKey);
  if (!from || !to) return '';
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const length = Math.max(1, Math.hypot(dx, dy));
  const unitX = dx / length;
  const unitY = dy / length;
  const start = { x: from.x + unitX * MAP_NODE_RADIUS, y: from.y + unitY * MAP_NODE_RADIUS };
  const end = { x: to.x - unitX * MAP_NODE_RADIUS, y: to.y - unitY * MAP_NODE_RADIUS };
  return `M${start.x.toFixed(1)} ${start.y.toFixed(1)} L${end.x.toFixed(1)} ${end.y.toFixed(1)}`;
}

function updateConnectedEdges(svg, key) {
  svg.querySelectorAll('.graph-edge').forEach((edge) => {
    if (edge.dataset.from !== key && edge.dataset.to !== key) return;
    const index = Number(edge.dataset.index);
    const relationship = state.graph.relationships[index];
    if (relationship) edge.setAttribute('d', straightEdgePath(relationship));
  });
}

function wireNodeDrag(svg, element) {
  let drag = null;
  element.addEventListener('pointerdown', (event) => {
    if (event.button !== 0 && event.pointerType !== 'touch') return;
    const origin = state.layout.get(element.dataset.key);
    if (!origin) return;
    const pointer = mapPoint(svg, event);
    drag = { pointerId: event.pointerId, startX: pointer.x, startY: pointer.y, originX: origin.x, originY: origin.y, moved: false };
    element.setPointerCapture(event.pointerId);
    element.classList.add('dragging');
  });
  element.addEventListener('pointermove', (event) => {
    if (!drag || drag.pointerId !== event.pointerId) return;
    const pointer = mapPoint(svg, event);
    const dx = pointer.x - drag.startX;
    const dy = pointer.y - drag.startY;
    if (Math.hypot(dx, dy) > 3) drag.moved = true;
    const next = {
      x: Math.max(46, Math.min(MAP_WIDTH - 46, drag.originX + dx)),
      y: Math.max(46, Math.min(mapHeight() - 64, drag.originY + dy))
    };
    state.layout.set(element.dataset.key, next);
    element.setAttribute('transform', `translate(${next.x.toFixed(1)} ${next.y.toFixed(1)})`);
    updateConnectedEdges(svg, element.dataset.key);
  });
  const finish = (event) => {
    if (!drag || drag.pointerId !== event.pointerId) return;
    const moved = drag.moved;
    drag = null;
    element.classList.remove('dragging');
    if (element.hasPointerCapture(event.pointerId)) element.releasePointerCapture(event.pointerId);
    if (moved) {
      state.dragSuppression = { key: element.dataset.key, until: performance.now() + 300 };
      renderMap();
    }
  };
  element.addEventListener('pointerup', finish);
  element.addEventListener('pointercancel', finish);
}

function renderMap() {
  const svg = document.querySelector('#securityGraph');
  const empty = document.querySelector('#mapEmpty');
  const reviewLegend = document.querySelector('#mapReviewLegend');
  const hasEntities = state.graph.entities.length > 0;
  svg.classList.toggle('hidden', !hasEntities);
  empty.hidden = hasEntities;
  if (!hasEntities) {
    reviewLegend.hidden = true;
    document.body.classList.remove('map-is-expanded');
    svg.setAttribute('viewBox', `0 0 ${MAP_WIDTH} ${BASE_MAP_HEIGHT}`);
    svg.innerHTML = '';
    return;
  }

  const height = mapHeight();
  const expanded = height > BASE_MAP_HEIGHT;
  document.body.classList.toggle('map-is-expanded', expanded);
  document.documentElement.style.setProperty('--map-expanded-height', `${height}px`);
  svg.setAttribute('viewBox', `0 0 ${MAP_WIDTH} ${height}`);

  ensureLayout();
  const sets = stateSets();
  const visibleKeys = new Set(mapEntities().map((entity) => entity.key));
  reviewLegend.hidden = ![...sets.watch].some((key) => visibleKeys.has(key));
  const visibleRelationships = new Set(mapRelationships());
  const edges = state.graph.relationships.map((edge, index) => {
    if (!visibleRelationships.has(edge)) return '';
    const from = state.layout.get(edge.fromKey);
    const to = state.layout.get(edge.toKey);
    if (!from || !to) return '';
    const hot = ['watch', 'impact'].includes(stateForKey(edge.fromKey, sets)) || ['watch', 'impact'].includes(stateForKey(edge.toKey, sets));
    return `<path class="graph-edge${hot ? ' hot' : ''}" data-index="${index}" data-from="${escapeHtml(edge.fromKey)}" data-to="${escapeHtml(edge.toKey)}" d="${straightEdgePath(edge)}"><title>${escapeHtml(edge.relation)}</title></path>`;
  }).join('');

  const nodes = mapEntities().map((entity, index) => {
    const point = state.layout.get(entity.key);
    if (!point) return '';
    const level = stateForKey(entity.key, sets);
    const selected = entity.key === state.selectedKey ? ' selected' : '';
    const name = displayEntityName(entity);
    const label = truncate(name, 20);
    const labelWidth = Math.max(48, Math.min(128, label.length * 6.1 + 16));
    const ownerName = entity.type === 'endpoint' ? deviceOwnerName(entity.key) : '';
    const ownerLabel = ownerName ? `<text class="node-owner" y="57">${escapeHtml(truncate(ownerName, 20))}</text>` : '';
    const shadowY = ownerName ? 82 : 65;
    const status = level === 'ok' ? '' : `<g class="status-badge ${level}" transform="translate(16 -16)"><circle r="7.5"></circle><text y="2.9">!</text></g>`;
    const floatX = (index % 2 ? 0.45 : -0.45).toFixed(2);
    const floatY = -(2.2 + (index % 2) * 0.4);
    const floatDuration = 6.8 + (index % 3) * 0.38;
    const floatBegin = -index * 0.61;
    const easing = '0.42 0 0.58 1;0.42 0 0.58 1';
    const action = level === 'watch' ? 'Review alerts for' : 'Inspect';
    return `<g class="node type-${safeClass(entity.type)} ${level}${selected}" data-key="${escapeHtml(entity.key)}" transform="translate(${point.x.toFixed(1)} ${point.y.toFixed(1)})" tabindex="0" role="button" aria-label="${action} ${escapeHtml(name)}, ${escapeHtml(entity.type || 'system')}"><title>${escapeHtml(name)} · ${escapeHtml(entity.type || 'system')}</title><ellipse class="node-shadow" cx="0" cy="${shadowY}" rx="20" ry="4.5"><animate attributeName="opacity" values="0.34;0.25;0.34" keyTimes="0;0.5;1" calcMode="spline" keySplines="${easing}" dur="${floatDuration.toFixed(2)}s" begin="${floatBegin.toFixed(2)}s" repeatCount="indefinite"></animate><animate attributeName="rx" values="20;18.5;20" keyTimes="0;0.5;1" calcMode="spline" keySplines="${easing}" dur="${floatDuration.toFixed(2)}s" begin="${floatBegin.toFixed(2)}s" repeatCount="indefinite"></animate></ellipse><g class="node-float"><animateTransform attributeName="transform" type="translate" values="0 0;${floatX} ${floatY};0 0" keyTimes="0;0.5;1" calcMode="spline" keySplines="${easing}" dur="${floatDuration.toFixed(2)}s" begin="${floatBegin.toFixed(2)}s" repeatCount="indefinite"></animateTransform><g class="node-visual" transform="scale(${MAP_NODE_SCALE})"><circle class="node-tile" r="21"></circle><g class="node-icon">${nodeIcon(entity)}</g>${status}<rect class="node-label" x="${(-labelWidth / 2).toFixed(1)}" y="27" width="${labelWidth.toFixed(1)}" height="18" rx="4"></rect><text class="node-name" y="39.5">${escapeHtml(label)}</text>${ownerLabel}</g></g></g>`;
  }).join('');

  svg.innerHTML = zoneBoxes() + edges + nodes;
  svg.querySelectorAll('.node').forEach((element) => {
    const select = () => {
      if (state.dragSuppression?.key === element.dataset.key && performance.now() < state.dragSuppression.until) return;
      state.dragSuppression = null;
      if (stateForKey(element.dataset.key, stateSets()) === 'watch') {
        openAlertsForEntity(element.dataset.key);
        return;
      }
      state.selectedKey = element.dataset.key;
      renderMap();
      renderDetail();
    };
    wireNodeDrag(svg, element);
    element.addEventListener('click', select);
    element.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select(); } });
  });
}

const HIDDEN_FACTS = new Set(['id', 'key', 'type', 'name', 'declared', 'provenance', 'firstSeen', 'lastSeen', 'schemaVersion']);

function renderDetail() {
  const panel = document.querySelector('#detailPanel');
  const workspace = document.querySelector('.workspace');
  if (!state.graph.entities.length || !state.selectedKey || !entityByKey().has(state.selectedKey)) {
    state.selectedKey = null;
    panel.hidden = true;
    panel.innerHTML = '';
    workspace.classList.remove('has-selection');
    return;
  }
  panel.hidden = false;
  workspace.classList.add('has-selection');
  const entity = entityByKey().get(state.selectedKey);
  const sets = stateSets();
  const level = stateForKey(entity.key, sets);
  const stateWord = { ok: 'NO OPEN ALERTS', watch: 'REVIEW', impact: 'IMPACT' }[level];
  const stateControl = level === 'watch'
    ? `<button class="state-pill ${level}" type="button" data-review-alerts="${escapeHtml(entity.key)}">${stateWord}</button>`
    : `<span class="state-pill ${level}">${stateWord}</span>`;

  const facts = Object.entries(entity)
    .filter(([name, value]) => !HIDDEN_FACTS.has(name)
      && (['number', 'boolean'].includes(typeof value) || (typeof value === 'string' && value.trim() && value.toLowerCase() !== 'unknown') || (Array.isArray(value) && value.length && value.every((item) => ['string', 'number'].includes(typeof item)))))
    .slice(0, 8)
    .map(([name, value]) => [humanize(name), Array.isArray(value) ? value.join(', ') : String(value)]);
  if (Number.isFinite(Date.parse(entity.lastSeen))) facts.unshift(['Last seen', formatRelative(entity.lastSeen)]);

  const related = state.graph.relationships
    .filter((edge) => (edge.fromKey === entity.key || edge.toKey === entity.key)
      && entityByKey().has(edge.fromKey === entity.key ? edge.toKey : edge.fromKey))
    .slice(0, 8)
    .map((edge) => {
      const otherKey = edge.fromKey === entity.key ? edge.toKey : edge.fromKey;
      const direction = edge.fromKey === entity.key ? edge.relation : `${edge.relation} (inbound)`;
      return `<div class="relationship"><i></i><span><em>${escapeHtml(direction.replaceAll('_', ' '))}</em> ${escapeHtml(entityName(otherKey))}</span></div>`;
    }).join('');

  const telemetry = state.graph.capabilities
    .filter((capability) => capability.entityKey === entity.key)
    .map((capability) => `<div class="fact-row"><span>${escapeHtml(humanize(capability.capability))}</span><strong><span class="pill ${escapeHtml(capability.status || 'unknown')}">${escapeHtml(capability.status || 'unknown')}</span></strong></div>`)
    .join('');

  const signals = openAlerts()
    .filter((alert) => (alert.entities || []).includes(entity.key))
    .slice(0, 3)
    .map((alert) => `<div class="detail-alert ${escapeHtml(alert.severity)}"><strong>${escapeHtml(alert.title)}</strong> · ${escapeHtml(formatRelative(alertTime(alert)))}</div>`)
    .join('');

  panel.innerHTML = `
    <div class="detail-hero"><button class="detail-close" type="button" aria-label="Close details">×</button><span class="kind">${escapeHtml((entity.type || 'system').toUpperCase())}</span><h2>${escapeHtml(displayEntityName(entity))}</h2>${stateControl}</div>
    <div class="detail-body">
      ${facts.length ? `<h3>KNOWN DETAILS</h3>${facts.map(([name, value]) => `<div class="fact-row"><span>${escapeHtml(name)}</span><strong>${escapeHtml(truncate(value, 60))}</strong></div>`).join('')}` : ''}
      ${related ? `<h3>RELATIONSHIPS</h3>${related}` : ''}
      ${telemetry || ''}
      ${signals ? `<h3>OPEN ALERTS</h3>${signals}` : ''}
    </div>`;
  panel.querySelector('.detail-close').addEventListener('click', () => {
    closeEntityDetail();
  });
  panel.querySelector('[data-review-alerts]')?.addEventListener('click', () => openAlertsForEntity(entity.key));
}

function closeEntityDetail() {
  state.selectedKey = null;
  renderMap();
  renderDetail();
}

/* ---------- tables ---------- */

const ASSET_FILTERS = [
  ['map', 'Network map', null],
  ['all', 'All assets', null],
  ['network', 'Network', ['network', 'zone', 'route']],
  ['endpoints', 'Endpoints', ['endpoint']],
  ['services', 'Services', ['service', 'software']],
  ['identities', 'Identities', ['identity']],
  ['credentials', 'Credentials', ['credential']],
  ['other', 'Controls & exposure', ['control', 'exposure', 'telemetry', 'cloud_resource', 'data_resource']]
];

function chipMarkup(options, selectedValue) {
  return options.map(([value, label]) => `<button type="button" class="chip${value === selectedValue ? ' selected' : ''}" data-chip="${escapeHtml(value)}" aria-pressed="${value === selectedValue}">${escapeHtml(label)}</button>`).join('');
}

const PERIOD_MS = {
  '1h': 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000
};

const ALERT_SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 };

function matchesPeriod(iso, period) {
  if (period === 'all') return true;
  const time = Date.parse(iso);
  return Number.isFinite(time) && time >= Date.now() - (PERIOD_MS[period] || 0);
}

function matchesTimeRange(iso, filters) {
  const time = Date.parse(iso);
  if (!Number.isFinite(time)) return false;
  const from = filters.from ? Date.parse(filters.from) : -Infinity;
  const to = filters.to ? Date.parse(filters.to) : Infinity;
  if (Number.isFinite(from) && time < from) return false;
  if (Number.isFinite(to) && time > to) return false;
  return filters.from || filters.to ? true : matchesPeriod(iso, filters.period);
}

function optionMarkup(options, selectedValue) {
  return options.map(([value, label]) => `<option value="${escapeHtml(value)}"${value === selectedValue ? ' selected' : ''}>${escapeHtml(label)}</option>`).join('');
}

function filterSelect(label, name, options, selectedValue) {
  return `<label><span>${escapeHtml(label)}</span><select name="${escapeHtml(name)}">${optionMarkup(options, selectedValue)}</select></label>`;
}

function filterInput(label, name, type, value, placeholder = '') {
  const step = type === 'datetime-local' ? ' step="1"' : '';
  return `<label><span>${escapeHtml(label)}</span><input type="${escapeHtml(type)}" name="${escapeHtml(name)}" value="${escapeHtml(value)}" placeholder="${escapeHtml(placeholder)}"${step}></label>`;
}

function renderTableTools(scope, controls, visibleCount, totalCount) {
  const tools = document.querySelector('#tableTools');
  tools.hidden = false;
  tools.innerHTML = `<div class="filter-bar" data-filter-scope="${escapeHtml(scope)}">${controls}</div><p class="filter-summary">Showing ${visibleCount} of ${totalCount}</p>`;
}

function tableMarkup(columns, rows, quietText) {
  if (!rows.length) return `<div class="table-quiet">${quietText}</div>`;
  return `<table class="data-table"><thead><tr>${columns.map((column) => `<th>${escapeHtml(column)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>`;
}

function pillCell(value) {
  return `<span class="pill ${escapeHtml(String(value))}">${escapeHtml(String(value))}</span>`;
}

function statePill(level) {
  const label = { ok: 'normal', watch: 'review', impact: 'impact' }[level] || level;
  return `<span class="pill ${escapeHtml(level)}">${escapeHtml(label)}</span>`;
}

function renderAssetsTable() {
  const tools = document.querySelector('#tableTools');
  tools.hidden = false;
  tools.innerHTML = `<div class="chips">${chipMarkup(ASSET_FILTERS.map(([value, label]) => [value, label]), state.assetFilter)}</div>`;
  const filter = ASSET_FILTERS.find(([value]) => value === state.assetFilter)?.[2] || null;
  const sets = stateSets();
  const entities = state.graph.entities.filter((entity) => {
    if (state.assetFilter === 'map') return GraphLayout.isTopologyEntity(entity, state.graph.capabilities);
    return !filter || filter.includes(entity.type);
  });
  const rows = entities.map((entity) => {
    const level = stateForKey(entity.key, sets);
    const detail = [entity.platform, entity.provider, Array.isArray(entity.addresses) ? entity.addresses[0] : null].filter(Boolean).join(' · ');
    return `<tr class="selectable" data-key="${escapeHtml(entity.key)}" data-state="${escapeHtml(level)}"><td><strong>${escapeHtml(displayEntityName(entity))}</strong></td><td class="mono">${escapeHtml(entity.type || '')}</td><td>${statePill(level)}</td><td>${escapeHtml(detail || '—')}</td><td class="mono">${escapeHtml(formatRelative(entity.lastSeen))}</td></tr>`;
  });
  document.querySelector('#tableContent').innerHTML = tableMarkup(
    ['System', 'Type', 'State', 'Details', 'Last seen'], rows,
    state.graph.entities.length
      ? state.assetFilter === 'credentials' ? 'No credential metadata was discovered. Lookout never inventories credential secrets.' : 'No assets match this filter.'
      : 'No systems are connected yet. Continue Setup to install Lookout and survey your environment.');
  document.querySelectorAll('#tableContent tr.selectable').forEach((row) => {
    row.addEventListener('click', () => {
      if (row.dataset.state === 'watch') {
        openAlertsForEntity(row.dataset.key);
        return;
      }
      state.selectedKey = row.dataset.key;
      goToView('overview');
    });
  });
}

function orderedAlerts() {
  return [...state.alerts].sort((a, b) => alertTime(b).localeCompare(alertTime(a)) || a.id.localeCompare(b.id));
}

function filteredAlerts() {
  const minimumRank = { all: 0, medium: 2, high: 3, critical: 4 }[state.alertFilters.severity] || 0;
  return orderedAlerts().filter((alert) => {
    const statusMatches = state.alertFilters.status === 'all'
      || (state.alertFilters.status === 'active' && ['open', 'to_fix'].includes(alert.status))
      || alert.status === state.alertFilters.status;
    return statusMatches
      && (ALERT_SEVERITY_RANK[alert.severity] || 0) >= minimumRank
      && matchesTimeRange(alertTime(alert), state.alertFilters);
  });
}

function renderAlertFilters(visibleCount) {
  renderTableTools('alerts', [
    filterSelect('Time', 'period', [['all', 'Any time'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days']], state.alertFilters.period),
    filterInput('From', 'from', 'datetime-local', state.alertFilters.from),
    filterInput('To', 'to', 'datetime-local', state.alertFilters.to),
    filterSelect('Severity', 'severity', [['all', 'Any severity'], ['medium', 'Medium+'], ['high', 'High+'], ['critical', 'Critical']], state.alertFilters.severity),
    filterSelect('Status', 'status', [['active', 'Open or marked to fix'], ['open', 'Open'], ['to_fix', 'To fix'], ['closed', 'Closed'], ['all', 'All statuses']], state.alertFilters.status)
  ].join(''), visibleCount, state.alerts.length);
}

function highestPriorityOpenAlert(entityKey = null) {
  const rank = { critical: 4, high: 3, medium: 2, low: 1 };
  return openAlerts().filter((alert) => !entityKey || (alert.entities || []).includes(entityKey)).sort((a, b) =>
    (rank[b.severity] || 0) - (rank[a.severity] || 0) ||
    alertTime(b).localeCompare(alertTime(a)) ||
    a.id.localeCompare(b.id))[0] || null;
}

function openHighestPriorityAlert() {
  const entityKey = typeof state.reviewAlertAfterNavigation === 'string' ? state.reviewAlertAfterNavigation : null;
  state.reviewAlertAfterNavigation = false;
  const alert = highestPriorityOpenAlert(entityKey);
  if (alert) openAlertDetail(alert.id);
}

function openAlertsForEntity(entityKey) {
  state.reviewAlertAfterNavigation = entityKey;
  if (state.view === 'alerts') openHighestPriorityAlert();
  else goToView('alerts');
}

function renderAlertsTable() {
  const alerts = filteredAlerts();
  renderAlertFilters(alerts.length);
  const rows = alerts.map((alert) =>
    `<tr class="selectable" data-alert-id="${escapeHtml(alert.id)}"><td>${pillCell(alert.severity)}</td><td><strong>${escapeHtml(alert.title)}</strong></td><td>${pillCell(alert.status)}</td><td>${escapeHtml(nameList(alert.entities, 4))}</td><td class="mono">${escapeHtml(formatRelative(alertTime(alert)))}</td></tr>`);
  document.querySelector('#tableContent').innerHTML = tableMarkup(
    ['Severity', 'Alert', 'Status', 'Systems', 'When'], rows,
    state.alerts.length ? 'No alerts match these filters.' : 'No alerts yet.');
  document.querySelectorAll('#tableContent tr[data-alert-id]').forEach((row) => row.addEventListener('click', () => openAlertDetail(row.dataset.alertId)));
}

function alertTimeline(detail) {
  return (detail.evidenceTimeline || []).map((event) => `
    <li><time>${escapeHtml(new Date(event.time).toLocaleString())}</time><strong>${escapeHtml(humanize(event.activity || event.class))}</strong><span>${escapeHtml(`${humanize(event.category)} · ${humanize(event.outcome)}`)}</span></li>`).join('');
}

function alertHistory(detail) {
  return (detail.statusHistory || []).map((entry) => `
    <li><time>${escapeHtml(new Date(entry.at).toLocaleString())}</time><strong>${escapeHtml(humanize(entry.status))}</strong><span>${escapeHtml(entry.reason ? `${entry.actor}: ${entry.reason}` : entry.actor)}</span></li>`).join('');
}

function nextAlertId(alertId) {
  const alerts = filteredAlerts();
  const index = alerts.findIndex((alert) => alert.id === alertId);
  return index >= 0 ? alerts[index + 1]?.id || null : null;
}

function alertDetailControls(nextId) {
  return `<div class="alert-detail-actions">
    <button class="alert-detail-next" type="button"${nextId ? '' : ' disabled'}>Next alert</button>
    <button class="alert-detail-close" type="button" aria-label="Close alert details">×</button>
  </div>`;
}

function wireAlertDetailControls(panel, nextId) {
  panel.querySelector('.alert-detail-close').addEventListener('click', closeAlertDetail);
  if (nextId) panel.querySelector('.alert-detail-next').addEventListener('click', () => openAlertDetail(nextId));
}

function renderAlertDetail() {
  const panel = document.querySelector('#alertDetailPanel');
  if (!state.selectedAlertId) { panel.hidden = true; return; }
  panel.hidden = false;
  const nextId = nextAlertId(state.selectedAlertId);
  if (!state.alertDetail || state.alertDetail.id !== state.selectedAlertId) {
    panel.innerHTML = `${alertDetailControls(nextId)}<p class="table-quiet">Loading alert…</p>`;
    wireAlertDetailControls(panel, nextId);
    return;
  }
  const detail = state.alertDetail;
  const systems = (detail.affectedSystems || []).map((system) => `<li><strong>${escapeHtml(system.name)}</strong><span>${escapeHtml(humanize(system.type))}</span></li>`).join('');
  const confidence = typeof detail.confidence === 'number' ? `${Math.round(detail.confidence * 100)}% confidence` : 'Confidence unavailable';
  const evidenceEmpty = detail.evidenceRemote
    ? `${detail.evidenceCount || 0} evidence events matched. Event details remain on the monitored infrastructure.`
    : 'Evidence events are no longer retained.';
  panel.innerHTML = `
    ${alertDetailControls(nextId)}
    <h2>${escapeHtml(detail.title)}</h2>
    <div class="alert-detail-meta">${pillCell(detail.severity)} ${pillCell(detail.status)} <span>${escapeHtml(confidence)}</span></div>
    <section><h3>MATCH REASON</h3><p>${escapeHtml(detail.matchReason || 'Match reason unavailable.')}</p></section>
    <section><h3>AFFECTED SYSTEMS</h3><ul class="alert-system-list">${systems || '<li><span>No mapped systems</span></li>'}</ul></section>
    <section><h3>EVIDENCE TIMELINE</h3><ol class="alert-timeline">${alertTimeline(detail) || `<li><span>${escapeHtml(evidenceEmpty)}</span></li>`}</ol></section>
    <section><h3>REVIEW HISTORY</h3><ol class="alert-timeline">${alertHistory(detail) || '<li><span>No review history.</span></li>'}</ol></section>
    <form id="alertStatusForm" class="alert-status-form">
      <label>Status<select name="status">
        <option value="open"${detail.status === 'open' ? ' selected' : ''}>Open</option>
        <option value="to_fix"${detail.status === 'to_fix' ? ' selected' : ''}>To fix</option>
        <option value="closed"${detail.status === 'closed' ? ' selected' : ''}>Closed</option>
      </select></label>
      <label>Reason (optional)<textarea name="reason" minlength="3" maxlength="1000" placeholder="Why is this status changing?"></textarea></label>
      <button type="submit">Save status</button><p id="alertStatusMessage" role="status"></p>
    </form>`;
  wireAlertDetailControls(panel, nextId);
  panel.querySelector('#alertStatusForm').addEventListener('submit', updateAlertStatus);
}

async function openAlertDetail(alertId) {
  state.selectedAlertId = alertId;
  state.alertDetail = null;
  renderAlertDetail();
  try {
    const detail = await LookoutApi.alert(alertId);
    if (state.selectedAlertId !== alertId) return;
    state.alertDetail = detail;
    renderAlertDetail();
  } catch (error) {
    if (state.selectedAlertId !== alertId) return;
    const panel = document.querySelector('#alertDetailPanel');
    const nextId = nextAlertId(alertId);
    panel.innerHTML = `${alertDetailControls(nextId)}<p class="table-quiet">${escapeHtml(error.message)}</p>`;
    wireAlertDetailControls(panel, nextId);
  }
}

function closeAlertDetail() {
  state.selectedAlertId = null;
  state.alertDetail = null;
  renderAlertDetail();
}

async function updateAlertStatus(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('button');
  const message = form.querySelector('#alertStatusMessage');
  button.disabled = true;
  message.textContent = 'Saving…';
  try {
    await LookoutApi.updateAlert(state.selectedAlertId, form.elements.status.value, form.elements.reason.value);
    state.alertDetail = await LookoutApi.alert(state.selectedAlertId);
    await refresh();
    renderAlertDetail();
  } catch (error) {
    message.textContent = error.message;
    button.disabled = false;
  }
}

function renderRulesTable() {
  const ruleById = new Map(state.rules.map((rule) => [rule.id, rule]));
  const active = state.plan.filter((item) => item.deploy !== false && item.state !== 'blocked' && ruleById.get(item.analyticId)?.enabled !== false);
  const planRows = active.map((item) => {
    const rule = ruleById.get(item.analyticId);
    return `<tr><td><strong>${escapeHtml(rule?.title || item.title || humanize(item.analyticId))}</strong></td><td>${rule?.severity || item.severity ? pillCell(rule?.severity || item.severity) : '—'}</td></tr>`;
  });
  document.querySelector('#tableContent').innerHTML = `
    <section class="rules-section active-rules-section">
      <h2>Active rules</h2>
      <div class="active-rule-count"><span>${active.length}</span><small>rules active</small></div>
      <p class="rules-note">Only rules supported by the telemetry currently reporting are active.</p>
    </section>
    <section class="rules-section"><h2>Rule list</h2>${tableMarkup(['Rule', 'Severity'], planRows, 'No rules are active for the currently available telemetry.')}</section>`;
}

function filteredEvents() {
  const keyword = state.activityFilters.keyword.trim().toLowerCase();
  return [...state.events]
    .filter((event) => state.activityFilters.source === 'all' || event.source?.adapter === state.activityFilters.source)
    .filter((event) => !keyword || JSON.stringify(event).toLowerCase().includes(keyword))
    .filter((event) => matchesTimeRange(event.time, state.activityFilters))
    .sort((a, b) => b.time.localeCompare(a.time))
    .slice(0, 100);
}

function renderActivityFilters(sources, visibleCount) {
  renderTableTools('logs', [
    filterInput('Search', 'keyword', 'search', state.activityFilters.keyword, 'Keyword'),
    filterSelect('Time', 'period', [['1h', 'Last hour'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days'], ['all', 'Any time']], state.activityFilters.period),
    filterInput('From', 'from', 'datetime-local', state.activityFilters.from),
    filterInput('To', 'to', 'datetime-local', state.activityFilters.to),
    filterSelect('Source', 'source', [['all', 'All sources'], ...sources.map((source) => [source, humanize(source)])], state.activityFilters.source)
  ].join(''), visibleCount, state.events.length);
}

function renderLogsTable() {
  if (LookoutApi.hosted) {
    document.querySelector('#tableTools').hidden = true;
    document.querySelector('#tableContent').innerHTML = '<div class="table-quiet">Log search is only available with cloud log storage.</div>';
    return;
  }
  const sources = [...new Set(state.events.map((event) => event.source?.adapter).filter(Boolean))].sort();
  const events = filteredEvents();
  renderActivityFilters(sources, events.length);
  const rows = events.map((event) =>
    `<tr class="selectable" data-event-id="${escapeHtml(event.id)}"><td class="mono">${escapeHtml(new Date(event.time).toLocaleString())}</td><td><strong>${escapeHtml(humanize(event.activity || event.class))}</strong></td><td>${escapeHtml(nameList(event.entityKeys, 3))}</td><td class="mono">${escapeHtml(event.source?.adapter || '')}</td><td>${escapeHtml(truncate(event.attributes?.message || event.attributes?.command || '', 100) || '—')}</td></tr>`);
  document.querySelector('#tableContent').innerHTML = tableMarkup(
    ['Time', 'Event', 'System', 'Source', 'Message'], rows,
    state.logSearchError || (state.events.length ? 'No logs match this query.' : LookoutApi.deploymentId ? 'Raw logs stay in your deployment and are not copied into the Lookout SaaS.' : 'No logs have been recorded yet.'));
  document.querySelectorAll('#tableContent tr[data-event-id]').forEach((row) =>
    row.addEventListener('click', () => openLogDetail(row.dataset.eventId)));
}

function logValue(value) {
  if (value === null || value === undefined || value === '') return '—';
  if (typeof value === 'object') return JSON.stringify(value, null, 2);
  return String(value);
}

function logFieldLabel(key) {
  return humanize(String(key).replace(/([a-z0-9])([A-Z])/g, '$1 $2'));
}

function logDetailRows(value) {
  if (!value || typeof value !== 'object' || !Object.keys(value).length) return '<p class="detail-quiet">—</p>';
  return `<dl class="log-detail-list">${Object.entries(value).map(([key, item]) =>
    `<div><dt>${escapeHtml(logFieldLabel(key))}</dt><dd class="${typeof item === 'object' ? 'pre-wrap' : ''}">${escapeHtml(logValue(item))}</dd></div>`).join('')}</dl>`;
}

function renderLogDetail() {
  const panel = document.querySelector('#logDetailPanel');
  const event = state.events.find((item) => item.id === state.selectedEventId);
  if (!event) { panel.hidden = true; return; }
  const systems = (event.entityKeys || []).map((key) => `<li><span>${escapeHtml(entityName(key))}</span><code>${escapeHtml(key)}</code></li>`).join('');
  const overview = {
    time: new Date(event.time).toLocaleString(),
    ingestedAt: event.ingestedAt ? new Date(event.ingestedAt).toLocaleString() : null,
    category: event.category,
    class: event.class,
    activity: event.activity,
    outcome: event.outcome,
    severity: event.severity,
    eventId: event.id,
    schemaVersion: event.schemaVersion
  };
  panel.hidden = false;
  panel.innerHTML = `
    <div class="log-detail-actions"><button class="log-detail-close" type="button" aria-label="Close log details">×</button></div>
    <h2>${escapeHtml(humanize(event.activity || event.class || 'Log event'))}</h2>
    <div class="log-detail-meta">${pillCell(event.outcome)} <span>${escapeHtml(humanize(event.category))} · ${escapeHtml(humanize(event.class))}</span></div>
    <section><h3>EVENT</h3>${logDetailRows(overview)}</section>
    <section><h3>SYSTEMS</h3><ul class="log-system-list">${systems || '<li><span>—</span></li>'}</ul></section>
    <section><h3>SOURCE</h3>${logDetailRows(event.source)}</section>
    <section><h3>NETWORK</h3>${logDetailRows({ sourceEndpoint: event.sourceEndpoint, destinationEndpoint: event.destinationEndpoint })}</section>
    <section><h3>ACTOR & SERVICE</h3>${logDetailRows({ actor: event.actor, service: event.service })}</section>
    <section><h3>CORRELATION</h3>${logDetailRows(event.correlation)}</section>
    <section><h3>ATTRIBUTES</h3>${logDetailRows(event.attributes)}</section>
    <section><h3>FULL EVENT</h3><pre class="log-event-json">${escapeHtml(JSON.stringify(event, null, 2))}</pre></section>`;
  panel.querySelector('.log-detail-close').addEventListener('click', closeLogDetail);
}

function openLogDetail(eventId) {
  state.selectedEventId = eventId;
  renderLogDetail();
}

function closeLogDetail() {
  state.selectedEventId = null;
  renderLogDetail();
}

function renderTableView() {
  const tools = document.querySelector('#tableTools');
  document.querySelector('.table-card').classList.toggle('rules-card', state.view === 'rules');
  document.querySelector('#tableContent').classList.toggle('rules-content', state.view === 'rules');
  tools.hidden = true;
  if (state.view === 'assets') renderAssetsTable();
  else if (state.view === 'alerts') renderAlertsTable();
  else if (state.view === 'rules') renderRulesTable();
  else if (state.view === 'logs') renderLogsTable();
}

/* ---------- view switching & refresh ---------- */

function renderAll() {
  renderHeader();
  renderBanner();
  renderBadges();
  renderAccount();
  if (state.view === 'setup') {
    renderSetupSession();
  } else if (state.view === 'settings') {
    renderSettingsSession();
  } else if (state.view === 'overview') {
    document.querySelector('#overviewView').classList.toggle('is-empty', !state.graph.entities.length);
    renderMap(); renderDetail();
  }
  else renderTableView();
}

function setView(view) {
  if (state.view === 'settings' && view !== 'settings') clearSupportAccountToken();
  state.view = view in VIEW_TEXT ? view : 'overview';
  const overview = state.view === 'overview';
  const setup = state.view === 'setup';
  const settings = state.view === 'settings';
  document.querySelector('#overviewView').classList.toggle('active', overview);
  document.querySelector('#tableView').classList.toggle('active', !overview && !setup && !settings);
  document.querySelector('#setupView').classList.toggle('active', setup);
  document.querySelector('#settingsView').classList.toggle('active', settings);
  document.querySelectorAll('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.view === state.view));
  if (state.view !== 'alerts') closeAlertDetail();
  if (state.view !== 'logs') closeLogDetail();
  renderAll();
  if (state.view === 'alerts' && state.reviewAlertAfterNavigation) openHighestPriorityAlert();
}

async function renderSetupSession() {
  if (typeof LookoutAuth === 'undefined' || !LookoutAuth.configured) {
    return;
  }
  const session = await LookoutAuth.session();
  if (!session) {
    window.location.assign('/signup');
    return;
  }
  document.querySelector('#setupCard').hidden = false;
  document.querySelector('#copySetupButton').disabled = false;
}

async function renderSettingsSession() {
  const email = document.querySelector('#settingsAccountEmail');
  const signOut = document.querySelector('#signOutButton');
  const disclosure = document.querySelector('#deleteAccountDisclosure');
  if (typeof LookoutAuth === 'undefined' || !LookoutAuth.configured) {
    email.textContent = 'Supabase Auth is not configured';
    signOut.hidden = true;
    disclosure.hidden = true;
    return;
  }
  const session = await LookoutAuth.session();
  if (!session) {
    window.location.assign('/signup');
    return;
  }
  email.textContent = session.user.email || 'Signed in';
  signOut.hidden = false;
  disclosure.hidden = false;
  disclosure.setAttribute('aria-expanded', String(state.accountDangerOpen));
  document.querySelector('#deleteAccountPanel').hidden = !state.accountDangerOpen;
}

function clearSupportAccountToken() {
  state.supportAccountToken = null;
}

function supportMcpSetup(token) {
  return `Configure the Lookout Support MCP server on this machine.

Name: devlookout
Transport: Streamable HTTP
URL: https://app.devlookout.com/support/mcp
Authentication: Bearer token, not OAuth
Bearer token: ${token}

Store the token securely in the coding agent's local MCP configuration. Do not print it,
add it to source control, logs, or URLs. Do not run OAuth login.

After configuration, verify that the server exposes:
- ask_lookout_support
- check_lookout_support`;
}

async function copySupportMcpSetup() {
  const button = document.querySelector('#copySupportMcpSetupButton');
  const status = document.querySelector('#supportMcpSetupStatus');
  button.disabled = true;
  status.textContent = 'Preparing MCP setup…';
  try {
    const result = await LookoutApi.supportAccountToken();
    state.supportAccountToken = result.token;
    await copySetupValue(supportMcpSetup(state.supportAccountToken), button, status, 'MCP setup copied', 'The MCP setup could not be copied. Try again.');
  } catch {
    status.textContent = 'The MCP setup could not be copied. Try again.';
  } finally {
    clearSupportAccountToken();
    button.disabled = false;
  }
}

function validStoredSetup(value) {
  return value && /^set_[A-Za-z0-9_-]{16,128}$/.test(value.session_id || '') && /^(?:lst|lrc)_[A-Za-z0-9_-]{43}$/.test(value.setup_token || '') && /^ldw_[A-Za-z0-9_-]{43}$/.test(value.support_token || '');
}

function storedSetupSession() {
  try {
    const value = JSON.parse(sessionStorage.getItem(SETUP_SESSION_STORAGE));
    return validStoredSetup(value) ? value : null;
  } catch { return null; }
}

function setupPhaseText(status, completed, total) {
  return {
    pending: 'Installer is waiting.',
    claimed: Number.isSafeInteger(total) ? `Discovered ${total} VM${total === 1 ? '' : 's'}. Verifying the installer…` : 'Installer approved. Verifying proof of possession…',
    connected: 'Connected',
    discovering: Number.isSafeInteger(total) ? `Discovering · ${total} VM${total === 1 ? '' : 's'} found` : 'Discovering',
    deploying: Number.isSafeInteger(completed) && Number.isSafeInteger(total) ? `Deploying ${completed}/${total}` : 'Deploying',
    verifying: Number.isSafeInteger(completed) && Number.isSafeInteger(total) ? `Verifying ${completed}/${total}` : 'Verifying',
    needs_access: 'Needs access',
    reporting_interrupted: 'Reporting interrupted',
    complete: Number.isSafeInteger(total) ? `Protected ${total}/${total}` : 'Protected',
    failed: Number.isSafeInteger(total) ? `Setup failed after selecting ${total} VM${total === 1 ? '' : 's'}.` : 'Setup failed.',
    expired: 'This setup token expired. Reload to create a new token.'
  }[status] || 'Preparing secure setup…';
}

function mapSetupPhaseText(status, completed, total) {
  if (status === 'discovering' && Number.isSafeInteger(total)) return `Discovered ${total} VM${total === 1 ? '' : 's'}`;
  return setupPhaseText(status, completed, total);
}

function setupEtaText(status, completed, total) {
  if (status === 'pending') return 'Run the copied prompt to begin. Most installations finish in 5-10 minutes after Connected.';
  if (status === 'failed') return '';
  if (status === 'needs_access') return 'Installation is paused until the required access is granted.';
  if (status === 'reporting_interrupted') return 'Installation is still running. Progress updates are delayed.';
  if (status === 'verifying') return 'Estimated time remaining: under 2 minutes.';
  if (status === 'deploying' && Number.isSafeInteger(completed) && Number.isSafeInteger(total) && completed > 0) return 'Estimated time remaining: 2-5 minutes.';
  if (['connected', 'claimed', 'discovering', 'deploying'].includes(status)) return 'Estimated time remaining: 5-10 minutes.';
  if (status === 'complete') return 'Setup complete.';
  return 'Most installations finish in 5-10 minutes.';
}

function setupProgressPresentation(status) {
  if (status === 'needs_access') return { label: 'ACTION REQUIRED', badge: 'PAUSED' };
  if (status === 'reporting_interrupted') return { label: 'INSTALLATION IN PROGRESS', badge: 'DELAYED' };
  if (status === 'complete') return { label: 'INSTALLATION COMPLETE', badge: 'DONE' };
  if (status === 'failed' || status === 'expired') return { label: 'INSTALLATION STOPPED', badge: 'STOPPED' };
  return { label: 'INSTALLATION IN PROGRESS', badge: 'LIVE' };
}

function showSetup(value, status = 'pending', completed, total) {
  state.setup = value;
  state.setupStatus = status;
  state.setupCompleted = Number.isSafeInteger(completed) ? completed : null;
  state.setupTotal = Number.isSafeInteger(total) ? total : null;
  document.querySelector('#setupPhase').textContent = setupPhaseText(status, completed, total);
  document.querySelector('#setupEta').textContent = setupEtaText(status, completed, total);
  const presentation = setupProgressPresentation(status);
  const progress = document.querySelector('#setupProgress');
  document.querySelector('#setupProgressLabel').textContent = presentation.label;
  document.querySelector('#setupProgressBadge').textContent = presentation.badge;
  progress.dataset.status = status;
  progress.hidden = false;
  document.querySelector('#resetSetupButton').hidden = status !== 'failed';
  renderHeader();
  renderBanner();
  if (state.view === 'overview') renderMap();
}

async function resetFailedSetup() {
  const button = document.querySelector('#resetSetupButton');
  button.disabled = true;
  if (state.setupPreparationFailed) {
    state.setupPreparationFailed = false;
    setupInitialization = null;
    document.querySelector('#setupPhase').textContent = 'Preparing secure setup…';
    document.querySelector('#setupData').textContent = '';
    document.querySelector('#setupProgressLabel').textContent = 'PREPARING SETUP';
    document.querySelector('#setupProgressBadge').textContent = 'CHECKING';
    try { await ensureSetupSession(); } finally { button.disabled = false; }
    return;
  }
  try {
    await LookoutApi.resetSetup();
    sessionStorage.removeItem(SETUP_SESSION_STORAGE);
    window.location.reload();
  } catch {
    button.disabled = false;
    document.querySelector('#setupData').textContent = 'Setup could not be reset. Try again.';
  }
}

async function pollSetupSession() {
  if (!state.setup) return;
  const setup = state.setup;
  clearTimeout(setupPollTimer);
  setupPollTimer = null;
  try {
    const status = await LookoutApi.setupStatus(setup.session_id);
    if (state.setup?.session_id !== setup.session_id) return;
    showSetup(setup, status.status, status.completed, status.total);
    const data = document.querySelector('#setupData');
    if (status.status === 'failed') {
      data.textContent = 'Try again with the same setup token.';
    } else if (status.deployment_id) {
      try {
        if (LookoutApi.deploymentId !== status.deployment_id) LookoutApi.selectDeployment(status.deployment_id);
        const graph = await LookoutApi.graph();
        const systems = (graph.entities || []).filter((entity) => entity.type === 'endpoint').length;
        data.textContent = systems ? `${systems} system${systems === 1 ? '' : 's'} reporting live data.` : 'The first deployment snapshot is reporting.';
      } catch {
        data.textContent = 'Waiting for the first protected system to report data.';
      }
    } else if (status.status === 'connected') {
      data.textContent = 'The installer is connected. Cloud discovery is starting.';
    }
    if (status.status === 'complete' && status.dashboard_url) {
      sessionStorage.removeItem(SETUP_SESSION_STORAGE);
      window.location.replace(status.dashboard_url);
      return;
    }
    if (status.status === 'expired') {
      sessionStorage.removeItem(SETUP_SESSION_STORAGE);
      state.setup = null;
      setupInitialization = null;
      setTimeout(() => { ensureSetupSession(); }, 0);
      return;
    }
    if (status.status === 'failed') return;
  } catch (error) {
    if (state.setup?.session_id !== setup.session_id) return;
    if (error?.status === 404) {
      sessionStorage.removeItem(SETUP_SESSION_STORAGE);
      state.setup = null;
      setupInitialization = null;
      setTimeout(() => { ensureSetupSession(); }, 0);
      return;
    }
    document.querySelector('#setupPhase').textContent = 'Unable to check setup status. Retrying…';
  }
  if (state.setup?.session_id === setup.session_id) setupPollTimer = setTimeout(pollSetupSession, 2000);
}

async function ensureSetupSession() {
  if (setupInitialization) return setupInitialization;
  setupInitialization = (async () => {
    let value = null;
    try { value = JSON.parse(sessionStorage.getItem(SETUP_SESSION_STORAGE)); } catch { /* No pending setup session. */ }
    if (LookoutApi.hosted) {
      const active = (await LookoutApi.activeSetup()).setup;
      if (active?.session_id) {
        value = { session_id: active.session_id, restored: true };
        document.querySelector('#setupCard').hidden = true;
        document.querySelector('#setupCoverage').hidden = false;
        sessionStorage.setItem(SETUP_SESSION_STORAGE, JSON.stringify(value));
        showSetup(value, active.status, active.completed, active.total);
        document.querySelector('#setupData').textContent = active.status === 'needs_access'
          ? 'Open the Needs access step to continue the same installation.'
          : active.status === 'failed'
            ? 'Try again with the same setup token.'
          : 'This installation was restored from Lookout and is still running.';
        clearTimeout(setupPollTimer);
        await pollSetupSession();
        return;
      }
      const result = await LookoutApi.deployments();
      const deployment = Array.isArray(result.deployments) ? result.deployments[0] : null;
      if (deployment?.status === 'central_missing' && validStoredSetup(deployment.recovery)) value = deployment.recovery;
      else if (deployment && deployment.status !== 'uninstalled') {
        sessionStorage.removeItem(SETUP_SESSION_STORAGE);
        document.querySelector('#setupCard').hidden = true;
        document.querySelector('#setupCoverage').hidden = true;
        document.querySelector('#setupProgress').hidden = false;
        document.querySelector('#setupPhase').textContent = 'Lookout is already set up for this account.';
        document.querySelector('#setupData').textContent = 'Open Map to view the monitored network.';
        return;
      }
    }
    if (!validStoredSetup(value)) value = await LookoutApi.createSetupSession();
    document.querySelector('#setupCard').hidden = false;
    document.querySelector('#setupCoverage').hidden = false;
    sessionStorage.setItem(SETUP_SESSION_STORAGE, JSON.stringify(value));
    const instructions = document.querySelector('#setupInstructions');
    instructions.textContent = instructions.textContent.replace(/LOOKOUT_SETUP_TOKEN_VALUE|(?:lst|lrc)_[A-Za-z0-9_-]{43}/g, value.setup_token);
    instructions.textContent = instructions.textContent.replace(/LOOKOUT_SUPPORT_TOKEN_VALUE|ldw_[A-Za-z0-9_-]{43}/g, value.support_token);
    if (instructions.textContent.includes('LOOKOUT_SETUP_TOKEN_VALUE') || instructions.textContent.includes('LOOKOUT_SUPPORT_TOKEN_VALUE') || !instructions.textContent.includes(`<lookout_setup_token>${value.setup_token}</lookout_setup_token>`) || !instructions.textContent.includes(`<lookout_support_token>${value.support_token}</lookout_support_token>`)) throw new Error('Setup prompt token injection failed');
    if (value.recovery) instructions.textContent = instructions.textContent.replace('Install Lookout on Linux VMs I control.', 'Recover Lookout central on an approved existing or new Linux VM I control.');
    document.querySelector('#copySetupButton').disabled = false;
    state.setup = value;
    showSetup(value, 'pending');
    clearTimeout(setupPollTimer);
    await pollSetupSession();
  })().catch((error) => {
    state.setupPreparationFailed = true;
    state.setupStatus = 'failed';
    const progress = document.querySelector('#setupProgress');
    progress.hidden = false;
    progress.dataset.status = 'failed';
    document.querySelector('#setupProgressLabel').textContent = 'SETUP NOT READY';
    document.querySelector('#setupProgressBadge').textContent = 'STOPPED';
    document.querySelector('#setupPhase').textContent = error?.code === 'LOOKOUT_REQUEST_TIMEOUT'
      ? 'Setup service did not respond within 10 seconds.'
      : 'Setup could not be prepared.';
    document.querySelector('#setupEta').textContent = '';
    document.querySelector('#setupData').textContent = 'Try again. If the problem continues, check the service status.';
    document.querySelector('#resetSetupButton').hidden = false;
  });
  return setupInitialization;
}

async function copySetupInstructions() {
  const text = document.querySelector('#setupInstructions').textContent;
  await copySetupValue(text, document.querySelector('#copySetupButton'), document.querySelector('#setupCopyStatus'));
}

async function deleteAccount() {
  if (!window.confirm('Delete your Lookout account, deployments, setup sessions, and cloud console data? Local VM data is not deleted. This cannot be undone.')) return;
  clearSupportAccountToken();
  const button = document.querySelector('#deleteAccountButton');
  button.disabled = true;
  button.textContent = 'Deleting…';
  try {
    clearTimeout(setupPollTimer);
    await LookoutApi.deleteAccount();
    sessionStorage.removeItem(SETUP_SESSION_STORAGE);
    if (typeof LookoutAuth !== 'undefined') await LookoutAuth.clearSession();
    else if (typeof LookoutAnalytics !== 'undefined') LookoutAnalytics.reset();
    window.location.replace('/signup');
  } catch {
    button.disabled = false;
    button.textContent = 'Delete account permanently';
    document.querySelector('#settingsAccountEmail').textContent = 'Account deletion could not finish. Cleanup is safe to retry.';
  }
}

async function copySetupValue(value, button, status, successMessage = 'Copied to clipboard.', failureMessage = 'Copy failed. Select the value and copy it manually.') {
  if (!value) return;
  const original = button.textContent;
  try {
    if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(value);
    else {
      const input = document.createElement('textarea');
      input.value = value; input.style.position = 'fixed'; input.style.opacity = '0';
      document.body.append(input); input.select(); document.execCommand('copy'); input.remove();
    }
    button.textContent = 'Copied';
    status.textContent = successMessage;
  } catch {
    status.textContent = failureMessage;
  }
  setTimeout(() => { button.textContent = original; }, 1600);
}

async function navigateToView(view) {
  if (view === 'setup' && typeof LookoutAuth !== 'undefined' && LookoutAuth.configured) {
    const session = await LookoutAuth.session();
    if (!session) { window.location.assign('/signup'); return; }
    state.user = {
      email: session.user.email,
      displayName: session.user.user_metadata?.full_name || session.user.user_metadata?.name || null,
      avatarUrl: session.user.user_metadata?.avatar_url || session.user.user_metadata?.picture || null
    };
  }
  setView(view);
}

function requestedView() {
  const legacyHashView = window.location.hash.slice(1);
  if (legacyHashView in VIEW_TEXT) return legacyHashView;
  return Object.entries(VIEW_PATHS).find(([, pathname]) => pathname === window.location.pathname)?.[0] || 'overview';
}

function viewUrl(view) {
  if (/^\/deployments\/dpl_[A-Za-z0-9_-]{32}$/.test(window.location.pathname)) return `${window.location.pathname}#${view}`;
  return VIEW_PATHS[view] || VIEW_PATHS.overview;
}

function goToView(view, { replace = false } = {}) {
  const target = view in VIEW_TEXT ? view : 'overview';
  window.history[replace ? 'replaceState' : 'pushState']({}, '', viewUrl(target));
  void navigateToView(target);
}

async function restoreHostedDashboard() {
  if (!LookoutApi.hosted || LookoutApi.deploymentId) return true;
  if (storedSetupSession()) {
    window.location.replace('/setup');
    return false;
  }
  const session = typeof LookoutAuth !== 'undefined' && LookoutAuth.configured ? await LookoutAuth.session() : null;
  if (!session) {
    window.location.replace('/signup');
    return false;
  }
  state.user = sessionUser(session);
  const result = await LookoutApi.deployments();
  const deployment = Array.isArray(result.deployments) ? result.deployments[0] : null;
  if (!deployment) {
    window.location.replace('/setup');
    return false;
  }
  LookoutApi.selectDeployment(deployment.deployment_id);
  state.installationStatus = deployment.status;
  state.recoverySetup = deployment.recovery || null;
  return true;
}

function hostedTopology(graph) {
  const entities = [...(graph?.entities || [])];
  const relationships = (graph?.relationships || []).map((edge) => ({ ...edge, fromKey: edge.fromKey || edge.from, toKey: edge.toKey || edge.to }));
  const capabilities = graph?.capabilities || [];
  if (!LookoutApi.hosted || !LookoutApi.deploymentId) return { entities, relationships, capabilities };
  const endpoints = entities.filter((entity) => entity.type === 'endpoint');
  if (!endpoints.length) return { entities, relationships, capabilities };
  let networks = entities.filter((entity) => entity.type === 'network');
  if (!networks.length) {
    const network = { key: `network:${LookoutApi.deploymentId}`, type: 'network', name: 'Private network' };
    entities.unshift(network);
    networks = [network];
  }
  const networkKeys = new Set(networks.map((network) => network.key));
  const connected = new Set(relationships.flatMap((edge) => networkKeys.has(edge.fromKey) ? [edge.toKey] : networkKeys.has(edge.toKey) ? [edge.fromKey] : []));
  for (const endpoint of endpoints) {
    if (!connected.has(endpoint.key)) relationships.push({ fromKey: endpoint.key, toKey: networks[0].key, relation: 'member_of' });
  }
  return { entities, relationships, capabilities };
}

async function refresh() {
  if (!supplementalRefresh) supplementalRefresh = Promise.allSettled([LookoutApi.rules(), LookoutApi.behaviors(), LookoutApi.me()])
    .then(([rules, behaviors, user]) => {
      if (rules.status === 'fulfilled' && Array.isArray(rules.value)) state.rules = rules.value;
      if (behaviors.status === 'fulfilled' && Array.isArray(behaviors.value)) state.behaviors = behaviors.value;
      if (user.status === 'fulfilled') state.user = { ...(state.user || {}), ...user.value, avatarUrl: user.value?.avatarUrl || state.user?.avatarUrl || null };
      renderAll();
    })
    .finally(() => { supplementalRefresh = null; });
  const [graph, alerts, plan, events, consoleHealth] = await Promise.allSettled([
    LookoutApi.graph(), LookoutApi.alerts(), LookoutApi.detectionPlan(),
    LookoutApi.events({ limit: 500, ...state.activityFilters }), LookoutApi.consoleHealth()
  ]);
  const reached = [graph, alerts, plan, events].some((result) => result.status === 'fulfilled');
  if (graph.status === 'fulfilled') state.graph = hostedTopology(graph.value);
  if (alerts.status === 'fulfilled' && Array.isArray(alerts.value)) state.alerts = alerts.value;
  if (plan.status === 'fulfilled' && Array.isArray(plan.value)) state.plan = plan.value;
  if (events.status === 'fulfilled' && Array.isArray(events.value)) { state.events = events.value; state.logSearchError = null; }
  if (consoleHealth.status === 'fulfilled') state.installationStatus = consoleHealth.value?.status || null;
  state.reachable = reached;
  if (reached) { state.loaded = true; state.lastUpdated = new Date(); }
  renderAll();
}

async function refreshLogs() {
  try {
    const events = await LookoutApi.events({ limit: 500, ...state.activityFilters });
    if (Array.isArray(events)) { state.events = events; state.logSearchError = null; }
  } catch {
    state.logSearchError = 'The deployment could not complete this log query.';
  } finally {
    if (state.view === 'logs') renderTableView();
  }
}

function wireControls() {
  window.addEventListener('popstate', () => navigateToView(requestedView()));
  document.querySelector('#accountAvatarImage').addEventListener('error', () => {
    if (!state.user?.avatarUrl) return;
    state.user = { ...state.user, avatarUrl: null };
    renderAccount();
  });
  document.querySelectorAll('[data-view]').forEach((element) => {
    element.addEventListener('click', (event) => {
      if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      goToView(element.dataset.view);
    });
  });
  document.addEventListener('pointerdown', (event) => {
    const panels = [
      ['#detailPanel', closeEntityDetail],
      ['#alertDetailPanel', closeAlertDetail],
      ['#logDetailPanel', closeLogDetail]
    ];
    for (const [selector, close] of panels) {
      const panel = document.querySelector(selector);
      if (!panel.hidden && !panel.contains(event.target) && !(selector === '#detailPanel' && event.target.closest('.node'))) close();
    }
  });
  document.querySelectorAll('[data-goto]').forEach((element) => {
    element.addEventListener('click', () => { if (element.dataset.goto) goToView(element.dataset.goto); });
  });
  document.querySelector('#bannerAction').addEventListener('click', (event) => {
    const target = event.currentTarget.dataset.goto;
    if (target === 'recovery' && state.recoverySetup) {
      sessionStorage.setItem(SETUP_SESSION_STORAGE, JSON.stringify(state.recoverySetup));
      window.location.assign('/setup');
      return;
    }
    if (target === 'alerts') {
      state.reviewAlertAfterNavigation = true;
      if (state.view === 'alerts') openHighestPriorityAlert();
      else goToView(target);
    } else if (target) goToView(target);
    else refresh();
  });
  document.querySelector('#tableTools').addEventListener('click', (event) => {
    const chip = event.target.closest('[data-chip]');
    if (!chip) return;
    if (state.view === 'assets') state.assetFilter = chip.dataset.chip;
    renderTableView();
  });
  document.querySelector('#tableTools').addEventListener('change', (event) => {
    const scope = event.target.closest('[data-filter-scope]')?.dataset.filterScope;
    const name = event.target.name;
    if (!scope || !name) return;
    if (scope === 'alerts' && name in state.alertFilters) state.alertFilters[name] = event.target.value;
    if (scope === 'logs' && name in state.activityFilters) {
      state.activityFilters[name] = event.target.value;
      refreshLogs();
      return;
    }
    renderTableView();
  });
  document.querySelector('#tableTools').addEventListener('input', (event) => {
    const scope = event.target.closest('[data-filter-scope]')?.dataset.filterScope;
    if (scope !== 'logs' || event.target.name !== 'keyword') return;
    state.activityFilters.keyword = event.target.value;
    const cursor = event.target.selectionStart;
    clearTimeout(logSearchTimer);
    logSearchTimer = setTimeout(async () => {
      await refreshLogs();
      const replacement = document.querySelector('#tableTools input[name="keyword"]');
      replacement.focus();
      replacement.setSelectionRange(cursor, cursor);
    }, 250);
  });
  document.querySelector('#copySetupButton').addEventListener('click', copySetupInstructions);
  document.querySelector('#resetSetupButton').addEventListener('click', resetFailedSetup);
  document.querySelector('#copySupportMcpSetupButton').addEventListener('click', copySupportMcpSetup);
  document.querySelector('#supportMcpSetupPreview').textContent = supportMcpSetup('<included in the copied setup>');
  document.querySelector('#copyUninstallInstructionsButton').addEventListener('click', () => copySetupValue(document.querySelector('#uninstallInstructions').textContent, document.querySelector('#copyUninstallInstructionsButton'), document.querySelector('#uninstallCopyStatus')));
  document.querySelector('#signOutButton').addEventListener('click', () => {
    clearSupportAccountToken();
    if (typeof LookoutAuth !== 'undefined') LookoutAuth.signOut();
  });
  document.querySelector('#deleteAccountDisclosure').addEventListener('click', () => {
    state.accountDangerOpen = !state.accountDangerOpen;
    renderSettingsSession();
  });
  document.querySelector('#deleteAccountButton').addEventListener('click', deleteAccount);
}

async function start() {
  wireControls();
  const initialView = requestedView();
  if (!/^\/deployments\/dpl_[A-Za-z0-9_-]{32}$/.test(window.location.pathname)) {
    window.history.replaceState({}, '', viewUrl(initialView));
  }
  if (initialView === 'setup') {
    await navigateToView(initialView);
  } else {
    try {
      if (!(await restoreHostedDashboard())) return;
      await refresh();
      setView(initialView);
    } catch {
      state.loaded = true;
      state.reachable = false;
      setView(initialView);
    }
  }
  setInterval(() => { if (state.view !== 'setup') refresh(); }, REFRESH_MS);
}

start();
