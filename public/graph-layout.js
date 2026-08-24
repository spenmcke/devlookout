'use strict';

/* Deterministic architecture layout. Entity types stay in stable horizontal
   layers while relationships pull connected nodes into readable clusters. */
const GraphLayout = (() => {
  const LANE_BY_TYPE = Object.freeze({
    identity: 0,
    credential: 0,
    exposure: 0,
    control: 1,
    network: 1,
    zone: 1,
    route: 1,
    endpoint: 2,
    telemetry: 2,
    cloud_resource: 2,
    service: 3,
    software: 3,
    data_resource: 3
  });

  function hash(text) {
    let value = 2166136261;
    for (let index = 0; index < text.length; index += 1) {
      value ^= text.charCodeAt(index);
      value = Math.imul(value, 16777619);
    }
    return (value >>> 0) / 4294967295;
  }

  function laneFor(entity) {
    return LANE_BY_TYPE[entity.type] ?? 2;
  }

  const USER_ENDPOINT_PLATFORMS = new Set(['android', 'chromeos', 'darwin', 'ios', 'macos', 'windows']);

  function isTopologyEntity(entity, capabilities = []) {
    if (!entity || entity.present === false || entity.attributes?.present === false) return false;
    if (entity.type === 'network') return true;
    if (entity.type !== 'endpoint' || String(entity.key || '').startsWith('link-layer:')) return false;
    const managed = entity.managed === true || capabilities.some((record) => record.entityKey === entity.key
      && record.capability === 'sensor_health'
      && ['available', 'degraded'].includes(record.status));
    if (managed) return true;
    const platform = String(entity.platform || entity.attributes?.platform || '').trim().toLowerCase();
    const role = String(entity.role || entity.attributes?.role || '').trim().toLowerCase();
    const tags = Array.isArray(entity.tags) ? entity.tags : (Array.isArray(entity.attributes?.tags) ? entity.attributes.tags : []);
    return USER_ENDPOINT_PLATFORMS.has(platform)
      || ['desktop', 'laptop', 'workstation', 'mobile'].includes(role)
      || tags.some((tag) => ['desktop', 'laptop', 'workstation', 'mobile'].includes(String(tag).toLowerCase()));
  }

  function distanceToSegment(point, start, end) {
    const dx = end.x - start.x;
    const dy = end.y - start.y;
    const squaredLength = dx * dx + dy * dy;
    if (!squaredLength) return { distance: Infinity, progress: 0 };
    const progress = Math.max(0, Math.min(1, ((point.x - start.x) * dx + (point.y - start.y) * dy) / squaredLength));
    const nearestX = start.x + progress * dx;
    const nearestY = start.y + progress * dy;
    return { distance: Math.hypot(point.x - nearestX, point.y - nearestY), progress };
  }

  function layout(entities, relationships, width, height, padding = 74) {
    const nodes = [...entities].sort((a, b) => a.key.localeCompare(b.key));
    if (!nodes.length) return new Map();
    const indexByKey = new Map(nodes.map((node, index) => [node.key, index]));
    const lanes = [0, 1, 2, 3].map((lane) => nodes.filter((node) => laneFor(node) === lane));
    const laneHeight = (height - padding * 2) / 3;
    const anchors = new Map();

    for (let lane = 0; lane < lanes.length; lane += 1) {
      const members = lanes[lane];
      const columns = Math.max(1, Math.min(4, members.length));
      const rows = Math.ceil(members.length / columns);
      members.forEach((node, index) => {
        const row = Math.floor(index / columns);
        const column = index % columns;
        const rowCount = Math.min(columns, members.length - row * columns);
        const x = padding + ((column + 1) / (rowCount + 1)) * (width - padding * 2);
        const rowOffset = (row - (rows - 1) / 2) * 100;
        const y = padding + lane * laneHeight + rowOffset;
        anchors.set(node.key, { x, y });
      });
    }

    const points = nodes.map((node) => {
      const anchor = anchors.get(node.key);
      return {
        x: anchor.x + (hash(`${node.key}:x`) - 0.5) * 24,
        y: anchor.y + (hash(`${node.key}:y`) - 0.5) * 16
      };
    });
    const links = relationships
      .map((edge) => [indexByKey.get(edge.fromKey), indexByKey.get(edge.toKey)])
      .filter(([from, to]) => from !== undefined && to !== undefined && from !== to);

    for (let iteration = 0; iteration < 180; iteration += 1) {
      const heat = Math.max(0.08, 1 - iteration / 180);
      for (let a = 0; a < points.length; a += 1) {
        for (let b = a + 1; b < points.length; b += 1) {
          const dx = points[a].x - points[b].x;
          const dy = points[a].y - points[b].y;
          const squared = dx * dx + dy * dy || 0.01;
          if (squared > 24000) continue;
          const distance = Math.sqrt(squared);
          const push = Math.min(10, 9000 / squared) * heat;
          points[a].x += (dx / distance) * push;
          points[a].y += (dy / distance) * push;
          points[b].x -= (dx / distance) * push;
          points[b].y -= (dy / distance) * push;
        }
      }
      for (const [from, to] of links) {
        const dx = points[to].x - points[from].x;
        const dy = points[to].y - points[from].y;
        const distance = Math.sqrt(dx * dx + dy * dy) || 0.01;
        const pull = ((distance - 155) / distance) * 0.018 * heat;
        points[from].x += dx * pull;
        points[from].y += dy * pull;
        points[to].x -= dx * pull;
        points[to].y -= dy * pull;
      }
      nodes.forEach((node, index) => {
        const anchor = anchors.get(node.key);
        points[index].x += (anchor.x - points[index].x) * 0.035 * heat;
        points[index].y += (anchor.y - points[index].y) * 0.075 * heat;
        points[index].x = Math.max(padding, Math.min(width - padding, points[index].x));
        points[index].y = Math.max(padding, Math.min(height - padding, points[index].y));
      });
    }

    for (let iteration = 0; iteration < 90; iteration += 1) {
      let moved = false;
      for (const [from, to] of links) {
        const start = points[from];
        const end = points[to];
        const dx = end.x - start.x;
        const dy = end.y - start.y;
        const length = Math.hypot(dx, dy) || 1;
        for (let nodeIndex = 0; nodeIndex < points.length; nodeIndex += 1) {
          if (nodeIndex === from || nodeIndex === to) continue;
          const hit = distanceToSegment(points[nodeIndex], start, end);
          if (hit.distance >= 62 || hit.progress <= 0.12 || hit.progress >= 0.88) continue;
          const direction = hit.distance < 0.5
            ? (hash(`${nodes[nodeIndex].key}:${nodes[from].key}:${nodes[to].key}`) < 0.5 ? -1 : 1)
            : Math.sign((points[nodeIndex].x - start.x) * -dy + (points[nodeIndex].y - start.y) * dx);
          const push = Math.min(8, (62 - hit.distance) * 0.18);
          points[nodeIndex].x += (-dy / length) * direction * push;
          points[nodeIndex].y += (dx / length) * direction * push * 0.35;
          points[nodeIndex].x = Math.max(padding, Math.min(width - padding, points[nodeIndex].x));
          points[nodeIndex].y = Math.max(padding, Math.min(height - padding, points[nodeIndex].y));
          moved = true;
        }
      }
      if (!moved) break;
    }

    return new Map(nodes.map((node, index) => [node.key, points[index]]));
  }

  return { layout, hash, laneFor, isTopologyEntity };
})();
