'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function graphLayout() {
  const source = `${fs.readFileSync(path.join(__dirname, '../public/graph-layout.js'), 'utf8')}\nglobalThis.__layout = GraphLayout;`;
  const context = {};
  vm.runInNewContext(source, context);
  return context.__layout;
}

test('network map includes topology and excludes inventory detail', () => {
  const { isTopologyEntity } = graphLayout();
  const capabilities = [{ entityKey: 'endpoint:vm', capability: 'sensor_health', status: 'available' }];
  const visible = [
    { key: 'network:tailnet', type: 'network', name: 'Tailnet' },
    { key: 'endpoint:vm', type: 'endpoint', name: 'VM' },
    { key: 'endpoint:workstation', type: 'endpoint', name: 'Workstation', platform: 'darwin' }
  ];
  const hidden = [
    { key: 'link-layer:42:01:0a:00:00:01', type: 'endpoint', name: 'ARP candidate' },
    { key: 'tailscale:unmanaged-linux', type: 'endpoint', name: 'Unmanaged VM', platform: 'linux' },
    { key: 'endpoint:vm:service:tcp:443', type: 'service', name: 'TCP 443', attributes: { serviceKind: 'network_listener', port: 443 } },
    { key: 'service:declared-app', type: 'service', name: 'Application' },
    { key: 'endpoint:vm:software:rpm:openssl', type: 'software', name: 'openssl' },
    { key: 'endpoint:vm:unit:sshd', type: 'service', name: 'sshd.service', attributes: { serviceKind: 'systemd' } },
    { key: 'endpoint:vm:unit:chronyd', type: 'service', name: 'chronyd.service' },
    { key: 'endpoint:vm:data:home', type: 'data_resource', name: '/home' },
    { key: 'endpoint:vm:identity:root', type: 'identity', name: 'root' },
    { key: 'service:lookout', type: 'service', name: 'Lookout', attributes: { product: 'lookout' } },
    { key: 'endpoint:removed', type: 'endpoint', name: 'Old', attributes: { present: false } }
  ];
  assert.equal(visible.every((entity) => isTopologyEntity(entity, capabilities)), true);
  assert.equal(hidden.some((entity) => isTopologyEntity(entity, capabilities)), false);
});

test('network map spaces four labels per row', () => {
  const { layout } = graphLayout();
  const entities = Array.from({ length: 8 }, (_, index) => ({ key: `endpoint:${index}`, type: 'endpoint', name: `Long endpoint label ${index}` }));
  const points = [...layout(entities, [], 1100, 680).values()];
  const rows = [points.slice(0, 4), points.slice(4, 8)];
  for (const row of rows) {
    const ordered = row.sort((left, right) => left.x - right.x);
    for (let index = 1; index < ordered.length; index += 1) assert.ok(ordered[index].x - ordered[index - 1].x >= 175);
  }
  assert.ok(Math.abs(rows[1][0].y - rows[0][0].y) >= 90);
});
