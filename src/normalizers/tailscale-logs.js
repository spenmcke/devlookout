'use strict';

const { createEvent } = require('../events/schema');
const { timestamp, addressEntity, endpoint, compact } = require('./helpers');

function splitEndpoint(value) {
  if (!value) return { address: null, port: null };
  const bracketed = String(value).match(/^\[([^\]]+)](?::(\d+))?$/);
  if (bracketed) return { address: bracketed[1], port: bracketed[2] ? Number(bracketed[2]) : null };
  const text = String(value);
  const colon = text.lastIndexOf(':');
  if (colon > 0 && text.indexOf(':') === colon && /^\d+$/.test(text.slice(colon + 1))) return { address: text.slice(0, colon), port: Number(text.slice(colon + 1)) };
  return { address: text, port: null };
}

function tailscaleLogNormalizer({ tailnet, instance = tailnet } = {}) {
  return {
    manifest: { id: 'tailscale-logs', version: '1.0.0', inputTypes: ['network-flow', 'configuration-audit'], capabilities: ['network_flow', 'configuration_change', 'identity'] },
    normalize(record, context = {}) {
      const effectiveTailnet = context.tailnet || tailnet;
      if (!effectiveTailnet) throw new Error('Tailscale log normalization requires context.tailnet');
      const effectiveInstance = context.instance || instance || effectiveTailnet;
      const prefix = `tailscale:${effectiveTailnet}`;
      const receivedAt = context.receivedAt || new Date().toISOString();
      if (context.logType === 'configuration-audit') {
        const eventTime = timestamp(record.eventTime || record.time || record.timestamp || record.created, receivedAt);
        const actorId = record.actor?.id || record.actor?.loginName || record.actor || record.user || 'unknown';
        const action = record.action || record.type || record.eventType || 'change';
        const target = record.target?.id || record.target || record.resource || 'tailnet';
        const targetType = record.target?.type;
        const eventClass = ['route', 'subnet_route', 'exit_node'].includes(String(targetType || '').toLowerCase()) ? 'route_activity' : 'network_policy_activity';
        return [createEvent({ time: eventTime, ingestedAt: receivedAt, category: 'configuration', class: eventClass, activity: String(action), outcome: record.success === false ? 'failure' : 'success', source: { adapter: 'tailscale-logs', instance: effectiveInstance, recordId: String(record.id || `${eventTime}:${actorId}:${action}:${target}`) }, entityKeys: [`${prefix}:network`], actor: { id: String(actorId), type: 'tailscale_identity' }, attributes: compact({ target: String(target), targetType, origin: record.origin, sourceIp: record.sourceIp }) })];
      }
      if (context.logType !== 'network-flow') throw new Error(`Unsupported Tailscale log type: ${context.logType}`);
      const time = timestamp(record.end || record.logged || record.start, receivedAt);
      const sourceNodeId = record.nodeId || record.srcNode?.nodeId;
      const sourceKey = sourceNodeId ? `${prefix}:device:${sourceNodeId}` : null;
      const destinationByAddress = new Map();
      for (const node of record.dstNodes || []) for (const address of node.addresses || []) destinationByAddress.set(address, `${prefix}:device:${node.nodeId}`);
      const output = [];
      for (const trafficType of ['virtualTraffic', 'subnetTraffic', 'exitTraffic', 'physicalTraffic']) {
        for (const [index, flow] of (record[trafficType] || []).entries()) {
          const src = splitEndpoint(flow.src);
          const dst = splitEndpoint(flow.dst);
          const destinationKey = destinationByAddress.get(dst.address) || addressEntity(dst.address);
          const entityKeys = [sourceKey, destinationKey].filter(Boolean);
          output.push(createEvent({
            time, ingestedAt: receivedAt, category: 'network', class: 'network_activity', activity: 'connection_summary', outcome: 'unknown',
            source: { adapter: 'tailscale-logs', instance: effectiveInstance, recordId: `${record.nodeId}:${record.start}:${trafficType}:${index}:${flow.src || ''}:${flow.dst || ''}` },
            entityKeys, sourceEndpoint: sourceKey ? { ...endpoint(src.address, src.port), id: sourceKey } : endpoint(src.address, src.port), destinationEndpoint: destinationKey ? { ...endpoint(dst.address, dst.port), id: destinationKey } : endpoint(dst.address, dst.port),
            service: compact({ protocol: flow.proto, port: dst.port }), correlation: compact({ reporterNodeId: record.nodeId, windowStart: record.start, windowEnd: record.end }),
            attributes: compact({ trafficType, bytesSent: flow.txBytes, bytesReceived: flow.rxBytes, packetsSent: flow.txPackets ?? flow.txPkts, packetsReceived: flow.rxPackets ?? flow.rxPkts, reporterIdentityVerified: true, flowDetailsVerified: false, sourceNodeOs: record.srcNode?.os, sourceNodeUser: record.srcNode?.user, sourceNodeTags: record.srcNode?.tags })
          }));
        }
      }
      return output;
    }
  };
}

module.exports = { splitEndpoint, tailscaleLogNormalizer };
