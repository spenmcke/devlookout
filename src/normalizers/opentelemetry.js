'use strict';

const { createEvent, EVENT_CATEGORIES, OUTCOMES } = require('../events/schema');
const { timestamp, addressEntity, digestText, compact } = require('./helpers');

function attributes(value) {
  if (!value) return {};
  if (!Array.isArray(value)) return { ...value };
  return Object.fromEntries(value.map((item) => [item.key, item.value?.stringValue ?? item.value?.intValue ?? item.value?.boolValue ?? item.value?.doubleValue ?? null]));
}

function otelTime(value, fallback) {
  if (typeof value === 'string' && /^\d+$/.test(value)) return new Date(Number(BigInt(value) / 1000000n)).toISOString();
  return timestamp(value, fallback);
}

function openTelemetryNormalizer({ instance = 'otel', retainBody = false } = {}) {
  return {
    manifest: { id: 'opentelemetry-log', version: '1.0.0', inputTypes: ['logical-log-record'], capabilities: ['application_log', 'service_auth', 'resource_access', 'configuration_change', 'data_movement'] },
    normalize(record, context = {}) {
      const receivedAt = context.receivedAt || new Date().toISOString();
      const attrs = attributes(record.Attributes || record.attributes);
      const resource = attributes(record.Resource || record.resource?.attributes || record.resource);
      const eventName = record.EventName || record.eventName || attrs['event.name'] || 'log';
      const category = EVENT_CATEGORIES.has(attrs['security.category']) ? attrs['security.category'] : 'application';
      const outcome = OUTCOMES.has(attrs['event.outcome']) ? attrs['event.outcome'] : 'unknown';
      const hostId = resource['host.id'] || resource['host.name'];
      const serviceId = resource['service.instance.id'] || resource['service.name'];
      const sourceAddress = attrs['client.address'] || attrs['source.address'];
      const sourceId = attrs['source.id'] || (sourceAddress ? addressEntity(sourceAddress) : null);
      const destinationId = attrs['destination.id'] || (hostId ? `endpoint:${hostId}` : null);
      const entityKeys = [sourceId, destinationId, serviceId ? `service:${serviceId}` : null].filter(Boolean);
      const body = record.Body ?? record.body;
      const safeAttributes = Object.fromEntries(Object.entries(attrs).filter(([key]) => !/(password|passphrase|secret|token|private[._-]?key|api[._-]?key)/i.test(key)).sort(([a], [b]) => a.localeCompare(b)));
      return [createEvent({
        time: otelTime(record.Timestamp || record.timeUnixNano || record.timestamp, otelTime(record.ObservedTimestamp || record.observedTimeUnixNano, receivedAt)),
        ingestedAt: receivedAt, category, class: attrs['security.class'] || eventName, activity: attrs['security.activity'] || eventName, outcome,
        severity: Math.max(0, Math.min(10, Math.ceil(Number(record.SeverityNumber || record.severityNumber || 0) / 2.4))),
        source: { adapter: 'opentelemetry-log', instance: context.instance || instance, recordId: context.recordId || `${record.TraceId || record.traceId || ''}:${record.SpanId || record.spanId || ''}:${record.Timestamp || record.timeUnixNano || digestText(body)}` },
        entityKeys,
        actor: attrs['enduser.id'] ? compact({ id: String(attrs['enduser.id']), type: 'user', targetId: attrs['security.actor.target_id'] }) : null,
        sourceEndpoint: sourceId ? compact({ id: String(sourceId), address: sourceAddress, port: attrs['client.port'] || attrs['source.port'] }) : null,
        destinationEndpoint: destinationId ? compact({ id: String(destinationId), address: attrs['server.address'] || resource['host.name'], port: attrs['server.port'] || attrs['destination.port'] }) : null,
        service: resource['service.name'] ? compact({ name: resource['service.name'], version: resource['service.version'], instanceId: resource['service.instance.id'] }) : null,
        correlation: compact({ traceId: record.TraceId || record.traceId, spanId: record.SpanId || record.spanId }),
        attributes: { ...safeAttributes, resource: Object.fromEntries(Object.entries(resource).sort(([a], [b]) => a.localeCompare(b))), bodyDigest: digestText(body), ...(retainBody ? { body } : {}) }
      })];
    }
  };
}

module.exports = { attributes, otelTime, openTelemetryNormalizer };
