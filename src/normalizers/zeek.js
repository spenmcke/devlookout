'use strict';

const { createEvent } = require('../events/schema');
const { timestamp, addressEntity, endpoint, compact } = require('./helpers');

function recordId(logType, record) {
  return [logType, record.uid || 'no-uid', record.trans_id ?? '', record.query || '', record.ts ?? ''].join(':');
}

function zeekNormalizer({ instance = 'zeek' } = {}) {
  return {
    manifest: { id: 'zeek', version: '1.0.0', inputTypes: ['conn', 'dns', 'notice', 'ssl', 'ssh'], capabilities: ['network_flow', 'dns', 'tls', 'network_finding', 'service_auth'] },
    normalize(record, context = {}) {
      const logType = context.logType;
      const ingestedAt = context.receivedAt || new Date().toISOString();
      const time = timestamp(record.ts, ingestedAt);
      const source = { adapter: 'zeek', instance: context.instance || instance, recordId: recordId(logType, record) };
      const srcAddress = record['id.orig_h'];
      const dstAddress = record['id.resp_h'];
      const entityKeys = [addressEntity(srcAddress), addressEntity(dstAddress)].filter(Boolean);
      const common = { time, ingestedAt, source, entityKeys, sourceEndpoint: endpoint(srcAddress, record['id.orig_p']), destinationEndpoint: endpoint(dstAddress, record['id.resp_p']), correlation: compact({ flowId: record.uid }) };

      if (logType === 'conn') return [createEvent({ ...common, category: 'network', class: 'network_activity', activity: 'connection', outcome: ['SF', 'S1'].includes(record.conn_state) ? 'success' : 'unknown', service: compact({ name: record.service, protocol: record.proto }), attributes: compact({ durationSeconds: record.duration, bytesSent: record.orig_bytes, bytesReceived: record.resp_bytes, packetsSent: record.orig_pkts, packetsReceived: record.resp_pkts, connectionState: record.conn_state, missedBytes: record.missed_bytes, history: record.history }) })];
      if (logType === 'dns') return [createEvent({ ...common, category: 'network', class: 'dns_activity', activity: 'query', outcome: Number(record.rcode) === 0 || record.rcode_name === 'NOERROR' ? 'success' : 'failure', service: { name: 'dns', protocol: record.proto }, attributes: compact({ query: record.query, queryType: record.qtype_name || record.qtype, responseCode: record.rcode_name || record.rcode, answers: Array.isArray(record.answers) ? [...record.answers].sort() : [], rejected: record.rejected }) })];
      if (logType === 'notice') return [createEvent({ ...common, category: 'finding', class: 'network_finding', activity: String(record.note || 'notice'), outcome: 'unknown', severity: Number(record.priority) || 5, attributes: compact({ note: record.note, message: record.msg, sub: record.sub, suppressForSeconds: record.suppress_for, peerDescription: record.peer_descr }) })];
      if (logType === 'ssl') return [createEvent({ ...common, category: 'network', class: 'tls_activity', activity: 'handshake', outcome: record.established === false ? 'failure' : 'success', service: { name: 'tls', protocol: 'tcp' }, attributes: compact({ version: record.version, cipher: record.cipher, serverName: record.server_name, resumed: record.resumed, established: record.established, certificateChain: record.cert_chain_fuids, validationStatus: record.validation_status }) })];
      if (logType === 'ssh') return [createEvent({ ...common, category: 'identity', class: 'authentication', activity: 'remote_logon', outcome: record.auth_success === true ? 'success' : record.auth_success === false ? 'failure' : 'unknown', actor: record.remote_location ? { type: 'remote_location', location: record.remote_location } : null, service: { name: 'ssh', protocol: 'tcp' }, attributes: compact({ direction: record.direction, client: record.client, server: record.server, authAttempts: record.auth_attempts }) })];
      throw new Error(`Unsupported Zeek log type: ${logType}`);
    }
  };
}

module.exports = { zeekNormalizer };
