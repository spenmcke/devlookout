'use strict';

const { createEvent } = require('../events/schema');
const { addressEntity, compact, digestText, timestamp } = require('./helpers');

function parseStructuredData(input, start) {
  if (input[start] === '-') return { value: {}, end: start + 1 };
  const groups = {};
  let index = start;
  while (input[index] === '[') {
    index += 1;
    let content = '';
    let escaped = false;
    while (index < input.length) {
      const char = input[index++];
      if (escaped) { content += char; escaped = false; continue; }
      if (char === '\\') { escaped = true; continue; }
      if (char === ']') break;
      content += char;
    }
    const firstSpace = content.indexOf(' ');
    const id = firstSpace < 0 ? content : content.slice(0, firstSpace);
    const parameters = {};
    const rest = firstSpace < 0 ? '' : content.slice(firstSpace + 1);
    for (const match of rest.matchAll(/([\w@.-]+)="((?:[^"\\]|\\.)*)"/g)) parameters[match[1]] = match[2].replace(/\\(["\\\]])/g, '$1');
    groups[id] = parameters;
  }
  return { value: groups, end: index };
}

function parseRFC5424(line) {
  if (typeof line !== 'string' || line.length > 65536) throw new Error('Syslog record must be a string of at most 65536 characters');
  const match = line.match(/^<(\d{1,3})>(\d{1,3}) (\S+) (\S+) (\S+) (\S+) (\S+) /);
  if (!match) throw new Error('Invalid RFC 5424 syslog header');
  const priority = Number(match[1]);
  if (priority > 191) throw new Error('Invalid syslog priority');
  const structured = parseStructuredData(line, match[0].length);
  const message = line.slice(structured.end).replace(/^ /, '');
  return { priority, facility: Math.floor(priority / 8), severity: priority % 8, version: Number(match[2]), time: match[3], hostname: match[4], appName: match[5], processId: match[6], messageId: match[7], structuredData: structured.value, message };
}

function syslogNormalizer({ instance = 'syslog', retainMessage = false } = {}) {
  return {
    manifest: { id: 'syslog-rfc5424', version: '1.0.0', inputTypes: ['rfc5424'], capabilities: ['application_log', 'authentication', 'service_state', 'configuration_change'] },
    normalize(record, context = {}) {
      const parsed = parseRFC5424(typeof record === 'string' ? record : record.message);
      const ingestedAt = context.receivedAt || new Date().toISOString();
      const hostKey = parsed.hostname === '-' ? null : addressEntity(parsed.hostname);
      const authFacility = parsed.facility === 4 || parsed.facility === 10;
      return [createEvent({
        time: timestamp(parsed.time, ingestedAt), ingestedAt,
        category: authFacility ? 'identity' : 'application',
        class: authFacility ? 'authentication_log' : 'application_log',
        activity: parsed.messageId === '-' ? 'log' : parsed.messageId,
        outcome: 'unknown', severity: Math.max(0, Math.min(10, 8 - parsed.severity)),
        source: { adapter: 'syslog-rfc5424', instance: context.instance || instance, recordId: context.recordId || `${parsed.hostname}:${parsed.appName}:${parsed.processId}:${parsed.time}:${digestText(parsed.message).slice(0, 16)}` },
        entityKeys: hostKey ? [hostKey] : [],
        service: parsed.appName === '-' ? null : { name: parsed.appName },
        attributes: compact({ facility: parsed.facility, syslogSeverity: parsed.severity, version: parsed.version, processId: parsed.processId === '-' ? null : parsed.processId, messageId: parsed.messageId === '-' ? null : parsed.messageId, structuredData: parsed.structuredData, messageDigest: digestText(parsed.message), message: retainMessage ? parsed.message : null })
      })];
    }
  };
}

module.exports = { parseStructuredData, parseRFC5424, syslogNormalizer };
