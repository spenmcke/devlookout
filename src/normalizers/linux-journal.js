'use strict';

const { createEvent } = require('../events/schema');
const { addressEntity, compact, digestText } = require('./helpers');

const MAX_RECORD_BYTES = 65536;
const MAX_FIELDS = 256;
const AUDIT_NUMERIC_TYPES = Object.freeze({
  1100: 'USER_AUTH', 1101: 'USER_ACCT', 1102: 'USER_MGMT', 1112: 'USER_LOGIN',
  1114: 'ADD_USER', 1115: 'DEL_USER', 1116: 'ADD_GROUP', 1117: 'DEL_GROUP',
  1130: 'SERVICE_START', 1131: 'SERVICE_STOP', 1300: 'SYSCALL', 1309: 'EXECVE',
  1328: 'EOE', 1331: 'PROCTITLE'
});

function boundedString(value, maximum = 4096) {
  return typeof value === 'string' && Buffer.byteLength(value, 'utf8') <= maximum ? value : null;
}

function redactJournalMessage(value) {
  if (typeof value !== 'string') return null;
  return value.slice(0, 8192)
    .replace(/\b(password|passwd|passphrase|secret|api[_-]?key|access[_-]?key|auth[_-]?token|refresh[_-]?token|session[_-]?token)\s*[:=]\s*("[^"]*"|'[^']*'|\S+)/gi, '$1=[REDACTED]')
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, '$1 [REDACTED]')
    .replace(/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/gi, '$1[REDACTED]@');
}

function parseAuditFields(message) {
  if (typeof message !== 'string' || Buffer.byteLength(message, 'utf8') > MAX_RECORD_BYTES) return {};
  const fields = {};
  const matcher = /(?:^|\s)([A-Za-z0-9_]+)=("(?:[^"\\]|\\.)*"|'[^']*'|[^\s]*)/g;
  for (const match of message.matchAll(matcher)) {
    if (Object.keys(fields).length >= MAX_FIELDS) break;
    let value = match[2];
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    if (Buffer.byteLength(value, 'utf8') <= 4096) fields[match[1].toLowerCase()] = value;
  }
  return fields;
}

function auditIdentity(value) {
  if (!value || value === '?' || value === 'unset' || value === '4294967295') return null;
  return String(value);
}

function outcomeFrom(value) {
  const normalized = String(value || '').toLowerCase();
  if (['yes', 'success', 'successful', '1'].includes(normalized)) return 'success';
  if (['no', 'failed', 'failure', '0'].includes(normalized)) return 'failure';
  return 'unknown';
}

function journalTime(record, fallback) {
  const micros = Number(record.__REALTIME_TIMESTAMP);
  return Number.isFinite(micros) && micros > 0 ? new Date(Math.floor(micros / 1000)).toISOString() : fallback;
}

function auditMetadata(record, message) {
  const typeMatch = message.match(/^type=([A-Z0-9_]+)/);
  const idMatch = message.match(/msg=audit\((\d+(?:\.\d+)?):(\d+)\)/);
  const reportedType = boundedString(typeMatch?.[1] || record.AUDIT_TYPE || record._AUDIT_TYPE, 64);
  return {
    type: AUDIT_NUMERIC_TYPES[reportedType] || reportedType,
    auditId: idMatch ? `${idMatch[1]}:${idMatch[2]}` : null,
    serial: idMatch?.[2] || null
  };
}

function classifyAudit(type, fields) {
  const upper = String(type || '').toUpperCase();
  if (['USER_AUTH', 'USER_LOGIN', 'USER_ACCT'].includes(upper)) return { category: 'identity', class: 'authentication', activity: upper.toLowerCase(), severity: 5 };
  if (/^(ADD|DEL|CHG)_(USER|GROUP)$/.test(upper) || ['USER_MGMT', 'GRP_MGMT'].includes(upper)) {
    const activity = upper.startsWith('ADD_') ? 'create' : upper.startsWith('DEL_') ? 'delete' : 'update';
    return { category: 'identity', class: upper.endsWith('_GROUP') || upper === 'GRP_MGMT' ? 'group_management' : 'account_management', activity, severity: 7 };
  }
  if (['SERVICE_START', 'SERVICE_STOP'].includes(upper)) return { category: 'configuration', class: 'service_activity', activity: upper === 'SERVICE_START' ? 'start' : 'stop', severity: 5 };
  if (['CONFIG_CHANGE', 'DAEMON_CONFIG'].includes(upper)) return { category: 'configuration', class: 'configuration_change', activity: upper.toLowerCase(), severity: 6 };
  if (upper === 'EXECVE') {
    const executable = fields.a0 || fields.exe || '';
    const clearing = /(^|\/)(journalctl|truncate|shred)$/.test(executable) && Object.values(fields).some((value) => /--vacuum|\/var\/log/.test(value));
    return clearing
      ? { category: 'configuration', class: 'log_activity', activity: 'clear', severity: 9 }
      : { category: 'system', class: 'process_activity', activity: 'start', severity: 3 };
  }
  if (upper === 'SYSCALL' && ['59', '221', '322', 'execve', 'execveat'].includes(String(fields.syscall || '').toLowerCase())) return { category: 'system', class: 'process_activity', activity: 'start', severity: 3 };
  if (upper === 'SYSCALL' && ['105', '106', '113', '114', '117', 'setuid', 'setgid', 'setreuid', 'setregid'].includes(String(fields.syscall || '').toLowerCase())) return { category: 'identity', class: 'privilege_use', activity: 'change_process_identity', severity: 7 };
  return null;
}

function classifyJournal(record, message) {
  const identifier = String(record.SYSLOG_IDENTIFIER || record._COMM || '').toLowerCase();
  if (identifier === 'sshd') {
    const accepted = /Accepted (?:password|publickey|keyboard-interactive) for (?:invalid user )?(\S+) from ([0-9a-f:.]+)/i.exec(message);
    const failed = /Failed (?:password|publickey|keyboard-interactive) for (?:invalid user )?(\S+) from ([0-9a-f:.]+)/i.exec(message);
    const match = accepted || failed;
    if (match) return { category: 'identity', class: 'authentication', activity: 'remote_logon', outcome: accepted ? 'success' : 'failure', severity: accepted ? 5 : 7, actor: match[1], address: match[2] };
  }
  if (identifier === 'sudo') {
    const actor = /^\s*([^ :]+)\s*:/.exec(message)?.[1];
    const target = /(?:^|\s)USER=([^ ;]+)/.exec(message)?.[1];
    return { category: 'identity', class: 'privilege_use', activity: 'sudo', outcome: /authentication failure/i.test(message) ? 'failure' : 'unknown', severity: 7, actor, target };
  }
  if (['useradd', 'userdel', 'usermod', 'groupadd', 'groupdel', 'groupmod', 'gpasswd', 'passwd', 'chage'].includes(identifier)) {
    const activity = /add$/.test(identifier) ? 'create' : /del$/.test(identifier) ? 'delete' : 'update';
    return { category: 'identity', class: identifier.startsWith('group') || identifier === 'gpasswd' ? 'group_management' : 'account_management', activity, outcome: 'unknown', severity: 7 };
  }
  if (identifier === 'systemctl' || record._SYSTEMD_UNIT === 'systemd.service' || /^systemd(?:\[\d+\])?$/.test(identifier)) {
    const state = /\bStarted\b/.test(message) ? 'start' : /\bStopped\b/.test(message) ? 'stop' : /\bReloaded\b/.test(message) ? 'reload' : null;
    if (state) return { category: 'configuration', class: 'service_activity', activity: state, outcome: 'unknown', severity: 5 };
  }
  if ((identifier === 'journalctl' && /--vacuum/i.test(message)) || /(?:journal|audit) log.*(?:cleared|vacuumed|rotated|deleted)/i.test(message)) return { category: 'configuration', class: 'log_activity', activity: 'clear', outcome: 'unknown', severity: 9 };
  return null;
}

function linuxJournalNormalizer({ instance = 'linux-journal', entityKey = null } = {}) {
  const remoteSessions = new Map();
  const rememberRemoteSession = (sessionId, value) => {
    if (!sessionId) return;
    remoteSessions.delete(sessionId);
    remoteSessions.set(sessionId, value);
    while (remoteSessions.size > 2048) remoteSessions.delete(remoteSessions.keys().next().value);
  };
  return {
    manifest: { id: 'linux-journal', version: '1.0.0', inputTypes: ['journald-json'], capabilities: ['authentication', 'privilege_use', 'account_change', 'process_execution', 'service_state', 'configuration_change', 'log_clearing'] },
    normalize(record, context = {}) {
      if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('Linux journal record must be an object');
      const serialized = JSON.stringify(record);
      if (Buffer.byteLength(serialized, 'utf8') > MAX_RECORD_BYTES || Object.keys(record).length > MAX_FIELDS) throw new Error('Linux journal record exceeds parsing bounds');
      const message = boundedString(record.MESSAGE, MAX_RECORD_BYTES);
      if (message == null) return [];
      const receivedAt = context.receivedAt || new Date().toISOString();
      const audit = auditMetadata(record, message);
      const fields = audit.type ? parseAuditFields(message) : {};
      const classification = (audit.type ? classifyAudit(audit.type, fields) : classifyJournal(record, message)) || {
        category: 'system', class: 'journal_record', activity: 'write', outcome: 'unknown', severity: Math.max(0, Math.min(10, 7 - Number(record.PRIORITY ?? 6)))
      };
      const hostname = boundedString(record._HOSTNAME || record.HOSTNAME, 255);
      const actorId = auditIdentity(fields.acct || fields.auid || fields.uid) || classification.actor || null;
      const targetId = auditIdentity(fields.id || fields.euid) || classification.target || null;
      const remoteAddress = boundedString(fields.addr || classification.address, 128);
      const cursor = boundedString(record.__CURSOR, 4096);
      const recordId = cursor || audit.auditId || context.recordId || digestText(serialized);
      const executable = boundedString(fields.exe || fields.a0 || record._EXE, 4096);
      const processId = boundedString(fields.pid || record._PID, 32);
      const parentProcessId = boundedString(fields.ppid, 32);
      const sessionId = boundedString(fields.ses, 128);
      const eventOutcome = classification.outcome || outcomeFrom(fields.res || fields.success);
      const activity = classification.class === 'authentication' && remoteAddress && audit.type === 'USER_LOGIN' ? 'remote_logon' : classification.activity;
      if (classification.class === 'authentication' && remoteAddress && eventOutcome === 'success') rememberRemoteSession(sessionId, { remoteAddress, actorId });
      const remoteSession = classification.class === 'process_activity' && sessionId ? remoteSessions.get(sessionId) : null;
      const effectiveRemoteAddress = remoteAddress || remoteSession?.remoteAddress || null;
      const effectiveActorId = remoteSession?.actorId || actorId || null;
      const commandName = String(executable || '').split('/').at(-1).toLowerCase();
      const processType = ['sh', 'bash', 'dash', 'zsh', 'ksh', 'fish', 'csh', 'tcsh', 'powershell', 'pwsh', 'cmd.exe'].includes(commandName) ? 'command_interpreter' : null;
      const endpointKey = context.entityKey || context.endpointEntityKey || entityKey || (hostname ? `endpoint:${hostname.toLowerCase()}` : null);
      const entityKeys = [endpointKey, effectiveActorId ? `identity:${effectiveActorId}` : null, effectiveRemoteAddress ? addressEntity(effectiveRemoteAddress) : null].filter(Boolean);
      return [createEvent({
        time: journalTime(record, receivedAt), ingestedAt: receivedAt,
        category: classification.category, class: classification.class, activity,
        outcome: eventOutcome, severity: classification.severity,
        source: { adapter: 'linux-journal', instance: context.instance || instance, recordId }, entityKeys,
        actor: effectiveActorId ? compact({ id: effectiveActorId, targetId }) : null,
        sourceEndpoint: effectiveRemoteAddress ? { id: addressEntity(effectiveRemoteAddress), address: effectiveRemoteAddress, port: null } : null,
        destinationEndpoint: endpointKey ? compact({ id: endpointKey, address: hostname, port: null }) : null,
        correlation: compact({ auditId: audit.auditId, auditSerial: audit.serial, sessionId, processId, parentProcessId }),
        attributes: compact({ auditType: audit.type, systemdUnit: boundedString(record._SYSTEMD_UNIT, 255), identifier: boundedString(record.SYSLOG_IDENTIFIER || record._COMM, 255), priority: boundedString(String(record.PRIORITY ?? ''), 8), executable, syscall: boundedString(fields.syscall, 64), auditKey: boundedString(fields.key, 255), parentType: remoteSession ? 'remote_session' : null, processType, message: redactJournalMessage(message), messageDigest: digestText(message) })
      })];
    }
  };
}

module.exports = { MAX_RECORD_BYTES, AUDIT_NUMERIC_TYPES, parseAuditFields, auditMetadata, classifyAudit, classifyJournal, redactJournalMessage, linuxJournalNormalizer };
