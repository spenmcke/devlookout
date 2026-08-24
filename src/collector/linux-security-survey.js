'use strict';

const fs = require('node:fs');
const { execFileSync } = require('node:child_process');
const { createFact } = require('../adapters/contract');
const { createEvent } = require('../events/schema');
const { stableId } = require('../core/canonical');

const MAX_RECORDS = 256;
const MAX_PACKAGES = 1000;
const COMMANDS = Object.freeze({
  ss: ['/usr/bin/ss', '/bin/ss'],
  systemctl: ['/usr/bin/systemctl', '/bin/systemctl'],
  getent: ['/usr/bin/getent', '/bin/getent'],
  findmnt: ['/usr/bin/findmnt', '/bin/findmnt'],
  dpkg: ['/usr/bin/dpkg-query'],
  rpm: ['/usr/bin/rpm']
});

function clean(value, maximum = 512) {
  return String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, '').slice(0, maximum);
}

function boundedOutput(value, maximum) {
  return String(value ?? '').replace(/\u0000/g, '').slice(0, maximum);
}

function keyPart(value) {
  return encodeURIComponent(clean(value).toLowerCase());
}

function commandRunner({ fsImpl = fs, execFileSyncImpl = execFileSync, timeoutMs = 5000, maximumOutputBytes = 4 * 1024 * 1024 } = {}) {
  return (name, args = []) => {
    const binary = (COMMANDS[name] || []).find((candidate) => {
      try { return fsImpl.statSync(candidate).isFile(); } catch { return false; }
    });
    if (!binary) return { ok: false, reason: 'command_unavailable', stdout: '' };
    try {
      const stdout = execFileSyncImpl(binary, args, { encoding: 'utf8', timeout: timeoutMs, maxBuffer: maximumOutputBytes, stdio: ['ignore', 'pipe', 'pipe'] });
      return { ok: true, stdout: boundedOutput(stdout, maximumOutputBytes), reason: null };
    } catch (error) {
      return { ok: false, reason: clean(error.code || error.message, 256), stdout: boundedOutput(error.stdout, maximumOutputBytes) };
    }
  };
}

function splitHostPort(value) {
  const text = clean(value, 1024);
  const match = /^(.*):(\*|\d+)$/.exec(text);
  if (!match || match[2] === '*') return null;
  return { address: match[1].replace(/^\[|\]$/g, '') || '*', port: Number(match[2]) };
}

function addressScope(address) {
  if (['127.0.0.1', '::1'].includes(address)) return 'loopback';
  if (['0.0.0.0', '::', '*'].includes(address)) return 'all_interfaces';
  return 'host_interface';
}

function parseListeners(output) {
  const grouped = new Map();
  for (const line of String(output).split('\n').slice(0, MAX_RECORDS * 4)) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 5 || !['tcp', 'udp'].includes(fields[0])) continue;
    const local = splitHostPort(fields[4]);
    if (!local || !Number.isSafeInteger(local.port) || local.port < 1 || local.port > 65535) continue;
    const id = `${fields[0]}:${local.port}`;
    const record = grouped.get(id) || { protocol: fields[0], port: local.port, addresses: new Set(), processNames: new Set() };
    record.addresses.add(local.address);
    for (const match of line.matchAll(/users:\(\("([^"\r\n]{1,128})"/g)) record.processNames.add(clean(match[1], 128));
    grouped.set(id, record);
  }
  return [...grouped.values()].map((item) => ({
    protocol: item.protocol, port: item.port, addresses: [...item.addresses].sort(), processNames: [...item.processNames].sort(),
    exposureScope: item.addresses.has('0.0.0.0') || item.addresses.has('::') || item.addresses.has('*') ? 'all_interfaces' : item.addresses.size && [...item.addresses].every((address) => addressScope(address) === 'loopback') ? 'loopback' : 'host_interface'
  })).sort((a, b) => a.protocol.localeCompare(b.protocol) || a.port - b.port).slice(0, MAX_RECORDS);
}

function parseUnitTable(output) {
  const units = new Map();
  for (const line of String(output).split('\n').slice(0, MAX_RECORDS * 2)) {
    const fields = line.trim().split(/\s+/);
    if (!fields[0]?.endsWith('.service')) continue;
    const name = clean(fields[0], 256);
    const record = units.get(name) || { name, enabledState: 'unknown', activeState: 'unknown' };
    if (['enabled', 'enabled-runtime', 'disabled', 'static', 'masked', 'indirect', 'generated', 'transient'].includes(fields[1])) record.enabledState = fields[1];
    if (fields.includes('running')) record.activeState = 'running';
    else if (fields.includes('failed')) record.activeState = 'failed';
    units.set(name, record);
  }
  return [...units.values()].filter((unit) => unit.activeState === 'running' || unit.enabledState === 'enabled' || unit.enabledState === 'enabled-runtime' || unit.enabledState === 'masked').slice(0, MAX_RECORDS).sort((a, b) => a.name.localeCompare(b.name));
}

function parsePasswd(output) {
  return String(output).split('\n').slice(0, MAX_RECORDS).flatMap((line) => {
    const fields = line.split(':');
    const uid = Number(fields[2]); const gid = Number(fields[3]);
    if (fields.length < 7 || !Number.isSafeInteger(uid) || !Number.isSafeInteger(gid)) return [];
    const shell = clean(fields[6], 256);
    return [{ name: clean(fields[0], 128), uid, gid, home: clean(fields[5], 512), shell, system: uid < 1000 && uid !== 0, loginEnabled: !/(nologin|false)$/.test(shell) }];
  }).sort((a, b) => a.uid - b.uid || a.name.localeCompare(b.name));
}

function parseGroups(output) {
  const memberships = new Map();
  for (const line of String(output).split('\n').slice(0, MAX_RECORDS)) {
    const fields = line.split(':');
    if (fields.length < 4) continue;
    const group = clean(fields[0], 128);
    for (const user of fields[3].split(',').map((value) => clean(value, 128)).filter(Boolean)) {
      if (!memberships.has(user)) memberships.set(user, new Set());
      memberships.get(user).add(group);
    }
  }
  return memberships;
}

function parsePackages(output, manager) {
  return String(output).split('\n').slice(0, MAX_PACKAGES + 1).flatMap((line) => {
    const [name, version] = line.split('\t');
    return name && version ? [{ name: clean(name, 256), version: clean(version, 256), manager }] : [];
  }).slice(0, MAX_PACKAGES).sort((a, b) => a.name.localeCompare(b.name));
}

function parseMounts(output) {
  let document;
  try { document = JSON.parse(output); } catch { return []; }
  const records = [];
  const visit = (items) => {
    for (const item of items || []) {
      const target = clean(item.target, 512);
      if (target && item.fstype) records.push({ target, source: clean(item.source, 512), filesystem: clean(item.fstype, 128), readOnly: String(item.options || '').split(',').includes('ro') });
      visit(item.children);
    }
  };
  visit(document.filesystems);
  return records.slice(0, MAX_RECORDS).sort((a, b) => a.target.localeCompare(b.target));
}

function sensitivityForMount(target) {
  if (/^\/(home|srv|data|backup)(\/|$)/.test(target) || /^\/var\/(lib|backups)(\/|$)/.test(target)) return 'potentially_high';
  return 'normal';
}

function linuxSecuritySurvey({ collectorId, entityKey, runner = commandRunner(), fsImpl = fs, platform = process.platform, excludedListenerPorts = [], excludedUnits = ['lookout.service', 'lookout-collector.service'] } = {}) {
  if (!collectorId || !entityKey) throw new Error('Linux security survey requires collectorId and entityKey');
  if (!Array.isArray(excludedListenerPorts) || excludedListenerPorts.some((port) => !Number.isSafeInteger(port) || port < 1 || port > 65535)) throw new Error('Linux security survey excluded listener ports are invalid');
  if (!Array.isArray(excludedUnits) || excludedUnits.some((unit) => typeof unit !== 'string' || !unit.endsWith('.service'))) throw new Error('Linux security survey excluded units are invalid');
  const excludedPortSet = new Set(excludedListenerPorts);
  const excludedUnitSet = new Set(excludedUnits);
  return {
    manifest: { id: 'linux-security-survey', version: '1.0.0', intervalSeconds: 300 },
    collect({ collectedAt, state: priorState = null }) {
      if (platform !== 'linux') return { facts: [], events: [] };
      if (priorState?.collectedAt && Date.parse(collectedAt) >= Date.parse(priorState.collectedAt) && Date.parse(collectedAt) - Date.parse(priorState.collectedAt) < 300000) return { facts: [], events: [], state: priorState };
      const facts = [];
      const events = [];
      const credentialKeys = [];
      const source = (recordId) => ({ adapter: 'linux-security-survey', instance: collectorId, recordId });
      const entity = (key, type, name, attributes, recordId = key) => facts.push(createFact({ kind: 'entity', observedAt: collectedAt, source: source(`entity:${recordId}`), data: { entityKey: key, entityType: type, name, attributes: { present: true, removedAt: null, ...attributes } } }));
      const relation = (from, to, name, recordId = `${from}:${name}:${to}`) => facts.push(createFact({ kind: 'relationship', observedAt: collectedAt, source: source(`relationship:${recordId}`), data: { from, to, relation: name } }));
      const capability = (name, status, attributes = {}) => facts.push(createFact({ kind: 'capability', observedAt: collectedAt, source: source(`capability:${name}`), data: { entityKey, capability: name, status, freshnessSeconds: 600, ...attributes } }));

      const listenerResult = runner('ss', ['-H', '-lntup']);
      const listeners = listenerResult.ok ? parseListeners(listenerResult.stdout).filter((listener) => !excludedPortSet.has(listener.port)) : [];
      for (const listener of listeners) {
        const serviceKey = `${entityKey}:service:${listener.protocol}:${listener.port}`;
        entity(serviceKey, 'service', `${listener.protocol.toUpperCase()} ${listener.port}`, { serviceKind: 'network_listener', ...listener });
        relation(entityKey, serviceKey, 'runs');
        if (listener.exposureScope !== 'loopback') {
          const exposureKey = `${serviceKey}:exposure`;
          entity(exposureKey, 'exposure', `${listener.protocol.toUpperCase()} ${listener.port} listener exposure`, { scope: listener.exposureScope, externallyReachable: 'unknown', addresses: listener.addresses });
          relation(serviceKey, exposureKey, 'exposed_through');
        }
      }
      capability('network_listener', listenerResult.ok ? (listenerResult.stdout.split('\n').length > MAX_RECORDS * 4 ? 'degraded' : 'available') : 'unavailable');
      capability('exposure', listenerResult.ok ? 'degraded' : 'unavailable');

      const unitFiles = runner('systemctl', ['list-unit-files', '--type=service', '--no-legend', '--no-pager']);
      const runningUnits = runner('systemctl', ['list-units', '--type=service', '--all', '--no-legend', '--no-pager']);
      const units = parseUnitTable(`${unitFiles.stdout}\n${runningUnits.stdout}`).filter((unit) => !excludedUnitSet.has(unit.name));
      for (const unit of units) {
        const serviceKey = `${entityKey}:unit:${keyPart(unit.name)}`;
        entity(serviceKey, 'service', unit.name, { serviceKind: 'systemd', manager: 'systemd', activeState: unit.activeState, enabledState: unit.enabledState });
        relation(entityKey, serviceKey, 'runs');
      }
      capability('service_inventory', unitFiles.ok || runningUnits.ok ? (unitFiles.ok && runningUnits.ok ? 'available' : 'degraded') : 'unavailable');
      capability('service_state', runningUnits.ok ? 'available' : 'degraded');

      const passwd = runner('getent', ['passwd']);
      const group = runner('getent', ['group']);
      const users = passwd.ok ? parsePasswd(passwd.stdout) : [];
      const groups = group.ok ? parseGroups(group.stdout) : new Map();
      const privilegedGroups = new Set(['sudo', 'wheel', 'admin']);
      for (const user of users) {
        const identityKey = `${entityKey}:identity:uid:${user.uid}`;
        const memberships = [...(groups.get(user.name) || [])].sort();
        const privileged = user.uid === 0 || memberships.some((name) => privilegedGroups.has(name));
        entity(identityKey, 'identity', user.name, { identityKind: 'local_account', uid: user.uid, gid: user.gid, system: user.system, loginEnabled: user.loginEnabled, shell: user.shell, groups: memberships, privileged });
        relation(identityKey, entityKey, privileged ? 'administers' : 'account_on');
        const authorizedKeysPath = `${user.home.replace(/\/$/, '')}/.ssh/authorized_keys`;
        try {
          const metadata = fsImpl.lstatSync(authorizedKeysPath);
          if (metadata.isFile() && !metadata.isSymbolicLink()) {
            const credentialKey = `${identityKey}:credential:authorized-keys`;
            credentialKeys.push({ key: credentialKey, identityName: user.name, ownerUid: user.uid, privilegedOwner: privileged, credentialKind: 'ssh_authorized_keys', sizeBytes: metadata.size, modifiedAt: metadata.mtime.toISOString(), mode: metadata.mode & 0o777 });
            entity(credentialKey, 'credential', `${user.name} authorized SSH keys`, { credentialKind: 'ssh_authorized_keys', storage: 'filesystem', ownerUid: metadata.uid, mode: metadata.mode & 0o777, sizeBytes: metadata.size, modifiedAt: metadata.mtime.toISOString() });
            relation(identityKey, credentialKey, 'uses');
            relation(credentialKey, entityKey, 'authenticates_to');
          }
        } catch { /* Absence and inaccessible homes are represented by capability state below. */ }
      }
      capability('identity', passwd.ok ? 'available' : 'unavailable');
      const identityTruncated = passwd.stdout.split('\n').length > MAX_RECORDS || group.stdout.split('\n').length > MAX_RECORDS;
      capability('identity_inventory', passwd.ok ? (group.ok && !identityTruncated ? 'available' : 'degraded') : 'unavailable');
      capability('privilege_inventory', passwd.ok && group.ok ? 'degraded' : 'unavailable');
      capability('credential_inventory', users.length ? 'degraded' : 'unknown');

      const dpkg = runner('dpkg', ['-W', '-f=${binary:Package}\t${Version}\n']);
      const rpm = dpkg.ok ? { ok: false, stdout: '' } : runner('rpm', ['-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\n']);
      const packages = dpkg.ok ? parsePackages(dpkg.stdout, 'dpkg') : rpm.ok ? parsePackages(rpm.stdout, 'rpm') : [];
      for (const item of packages) {
        const softwareKey = `${entityKey}:software:${item.manager}:${keyPart(item.name)}`;
        entity(softwareKey, 'software', item.name, { packageManager: item.manager, version: item.version });
        relation(entityKey, softwareKey, 'has_software');
      }
      const packageProbe = dpkg.ok || rpm.ok;
      capability('software_inventory', packageProbe ? ((dpkg.stdout || rpm.stdout).split('\n').length > MAX_PACKAGES ? 'degraded' : 'available') : 'unavailable');

      const mountsResult = runner('findmnt', ['--json', '--output', 'TARGET,SOURCE,FSTYPE,OPTIONS']);
      const mounts = mountsResult.ok ? parseMounts(mountsResult.stdout) : [];
      const dataResources = mounts.map((mount) => ({ ...mount, resourceKind: 'mounted_filesystem', sensitivity: sensitivityForMount(mount.target) }));
      for (const target of ['/home', '/srv', '/data', '/var/lib/postgresql', '/var/lib/mysql', '/var/lib/docker/volumes', '/var/backups']) {
        if (dataResources.some((item) => item.target === target)) continue;
        try {
          const metadata = fsImpl.lstatSync(target);
          if (metadata.isDirectory() && !metadata.isSymbolicLink()) dataResources.push({ target, source: 'local-directory', filesystem: null, readOnly: false, resourceKind: 'directory', sensitivity: 'potentially_high' });
        } catch { /* Missing and inaccessible conventional resources remain coverage gaps. */ }
      }
      for (const resource of dataResources.sort((a, b) => a.target.localeCompare(b.target))) {
        const resourceKey = `${entityKey}:data:${keyPart(resource.target)}`;
        entity(resourceKey, 'data_resource', resource.target, { resourceKind: resource.resourceKind, filesystem: resource.filesystem, sourceIdentifier: resource.source, readOnly: resource.readOnly, sensitivity: resource.sensitivity });
        relation(entityKey, resourceKey, 'stores');
      }
      capability('data_resource_inventory', mountsResult.ok ? 'degraded' : 'unavailable');
      capability('resource_access', 'unknown');
      capability('file_access', 'unknown');
      capability('data_movement', 'unknown');

      const controls = [
        ['auditd.service', 'Audit logging'], ['apparmor.service', 'AppArmor'], ['firewalld.service', 'firewalld'],
        ['ufw.service', 'Uncomplicated Firewall'], ['nftables.service', 'nftables'], ['fail2ban.service', 'Fail2ban']
      ];
      const byName = new Map(units.map((unit) => [unit.name, unit]));
      for (const [unitName, displayName] of controls) {
        const unit = byName.get(unitName);
        if (!unit) continue;
        const controlKey = `${entityKey}:control:${keyPart(unitName)}`;
        entity(controlKey, 'control', displayName, { controlKind: unitName, activeState: unit.activeState, enabledState: unit.enabledState });
        relation(controlKey, entityKey, 'protects');
      }
      capability('control_state', unitFiles.ok || runningUnits.ok ? 'degraded' : 'unavailable');
      capability('network_policy', 'unknown');
      capability('cloud_inventory', 'unknown');
      capability('criticality', dataResources.some((resource) => resource.sensitivity === 'potentially_high') ? 'degraded' : 'unknown');
      capability('inventory', 'available');
      const inventoryEntities = facts.filter((fact) => fact.kind === 'entity').map((fact) => ({ key: fact.data.entityKey, type: fact.data.entityType, name: fact.data.name })).sort((a, b) => a.key.localeCompare(b.key));
      const currentState = {
        schemaVersion: 1,
        collectedAt,
        listeners: listeners.map(({ protocol, port, exposureScope }) => ({ protocol, port, exposureScope })),
        accounts: users.map((user) => ({ uid: user.uid, name: user.name, loginEnabled: user.loginEnabled })),
        privilegedIdentities: users.filter((user) => user.uid === 0 || [...(groups.get(user.name) || [])].some((name) => privilegedGroups.has(name))).map((user) => ({ uid: user.uid, name: user.name })),
        credentials: credentialKeys.sort((a, b) => a.key.localeCompare(b.key)),
        services: units.map(({ name, activeState, enabledState }) => ({ name, activeState, enabledState })),
        controls: controls.flatMap(([unitName]) => byName.has(unitName) ? [{ unitName, activeState: byName.get(unitName).activeState, enabledState: byName.get(unitName).enabledState }] : []),
        sensitiveResources: dataResources.filter((resource) => resource.sensitivity === 'potentially_high').map((resource) => resource.target).sort(),
        inventoryEntities
      };
      const changeEvent = ({ component, category, eventClass, activity, severity, attributes }) => {
        const transition = stableId('survey-change', { component, previous: priorState?.[component] || [], current: currentState[component] || [], attributes });
        events.push(createEvent({
          time: collectedAt, ingestedAt: collectedAt, category, class: eventClass, activity, outcome: 'success', severity,
          source: { adapter: 'linux-security-survey', instance: collectorId, recordId: transition }, entityKeys: [entityKey],
          destinationEndpoint: { id: entityKey }, attributes: { surveyComponent: component, ...attributes }
        }));
      };
      if (priorState?.schemaVersion === 1) {
        const currentEntityKeys = new Set(inventoryEntities.map((item) => item.key));
        for (const previous of priorState.inventoryEntities || []) {
          if (currentEntityKeys.has(previous.key)) continue;
          facts.push(createFact({
            kind: 'entity', observedAt: collectedAt, source: source(`entity:${previous.key}`),
            data: { entityKey: previous.key, entityType: previous.type, name: previous.name, attributes: { present: false, removedAt: collectedAt } }
          }));
        }
        const previousListeners = new Set((priorState.listeners || []).map((item) => `${item.protocol}:${item.port}:${item.exposureScope}`));
        for (const listener of currentState.listeners) {
          if (previousListeners.has(`${listener.protocol}:${listener.port}:${listener.exposureScope}`)) continue;
          changeEvent({ component: 'listeners', category: 'configuration', eventClass: 'exposure_activity', activity: 'listener_create', severity: listener.exposureScope === 'all_interfaces' ? 8 : 5, attributes: listener });
        }
        if (Array.isArray(priorState.accounts)) {
          const previousAccounts = new Set(priorState.accounts.map((item) => `${item.uid}:${item.name}`));
          for (const account of currentState.accounts) if (!previousAccounts.has(`${account.uid}:${account.name}`)) changeEvent({ component: 'accounts', category: 'identity', eventClass: 'account_management', activity: 'create', severity: account.loginEnabled ? 8 : 5, attributes: { identityName: account.name, uid: account.uid, loginEnabled: account.loginEnabled } });
        }
        const previousPrivileged = new Set((priorState.privilegedIdentities || []).map((item) => `${item.uid}:${item.name}`));
        for (const identity of currentState.privilegedIdentities) if (!previousPrivileged.has(`${identity.uid}:${identity.name}`)) changeEvent({ component: 'privilegedIdentities', category: 'identity', eventClass: 'group_management', activity: 'grant_privilege', severity: 8, attributes: { identityName: identity.name, uid: identity.uid } });
        const previousCredentials = new Map((priorState.credentials || []).map((item) => [typeof item === 'string' ? item : item.key, item]));
        for (const credential of currentState.credentials) {
          const before = previousCredentials.get(credential.key);
          const credentialAttributes = { credentialReference: credential.key, credentialKind: credential.credentialKind, identityName: credential.identityName, ownerUid: credential.ownerUid, privilegedOwner: credential.privilegedOwner === true };
          if (!before) changeEvent({ component: 'credentials', category: 'identity', eventClass: 'credential_management', activity: 'add_credential', severity: credential.privilegedOwner ? 8 : 5, attributes: credentialAttributes });
          else if (JSON.stringify(before) !== JSON.stringify(credential)) changeEvent({ component: 'credentials', category: 'identity', eventClass: 'credential_management', activity: 'update_credential', severity: credential.privilegedOwner ? 8 : 5, attributes: credentialAttributes });
        }
        const currentCredentialKeys = new Set(currentState.credentials.map((item) => item.key));
        for (const credentialKey of previousCredentials.keys()) if (!currentCredentialKeys.has(credentialKey)) changeEvent({ component: 'credentials', category: 'identity', eventClass: 'credential_management', activity: 'delete_credential', severity: 5, attributes: { credentialReference: credentialKey } });
        if (Array.isArray(priorState.services)) {
          const previousServices = new Map(priorState.services.map((item) => [item.name, item]));
          for (const service of currentState.services) {
            const before = previousServices.get(service.name);
            if (!before) changeEvent({ component: 'services', category: 'configuration', eventClass: 'service_activity', activity: 'create', severity: 5, attributes: { serviceName: service.name, activeState: service.activeState, enabledState: service.enabledState } });
            else if (!['enabled', 'enabled-runtime'].includes(before.enabledState) && ['enabled', 'enabled-runtime'].includes(service.enabledState)) changeEvent({ component: 'services', category: 'configuration', eventClass: 'service_activity', activity: 'enable', severity: 5, attributes: { serviceName: service.name, activeState: service.activeState, enabledState: service.enabledState } });
          }
        }
        const previousControls = new Map((priorState.controls || []).map((item) => [item.unitName, item]));
        for (const control of currentState.controls) {
          const before = previousControls.get(control.unitName);
          if (before?.activeState === 'running' && control.activeState !== 'running') changeEvent({ component: 'controls', category: 'configuration', eventClass: 'security_control_activity', activity: 'disable', severity: 8, attributes: { controlName: control.unitName } });
        }
        const currentControlNames = new Set(currentState.controls.map((item) => item.unitName));
        for (const before of previousControls.values()) if (before.activeState === 'running' && !currentControlNames.has(before.unitName)) changeEvent({ component: 'controls', category: 'configuration', eventClass: 'security_control_activity', activity: 'disable', severity: 8, attributes: { controlName: before.unitName } });
        const previousResources = new Set(priorState.sensitiveResources || []);
        for (const resourceIdentifier of currentState.sensitiveResources) if (!previousResources.has(resourceIdentifier)) changeEvent({ component: 'sensitiveResources', category: 'data', eventClass: 'resource_activity', activity: 'create', severity: 5, attributes: { resourceIdentifier } });
      }
      return { facts, events, state: currentState };
    }
  };
}

module.exports = { MAX_RECORDS, MAX_PACKAGES, commandRunner, parseListeners, parseUnitTable, parsePasswd, parseGroups, parsePackages, parseMounts, linuxSecuritySurvey };
