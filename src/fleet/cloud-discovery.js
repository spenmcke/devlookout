'use strict';

const os = require('node:os');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');

function commandJson(command, args, { timeoutMs = 15000 } = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8', timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024,
    env: { ...process.env, AWS_PAGER: '', AZURE_CORE_ONLY_SHOW_ERRORS: '1', CLOUDSDK_CORE_DISABLE_PROMPTS: '1' }
  });
  if (result.error || result.status !== 0) return null;
  try { return JSON.parse(result.stdout); } catch { return null; }
}

function commandJsonAsync(command, args, { timeoutMs = 5000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      stdio: ['ignore', 'pipe', 'ignore'],
      env: { ...process.env, AWS_PAGER: '', AZURE_CORE_ONLY_SHOW_ERRORS: '1', CLOUDSDK_CORE_DISABLE_PROMPTS: '1' }
    });
    const chunks = [];
    let size = 0;
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.stdout.on('data', (chunk) => {
      size += chunk.length;
      if (size <= 16 * 1024 * 1024) chunks.push(chunk);
      else child.kill('SIGKILL');
    });
    child.once('error', () => { clearTimeout(timer); resolve(null); });
    child.once('close', (code) => {
      clearTimeout(timer);
      if (code !== 0 || size > 16 * 1024 * 1024) return resolve(null);
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { resolve(null); }
    });
  });
}

function commandTextAsync(command, args, { timeoutMs = 5000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      stdio: ['ignore', 'pipe', 'ignore'],
      env: { ...process.env, AWS_PAGER: '', AZURE_CORE_ONLY_SHOW_ERRORS: '1', CLOUDSDK_CORE_DISABLE_PROMPTS: '1' }
    });
    const chunks = [];
    let size = 0;
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.stdout.on('data', (chunk) => {
      size += chunk.length;
      if (size <= 1024 * 1024) chunks.push(chunk);
      else child.kill('SIGKILL');
    });
    child.once('error', () => { clearTimeout(timer); resolve(null); });
    child.once('close', (code) => {
      clearTimeout(timer);
      resolve(code === 0 && size <= 1024 * 1024 ? Buffer.concat(chunks).toString('utf8') : null);
    });
  });
}

function clean(value) { return typeof value === 'string' && value.trim() ? value.trim() : null; }
function linux(platform) { return /linux|ubuntu|debian|centos|rhel|rocky|alma|amzn/i.test(String(platform || 'linux')) ? 'linux' : String(platform || 'unknown').toLowerCase(); }
function nameTag(tags) { return (tags || []).find((tag) => tag?.Key === 'Name')?.Value || null; }

function discoverAws(run = commandJson, { profile = null } = {}) {
  const document = run('aws', ['ec2', 'describe-instances', '--filters', 'Name=instance-state-name,Values=running', '--output', 'json']);
  const nodes = [];
  for (const instance of (document?.Reservations || []).flatMap((item) => item.Instances || [])) {
    if (!clean(instance.InstanceId)) continue;
    nodes.push({
      id: `aws:${instance.InstanceId}`, provider: 'aws', instanceId: instance.InstanceId,
      hostname: clean(nameTag(instance.Tags)) || clean(instance.PrivateDnsName), address: clean(instance.PrivateIpAddress),
      publicAddress: clean(instance.PublicIpAddress), region: clean(instance.Placement?.AvailabilityZone)?.replace(/[a-z]$/, '') || null,
      zone: clean(instance.Placement?.AvailabilityZone), platform: linux(instance.PlatformDetails), online: true,
      local: false, transport: 'aws', sshUser: null, ...(profile ? { awsProfile: profile } : {})
    });
  }
  return nodes;
}

function discoverGcp(run = commandJson) {
  const records = run('gcloud', ['compute', 'instances', 'list', '--filter=status=RUNNING', '--format=json']) || [];
  return records.filter((item) => clean(String(item.id || ''))).map((item) => ({
    id: `gcp:${item.id}`, provider: 'gcp', instanceId: String(item.id), hostname: clean(item.name),
    address: clean(item.networkInterfaces?.[0]?.networkIP), publicAddress: clean(item.networkInterfaces?.[0]?.accessConfigs?.[0]?.natIP),
    region: clean(item.zone)?.split('/').pop()?.replace(/-[a-z]$/, '') || null, zone: clean(item.zone)?.split('/').pop() || null,
    project: clean(item.selfLink)?.split('/projects/')[1]?.split('/')[0] || null,
    platform: 'linux', online: true, local: false, transport: 'gcp', sshUser: null
  }));
}

function discoverAzure(run = commandJson) {
  const records = run('az', ['vm', 'list', '-d', '--show-details', '--query', "[?powerState=='VM running']", '-o', 'json']) || [];
  return records.filter((item) => clean(item.id)).map((item) => ({
    id: `azure:${item.vmId || crypto.createHash('sha256').update(item.id).digest('hex').slice(0, 32)}`, provider: 'azure', instanceId: item.vmId || item.id,
    resourceId: item.id, resourceGroup: clean(item.resourceGroup), hostname: clean(item.name),
    address: clean(item.privateIps)?.split(',')[0].trim() || null, publicAddress: clean(item.publicIps)?.split(',')[0].trim() || null,
    region: clean(item.location), zone: clean(item.zones?.[0]), platform: linux(item.storageProfile?.osDisk?.osType),
    online: true, local: false, transport: 'azure', sshUser: null
  }));
}

function discoverDigitalOcean(run = commandJson) {
  const records = run('doctl', ['compute', 'droplet', 'list', '--output', 'json']) || [];
  return records.filter((item) => item?.status === 'active' && item.id !== undefined).map((item) => {
    const v4 = item.networks?.v4 || [];
    return {
      id: `digitalocean:${item.id}`, provider: 'digitalocean', instanceId: String(item.id), hostname: clean(item.name),
      address: clean(v4.find((address) => address.type === 'private')?.ip_address),
      publicAddress: clean(v4.find((address) => address.type === 'public')?.ip_address),
      region: clean(item.region?.slug), zone: null, platform: 'linux', online: true,
      local: false, transport: 'openssh', sshUser: null
    };
  });
}

function localNode() {
  const machine = process.env.LOOKOUT_LOCAL_INSTANCE_ID || (() => {
    try { return require('node:fs').readFileSync('/etc/machine-id', 'utf8').trim(); } catch { return os.hostname(); }
  })();
  const addresses = Object.values(os.networkInterfaces()).flat().filter((item) => item?.family === 'IPv4' && !item.internal).map((item) => item.address);
  return {
    id: `local:${crypto.createHash('sha256').update(machine).digest('hex').slice(0, 24)}`,
    provider: 'local', instanceId: machine, hostname: os.hostname(), address: addresses.sort()[0] || null,
    platform: process.platform === 'linux' ? 'linux' : process.platform, online: true, local: true, transport: 'local'
  };
}

function mergeLocalIdentity(nodes, local = localNode(), { markLocal = true, includeUnmanagedLocal = true } = {}) {
  if (!markLocal) return nodes;
  const explicit = process.env.LOOKOUT_LOCAL_INSTANCE_ID;
  const match = nodes.find((node) => (explicit && node.instanceId === explicit) || (local.address && [node.address, node.publicAddress].includes(local.address)) || (node.hostname && node.hostname === local.hostname));
  if (!match) return includeUnmanagedLocal ? [...nodes, local] : nodes;
  match.local = true;
  match.transport = 'local';
  match.address ||= local.address;
  return nodes;
}

function discoverCloudFleet({ run = commandJson, local = localNode(), markLocal = true, includeUnmanagedLocal = true } = {}) {
  const providers = [discoverAws, discoverGcp, discoverAzure, discoverDigitalOcean];
  const nodes = providers.flatMap((discover) => {
    try { return discover(run); } catch { return []; }
  });
  const unique = new Map(nodes.map((node) => [node.id, node]));
  return mergeLocalIdentity([...unique.values()], local, { markLocal, includeUnmanagedLocal }).sort((a, b) => a.id.localeCompare(b.id));
}

async function discoverCloudFleetAsync({ run = commandJsonAsync, runText = commandTextAsync, local = localNode(), markLocal = false, includeUnmanagedLocal = false } = {}) {
  const [profileText, gcpProjects, azureAccounts] = await Promise.all([
    runText('aws', ['configure', 'list-profiles']),
    run('gcloud', ['projects', 'list', '--filter=lifecycleState=ACTIVE', '--format=json']),
    run('az', ['account', 'list', '--all', '-o', 'json'])
  ]);
  const profiles = [...new Set(String(profileText || '').split(/\r?\n/).map((item) => item.trim()).filter((item) => /^[A-Za-z0-9_+=,.@-]{1,128}$/.test(item)))];
  const awsProfiles = profiles.length ? profiles : [null];
  const awsRegions = await Promise.all(awsProfiles.map(async (profile) => {
    const suffix = profile ? ['--profile', profile] : [];
    const [document, caller] = await Promise.all([
      run('aws', ['ec2', 'describe-regions', '--region', 'us-east-1', '--output', 'json', ...suffix]),
      run('aws', ['sts', 'get-caller-identity', '--output', 'json', ...suffix])
    ]);
    const regions = (document?.Regions || []).map((item) => clean(item.RegionName)).filter(Boolean);
    const account = /^\d{12}$/.test(String(caller?.Account || '')) ? String(caller.Account) : null;
    return { profile, account, regions: regions.length ? regions : [null] };
  }));
  const projects = Array.isArray(gcpProjects) ? gcpProjects.map((item) => clean(item.projectId)).filter(Boolean) : [];
  const subscriptions = Array.isArray(azureAccounts) ? azureAccounts.filter((item) => item?.state === 'Enabled').map((item) => clean(item.id)).filter(Boolean) : [];
  const commands = [
    ...awsRegions.flatMap(({ profile, account, regions }) => regions.map((region) => ['aws', ['ec2', 'describe-instances', '--filters', 'Name=instance-state-name,Values=running', '--output', 'json', ...(region ? ['--region', region] : []), ...(profile ? ['--profile', profile] : [])], discoverAws, { profile, account, region }])),
    ...(projects.length ? projects : [null]).map((project) => ['gcloud', ['compute', 'instances', 'list', '--filter=status=RUNNING', '--format=json', ...(project ? ['--project', project] : [])], discoverGcp, { project }]),
    ...(subscriptions.length ? subscriptions : [null]).map((subscription) => ['az', ['vm', 'list', '-d', '--show-details', '--query', "[?powerState=='VM running']", '-o', 'json', ...(subscription ? ['--subscription', subscription] : [])], discoverAzure, { subscription }]),
    ['doctl', ['compute', 'droplet', 'list', '--output', 'json'], discoverDigitalOcean]
  ];
  const results = await Promise.all(commands.map(async ([command, args, parse, context = {}]) => {
    const document = await run(command, args);
    if (document === null) return [];
    return parse(() => document, context).map((node) => ({
      ...node,
      ...(context.account && context.region ? { id: `aws:${context.account}:${context.region}:${node.instanceId}` } : {}),
      ...(context.project ? { id: `gcp:${context.project}:${node.instanceId}` } : {}),
      ...(context.profile ? { awsProfile: context.profile } : {}),
      ...(context.project && !node.project ? { project: context.project } : {})
    }));
  }));
  const unique = new Map(results.flat().map((node) => [node.id, node]));
  return mergeLocalIdentity([...unique.values()], local, { markLocal, includeUnmanagedLocal }).sort((a, b) => a.id.localeCompare(b.id));
}

function installationScope(nodes) {
  const eligible = nodes.filter((node) => node.online !== false && node.platform === 'linux');
  if (!eligible.length) throw new Error('Automatic discovery found no running Linux VM');
  const central = eligible.find((node) => node.local) || eligible.sort((a, b) => a.id.localeCompare(b.id))[0];
  return {
    central_vm_id: central.id,
    vms: eligible.map((node) => ({
      id: node.id, provider: node.provider, name: node.hostname || node.id, instance_id: node.instanceId,
      ...(node.region ? { region: node.region } : {}), ...(node.zone ? { zone: node.zone } : {}),
      ...(node.address || node.publicAddress ? { address: node.address || node.publicAddress } : {}),
      ...(node.publicAddress ? { public_address: node.publicAddress } : {}),
      ...(node.awsProfile ? { aws_profile: node.awsProfile } : {}),
      platform: node.platform, local: node.local === true,
      ...(node.resourceGroup ? { resource_group: node.resourceGroup } : {}), ...(node.resourceId ? { resource_id: node.resourceId } : {}),
      ...(node.project ? { project: node.project } : {})
    }))
  };
}

function enrichInstallationScope(scope, nodes) {
  if (!scope || !Array.isArray(scope.vms)) return scope;
  const current = new Map(nodes.map((node) => [node.id, node]));
  return {
    ...scope,
    vms: scope.vms.map((vm) => {
      const node = current.get(vm.id);
      if (!node) return vm;
      return {
        ...vm,
        ...(node.address ? { address: node.address } : {}),
        ...(node.publicAddress ? { public_address: node.publicAddress } : {}),
        ...(node.awsProfile ? { aws_profile: node.awsProfile } : {})
      };
    })
  };
}

module.exports = { commandJson, commandJsonAsync, commandTextAsync, discoverAws, discoverGcp, discoverAzure, discoverDigitalOcean, discoverCloudFleet, discoverCloudFleetAsync, installationScope, enrichInstallationScope, localNode, mergeLocalIdentity };
