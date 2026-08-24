'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { discoverCloudFleet, discoverCloudFleetAsync, installationScope, enrichInstallationScope } = require('../src/fleet/cloud-discovery');
const { ProviderAccessBroker, accessPlan } = require('../src/fleet/access-broker');
const { DeploymentState } = require('../src/fleet/deployment-state');
const { persistedFleetNode, deploymentConfigName, legacyDeploymentConfigName } = require('../install/fleet');

test('automatic discovery combines authoritative AWS, GCP, Azure, and DigitalOcean inventory', () => {
  const run = (command) => ({
    aws: { Reservations: [{ Instances: [{ InstanceId: 'i-1', PrivateIpAddress: '10.0.0.1', PlatformDetails: 'Linux/UNIX', Placement: { AvailabilityZone: 'us-west-2a' }, Tags: [{ Key: 'Name', Value: 'aws-one' }] }] }] },
    gcloud: [{ id: '22', name: 'gcp-one', status: 'RUNNING', zone: 'https://compute/v1/projects/p/zones/us-central1-a', selfLink: 'https://compute/v1/projects/p/zones/us-central1-a/instances/gcp-one', networkInterfaces: [{ networkIP: '10.1.0.2' }] }],
    az: [{ id: '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/az-one', vmId: '33333333-3333-3333-3333-333333333333', resourceGroup: 'rg', name: 'az-one', privateIps: '10.2.0.3', powerState: 'VM running', location: 'westus' }],
    doctl: [{ id: 44, name: 'do-one', status: 'active', region: { slug: 'sfo3' }, networks: { v4: [{ type: 'private', ip_address: '10.3.0.4' }] } }]
  })[command] || null;
  const local = { id: 'local:test', provider: 'local', instanceId: 'local', hostname: 'coordinator', address: '10.9.0.9', platform: 'linux', online: true, local: true, transport: 'local' };
  const nodes = discoverCloudFleet({ run, local });
  assert.deepEqual(new Set(nodes.map((node) => node.provider)), new Set(['aws', 'gcp', 'azure', 'digitalocean', 'local']));
  const scope = installationScope(nodes);
  assert.equal(scope.central_vm_id, 'local:test');
  assert.equal(scope.vms.length, 5);
  assert.equal(scope.vms.filter((node) => node.local).length, 1);
});

test('blank-session discovery keeps the orchestration host outside the target scope', () => {
  const run = (command) => command === 'aws' ? { Reservations: [{ Instances: [{ InstanceId: 'i-remote', PrivateIpAddress: '10.0.0.8', PlatformDetails: 'Linux/UNIX', Placement: { AvailabilityZone: 'us-west-2b' } }] }] } : null;
  const local = { id: 'local:agent', provider: 'local', instanceId: 'agent', hostname: 'agent-host', address: '192.0.2.10', platform: 'linux', online: true, local: true, transport: 'local' };
  const nodes = discoverCloudFleet({ run, local, markLocal: false, includeUnmanagedLocal: false });
  const scope = installationScope(nodes);
  assert.equal(scope.central_vm_id, 'aws:i-remote');
  assert.equal(scope.vms.length, 1);
  assert.equal(scope.vms[0].local, false);
});

test('hosted discovery searches every AWS region, GCP project, and Azure subscription', async () => {
  const calls = [];
  const runText = async (command, args) => {
    assert.equal(command, 'aws');
    assert.deepEqual(args, ['configure', 'list-profiles']);
    return 'default\nproduction\n';
  };
  const run = async (command, args) => {
    calls.push([command, args]);
    if (command === 'aws' && args[1] === 'describe-regions') return { Regions: [{ RegionName: 'us-east-1' }, { RegionName: 'us-west-2' }] };
    if (command === 'aws' && args[0] === 'sts') return { Account: args.at(-1) === 'production' ? '222222222222' : '111111111111' };
    if (command === 'aws') {
      const profile = args[args.indexOf('--profile') + 1];
      const region = args[args.indexOf('--region') + 1];
      return { Reservations: [{ Instances: [{ InstanceId: `i-${profile}-${region}`, PrivateIpAddress: '10.0.0.8', PublicIpAddress: '203.0.113.8', PlatformDetails: 'Linux/UNIX', Placement: { AvailabilityZone: `${region}a` } }] }] };
    }
    if (command === 'gcloud' && args[0] === 'projects') return [{ projectId: 'project-one' }, { projectId: 'project-two' }];
    if (command === 'gcloud') {
      const project = args[args.indexOf('--project') + 1];
      return [{ id: project === 'project-one' ? '11' : '22', name: `vm-${project}`, zone: 'us-central1-a', selfLink: `https://compute/v1/projects/${project}/zones/us-central1-a/instances/vm-${project}`, networkInterfaces: [{ networkIP: '10.1.0.2' }] }];
    }
    if (command === 'az' && args[0] === 'account') return [{ id: 'sub-one', state: 'Enabled' }, { id: 'sub-disabled', state: 'Disabled' }];
    if (command === 'az') return [];
    return null;
  };
  const nodes = await discoverCloudFleetAsync({ run, runText });
  const awsNodes = nodes.filter((node) => node.provider === 'aws');
  assert.equal(awsNodes.length, 4);
  assert.deepEqual(new Set(awsNodes.map((node) => node.awsProfile)), new Set(['default', 'production']));
  assert.equal(calls.filter(([command]) => command === 'aws').length, 8);
  assert.ok(awsNodes.every((node) => /^aws:\d{12}:us-(?:east-1|west-2):i-/.test(node.id)));
  assert.deepEqual(nodes.filter((node) => node.provider === 'gcp').map((node) => node.project), ['project-one', 'project-two']);
  assert.equal(calls.filter(([command, args]) => command === 'az' && args[0] === 'vm').length, 1);
  const scope = installationScope(nodes);
  assert.deepEqual(new Set(scope.vms.filter((node) => node.provider === 'aws').map((node) => node.aws_profile)), new Set(['default', 'production']));
});

test('resume refreshes access metadata without expanding the approved VM scope', () => {
  const scope = { central_vm_id: 'digitalocean:1', vms: [{ id: 'digitalocean:1', provider: 'digitalocean', address: '10.0.0.1' }] };
  const enriched = enrichInstallationScope(scope, [
    { id: 'digitalocean:1', address: '10.0.0.1', publicAddress: '203.0.113.1' },
    { id: 'digitalocean:2', address: '10.0.0.2', publicAddress: '203.0.113.2' }
  ]);
  assert.deepEqual(enriched.vms, [{ id: 'digitalocean:1', provider: 'digitalocean', address: '10.0.0.1', public_address: '203.0.113.1' }]);
  assert.equal(enriched.vms.some((node) => node.id === 'digitalocean:2'), false);
});

test('fleet state retains bounded non-secret access context for uninstall reuse', () => {
  assert.equal(deploymentConfigName, 'security-observability-config.json');
  assert.equal(legacyDeploymentConfigName, 'fleet.json');
  const persisted = persistedFleetNode({
    id: 'aws:i-1', provider: 'aws', instanceId: 'i-1', hostname: 'vm-one', address: '10.0.0.1', publicAddress: '203.0.113.1',
    platform: 'linux', awsProfile: 'production', region: 'us-west-2', zone: 'us-west-2a', sshUser: 'ubuntu',
    managementTransport: 'aws-ssm', unavailableAccessMethods: ['aws-instance-connect'], reachable: true,
    consoleCredential: 'must-not-persist', arbitrary: 'must-not-persist'
  });
  assert.deepEqual(persisted, {
    id: 'aws:i-1', provider: 'aws', instanceId: 'i-1', hostname: 'vm-one', address: '10.0.0.1', publicAddress: '203.0.113.1',
    platform: 'linux', sshUser: 'ubuntu', awsProfile: 'production', zone: 'us-west-2a', region: 'us-west-2',
    managementTransport: 'aws-ssm', reachable: true, unavailableAccessMethods: ['aws-instance-connect']
  });
});

test('provider access broker follows native short-lived fallback order', () => {
  assert.deepEqual(accessPlan({ provider: 'aws' }), ['aws-ssm', 'aws-instance-connect', 'openssh']);
  assert.deepEqual(accessPlan({ provider: 'gcp' }), ['gcp-os-login', 'gcp-iap', 'openssh']);
  assert.deepEqual(accessPlan({ provider: 'azure' }), ['azure-run-command', 'openssh']);
  const attempts = [];
  const node = { provider: 'aws', id: 'aws:i-1', instanceId: 'i-1', zone: 'us-west-2a', sshUser: 'ubuntu' };
  const broker = new ProviderAccessBroker({
    publicKey: 'ssh-ed25519 AAAA fixture',
    run(method) { attempts.push(method); throw new Error('fixture unavailable'); },
    ssh() { attempts.push('openssh'); return 'Linux'; }
  });
  assert.equal(broker.execute(node, ['uname', '-s']), 'Linux');
  assert.equal(broker.execute(node, ['id', '-u']), 'Linux');
  assert.deepEqual(attempts, ['aws-ssm', 'aws-instance-connect', 'openssh', 'openssh']);
  assert.equal(node.managementTransport, 'openssh');
});

test('provider access broker passes the discovered AWS CLI context and prefers local gcloud', () => {
  const awsOptions = [];
  const aws = new ProviderAccessBroker({
    publicKey: 'ssh-ed25519 AAAA fixture',
    run(method, options) { awsOptions.push([method, options]); return 'Linux'; },
    ssh() { throw new Error('SSH should not run'); }
  });
  aws.execute({ provider: 'aws', instanceId: 'i-1', region: 'us-west-2', zone: 'us-west-2a', awsProfile: 'production' }, ['uname', '-s']);
  assert.equal(awsOptions[0][0], 'aws-ssm');
  assert.equal(awsOptions[0][1].profile, 'production');
  assert.equal(awsOptions[0][1].region, 'us-west-2');

  const methods = [];
  const gcp = new ProviderAccessBroker({
    run(method) { methods.push(method); if (method === 'gcp-os-login') return 'Linux'; throw new Error('unexpected method'); },
    ssh() { methods.push('openssh'); throw new Error('SSH should not run'); }
  });
  gcp.execute({ provider: 'gcp', hostname: 'gcp-one', zone: 'us-central1-a', project: 'project-one' }, ['uname', '-s']);
  assert.deepEqual(methods, ['gcp-os-login']);

  let azureOptions;
  const azure = new ProviderAccessBroker({
    run(method, options) { assert.equal(method, 'azure-run-command'); azureOptions = options; return 'Linux'; },
    ssh() { throw new Error('SSH should not run'); }
  });
  azure.execute({ provider: 'azure', resourceId: '/subscriptions/sub-one/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-one' }, ['uname', '-s']);
  assert.equal(azureOptions.resourceId, '/subscriptions/sub-one/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-one');
  assert.equal(azureOptions.resourceGroup, null);
});

test('provider access broker does not repeat failed account-level native methods', () => {
  const attempts = [];
  const node = { provider: 'aws', id: 'aws:i-1', instanceId: 'i-1', zone: 'us-west-2a', sshUser: 'ubuntu' };
  const broker = new ProviderAccessBroker({
    publicKey: 'ssh-ed25519 AAAA fixture',
    run(method) { attempts.push(method); throw new Error('fixture unavailable'); },
    ssh() { attempts.push('openssh'); const error = new Error('fixture unavailable'); error.failureKind = 'authentication'; throw error; }
  });
  assert.throws(() => broker.execute(node, ['uname', '-s']), /Needs access/);
  assert.throws(() => broker.execute(node, ['uname', '-s']), /Needs access/);
  assert.deepEqual(attempts, ['aws-ssm', 'aws-instance-connect', 'openssh', 'aws-instance-connect', 'openssh']);
});

test('provider access broker preserves remote command failures instead of reporting access failure', () => {
  const broker = new ProviderAccessBroker({
    run() {
      const error = new Error('release artifact is missing install/install.sh');
      error.code = 'LOOKOUT_REMOTE_COMMAND_FAILED';
      throw error;
    },
    ssh() { throw new Error('SSH fallback must not run'); }
  });
  assert.throws(
    () => broker.execute({ provider: 'gcp', hostname: 'vm-one', zone: 'us-central1-a', project: 'project-one' }, ['test', '-x', '/stage/install/install.sh']),
    /release artifact is missing install\/install\.sh/
  );
});

test('deployment state resumes from the last verified node checkpoint', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lookout-deployment-state-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filename = path.join(directory, 'state.json');
  const nodes = [{ id: 'central' }, { id: 'collector-a' }, { id: 'collector-b' }];
  const first = new DeploymentState(filename, 'deployment-test', nodes);
  first.checkpoint('central', { nodeId: 'central', total: 3, completed: 1 });
  first.checkpoint('protected', { nodeId: 'collector-a', total: 3, completed: 2 });
  const resumed = new DeploymentState(filename, 'deployment-test', nodes);
  assert.equal(resumed.completed('central', 'central'), true);
  assert.equal(resumed.completed('collector-a', 'protected'), true);
  assert.equal(resumed.completed('collector-b', 'protected'), false);
  assert.equal(fs.statSync(filename).mode & 0o777, 0o600);
});

test('installer source contains no target-side npm or Node.js download path', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../install/install.sh'), 'utf8');
  assert.doesNotMatch(source, /npm[^\n]*\bci\b/);
  assert.doesNotMatch(source, /nodejs\.org\/dist|Downloading the pinned Node\.js/);
  assert.match(source, /verified release does not contain prebuilt production dependencies/);
  assert.match(source, /atomic_symlink/);
  const fleet = fs.readFileSync(path.resolve(__dirname, '../install/fleet.js'), 'utf8');
  assert.doesNotMatch(fleet, /remote\(central, \['cat', '\/etc\/lookout\/tls\/server\.key'/);
  assert.match(fleet, /openssl genpkey -algorithm RSA/);
  assert.match(fleet, /installSecretFileRemote/);
});

test('installer allows bounded startup time on the smallest supported VMs', () => {
  const source = fs.readFileSync(path.resolve(__dirname, '../install/install.sh'), 'utf8');
  assert.equal((source.match(/while \[ "\$attempts" -lt 90 \]/g) || []).length, 2);
  assert.match(source, /health verification failed after 90 seconds/);
});
